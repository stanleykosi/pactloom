//! Private purpose-bound append kernels. Neither method accepts a caller bool,
//! generic mutation closure, raw scope descriptor or historical replay as authority.
use super::*;
use crate::durable_payment_owner_v1::{
    ConfiguredDurablePaymentWitnessV1, NativeDurablePaymentAdmissionSourceV1,
};

impl AuthorityJournal {
    pub(crate) fn commit_native_durable_payment_v1(
        &self,
        source: &mut NativeDurablePaymentAdmissionSourceV1,
        peer: &str,
        request: OwnerControlRequest,
    ) -> Result<MutationResult> {
        #[cfg(feature = "synthetic-qualification")]
        let observer = source.admission_observer().cloned();
        let result = (|| {
            crate::transport::admission_stage!(observer.as_ref(), JournalPreflight);
            source.check_open()?;
            let c = self
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
            authenticate_admission(&tx, peer)?;
            let mut ledger = load(&tx)?;
            let now = now_ms()?;
            crate::transport::admission_stage!(observer.as_ref(), ExactRequest);
            source.require_exact_locked(self, &ledger, peer, &request, now)?;
            let event = Event {
                mutation: AuthorityMutation::OwnerControl(request.clone()),
                authenticated_certificate_digest: peer.into(),
                witness_time_ms: now,
                writer_session_id: None,
                original_request_link: None,
            };
            ledger.authenticate_mutation(&event)?;
            if ledger.replay(&event)?.is_some() {
                return Err(AuthorityError::Uncertain);
            }
            // Correct lock order: journal lock and BEGIN IMMEDIATE + complete exact
            // preflight precede OPEN -> PUBLISHING. Never hold publication during TLS.
            crate::transport::admission_stage!(observer.as_ref(), Publication);
            let publication = crate::transport::admission_measure!(
                observer.as_ref(),
                Publication,
                source.take_publication_after_lock()
            )?;
            publication.check_current()?;
            let previous = ledger.snapshot.head.digest.clone();
            crate::transport::admission_stage!(observer.as_ref(), Apply);
            let result = ledger.apply(&event)?;
            crate::transport::admission_stage!(observer.as_ref(), Append);
            crate::transport::admission_measure!(
                observer.as_ref(),
                Append,
                append_exact(&tx, &ledger, &event, &previous)
            )?;
            crate::transport::admission_stage!(observer.as_ref(), FinalCurrent);
            self.born_owner
                .as_ref()
                .ok_or(AuthorityError::Permission)?
                .check_mutation_current()?;
            publication.check_current()?;
            let final_now = now_ms()?;
            let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control else {
                return Err(AuthorityError::Permission);
            };
            if final_now < now || final_now >= record.terms.valid_until_ms {
                return Err(AuthorityError::Expired);
            }
            crate::transport::admission_stage!(observer.as_ref(), Commit);
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.commit_entered();
            }
            let committed =
                crate::transport::admission_measure!(observer.as_ref(), Commit, tx.commit());
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.commit_returned(&committed);
            }
            committed.map_err(|_| AuthorityError::Uncertain)?;
            crate::transport::admission_stage!(observer.as_ref(), ControlledResult);
            let MutationResult::Controlled(snapshot) = &result else {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = &observer {
                    observer.controlled_result(false);
                }
                return Err(AuthorityError::CorruptHistory);
            };
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = &observer {
                observer.controlled_result(true);
            }
            crate::transport::admission_stage!(observer.as_ref(), SnapshotRecord);
            source.record_committed(snapshot.clone());
            Ok(result)
        })();
        crate::transport::admission_result!(observer.as_ref(), observe_semantic, result)
    }

    pub(crate) fn mutate_durable_payment_v1(
        &self,
        source: &ConfiguredDurablePaymentWitnessV1,
        peer: &str,
        mutation: AuthorityMutation,
        proof: Option<protocol::WriterSessionProof>,
        exporter: &[u8; 32],
        server_certificate: &str,
    ) -> Result<MutationResult> {
        source.check_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        authenticate_admission(&tx, peer)?;
        let mut ledger = load(&tx)?;
        let admission_id = source.require_locked(self, &ledger)?.to_owned();
        let now = now_ms()?;
        // Acquire's historical event has no writer attribution, even on retry.
        // Its transport proof is still verified separately against the saved key.
        let event_session = canonical_event_session(&mutation, proof.as_ref());
        ledger.require_durable_payment_mutation_v1(
            &admission_id,
            &mutation,
            event_session.as_deref(),
            now,
        )?;
        let mut event = Event {
            mutation,
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: now,
            writer_session_id: event_session,
            original_request_link: None,
        };
        ledger.authenticate_mutation(&event)?;
        ledger.require_account_use_for_new_mutation(&event.mutation)?;
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let mut key: Option<Zeroizing<[u8; 32]>> = None;
        match &event.mutation {
            AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ActivateWriter { .. },
                ..
            }) => {
                if proof.is_some() {
                    return Err(AuthorityError::InvalidBinding);
                }
            }
            AuthorityMutation::AcquireWriter(request) if ledger.replay(&event)?.is_none() => {
                if proof.is_some()
                    || request.session_id != crate::session::session_id(exporter)
                    || request.disclosure.pinned_server_certificate_digest != server_certificate
                {
                    return Err(AuthorityError::Authentication);
                }
                event.writer_session_id = None;
                key = Some(Zeroizing::new(*exporter));
            }
            AuthorityMutation::AcquireWriter(_) | AuthorityMutation::ReserveAuthorization(_) => {
                let proof = proof.as_ref().ok_or(AuthorityError::RecoveryRequired)?;
                let receipt = ledger
                    .sessions
                    .get(&proof.session_id)
                    .ok_or(AuthorityError::RecoveryRequired)?;
                ledger.require_unfenced_transport(&proof.session_id)?;
                if receipt.writer_certificate_digest != peer
                    || receipt.disclosure.pinned_server_certificate_digest != server_certificate
                    || now >= receipt.expires_at_ms
                    || (!matches!(event.mutation, AuthorityMutation::AcquireWriter(_))
                        && !ledger.activated_sessions.contains(&proof.session_id))
                {
                    return Err(AuthorityError::SessionRequired);
                }
                let original = read_session_key(&tx, &proof.session_id)?;
                crate::session::verify(&original, receipt, exporter, &event.mutation, proof)?;
            }
            _ => return Err(AuthorityError::Permission),
        }
        if matches!(event.mutation, AuthorityMutation::ReserveAuthorization(_))
            && !ledger.resolutions.is_empty()
            && self.revalidate_resolutions(&ledger).is_err()
        {
            self.append_reopen(&tx, &mut ledger, now)?;
            tx.commit().map_err(|_| AuthorityError::Uncertain)?;
            return Err(AuthorityError::ResolutionUnavailable);
        }
        if let Some(result) = ledger.replay(&event)? {
            source.check_mutation_current()?;
            ledger.require_durable_payment_mutation_v1(
                &admission_id,
                &event.mutation,
                event.writer_session_id.as_deref(),
                now_ms()?,
            )?;
            return Ok(result);
        }
        // Recheck the pre-append ledger at the final live time; applying below
        // consumes the same CAS/head once and does not reopen generic permission.
        source.check_mutation_current()?;
        ledger.require_durable_payment_mutation_v1(
            &admission_id,
            &event.mutation,
            event.writer_session_id.as_deref(),
            now_ms()?,
        )?;
        let previous = ledger.snapshot.head.digest.clone();
        let result = ledger.apply(&event)?;
        append_exact(&tx, &ledger, &event, &previous)?;
        if let Some(key) = key {
            let AuthorityMutation::AcquireWriter(request) = &event.mutation else {
                return Err(AuthorityError::CorruptHistory);
            };
            tx.execute(
                "INSERT INTO authority_session_keys VALUES(?1,?2)",
                params![request.session_id, key.as_slice()],
            )?;
        }
        source.check_mutation_current()?;
        let request = ledger
            .durable_payment_admission_v1(&admission_id)?
            .ok_or(AuthorityError::CorruptHistory)?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let final_now = now_ms()?;
        if final_now < now || final_now >= record.terms.valid_until_ms {
            return Err(AuthorityError::Expired);
        }
        // Post-apply state retains the same immutable operation, so this also
        // intersects original session/permit expiry immediately before commit.
        ledger.require_durable_payment_mutation_v1(
            &admission_id,
            &event.mutation,
            event.writer_session_id.as_deref(),
            final_now,
        )?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        Ok(result)
    }
}
fn append_exact(
    tx: &Transaction<'_>,
    ledger: &Ledger,
    event: &Event,
    previous: &str,
) -> Result<()> {
    let payload = encode(event)?;
    let bytes: u64 = tx.query_row(
        "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
        [],
        |r| r.get(0),
    )?;
    if bytes
        .checked_add(payload.len() as u64)
        .filter(|v| *v <= MAX_JOURNAL_BYTES)
        .is_none()
    {
        return Err(AuthorityError::Limit);
    }
    tx.execute(
        "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
        params![
            ledger.snapshot.head.sequence,
            event.mutation.operation_id(),
            previous,
            ledger.snapshot.head.digest,
            &*payload
        ],
    )?;
    Ok(())
}

fn canonical_event_session(
    mutation: &AuthorityMutation,
    proof: Option<&protocol::WriterSessionProof>,
) -> Option<String> {
    if matches!(mutation, AuthorityMutation::AcquireWriter(_)) {
        None
    } else {
        proof.map(|p| p.session_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_payment_v1::tests::{activate, admitted_fixture};
    #[test]
    fn exact_acquire_retry_keeps_canonical_none_but_requires_original_key_proof() {
        let (birth, mut ledger, mut events, admission) = admitted_fixture();
        activate(&birth, &mut ledger, &mut events, &admission);
        let mut receipt = ledger.snapshot.active_writer_session.clone().unwrap();
        let key = [0x26; 32];
        let reconnect_exporter = [0x28; 32];
        receipt.session_id = crate::session::session_id(&key);
        let mut mutation = events[events.len() - 2].mutation.clone();
        let AuthorityMutation::AcquireWriter(request) = &mut mutation else {
            panic!()
        };
        request.session_id = receipt.session_id.clone();
        let proof = crate::session::proof(
            &key,
            (
                &receipt.session_id,
                &receipt.disclosure,
                receipt.writer_epoch,
            ),
            &reconnect_exporter,
            &mutation,
        )
        .unwrap();
        assert!(canonical_event_session(&mutation, Some(&proof)).is_none());
        crate::session::verify(&key, &receipt, &reconnect_exporter, &mutation, &proof).unwrap();
        assert!(crate::session::verify(
            &[0x27; 32],
            &receipt,
            &reconnect_exporter,
            &mutation,
            &proof
        )
        .is_err());
        assert!(crate::session::verify(&key, &receipt, &[0x29; 32], &mutation, &proof).is_err());
        // This checks attribution + channel MAC only. No native source, live
        // namespace or financial append is constructed by this data test.
    }
}
