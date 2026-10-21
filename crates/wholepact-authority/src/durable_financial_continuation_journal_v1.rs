//! Private purpose-bound append kernels. Neither method accepts a caller bool,
//! generic mutation closure, raw scope descriptor or historical replay as authority.
use super::*;
use crate::durable_financial_continuation_owner_v1::NativeFinancialContinuationSourceV1;

impl AuthorityJournal {
    pub(crate) fn commit_native_financial_continuation_v1(
        &self,
        source: &mut NativeFinancialContinuationSourceV1,
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
            let result = ledger.apply_financial_continuation_v1(&event)?;
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
            let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
                return Err(AuthorityError::Permission);
            };
            if final_now < now || record.terms.require_live(final_now).is_err() {
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
    pub(crate) fn mutate_financial_continuation_v1(
        &self,
        source: &crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1,
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
        let mut ledger = load_financial_continuation_v1(&tx)?;
        let admission_id = source.require_locked(self, &ledger)?.to_owned();
        let now = now_ms()?;
        // Acquire's historical event has no writer attribution, even on retry.
        // Its transport proof is still verified separately against the saved key.
        let event_session = canonical_event_session(&mutation, proof.as_ref());
        ledger.require_financial_continuation_mutation_v1(
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
            ledger.require_financial_continuation_mutation_v1(
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
        ledger.require_financial_continuation_mutation_v1(
            &admission_id,
            &event.mutation,
            event.writer_session_id.as_deref(),
            now_ms()?,
        )?;
        let previous = ledger.snapshot.head.digest.clone();
        let result = ledger.apply_financial_continuation_v1(&event)?;
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
            .financial_continuation_v1(&admission_id)?
            .ok_or(AuthorityError::CorruptHistory)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let final_now = now_ms()?;
        if final_now < now || final_now >= record.terms.valid_until_ms {
            return Err(AuthorityError::Expired);
        }
        // Post-apply state retains the same immutable operation, so this also
        // intersects original session/permit expiry immediately before commit.
        ledger.require_financial_continuation_mutation_v1(
            &admission_id,
            &event.mutation,
            event.writer_session_id.as_deref(),
            final_now,
        )?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        Ok(result)
    }
}
pub(super) fn append_exact(
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

impl AuthorityJournal {
    pub(crate) fn financial_snapshot_v1(
        &self,
        peer: &str,
        account: &str,
        network: &str,
    ) -> Result<AccountSnapshot> {
        self.require_born_read_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        authenticate_admission(&tx, peer)?;
        let ledger = load_financial_continuation_v1(&tx)?;
        ledger.authenticate_read(peer, account, network)?;
        Ok(ledger.snapshot)
    }
    pub(crate) fn financial_history_page_v1(
        &self,
        peer: &str,
        account: &str,
        network: &str,
        expected: &AuthorityHead,
        after: u64,
        maximum: u16,
    ) -> Result<HistoryPage> {
        self.require_born_read_current()?;
        if maximum == 0 || maximum > 16 || after > expected.sequence {
            return Err(AuthorityError::Limit);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        authenticate_admission(&tx, peer)?;
        let ledger = load_financial_continuation_v1(&tx)?;
        ledger.authenticate_read(peer, account, network)?;
        history_page_at(&tx, ledger, expected, after, maximum)
    }
}
impl AuthorityJournal {
    pub(crate) fn completed_dispatch_snapshot_v1(
        &self,
        source: &crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1,
        peer: &str,
        account: &str,
        network: &str,
    ) -> Result<AccountSnapshot> {
        self.require_born_read_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let ledger = load_financial_continuation_v1(&tx)?;
        source.require_dispatcher_locked(self, &ledger, peer)?;
        if ledger.policy.account_id != account || ledger.policy.network_profile_id != network {
            return Err(AuthorityError::Authentication);
        }
        Ok(ledger.snapshot)
    }
    pub(crate) fn completed_dispatch_history_v1(
        &self,
        source: &crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1,
        peer: &str,
        account: &str,
        network: &str,
        expected: &AuthorityHead,
        after: u64,
        maximum: u16,
    ) -> Result<HistoryPage> {
        self.require_born_read_current()?;
        if maximum == 0 || maximum > 16 || after > expected.sequence {
            return Err(AuthorityError::Limit);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let ledger = load_financial_continuation_v1(&tx)?;
        source.require_dispatcher_locked(self, &ledger, peer)?;
        if ledger.policy.account_id != account || ledger.policy.network_profile_id != network {
            return Err(AuthorityError::Authentication);
        }
        history_page_at(&tx, ledger, expected, after, maximum)
    }
    pub(crate) fn authorize_completed_dispatch_v1(
        &self,
        source: &crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1,
        peer: &str,
        request: crate::completed_dispatch_v1::AuthorizeCompletedDispatchV1,
    ) -> Result<MutationResult> {
        source.check_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let mut ledger = load_financial_continuation_v1(&tx)?;
        // TLS has verified possession; the committed exact scope is the ONLY
        // dispatcher enrollment. It never enters the ordinary principals table.
        source.require_dispatcher_locked(self, &ledger, peer)?;
        let now = now_ms()?;
        let event = Event {
            mutation: AuthorityMutation::AuthorizeCompletedDispatchV1(request.clone()),
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: now,
            writer_session_id: None,
            original_request_link: None,
        };
        ledger.authenticate_mutation(&event)?;
        ledger.require_completed_dispatch_v1(&request, &event)?;
        if let Some(result) = ledger.replay(&event)? {
            source.check_mutation_current()?;
            let MutationResult::CompletedDispatchAdmittedV1(admission) = &result else {
                return Err(AuthorityError::CorruptHistory);
            };
            if now_ms()? >= admission.expires_at_ms {
                return Err(AuthorityError::Expired);
            }
            return Ok(result);
        }
        let previous = ledger.snapshot.head.digest.clone();
        let result = ledger.apply_financial_continuation_v1(&event)?;
        append_exact(&tx, &ledger, &event, &previous)?;
        source.check_mutation_current()?;
        let MutationResult::CompletedDispatchAdmittedV1(admission) = &result else {
            return Err(AuthorityError::CorruptHistory);
        };
        let final_now = now_ms()?;
        if final_now < now || final_now >= admission.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completed_dispatch_v1::*;
    use crate::durable_financial_continuation_v1::*;
    use crate::durable_payment_v1::tests::{h, history, owner_event};
    use std::os::unix::fs::PermissionsExt;

    /// Recorded never-funded data tests real encrypted append/reopen/immutability.
    /// It creates no native decision, enrolled live source, TLS owner or signature.
    #[test]
    fn encrypted_financial_profile_retains_original_and_dispatches_after_writer_expiry() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (journal, mut events, _) =
            crate::journal::durable_delivery_admission_journal_v2::tests::recorded_journal_with_attempts(
                &directory.path().join("never-funded-financial.db"),
                3,
            );
        let c = journal.connection.lock().unwrap();
        let mut ledger = load(c.connection()).unwrap();
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)
            .unwrap()
            .unwrap();
        let original = ledger
            .selected_durable_delivery_admission_v2()
            .unwrap()
            .unwrap()
            .clone();
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &original.control else {
            panic!()
        };
        let terms = FinancialContinuationTermsV1 {
            scope: record.scope.clone(),
            original_delivery_operation_id: original.operation_id.clone(),
            original_delivery_request_digest: original_delivery_request_digest_v1(&original)
                .unwrap(),
            original_delivery_committed_head: ledger.snapshot.head.clone(),
            original_local_intent_digest: h('b'),
            original_recipient_intent_digest: h('c'),
            original_recipient_enrollment_ref: h('d'),
            original_recipient_manifest_ref: h('e'),
            valid_from_ms: 129_000,
            valid_until_ms: 790_000,
        };
        let continuation =
            prepare_financial_continuation_request_v1(terms, h('f'), &history(&birth, &events))
                .unwrap();
        let event = owner_event(&ledger, continuation.clone(), 129_000);
        assert!(ledger.apply(&event).is_err());
        let prefix: Vec<Vec<u8>> = c
            .connection()
            .prepare("SELECT payload FROM authority_events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let append = |ledger: &mut Ledger, event: &Event, key: Option<&[u8; 32]>| {
            let tx =
                Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
            let previous = ledger.snapshot.head.digest.clone();
            ledger.apply_financial_continuation_v1(event).unwrap();
            append_exact(&tx, ledger, event, &previous).unwrap();
            if let Some(key) = key {
                tx.execute(
                    "INSERT INTO authority_session_keys VALUES(?1,?2)",
                    params![crate::session::session_id(key), key.as_slice()],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        };
        append(&mut ledger, &event, None);
        events.push(event);
        assert!(load(c.connection()).is_err());
        assert_eq!(
            load_financial_continuation_v1(c.connection())
                .unwrap()
                .snapshot
                .head,
            ledger.snapshot.head
        );
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &continuation.control else {
            panic!()
        };
        let key = [0x91; 32];
        let session_id = crate::session::session_id(&key);
        let acquire = Event {
            mutation: AuthorityMutation::AcquireWriter(AcquireWriterRequest {
                operation_id: record.acquire_operation_id(&continuation).unwrap(),
                account_id: ledger.policy.account_id.clone(),
                network_profile_id: ledger.policy.network_profile_id.clone(),
                writer_epoch: ledger.snapshot.writer_epoch,
                expected_head: ledger.snapshot.head.clone(),
                reconciled_history_digest: crate::session::history_digest(&ledger.snapshot)
                    .unwrap(),
                session_id: session_id.clone(),
                disclosure: birth.request.disclosure.clone(),
            }),
            authenticated_certificate_digest: ledger
                .policy
                .initial_writer_certificate_digest
                .clone(),
            witness_time_ms: 130_000,
            writer_session_id: None,
            original_request_link: None,
        };
        append(&mut ledger, &acquire, Some(&key));
        let activation = OwnerControlRequest {
            operation_id: "fixture-financial-activate".into(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ActivateWriter {
                session_id: session_id.clone(),
            },
        };
        let activation = owner_event(&ledger, activation, 131_000);
        append(&mut ledger, &activation, None);
        // Borrow only the existing pure reservation fixture builder, not an old admission.
        let inert = OwnerControlRequest {
            operation_id: "inert-reservation-builder".into(),
            account_id: continuation.account_id.clone(),
            network_profile_id: continuation.network_profile_id.clone(),
            writer_epoch: continuation.writer_epoch,
            expected_head: continuation.expected_head.clone(),
            control: OwnerControl::AdmitDurablePaymentV1 {
                record: Box::new(crate::durable_payment_v1::DurablePaymentAdmissionRecordV1 {
                    terms: record.terms.scope.authorization.clone(),
                    witness_native_review_digest: h('a'),
                }),
            },
        };
        let mut reservation = crate::durable_payment_v1::tests::reservation(&ledger, &inert);
        reservation.reviewed_at_ms = 132_000;
        reservation.permit_expires_at_ms = 133_000;
        let event = Event {
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(reservation.clone())),
            authenticated_certificate_digest: ledger
                .policy
                .initial_writer_certificate_digest
                .clone(),
            witness_time_ms: 132_000,
            writer_session_id: Some(session_id),
            original_request_link: None,
        };
        append(&mut ledger, &event, None);
        let mut owners = record
            .terms
            .scope
            .delivery
            .owners
            .iter()
            .map(|owner| CompletedDispatchOwnerV1 {
                account_id: owner.account_id.clone(),
                continuation_operation_id: if owner.account_id == ledger.policy.account_id {
                    continuation.operation_id.clone()
                } else {
                    "other-continuation".into()
                },
                continuation_request_digest: if owner.account_id == ledger.policy.account_id {
                    record.request_digest(&continuation).unwrap()
                } else {
                    h('b')
                },
                reservation_operation_id: owner.original_authorization_id.clone(),
                reservation_request_digest: if owner.account_id == ledger.policy.account_id {
                    reservation.request_digest().unwrap()
                } else {
                    h('c')
                },
                signature_result_digest: h('d'),
            })
            .collect::<Vec<_>>();
        owners.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        let context = CompletedDispatchContextV1 {
            fixed: record.terms.scope.authorization.fixed.clone(),
            delivery: record.terms.scope.delivery.clone(),
            owners,
            signed_result_request_digest: h('e'),
            signed_artifact_digest: h('f'),
            transaction_checkpoint_id: "fixture-checkpoint".into(),
            final_transaction_digest: h('1'),
            final_transaction_id: h('2'),
            transaction_expiry_height: reservation.transaction_expiry_height,
            network: "testnet".into(),
            consensus_branch_id: wholepact_chain::NU7_BRANCH_ID,
            backend_disclosure_digest: h('3'),
            attempt: 1,
        };
        let mut request = AuthorizeCompletedDispatchV1 {
            operation_id: String::new(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            context,
            host_reviewed_at_ms: 500_000,
            requested_admission_lifetime_ms: 30_000,
        };
        request.operation_id = request.canonical_operation_id().unwrap();
        assert!(
            ledger
                .snapshot
                .active_writer_session
                .as_ref()
                .unwrap()
                .expires_at_ms
                < 500_000
        );
        let event = Event {
            mutation: AuthorityMutation::AuthorizeCompletedDispatchV1(request.clone()),
            authenticated_certificate_digest: record
                .terms
                .scope
                .delivery
                .dispatcher
                .public_identity_commitment
                .clone(),
            witness_time_ms: 500_001,
            writer_session_id: None,
            original_request_link: None,
        };
        // A Witness that missed pair one may admit exact pair two, spending
        // the skipped slot rather than restoring the original budget.
        let mut skipped = request.clone();
        skipped.context.attempt = 2;
        skipped.operation_id = skipped.canonical_operation_id().unwrap();
        let mut skipped_event = event.clone();
        skipped_event.mutation = AuthorityMutation::AuthorizeCompletedDispatchV1(skipped.clone());
        assert!(
            ledger
                .require_completed_dispatch_v1(&skipped, &skipped_event)
                .is_ok()
        );
        append(&mut ledger, &event, None);
        let reopened = load_financial_continuation_v1(c.connection()).unwrap();
        assert_eq!(reopened.snapshot.head, ledger.snapshot.head);
        assert_eq!(
            reopened.snapshot.outstanding_debit_zatoshis,
            reservation.maximum_debit_zatoshis
        );
        let result = reopened.replay(&event).unwrap().unwrap();
        let MutationResult::CompletedDispatchAdmittedV1(admission) = result else {
            panic!()
        };
        assert_eq!(admission.activated_at_ms, 500_001);
        assert_eq!(admission.expires_at_ms, 530_001);
        let mut replay = event.clone();
        replay.witness_time_ms = 520_000;
        assert_eq!(
            reopened
                .require_completed_dispatch_v1(&request, &replay)
                .unwrap(),
            530_001
        );
        replay.witness_time_ms = 530_001;
        assert!(matches!(
            reopened.require_completed_dispatch_v1(&request, &replay),
            Err(AuthorityError::Expired)
        ));
        let mut next = request.clone();
        next.context.attempt = 2;
        next.expected_head = reopened.snapshot.head.clone();
        next.operation_id = next.canonical_operation_id().unwrap();
        let mut next_event = event.clone();
        next_event.mutation = AuthorityMutation::AuthorizeCompletedDispatchV1(next.clone());
        assert!(
            reopened
                .require_completed_dispatch_v1(&next, &next_event)
                .is_ok()
        );
        for case in 0..4 {
            let mut invalid = next.clone();
            match case {
                0 => invalid.context.attempt = 1, // same slot, changed request
                1 => invalid.context.attempt = 0, // lower than original bound
                2 => invalid.context.attempt = 4, // exceeds original budget
                3 => invalid.context.final_transaction_digest = h('9'),
                _ => unreachable!(),
            }
            invalid.operation_id = invalid.canonical_operation_id().unwrap();
            let mut invalid_event = event.clone();
            invalid_event.mutation =
                AuthorityMutation::AuthorizeCompletedDispatchV1(invalid.clone());
            assert!(
                reopened
                    .require_completed_dispatch_v1(&invalid, &invalid_event)
                    .is_err()
            );
        }
        let retained: Vec<Vec<u8>> = c
            .connection()
            .prepare("SELECT payload FROM authority_events WHERE sequence<=5 ORDER BY sequence")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(retained, prefix);
        assert!(load(c.connection()).is_err());
    }
}
impl AuthorityJournal {
    /// Monotone owner restrictions stay reachable after financial expiry. This
    /// path cannot issue/renew a financial action or clear existing exposure.
    pub(crate) fn restrict_financial_continuation_v1(
        &self,
        source: &crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1,
        peer: &str,
        request: OwnerControlRequest,
    ) -> Result<MutationResult> {
        if !matches!(
            request.control,
            OwnerControl::Pause
                | OwnerControl::Revoke
                | OwnerControl::PermanentlyExcludeAccount { .. }
        ) {
            return Err(AuthorityError::Permission);
        }
        source.check_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        authenticate_admission(&tx, peer)?;
        let mut ledger = load_financial_continuation_v1(&tx)?;
        source.require_locked(self, &ledger)?;
        if peer != ledger.policy.owner_certificate_digest {
            return Err(AuthorityError::Authentication);
        }
        let event = Event {
            mutation: AuthorityMutation::OwnerControl(request),
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: now_ms()?,
            writer_session_id: None,
            original_request_link: None,
        };
        ledger.authenticate_mutation(&event)?;
        if let Some(result) = ledger.replay(&event)? {
            source.check_mutation_current()?;
            return Ok(result);
        }
        let previous = ledger.snapshot.head.digest.clone();
        let result = ledger.apply_financial_continuation_v1(&event)?;
        append_exact(&tx, &ledger, &event, &previous)?;
        source.check_mutation_current()?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        Ok(result)
    }
}
