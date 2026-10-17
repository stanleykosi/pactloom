//! Concrete born journal transactions. Only the native configured owner reaches
//! these methods; generic DTO mutation cannot insert an admission or transport key.
use super::*;
use crate::{
    born_offline_admission_v1::*, born_offline_retry_v1::*, born_offline_witness_v1::*,
    offline_witness_v1::CurrentOfflineWitnessWindowV1,
};

#[allow(clippy::too_many_arguments)]
fn authenticated(
    c: &Connection,
    peer: &str,
    wire: &BornOfflineWitnessRequestV1,
    exporter: &[u8; 32],
    server: &str,
    now: u64,
) -> Result<Ledger> {
    authenticate_admission(c, peer)?;
    let l = load(c)?;
    let r = &wire.request.reservation;
    l.authenticate_read(
        peer,
        &r.intent.terms.account_id,
        &r.intent.terms.network_profile_id,
    )?;
    l.validate_born_offline_request_v1(&wire.request, now)?;
    let e = l.require_born_offline_original_session_v1(now)?;
    let session = &e.original_writer_session;
    if server != e.policy.witness_certificate_digest
        || session.disclosure.pinned_server_certificate_digest != server
    {
        return Err(AuthorityError::Authentication);
    }
    let record = wire.record()?;
    record.authentication.matches(r, &e.policy)?;
    if let Some(proof) = wire.authentication.select_original_proof(e, peer)? {
        let key = read_session_key(c, &proof.session_id)?;
        crate::session::verify(
            &key,
            session,
            exporter,
            &AuthorityMutation::ReserveBornOfflineV1(Box::new(record)),
            proof,
        )?;
    }
    Ok(l)
}
impl AuthorityJournal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_born_offline_original_v1(
        &self,
        peer: &str,
        wire: &BornOfflineWitnessRequestV1,
        exporter: &[u8; 32],
        server: &str,
        current: &CurrentOfflineWitnessWindowV1,
    ) -> Result<RetainedBornOfflineOriginalV1> {
        self.require_born_artifact_owner_current_v1()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let l = authenticated(&tx, peer, wire, exporter, server, current.check()?)?;
        let bytes = wire.envelope()?;
        let r = &wire.request.reservation;
        if let Some(old) = read_original(&tx, &r.operation_id)? {
            if old.original.request != wire.request
                || old.original.original.export_plan_template != wire.export_template
                || old.envelope != bytes
                || old.original.owner_transport_certificate_digest.as_deref()
                    != l.born_offline_enrollment_v1()?
                        .and_then(|e| e.enrollment.owner_continuation.as_ref().map(|_| peer))
            {
                return Err(AuthorityError::Conflict);
            }
            old.original.validate(&l)?;
            current.check()?;
            return Ok(old);
        }
        let claimed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_born_offline_originals WHERE construction_reservation_id=?1)", [&wire.request.construction_link.reservation_operation_id], |r| r.get(0))?;
        if claimed {
            return Err(AuthorityError::Conflict);
        }
        l.fence(&r.expected_head, r.writer_epoch)?;
        if l.operations.contains_key(&r.operation_id) {
            return Err(AuthorityError::Conflict);
        }
        let e = l.require_born_offline_original_session_v1(current.check()?)?;
        let mut original = BornOriginalPreparationV1 {
            version: 1,
            owner_transport_certificate_digest: e
                .owner_continuation
                .as_ref()
                .map(|_| peer.to_owned()),
            request: wire.request.clone(),
            original: crate::offline_retry::OriginalPreparation {
                schema_version: 1,
                request: r.clone(),
                export_plan_template: wire.export_template.clone(),
                original_envelope_digest: envelope_digest(&bytes),
                writer_certificate_digest: e
                    .original_writer_session
                    .writer_certificate_digest
                    .clone(),
                writer_session_id: e.original_writer_session.session_id.clone(),
                prepared_at_ms: current.check()?,
            },
            export_plan: wire.export_template.clone(),
        };
        let stream = original.export_stream()?;
        let last:u64=tx.query_row("SELECT coalesce(max(export_sequence),0) FROM authority_born_offline_originals WHERE export_stream=?1",[&stream],|r|r.get(0))?;
        original.export_plan.sequence = last
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(AuthorityError::Limit)?;
        original.export_plan.matches_preparation(r, &e.policy)?;
        original.validate(&l)?;
        self.require_born_artifact_owner_current_v1()?;
        l.validate_born_offline_request_v1(&wire.request, current.check()?)?;
        tx.execute(
            "INSERT INTO authority_born_offline_originals VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                r.operation_id,
                wire.request.request_digest()?,
                original.original.original_envelope_digest,
                stream,
                original.export_plan.sequence,
                &*encode(&original)?,
                bytes,
                wire.request.construction_link.reservation_operation_id,
            ],
        )?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        Ok(RetainedBornOfflineOriginalV1 {
            original,
            envelope: wire.envelope()?,
            receipt: None,
        })
    }
    /// Callback runs before the maintained inbox opens its write transaction.
    /// Retaining this receipt alone never admits exposure or supplies HPKE authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_born_offline_receipt_v1(
        &self,
        peer: &str,
        wire: &BornOfflineWitnessRequestV1,
        exporter: &[u8; 32],
        server: &str,
        receipt: &OriginalTransportReceipt,
        current: &CurrentOfflineWitnessWindowV1,
    ) -> Result<()> {
        self.require_born_artifact_owner_current_v1()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let l = authenticated(&tx, peer, wire, exporter, server, current.check()?)?;
        let old = read_original(&tx, &wire.request.reservation.operation_id)?
            .ok_or(AuthorityError::CorruptHistory)?;
        if old.original.request != wire.request {
            return Err(AuthorityError::Conflict);
        }
        let e = l.require_born_offline_original_session_v1(current.check()?)?;
        receipt.matches_born(&old.original.original, &e.policy)?;
        if let Some(prior) = old.receipt {
            if prior != *receipt {
                return Err(AuthorityError::Conflict);
            }
            return Ok(());
        }
        self.require_born_artifact_owner_current_v1()?;
        current.check()?;
        tx.execute(
            "INSERT INTO authority_born_offline_receipts VALUES(?1,?2)",
            params![wire.request.reservation.operation_id, &*encode(receipt)?],
        )?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_born_offline_v1(
        &self,
        peer: &str,
        wire: &BornOfflineWitnessRequestV1,
        exporter: &[u8; 32],
        server: &str,
        input: AuthenticatedBornInputV1,
        current: &CurrentOfflineWitnessWindowV1,
    ) -> Result<BornOfflineAuthorizationAdmissionV1> {
        self.require_born_artifact_owner_current_v1()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let mut l = authenticated(&tx, peer, wire, exporter, server, current.check()?)?;
        let old = read_original(&tx, &wire.request.reservation.operation_id)?
            .ok_or(AuthorityError::CorruptHistory)?;
        if old.original.request != wire.request || old.receipt.as_ref() != Some(input.receipt()) {
            return Err(AuthorityError::Authentication);
        }
        require_actual_inbox(&tx, &old, input.receipt())?;
        let record = wire.record()?;
        if record.authentication.envelope_digest != input.receipt().envelope_digest {
            return Err(AuthorityError::Authentication);
        }
        let event = Event {
            mutation: AuthorityMutation::ReserveBornOfflineV1(Box::new(record)),
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: current.check()?,
            writer_session_id: l
                .require_born_offline_original_session_v1(current.check()?)?
                .born_event_writer_session_v1(),
            original_request_link: None,
        };
        if let Some(result) = l.replay(&event)? {
            let MutationResult::BornOfflineReservedV1(a) = result else {
                return Err(AuthorityError::CorruptHistory);
            };
            return Ok(*a);
        }
        let previous = l.snapshot.head.digest.clone();
        let MutationResult::BornOfflineReservedV1(admission) = l.apply(&event)? else {
            return Err(AuthorityError::CorruptHistory);
        };
        old.original
            .export_plan
            .matches_commit(&admission.reserved)?;
        let payload = encode(&event)?;
        let total: u64 = tx.query_row(
            "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
            [],
            |r| r.get(0),
        )?;
        if total
            .checked_add(payload.len() as u64)
            .filter(|v| *v <= MAX_JOURNAL_BYTES)
            .is_none()
        {
            return Err(AuthorityError::Limit);
        }
        self.require_born_artifact_owner_current_v1()?;
        l.validate_born_offline_request_v1(&wire.request, current.check()?)?;
        tx.execute(
            "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
            params![
                l.snapshot.head.sequence,
                event.mutation.operation_id(),
                previous,
                l.snapshot.head.digest,
                &*payload
            ],
        )?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        Ok(*admission)
    }
    /// Read-only original lookup; no current event, allocation or emission. A
    /// genuine original namespace is still required, and quarantine fails closed.
    pub(crate) fn recover_born_offline_original_v1(
        &self,
        peer: &str,
        lookup: &BornOfflineDeliveryLookupV1,
    ) -> Result<(
        RetainedBornOfflineOriginalV1,
        BornOfflineAuthorizationAdmissionV1,
    )> {
        self.require_born_artifact_owner_read_current_v1()?;
        lookup.validate()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        authenticate_admission(&tx, peer)?;
        let l = load(&tx)?;
        l.authenticate_read(
            peer,
            &lookup.original.account_id,
            &lookup.original.network_profile_id,
        )?;
        if l.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let old =
            read_original(&tx, &lookup.original.operation_id)?.ok_or(AuthorityError::Uncertain)?;
        if BornOfflineDeliveryLookupV1::from_request(&old.original.request)? != *lookup {
            return Err(AuthorityError::Conflict);
        }
        let Some((
            AuthorityMutation::ReserveBornOfflineV1(record),
            original_peer,
            MutationResult::BornOfflineReservedV1(admission),
        )) = l.operations.get(&lookup.original.operation_id)
        else {
            return Err(AuthorityError::Uncertain);
        };
        if original_peer != peer || record.request != old.original.request {
            return Err(AuthorityError::Permission);
        }
        Ok((old, admission.as_ref().clone()))
    }
}
