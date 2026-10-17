//! Native-original journal owner only, never the generic mutation boundary.
use super::*;
use crate::{born_offline_dispatch_v1::*, offline_witness_v1::CurrentOfflineWitnessWindowV1};
impl AuthorityJournal {
    pub(crate) fn commit_born_dispatch_v1(
        &self,
        peer: &str,
        request: &BornOfflineDispatchRequestV1,
        authentication: &crate::born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1,
        exporter: &[u8; 32],
        server: &str,
        current: &CurrentOfflineWitnessWindowV1,
    ) -> Result<BornOfflineDispatchAdmissionV1> {
        self.require_born_artifact_owner_current_v1()?;
        request.validate()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        verify_born_artifact_schema_v1(&tx)?;
        authenticate_admission(&tx, peer)?;
        let mut ledger = load(&tx)?;
        ledger.validate_born_dispatch_current_v1(request, peer, current.check()?)?;
        let enrollment = ledger.require_born_offline_original_session_v1(current.check()?)?;
        let session = &enrollment.original_writer_session;
        if server != enrollment.policy.witness_certificate_digest
            || server != session.disclosure.pinned_server_certificate_digest
        {
            return Err(AuthorityError::Authentication);
        }
        let mutation = AuthorityMutation::AuthorizeBornOfflineDispatchV1(Box::new(request.clone()));
        if let Some(proof) = authentication.select_original_proof(enrollment, peer)? {
            let key = read_session_key(&tx, &proof.session_id)?;
            crate::session::verify(&key, session, exporter, &mutation, proof)?;
        }
        let event = Event {
            mutation,
            authenticated_certificate_digest: peer.into(),
            witness_time_ms: current.check()?,
            writer_session_id: enrollment.born_event_writer_session_v1(),
            original_request_link: None,
        };
        if let Some(result) = ledger.replay(&event)? {
            let MutationResult::BornOfflineDispatchAdmittedV1(admission) = result else {
                return Err(AuthorityError::CorruptHistory);
            };
            self.require_born_artifact_owner_current_v1()?;
            ledger.validate_born_dispatch_current_v1(request, peer, current.check()?)?;
            return Ok(*admission);
        }
        let previous = ledger.snapshot.head.digest.clone();
        let MutationResult::BornOfflineDispatchAdmittedV1(admission) = ledger.apply(&event)? else {
            return Err(AuthorityError::CorruptHistory);
        };
        let payload = encode(&event)?;
        let total: u64 = tx.query_row(
            "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
            [],
            |r| r.get(0),
        )?;
        if total
            .checked_add(payload.len() as u64)
            .filter(|n| *n <= MAX_JOURNAL_BYTES)
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
        // Recheck after every potentially blocking DB operation, before the only
        // publication point. An uncertain commit permanently keeps this exact
        // request; a fresh native-reviewed observation may only dispatch the
        // identical final transaction to the same original disclosed backend.
        self.require_born_artifact_owner_current_v1()?;
        ledger.validate_born_dispatch_current_v1(request, peer, current.check()?)?;
        // Validation itself is bounded but still consumes time. Sample again
        // immediately before the irreversible commit, not only before validation.
        self.require_born_artifact_owner_current_v1()?;
        current.check()?;
        tx.commit().map_err(|_| AuthorityError::Uncertain)?;
        current.check().map_err(|_| AuthorityError::Uncertain)?;
        Ok(*admission)
    }
}
