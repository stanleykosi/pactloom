//! Authenticated online construction transport. Public evidence cannot construct
//! either live wrapper; actual mTLS plus the current session MAC and exact
//! committed append are checked before returning a bounded one-use owner.
use super::*;
use crate::{
    manual_roster_construction_v3::*,
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
};
impl AuthorityClient {
    pub fn reserve_manual_roster_construction_v3(
        &self,
        history: &ReconciledAuthorityHistory,
        extension: &ManualRosterEnrollmentExtensionV2,
        continuation: &ManualRosterSessionContinuationV2,
        request: &ManualRosterConstructionReservationRequestV3,
    ) -> Result<AuthenticatedManualRosterConstructionReservationV3> {
        if !history.offline_permits.is_empty() || !history.born_offline_permits.is_empty() {
            return Err(AuthorityError::OfflineHistoryUnsupported);
        }
        if !history.permits.is_empty() || !history.automatic_key_use_admissions.is_empty() {
            return Err(AuthorityError::PolicyDenied);
        }
        history
            .account_use_history
            .require_not_permanently_excluded()?;
        extension.validate_original_birth(
            history
                .pending_birth_commit()
                .ok_or(AuthorityError::PolicyDenied)?,
        )?;
        extension.validate_original_policy(history.account_policy())?;
        request.validate_for(extension, continuation)?;
        history
            .snapshot
            .require_unfenced_transport(&request.session_id)?;
        let attempt =
            history.latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)?;
        if attempt.continuation.as_ref() != Some(continuation)
            || attempt.attempt_digest != request.attempt_digest
            || attempt.sequence != request.attempt_sequence
        {
            return Err(AuthorityError::StaleHead);
        }
        if history.disclosure != self.disclosure_descriptor()
            || history
                .manual_roster_enrollment_extension(&extension.account_extension.enrollment_ref)?
                != Some(extension)
            || history.snapshot.head != request.expected_head
            || history.snapshot.writer_status != WriterStatus::Active
            || history.snapshot.writer_epoch != request.writer_epoch
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        let approved = history
            .manual_roster_construction_approval_v3(&request.invocation_digest()?)?
            .ok_or(AuthorityError::Permission)?;
        approved.matches_request(&request.construction, extension)?;
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        let observed = std::time::Instant::now();
        let observed_at_ms = now_ms()?;
        if receipt.session_id != request.session_id
            || history.snapshot.active_writer_session.as_ref() != Some(receipt)
            || crate::session::session_id(&session.key) != request.session_id
            || observed_at_ms < request.reviewed_at_ms
            || observed_at_ms >= receipt.expires_at_ms
            || observed_at_ms >= request.construction.admission_expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let mutation =
            AuthorityMutation::ReserveManualRosterConstructionV3(Box::new(request.clone()));
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::ManualRosterConstructionReservedV3(record)) =
            response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        record.validate_for(extension, continuation)?;
        if record.request != *request || record.session != *receipt {
            return Err(AuthorityError::Authentication);
        }
        self.check_snapshot(&record.snapshot)?;
        let mut expected = history.snapshot.clone();
        expected.head = record.snapshot.head.clone();
        expected.last_witness_time_ms = record.admitted_at_ms;
        expected.outstanding_debit_zatoshis = expected
            .outstanding_debit_zatoshis
            .checked_add(record.reserved_debit_zatoshis)
            .ok_or(AuthorityError::Limit)?;
        expected.reserved_input_value_zatoshis = expected
            .reserved_input_value_zatoshis
            .checked_add(record.reserved_input_value_zatoshis)
            .ok_or(AuthorityError::Limit)?;
        expected.outstanding_reservations = expected
            .outstanding_reservations
            .checked_add(1)
            .ok_or(AuthorityError::Limit)?;
        if record.snapshot != expected {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &record.snapshot.head,
            AuthorityMutation::ReserveManualRosterConstructionV3(Box::new(request.clone())),
            record.admitted_at_ms,
            Some(request.session_id.clone()),
        )?;
        let result = AuthenticatedManualRosterConstructionReservationV3 {
            extension: extension.clone(),
            continuation: continuation.clone(),
            record: *record,
            observed,
            observed_at_ms,
        };
        result.check_current()?;
        Ok(result)
    }
    /// Moves the real reservation. Any failure/uncertain response loses this
    /// local handle. The server refuses Consume replay; reads remain audit-only.
    pub fn consume_manual_roster_construction_v3(
        &self,
        reservation: AuthenticatedManualRosterConstructionReservationV3,
        request: &ManualRosterConstructionConsumeRequestV3,
    ) -> Result<AuthenticatedManualRosterConstructionContributionV3> {
        reservation.check_current()?;
        request.validate_for(
            &reservation.record,
            &reservation.extension,
            &reservation.continuation,
        )?;
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if *receipt != reservation.record.session
            || request.session_id != receipt.session_id
            || crate::session::session_id(&session.key) != request.session_id
            || now_ms()? >= receipt.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let mutation = AuthorityMutation::ConsumeManualRosterConstructionV3(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::ManualRosterConstructionConsumedV3(consumed)) =
            response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        if consumed.request != *request {
            return Err(AuthorityError::Authentication);
        }
        consumed.validate_for(
            &reservation.record,
            &reservation.extension,
            &reservation.continuation,
        )?;
        self.check_snapshot(&consumed.snapshot)?;
        self.check_committed_head(
            &request.expected_head,
            &consumed.snapshot.head,
            AuthorityMutation::ConsumeManualRosterConstructionV3(request.clone()),
            consumed.consumed_at_ms,
            Some(request.session_id.clone()),
        )?;
        let result = AuthenticatedManualRosterConstructionContributionV3 {
            reservation,
            consumed: *consumed,
        };
        result.check_current()?;
        Ok(result)
    }
}
