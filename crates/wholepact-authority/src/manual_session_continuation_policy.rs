//! Complete-history deterministic continuation fold. No projection can erase an
//! old attempt, account exclusion, exposure, exporter key or activation receipt.
use crate::{
    manual_session_continuation::*,
    policy::{Event, Ledger},
    *,
};
impl Ledger {
    pub(crate) fn latest_manual_attempt(&self) -> Result<ManualAttemptObservation> {
        if self.manual_roster_extension()?.is_some() {
            return Err(AuthorityError::Permission);
        }
        let e = &self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let mut latest: Option<&ManualEnrollmentSessionContinuation> = None;
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ContinueManualEnrollmentSession { record },
                ..
            }) = mutation
            {
                record.validate_for(e)?;
                if latest.is_none_or(|old| record.continuation.sequence > old.sequence) {
                    latest = Some(&record.continuation);
                }
            }
        }
        let (sequence, attempt_digest, operation) = match latest {
            Some(c) => (c.sequence, c.digest_for(e)?, c.admission_operation_id(e)?),
            None => (
                1,
                initial_manual_attempt_digest(e)?,
                e.admission_operation_id()?,
            ),
        };
        let admission = match self.operations.get(&operation) {
            None => None,
            Some((_, _, MutationResult::ManualEnrollmentAdmitted(record))) if latest.is_none() => {
                record.validate_for(e)?;
                Some(ManualEnrollmentAdmissionEvidence::First {
                    record: record.as_ref().clone(),
                })
            }
            Some((_, _, MutationResult::ManualEnrollmentAdmittedV2(record)))
                if latest.is_some() =>
            {
                record.validate_for(e, latest.ok_or(AuthorityError::CorruptHistory)?)?;
                Some(ManualEnrollmentAdmissionEvidence::Continued {
                    record: record.as_ref().clone(),
                })
            }
            Some(_) => return Err(AuthorityError::CorruptHistory),
        };
        Ok(ManualAttemptObservation {
            extension_digest: e.digest()?,
            sequence,
            attempt_digest,
            continuation: latest.cloned(),
            snapshot: self.snapshot.clone(),
            admission,
        })
    }
    pub(crate) fn validate_new_manual_continuation(
        &self,
        record: &ManualEnrollmentSessionContinuationRecord,
        now: u64,
    ) -> Result<()> {
        self.require_supported_manual_history()?;
        let previous = self.latest_manual_attempt()?;
        let e = &self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        record.validate_for(e)?;
        let c = &record.continuation;
        if c.sequence
            != previous
                .sequence
                .checked_add(1)
                .ok_or(AuthorityError::Limit)?
            || c.previous_attempt_digest != previous.attempt_digest
            || c.expected_snapshot != self.snapshot
            || c.expected_previous_admission_digest != previous.last_admission_digest(e)?
        {
            return Err(AuthorityError::StaleHead);
        }
        if now < c.issued_at_ms
            || now >= c.initial_commit_deadline_ms
            || previous
                .last_publication_deadline_ms()
                .is_some_and(|deadline| now < deadline)
        {
            return Err(AuthorityError::Expired);
        }
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ContinueManualEnrollmentSession { record: old },
                ..
            }) = mutation
            {
                if old.continuation.attempt_nonce == c.attempt_nonce {
                    return Err(AuthorityError::Conflict);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn apply_manual_admission_v2(
        &self,
        request: &BornManualEnrollmentAdmissionRequestV2,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<BornManualEnrollmentAdmissionRecordV2> {
        self.require_manual_bootstrap_scope(
            &request.extension_digest,
            &event.mutation,
            event.witness_time_ms,
        )?;
        self.fence(&request.expected_head, request.writer_epoch)?;
        let e = &self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let attempt = self.latest_manual_attempt()?;
        let c = attempt
            .continuation
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        let session = self
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if event.writer_session_id.as_deref() != Some(session.session_id.as_str())
            || event.authenticated_certificate_digest != session.writer_certificate_digest
            || request.session_id != session.session_id
        {
            return Err(AuthorityError::SessionRequired);
        }
        let mut snapshot = self.snapshot.clone();
        snapshot.head = next.clone();
        snapshot.last_witness_time_ms = event.witness_time_ms;
        let record = BornManualEnrollmentAdmissionRecordV2 {
            request: request.clone(),
            snapshot,
            session: session.clone(),
            admitted_at_ms: event.witness_time_ms,
            publication_expires_at_ms: event
                .witness_time_ms
                .checked_add(crate::manual_enrollment::MANUAL_ENROLLMENT_PUBLICATION_MS)
                .ok_or(AuthorityError::Limit)?
                .min(e.terms.scope.expires_at_ms)
                .min(session.expires_at_ms),
        };
        record.validate_for(e, c)?;
        Ok(record)
    }
}
