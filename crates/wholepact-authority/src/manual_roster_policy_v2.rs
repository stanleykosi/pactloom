//! Deterministic V2 roster replay; the same original account ledger and exposure
//! remain authoritative. Host roster membership is a separate immutable binding.
use crate::{
    manual_roster_witness_v2::*,
    policy::{Event, Ledger},
    *,
};
impl Ledger {
    pub(crate) fn manual_roster_extension(
        &self,
    ) -> Result<Option<&ManualRosterEnrollmentExtensionRecordV2>> {
        let mut selected = None;
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ExtendManualRosterEnrollmentV2 { record },
                ..
            }) = mutation
            {
                record.validate()?;
                if selected.is_some() {
                    return Err(AuthorityError::CorruptHistory);
                }
                selected = Some(record.as_ref());
            }
        }
        Ok(selected)
    }
    pub(crate) fn validate_new_manual_roster_extension(
        &self,
        r: &ManualRosterEnrollmentExtensionRecordV2,
        now: u64,
    ) -> Result<()> {
        r.validate()?;
        r.extension.validate_original_policy(&self.policy)?;
        // Exact original first-extension guard, including empty history/head and
        // absence of existing/pending sessions. This does not widen an account.
        self.validate_new_manual_extension(&r.account_record, now)
    }
    pub(crate) fn latest_manual_roster_attempt_v2(
        &self,
    ) -> Result<ManualRosterAttemptObservationV2> {
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let mut latest: Option<&ManualRosterSessionContinuationV2> = None;
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ContinueManualRosterSessionV2 { record },
                ..
            }) = mutation
            {
                record.validate_for(e)?;
                if latest.is_none_or(|old| record.continuation.sequence() > old.sequence()) {
                    latest = Some(&record.continuation);
                }
            }
        }
        let (sequence, attempt_digest, operation) = match latest {
            Some(c) => (c.sequence(), c.digest_for(e)?, c.admission_operation_id(e)?),
            None => (
                1,
                initial_manual_roster_attempt_digest_v2(e)?,
                e.admission_operation_id()?,
            ),
        };
        let admission = match self.operations.get(&operation) {
            None => None,
            Some((_, _, MutationResult::ManualRosterEnrollmentAdmittedV2(r))) => {
                r.validate_for(e, latest)?;
                Some(r.as_ref().clone())
            }
            Some(_) => return Err(AuthorityError::CorruptHistory),
        };
        Ok(ManualRosterAttemptObservationV2 {
            extension_digest: e.digest()?,
            sequence,
            attempt_digest,
            continuation: latest.cloned(),
            snapshot: self.snapshot.clone(),
            admission,
        })
    }
    pub(crate) fn validate_new_manual_roster_continuation_v2(
        &self,
        record: &ManualRosterSessionContinuationRecordV2,
        now: u64,
    ) -> Result<()> {
        self.require_supported_manual_history()?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        record.validate_for(e)?;
        let previous = self.latest_manual_roster_attempt_v2()?;
        let c = record.continuation.inner();
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
            || now < self.roster_construction_drain_deadline_v2(&previous.attempt_digest)
            || now < self.roster_construction_drain_deadline_v3(&previous.attempt_digest)
            || now >= c.initial_commit_deadline_ms
            || previous
                .last_publication_deadline_ms()
                .is_some_and(|deadline| now < deadline)
        {
            return Err(AuthorityError::Expired);
        }
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ContinueManualRosterSessionV2 { record: old },
                ..
            }) = mutation
            {
                if old.continuation.inner().attempt_nonce == c.attempt_nonce {
                    return Err(AuthorityError::Conflict);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn require_manual_roster_bootstrap_scope_v2(
        &self,
        selected: &str,
        mutation: &AuthorityMutation,
        now: u64,
    ) -> Result<()> {
        self.require_supported_manual_history()?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        e.validate_original_policy(&self.policy)?;
        let inner = &e.account_extension;
        if selected != e.digest()? {
            return Err(AuthorityError::Permission);
        }
        if now < inner.terms.issued_at_ms || now >= inner.terms.scope.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        let a = self.latest_manual_roster_attempt_v2()?;
        match mutation {
            AuthorityMutation::ReserveManualRosterConstructionV3(_)
            | AuthorityMutation::ConsumeManualRosterConstructionV3(_) => {
                self.require_roster_construction_scope_v3(mutation, now)?;
            }
            AuthorityMutation::ReserveManualRosterConstructionV2(_)
            | AuthorityMutation::ConsumeManualRosterConstructionV2(_) => {
                self.require_roster_construction_scope_v2(mutation, now)?;
            }
            AuthorityMutation::AcquireWriter(r) => {
                if r.operation_id != a.acquire_operation_id(e)?
                    || r.account_id != inner.terms.identity.account_id
                    || r.network_profile_id != inner.terms.identity.network_profile_id
                    || r.writer_epoch != inner.terms.signer.writer_epoch
                {
                    return Err(AuthorityError::Permission);
                }
            }
            AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::ActivateWriter { session_id },
                ..
            }) => {
                let (_, _, result) = self
                    .operations
                    .get(&a.acquire_operation_id(e)?)
                    .ok_or(AuthorityError::SessionRequired)?;
                let MutationResult::WriterPending(receipt) = result else {
                    return Err(AuthorityError::CorruptHistory);
                };
                if receipt.session_id != *session_id || now >= receipt.expires_at_ms {
                    return Err(AuthorityError::SessionRequired);
                }
            }
            AuthorityMutation::AdmitBornManualRosterEnrollmentV2(r) => {
                r.validate_for(e, a.continuation.as_ref())?;
                let active = self
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .ok_or(AuthorityError::SessionRequired)?;
                if active.session_id != r.session_id || now >= active.expires_at_ms {
                    return Err(AuthorityError::SessionRequired);
                }
                if let Some((_, _, result)) = self.operations.get(&r.operation_id) {
                    let MutationResult::ManualRosterEnrollmentAdmittedV2(record) = result else {
                        return Err(AuthorityError::Conflict);
                    };
                    record.validate_for(e, a.continuation.as_ref())?;
                    if now < record.admitted_at_ms || now >= record.publication_expires_at_ms {
                        return Err(AuthorityError::Expired);
                    }
                    if self.snapshot.head != record.snapshot.head {
                        return Err(AuthorityError::StaleHead);
                    }
                }
            }
            _ => return Err(AuthorityError::Permission),
        }
        Ok(())
    }
    pub(crate) fn apply_manual_roster_admission_v2(
        &self,
        request: &BornManualRosterAdmissionRequestV2,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<BornManualRosterAdmissionRecordV2> {
        self.require_manual_roster_bootstrap_scope_v2(
            &request.extension_digest,
            &event.mutation,
            event.witness_time_ms,
        )?;
        self.fence(&request.expected_head, request.writer_epoch)?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let a = self.latest_manual_roster_attempt_v2()?;
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
        let record = BornManualRosterAdmissionRecordV2 {
            request: request.clone(),
            snapshot,
            session: session.clone(),
            admitted_at_ms: event.witness_time_ms,
            publication_expires_at_ms: event
                .witness_time_ms
                .checked_add(crate::manual_enrollment::MANUAL_ENROLLMENT_PUBLICATION_MS)
                .ok_or(AuthorityError::Limit)?
                .min(e.account_extension.terms.scope.expires_at_ms)
                .min(session.expires_at_ms),
        };
        record.validate_for(e, a.continuation.as_ref())?;
        Ok(record)
    }
}
