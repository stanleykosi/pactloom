//! Deterministic replay for the bounded first manual-enrollment extension.
use crate::manual_enrollment::*;
use crate::policy::{Event, Ledger};
use crate::*;

impl Ledger {
    pub(crate) fn manual_extension(&self) -> Result<Option<&ManualEnrollmentExtensionRecord>> {
        let mut selected = None;
        for (mutation, _, _) in self.operations.values() {
            let record = match mutation {
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::ExtendManualEnrollment { record },
                    ..
                }) => Some(record.as_ref()),
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::ExtendManualRosterEnrollmentV2 { record },
                    ..
                }) => {
                    record.validate()?;
                    Some(&record.account_record)
                }
                _ => None,
            };
            if let Some(record) = record {
                if selected.is_some() {
                    return Err(AuthorityError::CorruptHistory);
                }
                selected = Some(record);
            }
        }
        Ok(selected)
    }
    pub(crate) fn validate_manual_birth(
        &self,
        birth: Option<&crate::pending_birth::PendingBirthCommitRecord>,
    ) -> Result<()> {
        if let Some(record) = self.manual_roster_extension()? {
            record
                .extension
                .validate_original_birth(birth.ok_or(AuthorityError::CorruptHistory)?)?;
        }
        if let Some(record) = self.manual_extension()? {
            record
                .extension
                .validate_original_birth(birth.ok_or(AuthorityError::CorruptHistory)?)?;
        }
        Ok(())
    }
    pub(crate) fn require_supported_manual_history(&self) -> Result<()> {
        self.account_use_history
            .require_not_permanently_excluded()?;
        if self.policy.account_use_genesis.is_none() {
            return Err(AuthorityError::PolicyDenied);
        }
        // No empty projection of a used, offline, automated, resolved, replaced
        // or recovered history. All actual lifetime exposure remains unchanged.
        for (mutation, _, _) in self.operations.values() {
            match mutation {
                AuthorityMutation::ClaimConstructionTransportV1(_)
                | AuthorityMutation::UseConstructionTransportV1(_)
                | AuthorityMutation::AcquireWriter(_)
                | AuthorityMutation::ReserveManualRosterConstructionV3(_)
                | AuthorityMutation::ReserveManualRosterConstructionV2(_)
                | AuthorityMutation::ConsumeManualRosterConstructionV3(_)
                | AuthorityMutation::ConsumeManualRosterConstructionV2(_)
                | AuthorityMutation::AdmitBornManualEnrollment(_)
                | AuthorityMutation::AdmitBornManualEnrollmentV2(_)
                | AuthorityMutation::AdmitBornManualRosterEnrollmentV2(_) => {}
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control:
                        OwnerControl::GrantConstructionTransportV1 { .. }
                        | OwnerControl::ExtendManualEnrollment { .. }
                        | OwnerControl::ApproveManualRosterConstructionV3 { .. }
                        | OwnerControl::ApproveManualRosterConstructionV2 { .. }
                        | OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                        | OwnerControl::ContinueManualRosterSessionV2 { .. }
                        | OwnerControl::ContinueManualEnrollmentSession { .. }
                        | OwnerControl::ActivateWriter { .. },
                    ..
                }) => {}
                _ => return Err(AuthorityError::OfflineHistoryUnsupported),
            }
        }
        if self.snapshot.writer_epoch != self.policy.initial_writer_epoch
            || self.snapshot.writer_certificate_digest
                != self.policy.initial_writer_certificate_digest
            || self.snapshot.writer_status != WriterStatus::Active
        {
            return Err(AuthorityError::Inactive);
        }
        Ok(())
    }
    pub(crate) fn validate_new_manual_extension(
        &self,
        r: &ManualEnrollmentExtensionRecord,
        now: u64,
    ) -> Result<()> {
        r.validate()?;
        r.extension.validate_original_policy(&self.policy)?;
        self.require_supported_manual_history()?;
        if !self.operations.is_empty()
            || self.manual_extension()?.is_some()
            || self.snapshot.head.sequence != 0
            || self.snapshot.pending_writer_session.is_some()
            || self.snapshot.active_writer_session.is_some()
        {
            return Err(AuthorityError::Conflict);
        }
        if now < r.extension.terms.issued_at_ms || now >= r.extension.terms.scope.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
    /// Namespace admission selection is rechecked before all bootstrap mutations
    /// and exact retries. The actual namespace owner is checked by the caller.
    pub(crate) fn require_manual_bootstrap_scope(
        &self,
        selected: &str,
        mutation: &AuthorityMutation,
        now: u64,
    ) -> Result<()> {
        if self.manual_roster_extension()?.is_some() {
            return Err(AuthorityError::Permission);
        }
        self.require_supported_manual_history()?;
        let e = &self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        e.validate_original_policy(&self.policy)?;
        if e.digest()? != selected {
            return Err(AuthorityError::Permission);
        }
        if now < e.terms.issued_at_ms || now >= e.terms.scope.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        let attempt = self.latest_manual_attempt()?;
        match mutation {
            AuthorityMutation::AcquireWriter(r) => {
                if r.operation_id != attempt.acquire_operation_id(e)?
                    || r.account_id != e.terms.identity.account_id
                    || r.network_profile_id != e.terms.identity.network_profile_id
                    || r.writer_epoch != e.terms.signer.writer_epoch
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
                    .get(&attempt.acquire_operation_id(e)?)
                    .ok_or(AuthorityError::SessionRequired)?;
                let MutationResult::WriterPending(receipt) = result else {
                    return Err(AuthorityError::CorruptHistory);
                };
                if receipt.session_id != *session_id || now >= receipt.expires_at_ms {
                    return Err(AuthorityError::SessionRequired);
                }
            }
            AuthorityMutation::AdmitBornManualEnrollment(r) => {
                if attempt.sequence != 1 {
                    return Err(AuthorityError::Permission);
                }
                r.validate_for(e)?;
                let active = self
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .ok_or(AuthorityError::SessionRequired)?;
                if active.session_id != r.session_id || now >= active.expires_at_ms {
                    return Err(AuthorityError::SessionRequired);
                }
                if let Some((_, _, result)) = self.operations.get(&r.operation_id) {
                    let MutationResult::ManualEnrollmentAdmitted(record) = result else {
                        return Err(AuthorityError::Conflict);
                    };
                    record.validate_for(e)?;
                    if now < record.admitted_at_ms || now >= record.publication_expires_at_ms {
                        return Err(AuthorityError::Expired);
                    }
                    if self.snapshot.head != record.snapshot.head {
                        return Err(AuthorityError::StaleHead);
                    }
                }
            }
            AuthorityMutation::AdmitBornManualEnrollmentV2(r) => {
                let c = attempt
                    .continuation
                    .as_ref()
                    .ok_or(AuthorityError::Permission)?;
                r.validate_for(e, c)?;
                let active = self
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .ok_or(AuthorityError::SessionRequired)?;
                if active.session_id != r.session_id || now >= active.expires_at_ms {
                    return Err(AuthorityError::SessionRequired);
                }
                if let Some((_, _, result)) = self.operations.get(&r.operation_id) {
                    let MutationResult::ManualEnrollmentAdmittedV2(record) = result else {
                        return Err(AuthorityError::Conflict);
                    };
                    record.validate_for(e, c)?;
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
    pub(crate) fn apply_manual_admission(
        &self,
        request: &BornManualEnrollmentAdmissionRequest,
        event: &Event,
        next: &AuthorityHead,
    ) -> Result<BornManualEnrollmentAdmissionRecord> {
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
        let deadline = event
            .witness_time_ms
            .checked_add(MANUAL_ENROLLMENT_PUBLICATION_MS)
            .ok_or(AuthorityError::Limit)?
            .min(e.terms.scope.expires_at_ms)
            .min(session.expires_at_ms);
        let mut snapshot = self.snapshot.clone();
        snapshot.head = next.clone();
        snapshot.last_witness_time_ms = event.witness_time_ms;
        let record = BornManualEnrollmentAdmissionRecord {
            request: request.clone(),
            snapshot,
            session: session.clone(),
            admitted_at_ms: event.witness_time_ms,
            publication_expires_at_ms: deadline,
        };
        record.validate_for(e)?;
        Ok(record)
    }
}
