//! Pure event-time replay only. Live native append authority lives elsewhere.
use crate::{durable_payment_v1::*, policy::Ledger, *};

impl Ledger {
    pub(crate) fn durable_payment_admission_v1(
        &self,
        operation: &str,
    ) -> Result<Option<&OwnerControlRequest>> {
        id(operation)?;
        match self.operations.get(operation) {
            None => Ok(None),
            Some((AuthorityMutation::OwnerControl(r), _, MutationResult::Controlled(_)))
                if matches!(r.control, OwnerControl::AdmitDurablePaymentV1 { .. }) =>
            {
                Ok(Some(r))
            }
            Some(_) => Err(AuthorityError::InvalidBinding),
        }
    }
    pub(crate) fn selected_durable_payment_admission_v1(
        &self,
    ) -> Result<Option<&OwnerControlRequest>> {
        let mut selected = None;
        for (m, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(r) = m {
                if matches!(r.control, OwnerControl::AdmitDurablePaymentV1 { .. }) {
                    if selected.replace(r).is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
            }
        }
        Ok(selected)
    }
    /// Full event discriminator, not an empty financial projection. Readable
    /// after expiry; live status and clocks are checked separately.
    pub(crate) fn require_supported_durable_payment_history_v1(&self) -> Result<()> {
        if self.policy.account_use_genesis.is_none() || self.manual_roster_extension()?.is_none() {
            return Err(AuthorityError::PolicyDenied);
        }
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::PolicyDenied)?
            .extension;
        let (_, _, acquired) = self
            .operations
            .get(&e.acquire_operation_id()?)
            .ok_or(AuthorityError::PolicyDenied)?;
        let MutationResult::WriterPending(receipt) = acquired else {
            return Err(AuthorityError::CorruptHistory);
        };
        if !self.activated_sessions.contains(&receipt.session_id) {
            return Err(AuthorityError::PolicyDenied);
        }
        let (_, _, admitted) = self
            .operations
            .get(&e.admission_operation_id()?)
            .ok_or(AuthorityError::PolicyDenied)?;
        let MutationResult::ManualRosterEnrollmentAdmittedV2(original) = admitted else {
            return Err(AuthorityError::CorruptHistory);
        };
        original.validate_for(e, None)?;
        if original.session != *receipt
            || receipt.reconciled_head.sequence != 1
            || receipt.acquired_head.sequence != 2
            || original.request.expected_head.sequence != 3
            || original.snapshot.head.sequence != 4
        {
            return Err(AuthorityError::CorruptHistory);
        }
        for (mutation, _, _) in self.operations.values() {
            match mutation {
                AuthorityMutation::AcquireWriter(_)
                | AuthorityMutation::AdmitBornManualRosterEnrollmentV2(_)
                | AuthorityMutation::ReserveAuthorization(_) => {}
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control:
                        OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                        | OwnerControl::ActivateWriter { .. }
                        | OwnerControl::AdmitDurablePaymentV1 { .. }
                        | OwnerControl::Pause
                        | OwnerControl::Revoke
                        | OwnerControl::PermanentlyExcludeAccount { .. },
                    ..
                }) => {}
                _ => return Err(AuthorityError::PolicyDenied),
            }
        }
        Ok(())
    }
    /// Rejoins the actual immutable row after complete replay. No wall clock.
    pub(crate) fn validate_durable_payment_birth_v1(
        &self,
        birth: Option<&crate::pending_birth::PendingBirthCommitRecord>,
    ) -> Result<()> {
        let Some(r) = self.selected_durable_payment_admission_v1()? else {
            return Ok(());
        };
        let OwnerControl::AdmitDurablePaymentV1 { record } = &r.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let birth = birth.ok_or(AuthorityError::CorruptHistory)?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::CorruptHistory)?
            .extension;
        e.validate_original_birth(birth)?;
        record.terms.validate_original(&self.policy, e)?;
        record.validate_request(r, &birth.request.disclosure)
    }
    pub(crate) fn validate_new_durable_payment_admission_v1(
        &self,
        request: &OwnerControlRequest,
        now: u64,
    ) -> Result<()> {
        let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control else {
            return Err(AuthorityError::Permission);
        };
        self.require_supported_durable_payment_history_v1()?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        record.validate_request_shape(request)?;
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        record.terms.validate_original(&self.policy, e)?;
        self.fence(&request.expected_head, request.writer_epoch)?;
        if request.writer_epoch != self.policy.initial_writer_epoch
            || self.snapshot.writer_certificate_digest != record.terms.writer_certificate_digest
            || self.snapshot.writer_status != WriterStatus::Active
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        record.terms.require_live(now)?;
        if self.selected_durable_payment_admission_v1()?.is_some() {
            return Err(AuthorityError::Conflict);
        }
        let attempt = self.latest_manual_roster_attempt_v2()?;
        if attempt
            .last_publication_deadline_ms()
            .is_some_and(|deadline| now < deadline)
            || now < self.roster_construction_drain_deadline_v2(&attempt.attempt_digest)
            || now < self.roster_construction_drain_deadline_v3(&attempt.attempt_digest)
        {
            return Err(AuthorityError::Expired);
        }
        // The first profile preserves exactly the original four bootstrap
        // events, not an arbitrary earlier financial or continuation history.
        if self.snapshot.head.sequence != 4 || self.operations.len() != 4 {
            return Err(AuthorityError::PolicyDenied);
        }
        self.check_durable_payment_exposure_v1(&record.terms)?;
        if self.authorizations.contains(&record.terms.authorization_id) {
            return Err(AuthorityError::Conflict);
        }
        self.check_input_obligation_exclusions(
            &record.terms.fixed.obligation_id,
            record
                .terms
                .inputs
                .iter()
                .map(|i| (i.input_id.as_str(), i.nullifier.as_str())),
        )?;
        Ok(())
    }
    fn check_durable_payment_exposure_v1(&self, t: &DurablePaymentAdmissionTermsV1) -> Result<()> {
        let e = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        self.check_account_outstanding_limit(t.maximum_debit_zatoshis)?;
        let limit = self
            .policy
            .aggregate_budget_zatoshis
            .min(e.account_extension.terms.scope.aggregate_budget_zatoshis);
        self.snapshot
            .outstanding_debit_zatoshis
            .checked_add(self.snapshot.settled_debit_zatoshis)
            .and_then(|v| v.checked_add(t.maximum_debit_zatoshis))
            .filter(|v| *v <= limit)
            .ok_or(AuthorityError::BudgetExceeded)?;
        Ok(())
    }
    pub(crate) fn require_durable_payment_mutation_v1(
        &self,
        admission_operation_id: &str,
        mutation: &AuthorityMutation,
        writer_session_id: Option<&str>,
        now: u64,
    ) -> Result<()> {
        self.require_supported_durable_payment_history_v1()?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        let admission = self
            .durable_payment_admission_v1(admission_operation_id)?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let t = &record.terms;
        t.require_live(now)?;
        if self.snapshot.writer_epoch != admission.writer_epoch
            || self.snapshot.writer_certificate_digest != t.writer_certificate_digest
            || self.snapshot.writer_status != WriterStatus::Active
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        let acquire_id = record.acquire_operation_id(admission)?;
        let original = match self.operations.get(&acquire_id) {
            Some((
                AuthorityMutation::AcquireWriter(_),
                _,
                MutationResult::WriterPending(receipt),
            )) => Some(receipt),
            Some(_) => return Err(AuthorityError::CorruptHistory),
            None => None,
        };
        match mutation {
            AuthorityMutation::AcquireWriter(r) => {
                let e = &self
                    .manual_roster_extension()?
                    .ok_or(AuthorityError::CorruptHistory)?
                    .extension;
                let (_, _, initial) = self
                    .operations
                    .get(&e.acquire_operation_id()?)
                    .ok_or(AuthorityError::CorruptHistory)?;
                let MutationResult::WriterPending(initial) = initial else {
                    return Err(AuthorityError::CorruptHistory);
                };
                if r.disclosure != initial.disclosure
                    || r.operation_id != acquire_id
                    || r.account_id != t.identity.account_id
                    || r.network_profile_id != t.identity.network_profile_id
                    || r.writer_epoch != admission.writer_epoch
                    || writer_session_id.is_some()
                {
                    return Err(AuthorityError::Permission);
                }
                if let Some(receipt) = original {
                    // Only an exact same-key retry is retained evidence, never a replacement.
                    if receipt.session_id != r.session_id || now >= receipt.expires_at_ms {
                        return Err(AuthorityError::RecoveryRequired);
                    }
                    let (old, _, _) = self
                        .operations
                        .get(&acquire_id)
                        .ok_or(AuthorityError::CorruptHistory)?;
                    if old != mutation {
                        return Err(AuthorityError::Conflict);
                    }
                } else {
                    let (_, _, result) = self
                        .operations
                        .get(admission_operation_id)
                        .ok_or(AuthorityError::CorruptHistory)?;
                    let MutationResult::Controlled(committed) = result else {
                        return Err(AuthorityError::CorruptHistory);
                    };
                    if r.expected_head != committed.head || self.snapshot.head != committed.head {
                        return Err(AuthorityError::StaleHead);
                    }
                }
            }
            AuthorityMutation::OwnerControl(r) => {
                let OwnerControl::ActivateWriter { session_id } = &r.control else {
                    return Err(AuthorityError::Permission);
                };
                let receipt = original.ok_or(AuthorityError::SessionRequired)?;
                if writer_session_id.is_some()
                    || r.account_id != t.identity.account_id
                    || r.network_profile_id != t.identity.network_profile_id
                    || r.writer_epoch != admission.writer_epoch
                    || receipt.session_id != *session_id
                    || now >= receipt.expires_at_ms
                    || r.expected_head != receipt.acquired_head
                {
                    return Err(AuthorityError::RecoveryRequired);
                }
                if self.snapshot.pending_writer_session.as_ref() != Some(receipt)
                    && self.snapshot.active_writer_session.as_ref() != Some(receipt)
                {
                    return Err(AuthorityError::RecoveryRequired);
                }
            }
            AuthorityMutation::ReserveAuthorization(r) => {
                let receipt = original.ok_or(AuthorityError::SessionRequired)?;
                if self.snapshot.active_writer_session.as_ref() != Some(receipt)
                    || writer_session_id != Some(receipt.session_id.as_str())
                    || now >= receipt.expires_at_ms
                {
                    return Err(AuthorityError::RecoveryRequired);
                }
                require_exact_reservation_v1(t, admission.writer_epoch, r)?;
                let e = &self
                    .manual_roster_extension()?
                    .ok_or(AuthorityError::Permission)?
                    .extension;
                if r.reviewed_at_ms < receipt.acquired_at_ms
                    || r.reviewed_at_ms < t.valid_from_ms
                    || now < r.reviewed_at_ms
                    || now >= r.permit_expires_at_ms
                    || r.permit_expires_at_ms > t.valid_until_ms
                    || r.permit_expires_at_ms > receipt.expires_at_ms
                    || r.permit_expires_at_ms - r.reviewed_at_ms
                        > e.account_extension.terms.scope.maximum_permit_lifetime_ms
                {
                    return Err(AuthorityError::Expired);
                }
                // Exact retained results have already charged common exposure.
                if !self.operations.contains_key(&r.operation_id) {
                    self.check_durable_payment_exposure_v1(t)?;
                }
            }
            _ => return Err(AuthorityError::Permission),
        }
        Ok(())
    }
    /// Record-derived fences are independent of construction transport fences.
    pub(crate) fn require_unfenced_durable_payment_session_v1(&self, session: &str) -> Result<()> {
        if let Some(admission) = self.selected_durable_payment_admission_v1()? {
            let receipt = self
                .sessions
                .get(session)
                .ok_or(AuthorityError::SessionRequired)?;
            if receipt.acquired_head.sequence <= admission.expected_head.sequence {
                return Err(AuthorityError::RecoveryRequired);
            }
        }
        Ok(())
    }
}
pub(crate) fn require_exact_reservation_v1(
    t: &DurablePaymentAdmissionTermsV1,
    epoch: u64,
    r: &ReserveAuthorization,
) -> Result<()> {
    r.validate()?;
    let f = &t.fixed;
    if r.automation.is_some()
        || r.operation_id != t.authorization_id
        || r.authorization_id != t.authorization_id
        || r.account_id != t.identity.account_id
        || r.network_profile_id != t.identity.network_profile_id
        || r.writer_epoch != epoch
        || r.enrollment_ref != t.original_enrollment_ref
        || r.agreement_id != f.agreement_id
        || r.obligation_id != f.obligation_id
        || r.proposal_id != f.proposal_id
        || r.proposal_digest != f.proposal_digest
        || r.manifest_digest != f.manifest_digest
        || r.effects_digest != f.effects_commitment
        || r.artifact_digest != f.proved_artifact_digest
        || r.review_binding != f.review_binding
        || r.recipient_scope_digest != t.recipient_policy_scope_digest
        || r.inputs != t.inputs
        || r.maximum_debit_zatoshis != t.maximum_debit_zatoshis
        || r.fee_share_zatoshis != t.fee_share_zatoshis
        || r.transaction_fee_zatoshis != t.transaction_fee_zatoshis
        || r.transaction_expiry_height != f.expiry_height
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
