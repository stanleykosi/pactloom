//! Pure complete-history checks. Live native authority is deliberately separate.
use crate::{policy::Ledger, *};
impl Ledger {
    pub(crate) fn selected_durable_delivery_admission_v2(
        &self,
    ) -> Result<Option<&OwnerControlRequest>> {
        let mut selected = None;
        for (mutation, _, result) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(request) = mutation {
                if matches!(
                    request.control,
                    OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. }
                ) {
                    if !matches!(result, MutationResult::Controlled(_))
                        || selected.replace(request).is_some()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
            }
        }
        Ok(selected)
    }
    /// Deny-only gate. In live paths call immediately after complete load and
    /// before replay, receipt lookup, key selection or MAC verification. Ordered
    /// immutable replay encounters the four bootstrap events before v2 exists.
    pub(crate) fn require_delivery_admission_only_v2(
        &self,
        mutation: &AuthorityMutation,
    ) -> Result<()> {
        if self.selected_durable_delivery_admission_v2()?.is_some()
            && !matches!(
                mutation,
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::Pause
                        | OwnerControl::Revoke
                        | OwnerControl::PermanentlyExcludeAccount { .. },
                    ..
                })
            )
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    pub(crate) fn validate_new_durable_delivery_admission_v2(
        &self,
        request: &OwnerControlRequest,
        now: u64,
    ) -> Result<()> {
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            return Err(AuthorityError::Permission);
        };
        // Before admission the unchanged v1 validator is a pure complete
        // bootstrap verifier, not a v1 financial source or admission conversion.
        self.require_supported_durable_payment_history_v1()?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        record.validate_request_shape(request)?;
        let extension = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        record.validate_original(&self.policy, extension)?;
        self.fence(&request.expected_head, request.writer_epoch)?;
        if request.writer_epoch != self.policy.initial_writer_epoch
            || self.snapshot.writer_certificate_digest
                != record.scope.authorization.writer_certificate_digest
            || self.snapshot.writer_status != WriterStatus::Active
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        record.require_live(now)?;
        if self.selected_durable_payment_admission_v1()?.is_some()
            || self.selected_durable_delivery_admission_v2()?.is_some()
        {
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
        if self.snapshot.head.sequence != 4 || self.operations.len() != 4 {
            return Err(AuthorityError::PolicyDenied);
        }
        let authorization = &record.scope.authorization;
        self.check_account_outstanding_limit(authorization.maximum_debit_zatoshis)?;
        if self
            .snapshot
            .outstanding_debit_zatoshis
            .checked_add(self.snapshot.settled_debit_zatoshis)
            .and_then(|value| value.checked_add(authorization.maximum_debit_zatoshis))
            .filter(|value| {
                *value
                    <= self.policy.aggregate_budget_zatoshis.min(
                        extension
                            .account_extension
                            .terms
                            .scope
                            .aggregate_budget_zatoshis,
                    )
            })
            .is_none()
        {
            return Err(AuthorityError::BudgetExceeded);
        }
        if self
            .authorizations
            .contains(&authorization.authorization_id)
        {
            return Err(AuthorityError::Conflict);
        }
        self.check_input_obligation_exclusions(
            &authorization.fixed.obligation_id,
            authorization
                .inputs
                .iter()
                .map(|input| (input.input_id.as_str(), input.nullifier.as_str())),
        )?;
        Ok(())
    }
    /// Rejoin original immutable birth after complete replay, independently at
    /// every storage and authenticated transport history reconstruction boundary.
    pub(crate) fn validate_durable_delivery_birth_v2(
        &self,
        birth: Option<&crate::pending_birth::PendingBirthCommitRecord>,
    ) -> Result<()> {
        let Some(request) = self.selected_durable_delivery_admission_v2()? else {
            return Ok(());
        };
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let birth = birth.ok_or(AuthorityError::CorruptHistory)?;
        let extension = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::CorruptHistory)?
            .extension;
        extension.validate_original_birth(birth)?;
        record.validate_original(&self.policy, extension)?;
        record.validate_request(request, &birth.request.disclosure)?;
        let (_, _, acquired) = self
            .operations
            .get(&extension.acquire_operation_id()?)
            .ok_or(AuthorityError::CorruptHistory)?;
        let MutationResult::WriterPending(receipt) = acquired else {
            return Err(AuthorityError::CorruptHistory);
        };
        let (_, _, admitted) = self
            .operations
            .get(&extension.admission_operation_id()?)
            .ok_or(AuthorityError::CorruptHistory)?;
        let MutationResult::ManualRosterEnrollmentAdmittedV2(original) = admitted else {
            return Err(AuthorityError::CorruptHistory);
        };
        original.validate_for(extension, None)?;
        if original.session != *receipt
            || !self.activated_sessions.contains(&receipt.session_id)
            || receipt.reconciled_head.sequence != 1
            || receipt.acquired_head.sequence != 2
            || original.request.expected_head.sequence != 3
            || original.snapshot.head != request.expected_head
            || self.snapshot.writer_epoch != record.scope.original_writer_epoch
            || self.snapshot.writer_certificate_digest
                != record.scope.authorization.writer_certificate_digest
        {
            return Err(AuthorityError::CorruptHistory);
        }
        // No acceptance expansion of the old v1 supported-history predicate.
        // Every post-bootstrap event is admission or a monotone restriction.
        for (mutation, _, _) in self.operations.values() {
            match mutation {
                AuthorityMutation::AcquireWriter(r)
                    if r.operation_id == extension.acquire_operation_id()? => {}
                AuthorityMutation::AdmitBornManualRosterEnrollmentV2(r)
                    if r.operation_id == extension.admission_operation_id()? => {}
                AuthorityMutation::OwnerControl(r) => match &r.control {
                    OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                        if r.expected_head.sequence == 0 => {}
                    OwnerControl::ActivateWriter { session_id }
                        if r.expected_head.sequence == 2 && *session_id == receipt.session_id => {}
                    OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. } if r == request => {}
                    OwnerControl::Pause
                    | OwnerControl::Revoke
                    | OwnerControl::PermanentlyExcludeAccount { .. }
                        if r.expected_head.sequence >= 5 => {}
                    _ => return Err(AuthorityError::CorruptHistory),
                },
                _ => return Err(AuthorityError::CorruptHistory),
            }
        }
        Ok(())
    }
}
