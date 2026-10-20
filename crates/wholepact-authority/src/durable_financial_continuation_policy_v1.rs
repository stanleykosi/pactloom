//! Strict new financial profile; no widening of legacy V1 or admission-only V2.
use crate::{
    policy::{Event, Ledger},
    *,
};
impl Ledger {
    pub(crate) fn financial_continuation_v1(
        &self,
        operation: &str,
    ) -> Result<Option<&OwnerControlRequest>> {
        id(operation)?;
        match self.operations.get(operation) {
            None => Ok(None),
            Some((AuthorityMutation::OwnerControl(r), _, MutationResult::Controlled(_)))
                if matches!(r.control, OwnerControl::AdmitFinancialContinuationV1 { .. }) =>
            {
                Ok(Some(r))
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    pub(crate) fn selected_financial_continuation_v1(
        &self,
    ) -> Result<Option<&OwnerControlRequest>> {
        let mut found = None;
        for (mutation, _, result) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(r) = mutation {
                if matches!(r.control, OwnerControl::AdmitFinancialContinuationV1 { .. }) {
                    if !matches!(result, MutationResult::Controlled(_))
                        || found.replace(r).is_some()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
            }
        }
        Ok(found)
    }
    pub(crate) fn require_financial_continuation_history_v1(&self) -> Result<()> {
        let admission = self
            .selected_financial_continuation_v1()?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        record.validate_request(admission, &record.terms.scope.witness)?;
        let original = self
            .selected_durable_delivery_admission_v2()?
            .ok_or(AuthorityError::CorruptHistory)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record: delivery } =
            &original.control
        else {
            return Err(AuthorityError::CorruptHistory);
        };
        if original.operation_id != record.terms.original_delivery_operation_id
            || delivery.scope != record.terms.scope
            || crate::durable_financial_continuation_v1::original_delivery_request_digest_v1(
                original,
            )? != record.terms.original_delivery_request_digest
        {
            return Err(AuthorityError::CorruptHistory);
        }
        let (_, _, result) = self
            .operations
            .get(&original.operation_id)
            .ok_or(AuthorityError::CorruptHistory)?;
        if !matches!(result, MutationResult::Controlled(snapshot) if snapshot.head == record.terms.original_delivery_committed_head)
        {
            return Err(AuthorityError::CorruptHistory);
        }
        let extension = &self
            .manual_roster_extension()?
            .ok_or(AuthorityError::CorruptHistory)?
            .extension;
        let acquire = record.acquire_operation_id(admission)?;
        for (mutation, _, _) in self.operations.values() {
            match mutation {
                AuthorityMutation::AcquireWriter(r)
                    if r.operation_id == extension.acquire_operation_id()?
                        || r.operation_id == acquire => {}
                AuthorityMutation::AdmitBornManualRosterEnrollmentV2(r)
                    if r.operation_id == extension.admission_operation_id()? => {}
                AuthorityMutation::AuthorizeCompletedDispatchV1(r)
                    if r.context.owners.iter().any(|owner| {
                        owner.account_id == self.policy.account_id
                            && owner.continuation_operation_id == admission.operation_id
                    }) => {}
                AuthorityMutation::ReserveAuthorization(r) => {
                    crate::durable_payment_policy_v1::require_exact_reservation_v1(
                        &record.terms.scope.authorization,
                        admission.writer_epoch,
                        r,
                    )?
                }
                AuthorityMutation::OwnerControl(r) => match &r.control {
                    OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                        if r.expected_head.sequence == 0 => {}
                    OwnerControl::ActivateWriter { session_id }
                        if r.expected_head.sequence == 2
                            || (r.expected_head.sequence == 7
                                && self.sessions.get(session_id).is_some_and(|receipt| {
                                    receipt.acquired_head == r.expected_head
                                })) => {}
                    OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. } if r == original => {}
                    OwnerControl::AdmitFinancialContinuationV1 { .. } if r == admission => {}
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
    pub(crate) fn validate_new_financial_continuation_v1(
        &self,
        request: &OwnerControlRequest,
        now: u64,
    ) -> Result<()> {
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate_request(request, &record.terms.scope.witness)?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        self.fence(&request.expected_head, request.writer_epoch)?;
        if self.snapshot.writer_status != WriterStatus::Active
            || self.snapshot.writer_certificate_digest
                != record.terms.scope.authorization.writer_certificate_digest
            || self.operations.len() != 5
            || self.snapshot.head.sequence != 5
            || self.selected_financial_continuation_v1()?.is_some()
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        let original = self
            .selected_durable_delivery_admission_v2()?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record: delivery } =
            &original.control
        else {
            return Err(AuthorityError::Permission);
        };
        if original.operation_id != record.terms.original_delivery_operation_id
            || delivery.scope != record.terms.scope
            || crate::durable_financial_continuation_v1::original_delivery_request_digest_v1(
                original,
            )? != record.terms.original_delivery_request_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        record.terms.require_live(now)?;
        self.check_financial_continuation_exposure_v1(&record.terms.scope.authorization)?;
        Ok(())
    }
    fn check_financial_continuation_exposure_v1(
        &self,
        t: &crate::durable_payment_v1::DurablePaymentAdmissionTermsV1,
    ) -> Result<()> {
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
    pub(crate) fn require_financial_continuation_mutation_v1(
        &self,
        admission_operation_id: &str,
        mutation: &AuthorityMutation,
        writer_session_id: Option<&str>,
        now: u64,
    ) -> Result<()> {
        self.require_financial_continuation_history_v1()?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        let admission = self
            .financial_continuation_v1(admission_operation_id)?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let t = &record.terms.scope.authorization;
        record.terms.require_live(now)?;
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
                crate::durable_payment_policy_v1::require_exact_reservation_v1(
                    t,
                    admission.writer_epoch,
                    r,
                )?;
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
                    self.check_financial_continuation_exposure_v1(t)?;
                }
            }
            _ => return Err(AuthorityError::Permission),
        }
        Ok(())
    }
    pub(crate) fn validate_financial_continuation_birth_v1(
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
        self.require_financial_continuation_history_v1()
    }
}
