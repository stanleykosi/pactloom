//! Dedicated completed-only dispatch CAS. Never requires/reconstructs a live
//! signing session, and never grants Acquire/Activate/Reserve/sign permission.
use crate::{
    completed_dispatch_v1::*,
    policy::{Event, Ledger},
    *,
};
impl Ledger {
    pub(crate) fn require_completed_dispatch_v1(
        &self,
        request: &AuthorizeCompletedDispatchV1,
        event: &Event,
    ) -> Result<u64> {
        request.validate()?;
        self.require_financial_continuation_history_v1()?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        let continuation = self
            .selected_financial_continuation_v1()?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &continuation.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        let terms = &record.terms;
        let scope = &terms.scope;
        let now = event.witness_time_ms;
        terms.require_live(now)?;
        if event.writer_session_id.is_some()
            || event.original_request_link.is_some()
            || event.authenticated_certificate_digest
                != scope.delivery.dispatcher.public_identity_commitment
            || request.account_id != scope.authorization.identity.account_id
            || request.network_profile_id != scope.authorization.identity.network_profile_id
            || request.context.fixed != scope.authorization.fixed
            || request.context.delivery != scope.delivery
            || request.writer_epoch != scope.original_writer_epoch
            || self.snapshot.writer_epoch != scope.original_writer_epoch
            || self.snapshot.writer_certificate_digest
                != scope.authorization.writer_certificate_digest
            || self.snapshot.writer_status != WriterStatus::Active
        {
            return Err(AuthorityError::Permission);
        }
        let own = request
            .context
            .owners
            .iter()
            .find(|owner| owner.account_id == request.account_id)
            .ok_or(AuthorityError::InvalidBinding)?;
        if own.continuation_operation_id != continuation.operation_id
            || own.continuation_request_digest != record.request_digest(continuation)?
            || own.reservation_operation_id != scope.authorization.authorization_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let (_, _, result) = self
            .operations
            .get(&own.reservation_operation_id)
            .ok_or(AuthorityError::Permission)?;
        let MutationResult::Reserved(reservation) = result else {
            return Err(AuthorityError::InvalidBinding);
        };
        crate::durable_payment_policy_v1::require_exact_reservation_v1(
            &scope.authorization,
            request.writer_epoch,
            &reservation.request,
        )?;
        reservation.matches_request(&reservation.request)?;
        if own.reservation_request_digest != reservation.request_digest
            || request.context.transaction_expiry_height
                != reservation.request.transaction_expiry_height
            || !self
                .authorizations
                .contains(&scope.authorization.authorization_id)
            || !self
                .obligations
                .contains(&scope.authorization.fixed.obligation_id)
            || scope.authorization.inputs.iter().any(|input| {
                !self.input_ids.contains(&input.input_id)
                    || !self.nullifiers.contains(&input.nullifier)
            })
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut prior_attempt = 0;
        for (mutation, _, result) in self.operations.values() {
            if let AuthorityMutation::AuthorizeCompletedDispatchV1(old) = mutation {
                let MutationResult::CompletedDispatchAdmittedV1(admission) = result else {
                    return Err(AuthorityError::CorruptHistory);
                };
                admission.validate()?;
                let mut old_context = old.context.clone();
                old_context.attempt = request.context.attempt;
                if old_context != request.context {
                    return Err(AuthorityError::Conflict);
                }
                prior_attempt = prior_attempt.max(old.context.attempt);
                if old.operation_id == request.operation_id {
                    if old != request {
                        return Err(AuthorityError::Conflict);
                    }
                    // Historical replay retains its original fixed activation interval.
                    if now >= admission.expires_at_ms {
                        return Err(AuthorityError::Expired);
                    }
                    return Ok(admission.expires_at_ms);
                }
            }
        }
        // Pair attempts are globally bounded by the original plan. A peer may
        // miss an earlier one-sided attempt; skipping only consumes budget.
        // The Host retains and reconciles both exact previous requests.
        if request.context.attempt <= prior_attempt {
            return Err(AuthorityError::Conflict);
        }
        self.fence(&request.expected_head, request.writer_epoch)?;
        if now < request.host_reviewed_at_ms {
            return Err(AuthorityError::Expired);
        }
        let expires = now
            .checked_add(request.requested_admission_lifetime_ms)
            .ok_or(AuthorityError::Expired)?
            .min(
                request
                    .host_reviewed_at_ms
                    .checked_add(120_000)
                    .ok_or(AuthorityError::Expired)?,
            )
            .min(terms.valid_until_ms)
            .min(scope.delivery.valid_until_ms)
            .min(scope.original_ceilings.enrollment_expires_at_ms)
            .min(scope.original_ceilings.policy_expires_at_ms)
            .min(scope.original_ceilings.payment_valid_until_ms);
        if expires <= now {
            return Err(AuthorityError::Expired);
        }
        if self
            .final_transactions
            .get(&own.reservation_operation_id)
            .is_some_and(|old| {
                old != &(
                    request.context.final_transaction_digest.clone(),
                    request.context.final_transaction_id.clone(),
                )
            })
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(expires)
    }
    pub(crate) fn apply_completed_dispatch_v1(
        &mut self,
        request: &AuthorizeCompletedDispatchV1,
        event: &Event,
        next_head: &AuthorityHead,
    ) -> Result<CompletedDispatchAdmissionV1> {
        let expires_at_ms = self.require_completed_dispatch_v1(request, event)?;
        let admission = CompletedDispatchAdmissionV1 {
            request: request.clone(),
            request_digest: request.request_digest()?,
            witness_id: self.policy.witness_id.clone(),
            policy_digest: self.snapshot.policy_digest.clone(),
            committed_head: next_head.clone(),
            activated_at_ms: event.witness_time_ms,
            expires_at_ms,
        };
        admission.validate()?;
        let own = request
            .context
            .owners
            .iter()
            .find(|owner| owner.account_id == request.account_id)
            .ok_or(AuthorityError::InvalidBinding)?;
        self.final_transactions.insert(
            own.reservation_operation_id.clone(),
            (
                request.context.final_transaction_digest.clone(),
                request.context.final_transaction_id.clone(),
            ),
        );
        Ok(admission)
    }
}
