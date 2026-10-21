//! Explicit original financial continuation data. Canonical validation is not
//! native consent, source authentication, signing authority, or dispatch authority.
use crate::{durable_delivery_scope_v2::DurableDeliveryScopeV2, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialContinuationTermsV1 {
    pub scope: DurableDeliveryScopeV2,
    pub original_delivery_operation_id: String,
    pub original_delivery_request_digest: String,
    pub original_delivery_committed_head: AuthorityHead,
    pub original_local_intent_digest: String,
    pub original_recipient_intent_digest: String,
    pub original_recipient_enrollment_ref: String,
    pub original_recipient_manifest_ref: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}
impl FinancialContinuationTermsV1 {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        id(&self.original_delivery_operation_id)?;
        for value in [
            &self.original_delivery_request_digest,
            &self.original_delivery_committed_head.digest,
            &self.original_local_intent_digest,
            &self.original_recipient_intent_digest,
            &self.original_recipient_enrollment_ref,
            &self.original_recipient_manifest_ref,
        ] {
            hash(value)?;
        }
        if self.original_delivery_committed_head.sequence != 5
            || self.valid_from_ms < self.scope.delivery.valid_from_ms
            || self.valid_until_ms > self.scope.delivery.valid_until_ms
            || self.valid_until_ms <= self.valid_from_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    /// Seed for new local intent retention. Keeps the historical B1 intent digest
    /// but excludes the NEW continuation intent's own digest,
    /// the later Witness review digest and outer request, preventing a hash cycle.
    pub fn intent_terms_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:financial-continuation-intent-terms:v1", self)
    }
    pub fn require_live(&self, now: u64) -> Result<()> {
        self.validate()?;
        self.scope.authorization.require_live(now)?;
        if now < self.valid_from_ms || now >= self.valid_until_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialContinuationRecordV1 {
    pub terms: FinancialContinuationTermsV1,
    /// Canonical Signer intent preimage commits terms + actual original source
    /// and fresh SignExact/dispatch delegation review, never this field itself.
    pub signer_continuation_intent_digest: String,
    pub witness_native_review_digest: String,
}
impl FinancialContinuationRecordV1 {
    pub fn validate(&self) -> Result<()> {
        self.terms.validate()?;
        hash(&self.signer_continuation_intent_digest)?;
        hash(&self.witness_native_review_digest)
    }
    pub fn request_digest(&self, request: &OwnerControlRequest) -> Result<String> {
        self.validate_request(request, &self.terms.scope.witness)?;
        digest("wholepact:financial-continuation-request:v1", request)
    }
    pub fn acquire_operation_id(&self, request: &OwnerControlRequest) -> Result<String> {
        self.validate_request(request, &self.terms.scope.witness)?;
        Ok(format!(
            "financial-continuation-acquire-v1-{}",
            digest("wholepact:financial-continuation-acquire:v1", request)?
        ))
    }
    pub fn validate_request(
        &self,
        request: &OwnerControlRequest,
        disclosure: &WitnessDisclosureDescriptor,
    ) -> Result<()> {
        self.validate()?;
        disclosure.validate()?;
        if !matches!(&request.control, OwnerControl::AdmitFinancialContinuationV1 { record } if record.as_ref() == self)
            || request.account_id != self.terms.scope.authorization.identity.account_id
            || request.network_profile_id
                != self.terms.scope.authorization.identity.network_profile_id
            || request.writer_epoch != self.terms.scope.original_writer_epoch
            || request.expected_head != self.terms.original_delivery_committed_head
            || disclosure != &self.terms.scope.witness
            || request.operation_id != continuation_operation_id(self, request)?
            || self.witness_native_review_digest
                != continuation_review_digest(self, request, disclosure)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
fn continuation_operation_id(
    record: &FinancialContinuationRecordV1,
    request: &OwnerControlRequest,
) -> Result<String> {
    Ok(format!(
        "financial-continuation-admit-v1-{}",
        digest(
            "wholepact:financial-continuation-operation:v1",
            &(
                &record.terms,
                &record.signer_continuation_intent_digest,
                &request.account_id,
                &request.network_profile_id,
                request.writer_epoch,
                &request.expected_head
            )
        )?
    ))
}
fn continuation_review_digest(
    record: &FinancialContinuationRecordV1,
    request: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<String> {
    digest(
        "wholepact:financial-continuation-native-review:v1",
        &(
            &record.terms,
            &record.signer_continuation_intent_digest,
            &request.account_id,
            &request.network_profile_id,
            request.writer_epoch,
            &request.expected_head,
            disclosure,
        ),
    )
}
/// Canonical inert request; only the source-owned native endpoint may append it.
pub fn prepare_financial_continuation_request_v1(
    terms: FinancialContinuationTermsV1,
    signer_continuation_intent_digest: String,
    history: &ReconciledAuthorityHistory,
) -> Result<OwnerControlRequest> {
    terms.validate()?;
    hash(&signer_continuation_intent_digest)?;
    let original = history
        .durable_delivery_admission_v2(&terms.original_delivery_operation_id)?
        .ok_or(AuthorityError::Permission)?;
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &original.control else {
        return Err(AuthorityError::Permission);
    };
    if terms.scope != record.scope
        || original_delivery_request_digest_v1(original)? != terms.original_delivery_request_digest
        || history.snapshot.head != terms.original_delivery_committed_head
        || history.committed_operation_ids.len() != 5
        || history.snapshot.writer_status != WriterStatus::Active
        || history.snapshot.writer_epoch != terms.scope.original_writer_epoch
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let mut request = OwnerControlRequest {
        operation_id: String::new(),
        account_id: history.snapshot.account_id.clone(),
        network_profile_id: history.snapshot.network_profile_id.clone(),
        writer_epoch: history.snapshot.writer_epoch,
        expected_head: history.snapshot.head.clone(),
        control: OwnerControl::AdmitFinancialContinuationV1 {
            record: Box::new(FinancialContinuationRecordV1 {
                terms,
                signer_continuation_intent_digest,
                witness_native_review_digest: "0".repeat(64),
            }),
        },
    };
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
        unreachable!()
    };
    request.operation_id = continuation_operation_id(record, &request)?;
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
        unreachable!()
    };
    let review = continuation_review_digest(record, &request, &record.terms.scope.witness)?;
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &mut request.control else {
        unreachable!()
    };
    record.witness_native_review_digest = review;
    Ok(request)
}

/// Canonical commitment used by the genuine V3 preparation channel. Inert only.
pub fn original_delivery_request_digest_v1(request: &OwnerControlRequest) -> Result<String> {
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
        return Err(AuthorityError::Permission);
    };
    record.validate_request(request, &record.scope.witness)?;
    digest(
        "wholepact:durable-delivery-admission-preparation:v3",
        request,
    )
}

pub(crate) fn request_native_review_digest_v1(
    request: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<String> {
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
        return Err(AuthorityError::Permission);
    };
    continuation_review_digest(record, request, disclosure)
}

/// Complete original history received over the independently authenticated
/// financial endpoint. Inert historical evidence, never a current action grant.
pub struct AuthenticatedFinancialContinuationHistoryV1 {
    pub(crate) history: ReconciledAuthorityHistory,
    pub(crate) continuation: OwnerControlRequest,
    pub(crate) record: FinancialContinuationRecordV1,
    pub(crate) history_digest: String,
}
impl AuthenticatedFinancialContinuationHistoryV1 {
    pub fn continuation_request(&self) -> &OwnerControlRequest {
        &self.continuation
    }
    pub fn continuation_record(&self) -> &FinancialContinuationRecordV1 {
        &self.record
    }
    pub fn history_digest(&self) -> &str {
        &self.history_digest
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.history.snapshot
    }
    pub fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.history.disclosure
    }
    /// Historical evidence only. Membership does not grant an action, prove a
    /// current session, or permit replay of a previously committed operation.
    pub fn contains_operation(&self, operation_id: &str) -> bool {
        self.history.contains_operation(operation_id)
    }
    pub fn contains_head(&self, head: &AuthorityHead) -> bool {
        self.history.contains_head(head)
    }
    pub fn reservation(&self) -> Result<Option<&ReservationPermit>> {
        let id = &self.record.terms.scope.authorization.authorization_id;
        let mut found = self
            .history
            .permits
            .iter()
            .filter(|permit| permit.request.authorization_id == *id);
        let result = found.next();
        if found.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(result)
    }
}

impl AuthenticatedFinancialContinuationHistoryV1 {
    pub fn financial_continuation_admission_v1(
        &self,
        operation_id: &str,
    ) -> Result<Option<&OwnerControlRequest>> {
        id(operation_id)?;
        if self.continuation.operation_id != operation_id {
            return Err(AuthorityError::InvalidBinding);
        }
        self.record
            .validate_request(&self.continuation, &self.history.disclosure)?;
        Ok(Some(&self.continuation))
    }
    pub fn financial_continuation_online_permits_v1(
        &self,
        operation_id: &str,
    ) -> Result<&[ReservationPermit]> {
        self.financial_continuation_admission_v1(operation_id)?;
        if self.history.permits.len() > 1 {
            return Err(AuthorityError::CorruptHistory);
        }
        for permit in &self.history.permits {
            crate::durable_payment_policy_v1::require_exact_reservation_v1(
                &self.record.terms.scope.authorization,
                self.continuation.writer_epoch,
                &permit.request,
            )?;
            permit.matches_request(&permit.request)?;
            if !self.history.contains_head(&permit.committed_head)
                || permit.reserved_at_ms < self.record.terms.valid_from_ms
                || permit.request.permit_expires_at_ms > self.record.terms.valid_until_ms
            {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        Ok(&self.history.permits)
    }
    pub fn require_financial_continuation_session_v1(
        &self,
        operation_id: &str,
        active: &AuthenticatedWriterSession,
    ) -> Result<()> {
        self.financial_continuation_online_permits_v1(operation_id)?;
        self.history
            .account_use_history
            .require_not_permanently_excluded()?;
        self.record.terms.require_live(active.observed_at_ms())?;
        let receipt = active.receipt();
        if !self
            .history
            .contains_operation(&self.record.acquire_operation_id(&self.continuation)?)
            || active.snapshot() != &self.history.snapshot
            || active.disclosure() != &self.history.disclosure
            || active.history_digest() != self.history_digest
            || self.history.snapshot.writer_status != WriterStatus::Active
            || self.history.snapshot.writer_epoch != self.continuation.writer_epoch
            || self.history.snapshot.writer_certificate_digest
                != self
                    .record
                    .terms
                    .scope
                    .authorization
                    .writer_certificate_digest
            || self.history.snapshot.active_writer_session.as_ref() != Some(receipt)
            || receipt.writer_epoch != self.continuation.writer_epoch
            || receipt.writer_certificate_digest
                != self
                    .record
                    .terms
                    .scope
                    .authorization
                    .writer_certificate_digest
            || receipt.reconciled_head.sequence != 6
            || receipt.acquired_head.sequence != 7
            || !self.history.contains_head(&receipt.reconciled_head)
            || !self.history.contains_head(&receipt.acquired_head)
            || active.observed_at_ms() >= receipt.expires_at_ms
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        Ok(())
    }
}

impl AuthenticatedFinancialContinuationHistoryV1 {
    /// Exact original-operation outcome observation. No mutation, new interval,
    /// fresh attempt or conversion to a live admission can result from this API.
    pub fn completed_dispatch_outcome(
        &self,
        request: &crate::completed_dispatch_v1::AuthorizeCompletedDispatchV1,
    ) -> Result<Option<&crate::completed_dispatch_v1::CompletedDispatchAdmissionV1>> {
        request.validate()?;
        if request.account_id != self.history.snapshot.account_id
            || request.network_profile_id != self.history.snapshot.network_profile_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut matches = self
            .history
            .completed_dispatches_v1
            .iter()
            .filter(|entry| entry.request.operation_id == request.operation_id);
        let found = matches.next();
        if matches.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        if let Some(entry) = found {
            entry.validate()?;
            if entry.request != *request {
                return Err(AuthorityError::Conflict);
            }
        } else if self.history.contains_operation(&request.operation_id) {
            return Err(AuthorityError::Conflict);
        }
        Ok(found)
    }
}

#[cfg(test)]
mod evidence_api_tests {
    use super::AuthenticatedFinancialContinuationHistoryV1;
    #[test]
    fn operation_membership_is_borrowed_boolean_evidence_only() {
        // API shape: cannot consume history or construct a grant/session/token.
        let _: fn(&AuthenticatedFinancialContinuationHistoryV1, &str) -> bool =
            AuthenticatedFinancialContinuationHistoryV1::contains_operation;
    }
}
