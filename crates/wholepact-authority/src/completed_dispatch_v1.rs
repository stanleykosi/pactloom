//! Exact immutable completed-transaction dispatch data and authenticated admission.
//! No type here permits signing or constructs a transaction.
use crate::{
    durable_delivery_scope_v2::DurableDeliveryPlanV2,
    durable_payment_v1::DurableFixedCandidateBindingV1, *,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedDispatchOwnerV1 {
    pub account_id: String,
    pub continuation_operation_id: String,
    pub continuation_request_digest: String,
    pub reservation_operation_id: String,
    pub reservation_request_digest: String,
    pub signature_result_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedDispatchContextV1 {
    pub fixed: DurableFixedCandidateBindingV1,
    pub delivery: DurableDeliveryPlanV2,
    pub owners: Vec<CompletedDispatchOwnerV1>,
    pub signed_result_request_digest: String,
    pub signed_artifact_digest: String,
    pub transaction_checkpoint_id: String,
    pub final_transaction_digest: String,
    pub final_transaction_id: String,
    pub transaction_expiry_height: u32,
    pub network: String,
    pub consensus_branch_id: u32,
    pub backend_disclosure_digest: String,
    pub attempt: u32,
}
impl CompletedDispatchContextV1 {
    pub fn validate(&self) -> Result<()> {
        self.fixed.validate()?;
        // Full plan validation is performed against each actual original scope.
        if self.owners.len() != 2
            || self.owners[0].account_id >= self.owners[1].account_id
            || self.attempt == 0
            || self.attempt > self.delivery.maximum_explicitly_approved_attempts
            || self.transaction_expiry_height != self.fixed.expiry_height
            || self.network != "testnet"
            || self.consensus_branch_id != wholepact_chain::NU7_BRANCH_ID
        {
            return Err(AuthorityError::InvalidBinding);
        }
        id(&self.transaction_checkpoint_id)?;
        for value in [
            &self.signed_result_request_digest,
            &self.signed_artifact_digest,
            &self.final_transaction_digest,
            &self.final_transaction_id,
            &self.backend_disclosure_digest,
        ] {
            hash(value)?;
        }
        for owner in &self.owners {
            hash(&owner.account_id)?;
            id(&owner.continuation_operation_id)?;
            id(&owner.reservation_operation_id)?;
            for value in [
                &owner.continuation_request_digest,
                &owner.reservation_request_digest,
                &owner.signature_result_digest,
            ] {
                hash(value)?;
            }
        }
        if self
            .delivery
            .owners
            .iter()
            .map(|v| &v.account_id)
            .collect::<Vec<_>>()
            != self
                .owners
                .iter()
                .map(|v| &v.account_id)
                .collect::<Vec<_>>()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:completed-dispatch-context:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeCompletedDispatchV1 {
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub context: CompletedDispatchContextV1,
    pub host_reviewed_at_ms: u64,
    pub requested_admission_lifetime_ms: u64,
}
impl AuthorizeCompletedDispatchV1 {
    pub fn validate(&self) -> Result<()> {
        self.context.validate()?;
        id(&self.operation_id)?;
        hash(&self.account_id)?;
        id(&self.network_profile_id)?;
        hash(&self.expected_head.digest)?;
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.host_reviewed_at_ms == 0
            || self.host_reviewed_at_ms > i64::MAX as u64
            || self.requested_admission_lifetime_ms == 0
            || self.requested_admission_lifetime_ms > 120_000
            || self.requested_admission_lifetime_ms
                > self.context.delivery.maximum_fresh_admission_lifetime_ms
            || !self
                .context
                .owners
                .iter()
                .any(|v| v.account_id == self.account_id)
            || self.operation_id != self.canonical_operation_id()?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn canonical_operation_id(&self) -> Result<String> {
        Ok(format!(
            "completed-dispatch-v1-{}",
            digest(
                "wholepact:completed-dispatch-operation:v1",
                &(
                    &self.account_id,
                    &self.context.delivery.submission_journal_identity,
                    &self.context.delivery.submission_operation_id,
                    self.context.attempt
                )
            )?
        ))
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:completed-dispatch-request:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedDispatchAdmissionV1 {
    pub request: AuthorizeCompletedDispatchV1,
    pub request_digest: String,
    pub witness_id: String,
    pub policy_digest: String,
    pub committed_head: AuthorityHead,
    pub activated_at_ms: u64,
    pub expires_at_ms: u64,
}
impl CompletedDispatchAdmissionV1 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        id(&self.witness_id)?;
        hash(&self.policy_digest)?;
        hash(&self.committed_head.digest)?;
        if self.request_digest != self.request.request_digest()?
            || self.activated_at_ms < self.request.host_reviewed_at_ms
            || self.expires_at_ms <= self.activated_at_ms
            || self.expires_at_ms - self.activated_at_ms
                > self.request.requested_admission_lifetime_ms
            || self.expires_at_ms > self.request.context.delivery.valid_until_ms
            || self.expires_at_ms
                > self
                    .request
                    .host_reviewed_at_ms
                    .checked_add(120_000)
                    .ok_or(AuthorityError::Limit)?
            || self.committed_head.sequence
                != self
                    .request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::Limit)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
/// A real authenticated response, not reconstructible from serialized evidence.
/// Currentness means this admission's unchanged interval, not remote revocation
/// recall. The Witness commit is an immutable authorization linearization point.
pub struct AuthenticatedCompletedDispatchAdmissionV1 {
    pub(crate) admission: CompletedDispatchAdmissionV1,
    pub(crate) observed: std::time::Instant,
    pub(crate) observed_at_ms: u64,
}
impl AuthenticatedCompletedDispatchAdmissionV1 {
    pub fn admission(&self) -> &CompletedDispatchAdmissionV1 {
        &self.admission
    }
    pub fn check_current(&self) -> Result<()> {
        self.admission.validate()?;
        let now = now_ms()?;
        if now < self.observed_at_ms
            || now < self.admission.activated_at_ms
            || now >= self.admission.expires_at_ms
            || self.observed.elapsed().as_millis()
                >= u128::from(
                    self.admission
                        .expires_at_ms
                        .saturating_sub(self.observed_at_ms),
                )
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}
