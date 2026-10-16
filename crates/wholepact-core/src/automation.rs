//! Pure bounded local-automation policy. Passing these checks is not identity,
//! evidence, signer consent, currentness, or cryptographic verification.

use crate::{error::validate_id, Amount, CoreError, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const AUTOMATION_PROFILE: &str = "ironwood-testnet-nu7-candidate";
pub const MAX_AUTOMATION_SCOPE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationAccountPolicy {
    pub policy_id: String,
    pub account_id: String,
    pub writer_epoch: u64,
    /// One account-wide ceiling, shared by all applications and grants.
    pub maximum_outstanding_debit: Amount,
    pub valid_from_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationEvidenceKind {
    AccountControl,
    RecipientInstructions,
    ExactEffects,
    CurrentChain,
    ExposureContinuity,
    PrivateMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationEvidenceRequirement {
    pub kind: AutomationEvidenceKind,
    pub verifier_id: String,
    pub maximum_age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationGrantTerms {
    pub grant_id: String,
    pub application_id: String,
    pub account_id: String,
    pub account_policy_id: String,
    pub writer_epoch: u64,
    pub network_profile: String,
    pub signer_id: String,
    pub verifier_id: String,
    pub agreement_ids: Vec<String>,
    /// Digests of canonical, network-qualified receivers established by the
    /// trusted verifier. A caller's display address is never a receiver proof.
    pub recipient_fingerprints: Vec<String>,
    /// Maximum gross debit, including the participant's fees.
    pub maximum_payment_debit: Amount,
    pub maximum_payment_fee: Amount,
    pub maximum_outstanding_debit: Amount,
    pub evidence: Vec<AutomationEvidenceRequirement>,
    pub maximum_authorization_lifetime_ms: u64,
    pub maximum_expiry_height_delta: u32,
    pub valid_from_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationEvidence {
    pub kind: AutomationEvidenceKind,
    pub verifier_id: String,
    pub evidence_digest: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Claimed exact effects presented to a trusted verifier. No aggregate budget
/// field exists here: runtime derives it from retained owner-approved policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationRequest {
    pub authorization_id: String,
    pub application_id: String,
    pub account_id: String,
    pub writer_epoch: u64,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub network_profile: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub artifact_digest: String,
    pub input_ids: Vec<String>,
    pub recipient_fingerprints: Vec<String>,
    pub maximum_debit: Amount,
    pub fee: Amount,
    pub current_height: u32,
    pub transaction_expiry_height: u32,
    pub authorization_expires_at_ms: u64,
    pub evidence: Vec<AutomationEvidence>,
}

fn invalid(message: &'static str) -> CoreError {
    CoreError::new(ErrorCode::InvalidTerms, message)
}
fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "automation digest must be lowercase hexadecimal SHA-256",
        ));
    }
    Ok(())
}
fn unique(values: &[String], fingerprints: bool) -> Result<()> {
    if values.is_empty() || values.len() > MAX_AUTOMATION_SCOPE {
        return Err(invalid(
            "automation scope must have 1..=128 explicit entries",
        ));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if fingerprints {
            digest(value)?;
        } else {
            validate_id(value, "automation scope")?;
        }
        if !seen.insert(value) {
            return Err(invalid("duplicate automation scope entry"));
        }
    }
    Ok(())
}
fn interval(start: u64, end: u64) -> Result<()> {
    if start >= end || end > i64::MAX as u64 {
        return Err(invalid("invalid automation validity interval"));
    }
    Ok(())
}
fn current(start: u64, end: u64, now: u64) -> Result<()> {
    if now < start || now >= end {
        return Err(CoreError::new(
            ErrorCode::InvalidTransition,
            "automation policy is not currently valid",
        ));
    }
    Ok(())
}
impl AutomationAccountPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.policy_id, "automation account policy")?;
        validate_id(&self.account_id, "automation account")?;
        interval(self.valid_from_ms, self.expires_at_ms)?;
        if self.writer_epoch > i64::MAX as u64 || self.maximum_outstanding_debit == Amount::ZERO {
            return Err(invalid("automation account epoch or budget is invalid"));
        }
        Ok(())
    }
}
impl AutomationGrantTerms {
    pub fn validate(&self, policy: &AutomationAccountPolicy) -> Result<()> {
        policy.validate()?;
        for id in [
            &self.grant_id,
            &self.application_id,
            &self.account_id,
            &self.account_policy_id,
            &self.signer_id,
            &self.verifier_id,
        ] {
            validate_id(id, "automation identity")?;
        }
        interval(self.valid_from_ms, self.expires_at_ms)?;
        if self.account_id != policy.account_id
            || self.account_policy_id != policy.policy_id
            || self.writer_epoch != policy.writer_epoch
            || self.network_profile != AUTOMATION_PROFILE
            || self.valid_from_ms < policy.valid_from_ms
            || self.expires_at_ms > policy.expires_at_ms
        {
            return Err(invalid(
                "automation grant does not match the account policy and supported profile",
            ));
        }
        if self.maximum_payment_debit == Amount::ZERO
            || self.maximum_payment_fee > self.maximum_payment_debit
            || self.maximum_payment_debit > self.maximum_outstanding_debit
            || self.maximum_outstanding_debit > policy.maximum_outstanding_debit
            || self.maximum_authorization_lifetime_ms == 0
            || self.maximum_authorization_lifetime_ms > self.expires_at_ms - self.valid_from_ms
            || self.maximum_expiry_height_delta == 0
        {
            return Err(invalid(
                "automation monetary or lifetime bounds are invalid",
            ));
        }
        unique(&self.agreement_ids, false)?;
        unique(&self.recipient_fingerprints, true)?;
        let mut kinds = BTreeSet::new();
        if self.evidence.len() > 6 {
            return Err(invalid("too many automation evidence requirements"));
        }
        for evidence in &self.evidence {
            validate_id(&evidence.verifier_id, "evidence verifier")?;
            if evidence.maximum_age_ms == 0 || !kinds.insert(evidence.kind) {
                return Err(invalid(
                    "invalid or duplicate automation evidence requirement",
                ));
            }
        }
        for mandatory in [
            AutomationEvidenceKind::AccountControl,
            AutomationEvidenceKind::RecipientInstructions,
            AutomationEvidenceKind::ExactEffects,
            AutomationEvidenceKind::CurrentChain,
            AutomationEvidenceKind::ExposureContinuity,
        ] {
            if !kinds.contains(&mandatory) {
                return Err(CoreError::new(
                    ErrorCode::MissingEvidence,
                    "mandatory automation verifier requirement is missing",
                ));
            }
        }
        Ok(())
    }
}

/// Deterministic review/preview. All evidence entries remain untrusted claims
/// until the runtime's qualified verifier checks their original provenance.
pub fn evaluate_automation_request(
    policy: &AutomationAccountPolicy,
    grant: &AutomationGrantTerms,
    request: &AutomationRequest,
    now_ms: u64,
) -> Result<()> {
    grant.validate(policy)?;
    current(policy.valid_from_ms, policy.expires_at_ms, now_ms)?;
    current(grant.valid_from_ms, grant.expires_at_ms, now_ms)?;
    for id in [
        &request.authorization_id,
        &request.application_id,
        &request.account_id,
        &request.agreement_id,
        &request.obligation_id,
        &request.proposal_id,
    ] {
        validate_id(id, "automation request")?;
    }
    for value in [
        &request.manifest_digest,
        &request.effects_digest,
        &request.artifact_digest,
    ] {
        digest(value)?;
    }
    unique(&request.input_ids, false)?;
    unique(&request.recipient_fingerprints, true)?;
    if request.application_id != grant.application_id
        || request.account_id != grant.account_id
        || request.writer_epoch != grant.writer_epoch
        || request.network_profile != grant.network_profile
        || !grant.agreement_ids.contains(&request.agreement_id)
        || request
            .recipient_fingerprints
            .iter()
            .any(|r| !grant.recipient_fingerprints.contains(r))
    {
        return Err(invalid(
            "automation request is outside the explicit grant scope",
        ));
    }
    if request.maximum_debit == Amount::ZERO || request.maximum_debit > grant.maximum_payment_debit
    {
        return Err(CoreError::new(
            ErrorCode::DebitCapExceeded,
            "automation gross debit exceeds the grant",
        ));
    }
    if request.fee > grant.maximum_payment_fee || request.fee > request.maximum_debit {
        return Err(CoreError::new(
            ErrorCode::FeeCapExceeded,
            "automation fee exceeds the grant or gross debit",
        ));
    }
    if request.authorization_expires_at_ms <= now_ms
        || request.authorization_expires_at_ms > grant.expires_at_ms
        || request.authorization_expires_at_ms - now_ms > grant.maximum_authorization_lifetime_ms
        || request.transaction_expiry_height <= request.current_height
        || request.transaction_expiry_height - request.current_height
            > grant.maximum_expiry_height_delta
    {
        return Err(invalid(
            "automation authorization exceeds time or transaction expiry bounds",
        ));
    }
    if request.evidence.len() != grant.evidence.len() {
        return Err(CoreError::new(
            ErrorCode::MissingEvidence,
            "automation evidence set is incomplete or unexpected",
        ));
    }
    let mut seen = BTreeSet::new();
    for evidence in &request.evidence {
        digest(&evidence.evidence_digest)?;
        let requirement = grant
            .evidence
            .iter()
            .find(|r| r.kind == evidence.kind)
            .ok_or_else(|| {
                CoreError::new(ErrorCode::MissingEvidence, "unexpected automation evidence")
            })?;
        if !seen.insert(evidence.kind)
            || evidence.verifier_id != requirement.verifier_id
            || evidence.manifest_digest != request.manifest_digest
            || evidence.effects_digest != request.effects_digest
            || evidence.observed_at_ms > now_ms
            || evidence.expires_at_ms <= now_ms
            || evidence.expires_at_ms < request.authorization_expires_at_ms
            || now_ms - evidence.observed_at_ms > requirement.maximum_age_ms
        {
            return Err(CoreError::new(
                ErrorCode::MissingEvidence,
                "automation evidence scope, issuer, age or lifetime is invalid",
            ));
        }
    }
    Ok(())
}
