//! Inert bounded owner-approved journal metadata. Deserialization is never authority.
use crate::Amount;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInspectionRequest {
    pub request_id: String,
    pub principal_id: String,
    pub agreement_id: String,
    pub candidate_id: String,
    pub participant_id: String,
    pub manifest_digest: String,
}
impl OwnerInspectionRequest {
    pub fn validate(&self) -> bool {
        [
            &self.principal_id,
            &self.agreement_id,
            &self.candidate_id,
            &self.participant_id,
        ]
        .iter()
        .all(|s| is_id(s))
            && [&self.request_id, &self.manifest_digest]
                .iter()
                .all(|s| is_digest(s))
    }
}
fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAudit {
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub proposal_id: String,
    pub maximum_debit: Amount,
    pub transaction_expiry_height: u32,
    pub result_retained: bool,
    pub latest_settlement_record: Option<String>,
    pub automation_grant_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorAudit {
    pub policy_key: String,
    pub version: u64,
    pub terms_digest: String,
    pub status: String,
    pub aggregate_budget: Amount,
    pub expires_at: Option<String>,
    pub witness_id: String,
    pub witness_policy_digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationAudit {
    pub grant_id: String,
    pub application_id: String,
    pub revision: u64,
    pub terms_digest: String,
    pub status: String,
    pub maximum_payment_debit: Amount,
    pub maximum_outstanding_debit: Amount,
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInspectionSnapshot {
    pub schema_version: u32,
    pub request: OwnerInspectionRequest,
    /// Derived from the actual unlocked signer vault, never a caller account lookup.
    pub account_id: String,
    /// Native owner identity from the authenticated journal session, not the receiving service client.
    pub source_principal_id: String,
    pub writer_epoch: u64,
    pub recovery_required: bool,
    pub inspected_at_ms: u64,
    pub provenance: String,
    pub freshness: String,
    pub authorization_allowed: bool,
    pub balance: Option<Amount>,
    pub account_pending_exposure: Option<Amount>,
    pub account_settled_debit: Option<Amount>,
    pub account_remaining_budget: Option<Amount>,
    pub authorizations: Vec<AuthorizationAudit>,
    pub sponsor_policies: Vec<SponsorAudit>,
    pub automation_grants: Vec<AutomationAudit>,
}
impl OwnerInspectionSnapshot {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && self.request.validate()
            && is_id(&self.account_id)
            && is_id(&self.source_principal_id)
            && self.writer_epoch > 0
            && self.inspected_at_ms > 0
            && self.provenance == "native_owner_approved_local_signer_journal"
            && self.freshness == "historical_local_snapshot_no_live_witness_or_chain_observation"
            && !self.authorization_allowed
            && self.balance.is_none()
            && self.account_pending_exposure.is_none()
            && self.account_settled_debit.is_none()
            && self.account_remaining_budget.is_none()
            && self.authorizations.len() <= 128
            && self.sponsor_policies.len() <= 32
            && self.automation_grants.len() <= 32
            && self.authorizations.iter().all(|a| {
                is_id(&a.authorization_id)
                    && is_id(&a.proposal_id)
                    && a.automation_grant_id.as_deref().is_none_or(is_id)
                    && is_digest(&a.original_consent_ref)
                    && a.transaction_expiry_height > 0
                    && a.latest_settlement_record.as_deref().is_none_or(|s| {
                        matches!(s, "canonical_consumed" | "canonical_conflict" | "reopened")
                    })
            })
            && self.sponsor_policies.iter().all(|p| {
                p.version > 0
                    && is_id(&p.witness_id)
                    && p.expires_at
                        .as_ref()
                        .is_none_or(|s| s.len() == 20 && s.ends_with('Z'))
                    && is_digest(&p.policy_key)
                    && is_digest(&p.terms_digest)
                    && is_digest(&p.witness_policy_digest)
                    && matches!(p.status.as_str(), "active" | "paused" | "revoked")
            })
            && self.automation_grants.iter().all(|g| {
                g.revision > 0
                    && is_id(&g.grant_id)
                    && is_id(&g.application_id)
                    && g.expires_at_ms > 0
                    && is_digest(&g.terms_digest)
                    && matches!(
                        g.status.as_str(),
                        "draft" | "active" | "paused" | "revoked" | "expired"
                    )
            })
    }
}
