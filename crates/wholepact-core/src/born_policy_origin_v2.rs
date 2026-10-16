//! Complete inert preimage of a newly-created V2 birth. A version label or a
//! policy hash alone cannot upgrade a legacy birth. Consumers must compare this
//! validated digest with the ORIGINAL authenticated witness birth/genesis.
use crate::{
    CoreError, ErrorCode, Result,
    born_recipient_policy_v2::{BornConstructionRecipientPolicyV2, BornOriginalLimitsV2},
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornPolicyIdentityV2 {
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub network_profile_id: String,
    pub derivation_domain: String,
    pub exact_derivation: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornPolicyWitnessOriginV2 {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
}
/// Mirrors the existing genesis-free AccountPolicy projection exactly. The
/// authoritative consumer must also pass its maintained AccountPolicy validator.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornPolicyOriginalTermsV2 {
    pub witness_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub owner_certificate_digest: String,
    pub initial_writer_certificate_digest: String,
    pub initial_writer_epoch: u64,
    pub enrollment_refs: Vec<String>,
    pub agreement_ids: Vec<String>,
    pub recipient_scope_digests: Vec<String>,
    pub aggregate_budget_zatoshis: u64,
    pub per_operation_limit_zatoshis: u64,
    pub maximum_fee_share_zatoshis: u64,
    pub maximum_transaction_fee_zatoshis: u64,
    pub maximum_permit_lifetime_ms: u64,
    pub policy_expires_at_ms: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornRecipientPolicyBirthIntentV2 {
    pub version: u16,
    pub operation_id: String,
    pub generation_instance_id: String,
    pub identity: BornPolicyIdentityV2,
    pub witness_origin: BornPolicyWitnessOriginV2,
    pub original_policy_terms: BornPolicyOriginalTermsV2,
    pub original_policy_terms_digest: String,
    pub native_principal_id: String,
    pub native_measurement: String,
    pub original_target: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornRecipientPolicyOriginV2 {
    pub version: u16,
    pub intent: BornRecipientPolicyBirthIntentV2,
    pub recipient_policy: BornConstructionRecipientPolicyV2,
    pub birth_digest: String,
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid original version2 birth preimage",
    )
}
fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
fn text(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
impl BornPolicyOriginalTermsV2 {
    pub fn digest(&self) -> Result<String> {
        canonical_digest("wholepact:account-birth-original-policy-terms:v1", self)
    }
    pub fn limits(&self) -> BornOriginalLimitsV2 {
        BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: self.aggregate_budget_zatoshis,
            per_operation_limit_zatoshis: self.per_operation_limit_zatoshis,
            maximum_fee_share_zatoshis: self.maximum_fee_share_zatoshis,
            maximum_transaction_fee_zatoshis: self.maximum_transaction_fee_zatoshis,
            maximum_permit_lifetime_ms: self.maximum_permit_lifetime_ms,
            policy_expires_at_ms: self.policy_expires_at_ms,
        }
    }
}
impl BornRecipientPolicyOriginV2 {
    pub fn validate(&self) -> Result<()> {
        let i = &self.intent;
        let t = &i.original_policy_terms;
        let p = &self.recipient_policy;
        p.validate()?;
        if self.version != 2
            || i.version != 2
            || i.operation_id.len() != 38
            || !i.operation_id.starts_with("birth-")
            || !i.operation_id[6..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || t.initial_writer_epoch == 0
            || t.enrollment_refs.is_empty()
            || t.enrollment_refs.len() > 32
            || t.agreement_ids.is_empty()
            || t.agreement_ids.len() > 32
            || t.recipient_scope_digests.is_empty()
            || t.recipient_scope_digests.len() > 32
            || i.identity.account_id != t.account_id
            || i.identity.network_profile_id != t.network_profile_id
            || i.witness_origin.witness_id != t.witness_id
            || p.account_id != t.account_id
            || p.network_profile_id != t.network_profile_id
            || p.original_limits != t.limits()
            || !t.agreement_ids.contains(&p.agreement_id)
            || !t.recipient_scope_digests.contains(&p.digest()?)
            || i.original_policy_terms_digest != t.digest()?
        {
            return Err(invalid());
        }
        for h in [
            &i.generation_instance_id,
            &i.identity.account_id,
            &i.identity.full_viewing_key_digest,
            &i.witness_origin.pinned_server_certificate_digest,
            &i.native_measurement,
            &t.owner_certificate_digest,
            &t.initial_writer_certificate_digest,
            &self.birth_digest,
        ] {
            hash(h)?;
        }
        for s in [
            &i.identity.network_profile_id,
            &i.identity.derivation_domain,
            &i.identity.exact_derivation,
            &i.witness_origin.endpoint,
            &i.witness_origin.server_name,
            &i.witness_origin.witness_id,
            &i.native_principal_id,
            &i.original_target,
        ] {
            text(s)?;
        }
        for values in [&t.enrollment_refs, &t.recipient_scope_digests] {
            let mut seen = std::collections::BTreeSet::new();
            for h in values {
                hash(h)?;
                if !seen.insert(h) {
                    return Err(invalid());
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in &t.agreement_ids {
            text(id)?;
            if !seen.insert(id) {
                return Err(invalid());
            }
        }
        if !i.original_target.starts_with('/')
            || i.original_target == "/"
            || i.original_target.ends_with('/')
            || i.original_target
                .split('/')
                .skip(1)
                .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err(invalid());
        }
        let computed = canonical_digest("wholepact:native-account-birth-intent:v2", &(i, p))?;
        if computed != self.birth_digest
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > 96 * 1024
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(self.birth_digest.clone())
    }
}
