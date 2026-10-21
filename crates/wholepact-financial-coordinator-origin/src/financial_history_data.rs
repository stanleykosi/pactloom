//! Ordinary initial original-owner history data only. No successful parse,
//! digest or DTO grants Setup/Serve, proves prefix membership or source disposal,
//! or constructs any original actor. Actual issuers retain those obligations.
use crate::{
    financial_workflow_channel::SignerFinancialReadPresentationV1, rejected,
    signer_continue_state::hash, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FINANCIAL_HISTORY_PURPOSE: &str = "original-financial-history-service";
pub const FINANCIAL_HISTORY_MODE: &str = "one-original-owner-history";
const MAX_ENCODED: usize = 60 * 1024;
const PRESENTATION_DOMAIN: &[u8] = b"wholepact:financial-history:presentation:v1\0";

/// Existing paths and public selection only. No request JSON, private key bytes,
/// descriptor, origin or public permission constructor is part of this schema.
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialHistoryInputsV1 {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
    pub network_profile_id: String,
    pub expected_account_id: String,
    pub owner_certificate_der_hex: String,
    pub storage_key_file: String,
    pub server_certificate_der: String,
    pub server_private_key_pkcs8_der: String,
    pub trusted_client_root_der: String,
}
impl FinancialHistoryInputsV1 {
    pub fn validate(&self) -> Result<()> {
        if [
            &self.endpoint,
            &self.server_name,
            &self.witness_id,
            &self.network_profile_id,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
            || !hash(&self.pinned_server_certificate_digest)
            || !hash(&self.expected_account_id)
            || self.owner_certificate_der_hex.is_empty()
            || self.owner_certificate_der_hex.len() > 32768
            || self.owner_certificate_der_hex.len() % 2 != 0
            || !lower_hex(&self.owner_certificate_der_hex)
            || [
                &self.storage_key_file,
                &self.server_certificate_der,
                &self.server_private_key_pkcs8_der,
                &self.trusted_client_root_der,
            ]
            .iter()
            .any(|value| {
                !value.starts_with('/')
                    || value.len() > 4096
                    || value.bytes().any(|b| b < 0x20 || b == 0x7f)
            })
        {
            return Err(rejected("initial financial history selector shape"));
        }
        encoded_bound(self)
    }
}

/// Complete ORIGINAL v2 S Read presentation. It is immutable correlation data,
/// not a rebuilt source selection or evidence of the remote current head.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialHistoryReadBindingV1 {
    pub read: SignerFinancialReadPresentationV1,
}
impl FinancialHistoryReadBindingV1 {
    pub fn validate(&self) -> Result<()> {
        self.read.validate()?;
        encoded_bound(self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialHistoryPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub mode: String,
    pub display: String,
    pub backend_review_digest: String,
    pub presentation_digest: String,
    pub prepared_at_ms: u64,
    pub expires_at_ms: u64,
    pub account_id: String,
    pub network_profile_id: String,
    pub source_commitment: String,
    pub policy_digest: String,
    pub owner_certificate_digest: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub read_binding: FinancialHistoryReadBindingV1,
}
impl FinancialHistoryPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.validate_shape()?;
        // Nested tuples keep a fixed field order within serde's tuple limit.
        let bytes = serde_json::to_vec(&(
            (
                self.version,
                &self.purpose,
                &self.mode,
                &self.display,
                &self.backend_review_digest,
                self.prepared_at_ms,
                self.expires_at_ms,
            ),
            (
                &self.account_id,
                &self.network_profile_id,
                &self.source_commitment,
                &self.policy_digest,
                &self.owner_certificate_digest,
                self.expected_head_sequence,
                &self.expected_head_digest,
                &self.read_binding,
            ),
        ))
        .map_err(|_| rejected("initial financial history presentation encoding"))?;
        let mut digest = Sha256::new();
        digest.update(PRESENTATION_DOMAIN);
        digest.update(bytes);
        Ok(hex::encode(digest.finalize()))
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected(
                "initial financial history presentation commitment",
            ));
        }
        Ok(())
    }
    fn validate_shape(&self) -> Result<()> {
        self.read_binding.validate()?;
        let facts = &self.read_binding.read.facts;
        if self.version != 1
            || self.purpose != FINANCIAL_HISTORY_PURPOSE
            || self.mode != FINANCIAL_HISTORY_MODE
            || !display(&self.display)
            || !identifier(&self.network_profile_id)
            || ![
                &self.backend_review_digest,
                &self.account_id,
                &self.source_commitment,
                &self.policy_digest,
                &self.owner_certificate_digest,
                &self.expected_head_digest,
            ]
            .iter()
            .all(|value| hash(value))
            || self.account_id != facts.account_id
            || self.owner_certificate_digest != facts.owner_certificate_digest
            || self.prepared_at_ms < facts.reviewed_at_ms
            || self.expires_at_ms <= self.prepared_at_ms
            || self.expires_at_ms > facts.expires_at_ms
            || self.expires_at_ms > facts.source_expires_at_ms
            || self.expected_head_sequence > 65_536
            || !historical_prefix_shape(
                self.expected_head_sequence,
                &self.expected_head_digest,
                facts.original_delivery_head_sequence,
                &facts.original_delivery_head_digest,
            )
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("initial financial history presentation shape"));
        }
        // A larger actual current head is permitted: the old S delivery head is
        // historical. Only the actual source can prove the exact prefix exists.
        // Network/policy/disclosure provenance also belongs to that actual source.
        encoded_bound(self)
    }
}
fn historical_prefix_shape(
    current_sequence: u64,
    current_digest: &str,
    historical_sequence: u64,
    historical_digest: &str,
) -> bool {
    current_sequence >= historical_sequence
        && (current_sequence != historical_sequence || current_digest == historical_digest)
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn display(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32768
        && value
            .bytes()
            .all(|b| matches!(b, b'\n' | b'\t' | 0x20..=0x7e))
}
fn encoded_bound(value: &impl Serialize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| rejected("initial financial history data encoding"))?
        .len()
        > MAX_ENCODED
    {
        return Err(rejected(
            "initial financial history complete data exceeds frame budget",
        ));
    }
    // The genuine sender MUST separately cap the COMPLETE original64KiB frame.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        financial_workflow_channel::{
            FinancialActorContextV1, SignerFinancialReadFactsV1, READ_NOTICE, READ_PURPOSE,
        },
        financial_workflow_clock::PROFILE,
        signer_continue_channel::SignerContinueRoleV1,
    };
    // Fabricated public DTO/hash data only, no source, actor or token constructor.
    fn example() -> FinancialHistoryPresentationV1 {
        let h = "1".repeat(64);
        let mut facts = SignerFinancialReadFactsV1 {
            read_digest: String::new(),
            display: "Public synthetic historical delivery".into(),
            source_identity_digest: h.clone(),
            original_journal_digest: h.clone(),
            terms_digest: h.clone(),
            original_delivery_operation_id: "public-operation".into(),
            original_delivery_request_digest: h.clone(),
            original_delivery_head_sequence: 3,
            original_delivery_head_digest: h.clone(),
            original_host_process_instance: h.clone(),
            account_id: h.clone(),
            owner_certificate_digest: h.clone(),
            owner_selection_digest: h.clone(),
            disclosure_digest: h.clone(),
            session_digest: h.clone(),
            reviewed_at_ms: 1000,
            expires_at_ms: 121000,
            source_expires_at_ms: 301000,
        };
        facts.read_digest = facts.calculate_read_digest().unwrap();
        let mut read = SignerFinancialReadPresentationV1 {
            version: 2,
            purpose: READ_PURPOSE.into(),
            actor: FinancialActorContextV1 {
                profile: PROFILE.into(),
                coordinator_process_instance: h.clone(),
                coordinator_focus_epoch: 1,
                signer_role: SignerContinueRoleV1::Signer1,
                signer_process_instance: h.clone(),
                common_image_measurement: h.clone(),
                session_challenge: h.clone(),
            },
            facts,
            notice: READ_NOTICE.into(),
            selection_digest: h.clone(),
            source_entry_presentation_digest: h.clone(),
            read_challenge: h.clone(),
            source_ceiling_ms: 300000,
            read_ceiling_ms: 120000,
            presentation_digest: String::new(),
        };
        read.presentation_digest = read.calculate_presentation_digest().unwrap();
        let mut p = FinancialHistoryPresentationV1 {
            version: 1,
            purpose: FINANCIAL_HISTORY_PURPOSE.into(),
            mode: FINANCIAL_HISTORY_MODE.into(),
            display: "Public synthetic owner-only read service".into(),
            backend_review_digest: h.clone(),
            presentation_digest: String::new(),
            prepared_at_ms: 2000,
            expires_at_ms: 121000,
            account_id: h.clone(),
            network_profile_id: "public-network".into(),
            source_commitment: h.clone(),
            policy_digest: h.clone(),
            owner_certificate_digest: h,
            expected_head_sequence: 4,
            expected_head_digest: "2".repeat(64),
            read_binding: FinancialHistoryReadBindingV1 { read },
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn original_read_binding_and_distinct_actual_current_head_round_trip() {
        let p = example();
        p.validate().unwrap();
        let bytes = serde_json::to_vec(&p).unwrap();
        let decoded: FinancialHistoryPresentationV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(p == decoded);
        decoded.validate().unwrap();
        assert!(
            decoded.expected_head_sequence
                > decoded
                    .read_binding
                    .read
                    .facts
                    .original_delivery_head_sequence
        );
    }
    #[test]
    fn historical_delivery_head_is_not_fabricated_as_remote_current_head() {
        assert!(historical_prefix_shape(9, "new", 3, "old"));
        assert!(historical_prefix_shape(3, "old", 3, "old"));
        assert!(!historical_prefix_shape(2, "older", 3, "old"));
        assert!(!historical_prefix_shape(3, "changed", 3, "old"));
    }
    #[test]
    fn fixed_domain_scope_owner_and_original_expiry_are_not_reinterpreted() {
        let original = example();
        let mut p = original.clone();
        p.mode = "append".into();
        assert!(p.validate().is_err());
        let mut p = original.clone();
        p.owner_certificate_digest = "3".repeat(64);
        assert!(p.calculate_presentation_digest().is_err());
        let mut p = original.clone();
        p.expires_at_ms += 1;
        assert!(p.calculate_presentation_digest().is_err());
        let mut p = original.clone();
        p.prepared_at_ms = 999;
        assert!(p.calculate_presentation_digest().is_err());
        let mut p = original.clone();
        p.policy_digest = "4".repeat(64);
        assert!(p.validate().is_err());
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p.validate().unwrap();
        assert_ne!(p.presentation_digest, original.presentation_digest);
    }
    #[test]
    fn complete_presentation_bound_rejects_combined_large_valid_displays() {
        let mut p = example();
        p.display = "x".repeat(32768);
        p.read_binding.read.facts.display = "y".repeat(32768);
        let f = &mut p.read_binding.read.facts;
        f.read_digest = f.calculate_read_digest().unwrap();
        p.read_binding.read.presentation_digest =
            p.read_binding.read.calculate_presentation_digest().unwrap();
        assert!(p.calculate_presentation_digest().is_err());
    }
    #[test]
    fn unknown_duplicate_fields_and_request_injection_are_rejected() {
        let bytes = serde_json::to_string(&example()).unwrap();
        let unknown = bytes.replacen('{', "{\"permission\":true,", 1);
        assert!(serde_json::from_str::<FinancialHistoryPresentationV1>(&unknown).is_err());
        let duplicate = bytes.replacen('{', "{\"version\":1,", 1);
        assert!(serde_json::from_str::<FinancialHistoryPresentationV1>(&duplicate).is_err());
        let inputs = serde_json::to_string(&FinancialHistoryInputsV1::default()).unwrap();
        let injected = inputs.replacen('{', "{\"request_json\":\"{}\",", 1);
        assert!(serde_json::from_str::<FinancialHistoryInputsV1>(&injected).is_err());
    }
    #[test]
    fn maintained_identifier_and_digest_formats_stay_closed() {
        assert!(identifier("public-network.v1:test"));
        assert!(!identifier("public network"));
        assert!(!identifier(&"x".repeat(129)));
        let mut p = example();
        p.policy_digest = "A".repeat(64);
        assert!(p.validate().is_err());
        let mut p = example();
        p.expected_head_sequence = 65537;
        assert!(p.calculate_presentation_digest().is_err());
    }
}
