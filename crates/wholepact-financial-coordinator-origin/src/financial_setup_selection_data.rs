//! Bounded ordinary public configuration selections, never permissions.
use crate::{rejected, signer_continue_state::hash, Result, SignerV3OwnerSetupSelectionV1};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialWalletPolicySelectionV1 {
    pub confidence: String,
    pub source_id: String,
    pub endpoint: String,
    pub maximum_observation_age_seconds: u32,
    pub minimum_confirmations: u32,
    pub minimum_expiry_margin_blocks: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialWalletBirthdaySelectionV1 {
    pub prior_height: u32,
    pub prior_block_hash: String,
    pub sapling_tree: String,
    pub orchard_tree: String,
    pub ironwood_tree: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialWalletSetupSelectionV1 {
    pub schema_version: u32,
    pub purpose: String,
    pub policy: SignerFinancialWalletPolicySelectionV1,
    pub birthday: SignerFinancialWalletBirthdaySelectionV1,
    pub maximum_blocks: u32,
    pub retention: String,
}
impl SignerFinancialWalletSetupSelectionV1 {
    pub fn parse_json(raw: &str) -> Result<Self> {
        if raw.is_empty() || raw.len() > 32768 {
            return Err(rejected("wallet ordinary configuration bound"));
        }
        let s: Self = serde_json::from_str(raw)
            .map_err(|_| rejected("wallet ordinary configuration schema"))?;
        if s.schema_version != 1
            || s.purpose != "fresh_born_ephemeral_viewing_wallet_v1"
            || s.retention != "current_native_owner_only"
            || !(1..=1000).contains(&s.maximum_blocks)
            || s.policy.confidence != "trusted_single_provider_snapshot"
            || !(1..=300).contains(&s.policy.maximum_observation_age_seconds)
            || !(1..=100).contains(&s.policy.minimum_confirmations)
            || s.policy.minimum_expiry_margin_blocks == 0
            || s.policy.source_id.is_empty()
            || s.policy.source_id.len() > 128
            || s.policy.endpoint.is_empty()
            || s.policy.endpoint.len() > 2048
            || s.policy.endpoint.ends_with('/')
        {
            return Err(rejected("wallet ordinary configuration values"));
        }
        Ok(s)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialSetupSelectionV1 {
    pub source_identity_digest: String,
    pub audit_presentation_digest: String,
    pub recipient_intent_digest: String,
    pub fixed_identity_digest: String,
    pub writer_setup_json: String,
    pub wallet_setup_json: String,
    pub selection_nonce: String,
}
impl SignerFinancialSetupSelectionV1 {
    pub fn validate(&self) -> Result<()> {
        SignerV3OwnerSetupSelectionV1::parse_json(&self.writer_setup_json)?;
        SignerFinancialWalletSetupSelectionV1::parse_json(&self.wallet_setup_json)?;
        if ![
            &self.source_identity_digest,
            &self.audit_presentation_digest,
            &self.recipient_intent_digest,
            &self.fixed_identity_digest,
            &self.selection_nonce,
        ]
        .iter()
        .all(|v| hash(v))
            || serde_json::to_vec(self)
                .map_err(|_| rejected("financial ordinary selection encoding"))?
                .len()
                > 56 * 1024
        {
            return Err(rejected("financial ordinary selection binding"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn selection() -> SignerFinancialSetupSelectionV1 {
        let wallet = serde_json::json!({"schema_version":1,"purpose":"fresh_born_ephemeral_viewing_wallet_v1","policy":{"confidence":"trusted_single_provider_snapshot","source_id":"pinned","endpoint":"https://example.invalid","maximum_observation_age_seconds":60,"minimum_confirmations":1,"minimum_expiry_margin_blocks":1},"birthday":{"prior_height":1,"prior_block_hash":"00","sapling_tree":"","orchard_tree":"","ironwood_tree":""},"maximum_blocks":10,"retention":"current_native_owner_only"});
        SignerFinancialSetupSelectionV1 {
            source_identity_digest: "ab".repeat(32),
            audit_presentation_digest: "bc".repeat(32),
            recipient_intent_digest: "cd".repeat(32),
            fixed_identity_digest: "de".repeat(32),
            writer_setup_json: crate::signer_v3_delivery_data::tests::owner_json(),
            wallet_setup_json: wallet.to_string(),
            selection_nonce: "ef".repeat(32),
        }
    }
    #[test]
    fn exact_financial_wallet_profile_not_legacy_action() {
        let s = selection();
        s.validate().unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&s.wallet_setup_json).unwrap();
        v["action"] = serde_json::json!("approve");
        assert!(SignerFinancialWalletSetupSelectionV1::parse_json(&v.to_string()).is_err());
        v.as_object_mut().unwrap().remove("action");
        v.as_object_mut().unwrap().remove("birthday");
        assert!(SignerFinancialWalletSetupSelectionV1::parse_json(&v.to_string()).is_err());
    }
    #[test]
    fn selection_requires_exact_hashes_and_bounded_closed_config() {
        let mut s = selection();
        s.selection_nonce = "00".into();
        assert!(s.validate().is_err());
        let mut s = selection();
        s.wallet_setup_json = "x".repeat(32769);
        assert!(s.validate().is_err());
    }
}
