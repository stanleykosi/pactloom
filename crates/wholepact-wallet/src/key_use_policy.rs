//! Feature-stable exact policy persisted in original native consent.
//! This value is not permission or observed chain evidence.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletKeyUseConfidence {
    /// Explicitly accepted provider trust; this is never consensus verification.
    TrustedSingleProviderSnapshot,
    /// Currently unsupported. Requiring this policy always fails closed.
    IndependentlyVerifiedConsensus,
    /// Public never-funded local qualification only. Never accepted by the TLS
    /// provider profile, even in a binary built with synthetic qualification.
    SyntheticNeverChainEvidence,
}

/// Exact policy must be shown and bound into the native original authorization.
/// Supplying this record does not authenticate that approval. There is no default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletKeyUsePolicy {
    pub confidence: WalletKeyUseConfidence,
    pub source_id: String,
    pub endpoint: String,
    pub maximum_observation_age_seconds: u32,
    pub minimum_confirmations: u32,
    pub minimum_expiry_margin_blocks: u32,
}
