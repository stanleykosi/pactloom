//! Wholepact protocol qualification, not a wallet or broadcast adapter.
//!
//! Default builds expose candid capability metadata only. The opt-in fixture uses
//! real upstream cryptography over a synthetic, non-chain commitment tree. It does
//! not qualify a production signer, live settlement, or participant identity.

use serde::Serialize;

#[cfg(feature = "durable-proposal")]
pub mod durable_proposal_v1;

#[cfg(feature = "authorization")]
pub mod authorization;

#[cfg(feature = "upstream")]
mod bounded;
#[cfg(feature = "upstream")]
pub mod canonical_role_layout;
#[cfg(feature = "upstream")]
pub mod own_effects;
#[cfg(feature = "construction")]
pub mod construction;
#[cfg(feature = "construction")]
pub mod review_manifest;
#[cfg(feature = "proving")]
pub mod proving;
#[cfg(feature = "upstream")]
pub mod review;

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolCapability {
    pub profile: &'static str,
    pub pczt_encoding: u32,
    pub transaction_version: u32,
    pub pool: &'static str,
    pub consensus_branch_id: &'static str,
    pub note_plaintext_version: u8,
    pub upstream_crypto_compiled: bool,
    pub synthetic_fixture_compiled: bool,
    pub live_settlement_supported: bool,
    pub production_policy_verifier_supported: bool,
    pub limitation: &'static str,
}

pub fn capability() -> ProtocolCapability {
    ProtocolCapability {
        profile: "ironwood-testnet-nu7-candidate",
        pczt_encoding: 2,
        transaction_version: 6,
        pool: "ironwood",
        consensus_branch_id: "0x77190ad9",
        note_plaintext_version: 3,
        upstream_crypto_compiled: cfg!(feature = "upstream"),
        synthetic_fixture_compiled: cfg!(feature = "synthetic-qualification"),
        live_settlement_supported: false,
        production_policy_verifier_supported: false,
        limitation: "Synthetic qualification only. No live signer, wallet sync, chain validation, network submission, or independent identity qualification.",
    }
}

/// A structural check is deliberately not called policy verification.
#[cfg(feature = "upstream")]
pub fn inspect_candidate(bytes: &[u8]) -> Result<CandidateStructure, String> {
    bounded::preflight(bytes)?;
    if bytes.len() < 8 || &bytes[..4] != b"PCZT" || bytes[4..8] != 2_u32.to_le_bytes() {
        return Err("Candidate requires PCZT encoding v2".into());
    }
    let p = pczt::Pczt::parse(bytes).map_err(|e| format!("PCZT parse: {e}"))?;
    let canonical = pczt::v2::Pczt::try_from(p.clone())
        .map_err(|e| format!("PCZT canonical encoding: {e:?}"))?
        .serialize();
    if canonical != bytes {
        return Err("Noncanonical PCZT encoding".into());
    }
    if *p.global().tx_version() != 6 || *p.global().consensus_branch_id() != 0x77190ad9 {
        return Err("Candidate requires transaction v6 and NU7".into());
    }
    if !p.transparent().inputs().is_empty()
        || !p.transparent().outputs().is_empty()
        || !p.sapling().spends().is_empty()
        || !p.sapling().outputs().is_empty()
        || !p.orchard().actions().is_empty()
        || p.ironwood().actions().is_empty()
    {
        return Err("Candidate requires an Ironwood-only transaction".into());
    }
    if *p.global().expiry_height() == 0 {
        return Err("Wholepact requires finite transaction expiry".into());
    }
    if *p.global().coin_type() != 1 {
        return Err("Mainnet is disabled: testnet coin type required".into());
    }
    Ok(CandidateStructure {
        actions: p.ironwood().actions().len(),
        expiry_height: *p.global().expiry_height(),
        policy_verified: false,
        chain_validated: false,
    })
}

#[cfg(feature = "upstream")]
#[derive(Debug, Serialize)]
pub struct CandidateStructure {
    pub actions: usize,
    pub expiry_height: u32,
    pub policy_verified: bool,
    pub chain_validated: bool,
}

#[cfg(feature = "synthetic-qualification")]
pub mod synthetic;

#[cfg(test)]
mod tests {
    #[test]
    fn capability_never_promises_live_settlement() {
        let c = super::capability();
        assert!(!c.live_settlement_supported);
        assert!(!c.production_policy_verifier_supported);
        assert_eq!(c.pool, "ironwood");
    }

    #[cfg(feature = "upstream")]
    #[test]
    fn inspection_rejects_unsupported_bytes() {
        assert!(super::inspect_candidate(b"not a PCZT").is_err());
        assert!(super::inspect_candidate(b"PCZT\x01\0\0\0").is_err());
    }
}

#[cfg(feature = "transaction-checkpoint")]
pub mod recipient_local;

#[cfg(feature = "upstream")]
pub mod offline_return;
