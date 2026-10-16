//! Local inspection of external spend signatures, with optional encrypted result
//! and private transaction checkpoints. No signing, export, account authentication,
//! human approval or release capability is provided.
#[cfg(feature = "signed-retention")]
pub mod retention;

use crate::{
    proving::{ProvingLimits, verify_proved_candidate},
    review::{ReviewPolicy, verify_review},
};
use pczt::{
    Pczt,
    roles::{redactor::Redactor, signer::Signer},
};
use std::collections::BTreeSet;

/// Sensitive input; deliberately not Debug or serializable.
pub struct ExternalSignature {
    pub participant_index: usize,
    pub action_index: usize,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignatureInspection {
    pub verified_real_inputs: usize,
    pub required_real_inputs: usize,
    pub signatures_complete: bool,
    pub exact_candidate_preserved: bool,
    pub proof_verified: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
    pub chain_validated: bool,
}

/// Inspect a bounded complete set of received signatures against the immutable
/// saved proof. This does not authenticate application identities or consent.
/// The assembled PCZT is deliberately never returned to the caller.
pub fn inspect_external_signatures(
    base: &[u8],
    policy: &ReviewPolicy,
    expected_binding: &str,
    signatures: &[ExternalSignature],
    limits: ProvingLimits,
) -> Result<SignatureInspection, String> {
    assemble_external_signatures(base, policy, expected_binding, signatures, limits)
        .map(|(inspection, _)| inspection)
}

// Private: only the encrypted journal may retain the assembled candidate.
// No transaction extraction or public signed-byte accessor exists here.
fn assemble_external_signatures(
    base: &[u8],
    policy: &ReviewPolicy,
    expected_binding: &str,
    signatures: &[ExternalSignature],
    limits: ProvingLimits,
) -> Result<(SignatureInspection, Vec<u8>), String> {
    if signatures.len() > 64 {
        return Err("Signature limit exceeded".into());
    }
    verify_proved_candidate(base, policy, expected_binding, limits)?;
    let parsed = Pczt::parse(base).map_err(|_| "Candidate parse failed")?;
    if policy.inputs.iter().any(|i| {
        parsed.ironwood().actions()[i.action_index]
            .spend()
            .spend_auth_sig()
            .is_some()
    }) {
        return Err("Base checkpoint must have unsigned real inputs".into());
    }
    let mut seen = BTreeSet::new();
    let mut verifier =
        Signer::new(parsed).map_err(|_| "Signature verifier initialization failed")?;
    for s in signatures {
        if !seen.insert(s.action_index)
            || !policy.inputs.iter().any(|i| {
                i.action_index == s.action_index && i.participant_index == s.participant_index
            })
        {
            return Err("Duplicate, padding or incorrectly attributed signature".into());
        }
        verifier
            .apply_ironwood_signature(s.action_index, s.signature.into())
            .map_err(|_| "External spend signature verification failed")?;
    }
    let combined = verifier.finish();
    let encoded = pczt::v2::Pczt::try_from(combined.clone())
        .map_err(|_| "Candidate encoding failed")?
        .serialize();
    if verify_review(&encoded, policy)?.review_binding() != expected_binding {
        return Err("Signature intake changed review binding".into());
    }
    let normalized = Redactor::new(combined)
        .redact_ironwood_with(|mut bundle| {
            for index in &seen {
                bundle.redact_action(*index, |mut action| action.clear_spend_auth_sig());
            }
        })
        .finish();
    if pczt::v2::Pczt::try_from(normalized)
        .map_err(|_| "Candidate normalization failed")?
        .serialize()
        != base
    {
        return Err("Signature intake changed original candidate fields".into());
    }
    Ok((
        SignatureInspection {
            verified_real_inputs: seen.len(),
            required_real_inputs: policy.inputs.len(),
            signatures_complete: seen.len() == policy.inputs.len(),
            exact_candidate_preserved: true,
            proof_verified: true,
            authorization_allowed: false,
            distribution_allowed: false,
            chain_validated: false,
        },
        encoded,
    ))
}
