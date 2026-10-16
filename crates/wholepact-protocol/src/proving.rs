//! Bounded in-memory proving with economic review before and after the role change.
//!
//! No participant authorization, consent authentication, network operation or
//! persistence is performed. All supplied private data must already be permitted
//! for this local process. A service must run this CPU-intensive work in a bounded
//! worker; this synchronous API cannot enforce a wall-clock or process-memory limit.

use crate::review::{CryptographicReview, ReviewPolicy, verify_review};
use orchard::circuit::{Instance, OrchardCircuitVersion, ProvingKey, VerifyingKey};
use pczt::{
    Pczt,
    roles::{
        prover::Prover,
        redactor::Redactor,
        verifier::{OrchardError, Verifier},
    },
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};

/// Conservative proving envelope, separate from the parser's 64-action ceiling.
/// Larger owner/note counts are not a qualified proving service configuration.
pub const MAX_PROVING_ACTIONS: usize = 8;

#[derive(Clone, Copy)]
pub struct ProvingLimits {
    /// Must be in 1..=MAX_PROVING_ACTIONS. Padding actions count toward the limit.
    pub maximum_actions: usize,
}

/// Sensitive PCZT output: intentionally no Debug or serialization implementation.
pub struct ProvedCandidate {
    pub pczt_bytes: Vec<u8>,
    pub economic_review: CryptographicReview,
    pub proof_verified: bool,
    pub proof_bytes: usize,
    pub chain_validated: bool,
    pub distribution_allowed: bool,
    pub authorization_allowed: bool,
    /// This in-memory API has not established an encrypted durable checkpoint.
    pub encrypted_checkpoint_created: bool,
}

fn checked_review(
    bytes: &[u8],
    policy: &ReviewPolicy,
    expected_binding: &str,
    limits: ProvingLimits,
) -> Result<(Pczt, CryptographicReview), String> {
    if limits.maximum_actions == 0 || limits.maximum_actions > MAX_PROVING_ACTIONS {
        return Err("Proving action budget must be in 1..=8".into());
    }
    let structure = crate::inspect_candidate(bytes)?;
    if structure.actions > limits.maximum_actions {
        return Err("PCZT exceeds explicit proving action budget".into());
    }
    let review = verify_review(bytes, policy)?;
    if review.review_binding() != expected_binding {
        return Err("PCZT or policy differs from the expected reviewed binding".into());
    }
    let pczt = Pczt::parse(bytes).map_err(|_| "PCZT parse failed after bounded review")?;
    Ok((pczt, review))
}

fn verify_proof(pczt: Pczt, vk: &VerifyingKey) -> Result<usize, String> {
    let mut size = 0;
    Verifier::new(pczt)
        .with_ironwood::<String, _>(|bundle| {
            let error = OrchardError::Custom;
            let proof = bundle
                .zkproof()
                .as_ref()
                .ok_or_else(|| error("Ironwood proof missing".into()))?;
            size = proof.as_ref().len();
            if size != orchard::Proof::expected_proof_size(bundle.actions().len()) {
                return Err(error("Ironwood proof has noncanonical size".into()));
            }
            let instances = bundle
                .actions()
                .iter()
                .map(|action| {
                    Instance::from_parts(
                        *bundle.anchor(),
                        action.cv_net().clone(),
                        *action.spend().nullifier(),
                        action.spend().rk().clone(),
                        *action.output().cmx(),
                        *bundle.flags(),
                    )
                    .ok_or_else(|| error("Invalid proof instance".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            proof
                .verify(vk, &instances)
                .map_err(|_| error("Actual Ironwood proof verification failed".into()))?;
            Ok(())
        })
        .map_err(|_| "Ironwood proof verification failed")?;
    Ok(size)
}

/// Verify an existing proof and its exact economic review binding. This does not
/// validate spend authorizations or chain membership and never authorizes release.
pub fn verify_proved_candidate(
    bytes: &[u8],
    policy: &ReviewPolicy,
    expected_binding: &str,
    limits: ProvingLimits,
) -> Result<ProvedCandidate, String> {
    let (pczt, review) = checked_review(bytes, policy, expected_binding, limits)?;
    if pczt.ironwood().zkproof().is_none() {
        return Err("Ironwood proof missing".into());
    }
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let proof_bytes = verify_proof(pczt, &vk)?;
    Ok(ProvedCandidate {
        pczt_bytes: bytes.to_vec(),
        economic_review: review,
        proof_verified: true,
        proof_bytes,
        chain_validated: false,
        distribution_allowed: false,
        authorization_allowed: false,
        encrypted_checkpoint_created: false,
    })
}

/// Create exactly one Ironwood proof from already permitted witnesses. Requires
/// the caller's previously accepted review binding, checks economics before any
/// expensive proof, then verifies the proof and rechecks the complete binding.
/// Existing proofs are rejected, never silently overwritten; use the verify API.
/// The only permitted PCZT modification is addition of the Ironwood proof field.
pub fn prove_reviewed(
    bytes: &[u8],
    policy: &ReviewPolicy,
    expected_binding: &str,
    limits: ProvingLimits,
) -> Result<ProvedCandidate, String> {
    let (pczt, _review) = checked_review(bytes, policy, expected_binding, limits)?;
    if pczt.ironwood().zkproof().is_some() {
        return Err("Proof already present; verify the retained artifact instead".into());
    }
    let key = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(pczt)
        .create_ironwood_proof(UnwrapErr(SysRng), &key)
        .map_err(|_| "Ironwood proof construction failed")?
        .finish();
    let normalized = Redactor::new(proved.clone())
        .redact_ironwood_with(|mut b| b.clear_zkproof())
        .finish();
    let normalized = pczt::v2::Pczt::try_from(normalized)
        .map_err(|_| "PCZT v2 proof normalization failed")?
        .serialize();
    if normalized != bytes {
        return Err("Proving changed fields other than the permitted proof addition".into());
    }
    let proof_bytes = verify_proof(proved.clone(), &key.verifying_key())?;
    let pczt_bytes = pczt::v2::Pczt::try_from(proved)
        .map_err(|_| "PCZT v2 encoding failed")?
        .serialize();
    let (_, economic_review) = checked_review(&pczt_bytes, policy, expected_binding, limits)?;
    Ok(ProvedCandidate {
        pczt_bytes,
        economic_review,
        proof_verified: true,
        proof_bytes,
        chain_validated: false,
        distribution_allowed: false,
        authorization_allowed: false,
        encrypted_checkpoint_created: false,
    })
}
