//! Immutable, proved-before-signing, two-owner proposal verification.
//!
//! A fixed proposal binds exact canonical unsigned and proved artifacts separately
//! from economic effects. In particular, the NU7 shielded sighash does not commit
//! to the anchor; a matching sighash is never permission to re-anchor or re-prove.
//! Only detached, explicitly attributed spend signatures may be added afterwards.
//! This module neither authenticates people nor grants consent, writer authority,
//! release, retention, chain freshness, signing, export, or settlement permission.

use crate::{
    authorization::SignatureInspection,
    construction::{InputActionMapping, OutputActionMapping},
    proving::{MAX_PROVING_ACTIONS, ProvingLimits, verify_proved_candidate},
    review::{CryptographicReview, ReviewPolicy, verify_review},
    review_manifest::{policy_fingerprint, verify_manifest_policy},
};
use pczt::{
    Pczt,
    roles::{redactor::Redactor, signer::Signer},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wholepact_core::Proposal;

const PROPOSAL_DOMAIN: &[u8] = b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0";
const MAPPING_DOMAIN: &[u8] = b"wholepact:durable-fixed-action-mapping:v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"wholepact:durable-fixed-detached-signature-set:v1\0";

/// Persistable metadata, not a verified token. Deserialization never constructs
/// `VerifiedFixedProposal`; reopening must verify the private artifacts and policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedProposalIdentityV1 {
    pub schema_version: u32,
    pub network_profile_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub revision: u32,
    pub expiry_height: u32,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub unsigned_artifact_digest: String,
    pub proved_artifact_digest: String,
    pub effects_commitment: String,
    pub policy_digest: String,
    pub review_binding: String,
    pub action_mapping_digest: String,
    pub anchor: String,
    pub proposal_binding: String,
}

/// Sensitive detached ingress. The attribution is an exact claim checked against
/// the locally verified manifest and policy, not evidence of sender authentication.
/// `proposal_binding` additionally binds the exact proof/anchor omitted by sighash.
/// No Debug/Serialize implementation: usable signatures must not enter reports.
pub struct DetachedSpendSignatureV1 {
    pub proposal_binding: String,
    pub participant_id: String,
    pub account_id: String,
    pub action_index: usize,
    pub signature: [u8; 64],
}

/// A successful local check, without a public constructor or deserializer.
/// The private broad-witness policy and proved bytes are retained immutably.
pub struct VerifiedFixedProposal {
    identity: FixedProposalIdentityV1,
    proposal: Proposal,
    policy: ReviewPolicy,
    review: CryptographicReview,
    proved_bytes: Vec<u8>,
}

/// A persistable evidence summary, not authority or a deserializable verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSetIdentityV1 {
    pub proposal_binding: String,
    pub signature_set_digest: String,
    pub signed_artifact_digest: String,
    pub signed_action_indices: Vec<usize>,
    pub participant_ids: Vec<String>,
}

/// No assembled bytes escape this inspection. Existing encrypted retention APIs
/// must separately enforce current retention consent and authenticated provenance.
pub struct VerifiedSignatureSetV1 {
    identity: SignatureSetIdentityV1,
    inspection: SignatureInspection,
}

impl VerifiedSignatureSetV1 {
    pub fn identity(&self) -> &SignatureSetIdentityV1 {
        &self.identity
    }

    pub fn inspection(&self) -> &SignatureInspection {
        &self.inspection
    }
}

impl VerifiedFixedProposal {
    /// Revalidate the complete manifest/policy, require a proof-only transition
    /// from exact unsigned bytes, and verify the actual retained proof. Padding
    /// signatures created by IO finalization are preserved, never stripped.
    /// Caller-created reports and `ProvedCandidate` booleans are not accepted.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        unsigned_bytes: &[u8],
        proved_bytes: &[u8],
        proposal: &Proposal,
        policy: &ReviewPolicy,
        input_actions: &[InputActionMapping],
        output_actions: &[OutputActionMapping],
        limits: ProvingLimits,
    ) -> Result<Self, String> {
        require(
            (1..=MAX_PROVING_ACTIONS).contains(&limits.maximum_actions),
            "Durable proving action budget must be in 1..=8",
        )?;
        require(
            proposal.manifest().participants.len() == 2 && policy.participants.len() == 2,
            "Durable fixed proposal requires exactly two owners",
        )?;
        require(
            proposal.manifest().agreement.recipients.len() == 1,
            "Durable fixed proposal requires exactly one recipient",
        )?;
        require(
            !policy.inputs.is_empty()
                && policy.inputs.len() <= crate::bounded::MAX_ACTIONS
                && !policy.outputs.is_empty()
                && policy.outputs.len() <= crate::bounded::MAX_ACTIONS,
            "Durable policy allocation limit exceeded",
        )?;
        wholepact_core::validate_claimed_accounting(proposal.manifest())
            .map_err(|_| "Durable manifest accounting is invalid")?;
        verify_manifest_policy(proposal, policy, input_actions, output_actions)?;
        for owner in 0..2 {
            require(
                policy.inputs.iter().any(|input| input.participant_index == owner),
                "Each durable owner must have a selected real input",
            )?;
        }
        let unsigned = parse_candidate(unsigned_bytes)?;
        let proved = parse_candidate(proved_bytes)?;
        require(
            unsigned.ironwood().actions().len() <= limits.maximum_actions
                && proved.ironwood().actions().len() <= limits.maximum_actions,
            "Durable proposal exceeds explicit proving action budget",
        )?;
        require_exact_proof_addition(unsigned_bytes, &unsigned, &proved, policy)?;
        let unsigned_review = verify_review(unsigned_bytes, policy)?;
        verify_retained_padding_signatures(&unsigned, policy)?;
        let verified = verify_proved_candidate(
            proved_bytes,
            policy,
            unsigned_review.review_binding(),
            limits,
        )?;
        let manifest = proposal.manifest();
        let mut identity = FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: manifest.agreement.network_profile_id.clone(),
            agreement_id: manifest.agreement.agreement_id.clone(),
            obligation_id: manifest.agreement.obligation_id.clone(),
            proposal_id: proposal.input().proposal_id.clone(),
            revision: manifest.agreement.revision,
            expiry_height: manifest.expiry_height,
            proposal_digest: proposal.proposal_digest().into(),
            manifest_digest: proposal.manifest_digest().into(),
            unsigned_artifact_digest: digest(unsigned_bytes),
            proved_artifact_digest: digest(proved_bytes),
            effects_commitment: verified.economic_review.shielded_sighash().into(),
            policy_digest: policy_fingerprint(policy),
            review_binding: verified.economic_review.review_binding().into(),
            action_mapping_digest: mapping_digest(input_actions, output_actions),
            anchor: hex::encode(policy.anchor),
            proposal_binding: String::new(),
        };
        identity.proposal_binding = proposal_binding(&identity);
        Ok(Self {
            identity,
            proposal: proposal.clone(),
            policy: policy.clone(),
            review: verified.economic_review,
            proved_bytes: verified.pczt_bytes,
        })
    }

    pub fn identity(&self) -> &FixedProposalIdentityV1 {
        &self.identity
    }

    /// Broad private witness material. This accessor grants no disclosure consent.
    pub fn private_proved_pczt_bytes(&self) -> &[u8] {
        &self.proved_bytes
    }

    /// Broad private viewing authority, never serialize or include it in reports.
    pub fn private_review_policy(&self) -> &ReviewPolicy {
        &self.policy
    }

    pub fn economic_review(&self) -> &CryptographicReview {
        &self.review
    }

    /// Match independently supplied current mappings to the frozen attribution.
    /// This also rechecks complete manifest/policy coverage before digest equality.
    pub fn verify_action_mappings(
        &self,
        input_actions: &[InputActionMapping],
        output_actions: &[OutputActionMapping],
    ) -> Result<(), String> {
        verify_manifest_policy(&self.proposal, &self.policy, input_actions, output_actions)?;
        require(
            mapping_digest(input_actions, output_actions) == self.identity.action_mapping_digest,
            "Action mappings differ from the exact fixed proposal",
        )
    }

    /// Verify a complete supplied set of accumulated detached contributions, which
    /// may be partial. Each call starts from the exact immutable proved artifact;
    /// there is no merge, proof replacement, re-anchoring or PCZT-return ingress.
    /// Duplicate actions are rejected, including identical duplicates. A durable
    /// journal must handle replay/conflict decisions before supplying this set.
    pub fn verify_detached_signatures(
        &self,
        signatures: &[DetachedSpendSignatureV1],
    ) -> Result<VerifiedSignatureSetV1, String> {
        require(
            signatures.len() <= self.policy.inputs.len(),
            "Detached signature set exceeds selected real inputs",
        )?;
        let mut ordered: Vec<_> = signatures.iter().collect();
        ordered.sort_by_key(|signature| signature.action_index);
        let mut seen = BTreeSet::new();
        let mut participants = BTreeSet::new();
        // Validate every attribution before applying any signature. None of the
        // caller's claimed participant indices or ownership flags are trusted.
        for signature in &ordered {
            require(
                signature.proposal_binding == self.identity.proposal_binding,
                "Detached signature belongs to a different fixed proposal",
            )?;
            let owner = self
                .proposal
                .manifest()
                .participants
                .iter()
                .position(|participant| {
                    participant.participant_id == signature.participant_id
                        && participant.account_id == signature.account_id
                })
                .ok_or("Detached signature owner attribution differs from manifest")?;
            require(
                seen.insert(signature.action_index)
                    && self.policy.inputs.iter().any(|input| {
                        input.action_index == signature.action_index
                            && input.participant_index == owner
                    }),
                "Duplicate, padding or incorrectly attributed detached signature",
            )?;
            participants.insert(signature.participant_id.clone());
        }
        let parsed = parse_candidate(&self.proved_bytes)?;
        let mut verifier =
            Signer::new(parsed).map_err(|_| "Detached signature verifier initialization failed")?;
        for signature in &ordered {
            // Pinned PCZT API verifies the signature against the actual action rk
            // and shielded sighash before accepting the single field addition.
            verifier
                .apply_ironwood_signature(signature.action_index, signature.signature.into())
                .map_err(|_| "Detached spend signature verification failed")?;
        }
        let assembled = verifier.finish();
        let encoded = encode(assembled.clone())?;
        require(
            verify_review(&encoded, &self.policy)?.review_binding()
                == self.identity.review_binding,
            "Detached signature intake changed the economic review",
        )?;
        let normalized = Redactor::new(assembled)
            .redact_ironwood_with(|mut bundle| {
                for &index in &seen {
                    bundle.redact_action(index, |mut action| action.clear_spend_auth_sig());
                }
            })
            .finish();
        require(
            encode(normalized)? == self.proved_bytes,
            "Detached signature intake changed immutable proved fields",
        )?;
        Ok(VerifiedSignatureSetV1 {
            identity: SignatureSetIdentityV1 {
                proposal_binding: self.identity.proposal_binding.clone(),
                signature_set_digest: signature_set_digest(&self.identity.proposal_binding, &ordered),
                signed_artifact_digest: digest(&encoded),
                signed_action_indices: seen.into_iter().collect(),
                participant_ids: participants.into_iter().collect(),
            },
            inspection: SignatureInspection {
                verified_real_inputs: signatures.len(),
                required_real_inputs: self.policy.inputs.len(),
                signatures_complete: signatures.len() == self.policy.inputs.len(),
                exact_candidate_preserved: true,
                proof_verified: true,
                authorization_allowed: false,
                distribution_allowed: false,
                chain_validated: false,
            },
        })
    }
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.into()) }
}

fn parse_candidate(bytes: &[u8]) -> Result<Pczt, String> {
    crate::inspect_candidate(bytes)?;
    Pczt::parse(bytes).map_err(|_| "Durable PCZT parse failed".into())
}

fn encode(pczt: Pczt) -> Result<Vec<u8>, String> {
    pczt::v2::Pczt::try_from(pczt)
        .map(|pczt| pczt.serialize())
        .map_err(|_| "Durable PCZT canonical encoding failed".into())
}

fn require_exact_proof_addition(
    unsigned_bytes: &[u8],
    unsigned: &Pczt,
    proved: &Pczt,
    policy: &ReviewPolicy,
) -> Result<(), String> {
    require(
        unsigned.ironwood().zkproof().is_none() && proved.ironwood().zkproof().is_some(),
        "Durable predecessor must be unproved and successor must contain a proof",
    )?;
    for input in &policy.inputs {
        for pczt in [unsigned, proved] {
            let action = pczt
                .ironwood()
                .actions()
                .get(input.action_index)
                .ok_or("Durable input action is outside the artifact")?;
            require(
                action.spend().spend_auth_sig().is_none(),
                "Durable proposal real inputs must be unsigned before proof acceptance",
            )?;
        }
    }
    let normalized = Redactor::new(proved.clone())
        .redact_ironwood_with(|mut bundle| bundle.clear_zkproof())
        .finish();
    require(
        encode(normalized)? == unsigned_bytes,
        "Durable proved artifact differs from its exact unsigned predecessor",
    )
}

fn verify_retained_padding_signatures(pczt: &Pczt, policy: &ReviewPolicy) -> Result<(), String> {
    let real: BTreeSet<_> = policy.inputs.iter().map(|input| input.action_index).collect();
    let mut verifier =
        Signer::new(pczt.clone()).map_err(|_| "Padding signature verifier initialization failed")?;
    for (index, action) in pczt.ironwood().actions().iter().enumerate() {
        if !real.contains(&index) {
            let signature = action
                .spend()
                .spend_auth_sig()
                .ok_or("Fixed proposal is missing a retained padding signature")?;
            verifier
                .apply_ironwood_signature(index, signature.into())
                .map_err(|_| "Fixed proposal retained padding signature is invalid")?;
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn mapping_digest(inputs: &[InputActionMapping], outputs: &[OutputActionMapping]) -> String {
    let mut hash = Sha256::new();
    hash.update(MAPPING_DOMAIN);
    let mut inputs: Vec<_> = inputs.iter().collect();
    inputs.sort_by(|left, right| left.input_id.cmp(&right.input_id));
    hash.update((inputs.len() as u64).to_le_bytes());
    for input in inputs {
        field(&mut hash, input.input_id.as_bytes());
        field(&mut hash, input.account_id.as_bytes());
        hash.update((input.action_index as u64).to_le_bytes());
    }
    let mut outputs: Vec<_> = outputs.iter().collect();
    outputs.sort_by(|left, right| left.output_id.cmp(&right.output_id));
    hash.update((outputs.len() as u64).to_le_bytes());
    for output in outputs {
        field(&mut hash, output.output_id.as_bytes());
        hash.update((output.action_index as u64).to_le_bytes());
    }
    hex::encode(hash.finalize())
}

fn proposal_binding(identity: &FixedProposalIdentityV1) -> String {
    let mut hash = Sha256::new();
    hash.update(PROPOSAL_DOMAIN);
    hash.update(identity.schema_version.to_le_bytes());
    hash.update(identity.revision.to_le_bytes());
    hash.update(identity.expiry_height.to_le_bytes());
    for value in [
        &identity.network_profile_id,
        &identity.agreement_id,
        &identity.obligation_id,
        &identity.proposal_id,
        &identity.proposal_digest,
        &identity.manifest_digest,
        &identity.unsigned_artifact_digest,
        &identity.proved_artifact_digest,
        &identity.effects_commitment,
        &identity.policy_digest,
        &identity.review_binding,
        &identity.action_mapping_digest,
        &identity.anchor,
    ] {
        field(&mut hash, value.as_bytes());
    }
    hex::encode(hash.finalize())
}

fn signature_set_digest(binding: &str, signatures: &[&DetachedSpendSignatureV1]) -> String {
    let mut hash = Sha256::new();
    hash.update(SIGNATURE_DOMAIN);
    field(&mut hash, binding.as_bytes());
    hash.update((signatures.len() as u64).to_le_bytes());
    for signature in signatures {
        field(&mut hash, signature.participant_id.as_bytes());
        field(&mut hash, signature.account_id.as_bytes());
        hash.update((signature.action_index as u64).to_le_bytes());
        hash.update(signature.signature);
    }
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests;
