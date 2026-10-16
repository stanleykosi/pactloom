//! Canonical selected-evidence layout for the pinned PCZT encoding.
//!
//! This is NOT recipient-minimal privacy qualification. Independent economic
//! checks still require a separately held policy containing every owner's FVK.
//! No offline bridge, setup, consent, proof verification or key-use is enabled.
//! The producer accepts only already bounded canonical candidates; unexpected
//! proprietary fields are rejected, not silently laundered by redaction.
use crate::review::{ReviewPolicy, policy_digest};
use pczt::{Pczt, roles::redactor::Redactor};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const LAYOUT: &[u8] = b"wholepact:canonical-selected-evidence-layout:pczt-0.10.0-pre.1:v1\0";

/// Structural evidence only; no public constructor or deserialization.
pub struct CanonicalLayoutEvidence {
    artifact_digest: String,
    policy_digest: String,
}
impl CanonicalLayoutEvidence {
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}
/// A checked deterministic byte transformation, not proof of consent or privacy.
pub struct LayoutTransformation {
    original_digest: String,
    redacted_digest: String,
    commitment: String,
}
impl LayoutTransformation {
    pub fn original_digest(&self) -> &str {
        &self.original_digest
    }
    pub fn redacted_digest(&self) -> &str {
        &self.redacted_digest
    }
    pub fn commitment(&self) -> &str {
        &self.commitment
    }
}
pub struct CanonicalLayoutArtifact {
    bytes: Vec<u8>,
    evidence: CanonicalLayoutEvidence,
    transformation: LayoutTransformation,
}
impl CanonicalLayoutArtifact {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn evidence(&self) -> &CanonicalLayoutEvidence {
        &self.evidence
    }
    pub fn transformation(&self) -> &LayoutTransformation {
        &self.transformation
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}

// Checks exact required field presence and the role partition independently of
// the redactor. It does not establish the truth of caller-supplied policy terms.
fn parse_roles(bytes: &[u8], policy: &ReviewPolicy) -> Result<Pczt, String> {
    crate::inspect_candidate(bytes)?;
    require(
        (2..=32).contains(&policy.participants.len()),
        "Ordinary multi-owner policy required",
    )?;
    require(
        !policy.inputs.is_empty()
            && policy.inputs.len() <= 64
            && !policy.outputs.is_empty()
            && policy.outputs.len() <= 64,
        "Invalid policy bounds",
    )?;
    let p = Pczt::parse(bytes).map_err(|_| "Invalid PCZT")?;
    require(
        *p.global().version_group_id() == 0xd884b698
            && *p.global().tx_modifiable() == 0
            && p.global().fallback_lock_time().unwrap_or(0) == 0,
        "Unsupported mutable transaction layout",
    )?;
    require(
        *p.global().expiry_height() == policy.expiry_height
            && policy.expiry_height < 500_000_000
            && *p.ironwood().anchor() == Some(policy.anchor)
            && *p.ironwood().flags() == 7,
        "Wrong expiry, anchor or flags",
    )?;
    let n = p.ironwood().actions().len();
    let mut inputs = BTreeSet::new();
    for i in &policy.inputs {
        require(
            i.action_index < n
                && i.participant_index < policy.participants.len()
                && i.value_zatoshis > 0
                && inputs.insert(i.action_index),
            "Invalid real input role",
        )?;
    }
    let mut outputs = BTreeSet::new();
    for o in &policy.outputs {
        require(
            o.action_index < n && o.value_zatoshis > 0 && outputs.insert(o.action_index),
            "Invalid real output role",
        )?;
    }
    let owner_keys = policy
        .participants
        .iter()
        .map(|p| p.fvk.to_bytes())
        .collect::<BTreeSet<_>>();
    require(
        owner_keys.len() == policy.participants.len(),
        "Duplicate owner viewing key",
    )?;
    for action in p.ironwood().actions() {
        require(
            action.cv_net().is_some() && action.output().cmx().is_some(),
            "Missing explicit commitments",
        )?;
    }
    use pczt::roles::verifier::{OrchardError, Verifier};
    Verifier::new(p.clone())
        .with_ironwood::<String, _>(|bundle| {
            let check = |v, message| require(v, message).map_err(OrchardError::Custom);
            for (index, action) in bundle.actions().iter().enumerate() {
                let spend = action.spend();
                let output = action.output();
                check(action.rcv().is_some(), "Missing value commitment opening")?;
                check(
                    spend.recipient().is_some()
                        && spend.value().is_some()
                        && spend.rho().is_some()
                        && spend.rseed().is_some()
                        && spend.alpha().is_some(),
                    "Missing selected spend evidence",
                )?;
                check(
                    output.recipient().is_some()
                        && output.value().is_some()
                        && output.rseed().is_some(),
                    "Missing selected output evidence",
                )?;
                if let Some(i) = policy.inputs.iter().find(|i| i.action_index == index) {
                    check(
                        spend.value().map(|v| v.inner()) == Some(i.value_zatoshis)
                            && spend.nullifier().to_bytes() == i.nullifier
                            && spend.witness().is_some(),
                        "Wrong selected input evidence",
                    )?;
                    check(
                        spend.spend_auth_sig().is_none(),
                        "Real authorization is outside this layout",
                    )?;
                } else {
                    check(
                        spend.value().map(|v| v.inner()) == Some(0),
                        "Unmapped nonzero input",
                    )?;
                    let fvk = spend
                        .fvk()
                        .as_ref()
                        .ok_or_else(|| OrchardError::Custom("Missing dummy viewing key".into()))?;
                    check(
                        !owner_keys.contains(&fvk.to_bytes()),
                        "Owner viewing key in dummy role",
                    )?;
                }
                if let Some(o) = policy.outputs.iter().find(|o| o.action_index == index) {
                    check(
                        output.value().map(|v| v.inner()) == Some(o.value_zatoshis)
                            && *output.recipient() == Some(o.receiver),
                        "Wrong selected output evidence",
                    )?;
                } else {
                    check(
                        output.value().map(|v| v.inner()) == Some(0),
                        "Unmapped nonzero output",
                    )?;
                }
            }
            Ok(())
        })
        .map_err(|_| "Invalid parsed role evidence")?;
    Ok(p)
}
fn transform(p: Pczt, policy: &ReviewPolicy) -> Result<Vec<u8>, String> {
    let p = Redactor::new(p)
        .redact_sapling_with(|mut b| {
            b.clear_bsk();
            b.clear_anchor();
        })
        .redact_ironwood_with(|mut b| {
            b.clear_bsk();
            b.redact_actions(|mut a| {
                a.clear_spend_zip32_derivation();
                a.clear_output_zip32_derivation();
                a.clear_output_user_address();
                a.clear_output_ock();
            });
            for i in &policy.inputs {
                b.redact_action(i.action_index, |mut a| a.clear_spend_fvk());
            }
        })
        .finish();
    Ok(pczt::v2::Pczt::try_from(p)
        .map_err(|_| "Unencodable layout")?
        .serialize())
}

/// Rejects excess fields rather than accepting and silently redacting them.
/// Economic/proof/ownership validation must remain separate mandatory gates.
pub fn validate_canonical_layout(
    bytes: &[u8],
    policy: &ReviewPolicy,
) -> Result<CanonicalLayoutEvidence, String> {
    let p = parse_roles(bytes, policy)?;
    require(
        transform(p, policy)? == bytes,
        "Noncanonical selected-evidence layout",
    )?;
    Ok(CanonicalLayoutEvidence {
        artifact_digest: digest(bytes),
        policy_digest: hex::encode(policy_digest(policy)),
    })
}
/// Produces an exact field-reduced representation. Does not prove its economics,
/// proof validity, authenticated ownership, disclosure permission or chain state.
pub fn produce_canonical_layout(
    bytes: &[u8],
    policy: &ReviewPolicy,
) -> Result<CanonicalLayoutArtifact, String> {
    let p = parse_roles(bytes, policy)?;
    let redacted = transform(p, policy)?;
    let evidence = validate_canonical_layout(&redacted, policy)?;
    let transformation = verify_layout_transformation(bytes, &redacted, policy)?;
    Ok(CanonicalLayoutArtifact {
        bytes: redacted,
        evidence,
        transformation,
    })
}
/// Recomputes the transformation from the exact original; supplied hashes alone
/// cannot pass. The commitment includes both byte hashes and the full policy
/// fingerprint. It is never an alias allowing one artifact hash to replace another.
pub fn verify_layout_transformation(
    original: &[u8],
    redacted: &[u8],
    policy: &ReviewPolicy,
) -> Result<LayoutTransformation, String> {
    let p = parse_roles(original, policy)?;
    let evidence = validate_canonical_layout(redacted, policy)?;
    require(
        transform(p, policy)? == redacted,
        "Different original or redacted bytes",
    )?;
    let original_digest = digest(original);
    let redacted_digest = evidence.artifact_digest;
    let mut h = Sha256::new();
    h.update(LAYOUT);
    h.update(Sha256::digest(original));
    h.update(Sha256::digest(redacted));
    h.update(policy_digest(policy));
    Ok(LayoutTransformation {
        original_digest,
        redacted_digest,
        commitment: hex::encode(h.finalize()),
    })
}
