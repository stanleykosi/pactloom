//! Read-only inspection of an exact own-signature return.
//!
//! The caller retains the exact bytes that passed local own-effects inspection.
//! A returned PCZT may add signatures only at that inspection's selected own indices.
//! Every other byte, including proof material and other owners' signatures, must
//! survive normalization unchanged. This is neither proof verification nor online
//! admission, complete own-input coverage, authenticated transport, consent,
//! release authority, or settlement.
//! No signing API is used and no signed artifact is exported by this module.

use crate::{canonical_role_layout::LayoutTransformation, own_effects::OwnEffectsInspection};
use pczt::{
    Pczt,
    roles::{
        redactor::Redactor,
        verifier::{OrchardError, Verifier},
    },
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const RETURN_DOMAIN: &[u8] = b"wholepact:exact-own-signature-return:pczt-0.10.0-pre.1:v1\0";

/// Local signature/delta evidence with no public constructor or deserializer.
///
/// The commitment binds the exact reviewed and returned artifacts, the local
/// own-effects policy, the shielded sighash, and the exact selected-own-action list.
/// It confers no permission to sign, export, combine, submit, or claim payment.
/// Deliberately contains no signed bytes, signatures, keys, or issuer identity.
pub struct OpaqueVerifiedReturn {
    reviewed_artifact_digest: String,
    returned_artifact_digest: String,
    policy_digest: String,
    shielded_sighash: String,
    own_action_indices: Vec<usize>,
    commitment: String,
    layout_origin_digest: Option<String>,
    layout_transformation_commitment: Option<String>,
}

impl OpaqueVerifiedReturn {
    pub fn reviewed_artifact_digest(&self) -> &str {
        &self.reviewed_artifact_digest
    }
    pub fn returned_artifact_digest(&self) -> &str {
        &self.returned_artifact_digest
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn shielded_sighash(&self) -> &str {
        &self.shielded_sighash
    }
    pub fn own_action_indices(&self) -> &[usize] {
        &self.own_action_indices
    }
    pub fn commitment(&self) -> &str {
        &self.commitment
    }
    pub fn layout_origin_digest(&self) -> Option<&str> {
        self.layout_origin_digest.as_deref()
    }
    pub fn layout_transformation_commitment(&self) -> Option<&str> {
        self.layout_transformation_commitment.as_deref()
    }
}

struct BoundLayout {
    original: [u8; 32],
    redacted: [u8; 32],
    commitment: [u8; 32],
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn decode_digest(value: &str) -> Result<[u8; 32], String> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Inspection digest must be 32-byte lowercase hexadecimal",
    )?;
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "Invalid inspection digest")?;
    Ok(bytes)
}

fn parse_candidate(bytes: &[u8]) -> Result<Pczt, String> {
    // This performs allocation-free profile bounds before upstream parsing,
    // followed by exact v2 re-encoding and the narrow testnet candidate checks.
    crate::inspect_candidate(bytes)?;
    Pczt::parse(bytes).map_err(|_| "Invalid exact-return PCZT".into())
}

// Structural delta check only. It deliberately cannot create verified-return
// evidence; the public entry point also checks the opaque inspection and verifies
// each own signature using the maintained cryptographic verifier below.
fn require_exact_signature_delta(
    original_bytes: &[u8],
    original: &Pczt,
    returned: &Pczt,
    own_indices: &[usize],
) -> Result<(), String> {
    require(
        !own_indices.is_empty() && own_indices.len() <= crate::bounded::MAX_ACTIONS,
        "Own action list is empty or exceeds the profile bound",
    )?;
    let mut seen = BTreeSet::new();
    for &index in own_indices {
        require(seen.insert(index), "Duplicate own action index")?;
        let original_action = original
            .ironwood()
            .actions()
            .get(index)
            .ok_or("Own action index outside original artifact")?;
        let returned_action = returned
            .ironwood()
            .actions()
            .get(index)
            .ok_or("Own action index outside returned artifact")?;
        require(
            original_action.spend().spend_auth_sig().is_none(),
            "Original reviewed own actions must be unsigned",
        )?;
        require(
            returned_action.spend().spend_auth_sig().is_some(),
            "Returned artifact is missing an own signature",
        )?;
    }
    let normalized = Redactor::new(returned.clone())
        .redact_ironwood_with(|mut bundle| {
            for &index in own_indices {
                bundle.redact_action(index, |mut action| action.clear_spend_auth_sig());
            }
        })
        .finish();
    let encoded = pczt::v2::Pczt::try_from(normalized)
        .map_err(|_| "Unencodable exact-return normalization")?
        .serialize();
    require(
        encoded == original_bytes,
        "Returned artifact changed fields outside the exact own-signature set",
    )
}

fn verify_own_signatures(
    returned: Pczt,
    own_indices: &[usize],
    sighash: &[u8; 32],
) -> Result<(), String> {
    Verifier::new(returned)
        .with_ironwood::<String, _>(|bundle| {
            for &index in own_indices {
                let spend = bundle
                    .actions()
                    .get(index)
                    .ok_or_else(|| OrchardError::Custom("Own signature index missing".into()))?
                    .spend();
                let signature = spend
                    .spend_auth_sig()
                    .as_ref()
                    .ok_or_else(|| OrchardError::Custom("Own signature missing".into()))?;
                spend.rk().verify(sighash, signature).map_err(|_| {
                    OrchardError::Custom("Own spend signature verification failed".into())
                })?;
            }
            Ok(())
        })
        // Avoid exposing parsed private fields in error reports.
        .map_err(|_| "Returned own signature verification failed")?;
    Ok(())
}

fn return_commitment(
    original: &[u8; 32],
    returned: &[u8; 32],
    policy: &[u8; 32],
    sighash: &[u8; 32],
    own_indices: &[usize],
    layout: Option<&BoundLayout>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(RETURN_DOMAIN);
    hash.update(original);
    hash.update(returned);
    hash.update(policy);
    hash.update(sighash);
    hash.update((own_indices.len() as u64).to_le_bytes());
    for &index in own_indices {
        hash.update((index as u64).to_le_bytes());
    }
    match layout {
        None => hash.update([0]),
        Some(layout) => {
            hash.update([1]);
            hash.update(layout.original);
            hash.update(layout.redacted);
            hash.update(layout.commitment);
        }
    }
    hex::encode(hash.finalize())
}

/// Require an exact return adding signatures at all and only the inspection's
/// selected own-action indices, then cryptographically verify every one against
/// the reviewed shielded sighash. Other signatures and all other fields must be
/// unchanged. This does not establish complete account input coverage.
///
/// `inspection` must have been obtained by local own-effects verification of the
/// exact original bytes. An imported report or a matching human-readable summary
/// cannot replace it. Neither successful signature verification nor this opaque
/// result establishes proof validity, chain freshness, release consent, or online
/// admission. The original and returned byte slices are never modified.
pub fn inspect_exact_own_signature_return(
    original_reviewed_bytes: &[u8],
    returned_bytes: &[u8],
    inspection: &OwnEffectsInspection,
) -> Result<OpaqueVerifiedReturn, String> {
    inspect_return(original_reviewed_bytes, returned_bytes, inspection, None)
}

/// Additionally retain a previously checked immutable original-to-layout link.
///
/// Only an opaque `LayoutTransformation` is accepted, and its redacted digest
/// must identify these exact reviewed bytes. Its original digest is bound as a
/// distinct provenance value, never substituted for the reviewed-byte digest.
/// This consumes no broad multi-owner policy at the recipient and does not
/// reclassify structural layout evidence as authentication or disclosure consent.
pub fn inspect_exact_own_signature_return_with_layout(
    original_reviewed_bytes: &[u8],
    returned_bytes: &[u8],
    inspection: &OwnEffectsInspection,
    transformation: &LayoutTransformation,
) -> Result<OpaqueVerifiedReturn, String> {
    inspect_return(
        original_reviewed_bytes,
        returned_bytes,
        inspection,
        Some(transformation),
    )
}

fn inspect_return(
    original_reviewed_bytes: &[u8],
    returned_bytes: &[u8],
    inspection: &OwnEffectsInspection,
    transformation: Option<&LayoutTransformation>,
) -> Result<OpaqueVerifiedReturn, String> {
    let original = parse_candidate(original_reviewed_bytes)?;
    let original_digest = digest(original_reviewed_bytes);
    require(
        decode_digest(inspection.artifact_digest())? == original_digest,
        "Own-effects inspection belongs to different reviewed bytes",
    )?;
    let layout = transformation
        .map(|transformation| -> Result<BoundLayout, String> {
            let redacted = decode_digest(transformation.redacted_digest())?;
            require(
                redacted == original_digest,
                "Layout transformation belongs to different reviewed bytes",
            )?;
            Ok(BoundLayout {
                original: decode_digest(transformation.original_digest())?,
                redacted,
                commitment: decode_digest(transformation.commitment())?,
            })
        })
        .transpose()?;
    let policy = decode_digest(inspection.policy_digest())?;
    let sighash = decode_digest(inspection.shielded_sighash())?;
    let returned = parse_candidate(returned_bytes)?;
    let own_indices = inspection.own_action_indices();
    require_exact_signature_delta(original_reviewed_bytes, &original, &returned, own_indices)?;
    verify_own_signatures(returned, own_indices, &sighash)?;
    let returned_digest = digest(returned_bytes);
    Ok(OpaqueVerifiedReturn {
        reviewed_artifact_digest: hex::encode(original_digest),
        returned_artifact_digest: hex::encode(returned_digest),
        policy_digest: hex::encode(policy),
        shielded_sighash: hex::encode(sighash),
        own_action_indices: own_indices.to_vec(),
        commitment: return_commitment(
            &original_digest,
            &returned_digest,
            &policy,
            &sighash,
            own_indices,
            layout.as_ref(),
        ),
        layout_origin_digest: layout.as_ref().map(|layout| hex::encode(layout.original)),
        layout_transformation_commitment: layout.map(|layout| hex::encode(layout.commitment)),
    })
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    #[test]
    fn digest_decoder_rejects_noncanonical_or_wrong_length_hex() {
        assert_eq!(decode_digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        for invalid in [
            "AB".repeat(32),
            "0".repeat(63),
            "0".repeat(65),
            "gg".repeat(32),
        ] {
            assert!(decode_digest(&invalid).is_err());
        }
    }

    #[test]
    fn return_commitment_binds_every_exact_artifact_policy_and_layout_field() {
        let base = return_commitment(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[0, 2], None);
        for variant in [
            return_commitment(&[9; 32], &[2; 32], &[3; 32], &[4; 32], &[0, 2], None),
            return_commitment(&[1; 32], &[9; 32], &[3; 32], &[4; 32], &[0, 2], None),
            return_commitment(&[1; 32], &[2; 32], &[9; 32], &[4; 32], &[0, 2], None),
            return_commitment(&[1; 32], &[2; 32], &[3; 32], &[9; 32], &[0, 2], None),
            return_commitment(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[0], None),
            return_commitment(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[2, 0], None),
        ] {
            assert_ne!(base, variant);
        }
        let mut layout = BoundLayout {
            original: [5; 32],
            redacted: [1; 32],
            commitment: [6; 32],
        };
        let linked = return_commitment(
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 32],
            &[0, 2],
            Some(&layout),
        );
        assert_ne!(base, linked);
        layout.original[0] ^= 1;
        assert_ne!(
            linked,
            return_commitment(
                &[1; 32],
                &[2; 32],
                &[3; 32],
                &[4; 32],
                &[0, 2],
                Some(&layout)
            )
        );
        layout.original[0] ^= 1;
        layout.redacted[0] ^= 1;
        assert_ne!(
            linked,
            return_commitment(
                &[1; 32],
                &[2; 32],
                &[3; 32],
                &[4; 32],
                &[0, 2],
                Some(&layout)
            )
        );
        layout.redacted[0] ^= 1;
        layout.commitment[0] ^= 1;
        assert_ne!(
            linked,
            return_commitment(
                &[1; 32],
                &[2; 32],
                &[3; 32],
                &[4; 32],
                &[0, 2],
                Some(&layout)
            )
        );
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod normalization_tests {
    use super::*;
    use serde_json::{Value, json};

    // These helpers fabricate only upstream wire data. They never construct an
    // OwnEffectsInspection or OpaqueVerifiedReturn, sign an own input, or prove.
    fn wire(bytes: &[u8]) -> Value {
        serde_json::to_value(pczt::v2::Pczt::try_from(Pczt::parse(bytes).unwrap()).unwrap())
            .unwrap()
    }
    fn encode(wire: Value) -> Vec<u8> {
        serde_json::from_value::<pczt::v2::Pczt>(wire)
            .unwrap()
            .serialize()
    }
    fn add_fabricated_signatures(bytes: &[u8], indices: &[usize]) -> Vec<u8> {
        let mut value = wire(bytes);
        for &index in indices {
            value["ironwood"]["actions"][index]["spend"]["spend_auth_sig"] =
                json!(vec![0xa7_u8; 64]);
        }
        encode(value)
    }
    fn check(original: &[u8], returned: &[u8], indices: &[usize]) -> Result<(), String> {
        let parsed_original = parse_candidate(original)?;
        let parsed_returned = parse_candidate(returned)?;
        require_exact_signature_delta(original, &parsed_original, &parsed_returned, indices)
    }

    #[test]
    fn normalization_preserves_existing_nonown_signatures_exactly() {
        let fixture = crate::synthetic::review_fixture().unwrap();
        let own = fixture.policy.inputs[0].action_index;
        let foreign = fixture.policy.inputs[1].action_index;
        let original = add_fabricated_signatures(&fixture.pczt_bytes, &[foreign]);
        let returned = add_fabricated_signatures(&original, &[own]);
        assert!(check(&original, &returned, &[own]).is_ok());
        // The structural helper accepts a fabricated own signature, but it is
        // explicitly not the public cryptographic verification boundary.
        let sighash = [0; 32];
        assert!(
            verify_own_signatures(parse_candidate(&returned).unwrap(), &[own], &sighash).is_err()
        );
        for replacement in [Value::Null, json!(vec![0x55_u8; 64])] {
            let mut changed = wire(&returned);
            changed["ironwood"]["actions"][foreign]["spend"]["spend_auth_sig"] = replacement;
            assert!(check(&original, &encode(changed), &[own]).is_err());
        }
        let original = fixture.pczt_bytes;
        let returned = add_fabricated_signatures(&original, &[own, foreign]);
        assert!(check(&original, &returned, &[own]).is_err());
    }

    #[test]
    fn normalization_rejects_missing_preexisting_duplicate_or_out_of_range_own_signatures() {
        let fixture = crate::synthetic::review_fixture().unwrap();
        let indices = fixture
            .policy
            .inputs
            .iter()
            .map(|input| input.action_index)
            .collect::<Vec<_>>();
        let original = fixture.pczt_bytes;
        let complete = add_fabricated_signatures(&original, &indices);
        assert!(check(&original, &complete, &indices).is_ok());
        assert!(check(&original, &original, &indices).is_err());
        let partial = add_fabricated_signatures(&original, &indices[..1]);
        assert!(check(&original, &partial, &indices).is_err());
        assert!(check(&complete, &complete, &indices).is_err());
        assert!(check(&original, &complete, &[]).is_err());
        assert!(check(&original, &complete, &[indices[0], indices[0]]).is_err());
        assert!(check(&original, &complete, &[usize::MAX]).is_err());
        assert!(check(&original, &complete, &vec![0; 65]).is_err());
    }

    #[test]
    fn normalization_rejects_every_other_field_change_including_unsigned_metadata() {
        let fixture = crate::synthetic::review_fixture().unwrap();
        let own = fixture.policy.inputs[0].action_index;
        let original = fixture.pczt_bytes;
        let returned = add_fabricated_signatures(&original, &[own]);
        let baseline = wire(&returned);
        let mut variants = Vec::new();
        let mut changed = baseline.clone();
        changed["global"]["expiry_height"] = json!(141);
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["anchor"] = json!(vec![0_u8; 32]);
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["zkproof"] = json!([1, 2, 3]);
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["bsk"] = Value::Null;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["actions"][own]["spend"]["witness"] = Value::Null;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["actions"][own]["spend"]["alpha"] = Value::Null;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["actions"][own]["output"]["user_address"] =
            json!("unreviewed-metadata");
        variants.push(changed);
        let mut changed = baseline.clone();
        changed["ironwood"]["actions"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        variants.push(changed);
        for changed in variants {
            assert!(check(&original, &encode(changed), &[own]).is_err());
        }
        let parsed = Pczt::parse(&original).unwrap();
        let dummy = (0..parsed.ironwood().actions().len())
            .find(|&index| {
                parsed.ironwood().actions()[index]
                    .spend()
                    .spend_auth_sig()
                    .is_some()
            })
            .unwrap();
        let mut changed = baseline;
        changed["ironwood"]["actions"][dummy]["spend"]["spend_auth_sig"] = Value::Null;
        assert!(check(&original, &encode(changed), &[own]).is_err());
    }

    #[test]
    fn normalization_requires_bounded_canonical_candidates_on_both_sides() {
        let fixture = crate::synthetic::review_fixture().unwrap();
        let own = fixture.policy.inputs[0].action_index;
        let original = fixture.pczt_bytes;
        let returned = add_fabricated_signatures(&original, &[own]);
        let mut trailing = returned.clone();
        trailing.push(0);
        let mut wrong_version = returned.clone();
        wrong_version[4] = 1;
        for invalid in [
            vec![],
            vec![0; crate::bounded::MAX_BYTES + 1],
            trailing,
            wrong_version,
        ] {
            assert!(check(&original, &invalid, &[own]).is_err());
            assert!(check(&invalid, &returned, &[own]).is_err());
        }
    }
}
