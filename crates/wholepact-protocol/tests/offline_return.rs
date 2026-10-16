#![cfg(feature = "synthetic-qualification")]
//! Exact-return rejection tests over never-funded, unproved in-memory fixtures.
//!
//! `review_fixture` builds notes and finalizes IO, which creates dummy-spend
//! signatures only. These tests never invoke real-owner signing, a prover, final
//! transaction extraction, or network access. Fabricated/copied signatures are
//! adversarial inputs, never accepted authorization evidence. A positive public
//! cryptographic own-return test remains unavailable without a retained valid
//! fixture; private normalization-helper positives do not fill that gap.

use pczt::Pczt;
use serde_json::{Value, json};
use wholepact_protocol::{
    canonical_role_layout::{CanonicalLayoutArtifact, produce_canonical_layout},
    offline_return::{
        inspect_exact_own_signature_return, inspect_exact_own_signature_return_with_layout,
    },
    own_effects::{
        OwnEffectsPolicy, OwnInputExpectation, OwnOutputExpectation, OwnOutputPurpose,
        verify_own_effects,
    },
    review::OutputPurpose,
    synthetic::review_fixture,
};

fn fixture() -> (CanonicalLayoutArtifact, OwnEffectsPolicy) {
    let fixture = review_fixture().unwrap();
    // Broad fixture policy is used only on the producer side of layout reduction.
    let artifact = produce_canonical_layout(&fixture.pczt_bytes, &fixture.policy).unwrap();
    let own = &fixture.policy.participants[0];
    let policy = OwnEffectsPolicy {
        account_id: own.account_id.clone(),
        own_fvk: own.fvk.clone(),
        manifest_digest: fixture.policy.manifest_digest,
        anchor: fixture.policy.anchor,
        expiry_height: fixture.policy.expiry_height,
        maximum_selected_net_debit_zatoshis: own.maximum_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: own.contribution_zatoshis + own.fee_share_zatoshis,
        declared_fee_share_zatoshis: own.fee_share_zatoshis,
        exact_transaction_fee_zatoshis: fixture.policy.exact_fee_zatoshis,
        own_inputs: fixture
            .policy
            .inputs
            .iter()
            .filter(|input| input.participant_index == 0)
            .map(|input| OwnInputExpectation {
                action_index: input.action_index,
                nullifier: input.nullifier,
                value_zatoshis: input.value_zatoshis,
            })
            .collect(),
        outputs: fixture
            .policy
            .outputs
            .iter()
            .map(|output| OwnOutputExpectation {
                action_index: output.action_index,
                receiver: output.receiver,
                value_zatoshis: output.value_zatoshis,
                memo: output.memo,
                purpose: match output.purpose {
                    OutputPurpose::Recipient => OwnOutputPurpose::Recipient,
                    OutputPurpose::Return {
                        participant_index: 0,
                    } => OwnOutputPurpose::OwnReturn,
                    OutputPurpose::Return { .. } => OwnOutputPurpose::PeerReturnUnverified,
                },
            })
            .collect(),
    };
    // No peer FVK is retained in the recipient's local policy or inspection.
    (artifact, policy)
}

fn wire(bytes: &[u8]) -> Value {
    serde_json::to_value(pczt::v2::Pczt::try_from(Pczt::parse(bytes).unwrap()).unwrap()).unwrap()
}

fn encode(wire: Value) -> Vec<u8> {
    serde_json::from_value::<pczt::v2::Pczt>(wire)
        .unwrap()
        .serialize()
}

fn put_signature(bytes: &[u8], index: usize, signature: Value) -> Vec<u8> {
    let mut value = wire(bytes);
    value["ironwood"]["actions"][index]["spend"]["spend_auth_sig"] = signature;
    encode(value)
}

fn dummy_index(bytes: &[u8]) -> usize {
    Pczt::parse(bytes)
        .unwrap()
        .ironwood()
        .actions()
        .iter()
        .position(|action| action.spend().spend_auth_sig().is_some())
        .expect("IO-finalized fixture has a signed dummy spend")
}

#[test]
fn exact_return_rejects_missing_fabricated_and_copied_dummy_signatures() {
    let (artifact, policy) = fixture();
    let original = artifact.bytes();
    let inspection = verify_own_effects(original, &policy).unwrap();
    let own = inspection.own_action_indices()[0];
    assert!(
        inspect_exact_own_signature_return(original, original, &inspection)
            .err()
            .unwrap()
            .contains("missing an own signature")
    );
    let dummy_signature =
        wire(original)["ironwood"]["actions"][dummy_index(original)]["spend"]["spend_auth_sig"]
            .clone();
    for signature in [
        json!(vec![0_u8; 64]),
        json!(vec![0xff_u8; 64]),
        dummy_signature,
    ] {
        let returned = put_signature(original, own, signature);
        let original_copy = original.to_vec();
        let returned_copy = returned.clone();
        assert_eq!(
            inspect_exact_own_signature_return(original, &returned, &inspection)
                .err()
                .unwrap(),
            "Returned own signature verification failed"
        );
        assert!(original == original_copy);
        assert!(returned == returned_copy);
    }
}

#[test]
fn exact_return_rejects_same_effects_but_different_reviewed_bytes() {
    let (artifact, policy) = fixture();
    let original = artifact.bytes();
    let inspection = verify_own_effects(original, &policy).unwrap();
    let mut changed = wire(original);
    changed["ironwood"]["actions"][0]["output"]["user_address"] =
        json!("same-effects-byte-substitution");
    let changed = encode(changed);
    let changed_inspection = verify_own_effects(&changed, &policy).unwrap();
    assert_eq!(
        inspection.shielded_sighash(),
        changed_inspection.shielded_sighash()
    );
    assert_ne!(
        inspection.artifact_digest(),
        changed_inspection.artifact_digest()
    );
    assert_eq!(
        inspect_exact_own_signature_return(&changed, &changed, &inspection)
            .err()
            .unwrap(),
        "Own-effects inspection belongs to different reviewed bytes"
    );
}

#[test]
fn exact_return_rejects_foreign_signature_additions_and_dummy_signature_changes() {
    let (artifact, policy) = fixture();
    let original = artifact.bytes();
    let inspection = verify_own_effects(original, &policy).unwrap();
    let own = inspection.own_action_indices()[0];
    let value = wire(original);
    let foreign = value["ironwood"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .find_map(|(index, action)| {
            (index != own
                && action["spend"]["value"]
                    .as_u64()
                    .is_some_and(|value| value > 0))
            .then_some(index)
        })
        .unwrap();
    let dummy = dummy_index(original);
    let returned = put_signature(original, own, json!(vec![0xa7_u8; 64]));
    for (index, replacement) in [
        (foreign, json!(vec![0xb3_u8; 64])),
        (dummy, Value::Null),
        (dummy, json!(vec![0xc5_u8; 64])),
    ] {
        let changed = put_signature(&returned, index, replacement);
        assert_eq!(
            inspect_exact_own_signature_return(original, &changed, &inspection)
                .err()
                .unwrap(),
            "Returned artifact changed fields outside the exact own-signature set"
        );
    }
}

#[test]
fn exact_return_rejects_anchor_proof_and_unsigned_metadata_substitution() {
    let (artifact, policy) = fixture();
    let original = artifact.bytes();
    let inspection = verify_own_effects(original, &policy).unwrap();
    let own = inspection.own_action_indices()[0];
    let returned = put_signature(original, own, json!(vec![0xa7_u8; 64]));
    let baseline = wire(&returned);
    let mut variants = Vec::new();
    let mut changed = baseline.clone();
    changed["ironwood"]["anchor"] = json!(vec![0_u8; 32]);
    variants.push(changed);
    let mut changed = baseline.clone();
    changed["ironwood"]["zkproof"] = json!([1, 2, 3]);
    variants.push(changed);
    let mut changed = baseline;
    changed["ironwood"]["actions"][own]["output"]["user_address"] = json!("unreviewed-metadata");
    variants.push(changed);
    for changed in variants {
        assert_eq!(
            inspect_exact_own_signature_return(original, &encode(changed), &inspection)
                .err()
                .unwrap(),
            "Returned artifact changed fields outside the exact own-signature set"
        );
    }
}

#[test]
fn layout_link_cannot_replace_the_exact_reviewed_artifact_digest() {
    let (artifact, policy) = fixture();
    let (other, _) = fixture();
    let inspection = verify_own_effects(artifact.bytes(), &policy).unwrap();
    assert_ne!(
        artifact.transformation().original_digest(),
        inspection.artifact_digest()
    );
    assert_eq!(
        artifact.transformation().redacted_digest(),
        inspection.artifact_digest()
    );
    assert_eq!(
        inspect_exact_own_signature_return_with_layout(
            artifact.bytes(),
            artifact.bytes(),
            &inspection,
            other.transformation(),
        )
        .err()
        .unwrap(),
        "Layout transformation belongs to different reviewed bytes"
    );
    // A correct structural link still cannot stand in for absent own signatures.
    assert!(
        inspect_exact_own_signature_return_with_layout(
            artifact.bytes(),
            artifact.bytes(),
            &inspection,
            artifact.transformation(),
        )
        .err()
        .unwrap()
        .contains("missing an own signature")
    );
}

#[test]
fn exact_return_rejects_unbounded_noncanonical_and_non_pczt_intake() {
    let (artifact, policy) = fixture();
    let inspection = verify_own_effects(artifact.bytes(), &policy).unwrap();
    let mut trailing = artifact.bytes().to_vec();
    trailing.push(0);
    for returned in [
        vec![0; 1_048_577],
        trailing,
        b"{\"verified\":true}".to_vec(),
    ] {
        assert!(
            inspect_exact_own_signature_return(artifact.bytes(), &returned, &inspection).is_err()
        );
    }
}
