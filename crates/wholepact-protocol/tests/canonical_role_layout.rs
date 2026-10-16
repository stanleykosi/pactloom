#![cfg(feature = "synthetic-qualification")]
//! Canonical-layout checks over real, never-funded, unproved builder artifacts.
//!
//! `review_fixture` uses only its unproved construction path and IO finalization.
//! The latter creates dummy-spend signatures; these tests never invoke a prover,
//! real-owner signing, final TransactionExtractor, network access, or a wallet vault.
//! The broad policy is retained separately and remains necessary for review.

use pczt::{
    Pczt,
    roles::{redactor::Redactor, updater::Updater},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use wholepact_protocol::{
    canonical_role_layout::{
        produce_canonical_layout, validate_canonical_layout, verify_layout_transformation,
    },
    review::{ReviewPolicy, verify_review},
    synthetic::review_fixture,
};

fn encode(pczt: Pczt) -> Vec<u8> {
    pczt::v2::Pczt::try_from(pczt).unwrap().serialize()
}

// Inspect/mutate only fabricated upstream wire fields in memory. This does not
// deserialize or manufacture the opaque Wholepact evidence types under test.
fn wire(bytes: &[u8]) -> Value {
    serde_json::to_value(pczt::v2::Pczt::try_from(Pczt::parse(bytes).unwrap()).unwrap()).unwrap()
}

fn encode_wire(wire: Value) -> Vec<u8> {
    serde_json::from_value::<pczt::v2::Pczt>(wire)
        .unwrap()
        .serialize()
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn dummy_index(bytes: &[u8], policy: &ReviewPolicy) -> usize {
    let p = Pczt::parse(bytes).unwrap();
    (0..p.ironwood().actions().len())
        .find(|index| {
            !policy
                .inputs
                .iter()
                .any(|input| input.action_index == *index)
        })
        .expect("The three-output, two-input fixture must contain a dummy spend")
}

fn add_metadata_canaries(bytes: &[u8]) -> Vec<u8> {
    let p = Pczt::parse(bytes).unwrap();
    let count = p.ironwood().actions().len();
    encode(
        Updater::new(p)
            .update_ironwood_with(|mut bundle| {
                for index in 0..count {
                    bundle.update_action_with(index, |mut action| {
                        action.set_spend_zip32_derivation(
                            orchard::pczt::Zip32Derivation::parse(
                                [0x51; 32],
                                vec![0x8000_0020, 0x8000_0001, 0x8000_0000],
                            )
                            .unwrap(),
                        );
                        action.set_output_zip32_derivation(
                            orchard::pczt::Zip32Derivation::parse(
                                [0x52; 32],
                                vec![0x8000_0020, 0x8000_0001, 0x8000_0001],
                            )
                            .unwrap(),
                        );
                        action.set_output_user_address("synthetic-layout-address-canary".into());
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap()
            .finish(),
    )
}

#[test]
fn canonical_layout_has_exact_fields_and_preserves_independent_economic_review() {
    let f = review_fixture().unwrap();
    let original = add_metadata_canaries(&f.pczt_bytes);
    let before = verify_review(&original, &f.policy).unwrap();
    let artifact = produce_canonical_layout(&original, &f.policy).unwrap();
    let after = verify_review(artifact.bytes(), &f.policy).unwrap();

    assert_eq!(before.review_binding(), after.review_binding());
    assert_eq!(before.shielded_sighash(), after.shielded_sighash());
    assert_eq!(before.fee_zatoshis(), after.fee_zatoshis());
    assert_eq!(after.fee_zatoshis(), 15_000);
    assert_eq!(before.net_debits_zatoshis(), after.net_debits_zatoshis());
    assert_eq!(after.net_debits_zatoshis(), &[105_000, 210_000]);

    let mut expected = wire(&original);
    assert!(
        !expected["sapling"]["bsk"].is_null(),
        "Exercise empty Sapling binding context"
    );
    assert!(!expected["ironwood"]["bsk"].is_null());
    expected["sapling"] = Value::Null;
    expected["ironwood"]["bsk"] = Value::Null;
    let actions = expected["ironwood"]["actions"].as_array_mut().unwrap();
    let mut dummy_count = 0;
    for (index, action) in actions.iter_mut().enumerate() {
        assert!(!action["spend"]["zip32_derivation"].is_null());
        assert!(!action["output"]["zip32_derivation"].is_null());
        assert_eq!(
            action["output"]["user_address"],
            "synthetic-layout-address-canary"
        );
        assert!(action["spend"]["dummy_sk"].is_null());
        action["spend"]["zip32_derivation"] = Value::Null;
        action["output"]["zip32_derivation"] = Value::Null;
        action["output"]["user_address"] = Value::Null;
        action["output"]["ock"] = Value::Null;
        assert!(!action["spend"]["fvk"].is_null());
        if f.policy
            .inputs
            .iter()
            .any(|input| input.action_index == index)
        {
            assert!(action["spend"]["spend_auth_sig"].is_null());
            action["spend"]["fvk"] = Value::Null;
        } else {
            dummy_count += 1;
            assert_eq!(action["spend"]["value"], 0);
            assert!(!action["spend"]["alpha"].is_null());
            assert!(!action["spend"]["spend_auth_sig"].is_null());
        }
    }
    assert!(dummy_count > 0);
    // Complete structural equality also checks that openings, commitments,
    // ciphertexts, real witnesses and dummy FVK/alpha/signatures were preserved.
    assert!(wire(artifact.bytes()) == expected);
    assert!(artifact.bytes() == encode_wire(expected));
    assert!(artifact.bytes().len() < original.len());
    assert_eq!(
        artifact.evidence().artifact_digest(),
        digest(artifact.bytes())
    );
    assert_eq!(
        artifact.transformation().original_digest(),
        digest(&original)
    );
    assert_eq!(
        artifact.transformation().redacted_digest(),
        digest(artifact.bytes())
    );
    let evidence = validate_canonical_layout(artifact.bytes(), &f.policy).unwrap();
    assert_eq!(
        evidence.artifact_digest(),
        artifact.evidence().artifact_digest()
    );
    assert_eq!(
        evidence.policy_digest(),
        artifact.evidence().policy_digest()
    );

    let mut commitment = Sha256::new();
    commitment.update(b"wholepact:canonical-selected-evidence-layout:pczt-0.10.0-pre.1:v1\0");
    commitment.update(Sha256::digest(&original));
    commitment.update(Sha256::digest(artifact.bytes()));
    commitment.update(hex::decode(evidence.policy_digest()).unwrap());
    assert_eq!(
        artifact.transformation().commitment(),
        hex::encode(commitment.finalize())
    );
}

#[test]
fn canonical_layout_is_deterministic_idempotent_and_rejects_raw_broad_artifacts() {
    let f = review_fixture().unwrap();
    assert!(validate_canonical_layout(&f.pczt_bytes, &f.policy).is_err());
    let first = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let repeat = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let second = produce_canonical_layout(first.bytes(), &f.policy).unwrap();
    assert!(first.bytes() == repeat.bytes());
    assert!(first.bytes() == second.bytes());
    assert_eq!(
        first.evidence().artifact_digest(),
        second.evidence().artifact_digest()
    );
    assert_eq!(
        first.evidence().policy_digest(),
        second.evidence().policy_digest()
    );
    assert_eq!(
        first.transformation().commitment(),
        repeat.transformation().commitment()
    );
    assert_ne!(
        first.transformation().commitment(),
        second.transformation().commitment()
    );
    assert_eq!(
        second.transformation().original_digest(),
        first.evidence().artifact_digest()
    );
}

#[test]
fn canonical_layout_binds_exact_original_redacted_bytes_and_separate_policy() {
    let f = review_fixture().unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let enriched = add_metadata_canaries(&f.pczt_bytes);
    let other_origin =
        verify_layout_transformation(&enriched, artifact.bytes(), &f.policy).unwrap();
    // A different source may legitimately reduce to the same bytes. Its origin
    // hash and transformation commitment must still be distinct.
    assert_ne!(
        other_origin.original_digest(),
        artifact.transformation().original_digest()
    );
    assert_eq!(
        other_origin.redacted_digest(),
        artifact.transformation().redacted_digest()
    );
    assert_ne!(
        other_origin.commitment(),
        artifact.transformation().commitment()
    );

    let mut policies = Vec::new();
    let mut p = f.policy.clone();
    p.manifest_digest[0] ^= 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.participants[0].account_id.push_str("-changed");
    policies.push(p);
    let mut p = f.policy.clone();
    p.participants[0].maximum_net_debit_zatoshis += 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.participants[0].contribution_zatoshis += 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.participants[0].fee_share_zatoshis += 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.exact_fee_zatoshis += 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.outputs[0].memo[0] ^= 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.inputs[0].participant_index = 1;
    policies.push(p);
    let mut p = f.policy.clone();
    p.outputs[0].purpose = wholepact_protocol::review::OutputPurpose::Return {
        participant_index: 0,
    };
    policies.push(p);
    let mut p = f.policy.clone();
    p.participants[0].fvk = f.policy.participants[1].fvk.clone();
    p.participants[1].fvk = f.policy.participants[0].fvk.clone();
    policies.push(p);
    for policy in policies {
        let evidence = validate_canonical_layout(artifact.bytes(), &policy).unwrap();
        let changed =
            verify_layout_transformation(&f.pczt_bytes, artifact.bytes(), &policy).unwrap();
        assert_eq!(
            evidence.artifact_digest(),
            artifact.evidence().artifact_digest()
        );
        assert_ne!(
            evidence.policy_digest(),
            artifact.evidence().policy_digest()
        );
        assert_ne!(changed.commitment(), artifact.transformation().commitment());
    }

    let mut wrong_anchor = f.policy.clone();
    wrong_anchor.anchor[0] ^= 1;
    assert!(verify_layout_transformation(&f.pczt_bytes, artifact.bytes(), &wrong_anchor).is_err());
    let mut wrong_expiry = f.policy.clone();
    wrong_expiry.expiry_height += 1;
    assert!(verify_layout_transformation(&f.pczt_bytes, artifact.bytes(), &wrong_expiry).is_err());
}

#[test]
fn canonical_layout_rejects_each_missing_required_opening_or_commitment() {
    let f = review_fixture().unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let input = f.policy.inputs[0].action_index;
    let output = f.policy.outputs[0].action_index;
    for field in 0..13 {
        let index = if (8..=11).contains(&field) {
            output
        } else {
            input
        };
        let missing = encode(
            Redactor::new(Pczt::parse(artifact.bytes()).unwrap())
                .redact_ironwood_with(|mut bundle| {
                    bundle.redact_action(index, |mut action| match field {
                        0 => action.clear_cv_net(),
                        1 => action.clear_rcv(),
                        2 => action.clear_spend_recipient(),
                        3 => action.clear_spend_value(),
                        4 => action.clear_spend_rho(),
                        5 => action.clear_spend_rseed(),
                        6 => action.clear_spend_witness(),
                        7 => action.clear_spend_alpha(),
                        8 => action.clear_cmx(),
                        9 => action.clear_output_recipient(),
                        10 => action.clear_output_value(),
                        11 => action.clear_output_rseed(),
                        12 => (), // Anchor is a bundle field, cleared below.
                        _ => unreachable!(),
                    });
                    if field == 12 {
                        bundle.clear_anchor();
                    }
                })
                .finish(),
        );
        assert!(
            validate_canonical_layout(&missing, &f.policy).is_err(),
            "Missing field {field}"
        );
        assert!(
            produce_canonical_layout(&missing, &f.policy).is_err(),
            "Missing field {field}"
        );
        assert!(verify_layout_transformation(&f.pczt_bytes, &missing, &f.policy).is_err());
    }
}

#[test]
fn canonical_layout_rejects_wrong_encoding_and_trailing_bytes_on_every_entrypoint() {
    let f = review_fixture().unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let mut wrong_version = artifact.bytes().to_vec();
    wrong_version[4..8].copy_from_slice(&1_u32.to_le_bytes());
    let mut trailing = artifact.bytes().to_vec();
    trailing.push(0);
    for invalid in [wrong_version, trailing, b"not a PCZT".to_vec()] {
        assert!(validate_canonical_layout(&invalid, &f.policy).is_err());
        assert!(produce_canonical_layout(&invalid, &f.policy).is_err());
        assert!(verify_layout_transformation(&invalid, artifact.bytes(), &f.policy).is_err());
        assert!(verify_layout_transformation(&f.pczt_bytes, &invalid, &f.policy).is_err());
    }
}

#[test]
fn canonical_layout_is_not_an_economic_certificate_and_cannot_hide_ciphertext_changes() {
    let f = review_fixture().unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let output = f.policy.outputs[0].action_index;
    let mut corrupted = wire(artifact.bytes());
    let encrypted =
        corrupted["ironwood"]["actions"][output]["output"]["enc_ciphertext"]["Encrypted"]
            .as_array_mut()
            .unwrap();
    encrypted[0] = Value::from(encrypted[0].as_u64().unwrap() ^ 1);
    let corrupted = encode_wire(corrupted);
    // Presence and exact layout do not establish cryptographic consistency.
    let evidence = validate_canonical_layout(&corrupted, &f.policy).unwrap();
    assert_ne!(
        evidence.artifact_digest(),
        artifact.evidence().artifact_digest()
    );
    assert!(verify_review(&corrupted, &f.policy).is_err());
    assert!(verify_layout_transformation(&f.pczt_bytes, &corrupted, &f.policy).is_err());
    assert!(verify_layout_transformation(&corrupted, artifact.bytes(), &f.policy).is_err());
    assert!(verify_review(artifact.bytes(), &f.policy).is_ok());
}

#[test]
fn canonical_layout_rejects_owner_fvk_in_dummy_roles_and_real_signature_fields() {
    let f = review_fixture().unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let dummy = dummy_index(artifact.bytes(), &f.policy);
    let mut leaked = wire(artifact.bytes());
    leaked["ironwood"]["actions"][dummy]["spend"]["fvk"] =
        serde_json::to_value(f.policy.participants[0].fvk.to_bytes().to_vec()).unwrap();
    let leaked = encode_wire(leaked);
    assert!(produce_canonical_layout(&leaked, &f.policy).is_err());
    assert!(validate_canonical_layout(&leaked, &f.policy).is_err());

    let missing_dummy = encode(
        Redactor::new(Pczt::parse(artifact.bytes()).unwrap())
            .redact_ironwood_with(|mut bundle| {
                bundle.redact_action(dummy, |mut action| action.clear_spend_fvk());
            })
            .finish(),
    );
    assert!(produce_canonical_layout(&missing_dummy, &f.policy).is_err());
    assert!(validate_canonical_layout(&missing_dummy, &f.policy).is_err());

    let mut real_signature = wire(artifact.bytes());
    let existing_dummy_signature =
        real_signature["ironwood"]["actions"][dummy]["spend"]["spend_auth_sig"].clone();
    assert!(!existing_dummy_signature.is_null());
    real_signature["ironwood"]["actions"][f.policy.inputs[0].action_index]["spend"]["spend_auth_sig"] =
        existing_dummy_signature;
    let real_signature = encode_wire(real_signature);
    assert!(produce_canonical_layout(&real_signature, &f.policy).is_err());
    assert!(validate_canonical_layout(&real_signature, &f.policy).is_err());
}

#[test]
fn canonical_layout_rejects_proprietary_canaries_without_silent_sanitization() {
    let f = review_fixture().unwrap();
    for scope in 0..3 {
        let updater = Updater::new(Pczt::parse(&f.pczt_bytes).unwrap());
        let contaminated = if scope == 0 {
            updater
                .update_global_with(|mut global| {
                    global.set_proprietary("synthetic-layout-canary".into(), vec![0x53; 32]);
                })
                .finish()
        } else {
            updater
                .update_ironwood_with(|mut bundle| {
                    bundle.update_action_with(0, |mut action| {
                        if scope == 1 {
                            action.set_spend_proprietary(
                                "synthetic-layout-canary".into(),
                                vec![0x54; 32],
                            );
                        } else {
                            action.set_output_proprietary(
                                "synthetic-layout-canary".into(),
                                vec![0x55; 32],
                            );
                        }
                        Ok(())
                    })
                })
                .unwrap()
                .finish()
        };
        let contaminated = encode(contaminated);
        assert!(wholepact_protocol::inspect_candidate(&contaminated).is_err());
        assert!(produce_canonical_layout(&contaminated, &f.policy).is_err());
        assert!(validate_canonical_layout(&contaminated, &f.policy).is_err());
    }
}
