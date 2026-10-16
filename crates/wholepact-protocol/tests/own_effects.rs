#![cfg(feature = "synthetic-qualification")]
//! Unproved in-memory fixtures only. IO finalization creates dummy signatures;
//! no real-owner signing, prover, final extraction or network is invoked.
use pczt::{Pczt, roles::redactor::Redactor};
use wholepact_protocol::{
    canonical_role_layout::produce_canonical_layout,
    own_effects::*,
    review::{OutputPurpose, verify_review},
    synthetic::review_fixture,
};
fn fixture() -> (Vec<u8>, OwnEffectsPolicy, String) {
    let f = review_fixture().unwrap();
    let broad = verify_review(&f.pczt_bytes, &f.policy).unwrap();
    let bytes = produce_canonical_layout(&f.pczt_bytes, &f.policy)
        .unwrap()
        .bytes()
        .to_vec();
    let p = &f.policy.participants[0];
    let policy = OwnEffectsPolicy {
        account_id: p.account_id.clone(),
        own_fvk: p.fvk.clone(),
        manifest_digest: f.policy.manifest_digest,
        anchor: f.policy.anchor,
        expiry_height: f.policy.expiry_height,
        maximum_selected_net_debit_zatoshis: p.maximum_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: broad.net_debits_zatoshis()[0],
        declared_fee_share_zatoshis: p.fee_share_zatoshis,
        exact_transaction_fee_zatoshis: f.policy.exact_fee_zatoshis,
        own_inputs: f
            .policy
            .inputs
            .iter()
            .filter(|i| i.participant_index == 0)
            .map(|i| OwnInputExpectation {
                action_index: i.action_index,
                nullifier: i.nullifier,
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        outputs: f
            .policy
            .outputs
            .iter()
            .map(|o| OwnOutputExpectation {
                action_index: o.action_index,
                receiver: o.receiver,
                value_zatoshis: o.value_zatoshis,
                memo: o.memo,
                purpose: match o.purpose {
                    OutputPurpose::Recipient => OwnOutputPurpose::Recipient,
                    OutputPurpose::Return {
                        participant_index: 0,
                    } => OwnOutputPurpose::OwnReturn,
                    OutputPurpose::Return { .. } => OwnOutputPurpose::PeerReturnUnverified,
                },
            })
            .collect(),
    };
    (bytes, policy, broad.shielded_sighash().into())
}
fn encode(p: Pczt) -> Vec<u8> {
    pczt::v2::Pczt::try_from(p).unwrap().serialize()
}
#[test]
fn selected_own_effects_verify_without_any_peer_fvk_in_policy() {
    let (bytes, p, sighash) = fixture();
    let e = verify_own_effects(&bytes, &p).unwrap();
    assert_eq!(e.selected_net_debit_zatoshis(), 105_000);
    assert_eq!(e.own_return_zatoshis(), 95_000);
    assert_eq!(e.transaction_fee_zatoshis(), 15_000);
    assert_eq!(e.declared_fee_share_zatoshis(), 5_000);
    assert_eq!(e.shielded_sighash(), sighash);
    use sha2::{Digest, Sha256};
    assert_eq!(e.artifact_digest(), hex::encode(Sha256::digest(&bytes)));
    assert_eq!(
        e.own_action_indices(),
        p.own_inputs
            .iter()
            .map(|i| i.action_index)
            .collect::<Vec<_>>()
    );
}
#[test]
fn selected_own_effects_reject_embedded_real_viewing_keys() {
    let (bytes, p, _) = fixture();
    let mut wire =
        serde_json::to_value(pczt::v2::Pczt::try_from(Pczt::parse(&bytes).unwrap()).unwrap())
            .unwrap();
    let index = p.own_inputs[0].action_index;
    wire["ironwood"]["actions"][index]["spend"]["fvk"] =
        serde_json::to_value(p.own_fvk.to_bytes().to_vec()).unwrap();
    let contaminated = serde_json::from_value::<pczt::v2::Pczt>(wire)
        .unwrap()
        .serialize();
    assert!(verify_own_effects(&contaminated, &p).is_err());
}
#[test]
fn selected_own_effects_reject_changed_input_expectations_and_missing_evidence() {
    let (bytes, p, _) = fixture();
    for field in 0..4 {
        let mut changed = p.clone();
        match field {
            0 => changed.own_inputs[0].nullifier[0] ^= 1,
            1 => changed.own_inputs[0].value_zatoshis += 1,
            2 => changed.own_inputs.push(changed.own_inputs[0].clone()),
            _ => changed.anchor[0] ^= 1,
        };
        assert!(verify_own_effects(&bytes, &changed).is_err());
    }
    for field in 0..4 {
        let missing = encode(
            Redactor::new(Pczt::parse(&bytes).unwrap())
                .redact_ironwood_with(|mut b| {
                    b.redact_action(p.own_inputs[0].action_index, |mut a| match field {
                        0 => a.clear_spend_witness(),
                        1 => a.clear_spend_alpha(),
                        2 => a.clear_spend_rseed(),
                        _ => a.clear_spend_recipient(),
                    })
                })
                .finish(),
        );
        assert!(verify_own_effects(&missing, &p).is_err());
    }
}
#[test]
fn selected_own_effects_reject_wrong_key_and_return_classification() {
    let (bytes, p, _) = fixture();
    let f = review_fixture().unwrap();
    let mut wrong = p.clone();
    wrong.own_fvk = f.policy.participants[1].fvk.clone();
    assert!(verify_own_effects(&bytes, &wrong).is_err());
    let mut wrong = p.clone();
    wrong
        .outputs
        .iter_mut()
        .find(|o| matches!(o.purpose, OwnOutputPurpose::OwnReturn))
        .unwrap()
        .purpose = OwnOutputPurpose::PeerReturnUnverified;
    assert!(verify_own_effects(&bytes, &wrong).is_err());
    let mut wrong = p.clone();
    wrong
        .outputs
        .iter_mut()
        .find(|o| matches!(o.purpose, OwnOutputPurpose::PeerReturnUnverified))
        .unwrap()
        .purpose = OwnOutputPurpose::OwnReturn;
    assert!(verify_own_effects(&bytes, &wrong).is_err());
}
#[test]
fn selected_own_effects_reject_output_memo_fee_and_cap_substitution() {
    let (bytes, p, _) = fixture();
    for field in 0..7 {
        let mut wrong = p.clone();
        match field {
            0 => wrong.outputs[0].memo[0] ^= 1,
            1 => wrong.outputs[0].value_zatoshis += 1,
            2 => {
                wrong.outputs.pop();
            }
            3 => wrong.exact_transaction_fee_zatoshis += 1,
            4 => wrong.maximum_selected_net_debit_zatoshis = 0,
            5 => wrong.exact_selected_net_debit_zatoshis += 1,
            _ => wrong.outputs.push(wrong.outputs[0].clone()),
        };
        assert!(verify_own_effects(&bytes, &wrong).is_err());
    }
}
#[test]
fn selected_own_effects_bind_declarations_without_upgrading_peer_assurance() {
    let (bytes, p, _) = fixture();
    let first = verify_own_effects(&bytes, &p).unwrap();
    let mut changed = p.clone();
    changed
        .outputs
        .iter_mut()
        .find(|o| matches!(o.purpose, OwnOutputPurpose::PeerReturnUnverified))
        .unwrap()
        .purpose = OwnOutputPurpose::Recipient;
    let second = verify_own_effects(&bytes, &changed).unwrap();
    assert_eq!(first.artifact_digest(), second.artifact_digest());
    assert_ne!(first.policy_digest(), second.policy_digest());
    assert_eq!(
        first.selected_net_debit_zatoshis(),
        second.selected_net_debit_zatoshis()
    );
    let mut changed = p;
    changed.account_id.push_str("-untrusted-label");
    let third = verify_own_effects(&bytes, &changed).unwrap();
    assert_ne!(first.policy_digest(), third.policy_digest()); // Account label provenance is not established here.
}
#[test]
fn selected_own_effects_reject_corrupt_ciphertext_and_noncanonical_input() {
    let (bytes, p, _) = fixture();
    let mut wire =
        serde_json::to_value(pczt::v2::Pczt::try_from(Pczt::parse(&bytes).unwrap()).unwrap())
            .unwrap();
    let a=wire["ironwood"]["actions"][p.outputs[0].action_index]["output"]["enc_ciphertext"]["Encrypted"].as_array_mut().unwrap();
    a[0] = serde_json::Value::from(a[0].as_u64().unwrap() ^ 1);
    let changed = serde_json::from_value::<pczt::v2::Pczt>(wire)
        .unwrap()
        .serialize();
    assert!(verify_own_effects(&changed, &p).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(verify_own_effects(&trailing, &p).is_err());
}
