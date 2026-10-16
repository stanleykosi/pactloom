#![cfg(feature = "synthetic-selected-effects-tests")]
//! In-memory unproved builder only; IO-finalized dummy signatures, no prover,
//! real-owner signer, network or vault. Reports cannot become signing authority.
use wholepact_offline_bridge::inspect_selected_offline_effects;
use wholepact_protocol::{
    canonical_role_layout::produce_canonical_layout,
    own_effects::*,
    review::{OutputPurpose, verify_review},
    synthetic::review_fixture,
};
fn fixture() -> (
    Vec<u8>,
    OwnEffectsPolicy,
    String,
    wholepact_protocol::canonical_role_layout::CanonicalLayoutArtifact,
) {
    let f = review_fixture().unwrap();
    let broad = verify_review(&f.pczt_bytes, &f.policy).unwrap();
    let artifact = produce_canonical_layout(&f.pczt_bytes, &f.policy).unwrap();
    let bytes = artifact.bytes().to_vec();
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
    (bytes, policy, broad.shielded_sighash().into(), artifact)
}
#[test]
fn report_comes_from_actual_own_verifier_and_classifies_unknowns() {
    let (bytes, policy, _, _) = fixture();
    let report = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    assert_eq!(report.inspection().selected_net_debit_zatoshis(), 105_000);
    for text in [
        "Independently checked",
        "Declared only",
        "Attested facts: none",
        "peer input ownership",
        "completeness of own-controlled inputs",
        "transaction proof validity",
        "current unspentness",
        "Do not sign",
    ] {
        assert!(report.display().contains(text), "{text}");
    }
    assert!(
        report
            .display()
            .contains(report.inspection().artifact_digest())
    );
}
#[test]
fn report_does_not_display_untrusted_account_label_or_claim_attestation() {
    let (bytes, mut policy, _, _) = fixture();
    policy.account_id = "\x1b[31mtrusted attested approval".into();
    let report = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    assert!(!report.display().contains("\x1b"));
    assert!(!report.display().contains("trusted attested approval"));
    assert!(
        report
            .display()
            .contains("no named-verifier assurance mode is active")
    );
}
#[test]
fn report_fails_closed_when_actual_selected_effects_do_not_match() {
    let (bytes, mut policy, _, _) = fixture();
    policy.exact_selected_net_debit_zatoshis += 1;
    assert!(inspect_selected_offline_effects(&bytes, &policy).is_err());
}

#[test]
fn return_report_keeps_missing_signatures_and_foreign_layout_closed() {
    let (bytes, policy, _, artifact) = fixture();
    let (_, _, _, foreign) = fixture();
    let report = inspect_selected_offline_effects(&bytes, &policy).unwrap();
    for transformation in [artifact.transformation(), foreign.transformation()] {
        assert!(
            wholepact_offline_bridge::inspect_selected_offline_return(
                &bytes,
                &bytes,
                &report,
                transformation
            )
            .is_err()
        );
    }
    assert!(
        wholepact_offline_bridge::inspect_selected_offline_return(
            b"different original",
            &bytes,
            &report,
            artifact.transformation()
        )
        .is_err()
    );
}
