//! Pure shape/accounting tests. These synthetic DTOs have no authenticated
//! signer receipt, real notes, current-source evidence, or export permission.
use super::*;
use wholepact_core::{
    durable_input_projection_v1::{
        DurableInputProjectionIntentV1, DurableInputProjectionPurposeV1, DurableProjectedInputV1,
        DurableProjectionContextV1,
    },
    manual_construction::PreconstructionProvider,
    AgreementDraft, FundingPolicy, PrivacyMode,
};
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

fn a(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn fixture(selected: u64, own_fee_cap: u64, tx_fee_cap: u64) -> Vec<DurableInputProjectionV1> {
    let height = u32::from(
        Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu7)
            .unwrap(),
    );
    let mut agreement: AgreementDraft = wholepact_core::parse_typed_json(include_bytes!(
        "../../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.recipients[0].amount = a(300_000);
    agreement.funding_policy = FundingPolicy::Exact { target: a(300_000) };
    agreement.privacy_profile.mode = PrivacyMode::DeclaredOperator;
    agreement.privacy_profile.proving_operator = Some("synthetic-prover".into());
    let accounts = vec!["11".repeat(32), "22".repeat(32)];
    (0..2)
        .map(|owner| DurableInputProjectionV1 {
            version: 1,
            intent: DurableInputProjectionIntentV1 {
                version: 1,
                purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
                agreement: agreement.clone(),
                proposal_id: "synthetic-exact-discovery-candidate".into(),
                account_id: accounts[owner].clone(),
                participant_id: format!("owner-{owner}"),
                original_recipient_policy_digest: "00".repeat(32),
                privacy_domain: format!("synthetic-owner-{owner}-privacy"),
                contribution: a(150_000),
                maximum_fee_share: a(own_fee_cap),
                maximum_transaction_fee: a(tx_fee_cap),
                transaction_expiry_height: height + 100,
                provider: PreconstructionProvider {
                    source_id: "synthetic-provider".into(),
                    endpoint: "https://invalid.invalid".into(),
                    trust_profile: "single_tls_provider_report_not_consensus".into(),
                },
                anchor_height: height - 1,
                minimum_confirmations: 1,
                maximum_scan_blocks: 100,
                constructor_principal_id: "synthetic-constructor".into(),
                protected_destination: "/synthetic/coordination.sqlite".into(),
                retention_policy: "Synthetic finite retained metadata only.".into(),
                local_reviewer_account_ids: accounts.clone(),
                valid_from_unix_seconds: 100,
                valid_until_unix_seconds: 200,
            },
            inputs: vec![DurableProjectedInputV1 {
                input_id: format!(
                    "ironwood:{}:0",
                    if owner == 0 { "aa" } else { "bb" }.repeat(32)
                ),
                value: a(selected),
                commitment: "cc".repeat(32),
            }],
            selected_total: a(selected),
            own_return_receiver: format!("usyntheticownreturn{owner}"),
            context: DurableProjectionContextV1 {
                tip_height: height,
                tip_hash: "dd".repeat(32),
                anchor_height: height - 1,
                anchor_hash: "ee".repeat(32),
                anchor_root: "ff".repeat(32),
            },
            captured_at_unix_seconds: 101,
        })
        .collect()
}
const CREATED: &str = "2026-10-18T00:00:00Z";

#[test]
fn projected_candidate_uses_maintained_fee_and_keeps_exact_receipt_inputs() {
    let mut owners = fixture(300_000, 20_000, 40_000);
    let expected = exact_shape_fee(owners[0].context.tip_height + 1, 2, 3).unwrap();
    let proposal = candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
    assert_eq!(proposal.input().proposal_id, owners[0].intent.proposal_id);
    assert_eq!(proposal.manifest().transaction_fee, expected);
    assert_eq!(proposal.manifest().outputs.len(), 3);
    for (owner, input) in owners.iter().zip(&proposal.manifest().inputs) {
        assert_eq!(input.input_id, owner.inputs[0].input_id);
        assert_eq!(input.amount, owner.inputs[0].value);
        owner.matches_final_proposal(proposal.input()).unwrap();
    }
    owners.reverse();
    let reordered = candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
    assert_eq!(proposal.proposal_digest(), reordered.proposal_digest());
}

#[test]
fn projected_candidate_handles_exact_no_change_without_inventing_an_output() {
    let base = fixture(300_000, 20_000, 40_000);
    let fee = exact_shape_fee(base[0].context.tip_height + 1, 2, 1)
        .unwrap()
        .as_zatoshis();
    assert_eq!(fee % 2, 0);
    let owners = fixture(150_000 + fee / 2, fee / 2, fee);
    let proposal = candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
    assert_eq!(proposal.manifest().outputs.len(), 1);
    assert_eq!(proposal.manifest().transaction_fee, a(fee));
    assert!(proposal
        .manifest()
        .participants
        .iter()
        .all(|p| p.fee_share == a(fee / 2)));
}

#[test]
fn projected_candidate_handles_one_return_and_asymmetric_rounding() {
    let mut owners = fixture(300_000, 30_000, 40_000);
    owners[0].intent.contribution = a(100_001);
    owners[1].intent.contribution = a(199_999);
    let fee = exact_shape_fee(owners[0].context.tip_height + 1, 2, 2).unwrap();
    let expected = allocate_fees(
        fee,
        &owners
            .iter()
            .map(|owner| FeeWeight {
                participant_id: owner.intent.participant_id.clone(),
                contribution: owner.intent.contribution,
            })
            .collect::<Vec<_>>(),
        &owners[0].intent.agreement.fee_policy,
    )
    .unwrap();
    owners[0].intent.maximum_fee_share = expected[&owners[0].intent.participant_id];
    let exact = owners[0]
        .intent
        .contribution
        .checked_add(expected[&owners[0].intent.participant_id])
        .unwrap();
    owners[0].selected_total = exact;
    owners[0].inputs[0].value = exact;
    let proposal = candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
    assert_eq!(proposal.manifest().outputs.len(), 2);
    assert_eq!(proposal.manifest().transaction_fee, fee);
    assert_eq!(
        proposal.manifest().participants[0].fee_share,
        expected[&owners[0].intent.participant_id]
    );
    assert_eq!(
        proposal.manifest().participants[0]
            .fee_share
            .checked_add(proposal.manifest().participants[1].fee_share)
            .unwrap(),
        fee
    );
    assert!(matches!(
        &proposal.manifest().outputs[1].allocation,
        OutputAllocation::Return { account_id, .. } if account_id == &owners[1].intent.account_id
    ));
    for owner in &owners {
        owner.matches_final_proposal(proposal.input()).unwrap();
    }
}

#[test]
fn projected_candidate_rejects_conflicting_same_height_tips() {
    let mut owners = fixture(300_000, 20_000, 40_000);
    owners[1].context.tip_hash = "01".repeat(32);
    owners[1].validate().unwrap();
    assert!(candidate_from_retained_projections_v1(&owners, CREATED).is_err());
    owners[1].context.tip_height += 1;
    // This only permits planning from different historical capture heights.
    // No ancestry or current eligibility is asserted by this pure function.
    candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
}

#[test]
fn discovery_anchors_are_independent_and_never_rewritten_as_a_proof_anchor() {
    let mut owners = fixture(300_000, 20_000, 40_000);
    owners[1].context.anchor_height = owners[0].context.tip_height + 1;
    owners[1].intent.anchor_height = owners[1].context.anchor_height;
    owners[1].context.anchor_hash = "01".repeat(32);
    owners[1].context.anchor_root = "02".repeat(32);
    owners[1].context.tip_height = owners[1].context.anchor_height + 1;
    owners[1].context.tip_hash = "03".repeat(32);
    let historical = owners.clone();
    let proposal = candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
    assert!(owners == historical);
    for owner in &owners {
        owner.matches_final_proposal(proposal.input()).unwrap();
    }
    // An alleged later anchor at the exact earlier tip height must identify
    // that same historical block. No pure helper may resolve a fork by fiat.
    owners[1].context.anchor_height = owners[0].context.tip_height;
    owners[1].intent.anchor_height = owners[1].context.anchor_height;
    assert!(candidate_from_retained_projections_v1(&owners, CREATED).is_err());
    owners[1].context.anchor_hash = owners[0].context.tip_hash.clone();
    candidate_from_retained_projections_v1(&owners, CREATED).unwrap();
}

#[test]
fn projected_candidate_refuses_different_sources_accounts_and_exact_input_sets() {
    for mutation in 0..10 {
        let mut owners = fixture(300_000, 20_000, 40_000);
        match mutation {
            0 => owners[1].intent.proposal_id = "other-proposal".into(),
            1 => owners[1].intent.provider.source_id = "other-provider".into(),
            2 => owners[1].context.anchor_hash = "01".repeat(32),
            3 => owners[1].context.anchor_root = "02".repeat(32),
            4 => owners[1].intent.constructor_principal_id = "other-constructor".into(),
            5 => owners[1].intent.protected_destination = "/other/coordination.sqlite".into(),
            6 => owners[1].intent.agreement.revision += 1,
            7 => owners[1].inputs[0].input_id = owners[0].inputs[0].input_id.clone(),
            8 => owners[1].intent.account_id = owners[0].intent.account_id.clone(),
            _ => owners[1].intent.maximum_transaction_fee = Amount::ZERO,
        }
        assert!(
            candidate_from_retained_projections_v1(&owners, CREATED).is_err(),
            "mutation {mutation}"
        );
    }
    let mut owners = fixture(300_000, 20_000, 40_000);
    owners[1].intent.maximum_fee_share = Amount::ZERO;
    owners[1].validate().unwrap();
    assert!(candidate_from_retained_projections_v1(&owners, CREATED).is_err());
    assert!(candidate_from_retained_projections_v1(&owners[..1], CREATED).is_err());
}

#[test]
fn shape_calculator_is_bounded_and_never_relabels_a_pre_nu7_branch() {
    let owners = fixture(300_000, 20_000, 40_000);
    let target = owners[0].context.tip_height + 1;
    for (inputs, outputs) in [(0, 1), (1, 1), (9, 1), (2, 0), (2, 4)] {
        assert!(exact_shape_fee(target, inputs, outputs).is_err());
    }
    assert!(exact_shape_fee(1, 2, 1).is_err());
}
