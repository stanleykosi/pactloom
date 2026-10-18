//! Inert-data tests only. Synthetic receiving text is not address verification,
//! and none of these fixtures issue native permission or attest to spentness.
use super::*;
use crate::{ClaimedInput, ClaimedOutput, ParticipantAllocation, ProposalManifest};

fn a(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn h(byte: &str) -> String {
    byte.repeat(32)
}
fn fixture() -> (
    DurableInputProjectionV1,
    BornManualEnrollmentTerms,
    BornConstructionRecipientPolicyV2,
) {
    let (mut terms, mut policy) =
        crate::born_recipient_policy_v2::tests::modeled_terms_and_policy();
    let mut agreement: AgreementDraft =
        crate::parse_typed_json(include_bytes!("../../tests/fixtures/agreement.json")).unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.privacy_profile.mode = PrivacyMode::DeclaredOperator;
    agreement.privacy_profile.proving_operator = Some("synthetic-prover".into());
    policy.network_profile_id = agreement.network_profile_id.clone();
    terms.identity.network_profile_id = agreement.network_profile_id.clone();
    terms.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
    let intent = DurableInputProjectionIntentV1 {
        version: 1,
        purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
        agreement,
        proposal_id: "synthetic-durable-proposal".into(),
        account_id: h("11"),
        participant_id: "alice".into(),
        original_recipient_policy_digest: policy.digest().unwrap(),
        privacy_domain: terms.scope.privacy_domain.clone(),
        contribution: a(400_000_000),
        maximum_fee_share: a(12_000),
        maximum_transaction_fee: a(30_000),
        transaction_expiry_height: 3_000_000,
        provider: PreconstructionProvider {
            source_id: "synthetic-provider".into(),
            endpoint: "https://invalid.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        anchor_height: 2_900_000,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
        constructor_principal_id: "synthetic-host".into(),
        protected_destination: "/synthetic/host/coordination.sqlite".into(),
        retention_policy: "Retain this metadata only until the declared expiry.".into(),
        local_reviewer_account_ids: vec![h("11"), h("22")],
        valid_from_unix_seconds: 100,
        valid_until_unix_seconds: 200,
    };
    let projection = DurableInputProjectionV1 {
        version: 1,
        intent,
        inputs: vec![DurableProjectedInputV1 {
            input_id: format!("ironwood:{}:0", h("aa")),
            value: a(500_000_000),
            commitment: h("bb"),
        }],
        selected_total: a(500_000_000),
        own_return_receiver: "usyntheticreturnalice".into(),
        context: DurableProjectionContextV1 {
            tip_height: 2_900_001,
            tip_hash: h("cc"),
            anchor_height: 2_900_000,
            anchor_hash: h("dd"),
            anchor_root: h("ee"),
        },
        captured_at_unix_seconds: 101,
    };
    projection.validate().unwrap();
    projection
        .intent
        .require_original_policy(&terms, &policy)
        .unwrap();
    (projection, terms, policy)
}
fn candidate(projection: &DurableInputProjectionV1, fee: u64) -> ProposalInput {
    assert_eq!(fee % 5, 0);
    let alice_fee = fee * 2 / 5;
    let bob_fee = fee - alice_fee;
    let recipient = &projection.intent.agreement.recipients[0];
    let proposal = ProposalInput {
        proposal_id: projection.intent.proposal_id.clone(),
        previous_proposal_id: None,
        artifact_digest: None,
        effects_commitment: None,
        created_at: "2026-10-18T00:00:00Z".into(),
        manifest: ProposalManifest {
            agreement: projection.intent.agreement.clone(),
            participants: vec![
                ParticipantAllocation {
                    participant_id: "alice".into(),
                    account_id: h("11"),
                    contribution: a(400_000_000),
                    fee_share: a(alice_fee),
                    fee_cap: a(alice_fee),
                    maximum_net_debit: a(400_000_000 + alice_fee),
                    charges: vec![],
                },
                ParticipantAllocation {
                    participant_id: "bob".into(),
                    account_id: h("22"),
                    contribution: a(600_000_000),
                    fee_share: a(bob_fee),
                    fee_cap: a(bob_fee),
                    maximum_net_debit: a(600_000_000 + bob_fee),
                    charges: vec![],
                },
            ],
            inputs: vec![
                ClaimedInput {
                    input_id: projection.inputs[0].input_id.clone(),
                    participant_id: "alice".into(),
                    account_id: h("11"),
                    amount: a(500_000_000),
                    ownership_evidence_ref: None,
                },
                ClaimedInput {
                    input_id: format!("ironwood:{}:1", h("cc")),
                    participant_id: "bob".into(),
                    account_id: h("22"),
                    amount: a(700_000_000),
                    ownership_evidence_ref: None,
                },
            ],
            outputs: vec![
                ClaimedOutput {
                    output_id: "recipient".into(),
                    address: recipient.address.clone(),
                    amount: recipient.amount,
                    allocation: OutputAllocation::Recipient {
                        recipient_id: recipient.recipient_id.clone(),
                    },
                },
                ClaimedOutput {
                    output_id: "alice-return".into(),
                    address: projection.own_return_receiver.clone(),
                    amount: a(100_000_000 - alice_fee),
                    allocation: OutputAllocation::Return {
                        participant_id: "alice".into(),
                        account_id: h("11"),
                        ownership_evidence_ref: None,
                    },
                },
                ClaimedOutput {
                    output_id: "bob-return".into(),
                    address: "usyntheticreturnbob".into(),
                    amount: a(100_000_000 - bob_fee),
                    allocation: OutputAllocation::Return {
                        participant_id: "bob".into(),
                        account_id: h("22"),
                        ownership_evidence_ref: None,
                    },
                },
            ],
            transaction_fee: a(fee),
            expiry_height: projection.intent.transaction_expiry_height,
        },
    };
    Proposal::validate(proposal.clone()).unwrap();
    proposal
}

#[test]
fn projection_roundtrip_preserves_exact_metadata_without_fixing_final_fee_or_return_amount() {
    let (projection, _, _) = fixture();
    let encoded = serde_json::to_vec(&projection).unwrap();
    let decoded: DurableInputProjectionV1 = crate::parse_typed_json(&encoded).unwrap();
    assert!(decoded == projection);
    assert_eq!(decoded.digest().unwrap(), projection.digest().unwrap());
    assert_ne!(
        projection.digest().unwrap(),
        projection.intent.digest().unwrap()
    );
    assert_eq!(
        projection.intent.maximum_selection_debit().unwrap(),
        a(400_012_000)
    );
    for fee in [20_000, 30_000] {
        projection
            .matches_final_proposal(&candidate(&projection, fee))
            .unwrap();
    }
    assert!(projection.intent.require_metadata_current(100).is_ok());
    assert!(projection.intent.require_metadata_current(199).is_ok());
    assert!(projection.intent.require_metadata_current(99).is_err());
    assert!(projection.intent.require_metadata_current(200).is_err());
}

#[test]
fn projection_codec_and_resources_refuse_unknown_or_ambiguous_data() {
    let (projection, _, _) = fixture();
    let mut value = serde_json::to_value(&projection).unwrap();
    value["approved"] = true.into();
    assert!(serde_json::from_value::<DurableInputProjectionV1>(value).is_err());
    let mut value = serde_json::to_value(&projection).unwrap();
    value["intent"]["purpose"] = "construct_exact_accepted_candidate".into();
    assert!(serde_json::from_value::<DurableInputProjectionV1>(value).is_err());
    for index in ["00", "+1", "65536", "0:extra"] {
        let mut changed = projection.clone();
        changed.inputs[0].input_id = format!("ironwood:{}:{index}", h("aa"));
        assert!(changed.validate().is_err());
    }
    for mutation in 0..10 {
        let mut changed = projection.clone();
        match mutation {
            0 => changed.inputs[0].input_id = format!("ironwood:{}:0", h("AA")),
            1 => changed.inputs[0].commitment = h("zz"),
            2 => changed.inputs[0].value = Amount::ZERO,
            3 => changed.selected_total = a(500_000_001),
            4 => changed.inputs.push(changed.inputs[0].clone()),
            5 => changed.context.anchor_height -= 1,
            6 => changed.context.tip_height = changed.intent.transaction_expiry_height,
            7 => changed.captured_at_unix_seconds = changed.intent.valid_until_unix_seconds,
            8 => changed.inputs.clear(),
            _ => changed.own_return_receiver = "t1UnsupportedTransparentAddress".into(),
        }
        assert!(changed.validate().is_err(), "mutation {mutation}");
    }
}

#[test]
fn projection_intent_binds_original_policy_caps_and_explicit_metadata_audience() {
    let (projection, terms, policy) = fixture();
    for mutation in 0..16 {
        let mut changed = projection.intent.clone();
        match mutation {
            0 => changed.account_id = "alice".into(),
            1 => changed.original_recipient_policy_digest = h("00"),
            2 => changed.contribution = a(400_000_001),
            3 => changed.maximum_fee_share = a(12_001),
            4 => changed.maximum_transaction_fee = a(30_001),
            5 => changed.valid_until_unix_seconds = 201,
            6 => changed.provider.endpoint = "http://invalid.invalid".into(),
            7 => changed.provider.trust_profile = "consensus".into(),
            8 => changed.protected_destination = "/synthetic/../elsewhere".into(),
            9 => changed.local_reviewer_account_ids.reverse(),
            10 => changed.local_reviewer_account_ids = vec![h("11"), h("11")],
            11 => changed.local_reviewer_account_ids = vec![h("22"), h("33")],
            12 => changed.agreement.recipients[0].address = "uDifferentRecipient".into(),
            13 => changed.privacy_domain = "different-domain".into(),
            14 => changed.maximum_scan_blocks = 1001,
            _ => changed.valid_from_unix_seconds = 0,
        }
        assert!(
            changed.require_original_policy(&terms, &policy).is_err(),
            "mutation {mutation}"
        );
    }
    let mut narrower = terms.clone();
    narrower.scope.per_operation_limit_zatoshis -= 1;
    assert!(policy.require_enrollment(&narrower).is_ok());
    assert!(projection
        .intent
        .require_original_policy(&narrower, &policy)
        .is_err());
    let mut changed = projection.intent.clone();
    changed.local_reviewer_account_ids[1] = h("33");
    assert_ne!(
        changed.digest().unwrap(),
        projection.intent.digest().unwrap()
    );
    let mut changed = projection.intent.clone();
    changed.protected_destination = "/synthetic/other/coordination.sqlite".into();
    assert_ne!(
        changed.digest().unwrap(),
        projection.intent.digest().unwrap()
    );
}

#[test]
fn projection_join_rejects_silent_reselection_and_changed_final_terms() {
    let (projection, _, _) = fixture();
    let original = candidate(&projection, 30_000);
    for mutation in 0..9 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.manifest.inputs[0].input_id = format!("ironwood:{}:2", h("ff")),
            1 => {
                changed.manifest.inputs[0].amount = a(500_000_001);
                changed.manifest.outputs[1].amount = a(99_988_001);
            }
            2 => changed.manifest.outputs[1].address = "uDifferentReturn".into(),
            3 => changed.manifest.participants[0].fee_cap = a(12_001),
            4 => changed.manifest.participants[0].maximum_net_debit = a(400_012_001),
            5 => changed.manifest.expiry_height += 1,
            6 => changed.proposal_id = "different-proposal".into(),
            7 => changed.manifest.inputs[0].ownership_evidence_ref = Some("untrusted-claim".into()),
            _ => changed.manifest.agreement.revision += 1,
        }
        // These remain arithmetically valid. The projection join, not the generic
        // accounting validator, must reject the exact historical substitution.
        assert!(
            Proposal::validate(changed.clone()).is_ok(),
            "mutation {mutation}"
        );
        assert!(
            projection.matches_final_proposal(&changed).is_err(),
            "mutation {mutation}"
        );
    }
    let too_much_fee = candidate(&projection, 30_005);
    assert!(projection.matches_final_proposal(&too_much_fee).is_err());
    let mut relabeled = original;
    relabeled.manifest.participants[1].account_id = h("33");
    relabeled.manifest.inputs[1].account_id = h("33");
    if let OutputAllocation::Return { account_id, .. } =
        &mut relabeled.manifest.outputs[2].allocation
    {
        *account_id = h("33");
    }
    assert!(Proposal::validate(relabeled.clone()).is_ok());
    assert!(projection.matches_final_proposal(&relabeled).is_err());
}
