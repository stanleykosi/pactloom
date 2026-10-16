//! Never-funded synthetic policy fixtures. These tests verify declared accounting
//! and restrictions, not real ownership, independent identities or settlement.
use wholepact_core::sponsor::*;
use wholepact_core::*;

fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn manifest() -> ProposalManifest {
    serde_json::from_str(include_str!("fixtures/sponsor_manifest.json")).unwrap()
}
fn terms() -> SponsorPolicyTerms {
    serde_json::from_str(include_str!("fixtures/sponsor_policy.json")).unwrap()
}

#[test]
fn concrete_floor_cap_fee_exclusions_and_missing_evidence() {
    let mut manifest = manifest();
    manifest.inputs[0].ownership_evidence_ref = Some("coordinator-claims-verified".into());
    let result = evaluate_sponsor_policy(&terms(), &manifest).unwrap();
    assert_eq!(result.evaluation.eligible_total, amount(8));
    assert_eq!(result.evaluation.calculated_match, amount(5));
    assert_eq!(result.sponsor_net_debit, amount(6));
    assert_eq!(result.sponsor_fee_share, amount(1));
    assert_eq!(result.excluded_transaction_fee, amount(3));
    assert_eq!(result.excluded_service_charges, Amount::ZERO);
    assert_eq!(result.excluded_contributions[0].participant_id, "sponsor");
    assert_eq!(result.excluded_contributions[0].contribution, amount(5));
    assert_eq!(result.eligible_allocations[0].input_ids, ["input-alice"]);
    assert_eq!(
        result.sponsor_allocation.return_output_ids,
        ["return-sponsor"]
    );
    assert_eq!(
        result.evaluation.evidence_status,
        MatchEvidenceStatus::Unverifiable
    );
    assert!(!result.evaluation.authorization_allowed);
    let mut capped = terms();
    capped.rate_numerator = MAX_SPONSOR_RATE_TERM;
    capped.maximum_match = amount(5);
    assert_eq!(
        evaluate_sponsor_policy(&capped, &manifest)
            .unwrap()
            .evaluation
            .calculated_match,
        amount(5)
    );
    let mut includes_fees = terms();
    includes_fees.rate_numerator = 1;
    includes_fees.rate_denominator = 2;
    // Counting total debit 10 instead of funding 8 would incorrectly yield 5.
    assert_eq!(
        evaluate_sponsor_policy(&includes_fees, &manifest)
            .unwrap_err()
            .code,
        ErrorCode::ConservationFailure
    );
}

#[test]
fn assurance_never_falls_back_and_attestation_label_is_not_proof() {
    let independent = evaluate_sponsor_policy(&terms(), &manifest()).unwrap();
    assert_eq!(
        independent.evaluation.assurance,
        MatchAssurance::IndependentlyVerified
    );
    let mut attested = terms();
    attested.assurance = MatchAssurance::Attested {
        verifier_identity: "explicit-verifier".into(),
    };
    let result = evaluate_sponsor_policy(&attested, &manifest()).unwrap();
    assert_eq!(result.evaluation.assurance, attested.assurance);
    assert!(!result.evaluation.authorization_allowed);
    assert!(result
        .evaluation
        .required_evidence
        .iter()
        .any(|s| s.contains("explicit-verifier")));
    let mut forged = serde_json::to_value(attested).unwrap();
    forged["assurance"]["verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SponsorPolicyTerms>(forged).is_err());
}

#[test]
fn recipient_address_amount_network_scope_and_privacy_are_exact_constraints() {
    let original = manifest();
    let mut changed = original.clone();
    changed.agreement.recipients[0].address = "utestsubstitutedrecipient".into();
    changed.outputs[0].address = changed.agreement.recipients[0].address.clone();
    validate_claimed_accounting(&changed).unwrap();
    assert_eq!(
        evaluate_sponsor_policy(&terms(), &changed)
            .unwrap_err()
            .code,
        ErrorCode::InvalidTerms
    );
    let mut restricted = terms();
    restricted.beneficiaries[0].maximum_amount = amount(12);
    assert!(evaluate_sponsor_policy(&restricted, &original).is_err());
    restricted = terms();
    restricted.agreement_scope = vec!["different-agreement".into()];
    assert!(evaluate_sponsor_policy(&restricted, &original).is_err());
    restricted = terms();
    restricted.network_profile_id = "different-network".into();
    assert!(evaluate_sponsor_policy(&restricted, &original).is_err());
    restricted = terms();
    restricted.privacy_profile.mode = PrivacyMode::DeclaredOperator;
    restricted.privacy_profile.proving_operator = Some("named-operator".into());
    assert_eq!(
        evaluate_sponsor_policy(&restricted, &original)
            .unwrap_err()
            .code,
        ErrorCode::PrivacyIncompatible
    );
}

#[test]
fn duplicate_overlap_and_bounds_fail_closed() {
    let cases = [
        ("same participant", 0),
        ("same account", 1),
        ("duplicate contributor", 2),
        ("zero denominator", 3),
        ("zero numerator", 4),
        ("debit cap", 5),
        ("aggregate budget", 6),
        ("no recipients", 7),
        ("no eligibility", 8),
        ("unbounded scope", 9),
        ("duplicate beneficiary", 10),
    ];
    for (label, case) in cases {
        let mut policy = terms();
        match case {
            0 => {
                policy.eligible_contributors[0].participant_id =
                    policy.sponsor.participant_id.clone()
            }
            1 => policy.eligible_contributors[0].account_id = policy.sponsor.account_id.clone(),
            2 => policy
                .eligible_contributors
                .push(policy.eligible_contributors[0].clone()),
            3 => policy.rate_denominator = 0,
            4 => policy.rate_numerator = 0,
            5 => policy.maximum_net_debit = amount(12),
            6 => policy.aggregate_budget = amount(12),
            7 => policy.beneficiaries.clear(),
            8 => policy.eligible_contributors.clear(),
            9 => policy.agreement_scope = (0..33).map(|i| format!("agreement-{i}")).collect(),
            10 => policy.beneficiaries.push(policy.beneficiaries[0].clone()),
            _ => unreachable!(),
        }
        assert!(policy.validate().is_err(), "{label}");
    }
    let mut policy = terms();
    policy.fee_cap = Amount::ZERO;
    assert_eq!(
        evaluate_sponsor_policy(&policy, &manifest())
            .unwrap_err()
            .code,
        ErrorCode::FeeCapExceeded
    );
    policy = terms();
    policy.minimum_qualifying_total = amount(9);
    assert!(evaluate_sponsor_policy(&policy, &manifest()).is_err());
    let mut overlap = manifest();
    overlap.inputs[1].input_id = overlap.inputs[0].input_id.clone();
    assert_eq!(
        evaluate_sponsor_policy(&terms(), &overlap)
            .unwrap_err()
            .code,
        ErrorCode::DuplicateIdentifier
    );
    let mut overlap = manifest();
    overlap.outputs[2].output_id = overlap.outputs[1].output_id.clone();
    assert_eq!(
        evaluate_sponsor_policy(&terms(), &overlap)
            .unwrap_err()
            .code,
        ErrorCode::DuplicateIdentifier
    );
}

#[test]
fn account_relabeling_is_rejected_and_ineligible_funding_is_excluded() {
    let mut changed = manifest();
    changed.participants[0].account_id = "other-account".into();
    changed.inputs[0].account_id = "other-account".into();
    if let OutputAllocation::Return { account_id, .. } = &mut changed.outputs[1].allocation {
        *account_id = "other-account".into();
    }
    validate_claimed_accounting(&changed).unwrap();
    assert!(evaluate_sponsor_policy(&terms(), &changed).is_err());

    let mut changed = manifest();
    let mut ineligible = changed.participants[0].clone();
    ineligible.participant_id = "carol".into();
    ineligible.account_id = "account-c".into();
    ineligible.contribution = amount(9);
    ineligible.fee_share = amount(1);
    changed.participants.push(ineligible);
    changed.participants[0].fee_share = amount(1);
    changed.inputs[0].amount = amount(11);
    changed.inputs.push(ClaimedInput {
        input_id: "input-carol".into(),
        participant_id: "carol".into(),
        account_id: "account-c".into(),
        amount: amount(10),
        ownership_evidence_ref: None,
    });
    changed.agreement.recipients[0].amount = amount(22);
    changed.agreement.funding_policy = FundingPolicy::Exact { target: amount(22) };
    changed.outputs[0].amount = amount(22);
    let result = evaluate_sponsor_policy(&terms(), &changed).unwrap();
    assert_eq!(result.evaluation.eligible_total, amount(8));
    assert_eq!(result.evaluation.calculated_match, amount(5));
    assert_eq!(result.excluded_contributions[1].participant_id, "carol");
    assert_eq!(result.excluded_contributions[1].contribution, amount(9));
}
