use wholepact_core::*;

fn a(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn agreement() -> AgreementDraft {
    parse_typed_json(include_bytes!("fixtures/agreement.json")).unwrap()
}
fn proposal() -> ProposalInput {
    ProposalInput {
        proposal_id: "proposal-example-01".into(),
        previous_proposal_id: None,
        artifact_digest: None,
        effects_commitment: None,
        created_at: "2026-10-13T14:00:00Z".into(),
        manifest: ProposalManifest {
            agreement: agreement(),
            participants: vec![
                ParticipantAllocation {
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                    contribution: a(400_000_000),
                    fee_share: a(12_000),
                    fee_cap: a(12_000),
                    maximum_net_debit: a(400_012_000),
                    charges: vec![],
                },
                ParticipantAllocation {
                    participant_id: "bob".into(),
                    account_id: "account-bob".into(),
                    contribution: a(600_000_000),
                    fee_share: a(18_000),
                    fee_cap: a(18_000),
                    maximum_net_debit: a(600_018_000),
                    charges: vec![],
                },
            ],
            inputs: vec![
                ClaimedInput {
                    input_id: "input-alice".into(),
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                    amount: a(500_000_000),
                    ownership_evidence_ref: None,
                },
                ClaimedInput {
                    input_id: "input-bob".into(),
                    participant_id: "bob".into(),
                    account_id: "account-bob".into(),
                    amount: a(700_000_000),
                    ownership_evidence_ref: None,
                },
            ],
            outputs: vec![
                ClaimedOutput {
                    output_id: "recipient-output".into(),
                    address: agreement().recipients[0].address.clone(),
                    amount: a(1_000_000_000),
                    allocation: OutputAllocation::Recipient {
                        recipient_id: "recipient-example".into(),
                    },
                },
                ClaimedOutput {
                    output_id: "alice-return".into(),
                    address: "usyntheticreturnalice".into(),
                    amount: a(99_988_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "alice".into(),
                        account_id: "account-alice".into(),
                        ownership_evidence_ref: None,
                    },
                },
                ClaimedOutput {
                    output_id: "bob-return".into(),
                    address: "usyntheticreturnbob".into(),
                    amount: a(99_982_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "bob".into(),
                        account_id: "account-bob".into(),
                        ownership_evidence_ref: None,
                    },
                },
            ],
            transaction_fee: a(30_000),
            expiry_height: 3_000_000,
        },
    }
}

#[test]
fn precise_per_participant_and_global_conservation_is_not_crypto_verification() {
    let proposal = Proposal::validate(proposal()).unwrap();
    let accounting = proposal.accounting();
    assert_eq!(accounting.input_total, a(1_200_000_000));
    assert_eq!(accounting.output_total, a(1_199_970_000));
    assert_eq!(accounting.participant_net_debits["alice"], a(400_012_000));
    assert!(!accounting.authorization_allowed);
    assert_eq!(accounting.assurance, "claimed_accounting_only");
    assert!(!accounting.blocking_reasons.is_empty());
}

#[test]
fn debit_fee_caps_and_unexplained_values_fail_closed() {
    let mut changed = proposal();
    changed.manifest.participants[0].maximum_net_debit = a(400_011_999);
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::DebitCapExceeded
    );
    let mut changed = proposal();
    changed.manifest.participants[1].fee_cap = a(17_999);
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::FeeCapExceeded
    );
    let mut changed = proposal();
    changed.manifest.inputs[0].amount = a(500_000_001);
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::ConservationFailure
    );
    let mut changed = proposal();
    changed.manifest.outputs[0].address = "uattacker".into();
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::ConservationFailure
    );
}

#[test]
fn ownership_labels_never_unlock_authorization_and_mismatched_accounts_fail() {
    let mut changed = proposal();
    changed.manifest.outputs[1].address = "uattackerlabeledaschange".into();
    let report = Proposal::validate(changed).unwrap();
    // The pure layer cannot detect an unproven address-owner lie. It must not
    // present accounting success as transaction verification or authorization.
    assert!(!report.accounting().authorization_allowed);
    let mut changed = proposal();
    changed.manifest.outputs[1].allocation = OutputAllocation::Return {
        participant_id: "alice".into(),
        account_id: "attacker-account".into(),
        ownership_evidence_ref: Some("forged-reference".into()),
    };
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::MissingEvidence
    );
}

#[test]
fn duplicate_inputs_hidden_charges_and_missing_recipients_fail() {
    let mut changed = proposal();
    changed
        .manifest
        .inputs
        .push(changed.manifest.inputs[0].clone());
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::DuplicateIdentifier
    );
    let mut changed = proposal();
    changed.manifest.outputs[1].allocation = OutputAllocation::Charge {
        participant_id: "alice".into(),
        charge_id: "hidden-relay-charge".into(),
    };
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::InvalidTerms
    );
    let mut changed = proposal();
    changed.manifest.outputs.remove(0);
    assert_eq!(
        Proposal::validate(changed).unwrap_err().code,
        ErrorCode::ConservationFailure
    );
}

#[test]
fn explicit_service_charge_is_separate_and_conserved() {
    let mut input = proposal();
    input.manifest.participants[0].charges.push(ChargeConsent {
        charge_id: "proof-service".into(),
        address: "userviceprovider".into(),
        amount: a(100),
        purpose: "Explicit synthetic quote".into(),
    });
    input.manifest.participants[0].maximum_net_debit = a(400_012_100);
    input.manifest.outputs[1].amount = a(99_987_900);
    input.manifest.outputs.push(ClaimedOutput {
        output_id: "charge-output".into(),
        address: "userviceprovider".into(),
        amount: a(100),
        allocation: OutputAllocation::Charge {
            participant_id: "alice".into(),
            charge_id: "proof-service".into(),
        },
    });
    let result = Proposal::validate(input).unwrap();
    assert_eq!(result.accounting().charge_total, a(100));
    assert_eq!(
        result.accounting().participant_net_debits["alice"],
        a(400_012_100)
    );
}

#[test]
fn material_terms_are_bound_and_digest_domains_are_separate() {
    let original = Proposal::validate(proposal()).unwrap();
    let mut changed = proposal();
    changed.manifest.expiry_height += 1;
    let revised = Proposal::validate(changed).unwrap();
    assert_ne!(original.manifest_digest(), revised.manifest_digest());
    assert_ne!(original.manifest_digest(), original.proposal_digest());
    let first = serde_json::json!({"b":2,"a":1});
    let second: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
    assert_eq!(
        canonical_digest("test:v1", &first).unwrap(),
        canonical_digest("test:v1", &second).unwrap()
    );
    assert_ne!(
        canonical_digest("test:v1", &first).unwrap(),
        canonical_digest("other:v1", &first).unwrap()
    );
    assert!(canonical_digest("test:v1", &serde_json::json!({"float":1.5})).is_err());
}

#[test]
fn draft_rejects_unknown_required_fields_extensions_and_bad_dates() {
    agreement().validate().unwrap();
    let mut value = serde_json::to_value(agreement()).unwrap();
    value["required_secret_condition"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AgreementDraft>(value).is_err());
    let mut draft = agreement();
    draft.extensions.push(Extension {
        name: "hidden-condition".into(),
        required: true,
        schema_version: 1,
        value: serde_json::json!({}),
    });
    assert_eq!(
        draft.validate().unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
    for invalid in [
        "2026-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:00+00:00",
    ] {
        assert!(validate_timestamp(invalid).is_err());
    }
    assert!(validate_timestamp("2028-02-29T23:59:59Z").is_ok());
}
