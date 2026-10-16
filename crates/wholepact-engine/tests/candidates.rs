use serde_json::json;
use wholepact_core::*;
use wholepact_engine::{Access, CandidateRequest, Engine};

fn actor() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: "local-organizer".into(),
        ..Access::default()
    }
}
fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn request() -> CandidateRequest {
    let mut agreement: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.recipients[0].amount = amount(300_000);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(300_000),
    };
    let participants = vec![
        ParticipantAllocation {
            participant_id: "alice".into(),
            account_id: "account-a".into(),
            contribution: amount(100_000),
            fee_share: amount(5_000),
            fee_cap: amount(5_000),
            maximum_net_debit: amount(105_000),
            charges: vec![],
        },
        ParticipantAllocation {
            participant_id: "bob".into(),
            account_id: "account-b".into(),
            contribution: amount(200_000),
            fee_share: amount(10_000),
            fee_cap: amount(10_000),
            maximum_net_debit: amount(210_000),
            charges: vec![],
        },
    ];
    let inputs = participants
        .iter()
        .enumerate()
        .map(|(i, p)| ClaimedInput {
            input_id: format!("input-{i}"),
            participant_id: p.participant_id.clone(),
            account_id: p.account_id.clone(),
            amount: amount(if i == 0 { 200_000 } else { 300_000 }),
            ownership_evidence_ref: None,
        })
        .collect();
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: agreement.recipients[0].address.clone(),
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: agreement.recipients[0].recipient_id.clone(),
        },
    }];
    for (i, p) in participants.iter().enumerate() {
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: format!("utestsyntheticchange{i}"),
            amount: amount(if i == 0 { 95_000 } else { 90_000 }),
            allocation: OutputAllocation::Return {
                participant_id: p.participant_id.clone(),
                account_id: p.account_id.clone(),
                ownership_evidence_ref: None,
            },
        });
    }
    CandidateRequest {
        manifest: ProposalManifest {
            agreement,
            participants,
            inputs,
            outputs,
            transaction_fee: amount(15_000),
            expiry_height: 4_465_070,
        },
        previous_candidate_id: None,
    }
}
fn create_intents(engine: &Engine, request: &CandidateRequest) {
    let id = &request.manifest.agreement.agreement_id;
    engine
        .create(
            &actor(),
            "candidate-create-agreement",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &actor(),
                &format!("candidate-intent-{i:04}"),
                id,
                i as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{i}"),
                    agreement_id: id.clone(),
                    participant_id: p.participant_id.clone(),
                    desired_contribution: p.contribution,
                    maximum_net_debit: p.maximum_net_debit,
                    fee_cap: p.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
}

#[test]
fn exact_candidate_lifecycle_is_durable_idempotent_and_nonbinding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-claims.sqlite");
    let engine = Engine::open(&path).unwrap();
    let input = request();
    create_intents(&engine, &input);
    let id = input.manifest.agreement.agreement_id.clone();
    let frozen = engine
        .create_candidate(&actor(), "candidate-freeze-command", &id, 3, input.clone())
        .unwrap();
    let candidate = &frozen.agreement.candidates[0];
    assert_eq!(candidate.accounting["authorization_allowed"], false);
    assert_eq!(
        candidate.accounting["participant_net_debits"]["alice"],
        "105000"
    );
    let candidate_id = candidate.candidate_id.clone();
    let reviewed = engine
        .review_candidate(&actor(), "candidate-review-command", &candidate_id, 4)
        .unwrap();
    let report = &reviewed.agreement.candidates[0].reviews[0];
    assert_eq!(report.status, "claims_checked_only");
    assert!(
        !report.economic_terms_verified
            && !report.authorization_allowed
            && !report.distribution_allowed
    );
    assert_eq!(report.human_approval, "not_requested");
    assert!(!report.chain_validated);
    drop(engine);
    let restarted = Engine::open(&path).unwrap();
    let replay = restarted
        .create_candidate(&actor(), "candidate-freeze-command", &id, 3, input.clone())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, frozen.operation_id);
    assert_eq!(replay.agreement.revision, 4);
    let replay = restarted
        .review_candidate(&actor(), "candidate-review-command", &candidate_id, 4)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, reviewed.operation_id);
    let (_, fetched) = restarted.candidate(&actor(), &candidate_id).unwrap();
    assert_eq!(fetched.reviews.len(), 1);
    assert_eq!(
        restarted
            .operation(&actor(), &reviewed.operation_id)
            .unwrap()["status"],
        "succeeded"
    );
    let outsider = Access {
        include_owned_agreements: true,
        principal_id: "other".into(),
        ..Access::default()
    };
    assert_eq!(
        restarted
            .candidate(&outsider, &candidate_id)
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    assert_eq!(
        restarted
            .operation(&outsider, &reviewed.operation_id)
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    let mut changed = input;
    changed.manifest.expiry_height += 1;
    assert_eq!(
        restarted
            .create_candidate(&actor(), "candidate-freeze-command", &id, 3, changed)
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        restarted.get(&actor(), &id).unwrap().authorization_exposure,
        "unknown"
    );
    assert_eq!(
        restarted.get(&actor(), &id).unwrap().chain_observation,
        "unknown"
    );
}

#[test]
fn candidate_rejects_mismatched_terms_caps_assignments_and_stale_state() {
    let engine = Engine::in_memory().unwrap();
    let input = request();
    create_intents(&engine, &input);
    let id = input.manifest.agreement.agreement_id.clone();
    let mut changed = input.clone();
    changed.manifest.agreement.purpose = "substituted purpose".into();
    assert_eq!(
        engine
            .create_candidate(&actor(), "changed-candidate-01", &id, 3, changed)
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
    let mut changed = input.clone();
    changed.manifest.participants[0].maximum_net_debit = amount(105_001);
    assert_eq!(
        engine
            .create_candidate(&actor(), "changed-candidate-02", &id, 3, changed)
            .unwrap_err()
            .code,
        "DEBIT_CAP_EXCEEDED"
    );
    let mut changed = input.clone();
    changed.manifest.outputs[0].address = "utestsubstitutedreceiver".into();
    assert!(
        engine
            .create_candidate(&actor(), "changed-candidate-03", &id, 3, changed)
            .is_err()
    );
    let mut changed = input.clone();
    changed.manifest.inputs[0].account_id = "account-b".into();
    assert!(
        engine
            .create_candidate(&actor(), "changed-candidate-04", &id, 3, changed)
            .is_err()
    );
    assert_eq!(
        engine
            .create_candidate(&actor(), "changed-candidate-05", &id, 2, input.clone())
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(engine.get(&actor(), &id).unwrap().revision, 3);
    engine
        .withdraw(&actor(), "withdraw-before-candidate", &id, "intent-0", 3)
        .unwrap();
    assert_eq!(
        engine
            .create_candidate(&actor(), "changed-candidate-06", &id, 4, input)
            .unwrap_err()
            .code,
        "MISSING_EVIDENCE"
    );
}

#[test]
fn imported_verified_flags_and_unknown_fields_are_rejected() {
    let mut value = serde_json::to_value(request()).unwrap();
    value["economic_terms_verified"] = json!(true);
    assert!(
        wholepact_core::parse_typed_json::<CandidateRequest>(&serde_json::to_vec(&value).unwrap())
            .is_err()
    );
}

#[test]
fn altered_candidate_snapshot_fails_closed_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("claims.sqlite");
    let engine = Engine::open(&path).unwrap();
    let input = request();
    create_intents(&engine, &input);
    let id = input.manifest.agreement.agreement_id.clone();
    let frozen = engine
        .create_candidate(&actor(), "candidate-freeze-command", &id, 3, input)
        .unwrap();
    let candidate_id = frozen.agreement.candidates[0].candidate_id.clone();
    let store = wholepact_store::Store::open(&path).unwrap();
    let mut record = store.get_agreement(&id).unwrap().unwrap();
    record.payload["view"]["candidates"][0]["accounting"]["authorization_allowed"] = json!(true);
    let c = wholepact_store::CommandContext::for_request(
        "test",
        "candidate-corruption",
        &json!({"synthetic_test":true}),
    )
    .unwrap();
    store
        .update_agreement(&c, &id, 4, record.payload, "synthetic_corruption")
        .unwrap();
    drop(engine);
    let engine = Engine::open(&path).unwrap();
    assert_eq!(
        engine.candidate(&actor(), &candidate_id).unwrap_err().code,
        "RECOVERY_REQUIRED"
    );
    assert_eq!(
        engine
            .review_candidate(&actor(), "candidate-review-corrupt", &candidate_id, 5)
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
}
