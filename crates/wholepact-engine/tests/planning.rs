use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wholepact_core::{AgreementDraft, Amount, FundingPolicy, IntentStatus, ParticipationIntent};
use wholepact_engine::{
    Access, CandidateRequest, Engine,
    planning::{MAX_COMPARISON_CHANGES, RosterSelectionRequest},
};

fn actor(id: &str, agreement: &str) -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: id.into(),
        agreement_ids: [agreement.into()].into(),
        ..Access::default()
    }
}
fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn draft(id: &str) -> AgreementDraft {
    let mut agreement: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.agreement_id = id.into();
    agreement.obligation_id = format!("obligation-{id}");
    agreement.recipients[0].amount = amount(100);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(100),
    };
    agreement
}
fn intent(id: &str, agreement: &str, desired: u64) -> ParticipationIntent {
    ParticipationIntent {
        intent_id: id.into(),
        agreement_id: agreement.into(),
        participant_id: format!("participant-{id}"),
        desired_contribution: amount(desired),
        maximum_net_debit: amount(desired + 10),
        fee_cap: amount(10),
        conditions: vec![],
        valid_until: None,
        status: IntentStatus::Active,
    }
}
fn selected(ids: &[&str]) -> RosterSelectionRequest {
    RosterSelectionRequest {
        selected_intent_ids: ids.iter().map(|id| (*id).into()).collect(),
    }
}
fn setup(engine: &Engine, id: &str) -> Access {
    let owner = actor("organizer", id);
    engine
        .create(&owner, &format!("create-agreement-{id}"), draft(id))
        .unwrap();
    for (index, (name, value)) in [("alice", 60), ("bob", 40), ("carol", 100)]
        .into_iter()
        .enumerate()
    {
        engine
            .add_intent(
                &actor(name, id),
                &format!("record-intent-{name}"),
                id,
                index as u64 + 1,
                intent(name, id, value),
            )
            .unwrap();
    }
    owner
}

#[test]
fn exact_roster_waitlists_excess_preserves_snapshots_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("planning.sqlite");
    let engine = Engine::open(&path).unwrap();
    let owner = setup(&engine, "roster");
    let selected_roster = engine
        .select_roster(
            &owner,
            "select-roster-first",
            "roster",
            4,
            selected(&["alice", "bob"]),
        )
        .unwrap();
    assert_eq!(
        selected_roster
            .agreement
            .intents
            .iter()
            .map(|i| i.status)
            .collect::<Vec<_>>(),
        [
            IntentStatus::Selected,
            IntentStatus::Selected,
            IntentStatus::Waitlisted
        ]
    );
    assert!(selected_roster.agreement.roster_selected);
    assert_eq!(
        selected_roster
            .agreement
            .intents
            .iter()
            .map(|i| i.desired_contribution.as_zatoshis())
            .collect::<Vec<_>>(),
        [60, 40, 100]
    );
    assert_eq!(selected_roster.agreement.authorization_exposure, "unknown");
    assert_eq!(selected_roster.agreement.chain_observation, "unknown");
    let first = engine
        .propose(&owner, "preview-roster-first", "roster", 5)
        .unwrap();
    let old = first.agreement.proposals[0].clone();
    assert_eq!(old.manifest["intents"].as_array().unwrap().len(), 2);
    engine
        .select_roster(
            &owner,
            "select-roster-second",
            "roster",
            6,
            selected(&["carol"]),
        )
        .unwrap();
    let second = engine
        .propose(&owner, "preview-roster-second", "roster", 7)
        .unwrap();
    let new = &second.agreement.proposals[1];
    assert_eq!(new.manifest["intents"][0]["intent_id"], "carol");
    assert_eq!(second.agreement.proposals[0].manifest, old.manifest);
    let before = engine.events(&owner, 0, 100).unwrap();
    let comparison = engine
        .compare_proposals(&owner, &old.proposal_id, &new.proposal_id)
        .unwrap();
    assert!(comparison.material_change && comparison.renewed_review_required);
    assert!(!comparison.signable);
    assert_eq!(comparison.scope, "nonbinding_terms_only");
    assert_eq!(comparison.changes.len(), 1);
    assert_eq!(comparison.changes[0].field, "intents");
    assert!(comparison.changes.len() <= MAX_COMPARISON_CHANGES);
    assert_eq!(before, engine.events(&owner, 0, 100).unwrap());
    assert_eq!(engine.get(&owner, "roster").unwrap().revision, 8);
    drop(engine);
    let restarted = Engine::open(&path).unwrap();
    let replay = restarted
        .select_roster(
            &owner,
            "select-roster-first",
            "roster",
            4,
            selected(&["alice", "bob"]),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, selected_roster.operation_id);
    assert_eq!(replay.agreement.revision, 5);
    assert_eq!(restarted.get(&owner, "roster").unwrap().revision, 8);
    assert_eq!(
        restarted
            .select_roster(
                &owner,
                "select-roster-first",
                "roster",
                4,
                selected(&["carol"])
            )
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        restarted
            .select_roster(
                &owner,
                "select-roster-stale",
                "roster",
                4,
                selected(&["carol"])
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
}

#[test]
fn selection_rejects_invalid_and_inexact_requests_without_partial_changes() {
    let engine = Engine::in_memory().unwrap();
    let owner = setup(&engine, "invalid");
    let before = serde_json::to_value(engine.get(&owner, "invalid").unwrap()).unwrap();
    let cases = [
        (selected(&[]), "INVALID_REQUEST"),
        (selected(&["alice", "alice"]), "INVALID_REQUEST"),
        (selected(&["alice", "missing"]), "INVALID_TERMS"),
        (selected(&["alice"]), "CONSERVATION_FAILURE"),
        (selected(&["alice", "carol"]), "CONSERVATION_FAILURE"),
        (selected(&["bad/id"]), "INVALID_REQUEST"),
        (
            RosterSelectionRequest {
                selected_intent_ids: vec!["x".repeat(129)],
            },
            "INVALID_REQUEST",
        ),
        (
            RosterSelectionRequest {
                selected_intent_ids: (0..33).map(|i| format!("id-{i}")).collect(),
            },
            "INVALID_REQUEST",
        ),
    ];
    for (index, (request, error)) in cases.into_iter().enumerate() {
        assert_eq!(
            engine
                .select_roster(
                    &owner,
                    &format!("invalid-selection-{index:04}"),
                    "invalid",
                    4,
                    request
                )
                .unwrap_err()
                .code,
            error
        );
        assert_eq!(
            serde_json::to_value(engine.get(&owner, "invalid").unwrap()).unwrap(),
            before
        );
    }
    assert!(
        serde_json::from_value::<RosterSelectionRequest>(
            json!({"selected_intent_ids":["alice"],"verified":true})
        )
        .is_err()
    );
}

#[test]
fn scoped_readers_cannot_select_or_propose_and_intent_owners_can_withdraw() {
    let engine = Engine::in_memory().unwrap();
    let owner = setup(&engine, "permissions");
    let alice = actor("alice", "permissions");
    assert_eq!(
        engine
            .select_roster(
                &alice,
                "reader-select-denied",
                "permissions",
                4,
                selected(&["alice", "bob"])
            )
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(
        engine
            .propose(&alice, "reader-preview-denied", "permissions", 4)
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    engine
        .select_roster(
            &owner,
            "owner-select-allowed",
            "permissions",
            4,
            selected(&["alice", "bob"]),
        )
        .unwrap();
    assert_eq!(
        engine
            .withdraw(&owner, "owner-withdraw-denied", "permissions", "alice", 5)
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    for (name, status) in [
        ("alice", IntentStatus::Selected),
        ("carol", IntentStatus::Waitlisted),
    ] {
        let current = engine.get(&owner, "permissions").unwrap();
        assert_eq!(
            current
                .intents
                .iter()
                .find(|i| i.intent_id == name)
                .unwrap()
                .status,
            status
        );
        let mut duplicate = intent(&format!("duplicate-{name}"), "permissions", 100);
        duplicate.participant_id = format!("participant-{name}");
        assert_eq!(
            engine
                .add_intent(
                    &actor(name, "permissions"),
                    &format!("duplicate-intent-{name}"),
                    "permissions",
                    current.revision,
                    duplicate
                )
                .unwrap_err()
                .code,
            "INVALID_TERMS"
        );
        engine
            .withdraw(
                &actor(name, "permissions"),
                &format!("withdraw-intent-{name}"),
                "permissions",
                name,
                current.revision,
            )
            .unwrap();
    }
    let current = engine.get(&owner, "permissions").unwrap();
    assert!(current.roster_selected);
    assert_eq!(current.intents[0].status, IntentStatus::Withdrawn);
    assert_eq!(current.intents[2].status, IntentStatus::Withdrawn);
}

#[test]
fn withdrawing_selected_intent_never_silently_substitutes_active_or_waitlisted_intents() {
    let engine = Engine::in_memory().unwrap();
    let owner = setup(&engine, "withdrawal");
    engine
        .select_roster(
            &owner,
            "withdrawal-roster-select",
            "withdrawal",
            4,
            selected(&["carol"]),
        )
        .unwrap();
    let old = engine
        .propose(&owner, "withdrawal-old-preview", "withdrawal", 5)
        .unwrap()
        .agreement
        .proposals[0]
        .clone();
    engine
        .withdraw(
            &actor("carol", "withdrawal"),
            "withdrawal-carol-intent",
            "withdrawal",
            "carol",
            6,
        )
        .unwrap();
    engine
        .add_intent(
            &actor("dave", "withdrawal"),
            "withdrawal-new-active",
            "withdrawal",
            7,
            intent("dave", "withdrawal", 100),
        )
        .unwrap();
    assert_eq!(
        engine
            .propose(&owner, "withdrawal-preview-blocked", "withdrawal", 8)
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    assert_eq!(
        engine.get(&owner, "withdrawal").unwrap().proposals[0].manifest,
        old.manifest
    );
    let repaired = engine
        .select_roster(
            &owner,
            "withdrawal-roster-repair",
            "withdrawal",
            8,
            selected(&["alice", "bob"]),
        )
        .unwrap();
    assert_eq!(
        repaired.agreement.intents[2].status,
        IntentStatus::Withdrawn
    );
    assert_eq!(
        repaired.agreement.intents[3].status,
        IntentStatus::Waitlisted
    );
    assert_eq!(
        engine
            .propose(&owner, "withdrawal-repaired-preview", "withdrawal", 9)
            .unwrap()
            .agreement
            .proposals
            .len(),
        2
    );
}

#[test]
fn expired_intents_deadlines_and_cancellation_block_roster_selection() {
    for mode in ["intent", "deadline", "cancellation"] {
        let engine = Engine::in_memory().unwrap();
        let owner = actor("owner", mode);
        let mut agreement = draft(mode);
        if mode == "deadline" {
            agreement.coordination_deadline = Some("2000-01-01T00:00:00Z".into());
        }
        engine
            .create(&owner, "expiry-create-agreement", agreement)
            .unwrap();
        let mut contribution = intent("expired", mode, 100);
        if mode == "intent" {
            contribution.valid_until = Some("2000-01-01T00:00:00Z".into());
        }
        engine
            .add_intent(&owner, "expiry-record-intent", mode, 1, contribution)
            .unwrap();
        let revision = if mode == "cancellation" {
            engine
                .cancel(&owner, "expiry-cancel-agreement", mode, 2)
                .unwrap()
                .agreement
                .revision
        } else {
            2
        };
        assert_eq!(
            engine
                .select_roster(
                    &owner,
                    "expiry-select-roster",
                    mode,
                    revision,
                    selected(&["expired"])
                )
                .unwrap_err()
                .code,
            "INVALID_TRANSITION"
        );
        let current = engine.get(&owner, mode).unwrap();
        assert!(!current.roster_selected);
        assert_eq!(current.revision, revision);
        assert_eq!(current.intents[0].status, IntentStatus::Active);
    }
}

#[test]
fn comparison_preserves_same_terms_review_requirement_and_access_boundaries() {
    let engine = Engine::in_memory().unwrap();
    let owner = actor("owner", "compare");
    engine
        .create(&owner, "compare-create-agreement", draft("compare"))
        .unwrap();
    let first = engine
        .propose(&owner, "compare-first-preview", "compare", 1)
        .unwrap()
        .agreement
        .proposals[0]
        .proposal_id
        .clone();
    let second = engine
        .propose(&owner, "compare-second-preview", "compare", 2)
        .unwrap()
        .agreement
        .proposals[1]
        .proposal_id
        .clone();
    let comparison = engine.compare_proposals(&owner, &first, &second).unwrap();
    assert!(!comparison.material_change);
    assert!(comparison.changes.is_empty());
    assert!(comparison.renewed_review_required);
    assert!(!comparison.signable);
    assert!(
        !engine
            .compare_proposals(&owner, &first, &first)
            .unwrap()
            .renewed_review_required
    );
    assert_eq!(
        engine
            .compare_proposals(&owner, &second, &first)
            .unwrap_err()
            .code,
        "INVALID_REQUEST"
    );
    assert_eq!(
        engine
            .compare_proposals(&actor("stranger", "unrelated"), &first, &second)
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    engine
        .create(&owner, "compare-create-other", draft("other"))
        .unwrap();
    let other = engine
        .propose(&owner, "compare-other-preview", "other", 1)
        .unwrap()
        .agreement
        .proposals[0]
        .proposal_id
        .clone();
    assert_eq!(
        engine
            .compare_proposals(&owner, &first, &other)
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
}

fn mutate_record(path: &std::path::Path, id: &str, edit: impl FnOnce(&mut Value)) {
    let store = wholepact_store::Store::open(path).unwrap();
    let mut record = store.get_agreement(id).unwrap().unwrap();
    edit(&mut record.payload);
    let context = wholepact_store::CommandContext::for_request(
        "test",
        "planning-test-mutation",
        &json!({"id":id}),
    )
    .unwrap();
    store
        .update_agreement(
            &context,
            id,
            record.revision,
            record.payload,
            "test_fixture_mutation",
        )
        .unwrap();
}

#[test]
fn comparison_rejects_corrupted_snapshots_outer_binding_and_unknown_fields() {
    for variant in ["digest", "binding", "unknown", "revision"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.sqlite");
        let engine = Engine::open(&path).unwrap();
        let owner = actor("owner", "corrupt");
        engine
            .create(&owner, "corrupt-create-agreement", draft("corrupt"))
            .unwrap();
        let id = engine
            .propose(&owner, "corrupt-preview-terms", "corrupt", 1)
            .unwrap()
            .agreement
            .proposals[0]
            .proposal_id
            .clone();
        mutate_record(&path, "corrupt", |payload| {
            let proposal = &mut payload["view"]["proposals"][0];
            match variant {
                "digest" => proposal["manifest"]["agreement"]["purpose"] = json!("tampered"),
                "binding" => proposal["agreement_id"] = json!("different-agreement"),
                "revision" => proposal["revision"] = json!(2),
                "unknown" => {
                    proposal["manifest"]["unexpected_required_evidence"] = json!(true);
                    let mut hash = Sha256::new();
                    hash.update(b"wholepact:terms-preview:v1\0");
                    hash.update(serde_json::to_vec(&proposal["manifest"]).unwrap());
                    proposal["manifest_digest"] = json!(hex::encode(hash.finalize()));
                }
                _ => unreachable!(),
            }
        });
        assert_eq!(
            engine.compare_proposals(&owner, &id, &id).unwrap_err().code,
            "RECOVERY_REQUIRED",
            "variant {variant}"
        );
    }
}

#[test]
fn legacy_records_without_roster_marker_remain_readable_and_preview_active_terms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.sqlite");
    let engine = Engine::open(&path).unwrap();
    let owner = setup(&engine, "legacy");
    mutate_record(&path, "legacy", |payload| {
        payload["view"]
            .as_object_mut()
            .unwrap()
            .remove("roster_selected");
    });
    let preview = engine
        .propose(&owner, "legacy-preview-terms", "legacy", 5)
        .unwrap();
    assert!(!preview.agreement.roster_selected);
    assert_eq!(
        preview.agreement.proposals[0].manifest["intents"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn exact_candidate_creation_honors_explicit_roster_and_owner_authority() {
    let engine = Engine::in_memory().unwrap();
    let request: CandidateRequest =
        serde_json::from_str(include_str!("fixtures/candidate-request.json")).unwrap();
    let id = request.manifest.agreement.agreement_id.clone();
    let owner = actor("owner", &id);
    engine
        .create(
            &owner,
            "candidate-roster-create",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    for (index, p) in request.manifest.participants.iter().enumerate() {
        let mut i = intent(&p.participant_id, &id, p.contribution.as_zatoshis());
        i.participant_id = p.participant_id.clone();
        i.fee_cap = p.fee_cap;
        i.maximum_net_debit = p.maximum_net_debit;
        engine
            .add_intent(
                &owner,
                &format!("candidate-roster-intent-{index}"),
                &id,
                index as u64 + 1,
                i,
            )
            .unwrap();
    }
    engine
        .add_intent(
            &owner,
            "candidate-roster-excess",
            &id,
            3,
            intent("alternate", &id, 300_000),
        )
        .unwrap();
    engine
        .select_roster(
            &owner,
            "candidate-roster-select",
            &id,
            4,
            selected(&["alice", "bob"]),
        )
        .unwrap();
    let reader = actor("reader", &id);
    assert_eq!(
        engine
            .create_candidate(&reader, "candidate-reader-denied", &id, 5, request.clone())
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    let mut reduced = request.clone();
    reduced.manifest.participants[0].contribution = amount(90_000);
    assert_eq!(
        engine
            .create_candidate(&owner, "candidate-no-reduction", &id, 5, reduced)
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
    let created = engine
        .create_candidate(&owner, "candidate-roster-freeze", &id, 5, request.clone())
        .unwrap();
    assert!(
        !created.agreement.candidates[0].accounting["authorization_allowed"]
            .as_bool()
            .unwrap()
    );
    engine
        .select_roster(
            &owner,
            "candidate-roster-replace",
            &id,
            6,
            selected(&["alternate"]),
        )
        .unwrap();
    let mut stale = request;
    stale.previous_candidate_id = Some(created.agreement.candidates[0].candidate_id.clone());
    assert_eq!(
        engine
            .create_candidate(&owner, "candidate-roster-stale", &id, 7, stale)
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
    assert_eq!(engine.get(&owner, &id).unwrap().candidates.len(), 1);
}

#[test]
fn terminal_intents_remain_untouched_and_expired_selected_roster_blocks_new_preview() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("terminal.sqlite");
    let engine = Engine::open(&path).unwrap();
    let owner = setup(&engine, "terminal");
    mutate_record(&path, "terminal", |payload| {
        payload["view"]["intents"][0]["status"] = json!("expired");
        payload["view"]["intents"][1]["status"] = json!("declined");
    });
    assert_eq!(
        engine
            .select_roster(
                &owner,
                "terminal-select-blocked",
                "terminal",
                5,
                selected(&["alice", "bob"])
            )
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    let selected = engine
        .select_roster(
            &owner,
            "terminal-select-carol",
            "terminal",
            5,
            selected(&["carol"]),
        )
        .unwrap();
    assert_eq!(selected.agreement.intents[0].status, IntentStatus::Expired);
    assert_eq!(selected.agreement.intents[1].status, IntentStatus::Declined);
    let snapshot = engine
        .propose(&owner, "terminal-previous-preview", "terminal", 6)
        .unwrap()
        .agreement
        .proposals[0]
        .clone();
    // Model the clock becoming later than a stored validity deadline without
    // introducing a wall-clock sleep into a deterministic regression test.
    let store = wholepact_store::Store::open(&path).unwrap();
    let mut record = store.get_agreement("terminal").unwrap().unwrap();
    record.payload["view"]["intents"][2]["valid_until"] = json!("2000-01-01T00:00:00Z");
    let context = wholepact_store::CommandContext::for_request(
        "test",
        "terminal-expiry-fixture",
        &json!({"expiry":true}),
    )
    .unwrap();
    store
        .update_agreement(
            &context,
            "terminal",
            7,
            record.payload,
            "test_expiry_fixture",
        )
        .unwrap();
    assert_eq!(
        engine
            .propose(&owner, "terminal-expired-preview", "terminal", 8)
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    assert_eq!(
        engine.get(&owner, "terminal").unwrap().proposals[0].manifest,
        snapshot.manifest
    );
    assert!(
        !engine
            .compare_proposals(&owner, &snapshot.proposal_id, &snapshot.proposal_id)
            .unwrap()
            .signable
    );
}

#[test]
fn candidate_comparison_reports_fees_accounts_inputs_outputs_and_expiry_without_review_transfer() {
    let engine = Engine::in_memory().unwrap();
    let request: CandidateRequest =
        serde_json::from_str(include_str!("fixtures/candidate-request.json")).unwrap();
    let id = request.manifest.agreement.agreement_id.clone();
    let owner = actor("owner", &id);
    engine
        .create(
            &owner,
            "comparison-candidate-create",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    for (index, p) in request.manifest.participants.iter().enumerate() {
        let mut i = intent(&p.participant_id, &id, p.contribution.as_zatoshis());
        i.participant_id = p.participant_id.clone();
        i.fee_cap = p.fee_cap;
        i.maximum_net_debit = p.maximum_net_debit;
        engine
            .add_intent(
                &owner,
                &format!("comparison-candidate-intent-{index}"),
                &id,
                index as u64 + 1,
                i,
            )
            .unwrap();
    }
    let first = engine
        .create_candidate(
            &owner,
            "comparison-candidate-first",
            &id,
            3,
            request.clone(),
        )
        .unwrap()
        .agreement
        .candidates[0]
        .clone();
    let mut revised = request.clone();
    revised.previous_candidate_id = Some(first.candidate_id.clone());
    revised.manifest.transaction_fee = amount(7_500);
    revised.manifest.participants[0].fee_share = amount(2_500);
    revised.manifest.participants[1].fee_share = amount(5_000);
    revised.manifest.participants[0].account_id = "account-alice-revised".into();
    revised.manifest.inputs[0].account_id = "account-alice-revised".into();
    revised.manifest.inputs[0].amount = amount(210_000);
    revised.manifest.outputs[1].amount = amount(107_500);
    revised.manifest.outputs[2].amount = amount(95_000);
    revised.manifest.outputs[1].address = "utestsyntheticrevisedchange".into();
    if let wholepact_core::OutputAllocation::Return { account_id, .. } =
        &mut revised.manifest.outputs[1].allocation
    {
        *account_id = "account-alice-revised".into();
    }
    revised.manifest.expiry_height += 1;
    let second = engine
        .create_candidate(&owner, "comparison-candidate-second", &id, 4, revised)
        .unwrap()
        .agreement
        .candidates[1]
        .clone();
    let events = engine.events(&owner, 0, 100).unwrap();
    let comparison = engine
        .compare_candidates(&owner, &first.candidate_id, &second.candidate_id)
        .unwrap();
    assert_eq!(comparison.scope, "unsigned_candidate_claims");
    assert!(comparison.material_change && comparison.renewed_review_required);
    assert!(!comparison.signable);
    assert_eq!(
        comparison
            .changes
            .iter()
            .map(|c| c.field.as_str())
            .collect::<Vec<_>>(),
        [
            "participants",
            "inputs",
            "outputs",
            "transaction_fee",
            "expiry_height"
        ]
    );
    let fee = comparison
        .changes
        .iter()
        .find(|c| c.field == "transaction_fee")
        .unwrap();
    assert_eq!(fee.older, "15000");
    assert_eq!(fee.newer, "7500");
    assert_eq!(engine.events(&owner, 0, 100).unwrap(), events);
    let current = engine.get(&owner, &id).unwrap();
    assert_eq!(current.revision, 5);
    assert_eq!(current.candidates[0].proposal, first.proposal);
    assert!(current.candidates.iter().all(|c| c.reviews.is_empty()));
    assert!(
        !engine
            .compare_candidates(&owner, &first.candidate_id, &first.candidate_id)
            .unwrap()
            .renewed_review_required
    );
    assert_eq!(
        engine
            .compare_candidates(&owner, &second.candidate_id, &first.candidate_id)
            .unwrap_err()
            .code,
        "INVALID_REQUEST"
    );
    assert_eq!(
        engine
            .compare_candidates(
                &actor("stranger", "other"),
                &first.candidate_id,
                &second.candidate_id
            )
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );

    let mut other = request;
    other.manifest.agreement.agreement_id = "other-candidate-agreement".into();
    other.manifest.agreement.obligation_id = "other-candidate-obligation".into();
    let other_id = other.manifest.agreement.agreement_id.clone();
    engine
        .create(
            &owner,
            "comparison-other-create",
            other.manifest.agreement.clone(),
        )
        .unwrap();
    for (index, p) in other.manifest.participants.iter().enumerate() {
        let mut i = intent(&p.participant_id, &other_id, p.contribution.as_zatoshis());
        i.participant_id = p.participant_id.clone();
        i.fee_cap = p.fee_cap;
        i.maximum_net_debit = p.maximum_net_debit;
        engine
            .add_intent(
                &owner,
                &format!("comparison-other-intent-{index}"),
                &other_id,
                index as u64 + 1,
                i,
            )
            .unwrap();
    }
    let other = engine
        .create_candidate(&owner, "comparison-other-freeze", &other_id, 3, other)
        .unwrap()
        .agreement
        .candidates[0]
        .candidate_id
        .clone();
    assert_eq!(
        engine
            .compare_candidates(&owner, &first.candidate_id, &other)
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
}
