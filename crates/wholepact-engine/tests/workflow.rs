use serde_json::json;
use wholepact_core::{AgreementDraft, ParticipationIntent};
use wholepact_engine::{Access, Engine};

fn actor(id: &str) -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: id.into(),
        ..Access::default()
    }
}
fn draft(id: &str) -> AgreementDraft {
    let mut d: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    d.agreement_id = id.into();
    d.obligation_id = format!("obligation-{id}");
    d
}
fn intent(id: &str) -> ParticipationIntent {
    serde_json::from_value(json!({"intent_id":"intent-1","agreement_id":id,"participant_id":"participant-1","desired_contribution":"1000000000","maximum_net_debit":"1000010000","fee_cap":"10000","conditions":[],"valid_until":null,"status":"active"})).unwrap()
}

#[test]
fn persisted_complete_nonbinding_workflow_and_safe_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let user = actor("owner");
    let engine = Engine::open(&path).unwrap();
    let d = draft("agreement-1");
    let created = engine
        .create(&user, "create-command-0001", d.clone())
        .unwrap();
    assert_eq!(created.agreement.revision, 1);
    let replay = engine.create(&user, "create-command-0001", d).unwrap();
    assert_eq!(created.operation_id, replay.operation_id);
    assert!(replay.replayed);
    let added = engine
        .add_intent(
            &user,
            "intent-command-0001",
            "agreement-1",
            1,
            intent("agreement-1"),
        )
        .unwrap();
    assert_eq!(added.agreement.revision, 2);
    assert_eq!(
        engine
            .propose(&user, "stale-command-0001", "agreement-1", 1)
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let preview = engine
        .propose(&user, "preview-command-001", "agreement-1", 2)
        .unwrap();
    assert_eq!(
        preview.agreement.proposals[0].status,
        "terms_only_not_signable"
    );
    let proposal_id = preview.agreement.proposals[0].proposal_id.clone();
    let reviewed = engine
        .review(&user, "review-command-0001", &proposal_id, 3)
        .unwrap();
    assert_eq!(
        reviewed.agreement.verification_reports[0].status,
        "unsupported"
    );
    assert_eq!(
        reviewed.agreement.verification_reports[0].review_summary["signable"],
        false
    );
    let cancelled = engine
        .cancel(&user, "cancel-command-0001", "agreement-1", 4)
        .unwrap();
    assert!(cancelled.agreement.cancellation_requested);
    assert_eq!(cancelled.agreement.authorization_exposure, "unknown");
    assert_eq!(cancelled.agreement.chain_observation, "unknown");
    drop(engine);
    let restarted = Engine::open(path).unwrap();
    assert_eq!(restarted.get(&user, "agreement-1").unwrap().revision, 5);
    let replay = restarted
        .review(&user, "review-command-0001", &proposal_id, 3)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, reviewed.operation_id);
    assert_eq!(replay.agreement.revision, 4);
    assert_eq!(
        restarted.recovery(&user).unwrap()["new_authorization_allowed"],
        false
    );
}

#[test]
fn changed_payload_same_key_conflicts_and_grants_control_replay() {
    let e = Engine::in_memory().unwrap();
    let owner = actor("owner");
    let mut other = actor("other");
    e.create(&owner, "create-command-0001", draft("private"))
        .unwrap();
    assert!(e.get(&other, "private").is_err());
    assert!(e.list(&other).unwrap().is_empty());
    other.agreement_ids.insert("private".into());
    let first = e
        .add_intent(
            &other,
            "intent-command-0001",
            "private",
            1,
            intent("private"),
        )
        .unwrap();
    let mut changed = intent("private");
    changed.conditions.push("Changed condition".into());
    assert_eq!(
        e.add_intent(&other, "intent-command-0001", "private", 1, changed)
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    other.agreement_ids.clear();
    assert_eq!(
        e.add_intent(
            &other,
            "intent-command-0001",
            "private",
            1,
            intent("private")
        )
        .unwrap_err()
        .code,
        "NOT_FOUND"
    );
    assert!(e.operation(&other, &first.operation_id).is_err());
    assert!(
        e.events(&other, 0, 100)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        e.withdraw(&owner, "withdraw-command-01", "private", "intent-1", 2)
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
}

#[test]
fn hidden_event_prefix_does_not_starve_allowed_replay() {
    let e = Engine::in_memory().unwrap();
    let hidden = actor("hidden");
    let hidden_second = actor("hidden-second");
    let visible = actor("visible");
    for i in 0..110 {
        e.create(
            if i < 55 { &hidden } else { &hidden_second },
            &format!("hidden-create-{i:016}"),
            draft(&format!("hidden-{i}")),
        )
        .unwrap();
    }
    e.create(&visible, "visible-create-0001", draft("visible"))
        .unwrap();
    let (events, cursor) = e.event_batch(&visible, 0, 100).unwrap();
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["aggregate_id"], "visible");
    assert_eq!(cursor, 111);
}

#[test]
fn corrupted_preview_cannot_claim_integrity_pass() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let user = actor("owner");
    let e = Engine::open(&path).unwrap();
    e.create(&user, "create-command-0001", draft("agreement"))
        .unwrap();
    let p = e
        .propose(&user, "preview-command-001", "agreement", 1)
        .unwrap();
    let id = p.agreement.proposals[0].proposal_id.clone();
    let store = wholepact_store::Store::open(path).unwrap();
    let mut record = store.get_agreement("agreement").unwrap().unwrap();
    record.payload["view"]["proposals"][0]["manifest"]["scope"] = json!("corrupted");
    let context = wholepact_store::CommandContext::for_request(
        "test",
        "corruption-test-key",
        &json!({"test":"corruption"}),
    )
    .unwrap();
    store
        .update_agreement(&context, "agreement", 2, record.payload, "test_corruption")
        .unwrap();
    assert_eq!(
        e.review(&user, "review-command-0001", &id, 3)
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
}

#[test]
fn mainnet_and_unknown_profiles_fail_closed() {
    let engine = Engine::in_memory().unwrap();
    let user = actor("owner");
    for profile in ["zcash-mainnet", "zcash-testnet-unknown-version"] {
        let mut agreement = draft("unsupported");
        agreement.network_profile_id = profile.into();
        assert_eq!(
            engine.validate(&agreement).unwrap_err().code,
            "UNSUPPORTED_CAPABILITY"
        );
        assert_eq!(
            engine
                .create(&user, "unsupported-create-01", agreement)
                .unwrap_err()
                .code,
            "UNSUPPORTED_CAPABILITY"
        );
    }
}

#[test]
fn public_event_preserves_persisted_millisecond_timestamp() {
    let stored = wholepact_store::StoredEvent {
        event_id: "event-42".into(),
        sequence: 42,
        occurred_at_ms: 1_792_000_000_123,
        aggregate_type: "agreement".into(),
        aggregate_id: "agreement-1".into(),
        aggregate_revision: 3,
        kind: "intent_recorded".into(),
        payload: json!({"id":"agreement-1","revision":3}),
        operation_id: "operation-42".into(),
    };
    let expected = time::OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(stored.occurred_at_ms) * 1_000_000,
    )
    .unwrap()
    .format(&time::format_description::well_known::Rfc3339)
    .unwrap();
    let public = wholepact_engine::Event::try_from(stored.clone()).unwrap();
    assert_eq!(public.occurred_at, expected);
    assert_eq!(public.event_id, stored.event_id);
    assert_eq!(public.sequence, stored.sequence);
    assert_eq!(public.operation_id, stored.operation_id);
}

#[test]
fn private_aggregate_id_collision_never_leaks_into_agreement_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-metadata.sqlite");
    let e = Engine::open(&path).unwrap();
    let owner = actor("owner");
    e.create(&owner, "create-visible-collision", draft("same-id"))
        .unwrap();
    let store = wholepact_store::Store::open(&path).unwrap();
    let context = wholepact_store::CommandContext::for_request(
        "private-runtime",
        "private-record-collision",
        &json!({"synthetic":true}),
    )
    .unwrap();
    store
        .commit_record(
            &context,
            "private_fixture",
            "same-id",
            None,
            json!({"private_field":"must-not-leak"}),
            "private_fixture_created",
        )
        .unwrap();
    let (events, cursor) = e.event_batch(&owner, 0, 100).unwrap();
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["aggregate_type"], "agreement");
    assert!(!events.to_string().contains("must-not-leak"));
    assert_eq!(cursor, 2);
}
