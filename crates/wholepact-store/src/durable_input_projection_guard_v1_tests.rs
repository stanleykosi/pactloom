//! Storage-only synthetic metadata, no native disclosure or authority claims.
use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use wholepact_storage_security::DatabaseKey;

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn payload(store: &Store, path: &Path) -> Value {
    let origin = hex::encode(store.verify_original_encrypted_destination(path).unwrap());
    let a = json!({"operation_id":"discover-a", "intent": {"account_id": "synthetic-a", "protected_destination": path}});
    let b = json!({"operation_id":"discover-b", "intent": {"account_id": "synthetic-b", "protected_destination": path}});
    json!({"durable_input_projections_v1": {"synthetic-round": {
        "metadata_origin": origin,
        "requests": {"synthetic-a": a.clone(), "synthetic-b": b},
        "intakes": {"synthetic-a": {"outbox": {"request": a}}}
    }}})
}
fn check(store: &Store, payload: &Value) -> Result<()> {
    store.check_durable_projection_destination_v1(&store.connection.lock().unwrap(), payload)
}

#[test]
fn projection_destination_requires_actual_original_encrypted_file() {
    let dir = directory();
    let path = dir.path().join("projection.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([72; 32])).unwrap();
    let valid = payload(&store, &path);
    check(&store, &valid).unwrap();
    for mutation in 0..7 {
        let mut changed = valid.clone();
        let round = &mut changed["durable_input_projections_v1"]["synthetic-round"];
        match mutation {
            0 => round["metadata_origin"] = json!("00".repeat(32)),
            1 => {
                round["requests"]["synthetic-a"]["intent"]["protected_destination"] =
                    json!("relative.sqlite")
            }
            2 => round["requests"]["synthetic-a"]["intent"]["account_id"] = json!("synthetic-b"),
            3 => {
                round["requests"]
                    .as_object_mut()
                    .unwrap()
                    .remove("synthetic-b");
            }
            4 => round["intakes"]["foreign-account"] = json!({}),
            5 => round["intakes"]["synthetic-a"]["outbox"]["request"] = json!({}),
            _ => round["intakes"] = json!([]),
        }
        assert!(check(&store, &changed).is_err(), "mutation {mutation}");
    }
    let memory = Store::in_memory().unwrap();
    assert!(check(&memory, &valid).is_err());
    check(&memory, &json!({"durable_input_projections_v1": {}})).unwrap();
    check(&memory, &json!({"ordinary": "legacy"})).unwrap();
    for value in [json!(null), json!([]), json!(true), json!("wrong")] {
        assert!(check(&store, &json!({"durable_input_projections_v1": value})).is_err());
    }
}

#[test]
fn projection_destination_rejects_same_path_replacement_and_other_original() {
    let dir = directory();
    let path = dir.path().join("projection.sqlite");
    let other_path = dir.path().join("other.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([73; 32])).unwrap();
    let other = Store::create_encrypted(&other_path, &DatabaseKey::from_bytes([74; 32])).unwrap();
    let valid = payload(&store, &path);
    assert!(check(&other, &valid).is_err());
    std::fs::rename(&path, dir.path().join("preserved-original.sqlite")).unwrap();
    // Contents do not matter: the retained open original file identity must
    // reject a different inode at the exact approved path before any admission.
    std::fs::copy(&other_path, &path).unwrap();
    assert!(check(&store, &valid).is_err());
}

fn command(key: &str) -> CommandContext {
    CommandContext::for_request("synthetic-owner", key, &json!({"synthetic":true})).unwrap()
}
fn empty_record(store: &Store) -> (CommandContext, MutationResult) {
    let context = command("synthetic-agreement-create");
    let result = store
        .create_agreement(&context, "agreement", json!({}))
        .unwrap();
    (context, result)
}
fn counts(store: &Store) -> Vec<u64> {
    let connection = store.connection.lock().unwrap();
    [
        "records",
        "operations",
        "idempotency",
        "events",
        "authority_exposures",
        "authority_events",
    ]
    .iter()
    .map(|table| {
        connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    })
    .collect()
}

#[test]
fn capture_intents_join_exact_saved_operation_account_and_original_destination() {
    let dir = directory();
    let path = dir.path().join("capture.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([80; 32])).unwrap();
    let mut valid = payload(&store, &path);
    valid[PROJECTION_KEY]["synthetic-round"]["capture_intents"] = json!({
        "capture-a": {"request": {"operation_id":"capture-a", "scope":{
            "account_id":"synthetic-a", "protected_destination":path
        }}}
    });
    check(&store, &valid).unwrap();
    for mutation in 0..10 {
        let mut changed = valid.clone();
        let round = &mut changed[PROJECTION_KEY]["synthetic-round"];
        match mutation {
            0 => round["capture_intents"] = json!(null),
            1 => round["capture_intents"] = json!([]),
            2 => {
                round["capture_intents"]["capture-a"]["request"]["operation_id"] =
                    json!("substituted")
            }
            3 => {
                round["capture_intents"]["capture-a"]["request"]["scope"]["account_id"] =
                    json!("foreign")
            }
            4 => {
                round["capture_intents"]["capture-a"]["request"]["scope"]["protected_destination"] =
                    json!("relative.sqlite")
            }
            5 => {
                round["capture_intents"]["capture-a"]["padding"] =
                    json!("x".repeat(MAX_CAPTURE_INTENT_BYTES))
            }
            6 => {
                let capture = round["capture_intents"]["capture-a"].take();
                round["capture_intents"]["discover-a"] = capture;
                round["capture_intents"]["discover-a"]["request"]["operation_id"] =
                    json!("discover-a");
            }
            7 => round["requests"]["synthetic-b"]["operation_id"] = json!("discover-a"),
            8 => {
                for index in 0..5 {
                    let mut capture = round["capture_intents"]["capture-a"].clone();
                    let operation = format!("capture-{index}");
                    capture["request"]["operation_id"] = json!(operation);
                    round["capture_intents"][&operation] = capture;
                }
            }
            _ => round["intakes"] = json!({}),
        }
        assert!(check(&store, &changed).is_err(), "mutation {mutation}");
    }
}

#[test]
fn public_mutation_reads_and_replay_validate_actual_retained_private_result() {
    let dir = directory();
    let path = dir.path().join("live.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([81; 32])).unwrap();
    let private = payload(&store, &path);
    let context = command("synthetic-private-create");
    let original = store
        .create_agreement(&context, "agreement", private.clone())
        .unwrap();
    assert_eq!(
        store.get_agreement("agreement").unwrap().unwrap(),
        original.record
    );
    assert_eq!(
        store.list_agreements().unwrap(),
        vec![original.record.clone()]
    );
    assert!(
        store
            .get_operation(&original.operation_id)
            .unwrap()
            .is_some()
    );
    assert!(store.find_replay(&context).unwrap().unwrap().replayed);
    assert_eq!(
        store
            .create_agreement(&context, "agreement", json!({}))
            .unwrap()
            .record
            .payload,
        private
    );
    store
        .update_agreement(
            &command("synthetic-private-clear"),
            "agreement",
            1,
            json!({}),
            "agreement.updated",
        )
        .unwrap();
    // Historical payload is checked even though the current record and incoming
    // retry no longer contain private metadata.
    let mut wrong = serde_json::to_value(&original).unwrap();
    wrong["record"]["payload"][PROJECTION_KEY]["synthetic-round"]["metadata_origin"] =
        json!("00".repeat(32));
    let connection = store.connection.lock().unwrap();
    connection
        .execute(
            "UPDATE operations SET result=?1 WHERE operation_id=?2",
            params![wrong.to_string(), original.operation_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE idempotency SET result=?1 WHERE idempotency_key=?2",
            params![wrong.to_string(), context.idempotency_key],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        store.get_agreement("agreement").unwrap().unwrap().payload,
        json!({})
    );
    assert!(store.get_operation(&original.operation_id).is_err());
    assert!(store.find_replay(&context).is_err());
    let before = counts(&store);
    assert!(
        store
            .create_agreement(&context, "agreement", json!({}))
            .is_err()
    );
    assert_eq!(counts(&store), before);
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE records SET payload=?1 WHERE id='agreement'",
            [wrong["record"]["payload"].to_string()],
        )
        .unwrap();
    assert!(store.get_agreement("agreement").is_err());
    assert!(store.list_agreements().is_err());
    assert!(
        store
            .update_agreement(
                &command("synthetic-strip-wrong"),
                "agreement",
                2,
                json!({}),
                "agreement.updated"
            )
            .is_err()
    );
}

#[test]
fn public_writes_refuse_plaintext_memory_wrong_original_and_recovered_state() {
    let dir = directory();
    let path = dir.path().join("original.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([82; 32])).unwrap();
    let private = payload(&store, &path);
    let other = Store::create_encrypted(
        dir.path().join("other.sqlite"),
        &DatabaseKey::from_bytes([83; 32]),
    )
    .unwrap();
    let plain = Store::open(dir.path().join("plain.sqlite")).unwrap();
    for rejected in [Store::in_memory().unwrap(), plain, other] {
        let before = counts(&rejected);
        assert!(
            rejected
                .create_agreement(
                    &command("synthetic-denied-write"),
                    "agreement",
                    private.clone()
                )
                .is_err()
        );
        assert_eq!(counts(&rejected), before);
    }
    // This exercises the independent recovered-handle denial predicate only;
    // authenticated generation and original/layer fixtures live in recovery's
    // dedicated regression module, not in a fabricated database checkpoint.
    let mut recovered_flag = store;
    recovered_flag.recovered_generation = true;
    assert!(check(&recovered_flag, &private).is_err());
}

#[test]
fn precommit_path_replacement_rolls_back_but_postcommit_refusal_preserves_effect() {
    for after_commit in [false, true] {
        let dir = directory();
        let path = dir.path().join("original.sqlite");
        let preserved = dir.path().join("preserved.sqlite");
        let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([84; 32])).unwrap();
        let private = payload(&store, &path);
        let hook_path = path.clone();
        COMMIT_HOOK.with(|slot| {
            *slot.borrow_mut() = Some((
                after_commit,
                Box::new(move || {
                    std::fs::rename(&hook_path, &preserved).unwrap();
                    std::fs::write(&hook_path, [0u8; 4096]).unwrap();
                    std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }),
            ))
        });
        assert!(
            store
                .create_agreement(&command("synthetic-raced-write"), "agreement", private)
                .is_err()
        );
        let actual = counts(&store);
        assert_eq!(
            &actual[..4],
            if after_commit {
                &[1, 1, 1, 1]
            } else {
                &[0, 0, 0, 0]
            }
        );
        // No cleanup, replay, compensating delete, or claim that a postcommit
        // refusal erased already-durable evidence.
    }
}

fn release() -> crate::authority::ReleaseIntent {
    crate::authority::ReleaseIntent {
        authorization_id: "synthetic-authorization".into(),
        account_id: "synthetic-account".into(),
        writer_epoch: 1,
        obligation_id: "synthetic-obligation".into(),
        proposal_id: "synthetic-proposal".into(),
        manifest_digest: "a".repeat(64),
        effects_digest: "b".repeat(64),
        artifact_digest: "c".repeat(64),
        maximum_debit: "1".into(),
        input_ids: vec!["synthetic-input".into()],
        aggregate_budget_limit: "2".into(),
    }
}

#[test]
fn direct_settlement_refuses_private_current_replacement_snapshot_and_saved_replay() {
    for mode in 0..4 {
        let dir = directory();
        let path = dir.path().join("settlement.sqlite");
        let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([85; 32])).unwrap();
        let private = payload(&store, &path);
        let (_, initial) = empty_record(&store);
        let mut snapshot = vec![initial.record.clone()];
        let mut updates = vec![("agreement".into(), json!({}))];
        match mode {
            0 => {
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute(
                        "UPDATE records SET payload=?1 WHERE id='agreement'",
                        [private.to_string()],
                    )
                    .unwrap();
            }
            1 => updates[0].1 = private,
            2 => snapshot[0].payload = private,
            _ => {
                // Create the actual checkpoint via the supported path, then
                // retain private history only in a saved mutation result.
                store
                    .reopen_settlement_obligation(
                        "synthetic-evidence",
                        "synthetic-obligation",
                        &snapshot,
                        &[],
                        &[],
                    )
                    .unwrap();
                let mut saved = serde_json::to_value(initial).unwrap();
                saved["record"]["payload"] = private;
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute("UPDATE idempotency SET result=?1", [saved.to_string()])
                    .unwrap();
            }
        }
        let before = counts(&store);
        assert!(
            store
                .reopen_settlement_obligation(
                    "synthetic-evidence",
                    "synthetic-obligation",
                    &snapshot,
                    &[],
                    &updates
                )
                .is_err()
        );
        assert!(
            store
                .consume_exact_settlement_release(
                    &release(),
                    "synthetic-release",
                    &json!({}),
                    &snapshot,
                    &updates,
                    &|| Ok(())
                )
                .is_err()
        );
        assert_eq!(counts(&store), before);
    }
}

#[test]
fn exact_settlement_saved_checkpoint_replay_refuses_private_history() {
    let dir = directory();
    let path = dir.path().join("settlement-replay.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([86; 32])).unwrap();
    let (_, initial) = empty_record(&store);
    let snapshot = vec![initial.record.clone()];
    let intent = release();
    store
        .consume_exact_settlement_release(
            &intent,
            "synthetic-release",
            &json!({}),
            &snapshot,
            &[],
            &|| Ok(()),
        )
        .unwrap();
    let mut saved = serde_json::to_value(initial).unwrap();
    saved["record"]["payload"] = payload(&store, &path);
    store
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE operations SET result=?1", [saved.to_string()])
        .unwrap();
    let before = counts(&store);
    assert!(
        store
            .consume_exact_settlement_release(
                &intent,
                "synthetic-release",
                &json!({}),
                &snapshot,
                &[],
                &|| Ok(())
            )
            .is_err()
    );
    assert_eq!(counts(&store), before);
}

#[test]
fn public_reads_refuse_file_substitution_even_for_saved_private_replay() {
    let dir = directory();
    let path = dir.path().join("read-original.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([87; 32])).unwrap();
    let context = command("synthetic-original-read");
    let result = store
        .create_agreement(&context, "agreement", payload(&store, &path))
        .unwrap();
    std::fs::rename(&path, dir.path().join("preserved-read-original.sqlite")).unwrap();
    std::fs::write(&path, [0u8; 4096]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.get_agreement("agreement").is_err());
    assert!(store.list_agreements().is_err());
    assert!(store.get_operation(&result.operation_id).is_err());
    assert!(store.find_replay(&context).is_err());
    assert!(
        store
            .create_agreement(&context, "agreement", json!({}))
            .is_err()
    );
    assert_eq!(&counts(&store)[..4], &[1, 1, 1, 1]);
}
