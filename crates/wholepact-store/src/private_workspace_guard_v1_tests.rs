//! Synthetic first-write storage regressions. No native association or approval.
use super::*;
use crate::private_workspace_origin_v1::{
    PRIVATE_WORKSPACE_ORIGIN_KEY_V1 as KEY, PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1,
    PrivateWorkspaceOriginV1,
};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use wholepact_storage_security::DatabaseKey;

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Store) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("workspace.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([91; 32])).unwrap();
    (directory, path, store)
}
fn command(key: &str) -> CommandContext {
    CommandContext::for_request("synthetic-constructor", key, &json!({"seed":true})).unwrap()
}
fn payload(store: &Store, path: &Path) -> Value {
    let marker = PrivateWorkspaceOriginV1 {
        version: 1,
        purpose: PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1.into(),
        native_association_digest: "11".repeat(32),
        source_digest: "22".repeat(32),
        principal_id: "synthetic-constructor".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        reviewer_account_ids: vec!["33".repeat(32), "44".repeat(32)],
        protected_destination: path.to_str().unwrap().into(),
        retention_policy: "synthetic-local-only".into(),
        metadata_origin: hex::encode(store.verify_original_encrypted_destination(path).unwrap()),
    };
    json!({KEY: marker, "owner_client_id":"synthetic-constructor",
        "view":{"agreement":{"agreement_id":"agreement","obligation_id":"obligation"}},
        "durable_construction_v1":{},"durable_input_projections_v1":{}})
}
fn counts(store: &Store) -> Vec<u64> {
    let c = store.connection.lock().unwrap();
    [
        "records",
        "operations",
        "idempotency",
        "events",
        "authority_accounts",
        "authority_exposures",
        "authority_reservations",
        "authority_events",
        "effect_intents",
    ]
    .iter()
    .map(|table| {
        c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    })
    .collect()
}
fn seed(store: &Store, path: &Path) -> (CommandContext, MutationResult) {
    let context = command("synthetic-private-seed");
    let result = store
        .create_agreement(&context, "agreement", payload(store, path))
        .unwrap();
    (context, result)
}

#[test]
fn marker_only_seed_is_atomic_readable_on_exact_original_and_reopens_unchanged() {
    let (_dir, path, store) = fixture();
    let (context, first) = seed(&store, &path);
    assert!(counts(&store) == [1, 1, 1, 1, 0, 0, 0, 0, 0]);
    assert!(store.get_agreement("agreement").unwrap().unwrap() == first.record);
    assert!(store.list_agreements().unwrap() == [first.record.clone()]);
    assert!(store.get_operation(&first.operation_id).unwrap().is_some());
    assert!(store.find_replay(&context).unwrap().unwrap().record == first.record);
    let events = store.events_after(0, 10).unwrap();
    assert!(events.len() == 1 && events[0].payload == json!({"id":"agreement","revision":1}));
    drop(store);
    let reopened = Store::open_encrypted(&path, &DatabaseKey::from_bytes([91; 32])).unwrap();
    assert!(reopened.get_agreement("agreement").unwrap().unwrap() == first.record);
    assert!(reopened.find_replay(&context).unwrap().unwrap().record == first.record);
}

#[test]
fn marker_seed_event_failure_rolls_back_all_first_write_rows() {
    let (_dir, path, store) = fixture();
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER fail_seed_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'synthetic'); END;"
    ).unwrap();
    assert!(
        store
            .create_agreement(
                &command("synthetic-failed-seed"),
                "agreement",
                payload(&store, &path)
            )
            .is_err()
    );
    assert!(counts(&store) == [0; 9]);
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_seed_event")
        .unwrap();
    seed(&store, &path);
}

#[test]
fn marker_transitions_reject_strip_replace_relabel_and_add_to_legacy() {
    let (_dir, path, store) = fixture();
    let (_, first) = seed(&store, &path);
    let before = counts(&store);
    for change in 0..6 {
        let mut changed = first.record.payload.clone();
        match change {
            0 => {
                changed.as_object_mut().unwrap().remove(KEY);
            }
            1 => changed[KEY]["source_digest"] = json!("66".repeat(32)),
            2 => changed[KEY]["native_association_digest"] = json!("66".repeat(32)),
            3 => changed[KEY]["retention_policy"] = json!("other-retention"),
            4 => changed["owner_client_id"] = json!("other-owner"),
            _ => changed["view"]["agreement"]["obligation_id"] = json!("other-obligation"),
        }
        assert!(
            store
                .update_agreement(
                    &command("synthetic-marker-change"),
                    "agreement",
                    1,
                    changed,
                    "agreement.updated"
                )
                .is_err()
        );
        assert!(counts(&store) == before);
        assert!(store.get_agreement("agreement").unwrap().unwrap() == first.record);
    }
    let other = CommandContext::for_request("other-principal", "synthetic-other-owner", &json!({}))
        .unwrap();
    assert!(
        store
            .update_agreement(
                &other,
                "agreement",
                1,
                first.record.payload.clone(),
                "agreement.updated"
            )
            .is_err()
    );
    for (kind, id) in [("proposal", "agreement"), ("agreement", "other-agreement")] {
        assert!(
            store
                .commit_record(
                    &command("synthetic-relocate-marker"),
                    kind,
                    id,
                    None,
                    first.record.payload.clone(),
                    "agreement.created"
                )
                .is_err()
        );
    }
    let (_dir, path, legacy) = fixture();
    legacy
        .create_agreement(&command("synthetic-legacy-first"), "agreement", json!({}))
        .unwrap();
    assert!(
        legacy
            .update_agreement(
                &command("synthetic-add-marker"),
                "agreement",
                1,
                payload(&legacy, &path),
                "agreement.updated"
            )
            .is_err()
    );
}

#[test]
fn exact_private_replay_preserves_marker_and_cannot_return_under_harmless_payload() {
    let (_dir, path, store) = fixture();
    let (context, first) = seed(&store, &path);
    let mut next = first.record.payload.clone();
    next["view"]["progress"] = json!("preparing");
    store
        .update_agreement(
            &command("synthetic-preserve-marker"),
            "agreement",
            1,
            next,
            "agreement.updated",
        )
        .unwrap();
    assert!(
        store
            .create_agreement(&context, "agreement", first.record.payload.clone())
            .unwrap()
            .record
            == first.record
    );
    let before = counts(&store);
    assert!(
        store
            .create_agreement(&context, "agreement", json!({}))
            .is_err()
    );
    assert!(counts(&store) == before);
    assert!(store.find_replay(&context).unwrap().unwrap().record == first.record);
    // A stripped actual current row cannot authorize a saved private replay.
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE records SET payload='{}' WHERE aggregate_type='agreement'",
            [],
        )
        .unwrap();
    assert!(store.find_replay(&context).is_err());
    assert!(store.get_operation(&first.operation_id).is_err());
    assert!(
        store
            .create_agreement(&context, "agreement", json!({}))
            .is_err()
    );
}

#[test]
fn private_current_refuses_legacy_or_replaced_saved_replay() {
    for field in ["absent", "source_digest"] {
        let (_dir, path, store) = fixture();
        let (context, first) = seed(&store, &path);
        let mut saved = serde_json::to_value(&first).unwrap();
        if field == "absent" {
            saved["record"]["payload"]
                .as_object_mut()
                .unwrap()
                .remove(KEY);
        } else {
            saved["record"]["payload"][KEY][field] = json!("66".repeat(32));
        }
        let c = store.connection.lock().unwrap();
        c.execute("UPDATE operations SET result=?1", [saved.to_string()])
            .unwrap();
        c.execute("UPDATE idempotency SET result=?1", [saved.to_string()])
            .unwrap();
        drop(c);
        assert!(store.get_operation(&first.operation_id).is_err());
        assert!(store.find_replay(&context).is_err());
        assert!(
            store
                .create_agreement(&context, "agreement", first.record.payload)
                .is_err()
        );
    }
}

#[test]
fn marked_workspace_refuses_unrelated_unmarked_namespace_even_from_saved_history() {
    let (_dir, path, store) = fixture();
    seed(&store, &path);
    for historical_only in [false, true] {
        if historical_only {
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE records SET payload='{}' WHERE aggregate_type='agreement'",
                    [],
                )
                .unwrap();
        }
        let before = counts(&store);
        for kind in ["agreement", "proposal", "other"] {
            assert!(
                store
                    .commit_record(
                        &command("synthetic-unmarked-extension"),
                        kind,
                        "different",
                        None,
                        json!({}),
                        "agreement.created",
                    )
                    .is_err()
            );
        }
        assert!(counts(&store) == before);
    }
}

#[test]
fn marker_reads_join_actual_record_and_operation_columns() {
    for change in 0..5 {
        let (_dir, path, store) = fixture();
        let (_, first) = seed(&store, &path);
        let c = store.connection.lock().unwrap();
        match change {
            0 => c.execute("UPDATE records SET id='different'", []).unwrap(),
            1 => c
                .execute("UPDATE records SET aggregate_type='proposal'", [])
                .unwrap(),
            2 => c
                .execute("UPDATE operations SET principal_id='different'", [])
                .unwrap(),
            3 => c
                .execute("UPDATE operations SET resource_id='different'", [])
                .unwrap(),
            _ => c
                .execute("UPDATE operations SET operation_id='different'", [])
                .unwrap(),
        };
        drop(c);
        match change {
            0 => {
                assert!(store.get_agreement("different").is_err());
                assert!(store.list_agreements().is_err());
            }
            1 => assert!(store.get_record("proposal", "agreement").is_err()),
            4 => assert!(store.get_operation("different").is_err()),
            _ => assert!(store.get_operation(&first.operation_id).is_err()),
        }
    }
}

#[test]
fn marker_first_write_refuses_existing_content_accounts_effects_and_deleted_history() {
    for mode in 0..5 {
        let (_dir, path, store) = fixture();
        match mode {
            0 => {
                store
                    .create_agreement(&command("synthetic-existing-row"), "other", json!({}))
                    .unwrap();
            }
            1 => store
                .initialize_authority_account("synthetic-account", 1)
                .unwrap(),
            2 => {
                store
                    .record_effect_intent(
                        "effect",
                        "synthetic",
                        "other",
                        &"aa".repeat(32),
                        "synthetic-ref",
                    )
                    .unwrap();
            }
            3 => {
                store.settlement_destination().unwrap();
            }
            _ => {
                store
                    .create_agreement(&command("synthetic-deleted-history"), "other", json!({}))
                    .unwrap();
                store.connection.lock().unwrap().execute_batch("DELETE FROM records; DELETE FROM operations; DELETE FROM idempotency; DELETE FROM events;").unwrap();
            }
        }
        let before = counts(&store);
        assert!(
            store
                .create_agreement(
                    &command("synthetic-not-first-write"),
                    "agreement",
                    payload(&store, &path)
                )
                .is_err()
        );
        assert!(counts(&store) == before);
    }
}

#[test]
fn marker_destination_requires_actual_original_encrypted_unrecovered_handle() {
    let (dir, path, store) = fixture();
    let original = payload(&store, &path);
    let (_other_dir, _other_path, other) = fixture();
    let plain = Store::open(dir.path().join("plain.sqlite")).unwrap();
    for denied in [Store::in_memory().unwrap(), plain, other] {
        assert!(
            denied
                .create_agreement(
                    &command("synthetic-wrong-destination"),
                    "agreement",
                    original.clone()
                )
                .is_err()
        );
        assert!(counts(&denied) == [0; 9]);
    }
    for field in ["metadata_origin", "protected_destination"] {
        let mut wrong = original.clone();
        wrong[KEY][field] = if field == "metadata_origin" {
            json!("00".repeat(32))
        } else {
            json!("/synthetic/wrong.sqlite")
        };
        assert!(
            store
                .create_agreement(&command("synthetic-wrong-origin"), "agreement", wrong)
                .is_err()
        );
    }
    // Independent recovered-handle restriction only; real generation and
    // original/layer fixtures are covered by the dedicated recovery leaves.
    let mut recovered_flag = store;
    recovered_flag.recovered_generation = true;
    assert!(
        recovered_flag
            .create_agreement(&command("synthetic-recovered"), "agreement", original)
            .is_err()
    );
}

#[test]
fn marker_precommit_replacement_rolls_back_and_postcommit_denial_preserves_seed() {
    for after in [false, true] {
        let (dir, path, store) = fixture();
        let seed = payload(&store, &path);
        let replaced = path.clone();
        let preserved = dir.path().join("preserved.sqlite");
        COMMIT_HOOK.with(|slot| {
            *slot.borrow_mut() = Some((
                after,
                Box::new(move || {
                    std::fs::rename(&replaced, &preserved).unwrap();
                    std::fs::write(&replaced, [0u8; 4096]).unwrap();
                    std::fs::set_permissions(&replaced, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }),
            ))
        });
        assert!(
            store
                .create_agreement(&command("synthetic-raced-seed"), "agreement", seed)
                .is_err()
        );
        assert!(counts(&store)[..4] == if after { [1; 4] } else { [0; 4] });
        if after {
            assert!(store.get_agreement("agreement").is_err());
            assert!(store.find_replay(&command("synthetic-raced-seed")).is_err());
        }
    }
}

#[test]
fn malformed_hidden_and_duplicate_markers_refuse_all_live_json_routes() {
    for raw in [
        r#"{"private_workspace_origin_v1":null}"#,
        r#"{"private_workspace_origin_v1":{}}"#,
        r#"{"private_workspace_origin_v1":[],"private_workspace_origin_v\u0031":{}}"#,
        r#"{"nested":{"private_workspace_origin_v\u0031":{}}}"#,
    ] {
        let (_dir, path, store) = fixture();
        let (context, first) = seed(&store, &path);
        for (table, column) in [
            ("records", "payload"),
            ("operations", "result"),
            ("idempotency", "result"),
            ("events", "payload"),
        ] {
            let c = store.connection.lock().unwrap();
            let original: String = c
                .query_row(&format!("SELECT {column} FROM {table}"), [], |r| r.get(0))
                .unwrap();
            let tampered = if table == "operations" || table == "idempotency" {
                // Wrapper-level reserved fields must never become a bypass.
                // Embed the raw bytes so decoded duplicate names are preserved.
                format!("{{\"extra\":{raw},{}", original.strip_prefix('{').unwrap())
            } else {
                raw.to_owned()
            };
            c.execute(&format!("UPDATE {table} SET {column}=?1"), [&tampered])
                .unwrap();
            drop(c);
            match table {
                "records" => {
                    assert!(store.get_agreement("agreement").is_err());
                    assert!(store.list_agreements().is_err());
                }
                "operations" => assert!(store.get_operation(&first.operation_id).is_err()),
                "idempotency" => assert!(store.find_replay(&context).is_err()),
                _ => assert!(store.events_after(0, 10).is_err()),
            }
            store
                .connection
                .lock()
                .unwrap()
                .execute(&format!("UPDATE {table} SET {column}=?1"), [&original])
                .unwrap();
        }
    }
}

fn release() -> crate::authority::ReleaseIntent {
    crate::authority::ReleaseIntent {
        authorization_id: "synthetic-release".into(),
        account_id: "synthetic-account".into(),
        writer_epoch: 1,
        obligation_id: "obligation".into(),
        proposal_id: "synthetic-proposal".into(),
        manifest_digest: "aa".repeat(32),
        effects_digest: "bb".repeat(32),
        artifact_digest: "cc".repeat(32),
        maximum_debit: "1".into(),
        input_ids: vec!["synthetic-input".into()],
        aggregate_budget_limit: "2".into(),
    }
}

#[test]
fn marker_only_current_snapshot_updates_and_saved_history_refuse_direct_settlement() {
    for mode in 0..4 {
        let (_dir, path, store) = fixture();
        let private = payload(&store, &path);
        let first = store
            .create_agreement(
                &command("synthetic-settlement-first"),
                "agreement",
                json!({}),
            )
            .unwrap();
        let mut snapshot = vec![first.record.clone()];
        let mut updates = vec![("agreement".into(), json!({}))];
        match mode {
            0 => {
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute("UPDATE records SET payload=?1", [private.to_string()])
                    .unwrap();
            }
            1 => snapshot[0].payload = private,
            2 => updates[0].1 = private,
            _ => {
                store
                    .reopen_settlement_obligation("evidence", "obligation", &snapshot, &[], &[])
                    .unwrap();
                let mut saved = serde_json::to_value(&first).unwrap();
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
        let live = std::cell::Cell::new(0);
        let check = || {
            live.set(live.get() + 1);
            Ok(())
        };
        assert!(
            store
                .reopen_settlement_obligation("evidence", "obligation", &snapshot, &[], &updates)
                .is_err()
        );
        assert!(
            store
                .consume_exact_settlement_release(
                    &release(),
                    "release-evidence",
                    &json!({}),
                    &snapshot,
                    &updates,
                    &check
                )
                .is_err()
        );
        assert!(
            store
                .retain_exact_conflict_release(
                    &release(),
                    "release-evidence",
                    &json!({}),
                    &snapshot,
                    &updates,
                    &check
                )
                .is_err()
        );
        assert!(counts(&store) == before && live.get() == 0);
    }
}

#[test]
fn exact_settlement_replay_and_provenance_refuse_marker_only_history() {
    let (_dir, path, store) = fixture();
    let private = payload(&store, &path);
    let first = store
        .create_agreement(
            &command("synthetic-checkpoint-first"),
            "agreement",
            json!({}),
        )
        .unwrap();
    let snapshot = vec![first.record.clone()];
    store
        .consume_exact_settlement_release(
            &release(),
            "evidence",
            &json!({}),
            &snapshot,
            &[],
            &|| Ok(()),
        )
        .unwrap();
    assert!(
        store
            .consume_exact_settlement_release(
                &release(),
                "other-evidence",
                &private,
                &snapshot,
                &[],
                &|| panic!("private provenance must refuse before live check")
            )
            .is_err()
    );
    let mut saved = serde_json::to_value(first).unwrap();
    saved["record"]["payload"] = private;
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
                &release(),
                "evidence",
                &json!({}),
                &snapshot,
                &[],
                &|| panic!("private replay must refuse before live check")
            )
            .is_err()
    );
    assert!(counts(&store) == before);
}
