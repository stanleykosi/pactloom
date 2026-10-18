//! Portable raw-input and live-event regressions. No native authority fixtures.
use super::*;
use serde_json::json;

fn command(key: &str) -> CommandContext {
    CommandContext::for_request("synthetic-parser", key, &json!({"create": true})).unwrap()
}
fn fixture() -> (Store, CommandContext, MutationResult) {
    let store = Store::in_memory().unwrap();
    let command = command("synthetic-parser-create");
    let result = store
        .create_agreement(&command, "agreement", json!({}))
        .unwrap();
    (store, command, result)
}
fn invalid_json() -> Vec<String> {
    vec![
        r#"{"x":1,"x":2}"#.into(),
        r#"{"x":1,"\u0078":2}"#.into(),
        r#"{"nested":[{"a":1,"a":2}]}"#.into(),
        r#"{"durable_input_projections_v1":{},"durable_input_projections_v\u0031":{}}"#.into(),
        "{} {}".into(),
        "{\"truncated\":".into(),
        format!("{}0{}", "[".repeat(33), "]".repeat(33)),
        format!(
            "[{}0]",
            "0,".repeat(wholepact_core::strict_json::MAX_JSON_NODES)
        ),
        " ".repeat(MAX_MUTATION_JSON_BYTES + 1),
    ]
}

#[test]
fn raw_record_operation_replay_and_event_reads_reject_ambiguity_and_limits() {
    for raw in invalid_json() {
        let (store, command, result) = fixture();
        for (table, column) in [
            ("records", "payload"),
            ("operations", "result"),
            ("idempotency", "result"),
            ("events", "payload"),
        ] {
            let connection = store.connection.lock().unwrap();
            let original: String = connection
                .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            connection
                .execute(&format!("UPDATE {table} SET {column}=?1"), [&raw])
                .unwrap();
            drop(connection);
            match table {
                "records" => {
                    assert!(store.get_agreement("agreement").is_err());
                    assert!(store.list_agreements().is_err());
                }
                "operations" => assert!(store.get_operation(&result.operation_id).is_err()),
                "idempotency" => {
                    assert!(store.find_replay(&command).is_err());
                    assert!(
                        store
                            .create_agreement(&command, "agreement", json!({}))
                            .is_err()
                    );
                }
                "events" => assert!(store.events_after(0, 10).is_err()),
                _ => unreachable!(),
            }
            let connection = store.connection.lock().unwrap();
            let unchanged: String = connection
                .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(unchanged, raw);
            connection
                .execute(&format!("UPDATE {table} SET {column}=?1"), [&original])
                .unwrap();
        }
    }
}

#[test]
fn live_agreement_events_are_only_empty_or_exact_row_bound_metadata() {
    let (store, _, _) = fixture();
    for raw in ["{}", r#"{"id":"agreement","revision":1}"#] {
        store
            .connection
            .lock()
            .unwrap()
            .execute("UPDATE events SET payload=?1", [raw])
            .unwrap();
        assert_eq!(
            store.events_after(0, 10).unwrap()[0].payload,
            serde_json::from_str::<Value>(raw).unwrap()
        );
    }
    for raw in [
        r#"{"id":"other","revision":1}"#,
        r#"{"id":"agreement","revision":2}"#,
        r#"{"id":"agreement","revision":1,"private":"extra"}"#,
        r#"{"id":"agreement"}"#,
        r#"{"id":"agreement","revision":"1"}"#,
        r#"{"durable_input_projections_v1":{}}"#,
        "null",
        "[]",
        "1",
    ] {
        store
            .connection
            .lock()
            .unwrap()
            .execute("UPDATE events SET payload=?1", [raw])
            .unwrap();
        assert!(store.events_after(0, 10).is_err());
    }
}

#[test]
fn every_event_kind_refuses_new_private_keys_independent_of_current_record() {
    let (store, _, _) = fixture();
    for kind in ["agreement", "proposal", "legacy_other"] {
        for private in [
            r#"{"durable_input_projections_v1":{"round":"synthetic-private"}}"#,
            r#"{"nested":{"durable_input_projections_v\u0031":{"round":"synthetic-private"}}}"#,
            r#"{"durable_input_projections_v1":null}"#,
            r#"{"durable_input_projections_v1":[]}"#,
        ] {
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE events SET aggregate_type=?1,payload=?2",
                    params![kind, private],
                )
                .unwrap();
            assert!(store.events_after(0, 10).is_err());
        }
    }
    // Non-agreement opaque legacy event shapes remain untouched, and strings
    // that merely mention the reserved spelling are not recursively decoded.
    let raw = r#"{"opaque":"{\"durable_input_projections_v1\":{\"x\":1}}"}"#;
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE events SET aggregate_type='legacy_other',payload=?1",
            [raw],
        )
        .unwrap();
    assert_eq!(
        store.events_after(0, 10).unwrap()[0].payload,
        serde_json::from_str::<Value>(raw).unwrap()
    );
}

#[test]
fn legacy_empty_maps_and_distinct_mutation_wrapper_limit_roundtrip() {
    let store = Store::in_memory().unwrap();
    let context = command("synthetic-empty-roundtrip");
    let empty = json!({"durable_input_projections_v1":{},"durable_construction_v1":{}});
    let result = store
        .create_agreement(&context, "empty", empty.clone())
        .unwrap();
    assert_eq!(
        store.get_agreement("empty").unwrap().unwrap().payload,
        empty
    );
    assert_eq!(store.list_agreements().unwrap().len(), 1);
    assert_eq!(
        store.find_replay(&context).unwrap().unwrap().record,
        result.record
    );
    assert!(store.get_operation(&result.operation_id).unwrap().is_some());
    let payload = json!({"data":"a".repeat(MAX_JSON_BYTES - 11)});
    assert_eq!(serde_json::to_vec(&payload).unwrap().len(), MAX_JSON_BYTES);
    let result = store
        .create_agreement(&command("synthetic-max-record"), "large", payload)
        .unwrap();
    let raw = serde_json::to_string(&result).unwrap();
    assert!(raw.len() > MAX_JSON_BYTES && raw.len() < MAX_MUTATION_JSON_BYTES);
    assert!(decode_mutation_value(&raw).is_ok());
    assert!(store.get_operation(&result.operation_id).unwrap().is_some());
    let oversized = json!({"data":"a".repeat(MAX_JSON_BYTES - 10)});
    assert!(
        store
            .create_agreement(
                &command("synthetic-oversized"),
                "too-large",
                oversized.clone()
            )
            .is_err()
    );
    let mut tampered = serde_json::to_value(result).unwrap();
    tampered["record"]["payload"] = oversized;
    assert!(decode_mutation_value(&tampered.to_string()).is_err());
}

#[test]
fn generic_write_does_not_commit_payload_or_wrapper_it_cannot_read() {
    for depth in [31, 33] {
        let store = Store::in_memory().unwrap();
        let mut payload = json!(0);
        for _ in 0..depth {
            payload = json!([payload]);
        }
        assert!(
            store
                .create_agreement(&command("synthetic-depth-write"), "a", payload)
                .is_err()
        );
        for table in ["records", "operations", "idempotency", "events"] {
            let count: u64 = store
                .connection
                .lock()
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
    }
}

#[test]
fn new_read_guards_preserve_opaque_legacy_construction_history() {
    let (store, context, original) = fixture();
    let legacy = json!({"durable_construction_v1":{"legacy":"opaque-history"}});
    let mut saved = serde_json::to_value(&original).unwrap();
    saved["record"]["payload"] = legacy.clone();
    let connection = store.connection.lock().unwrap();
    connection
        .execute("UPDATE records SET payload=?1", [legacy.to_string()])
        .unwrap();
    for table in ["operations", "idempotency"] {
        connection
            .execute(
                &format!("UPDATE {table} SET result=?1"),
                [saved.to_string()],
            )
            .unwrap();
    }
    drop(connection);
    assert_eq!(
        store.get_agreement("agreement").unwrap().unwrap().payload,
        legacy
    );
    assert_eq!(store.list_agreements().unwrap()[0].payload, legacy);
    assert!(
        store
            .get_operation(&original.operation_id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store.find_replay(&context).unwrap().unwrap().record.payload,
        legacy
    );
    assert_eq!(
        store
            .create_agreement(&context, "agreement", json!({}))
            .unwrap()
            .record
            .payload,
        legacy
    );
}

#[test]
fn unknown_wrappers_and_nested_reserved_maps_do_not_bypass_destination_guard() {
    let (store, _, result) = fixture();
    let private = json!({"durable_input_projections_v1":{"round":"synthetic-private"}});
    let mut saved = serde_json::to_value(&result).unwrap();
    saved["unknown"] = private.clone();
    store
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE operations SET result=?1", [saved.to_string()])
        .unwrap();
    assert!(store.get_operation(&result.operation_id).is_err());
    assert!(
        store
            .create_agreement(
                &command("synthetic-nested-private"),
                "nested",
                json!({"unknown":private})
            )
            .is_err()
    );
}

#[test]
fn negative_event_row_revision_cannot_make_missing_revision_equal() {
    for raw in [
        r#"{"id":"agreement","private":"extra"}"#,
        r#"{"id":"agreement","revision":null}"#,
        "{}",
    ] {
        assert!(decode_live_event(raw, "agreement", "agreement", -1).is_err());
    }
}
