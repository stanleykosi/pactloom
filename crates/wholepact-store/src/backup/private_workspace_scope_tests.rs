//! Workspace-marker scope regressions. These synthetic consistency markers are
//! not native associations, privacy approvals, or authority to spend.
use super::*;
use crate::private_workspace_origin_v1::{
    PRIVATE_WORKSPACE_ORIGIN_KEY_V1, PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1, PrivateWorkspaceOriginV1,
};

const MARKER: &str = PRIVATE_WORKSPACE_ORIGIN_KEY_V1;

fn marked_seed(path: &Path) -> Store {
    let store = Store::create_encrypted(path, &key(75)).unwrap();
    let marker = PrivateWorkspaceOriginV1 {
        version: 1,
        purpose: PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1.into(),
        native_association_digest: "11".repeat(32),
        source_digest: "22".repeat(32),
        principal_id: "constructor".into(),
        agreement_id: "synthetic-agreement".into(),
        obligation_id: "synthetic-obligation".into(),
        reviewer_account_ids: vec!["33".repeat(32), "44".repeat(32)],
        protected_destination: fs::canonicalize(path).unwrap().to_str().unwrap().into(),
        retention_policy: "synthetic-exact-local-retention".into(),
        metadata_origin: hex::encode(store.original_database_origin_fail_fast().unwrap()),
    };
    marker.validate().unwrap();
    let payload = json!({
        "owner_client_id": "constructor",
        "view": {"agreement": {
            "agreement_id": "synthetic-agreement",
            "obligation_id": "synthetic-obligation"
        }},
        "durable_construction_v1": {},
        "durable_input_projections_v1": {},
        MARKER: marker
    });
    let context = CommandContext::for_request(
        "constructor",
        "synthetic-private-seed",
        &json!({"create": true}),
    )
    .unwrap();
    store
        .create_agreement(&context, "synthetic-agreement", payload)
        .unwrap();
    store
}

fn marked_cell(table: &str, original: &str, marker: Value) -> String {
    let mut value: Value = serde_json::from_str(original).unwrap();
    let payload = if matches!(table, "operations" | "idempotency") {
        &mut value["record"]["payload"]
    } else {
        &mut value
    };
    payload[MARKER] = marker;
    value.to_string()
}

#[test]
fn every_workspace_marker_presence_refuses_all_modes_but_strings_remain_opaque() {
    let mut raw = [
        json!({}),
        json!(null),
        json!([]),
        json!(false),
        json!(0),
        json!("private"),
        json!({"purpose": CANARY}),
    ]
    .into_iter()
    .map(|value| json!({MARKER: value}).to_string())
    .collect::<Vec<_>>();
    raw.extend([
        r#"{"private_workspace_origin_v\u0031":{}}"#.into(),
        r#"{"private_workspace_origin_v1":{},"private_workspace_origin_v\u0031":null}"#.into(),
        r#"{"private_workspace_origin_v1":null,"private_workspace_origin_v1":{}}"#.into(),
        r#"{"nested":[{"private_workspace_origin_v1":{}}]}"#.into(),
        r#"{"record":{"payload":{}},"unknown":{"private_workspace_origin_v1":null}}"#.into(),
        r#"{"private_workspace_origin_v1":"truncated"#.into(),
    ]);
    for scope in [
        PrivateMetadataScope::CoordinationOnly,
        PrivateMetadataScope::NoInputProjections,
        PrivateMetadataScope::NoWorkspaceOrigins,
    ] {
        for payload in &raw {
            assert_error(
                validate_private_metadata_json(payload, scope),
                scope.error(),
            );
        }
        for harmless in [
            "{}",
            r#"{"durable_construction_v1":{},"durable_input_projections_v1":{}}"#,
            r#"{"opaque":"{\"private_workspace_origin_v1\":null}"}"#,
            r#"["private_workspace_origin_v1", "{\"private_workspace_origin_v1\":{}}"]"#,
        ] {
            validate_private_metadata_json(harmless, scope).unwrap();
        }
    }
}

#[test]
fn marker_only_zero_round_seed_refuses_backup_and_bundle_before_staging() {
    let originals = directory();
    let destinations = directory();
    let store = marked_seed(&originals.path().join("source.sqlite"));
    let connection = store.connection.lock().unwrap();
    for (table, column) in COLUMNS {
        let raw = read_cell(&connection, table, column);
        let value: Value = serde_json::from_str(&raw).unwrap();
        if table == "events" {
            assert!(value.get(MARKER).is_none());
            assert_eq!(value.as_object().unwrap().len(), 2);
        } else {
            let payload = if table == "records" {
                &value
            } else {
                &value["record"]["payload"]
            };
            assert!(payload.get(MARKER).is_some());
            assert!(payload[KEY].as_object().unwrap().is_empty());
        }
        let count: u64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }
    drop(connection);
    let before = fingerprint(originals.path());
    let destination = destinations.path().join("must-not-exist.sqlite");
    refuse(&store, &destination);
    crate::bundle::reset_bundle_visitor_calls();
    assert!(matches!(
        crate::bundle::CoordinationBundleAdapter::new(&store),
        Err(wholepact_storage_security::bundle::BundleError::Integrity)
    ));
    assert_eq!(crate::bundle::bundle_visitor_calls(), 0);
    assert_no_destination(&destination);
    assert!(before == fingerprint(originals.path()));
}

#[test]
fn empty_and_null_marker_in_every_raw_column_refuse_and_preserve_originals() {
    let originals = directory();
    let destinations = directory();
    let store = source(&originals.path().join("source.sqlite"));
    let destination = destinations.path().join("must-not-exist.sqlite");
    for (table, column) in COLUMNS {
        let original = read_cell(&store.connection.lock().unwrap(), table, column);
        for marker in [json!({}), json!(null)] {
            let raw = marked_cell(table, &original, marker);
            replace_cell(&store.connection.lock().unwrap(), table, column, &raw);
            if table != "records" {
                let current = read_cell(&store.connection.lock().unwrap(), "records", "payload");
                assert!(
                    serde_json::from_str::<Value>(&current)
                        .unwrap()
                        .get(MARKER)
                        .is_none()
                );
            }
            let before = fingerprint(originals.path());
            refuse(&store, &destination);
            assert_error(
                validate_no_private_input_projections(&store.connection.lock().unwrap()),
                PRIVATE_INPUT_PROJECTION_SCOPE_ERROR,
            );
            assert_error(
                validate_no_private_workspace_origins(&store.connection.lock().unwrap()),
                PRIVATE_WORKSPACE_ORIGIN_SCOPE_ERROR,
            );
            assert!(before == fingerprint(originals.path()));
            assert!(raw == read_cell(&store.connection.lock().unwrap(), table, column));
        }
        replace_cell(&store.connection.lock().unwrap(), table, column, &original);
    }
}

#[test]
fn keyed_recomputed_marker_archives_refuse_before_restore_destinations() {
    let originals = directory();
    let destinations = directory();
    let store = source(&originals.path().join("source.sqlite"));
    let archive = originals.path().join("archive.sqlite");
    store.backup_agreement_journal(&archive, &key(76)).unwrap();
    drop(store);
    let writer = open_encrypted(&archive, &key(76)).unwrap();
    let connection = writer.connection();
    let destination = destinations.path().join("must-not-exist.sqlite");
    for (table, column) in COLUMNS {
        let original = read_cell(connection, table, column);
        for raw in [
            marked_cell(table, &original, json!({})),
            marked_cell(table, &original, json!(null)),
            r#"{"private_workspace_origin_v\u0031":{}}"#.into(),
            r#"{"private_workspace_origin_v1":null,"private_workspace_origin_v\u0031":{}}"#.into(),
        ] {
            replace_cell(connection, table, column, &raw);
            let stats = inspect_rows(connection, SCHEMA_VERSION).unwrap();
            connection
                .execute(
                    "UPDATE backup_manifest SET snapshot_digest=?1,row_count=?2,data_bytes=?3",
                    params![stats.digest, stats.rows, stats.bytes],
                )
                .unwrap();
            let before = fingerprint(originals.path());
            assert_error(
                inspect_agreement_backup(&archive, &key(76)),
                PRIVATE_CONSTRUCTION_SCOPE_ERROR,
            );
            assert_error(
                restore_agreement_journal(&archive, &key(76), &destination, &key(77)),
                PRIVATE_CONSTRUCTION_SCOPE_ERROR,
            );
            assert_error(
                test_restore_agreement_journal(&archive, &key(76), &destination, &key(77)),
                PRIVATE_CONSTRUCTION_SCOPE_ERROR,
            );
            assert_no_destination(&destination);
            assert!(before == fingerprint(originals.path()));
            assert!(raw == read_cell(connection, table, column));
        }
        replace_cell(connection, table, column, &original);
    }
}

#[test]
fn workspace_only_scope_preserves_projection_and_construction_semantics_and_bounds() {
    let scope = PrivateMetadataScope::NoWorkspaceOrigins;
    for key in ["durable_input_projections_v1", "durable_construction_v1"] {
        for value in [
            json!({}),
            json!(null),
            json!([]),
            json!(true),
            json!("legacy"),
            json!({"retained": CANARY}),
        ] {
            let raw = json!({key: value}).to_string();
            validate_private_metadata_json(&raw, scope).unwrap();
        }
    }
    let directory = directory();
    let store = source(&directory.path().join("source.sqlite"));
    for (table, column) in COLUMNS {
        let original = read_cell(&store.connection.lock().unwrap(), table, column);
        replace_cell(
            &store.connection.lock().unwrap(),
            table,
            column,
            &private_cell(table, &original),
        );
        validate_no_private_workspace_origins(&store.connection.lock().unwrap()).unwrap();
        replace_cell(&store.connection.lock().unwrap(), table, column, &original);
    }
    for raw in [
        r#"{"ordinary":1,"ordinar\u0079":2}"#.into(),
        "{} trailing".into(),
        format!(
            "{}0{}",
            "[".repeat(wholepact_core::strict_json::MAX_JSON_DEPTH + 1),
            "]".repeat(wholepact_core::strict_json::MAX_JSON_DEPTH + 1)
        ),
        format!(
            "[{}0]",
            "0,".repeat(wholepact_core::strict_json::MAX_JSON_NODES)
        ),
        format!("\"{}\"", "x".repeat(MAX_CELL_BYTES - 1)),
    ] {
        assert_error(validate_private_metadata_json(&raw, scope), scope.error());
    }
}
