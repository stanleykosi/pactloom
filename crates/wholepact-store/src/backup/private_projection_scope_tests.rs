//! Feature-independent synthetic scope regressions, not native receipt fixtures.
use super::*;
use crate::CommandContext;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use wholepact_storage_security::open_encrypted;

const KEY: &str = "durable_input_projections_v1";
const CANARY: &str = "SYNTHETIC-PRIVATE-SELECTED-INPUT-METADATA-91827";
const COLUMNS: [(&str, &str); 4] = [
    ("records", "payload"),
    ("operations", "result"),
    ("idempotency", "result"),
    ("events", "payload"),
];

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn key(value: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([value; 32])
}
fn source(path: &Path) -> Store {
    let source = Store::create_encrypted(path, &key(75)).unwrap();
    let command = CommandContext::for_request(
        "constructor",
        "synthetic-projection-create",
        &json!({"create": true}),
    )
    .unwrap();
    source
        .create_agreement(
            &command,
            "synthetic-agreement",
            json!({"durable_construction_v1": {}, "durable_input_projections_v1": {}}),
        )
        .unwrap();
    source
}
fn assert_error<T>(result: Result<T>, expected: &'static str) {
    match result {
        Err(StoreError::InvalidInput(message)) => {
            assert_eq!(message, expected);
            assert!(!message.contains(CANARY));
        }
        _ => panic!("private projection scope must fail closed"),
    }
}
fn assert_no_destination(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        assert!(!Path::new(&file).exists());
    }
}
fn refuse(source: &Store, path: &Path) {
    assert_error(
        source.backup_agreement_journal(path, &key(76)),
        PRIVATE_CONSTRUCTION_SCOPE_ERROR,
    );
    assert_no_destination(path);
}
fn read_cell(connection: &Connection, table: &str, column: &str) -> String {
    connection
        .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}
fn replace_cell(connection: &Connection, table: &str, column: &str, raw: &str) {
    connection
        .execute(&format!("UPDATE {table} SET {column}=?1"), [raw])
        .unwrap();
    // Finish ordinary fixture write/read setup before taking the preservation
    // baseline. SQLite's first read after a write may advance the live SHM WAL
    // read mark; the operation under test must not be used to normalize it.
    assert!(
        read_cell(connection, table, column) == raw,
        "fixture must retain the exact raw cell"
    );
}
fn private_cell(table: &str, original: &str) -> String {
    let mut value: Value = serde_json::from_str(original).unwrap();
    let payload = if matches!(table, "operations" | "idempotency") {
        &mut value["record"]["payload"]
    } else {
        &mut value
    };
    payload[KEY] = json!({"synthetic-round": CANARY});
    value.to_string()
}

// Reads can change atime. After ordinary fixture write/read setup, hashes of
// every byte (including all SHM bytes), lengths, names, permissions, identity
// and mtime must stay unchanged. This does not claim that the first-ever SQLite
// read leaves WAL-index bookkeeping untouched. Never retain bytes in assertion
// Debug output: a failing preservation check must not dump private file data.
type FileFingerprint = ([u8; 32], u64, u32, u64, u64, i64, i64);
fn fingerprint(dir: &Path) -> BTreeMap<std::path::PathBuf, FileFingerprint> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(meta.is_file() && !meta.file_type().is_symlink());
            let bytes = fs::read(&path).unwrap();
            assert_eq!(meta.mode() & 0o077, 0);
            assert!(
                !bytes
                    .windows(CANARY.len())
                    .any(|part| part == CANARY.as_bytes())
            );
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            (
                path,
                (
                    digest,
                    meta.len(),
                    meta.mode(),
                    meta.dev(),
                    meta.ino(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                ),
            )
        })
        .collect()
}

#[test]
fn private_projection_in_each_column_refuses_backup_without_touching_originals() {
    let originals = directory();
    let destinations = directory();
    let source = source(&originals.path().join("source.sqlite"));
    let output = destinations.path().join("forbidden.sqlite");
    for (table, column) in COLUMNS {
        let original = read_cell(&source.connection.lock().unwrap(), table, column);
        let raw = private_cell(table, &original);
        replace_cell(&source.connection.lock().unwrap(), table, column, &raw);
        if table != "records" {
            // Historical payloads must be refused even with an empty current map.
            assert!(
                source
                    .get_agreement("synthetic-agreement")
                    .unwrap()
                    .unwrap()
                    .payload[KEY]
                    .as_object()
                    .unwrap()
                    .is_empty()
            );
        }
        let before = fingerprint(originals.path());
        refuse(&source, &output);
        assert_error(
            validate_no_private_input_projections(&source.connection.lock().unwrap()),
            PRIVATE_INPUT_PROJECTION_SCOPE_ERROR,
        );
        assert!(
            before == fingerprint(originals.path()),
            "refusal must preserve all original file and sidecar fingerprints"
        );
        assert!(
            raw == read_cell(&source.connection.lock().unwrap(), table, column),
            "refusal must preserve the exact raw cell"
        );
        replace_cell(&source.connection.lock().unwrap(), table, column, &original);
    }
}

fn invalid_raw_payloads() -> Vec<String> {
    let mut payloads = [
        json!(null),
        json!([]),
        json!(1),
        json!(true),
        json!("private"),
        json!({"synthetic-round": CANARY}),
    ]
    .into_iter()
    .map(|value| json!({"durable_input_projections_v1": value}).to_string())
    .collect::<Vec<_>>();
    payloads.extend([
        format!(r#"{{"{KEY}":{{"round":"{CANARY}"}},"{KEY}":{{}}}}"#),
        format!(r#"{{"{KEY}":{{}},"{KEY}":{{"round":"{CANARY}"}}}}"#),
        format!(r#"{{"{KEY}":{{}},"durable_input_projections_v\u0031":{{}}}}"#),
        format!(r#"{{"durable_input_projections_v\u0031":{{"round":"{CANARY}"}}}}"#),
        format!(r#"{{"nested":[{{"{KEY}":{{"round":"{CANARY}"}}}}]}}"#),
        r#"{"ordinary":{},"ordinar\u0079":{}}"#.into(),
        r#"{"nested":[{"ordinary":0,"ordinary":1}]}"#.into(),
        format!(r#"{{"{KEY}":{{"round":"truncated"#),
        format!(r#"{{"{KEY}":{{}}}} trailing"#),
        format!(r#"{{"{KEY}":{{}}}} {{}}"#),
        format!(
            "{}0{}",
            "[".repeat(wholepact_core::strict_json::MAX_JSON_DEPTH + 1),
            "]".repeat(wholepact_core::strict_json::MAX_JSON_DEPTH + 1)
        ),
        format!(
            "[{}0]",
            "0,".repeat(wholepact_core::strict_json::MAX_JSON_NODES)
        ),
    ]);
    payloads
}

#[test]
fn duplicate_escaped_malformed_and_unbounded_json_cannot_hide_in_any_column() {
    let originals = directory();
    let destinations = directory();
    let source = source(&originals.path().join("source.sqlite"));
    let output = destinations.path().join("forbidden.sqlite");
    let payloads = invalid_raw_payloads();
    for (table, column) in COLUMNS {
        let original = read_cell(&source.connection.lock().unwrap(), table, column);
        for raw in &payloads {
            replace_cell(&source.connection.lock().unwrap(), table, column, raw);
            let before = fingerprint(originals.path());
            refuse(&source, &output);
            assert_error(
                validate_no_private_input_projections(&source.connection.lock().unwrap()),
                PRIVATE_INPUT_PROJECTION_SCOPE_ERROR,
            );
            assert!(
                before == fingerprint(originals.path()),
                "refusal must preserve all original file and sidecar fingerprints"
            );
            assert!(
                *raw == read_cell(&source.connection.lock().unwrap(), table, column),
                "refusal must preserve the exact raw cell"
            );
        }
        replace_cell(&source.connection.lock().unwrap(), table, column, &original);
    }
}

#[test]
fn scanner_modes_have_fixed_distinct_construction_scope_and_identical_json_bounds() {
    let source_dir = directory();
    let source = source(&source_dir.path().join("source.sqlite"));
    let construction = json!({
        "durable_construction_v1": {"synthetic-candidate": CANARY},
        "durable_input_projections_v1": {}
    })
    .to_string();
    for (table, column) in COLUMNS {
        let original = read_cell(&source.connection.lock().unwrap(), table, column);
        replace_cell(
            &source.connection.lock().unwrap(),
            table,
            column,
            &construction,
        );
        validate_no_private_input_projections(&source.connection.lock().unwrap()).unwrap();
        assert_error(
            validate_coordination_only_scope(&source.connection.lock().unwrap()),
            PRIVATE_CONSTRUCTION_SCOPE_ERROR,
        );
        replace_cell(&source.connection.lock().unwrap(), table, column, &original);
    }
    // Old construction encodings are not a new-input-projection policy choice.
    // The broader caller's existing typed construction validation still applies.
    for value in [
        json!(null),
        json!([]),
        json!(true),
        json!("legacy"),
        json!({"x": 1}),
    ] {
        let raw = json!({"durable_construction_v1": value}).to_string();
        validate_no_private_input_projections_json(&raw).unwrap();
        assert_error(
            validate_private_metadata_json(&raw, PrivateMetadataScope::CoordinationOnly),
            PRIVATE_CONSTRUCTION_SCOPE_ERROR,
        );
    }
    for raw in [
        r#"{"durable_construction_v1":{},"durable_construction_v\u0031":{}}"#,
        r#"{"nested":[{"durable_construction_v\u0031":{"private":true}}]}"#,
    ] {
        assert_error(
            validate_private_metadata_json(raw, PrivateMetadataScope::CoordinationOnly),
            PRIVATE_CONSTRUCTION_SCOPE_ERROR,
        );
    }
    for scope in [
        PrivateMetadataScope::CoordinationOnly,
        PrivateMetadataScope::NoInputProjections,
    ] {
        for raw in [
            "{}",
            r#"{"durable_input_projections_v1":{}}"#,
            r#"{"durable_construction_v1":{},"durable_input_projections_v\u0031": { }}"#,
            r#"{"nested":[{"durable_input_projections_v1":{}}]}"#,
            r#"{"value":"durable_input_projections_v1 is just text"}"#,
        ] {
            validate_private_metadata_json(raw, scope).unwrap();
        }
        for raw in invalid_raw_payloads() {
            assert_error(validate_private_metadata_json(&raw, scope), scope.error());
        }
        let exact_depth = format!(
            "{}0{}",
            "[".repeat(wholepact_core::strict_json::MAX_JSON_DEPTH),
            "]".repeat(wholepact_core::strict_json::MAX_JSON_DEPTH)
        );
        validate_private_metadata_json(&exact_depth, scope).unwrap();
        let exact_nodes = format!(
            "[{}0]",
            "0,".repeat(wholepact_core::strict_json::MAX_JSON_NODES - 2)
        );
        validate_private_metadata_json(&exact_nodes, scope).unwrap();
        let exact_cell = format!("\"{}\"", "x".repeat(MAX_CELL_BYTES - 2));
        validate_private_metadata_json(&exact_cell, scope).unwrap();
        let oversized = format!("\"{}\"", "x".repeat(MAX_CELL_BYTES - 1));
        assert_error(
            validate_private_metadata_json(&oversized, scope),
            scope.error(),
        );
    }
    validate_no_private_input_projections_json(&construction).unwrap();
    assert_error(
        validate_no_private_input_projections_json(&format!(r#"{{"{KEY}":null}}"#)),
        PRIVATE_INPUT_PROJECTION_SCOPE_ERROR,
    );
}

#[test]
fn correctly_keyed_recomputed_archives_refuse_each_private_column_before_restore() {
    let originals = directory();
    let destinations = directory();
    let source = source(&originals.path().join("source.sqlite"));
    let archive = originals.path().join("archive.sqlite");
    source.backup_agreement_journal(&archive, &key(76)).unwrap();
    drop(source);
    let writer = open_encrypted(&archive, &key(76)).unwrap();
    let connection = writer.connection();
    let destination = destinations.path().join("must-not-exist.sqlite");
    for (table, column) in COLUMNS {
        let original = read_cell(connection, table, column);
        for raw in [
            private_cell(table, &original),
            format!(r#"{{"durable_input_projections_v\u0031":{{"round":"{CANARY}"}}}}"#),
            format!(r#"{{"{KEY}":{{}},"durable_input_projections_v\u0031":{{}}}}"#),
            format!(r#"{{"{KEY}":{{"round":"truncated"#),
        ] {
            replace_cell(connection, table, column, &raw);
            // The archive is correctly keyed and its inventory authentically
            // recomputed. Refusal must be semantic, not a stale digest failure.
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
            assert!(
                before == fingerprint(originals.path()),
                "refusal must preserve all original file and sidecar fingerprints"
            );
        }
        replace_cell(connection, table, column, &original);
    }
}

#[test]
fn exact_empty_private_metadata_keeps_legacy_backup_roundtrip_and_quarantine() {
    let dir = directory();
    let source = source(&dir.path().join("source.sqlite"));
    let original = read_cell(&source.connection.lock().unwrap(), "records", "payload");
    let archive = dir.path().join("archive.sqlite");
    let summary = source.backup_agreement_journal(&archive, &key(76)).unwrap();
    assert_eq!(
        inspect_agreement_backup(&archive, &key(76)).unwrap(),
        summary
    );
    let (restored, report) = restore_agreement_journal(
        &archive,
        &key(76),
        dir.path().join("restored.sqlite"),
        &key(77),
    )
    .unwrap();
    assert!(report.recovery_required && !report.authorization_allowed);
    assert!(restored.recovery_state().unwrap().recovery_required);
    assert!(
        original == read_cell(&restored.connection.lock().unwrap(), "records", "payload"),
        "restore must preserve the exact raw cell"
    );
    assert!(
        restored
            .get_agreement("synthetic-agreement")
            .unwrap()
            .unwrap()
            .payload[KEY]
            .as_object()
            .unwrap()
            .is_empty()
    );
    fingerprint(dir.path());
}
