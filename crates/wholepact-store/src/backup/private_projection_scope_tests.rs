//! Inactive until the feature-independent legacy backup scanner includes the
//! new private metadata key. These synthetic fixtures are not native receipts.
use super::*;
use crate::CommandContext;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

const KEY: &str = "durable_input_projections_v1";
const CANARY: &str = "SYNTHETIC-PRIVATE-SELECTED-INPUT-METADATA-91827";
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
        &json!({"create":true}),
    )
    .unwrap();
    source
        .create_agreement(
            &command,
            "synthetic-agreement",
            json!({"durable_input_projections_v1": {}}),
        )
        .unwrap();
    source
}
fn refuse(source: &Store, path: &Path) {
    assert!(matches!(
        source.backup_agreement_journal(path, &key(76)),
        Err(StoreError::InvalidInput(PRIVATE_CONSTRUCTION_SCOPE_ERROR))
    ));
    assert!(!path.exists());
}

#[test]
fn private_projection_history_refuses_legacy_backup_even_if_current_map_empty() {
    let dir = directory();
    let source = source(&dir.path().join("source.sqlite"));
    let output = dir.path().join("forbidden.sqlite");
    for (table, column) in [
        ("operations", "result"),
        ("idempotency", "result"),
        ("events", "payload"),
    ] {
        let original: String = source
            .connection
            .lock()
            .unwrap()
            .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut history: Value = serde_json::from_str(&original).unwrap();
        let payload = if table == "events" {
            &mut history
        } else {
            &mut history["record"]["payload"]
        };
        payload[KEY] = json!({"synthetic-round": CANARY});
        source
            .connection
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE {table} SET {column}=?1"),
                [history.to_string()],
            )
            .unwrap();
        assert!(source
            .get_agreement("synthetic-agreement")
            .unwrap()
            .unwrap()
            .payload[KEY]
            .as_object()
            .unwrap()
            .is_empty());
        refuse(&source, &output);
        source
            .connection
            .lock()
            .unwrap()
            .execute(&format!("UPDATE {table} SET {column}=?1"), [&original])
            .unwrap();
    }
}

#[test]
fn private_projection_duplicate_escaped_and_malformed_keys_never_hide_from_backup() {
    let dir = directory();
    let source = source(&dir.path().join("source.sqlite"));
    let output = dir.path().join("forbidden.sqlite");
    let mut payloads = [
        json!(null),
        json!([]),
        json!(1),
        json!(true),
        json!("private"),
        json!({"synthetic-round":CANARY}),
    ]
    .into_iter()
    .map(|value| json!({"durable_input_projections_v1":value}).to_string())
    .collect::<Vec<_>>();
    payloads.push(format!(
        r#"{{"{KEY}":{{"round":"{CANARY}"}},"{KEY}":{{}}}}"#
    ));
    payloads.push(format!(
        r#"{{"durable_input_projections_v\u0031":{{"round":"{CANARY}"}}}}"#
    ));
    payloads.push(format!(r#"{{"{KEY}":{{"round":"truncated"#));
    for raw in payloads {
        source
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE records SET payload=?1 WHERE id='synthetic-agreement'",
                [&raw],
            )
            .unwrap();
        refuse(&source, &output);
        let unchanged: String = source
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT payload FROM records WHERE id='synthetic-agreement'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unchanged, raw);
    }
}

#[test]
fn empty_projection_metadata_does_not_change_legacy_backup_roundtrip() {
    let dir = directory();
    let source = source(&dir.path().join("source.sqlite"));
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
    assert!(restored
        .get_agreement("synthetic-agreement")
        .unwrap()
        .unwrap()
        .payload[KEY]
        .as_object()
        .unwrap()
        .is_empty());
}
