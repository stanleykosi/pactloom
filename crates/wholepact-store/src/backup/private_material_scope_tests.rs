//! Synthetic legacy-scope fixtures. No live keys, wallet data or authority.
use super::*;
use crate::CommandContext;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use wholepact_storage_security::open_encrypted;

const PRIVATE_CANARY: &str = "SYNTHETIC-PRIVATE-CONSTRUCTION-SCOPE-CANARY-c8b62a";

fn key(byte: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([byte; 32])
}

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn create_agreement(source: &Store, principal: &str, id: &str, payload: Value) {
    let command = CommandContext::for_request(
        principal,
        &format!("scope-create-{id}-001"),
        &json!({"create": id}),
    )
    .unwrap();
    source.create_agreement(&command, id, payload).unwrap();
}

fn assert_scope_error<T>(result: Result<T>) {
    match result {
        Err(StoreError::InvalidInput(message)) => {
            assert_eq!(message, PRIVATE_CONSTRUCTION_SCOPE_ERROR);
            assert!(!message.contains(PRIVATE_CANARY));
        }
        _ => panic!("legacy backup must reject private construction scope"),
    }
}

fn assert_no_destination(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        assert!(!Path::new(&file).exists());
    }
}

fn assert_private_files(dir: &Path) {
    assert_eq!(fs::metadata(dir).unwrap().mode() & 0o777, 0o700);
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o077, 0);
        assert!(
            !fs::read(path)
                .unwrap()
                .windows(PRIVATE_CANARY.len())
                .any(|bytes| bytes == PRIVATE_CANARY.as_bytes())
        );
    }
}

#[test]
fn ordinary_and_empty_private_maps_keep_legacy_backup_roundtrip_and_quarantine() {
    let dir = directory();
    let source = Store::create_encrypted(dir.path().join("source.sqlite"), &key(121)).unwrap();
    for (principal, id, payload) in [
        ("owner-a", "absent", json!({"profile": "legacy"})),
        (
            "owner-b",
            "empty",
            json!({"profile": "durable", "durable_construction_v1": {}}),
        ),
    ] {
        create_agreement(&source, principal, id, payload);
    }
    let archive = dir.path().join("archive.sqlite");
    let summary = source
        .backup_agreement_journal(&archive, &key(122))
        .unwrap();
    assert_eq!(summary.scope, "coordination_and_authority_only");
    assert!(!summary.wallet_secrets_included);
    assert!(!summary.separate_artifact_journals_included);
    assert_eq!(
        inspect_agreement_backup(&archive, &key(122)).unwrap(),
        summary
    );
    let (restored, report) = restore_agreement_journal(
        &archive,
        &key(122),
        dir.path().join("restored.sqlite"),
        &key(123),
    )
    .unwrap();
    assert!(report.recovery_required);
    assert!(!report.authorization_allowed && !report.signer_recovered);
    assert_eq!(restored.list_agreements().unwrap().len(), 2);
    assert!(restored.recovery_state().unwrap().recovery_required);
    assert_private_files(dir.path());
}

#[test]
fn private_or_malformed_maps_refuse_before_archive_creation_for_every_owner() {
    let dir = directory();
    let source = Store::create_encrypted(dir.path().join("source.sqlite"), &key(124)).unwrap();
    create_agreement(&source, "owner-a", "ordinary", json!({"profile": "legacy"}));
    create_agreement(
        &source,
        "owner-b",
        "retained",
        json!({"profile": "durable"}),
    );
    let destination = dir.path().join("must-not-exist.sqlite");
    let mut payloads: Vec<String> = [
        json!({"candidate": {"viewing_key": PRIVATE_CANARY, "notes": [PRIVATE_CANARY], "witness": PRIVATE_CANARY}}),
        json!(null),
        json!([]),
        json!(""),
        json!(1),
        json!(true),
    ]
    .into_iter()
    .map(|value| json!({"durable_construction_v1": value}).to_string())
    .collect();
    payloads.push(format!(
        r#"{{"durable_construction_v1":{{"candidate":"{PRIVATE_CANARY}"}},"durable_construction_v1":{{}}}}"#
    ));
    payloads.push(format!(
        r#"{{"durable_construction_v\u0031":{{"candidate":"{PRIVATE_CANARY}"}}}}"#
    ));
    payloads.push(r#"{"durable_construction_v1":{"candidate":"truncated"#.into());
    for raw in payloads {
        source
            .connection
            .lock()
            .unwrap()
            .execute("UPDATE records SET payload=?1 WHERE id='retained'", [&raw])
            .unwrap();
        assert_scope_error(source.backup_agreement_journal(&destination, &key(125)));
        assert_no_destination(&destination);
        let retained: String = source
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT payload FROM records WHERE id='retained'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, raw);
    }
    assert_private_files(dir.path());
}

#[test]
fn private_history_alone_blocks_backup_even_with_an_empty_current_record() {
    let dir = directory();
    let source = Store::create_encrypted(dir.path().join("source.sqlite"), &key(126)).unwrap();
    create_agreement(
        &source,
        "owner-history",
        "history",
        json!({"durable_construction_v1": {}}),
    );
    let destination = dir.path().join("must-not-exist.sqlite");
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
        payload["durable_construction_v1"] = json!({"retained-candidate": PRIVATE_CANARY});
        source
            .connection
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE {table} SET {column}=?1"),
                [history.to_string()],
            )
            .unwrap();
        assert!(
            source.get_agreement("history").unwrap().unwrap().payload["durable_construction_v1"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        assert_scope_error(source.backup_agreement_journal(&destination, &key(127)));
        assert_no_destination(&destination);
        source
            .connection
            .lock()
            .unwrap()
            .execute(&format!("UPDATE {table} SET {column}=?1"), [&original])
            .unwrap();
    }
    assert_private_files(dir.path());
}

type FileFingerprint = (Vec<u8>, u32, u64, u64, i64, i64);

fn fingerprint(dir: &Path) -> BTreeMap<std::path::PathBuf, FileFingerprint> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(meta.is_file() && !meta.file_type().is_symlink());
            let bytes = fs::read(&path).unwrap();
            (
                path,
                (
                    bytes,
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
fn correctly_keyed_private_archives_cannot_claim_legacy_scope_or_restore() {
    let originals = directory();
    let destinations = directory();
    let source =
        Store::create_encrypted(originals.path().join("source.sqlite"), &key(128)).unwrap();
    create_agreement(
        &source,
        "owner-archive",
        "archive",
        json!({"durable_construction_v1": {}}),
    );
    let archive = originals.path().join("archive.sqlite");
    source
        .backup_agreement_journal(&archive, &key(129))
        .unwrap();
    drop(source);
    let writer = open_encrypted(&archive, &key(129)).unwrap();
    for (table, column) in [
        ("records", "payload"),
        ("operations", "result"),
        ("idempotency", "result"),
        ("events", "payload"),
    ] {
        let connection = writer.connection();
        let original: String = connection
            .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut value: Value = serde_json::from_str(&original).unwrap();
        let payload = if matches!(table, "operations" | "idempotency") {
            &mut value["record"]["payload"]
        } else {
            &mut value
        };
        payload["durable_construction_v1"] = json!({"private-candidate": PRIVATE_CANARY});
        connection
            .execute(
                &format!("UPDATE {table} SET {column}=?1"),
                [value.to_string()],
            )
            .unwrap();
        // Recompute the authentic row inventory, so refusal tests semantic scope
        // rather than an invalid key, digest or byte count.
        let stats = inspect_rows(connection, SCHEMA_VERSION).unwrap();
        connection
            .execute(
                "UPDATE backup_manifest SET snapshot_digest=?1,row_count=?2,data_bytes=?3",
                params![stats.digest, stats.rows, stats.bytes],
            )
            .unwrap();
        let before = fingerprint(originals.path());
        assert_scope_error(inspect_agreement_backup(&archive, &key(129)));
        let destination = destinations.path().join("must-not-exist.sqlite");
        assert_scope_error(restore_agreement_journal(
            &archive,
            &key(129),
            &destination,
            &key(130),
        ));
        assert_scope_error(test_restore_agreement_journal(
            &archive,
            &key(129),
            &destination,
            &key(130),
        ));
        assert_no_destination(&destination);
        assert_eq!(before, fingerprint(originals.path()));
        connection
            .execute(&format!("UPDATE {table} SET {column}=?1"), [&original])
            .unwrap();
    }
    assert_private_files(originals.path());
    assert_private_files(destinations.path());
}
