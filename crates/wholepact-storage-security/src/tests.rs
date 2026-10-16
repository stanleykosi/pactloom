use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

/// Synthetic source-tree evidence, including names, contents and metadata.
/// Access time is excluded because ordinary reads may legitimately update it.
type TreeFingerprintEntry = (Vec<u8>, u32, u64, u64, i64, i64);
pub(crate) fn tree_fingerprint(
    root: &Path,
) -> std::collections::BTreeMap<std::path::PathBuf, TreeFingerprintEntry> {
    use std::os::unix::fs::MetadataExt;
    let mut result = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let bytes = if metadata.is_dir() {
                pending.push(path.clone());
                Vec::new()
            } else {
                fs::read(&path).unwrap()
            };
            result.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                (
                    bytes,
                    metadata.mode(),
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            );
        }
    }
    result
}

const CANARY: &str = "SYNTHETIC-PRIVATE-WHOLEPACT-NOTE-WITNESS-4f33c015";
fn synthetic_key(byte: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([byte; 32])
}
fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn assert_no_canary(path: &Path) {
    for entry in fs::read_dir(path).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            let bytes = fs::read(&p).unwrap();
            assert!(
                !bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
                "plaintext canary in {}",
                p.display()
            );
        }
    }
}

#[test]
fn pinned_runtime_durable_wal_and_keyed_reopen() {
    let dir = private_dir();
    let path = dir.path().join("database.sqlite");
    let key = synthetic_key(17);
    let db = create_encrypted(&path, &key).unwrap();
    let c = db.connection();
    assert_eq!(
        c.query_row("PRAGMA cipher_status", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "1"
    );
    c.execute_batch("PRAGMA wal_autocheckpoint=0; CREATE TABLE secrets(id INTEGER PRIMARY KEY, value BLOB NOT NULL);").unwrap();
    c.execute("INSERT INTO secrets(value) VALUES(?1)", [CANARY])
        .unwrap();
    assert!(
        fs::metadata(path.with_extension("sqlite-wal"))
            .unwrap()
            .len()
            > 32
    );
    // Exercise ephemeral data paths as well as main/WAL pages.
    c.execute_batch("CREATE TEMP TABLE temporary_values(value); INSERT INTO temporary_values SELECT value FROM secrets;").unwrap();
    assert_eq!(
        c.query_row("PRAGMA temp_store", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        c.query_row("SELECT value FROM temporary_values", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        CANARY
    );
    assert_no_canary(dir.path());
    drop(db);
    assert!(!fs::read(&path).unwrap().starts_with(HEADER));
    let reopened = open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened
            .connection()
            .query_row("SELECT value FROM secrets", [], |r| r.get::<_, String>(0))
            .unwrap(),
        CANARY
    );
    assert_no_canary(dir.path());
}

#[test]
fn wrong_key_unkeyed_handle_plaintext_and_missing_are_refused() {
    let dir = private_dir();
    let path = dir.path().join("database.sqlite");
    let key = synthetic_key(23);
    let db = create_encrypted(&path, &key).unwrap();
    db.connection()
        .execute_batch("CREATE TABLE secrets(value);")
        .unwrap();
    drop(db);
    assert!(matches!(
        open_encrypted(&path, &synthetic_key(24)),
        Err(StorageSecurityError::AuthenticationFailed)
    ));
    let unkeyed = Connection::open(&path).unwrap();
    assert!(unkeyed
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r
            .get::<_, i64>(0))
        .is_err());
    drop(unkeyed);
    assert!(matches!(
        create_encrypted(&path, &key),
        Err(StorageSecurityError::AlreadyExists)
    ));
    assert!(matches!(
        open_encrypted(dir.path().join("missing.sqlite"), &key),
        Err(StorageSecurityError::MissingDatabase)
    ));
    let empty = dir.path().join("empty.sqlite");
    fs::write(&empty, []).unwrap();
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        open_encrypted(&empty, &key),
        Err(StorageSecurityError::MissingDatabase)
    ));
    let plain = dir.path().join("plain.sqlite");
    Connection::open(&plain)
        .unwrap()
        .execute_batch("CREATE TABLE leaks(value);")
        .unwrap();
    fs::set_permissions(&plain, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        open_encrypted(&plain, &key),
        Err(StorageSecurityError::PlaintextRefused)
    ));
}

#[test]
fn backup_uses_independent_key_and_retains_committed_wal_data() {
    let dir = private_dir();
    let path = dir.path().join("database.sqlite");
    let backup = dir.path().join("backup.sqlite");
    let key = synthetic_key(31);
    let backup_key = synthetic_key(32);
    let db = create_encrypted(&path, &key).unwrap();
    db.connection()
        .execute_batch("PRAGMA wal_autocheckpoint=0; CREATE TABLE secrets(value);")
        .unwrap();
    db.connection()
        .execute("INSERT INTO secrets VALUES(?1)", [CANARY])
        .unwrap();
    backup_encrypted(&db, &backup, &backup_key).unwrap();
    assert_no_canary(dir.path());
    assert!(open_encrypted(&backup, &key).is_err());
    let restored = open_encrypted(&backup, &backup_key).unwrap();
    assert_eq!(
        restored
            .connection()
            .query_row("SELECT value FROM secrets", [], |r| r.get::<_, String>(0))
            .unwrap(),
        CANARY
    );
    assert!(matches!(
        backup_encrypted(&db, &backup, &backup_key),
        Err(StorageSecurityError::AlreadyExists)
    ));
}

#[test]
fn tampered_data_page_fails_integrity_even_when_schema_survives() {
    let dir = private_dir();
    let path = dir.path().join("database.sqlite");
    let key = synthetic_key(37);
    let db = create_encrypted(&path, &key).unwrap();
    db.connection()
        .execute_batch("CREATE TABLE secrets(value); INSERT INTO secrets VALUES(zeroblob(16000));")
        .unwrap();
    drop(db);
    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 8192);
    bytes[8192 + 128] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        open_encrypted(&path, &key),
        Err(StorageSecurityError::AuthenticationFailed)
    ));
}

#[test]
fn file_and_directory_permissions_and_symlinks_fail_closed() {
    let dir = private_dir();
    let path = dir.path().join("database.sqlite");
    let key = synthetic_key(41);
    drop(create_encrypted(&path, &key).unwrap());
    let link = dir.path().join("link.sqlite");
    symlink(&path, &link).unwrap();
    assert!(matches!(
        open_encrypted(&link, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        open_encrypted(&path, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        open_encrypted(&path, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
}

#[test]
fn key_debug_is_redacted() {
    assert_eq!(
        format!("{:?}", synthetic_key(42)),
        "DatabaseKey([REDACTED])"
    );
}

#[test]
fn crash_child_fixture() {
    let Some(directory) = std::env::var_os("WHOLEPACT_SYNTHETIC_CRASH_DIRECTORY") else {
        return;
    };
    let path = std::path::PathBuf::from(directory).join("crash.sqlite");
    let key = synthetic_key(53);
    let db = create_encrypted(path, &key).unwrap();
    db.connection()
        .execute_batch("PRAGMA wal_autocheckpoint=0; CREATE TABLE secrets(value);")
        .unwrap();
    db.connection()
        .execute("INSERT INTO secrets VALUES(?1)", [CANARY])
        .unwrap();
    db.connection()
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO secrets VALUES('UNCOMMITTED-SYNTHETIC-ROW');")
        .unwrap();
    // Simulate process loss after a durable commit and during a second transaction.
    // exit skips Rust/SQLite destructors; no actual credentials or account exist.
    std::process::exit(0);
}

#[test]
fn process_loss_recovers_committed_wal_and_discards_partial_transaction() {
    let dir = private_dir();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::crash_child_fixture", "--nocapture"])
        .env("WHOLEPACT_SYNTHETIC_CRASH_DIRECTORY", dir.path())
        .status()
        .unwrap();
    assert!(result.success());
    let path = dir.path().join("crash.sqlite");
    assert!(path.with_extension("sqlite-wal").exists());
    assert_no_canary(dir.path());
    let db = open_encrypted(path, &synthetic_key(53)).unwrap();
    assert_eq!(
        db.connection()
            .query_row("SELECT count(*) FROM secrets", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.connection()
            .query_row("SELECT value FROM secrets", [], |r| r.get::<_, String>(0))
            .unwrap(),
        CANARY
    );
}

#[test]
fn preexisting_sidecar_symlink_and_hardlink_are_refused() {
    let dir = private_dir();
    let path = dir.path().join("database.sqlite");
    let key = synthetic_key(59);
    let target = dir.path().join("unrelated.txt");
    fs::write(&target, b"unrelated").unwrap();
    let wal = path.with_extension("sqlite-wal");
    symlink(&target, &wal).unwrap();
    assert!(matches!(
        create_encrypted(&path, &key),
        Err(StorageSecurityError::AlreadyExists)
    ));
    fs::remove_file(&wal).unwrap();
    drop(create_encrypted(&path, &key).unwrap());
    symlink(&target, &wal).unwrap();
    assert!(matches!(
        open_encrypted(&path, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
    assert_eq!(fs::read(&target).unwrap(), b"unrelated");
    fs::remove_file(&wal).unwrap();
    fs::hard_link(&path, dir.path().join("hardlink.sqlite")).unwrap();
    assert!(matches!(
        open_encrypted(&path, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
}

#[test]
fn uninitialized_create_handle_cannot_be_adopted_after_process_loss() {
    let Some(directory) = std::env::var_os("WHOLEPACT_SYNTHETIC_EMPTY_CRASH_DIRECTORY") else {
        return;
    };
    let path = std::path::PathBuf::from(directory).join("empty-crash.sqlite");
    let _initialization_handle = create_encrypted(path, &synthetic_key(61)).unwrap();
    // Crash before a journal schema or a restore quarantine marker commits.
    std::process::exit(0);
}
#[test]
fn crash_before_schema_or_quarantine_marker_does_not_bootstrap_authority() {
    let dir = private_dir();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::uninitialized_create_handle_cannot_be_adopted_after_process_loss",
            "--nocapture",
        ])
        .env("WHOLEPACT_SYNTHETIC_EMPTY_CRASH_DIRECTORY", dir.path())
        .status()
        .unwrap();
    assert!(result.success());
    let path = dir.path().join("empty-crash.sqlite");
    assert!(matches!(
        open_encrypted(&path, &synthetic_key(61)),
        Err(StorageSecurityError::UninitializedDatabase)
    ));
    assert!(matches!(
        create_encrypted(&path, &synthetic_key(61)),
        Err(StorageSecurityError::AlreadyExists)
    ));
    assert!(path.exists()); // No destructive recovery fallback.
    let initialized = dir.path().join("explicit-initialization.sqlite");
    let db = create_encrypted(&initialized, &synthetic_key(62)).unwrap();
    db.connection()
        .execute_batch("CREATE TABLE initialized(value TEXT);")
        .unwrap();
    drop(db);
    assert!(open_encrypted(&initialized, &synthetic_key(62)).is_ok());
}

#[test]
fn quiescent_open_rejection_preflight_preserves_every_original_file() {
    // Synthetic quiescent owner scopes. No concurrent writers/checkpointers or
    // path replacement are allowed during an ordinary open's qualified boundary.
    for (name, application, marker, initialized) in [
        (
            "recovered",
            bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID,
            false,
            true,
        ),
        (
            "quarantined",
            bundle::QUARANTINE_APPLICATION_ID,
            false,
            true,
        ),
        ("marker-only", 0, true, true),
        ("uninitialized", 0, false, false),
    ] {
        let directory = private_dir();
        let path = directory.path().join(format!("{name}.sqlite"));
        let key = synthetic_key(71);
        let connection = create_encrypted(&path, &key).unwrap();
        if initialized {
            connection
                .connection()
                .execute_batch("CREATE TABLE synthetic_private(value TEXT);")
                .unwrap();
            connection
                .connection()
                .pragma_update(None, "application_id", application)
                .unwrap();
            if marker {
                connection.connection().execute_batch("CREATE TABLE wholepact_recovered_generation(singleton INTEGER PRIMARY KEY,binding BLOB);").unwrap();
            }
        }
        drop(connection);
        let before = tree_fingerprint(directory.path());
        assert!(open_encrypted_quiescent(&path, &key).is_err());
        assert!(
            before == tree_fingerprint(directory.path()),
            "protected/uninitialized rejection changed source tree: {name}"
        );
        assert!(open_encrypted_quiescent(&path, &synthetic_key(72)).is_err());
        assert!(
            before == tree_fingerprint(directory.path()),
            "wrong-key rejection changed source tree: {name}"
        );
    }
}

#[test]
fn quiescent_open_source_guard_rejects_wrong_path_and_detected_replacement_before_sql() {
    let directory = private_dir();
    let path = directory.path().join("source.sqlite");
    let other = directory.path().join("other.sqlite");
    let key = synthetic_key(73);
    let original = create_encrypted(&path, &key).unwrap();
    original
        .connection()
        .execute_batch("CREATE TABLE synthetic_source(value TEXT)")
        .unwrap();
    drop(original);
    let replacement = create_encrypted(&other, &key).unwrap();
    replacement
        .connection()
        .execute_batch("CREATE TABLE synthetic_protected(value TEXT)")
        .unwrap();
    replacement
        .connection()
        .pragma_update(
            None,
            "application_id",
            bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID,
        )
        .unwrap();
    drop(replacement);
    let preflight = open_encrypted_read_only(&path, &key).unwrap();
    let before = tree_fingerprint(directory.path());
    assert!(matches!(
        keyed_connection_checked(&other, &key, false, Some(&preflight)),
        Err(StorageSecurityError::SourceChanged)
    ));
    assert!(
        before == tree_fingerprint(directory.path()),
        "wrong-path guard changed source tree"
    );
    // Deliberately violate quiescence before admission to verify the race
    // detector. No guarantee is claimed for hostile swaps after the final check.
    fs::rename(&other, &path).unwrap();
    let before = tree_fingerprint(directory.path());
    assert!(matches!(
        keyed_connection_checked(&path, &key, false, Some(&preflight)),
        Err(StorageSecurityError::SourceChanged)
    ));
    assert!(
        before == tree_fingerprint(directory.path()),
        "detected replacement was opened or changed"
    );
}

#[test]
fn ordinary_open_keeps_separate_sqlite_connections_without_quiescent_capture() {
    let directory = private_dir();
    let path = directory.path().join("concurrent.sqlite");
    let key = synthetic_key(74);
    let first = create_encrypted(&path, &key).unwrap();
    first
        .connection()
        .execute_batch(
            "CREATE TABLE synthetic_shared(value INTEGER); INSERT INTO synthetic_shared VALUES(1);",
        )
        .unwrap();
    first
        .connection()
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO synthetic_shared VALUES(2);")
        .unwrap();
    // An existing independent writer owns an uncommitted transaction. Ordinary
    // open retains SQLite's concurrent-read/serialized-write contract; it must
    // not require a whole-profile no-writer capability or source-copy preflight.
    let second = open_encrypted(&path, &key).unwrap();
    assert_eq!(
        second
            .connection()
            .query_row("SELECT count(*) FROM synthetic_shared", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    first.connection().execute_batch("COMMIT;").unwrap();
    second
        .connection()
        .execute("INSERT INTO synthetic_shared VALUES(3)", [])
        .unwrap();
    assert_eq!(
        first
            .connection()
            .query_row("SELECT count(*) FROM synthetic_shared", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
}
