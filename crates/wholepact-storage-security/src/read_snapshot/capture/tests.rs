use super::*;
use crate::{create_encrypted, open_encrypted_read_only, tests::tree_fingerprint};
use std::os::unix::fs::symlink;

const CANARY: &str = "SYNTHETIC-RECOVERY-CIPHERTEXT-ONLY-9d4f";

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn initialized(path: &Path, key: &DatabaseKey) -> crate::EncryptedConnection {
    let database = create_encrypted(path, key).unwrap();
    database
        .connection()
        .execute_batch(
            "PRAGMA wal_autocheckpoint=0; CREATE TABLE synthetic_history(value TEXT NOT NULL);",
        )
        .unwrap();
    crate::checkpoint_and_sync(database.connection(), path).unwrap();
    database
}
fn check_private_ciphertext(snapshot: &ReadOnlySnapshot) {
    let directory = snapshot._directory.path();
    assert_eq!(fs::metadata(directory).unwrap().mode() & 0o777, 0o700);
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(entry.metadata().unwrap().mode() & 0o077, 0);
        assert!(!fs::read(entry.path())
            .unwrap()
            .windows(CANARY.len())
            .any(|bytes| bytes == CANARY.as_bytes()));
    }
}

#[test]
fn source_preserving_read_without_sidecars_is_private_readonly_and_cleans_up() {
    let directory = private_directory();
    let path = directory.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([231; 32]);
    let database = initialized(&path, &key);
    database
        .connection()
        .execute("INSERT INTO synthetic_history VALUES(?1)", [CANARY])
        .unwrap();
    drop(database);
    assert!(SUFFIXES[1..]
        .iter()
        .all(|suffix| !suffixed(&path, suffix).exists()));
    let before = tree_fingerprint(directory.path());
    let snapshot = open_encrypted_read_only(&path, &key).unwrap();
    assert_eq!(
        snapshot
            .query_row("SELECT value FROM synthetic_history", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        CANARY
    );
    assert!(snapshot
        .execute("DELETE FROM synthetic_history", [])
        .is_err());
    check_private_ciphertext(&snapshot);
    let temporary = snapshot._directory.path().to_path_buf();
    assert!(!temporary.starts_with(directory.path()));
    assert_eq!(before, tree_fingerprint(directory.path()));
    drop(snapshot);
    assert!(!temporary.exists());
    assert!(matches!(
        open_encrypted_read_only(&path, &DatabaseKey::from_bytes([232; 32])),
        Err(StorageSecurityError::AuthenticationFailed)
    ));
    assert_eq!(before, tree_fingerprint(directory.path()));
}

#[test]
fn source_preserving_read_includes_committed_wal_and_ignores_stale_shm() {
    let writer_directory = private_directory();
    let writer_path = writer_directory.path().join("writer.sqlite");
    let key = DatabaseKey::from_bytes([233; 32]);
    let writer = initialized(&writer_path, &key);
    writer
        .connection()
        .execute("INSERT INTO synthetic_history VALUES(?1)", [CANARY])
        .unwrap();
    assert!(fs::metadata(suffixed(&writer_path, "-wal")).unwrap().len() > 32);

    // A quiescent synthetic recovered set. The committed row exists only in
    // WAL; its SHM is deliberately stale and must never be trusted or rewritten.
    let directory = private_directory();
    let path = directory.path().join("source.sqlite");
    for suffix in ["", "-wal"] {
        fs::copy(suffixed(&writer_path, suffix), suffixed(&path, suffix)).unwrap();
    }
    let mut shm = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(suffixed(&path, "-shm"))
        .unwrap();
    shm.write_all(&[0xa5; 32768]).unwrap();
    drop(shm);
    let before = tree_fingerprint(directory.path());
    for _ in 0..2 {
        let snapshot = open_encrypted_read_only(&path, &key).unwrap();
        assert_eq!(
            snapshot
                .query_row("SELECT value FROM synthetic_history", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            CANARY
        );
        check_private_ciphertext(&snapshot);
        let temporary = snapshot._directory.path().to_path_buf();
        assert_eq!(before, tree_fingerprint(directory.path()));
        drop(snapshot);
        assert!(!temporary.exists());
        assert_eq!(before, tree_fingerprint(directory.path()));
    }
}

#[test]
fn snapshot_capture_rejects_file_replacement_growth_and_sidecar_appearance() {
    let directory = private_directory();
    let path = directory.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([234; 32]);
    drop(initialized(&path, &key));
    let sources = SourceSet::open(&path).unwrap();
    let replacement = directory.path().join("replacement.sqlite");
    fs::copy(&path, &replacement).unwrap();
    fs::rename(&replacement, &path).unwrap();
    assert!(matches!(
        sources.check_unchanged(),
        Err(StorageSecurityError::SourceChanged)
    ));

    let sources = SourceSet::open(&path).unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(file.metadata().unwrap().len() + 4096).unwrap();
    assert!(matches!(
        sources.check_unchanged(),
        Err(StorageSecurityError::SourceChanged)
    ));

    let sources = SourceSet::open(&path).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(suffixed(&path, "-wal"))
        .unwrap();
    assert!(matches!(
        sources.check_unchanged(),
        Err(StorageSecurityError::SourceChanged)
    ));
}

#[test]
fn snapshot_capture_rejects_aggregate_oversize_and_unsafe_sidecars() {
    let directory = private_directory();
    let path = directory.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([235; 32]);
    drop(initialized(&path, &key));
    let journal_path = suffixed(&path, "-journal");
    let journal = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&journal_path)
        .unwrap();
    journal.set_len(MAX_SNAPSHOT_BYTES).unwrap();
    assert!(matches!(
        open_encrypted_read_only(&path, &key),
        Err(StorageSecurityError::SnapshotLimit)
    ));
    drop(journal);
    fs::remove_file(&journal_path).unwrap();
    symlink(&path, &journal_path).unwrap();
    assert!(matches!(
        open_encrypted_read_only(&path, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
    fs::remove_file(&journal_path).unwrap();
    fs::hard_link(&path, &journal_path).unwrap();
    assert!(matches!(
        open_encrypted_read_only(&path, &key),
        Err(StorageSecurityError::UnsafePath)
    ));
}

#[test]
fn public_read_snapshot_rejects_quarantine_and_uninitialized_without_source_changes() {
    let directory = private_directory();
    let path = directory.path().join("source.sqlite");
    let key = DatabaseKey::from_bytes([236; 32]);
    drop(create_encrypted(&path, &key).unwrap());
    let before = tree_fingerprint(directory.path());
    assert!(matches!(
        crate::open_encrypted_read_snapshot(&path, &key),
        Err(StorageSecurityError::UninitializedDatabase)
    ));
    assert_eq!(before, tree_fingerprint(directory.path()));

    let database = crate::keyed_connection(&path, &key).unwrap();
    database
        .execute_batch("CREATE TABLE synthetic_history(value TEXT NOT NULL);")
        .unwrap();
    database
        .execute("INSERT INTO synthetic_history VALUES(?1)", [CANARY])
        .unwrap();
    drop(database);
    let before = tree_fingerprint(directory.path());
    let read = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
    assert_eq!(
        read.connection()
            .query_row("SELECT value FROM synthetic_history", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        CANARY
    );
    assert!(read
        .connection()
        .execute("DELETE FROM synthetic_history", [])
        .is_err());
    // Even disabling query_only cannot make the read-only file handle writable.
    read.connection()
        .execute_batch("PRAGMA query_only=OFF;")
        .unwrap();
    assert!(read
        .connection()
        .execute("DELETE FROM synthetic_history", [])
        .is_err());
    drop(read);
    assert_eq!(before, tree_fingerprint(directory.path()));

    let database = crate::keyed_connection(&path, &key).unwrap();
    database
        .pragma_update(
            None,
            "application_id",
            crate::bundle::QUARANTINE_APPLICATION_ID,
        )
        .unwrap();
    drop(database);
    let before = tree_fingerprint(directory.path());
    assert!(matches!(
        crate::open_encrypted_read_snapshot(&path, &key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert_eq!(before, tree_fingerprint(directory.path()));
}
