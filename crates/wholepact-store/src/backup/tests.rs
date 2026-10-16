use super::*;
use crate::{CommandContext, authority::ReleaseIntent};
use serde_json::json;
use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use wholepact_storage_security::open_encrypted;

const CANARY: &str = "SYNTHETIC-AGREEMENT-BACKUP-PRIVATE-CANARY-e9377a";
struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wholepact-backup-{}-{}-{}",
            std::process::id(),
            now_ms(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key(byte: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([byte; 32])
}
fn request(id: &str) -> ReleaseIntent {
    ReleaseIntent {
        authorization_id: id.into(),
        account_id: "account-a".into(),
        writer_epoch: 7,
        obligation_id: format!("obligation-{id}"),
        proposal_id: format!("proposal-{id}"),
        manifest_digest: "a".repeat(64),
        effects_digest: "b".repeat(64),
        artifact_digest: "c".repeat(64),
        maximum_debit: "60".into(),
        input_ids: vec![format!("input-{id}")],
        aggregate_budget_limit: "200".into(),
    }
}
fn populated(dir: &TestDirectory) -> (Store, CommandContext) {
    let source = Store::create_encrypted(dir.path("source.sqlite"), &key(10)).unwrap();
    let command = CommandContext::for_request(
        "client-a",
        "create-agreement-key-001",
        &json!({"create":"agreement-a"}),
    )
    .unwrap();
    source
        .create_agreement(&command, "agreement-a", json!({"purpose":CANARY}))
        .unwrap();
    source.initialize_authority_account("account-a", 7).unwrap();
    source
        .record_authorization_release_intent(&request("auth-a"))
        .unwrap();
    source.mark_authorization_released("auth-a").unwrap();
    source
        .record_effect_intent(
            "effect-a",
            "submit",
            "agreement-a",
            &"d".repeat(64),
            "protected-artifact-ref",
        )
        .unwrap();
    (source, command)
}
fn no_plaintext(dir: &TestDirectory) {
    for entry in fs::read_dir(&dir.0).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            assert!(
                !fs::read(entry.path())
                    .unwrap()
                    .windows(CANARY.len())
                    .any(|part| part == CANARY.as_bytes())
            );
        }
    }
}

// Byte/name/identity evidence for the whole synthetic archive directory. Reads
// can update atime, which is deliberately not an immutability assertion here.
type TreeFingerprintEntry = (Vec<u8>, u32, u64, u64, i64, i64);
fn tree_fingerprint(root: &Path) -> BTreeMap<PathBuf, TreeFingerprintEntry> {
    use std::os::unix::fs::MetadataExt;
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
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

#[test]
fn legacy_archive_inspection_and_restore_preserve_complete_source_tree_with_wal() {
    let originals = TestDirectory::new();
    let destinations = TestDirectory::new();
    let (source, _) = populated(&originals);
    let archive = originals.path("backup.sqlite");
    let initial = source.backup_agreement_journal(&archive, &key(81)).unwrap();
    drop(source);
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut path = archive.as_os_str().to_os_string();
        path.push(suffix);
        assert!(!Path::new(&path).exists());
    }
    let without_sidecars = tree_fingerprint(&originals.0);
    assert_eq!(
        inspect_agreement_backup(&archive, &key(81)).unwrap(),
        initial
    );
    assert!(inspect_agreement_backup(&archive, &key(82)).is_err());
    let test_report = test_restore_agreement_journal(
        &archive,
        &key(81),
        destinations.path("test.sqlite"),
        &key(83),
    )
    .unwrap();
    assert_eq!(test_report.backup, initial);
    assert_eq!(without_sidecars, tree_fingerprint(&originals.0));

    // A committed manifest change remains only in WAL. It is outside the row
    // digest but part of the authenticated archive summary, so a reader that
    // ignores WAL would return the old timestamp and fail this assertion.
    let writer = open_encrypted(&archive, &key(81)).unwrap();
    writer.connection().execute_batch("PRAGMA wal_autocheckpoint=0; UPDATE backup_manifest SET created_at_ms=created_at_ms+1;").unwrap();
    assert!(
        fs::metadata(originals.path("backup.sqlite-wal"))
            .unwrap()
            .len()
            > 32
    );
    let mut expected = initial;
    expected.created_at_ms += 1;
    let with_wal = tree_fingerprint(&originals.0);
    assert_eq!(
        inspect_agreement_backup(&archive, &key(81)).unwrap(),
        expected
    );
    let (restored, report) = restore_agreement_journal(
        &archive,
        &key(81),
        destinations.path("restored.sqlite"),
        &key(84),
    )
    .unwrap();
    assert_eq!(report.backup, expected);
    assert!(report.recovery_required);
    assert_eq!(restored.outstanding_debit("account-a").unwrap(), "60");
    drop(restored);
    assert!(
        restore_agreement_journal(
            &archive,
            &key(81),
            destinations.path("restored.sqlite"),
            &key(84),
        )
        .is_err()
    );
    assert_eq!(with_wal, tree_fingerprint(&originals.0));

    writer
        .connection()
        .execute(
            "UPDATE backup_manifest SET snapshot_digest=?1",
            ["0".repeat(64)],
        )
        .unwrap();
    let invalid_wal = tree_fingerprint(&originals.0);
    assert!(inspect_agreement_backup(&archive, &key(81)).is_err());
    assert!(
        restore_agreement_journal(
            &archive,
            &key(81),
            destinations.path("invalid.sqlite"),
            &key(85),
        )
        .is_err()
    );
    assert_eq!(invalid_wal, tree_fingerprint(&originals.0));
    no_plaintext(&originals);
    no_plaintext(&destinations);
}

#[test]
fn legacy_archive_bound_includes_rollback_journal() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = TestDirectory::new();
    let (source, _) = populated(&dir);
    let archive = dir.path("backup.sqlite");
    source.backup_agreement_journal(&archive, &key(86)).unwrap();
    let journal = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.path("backup.sqlite-journal"))
        .unwrap();
    journal.set_len(MAX_FILE_BYTES).unwrap();
    assert!(matches!(
        inspect_agreement_backup(&archive, &key(86)),
        Err(StoreError::ResourceExhausted)
    ));
}

#[test]
fn encrypted_full_journal_roundtrip_preserves_replay_exposure_and_quarantines() {
    let dir = TestDirectory::new();
    let (source, command) = populated(&dir);
    let before_events = source.events_after(0, 100).unwrap();
    let before_exposure = source.exposure("auth-a").unwrap().unwrap();
    let before_effect = source.effect_intent("effect-a").unwrap().unwrap();
    let archive = dir.path("backup.sqlite");
    let summary = source.backup_agreement_journal(&archive, &key(11)).unwrap();
    assert_eq!(summary.scope, "coordination_and_authority_only");
    assert!(
        !summary.wallet_secrets_included
            && !summary.separate_artifact_journals_included
            && !summary.freshness_established
    );
    assert_eq!(summary.table_rows["idempotency"], 1);
    assert_eq!(summary.table_rows["effect_intents"], 1);
    assert!(
        source
            .authority_account("account-a")
            .unwrap()
            .is_some_and(|a| !a.recovery_required)
    );
    assert!(Store::open_encrypted(&archive, &key(11)).is_err());
    assert!(inspect_agreement_backup(&archive, &key(10)).is_err());
    assert_eq!(
        inspect_agreement_backup(&archive, &key(11)).unwrap(),
        summary
    );
    // A valid backup can omit later released obligations. Restoring it must not
    // treat its smaller known exposure as complete or current authority.
    source
        .record_authorization_release_intent(&request("auth-after-backup"))
        .unwrap();
    assert_eq!(source.outstanding_debit("account-a").unwrap(), "120");
    let (restored, report) =
        restore_agreement_journal(&archive, &key(11), dir.path("restored.sqlite"), &key(12))
            .unwrap();
    assert!(report.integrity_verified && report.recovery_required);
    assert!(!report.authorization_allowed && !report.signer_recovered && !report.migration_applied);
    assert_eq!(report.quarantined_authority_accounts, 1);
    assert_eq!(restored.events_after(0, 100).unwrap(), before_events);
    assert_eq!(
        restored.exposure("auth-a").unwrap().unwrap(),
        before_exposure
    );
    assert_eq!(
        restored
            .effect_intent("effect-a")
            .unwrap()
            .unwrap()
            .payload_digest,
        before_effect.payload_digest
    );
    assert_eq!(restored.outstanding_debit("account-a").unwrap(), "60");
    assert!(
        restored
            .authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert!(restored.find_replay(&command).unwrap().unwrap().replayed);
    assert_eq!(
        restored
            .record_authorization_release_intent(&request("auth-a"))
            .unwrap(),
        before_exposure
    );
    assert!(matches!(
        restored.record_authorization_release_intent(&request("auth-b")),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        restored.initialize_authority_account("new-account", 1),
        Err(StoreError::RecoveryRequired)
    ));
    // Resuming unsigned metadata work retains original event sequence and operation IDs.
    let next = CommandContext::for_request(
        "client-a",
        "update-agreement-key-001",
        &json!({"update":"agreement-a"}),
    )
    .unwrap();
    let mutation = restored
        .update_agreement(
            &next,
            "agreement-a",
            1,
            json!({"purpose":CANARY,"revision":2}),
            "agreement.updated",
        )
        .unwrap();
    assert_eq!(
        mutation.event_sequence,
        before_events.last().unwrap().sequence + 1
    );
    drop(restored);
    let reopened = Store::open_encrypted(dir.path("restored.sqlite"), &key(12)).unwrap();
    assert!(reopened.recovery_state().unwrap().recovery_required);
    no_plaintext(&dir);
}

#[test]
fn empty_restore_and_test_restore_never_bootstrap_fresh_authority() {
    let dir = TestDirectory::new();
    let source = Store::create_encrypted(dir.path("source.sqlite"), &key(20)).unwrap();
    source
        .backup_agreement_journal(dir.path("backup.sqlite"), &key(21))
        .unwrap();
    let report = test_restore_agreement_journal(
        dir.path("backup.sqlite"),
        &key(21),
        dir.path("test-restored.sqlite"),
        &key(22),
    )
    .unwrap();
    assert_eq!(report.quarantined_authority_accounts, 0);
    assert!(report.recovery_required);
    let restored = Store::open_encrypted(dir.path("test-restored.sqlite"), &key(22)).unwrap();
    assert!(matches!(
        restored.initialize_authority_account("account-new", 1),
        Err(StoreError::RecoveryRequired)
    ));
    restored.import_restored_account("account-new", 9).unwrap();
    assert!(
        restored
            .authority_account("account-new")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert!(!source.recovery_state().unwrap().recovery_required);
}

#[test]
fn explicit_v1_live_migration_and_v1_archive_restore_preserve_history() {
    let dir = TestDirectory::new();
    // A historical live v1 store is migrated transactionally without being
    // mislabeled restored. This is compatibility, not rollback detection.
    let legacy = create_encrypted(dir.path("legacy.sqlite"), &key(30)).unwrap();
    initialize_schema(legacy.connection(), 1).unwrap();
    legacy
        .connection()
        .execute(
            "INSERT INTO authority_accounts VALUES('legacy-account',3,0)",
            [],
        )
        .unwrap();
    legacy
        .connection()
        .pragma_update(None, "user_version", 1)
        .unwrap();
    drop(legacy);
    let migrated = Store::open_encrypted(dir.path("legacy.sqlite"), &key(30)).unwrap();
    assert!(!migrated.recovery_state().unwrap().recovery_required);
    assert_eq!(
        migrated
            .authority_account("legacy-account")
            .unwrap()
            .unwrap()
            .writer_epoch,
        3
    );
    // Supported v1 archive schema migration is exercised independently.
    let archive = create_encrypted(dir.path("legacy-archive.sqlite"), &key(31)).unwrap();
    let c = archive.connection();
    initialize_schema(c, 1).unwrap();
    c.execute(
        "INSERT INTO authority_accounts VALUES('legacy-account',3,0)",
        [],
    )
    .unwrap();
    let stats = inspect_rows(c, 1).unwrap();
    c.execute_batch(ARCHIVE_SCHEMA).unwrap();
    c.pragma_update(None, "application_id", ARCHIVE_APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", ARCHIVE_VERSION)
        .unwrap();
    c.execute(
        "INSERT INTO backup_manifest VALUES(1,1,1,?1,?2,?3,?4,'coordination_and_authority_only')",
        params![now_ms(), stats.digest, stats.rows, stats.bytes],
    )
    .unwrap();
    drop(archive);
    let (restored, report) = restore_agreement_journal(
        dir.path("legacy-archive.sqlite"),
        &key(31),
        dir.path("migrated-restore.sqlite"),
        &key(32),
    )
    .unwrap();
    assert!(report.migration_applied && report.recovery_required);
    assert_eq!(report.destination_schema_version, SCHEMA_VERSION as u32);
    assert!(
        restored
            .authority_account("legacy-account")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert_eq!(
        restored
            .authority_account("legacy-account")
            .unwrap()
            .unwrap()
            .writer_epoch,
        3
    );
    let interrupted = create_encrypted(dir.path("migration-rollback.sqlite"), &key(33)).unwrap();
    initialize_schema(interrupted.connection(), 1).unwrap();
    interrupted
        .connection()
        .pragma_update(None, "user_version", 1)
        .unwrap();
    interrupted
        .connection()
        .pragma_update(None, "query_only", true)
        .unwrap();
    assert!(Store::from_encrypted_connection(interrupted).is_err());
    let still_legacy = open_encrypted(dir.path("migration-rollback.sqlite"), &key(33)).unwrap();
    assert_eq!(
        still_legacy
            .connection()
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        still_legacy
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='store_recovery'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    drop(still_legacy);
    assert!(
        !Store::open_encrypted(dir.path("migration-rollback.sqlite"), &key(33))
            .unwrap()
            .recovery_state()
            .unwrap()
            .recovery_required
    );
}

#[test]
fn malformed_versions_content_schemas_and_nonprotected_sources_refuse() {
    let dir = TestDirectory::new();
    assert!(
        Store::in_memory()
            .unwrap()
            .backup_agreement_journal(dir.path("memory-backup.sqlite"), &key(40))
            .is_err()
    );
    assert!(!dir.path("memory-backup.sqlite").exists());
    let (source, _) = populated(&dir);
    source
        .backup_agreement_journal(dir.path("backup.sqlite"), &key(41))
        .unwrap();
    let archive = open_encrypted(dir.path("backup.sqlite"), &key(41)).unwrap();
    archive
        .connection()
        .execute("UPDATE backup_manifest SET source_schema_version=99", [])
        .unwrap();
    assert!(matches!(
        inspect_agreement_backup(dir.path("backup.sqlite"), &key(41)),
        Err(StoreError::UnsupportedSchema(99))
    ));
    archive
        .connection()
        .execute("UPDATE backup_manifest SET source_schema_version=2", [])
        .unwrap();
    archive
        .connection()
        .execute("UPDATE records SET payload='{}'", [])
        .unwrap();
    assert!(inspect_agreement_backup(dir.path("backup.sqlite"), &key(41)).is_err());
    assert!(
        restore_agreement_journal(
            dir.path("backup.sqlite"),
            &key(41),
            dir.path("refused.sqlite"),
            &key(42)
        )
        .is_err()
    );
    assert!(!dir.path("refused.sqlite").exists());
    source
        .connection
        .lock()
        .unwrap()
        .execute_batch("CREATE TABLE sqliteXunexpected_secret(value TEXT);")
        .unwrap();
    assert!(
        source
            .backup_agreement_journal(dir.path("extra-table.sqlite"), &key(43))
            .is_err()
    );
    assert!(!dir.path("extra-table.sqlite").exists());
    // Existing unknown live schemas are not opportunistically migrated.
    let foreign = create_encrypted(dir.path("future.sqlite"), &key(44)).unwrap();
    foreign
        .connection()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    drop(foreign);
    assert!(matches!(
        Store::open_encrypted(dir.path("future.sqlite"), &key(44)),
        Err(StoreError::UnsupportedSchema(99))
    ));
}

#[test]
fn precommit_failures_leave_fenced_destinations_and_retry_requires_new_path() {
    let dir = TestDirectory::new();
    let (source, command) = populated(&dir);
    INJECTED_FAILURE.with(|f| f.set(Some("backup")));
    let failure = source.backup_agreement_journal(dir.path("failed-backup.sqlite"), &key(51));
    INJECTED_FAILURE.with(|f| f.set(None));
    assert!(failure.is_err());
    assert!(source.find_replay(&command).unwrap().is_some());
    assert!(Store::open_encrypted(dir.path("failed-backup.sqlite"), &key(51)).is_err());
    assert!(
        source
            .backup_agreement_journal(dir.path("failed-backup.sqlite"), &key(51))
            .is_err()
    );
    source
        .backup_agreement_journal(dir.path("backup.sqlite"), &key(52))
        .unwrap();
    INJECTED_FAILURE.with(|f| f.set(Some("restore")));
    let failure = restore_agreement_journal(
        dir.path("backup.sqlite"),
        &key(52),
        dir.path("failed-restore.sqlite"),
        &key(53),
    );
    INJECTED_FAILURE.with(|f| f.set(None));
    assert!(failure.is_err());
    assert!(Store::open_encrypted(dir.path("failed-restore.sqlite"), &key(53)).is_err());
    assert!(
        restore_agreement_journal(
            dir.path("backup.sqlite"),
            &key(52),
            dir.path("failed-restore.sqlite"),
            &key(53)
        )
        .is_err()
    );
    let c = open_encrypted(dir.path("failed-restore.sqlite"), &key(53)).unwrap();
    assert_eq!(
        c.connection()
            .pragma_query_value(None, "application_id", |r| r.get::<_, i64>(0))
            .unwrap(),
        RESTORING_APPLICATION_ID
    );
    assert_eq!(
        c.connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    let (restored, report) = restore_agreement_journal(
        dir.path("backup.sqlite"),
        &key(52),
        dir.path("successful-retry.sqlite"),
        &key(54),
    )
    .unwrap();
    assert!(report.recovery_required);
    assert_eq!(restored.outstanding_debit("account-a").unwrap(), "60");
    // The earliest factory-only interrupted file must also never initialize via open.
    drop(create_encrypted(dir.path("interrupted-empty.sqlite"), &key(55)).unwrap());
    assert!(matches!(
        Store::open_encrypted(dir.path("interrupted-empty.sqlite"), &key(55)),
        Err(StoreError::StorageSecurity(
            wholepact_storage_security::StorageSecurityError::UninitializedDatabase
        ))
    ));
}

#[test]
fn existing_destinations_and_oversized_values_are_never_overwritten_or_truncated() {
    let dir = TestDirectory::new();
    let (source, _) = populated(&dir);
    source
        .backup_agreement_journal(dir.path("backup.sqlite"), &key(61))
        .unwrap();
    let bytes = fs::read(dir.path("backup.sqlite")).unwrap();
    assert!(
        source
            .backup_agreement_journal(dir.path("backup.sqlite"), &key(61))
            .is_err()
    );
    assert_eq!(fs::read(dir.path("backup.sqlite")).unwrap(), bytes);
    assert!(
        restore_agreement_journal(
            dir.path("backup.sqlite"),
            &key(61),
            dir.path("source.sqlite"),
            &key(10)
        )
        .is_err()
    );
    assert_eq!(source.outstanding_debit("account-a").unwrap(), "60");
    source
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE records SET payload=?1",
            ["x".repeat(MAX_CELL_BYTES + 1)],
        )
        .unwrap();
    assert!(
        source
            .backup_agreement_journal(dir.path("oversized.sqlite"), &key(62))
            .is_err()
    );
    assert!(!dir.path("oversized.sqlite").exists());
}

#[path = "common_context_v3_migration.rs"]
mod common_context_v3_migration;
