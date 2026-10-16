use super::*;
use crate::bundle::recovery::{
    evidence,
    wallet::tests::{fixture, fixture_for, WALLET},
    RecoveryCell,
};
use std::os::unix::fs::PermissionsExt;

// Synthetic storage-only fixtures. No proof, signature, wallet secret, socket,
// listener, financial effect or assertion of native publication is involved.
static COORDINATION: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 3,
    create_sql: WALLET.create_sql,
};
const OVERLAY: &str = "CREATE TABLE recovery_fences(id INTEGER PRIMARY KEY, original_count INTEGER NOT NULL, state TEXT NOT NULL CHECK(state='uncertain'));
    CREATE TRIGGER immutable_recovery_fence_update BEFORE UPDATE ON recovery_fences BEGIN SELECT RAISE(ABORT,'immutable'); END;
    CREATE TRIGGER immutable_recovery_fence_delete BEFORE DELETE ON recovery_fences BEGIN SELECT RAISE(ABORT,'immutable'); END;";
static SUCCESSOR: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 4,
    create_sql: "CREATE TABLE parent(id INTEGER PRIMARY KEY AUTOINCREMENT,label TEXT NOT NULL);
            CREATE TABLE child(parent_id INTEGER PRIMARY KEY REFERENCES parent(id),payload BLOB NOT NULL) WITHOUT ROWID;
            CREATE TABLE audit(id INTEGER PRIMARY KEY,parent_id INTEGER NOT NULL REFERENCES parent(id));
            CREATE TRIGGER parent_audit AFTER INSERT ON parent BEGIN INSERT INTO audit(parent_id) VALUES(NEW.id); END;
            CREATE TABLE arbitrary(integer_cell,real_cell,text_cell,blob_cell,null_cell);
            CREATE TABLE metadata(singleton INTEGER PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO metadata VALUES(1,'template-initialization');
CREATE TABLE recovery_fences(id INTEGER PRIMARY KEY, original_count INTEGER NOT NULL, state TEXT NOT NULL CHECK(state='uncertain'));
    CREATE TRIGGER immutable_recovery_fence_update BEFORE UPDATE ON recovery_fences BEGIN SELECT RAISE(ABORT,'immutable'); END;
    CREATE TRIGGER immutable_recovery_fence_delete BEFORE DELETE ON recovery_fences BEGIN SELECT RAISE(ABORT,'immutable'); END;",
};
fn target() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn binding() -> GenerationBinding {
    GenerationBinding::new(&"a1".repeat(32), &"b2".repeat(32)).unwrap()
}
fn overlay(connection: &Connection) -> Result<()> {
    connection.execute_batch(OVERLAY)?;
    connection.execute(
        "INSERT INTO recovery_fences VALUES(1,(SELECT count(*) FROM arbitrary),'uncertain')",
        [],
    )?;
    Ok(())
}

#[test]
fn evidence_preserves_source_tree_and_exact_rows_without_live_open() {
    let source = fixture();
    let output = target();
    let path = output.path().join("history-wallet.sqlite");
    let key = DatabaseKey::from_bytes([211; 32]);
    let binding = binding();
    let before = crate::tests::tree_fingerprint(source.directory.path());
    for _ in 0..2 {
        evidence::reconstruct_wallet_scan_evidence(&source.source, &WALLET, &path, &key, &binding)
            .unwrap();
    }
    let reopened = evidence::open_wallet_scan_evidence(
        &path,
        &key,
        &binding,
        source.source.provenance(),
        &WALLET,
    )
    .unwrap();
    let rows = reopened
        .tables()
        .iter()
        .find(|table| table.name() == "arbitrary")
        .unwrap();
    let row = rows
        .rows()
        .iter()
        .find(|row| row.rowid() == Some(-7))
        .unwrap();
    assert!(matches!(&row.cells()[0], RecoveryCell::Integer(-42)));
    assert!(
        matches!(&row.cells()[1], RecoveryCell::RealBits(value) if *value == 1.25f64.to_bits())
    );
    assert!(matches!(&row.cells()[2], RecoveryCell::Text(value) if value == "synthetic-text"));
    assert!(matches!(&row.cells()[3], RecoveryCell::Blob(value) if value == &[0,255]));
    assert!(matches!(&row.cells()[4], RecoveryCell::Null));
    let sequence = reopened
        .tables()
        .iter()
        .find(|table| table.name() == "sqlite_sequence")
        .unwrap();
    assert_eq!(sequence.rows()[0].rowid(), Some(22));
    assert!(matches!(
        sequence.rows()[0].cells()[1],
        RecoveryCell::Integer(400)
    ));
    let audit = reopened
        .tables()
        .iter()
        .find(|table| table.name() == "audit")
        .unwrap();
    assert_eq!(audit.rows().len(), 1);
    assert!(matches!(
        crate::open_encrypted(&path, &key),
        Err(StorageSecurityError::RecoveredGeneration)
    ));
    assert!(matches!(
        crate::open_encrypted_read_snapshot(&path, &key),
        Err(StorageSecurityError::RecoveredGeneration)
    ));
    assert_eq!(
        before,
        crate::tests::tree_fingerprint(source.directory.path())
    );
}

#[test]
fn evidence_rejects_wrong_generation_path_kind_and_changed_originals() {
    let source = fixture();
    let output = target();
    let key = DatabaseKey::from_bytes([212; 32]);
    let binding = binding();
    let before = crate::tests::tree_fingerprint(source.directory.path());
    assert!(evidence::reconstruct_inbox_evidence(
        &source.source,
        &WALLET,
        output.path().join("wrong-kind"),
        &key,
        &binding
    )
    .is_err());
    assert!(!output.path().join("wrong-kind").exists());
    let path = output.path().join("history.sqlite");
    evidence::reconstruct_wallet_scan_evidence(&source.source, &WALLET, &path, &key, &binding)
        .unwrap();
    let wrong_binding =
        GenerationBinding::new(&"c3".repeat(32), binding.inventory_digest()).unwrap();
    assert!(evidence::open_wallet_scan_evidence(
        &path,
        &key,
        &wrong_binding,
        source.source.provenance(),
        &WALLET
    )
    .is_err());
    assert!(evidence::open_wallet_scan_evidence(
        &path,
        &DatabaseKey::from_bytes([213; 32]),
        &binding,
        source.source.provenance(),
        &WALLET
    )
    .is_err());
    let moved = output.path().join("moved.sqlite");
    std::fs::copy(&path, &moved).unwrap();
    assert!(evidence::open_wallet_scan_evidence(
        &moved,
        &key,
        &binding,
        source.source.provenance(),
        &WALLET
    )
    .is_err());
    for (index, sql) in [
        "UPDATE arbitrary SET rowid=55 WHERE rowid=-7",
        "UPDATE arbitrary SET blob_cell=x'11' WHERE rowid=-7",
        "DELETE FROM arbitrary WHERE rowid=-7",
        "INSERT INTO arbitrary(rowid) VALUES(999)",
        "CREATE TABLE unrecognized_schema(id INTEGER)",
    ]
    .into_iter()
    .enumerate()
    {
        let mutated = output.path().join(format!("mutated-{index}.sqlite"));
        evidence::reconstruct_wallet_scan_evidence(
            &source.source,
            &WALLET,
            &mutated,
            &key,
            &binding,
        )
        .unwrap();
        let connection = crate::keyed_connection(&mutated, &key).unwrap();
        connection.execute_batch(sql).unwrap();
        crate::checkpoint_and_sync(&connection, &mutated).unwrap();
        drop(connection);
        assert!(evidence::open_wallet_scan_evidence(
            &mutated,
            &key,
            &binding,
            source.source.provenance(),
            &WALLET
        )
        .is_err());
        assert!(evidence::reconstruct_wallet_scan_evidence(
            &source.source,
            &WALLET,
            &mutated,
            &key,
            &binding
        )
        .is_err());
    }
    assert!(evidence::reconstruct_wallet_scan_evidence(
        &source.source,
        &WALLET,
        &source.restored,
        &source.restored_key,
        &binding
    )
    .is_err());
    assert_eq!(
        before,
        crate::tests::tree_fingerprint(source.directory.path())
    );
}

#[test]
fn coordination_generation_requires_complete_marker_and_retries_without_overlay_replay() {
    let source = fixture_for(&COORDINATION);
    let output = target();
    let path = output.path().join("coordination.sqlite");
    let key = DatabaseKey::from_bytes([214; 32]);
    let binding = binding();
    let before = crate::tests::tree_fingerprint(source.directory.path());
    initialize_coordination_generation(
        &source.source,
        &COORDINATION,
        &SUCCESSOR,
        &binding,
        &path,
        &key,
        overlay,
    )
    .unwrap();
    initialize_coordination_generation(
        &source.source,
        &COORDINATION,
        &SUCCESSOR,
        &binding,
        &path,
        &key,
        |_| panic!("completed retry replayed overlay"),
    )
    .unwrap();
    assert!(matches!(
        crate::open_encrypted(&path, &key),
        Err(StorageSecurityError::RecoveredGeneration)
    ));
    let live = open_recovered_generation(
        &path,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .unwrap();
    let count: i64 = live
        .connection()
        .query_row("SELECT original_count FROM recovery_fences", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 2);
    assert!(live
        .connection()
        .execute(
            "UPDATE wholepact_recovered_generation SET binding=x'00'",
            []
        )
        .is_err());
    assert!(live
        .connection()
        .execute("DELETE FROM wholepact_recovered_generation", [])
        .is_err());
    // A later ordinary live-data mutation does not alter original provenance.
    live.connection()
        .execute(
            "INSERT INTO arbitrary(rowid,integer_cell) VALUES(900,1)",
            [],
        )
        .unwrap();
    drop(live);
    open_recovered_generation(
        &path,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .unwrap();
    assert_eq!(
        before,
        crate::tests::tree_fingerprint(source.directory.path())
    );
}

#[test]
fn partial_generation_and_erased_marker_never_enter_ordinary_factories() {
    let source = fixture_for(&COORDINATION);
    let output = target();
    let key = DatabaseKey::from_bytes([215; 32]);
    let binding = binding();
    let partial = output.path().join("partial.sqlite");
    assert!(initialize_coordination_generation(
        &source.source,
        &COORDINATION,
        &SUCCESSOR,
        &binding,
        &partial,
        &key,
        |_| Err(BundleError::Permission)
    )
    .is_err());
    assert!(matches!(
        crate::open_encrypted(&partial, &key),
        Err(StorageSecurityError::RecoveredGeneration)
    ));
    assert!(open_recovered_generation(
        &partial,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR
    )
    .is_err());
    initialize_coordination_generation(
        &source.source,
        &COORDINATION,
        &SUCCESSOR,
        &binding,
        &partial,
        &key,
        overlay,
    )
    .unwrap();
    let live = open_recovered_generation(
        &partial,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .unwrap();
    live.connection()
        .execute_batch("DROP TABLE wholepact_recovered_generation")
        .unwrap();
    drop(live);
    assert!(matches!(
        crate::open_encrypted(&partial, &key),
        Err(StorageSecurityError::RecoveredGeneration)
    ));
    assert!(open_recovered_generation(
        &partial,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR
    )
    .is_err());
    // Changing only application_id is equally insufficient while a marker exists.
    let other = output.path().join("changed-id.sqlite");
    initialize_coordination_generation(
        &source.source,
        &COORDINATION,
        &SUCCESSOR,
        &binding,
        &other,
        &key,
        overlay,
    )
    .unwrap();
    let connection = crate::keyed_connection(&other, &key).unwrap();
    connection.pragma_update(None, "application_id", 0).unwrap();
    drop(connection);
    assert!(matches!(
        crate::open_encrypted(&other, &key),
        Err(StorageSecurityError::RecoveredGeneration)
    ));
}

fn copy_database_wal(source: &Path, destination: &Path) {
    for suffix in ["", "-wal"] {
        let from = std::path::PathBuf::from(format!("{}{suffix}", source.display()));
        let to = std::path::PathBuf::from(format!("{}{suffix}", destination.display()));
        std::fs::copy(from, to).unwrap();
    }
    // A copied SHM is never a trusted durable index. The immutable reader must
    // validate its private-file shape while rebuilding only its temporary copy.
    let shm = std::path::PathBuf::from(format!("{}-shm", destination.display()));
    std::fs::write(&shm, [0xa5; 32768]).unwrap();
    std::fs::set_permissions(shm, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn generation_read_snapshot_preserves_wal_and_relocation_never_opens_runtime() {
    let source = fixture_for(&COORDINATION);
    let original = target();
    let original_path = original.path().join("coordination.sqlite");
    let key = DatabaseKey::from_bytes([216; 32]);
    let binding = binding();
    initialize_coordination_generation(
        &source.source,
        &COORDINATION,
        &SUCCESSOR,
        &binding,
        &original_path,
        &key,
        overlay,
    )
    .unwrap();
    let live = crate::keyed_connection(&original_path, &key).unwrap();
    live.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    live.execute(
        "INSERT INTO arbitrary(rowid,integer_cell) VALUES(901,12345)",
        [],
    )
    .unwrap();
    let before = crate::tests::tree_fingerprint(original.path());
    let read = open_recovered_generation_snapshot(
        &original_path,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .unwrap();
    assert_eq!(
        read.connection()
            .query_row(
                "SELECT integer_cell FROM arbitrary WHERE rowid=901",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
        12345
    );
    assert!(read
        .connection()
        .execute("DELETE FROM arbitrary", [])
        .is_err());
    drop(read);
    assert!(
        before == crate::tests::tree_fingerprint(original.path()),
        "original-path immutable read changed source tree"
    );

    let restored = target();
    let restored_path = restored.path().join("archived-coordination.sqlite");
    copy_database_wal(&original_path, &restored_path);
    drop(live);
    original.close().unwrap();
    assert!(!original_path.exists());
    let before = crate::tests::tree_fingerprint(restored.path());
    for _ in 0..2 {
        let read = open_archived_generation_snapshot(
            &restored_path,
            &original_path,
            &key,
            &binding,
            source.source.provenance(),
            &SUCCESSOR,
        )
        .unwrap();
        assert_eq!(read.generation(), &binding);
        assert_eq!(read.provenance(), source.source.provenance());
        assert_eq!(
            read.connection()
                .query_row(
                    "SELECT integer_cell FROM arbitrary WHERE rowid=901",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap(),
            12345
        );
    }
    assert!(
        before == crate::tests::tree_fingerprint(restored.path()),
        "archived immutable reads changed source tree"
    );
    assert!(open_recovered_generation_snapshot(
        &restored_path,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .is_err());
    assert!(
        before == crate::tests::tree_fingerprint(restored.path()),
        "rejected original-path immutable read changed source tree"
    );
    assert!(open_recovered_generation(
        &restored_path,
        &key,
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .is_err());
    assert!(
        before == crate::tests::tree_fingerprint(restored.path()),
        "rejected dedicated runtime open changed source tree"
    );
    for wrong_origin in [
        original_path.with_file_name("other.sqlite"),
        std::path::PathBuf::from("relative.sqlite"),
        std::path::PathBuf::from("/tmp/../missing.sqlite"),
    ] {
        assert!(open_archived_generation_snapshot(
            &restored_path,
            &wrong_origin,
            &key,
            &binding,
            source.source.provenance(),
            &SUCCESSOR,
        )
        .is_err());
    }
    assert!(open_archived_generation_snapshot(
        &restored_path,
        &original_path,
        &DatabaseKey::from_bytes([217; 32]),
        &binding,
        source.source.provenance(),
        &SUCCESSOR,
    )
    .is_err());
    assert!(
        before == crate::tests::tree_fingerprint(restored.path()),
        "rejected archived-origin or wrong-key immutable read changed source tree"
    );
    assert!(crate::open_encrypted_quiescent(&restored_path, &key).is_err());
    assert!(
        before == crate::tests::tree_fingerprint(restored.path()),
        "rejected quiescent runtime open changed source tree"
    );
}

#[test]
fn relocated_immutable_evidence_requires_exact_origin_and_every_original_row() {
    let source = fixture();
    let original = target();
    let original_path = original.path().join("history-wallet.sqlite");
    let restored = target();
    let restored_path = restored.path().join("relocated-wallet.sqlite");
    let key = DatabaseKey::from_bytes([218; 32]);
    let binding = binding();
    evidence::reconstruct_wallet_scan_evidence(
        &source.source,
        &WALLET,
        &original_path,
        &key,
        &binding,
    )
    .unwrap();
    std::fs::copy(&original_path, &restored_path).unwrap();
    original.close().unwrap();
    let before = crate::tests::tree_fingerprint(restored.path());
    let read = evidence::open_archived_wallet_scan_evidence(
        &restored_path,
        &original_path,
        &key,
        &binding,
        source.source.provenance(),
        &WALLET,
    )
    .unwrap();
    assert_eq!(read.provenance(), source.source.provenance());
    assert!(read
        .tables()
        .iter()
        .find(|t| t.name() == "arbitrary")
        .unwrap()
        .rows()
        .iter()
        .any(|r| r.rowid() == Some(-7)));
    assert!(evidence::open_wallet_scan_evidence(
        &restored_path,
        &key,
        &binding,
        source.source.provenance(),
        &WALLET,
    )
    .is_err());
    assert!(evidence::open_archived_wallet_scan_evidence(
        &restored_path,
        &restored_path,
        &key,
        &binding,
        source.source.provenance(),
        &WALLET,
    )
    .is_err());
    assert!(crate::open_encrypted(&restored_path, &key).is_err());
    assert!(
        before == crate::tests::tree_fingerprint(restored.path()),
        "immutable evidence read changed source tree"
    );
    let corrupt = crate::keyed_connection(&restored_path, &key).unwrap();
    corrupt
        .execute("UPDATE arbitrary SET blob_cell=x'ff' WHERE rowid=-7", [])
        .unwrap();
    crate::checkpoint_and_sync(&corrupt, &restored_path).unwrap();
    drop(corrupt);
    assert!(evidence::open_archived_wallet_scan_evidence(
        &restored_path,
        &original_path,
        &key,
        &binding,
        source.source.provenance(),
        &WALLET,
    )
    .is_err());
}

#[test]
fn ordinary_template_snapshot_is_source_preserving_and_rejects_wrong_identity() {
    let writer_directory = target();
    let writer_path = writer_directory.path().join("writer.sqlite");
    let key = DatabaseKey::from_bytes([219; 32]);
    let writer = crate::create_encrypted(&writer_path, &key).unwrap();
    writer
        .connection()
        .execute_batch(COORDINATION.create_sql)
        .unwrap();
    writer
        .connection()
        .pragma_update(None, "application_id", COORDINATION.application_id)
        .unwrap();
    writer
        .connection()
        .pragma_update(None, "user_version", COORDINATION.schema_version)
        .unwrap();
    crate::checkpoint_and_sync(writer.connection(), &writer_path).unwrap();
    writer
        .connection()
        .execute_batch("PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    writer
        .connection()
        .execute(
            "INSERT INTO arbitrary(rowid,integer_cell) VALUES(902,54321)",
            [],
        )
        .unwrap();
    let frozen = target();
    let path = frozen.path().join("source.sqlite");
    copy_database_wal(&writer_path, &path);
    let before = crate::tests::tree_fingerprint(frozen.path());
    let read = crate::bundle::open_journal_read_snapshot(&path, &key, &COORDINATION).unwrap();
    assert_eq!(
        read.connection()
            .query_row(
                "SELECT integer_cell FROM arbitrary WHERE rowid=902",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
        54321
    );
    assert!(read
        .connection()
        .execute("DELETE FROM arbitrary", [])
        .is_err());
    assert!(crate::bundle::open_journal_read_snapshot(&path, &key, &WALLET).is_err());
    assert!(crate::bundle::open_journal_read_snapshot(
        &path,
        &DatabaseKey::from_bytes([220; 32]),
        &COORDINATION
    )
    .is_err());
    assert!(crate::bundle::open_journal_read_snapshot(&path, &key, &SUCCESSOR).is_err());
    drop(read);
    assert!(
        before == crate::tests::tree_fingerprint(frozen.path()),
        "ordinary immutable read changed source tree"
    );
    let quarantine = fixture_for(&COORDINATION);
    assert!(crate::bundle::open_journal_read_snapshot(
        &quarantine.restored,
        &quarantine.restored_key,
        &COORDINATION
    )
    .is_err());
    let changed = crate::keyed_connection(&path, &key).unwrap();
    changed
        .execute_batch("CREATE TABLE unrecognized(value TEXT)")
        .unwrap();
    crate::checkpoint_and_sync(&changed, &path).unwrap();
    drop(changed);
    let before = crate::tests::tree_fingerprint(frozen.path());
    assert!(crate::bundle::open_journal_read_snapshot(&path, &key, &COORDINATION).is_err());
    assert!(
        before == crate::tests::tree_fingerprint(frozen.path()),
        "ordinary immutable read changed source tree"
    );
}

mod history;
