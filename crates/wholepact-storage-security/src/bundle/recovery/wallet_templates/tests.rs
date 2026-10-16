//! Staged, unexecuted synthetic storage fixtures. No wallet import, runtime
//! activation, key-provider call, network request, signature, proof or funds.
use super::*;
use crate::bundle::recovery::{
    RecoveryCell, evidence,
    generation::GenerationBinding,
    wallet::tests::{WALLET, fixture_for},
};
use std::{os::unix::fs::PermissionsExt, sync::OnceLock};

const RECORD_SCHEMA: &str = "CREATE TABLE ext_wholepact_import_records(sequence INTEGER PRIMARY KEY CHECK(sequence IN (0,1)), format_version INTEGER NOT NULL CHECK(format_version=1), record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=262144));";
fn recorded() -> &'static JournalTemplate {
    static TEMPLATE: OnceLock<JournalTemplate> = OnceLock::new();
    TEMPLATE.get_or_init(|| JournalTemplate {
        kind: WALLET.kind,
        application_id: WALLET.application_id,
        schema_version: WALLET.schema_version,
        create_sql: Box::leak(format!("{}\n{}", WALLET.create_sql, RECORD_SCHEMA).into_boxed_str()),
    })
}
fn templates() -> Templates {
    [&WALLET, recorded()]
}
fn private_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn ordinary(template: &'static JournalTemplate) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(template.create_sql).unwrap();
    connection
        .pragma_update(None, "application_id", template.application_id)
        .unwrap();
    connection
        .pragma_update(None, "user_version", template.schema_version)
        .unwrap();
    connection
}
fn record_fixture(record_count: usize) -> &'static JournalTemplate {
    let mut sql = recorded().create_sql.to_string();
    for sequence in 0..record_count {
        // SQL-valid, deliberately semantically malformed record bytes. Layout
        // selection and historical reconstruction must never repair these.
        sql.push_str(&format!(
            "INSERT INTO ext_wholepact_import_records VALUES({sequence},1,x'00ff7b');"
        ));
    }
    Box::leak(Box::new(JournalTemplate {
        kind: WALLET.kind,
        application_id: WALLET.application_id,
        schema_version: WALLET.schema_version,
        create_sql: Box::leak(sql.into_boxed_str()),
    }))
}
#[test]
fn same_application_and_version_choose_only_complete_layout() {
    assert_eq!(WALLET.schema_version, recorded().schema_version);
    for expected in templates() {
        let connection = ordinary(expected);
        assert!(std::ptr::eq(
            choose_ordinary(&connection, templates()).unwrap(),
            expected
        ));
        assert!(matches!(
            choose_ordinary(&connection, [expected, expected]),
            Err(BundleError::Unsupported)
        ));
    }
}
#[test]
fn unknown_object_or_version_never_falls_back_to_legacy() {
    let connection = ordinary(recorded());
    connection
        .execute_batch("CREATE TABLE unknown_import_state(value BLOB);")
        .unwrap();
    assert!(matches!(
        choose_ordinary(&connection, templates()),
        Err(BundleError::Unsupported)
    ));
    connection
        .execute_batch("DROP TABLE unknown_import_state;")
        .unwrap();
    connection
        .pragma_update(None, "user_version", WALLET.schema_version + 1)
        .unwrap();
    assert!(matches!(
        choose_ordinary(&connection, templates()),
        Err(BundleError::Unsupported)
    ));
}
#[test]
fn matching_schema_with_any_missing_or_changed_descriptor_fails() {
    let fixture = fixture_for(recorded());
    let component = fixture
        .source
        .manifest()
        .components
        .iter()
        .find(|c| c.id == "wallet")
        .unwrap();
    assert!(std::ptr::eq(
        choose_component(component, templates()).unwrap(),
        recorded()
    ));
    let mut missing = component.clone();
    missing.tables.pop();
    assert!(matches!(
        choose_component(&missing, templates()),
        Err(BundleError::Integrity)
    ));
    let mut missing_column = component.clone();
    missing_column.tables[0].columns.pop();
    assert!(matches!(
        choose_component(&missing_column, templates()),
        Err(BundleError::Integrity)
    ));
    let mut changed_rowid = component.clone();
    changed_rowid.tables[0].rowid = !changed_rowid.tables[0].rowid;
    assert!(matches!(
        choose_component(&changed_rowid, templates()),
        Err(BundleError::Integrity)
    ));
    let mut changed_order = component.clone();
    changed_order.tables.reverse();
    assert!(matches!(
        choose_component(&changed_order, templates()),
        Err(BundleError::Integrity)
    ));
    let mut extra = component.clone();
    extra.tables.push(component.tables[0].clone());
    assert!(matches!(
        choose_component(&extra, templates()),
        Err(BundleError::Integrity)
    ));
}
#[test]
fn authenticated_bundle_and_sealed_component_select_both_layouts_without_source_changes() {
    for expected in templates() {
        let fixture = fixture_for(expected);
        let before = crate::tests::tree_fingerprint(fixture.directory.path());
        let key = DatabaseKey::from_bytes([203; 32]); // Existing synthetic fixture archive key.
        let selected = for_bundle_component(
            &fixture.directory.path().join("archive.db"),
            &key,
            "wallet",
            templates(),
        )
        .unwrap();
        assert!(std::ptr::eq(selected, expected));
        assert!(std::ptr::eq(
            for_recovery_component(&fixture.source, templates()).unwrap(),
            expected
        ));
        assert_eq!(
            before,
            crate::tests::tree_fingerprint(fixture.directory.path())
        );
    }
}
#[test]
fn ordinary_snapshot_selection_preserves_main_and_sidecars() {
    for expected in templates() {
        let directory = private_dir();
        let path = directory.path().join("ordinary.sqlite");
        let key = DatabaseKey::from_bytes([181; 32]);
        let source = crate::create_encrypted(&path, &key).unwrap();
        source
            .connection()
            .execute_batch(expected.create_sql)
            .unwrap();
        source
            .connection()
            .pragma_update(None, "application_id", expected.application_id)
            .unwrap();
        source
            .connection()
            .pragma_update(None, "user_version", expected.schema_version)
            .unwrap();
        assert!(std::ptr::eq(
            for_backup_source(&source, templates()).unwrap(),
            expected
        ));
        let before = crate::tests::tree_fingerprint(directory.path());
        let snapshot = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
        let selected = for_read_snapshot(&snapshot, templates()).unwrap();
        assert!(std::ptr::eq(selected, expected));
        assert!(!snapshot.connection().is_autocommit());
        // The validated capture itself is retained; no second capture is needed.
        assert!(std::ptr::eq(
            for_read_snapshot(&snapshot, templates()).unwrap(),
            expected
        ));
        drop(snapshot);
        assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
    }
}
#[test]
fn original_and_relocated_evidence_preserve_every_malformed_record_cell() {
    for count in 0..=2 {
        let fixture = fixture_for(record_fixture(count));
        let output = private_dir();
        let path = output.path().join("evidence.sqlite");
        let key = DatabaseKey::from_bytes([182; 32]);
        let binding = GenerationBinding::new(&"a1".repeat(32), &"b2".repeat(32)).unwrap();
        let before = crate::tests::tree_fingerprint(fixture.directory.path());
        let selected = for_recovery_component(&fixture.source, templates()).unwrap();
        evidence::reconstruct_wallet_scan_evidence(
            &fixture.source,
            selected,
            &path,
            &key,
            &binding,
        )
        .unwrap();
        let selected = for_evidence_file(&path, &key, templates()).unwrap();
        let evidence = evidence::open_wallet_scan_evidence(
            &path,
            &key,
            &binding,
            fixture.source.provenance(),
            selected,
        )
        .unwrap();
        let records = evidence
            .tables()
            .iter()
            .find(|table| table.name() == "ext_wholepact_import_records")
            .unwrap();
        assert_eq!(records.rows().len(), count);
        for row in records.rows() {
            assert!(matches!(&row.cells()[2], RecoveryCell::Blob(bytes) if bytes == &[0,255,123]));
        }
        let relocated = private_dir();
        let archived = relocated.path().join("evidence.sqlite");
        std::fs::copy(&path, &archived).unwrap();
        std::fs::set_permissions(&archived, std::fs::Permissions::from_mode(0o600)).unwrap();
        let original_before = crate::tests::tree_fingerprint(output.path());
        let archived_before = crate::tests::tree_fingerprint(relocated.path());
        let selected = for_evidence_file(&archived, &key, templates()).unwrap();
        let archived_evidence = evidence::open_archived_wallet_scan_evidence(
            &archived,
            &path,
            &key,
            &binding,
            fixture.source.provenance(),
            selected,
        )
        .unwrap();
        assert_eq!(archived_evidence.provenance(), evidence.provenance());
        assert!(
            evidence::open_wallet_scan_evidence(
                &archived,
                &key,
                &binding,
                fixture.source.provenance(),
                selected
            )
            .is_err()
        );
        assert!(
            for_evidence_file(&archived, &DatabaseKey::from_bytes([183; 32]), templates()).is_err()
        );
        assert_eq!(
            before,
            crate::tests::tree_fingerprint(fixture.directory.path())
        );
        assert_eq!(
            original_before,
            crate::tests::tree_fingerprint(output.path())
        );
        assert_eq!(
            archived_before,
            crate::tests::tree_fingerprint(relocated.path())
        );
    }
}
#[test]
fn legacy_evidence_still_selects_legacy_without_new_records() {
    let fixture = fixture_for(&WALLET);
    let output = private_dir();
    let path = output.path().join("legacy.sqlite");
    let key = DatabaseKey::from_bytes([184; 32]);
    let binding = GenerationBinding::new(&"c3".repeat(32), &"d4".repeat(32)).unwrap();
    evidence::reconstruct_wallet_scan_evidence(&fixture.source, &WALLET, &path, &key, &binding)
        .unwrap();
    assert!(std::ptr::eq(
        for_evidence_file(&path, &key, templates()).unwrap(),
        &WALLET
    ));
    let reopened = evidence::open_wallet_scan_evidence(
        &path,
        &key,
        &binding,
        fixture.source.provenance(),
        &WALLET,
    )
    .unwrap();
    assert!(
        !reopened
            .tables()
            .iter()
            .any(|table| table.name() == "ext_wholepact_import_records")
    );
}

#[test]
fn selected_schema_never_launders_modified_evidence_rows() {
    let fixture = fixture_for(record_fixture(1));
    let output = private_dir();
    let path = output.path().join("tampered.sqlite");
    let key = DatabaseKey::from_bytes([185; 32]);
    let binding = GenerationBinding::new(&"e5".repeat(32), &"f6".repeat(32)).unwrap();
    evidence::reconstruct_wallet_scan_evidence(&fixture.source, recorded(), &path, &key, &binding)
        .unwrap();
    // Deliberate synthetic corruption through the crate-private fixture path.
    let corrupt = crate::keyed_connection(&path, &key).unwrap();
    corrupt
        .execute(
            "UPDATE ext_wholepact_import_records SET record=x'0102' WHERE sequence=0",
            [],
        )
        .unwrap();
    crate::checkpoint_and_sync(&corrupt, &path).unwrap();
    drop(corrupt);
    let before = crate::tests::tree_fingerprint(output.path());
    let selected = for_evidence_file(&path, &key, templates()).unwrap();
    assert!(
        evidence::open_wallet_scan_evidence(
            &path,
            &key,
            &binding,
            fixture.source.provenance(),
            selected
        )
        .is_err()
    );
    assert_eq!(before, crate::tests::tree_fingerprint(output.path()));
}

#[test]
fn populated_import_history_selects_but_changed_columns_and_rowid_layout_deny() {
    let connection = ordinary(recorded());
    connection
        .execute_batch(
            "INSERT INTO ext_wholepact_import_records VALUES(0,1,x'00ff7b');
         INSERT INTO ext_wholepact_import_records VALUES(1,1,x'010203');",
        )
        .unwrap();
    assert!(std::ptr::eq(
        choose_ordinary(&connection, templates()).unwrap(),
        recorded()
    ));
    connection
        .execute_batch("ALTER TABLE ext_wholepact_import_records ADD COLUMN unknown INTEGER;")
        .unwrap();
    assert!(matches!(
        choose_ordinary(&connection, templates()),
        Err(BundleError::Unsupported)
    ));

    let changed_rowid = ordinary(recorded());
    changed_rowid
        .execute_batch("DROP TABLE ext_wholepact_import_records;")
        .unwrap();
    let without_rowid = RECORD_SCHEMA.trim_end_matches(';').to_string() + " WITHOUT ROWID;";
    changed_rowid.execute_batch(&without_rowid).unwrap();
    changed_rowid
        .execute_batch("INSERT INTO ext_wholepact_import_records VALUES(0,1,x'ff');")
        .unwrap();
    assert!(matches!(
        choose_ordinary(&changed_rowid, templates()),
        Err(BundleError::Unsupported)
    ));
}

#[test]
fn immutable_snapshot_checks_integrity_without_adding_live_backup_scans() {
    let directory = private_dir();
    let path = directory.path().join("foreign-key-invalid.sqlite");
    let key = DatabaseKey::from_bytes([186; 32]);
    let source = crate::create_encrypted(&path, &key).unwrap();
    source
        .connection()
        .execute_batch(recorded().create_sql)
        .unwrap();
    source
        .connection()
        .pragma_update(None, "application_id", recorded().application_id)
        .unwrap();
    source
        .connection()
        .pragma_update(None, "user_version", recorded().schema_version)
        .unwrap();
    // A complete supported schema with deliberately invalid synthetic row data.
    source
        .connection()
        .execute_batch(
            "PRAGMA foreign_keys=OFF; INSERT INTO child VALUES(999,x'01'); PRAGMA foreign_keys=ON;",
        )
        .unwrap();
    // Existing bundle snapshot work remains the live adapter's row-integrity gate.
    assert!(std::ptr::eq(
        for_backup_source(&source, templates()).unwrap(),
        recorded()
    ));
    let before = crate::tests::tree_fingerprint(directory.path());
    let snapshot = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
    assert!(matches!(
        for_read_snapshot(&snapshot, templates()),
        Err(BundleError::Integrity)
    ));
    drop(snapshot);
    assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
}

const ROSTER_RECORD_SCHEMA: &str = "CREATE TABLE ext_wholepact_roster_import_records_v2(sequence INTEGER PRIMARY KEY CHECK(sequence IN (0,1)), format_version INTEGER NOT NULL CHECK(format_version=2), record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=262144));";
fn roster_recorded() -> &'static JournalTemplate {
    static TEMPLATE: OnceLock<JournalTemplate> = OnceLock::new();
    TEMPLATE.get_or_init(|| JournalTemplate {
        kind: WALLET.kind,
        application_id: WALLET.application_id,
        schema_version: WALLET.schema_version,
        create_sql: Box::leak(
            format!("{}\n{}", WALLET.create_sql, ROSTER_RECORD_SCHEMA).into_boxed_str(),
        ),
    })
}
fn roster_templates() -> Templates<3> {
    [&WALLET, recorded(), roster_recorded()]
}
fn roster_record_fixture(count: usize) -> &'static JournalTemplate {
    let mut sql = roster_recorded().create_sql.to_string();
    for sequence in 0..count {
        sql.push_str(&format!(
            "INSERT INTO ext_wholepact_roster_import_records_v2 VALUES({sequence},2,x'00ff7b');"
        ));
    }
    Box::leak(Box::new(JournalTemplate {
        kind: WALLET.kind,
        application_id: WALLET.application_id,
        schema_version: WALLET.schema_version,
        create_sql: Box::leak(sql.into_boxed_str()),
    }))
}
#[test]
fn three_layouts_require_unique_full_schema_and_preserve_two_layout_rejection() {
    for expected in roster_templates() {
        let connection = ordinary(expected);
        assert!(std::ptr::eq(
            choose_ordinary(&connection, roster_templates()).unwrap(),
            expected
        ));
        let duplicate = [expected, expected, &WALLET];
        assert!(choose_ordinary(&connection, duplicate).is_err());
        let none: Templates<0> = [];
        assert!(choose_ordinary(&connection, none).is_err());
        assert!(choose_ordinary(&connection, [expected; 9]).is_err());
    }
    assert!(choose_ordinary(&ordinary(roster_recorded()), templates()).is_err());
    let legacy = ordinary(&WALLET);
    assert!(choose_ordinary(&legacy, [&WALLET, recorded(), recorded()]).is_err());
    let connection = ordinary(roster_recorded());
    connection
        .execute_batch("CREATE TABLE unknown_roster_payload(value BLOB);")
        .unwrap();
    assert!(choose_ordinary(&connection, roster_templates()).is_err());
    let connection = ordinary(roster_recorded());
    connection.execute_batch(RECORD_SCHEMA).unwrap(); // Hybrid V1+V2 is not a compiled template.
    assert!(choose_ordinary(&connection, roster_templates()).is_err());
    let connection = ordinary(roster_recorded());
    connection
        .execute_batch(
            "ALTER TABLE ext_wholepact_roster_import_records_v2 ADD COLUMN unknown BLOB;",
        )
        .unwrap();
    assert!(choose_ordinary(&connection, roster_templates()).is_err());
}

#[test]
fn third_layout_bundle_and_component_retain_full_table_descriptors() {
    let fixture = fixture_for(roster_record_fixture(2));
    let before = crate::tests::tree_fingerprint(fixture.directory.path());
    let key = DatabaseKey::from_bytes([203; 32]);
    assert!(std::ptr::eq(
        for_bundle_component(
            &fixture.directory.path().join("archive.db"),
            &key,
            "wallet",
            roster_templates()
        )
        .unwrap(),
        roster_recorded()
    ));
    assert!(std::ptr::eq(
        for_recovery_component(&fixture.source, roster_templates()).unwrap(),
        roster_recorded()
    ));
    let component = fixture
        .source
        .manifest()
        .components
        .iter()
        .find(|c| c.id == "wallet")
        .unwrap();
    let mut omitted = component.clone();
    omitted
        .tables
        .retain(|t| t.name != "ext_wholepact_roster_import_records_v2");
    assert!(choose_component(&omitted, roster_templates()).is_err());
    let mut changed = component.clone();
    changed
        .tables
        .iter_mut()
        .find(|t| t.name == "ext_wholepact_roster_import_records_v2")
        .unwrap()
        .columns
        .pop();
    assert!(choose_component(&changed, roster_templates()).is_err());
    assert_eq!(
        before,
        crate::tests::tree_fingerprint(fixture.directory.path())
    );
}

#[test]
fn third_layout_immutable_capture_checks_integrity_and_preserves_source_tree() {
    let directory = private_dir();
    let path = directory.path().join("roster.sqlite");
    let key = DatabaseKey::from_bytes([187; 32]);
    let source = crate::create_encrypted(&path, &key).unwrap();
    source
        .connection()
        .execute_batch(roster_record_fixture(2).create_sql)
        .unwrap();
    source
        .connection()
        .pragma_update(None, "application_id", roster_recorded().application_id)
        .unwrap();
    source
        .connection()
        .pragma_update(None, "user_version", roster_recorded().schema_version)
        .unwrap();
    assert!(std::ptr::eq(
        for_backup_source(&source, roster_templates()).unwrap(),
        roster_recorded()
    ));
    let before = crate::tests::tree_fingerprint(directory.path());
    let snapshot = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
    assert!(std::ptr::eq(
        for_read_snapshot(&snapshot, roster_templates()).unwrap(),
        roster_recorded()
    ));
    assert!(for_read_snapshot(&snapshot, templates()).is_err());
    drop(snapshot);
    assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
}

#[test]
fn third_layout_pending_and_malformed_cells_survive_evidence_unchanged() {
    for count in 0..=2 {
        let fixture = fixture_for(roster_record_fixture(count));
        let before = crate::tests::tree_fingerprint(fixture.directory.path());
        let output = private_dir();
        let path = output.path().join("evidence.sqlite");
        let key = DatabaseKey::from_bytes([188; 32]);
        let binding = GenerationBinding::new(&"e7".repeat(32), &"e8".repeat(32)).unwrap();
        evidence::reconstruct_wallet_scan_evidence(
            &fixture.source,
            roster_recorded(),
            &path,
            &key,
            &binding,
        )
        .unwrap();
        let selected = for_evidence_file(&path, &key, roster_templates()).unwrap();
        assert!(std::ptr::eq(selected, roster_recorded()));
        assert!(for_evidence_file(&path, &key, templates()).is_err());
        let data = evidence::open_wallet_scan_evidence(
            &path,
            &key,
            &binding,
            fixture.source.provenance(),
            selected,
        )
        .unwrap();
        let records = data
            .tables()
            .iter()
            .find(|t| t.name() == "ext_wholepact_roster_import_records_v2")
            .unwrap();
        assert_eq!(records.rows().len(), count);
        assert_eq!(records.columns(), ["sequence", "format_version", "record"]);
        for row in records.rows() {
            assert!(matches!(&row.cells()[1], RecoveryCell::Integer(2)));
            assert!(matches!(&row.cells()[2],RecoveryCell::Blob(bytes) if bytes == &[0,255,123]));
        }
        let archived = output.path().join("archived.sqlite");
        std::fs::copy(&path, &archived).unwrap();
        std::fs::set_permissions(&archived, std::fs::Permissions::from_mode(0o600)).unwrap();
        let frozen = crate::tests::tree_fingerprint(output.path());
        let selected = for_evidence_file(&archived, &key, roster_templates()).unwrap();
        let reopened = evidence::open_archived_wallet_scan_evidence(
            &archived,
            &path,
            &key,
            &binding,
            fixture.source.provenance(),
            selected,
        )
        .unwrap();
        assert_eq!(reopened.provenance(), data.provenance());
        assert_eq!(frozen, crate::tests::tree_fingerprint(output.path()));
        assert_eq!(
            before,
            crate::tests::tree_fingerprint(fixture.directory.path())
        );
    }
}
