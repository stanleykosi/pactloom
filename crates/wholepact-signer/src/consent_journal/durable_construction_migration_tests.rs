//! Inert schema/retention qualification. No native decision, provider, wallet,
//! signing key or spending authority is constructed by these fixtures.
use super::*;
use rusqlite::{params, types::Value};

const ACCOUNT: &str = "synthetic-durable-migration";

fn source(sql: &str, version: i64, account: &str) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(sql).unwrap();
    c.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", version).unwrap();
    c.execute("INSERT INTO signer_account VALUES(1,?1,7,1)", [account])
        .unwrap();
    c
}
fn rows(c: &Connection, schema: &str) -> Vec<(String, Vec<Vec<Value>>)> {
    let reference = Connection::open_in_memory().unwrap();
    reference.execute_batch(schema).unwrap();
    let mut q = reference
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    q.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(|name| {
            let mut q = c
                .prepare(&format!("SELECT rowid,* FROM {name} ORDER BY rowid"))
                .unwrap();
            let width = q.column_count();
            let values = q
                .query_map([], |r| (0..width).map(|i| r.get(i)).collect())
                .unwrap()
                .collect::<std::result::Result<Vec<Vec<Value>>, _>>()
                .unwrap();
            (name, values)
        })
        .collect()
}
fn outbox_empty(c: &Connection) {
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM signer_durable_construction_outbox",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn schema18_every_exact_legacy_schema_gets_only_an_empty_outbox() {
    use std::os::unix::fs::PermissionsExt;
    for (version, sql) in [
        (8, V8_SCHEMA),
        (9, V9_SCHEMA),
        (10, V10_SCHEMA),
        (11, V11_SCHEMA),
        (12, V12_SCHEMA),
        (13, V13_SCHEMA),
        (14, V14_SCHEMA),
        (15, V15_SCHEMA),
        (16, V16_SCHEMA),
        (17, V17_SCHEMA),
        (18, V18_SCHEMA),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
        let path = dir.path().join("original.sqlite");
        let owner = directory
            .signer_journal_source_owner_for_test(&path)
            .unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([179; 32]);
        let encrypted = wholepact_storage_security::create_encrypted(&path, &key).unwrap();
        let c = encrypted.connection();
        c.execute_batch(sql).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", version).unwrap();
        c.execute("INSERT INTO signer_account VALUES(1,?1,7,1)", [ACCOUNT])
            .unwrap();
        c.execute("INSERT INTO signer_sponsor_policy_events VALUES('synthetic-inert-policy',1,'exact original bytes')", []).unwrap();
        let before = rows(c, sql);
        drop(encrypted);
        let files = || -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = std::fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect()
        };
        let bytes = files();
        let result = SignerConsentJournal::open_encrypted(&path, &key, ACCOUNT, &owner);
        if version <= 11 {
            // UNKNOWN pre-genesis format is not proof of ordinary provenance.
            assert!(matches!(result, Err(JournalError::RecoveryRequired)));
            assert!(
                bytes == files(),
                "UNKNOWN schema {version} changed retained files"
            );
            let snapshot =
                wholepact_storage_security::open_encrypted_read_snapshot(&path, &key).unwrap();
            verify_exact_schema(snapshot.connection(), sql).unwrap();
            assert_eq!(before, rows(snapshot.connection(), sql));
            assert_eq!(
                snapshot
                    .connection()
                    .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            continue;
        }
        let journal = result.unwrap();
        let c = journal.connection.lock().unwrap();
        verify_exact_schema(&c, SCHEMA).unwrap();
        assert_eq!(before, rows(&c, sql));
        outbox_empty(&c);
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM signer_durable_payment_admission_intents",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        let account = storage::read_account(&c).unwrap();
        assert_eq!(account.writer_epoch, 7);
        assert!(account.recovery_required);
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }
}

#[test]
fn schema18_interruption_wrong_account_and_schema_drift_do_not_mutate_v17() {
    let mut c = source(V17_SCHEMA, 17, ACCOUNT);
    c.execute("INSERT INTO signer_common_context_reentry_v1 VALUES('original','reentered',?1,'digest','exact old unparsed V3 lineage')", [ACCOUNT]).unwrap();
    let before = rows(&c, V17_SCHEMA);
    assert!(matches!(
        migrate_v17(&mut c, "wrong-account"),
        Err(JournalError::InvalidBinding)
    ));
    assert!(matches!(
        migrate_v17_inner(&mut c, ACCOUNT, true),
        Err(JournalError::Database)
    ));
    verify_exact_schema(&c, V17_SCHEMA).unwrap();
    assert_eq!(before, rows(&c, V17_SCHEMA));
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        17
    );
    for extra in [
        "CREATE TABLE extra(x TEXT)",
        "CREATE VIEW extra AS SELECT account_id FROM signer_account",
        "CREATE INDEX extra ON signer_account(account_id)",
        "CREATE TRIGGER extra AFTER INSERT ON signer_account BEGIN SELECT 1; END",
    ] {
        let mut drift = source(V17_SCHEMA, 17, ACCOUNT);
        drift.execute_batch(extra).unwrap();
        let before = rows(&drift, V17_SCHEMA);
        assert!(matches!(
            migrate_v17(&mut drift, ACCOUNT),
            Err(JournalError::UnsupportedSchema)
        ));
        assert_eq!(before, rows(&drift, V17_SCHEMA));
        assert_eq!(
            drift
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            17
        );
    }
    for version in [0, 7, 16, 18, 99] {
        let mut wrong = source(V17_SCHEMA, version, ACCOUNT);
        assert!(matches!(
            migrate_v17(&mut wrong, ACCOUNT),
            Err(JournalError::UnsupportedSchema)
        ));
        verify_exact_schema(&wrong, V17_SCHEMA).unwrap();
    }
    c.pragma_update(None, "application_id", 0).unwrap();
    assert!(matches!(
        migrate_v17(&mut c, ACCOUNT),
        Err(JournalError::UnsupportedSchema)
    ));
    assert_eq!(before, rows(&c, V17_SCHEMA));
}

// Signed V3 approval verification is deliberately unavailable in the default
// signer profile. This feature forwards the genuine authority verifier.
#[cfg(feature = "pending-birth-owner-signing")]
#[test]
fn schema18_old_v3_typed_history_is_readable_without_rewriting_original_bytes() {
    let (inventory, evidence) =
        crate::consent_journal::common_context_audit_tests::fixture::fixture();
    let account = &evidence.request.account_id;
    let mut c = source(V17_SCHEMA, 17, account);
    for row in &inventory.rows {
        c.execute(
            "INSERT INTO signer_common_context_audit_v3 VALUES(?1,?2,?3,?4,?5)",
            params![
                row.invocation_digest().unwrap(),
                row.phase(),
                row.account_id(),
                row.digest().unwrap(),
                encode(row).unwrap().as_str(),
            ],
        )
        .unwrap();
    }
    let before = rows(&c, V17_SCHEMA);
    let original =
        serde_json::to_vec(&construction_audit_v3::read_all(&c, account).unwrap()).unwrap();
    migrate_v17(&mut c, account).unwrap();
    assert_eq!(before, rows(&c, V17_SCHEMA));
    storage::verify_schema(&c).unwrap();
    assert_eq!(
        original,
        serde_json::to_vec(&construction_audit_v3::read_all(&c, account).unwrap()).unwrap()
    );
    assert!(storage::read_account(&c).unwrap().recovery_required);
    outbox_empty(&c);
}

#[cfg(not(feature = "pending-birth-owner-signing"))]
#[test]
fn schema18_default_refuses_unverifiable_v3_history_without_rewriting() {
    // Exercise a fallible read of the exact original signed fixture, rather
    // than treating the supported-profile fixture constructor's panic as
    // refusal evidence. This is a read-only verifier-availability test, not
    // typed migration coverage; the schema/rollback tests remain independent.
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/common-context-authority-audit.synthetic.json"
    ))
    .expect("fixed synthetic JSON fixture");
    for key in ["complete_history", "pre_reserve_history"] {
        let history: wholepact_authority::ConstructionHistoryV2 =
            serde_json::from_value(raw[key].clone()).expect("original V3 history shape");
        let before = serde_json::to_vec(&history).unwrap();
        assert!(matches!(
            history.validate(),
            Err(wholepact_authority::AuthorityError::ConstructionHistoryUnsupported)
        ));
        assert_eq!(before, serde_json::to_vec(&history).unwrap());
    }
}

#[test]
fn schema18_outbox_is_immutable_foreign_key_bound_and_capacity_accounted() {
    let c = source(SCHEMA, SCHEMA_VERSION, ACCOUNT);
    c.pragma_update(None, "foreign_keys", true).unwrap();
    assert!(c.execute("INSERT INTO signer_durable_construction_outbox VALUES('orphan','digest','missing','missing','unparsed')", []).is_err());
    c.execute("INSERT INTO signer_enrollments VALUES('enrollment',?1,'agreement','participant','unparsed')", [ACCOUNT]).unwrap();
    c.execute("INSERT INTO signer_accepted_manifests VALUES('manifest','enrollment','proposal','proposal-digest','unparsed')", []).unwrap();
    let before = storage::capacity_estimate(&c).unwrap();
    c.execute("INSERT INTO signer_durable_construction_outbox VALUES('operation','digest','enrollment','manifest','inert retained disclosure')", []).unwrap();
    let after = storage::capacity_estimate(&c).unwrap();
    assert_eq!(after.0, before.0 + 1);
    assert!(after.1 > before.1 + 2048);
    for sql in [
        "UPDATE signer_durable_construction_outbox SET payload='changed'",
        "DELETE FROM signer_durable_construction_outbox",
        "INSERT OR REPLACE INTO signer_durable_construction_outbox VALUES('operation','other','enrollment','manifest','changed')",
        "INSERT OR REPLACE INTO signer_durable_construction_outbox VALUES('other','digest','enrollment','manifest','changed')",
    ] {
        assert!(c.execute(sql, []).is_err());
    }
    assert_eq!(after, storage::capacity_estimate(&c).unwrap());
}

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[test]
fn schema18_backup_keeps_v17_template_frozen_and_distinct() {
    assert_eq!(
        recovery_template(17).unwrap().create_sql.as_bytes(),
        V17_SCHEMA.as_bytes()
    );
    assert_eq!(recovery_template(17).unwrap().schema_version, 17);
    assert_eq!(
        recovery_template(18).unwrap().create_sql.as_bytes(),
        V18_SCHEMA.as_bytes()
    );
    assert_eq!(recovery_template(18).unwrap().schema_version, 18);
    assert_eq!(
        recovery_template(19).unwrap().create_sql.as_bytes(),
        SCHEMA.as_bytes()
    );
    assert_eq!(SignerConsentBundleAdapter::template().schema_version, 19);
    assert_eq!(
        SignerConsentBundleAdapter::template().create_sql.as_bytes(),
        SCHEMA.as_bytes()
    );
    assert!(SCHEMA.as_bytes().starts_with(V17_SCHEMA.as_bytes()));
    assert!(SCHEMA.as_bytes().starts_with(V18_SCHEMA.as_bytes()));
    assert!(!V17_SCHEMA.contains("signer_durable_construction_outbox"));
    assert!(V18_SCHEMA.contains("signer_durable_construction_outbox"));
    assert!(!V18_SCHEMA.contains("signer_durable_payment_admission_intents"));
    assert!(SCHEMA.contains("signer_durable_payment_admission_intents"));
    assert_ne!(V18_SCHEMA.as_bytes(), SCHEMA.as_bytes());
}

#[cfg(all(
    feature = "pending-birth-owner-signing",
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[test]
fn schema18_sealed_v17_v3_backup_stays_readable_without_activating_or_mutating_source() {
    use std::{os::unix::fs::PermissionsExt, sync::Mutex};
    use wholepact_storage_security::{bundle::*, DatabaseKey};

    // This test-only adapter represents an already-enrolled historical schema.
    // It has no issuer, vault or signer-journal factory and exposes no connection
    // outside the exact backup permit's checked callback.
    struct HistoricalAdapter(Mutex<Connection>);
    impl JournalAdapter for HistoricalAdapter {
        fn template(&self) -> &'static JournalTemplate {
            recovery_template(17).unwrap()
        }
        fn read_locked(
            &self,
            permit: &BackupReadPermit<'_>,
            visitor: &mut dyn FnMut(&Connection) -> std::result::Result<(), BundleError>,
        ) -> std::result::Result<(), BundleError> {
            permit.check(self)?;
            let c = self.0.lock().unwrap();
            verify_exact_schema(&c, V17_SCHEMA).map_err(|_| BundleError::Integrity)?;
            visitor(&c)
        }
    }

    let (inventory, evidence) =
        crate::consent_journal::common_context_audit_tests::fixture::fixture();
    let account = &evidence.request.account_id;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
    let original_path = dir.path().join("synthetic-v17-original.sqlite");
    let original_key = DatabaseKey::from_bytes([0x71; 32]);
    let c = wholepact_storage_security::create_encrypted(&original_path, &original_key)
        .unwrap()
        .into_connection();
    c.execute_batch(V17_SCHEMA).unwrap();
    c.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", 17).unwrap();
    c.execute("INSERT INTO signer_account VALUES(1,?1,7,0)", [account])
        .unwrap();
    for row in &inventory.rows {
        c.execute(
            "INSERT INTO signer_common_context_audit_v3 VALUES(?1,?2,?3,?4,?5)",
            params![
                row.invocation_digest().unwrap(),
                row.phase(),
                row.account_id(),
                row.digest().unwrap(),
                encode(row).unwrap().as_str(),
            ],
        )
        .unwrap();
    }
    let adapter = HistoricalAdapter(Mutex::new(c));
    let archive = dir.path().join("synthetic-v17-archive.sqlite");
    let restored = dir.path().join("synthetic-v17-quarantined.sqlite");
    let archive_key = DatabaseKey::from_bytes([0x72; 32]);
    let restored_key = DatabaseKey::from_bytes([0x73; 32]);
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage: crate::account::backup::coverage(false),
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    let report = restore(RestoreRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        archive: &archive,
        key: &archive_key,
        targets: &[RestoreTarget {
            component_id: "signer-authority",
            template: recovery_template(17).unwrap(),
            destination: &restored,
            key: &restored_key,
        }],
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    assert!(SignerConsentJournal::open_encrypted(
        &restored,
        &restored_key,
        account,
        &private_directory
            .signer_journal_source_owner_for_test(&restored)
            .unwrap()
    )
    .is_err());
    let sealed = recovery::VerifiedSignerRecoverySource::open(
        history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "signer-authority",
            restored_component: &restored,
            restored_key: &restored_key,
        },
        recovery_template(17).unwrap(),
    )
    .unwrap();
    assert_eq!(sealed.provenance().schema_version, 17);
    assert!(matches!(
        offline_history::require_legacy_recovery_source(&sealed),
        Err(JournalError::ConstructionHistoryUnsupported)
    ));
    let table = sealed
        .tables()
        .iter()
        .find(|t| t.name() == "signer_common_context_audit_v3")
        .unwrap();
    assert_eq!(table.rows().len(), inventory.rows.len());
    let original_before = std::fs::read(&original_path).unwrap();
    let archive_before = std::fs::read(&archive).unwrap();
    let restored_before = std::fs::read(&restored).unwrap();
    let read = QuarantinedJournalRead::from_verified(sealed, account).unwrap();
    assert_eq!(read.account_id(), account);
    assert_eq!(read.writer_epoch(), 7);
    assert!(!read.checkpoint_id().is_empty());
    assert_eq!(std::fs::read(&original_path).unwrap(), original_before);
    assert_eq!(std::fs::read(&archive).unwrap(), archive_before);
    assert_eq!(std::fs::read(&restored).unwrap(), restored_before);
    let c = adapter.0.lock().unwrap();
    verify_exact_schema(&c, V17_SCHEMA).unwrap();
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        17
    );
    assert!(!storage::read_account(&c).unwrap().recovery_required);
    assert_eq!(
        serde_json::to_vec(&construction_audit_v3::read_all(&c, account).unwrap()).unwrap(),
        serde_json::to_vec(&inventory).unwrap()
    );
}
