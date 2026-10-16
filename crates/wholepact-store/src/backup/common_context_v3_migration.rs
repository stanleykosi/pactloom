//! Authenticated synthetic schema-boundary tests. No live keys or native owners.
use super::*;
use crate::manual_enrollment::{
    construction_claim_v2::{
        CONSTRUCTION_CLAIM_V2, append_modeled_construction_root, append_modeled_construction_rows,
    },
    construction_claim_v3::{append_modeled_construction_rows_v3, exact_manual_rows},
};

#[test]
fn common_context_v3_schema_two_migration_keeps_v2_bytes_and_restored_flags() {
    for recovered in [false, true] {
        let dir = TestDirectory::new();
        let path = dir.path("legacy-v2.sqlite");
        let source = Store::create_encrypted(&path, &key(91)).unwrap();
        let root = append_modeled_construction_root(&source);
        let (claim, receipt) = append_modeled_construction_rows(&source, &root, true);
        let exact = exact_manual_rows(&source);
        {
            let connection = source.connection.lock().unwrap();
            if recovered {
                connection.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=1,source_snapshot_digest=?1",["a".repeat(64)]).unwrap();
            }
            connection.pragma_update(None, "user_version", 2).unwrap();
        }
        drop(source);
        let migrated = Store::open_encrypted(&path, &key(91)).unwrap();
        assert_eq!(
            migrated
                .connection
                .lock()
                .unwrap()
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(exact_manual_rows(&migrated), exact);
        assert_eq!(
            migrated.recovery_state().unwrap().recovery_required,
            recovered
        );
        assert!(
            migrated
                .manual_roster_construction_evidence_v2(
                    &claim.principal_id,
                    &claim.construction_key
                )
                .unwrap()
                .unwrap()
                == (claim, receipt)
        );
        let state = migrated.recovery_state().unwrap();
        if recovered {
            assert_eq!(state.restored_at_ms, Some(1));
            assert_eq!(state.source_snapshot_digest, Some("a".repeat(64)));
        }
    }
}

#[test]
fn common_context_v3_schema_downgrade_unknown_and_malformed_history_do_not_migrate() {
    for corruption in [
        "v3-under-v2",
        "unknown-marker",
        "extra-schema-object",
        "malformed-v2",
    ] {
        let dir = TestDirectory::new();
        let path = dir.path("denied-migration.sqlite");
        let source = Store::create_encrypted(&path, &key(92)).unwrap();
        let root = append_modeled_construction_root(&source);
        let (v2, _) = append_modeled_construction_rows(&source, &root, false);
        if corruption == "v3-under-v2" {
            append_modeled_construction_rows_v3(&source, &root, true);
        }
        let expected_marker = if corruption == "unknown-marker" {
            99
        } else {
            2
        };
        {
            let connection = source.connection.lock().unwrap();
            if corruption == "extra-schema-object" {
                connection
                    .execute_batch("CREATE TABLE unsupported_object(value TEXT)")
                    .unwrap();
            }
            if corruption == "malformed-v2" {
                let mut payload = serde_json::to_value(&v2).unwrap();
                payload["unrecognized_history"] = true.into();
                connection
                    .execute(
                        "UPDATE records SET payload=?1 WHERE aggregate_type=?2 AND id=?3",
                        params![
                            serde_json::to_string(&payload).unwrap(),
                            CONSTRUCTION_CLAIM_V2,
                            v2.digest().unwrap()
                        ],
                    )
                    .unwrap();
            }
            connection
                .pragma_update(None, "user_version", expected_marker)
                .unwrap();
            assert!(require_construction_v3_encoding(&connection).is_err());
        }
        let exact = exact_manual_rows(&source);
        drop(source);
        assert!(
            Store::open_encrypted(&path, &key(92)).is_err(),
            "{corruption}"
        );
        let raw = open_encrypted(&path, &key(92)).unwrap();
        let connection = raw.connection();
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            expected_marker
        );
        let retained = connection.prepare("SELECT aggregate_type,id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type LIKE 'generation_manual_%' ORDER BY aggregate_type,id").unwrap()
            .query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u64>(2)?,r.get::<_,String>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(retained, exact);
    }
}

#[test]
fn common_context_v3_legacy_v1_v2_archives_restore_without_rewriting_originals() {
    for version in [1, 2] {
        let originals = TestDirectory::new();
        let destinations = TestDirectory::new();
        let source = Store::create_encrypted(originals.path("source.sqlite"), &key(93)).unwrap();
        let root = append_modeled_construction_root(&source);
        let (claim, receipt) = append_modeled_construction_rows(&source, &root, true);
        let exact = exact_manual_rows(&source);
        let archive_path = originals.path("legacy-archive.sqlite");
        let archive = create_encrypted(&archive_path, &key(94)).unwrap();
        let connection = archive.connection();
        initialize_schema(connection, version).unwrap();
        if version >= 2 {
            connection
                .execute("DELETE FROM store_recovery", [])
                .unwrap();
        }
        copy_tables(&source.connection.lock().unwrap(), connection, version).unwrap();
        let stats = inspect_rows(connection, version).unwrap();
        connection.execute_batch(ARCHIVE_SCHEMA).unwrap();
        connection
            .pragma_update(None, "application_id", ARCHIVE_APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", ARCHIVE_VERSION)
            .unwrap();
        connection.execute("INSERT INTO backup_manifest VALUES(1,?1,?2,1,?3,?4,?5,'coordination_and_authority_only')",
            params![ARCHIVE_VERSION,version,stats.digest,stats.rows,stats.bytes]).unwrap();
        drop(archive);
        drop(source);
        let before = tree_fingerprint(&originals.0);
        let (restored, report) = restore_agreement_journal(
            &archive_path,
            &key(94),
            destinations.path("restored.sqlite"),
            &key(95),
        )
        .unwrap();
        assert!(
            report.migration_applied && report.recovery_required && !report.authorization_allowed
        );
        assert_eq!(report.destination_schema_version, SCHEMA_VERSION as u32);
        assert_eq!(exact_manual_rows(&restored), exact);
        assert!(
            restored
                .manual_roster_construction_evidence_v2(
                    &claim.principal_id,
                    &claim.construction_key
                )
                .unwrap()
                .unwrap()
                == (claim, receipt)
        );
        assert_eq!(tree_fingerprint(&originals.0), before);
    }
}

#[test]
fn encrypted_common_context_v3_archive_refusals_preserve_complete_source_tree() {
    for refusal in [
        "wrong-key",
        "protected-source-path",
        "marker-downgrade",
        "unknown-version",
        "orphan-provenance",
    ] {
        let originals = TestDirectory::new();
        let destinations = TestDirectory::new();
        let source = Store::create_encrypted(originals.path("source.sqlite"), &key(96)).unwrap();
        let root = append_modeled_construction_root(&source);
        append_modeled_construction_rows(&source, &root, false);
        append_modeled_construction_rows_v3(&source, &root, true);
        let archive_path = originals.path("mixed-archive.sqlite");
        source
            .backup_agreement_journal(&archive_path, &key(97))
            .unwrap();
        drop(source);
        let writer = open_encrypted(&archive_path, &key(97)).unwrap();
        match refusal {
            "marker-downgrade" => {
                writer
                    .connection()
                    .execute("UPDATE backup_manifest SET source_schema_version=2", [])
                    .unwrap();
            }
            "unknown-version" => {
                writer
                    .connection()
                    .execute("UPDATE backup_manifest SET source_schema_version=99", [])
                    .unwrap();
            }
            "orphan-provenance" => {
                writer
                    .connection()
                    .execute(
                        "DELETE FROM records WHERE aggregate_type=?1",
                        [crate::manual_enrollment::CONTINUATION_V4],
                    )
                    .unwrap();
            }
            _ => {}
        }
        let before = tree_fingerprint(&originals.0);
        let source_key = if refusal == "wrong-key" {
            key(98)
        } else {
            key(97)
        };
        let target = if refusal == "protected-source-path" {
            archive_path.clone()
        } else {
            destinations.path("denied.sqlite")
        };
        assert!(
            restore_agreement_journal(&archive_path, &source_key, &target, &key(99)).is_err(),
            "{refusal}"
        );
        assert_eq!(tree_fingerprint(&originals.0), before, "{refusal}");
        drop(writer);
    }
}
