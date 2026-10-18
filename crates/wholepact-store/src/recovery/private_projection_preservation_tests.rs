//! Encrypted preservation regressions reuse the existing inert construction
//! fixture and its exact gates. They do not qualify native disclosure or signing.
use super::*;
use wholepact_storage_security::{
    bundle::recovery::{self as recovery, generation::GenerationBinding},
    generation_archive::{self as archive, ArchivedGenerationSource},
};

const SCOPE_ERROR: &str = "private input projection material is outside export or recovery scope";
const PRIVATE: &str = r#"{"durable_input_projections_v\u0031":{"selected":"SYNTHETIC-PRIVATE"},"durable_input_projections_v1":{}}"#;
const COLUMNS: [(&str, &str, usize); 4] = [
    ("records", "payload", 3),
    ("operations", "result", 5),
    ("idempotency", "result", 3),
    ("events", "payload", 5),
];

fn refuse<T>(result: crate::Result<T>) {
    assert!(matches!(result, Err(StoreError::InvalidInput(SCOPE_ERROR))));
}

fn edit_immutable_row(c: &rusqlite::Connection, trigger: &str, edit: impl FnOnce()) {
    let definition: String = c
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
            [trigger],
            |row| row.get(0),
        )
        .unwrap();
    c.execute_batch(&format!("DROP TRIGGER {trigger}")).unwrap();
    edit();
    c.execute_batch(&definition).unwrap();
}

struct ExactArchiveAuthority(archive::ArchiveScope);
struct ExactArchiveLease;
impl archive::ArchiveAuthority for ExactArchiveAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &archive::ArchiveScope,
    ) -> std::result::Result<Box<dyn archive::ArchiveLease + 'a>, archive::ArchiveError> {
        if scope != &self.0 {
            return Err(archive::ArchiveError::Permission);
        }
        Ok(Box::new(ExactArchiveLease))
    }
}
impl archive::ArchiveLease for ExactArchiveLease {
    fn check_current(&self) -> std::result::Result<(), archive::ArchiveError> {
        Ok(())
    }
}

fn seal_generation(
    source: &Path,
    root: &Path,
    binding: &GenerationBinding,
    provenance: &recovery::RecoveryProvenance,
    source_key: &DatabaseKey,
    capsule: &Path,
    template: &'static JournalTemplate,
) -> ArchivedGenerationSource {
    let root_lock = fs::File::open(root).unwrap();
    root_lock.try_lock().unwrap();
    let capsule_key = key(0x71);
    let capsule_id = "71".repeat(32);
    let sources = [archive::RegisteredSource::new(
        "coordination",
        "current-coordination",
        archive::Source::Journal(source),
    )
    .unwrap()];
    let node = archive::NodeSpec {
        generation_id: binding.generation_id().into(),
        profile_id: "synthetic-staging-profile".into(),
        original_root: root.into(),
    };
    let authority = ExactArchiveAuthority(
        archive::ArchiveScope::for_snapshot(
            capsule,
            &capsule_key,
            &capsule_id,
            &node,
            &sources,
            &[],
        )
        .unwrap(),
    );
    unchanged(root, || {
        archive::snapshot(archive::SnapshotRequest {
            destination: capsule,
            key: &capsule_key,
            capsule_id: &capsule_id,
            node: &node,
            sources: &sources,
            parents: &[],
            authority: &authority,
        })
        .unwrap()
    });
    let archive = archive::inspect(capsule, &capsule_key).unwrap();
    archive
        .journal(archive.manifest_digest(), "coordination")
        .unwrap()
        .open_generation(source_key, binding, provenance, template)
        .unwrap()
}

#[test]
fn private_current_four_columns_refuse_snapshot_before_projection_without_source_changes() {
    for (table, column, _) in COLUMNS {
        let f = Fixture::new(true);
        let c = f.store.connection.lock().unwrap();
        let edit = || {
            c.execute(&format!("UPDATE {table} SET {column}=?1"), [PRIVATE])
                .unwrap();
        };
        match table {
            "records" => edit_immutable_row(&c, "store_generation_records_no_update", edit),
            "operations" => edit_immutable_row(&c, "store_generation_operations_no_update", edit),
            _ => edit(),
        }
        drop(c);
        unchanged(f.directory.path(), || refuse(f.snapshot()));
    }
}

#[test]
fn private_originals_alone_refuse_snapshot_and_successor_before_destination_creation() {
    for (table, _, column) in COLUMNS {
        let f = Fixture::new(true);
        let c = f.store.connection.lock().unwrap();
        let encoded: String = c.query_row(
            "SELECT payload FROM store_generation_original_rows WHERE table_name=?1 AND ordinal=0",
            [table], |row| row.get(0),
        ).unwrap();
        let mut cells: Vec<serde_json::Value> = serde_json::from_str(&encoded).unwrap();
        cells[column] = serde_json::Value::String(PRIVATE.into());
        edit_immutable_row(&c, "store_generation_originals_no_update", || {
            c.execute("UPDATE store_generation_original_rows SET payload=?1 WHERE table_name=?2 AND ordinal=0", rusqlite::params![serde_json::to_string(&cells).unwrap(), table]).unwrap();
        });
        crate::backup::validate_no_private_input_projections(&c).unwrap();
        drop(c);
        unchanged(f.directory.path(), || refuse(f.snapshot()));
        let output = tempfile::tempdir().unwrap();
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _writer_exclusion = f.store.connection.lock().unwrap();
        let sealed = seal_generation(
            &f.path(),
            f.directory.path(),
            &f.binding,
            &f.provenance,
            &key(0x61),
            &output.path().join("capsule.sqlite"),
            crate::recovery::coordination_successor_template(),
        );
        let binding = GenerationBinding::new(&"72".repeat(32), &"73".repeat(32)).unwrap();
        let destination = output.path().join("forbidden-successor.sqlite");
        unchanged(f.directory.path(), || {
            unchanged(output.path(), || {
                refuse(crate::recovery::stage_layered_coordination_successor(
                    &sealed,
                    &binding,
                    &destination,
                    &key(0x74),
                ));
            })
        });
        assert!(!destination.exists());
    }
}

#[test]
fn private_layer_history_alone_refuses_snapshot_and_successor_without_rewriting_sources() {
    // First stage real, valid construction history through the existing public
    // archive path. Corrupt only one encoded retained layer cell afterwards.
    for wrapped in [false, true] {
        let f = Fixture::new(true);
        let output = tempfile::tempdir().unwrap();
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let sealed = {
            let _writer_exclusion = f.store.connection.lock().unwrap();
            seal_generation(
                &f.path(),
                f.directory.path(),
                &f.binding,
                &f.provenance,
                &key(0x61),
                &output.path().join("parent.sqlite"),
                crate::recovery::coordination_successor_template(),
            )
        };
        let binding = GenerationBinding::new(&"75".repeat(32), &"76".repeat(32)).unwrap();
        let path = output.path().join("layered.sqlite");
        crate::recovery::stage_layered_coordination_successor(&sealed, &binding, &path, &key(0x77))
            .unwrap();
        let store = Store::open_recovered_generation(
            &path,
            &key(0x77),
            &binding,
            sealed.source_provenance(),
        )
        .unwrap();
        let c = store.connection.lock().unwrap();
        let table = if wrapped {
            "store_generation_original_rows"
        } else {
            "events"
        };
        let (ordinal, encoded): (i64, String) = c.query_row(
            "SELECT ordinal,payload FROM store_generation_layer_rows WHERE layer=1 AND table_name=?1 ORDER BY ordinal LIMIT 1",
            [table], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let mut row: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        if wrapped {
            // Pick the retained original events row, not an arbitrary string.
            let mut query = c.prepare("SELECT ordinal,payload FROM store_generation_layer_rows WHERE layer=1 AND table_name='store_generation_original_rows' ORDER BY ordinal").unwrap();
            let (ordinal, encoded) = query
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .map(|row| row.unwrap())
                .find(|(_, encoded)| {
                    serde_json::from_str::<serde_json::Value>(encoded).unwrap()["cells"][0]
                        == "events"
                })
                .unwrap();
            let mut wrapper: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            let mut originals: Vec<serde_json::Value> =
                serde_json::from_str(wrapper["cells"][2].as_str().unwrap()).unwrap();
            originals[5] = serde_json::Value::String(PRIVATE.into());
            wrapper["cells"][2] =
                serde_json::Value::String(serde_json::to_string(&originals).unwrap());
            edit_immutable_row(&c, "store_generation_layer_rows_no_update", || {
                c.execute("UPDATE store_generation_layer_rows SET payload=?1 WHERE layer=1 AND table_name=?2 AND ordinal=?3", rusqlite::params![wrapper.to_string(), table, ordinal]).unwrap();
            });
        } else {
            row["cells"][5] = serde_json::Value::String(PRIVATE.into());
            edit_immutable_row(&c, "store_generation_layer_rows_no_update", || {
                c.execute("UPDATE store_generation_layer_rows SET payload=?1 WHERE layer=1 AND table_name=?2 AND ordinal=?3", rusqlite::params![row.to_string(), table, ordinal]).unwrap();
            });
        }
        crate::backup::validate_no_private_input_projections(&c).unwrap();
        drop(c);
        unchanged(output.path(), || {
            refuse(RecoveredStoreSnapshot::open(
                &path,
                &key(0x77),
                &binding,
                sealed.source_provenance(),
            ))
        });
        let archive_output = tempfile::tempdir().unwrap();
        fs::set_permissions(archive_output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _writer_exclusion = store.connection.lock().unwrap();
        let private = seal_generation(
            &path,
            output.path(),
            &binding,
            sealed.source_provenance(),
            &key(0x77),
            &archive_output.path().join("private-layer.sqlite"),
            crate::recovery::coordination_layered_successor_template(),
        );
        let next = GenerationBinding::new(&"78".repeat(32), &"79".repeat(32)).unwrap();
        let destination = archive_output.path().join("forbidden-successor.sqlite");
        unchanged(output.path(), || {
            unchanged(archive_output.path(), || {
                refuse(crate::recovery::stage_layered_coordination_successor(
                    &private,
                    &next,
                    &destination,
                    &key(0x7a),
                ));
            })
        });
        assert!(!destination.exists());
    }
}

// Deliberately forged but correctly authenticated bundle metadata exercises
// the Store boundary, rather than relying on the safe adapter to create it.
struct ForgedMetadataAdapter<'a>(&'a Store);
impl JournalAdapter for ForgedMetadataAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        crate::bundle::coordination_template()
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&rusqlite::Connection) -> std::result::Result<(), BundleError>,
    ) -> std::result::Result<(), BundleError> {
        permit.check(self)?;
        let connection = self.0.connection.lock().map_err(|_| BundleError::Storage)?;
        visitor(&connection)
    }
}

fn coverage() -> Coverage {
    Coverage {
        present: BTreeMap::from([(
            JournalKind::CoordinationAuthority,
            vec!["coordination".into()],
        )]),
        absent: [
            JournalKind::SignerConsentAuthority,
            JournalKind::WalletScan,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::Submission,
            JournalKind::TransportInbox,
            JournalKind::TransportOutbox,
        ]
        .into_iter()
        .collect(),
    }
}

#[test]
fn private_four_columns_refuse_bundle_inventory_and_both_history_routes() {
    for (table, column, _) in COLUMNS {
        let f = Fixture::new(true);
        let checked = crate::bundle::CoordinationBundleAdapter::new(&f._source_store).unwrap();
        f._source_store
            .connection
            .lock()
            .unwrap()
            .execute(&format!("UPDATE {table} SET {column}=?1"), [PRIVATE])
            .unwrap();
        assert!(matches!(
            crate::bundle::CoordinationBundleAdapter::new(&f._source_store),
            Err(BundleError::Integrity)
        ));
        let output = tempfile::tempdir().unwrap();
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // The source changed after adapter preflight. The under-lock scan must
        // still reject before bundle's visitor can copy a single source row.
        let checked_sources = [RegisteredJournal::new("coordination", &checked).unwrap()];
        let late_destination = output.path().join("late-refusal.sqlite");
        crate::bundle::reset_bundle_visitor_calls();
        assert!(matches!(
            bundle::snapshot(SnapshotRequest {
                principal_id: "synthetic-history-admin",
                profile_id: "synthetic-profile",
                coverage: coverage(),
                sources: &checked_sources,
                destination: &late_destination,
                key: &key(0x7b),
                authority: &FixtureArchiveGate,
            }),
            Err(BundleError::Integrity)
        ));
        assert_eq!(crate::bundle::bundle_visitor_calls(), 0);
        // Generic bundle storage creates staging before invoking read_locked.
        // That staging artifact may remain after this late-race refusal; only
        // constructor preflight rejects already-private sources before staging.
        // This single-component fixture proves zero coordination visitor calls,
        // not no-artifact atomicity. In a multi-component backup, previously
        // authorized visitors may already have run. Preserve the partial archive;
        // do not infer that it is empty or claim a successful backup.
        assert!(late_destination.is_file());
        assert!(bundle::inspect(&late_destination, &key(0x7b)).is_err());
        let archive = output.path().join("forged.sqlite");
        let restored = output.path().join("restored.sqlite");
        let adapter = ForgedMetadataAdapter(&f._source_store);
        let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
        bundle::snapshot(SnapshotRequest {
            principal_id: "synthetic-history-admin",
            profile_id: "synthetic-profile",
            coverage: coverage(),
            sources: &sources,
            destination: &archive,
            key: &key(0x7b),
            authority: &FixtureArchiveGate,
        })
        .unwrap();
        bundle::restore(RestoreRequest {
            principal_id: "synthetic-history-admin",
            profile_id: "synthetic-profile",
            archive: &archive,
            key: &key(0x7b),
            targets: &[RestoreTarget {
                component_id: "coordination",
                template: crate::bundle::coordination_template(),
                destination: &restored,
                key: &key(0x7c),
            }],
            authority: &FixtureArchiveGate,
        })
        .unwrap();
        let source = recovery::VerifiedRecoveryComponent::open(
            bundle::history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &key(0x7b),
                restored_component: &restored,
                restored_key: &key(0x7c),
                component_id: "coordination",
            },
            crate::bundle::coordination_template(),
        )
        .unwrap();
        refuse(crate::recovery::StoreRecoveryInventory::inspect(&source));
        assert!(matches!(
            crate::history::open_quarantined_history(bundle::history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &key(0x7b),
                restored_component: &restored,
                restored_key: &key(0x7c),
                component_id: "coordination"
            }),
            Err(BundleError::Integrity)
        ));
        let binding = GenerationBinding::new(&"7d".repeat(32), &"7e".repeat(32)).unwrap();
        let destination = output.path().join("forbidden.sqlite");
        unchanged(output.path(), || {
            refuse(crate::recovery::stage_coordination_successor(
                &source,
                &binding,
                &destination,
                &key(0x7f),
            ));
            assert!(
                crate::bundle::reconstruct_coordination_successor_evidence(
                    &source,
                    &destination,
                    &key(0x7f),
                    &binding
                )
                .is_err()
            );
        });
        assert!(!destination.exists());
        let evidence_path = output.path().join("evidence.sqlite");
        recovery::evidence::reconstruct_coordination_evidence(
            &source,
            crate::bundle::coordination_template(),
            &evidence_path,
            &key(0x7f),
            &binding,
        )
        .unwrap();
        let evidence = recovery::evidence::open_coordination_evidence(
            &evidence_path,
            &key(0x7f),
            &binding,
            source.provenance(),
            crate::bundle::coordination_template(),
        )
        .unwrap();
        assert!(matches!(
            crate::history::validate_successor_construction_history(&evidence),
            Err(BundleError::Integrity)
        ));
    }
}

#[test]
fn exact_empty_projection_keeps_existing_construction_snapshot_and_bundle_scope() {
    let f = Fixture::new(true);
    let context = crate::CommandContext::for_request(
        "synthetic-principal",
        "empty-projection",
        &serde_json::json!(["empty-projection"]),
    )
    .unwrap();
    f.store.create_agreement(&context, "empty-projection-agreement", serde_json::json!({"view":{"agreement":{"agreement_id":"empty-projection-agreement"}},"durable_input_projections_v1":{}})).unwrap();
    let snapshot = unchanged(f.directory.path(), || f.snapshot().unwrap());
    unchanged(f.directory.path(), || {
        let retained = snapshot
            .manual_roster_construction_evidence_v2(
                &f.claim.principal_id,
                &f.claim.construction_key,
            )
            .unwrap()
            .unwrap();
        assert!(retained == (f.claim.clone(), f.receipt.clone()));
    });
    let c = f._source_store.connection.lock().unwrap();
    c.execute(
        "UPDATE records SET payload=?1",
        [r#"{"durable_construction_v1":{"old":"retained"},"durable_input_projections_v1":{}}"#],
    )
    .unwrap();
    drop(c);
    crate::bundle::CoordinationBundleAdapter::new(&f._source_store).unwrap();
}
