use super::*;
use crate::{create_encrypted, open_encrypted, EncryptedConnection};
use std::sync::Mutex;

static COORD:JournalTemplate=JournalTemplate {kind:JournalKind::CoordinationAuthority,application_id:0,schema_version:2,create_sql:"CREATE TABLE records(id INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL); CREATE TABLE state(singleton INTEGER PRIMARY KEY,value TEXT NOT NULL); INSERT INTO state VALUES(1,'initial'); CREATE TRIGGER immutable_record BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'immutable'); END;"};
static PROOF: JournalTemplate = JournalTemplate {
    kind: JournalKind::ProofWitness,
    application_id: 1464881226,
    schema_version: 1,
    create_sql: "CREATE TABLE jobs(id TEXT PRIMARY KEY, bytes BLOB NOT NULL);",
};
struct Adapter {
    connection: Mutex<EncryptedConnection>,
    template: &'static JournalTemplate,
}
impl JournalAdapter for Adapter {
    fn template(&self) -> &'static JournalTemplate {
        self.template
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<()>,
    ) -> Result<()> {
        permit.check(self)?;
        visitor(self.connection.lock().unwrap().connection())
    }
}
struct Gate {
    bindings: Vec<JournalBinding>,
    allow: bool,
}
struct Lease;
impl BundleLease for Lease {
    fn check_current(&self) -> Result<()> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "fixture-checkpoint"
    }
}
impl BundleAuthority for Gate {
    fn acquire<'a>(&'a self, scope: &BundleScope<'_>) -> Result<Box<dyn BundleLease + 'a>> {
        if !self.allow
            || scope.principal_id != "admin"
            || scope.profile_id != "profile"
            || scope.wallet_spending_secrets_included
            || scope
                .sources
                .iter()
                .map(|s| s.1.clone())
                .collect::<Vec<_>>()
                != self.bindings
                && scope.action == BundleAction::Snapshot
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(Lease))
    }
}
fn adapter(path: &Path, key: &DatabaseKey, template: &'static JournalTemplate) -> Adapter {
    let connection = create_encrypted(path, key).unwrap();
    connection
        .connection()
        .execute_batch(template.create_sql)
        .unwrap();
    connection
        .connection()
        .pragma_update(None, "application_id", template.application_id)
        .unwrap();
    connection
        .connection()
        .pragma_update(None, "user_version", template.schema_version)
        .unwrap();
    Adapter {
        connection: Mutex::new(connection),
        template,
    }
}
fn coverage() -> Coverage {
    Coverage {
        present: BTreeMap::from([
            (JournalKind::CoordinationAuthority, vec!["coord".into()]),
            (JournalKind::ProofWitness, vec!["proof".into()]),
        ]),
        absent: KINDS
            .into_iter()
            .filter(|k| {
                !matches!(
                    k,
                    JournalKind::CoordinationAuthority | JournalKind::ProofWitness
                )
            })
            .collect(),
    }
}
#[test]
fn complete_inventory_encrypted_roundtrip_preserves_rows_and_quarantines_every_component() {
    let dir = private_dir();
    let k = DatabaseKey::from_bytes([41; 32]);
    let archive_key = DatabaseKey::from_bytes([42; 32]);
    let restore_key = DatabaseKey::from_bytes([43; 32]);
    let coord = adapter(&dir.path().join("coord"), &k, &COORD);
    let proof = adapter(&dir.path().join("proof"), &k, &PROOF);
    coord
        .connection
        .lock()
        .unwrap()
        .connection()
        .execute(
            "INSERT INTO records(id,payload) VALUES(7,?1)",
            [b"private-journal-canary".as_slice()],
        )
        .unwrap();
    // A deleted high ID must not be reused after recovery. Restore the same
    // compiled immutable trigger after this controlled synthetic history setup.
    coord.connection.lock().unwrap().connection().execute_batch("DROP TRIGGER immutable_record; INSERT INTO records(id,payload) VALUES(900,X'01'); DELETE FROM records WHERE id=900; CREATE TRIGGER immutable_record BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'immutable'); END;").unwrap();
    proof
        .connection
        .lock()
        .unwrap()
        .connection()
        .execute(
            "INSERT INTO jobs VALUES('proof-original',?1)",
            [b"private-proof-canary".as_slice()],
        )
        .unwrap();
    let sources = [
        RegisteredJournal::new("coord", &coord).unwrap(),
        RegisteredJournal::new("proof", &proof).unwrap(),
    ];
    let gate = Gate {
        bindings: sources.iter().map(|s| s.binding()).collect(),
        allow: true,
    };
    let path = dir.path().join("bundle");
    let manifest = snapshot(SnapshotRequest {
        principal_id: "admin",
        profile_id: "profile",
        coverage: coverage(),
        sources: &sources,
        destination: &path,
        key: &archive_key,
        authority: &gate,
    })
    .unwrap();
    assert_eq!(manifest.components.len(), 2);
    assert!(!manifest.writer_freshness_established);
    assert_eq!(inspect(&path, &archive_key).unwrap(), manifest);
    assert!(inspect(&path, &k).is_err());
    let coord_path = dir.path().join("restored-coord");
    let proof_path = dir.path().join("restored-proof");
    let targets = [
        RestoreTarget {
            component_id: "coord",
            template: &COORD,
            destination: &coord_path,
            key: &restore_key,
        },
        RestoreTarget {
            component_id: "proof",
            template: &PROOF,
            destination: &proof_path,
            key: &restore_key,
        },
    ];
    let report = test_restore(RestoreRequest {
        principal_id: "admin",
        profile_id: "profile",
        archive: &path,
        key: &archive_key,
        targets: &targets,
        authority: &gate,
    })
    .unwrap();
    assert!(report.integrity_verified && report.all_components_quarantined);
    assert!(!report.authorization_allowed);
    for path in [&coord_path, &proof_path] {
        assert!(matches!(
            open_encrypted(path, &restore_key),
            Err(StorageSecurityError::QuarantinedDatabase)
        ));
    }
    let restored = crate::open_quarantined(&coord_path, &restore_key).unwrap();
    let bytes: Vec<u8> = restored
        .connection()
        .query_row("SELECT payload FROM records WHERE id=7", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bytes, b"private-journal-canary");
    let sequence: i64 = restored
        .connection()
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='records'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sequence, 900);
    assert!(restored
        .connection()
        .execute("DELETE FROM records", [])
        .is_err());
    for file in [&path, &coord_path, &proof_path] {
        let bytes = std::fs::read(file).unwrap();
        assert!(!bytes.windows(22).any(|w| w == b"private-journal-canary"));
        assert!(!bytes.starts_with(b"SQLite format 3"));
    }
}
#[test]
fn missing_inventory_permission_schema_and_overwrite_fail_closed() {
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([44; 32]);
    let coord = adapter(&dir.path().join("source"), &key, &COORD);
    let sources = [RegisteredJournal::new("coord", &coord).unwrap()];
    let gate = Gate {
        bindings: vec![sources[0].binding()],
        allow: true,
    };
    let archive = dir.path().join("archive");
    let mut cov = coverage();
    cov.present.remove(&JournalKind::ProofWitness);
    assert!(matches!(
        snapshot(SnapshotRequest {
            principal_id: "admin",
            profile_id: "profile",
            coverage: cov.clone(),
            sources: &sources,
            destination: &archive,
            key: &key,
            authority: &gate
        }),
        Err(BundleError::Invalid)
    ));
    cov.absent.insert(JournalKind::ProofWitness);
    let denied = Gate {
        bindings: gate.bindings.clone(),
        allow: false,
    };
    assert!(matches!(
        snapshot(SnapshotRequest {
            principal_id: "admin",
            profile_id: "profile",
            coverage: cov.clone(),
            sources: &sources,
            destination: &archive,
            key: &key,
            authority: &denied
        }),
        Err(BundleError::Permission)
    ));
    assert!(!archive.exists());
    snapshot(SnapshotRequest {
        principal_id: "admin",
        profile_id: "profile",
        coverage: cov.clone(),
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &gate,
    })
    .unwrap();
    assert!(snapshot(SnapshotRequest {
        principal_id: "admin",
        profile_id: "profile",
        coverage: cov,
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &gate
    })
    .is_err());
    let dest = dir.path().join("wrong");
    let targets = [RestoreTarget {
        component_id: "coord",
        template: &PROOF,
        destination: &dest,
        key: &key,
    }];
    assert!(matches!(
        restore(RestoreRequest {
            principal_id: "admin",
            profile_id: "profile",
            archive: &archive,
            key: &key,
            targets: &targets,
            authority: &gate
        }),
        Err(BundleError::Unsupported)
    ));
    assert!(!dest.exists());
    coord
        .connection
        .lock()
        .unwrap()
        .connection()
        .execute_batch("CREATE TABLE unexpected(secret BLOB);")
        .unwrap();
    let bad = dir.path().join("bad");
    let mut cov = coverage();
    cov.present.remove(&JournalKind::ProofWitness);
    cov.absent.insert(JournalKind::ProofWitness);
    assert!(matches!(
        snapshot(SnapshotRequest {
            principal_id: "admin",
            profile_id: "profile",
            coverage: cov,
            sources: &sources,
            destination: &bad,
            key: &key,
            authority: &gate
        }),
        Err(BundleError::Unsupported)
    ));
    assert!(inspect(&bad, &key).is_err());
}
#[test]
fn corrupted_manifest_rows_and_partial_restore_never_activate() {
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([45; 32]);
    let coord = adapter(&dir.path().join("coord"), &key, &COORD);
    let proof = adapter(&dir.path().join("proof"), &key, &PROOF);
    let sources = [
        RegisteredJournal::new("coord", &coord).unwrap(),
        RegisteredJournal::new("proof", &proof).unwrap(),
    ];
    let gate = Gate {
        bindings: sources.iter().map(|s| s.binding()).collect(),
        allow: true,
    };
    let path = dir.path().join("bundle");
    snapshot(SnapshotRequest {
        principal_id: "admin",
        profile_id: "profile",
        coverage: coverage(),
        sources: &sources,
        destination: &path,
        key: &key,
        authority: &gate,
    })
    .unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("existing");
    std::fs::write(&second, b"do not overwrite").unwrap();
    let targets = [
        RestoreTarget {
            component_id: "coord",
            template: &COORD,
            destination: &first,
            key: &key,
        },
        RestoreTarget {
            component_id: "proof",
            template: &PROOF,
            destination: &second,
            key: &key,
        },
    ];
    assert!(restore(RestoreRequest {
        principal_id: "admin",
        profile_id: "profile",
        archive: &path,
        key: &key,
        targets: &targets,
        authority: &gate
    })
    .is_err());
    assert!(matches!(
        open_encrypted(&first, &key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert_eq!(std::fs::read(&second).unwrap(), b"do not overwrite");
    let source = open_encrypted(&path, &key).unwrap();
    source
        .connection()
        .execute(
            "UPDATE bundle_rows SET payload=X'7b7d' WHERE component='coord'",
            [],
        )
        .unwrap();
    drop(source);
    assert!(inspect(&path, &key).is_err());
}

#[test]
fn one_adapters_permit_cannot_be_forwarded_to_another_registered_source() {
    #[repr(transparent)]
    struct Forward(Adapter);
    impl JournalAdapter for Forward {
        fn template(&self) -> &'static JournalTemplate {
            &COORD
        }
        fn read_locked(
            &self,
            permit: &BackupReadPermit<'_>,
            visitor: &mut dyn FnMut(&Connection) -> Result<()>,
        ) -> Result<()> {
            permit.check(self)?;
            self.0.read_locked(permit, visitor)
        }
    }
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([46; 32]);
    let protected = adapter(&dir.path().join("private"), &key, &COORD);
    let forwarding = Forward(protected);
    let wrapper: &dyn JournalAdapter = &forwarding;
    let inner: &dyn JournalAdapter = &forwarding.0;
    assert!(std::ptr::addr_eq(wrapper, inner));
    assert!(!std::ptr::eq(wrapper, inner));
    let sources = [RegisteredJournal::new("coord", &forwarding).unwrap()];
    let gate = Gate {
        bindings: vec![sources[0].binding()],
        allow: true,
    };
    let mut cov = coverage();
    cov.present.remove(&JournalKind::ProofWitness);
    cov.absent.insert(JournalKind::ProofWitness);
    assert!(matches!(
        snapshot(SnapshotRequest {
            principal_id: "admin",
            profile_id: "profile",
            coverage: cov,
            sources: &sources,
            destination: &dir.path().join("denied"),
            key: &key,
            authority: &gate
        }),
        Err(BundleError::SourceBinding)
    ));
}

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
#[test]
fn authenticated_but_incomplete_table_inventory_is_refused_before_restore() {
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([107; 32]);
    let coord = adapter(&dir.path().join("coord"), &key, &COORD);
    let sources = [RegisteredJournal::new("coord", &coord).unwrap()];
    let gate = Gate {
        bindings: sources.iter().map(|s| s.binding()).collect(),
        allow: true,
    };
    let archive = dir.path().join("archive");
    snapshot(SnapshotRequest {
        principal_id: "admin",
        profile_id: "profile",
        coverage: Coverage {
            present: BTreeMap::from([(JournalKind::CoordinationAuthority, vec!["coord".into()])]),
            absent: KINDS
                .into_iter()
                .filter(|k| *k != JournalKind::CoordinationAuthority)
                .collect(),
        },
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &gate,
    })
    .unwrap();
    let encrypted = open_encrypted(&archive, &key).unwrap();
    let c = encrypted.connection();
    let bytes: Vec<u8> = c
        .query_row("SELECT manifest FROM bundle_manifest", [], |r| r.get(0))
        .unwrap();
    let mut manifest: BundleManifest = serde_json::from_slice(&bytes).unwrap();
    let component = &mut manifest.components[0];
    // sqlite_sequence is initially empty, but omitting its inventory declaration
    // still violates complete coverage even with internally matching digests.
    assert_eq!(
        component
            .tables
            .iter()
            .find(|t| t.name == "sqlite_sequence")
            .unwrap()
            .rows,
        0
    );
    component.tables.retain(|t| t.name != "sqlite_sequence");
    let mut hash = Sha256::new();
    hash.update(b"wholepact.bundle.component.v1\0");
    hash.update(encode(&component.schema).unwrap());
    for table in &component.tables {
        hash.update(encode(table).unwrap());
        let mut stmt=c.prepare("SELECT payload FROM bundle_rows WHERE component=?1 AND table_name=?2 ORDER BY row_number").unwrap();
        let payloads = stmt
            .query_map(params![component.id, table.name], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .unwrap();
        for data in payloads {
            let data = data.unwrap();
            hash.update((data.len() as u64).to_be_bytes());
            hash.update(data);
        }
    }
    component.digest = hex_digest(hash);
    manifest.digest = manifest_digest(&manifest).unwrap();
    c.execute(
        "UPDATE bundle_manifest SET manifest=?1",
        [encode(&manifest).unwrap()],
    )
    .unwrap();
    drop(encrypted);
    assert!(matches!(
        inspect(&archive, &key),
        Err(BundleError::Integrity)
    ));
    let destination = dir.path().join("should-not-exist");
    assert!(restore(RestoreRequest {
        principal_id: "admin",
        profile_id: "profile",
        archive: &archive,
        key: &key,
        targets: &[RestoreTarget {
            component_id: "coord",
            template: &COORD,
            destination: &destination,
            key: &key
        }],
        authority: &gate
    })
    .is_err());
    assert!(!destination.exists());
    // The compiled schema also binds exact column order and hidden rowid rules,
    // independently of table names and any validly recomputed archive digest.
    let mut original = snapshot(SnapshotRequest {
        principal_id: "admin",
        profile_id: "profile",
        coverage: Coverage {
            present: BTreeMap::from([(JournalKind::CoordinationAuthority, vec!["coord".into()])]),
            absent: KINDS
                .into_iter()
                .filter(|k| *k != JournalKind::CoordinationAuthority)
                .collect(),
        },
        sources: &sources,
        destination: &dir.path().join("second-archive"),
        key: &key,
        authority: &gate,
    })
    .unwrap();
    original.components[0].tables[0].rowid = !original.components[0].tables[0].rowid;
    assert!(matches!(
        validate_component_template(&original.components[0], &COORD),
        Err(BundleError::Integrity)
    ));
    original.components[0].tables[0].rowid = !original.components[0].tables[0].rowid;
    original.components[0].tables[0].columns.reverse();
    assert!(matches!(
        validate_component_template(&original.components[0], &COORD),
        Err(BundleError::Integrity)
    ));
}

#[test]
fn inventory_requires_explicit_coordinator_or_signer_authority_profile() {
    let mut inventory = coverage();
    inventory
        .present
        .remove(&JournalKind::CoordinationAuthority);
    inventory.absent.insert(JournalKind::CoordinationAuthority);
    assert!(validate_coverage(&inventory).is_err());
    inventory
        .absent
        .remove(&JournalKind::SignerConsentAuthority);
    inventory
        .present
        .insert(JournalKind::SignerConsentAuthority, vec!["signer".into()]);
    assert!(validate_coverage(&inventory).is_ok());
    inventory.absent.remove(&JournalKind::WalletScan);
    assert!(validate_coverage(&inventory).is_err());
}
