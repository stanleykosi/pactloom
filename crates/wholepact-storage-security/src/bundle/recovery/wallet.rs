//! Narrow wallet-scan reconstruction. Historical rows are immutable evidence;
//! the caller's profile activation protocol retains all key-use authority.

use super::{RecoveryCell, VerifiedRecoveryComponent};
use crate::{DatabaseKey, StorageSecurityError};
use rusqlite::{params_from_iter, types::ValueRef, Connection, TransactionBehavior};
use std::path::Path;

use super::super::{
    integrity, quote, template_schema, validate_component_template, verify_restored_rows,
    BundleError, ComponentManifest, JournalKind, JournalTemplate, MAX_OBJECTS,
    QUARANTINE_APPLICATION_ID,
};

type Result<T> = std::result::Result<T, BundleError>;
pub(super) type SchemaObject = (String, String, String, Option<String>);

/// Reconstruct only a WalletScan component using an executable-owned template.
/// Consumers should use the wallet crate's wrapper, which supplies its pinned
/// maintained-library template rather than accepting a caller-selected schema.
///
/// The caller must hold the whole-profile recovery lease and retain the newly
/// allocated database key until final profile activation. Success is a durable
/// historical copy, not a freshness claim, profile activation, or permission to
/// synchronize/use viewing keys. No quarantine marker is removed. A retry either
/// verifies the complete existing reconstruction or initializes an authenticated
/// encrypted database with absolutely no schema/application state. Zero-byte or
/// otherwise unauthenticated files are never adopted.
pub fn reconstruct_wallet_scan_successor(
    source: &VerifiedRecoveryComponent,
    template: &'static JournalTemplate,
    path: impl AsRef<Path>,
    key: &DatabaseKey,
) -> Result<()> {
    let provenance = source.provenance();
    if template.kind != JournalKind::WalletScan || provenance.kind != JournalKind::WalletScan {
        return Err(BundleError::Unsupported);
    }
    let component = source
        .manifest()
        .components
        .iter()
        .find(|component| component.id == provenance.component_id)
        .ok_or(BundleError::Integrity)?;
    // A sealed source may have been opened against another executable-owned
    // template. Rebind it to this exact schema, kind, application and version.
    validate_component_template(component, template)?;
    let reference = Connection::open_in_memory()?;
    reference.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")?;
    reference.execute_batch(template.create_sql)?;
    let expected_schema = exact_schema(&reference)?;
    drop(reference);

    let path = path.as_ref();
    let mut output = match crate::create_encrypted(path, key) {
        Ok(connection) => connection.into_connection(),
        Err(StorageSecurityError::AlreadyExists) => {
            // Authenticate read-only first. In particular, even an accidental
            // attempt to use the quarantined source as a destination never opens
            // that source for writes or clears its quarantine marker.
            let existing = crate::open_encrypted_read_only(path, key)?;
            if application_id(&existing)? == QUARANTINE_APPLICATION_ID {
                return Err(BundleError::Integrity);
            }
            drop(existing);
            // The private factory permits the interrupted empty case. The
            // immediate transaction below rechecks every property before writes.
            crate::keyed_connection(path, key)?
        }
        Err(error) => return Err(error.into()),
    };
    let transaction = output.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if is_truly_empty(&transaction)? {
        populate(&transaction, source, template, &expected_schema)?;
    }
    verify_complete(&transaction, component, template, &expected_schema)?;
    transaction.commit()?;
    crate::checkpoint_and_sync(&output, path)?;
    drop(output);

    // Verify the persisted successor independently, under its own key, rather
    // than treating an in-memory write or checkpoint return as sufficient.
    let persisted = crate::open_encrypted_read_only(path, key)?;
    persisted.execute_batch("BEGIN DEFERRED;")?;
    verify_complete(&persisted, component, template, &expected_schema)
}

pub(super) fn application_id(connection: &Connection) -> Result<i64> {
    Ok(connection.pragma_query_value(None, "application_id", |row| row.get(0))?)
}

pub(super) fn is_truly_empty(connection: &Connection) -> Result<bool> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let count: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    Ok(application_id(connection)? == 0 && version == 0 && count == 0)
}

// Include SQLite-generated indexes and tables too: a deterministic successor
// cannot be substituted by an otherwise matching schema with extra objects.
pub(super) fn exact_schema(connection: &Connection) -> Result<Vec<SchemaObject>> {
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
    let mut rows = statement.query([])?;
    let mut objects = Vec::new();
    while let Some(row) = rows.next()? {
        if objects.len() >= MAX_OBJECTS {
            return Err(BundleError::Limit);
        }
        objects.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
    }
    Ok(objects)
}

fn verify_complete(
    connection: &Connection,
    component: &ComponentManifest,
    template: &JournalTemplate,
    expected_schema: &[SchemaObject],
) -> Result<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id(connection)? != template.application_id
        || version != template.schema_version
        || exact_schema(connection)? != expected_schema
    {
        return Err(BundleError::Integrity);
    }
    // This authenticates all typed cells and hidden rowids, not just row counts,
    // metadata labels, or the presence of expected rows. Extra rows also fail.
    verify_restored_rows(connection, component)?;
    integrity(connection)
}

// Private shared copy kernel. Only fixed-kind recovery paths may invoke this;
// no generic public helper can turn quarantined history into a live journal.
pub(super) fn populate(
    connection: &Connection,
    source: &VerifiedRecoveryComponent,
    template: &JournalTemplate,
    expected_schema: &[SchemaObject],
) -> Result<()> {
    connection.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    connection.execute_batch(template.create_sql)?;
    if connection.is_autocommit() || exact_schema(connection)? != expected_schema {
        return Err(BundleError::Integrity);
    }
    // Only trusted compiled trigger SQL is ever executed. Triggers and template
    // seed rows must not synthesize additional data while historical rows copy.
    let trusted = template_schema(template)?;
    for object in trusted.iter().filter(|object| object.kind == "trigger") {
        connection.execute_batch(&format!("DROP TRIGGER {}", quote(&object.name)?))?;
    }
    for table in source.tables().iter().rev() {
        connection.execute(&format!("DELETE FROM {}", quote(table.name())?), [])?;
    }
    let tables = source
        .tables()
        .iter()
        .filter(|table| table.name() != "sqlite_sequence")
        .chain(
            source
                .tables()
                .iter()
                .filter(|table| table.name() == "sqlite_sequence"),
        );
    for table in tables {
        // AUTOINCREMENT inserts can recreate sequence rows. Restore the exact
        // historical sequence, including its hidden rowids, after all tables.
        if table.name() == "sqlite_sequence" {
            connection.execute("DELETE FROM sqlite_sequence", [])?;
        }
        let columns = table
            .columns()
            .iter()
            .map(|column| quote(column))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let count = table.columns().len() + usize::from(table.has_rowid());
        let sql = format!(
            "INSERT INTO {} ({}{}) VALUES ({})",
            quote(table.name())?,
            if table.has_rowid() { "rowid," } else { "" },
            columns,
            vec!["?"; count].join(",")
        );
        let mut insert = connection.prepare(&sql)?;
        for row in table.rows() {
            if row.rowid().is_some() != table.has_rowid()
                || row.cells().len() != table.columns().len()
            {
                return Err(BundleError::Integrity);
            }
            // Borrow sensitive text/blob bytes rather than allocating unzeroized
            // copies. The sealed source zeroizes its owned bytes when dropped.
            let mut values = Vec::with_capacity(count);
            if let Some(rowid) = row.rowid() {
                values.push(ValueRef::Integer(rowid));
            }
            for cell in row.cells() {
                values.push(match cell {
                    RecoveryCell::Null => ValueRef::Null,
                    RecoveryCell::Integer(value) => ValueRef::Integer(*value),
                    RecoveryCell::RealBits(bits) => ValueRef::Real(f64::from_bits(*bits)),
                    RecoveryCell::Text(value) => ValueRef::Text(value.as_bytes()),
                    RecoveryCell::Blob(value) => ValueRef::Blob(value),
                });
            }
            insert.execute(params_from_iter(
                values
                    .into_iter()
                    .map(rusqlite::types::ToSqlOutput::Borrowed),
            ))?;
        }
    }
    for object in trusted.iter().filter(|object| object.kind == "trigger") {
        connection.execute_batch(object.sql.as_deref().ok_or(BundleError::Unsupported)?)?;
    }
    connection.pragma_update(None, "application_id", template.application_id)?;
    connection.pragma_update(None, "user_version", template.schema_version)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(in crate::bundle::recovery) mod tests {
    use super::*;
    use crate::{
        bundle::{
            history::HistoryOpenRequest, restore, snapshot, BackupReadPermit, BundleAuthority,
            BundleLease, BundleScope, Coverage, JournalAdapter, RegisteredJournal, RestoreRequest,
            RestoreTarget, SnapshotRequest, KINDS,
        },
        EncryptedConnection,
    };
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf};

    // These rows and keys are synthetic fixtures. No wallet secrets, network
    // activity, signing, proofs, or funds are involved in this qualification.
    pub(in crate::bundle::recovery) static WALLET: JournalTemplate = JournalTemplate {
        kind: JournalKind::WalletScan,
        application_id: 0x57505754,
        schema_version: 3,
        create_sql: "CREATE TABLE parent(id INTEGER PRIMARY KEY AUTOINCREMENT,label TEXT NOT NULL);
            CREATE TABLE child(parent_id INTEGER PRIMARY KEY REFERENCES parent(id),payload BLOB NOT NULL) WITHOUT ROWID;
            CREATE TABLE audit(id INTEGER PRIMARY KEY,parent_id INTEGER NOT NULL REFERENCES parent(id));
            CREATE TRIGGER parent_audit AFTER INSERT ON parent BEGIN INSERT INTO audit(parent_id) VALUES(NEW.id); END;
            CREATE TABLE arbitrary(integer_cell,real_cell,text_cell,blob_cell,null_cell);
            CREATE TABLE metadata(singleton INTEGER PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO metadata VALUES(1,'template-initialization');",
    };
    static ANCHOR: JournalTemplate = JournalTemplate {
        kind: JournalKind::SignerConsentAuthority,
        application_id: 0x57505343,
        schema_version: 1,
        create_sql: "CREATE TABLE synthetic_authority(id INTEGER PRIMARY KEY);",
    };
    struct Adapter {
        connection: EncryptedConnection,
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
            visitor(self.connection.connection())
        }
    }
    struct Gate;
    impl BundleAuthority for Gate {
        fn acquire<'a>(&'a self, _: &BundleScope<'_>) -> Result<Box<dyn BundleLease + 'a>> {
            Ok(Box::new(Gate))
        }
    }
    impl BundleLease for Gate {
        fn check_current(&self) -> Result<()> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-wallet-checkpoint"
        }
    }
    pub(in crate::bundle::recovery) struct Fixture {
        pub(in crate::bundle::recovery) directory: tempfile::TempDir,
        pub(in crate::bundle::recovery) source: VerifiedRecoveryComponent,
        pub(in crate::bundle::recovery) restored: PathBuf,
        pub(in crate::bundle::recovery) restored_key: DatabaseKey,
    }
    fn initialize(path: &Path, key: &DatabaseKey, template: &'static JournalTemplate) -> Adapter {
        let connection = crate::create_encrypted(path, key).unwrap();
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
            connection,
            template,
        }
    }
    pub(in crate::bundle::recovery) fn fixture() -> Fixture {
        fixture_for(&WALLET)
    }
    pub(in crate::bundle::recovery) fn fixture_for(template: &'static JournalTemplate) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source_key = DatabaseKey::from_bytes([201; 32]);
        let anchor_key = DatabaseKey::from_bytes([202; 32]);
        let archive_key = DatabaseKey::from_bytes([203; 32]);
        let restored_key = DatabaseKey::from_bytes([204; 32]);
        let restored_anchor_key = DatabaseKey::from_bytes([205; 32]);
        let wallet = initialize(&directory.path().join("source.db"), &source_key, template);
        wallet.connection.connection().execute_batch(
            "INSERT INTO parent(id,label) VALUES(7,'synthetic-parent');
            INSERT INTO child VALUES(7,x'000102ff');
            UPDATE sqlite_sequence SET seq=400,rowid=22 WHERE name='parent';
            INSERT INTO arbitrary(rowid,integer_cell,real_cell,text_cell,blob_cell,null_cell) VALUES(-7,-42,1.25,'synthetic-text',x'00ff',NULL);
            INSERT INTO arbitrary(rowid,integer_cell,real_cell,text_cell,blob_cell,null_cell) VALUES(41,9223372036854775807,-0.125,'',x'',NULL);
            UPDATE metadata SET value='authenticated-history';",
        ).unwrap();
        let anchor = initialize(&directory.path().join("authority.db"), &anchor_key, &ANCHOR);
        let sources = [
            RegisteredJournal::new("wallet", &wallet).unwrap(),
            RegisteredJournal::new("authority", &anchor).unwrap(),
        ];
        let coverage = Coverage {
            present: BTreeMap::from([
                (template.kind, vec!["wallet".into()]),
                (
                    JournalKind::SignerConsentAuthority,
                    vec!["authority".into()],
                ),
            ]),
            absent: KINDS
                .into_iter()
                .filter(|kind| {
                    *kind != template.kind && *kind != JournalKind::SignerConsentAuthority
                })
                .collect(),
        };
        let archive = directory.path().join("archive.db");
        let restored = directory.path().join("restored.db");
        let restored_anchor = directory.path().join("restored-authority.db");
        snapshot(SnapshotRequest {
            principal_id: "synthetic-admin",
            profile_id: "synthetic-profile",
            coverage,
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &Gate,
        })
        .unwrap();
        restore(RestoreRequest {
            principal_id: "synthetic-admin",
            profile_id: "synthetic-profile",
            archive: &archive,
            key: &archive_key,
            targets: &[
                RestoreTarget {
                    component_id: "wallet",
                    template,
                    destination: &restored,
                    key: &restored_key,
                },
                RestoreTarget {
                    component_id: "authority",
                    template: &ANCHOR,
                    destination: &restored_anchor,
                    key: &restored_anchor_key,
                },
            ],
            authority: &Gate,
        })
        .unwrap();
        let before = crate::tests::tree_fingerprint(directory.path());
        let source = VerifiedRecoveryComponent::open(
            HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "wallet",
                restored_component: &restored,
                restored_key: &restored_key,
            },
            template,
        )
        .unwrap();
        assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
        Fixture {
            directory,
            source,
            restored,
            restored_key,
        }
    }

    #[test]
    fn synthetic_wallet_copy_preserves_all_types_rowids_sequences_and_quarantine() {
        let fixture = fixture();
        let path = fixture.directory.path().join("successor.db");
        let key = DatabaseKey::from_bytes([206; 32]);
        let original = std::fs::read(&fixture.restored).unwrap();
        reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &path, &key).unwrap();
        reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &path, &key).unwrap();
        let copy = crate::open_encrypted(&path, &key).unwrap();
        let cells: (i64, i64, f64, String, Vec<u8>, Option<i64>) = copy.connection().query_row(
            "SELECT rowid,integer_cell,real_cell,text_cell,blob_cell,null_cell FROM arbitrary WHERE rowid=-7", [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).unwrap();
        assert_eq!(
            cells,
            (-7, -42, 1.25, "synthetic-text".into(), vec![0, 255], None)
        );
        let sequence: (i64, i64) = copy
            .connection()
            .query_row(
                "SELECT rowid,seq FROM sqlite_sequence WHERE name='parent'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(sequence, (22, 400));
        let audit_rows: i64 = copy
            .connection()
            .query_row("SELECT count(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(audit_rows, 1);
        assert!(matches!(
            crate::open_encrypted(&fixture.restored, &fixture.restored_key),
            Err(StorageSecurityError::QuarantinedDatabase)
        ));
        assert_eq!(original, std::fs::read(&fixture.restored).unwrap());
        let before_reject = crate::tests::tree_fingerprint(fixture.directory.path());
        assert!(matches!(
            reconstruct_wallet_scan_successor(
                &fixture.source,
                &WALLET,
                &fixture.restored,
                &fixture.restored_key
            ),
            Err(BundleError::Integrity)
        ));
        assert_eq!(
            before_reject,
            crate::tests::tree_fingerprint(fixture.directory.path())
        );
        assert_eq!(original, std::fs::read(&fixture.restored).unwrap());
    }

    #[test]
    fn synthetic_wallet_retry_rejects_changed_missing_extra_rows_and_alien_schema() {
        let fixture = fixture();
        let key = DatabaseKey::from_bytes([207; 32]);
        for (index, mutation) in [
            "UPDATE arbitrary SET blob_cell=x'01' WHERE rowid=-7",
            "UPDATE arbitrary SET rowid=99 WHERE rowid=-7",
            "UPDATE arbitrary SET real_cell=CAST(real_cell AS TEXT) WHERE rowid=-7",
            "DELETE FROM arbitrary WHERE rowid=-7",
            "INSERT INTO arbitrary(rowid,integer_cell) VALUES(100,1)",
            "CREATE TABLE alien(extra TEXT)",
            "CREATE TRIGGER alien_trigger AFTER INSERT ON arbitrary BEGIN SELECT 1; END",
            "ANALYZE",
        ]
        .into_iter()
        .enumerate()
        {
            let path = fixture.directory.path().join(format!("changed-{index}.db"));
            reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &path, &key).unwrap();
            let changed = crate::open_encrypted(&path, &key).unwrap();
            changed.connection().execute_batch(mutation).unwrap();
            crate::checkpoint_and_sync(changed.connection(), &path).unwrap();
            drop(changed);
            assert!(matches!(
                reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &path, &key),
                Err(BundleError::Integrity)
            ));
        }
    }

    #[test]
    fn synthetic_wallet_retry_accepts_only_authenticated_empty_initialization() {
        let fixture = fixture();
        let key = DatabaseKey::from_bytes([208; 32]);
        let empty = fixture.directory.path().join("interrupted-empty.db");
        drop(crate::create_encrypted(&empty, &key).unwrap());
        assert!(matches!(
            crate::open_encrypted(&empty, &key),
            Err(StorageSecurityError::UninitializedDatabase)
        ));
        reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &empty, &key).unwrap();

        let before_wrong_key = std::fs::read(&empty).unwrap();
        let original_source = std::fs::read(&fixture.restored).unwrap();
        assert!(matches!(
            reconstruct_wallet_scan_successor(
                &fixture.source,
                &WALLET,
                &empty,
                &DatabaseKey::from_bytes([210; 32]),
            ),
            Err(BundleError::Storage)
        ));
        assert_eq!(before_wrong_key, std::fs::read(&empty).unwrap());
        assert_eq!(original_source, std::fs::read(&fixture.restored).unwrap());
        reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &empty, &key).unwrap();
        assert!(matches!(
            crate::open_encrypted(&fixture.restored, &fixture.restored_key),
            Err(StorageSecurityError::QuarantinedDatabase)
        ));

        let alien = fixture.directory.path().join("alien.db");
        let initialized = crate::create_encrypted(&alien, &key).unwrap();
        initialized
            .connection()
            .execute_batch("CREATE TABLE alien(id INTEGER)")
            .unwrap();
        drop(initialized);
        assert!(matches!(
            reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &alien, &key),
            Err(BundleError::Integrity)
        ));

        let zero = fixture.directory.path().join("unauthenticated-zero.db");
        std::fs::File::create(&zero).unwrap();
        std::fs::set_permissions(&zero, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(reconstruct_wallet_scan_successor(&fixture.source, &WALLET, &zero, &key).is_err());
        assert_eq!(std::fs::metadata(zero).unwrap().len(), 0);
    }

    #[test]
    fn synthetic_wallet_rejects_wrong_kind_version_and_schema_before_creation() {
        let fixture = fixture();
        let key = DatabaseKey::from_bytes([209; 32]);
        static WRONG_VERSION: JournalTemplate = JournalTemplate {
            schema_version: 4,
            ..WALLET
        };
        static WRONG_SCHEMA: JournalTemplate = JournalTemplate {
            kind: JournalKind::WalletScan,
            application_id: 0x57505754,
            schema_version: 3,
            create_sql: "CREATE TABLE different(id INTEGER PRIMARY KEY)",
        };
        for (index, template) in [&ANCHOR, &WRONG_VERSION, &WRONG_SCHEMA]
            .into_iter()
            .enumerate()
        {
            let path = fixture.directory.path().join(format!("invalid-{index}.db"));
            assert!(matches!(
                reconstruct_wallet_scan_successor(&fixture.source, template, &path, &key),
                Err(BundleError::Unsupported)
            ));
            assert!(!path.exists());
        }
    }
}
