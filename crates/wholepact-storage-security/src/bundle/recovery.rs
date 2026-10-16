//! Authenticated immutable recovery material. This is historical evidence only:
//! the source types never clear quarantine or establish freshness. Fixed-kind
//! reconstruction retains separate evidence; generation integrity proofs never
//! establish native consent, signer continuity, or whole-host publication.
use super::*;
pub(crate) mod archive;
pub mod evidence;
pub mod generation;
pub mod wallet;
pub mod wallet_templates;
use zeroize::Zeroize;
const QUARANTINE_SCHEMA: &str = "CREATE TABLE wholepact_bundle_quarantine(singleton INTEGER PRIMARY KEY CHECK(singleton=1), bundle_digest TEXT NOT NULL, component_id TEXT NOT NULL, original_application_id INTEGER NOT NULL, original_schema_version INTEGER NOT NULL, recovery_required INTEGER NOT NULL CHECK(recovery_required=1));";

/// No Debug or serialization: these values can contain private signer history.
pub enum RecoveryCell {
    Null,
    Integer(i64),
    RealBits(u64),
    Text(String),
    Blob(Vec<u8>),
}
impl Drop for RecoveryCell {
    fn drop(&mut self) {
        match self {
            Self::Text(value) => value.zeroize(),
            Self::Blob(value) => value.zeroize(),
            _ => (),
        }
    }
}
pub struct RecoveryRow {
    rowid: Option<i64>,
    cells: Vec<RecoveryCell>,
}
impl RecoveryRow {
    pub fn rowid(&self) -> Option<i64> {
        self.rowid
    }
    pub fn cells(&self) -> &[RecoveryCell] {
        &self.cells
    }
}
pub struct RecoveryTable {
    name: String,
    columns: Vec<String>,
    rows: Vec<RecoveryRow>,
    has_rowid: bool,
}
impl RecoveryTable {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn columns(&self) -> &[String] {
        &self.columns
    }
    pub fn rows(&self) -> &[RecoveryRow] {
        &self.rows
    }
    pub fn has_rowid(&self) -> bool {
        self.has_rowid
    }
}

/// Exact provenance of the immutable inventory, not an activation credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProvenance {
    pub profile_id: String,
    pub checkpoint_id: String,
    pub bundle_digest: String,
    pub component_id: String,
    pub kind: JournalKind,
    pub component_digest: String,
    pub application_id: i64,
    pub schema_version: i64,
    pub rows: usize,
}

/// Construction authenticates BOTH the encrypted archive and exact restored
/// component against the supplied executable-owned schema. All returned rows
/// originate from that complete authenticated inventory. No mutable connection,
/// generic query, raw SQL, or public constructor is available.
pub struct VerifiedRecoveryComponent {
    provenance: RecoveryProvenance,
    manifest: BundleManifest,
    tables: Vec<RecoveryTable>,
}
impl VerifiedRecoveryComponent {
    /// The caller must hold the owning recovery/profile locks and keep archive
    /// and component file sets quiescent throughout open. Metadata checks reject
    /// detected changes but cannot replace external writer exclusion. SQLite
    /// reads private encrypted copies, including committed WAL frames, so even
    /// original SHM sidecars and absent sidecars are preserved.
    pub fn open(
        request: history::HistoryOpenRequest<'_>,
        template: &'static JournalTemplate,
    ) -> Result<Self> {
        identifier(request.component_id)?;
        bounded_file(request.archive)?;
        bounded_file(request.restored_component)?;
        let archive = crate::open_encrypted_read_only(request.archive, request.archive_key)?;
        archive.execute_batch("BEGIN DEFERRED;")?;
        let manifest = validate_archive(&archive)?;
        let component = manifest
            .components
            .iter()
            .find(|c| c.id == request.component_id)
            .ok_or(BundleError::Invalid)?;
        validate_component_template(component, template)?;
        let restored =
            crate::open_encrypted_read_only(request.restored_component, request.restored_key)?;
        restored.execute_batch("BEGIN DEFERRED;")?;
        let application: i64 = restored.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = restored.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != QUARANTINE_APPLICATION_ID || version != component.schema_version {
            return Err(BundleError::Integrity);
        }
        let reference = Connection::open_in_memory()?;
        reference.execute_batch(template.create_sql)?;
        reference.execute_batch(QUARANTINE_SCHEMA)?;
        if schema(&restored)? != schema(&reference)? {
            return Err(BundleError::Integrity);
        }
        let marker: (String, String, i64, i64, i64) = restored.query_row(
            "SELECT bundle_digest,component_id,original_application_id,original_schema_version,recovery_required FROM wholepact_bundle_quarantine WHERE singleton=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        let markers: i64 = restored.query_row(
            "SELECT count(*) FROM wholepact_bundle_quarantine",
            [],
            |r| r.get(0),
        )?;
        if markers != 1
            || marker
                != (
                    manifest.digest.clone(),
                    component.id.clone(),
                    component.application_id,
                    component.schema_version,
                    1,
                )
        {
            return Err(BundleError::Integrity);
        }
        integrity(&restored)?;
        verify_restored_rows(&restored, component)?;
        let mut tables = Vec::new();
        for table in &component.tables {
            let mut statement = archive.prepare("SELECT payload FROM bundle_rows WHERE component=?1 AND table_name=?2 ORDER BY row_number")?;
            let mut query = statement.query(params![component.id, table.name])?;
            let mut rows = Vec::new();
            while let Some(row) = query.next()? {
                let bytes = zeroize::Zeroizing::new(row.get::<_, Vec<u8>>(0)?);
                let row: Row =
                    serde_json::from_slice(&bytes).map_err(|_| BundleError::Integrity)?;
                validate_row(&row, table)?;
                rows.push(RecoveryRow {
                    rowid: row.rowid,
                    cells: row
                        .cells
                        .into_iter()
                        .map(|v| match v {
                            Cell::Null => RecoveryCell::Null,
                            Cell::Integer(v) => RecoveryCell::Integer(v),
                            Cell::Real(v) => RecoveryCell::RealBits(v),
                            Cell::Text(v) => RecoveryCell::Text(v),
                            Cell::Blob(v) => RecoveryCell::Blob(v),
                        })
                        .collect(),
                });
            }
            if rows.len() != table.rows {
                return Err(BundleError::Integrity);
            }
            tables.push(RecoveryTable {
                name: table.name.clone(),
                columns: table.columns.clone(),
                rows,
                has_rowid: table.rowid,
            });
        }
        let provenance = RecoveryProvenance {
            profile_id: manifest.profile_id.clone(),
            checkpoint_id: manifest.checkpoint_id.clone(),
            bundle_digest: manifest.digest.clone(),
            component_id: component.id.clone(),
            kind: component.kind,
            component_digest: component.digest.clone(),
            application_id: component.application_id,
            schema_version: component.schema_version,
            rows: component.rows,
        };
        Ok(Self {
            provenance,
            manifest,
            tables,
        })
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }
    pub fn tables(&self) -> &[RecoveryTable] {
        &self.tables
    }
}

/// Signer-specific wrapper prevents a wallet or host component from being
/// mistaken for signer originals by the native activation protocol.
pub struct VerifiedSignerRecoverySource(
    VerifiedRecoveryComponent,
    Option<VerifiedRecoveryComponent>,
);
impl VerifiedSignerRecoverySource {
    pub fn open(
        request: history::HistoryOpenRequest<'_>,
        template: &'static JournalTemplate,
    ) -> Result<Self> {
        if template.kind != JournalKind::SignerConsentAuthority {
            return Err(BundleError::Unsupported);
        }
        Ok(Self(
            VerifiedRecoveryComponent::open(request, template)?,
            None,
        ))
    }
    /// Attach only authenticated wallet history from the exact same inventory.
    /// This grants no wallet freshness or authorization capability.
    pub fn with_wallet(mut self, wallet: VerifiedRecoveryComponent) -> Result<Self> {
        if self.1.is_some()
            || wallet.provenance().kind != JournalKind::WalletScan
            || wallet.manifest() != self.manifest()
        {
            return Err(BundleError::Integrity);
        }
        self.1 = Some(wallet);
        Ok(self)
    }
    pub fn wallet(&self) -> Option<&VerifiedRecoveryComponent> {
        self.1.as_ref()
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        self.0.provenance()
    }
    pub fn manifest(&self) -> &BundleManifest {
        self.0.manifest()
    }
    pub fn tables(&self) -> &[RecoveryTable] {
        self.0.tables()
    }
    /// Every column is retained. The signer must validate the semantic payload.
    pub fn original_consents(&self) -> Result<&RecoveryTable> {
        self.table("signer_original_consents")
    }
    pub fn remote_exposures(&self) -> Result<&RecoveryTable> {
        self.table("signer_remote_exposures")
    }
    pub fn account(&self) -> Result<&RecoveryTable> {
        self.table("signer_account")
    }
    fn table(&self, name: &str) -> Result<&RecoveryTable> {
        self.tables()
            .iter()
            .find(|t| t.name == name)
            .ok_or(BundleError::Unsupported)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    struct Adapter(crate::EncryptedConnection);
    impl JournalAdapter for Adapter {
        fn template(&self) -> &'static JournalTemplate {
            &SIGNER
        }
        fn read_locked(
            &self,
            permit: &BackupReadPermit<'_>,
            visitor: &mut dyn FnMut(&Connection) -> Result<()>,
        ) -> Result<()> {
            permit.check(self)?;
            visitor(self.0.connection())
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
            "synthetic-checkpoint"
        }
    }
    static SIGNER: JournalTemplate = JournalTemplate {
        kind: JournalKind::SignerConsentAuthority,
        application_id: 0x57505343,
        schema_version: 8,
        create_sql: "CREATE TABLE signer_account(singleton INTEGER PRIMARY KEY,account_id TEXT,writer_epoch INTEGER,recovery_required INTEGER); CREATE TABLE signer_original_consents(reference TEXT PRIMARY KEY,payload TEXT); CREATE TABLE signer_remote_exposures(authorization_id TEXT PRIMARY KEY,payload TEXT); CREATE TABLE retained_results(id TEXT PRIMARY KEY,bytes BLOB);",
    };
    #[test]
    fn synthetic_verified_signer_rows_preserve_all_tables_and_never_activate_source() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = DatabaseKey::from_bytes([171; 32]);
        let archive_key = DatabaseKey::from_bytes([172; 32]);
        let restored_key = DatabaseKey::from_bytes([173; 32]);
        let source = Adapter(create_encrypted(dir.path().join("source.db"), &key).unwrap());
        source
            .0
            .connection()
            .execute_batch(SIGNER.create_sql)
            .unwrap();
        source
            .0
            .connection()
            .pragma_update(None, "application_id", SIGNER.application_id)
            .unwrap();
        source
            .0
            .connection()
            .pragma_update(None, "user_version", SIGNER.schema_version)
            .unwrap();
        source.0.connection().execute_batch("INSERT INTO signer_account VALUES(1,'synthetic-account',3,0); INSERT INTO signer_original_consents VALUES('synthetic-original','{}'); INSERT INTO retained_results VALUES('synthetic-result',x'010203');").unwrap();
        let registered = RegisteredJournal::new("signer", &source).unwrap();
        let gate = Gate;
        let coverage = Coverage {
            present: BTreeMap::from([(JournalKind::SignerConsentAuthority, vec!["signer".into()])]),
            absent: KINDS
                .into_iter()
                .filter(|k| *k != JournalKind::SignerConsentAuthority)
                .collect(),
        };
        let archive = dir.path().join("archive.db");
        let restored = dir.path().join("restored.db");
        let manifest = snapshot(SnapshotRequest {
            principal_id: "admin",
            profile_id: "profile",
            coverage,
            sources: &[registered],
            destination: &archive,
            key: &archive_key,
            authority: &gate,
        })
        .unwrap();
        restore(RestoreRequest {
            principal_id: "admin",
            profile_id: "profile",
            archive: &archive,
            key: &archive_key,
            targets: &[RestoreTarget {
                component_id: "signer",
                template: &SIGNER,
                destination: &restored,
                key: &restored_key,
            }],
            authority: &gate,
        })
        .unwrap();
        let open = || {
            VerifiedSignerRecoverySource::open(
                history::HistoryOpenRequest {
                    archive: &archive,
                    archive_key: &archive_key,
                    component_id: "signer",
                    restored_component: &restored,
                    restored_key: &restored_key,
                },
                &SIGNER,
            )
        };
        let before = crate::tests::tree_fingerprint(dir.path());
        static WRONG_VERSION: JournalTemplate = JournalTemplate {
            kind: JournalKind::SignerConsentAuthority,
            application_id: 0x57505343,
            schema_version: 9,
            create_sql: SIGNER.create_sql,
        };
        let request = || history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "signer",
            restored_component: &restored,
            restored_key: &restored_key,
        };
        assert!(matches!(
            VerifiedSignerRecoverySource::open(request(), &WRONG_VERSION),
            Err(BundleError::Unsupported)
        ));
        let generic = VerifiedRecoveryComponent::open(request(), &SIGNER).unwrap();
        assert_eq!(
            generic.provenance().kind,
            JournalKind::SignerConsentAuthority
        );
        assert_eq!(generic.manifest().coverage, manifest.coverage);
        let verified = open().unwrap();
        assert_eq!(verified.provenance().bundle_digest, manifest.digest);
        assert_eq!(verified.tables().len(), 4);
        assert_eq!(verified.original_consents().unwrap().rows().len(), 1);
        assert_eq!(verified.remote_exposures().unwrap().rows().len(), 0);
        let result = verified
            .tables()
            .iter()
            .find(|t| t.name() == "retained_results")
            .unwrap();
        assert!(
            matches!(&result.rows()[0].cells()[1], RecoveryCell::Blob(bytes) if bytes == &[1,2,3])
        );
        assert_eq!(before, crate::tests::tree_fingerprint(dir.path()));
        assert!(matches!(
            crate::open_encrypted(&restored, &restored_key),
            Err(StorageSecurityError::QuarantinedDatabase)
        ));
        // Altered payloads cannot be laundered through otherwise correct markers.
        let changed = crate::open_quarantined(&restored, &restored_key).unwrap();
        // Keep committed frames in WAL. Readers must include those frames while
        // leaving the complete original source tree, including SHM, unchanged.
        changed
            .connection()
            .execute_batch("PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        changed
            .connection()
            .execute("UPDATE retained_results SET bytes=x'010203'", [])
            .unwrap();
        let with_wal = crate::tests::tree_fingerprint(dir.path());
        assert!(open().is_ok());
        assert_eq!(with_wal, crate::tests::tree_fingerprint(dir.path()));
        changed
            .connection()
            .execute("UPDATE retained_results SET bytes=x'04'", [])
            .unwrap();
        let with_changed_wal = crate::tests::tree_fingerprint(dir.path());
        assert!(matches!(open(), Err(BundleError::Integrity)));
        assert_eq!(with_changed_wal, crate::tests::tree_fingerprint(dir.path()));
    }
}
