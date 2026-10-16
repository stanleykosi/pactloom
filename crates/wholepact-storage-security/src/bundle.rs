//! Consistent, bounded encrypted logical multi-journal archives. The trusted host
//! supplies a real whole-profile quiescence/admin lease and compiled templates.
//! Archive schema text is inert evidence: restoration never executes imported SQL.
pub mod history;
pub mod recovery;

use crate::{create_encrypted, DatabaseKey, StorageSecurityError};
use rusqlite::{
    params, params_from_iter,
    types::{Value, ValueRef},
    Connection, OptionalExtension,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

pub const QUARANTINE_APPLICATION_ID: i64 = 0x57505152;
const ARCHIVE_ID: i64 = 0x5750424d;
const STAGING_ID: i64 = 0x57504250;
const FORMAT: u32 = 1;
const MAX_COMPONENTS: usize = 64;
const MAX_OBJECTS: usize = 256;
const MAX_ROWS: usize = 100_000;
const MAX_CELL: usize = 4 * 1024 * 1024;
const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = crate::read_snapshot::MAX_SNAPSHOT_BYTES;
const ARCHIVE_SCHEMA: &str = "CREATE TABLE bundle_manifest(singleton INTEGER PRIMARY KEY CHECK(singleton=1), manifest BLOB NOT NULL); CREATE TABLE bundle_rows(component TEXT NOT NULL, table_name TEXT NOT NULL, row_number INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(component,table_name,row_number));";

type Result<T> = std::result::Result<T, BundleError>;
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("multi-journal backup permission or quiescence is unavailable")]
    Permission,
    #[error("backup read permit does not match the exact registered adapter")]
    SourceBinding,
    #[error("multi-journal backup scope, inventory or schema is invalid")]
    Invalid,
    #[error("multi-journal backup exceeds its bounded resource profile")]
    Limit,
    #[error("multi-journal backup integrity verification failed")]
    Integrity,
    #[error("multi-journal backup version or component is unsupported")]
    Unsupported,
    #[error("encrypted multi-journal storage failed; partial encrypted output may exist")]
    Storage,
    #[error("permission changed; encrypted output may exist and remains quarantined")]
    PermissionChanged,
}
impl From<rusqlite::Error> for BundleError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<StorageSecurityError> for BundleError {
    fn from(_: StorageSecurityError) -> Self {
        Self::Storage
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalKind {
    CoordinationAuthority,
    SignerConsentAuthority,
    WalletScan,
    ProofWitness,
    SignedResults,
    ExactTransactions,
    Submission,
    TransportInbox,
    TransportOutbox,
}
const KINDS: [JournalKind; 9] = [
    JournalKind::CoordinationAuthority,
    JournalKind::SignerConsentAuthority,
    JournalKind::WalletScan,
    JournalKind::ProofWitness,
    JournalKind::SignedResults,
    JournalKind::ExactTransactions,
    JournalKind::Submission,
    JournalKind::TransportInbox,
    JournalKind::TransportOutbox,
];

/// Only executable-owned constant SQL may appear here. Templates are never read
/// from an archive, a filesystem configuration, a network request or user text.
/// Use the current compiled journal schema, including all indexes and triggers.
pub struct JournalTemplate {
    pub kind: JournalKind,
    pub application_id: i64,
    pub schema_version: i64,
    pub create_sql: &'static str,
}

/// Authenticate a source-preserving snapshot against an executable-owned
/// ordinary journal schema. No source is opened through SQLite, migrated, or
/// checkpointed. Restored and generation identities remain rejected by this
/// ordinary reader; their dedicated immutable readers must be used instead.
/// The caller must retain the owning locks and exclude writers for capture.
pub fn open_journal_read_snapshot(
    path: &Path,
    key: &DatabaseKey,
    template: &'static JournalTemplate,
) -> Result<crate::EncryptedReadSnapshot> {
    let expected = template_schema(template)?;
    let snapshot = crate::open_encrypted_read_snapshot(path, key)?;
    let connection = snapshot.connection();
    connection.execute_batch("BEGIN DEFERRED;")?;
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != template.application_id
        || version != template.schema_version
        || schema(connection)? != expected
    {
        return Err(BundleError::Unsupported);
    }
    integrity(connection)?;
    Ok(snapshot)
}
/// Trusted adapter over the actual enrolled open journal; callbacks must retain
/// its database mutex. No adapter may open an arbitrary caller-selected path.
/// The profile lease must stop all writers and external-effect workers, including
/// independent connections, for the full snapshot, not just each callback.
pub trait JournalAdapter {
    fn template(&self) -> &'static JournalTemplate;
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<()>,
    ) -> Result<()>;
}
/// Unforgeable, non-cloneable, exact-source read permission. Only `snapshot`
/// creates one while the profile authority/quiescence lease is alive. Adapters
/// must check their exact self before exposing their connection to the visitor.
pub struct BackupReadPermit<'a> {
    registered: &'a RegisteredJournal<'a>,
    lease: &'a dyn BundleLease,
}
impl BackupReadPermit<'_> {
    pub fn check<T: JournalAdapter>(&self, adapter: &T) -> Result<()> {
        // Both sides capture a concrete Sized T in non-overridable generic code.
        // Do not add a dyn registration overload or a virtual caller-supplied tag.
        // The private registration retains its nonce and borrowed source lifetime.
        // A first-field wrapper shares an address but has a different concrete T.
        // Type names are local to this pinned executable graph, never wire identity.
        if self.registered.concrete_type != std::any::type_name::<T>()
            || !std::ptr::addr_eq(self.registered.adapter, adapter as &dyn JournalAdapter)
        {
            return Err(BundleError::SourceBinding);
        }
        self.lease.check_current()
    }
}

#[derive(Clone)]
pub struct JournalBinding(Arc<()>);
impl PartialEq for JournalBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for JournalBinding {}
impl std::fmt::Debug for JournalBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JournalBinding([opaque])")
    }
}
/// Registration is an identity handle, not an enrollment or permission grant.
pub struct RegisteredJournal<'a> {
    id: String,
    adapter: &'a dyn JournalAdapter,
    concrete_type: &'static str,
    binding: JournalBinding,
}
impl<'a> RegisteredJournal<'a> {
    pub fn new<T: JournalAdapter>(id: &str, adapter: &'a T) -> Result<Self> {
        identifier(id)?;
        Ok(Self {
            id: id.into(),
            adapter,
            concrete_type: std::any::type_name::<T>(),
            binding: JournalBinding(Arc::new(())),
        })
    }
    pub fn binding(&self) -> JournalBinding {
        self.binding.clone()
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub present: BTreeMap<JournalKind, Vec<String>>,
    /// A trusted profile inventory attests these components never existed or are
    /// inapplicable. "Missing" or "lost" cannot be declared absent.
    pub absent: BTreeSet<JournalKind>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleAction {
    Snapshot,
    Restore,
    TestRestore,
}
pub struct BundleScope<'a> {
    pub principal_id: &'a str,
    pub profile_id: &'a str,
    pub action: BundleAction,
    pub archive: &'a Path,
    pub destinations: &'a [PathBuf],
    pub coverage: &'a Coverage,
    pub sources: &'a [(String, JournalBinding)],
    pub retention: &'static str,
    pub wallet_spending_secrets_included: bool,
    pub private_viewing_witness_and_correlation_data_may_be_included: bool,
}
pub trait BundleLease {
    /// Must stay current while held; implementations must synchronize actual
    /// revocation and ALL participating writers/external effects. Rechecks alone
    /// cannot establish a consistent checkpoint or concurrent revocation safety.
    fn check_current(&self) -> Result<()>;
    fn checkpoint_id(&self) -> &str;
}
pub trait BundleAuthority {
    fn acquire<'a>(&'a self, scope: &BundleScope<'_>) -> Result<Box<dyn BundleLease + 'a>>;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaObject {
    kind: String,
    name: String,
    table: String,
    sql: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableManifest {
    name: String,
    columns: Vec<String>,
    rowid: bool,
    rows: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentManifest {
    pub id: String,
    pub kind: JournalKind,
    pub application_id: i64,
    pub schema_version: i64,
    pub rows: usize,
    pub logical_bytes: usize,
    pub digest: String,
    schema: Vec<SchemaObject>,
    tables: Vec<TableManifest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub format_version: u32,
    pub profile_id: String,
    pub checkpoint_id: String,
    pub coverage: Coverage,
    pub components: Vec<ComponentManifest>,
    pub digest: String,
    pub wallet_spending_secrets_included: bool,
    pub private_viewing_witness_and_correlation_data_may_be_included: bool,
    pub writer_freshness_established: bool,
    pub restore_requires_recovery: bool,
}
/// Metadata is private full-profile administration data, not scoped-reader output.
#[derive(Clone, Debug, Serialize)]
pub struct BundleRestoreReport {
    pub manifest: BundleManifest,
    pub restored_components: usize,
    pub integrity_verified: bool,
    pub all_components_quarantined: bool,
    pub authorization_allowed: bool,
    pub signer_recovered: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum Cell {
    Null,
    Integer(i64),
    Real(u64),
    Text(String),
    Blob(Vec<u8>),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    rowid: Option<i64>,
    cells: Vec<Cell>,
}

pub struct SnapshotRequest<'a> {
    pub principal_id: &'a str,
    pub profile_id: &'a str,
    pub coverage: Coverage,
    pub sources: &'a [RegisteredJournal<'a>],
    pub destination: &'a Path,
    pub key: &'a DatabaseKey,
    pub authority: &'a dyn BundleAuthority,
}

pub fn snapshot(request: SnapshotRequest<'_>) -> Result<BundleManifest> {
    identifier(request.principal_id)?;
    identifier(request.profile_id)?;
    private_path(request.destination)?;
    validate_coverage(&request.coverage)?;
    let sources: Vec<_> = request
        .sources
        .iter()
        .map(|s| (s.id.clone(), s.binding()))
        .collect();
    if sources.len() > MAX_COMPONENTS {
        return Err(BundleError::Limit);
    }
    let mut supplied = BTreeMap::<JournalKind, Vec<String>>::new();
    let mut ids = BTreeSet::new();
    for source in request.sources {
        if !ids.insert(source.id.clone()) {
            return Err(BundleError::Invalid);
        }
        supplied
            .entry(source.adapter.template().kind)
            .or_default()
            .push(source.id.clone());
    }
    for ids in supplied.values_mut() {
        ids.sort();
    }
    if supplied != request.coverage.present {
        return Err(BundleError::Invalid);
    }
    let scope = BundleScope {
        principal_id: request.principal_id,
        profile_id: request.profile_id,
        action: BundleAction::Snapshot,
        archive: request.destination,
        destinations: &[],
        coverage: &request.coverage,
        sources: &sources,
        retention: "local-only; retain until deliberately removed",
        wallet_spending_secrets_included: false,
        private_viewing_witness_and_correlation_data_may_be_included: true,
    };
    let lease = request.authority.acquire(&scope)?;
    lease.check_current()?;
    identifier(lease.checkpoint_id())?;
    let mut output = create_encrypted(request.destination, request.key)?.into_connection();
    output.pragma_update(None, "application_id", STAGING_ID)?;
    output.pragma_update(None, "max_page_count", 131072)?;
    let tx = output.transaction()?;
    tx.execute_batch(ARCHIVE_SCHEMA)?;
    let mut components = Vec::new();
    let mut total = 0usize;
    for source in request.sources {
        lease.check_current()?;
        let mut called = false;
        let permit = BackupReadPermit {
            registered: source,
            lease: lease.as_ref(),
        };
        source.adapter.read_locked(&permit, &mut |connection| {
            if called {
                return Err(BundleError::Invalid);
            }
            called = true;
            let component = copy_source(connection, source.adapter.template(), &source.id, &tx)?;
            total = total
                .checked_add(component.logical_bytes)
                .ok_or(BundleError::Limit)?;
            if total > MAX_BUNDLE_BYTES {
                return Err(BundleError::Limit);
            }
            components.push(component);
            Ok(())
        })?;
        if !called {
            return Err(BundleError::Invalid);
        }
    }
    lease.check_current()?;
    components.sort_by(|a, b| a.id.cmp(&b.id));
    let mut manifest = BundleManifest {
        format_version: FORMAT,
        profile_id: request.profile_id.into(),
        checkpoint_id: lease.checkpoint_id().into(),
        coverage: request.coverage,
        components,
        digest: String::new(),
        wallet_spending_secrets_included: false,
        private_viewing_witness_and_correlation_data_may_be_included: true,
        writer_freshness_established: false,
        restore_requires_recovery: true,
    };
    manifest.digest = manifest_digest(&manifest)?;
    tx.execute(
        "INSERT INTO bundle_manifest VALUES(1,?1)",
        [encode(&manifest)?],
    )?;
    tx.pragma_update(None, "application_id", ARCHIVE_ID)?;
    tx.pragma_update(None, "user_version", FORMAT)?;
    tx.commit()?;
    crate::checkpoint_and_sync(&output, request.destination)?;
    drop(output);
    lease
        .check_current()
        .map_err(|_| BundleError::PermissionChanged)?;
    let verified = inspect(request.destination, request.key)?;
    lease
        .check_current()
        .map_err(|_| BundleError::PermissionChanged)?;
    Ok(verified)
}

fn copy_source(
    source: &Connection,
    template: &JournalTemplate,
    id: &str,
    output: &Connection,
) -> Result<ComponentManifest> {
    crate::verify_runtime(source)?;
    crate::verify_cipher_integrity(source)?;
    let read = source.unchecked_transaction()?;
    let application_id: i64 = read.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = read.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application_id != template.application_id || version != template.schema_version {
        return Err(BundleError::Unsupported);
    }
    let expected = template_schema(template)?;
    let schema = schema(&read)?;
    if schema != expected {
        return Err(BundleError::Unsupported);
    }
    integrity(&read)?;
    let mut tables = Vec::new();
    let mut rows = 0usize;
    let mut bytes = 0usize;
    let mut hash = Sha256::new();
    hash.update(b"wholepact.bundle.component.v1\0");
    hash.update(encode(&schema)?);
    for object in schema.iter().filter(|o| o.kind == "table") {
        let mut table = table_manifest(&read, &object.name)?;
        let columns = table
            .columns
            .iter()
            .map(|c| quote(c))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let sql = format!(
            "SELECT {}{} FROM {}",
            if table.rowid { "rowid," } else { "" },
            columns,
            quote(&table.name)?
        );
        let mut statement = read.prepare(&sql)?;
        let mut query = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = query.next()? {
            let offset = usize::from(table.rowid);
            let mut cells = Vec::new();
            for index in 0..table.columns.len() {
                cells.push(match row.get_ref(index + offset)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(x) => Cell::Integer(x),
                    ValueRef::Real(x) => {
                        if !x.is_finite() {
                            return Err(BundleError::Unsupported);
                        }
                        Cell::Real(x.to_bits())
                    }
                    ValueRef::Text(x) => {
                        if x.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        Cell::Text(
                            std::str::from_utf8(x)
                                .map_err(|_| BundleError::Integrity)?
                                .to_owned(),
                        )
                    }
                    ValueRef::Blob(x) => {
                        if x.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        Cell::Blob(x.to_vec())
                    }
                });
            }
            let data = encode(&Row {
                rowid: if table.rowid { Some(row.get(0)?) } else { None },
                cells,
            })?;
            bytes = bytes.checked_add(data.len()).ok_or(BundleError::Limit)?;
            rows += 1;
            if bytes > MAX_COMPONENT_BYTES || rows > MAX_ROWS {
                return Err(BundleError::Limit);
            }
            encoded_rows.push(data);
        }
        // Stable typed order works for WITHOUT ROWID tables too. Hidden rowids are
        // retained explicitly rather than silently renumbered during recovery.
        encoded_rows.sort();
        table.rows = encoded_rows.len();
        hash.update(encode(&table)?);
        for (number, data) in encoded_rows.iter().enumerate() {
            hash.update((data.len() as u64).to_be_bytes());
            hash.update(data);
            output.execute(
                "INSERT INTO bundle_rows VALUES(?1,?2,?3,?4)",
                params![id, table.name, number as i64, data],
            )?;
        }
        tables.push(table);
    }
    read.commit()?;
    Ok(ComponentManifest {
        id: id.into(),
        kind: template.kind,
        application_id,
        schema_version: version,
        rows,
        logical_bytes: bytes,
        digest: hex_digest(hash),
        schema,
        tables,
    })
}

/// Inspect a private encrypted copy without changing archive sidecars. The
/// caller must keep the archive file set quiescent under its owning locks.
pub fn inspect(path: &Path, key: &DatabaseKey) -> Result<BundleManifest> {
    bounded_file(path)?;
    let source = crate::open_encrypted_read_only(path, key)?;
    let read = source.unchecked_transaction()?;
    let manifest = validate_archive(&read)?;
    read.commit()?;
    Ok(manifest)
}
fn validate_archive(source: &Connection) -> Result<BundleManifest> {
    let app: i64 = source.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: u32 = source.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app != ARCHIVE_ID || version != FORMAT {
        return Err(BundleError::Unsupported);
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(ARCHIVE_SCHEMA)?;
    if schema(source)? != schema(&reference)? {
        return Err(BundleError::Integrity);
    }
    integrity(source)?;
    let encoded: Vec<u8> = source.query_row(
        "SELECT manifest FROM bundle_manifest WHERE singleton=1 AND length(manifest)<=1048576",
        [],
        |r| r.get(0),
    )?;
    let manifest: BundleManifest =
        serde_json::from_slice(&encoded).map_err(|_| BundleError::Integrity)?;
    identifier(&manifest.profile_id)?;
    identifier(&manifest.checkpoint_id)?;
    validate_coverage(&manifest.coverage)?;
    if manifest.format_version != FORMAT
        || manifest.components.is_empty()
        || manifest.components.len() > MAX_COMPONENTS
        || manifest.wallet_spending_secrets_included
        || !manifest.private_viewing_witness_and_correlation_data_may_be_included
        || manifest.writer_freshness_established
        || !manifest.restore_requires_recovery
        || manifest.digest != manifest_digest(&manifest)?
    {
        return Err(BundleError::Integrity);
    }
    let mut actual = BTreeMap::<JournalKind, Vec<String>>::new();
    let mut ids = BTreeSet::new();
    let mut total = 0usize;
    let mut all_rows = 0usize;
    for component in &manifest.components {
        identifier(&component.id)?;
        if !ids.insert(&component.id)
            || component.schema.len() > MAX_OBJECTS
            || component.tables.len() > MAX_OBJECTS
        {
            return Err(BundleError::Integrity);
        }
        let expected_tables: Vec<_> = component
            .schema
            .iter()
            .filter(|o| o.kind == "table")
            .map(|o| o.name.as_str())
            .collect();
        let declared_tables: Vec<_> = component.tables.iter().map(|t| t.name.as_str()).collect();
        if declared_tables != expected_tables {
            return Err(BundleError::Integrity);
        }
        actual
            .entry(component.kind)
            .or_default()
            .push(component.id.clone());
        let mut hash = Sha256::new();
        hash.update(b"wholepact.bundle.component.v1\0");
        hash.update(encode(&component.schema)?);
        let mut count = 0usize;
        let mut bytes = 0usize;
        let mut names = BTreeSet::new();
        for table in &component.tables {
            identifier(&table.name)?;
            if !names.insert(&table.name)
                || table.columns.is_empty()
                || table.columns.len() > 64
                || table.rows > MAX_ROWS
            {
                return Err(BundleError::Integrity);
            }
            for column in &table.columns {
                identifier(column)?;
            }
            hash.update(encode(table)?);
            let mut stmt=source.prepare("SELECT row_number,payload FROM bundle_rows WHERE component=?1 AND table_name=?2 ORDER BY row_number")?;
            let mut query = stmt.query(params![component.id, table.name])?;
            let mut n = 0usize;
            while let Some(row) = query.next()? {
                let seq: i64 = row.get(0)?;
                let payload = row.get_ref(1)?;
                let payload = payload.as_blob().map_err(|_| BundleError::Integrity)?;
                if seq != n as i64 || payload.len() > MAX_COMPONENT_BYTES {
                    return Err(BundleError::Integrity);
                }
                bytes = bytes.checked_add(payload.len()).ok_or(BundleError::Limit)?;
                count += 1;
                if bytes > MAX_COMPONENT_BYTES || count > MAX_ROWS {
                    return Err(BundleError::Limit);
                }
                let parsed: Row =
                    serde_json::from_slice(payload).map_err(|_| BundleError::Integrity)?;
                validate_row(&parsed, table)?;
                hash.update((payload.len() as u64).to_be_bytes());
                hash.update(payload);
                n += 1;
            }
            if n != table.rows {
                return Err(BundleError::Integrity);
            }
        }
        if count != component.rows
            || bytes != component.logical_bytes
            || hex_digest(hash) != component.digest
        {
            return Err(BundleError::Integrity);
        }
        total = total.checked_add(bytes).ok_or(BundleError::Limit)?;
        all_rows += count;
        if total > MAX_BUNDLE_BYTES {
            return Err(BundleError::Limit);
        }
    }
    for ids in actual.values_mut() {
        ids.sort();
    }
    let stored_count: i64 =
        source.query_row("SELECT count(*) FROM bundle_rows", [], |r| r.get(0))?;
    if actual != manifest.coverage.present || stored_count != all_rows as i64 {
        return Err(BundleError::Integrity);
    }
    Ok(manifest)
}

pub struct RestoreTarget<'a> {
    pub component_id: &'a str,
    pub template: &'static JournalTemplate,
    pub destination: &'a Path,
    pub key: &'a DatabaseKey,
}
pub struct RestoreRequest<'a> {
    pub principal_id: &'a str,
    pub profile_id: &'a str,
    /// Keep this archive and its sidecars quiescent under the owning locks for
    /// the operation. SQLite only opens a private encrypted read snapshot.
    pub archive: &'a Path,
    pub key: &'a DatabaseKey,
    pub targets: &'a [RestoreTarget<'a>],
    pub authority: &'a dyn BundleAuthority,
}

pub fn restore(request: RestoreRequest<'_>) -> Result<BundleRestoreReport> {
    restore_action(request, BundleAction::Restore)
}
pub fn test_restore(request: RestoreRequest<'_>) -> Result<BundleRestoreReport> {
    restore_action(request, BundleAction::TestRestore)
}
fn restore_action(
    request: RestoreRequest<'_>,
    action: BundleAction,
) -> Result<BundleRestoreReport> {
    identifier(request.principal_id)?;
    identifier(request.profile_id)?;
    private_path(request.archive)?;
    bounded_file(request.archive)?;
    let source = crate::open_encrypted_read_only(request.archive, request.key)?;
    let read = source.unchecked_transaction()?;
    let manifest = validate_archive(&read)?;
    if manifest.profile_id != request.profile_id
        || request.targets.len() != manifest.components.len()
    {
        return Err(BundleError::Invalid);
    }
    let destinations: Vec<_> = request
        .targets
        .iter()
        .map(|t| t.destination.to_path_buf())
        .collect();
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for target in request.targets {
        private_path(target.destination)?;
        if target.destination == request.archive
            || !ids.insert(target.component_id)
            || !paths.insert(target.destination)
        {
            return Err(BundleError::Invalid);
        }
        let component = manifest
            .components
            .iter()
            .find(|c| c.id == target.component_id)
            .ok_or(BundleError::Invalid)?;
        validate_component_template(component, target.template)?;
    }
    let scope = BundleScope {
        principal_id: request.principal_id,
        profile_id: request.profile_id,
        action,
        archive: request.archive,
        destinations: &destinations,
        coverage: &manifest.coverage,
        sources: &[],
        retention: "local-only; retain until deliberately removed",
        wallet_spending_secrets_included: false,
        private_viewing_witness_and_correlation_data_may_be_included: true,
    };
    let lease = request.authority.acquire(&scope)?;
    lease.check_current()?;
    for target in request.targets {
        lease.check_current()?;
        let component = manifest
            .components
            .iter()
            .find(|c| c.id == target.component_id)
            .ok_or(BundleError::Invalid)?;
        restore_component(&read, component, target, &manifest.digest)?;
        lease
            .check_current()
            .map_err(|_| BundleError::PermissionChanged)?;
    }
    read.commit()?;
    Ok(BundleRestoreReport {
        manifest,
        restored_components: request.targets.len(),
        integrity_verified: true,
        all_components_quarantined: true,
        authorization_allowed: false,
        signer_recovered: false,
    })
}
fn restore_component(
    source: &Connection,
    component: &ComponentManifest,
    target: &RestoreTarget<'_>,
    bundle_digest: &str,
) -> Result<()> {
    let mut output = create_encrypted(target.destination, target.key)?.into_connection();
    // Persist quarantine BEFORE any schema/data import. Even interrupted outputs
    // cannot be reopened by the ordinary protected factory or live journal APIs.
    output.pragma_update(None, "application_id", QUARANTINE_APPLICATION_ID)?;
    crate::checkpoint_and_sync(&output, target.destination)?;
    output.pragma_update(None, "max_page_count", 32768)?;
    let tx = output.transaction()?;
    tx.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    tx.execute_batch(target.template.create_sql)?;
    if tx.is_autocommit() || schema(&tx)? != component.schema {
        return Err(BundleError::Integrity);
    }
    // Templates may initialize singleton metadata and immutable triggers. Temporarily
    // remove only COMPILED template triggers, clear initialization, import all rows,
    // then recreate those same trusted triggers. Never execute archive SQL.
    let trusted = template_schema(target.template)?;
    for object in trusted.iter().filter(|o| o.kind == "trigger") {
        tx.execute_batch(&format!("DROP TRIGGER {}", quote(&object.name)?))?;
    }
    for table in component.tables.iter().rev() {
        tx.execute(&format!("DELETE FROM {}", quote(&table.name)?), [])?;
    }
    let restore_tables = component
        .tables
        .iter()
        .filter(|t| t.name != "sqlite_sequence")
        .chain(
            component
                .tables
                .iter()
                .filter(|t| t.name == "sqlite_sequence"),
        );
    for table in restore_tables {
        // AUTOINCREMENT inserts may have rebuilt this internal table. Restore its
        // exact original values only after all ordinary rows, with no duplicates.
        if table.name == "sqlite_sequence" {
            tx.execute("DELETE FROM sqlite_sequence", [])?;
        }
        let columns = table
            .columns
            .iter()
            .map(|c| quote(c))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let count = table.columns.len() + usize::from(table.rowid);
        let sql = format!(
            "INSERT INTO {} ({}{}) VALUES ({})",
            quote(&table.name)?,
            if table.rowid { "rowid," } else { "" },
            columns,
            vec!["?"; count].join(",")
        );
        let mut insert = tx.prepare(&sql)?;
        let mut stmt=source.prepare("SELECT payload FROM bundle_rows WHERE component=?1 AND table_name=?2 ORDER BY row_number")?;
        let mut rows = stmt.query(params![component.id, table.name])?;
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            let row: Row = serde_json::from_slice(&bytes).map_err(|_| BundleError::Integrity)?;
            validate_row(&row, table)?;
            let mut values = Vec::new();
            if let Some(rowid) = row.rowid {
                values.push(Value::Integer(rowid));
            }
            values.extend(row.cells.into_iter().map(|v| match v {
                Cell::Null => Value::Null,
                Cell::Integer(x) => Value::Integer(x),
                Cell::Real(x) => Value::Real(f64::from_bits(x)),
                Cell::Text(x) => Value::Text(x),
                Cell::Blob(x) => Value::Blob(x),
            }));
            insert.execute(params_from_iter(values))?;
        }
    }
    for object in trusted.iter().filter(|o| o.kind == "trigger") {
        tx.execute_batch(object.sql.as_deref().ok_or(BundleError::Unsupported)?)?;
    }
    if schema(&tx)? != component.schema {
        return Err(BundleError::Integrity);
    }
    verify_restored_rows(&tx, component)?;
    tx.execute_batch("CREATE TABLE wholepact_bundle_quarantine(singleton INTEGER PRIMARY KEY CHECK(singleton=1), bundle_digest TEXT NOT NULL, component_id TEXT NOT NULL, original_application_id INTEGER NOT NULL, original_schema_version INTEGER NOT NULL, recovery_required INTEGER NOT NULL CHECK(recovery_required=1));")?;
    tx.execute(
        "INSERT INTO wholepact_bundle_quarantine VALUES(1,?1,?2,?3,?4,1)",
        params![
            bundle_digest,
            component.id,
            component.application_id,
            component.schema_version
        ],
    )?;
    tx.pragma_update(None, "application_id", QUARANTINE_APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", component.schema_version)?;
    integrity(&tx)?;
    tx.commit()?;
    crate::checkpoint_and_sync(&output, target.destination)?;
    drop(output);
    let verify = crate::open_quarantined(target.destination, target.key)?;
    integrity(verify.connection())?;
    let digest:String=verify.connection().query_row("SELECT bundle_digest FROM wholepact_bundle_quarantine WHERE singleton=1 AND recovery_required=1",[],|r|r.get(0))?;
    if digest != bundle_digest {
        return Err(BundleError::Integrity);
    }
    Ok(())
}
fn verify_restored_rows(connection: &Connection, component: &ComponentManifest) -> Result<()> {
    let mut hash = Sha256::new();
    hash.update(b"wholepact.bundle.component.v1\0");
    hash.update(encode(&component.schema)?);
    let mut total = 0usize;
    let mut count = 0usize;
    for table in &component.tables {
        let columns = table
            .columns
            .iter()
            .map(|c| quote(c))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let mut stmt = connection.prepare(&format!(
            "SELECT {}{} FROM {}",
            if table.rowid { "rowid," } else { "" },
            columns,
            quote(&table.name)?
        ))?;
        let mut query = stmt.query([])?;
        let mut encoded = Vec::new();
        while let Some(row) = query.next()? {
            let mut cells = Vec::new();
            let offset = usize::from(table.rowid);
            for index in 0..table.columns.len() {
                cells.push(match row.get_ref(index + offset)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(x) => Cell::Integer(x),
                    ValueRef::Real(x) => Cell::Real(x.to_bits()),
                    ValueRef::Text(x) => {
                        if x.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        Cell::Text(
                            std::str::from_utf8(x)
                                .map_err(|_| BundleError::Integrity)?
                                .into(),
                        )
                    }
                    ValueRef::Blob(x) => {
                        if x.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        Cell::Blob(x.to_vec())
                    }
                });
            }
            let bytes = encode(&Row {
                rowid: if table.rowid { Some(row.get(0)?) } else { None },
                cells,
            })?;
            total = total.checked_add(bytes.len()).ok_or(BundleError::Limit)?;
            count += 1;
            if total > MAX_COMPONENT_BYTES || count > MAX_ROWS {
                return Err(BundleError::Limit);
            }
            encoded.push(bytes);
        }
        if encoded.len() != table.rows {
            return Err(BundleError::Integrity);
        }
        encoded.sort();
        hash.update(encode(table)?);
        for bytes in encoded {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
    if total != component.logical_bytes
        || count != component.rows
        || hex_digest(hash) != component.digest
    {
        return Err(BundleError::Integrity);
    }
    Ok(())
}

fn validate_coverage(coverage: &Coverage) -> Result<()> {
    // A coordinator profile and an isolated signer profile have distinct keys.
    // Either authority journal can anchor a complete explicitly scoped inventory.
    if coverage.present.is_empty()
        || !(coverage
            .present
            .contains_key(&JournalKind::CoordinationAuthority)
            || coverage
                .present
                .contains_key(&JournalKind::SignerConsentAuthority))
    {
        return Err(BundleError::Invalid);
    }
    for kind in KINDS {
        match (coverage.present.get(&kind), coverage.absent.contains(&kind)) {
            (Some(ids), false) => {
                if ids.is_empty() || ids.len() > MAX_COMPONENTS {
                    return Err(BundleError::Invalid);
                }
                let mut prev = None;
                for id in ids {
                    identifier(id)?;
                    if prev.is_some_and(|p: &String| p >= id) {
                        return Err(BundleError::Invalid);
                    }
                    prev = Some(id);
                }
            }
            (None, true) => {}
            _ => return Err(BundleError::Invalid),
        }
    }
    Ok(())
}
// Match every table, column order and hidden-rowid rule to executable-owned
// schema. Schema text equality alone cannot prove an archive omitted no tables
// or columns. No archive SQL is ever executed by this comparison.
fn validate_component_template(
    component: &ComponentManifest,
    template: &JournalTemplate,
) -> Result<()> {
    if component.kind != template.kind
        || component.application_id != template.application_id
        || component.schema_version != template.schema_version
        || component.schema != template_schema(template)?
    {
        return Err(BundleError::Unsupported);
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(template.create_sql)?;
    let expected = schema(&reference)?
        .iter()
        .filter(|o| o.kind == "table")
        .map(|o| table_manifest(&reference, &o.name))
        .collect::<Result<Vec<_>>>()?;
    let mut actual = component.tables.clone();
    for table in &mut actual {
        table.rows = 0;
    }
    if actual != expected {
        return Err(BundleError::Integrity);
    }
    Ok(())
}
fn template_schema(template: &JournalTemplate) -> Result<Vec<SchemaObject>> {
    if template.application_id == QUARANTINE_APPLICATION_ID
        || template.application_id == recovery::generation::RECOVERED_GENERATION_APPLICATION_ID
        || template.schema_version < 0
        || template.create_sql.len() > 1024 * 1024
    {
        return Err(BundleError::Unsupported);
    }
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")?;
    connection.execute_batch(template.create_sql)?;
    if !connection.is_autocommit() {
        return Err(BundleError::Unsupported);
    }
    let objects = schema(&connection)?;
    if objects.iter().any(|o| {
        matches!(
            o.name.as_str(),
            "wholepact_bundle_quarantine" | "wholepact_recovered_generation"
        )
    }) {
        return Err(BundleError::Unsupported);
    }
    Ok(objects)
}
fn schema(connection: &Connection) -> Result<Vec<SchemaObject>> {
    let mut stmt=connection.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' OR name='sqlite_sequence' ORDER BY type,name")?;
    let mut rows = stmt.query([])?;
    let mut objects = Vec::new();
    while let Some(row) = rows.next()? {
        if objects.len() >= MAX_OBJECTS {
            return Err(BundleError::Limit);
        }
        let object = SchemaObject {
            kind: row.get(0)?,
            name: row.get(1)?,
            table: row.get(2)?,
            sql: row.get(3)?,
        };
        identifier(&object.name)?;
        identifier(&object.table)?;
        if !matches!(object.kind.as_str(), "table" | "index" | "trigger" | "view")
            || object.sql.as_ref().is_some_and(|s| s.len() > 65536)
        {
            return Err(BundleError::Unsupported);
        }
        objects.push(object);
    }
    Ok(objects)
}
fn table_manifest(connection: &Connection, name: &str) -> Result<TableManifest> {
    let mut stmt = connection.prepare(&format!("PRAGMA table_xinfo({})", quote(name)?))?;
    let mut rows = stmt.query([])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        let hidden: i64 = row.get(6)?;
        let column: String = row.get(1)?;
        identifier(&column)?;
        if hidden != 0 || column.eq_ignore_ascii_case("rowid") || columns.len() >= 64 {
            return Err(BundleError::Unsupported);
        }
        columns.push(column);
    }
    let without_rowid: i64 = connection.query_row(
        "SELECT wr FROM pragma_table_list WHERE name=?1 AND schema='main'",
        [name],
        |r| r.get(0),
    )?;
    Ok(TableManifest {
        name: name.into(),
        columns,
        rowid: without_rowid == 0,
        rows: 0,
    })
}
fn validate_row(row: &Row, table: &TableManifest) -> Result<()> {
    if row.rowid.is_some() != table.rowid || row.cells.len() != table.columns.len() {
        return Err(BundleError::Integrity);
    }
    for value in &row.cells {
        match value {
            Cell::Text(s) if s.len() > MAX_CELL => return Err(BundleError::Limit),
            Cell::Blob(s) if s.len() > MAX_CELL => return Err(BundleError::Limit),
            Cell::Real(bits) if !f64::from_bits(*bits).is_finite() => {
                return Err(BundleError::Unsupported);
            }
            _ => {}
        }
    }
    Ok(())
}
fn integrity(connection: &Connection) -> Result<()> {
    let status: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if status != "ok" {
        return Err(BundleError::Integrity);
    }
    let violation: Option<i64> = connection
        .query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    if violation.is_some() {
        return Err(BundleError::Integrity);
    }
    Ok(())
}
fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
    {
        Err(BundleError::Invalid)
    } else {
        Ok(())
    }
}
fn quote(value: &str) -> Result<String> {
    identifier(value)?;
    Ok(format!("\"{value}\""))
}
fn private_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        Err(BundleError::Invalid)
    } else {
        Ok(())
    }
}
fn bounded_file(path: &Path) -> Result<()> {
    private_path(path)?;
    let mut total = 0u64;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut p = path.as_os_str().to_os_string();
        p.push(suffix);
        match std::fs::symlink_metadata(Path::new(&p)) {
            Ok(m) => {
                if !m.is_file() || m.file_type().is_symlink() {
                    return Err(BundleError::Invalid);
                }
                total = total.checked_add(m.len()).ok_or(BundleError::Limit)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {}
            Err(_) => return Err(BundleError::Storage),
        }
    }
    if total > MAX_FILE_BYTES {
        Err(BundleError::Limit)
    } else {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| BundleError::Invalid)
}
fn manifest_digest(manifest: &BundleManifest) -> Result<String> {
    let mut m = manifest.clone();
    m.digest.clear();
    let mut h = Sha256::new();
    h.update(b"wholepact.bundle.manifest.v1\0");
    h.update(encode(&m)?);
    Ok(hex_digest(h))
}
fn hex_digest(hash: Sha256) -> String {
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
