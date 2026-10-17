//! Versioned encrypted coordination/authority-journal snapshots. This is not a
//! wallet backup or a coordinated snapshot of the separate private artifact stores.
//! No key creation, transport, arbitrary SQL import, overwrite or authority reset.
use crate::{Result, SCHEMA_VERSION, StorageProtection, Store, StoreError, now_ms};
use rusqlite::{Connection, TransactionBehavior, params, params_from_iter, types::ValueRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
pub use wholepact_storage_security::DatabaseKey;
use wholepact_storage_security::{
    EncryptedReadSnapshot, create_encrypted, open_encrypted_read_snapshot,
};

const ARCHIVE_APPLICATION_ID: i64 = 0x57504241;
const RESTORING_APPLICATION_ID: i64 = 0x57505253;
const ARCHIVE_VERSION: i64 = 1;
const MAX_ROWS: u64 = 100_000;
const MAX_DATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CELL_BYTES: usize = 4 * 1024 * 1024;
const ARCHIVE_SCHEMA: &str = "CREATE TABLE backup_manifest(singleton INTEGER PRIMARY KEY CHECK(singleton=1), format_version INTEGER NOT NULL, source_schema_version INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, snapshot_digest TEXT NOT NULL, row_count INTEGER NOT NULL, data_bytes INTEGER NOT NULL, scope TEXT NOT NULL CHECK(scope='coordination_and_authority_only'));";

struct Table {
    name: &'static str,
    columns: &'static str,
    order: &'static str,
}
const TABLES: &[Table] = &[
    Table {
        name: "records",
        columns: "aggregate_type,id,revision,payload,created_at_ms,updated_at_ms",
        order: "aggregate_type,id",
    },
    Table {
        name: "operations",
        columns: "operation_id,principal_id,kind,resource_id,status,result,created_at_ms,updated_at_ms",
        order: "operation_id",
    },
    Table {
        name: "idempotency",
        columns: "principal_id,idempotency_key,request_digest,result",
        order: "principal_id,idempotency_key",
    },
    Table {
        name: "events",
        columns: "sequence,aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms",
        order: "sequence",
    },
    Table {
        name: "authority_accounts",
        columns: "account_id,writer_epoch,recovery_required",
        order: "account_id",
    },
    Table {
        name: "authority_exposures",
        columns: "authorization_id,account_id,obligation_id,proposal_id,request_digest,maximum_debit,state,release_intent,payload,created_at_ms,updated_at_ms",
        order: "authorization_id",
    },
    Table {
        name: "authority_reservations",
        columns: "account_id,input_id,authorization_id",
        order: "account_id,input_id",
    },
    Table {
        name: "authority_events",
        columns: "sequence,authorization_id,kind,evidence_ref,occurred_at_ms",
        order: "sequence",
    },
    Table {
        name: "effect_intents",
        columns: "operation_id,kind,resource_id,payload_digest,protected_payload_ref,status,created_at_ms,updated_at_ms",
        order: "operation_id",
    },
];
const RECOVERY: Table = Table {
    name: "store_recovery",
    columns: "singleton,recovery_required,restored_at_ms,source_snapshot_digest",
    order: "singleton",
};
const SEQUENCES: Table = Table {
    name: "sqlite_sequence",
    columns: "name,seq",
    order: "name",
};

/// Safe local metadata only. Counts still describe private activity: callers must
/// apply their own read/disclosure permission before presenting or exporting it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgreementBackupSummary {
    pub format_version: u32,
    pub source_schema_version: u32,
    pub created_at_ms: i64,
    pub snapshot_digest: String,
    pub row_count: u64,
    pub data_bytes: u64,
    pub table_rows: BTreeMap<String, u64>,
    pub scope: &'static str,
    pub wallet_secrets_included: bool,
    pub separate_artifact_journals_included: bool,
    pub freshness_established: bool,
    pub restore_requires_recovery: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryState {
    pub recovery_required: bool,
    pub restored_at_ms: Option<i64>,
    pub source_snapshot_digest: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgreementRestoreReport {
    pub backup: AgreementBackupSummary,
    pub destination_schema_version: u32,
    pub migration_applied: bool,
    pub integrity_verified: bool,
    pub recovery_required: bool,
    pub quarantined_authority_accounts: u64,
    pub authorization_allowed: bool,
    pub signer_recovered: bool,
}

impl Store {
    /// Snapshot ALL records of this protected store, including idempotency,
    /// observations and unresolved effects. Not a participant-scoped disclosure.
    /// The destination needs a separately provisioned independent key and a private
    /// directory. A failure leaves any partial destination untouched for inspection.
    pub fn backup_agreement_journal(
        &self,
        destination: impl AsRef<Path>,
        backup_key: &DatabaseKey,
    ) -> Result<AgreementBackupSummary> {
        if self.protection != StorageProtection::Encrypted {
            return Err(StoreError::InvalidInput(
                "encrypted source journal required",
            ));
        }
        let mut source = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let snapshot = source.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let version: i64 = snapshot.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let application: i64 = snapshot.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(version));
        }
        if application != 0 {
            return Err(StoreError::InvalidInput("not a live coordination journal"));
        }
        validate_schema(&snapshot, SCHEMA_VERSION, false)?;
        validate_integrity(&snapshot)?;
        let stats = inspect_rows(&snapshot, SCHEMA_VERSION)?;
        let destination = destination.as_ref();
        let mut archive = create_encrypted(destination, backup_key)?.into_connection();
        archive.pragma_update(None, "max_page_count", 32768)?;
        let tx = archive.transaction_with_behavior(TransactionBehavior::Immediate)?;
        initialize_schema(&tx, SCHEMA_VERSION)?;
        tx.execute_batch(ARCHIVE_SCHEMA)?;
        tx.pragma_update(None, "application_id", ARCHIVE_APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", ARCHIVE_VERSION)?;
        tx.execute("DELETE FROM store_recovery", [])?;
        copy_tables(&snapshot, &tx, SCHEMA_VERSION)?;
        let created = now_ms();
        tx.execute("INSERT INTO backup_manifest VALUES(1,?1,?2,?3,?4,?5,?6,'coordination_and_authority_only')", params![ARCHIVE_VERSION, SCHEMA_VERSION, created, stats.digest, stats.rows, stats.bytes])?;
        validate_integrity(&tx)?;
        #[cfg(test)]
        fail_before_commit("backup")?;
        tx.commit()?;
        snapshot.commit()?;
        sync_database(&archive, destination)?;
        drop(archive);
        // Re-authenticate persisted pages under the backup key, and recalculate
        // the complete bounded content digest before reporting success.
        inspect_agreement_backup(destination, backup_key)
    }

    pub fn recovery_state(&self) -> Result<RecoveryState> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        read_recovery_state(&c)
    }
}

/// Authenticate, validate schema/inventory, and recalculate the snapshot digest.
/// This validates an archive's integrity, never its currency or writer authority.
/// Hold the owning archive/profile locks and keep its file set quiescent during
/// inspection. SQLite reads a private encrypted copy and preserves all source
/// files and sidecars; access-time changes from ordinary reads are possible.
pub fn inspect_agreement_backup(
    archive: impl AsRef<Path>,
    key: &DatabaseKey,
) -> Result<AgreementBackupSummary> {
    let connection = open_archive(archive.as_ref(), key)?;
    let snapshot = connection.connection().unchecked_transaction()?;
    let summary = validate_archive(&snapshot)?;
    snapshot.commit()?;
    Ok(summary)
}

/// Restore only to an exclusively created encrypted destination. All source rows
/// are imported in one transaction; all authority accounts and the entire store
/// are fenced before that transaction exposes a live-store application identity.
/// The archive is unchanged. No API clears the recovery fence.
/// The caller must hold the owning archive/profile locks and keep the archive
/// and its sidecars quiescent throughout capture, as for inspection.
pub fn restore_agreement_journal(
    archive: impl AsRef<Path>,
    backup_key: &DatabaseKey,
    destination: impl AsRef<Path>,
    destination_key: &DatabaseKey,
) -> Result<(Store, AgreementRestoreReport)> {
    let source = open_archive(archive.as_ref(), backup_key)?;
    let source_tx = source.connection().unchecked_transaction()?;
    let summary = validate_archive(&source_tx)?;
    let version = i64::from(summary.source_schema_version);
    let destination = destination.as_ref();
    let mut restored = create_encrypted(destination, destination_key)?.into_connection();
    restored.pragma_update(None, "max_page_count", 32768)?;
    // An interrupted staging file is refused by ordinary Store opening. An
    // interruption before this marker leaves version zero, also refused by the
    // encrypted open constructor (only explicit create may initialize it).
    restored.pragma_update(None, "application_id", RESTORING_APPLICATION_ID)?;
    let tx = restored.transaction_with_behavior(TransactionBehavior::Immediate)?;
    initialize_schema(&tx, SCHEMA_VERSION)?;
    if version >= 2 {
        tx.execute("DELETE FROM store_recovery", [])?;
    }
    copy_tables(&source_tx, &tx, version)?;
    let imported = inspect_rows(&tx, version)?;
    if imported.digest != summary.snapshot_digest {
        return Err(StoreError::InvalidInput(
            "restored journal differs from archive",
        ));
    }
    let quarantined: u64 =
        tx.query_row("SELECT count(*) FROM authority_accounts", [], |r| r.get(0))?;
    tx.execute("UPDATE authority_accounts SET recovery_required=1", [])?;
    tx.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=?1,source_snapshot_digest=?2 WHERE singleton=1", params![now_ms(), summary.snapshot_digest])?;
    validate_live_schema_and_rows(&tx, SCHEMA_VERSION)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.pragma_update(None, "application_id", 0)?;
    #[cfg(test)]
    fail_before_commit("restore")?;
    tx.commit()?;
    source_tx.commit()?;
    sync_database(&restored, destination)?;
    drop(restored);
    let store = Store::open_encrypted(destination, destination_key)?;
    if !store.recovery_state()?.recovery_required {
        return Err(StoreError::RecoveryRequired);
    }
    let report = AgreementRestoreReport {
        migration_applied: version != SCHEMA_VERSION,
        backup: summary,
        destination_schema_version: SCHEMA_VERSION as u32,
        integrity_verified: true,
        recovery_required: true,
        quarantined_authority_accounts: quarantined,
        authorization_allowed: false,
        signer_recovered: false,
    };
    Ok((store, report))
}

/// Perform the same real keyed restoration and reopen checks as normal restore.
/// The caller chooses a fresh private destination; this helper never overwrites
/// or deletes files. The restored test copy remains quarantined on disk.
pub fn test_restore_agreement_journal(
    archive: impl AsRef<Path>,
    backup_key: &DatabaseKey,
    destination: impl AsRef<Path>,
    destination_key: &DatabaseKey,
) -> Result<AgreementRestoreReport> {
    let (store, report) =
        restore_agreement_journal(archive, backup_key, destination, destination_key)?;
    store.verify_integrity()?;
    drop(store);
    Ok(report)
}

pub(crate) fn read_recovery_state(connection: &Connection) -> Result<RecoveryState> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM store_recovery", [], |r| r.get(0))?;
    if count != 1 {
        return Err(StoreError::RecoveryRequired);
    }
    let state = connection.query_row("SELECT recovery_required,restored_at_ms,source_snapshot_digest FROM store_recovery WHERE singleton=1", [], |r| Ok(RecoveryState { recovery_required: r.get(0)?, restored_at_ms: r.get(1)?, source_snapshot_digest: r.get(2)? }))?;
    match (
        &state.source_snapshot_digest,
        state.restored_at_ms,
        state.recovery_required,
    ) {
        (None, None, false) => Ok(state),
        (Some(digest), Some(at), true)
            if at >= 0
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok(state)
        }
        _ => Err(StoreError::RecoveryRequired),
    }
}

/// Ordinary journal authentication. Version is explicit because archive user_version
/// describes the archive envelope, and migration must check the old encoding first.
pub(crate) fn validate_live_schema_and_rows(connection: &Connection, version: i64) -> Result<()> {
    validate_schema(connection, version, false)?;
    validate_integrity(connection)?;
    inspect_rows(connection, version)?;
    if version >= 2 {
        read_recovery_state(connection)?;
    }
    Ok(())
}

pub(crate) fn validate_construction_encoding(
    connection: &Connection,
    supports_v3: bool,
    supports_v4: bool,
    supports_v5: bool,
) -> Result<()> {
    if !supports_v3 {
        let has_v3: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type IN(?1,?2))",
            params![
                crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3,
                crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3
            ],
            |r| r.get(0),
        )?;
        if has_v3 {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if !supports_v4 || !supports_v5 {
        // Inspect the raw encoding before typed decoding: even an explicit null
        // provenance field is a new field and cannot hide under a legacy marker.
        let kind = crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3;
        // Preserve the typed reader's combined claim/checkpoint bounds before
        // materializing any raw JSON for this earlier marker check.
        let (count, bytes): (u64, u64) = connection.query_row(
            "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type IN(?1,?2)",
            params![kind, crate::manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if count > 512 || bytes > 32 * 1024 * 1024 {
            return Err(StoreError::ResourceExhausted);
        }
        let mut query = connection.prepare(
            "SELECT payload FROM records WHERE aggregate_type=?1",
        )?;
        for row in query.query_map([kind], |r| r.get::<_, String>(0))? {
            let payload: serde_json::Value = serde_json::from_str(&row?)?;
            if (!supports_v4 && crate::recovery::is_construction_v4_claim(kind, &payload))
                || (!supports_v5 && crate::recovery::is_construction_v5_claim(kind, &payload))
            {
                return Err(StoreError::RecoveryRequired);
            }
        }
    }
    crate::manual_enrollment::construction_claim_union::validate_current(connection)
}

/// Restriction-only runtime guard. Historical recovered templates stay immutable;
/// a legacy generation cannot append a new encoding under its old marker.
pub(crate) fn require_construction_v3_encoding(connection: &Connection) -> Result<()> {
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let recovered = wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID;
    if (application == 0 && version == SCHEMA_VERSION)
        || (application == recovered && matches!(version, 4 | 5 | 6 | 7 | 8 | 9))
    {
        Ok(())
    } else {
        Err(StoreError::RecoveryRequired)
    }
}
pub(crate) fn require_construction_v4_encoding(connection: &Connection) -> Result<()> {
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let recovered = wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID;
    if (application == 0 && version == SCHEMA_VERSION)
        || (application == recovered && matches!(version, 6 | 7 | 8 | 9))
    {
        Ok(())
    } else {
        Err(StoreError::RecoveryRequired)
    }
}
pub(crate) fn require_construction_v5_encoding(connection: &Connection) -> Result<()> {
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let recovered = wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID;
    if (application == 0 && version == 5)
        || (application == recovered && matches!(version, 8 | 9))
    {
        Ok(())
    } else {
        Err(StoreError::RecoveryRequired)
    }
}
fn initialize_schema(connection: &Connection, version: i64) -> Result<()> {
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(StoreError::UnsupportedSchema(version));
    }
    connection.execute_batch(include_str!("schema.sql"))?;
    if version >= 2 {
        connection.execute_batch(include_str!("migration-v2.sql"))?;
    }
    Ok(())
}
fn tables(version: i64) -> impl Iterator<Item = &'static Table> {
    TABLES
        .iter()
        .chain((version >= 2).then_some(&RECOVERY))
        .chain(std::iter::once(&SEQUENCES))
}
fn schema_rows(connection: &Connection) -> Result<Vec<(String, String, String)>> {
    let invalid: u64 = connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' AND (length(type)>32 OR length(name)>128 OR length(sql)>65536 OR sql IS NULL)", [], |r| r.get(0))?;
    let count: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
        [],
        |r| r.get(0),
    )?;
    if invalid != 0 || count > 32 {
        return Err(StoreError::ResourceExhausted);
    }
    let mut q = connection.prepare(
        "SELECT type,name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name",
    )?;
    let rows = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows)
}
fn validate_schema(connection: &Connection, version: i64, archive: bool) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    initialize_schema(&expected, version)?;
    if archive {
        expected.execute_batch(ARCHIVE_SCHEMA)?;
    }
    if schema_rows(connection)? != schema_rows(&expected)? {
        return Err(StoreError::InvalidInput(
            "unsupported journal schema or extra database objects",
        ));
    }
    Ok(())
}
fn validate_integrity(connection: &Connection) -> Result<()> {
    let mut q = connection.prepare("PRAGMA quick_check")?;
    let mut rows = q.query([])?;
    if rows
        .next()?
        .map(|r| r.get::<_, String>(0))
        .transpose()?
        .as_deref()
        != Some("ok")
        || rows.next()?.is_some()
    {
        return Err(StoreError::InvalidInput("journal integrity check failed"));
    }
    if connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        return Err(StoreError::InvalidInput("journal foreign key check failed"));
    }
    Ok(())
}
struct Stats {
    rows: u64,
    bytes: u64,
    digest: String,
    table_rows: BTreeMap<String, u64>,
}
fn inspect_rows(connection: &Connection, version: i64) -> Result<Stats> {
    let mut stats = Stats {
        rows: 0,
        bytes: 0,
        digest: String::new(),
        table_rows: BTreeMap::new(),
    };
    let mut hash = Sha256::new();
    hash.update(b"wholepact:coordination-journal-snapshot:v1\0");
    hash.update(version.to_be_bytes());
    for table in tables(version) {
        let columns: Vec<_> = table.columns.split(',').collect();
        let size_expression = columns
            .iter()
            .map(|c| format!("coalesce(length(CAST({c} AS BLOB)),0)"))
            .collect::<Vec<_>>()
            .join("+");
        let (count, bytes): (u64, u64) = connection.query_row(
            &format!(
                "SELECT count(*),coalesce(sum({size_expression}),0) FROM {}",
                table.name
            ),
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        stats.rows = stats
            .rows
            .checked_add(count)
            .ok_or(StoreError::ResourceExhausted)?;
        stats.bytes = stats
            .bytes
            .checked_add(bytes)
            .ok_or(StoreError::ResourceExhausted)?;
        if stats.rows > MAX_ROWS || stats.bytes > MAX_DATA_BYTES {
            return Err(StoreError::ResourceExhausted);
        }
        stats.table_rows.insert(table.name.into(), count);
        hash.update((table.name.len() as u64).to_be_bytes());
        hash.update(table.name.as_bytes());
        hash.update(count.to_be_bytes());
        let mut q = connection.prepare(&format!(
            "SELECT {} FROM {} ORDER BY {}",
            table.columns, table.name, table.order
        ))?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            for index in 0..columns.len() {
                match row.get_ref(index)? {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(value) => {
                        hash.update([1]);
                        hash.update(value.to_be_bytes());
                    }
                    ValueRef::Text(value) if value.len() <= MAX_CELL_BYTES => {
                        std::str::from_utf8(value)
                            .map_err(|_| StoreError::InvalidInput("invalid journal text"))?;
                        hash.update([2]);
                        hash.update((value.len() as u64).to_be_bytes());
                        hash.update(value);
                    }
                    _ => {
                        return Err(StoreError::InvalidInput(
                            "unsupported or oversized journal value",
                        ));
                    }
                }
            }
        }
    }
    let unknown_sequences: u64 = connection.query_row("SELECT count(*) FROM sqlite_sequence WHERE name NOT IN('events','authority_events') OR seq < 0", [], |r| r.get(0))?;
    if unknown_sequences != 0 {
        return Err(StoreError::InvalidInput("unsupported journal sequence"));
    }
    let support = crate::recovery::construction_encoding_support(0, version)?;
    validate_construction_encoding(connection, support.0, support.1, support.2)?;
    if version >= 2 {
        read_recovery_state(connection)?;
    }
    stats.digest = hex::encode(hash.finalize());
    Ok(stats)
}
fn copy_tables(source: &Connection, destination: &Connection, version: i64) -> Result<()> {
    for table in tables(version) {
        if table.name == "sqlite_sequence" {
            destination.execute("DELETE FROM sqlite_sequence", [])?;
        }
        let count = table.columns.split(',').count();
        let placeholders = (1..=count)
            .map(|n| format!("?{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut read = source.prepare(&format!(
            "SELECT {} FROM {} ORDER BY {}",
            table.columns, table.name, table.order
        ))?;
        let mut write = destination.prepare(&format!(
            "INSERT INTO {}({}) VALUES({})",
            table.name, table.columns, placeholders
        ))?;
        let mut rows = read.query([])?;
        while let Some(row) = rows.next()? {
            let values = (0..count)
                .map(|i| row.get::<_, rusqlite::types::Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            write.execute(params_from_iter(values))?;
        }
    }
    Ok(())
}
fn open_archive(path: &Path, key: &DatabaseKey) -> Result<EncryptedReadSnapshot> {
    let mut total = 0u64;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        match fs::symlink_metadata(Path::new(&name)) {
            Ok(meta) => {
                total = total
                    .checked_add(meta.len())
                    .ok_or(StoreError::ResourceExhausted)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {}
            Err(e) => return Err(e.into()),
        }
    }
    if total > MAX_FILE_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    Ok(open_encrypted_read_snapshot(path, key)?)
}
fn validate_archive(connection: &Connection) -> Result<AgreementBackupSummary> {
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let format: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != ARCHIVE_APPLICATION_ID || format != ARCHIVE_VERSION {
        return Err(StoreError::InvalidInput(
            "unsupported agreement archive format",
        ));
    }
    let count: i64 =
        connection.query_row("SELECT count(*) FROM backup_manifest", [], |r| r.get(0))?;
    if count != 1 {
        return Err(StoreError::InvalidInput("incomplete agreement archive"));
    }
    let (declared_format, version, created, digest, rows, bytes): (i64, i64, i64, String, u64, u64) = connection.query_row("SELECT format_version,source_schema_version,created_at_ms,snapshot_digest,row_count,data_bytes FROM backup_manifest WHERE singleton=1 AND scope='coordination_and_authority_only'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    if declared_format != ARCHIVE_VERSION || !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(StoreError::UnsupportedSchema(version));
    }
    if created < 0 || digest.len() != 64 || rows > MAX_ROWS || bytes > MAX_DATA_BYTES {
        return Err(StoreError::InvalidInput(
            "invalid agreement archive manifest",
        ));
    }
    validate_schema(connection, version, true)?;
    validate_integrity(connection)?;
    let stats = inspect_rows(connection, version)?;
    if digest != stats.digest || rows != stats.rows || bytes != stats.bytes {
        return Err(StoreError::InvalidInput(
            "agreement archive content mismatch",
        ));
    }
    Ok(AgreementBackupSummary {
        format_version: ARCHIVE_VERSION as u32,
        source_schema_version: version as u32,
        created_at_ms: created,
        snapshot_digest: digest,
        row_count: rows,
        data_bytes: bytes,
        table_rows: stats.table_rows,
        scope: "coordination_and_authority_only",
        wallet_secrets_included: false,
        separate_artifact_journals_included: false,
        freshness_established: false,
        restore_requires_recovery: true,
    })
}
fn sync_database(connection: &Connection, path: &Path) -> Result<()> {
    let (busy, _, _): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    if busy != 0 {
        return Err(StoreError::InvalidInput(
            "encrypted journal checkpoint incomplete",
        ));
    }
    fs::File::open(path)?.sync_all()?;
    fs::File::open(path.parent().ok_or(StoreError::InvalidInput(
        "private destination directory required",
    ))?)?
    .sync_all()?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(test)]
std::thread_local! {
    static INJECTED_FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn fail_before_commit(operation: &str) -> Result<()> {
    if INJECTED_FAILURE.with(|fault| fault.get() == Some(operation)) {
        Err(StoreError::InvalidInput(
            "synthetic pre-commit interruption",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod historical_provenance_v5_marker_tests;
