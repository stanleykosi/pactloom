//! Durable coordination metadata and conservative authority-ledger primitives.
//!
//! Encrypted disk constructors require the qualified keyed-connection boundary.
//! Legacy `open` is plaintext development storage and must never hold protected
//! wallet or witness material. Protection is derived from the constructor, not a DTO.
//! The signer must independently verify before using its authority ledger.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

// Version 5 adds mandatory historical provenance to the construction encoding
// boundary. The SQL layout remains version 2, and legacy claim bytes are never
// rewritten or supplied with inferred provenance during a marker upgrade.
const SCHEMA_VERSION: i64 = 5;
pub mod backup;
mod draft_history;
const MAX_JSON_BYTES: usize = 1_048_576;
pub const MAX_AGREEMENTS: u64 = 256;
pub const MAX_AGREEMENTS_PER_PRINCIPAL: u64 = 64;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("encrypted storage is unavailable or authentication failed")]
    StorageSecurity(#[from] wholepact_storage_security::StorageSecurityError),
    #[error("storage operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("stored record could not be encoded or decoded")]
    Encoding(#[from] serde_json::Error),
    #[error("storage mutex unavailable")]
    Poisoned,
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("aggregate revision did not match")]
    RevisionConflict,
    #[error("record was not found")]
    NotFound,
    #[error("record already exists")]
    AlreadyExists,
    #[error("invalid store input: {0}")]
    InvalidInput(&'static str),
    #[error("unsupported database schema version {0}")]
    UnsupportedSchema(i64),
    #[error("account requires exposure and writer reconciliation")]
    RecoveryRequired,
    #[error("writer epoch does not match the authoritative account")]
    WriterEpochMismatch,
    #[error("this obligation has a potentially executable or consumed authorization")]
    LiveAuthorizationExists,
    #[error("an input is reserved by an outstanding authorization")]
    InputReserved,
    #[error("local storage resource limit reached")]
    ResourceExhausted,
    #[error("aggregate authorization exposure exceeds the budget")]
    BudgetExceeded,
    #[error("authorization state transition is not permitted")]
    InvalidTransition,
    #[error("could not create storage file")]
    File(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// Engine-created request context. Digest covers command, scope, expected
/// revision and the original semantic request, never timestamps/random output.
/// Do not accept an unverified digest from an external client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandContext {
    pub principal_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
}
impl CommandContext {
    pub fn for_request(
        principal_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        request: &Value,
    ) -> Result<Self> {
        Ok(Self {
            principal_id: principal_id.into(),
            idempotency_key: idempotency_key.into(),
            request_digest: request_digest(request)?,
        })
    }
}

/// Stable digest for internal idempotency, not a portable manifest or protocol
/// effects commitment. Object keys are sorted recursively; floats are rejected.
pub fn request_digest(value: &Value) -> Result<String> {
    fn canonical(value: &Value) -> Result<Value> {
        match value {
            Value::Number(n) if !n.is_i64() && !n.is_u64() => Err(StoreError::InvalidInput(
                "floating point is not a semantic request amount",
            )),
            Value::Object(map) => {
                let sorted: std::collections::BTreeMap<_, _> = map
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), canonical(v)?)))
                    .collect::<Result<_>>()?;
                Ok(Value::Object(sorted.into_iter().collect()))
            }
            Value::Array(values) => Ok(Value::Array(
                values.iter().map(canonical).collect::<Result<_>>()?,
            )),
            other => Ok(other.clone()),
        }
    }
    let encoded = encode(&canonical(value)?)?;
    let mut hash = Sha256::new();
    hash.update(b"wholepact.local-command.v1\0");
    hash.update(encoded.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredRecord {
    pub id: String,
    pub revision: u64,
    pub payload: Value,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MutationResult {
    pub record: StoredRecord,
    pub operation_id: String,
    pub event_sequence: u64,
    pub replayed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredEvent {
    pub event_id: String,
    pub sequence: u64,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub aggregate_revision: u64,
    pub kind: String,
    pub payload: Value,
    pub operation_id: String,
    pub occurred_at_ms: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredOperation {
    pub operation_id: String,
    pub principal_id: String,
    pub kind: String,
    pub resource_id: String,
    pub status: String,
    pub result: Value,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageProtection {
    Encrypted,
    InMemory,
    PlaintextDevelopment,
}

pub struct Store {
    connection: Mutex<Connection>,
    protection: StorageProtection,
    // Captured from the sealed authenticated factory connection at ownership
    // transfer, never recreated from a later path or an application assertion.
    original_database: Option<wholepact_storage_security::DatabaseFileIdentity>,
    // Set only by the dedicated authenticated generation opener, never a DTO.
    recovered_generation: bool,
    recovered_binding:
        Option<wholepact_storage_security::bundle::recovery::generation::GenerationBinding>,
}
impl Store {
    /// Legacy development path. Never use for private wallet or witness data.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // New files are private. Existing permissions are not silently changed.
        if !path.exists() {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Self::from_connection(
            Connection::open(path)?,
            StorageProtection::PlaintextDevelopment,
        )
    }
    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, StorageProtection::InMemory)
    }
    pub fn from_encrypted_connection(
        connection: wholepact_storage_security::EncryptedConnection,
    ) -> Result<Self> {
        // Only explicit create initializes a new encrypted store. An interrupted
        // archive/restore must not turn an existing empty file into fresh authority.
        let version: i64 =
            connection
                .connection()
                .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            return Err(StoreError::RecoveryRequired);
        }
        let original = connection.database_identity()?;
        Self::from_connection_with_origin(
            connection.into_connection(),
            StorageProtection::Encrypted,
            Some(original),
        )
    }
    pub fn create_encrypted(
        path: impl AsRef<Path>,
        key: &wholepact_storage_security::DatabaseKey,
    ) -> Result<Self> {
        let connection = wholepact_storage_security::create_encrypted(path, key)?;
        let original = connection.database_identity()?;
        Self::from_connection_with_origin(
            connection.into_connection(),
            StorageProtection::Encrypted,
            Some(original),
        )
    }
    pub fn open_encrypted(
        path: impl AsRef<Path>,
        key: &wholepact_storage_security::DatabaseKey,
    ) -> Result<Self> {
        Self::from_encrypted_connection(wholepact_storage_security::open_encrypted(path, key)?)
    }
    pub fn protection(&self) -> StorageProtection {
        self.protection
    }

    /// Correlation only, never authority. The caller still holds its original
    /// Directory exclusion owner. Recheck the actual retained SQLite handle;
    /// plaintext/in-memory or reconstructed-history stores cannot mint origins.
    /// Filesystem checks have no hard completion-time guarantee.
    pub fn original_database_origin_fail_fast(&self) -> Result<[u8; 32]> {
        let original = self
            .original_database
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        if self.protection != StorageProtection::Encrypted {
            return Err(StoreError::RecoveryRequired);
        }
        let connection = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        original.check_current(&connection)?;
        Ok(original.origin_commitment())
    }

    /// Verify a native-approved private destination against this actual open,
    /// authenticated encrypted SQLite handle. A supplied path alone is never
    /// storage provenance. This is correlation only, not spending authority.
    pub fn verify_original_encrypted_destination(&self, expected: &Path) -> Result<[u8; 32]> {
        if self.protection != StorageProtection::Encrypted || self.recovered_generation {
            return Err(StoreError::RecoveryRequired);
        }
        let original = self
            .original_database
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        let connection = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        original.check_current(&connection)?;
        let actual = connection.path().ok_or(StoreError::RecoveryRequired)?;
        if !expected.is_absolute()
            || std::fs::canonicalize(expected)? != expected
            || std::fs::canonicalize(actual)? != expected
        {
            return Err(StoreError::RecoveryRequired);
        }
        original.check_current(&connection)?;
        Ok(original.origin_commitment())
    }

    fn from_connection(connection: Connection, protection: StorageProtection) -> Result<Self> {
        Self::from_connection_with_origin(connection, protection, None)
    }
    fn from_connection_with_origin(
        mut connection: Connection,
        protection: StorageProtection,
        original_database: Option<wholepact_storage_security::DatabaseFileIdentity>,
    ) -> Result<Self> {
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if application != 0 {
            return Err(StoreError::InvalidInput("not a live coordination journal"));
        }
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if !(0..=SCHEMA_VERSION).contains(&version) {
            return Err(StoreError::UnsupportedSchema(version));
        }
        // Validate the complete original schema and history before changing its
        // version. Migration is atomic and never rewrites immutable row payloads
        // or clears a restored-store fence. The Immediate transaction also closes
        // the race with another opener performing the same migration.
        let behavior = if version < SCHEMA_VERSION {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        };
        let tx = connection.transaction_with_behavior(behavior)?;
        let current: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if application != 0 || current < version {
            return Err(StoreError::RecoveryRequired);
        }
        match current {
            0 => {
                let objects: i64 = tx.query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                    [],
                    |r| r.get(0),
                )?;
                if objects != 0 {
                    return Err(StoreError::RecoveryRequired);
                }
                tx.execute_batch(include_str!("schema.sql"))?;
                tx.execute_batch(include_str!("migration-v2.sql"))?;
            }
            1..=SCHEMA_VERSION => {
                backup::validate_live_schema_and_rows(&tx, current)?;
                if current == 1 {
                    tx.execute_batch(include_str!("migration-v2.sql"))?;
                }
            }
            _ => return Err(StoreError::UnsupportedSchema(current)),
        }
        if current < SCHEMA_VERSION {
            backup::validate_live_schema_and_rows(&tx, SCHEMA_VERSION)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        tx.commit()?;
        if let Some(original) = &original_database {
            original.check_current(&connection)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            protection,
            original_database,
            recovered_generation: false,
            recovered_binding: None,
        })
    }
    pub fn verify_integrity(&self) -> Result<()> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let status: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if status == "ok" {
            Ok(())
        } else {
            Err(StoreError::InvalidInput("database integrity check failed"))
        }
    }
    pub fn find_replay(&self, context: &CommandContext) -> Result<Option<MutationResult>> {
        validate_context(context)?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        self.require_current_replay(&c, context)?;
        crate::manual_enrollment::require_generic_request_not_manual(&c, context)?;
        replay(&c, context)
    }
    pub fn create_agreement(
        &self,
        context: &CommandContext,
        id: &str,
        payload: Value,
    ) -> Result<MutationResult> {
        self.commit_record(context, "agreement", id, None, payload, "agreement.created")
    }
    pub fn update_agreement(
        &self,
        context: &CommandContext,
        id: &str,
        expected_revision: u64,
        payload: Value,
        event_kind: &str,
    ) -> Result<MutationResult> {
        self.commit_record(
            context,
            "agreement",
            id,
            Some(expected_revision),
            payload,
            event_kind,
        )
    }
    pub fn get_agreement(&self, id: &str) -> Result<Option<StoredRecord>> {
        self.get_record("agreement", id)
    }
    pub fn list_agreements(&self) -> Result<Vec<StoredRecord>> {
        self.list_records("agreement")
    }
    pub fn get_record(&self, aggregate_type: &str, id: &str) -> Result<Option<StoredRecord>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        read_record(&c, aggregate_type, id)
    }
    pub fn list_records(&self, aggregate_type: &str) -> Result<Vec<StoredRecord>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        if matches!(
            aggregate_type,
            manual_enrollment::construction_claim_v2::CONSTRUCTION_CLAIM_V2
                | manual_enrollment::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2
                | manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3
                | manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3
        ) {
            manual_enrollment::construction_claim_v2::read_construction_rows(&c)?;
        }
        let mut query = c.prepare("SELECT id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type=?1 ORDER BY created_at_ms,id")?;
        let raw = query
            .query_map([aggregate_type], record_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raw.into_iter().map(decode_record).collect()
    }
    /// Generic atomic metadata mutation. Immutable proposals use creation only;
    /// updates of a `proposal` aggregate are always rejected.
    pub fn commit_record(
        &self,
        context: &CommandContext,
        aggregate_type: &str,
        id: &str,
        expected_revision: Option<u64>,
        payload: Value,
        event_kind: &str,
    ) -> Result<MutationResult> {
        // Automation lifecycle, budgets and authorization history are owned by
        // the trusted atomic runtime, never by generic client metadata writes.
        if aggregate_type.starts_with("automation_")
            || aggregate_type.starts_with("settlement_")
            || aggregate_type.starts_with("generation_manual_")
        {
            return Err(StoreError::InvalidInput(
                "automation records require the bounded runtime",
            ));
        }
        validate_context(context)?;
        validate_id(id)?;
        validate_id(aggregate_type)?;
        validate_id(event_kind)?;
        if aggregate_type == "proposal" && expected_revision.is_some() {
            return Err(StoreError::InvalidInput("proposal revisions are immutable"));
        }
        if aggregate_type == "agreement"
            && expected_revision.is_none()
            && event_kind != "agreement.created"
        {
            return Err(StoreError::InvalidInput(
                "agreement creation event kind is fixed",
            ));
        }
        let encoded = encode(&payload)?;
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        self.check_durable_private_destination(&c, &payload)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_current_replay(&tx, context)?;
        crate::manual_enrollment::require_generic_request_not_manual(&tx, context)?;
        self.require_current_record_write(&tx, aggregate_type, id, &payload)?;
        if let Some(existing) = replay(&tx, context)? {
            if existing.record.id != id {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(existing);
        }
        let existing = read_record(&tx, aggregate_type, id)?;
        if aggregate_type == "agreement" && event_kind == "agreement_terms_revised" {
            let old = existing.as_ref().ok_or(StoreError::NotFound)?;
            if expected_revision != Some(old.revision) {
                return Err(StoreError::RevisionConflict);
            }
            let owner = old.payload["owner_client_id"]
                .as_str()
                .ok_or(StoreError::RecoveryRequired)?;
            let obligation = old.payload["view"]["agreement"]["obligation_id"]
                .as_str()
                .ok_or(StoreError::RecoveryRequired)?;
            if old.payload["terms_editing_origin"] != true
                || owner != context.principal_id
                || !draft_history::is_local_draft(&tx, id, old.revision, owner, obligation)?
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        if aggregate_type == "agreement" && expected_revision.is_none() && existing.is_none() {
            let total: u64 = tx.query_row(
                "SELECT COUNT(*) FROM records WHERE aggregate_type='agreement'",
                [],
                |r| r.get(0),
            )?;
            let owned:u64=tx.query_row("SELECT COUNT(*) FROM operations WHERE kind='agreement.created' AND principal_id=?1",[&context.principal_id],|r|r.get(0))?;
            if total >= MAX_AGREEMENTS || owned >= MAX_AGREEMENTS_PER_PRINCIPAL {
                return Err(StoreError::ResourceExhausted);
            }
        }
        let now = now_ms();
        let (revision, created_at_ms) = match (existing, expected_revision) {
            (None, None) => (1, now),
            (Some(_), None) => return Err(StoreError::AlreadyExists),
            (None, Some(_)) => return Err(StoreError::NotFound),
            (Some(old), Some(expected)) if old.revision == expected => (
                expected
                    .checked_add(1)
                    .ok_or(StoreError::RevisionConflict)?,
                old.created_at_ms,
            ),
            _ => return Err(StoreError::RevisionConflict),
        };
        let revision_sql = i64::try_from(revision).map_err(|_| StoreError::RevisionConflict)?;
        tx.execute("INSERT INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(aggregate_type,id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,updated_at_ms=excluded.updated_at_ms", params![aggregate_type,id,revision_sql,encoded,created_at_ms,now])?;
        let operation_id = operation_id(context);
        // Event payload is minimal metadata. Consumers retrieve the authorized
        // aggregate rather than receiving private descriptions/amounts in SSE.
        let event_payload = serde_json::json!({"id":id,"revision":revision});
        tx.execute("INSERT INTO events(aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![aggregate_type,id,revision_sql,event_kind,encode(&event_payload)?,operation_id,now])?;
        let sequence = u64::try_from(tx.last_insert_rowid())
            .map_err(|_| StoreError::InvalidInput("event sequence overflow"))?;
        let result = MutationResult {
            record: StoredRecord {
                id: id.into(),
                revision,
                payload,
                created_at_ms,
                updated_at_ms: now,
            },
            operation_id: operation_id.clone(),
            event_sequence: sequence,
            replayed: false,
        };
        let serialized = serde_json::to_string(&result)?;
        tx.execute("INSERT INTO operations(operation_id,principal_id,kind,resource_id,status,result,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,'succeeded',?5,?6,?6)", params![operation_id,context.principal_id,event_kind,id,serialized,now])?;
        tx.execute("INSERT INTO idempotency(principal_id,idempotency_key,request_digest,result) VALUES(?1,?2,?3,?4)", params![context.principal_id,context.idempotency_key,context.request_digest,serialized])?;
        self.check_durable_private_destination(&tx, &result.record.payload)?;
        tx.commit()?;
        self.check_durable_private_destination(&c, &result.record.payload)?;
        Ok(result)
    }

    // A private-data record cannot be committed to a substituted destination
    // between the embedding's admission check and the actual metadata commit.
    // This verifies storage identity only, never native consent or owner claims.
    fn check_durable_private_destination(
        &self,
        connection: &Connection,
        payload: &Value,
    ) -> Result<()> {
        let Some(value) = payload.get("durable_construction_v1") else {
            return Ok(());
        };
        let rosters = value.as_object().ok_or(StoreError::RecoveryRequired)?;
        if rosters.is_empty() {
            return Ok(());
        }
        if self.protection != StorageProtection::Encrypted || self.recovered_generation {
            return Err(StoreError::RecoveryRequired);
        }
        let original = self
            .original_database
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        original.check_current(connection)?;
        let actual = std::fs::canonicalize(connection.path().ok_or(StoreError::RecoveryRequired)?)?;
        let origin = hex::encode(original.origin_commitment());
        for roster in rosters.values() {
            let owners = roster
                .get("owners")
                .and_then(Value::as_object)
                .ok_or(StoreError::RecoveryRequired)?;
            if owners.is_empty() || owners.len() > 2 {
                return Err(StoreError::RecoveryRequired);
            }
            for intake in owners.values() {
                let expected = intake["outbox"]["request"]["scope"]["protected_destination"]
                    .as_str()
                    .ok_or(StoreError::RecoveryRequired)?;
                let expected = Path::new(expected);
                if !expected.is_absolute()
                    || std::fs::canonicalize(expected)? != expected
                    || actual != expected
                    || intake["metadata_origin"].as_str() != Some(origin.as_str())
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
        original.check_current(connection)?;
        Ok(())
    }
    pub fn events_after(&self, after_sequence: u64, limit: u32) -> Result<Vec<StoredEvent>> {
        let cursor = i64::try_from(after_sequence)
            .map_err(|_| StoreError::InvalidInput("cursor overflow"))?;
        if limit == 0 || limit > 1000 {
            return Err(StoreError::InvalidInput(
                "event page limit must be 1 to 1000",
            ));
        }
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut q = c.prepare("SELECT sequence,aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms FROM events WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
        let raw = q
            .query_map(params![cursor, limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(
                |(
                    seq,
                    aggregate_type,
                    aggregate_id,
                    rev,
                    kind,
                    payload,
                    operation_id,
                    occurred_at_ms,
                )| {
                    Ok(StoredEvent {
                        event_id: format!("event_{seq}"),
                        sequence: seq as u64,
                        aggregate_type,
                        aggregate_id,
                        aggregate_revision: rev as u64,
                        kind,
                        payload: serde_json::from_str(&payload)?,
                        operation_id,
                        occurred_at_ms,
                    })
                },
            )
            .collect()
    }
    pub fn get_operation(&self, id: &str) -> Result<Option<StoredOperation>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        if self.generation_fenced(&c, "operation", id)? {
            return Err(StoreError::RecoveryRequired);
        }
        let raw = c.query_row("SELECT operation_id,principal_id,kind,resource_id,status,result,created_at_ms,updated_at_ms FROM operations WHERE operation_id=?1", [id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,i64>(6)?,r.get::<_,i64>(7)?))).optional()?;
        raw.map(
            |(
                operation_id,
                principal_id,
                kind,
                resource_id,
                status,
                result,
                created_at_ms,
                updated_at_ms,
            )| {
                Ok(StoredOperation {
                    operation_id,
                    principal_id,
                    kind,
                    resource_id,
                    status,
                    result: serde_json::from_str(&result)?,
                    created_at_ms,
                    updated_at_ms,
                })
            },
        )
        .transpose()
    }
}

type RawRecord = (String, i64, String, i64, i64);
fn record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}
fn decode_record(
    (id, revision, payload, created_at_ms, updated_at_ms): RawRecord,
) -> Result<StoredRecord> {
    Ok(StoredRecord {
        id,
        revision: u64::try_from(revision)
            .map_err(|_| StoreError::InvalidInput("negative stored revision"))?,
        payload: serde_json::from_str(&payload)?,
        created_at_ms,
        updated_at_ms,
    })
}
fn read_record(c: &Connection, aggregate_type: &str, id: &str) -> Result<Option<StoredRecord>> {
    let record = c.query_row("SELECT id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type=?1 AND id=?2", params![aggregate_type,id],record_row).optional()?.map(decode_record).transpose()?;
    if matches!(
        aggregate_type,
        manual_enrollment::construction_claim_v2::CONSTRUCTION_CLAIM_V2
            | manual_enrollment::construction_claim_v2::CONSTRUCTION_CHECKPOINT_V2
            | manual_enrollment::construction_claim_v3::CONSTRUCTION_CLAIM_V3
            | manual_enrollment::construction_claim_v3::CONSTRUCTION_CHECKPOINT_V3
    ) {
        manual_enrollment::construction_claim_v2::read_construction_rows(c)?;
    }
    Ok(record)
}
fn replay(c: &Connection, context: &CommandContext) -> Result<Option<MutationResult>> {
    let value = c.query_row("SELECT request_digest,result FROM idempotency WHERE principal_id=?1 AND idempotency_key=?2", params![context.principal_id,context.idempotency_key],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?;
    value
        .map(|(digest, result)| {
            if digest != context.request_digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let mut result: MutationResult = serde_json::from_str(&result)?;
            result.replayed = true;
            Ok(result)
        })
        .transpose()
}
fn validate_context(c: &CommandContext) -> Result<()> {
    validate_id(&c.principal_id)?;
    if c.idempotency_key.len() < 16
        || c.idempotency_key.len() > 128
        || !c.idempotency_key.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(StoreError::InvalidInput(
            "idempotency key must be 16 to 128 visible ASCII bytes",
        ));
    }
    if c.request_digest.len() != 64
        || !c
            .request_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StoreError::InvalidInput(
            "request digest must be lowercase SHA-256 hex",
        ));
    }
    Ok(())
}
fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 256 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        Err(StoreError::InvalidInput(
            "identifier must be 1 to 256 visible ASCII bytes",
        ))
    } else {
        Ok(())
    }
}
fn encode(value: &Value) -> Result<String> {
    let encoded = serde_json::to_string(value)?;
    if encoded.len() > MAX_JSON_BYTES {
        Err(StoreError::InvalidInput("record exceeds one MiB limit"))
    } else {
        Ok(encoded)
    }
}
fn operation_id(c: &CommandContext) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact.operation.v1\0");
    for s in [&c.principal_id, &c.idempotency_key, &c.request_digest] {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    format!("op_{}", hex::encode(h.finalize()))
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub mod authority;
pub mod financial_preflight;
pub mod manual_enrollment;
pub mod settlement;

/// Immutable description of an external effect that has been durably intended.
/// It is not evidence of delivery, approval, network acceptance or inclusion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectIntent {
    pub operation_id: String,
    pub kind: String,
    pub resource_id: String,
    pub payload_digest: String,
    pub protected_payload_ref: String,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
impl Store {
    /// Call only after policy checks. A reference alone does not prove that the
    /// exact payload exists: the orchestrator must persist/verify it first.
    pub fn record_effect_intent(
        &self,
        operation_id: &str,
        kind: &str,
        resource_id: &str,
        payload_digest: &str,
        protected_payload_ref: &str,
    ) -> Result<EffectIntent> {
        for id in [operation_id, kind, resource_id, protected_payload_ref] {
            validate_id(id)?;
        }
        if payload_digest.len() != 64
            || !payload_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StoreError::InvalidInput(
                "effect payload digest must be lowercase SHA-256 hex",
            ));
        }
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.generation_fenced(&tx, "effect", operation_id)?
            || self.generation_fenced(&tx, "record", &format!("agreement:{resource_id}"))?
        {
            return Err(StoreError::RecoveryRequired);
        }
        crate::manual_enrollment::require_generic_operation_not_manual(&tx, operation_id)?;
        if let Some(old) = read_effect_intent(&tx, operation_id)? {
            if old.kind != kind
                || old.resource_id != resource_id
                || old.payload_digest != payload_digest
                || old.protected_payload_ref != protected_payload_ref
            {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(old);
        }
        let now = now_ms();
        // Even a crash before the actual external call is conservatively
        // unresolved. The persisted payload identity is the only retry target.
        tx.execute("INSERT INTO effect_intents(operation_id,kind,resource_id,payload_digest,protected_payload_ref,status,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,'outcome_unknown',?6,?6)",params![operation_id,kind,resource_id,payload_digest,protected_payload_ref,now])?;
        tx.commit()?;
        Ok(EffectIntent {
            operation_id: operation_id.into(),
            kind: kind.into(),
            resource_id: resource_id.into(),
            payload_digest: payload_digest.into(),
            protected_payload_ref: protected_payload_ref.into(),
            status: "outcome_unknown".into(),
            created_at_ms: now,
            updated_at_ms: now,
        })
    }
    pub fn effect_intent(&self, operation_id: &str) -> Result<Option<EffectIntent>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        read_effect_intent(&c, operation_id)
    }
    pub fn unresolved_effect_intents(&self) -> Result<Vec<EffectIntent>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut q=c.prepare("SELECT operation_id FROM effect_intents WHERE status='outcome_unknown' ORDER BY created_at_ms,operation_id")?;
        let ids = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|id| read_effect_intent(&c, id)?.ok_or(StoreError::NotFound))
            .collect()
    }
}
fn read_effect_intent(c: &Connection, id: &str) -> Result<Option<EffectIntent>> {
    Ok(c.query_row("SELECT operation_id,kind,resource_id,payload_digest,protected_payload_ref,status,created_at_ms,updated_at_ms FROM effect_intents WHERE operation_id=?1",[id],|r|Ok(EffectIntent{operation_id:r.get(0)?,kind:r.get(1)?,resource_id:r.get(2)?,payload_digest:r.get(3)?,protected_payload_ref:r.get(4)?,status:r.get(5)?,created_at_ms:r.get(6)?,updated_at_ms:r.get(7)?})).optional()?)
}

pub mod automation;
#[cfg(test)]
mod tests;

pub mod bundle;
pub mod history;
pub mod recovery;

#[cfg(all(test, target_os = "linux"))]
mod original_database_fail_fast_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn origin_requires_authenticated_constructor_and_actual_retained_handle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("synthetic-origin.sqlite");
        let key = wholepact_storage_security::DatabaseKey::from_bytes([0x78; 32]);
        let store = Store::create_encrypted(&path, &key).unwrap();
        let origin = store.original_database_origin_fail_fast().unwrap();
        assert_eq!(
            origin,
            store
                .original_database
                .as_ref()
                .unwrap()
                .origin_commitment()
        );
        {
            let _held = store.connection.lock().unwrap();
            assert!(matches!(
                store.original_database_origin_fail_fast(),
                Err(StoreError::ResourceExhausted)
            ));
        }
        assert!(
            Store::in_memory()
                .unwrap()
                .original_database_origin_fail_fast()
                .is_err()
        );
        // Deliberately violate Directory exclusion to test defensive detection;
        // this does not claim immunity against a hostile same-user race.
        std::fs::rename(&path, dir.path().join("retained-original.sqlite")).unwrap();
        std::fs::write(&path, [0u8; 4096]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.original_database_origin_fail_fast().is_err());
    }
}
