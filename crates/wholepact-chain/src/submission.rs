//! Encrypted exact-byte intent persistence and bounded dispatch/observation history.
use crate::ChainError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Serialized transaction bytes are retained by the journal, never emitted in Debug.
/// This owned buffer is zeroized on drop; maintained parsers/SQLite/RPC encoders may
/// make internal copies outside this wrapper, so this is not universal memory erasure.
/// This is an intent record, not permission to broadcast or proof of valid effects.
#[derive(Clone)]
pub struct ExactSubmissionIntent {
    operation_id: String,
    transaction_bytes: Zeroizing<Vec<u8>>,
    bytes_sha256: String,
}
impl ExactSubmissionIntent {
    pub fn new(operation_id: &str, bytes: &[u8]) -> Result<Self, ChainError> {
        validate_operation_id(operation_id)?;
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            return Err(ChainError::ResourceLimit);
        }
        Ok(Self {
            operation_id: operation_id.into(),
            transaction_bytes: Zeroizing::new(bytes.to_vec()),
            bytes_sha256: hex::encode(Sha256::digest(bytes)),
        })
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    /// Digest identifies exact serialized bytes; it is NOT the Zcash transaction id.
    pub fn bytes_sha256(&self) -> &str {
        &self.bytes_sha256
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionState {
    /// Committed before any dispatch; restart must conservatively consider possible delivery.
    SubmissionUnknown,
    /// One provider acknowledged; no inclusion, expiry, or exposure resolution is implied.
    BackendAcknowledged,
    /// Historical provider rejection, not current non-delivery. A later uncertain retry
    /// may have succeeded; other parties may also have broadcast these bytes.
    BackendRejected,
}
/// Implementations MUST atomically bind operation id to exact bytes, commit with durable
/// sync before returning, and reject changed-byte replays. Persistence is the store's
/// responsibility. No provider error or missing acknowledgment permits changing bytes.
pub trait SubmissionJournal {
    fn record_exact_intent(
        &mut self,
        intent: &ExactSubmissionIntent,
    ) -> Result<SubmissionState, ChainError>;
    fn record_backend_result(
        &mut self,
        operation_id: &str,
        state: SubmissionState,
    ) -> Result<(), ChainError>;
}

use rusqlite::{Connection, TransactionBehavior, params};
use wholepact_storage_security::EncryptedConnection;
#[cfg(feature = "submission-dispatch")]
#[path = "submission_history.rs"]
mod history;

#[derive(Debug, Clone, Serialize)]
pub struct SubmissionIntentSummary {
    pub operation_id: String,
    pub bytes_sha256: String,
    pub historical_provider_state: SubmissionState,
}

const APPLICATION_ID: i64 = 0x5750534a;
const MAX_RECORDS: i64 = 1024;
const MAX_TOTAL_BYTES: i64 = 64 * 1024 * 1024;

/// Dedicated encrypted journal, with no deletion, replacement or broadcast API.
/// An intent is opaque data, NOT evidence of authorization or valid transaction effects.
/// The caller must separately verify authorization before any future dispatch.
/// SQLCipher authenticates storage, not freshness: restoring an old copy cannot prove
/// absence of later submissions. Recovery must reconcile external exposure separately.
/// Limits are 1024 intents, 2 MiB per intent and 64 MiB of retained transaction bytes.
/// Records are never evicted to make room: exhaustion fails closed.
pub struct EncryptedSubmissionJournal {
    pub(crate) connection: Connection,
    journal_identity: String,
}
impl EncryptedSubmissionJournal {
    /// Accept only the protected-storage factory's opaque, authenticated disk handle.
    /// New schema creation and every mutation use FULL synchronous WAL commits.
    /// This constructor refuses foreign schemas and unknown versions; it never migrates
    /// plaintext, creates keys, or repairs corrupt records by silently discarding them.
    pub fn from_encrypted_connection(connection: EncryptedConnection) -> Result<Self, ChainError> {
        let mut connection = connection.into_connection();
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=4194304;")
            .map_err(|_| ChainError::JournalFailure)?;
        let page_limit: i64 = connection
            .query_row("PRAGMA max_page_count=32768", [], |r| r.get(0))
            .map_err(|_| ChainError::JournalFailure)?;
        if page_limit > 32768 {
            return Err(ChainError::ResourceLimit);
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        let app: i64 = tx
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| ChainError::JournalFailure)?;
        let version: i64 = tx
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| ChainError::JournalFailure)?;
        let objects: i64 = tx
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| ChainError::JournalFailure)?;
        if app == 0 && version == 0 && objects == 0 {
            tx.execute_batch("CREATE TABLE submission_intents(operation TEXT PRIMARY KEY NOT NULL CHECK(length(operation) BETWEEN 16 AND 128), bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 2097152), digest TEXT NOT NULL CHECK(length(digest)=64), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2)) STRICT;")
                .map_err(|_| ChainError::JournalFailure)?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(|_| ChainError::JournalFailure)?;
            tx.pragma_update(None, "user_version", 1)
                .map_err(|_| ChainError::JournalFailure)?;
        } else if app != APPLICATION_ID || !matches!((version, objects), (1, 1) | (2, 5) | (3, 7)) {
            return Err(ChainError::JournalFailure);
        }
        // Atomic additive migration preserves every existing exact intent. No row is
        // interpreted as previously authorized merely because it predated this schema.
        if version <= 1 {
            tx.execute_batch("CREATE TABLE submission_journal_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL CHECK(length(identity)=64)) STRICT;
                INSERT INTO submission_journal_identity(singleton,identity) VALUES(1,lower(hex(randomblob(32))));
                CREATE TABLE submission_bindings(operation TEXT PRIMARY KEY NOT NULL REFERENCES submission_intents(operation), obligation TEXT NOT NULL UNIQUE, descriptor TEXT NOT NULL CHECK(length(descriptor)<=4096)) STRICT;
                CREATE TABLE submission_attempts(operation TEXT NOT NULL REFERENCES submission_intents(operation), number INTEGER NOT NULL CHECK(number BETWEEN 1 AND 128), source TEXT NOT NULL, started INTEGER NOT NULL CHECK(started>=0), outcome TEXT NOT NULL CHECK(length(outcome)<=1024), PRIMARY KEY(operation,number)) STRICT;
                CREATE TABLE submission_observations(operation TEXT PRIMARY KEY NOT NULL REFERENCES submission_intents(operation), report TEXT NOT NULL CHECK(length(report)<=16384)) STRICT;")
                .map_err(|_| ChainError::JournalFailure)?;
            tx.pragma_update(None, "user_version", 2)
                .map_err(|_| ChainError::JournalFailure)?;
        }
        if version <= 2 {
            tx.execute_batch(include_str!("settlement_evidence_schema.sql"))
                .map_err(|_| ChainError::JournalFailure)?;
            tx.pragma_update(None, "user_version", 3)
                .map_err(|_| ChainError::JournalFailure)?;
        }
        tx.commit().map_err(|_| ChainError::JournalFailure)?;
        let journal_identity: String = connection
            .query_row(
                "SELECT identity FROM submission_journal_identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| ChainError::JournalFailure)?;
        if journal_identity.len() != 64
            || hex::decode(&journal_identity).map_or(true, |b| b.iter().all(|b| *b == 0))
        {
            return Err(ChainError::JournalFailure);
        }
        let journal = Self {
            connection,
            journal_identity,
        };
        journal.validate_records()?;
        journal.validate_history()?;
        Ok(journal)
    }

    /// Opaque destination binding, never an authority/freshness credential. A restored
    /// or cloned database intentionally retains its original identity.
    pub fn identity(&self) -> &str {
        &self.journal_identity
    }
    pub(crate) fn verify_identity(&self) -> Result<(), ChainError> {
        let (count, identity): (i64, String) = self
            .connection
            .query_row(
                "SELECT count(*),min(identity) FROM submission_journal_identity",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| ChainError::JournalFailure)?;
        if count != 1 || identity != self.journal_identity {
            return Err(ChainError::JournalFailure);
        }
        Ok(())
    }

    /// Safe recovery metadata. Exact retained bytes never leave this journal API.
    pub fn recover_intent_summary(
        &self,
        operation_id: &str,
    ) -> Result<Option<SubmissionIntentSummary>, ChainError> {
        self.recover_exact_intent(operation_id).map(|value| {
            value.map(|(intent, state)| SubmissionIntentSummary {
                operation_id: intent.operation_id().into(),
                bytes_sha256: intent.bytes_sha256().into(),
                historical_provider_state: state,
            })
        })
    }

    fn validate_records(&self) -> Result<(), ChainError> {
        let (count, size): (i64, i64) = self
            .connection
            .query_row(
                "SELECT count(*), coalesce(sum(length(bytes)),0) FROM submission_intents",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| ChainError::JournalFailure)?;
        if count > MAX_RECORDS || size > MAX_TOTAL_BYTES {
            return Err(ChainError::ResourceLimit);
        }
        let mut statement = self
            .connection
            .prepare("SELECT operation, bytes, digest, state FROM submission_intents")
            .map_err(|_| ChainError::JournalFailure)?;
        let mut rows = statement
            .query([])
            .map_err(|_| ChainError::JournalFailure)?;
        while let Some(row) = rows.next().map_err(|_| ChainError::JournalFailure)? {
            decode_record(row)?;
        }
        Ok(())
    }

    /// Recover exact persisted bytes after restart. This does not approve, sign,
    /// validate, or dispatch them, and provider results do not resolve exposure.
    pub(crate) fn recover_exact_intent(
        &self,
        operation_id: &str,
    ) -> Result<Option<(ExactSubmissionIntent, SubmissionState)>, ChainError> {
        validate_operation_id(operation_id)?;
        read_record(&self.connection, operation_id)
    }
}

pub(crate) fn validate_operation_id(id: &str) -> Result<(), ChainError> {
    if !(16..=128).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ChainError::InvalidConfiguration);
    }
    Ok(())
}
fn decode_record(
    row: &rusqlite::Row<'_>,
) -> Result<(ExactSubmissionIntent, SubmissionState), ChainError> {
    // Check borrowed SQLite values before allocating any potentially corrupt large blob.
    let id = row
        .get_ref(0)
        .and_then(|v| v.as_str().map_err(Into::into))
        .map_err(|_| ChainError::JournalFailure)?;
    let bytes = row
        .get_ref(1)
        .and_then(|v| v.as_blob().map_err(Into::into))
        .map_err(|_| ChainError::JournalFailure)?;
    let digest = row
        .get_ref(2)
        .and_then(|v| v.as_str().map_err(Into::into))
        .map_err(|_| ChainError::JournalFailure)?;
    if digest.len() != 64 {
        return Err(ChainError::JournalFailure);
    }
    let state: i64 = row.get(3).map_err(|_| ChainError::JournalFailure)?;
    let intent = ExactSubmissionIntent::new(id, bytes).map_err(|_| ChainError::JournalFailure)?;
    if digest != intent.bytes_sha256() {
        return Err(ChainError::JournalFailure);
    }
    let state = match state {
        0 => SubmissionState::SubmissionUnknown,
        1 => SubmissionState::BackendAcknowledged,
        2 => SubmissionState::BackendRejected,
        _ => return Err(ChainError::JournalFailure),
    };
    Ok((intent, state))
}
fn read_record(
    connection: &Connection,
    id: &str,
) -> Result<Option<(ExactSubmissionIntent, SubmissionState)>, ChainError> {
    let mut statement = connection
        .prepare(
            "SELECT operation, bytes, digest, state FROM submission_intents WHERE operation=?1",
        )
        .map_err(|_| ChainError::JournalFailure)?;
    let mut rows = statement
        .query([id])
        .map_err(|_| ChainError::JournalFailure)?;
    rows.next()
        .map_err(|_| ChainError::JournalFailure)?
        .map(decode_record)
        .transpose()
}
impl SubmissionJournal for EncryptedSubmissionJournal {
    fn record_exact_intent(
        &mut self,
        intent: &ExactSubmissionIntent,
    ) -> Result<SubmissionState, ChainError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        if let Some((old, state)) = read_record(&tx, intent.operation_id())? {
            if old.exact_bytes() != intent.exact_bytes() {
                return Err(ChainError::IdempotencyConflict);
            }
            tx.commit().map_err(|_| ChainError::JournalFailure)?;
            return Ok(state);
        }
        let (count, size): (i64, i64) = tx
            .query_row(
                "SELECT count(*), coalesce(sum(length(bytes)),0) FROM submission_intents",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| ChainError::JournalFailure)?;
        if count >= MAX_RECORDS || size + intent.exact_bytes().len() as i64 > MAX_TOTAL_BYTES {
            return Err(ChainError::ResourceLimit);
        }
        tx.execute(
            "INSERT INTO submission_intents(operation,bytes,digest,state) VALUES(?1,?2,?3,0)",
            params![
                intent.operation_id(),
                intent.exact_bytes(),
                intent.bytes_sha256()
            ],
        )
        .map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)?;
        Ok(SubmissionState::SubmissionUnknown)
    }
    fn record_backend_result(
        &mut self,
        id: &str,
        state: SubmissionState,
    ) -> Result<(), ChainError> {
        validate_operation_id(id)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        let (_, old) = read_record(&tx, id)?.ok_or(ChainError::JournalFailure)?;
        // Acknowledgment is a sticky observation, never settlement. A later rejection
        // or lost response cannot erase evidence that a provider received the bytes.
        let next = match (old, state) {
            (SubmissionState::BackendAcknowledged, _)
            | (_, SubmissionState::BackendAcknowledged) => 1,
            (SubmissionState::BackendRejected, _) | (_, SubmissionState::BackendRejected) => 2,
            _ => 0,
        };
        tx.execute(
            "UPDATE submission_intents SET state=?2 WHERE operation=?1",
            params![id, next],
        )
        .map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};

    const CANARY: &[u8] = b"SYNTHETIC-NOT-A-TRANSACTION-private-submission-343093";
    fn setup() -> (tempfile::TempDir, std::path::PathBuf, DatabaseKey) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("submission.sqlite");
        (dir, path, DatabaseKey::from_bytes([79; 32]))
    }
    // Fake delivery only; no network, signature, transaction validity or settlement.
    fn fake_dispatch(
        j: &mut impl SubmissionJournal,
        i: &ExactSubmissionIntent,
        f: impl FnOnce(&[u8]) -> SubmissionState,
    ) -> Result<(), ChainError> {
        j.record_exact_intent(i)?;
        j.record_backend_result(i.operation_id(), f(i.exact_bytes()))
    }
    #[test]
    fn encrypted_restart_replay_and_conservative_provider_observations() {
        let (dir, path, key) = setup();
        let i = ExactSubmissionIntent::new("synthetic-operation-1", CANARY).unwrap();
        let mut j = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        assert!(
            j.record_backend_result(i.operation_id(), SubmissionState::BackendAcknowledged)
                .is_err()
        );
        assert_eq!(
            j.record_exact_intent(&i).unwrap(),
            SubmissionState::SubmissionUnknown
        );
        // Simulated process loss after durable intent and before recording a result.
        drop(j);
        let mut j = EncryptedSubmissionJournal::from_encrypted_connection(
            open_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        let (restored, state) = j.recover_exact_intent(i.operation_id()).unwrap().unwrap();
        assert_eq!(restored.exact_bytes(), CANARY);
        assert_eq!(restored.bytes_sha256(), i.bytes_sha256());
        assert_eq!(state, SubmissionState::SubmissionUnknown);
        fake_dispatch(&mut j, &i, |b| {
            assert_eq!(b, CANARY);
            SubmissionState::SubmissionUnknown
        })
        .unwrap();
        j.record_backend_result(i.operation_id(), SubmissionState::BackendRejected)
            .unwrap();
        assert_eq!(
            j.record_exact_intent(&i).unwrap(),
            SubmissionState::BackendRejected
        );
        j.record_backend_result(i.operation_id(), SubmissionState::BackendAcknowledged)
            .unwrap();
        j.record_backend_result(i.operation_id(), SubmissionState::SubmissionUnknown)
            .unwrap();
        j.record_backend_result(i.operation_id(), SubmissionState::BackendRejected)
            .unwrap();
        let changed =
            ExactSubmissionIntent::new(i.operation_id(), b"different synthetic bytes").unwrap();
        assert_eq!(
            fake_dispatch(&mut j, &changed, |_| panic!("changed bytes dispatched")),
            Err(ChainError::IdempotencyConflict)
        );
        for entry in fs::read_dir(dir.path()).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(CANARY.len()).any(|b| b == CANARY));
        }
        drop(j);
        let mut j = EncryptedSubmissionJournal::from_encrypted_connection(
            open_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            j.record_exact_intent(&i).unwrap(),
            SubmissionState::BackendAcknowledged
        );
        drop(j);
        assert!(open_encrypted(&path, &DatabaseKey::from_bytes([80; 32])).is_err());
        // Authenticated pages cannot be silently reopened under corruption.
        let mut disk = fs::read(&path).unwrap();
        disk[100] ^= 1;
        fs::write(&path, disk).unwrap();
        assert!(open_encrypted(&path, &key).is_err());
    }

    #[test]
    fn bounds_schema_and_logical_corruption_fail_closed_before_dispatch() {
        let (_dir, path, key) = setup();
        assert!(ExactSubmissionIntent::new("short", CANARY).is_err());
        assert!(ExactSubmissionIntent::new("synthetic-operation-1", &[]).is_err());
        assert!(ExactSubmissionIntent::new("synthetic-operation-1", &vec![0; 2097153]).is_err());
        let mut j = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        // Fill the row budget in one test transaction, using valid synthetic data.
        let tx = j.connection.transaction().unwrap();
        for n in 0..MAX_RECORDS {
            tx.execute(
                "INSERT INTO submission_intents VALUES(?1,?2,?3,0)",
                params![
                    format!("synthetic-operation-{n}"),
                    CANARY,
                    hex::encode(Sha256::digest(CANARY))
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        let i = ExactSubmissionIntent::new("synthetic-operation-new", CANARY).unwrap();
        assert_eq!(
            fake_dispatch(&mut j, &i, |_| panic!("full journal dispatched")),
            Err(ChainError::ResourceLimit)
        );
        // Replays remain possible even when the budget is exhausted.
        assert_eq!(
            j.record_exact_intent(
                &ExactSubmissionIntent::new("synthetic-operation-0", CANARY).unwrap()
            )
            .unwrap(),
            SubmissionState::SubmissionUnknown
        );
        j.connection
            .execute(
                "UPDATE submission_intents SET digest=?1 WHERE operation='synthetic-operation-0'",
                ["0".repeat(64)],
            )
            .unwrap();
        assert!(j.recover_exact_intent("synthetic-operation-0").is_err());
        drop(j);
        assert!(
            EncryptedSubmissionJournal::from_encrypted_connection(
                open_encrypted(&path, &key).unwrap()
            )
            .is_err()
        );
        let db = open_encrypted(&path, &key).unwrap();
        db.connection()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        assert!(EncryptedSubmissionJournal::from_encrypted_connection(db).is_err());

        let (_large_dir, large_path, large_key) = setup();
        let mut large = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(&large_path, &large_key).unwrap(),
        )
        .unwrap();
        let bytes = vec![42; 2 * 1024 * 1024];
        let digest = hex::encode(Sha256::digest(&bytes));
        let tx = large.connection.transaction().unwrap();
        for n in 0..32 {
            tx.execute(
                "INSERT INTO submission_intents VALUES(?1,?2,?3,0)",
                params![format!("synthetic-large-{n:04}"), &bytes, &digest],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        assert_eq!(
            fake_dispatch(&mut large, &i, |_| panic!("byte budget exceeded")),
            Err(ChainError::ResourceLimit)
        );
        assert_eq!(
            large
                .record_exact_intent(
                    &ExactSubmissionIntent::new("synthetic-large-0000", &bytes).unwrap()
                )
                .unwrap(),
            SubmissionState::SubmissionUnknown
        );
    }

    #[test]
    fn failed_persistence_never_reaches_fake_dispatch() {
        let (_dir, path, key) = setup();
        let mut j = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        j.connection
            .pragma_update(None, "query_only", true)
            .unwrap();
        let i = ExactSubmissionIntent::new("synthetic-operation-1", CANARY).unwrap();
        assert_eq!(
            fake_dispatch(&mut j, &i, |_| panic!("failed persistence dispatched")),
            Err(ChainError::JournalFailure)
        );
        assert!(j.recover_exact_intent(i.operation_id()).unwrap().is_none());
    }
}

impl EncryptedSubmissionJournal {
    fn validate_history(&self) -> Result<(), ChainError> {
        self.verify_identity()?;
        let orphans: i64 = self.connection.query_row(
            "SELECT (SELECT count(*) FROM submission_bindings b LEFT JOIN submission_intents i ON b.operation=i.operation WHERE i.operation IS NULL) + (SELECT count(*) FROM submission_attempts a LEFT JOIN submission_bindings b ON a.operation=b.operation WHERE b.operation IS NULL) + (SELECT count(*) FROM submission_observations o LEFT JOIN submission_intents i ON o.operation=i.operation WHERE i.operation IS NULL)", [], |r| r.get(0)).map_err(|_| ChainError::JournalFailure)?;
        if orphans != 0 {
            return Err(ChainError::JournalFailure);
        }
        let mut stmt = self
            .connection
            .prepare("SELECT operation, report FROM submission_observations")
            .map_err(|_| ChainError::JournalFailure)?;
        let mut rows = stmt.query([]).map_err(|_| ChainError::JournalFailure)?;
        while let Some(row) = rows.next().map_err(|_| ChainError::JournalFailure)? {
            let report = decode_report(
                row.get_ref(1)
                    .and_then(|v| v.as_str().map_err(Into::into))
                    .map_err(|_| ChainError::JournalFailure)?,
            )?;
            let id: String = row.get(0).map_err(|_| ChainError::JournalFailure)?;
            let (intent, _) =
                read_record(&self.connection, &id)?.ok_or(ChainError::JournalFailure)?;
            validate_report_transaction(&intent, &report)?;
        }
        #[cfg(feature = "submission-dispatch")]
        self.validate_dispatch_history()?;
        // A featureless build cannot validate dispatch-specific schema contents and
        // therefore refuses them, rather than silently treating them as safe records.
        #[cfg(not(feature = "submission-dispatch"))]
        {
            let dispatch_rows: i64 = self.connection.query_row("SELECT (SELECT count(*) FROM submission_bindings)+(SELECT count(*) FROM submission_attempts)", [], |r| r.get(0)).map_err(|_| ChainError::JournalFailure)?;
            if dispatch_rows != 0 {
                return Err(ChainError::UnsupportedCapability);
            }
        }
        Ok(())
    }
    /// Persist only a bounded, normalized provider report. Never clears exposure.
    pub fn record_reconciliation(
        &mut self,
        operation_id: &str,
        report: &crate::ReconciliationReport,
    ) -> Result<(), ChainError> {
        validate_operation_id(operation_id)?;
        report.validate()?;
        let encoded = serde_json::to_string(report).map_err(|_| ChainError::JournalFailure)?;
        if encoded.len() > 16384 {
            return Err(ChainError::ResourceLimit);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ChainError::JournalFailure)?;
        let (intent, _) = read_record(&tx, operation_id)?.ok_or(ChainError::JournalFailure)?;
        validate_report_transaction(&intent, report)?;
        if let Some(previous) = read_report(&tx, operation_id)? {
            if report.observed_at_unix_seconds < previous.observed_at_unix_seconds {
                return Err(ChainError::StaleChain);
            }
            if report.policy != previous.policy
                || report.transaction_id != previous.transaction_id
                || report.expiry_height != previous.expiry_height
            {
                return Err(ChainError::IdempotencyConflict);
            }
            if previous.last_inclusion.is_some() && report.last_inclusion.is_none() {
                return Err(ChainError::ContradictoryChain);
            }
        }
        tx.execute("INSERT INTO submission_observations(operation,report) VALUES(?1,?2) ON CONFLICT(operation) DO UPDATE SET report=excluded.report", params![operation_id, encoded]).map_err(|_| ChainError::JournalFailure)?;
        tx.commit().map_err(|_| ChainError::JournalFailure)
    }
    /// Restored reports are marked stale before returning, regardless of saved TTL.
    pub fn recover_reconciler(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::SettlementReconciler>, ChainError> {
        validate_operation_id(operation_id)?;
        read_report(&self.connection, operation_id)?
            .map(crate::SettlementReconciler::restore)
            .transpose()
    }
}
fn validate_report_transaction(
    intent: &ExactSubmissionIntent,
    report: &crate::ReconciliationReport,
) -> Result<(), ChainError> {
    let expected = zcash_protocol::TxId::from_hex(&report.transaction_id)
        .ok_or(ChainError::MalformedEvidence)?;
    crate::verify_transaction_id(intent.exact_bytes(), expected)?;
    let tx = zcash_primitives::transaction::Transaction::read(
        intent.exact_bytes(),
        zcash_protocol::consensus::BranchId::Nu7,
    )
    .map_err(|_| ChainError::MalformedEvidence)?;
    if u32::from(tx.expiry_height()) != report.expiry_height {
        return Err(ChainError::ContradictoryChain);
    }
    Ok(())
}
fn decode_report(encoded: &str) -> Result<crate::ReconciliationReport, ChainError> {
    if encoded.len() > 16384 {
        return Err(ChainError::ResourceLimit);
    }
    let report: crate::ReconciliationReport =
        serde_json::from_str(encoded).map_err(|_| ChainError::JournalFailure)?;
    report.validate().map_err(|_| ChainError::JournalFailure)?;
    Ok(report)
}
fn read_report(
    connection: &Connection,
    id: &str,
) -> Result<Option<crate::ReconciliationReport>, ChainError> {
    let mut stmt = connection
        .prepare("SELECT report FROM submission_observations WHERE operation=?1")
        .map_err(|_| ChainError::JournalFailure)?;
    let mut rows = stmt.query([id]).map_err(|_| ChainError::JournalFailure)?;
    rows.next()
        .map_err(|_| ChainError::JournalFailure)?
        .map(|row| {
            decode_report(
                row.get_ref(0)
                    .and_then(|v| v.as_str().map_err(Into::into))
                    .map_err(|_| ChainError::JournalFailure)?,
            )
        })
        .transpose()
}

// Synthetic protected-storage boundary tests only. No account, network,
// signing, proof execution, enrollment or live credential is created.
#[cfg(all(test, target_os = "linux"))]
mod internal_name_filter_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wholepact-schema-EncryptedSubmissionJournal-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn sqlite_prefix_user_table_and_trigger_cannot_admit_initialization() {
        for trigger in [false, true] {
            let dir = Temp::new();
            let path = dir.0.join("synthetic.sqlite");
            let key = DatabaseKey::from_bytes([0x75; 32]);
            let encrypted = create_encrypted(&path, &key).unwrap();
            encrypted.connection().execute_batch("CREATE TABLE sqliteXextra(value TEXT); INSERT INTO sqliteXextra VALUES('synthetic-preserved');").unwrap();
            if trigger {
                encrypted.connection().execute_batch("CREATE TRIGGER sqliteXtrigger AFTER INSERT ON sqliteXextra BEGIN SELECT 1; END;").unwrap();
            }
            assert!(matches!(
                EncryptedSubmissionJournal::from_encrypted_connection(encrypted),
                Err(ChainError::JournalFailure)
            ));
            let reopened = open_encrypted(&path, &key).unwrap();
            let c = reopened.connection();
            let app: i64 = c
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .unwrap();
            let version: i64 = c
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!((app, version), (0, 0));
            let preserved: String = c
                .query_row("SELECT value FROM sqliteXextra", [], |r| r.get(0))
                .unwrap();
            assert_eq!(preserved, "synthetic-preserved");
            let initialized: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='submission_intents')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!initialized);
        }
    }
    #[test]
    fn legitimate_sqlite_internal_objects_allow_initialization_and_exact_reopen() {
        let dir = Temp::new();
        let path = dir.0.join("synthetic.sqlite");
        let key = DatabaseKey::from_bytes([0x76; 32]);
        let encrypted = create_encrypted(&path, &key).unwrap();
        encrypted.connection().execute_batch("ANALYZE;").unwrap();
        let stats: bool = encrypted
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_stat1')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stats);
        let journal = EncryptedSubmissionJournal::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = EncryptedSubmissionJournal::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
    #[test]
    fn existing_submission_journal_rejects_sqlite_prefix_extra_table_or_trigger() {
        for sql in [
            "CREATE TABLE sqliteXextra(value TEXT)",
            "CREATE TRIGGER sqliteXextra AFTER INSERT ON submission_intents BEGIN SELECT 1; END",
        ] {
            let dir = Temp::new();
            let path = dir.0.join("synthetic.sqlite");
            let key = DatabaseKey::from_bytes([0x77; 32]);
            let journal = EncryptedSubmissionJournal::from_encrypted_connection(
                create_encrypted(&path, &key).unwrap(),
            )
            .unwrap();
            drop(journal);
            let changed = open_encrypted(&path, &key).unwrap();
            changed.connection().execute_batch(sql).unwrap();
            assert!(matches!(
                EncryptedSubmissionJournal::from_encrypted_connection(changed),
                Err(ChainError::JournalFailure)
            ));
        }
    }
}
