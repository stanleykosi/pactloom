//! Encrypted, local-only private checkpoints and recoverable proof jobs.
//!
//! The consent implementation is a trusted embedding boundary, not a human
//! approval flag supplied by an application. This crate never signs, broadcasts,
//! exports, authenticates a person, or grants distribution permission. Encryption
//! is confidentiality at rest, not clone detection or authority-journal freshness.

mod original_read_revision_v3;
mod policy;
mod status_snapshot;
pub use original_read_revision_v3::OriginalProofReadRevisionV3;
pub use status_snapshot::ProofStatusSnapshot;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Mutex};
use thiserror::Error;
use wholepact_protocol::{
    proving::{MAX_PROVING_ACTIONS, ProvingLimits, prove_reviewed, verify_proved_candidate},
    review::{ReviewPolicy, verify_review},
};
use wholepact_storage_security::{DatabaseFileIdentity, EncryptedConnection};
use zeroize::Zeroizing;

const APPLICATION_ID: i64 = 0x5750504a;
const MAX_ARTIFACT_BYTES: usize = 1_048_576;
const MAX_POLICY_BYTES: usize = 131_072;
const MAX_JOBS: i64 = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JobError {
    #[error("local private-data permission is missing or revoked")]
    ConsentDenied,
    #[error("proof job was not found in the caller's scope")]
    NotFound,
    #[error("invalid or unsupported private checkpoint request")]
    InvalidRequest,
    #[error("private artifact or economic binding verification failed")]
    VerificationFailed,
    #[error("idempotency key already names a different checkpoint request")]
    IdempotencyConflict,
    #[error("proof job requires explicit interrupted-worker recovery")]
    RecoveryRequired,
    #[error("proof job is not in the expected state or attempt")]
    StateConflict,
    #[error("encrypted proof job storage failed; reopen and inspect durable state")]
    Storage,
    #[error("unsupported encrypted proof job schema")]
    UnsupportedSchema,
    #[error("local proof queue capacity reached")]
    ResourceExhausted,
}
pub type Result<T> = std::result::Result<T, JobError>;

/// Exact local retention/proving scope. No field establishes human approval.
/// Construct this from trusted local agreement and consent records, not a remote
/// request. Full dedicated-account FVKs remain privacy-sensitive indefinitely.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointScope {
    pub principal_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub effects_commitment: String,
    pub coordination_request_digest: String,
    pub review_binding: String,
    pub account_ids: Vec<String>,
    pub local_operator: String,
    pub purpose: String,
    pub retention_policy: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAction {
    InspectStatus,
    RetainPrivateWitnesses,
    ProveLocally,
    ReadPrivateArtifact,
    RecoverInterrupted,
}

/// The embedding authenticates the caller and verifies current exact consent
/// for all named accounts/operator/purpose/retention. Return false on incomplete,
/// expired or revoked consent. There is deliberately no permissive implementation,
/// deserializable permit, or network/human authorization side effect here.
pub trait LocalProofConsent {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Uncertain,
    Succeeded,
    Failed,
}
impl JobState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Uncertain => "uncertain",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "uncertain" => Ok(Self::Uncertain),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(JobError::Storage),
        }
    }
}

/// Minimal status only: no FVK, witnesses, raw artifacts, account roster or policy.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct JobSummary {
    pub job_id: String,
    pub scope_digest: String,
    pub candidate_id: String,
    pub state: JobState,
    pub attempt: u32,
    pub input_digest: String,
    pub manifest_digest: String,
    pub effects_commitment: String,
    pub coordination_request_digest: String,
    pub result_digest: Option<String>,
    pub review_binding: String,
    pub encrypted_checkpoint_created: bool,
    pub proof_verified: bool,
    pub chain_validated: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
}

/// Sensitive local output, intentionally neither Debug nor Serialize. Returning
/// these bytes to a remote caller or transport needs a separate disclosure path.
pub struct VerifiedCheckpoint {
    original_bytes: Zeroizing<Vec<u8>>,
    bytes: Zeroizing<Vec<u8>>,
    summary: JobSummary,
    scope: CheckpointScope,
    policy: ReviewPolicy,
}
impl VerifiedCheckpoint {
    /// The exact immutable unsigned predecessor, under the same current private
    /// artifact read consent as the proved result. This is data, never authority.
    pub fn private_unsigned_pczt_bytes(&self) -> &[u8] {
        &self.original_bytes
    }
    pub fn summary(&self) -> &JobSummary {
        &self.summary
    }
    /// Protected local policy, never an application DTO or disclosure grant.
    pub fn policy(&self) -> &ReviewPolicy {
        &self.policy
    }
    pub fn scope(&self) -> &CheckpointScope {
        &self.scope
    }
    pub fn pczt_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct ProofJobStore {
    connection: Mutex<Connection>,
    // Populated only by the purpose-specific authenticated factory. Legacy
    // stores do not acquire an original-workspace identity merely by opening.
    original_database: Option<DatabaseFileIdentity>,
}

/// Borrow of one actual authenticated proof store, never a permission token.
/// The embedding retains the original profile/directory exclusion owner and
/// independently joins this origin to its immutable workspace association.
/// No raw store, key, connection, or token-free proof runner is exposed.
pub struct OriginalProofJobSourceV1<'a> {
    store: &'a ProofJobStore,
    origin: &'a DatabaseFileIdentity,
}

/// Actual enqueue outcome. An identical retained row is data-only replay and
/// never yields another live first-attempt continuation.
pub struct OriginalEnqueueOutcomeV1<'a> {
    summary: JobSummary,
    fresh: Option<FreshOriginalEnqueueV1<'a>>,
}
impl<'a> OriginalEnqueueOutcomeV1<'a> {
    pub fn into_parts(self) -> (JobSummary, Option<FreshOriginalEnqueueV1<'a>>) {
        (self.summary, self.fresh)
    }
}

/// Non-Clone, non-serializable process continuity from one confirmed original
/// INSERT + Queued event + commit. It is not native permission: the embedding
/// must also own its newly committed constructor receipt and current consent.
/// Drop, ambiguous commit, replay and reopen cannot recreate this value.
pub struct FreshOriginalEnqueueV1<'a> {
    source: OriginalProofJobSourceV1<'a>,
    scope: CheckpointScope,
    request_digest: String,
    summary: JobSummary,
}
impl FreshOriginalEnqueueV1<'_> {
    pub fn summary(&self) -> &JobSummary {
        &self.summary
    }
    pub fn matches_source(&self, source: &OriginalProofJobSourceV1<'_>) -> bool {
        std::ptr::eq(self.source.store, source.store) && self.source.origin == source.origin
    }
    /// Consume continuity BEFORE admission. The original atomic Queued/attempt0
    /// gate and every current consent check still execute on the exact row.
    pub fn run_original_queued_v1(self, consent: &dyn LocalProofConsent) -> Result<JobSummary> {
        self.source.check_current()?;
        self.source.store.run_mode_checked(
            &self.scope.principal_id,
            &self.summary.job_id,
            consent,
            true,
            Some((&self.source, &self.scope, &self.request_digest)),
        )
    }
}

impl<'a> OriginalProofJobSourceV1<'a> {
    pub fn origin_commitment(&self) -> [u8; 32] {
        self.origin.origin_commitment()
    }
    pub fn check_current(&self) -> Result<()> {
        let connection = self
            .store
            .connection
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => JobError::ResourceExhausted,
                std::sync::TryLockError::Poisoned(_) => JobError::Storage,
            })?;
        check_original_connection(Some(self.origin), &connection)
    }
    pub fn status_for_key(
        &self,
        principal: &str,
        idempotency_key: &str,
        coordination_request_digest: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<Option<JobSummary>> {
        self.check_current()?;
        self.store.status_for_key_checked(
            principal,
            idempotency_key,
            coordination_request_digest,
            consent,
            Some(self.origin),
        )
    }
    pub fn status(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        self.check_current()?;
        self.store
            .status_checked(principal, job_id, consent, Some(self.origin))
    }
    pub fn load_verified(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<VerifiedCheckpoint> {
        self.check_current()?;
        self.store
            .load_verified_checked(principal, job_id, consent, Some(self.origin))
    }
    /// Commitment to the exact immutable event history of this ONE original
    /// completed attempt. This is not proof verification or a whole-journal
    /// audit: the caller must also load_verified and join its retained lineage.
    pub fn original_attempt_history_digest_v1(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<String> {
        self.check_current()?;
        let mut connection = self
            .store
            .connection
            .lock()
            .map_err(|_| JobError::Storage)?;
        check_original_connection(Some(self.origin), &connection)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(db)?;
        let retained = record(&tx, principal, job_id)?.ok_or(JobError::NotFound)?;
        gate(consent, &retained.scope, LocalAction::InspectStatus)?;
        let events = {
            let mut statement = tx.prepare(
                "SELECT sequence,CASE WHEN typeof(state)='text' AND length(state)<=16 THEN state ELSE NULL END,attempt FROM proof_events WHERE job_id=?1 ORDER BY sequence LIMIT 4",
            ).map_err(db)?;
            let rows = statement
                .query_map([job_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                })
                .map_err(db)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db)?
        };
        let digest = original_event_history_digest_v1(&retained, &events)?;
        gate(consent, &retained.scope, LocalAction::InspectStatus)?;
        check_original_connection(Some(self.origin), &tx)?;
        // Read-only snapshot: no status repair, new event, or proof admission.
        drop(tx);
        check_original_connection(Some(self.origin), &connection)?;
        Ok(digest)
    }

    pub fn enqueue_original_once_v1(
        &self,
        scope: &CheckpointScope,
        idempotency_key: &str,
        pczt: &[u8],
        policy: &ReviewPolicy,
        limits: ProvingLimits,
        consent: &dyn LocalProofConsent,
    ) -> Result<OriginalEnqueueOutcomeV1<'a>> {
        self.check_current()?;
        let (summary, created, request_digest) = self.store.enqueue_with_mode_checked(
            EnqueueInput {
                scope,
                idempotency_key,
                pczt,
                policy,
                limits,
            },
            consent,
            EnqueueMode::FailFast,
            Some(self.origin),
        )?;
        let fresh = created.then(|| FreshOriginalEnqueueV1 {
            source: OriginalProofJobSourceV1 {
                store: self.store,
                origin: self.origin,
            },
            scope: scope.clone(),
            request_digest,
            summary: summary.clone(),
        });
        Ok(OriginalEnqueueOutcomeV1 { summary, fresh })
    }
}

fn original_event_history_digest_v1(
    retained: &Record,
    events: &[(i64, String, u32)],
) -> Result<String> {
    if retained.summary.state != JobState::Succeeded
        || retained.summary.attempt != 1
        || events.len() != 3
        || events
            .iter()
            .zip([("queued", 0), ("running", 1), ("succeeded", 1)])
            .any(|((sequence, state, attempt), (expected, number))| {
                *sequence <= 0 || state != expected || *attempt != number
            })
        || events.windows(2).any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(JobError::StateConflict);
    }
    let body = serde_json::to_vec(&(
        &retained.scope,
        &retained.request_digest,
        &retained.summary,
        events,
    ))
    .map_err(|_| JobError::Storage)?;
    let mut hash = Sha256::new();
    hash.update(b"wholepact:original-proof-selected-attempt-history:v1\0");
    hash.update((body.len() as u64).to_le_bytes());
    hash.update(body);
    Ok(hex::encode(hash.finalize()))
}

fn check_original_connection(
    origin: Option<&DatabaseFileIdentity>,
    connection: &Connection,
) -> Result<()> {
    if let Some(origin) = origin {
        origin
            .check_current(connection)
            .map_err(|_| JobError::Storage)?;
    }
    Ok(())
}
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::Duration;

struct EnqueueInput<'a> {
    scope: &'a CheckpointScope,
    idempotency_key: &'a str,
    pczt: &'a [u8],
    policy: &'a ReviewPolicy,
    limits: ProvingLimits,
}

#[derive(Clone, Copy)]
enum EnqueueMode {
    Existing,
    FailFast,
}
impl EnqueueMode {
    fn with_connection<T>(
        self,
        connection: &mut rusqlite::Connection,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Existing => operation(connection),
            Self::FailFast => with_zero_busy_timeout(connection, operation),
        }
    }
}

/// Called only while the caller owns this connection's mutex. The supported
/// stores use SQLite timeout policies, never caller-installed busy callbacks.
/// Capture the actual previous timeout; do not assume the factory's 5 seconds.
/// This limits lock contention, not synchronous SQLite/fsync/filesystem time.
fn with_zero_busy_timeout<T>(
    connection: &mut rusqlite::Connection,
    operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    let milliseconds: u32 = connection
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .map_err(db)?;
    // SQLite cannot recover an arbitrary custom busy callback. A zero value
    // does not distinguish such a callback from a known immediate policy, so
    // this dedicated adapter refuses it rather than silently replacing it.
    if milliseconds == 0 || milliseconds > i32::MAX as u32 {
        return Err(JobError::Storage);
    }
    let previous = Duration::from_millis(u64::from(milliseconds));
    // Catch only to restore the connection policy before resuming the same
    // unwind. No panic is converted into permission or a successful operation.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        connection.busy_timeout(Duration::ZERO).map_err(db)?;
        operation(connection)
    }));
    let restored = connection.busy_timeout(previous);
    match (outcome, restored) {
        (Ok(result), Ok(())) => result,
        // This may follow a durable commit. Returning an error must preserve
        // the original claim/checkpoint uncertainty and never permit retry.
        (Ok(_), Err(error)) => Err(db(error)),
        (Err(payload), Ok(())) => resume_unwind(payload),
        // Do not suppress restoration failure during unwinding. This occurs
        // outside the caught unwind, so the held mutex is poisoned normally.
        // The stricter no-wait policy may remain; no wait is silently widened.
        (Err(_), Err(_)) => panic!("SQLite busy timeout restoration failed during unwind"),
    }
}

struct Record {
    scope: CheckpointScope,
    request_digest: String,
    summary: JobSummary,
    maximum_actions: usize,
}
struct PrivateRecord {
    record: Record,
    input: Zeroizing<Vec<u8>>,
    policy_bytes: Zeroizing<Vec<u8>>,
    result: Option<Zeroizing<Vec<u8>>>,
}

impl ProofJobStore {
    /// A dedicated database only. No plaintext/in-memory constructor exists.
    /// Opening never declares an in-flight worker dead or restarts work silently.
    pub fn from_encrypted_connection(encrypted: EncryptedConnection) -> Result<Self> {
        let mut connection = encrypted.into_connection();
        let app: i64 = connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(db)?;
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db)?;
        if app == 0 && version == 0 {
            let tables: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                    [],
                    |r| r.get(0),
                )
                .map_err(db)?;
            if tables != 0 {
                return Err(JobError::UnsupportedSchema);
            }
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            tx.execute_batch("CREATE TABLE proof_jobs (
              job_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, idem_key TEXT NOT NULL,
              request_digest TEXT NOT NULL, scope BLOB NOT NULL, input_digest TEXT NOT NULL,
              input BLOB NOT NULL, policy BLOB NOT NULL, maximum_actions INTEGER NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('queued','running','uncertain','succeeded','failed')),
              attempt INTEGER NOT NULL DEFAULT 0, result BLOB, result_digest TEXT,
              UNIQUE(principal_id,idem_key), CHECK(length(input)<=1048576),
              CHECK(length(policy)<=131072), CHECK(result IS NULL OR length(result)<=1048576),
              CHECK((state='succeeded')=(result IS NOT NULL AND result_digest IS NOT NULL))
            );
            CREATE TABLE proof_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              job_id TEXT NOT NULL REFERENCES proof_jobs(job_id), state TEXT NOT NULL, attempt INTEGER NOT NULL);
            PRAGMA application_id=1464881226; PRAGMA user_version=1;") .map_err(db)?;
            tx.commit().map_err(db)?;
        } else if app != APPLICATION_ID || version != 1 {
            return Err(JobError::UnsupportedSchema);
        }
        Ok(Self {
            connection: Mutex::new(connection),
            original_database: None,
        })
    }

    /// Purpose-specific source factory. Capture the authenticated live origin
    /// before consuming the connection; the legacy schema/init behavior is
    /// unchanged. Original reopen must separately preflight its initialized
    /// schema and compare this origin with the retained association.
    pub fn from_original_encrypted_connection_v1(encrypted: EncryptedConnection) -> Result<Self> {
        let origin = encrypted
            .database_identity()
            .map_err(|_| JobError::Storage)?;
        let mut store = Self::from_encrypted_connection(encrypted)?;
        origin
            .check_current(store.connection.get_mut().map_err(|_| JobError::Storage)?)
            .map_err(|_| JobError::Storage)?;
        store.original_database = Some(origin);
        Ok(store)
    }

    pub fn original_source_v1(&self) -> Result<OriginalProofJobSourceV1<'_>> {
        let source = OriginalProofJobSourceV1 {
            store: self,
            origin: self
                .original_database
                .as_ref()
                .ok_or(JobError::InvalidRequest)?,
        };
        source.check_current()?;
        Ok(source)
    }

    /// Commits the immutable unproved candidate, private policy and job intent in
    /// one encrypted FULL-synchronous transaction before any proof work. Replay
    /// never reconstructs a candidate or replaces randomized bytes.
    pub fn enqueue(
        &self,
        scope: &CheckpointScope,
        idempotency_key: &str,
        pczt: &[u8],
        policy: &ReviewPolicy,
        limits: ProvingLimits,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        self.enqueue_with_mode(
            EnqueueInput {
                scope,
                idempotency_key,
                pczt,
                policy,
                limits,
            },
            consent,
            EnqueueMode::Existing,
        )
    }
    /// Same exact validation, current consent and immutable idempotency, with
    /// no mutex/SQLite contention wait. This does not execute a proof and does
    /// not promise a hard deadline for synchronous storage/verification work.
    /// Consent callbacks may reenter Store, never this proof journal.
    pub fn enqueue_fail_fast(
        &self,
        scope: &CheckpointScope,
        idempotency_key: &str,
        pczt: &[u8],
        policy: &ReviewPolicy,
        limits: ProvingLimits,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        self.enqueue_with_mode(
            EnqueueInput {
                scope,
                idempotency_key,
                pczt,
                policy,
                limits,
            },
            consent,
            EnqueueMode::FailFast,
        )
    }
    fn enqueue_with_mode(
        &self,
        input: EnqueueInput<'_>,
        consent: &dyn LocalProofConsent,
        mode: EnqueueMode,
    ) -> Result<JobSummary> {
        self.enqueue_with_mode_checked(input, consent, mode, None)
            .map(|(summary, _, _)| summary)
    }
    fn enqueue_with_mode_checked(
        &self,
        input: EnqueueInput<'_>,
        consent: &dyn LocalProofConsent,
        mode: EnqueueMode,
        origin: Option<&DatabaseFileIdentity>,
    ) -> Result<(JobSummary, bool, String)> {
        let EnqueueInput {
            scope,
            idempotency_key,
            pczt,
            policy,
            limits,
        } = input;
        validate_scope(scope)?;
        gate(consent, scope, LocalAction::RetainPrivateWitnesses)?;
        if !(16..=128).contains(&idempotency_key.len())
            || !idempotency_key.bytes().all(|b| (33..=126).contains(&b))
            || pczt.len() > MAX_ARTIFACT_BYTES
            || !(1..=MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
        {
            return Err(JobError::InvalidRequest);
        }
        let encoded = policy::encode(policy)?;
        let scope_bytes = serde_json::to_vec(scope).map_err(|_| JobError::InvalidRequest)?;
        let input_digest = digest(pczt);
        let request_digest = framed_digest(&[
            &scope_bytes,
            pczt,
            &encoded,
            &(limits.maximum_actions as u64).to_le_bytes(),
        ]);
        let job_id = job_id_for_key(&scope.principal_id, idempotency_key)?;
        let mut connection = match mode {
            EnqueueMode::Existing => self.connection.lock().map_err(|_| JobError::Storage)?,
            EnqueueMode::FailFast => self.connection.try_lock().map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => JobError::ResourceExhausted,
                std::sync::TryLockError::Poisoned(_) => JobError::Storage,
            })?,
        };
        check_original_connection(origin, &connection)?;
        let outcome = mode.with_connection(&mut connection, |connection| {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        if let Some(existing) = record(&tx, &scope.principal_id, &job_id)? {
            if existing.request_digest != request_digest {
                return Err(JobError::IdempotencyConflict);
            }
            gate(
                consent,
                &existing.scope,
                LocalAction::RetainPrivateWitnesses,
            )?;
            check_original_connection(origin, &tx)?;
            return Ok((existing.summary, false, request_digest));
        }
        if tx
            .query_row("SELECT count(*) FROM proof_jobs", [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(db)?
            >= MAX_JOBS
        {
            return Err(JobError::ResourceExhausted);
        }
        validate_input(pczt, policy, scope, limits)?;
        gate(consent, scope, LocalAction::RetainPrivateWitnesses)?;
        check_original_connection(origin, &tx)?;
        tx.execute("INSERT INTO proof_jobs(job_id,principal_id,idem_key,request_digest,scope,input_digest,input,policy,maximum_actions,state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'queued')",
            params![job_id, scope.principal_id, idempotency_key, request_digest, scope_bytes, input_digest, pczt, encoded.as_slice(), limits.maximum_actions as u32]).map_err(db)?;
        event(&tx, &job_id, JobState::Queued, 0)?;
        let summary = record(&tx, &scope.principal_id, &job_id)?
            .ok_or(JobError::Storage)?
            .summary;
        gate(consent, scope, LocalAction::RetainPrivateWitnesses)?;
        check_original_connection(origin, &tx)?;
        tx.commit().map_err(db)?;
        Ok((summary, true, request_digest))
        })?;
        check_original_connection(origin, &connection)?;
        Ok(outcome)
    }

    /// Recover a stable job identity before randomized construction. This is
    /// useful when a separate coordination-summary commit was interrupted after
    /// the private checkpoint committed. None is the only absent result;
    /// storage/permission errors must never be treated as permission to rebuild.
    pub fn status_for_key(
        &self,
        principal: &str,
        idempotency_key: &str,
        expected_coordination_request_digest: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<Option<JobSummary>> {
        self.status_for_key_checked(
            principal,
            idempotency_key,
            expected_coordination_request_digest,
            consent,
            None,
        )
    }
    fn status_for_key_checked(
        &self,
        principal: &str,
        idempotency_key: &str,
        expected_coordination_request_digest: &str,
        consent: &dyn LocalProofConsent,
        origin: Option<&DatabaseFileIdentity>,
    ) -> Result<Option<JobSummary>> {
        if !hash_text(expected_coordination_request_digest)
            || !bounded(principal, 128)
            || !(16..=128).contains(&idempotency_key.len())
            || !idempotency_key.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(JobError::InvalidRequest);
        }
        let job_id = job_id_for_key(principal, idempotency_key)?;
        let connection = self.connection.lock().map_err(|_| JobError::Storage)?;
        check_original_connection(origin, &connection)?;
        let Some(r) = record(&connection, principal, &job_id)? else {
            check_original_connection(origin, &connection)?;
            return Ok(None);
        };
        gate(consent, &r.scope, LocalAction::InspectStatus)?;
        if r.scope.coordination_request_digest != expected_coordination_request_digest {
            return Err(JobError::IdempotencyConflict);
        }
        check_original_connection(origin, &connection)?;
        Ok(Some(r.summary))
    }

    pub fn status(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        self.status_checked(principal, job_id, consent, None)
    }
    fn status_checked(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
        origin: Option<&DatabaseFileIdentity>,
    ) -> Result<JobSummary> {
        let connection = self.connection.lock().map_err(|_| JobError::Storage)?;
        check_original_connection(origin, &connection)?;
        let r = record(&connection, principal, job_id)?.ok_or(JobError::NotFound)?;
        gate(consent, &r.scope, LocalAction::InspectStatus)?;
        check_original_connection(origin, &connection)?;
        Ok(r.summary)
    }

    /// Explicitly fence an interrupted/unknown attempt. A still-running worker
    /// loses its ability to commit. This is not proof that its memory was erased.
    /// The operator must establish the old process stopped before starting more
    /// CPU work; a database open alone never supplies that evidence.
    pub fn recover_interrupted(
        &self,
        principal: &str,
        job_id: &str,
        expected_attempt: u32,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        let mut connection = self.connection.lock().map_err(|_| JobError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let r = record(&tx, principal, job_id)?.ok_or(JobError::NotFound)?;
        gate(consent, &r.scope, LocalAction::RecoverInterrupted)?;
        if r.summary.attempt != expected_attempt || r.summary.state != JobState::Running {
            return Err(JobError::StateConflict);
        }
        tx.execute(
            "UPDATE proof_jobs SET state='uncertain' WHERE job_id=?1",
            [job_id],
        )
        .map_err(db)?;
        event(&tx, job_id, JobState::Uncertain, expected_attempt)?;
        let summary = record(&tx, principal, job_id)?
            .ok_or(JobError::Storage)?
            .summary;
        tx.commit().map_err(db)?;
        Ok(summary)
    }

    /// Synchronous CPU work: the embedding must use a bounded worker. A durable
    /// running intent precedes proving; success and exact bytes commit together.
    /// An explicit uncertain state may retry only the identical saved candidate.
    /// Completed calls verify and replay the saved proof, never regenerate it.
    pub fn run(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        self.run_mode(principal, job_id, consent, false)
    }

    /// One first attempt of an original saved queued job only. Unlike `run`,
    /// this never retries uncertain work or replays a completed result. The
    /// exact state/attempt restriction is checked under the SAME immediate
    /// transaction that admits Running, not a racy external status preflight.
    /// The embedding still authenticates the actual retained constructor and
    /// exact saved-scope native permission; job IDs alone grant no permission.
    pub fn run_original_queued(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<JobSummary> {
        self.run_mode(principal, job_id, consent, true)
    }

    fn run_mode(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
        original_queued_only: bool,
    ) -> Result<JobSummary> {
        self.run_mode_checked(principal, job_id, consent, original_queued_only, None)
    }
    fn run_mode_checked(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
        original_queued_only: bool,
        original: Option<(&OriginalProofJobSourceV1<'_>, &CheckpointScope, &str)>,
    ) -> Result<JobSummary> {
        let origin = original.map(|(source, _, _)| source.origin);
        let private = {
            let mut connection = self.connection.lock().map_err(|_| JobError::Storage)?;
            check_original_connection(origin, &connection)?;
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            let r = record(&tx, principal, job_id)?.ok_or(JobError::NotFound)?;
            if let Some((_, scope, request_digest)) = original {
                if &r.scope != scope || r.request_digest != request_digest {
                    return Err(JobError::IdempotencyConflict);
                }
            }
            gate(consent, &r.scope, LocalAction::ProveLocally)?;
            gate(consent, &r.scope, LocalAction::RetainPrivateWitnesses)?;
            if original_queued_only
                && (r.summary.state != JobState::Queued || r.summary.attempt != 0)
            {
                return Err(JobError::StateConflict);
            }
            let mut p = private_record(&tx, principal, job_id)?;
            match p.record.summary.state {
                JobState::Succeeded => {
                    verify_saved(&p)?;
                    gate(consent, &p.record.scope, LocalAction::ProveLocally)?;
                    gate(
                        consent,
                        &p.record.scope,
                        LocalAction::RetainPrivateWitnesses,
                    )?;
                    return Ok(p.record.summary);
                }
                JobState::Running => return Err(JobError::RecoveryRequired),
                JobState::Failed => return Err(JobError::VerificationFailed),
                JobState::Queued | JobState::Uncertain => {}
            }
            if tx
                .query_row(
                    "SELECT count(*) FROM proof_jobs WHERE state='running'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(db)?
                != 0
            {
                return Err(JobError::ResourceExhausted);
            }
            let next = p
                .record
                .summary
                .attempt
                .checked_add(1)
                .ok_or(JobError::ResourceExhausted)?;
            check_original_connection(origin, &tx)?;
            tx.execute(
                "UPDATE proof_jobs SET state='running',attempt=?2 WHERE job_id=?1",
                params![job_id, next],
            )
            .map_err(db)?;
            event(&tx, job_id, JobState::Running, next)?;
            check_original_connection(origin, &tx)?;
            tx.commit().map_err(db)?;
            check_original_connection(origin, &connection)?;
            p.record.summary.state = JobState::Running;
            p.record.summary.attempt = next;
            p
        };
        let attempt = private.record.summary.attempt;
        let result = (|| {
            let policy = policy::decode(&private.policy_bytes)?;
            validate_input(
                &private.input,
                &policy,
                &private.record.scope,
                limits(&private.record),
            )?;
            let proved = prove_reviewed(
                &private.input,
                &policy,
                &private.record.scope.review_binding,
                limits(&private.record),
            )
            .map_err(|_| JobError::VerificationFailed)?;
            Ok::<_, JobError>(Zeroizing::new(proved.pczt_bytes))
        })();
        let mut connection = self.connection.lock().map_err(|_| JobError::Storage)?;
        check_original_connection(origin, &connection)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let current = record(&tx, principal, job_id)?.ok_or(JobError::NotFound)?;
        if let Some((_, scope, request_digest)) = original {
            if &current.scope != scope || current.request_digest != request_digest {
                return Err(JobError::IdempotencyConflict);
            }
        }
        if current.summary.state != JobState::Running || current.summary.attempt != attempt {
            return Err(JobError::StateConflict);
        }
        // Consent is rechecked after lengthy computation. Revocation releases no
        // private output and never marks a proof complete.
        if !consent.permits(&current.scope, LocalAction::ProveLocally)
            || !consent.permits(&current.scope, LocalAction::RetainPrivateWitnesses)
        {
            tx.execute(
                "UPDATE proof_jobs SET state='uncertain' WHERE job_id=?1",
                [job_id],
            )
            .map_err(db)?;
            event(&tx, job_id, JobState::Uncertain, attempt)?;
            check_original_connection(origin, &tx)?;
            tx.commit().map_err(db)?;
            return Err(JobError::ConsentDenied);
        }
        check_original_connection(origin, &tx)?;
        match result {
            Ok(bytes) => {
                if bytes.len() > MAX_ARTIFACT_BYTES {
                    return Err(JobError::ResourceExhausted);
                }
                tx.execute("UPDATE proof_jobs SET state='succeeded',result=?2,result_digest=?3 WHERE job_id=?1", params![job_id,bytes.as_slice(),digest(&bytes)]).map_err(db)?;
                event(&tx, job_id, JobState::Succeeded, attempt)?;
            }
            Err(_) => {
                tx.execute(
                    "UPDATE proof_jobs SET state='failed' WHERE job_id=?1",
                    [job_id],
                )
                .map_err(db)?;
                event(&tx, job_id, JobState::Failed, attempt)?;
                check_original_connection(origin, &tx)?;
                tx.commit().map_err(db)?;
                return Err(JobError::VerificationFailed);
            }
        }
        let summary = record(&tx, principal, job_id)?
            .ok_or(JobError::Storage)?
            .summary;
        check_original_connection(origin, &tx)?;
        tx.commit().map_err(db)?;
        check_original_connection(origin, &connection)?;
        Ok(summary)
    }

    /// Local-only read, with current consent and real proof/economic verification
    /// on every call, including after restart. Never reads a merely queued result.
    pub fn load_verified(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<VerifiedCheckpoint> {
        self.load_verified_checked(principal, job_id, consent, None)
    }
    fn load_verified_checked(
        &self,
        principal: &str,
        job_id: &str,
        consent: &dyn LocalProofConsent,
        origin: Option<&DatabaseFileIdentity>,
    ) -> Result<VerifiedCheckpoint> {
        let connection = self.connection.lock().map_err(|_| JobError::Storage)?;
        check_original_connection(origin, &connection)?;
        let r = record(&connection, principal, job_id)?.ok_or(JobError::NotFound)?;
        gate(consent, &r.scope, LocalAction::ReadPrivateArtifact)?;
        let mut p = private_record(&connection, principal, job_id)?;
        verify_saved(&p)?;
        gate(consent, &p.record.scope, LocalAction::ReadPrivateArtifact)?;
        check_original_connection(origin, &connection)?;
        Ok(VerifiedCheckpoint {
            original_bytes: p.input,
            bytes: p.result.take().ok_or(JobError::Storage)?,
            policy: policy::decode(&p.policy_bytes)?,
            scope: p.record.scope,
            summary: p.record.summary,
        })
    }
}

/// Stable local job identity for a scoped idempotency key. This grants no access
/// and is not an artifact/economic commitment. Useful for journaling an engine
/// provenance receipt before the separate private checkpoint transaction.
pub fn job_id_for_key(principal: &str, idempotency_key: &str) -> Result<String> {
    if !bounded(principal, 128)
        || !(16..=128).contains(&idempotency_key.len())
        || !idempotency_key.bytes().all(|b| (33..=126).contains(&b))
    {
        return Err(JobError::InvalidRequest);
    }
    Ok(format!(
        "proof-{}",
        framed_digest(&[principal.as_bytes(), idempotency_key.as_bytes()])
    ))
}

fn db(_: rusqlite::Error) -> JobError {
    JobError::Storage
}
fn gate(
    consent: &dyn LocalProofConsent,
    scope: &CheckpointScope,
    action: LocalAction,
) -> Result<()> {
    if consent.permits(scope, action) {
        Ok(())
    } else {
        Err(JobError::ConsentDenied)
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn framed_digest(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact.private-proof-job.v1\0");
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    hex::encode(h.finalize())
}
fn bounded(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn hash_text(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn validate_scope(s: &CheckpointScope) -> Result<()> {
    let accounts: BTreeSet<_> = s.account_ids.iter().collect();
    if !bounded(&s.principal_id, 128)
        || !bounded(&s.candidate_id, 128)
        || !bounded(&s.local_operator, 256)
        || !bounded(&s.purpose, 512)
        || !bounded(&s.retention_policy, 1024)
        || !hash_text(&s.manifest_digest)
        || !hash_text(&s.review_binding)
        || !hash_text(&s.artifact_digest)
        || !hash_text(&s.effects_commitment)
        || !hash_text(&s.coordination_request_digest)
        || accounts.is_empty()
        || accounts.len() > MAX_PROVING_ACTIONS
        || accounts.len() != s.account_ids.len()
        || accounts.iter().any(|id| !bounded(id, 128))
    {
        return Err(JobError::InvalidRequest);
    }
    Ok(())
}
fn validate_input(
    bytes: &[u8],
    policy: &ReviewPolicy,
    scope: &CheckpointScope,
    limits: ProvingLimits,
) -> Result<()> {
    let structure =
        wholepact_protocol::inspect_candidate(bytes).map_err(|_| JobError::VerificationFailed)?;
    if !(1..=MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
        || structure.actions > limits.maximum_actions
    {
        return Err(JobError::InvalidRequest);
    }
    let pczt = pczt::Pczt::parse(bytes).map_err(|_| JobError::VerificationFailed)?;
    // This pipeline owns candidates with unsigned real inputs only. Retaining usable spend
    // authorizations needs the separate signer-authoritative release journal.
    // Upstream-generated zero-value padding signatures are not real input authority.
    if pczt.ironwood().zkproof().is_some()
        || policy.inputs.iter().any(|i| {
            pczt.ironwood()
                .actions()
                .get(i.action_index)
                .is_some_and(|a| a.spend().spend_auth_sig().is_some())
        })
    {
        return Err(JobError::InvalidRequest);
    }
    let review = verify_review(bytes, policy).map_err(|_| JobError::VerificationFailed)?;
    if digest(bytes) != scope.artifact_digest
        || hex::encode(policy.manifest_digest) != scope.manifest_digest
        || policy
            .participants
            .iter()
            .map(|p| p.account_id.as_str())
            .collect::<BTreeSet<_>>()
            != scope.account_ids.iter().map(String::as_str).collect()
        || review.review_binding() != scope.review_binding
        || review.shielded_sighash() != scope.effects_commitment
    {
        return Err(JobError::VerificationFailed);
    }
    Ok(())
}
fn limits(r: &Record) -> ProvingLimits {
    ProvingLimits {
        maximum_actions: r.maximum_actions,
    }
}
fn event(c: &Connection, job_id: &str, state: JobState, attempt: u32) -> Result<()> {
    c.execute(
        "INSERT INTO proof_events(job_id,state,attempt) VALUES (?1,?2,?3)",
        params![job_id, state.as_str(), attempt],
    )
    .map_err(db)?;
    Ok(())
}
fn record(c: &Connection, principal: &str, job_id: &str) -> Result<Option<Record>> {
    type Row = (
        Option<Vec<u8>>,
        String,
        String,
        u32,
        String,
        Option<String>,
        usize,
    );
    let row: Option<Row> = c.query_row("SELECT CASE WHEN length(scope)<=8192 THEN scope ELSE NULL END,request_digest,state,attempt,input_digest,result_digest,maximum_actions FROM proof_jobs WHERE principal_id=?1 AND job_id=?2",
        params![principal,job_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(db)?;
    row.map(
        |(scope, request_digest, state, attempt, input_digest, result_digest, maximum_actions)| {
            let scope = scope.ok_or(JobError::Storage)?;
            let scope_digest = digest(&scope);
            let scope: CheckpointScope =
                serde_json::from_slice(&scope).map_err(|_| JobError::Storage)?;
            validate_scope(&scope).map_err(|_| JobError::Storage)?;
            let state = JobState::parse(&state)?;
            if scope.principal_id != principal
                || !(1..=MAX_PROVING_ACTIONS).contains(&maximum_actions)
            {
                return Err(JobError::Storage);
            }
            Ok(Record {
                summary: JobSummary {
                    job_id: job_id.into(),
                    scope_digest,
                    candidate_id: scope.candidate_id.clone(),
                    state,
                    attempt,
                    input_digest,
                    manifest_digest: scope.manifest_digest.clone(),
                    effects_commitment: scope.effects_commitment.clone(),
                    coordination_request_digest: scope.coordination_request_digest.clone(),
                    result_digest,
                    review_binding: scope.review_binding.clone(),
                    encrypted_checkpoint_created: true,
                    proof_verified: state == JobState::Succeeded,
                    chain_validated: false,
                    authorization_allowed: false,
                    distribution_allowed: false,
                },
                scope,
                request_digest,
                maximum_actions,
            })
        },
    )
    .transpose()
}
fn private_record(c: &Connection, principal: &str, job_id: &str) -> Result<PrivateRecord> {
    let record = record(c, principal, job_id)?.ok_or(JobError::NotFound)?;
    type Blobs = (
        Zeroizing<Vec<u8>>,
        Zeroizing<Vec<u8>>,
        Option<Zeroizing<Vec<u8>>>,
    );
    let (input,policy,result): Blobs = c.query_row("SELECT input,policy,result FROM proof_jobs WHERE job_id=?1 AND length(input)<=1048576 AND length(policy)<=131072 AND (result IS NULL OR length(result)<=1048576)", [job_id], |r| Ok((Zeroizing::new(r.get(0)?),Zeroizing::new(r.get(1)?),r.get::<_,Option<Vec<u8>>>(2)?.map(Zeroizing::new)))).map_err(db)?;
    if digest(&input) != record.summary.input_digest {
        return Err(JobError::VerificationFailed);
    }
    Ok(PrivateRecord {
        record,
        input,
        policy_bytes: policy,
        result,
    })
}
fn verify_saved(p: &PrivateRecord) -> Result<()> {
    if p.record.summary.state != JobState::Succeeded {
        return Err(JobError::StateConflict);
    }
    let bytes = p.result.as_ref().ok_or(JobError::Storage)?;
    if Some(digest(bytes)) != p.record.summary.result_digest {
        return Err(JobError::VerificationFailed);
    }
    let policy = policy::decode(&p.policy_bytes)?;
    validate_input(&p.input, &policy, &p.record.scope, limits(&p.record))?;
    let verified = verify_proved_candidate(
        bytes,
        &policy,
        &p.record.scope.review_binding,
        limits(&p.record),
    )
    .map_err(|_| JobError::VerificationFailed)?;
    let _verified_copy = Zeroizing::new(verified.pczt_bytes);
    // The actual proved bytes must differ from the immutable predecessor only
    // by the supported proof addition, including on recovery/replay.
    let proved = pczt::Pczt::parse(bytes).map_err(|_| JobError::VerificationFailed)?;
    let normalized = pczt::roles::redactor::Redactor::new(proved)
        .redact_ironwood_with(|mut b| b.clear_zkproof())
        .finish();
    let normalized = Zeroizing::new(
        pczt::v2::Pczt::try_from(normalized)
            .map_err(|_| JobError::VerificationFailed)?
            .serialize(),
    );
    if normalized.as_slice() != p.input.as_slice() {
        return Err(JobError::VerificationFailed);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod original_queued_tests;
#[cfg(all(test, target_os = "linux"))]
mod original_source_v1_tests;
#[cfg(all(test, target_os = "linux"))]
mod tests;

pub mod backup;

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
                "wholepact-schema-ProofJobStore-{}-{}",
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
                ProofJobStore::from_encrypted_connection(encrypted),
                Err(JobError::UnsupportedSchema)
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
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='proof_jobs')",
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
        let journal = ProofJobStore::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = ProofJobStore::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
}
