//! Immutable encrypted signature-set intent and exact signed-PCZT result.
//!
//! This low-level primitive does not authenticate application identities. The
//! engine adapter must authenticate delivery/account attribution and reload its
//! original checkpoint. Optional private transaction checkpointing has no byte
//! getter, release, export, authority recovery or production association issuer.
#[cfg(feature = "transaction-checkpoint")]
pub mod transaction;

pub mod durable_intake_v1;

use super::{ExternalSignature, SignatureInspection, assemble_external_signatures};
use crate::{proving::ProvingLimits, review::ReviewPolicy};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use wholepact_storage_security::EncryptedConnection;
use zeroize::Zeroizing;

const APPLICATION_ID: i64 = 0x57505352;
const MAX_RESULTS: i64 = 64;
const MAX_BYTES: usize = 1_048_576;

/// Exact private retention context supplied by the trusted local adapter. It is
/// not a transport, human-approval, writer-authority or application identity token.
#[derive(Clone, Serialize)]
pub struct SignedCandidateContext {
    pub principal_id: String,
    pub candidate_id: String,
    pub proof_job_id: String,
    pub checkpoint_scope_digest: String,
    pub proved_artifact_digest: String,
    pub manifest_digest: String,
    pub review_binding: String,
    pub delivery_provenance_digest: String,
    pub account_ids: Vec<String>,
    pub local_operator: String,
    pub purpose: String,
    pub retention_policy: String,
}

/// Constructed by the journal, never deserialized as a grant. The trusted local
/// embedding must check current exact consent, including retention of usable
/// spend signatures, separately from permission to read unsigned witnesses.
#[derive(Serialize)]
pub struct SignedRetentionScope {
    pub context: SignedCandidateContext,
    pub signature_set_digest: String,
}
/// Callbacks must not reenter this journal: some checks run with its mutex and
/// transaction held. Rechecks are not an atomic revocation protocol with another
/// database; strict concurrent revocation requires an embedding-held authority
/// lock/lease covering this operation. They never establish spending authority.
pub trait SignedRetentionConsent {
    fn permits(&self, scope: &SignedRetentionScope) -> bool;
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedResultSummary {
    pub result_id: String,
    pub request_digest: String,
    pub signed_candidate_digest: String,
    pub exact_replay: bool,
    pub historical_reconciliation: bool,
    pub inspection: SignatureInspection,
    pub transaction_extracted: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetentionError {
    InvalidRequest,
    ConsentDenied,
    IdempotencyConflict,
    IntentNotFound,
    RecoveryRequired,
    IncompleteSignatures,
    VerificationFailed,
    UnsupportedSchema,
    ResourceExhausted,
    Storage,
}
type Result<T> = std::result::Result<T, RetentionError>;

pub struct SignedResultJournal {
    connection: Mutex<Connection>,
}
impl SignedResultJournal {
    /// Dedicated SQLCipher database. Encryption is not rollback/clone protection
    /// and does not qualify a restored controller to authorize new spending.
    pub fn from_encrypted_connection(encrypted: EncryptedConnection) -> Result<Self> {
        let mut c = encrypted.into_connection();
        let mode: String = c
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(db)?;
        c.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;",
        )
        .map_err(db)?;
        let sync: i64 = c
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .map_err(db)?;
        let foreign_keys: i64 = c
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .map_err(db)?;
        if mode != "wal" || sync != 2 || foreign_keys != 1 {
            return Err(RetentionError::Storage);
        }
        let app: i64 = c
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(db)?;
        let version: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db)?;
        if app == 0 && version == 0 {
            let tables: i64 = c
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                    [],
                    |r| r.get(0),
                )
                .map_err(db)?;
            if tables != 0 {
                return Err(RetentionError::UnsupportedSchema);
            }
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            tx.execute_batch("CREATE TABLE signed_intents (
                result_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, idem_key TEXT NOT NULL,
                request_digest TEXT NOT NULL, scope BLOB NOT NULL CHECK(length(scope)<=16384),
                signatures BLOB NOT NULL CHECK(length(signatures)<=10240),
                UNIQUE(principal_id,idem_key));
                CREATE TABLE signed_results (
                result_id TEXT PRIMARY KEY REFERENCES signed_intents(result_id),
                bytes BLOB NOT NULL CHECK(length(bytes)<=1048576), digest TEXT NOT NULL);
                CREATE TRIGGER immutable_signed_intent_update BEFORE UPDATE ON signed_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_signed_intent_delete BEFORE DELETE ON signed_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_signed_result_update BEFORE UPDATE ON signed_results BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_signed_result_delete BEFORE DELETE ON signed_results BEGIN SELECT RAISE(ABORT,'immutable'); END;
                PRAGMA application_id=1464882002; PRAGMA user_version=1;").map_err(db)?;
            tx.commit().map_err(db)?;
        } else if app != APPLICATION_ID || version != 1 {
            return Err(RetentionError::UnsupportedSchema);
        }
        Ok(Self {
            connection: Mutex::new(c),
        })
    }

    /// Reauthentication and checkpoint reload belong to the engine adapter. Every
    /// call (including replay) checks dedicated current retention consent, verifies
    /// signatures/proof and reproduces the exact deterministic signed PCZT.
    /// Intent commits before assembly. An interrupted intent can resume only with
    /// the same original proof, context and signature set. No randomized binding
    /// signature or transaction is produced. Results are never returned as bytes.
    // Keep checkpoint, delivery and consent boundaries explicit at this adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn retain(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        consent: &dyn SignedRetentionConsent,
    ) -> Result<SignedResultSummary> {
        self.retain_inner(
            context,
            idempotency_key,
            base,
            policy,
            signatures,
            limits,
            consent,
            false,
        )
    }

    /// Existing-intent-only reconciliation. This can use historical authenticated
    /// deliveries but cannot create a new retention intent, refresh approval or
    /// grant release authority. A missing original intent is an error, not a new
    /// request. Current consent and exact checkpoint/signature binding still apply.
    // Keep checkpoint, delivery and consent boundaries explicit at this adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        consent: &dyn SignedRetentionConsent,
    ) -> Result<SignedResultSummary> {
        self.retain_inner(
            context,
            idempotency_key,
            base,
            policy,
            signatures,
            limits,
            consent,
            true,
        )
    }

    // Keep checkpoint, delivery and consent boundaries explicit at this adapter.
    #[allow(clippy::too_many_arguments)]
    fn retain_inner(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        consent: &dyn SignedRetentionConsent,
        historical: bool,
    ) -> Result<SignedResultSummary> {
        validate(&context)?;
        if !(16..=128).contains(&idempotency_key.len())
            || !idempotency_key.bytes().all(|b| (33..=126).contains(&b))
            || base.len() > MAX_BYTES
            || signatures.is_empty()
            || signatures.len() > 64
            || hash(base) != context.proved_artifact_digest
            || hex::encode(policy.manifest_digest) != context.manifest_digest
            || !(1..=crate::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
            || policy
                .participants
                .iter()
                .map(|p| p.account_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                != context.account_ids.iter().map(String::as_str).collect()
        {
            return Err(RetentionError::InvalidRequest);
        }
        let encoded_signatures = encode_signatures(signatures)?;
        let scope = SignedRetentionScope {
            context,
            signature_set_digest: hash(&encoded_signatures),
        };
        gate(consent, &scope)?;
        let scope_bytes =
            Zeroizing::new(serde_json::to_vec(&scope).map_err(|_| RetentionError::InvalidRequest)?);
        if scope_bytes.len() > 16384 {
            return Err(RetentionError::InvalidRequest);
        }
        let request_digest = framed(&[
            &scope_bytes,
            &encoded_signatures,
            &(limits.maximum_actions as u64).to_le_bytes(),
        ]);
        let result_id = format!(
            "signed-{}",
            framed(&[
                scope.context.principal_id.as_bytes(),
                idempotency_key.as_bytes()
            ])
        );
        {
            let mut c = self
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            let existing: Option<(String, Vec<u8>, Vec<u8>)> = tx.query_row(
                "SELECT request_digest,scope,signatures FROM signed_intents WHERE result_id=?1 AND length(scope)<=16384 AND length(signatures)<=10240", [&result_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional().map_err(db)?;
            if let Some((digest, saved_scope, saved_signatures)) = existing {
                let saved_scope = Zeroizing::new(saved_scope);
                let saved_signatures = Zeroizing::new(saved_signatures);
                if digest != request_digest
                    || *saved_scope != *scope_bytes
                    || *saved_signatures != *encoded_signatures
                {
                    return Err(RetentionError::IdempotencyConflict);
                }
            } else {
                if historical {
                    return Err(RetentionError::IntentNotFound);
                }
                let count: i64 = tx
                    .query_row("SELECT count(*) FROM signed_intents", [], |r| r.get(0))
                    .map_err(db)?;
                if count >= MAX_RESULTS {
                    return Err(RetentionError::ResourceExhausted);
                }
                tx.execute("INSERT INTO signed_intents(result_id,principal_id,idem_key,request_digest,scope,signatures) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![result_id,scope.context.principal_id,idempotency_key,request_digest,scope_bytes.as_slice(),encoded_signatures.as_slice()]).map_err(db)?;
            }
            gate(consent, &scope)?;
            tx.commit().map_err(db)?;
        }
        gate(consent, &scope)?;
        let (inspection, bytes) = assemble_external_signatures(
            base,
            policy,
            &scope.context.review_binding,
            signatures,
            limits,
        )
        .map_err(|_| RetentionError::VerificationFailed)?;
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > MAX_BYTES {
            return Err(RetentionError::ResourceExhausted);
        }
        gate(consent, &scope)?;
        let digest = hash(&bytes);
        let mut c = self
            .connection
            .lock()
            .map_err(|_| RetentionError::Storage)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let saved: Option<(Vec<u8>, String)> = tx.query_row("SELECT bytes,digest FROM signed_results WHERE result_id=?1 AND length(bytes)<=1048576", [&result_id], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
        let exact_replay = saved.is_some();
        if let Some((saved, saved_digest)) = saved {
            let saved = Zeroizing::new(saved);
            if saved_digest != digest || hash(&saved) != digest || *saved != *bytes {
                return Err(RetentionError::VerificationFailed);
            }
        } else {
            tx.execute(
                "INSERT INTO signed_results(result_id,bytes,digest) VALUES (?1,?2,?3)",
                params![result_id, bytes.as_slice(), digest],
            )
            .map_err(db)?;
        }
        gate(consent, &scope)?;
        tx.commit().map_err(db)?;
        gate(consent, &scope)?;
        Ok(SignedResultSummary {
            result_id,
            request_digest,
            signed_candidate_digest: digest,
            exact_replay,
            historical_reconciliation: historical,
            inspection,
            transaction_extracted: false,
            authorization_allowed: false,
            distribution_allowed: false,
        })
    }
}

fn encode_signatures(signatures: &[ExternalSignature]) -> Result<Zeroizing<Vec<u8>>> {
    let mut sorted: Vec<_> = signatures.iter().collect();
    sorted.sort_by_key(|s| (s.action_index, s.participant_index));
    if sorted
        .windows(2)
        .any(|w| w[0].action_index == w[1].action_index)
    {
        return Err(RetentionError::InvalidRequest);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(sorted.len() * 80));
    for s in sorted {
        out.extend_from_slice(&(s.participant_index as u64).to_le_bytes());
        out.extend_from_slice(&(s.action_index as u64).to_le_bytes());
        out.extend_from_slice(&s.signature);
    }
    Ok(out)
}
fn validate(c: &SignedCandidateContext) -> Result<()> {
    let text = |s: &str, max: usize| {
        !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
    };
    let digest = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !text(&c.principal_id, 128)
        || !text(&c.candidate_id, 128)
        || !text(&c.proof_job_id, 128)
        || !text(&c.local_operator, 256)
        || !text(&c.purpose, 512)
        || !text(&c.retention_policy, 1024)
        || [
            &c.checkpoint_scope_digest,
            &c.proved_artifact_digest,
            &c.manifest_digest,
            &c.review_binding,
            &c.delivery_provenance_digest,
        ]
        .iter()
        .any(|s| !digest(s))
        || c.account_ids.is_empty()
        || c.account_ids.len() > 8
        || c.account_ids.iter().any(|s| !text(s, 128))
        || c.account_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != c.account_ids.len()
    {
        return Err(RetentionError::InvalidRequest);
    }
    Ok(())
}
fn gate(consent: &dyn SignedRetentionConsent, scope: &SignedRetentionScope) -> Result<()> {
    if consent.permits(scope) {
        Ok(())
    } else {
        Err(RetentionError::ConsentDenied)
    }
}
fn db(_: rusqlite::Error) -> RetentionError {
    RetentionError::Storage
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn framed(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact.signed-result.v1\0");
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    hex::encode(h.finalize())
}

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
                "wholepact-schema-SignedResultJournal-{}-{}",
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
                SignedResultJournal::from_encrypted_connection(encrypted),
                Err(RetentionError::UnsupportedSchema)
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
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='signed_intents')",
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
        let journal = SignedResultJournal::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = SignedResultJournal::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
}
