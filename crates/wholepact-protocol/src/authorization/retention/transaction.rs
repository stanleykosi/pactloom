//! Private maintained extraction to an immutable encrypted transaction checkpoint.
//! No implicit export, broadcaster or signer authority is provided. The portable
//! module requires separate exact native disclosure before lending finalized bytes.
//! An incomplete randomized extraction intent is fenced, never auto-retried.
use super::*;
use orchard::bundle::BatchValidator;
use pczt::{Pczt, roles::tx_extractor::TransactionExtractor};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zcash_primitives::transaction::{
    Authorization, Authorized, Transaction, TxVersion,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::consensus::BranchId;

#[cfg(feature = "submission-handoff")]
pub mod submission_handoff;

pub mod portable;
mod recovery;
pub use recovery::{
    LocalTransactionRecovery, RecoveryAction, RecoveryNextAction, RecoveryState,
    TransactionRecoveryConsent, TransactionRecoveryScope, TransactionRecoverySummary,
};

const APPLICATION_ID: i64 = 0x57505458;

#[derive(Serialize)]
pub struct TransactionRetentionScope {
    pub signed_scope: SignedRetentionScope,
    pub signed_result_id: String,
    pub signed_request_digest: String,
    pub signed_candidate_digest: String,
}
/// Separate exact permission to retain usable transaction bytes locally. This is
/// not spending/release approval. Callbacks must not reenter either journal, and
/// strict cross-store revocation requires an embedding-held authority lock/lease.
pub trait TransactionRetentionConsent {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool;
    /// Denial-only, nonblocking final extraction restriction. Legacy remains
    /// inert; this must never prompt or re-enter a source/journal.
    fn check_final_effect_restriction(&self) -> bool { true }
}

pub struct LocalTransactionCheckpoint<'a> {
    pub journal: &'a TransactionCheckpointJournal,
    pub consent: &'a dyn TransactionRetentionConsent,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionCheckpointSummary {
    pub checkpoint_id: String,
    pub signed_result_id: String,
    pub transaction_digest: String,
    pub txid: String,
    pub exact_replay: bool,
    pub cryptographic_transaction_verified: bool,
    pub transaction_extracted: bool,
    pub chain_validated: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
    pub release_allowed: bool,
}

pub struct TransactionCheckpointJournal {
    connection: Mutex<Connection>,
    #[cfg(test)]
    extraction_invocations: std::sync::atomic::AtomicUsize,
}

struct CombinedRetentionGate<'a> {
    signed: &'a dyn SignedRetentionConsent,
    transaction: &'a dyn TransactionRetentionConsent,
}
impl TransactionRetentionConsent for CombinedRetentionGate<'_> {
    fn check_final_effect_restriction(&self) -> bool {
        self.transaction.check_final_effect_restriction()
    }
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        self.signed.permits(&scope.signed_scope)
            && self.transaction.permits(scope)
            && self.signed.permits(&scope.signed_scope)
    }
}

impl SignedResultJournal {
    /// Reverify the exact existing signed result, then privately extract and retain
    /// a transaction. Completed calls read/verify saved bytes, never re-extract.
    /// Current signed-retention permission is required in addition to the separate
    /// transaction-retention permission. No result can escape as transaction bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_transaction(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        local: LocalTransactionCheckpoint<'_>,
    ) -> Result<TransactionCheckpointSummary> {
        let (scope, bytes) = self.verified_transaction_predecessor(
            context,
            idempotency_key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
        )?;
        let consent = CombinedRetentionGate {
            signed: signed_consent,
            transaction: local.consent,
        };
        gate(&consent, &scope)?;
        local.journal.checkpoint(&scope, &bytes, policy, &consent)
    }
    /// Financial continuation extraction requires a completed original union.
    /// Unlike the legacy explicit repair path, this never fills a missing signed
    /// result. The unchanged extraction kernel fences intent-without-result.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_completed_transaction(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        local: LocalTransactionCheckpoint<'_>,
    ) -> Result<TransactionCheckpointSummary> {
        let (scope, bytes) = self.verified_completed_transaction_predecessor(
            context, idempotency_key, base, policy, signatures, limits, signed_consent,
        )?;
        let consent = CombinedRetentionGate {
            signed: signed_consent, transaction: local.consent,
        };
        gate(&consent, &scope)?;
        local.journal.checkpoint(&scope, &bytes, policy, &consent)
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_transaction_predecessor(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
    ) -> Result<(TransactionRetentionScope, Zeroizing<Vec<u8>>)> {
        let summary = self.reconcile_existing(
            context.clone(),
            idempotency_key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
        )?;
        if !summary.inspection.signatures_complete {
            return Err(RetentionError::IncompleteSignatures);
        }
        let signed_scope = SignedRetentionScope {
            context,
            signature_set_digest: hash(&encode_signatures(signatures)?),
        };
        let scope = TransactionRetentionScope {
            signed_scope,
            signed_result_id: summary.result_id.clone(),
            signed_request_digest: summary.request_digest,
            signed_candidate_digest: summary.signed_candidate_digest,
        };
        super::gate(signed_consent, &scope.signed_scope)?;
        let bytes = {
            let c = self
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let (bytes, digest): (Vec<u8>, String) = c.query_row(
                "SELECT bytes,digest FROM signed_results WHERE result_id=?1 AND length(bytes)<=1048576",
                [&summary.result_id], |r| Ok((r.get(0)?, r.get(1)?))).map_err(db)?;
            let bytes = Zeroizing::new(bytes);
            if digest != scope.signed_candidate_digest || hash(&bytes) != digest {
                return Err(RetentionError::VerificationFailed);
            }
            bytes
        };
        Ok((scope, bytes))
    }
}

impl TransactionCheckpointJournal {
    /// Dedicated authenticated SQLCipher database, with durability reasserted at
    /// handoff. Opening never clears or retries an interrupted extraction intent.
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
            tx.execute_batch("CREATE TABLE transaction_intents (
                checkpoint_id TEXT PRIMARY KEY, signed_result_id TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL, scope BLOB NOT NULL CHECK(length(scope)<=16384));
                CREATE TABLE transaction_results (
                checkpoint_id TEXT PRIMARY KEY REFERENCES transaction_intents(checkpoint_id),
                bytes BLOB NOT NULL CHECK(length(bytes)<=1048576), digest TEXT NOT NULL, txid TEXT NOT NULL);
                CREATE TRIGGER immutable_transaction_intent_update BEFORE UPDATE ON transaction_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_transaction_intent_delete BEFORE DELETE ON transaction_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_transaction_result_update BEFORE UPDATE ON transaction_results BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_transaction_result_delete BEFORE DELETE ON transaction_results BEGIN SELECT RAISE(ABORT,'immutable'); END;
                PRAGMA application_id=1464882264; PRAGMA user_version=1;").map_err(db)?;
            tx.commit().map_err(db)?;
        } else if app != APPLICATION_ID || version != 1 {
            return Err(RetentionError::UnsupportedSchema);
        }
        Ok(Self {
            connection: Mutex::new(c),
            #[cfg(test)]
            extraction_invocations: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn checkpoint(
        &self,
        scope: &TransactionRetentionScope,
        signed: &[u8],
        policy: &ReviewPolicy,
        consent: &dyn TransactionRetentionConsent,
    ) -> Result<TransactionCheckpointSummary> {
        gate(consent, scope)?;
        let scope_bytes =
            Zeroizing::new(serde_json::to_vec(scope).map_err(|_| RetentionError::InvalidRequest)?);
        if scope_bytes.len() > 16384
            || signed.len() > MAX_BYTES
            || hash(signed) != scope.signed_candidate_digest
        {
            return Err(RetentionError::InvalidRequest);
        }
        let request_digest = framed(&[b"transaction-checkpoint-v1", &scope_bytes]);
        let checkpoint_id = format!(
            "transaction-{}",
            framed(&[b"transaction-id-v1", scope.signed_result_id.as_bytes()])
        );
        let saved = {
            let mut c = self
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            let existing: Option<(String, Vec<u8>)> = tx.query_row(
                "SELECT request_digest,scope FROM transaction_intents WHERE checkpoint_id=?1 AND length(scope)<=16384", [&checkpoint_id],
                |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
            let saved = if let Some((digest, bytes)) = existing {
                let bytes = Zeroizing::new(bytes);
                if digest != request_digest || *bytes != *scope_bytes {
                    return Err(RetentionError::IdempotencyConflict);
                }
                let saved: Option<(Vec<u8>,String,String)> = tx.query_row(
                    "SELECT bytes,digest,txid FROM transaction_results WHERE checkpoint_id=?1 AND length(bytes)<=1048576", [&checkpoint_id],
                    |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db)?;
                // Even if no bytes were generated before interruption, this call
                // cannot prove it. Never silently regenerate a binding signature.
                Some(saved.ok_or(RetentionError::RecoveryRequired)?)
            } else {
                let count: i64 = tx
                    .query_row("SELECT count(*) FROM transaction_intents", [], |r| r.get(0))
                    .map_err(db)?;
                if count >= MAX_RESULTS {
                    return Err(RetentionError::ResourceExhausted);
                }
                tx.execute("INSERT INTO transaction_intents(checkpoint_id,signed_result_id,request_digest,scope) VALUES (?1,?2,?3,?4)",
                    params![checkpoint_id,scope.signed_result_id,request_digest,scope_bytes.as_slice()]).map_err(db)?;
                None
            };
            gate(consent, scope)?;
            tx.commit().map_err(db)?;
            saved
        };
        gate(consent, scope)?;
        let exact_replay = saved.is_some();
        let (bytes, digest, txid) = if let Some((bytes, digest, txid)) = saved {
            let bytes = Zeroizing::new(bytes);
            if hash(&bytes) != digest {
                return Err(RetentionError::VerificationFailed);
            }
            let verified_txid = verify_saved_transaction(&bytes, signed, policy)?;
            if verified_txid != txid {
                return Err(RetentionError::VerificationFailed);
            }
            (bytes, digest, txid)
        } else {
            let parsed = Pczt::parse(signed).map_err(|_| RetentionError::VerificationFailed)?;
            let extractor = TransactionExtractor::new(parsed);
            // Parsing/setup cannot carry an earlier restriction sample across
            // this one physical extraction attempt. Existing consent stays exact.
            if !consent.check_final_effect_restriction() { return Err(RetentionError::ConsentDenied); }
            #[cfg(test)]
            self.extraction_invocations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let transaction = extractor.extract(UnwrapErr(SysRng))
                .map_err(|_| RetentionError::VerificationFailed)?;
            let mut bytes = Zeroizing::new(Vec::new());
            transaction
                .write(&mut *bytes)
                .map_err(|_| RetentionError::VerificationFailed)?;
            if bytes.len() > MAX_BYTES {
                return Err(RetentionError::ResourceExhausted);
            }
            let txid = verify_saved_transaction(&bytes, signed, policy)?;
            let digest = hash(&bytes);
            (bytes, digest, txid)
        };
        gate(consent, scope)?;
        if !exact_replay {
            let mut c = self
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            // Only the caller that inserted the immutable intent reaches this
            // point. Concurrent callers seeing the intent are fenced above.
            tx.execute("INSERT INTO transaction_results(checkpoint_id,bytes,digest,txid) VALUES (?1,?2,?3,?4)",
                params![checkpoint_id,bytes.as_slice(),digest,txid]).map_err(db)?;
            gate(consent, scope)?;
            tx.commit().map_err(db)?;
        }
        gate(consent, scope)?;
        Ok(TransactionCheckpointSummary {
            checkpoint_id,
            signed_result_id: scope.signed_result_id.clone(),
            transaction_digest: digest,
            txid,
            exact_replay,
            cryptographic_transaction_verified: true,
            transaction_extracted: true,
            chain_validated: false,
            authorization_allowed: false,
            distribution_allowed: false,
            release_allowed: false,
        })
    }
}

fn gate(
    consent: &dyn TransactionRetentionConsent,
    scope: &TransactionRetentionScope,
) -> Result<()> {
    if consent.permits(scope) {
        Ok(())
    } else {
        Err(RetentionError::ConsentDenied)
    }
}

// Verification consumes no extraction randomness and cannot generate replacement
// bytes. Auth-independent txid/effects are insufficient: proof and every spend
// authorization must also equal the immutable signed PCZT exactly.
fn verify_saved_transaction(bytes: &[u8], signed: &[u8], policy: &ReviewPolicy) -> Result<String> {
    let reject = || RetentionError::VerificationFailed;
    if bytes.len() > MAX_BYTES {
        return Err(reject());
    }
    let pczt = Pczt::parse(signed).map_err(|_| reject())?;
    let branch = BranchId::try_from(*pczt.global().consensus_branch_id()).map_err(|_| reject())?;
    let mut cursor = std::io::Cursor::new(bytes);
    let tx = Transaction::read(&mut cursor, branch).map_err(|_| reject())?;
    if cursor.position() as usize != bytes.len()
        || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != branch
        || tx.transparent_bundle().is_some()
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
        || tx.sprout_bundle().is_some()
    {
        return Err(reject());
    }
    let mut canonical = Zeroizing::new(Vec::new());
    tx.write(&mut *canonical).map_err(|_| reject())?;
    if canonical.as_slice() != bytes {
        return Err(reject());
    }
    let review = crate::review::verify_review(signed, policy).map_err(|_| reject())?;
    // Maintained hashing requires a transparent authorizing context even for a
    // shielded-only transaction. No transparent bundle is allowed above; map its
    // absent slot to upstream EffectsOnly while preserving every shielded field.
    struct ShieldedEffects;
    impl Authorization for ShieldedEffects {
        type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
        type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
        type OrchardAuth = <Authorized as Authorization>::OrchardAuth;
    }
    let effects = (*tx)
        .clone()
        .map_bundles::<ShieldedEffects>(|_| None, |s| s, |o| o);
    let sighash = signature_hash(
        &effects,
        &SignableInput::Shielded,
        &effects.digest(TxIdDigester),
    );
    if hex::encode(sighash.as_ref()) != review.shielded_sighash() {
        return Err(reject());
    }
    let bundle = tx.ironwood_bundle().ok_or_else(reject)?;
    let proof = pczt.ironwood().zkproof().as_ref().ok_or_else(reject)?;
    if bundle.authorization().proof().as_ref() != proof.as_slice()
        || bundle.actions().len() != pczt.ironwood().actions().len()
    {
        return Err(reject());
    }
    for (actual, expected) in bundle.actions().iter().zip(pczt.ironwood().actions()) {
        let signature: [u8; 64] = actual.authorization().into();
        if expected.spend().spend_auth_sig() != &Some(signature) {
            return Err(reject());
        }
    }
    let vk = orchard::circuit::VerifyingKey::build(bundle.bundle_version().circuit_version());
    let mut validator = BatchValidator::new(&vk);
    validator
        .add_bundle(bundle, *sighash.as_ref())
        .map_err(|_| reject())?;
    if !validator.validate(UnwrapErr(SysRng)) {
        return Err(reject());
    }
    Ok(tx.txid().to_string())
}

#[cfg(all(test, feature = "synthetic-qualification", target_os = "linux"))]
mod tests {
    use super::*;
    use wholepact_storage_security::{DatabaseKey, create_encrypted};

    #[test]
    fn incomplete_and_corrupt_completed_intents_never_invoke_extractor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "wholepact-extraction-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(
                dir.join("transaction.db"),
                &DatabaseKey::from_bytes([0x67; 32]),
            )
            .unwrap(),
        )
        .unwrap();
        let fixture = crate::synthetic::review_fixture().unwrap();
        let context = SignedCandidateContext {
            principal_id: "synthetic-controller".into(),
            candidate_id: "synthetic-candidate".into(),
            proof_job_id: "synthetic-proof".into(),
            checkpoint_scope_digest: "11".repeat(32),
            proved_artifact_digest: hash(&fixture.pczt_bytes),
            manifest_digest: hex::encode(fixture.policy.manifest_digest),
            review_binding: "22".repeat(32),
            delivery_provenance_digest: "33".repeat(32),
            account_ids: fixture
                .policy
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect(),
            local_operator: "synthetic-local".into(),
            purpose: "Negative extraction fixture".into(),
            retention_policy: "Temporary only".into(),
        };
        let scope = TransactionRetentionScope {
            signed_scope: SignedRetentionScope {
                context,
                signature_set_digest: "44".repeat(32),
            },
            signed_result_id: "synthetic-signed".into(),
            signed_request_digest: "55".repeat(32),
            signed_candidate_digest: hash(&fixture.pczt_bytes),
        };
        struct Consent;
        impl TransactionRetentionConsent for Consent {
            fn permits(&self, _: &TransactionRetentionScope) -> bool {
                true
            }
        }
        let scope_bytes = serde_json::to_vec(&scope).unwrap();
        let request = framed(&[b"transaction-checkpoint-v1", &scope_bytes]);
        let id = format!(
            "transaction-{}",
            framed(&[b"transaction-id-v1", scope.signed_result_id.as_bytes()])
        );
        {
            let c = journal.connection.lock().unwrap();
            c.execute("INSERT INTO transaction_intents(checkpoint_id,signed_result_id,request_digest,scope) VALUES (?1,?2,?3,?4)",
                params![id,scope.signed_result_id,request,scope_bytes]).unwrap();
        }
        assert_eq!(
            journal
                .checkpoint(&scope, &fixture.pczt_bytes, &fixture.policy, &Consent)
                .unwrap_err(),
            RetentionError::RecoveryRequired
        );
        assert_eq!(
            journal
                .extraction_invocations
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        {
            let c = journal.connection.lock().unwrap();
            let corrupt = [1u8, 2, 3];
            c.execute("INSERT INTO transaction_results(checkpoint_id,bytes,digest,txid) VALUES (?1,?2,?3,?4)",
                params![id,corrupt.as_slice(),hash(&corrupt),"00".repeat(32)]).unwrap();
        }
        assert_eq!(
            journal
                .checkpoint(&scope, &fixture.pczt_bytes, &fixture.policy, &Consent)
                .unwrap_err(),
            RetentionError::VerificationFailed
        );
        assert_eq!(
            journal
                .extraction_invocations
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        drop(journal);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

pub mod backup;

pub mod recipient;


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
                "wholepact-schema-TransactionCheckpointJournal-{}-{}",
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
                TransactionCheckpointJournal::from_encrypted_connection(encrypted),
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
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='transaction_intents')",
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
        let journal = TransactionCheckpointJournal::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = TransactionCheckpointJournal::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
}
