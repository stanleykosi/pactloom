//! Explicit recovery of existing immutable intents. Only retained original bytes
//! can be restored; this module has no extractor and never creates an intent.
use super::*;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    InspectExistingIntent,
    ReadRetainedCopy,
    RestoreExactRetainedCopy,
}

/// An exact local recovery decision, not writer/release authority. Inspection and
/// source reads are separately checked before any restoration. Restore approval
/// names the source's exact retained byte digest and txid, never txid alone.
#[derive(Serialize)]
pub struct TransactionRecoveryScope<'a> {
    pub retention: &'a TransactionRetentionScope,
    pub action: RecoveryAction,
    pub transaction_digest: Option<&'a str>,
    pub txid: Option<&'a str>,
}
pub trait TransactionRecoveryConsent {
    fn permits(&self, scope: &TransactionRecoveryScope<'_>) -> bool;
}

pub struct LocalTransactionRecovery<'a> {
    pub destination: LocalTransactionCheckpoint<'a>,
    /// An already authenticated encrypted journal holding the original result.
    /// None means inspect/fence only. This is not an arbitrary byte import.
    pub retained_copy: Option<&'a TransactionCheckpointJournal>,
    pub consent: &'a dyn TransactionRecoveryConsent,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    CompleteExactReplay,
    RestoredExactRetainedBytes,
    FencedOriginalBytesMissing,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryNextAction {
    None,
    LocateMatchingEncryptedCheckpoint,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionRecoverySummary {
    pub checkpoint_id: String,
    pub state: RecoveryState,
    pub next_action: RecoveryNextAction,
    pub checkpoint: Option<TransactionCheckpointSummary>,
    pub re_extraction_allowed: bool,
    pub authorization_allowed: bool,
    pub distribution_allowed: bool,
    pub release_allowed: bool,
}

impl SignedResultJournal {
    /// Reverify the original signed predecessor, then inspect or recover an
    /// existing transaction intent. The embedding must still authenticate account
    /// associations and checkpoint provenance/read consent as for extraction.
    /// No missing transaction is regenerated; exact source bytes never escape.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_transaction_checkpoint(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        local: LocalTransactionRecovery<'_>,
    ) -> Result<TransactionRecoverySummary> {
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
            transaction: local.destination.consent,
        };
        local.destination.journal.recover_existing(
            &scope,
            &bytes,
            policy,
            &consent,
            local.retained_copy,
            local.consent,
        )
    }
}

pub(super) struct OriginalResult {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    pub(super) digest: String,
    pub(super) txid: String,
}

impl TransactionCheckpointJournal {
    fn recover_existing(
        &self,
        scope: &TransactionRetentionScope,
        signed: &[u8],
        policy: &ReviewPolicy,
        retention: &dyn TransactionRetentionConsent,
        source: Option<&Self>,
        recovery: &dyn TransactionRecoveryConsent,
    ) -> Result<TransactionRecoverySummary> {
        recovery_gate(
            retention,
            recovery,
            scope,
            RecoveryAction::InspectExistingIntent,
            None,
        )?;
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
        let existing = {
            let c = self
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            read_existing(&c, &checkpoint_id, &request_digest, &scope_bytes)?
        };
        if let Some(existing) = existing {
            verify_original(&existing, signed, policy)?;
            if let Some(source) = source {
                recovery_gate(
                    retention,
                    recovery,
                    scope,
                    RecoveryAction::ReadRetainedCopy,
                    None,
                )?;
                let retained = {
                    let c = source
                        .connection
                        .lock()
                        .map_err(|_| RetentionError::Storage)?;
                    read_existing(&c, &checkpoint_id, &request_digest, &scope_bytes)?
                        .ok_or(RetentionError::RecoveryRequired)?
                };
                verify_original(&retained, signed, policy)?;
                recovery_gate(
                    retention,
                    recovery,
                    scope,
                    RecoveryAction::ReadRetainedCopy,
                    Some(&retained),
                )?;
                if retained.digest != existing.digest
                    || retained.txid != existing.txid
                    || retained.bytes.as_slice() != existing.bytes.as_slice()
                {
                    return Err(RetentionError::IdempotencyConflict);
                }
            }
            recovery_gate(
                retention,
                recovery,
                scope,
                RecoveryAction::InspectExistingIntent,
                Some(&existing),
            )?;
            return Ok(summary(
                &checkpoint_id,
                scope,
                RecoveryState::CompleteExactReplay,
                Some(&existing),
            ));
        }
        let Some(source) = source else {
            recovery_gate(
                retention,
                recovery,
                scope,
                RecoveryAction::InspectExistingIntent,
                None,
            )?;
            return Ok(summary(
                &checkpoint_id,
                scope,
                RecoveryState::FencedOriginalBytesMissing,
                None,
            ));
        };
        recovery_gate(
            retention,
            recovery,
            scope,
            RecoveryAction::ReadRetainedCopy,
            None,
        )?;
        let original = {
            // Never hold two journal locks together (including when source=self).
            let c = source
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            read_existing(&c, &checkpoint_id, &request_digest, &scope_bytes)?
        };
        let Some(original) = original else {
            recovery_gate(
                retention,
                recovery,
                scope,
                RecoveryAction::ReadRetainedCopy,
                None,
            )?;
            return Ok(summary(
                &checkpoint_id,
                scope,
                RecoveryState::FencedOriginalBytesMissing,
                None,
            ));
        };
        verify_original(&original, signed, policy)?;
        recovery_gate(
            retention,
            recovery,
            scope,
            RecoveryAction::ReadRetainedCopy,
            Some(&original),
        )?;
        recovery_gate(
            retention,
            recovery,
            scope,
            RecoveryAction::RestoreExactRetainedCopy,
            Some(&original),
        )?;
        let state = {
            let mut c = self
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            // Recheck immutable intent and a potentially completed concurrent
            // writer. Its different bytes are a conflict, never overwritten.
            let current = read_existing(&tx, &checkpoint_id, &request_digest, &scope_bytes)?;
            let state = if let Some(current) = current {
                if current.digest != original.digest
                    || current.txid != original.txid
                    || current.bytes.as_slice() != original.bytes.as_slice()
                {
                    return Err(RetentionError::IdempotencyConflict);
                }
                RecoveryState::CompleteExactReplay
            } else {
                tx.execute("INSERT INTO transaction_results(checkpoint_id,bytes,digest,txid) VALUES (?1,?2,?3,?4)",
                    params![checkpoint_id,original.bytes.as_slice(),original.digest,original.txid]).map_err(db)?;
                RecoveryState::RestoredExactRetainedBytes
            };
            recovery_gate(
                retention,
                recovery,
                scope,
                RecoveryAction::RestoreExactRetainedCopy,
                Some(&original),
            )?;
            tx.commit().map_err(db)?;
            state
        };
        recovery_gate(
            retention,
            recovery,
            scope,
            RecoveryAction::RestoreExactRetainedCopy,
            Some(&original),
        )?;
        Ok(summary(&checkpoint_id, scope, state, Some(&original)))
    }
}

// Missing and malformed intents are errors; a real matching intent with no result
// is the only None. Recovery never creates a replacement intent or accepts raw
// caller-supplied transaction bytes.
pub(super) fn read_existing(
    c: &Connection,
    id: &str,
    request: &str,
    scope: &[u8],
) -> Result<Option<OriginalResult>> {
    let existing: Option<(String,Vec<u8>)> = c.query_row(
        "SELECT substr(request_digest,1,65),scope FROM transaction_intents WHERE checkpoint_id=?1 AND length(scope)<=16384", [id],
        |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
    let (digest, bytes) = existing.ok_or(RetentionError::IntentNotFound)?;
    let bytes = Zeroizing::new(bytes);
    if digest != request || bytes.as_slice() != scope {
        return Err(RetentionError::IdempotencyConflict);
    }
    // CASE preserves the distinction between an absent result and an oversized
    // corrupt result; corruption must never be treated as permission to restore.
    let result: Option<(Option<Vec<u8>>,String,String)> = c.query_row(
        "SELECT CASE WHEN length(bytes)<=1048576 THEN bytes ELSE NULL END,substr(digest,1,65),substr(txid,1,65) FROM transaction_results WHERE checkpoint_id=?1", [id],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db)?;
    result
        .map(|(bytes, digest, txid)| {
            Ok(OriginalResult {
                bytes: Zeroizing::new(bytes.ok_or(RetentionError::VerificationFailed)?),
                digest,
                txid,
            })
        })
        .transpose()
}
pub(super) fn verify_original(original: &OriginalResult, signed: &[u8], policy: &ReviewPolicy) -> Result<()> {
    if hash(&original.bytes) != original.digest
        || verify_saved_transaction(&original.bytes, signed, policy)? != original.txid
    {
        return Err(RetentionError::VerificationFailed);
    }
    Ok(())
}
fn recovery_gate(
    retention: &dyn TransactionRetentionConsent,
    recovery: &dyn TransactionRecoveryConsent,
    scope: &TransactionRetentionScope,
    action: RecoveryAction,
    original: Option<&OriginalResult>,
) -> Result<()> {
    gate(retention, scope)?;
    let request = TransactionRecoveryScope {
        retention: scope,
        action,
        transaction_digest: original.map(|r| r.digest.as_str()),
        txid: original.map(|r| r.txid.as_str()),
    };
    if !recovery.permits(&request) {
        return Err(RetentionError::ConsentDenied);
    }
    gate(retention, scope)
}
fn summary(
    id: &str,
    scope: &TransactionRetentionScope,
    state: RecoveryState,
    original: Option<&OriginalResult>,
) -> TransactionRecoverySummary {
    TransactionRecoverySummary {
        checkpoint_id: id.into(),
        state,
        next_action: if original.is_some() {
            RecoveryNextAction::None
        } else {
            RecoveryNextAction::LocateMatchingEncryptedCheckpoint
        },
        checkpoint: original.map(|r| TransactionCheckpointSummary {
            checkpoint_id: id.into(),
            signed_result_id: scope.signed_result_id.clone(),
            transaction_digest: r.digest.clone(),
            txid: r.txid.clone(),
            exact_replay: true,
            cryptographic_transaction_verified: true,
            transaction_extracted: true,
            chain_validated: false,
            authorization_allowed: false,
            distribution_allowed: false,
            release_allowed: false,
        }),
        re_extraction_allowed: false,
        authorization_allowed: false,
        distribution_allowed: false,
        release_allowed: false,
    }
}

#[cfg(all(test, feature = "synthetic-qualification", target_os = "linux"))]
mod tests {
    use super::*;
    use orchard::keys::{SpendAuthorizingKey, SpendingKey};
    use std::sync::atomic::Ordering;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};

    struct Consent;
    impl SignedRetentionConsent for Consent {
        fn permits(&self, s: &SignedRetentionScope) -> bool {
            s.context.principal_id == "synthetic-recovery"
        }
    }
    impl TransactionRetentionConsent for Consent {
        fn permits(&self, s: &TransactionRetentionScope) -> bool {
            SignedRetentionConsent::permits(self, &s.signed_scope)
        }
    }
    impl TransactionRecoveryConsent for Consent {
        fn permits(&self, s: &TransactionRecoveryScope<'_>) -> bool {
            TransactionRetentionConsent::permits(self, s.retention)
                && (s.action != RecoveryAction::RestoreExactRetainedCopy
                    || (s.transaction_digest.is_some_and(|d| d.len() == 64)
                        && s.txid.is_some_and(|d| d.len() == 64)))
        }
    }
    struct Deny;
    impl TransactionRecoveryConsent for Deny {
        fn permits(&self, _: &TransactionRecoveryScope<'_>) -> bool {
            false
        }
    }
    impl TransactionRetentionConsent for Deny {
        fn permits(&self, _: &TransactionRetentionScope) -> bool {
            false
        }
    }
    impl SignedRetentionConsent for Deny {
        fn permits(&self, _: &SignedRetentionScope) -> bool {
            false
        }
    }
    struct DenyRestore;
    impl TransactionRecoveryConsent for DenyRestore {
        fn permits(&self, s: &TransactionRecoveryScope<'_>) -> bool {
            s.action != RecoveryAction::RestoreExactRetainedCopy
        }
    }

    #[test]
    fn explicit_recovery_restores_only_exact_retained_bytes_and_never_extracts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "wholepact-recovery-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([0x68; 32]);
        let signed_journal = SignedResultJournal::from_encrypted_connection(
            create_encrypted(dir.join("signed.db"), &key).unwrap(),
        )
        .unwrap();
        let fixture = crate::synthetic::review_fixture().unwrap();
        let review = crate::review::verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
        let limits = ProvingLimits { maximum_actions: 8 };
        let proof = crate::proving::prove_reviewed(
            &fixture.pczt_bytes,
            &fixture.policy,
            review.review_binding(),
            limits,
        )
        .unwrap();
        let mut signatures = Vec::new();
        for input in &fixture.policy.inputs {
            let mut signer =
                pczt::roles::signer::Signer::new(Pczt::parse(&proof.pczt_bytes).unwrap()).unwrap();
            let key = SpendingKey::from_bytes([input.participant_index as u8 + 1; 32]).unwrap();
            signer
                .sign_ironwood(
                    UnwrapErr(SysRng),
                    input.action_index,
                    &SpendAuthorizingKey::from(&key),
                )
                .unwrap();
            let signed = signer.finish();
            signatures.push(ExternalSignature {
                participant_index: input.participant_index,
                action_index: input.action_index,
                signature: signed.ironwood().actions()[input.action_index]
                    .spend()
                    .spend_auth_sig()
                    .unwrap(),
            });
        }
        let context = SignedCandidateContext {
            principal_id: "synthetic-recovery".into(),
            candidate_id: "synthetic-candidate".into(),
            proof_job_id: "synthetic-proof".into(),
            checkpoint_scope_digest: "11".repeat(32),
            proved_artifact_digest: hash(&proof.pczt_bytes),
            manifest_digest: hex::encode(fixture.policy.manifest_digest),
            review_binding: review.review_binding().into(),
            delivery_provenance_digest: "22".repeat(32),
            account_ids: fixture
                .policy
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect(),
            local_operator: "synthetic-local".into(),
            purpose: "Exact retained-byte recovery fixture".into(),
            retention_policy: "Temporary encrypted fixture".into(),
        };
        let idem = "synthetic-recovery-signatures";
        signed_journal
            .retain(
                context.clone(),
                idem,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &Consent,
            )
            .unwrap();
        let source = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(dir.join("source.db"), &key).unwrap(),
        )
        .unwrap();
        let first = signed_journal
            .checkpoint_transaction(
                context.clone(),
                idem,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &Consent,
                LocalTransactionCheckpoint {
                    journal: &source,
                    consent: &Consent,
                },
            )
            .unwrap();
        assert_eq!(source.extraction_invocations.load(Ordering::SeqCst), 1);
        let (scope, signed) = signed_journal
            .verified_transaction_predecessor(
                context.clone(),
                idem,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &Consent,
            )
            .unwrap();
        let destination_path = dir.join("destination.db");
        let destination = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(&destination_path, &key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            destination
                .recover_existing(
                    &scope,
                    &signed,
                    &fixture.policy,
                    &Consent,
                    Some(&source),
                    &Consent
                )
                .unwrap_err(),
            RetentionError::IntentNotFound
        );
        // An exact earlier checkpoint containing the intent but not its result.
        let (id, signed_id, request, scope_bytes): (String,String,String,Vec<u8>) = source.connection.lock().unwrap().query_row(
            "SELECT checkpoint_id,signed_result_id,request_digest,scope FROM transaction_intents",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        destination.connection.lock().unwrap().execute("INSERT INTO transaction_intents(checkpoint_id,signed_result_id,request_digest,scope) VALUES (?1,?2,?3,?4)",
            params![id,signed_id,request,scope_bytes]).unwrap();
        drop(destination);
        let destination = TransactionCheckpointJournal::from_encrypted_connection(
            open_encrypted(&destination_path, &key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            destination
                .recover_existing(&scope, &signed, &fixture.policy, &Consent, None, &Deny)
                .unwrap_err(),
            RetentionError::ConsentDenied
        );
        assert_eq!(
            destination
                .recover_existing(&scope, &signed, &fixture.policy, &Deny, None, &Consent)
                .unwrap_err(),
            RetentionError::ConsentDenied
        );
        let mismatch = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(dir.join("mismatch.db"), &key).unwrap(),
        )
        .unwrap();
        mismatch.connection.lock().unwrap().execute("INSERT INTO transaction_intents(checkpoint_id,signed_result_id,request_digest,scope) VALUES (?1,?2,?3,?4)",
            params![id,signed_id,"not-the-original-request",scope_bytes]).unwrap();
        assert_eq!(
            destination
                .recover_existing(
                    &scope,
                    &signed,
                    &fixture.policy,
                    &Consent,
                    Some(&mismatch),
                    &Consent
                )
                .unwrap_err(),
            RetentionError::IdempotencyConflict
        );
        drop(mismatch);
        let fenced = destination
            .recover_existing(&scope, &signed, &fixture.policy, &Consent, None, &Consent)
            .unwrap();
        assert_eq!(fenced.state, RecoveryState::FencedOriginalBytesMissing);
        assert_eq!(
            fenced.next_action,
            RecoveryNextAction::LocateMatchingEncryptedCheckpoint
        );
        assert!(
            fenced.checkpoint.is_none() && !fenced.re_extraction_allowed && !fenced.release_allowed
        );
        assert_eq!(
            destination
                .recover_existing(
                    &scope,
                    &signed,
                    &fixture.policy,
                    &Consent,
                    Some(&destination),
                    &Consent
                )
                .unwrap()
                .state,
            RecoveryState::FencedOriginalBytesMissing
        );
        assert_eq!(
            destination
                .recover_existing(
                    &scope,
                    &signed,
                    &fixture.policy,
                    &Consent,
                    Some(&source),
                    &DenyRestore
                )
                .unwrap_err(),
            RetentionError::ConsentDenied
        );
        // Corrupt source metadata cannot become a restore grant.
        {
            let c = source.connection.lock().unwrap();
            c.execute_batch("DROP TRIGGER immutable_transaction_result_update;")
                .unwrap();
            c.execute("UPDATE transaction_results SET digest='corrupt'", [])
                .unwrap();
        }
        assert_eq!(
            destination
                .recover_existing(
                    &scope,
                    &signed,
                    &fixture.policy,
                    &Consent,
                    Some(&source),
                    &Consent
                )
                .unwrap_err(),
            RetentionError::VerificationFailed
        );
        source
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE transaction_results SET digest=?1",
                [&first.transaction_digest],
            )
            .unwrap();
        let restored = signed_journal
            .recover_transaction_checkpoint(
                context,
                idem,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &Consent,
                LocalTransactionRecovery {
                    destination: LocalTransactionCheckpoint {
                        journal: &destination,
                        consent: &Consent,
                    },
                    retained_copy: Some(&source),
                    consent: &Consent,
                },
            )
            .unwrap();
        assert_eq!(restored.state, RecoveryState::RestoredExactRetainedBytes);
        assert!(
            !restored.re_extraction_allowed
                && !restored.authorization_allowed
                && !restored.distribution_allowed
                && !restored.release_allowed
        );
        assert_eq!(
            restored.checkpoint.as_ref().unwrap().transaction_digest,
            first.transaction_digest
        );
        assert_eq!(restored.checkpoint.as_ref().unwrap().txid, first.txid);
        assert_eq!(destination.extraction_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(source.extraction_invocations.load(Ordering::SeqCst), 1);
        drop(destination);
        let destination = TransactionCheckpointJournal::from_encrypted_connection(
            open_encrypted(&destination_path, &key).unwrap(),
        )
        .unwrap();
        let replay = destination
            .recover_existing(&scope, &signed, &fixture.policy, &Consent, None, &Consent)
            .unwrap();
        assert_eq!(replay.state, RecoveryState::CompleteExactReplay);
        assert_eq!(
            replay.checkpoint.as_ref().unwrap().transaction_digest,
            first.transaction_digest
        );
        assert_eq!(
            destination
                .recover_existing(
                    &scope,
                    &signed,
                    &fixture.policy,
                    &Consent,
                    Some(&source),
                    &Consent
                )
                .unwrap()
                .state,
            RecoveryState::CompleteExactReplay
        );
        let source_bytes: Vec<u8> = source
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT bytes FROM transaction_results", [], |r| r.get(0))
            .unwrap();
        let destination_bytes: Vec<u8> = destination
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT bytes FROM transaction_results", [], |r| r.get(0))
            .unwrap();
        assert!(source_bytes == destination_bytes);
        assert_eq!(destination.extraction_invocations.load(Ordering::SeqCst), 0);
        drop(destination);
        drop(source);
        drop(signed_journal);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
