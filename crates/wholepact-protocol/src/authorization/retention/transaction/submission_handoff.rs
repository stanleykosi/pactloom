//! Narrow retained-transaction to encrypted submission-journal handoff.
//! No extraction, byte export, network I/O or implicit submission authority.
use super::*;
use wholepact_chain::{
    BackendIdentity, ChainContext, ChainError, EncryptedSubmissionJournal, SubmissionAuthority,
    SubmissionClock, SubmissionDescriptor, SubmissionPermit, SubmissionPlan, SubmissionPolicy,
    SubmissionReview, retain_submission_plan,
};

pub struct SubmissionHandoffScope<'a> {
    pub retained: &'a TransactionRetentionScope,
    pub descriptor: &'a SubmissionDescriptor,
    pub backend: &'a BackendIdentity,
    /// Authenticated local database identity, not rollback/writer freshness.
    pub destination_journal_identity: &'a str,
}
/// Dedicated permission to copy usable transaction bytes into the named local
/// submission journal for the exact obligation and backend. Privacy/read consent
/// alone is insufficient. Embeddings must hold an authority lease for revocation.
pub trait SubmissionHandoffConsent {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool;
}
pub struct LocalSubmissionHandoff<'a, A, C> {
    pub transactions: LocalTransactionCheckpoint<'a>,
    pub submission_journal: &'a mut EncryptedSubmissionJournal,
    pub authority: &'a mut A,
    pub backend: &'a BackendIdentity,
    pub chain_context: &'a ChainContext,
    pub clock: &'a C,
    pub policy: SubmissionPolicy,
    pub consent: &'a dyn SubmissionHandoffConsent,
}
/// A locally reverified immutable predecessor. No public constructor, byte getter,
/// deserialization, cloning or authority claim exists. Current permissions must
/// still be acquired at the eventual durable dispatch boundary.
pub struct VerifiedRetainedSubmission {
    scope: TransactionRetentionScope,
    plan: SubmissionPlan,
}
impl VerifiedRetainedSubmission {
    /// Exact original metadata from the scope checked against both private journals.
    /// Inert original retention metadata; never a permission or byte export.
    pub fn retention_scope(&self) -> &TransactionRetentionScope { &self.scope }
    pub fn signed_result_id(&self) -> &str {
        &self.scope.signed_result_id
    }
    pub fn signed_request_digest(&self) -> &str {
        &self.scope.signed_request_digest
    }
    pub fn signed_candidate_digest(&self) -> &str {
        &self.scope.signed_candidate_digest
    }
    pub fn checkpoint_id(&self) -> String {
        format!(
            "transaction-{}",
            framed(&[b"transaction-id-v1", self.scope.signed_result_id.as_bytes()])
        )
    }
    pub fn descriptor(&self) -> &SubmissionDescriptor {
        self.plan.descriptor()
    }
    pub fn context(&self) -> &SignedCandidateContext {
        &self.scope.signed_scope.context
    }
}

/// One explicit exact-byte dispatch. No raw transaction getter, reconstruction,
/// implicit retry or authority synthesized from privacy consent is provided.
pub struct LocalSubmissionDispatch<'a, A, B, C> {
    pub transactions: LocalTransactionCheckpoint<'a>,
    pub submission_journal: &'a mut EncryptedSubmissionJournal,
    pub authority: &'a mut A,
    pub backend: &'a mut B,
    pub clock: &'a C,
    pub policy: SubmissionPolicy,
    pub consent: &'a dyn SubmissionHandoffConsent,
}

#[derive(Debug)]
pub enum SubmissionHandoffError {
    Retention(RetentionError),
    Submission(ChainError),
}
impl From<RetentionError> for SubmissionHandoffError {
    fn from(error: RetentionError) -> Self {
        Self::Retention(error)
    }
}
impl From<ChainError> for SubmissionHandoffError {
    fn from(error: ChainError) -> Self {
        Self::Submission(error)
    }
}

impl SignedResultJournal {
    /// Reverify an existing signed predecessor and exact completed transaction;
    /// retain it in the concrete encrypted submission journal under fresh gates.
    /// Missing originals stay fenced. The caller must bind obligation/proposal IDs
    /// to its authenticated immutable agreement, never arbitrary browser labels.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_transaction_for_submission<A: SubmissionAuthority, C: SubmissionClock>(
        &self,
        context: SignedCandidateContext,
        signature_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        obligation_id: &str,
        proposal_id: &str,
        submission_operation_id: &str,
        local: LocalSubmissionHandoff<'_, A, C>,
    ) -> std::result::Result<SubmissionDescriptor, SubmissionHandoffError> {
        let VerifiedRetainedSubmission { scope, plan } = self.verify_retained_submission(
            context,
            signature_key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
            obligation_id,
            proposal_id,
            submission_operation_id,
            &local.transactions,
        )?;
        let retained_consent = CombinedRetentionGate {
            signed: signed_consent,
            transaction: local.transactions.consent,
        };
        let mut authority = HandoffAuthority {
            inner: local.authority,
            retained: &scope,
            retention: &retained_consent,
            consent: local.consent,
        };
        let result = retain_submission_plan(
            local.submission_journal,
            &plan,
            &mut authority,
            local.backend,
            local.chain_context,
            local.clock,
            local.policy,
        )?;
        // The destination has committed by this point. A late privacy revocation
        // must preserve the possibly-retained outcome rather than imply no effect.
        gate(&retained_consent, &scope).map_err(|_| {
            SubmissionHandoffError::Submission(ChainError::SubmissionRetentionUncertain)
        })?;
        Ok(result)
    }
    /// Revalidate the exact completed transaction against its original saved
    /// proof, signatures and review policy before every explicit dispatch/retry.
    /// A mutable runtime owns all journals and the backend through the await.
    /// Cancellation after attempt commit leaves Unknown exposure in the journal.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_retained_transaction<
        A: SubmissionAuthority,
        B: wholepact_chain::SubmissionBackend,
        C: SubmissionClock,
    >(
        &self,
        context: SignedCandidateContext,
        signature_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        obligation_id: &str,
        proposal_id: &str,
        submission_operation_id: &str,
        local: LocalSubmissionDispatch<'_, A, B, C>,
    ) -> std::result::Result<wholepact_chain::SubmissionDispatchReport, SubmissionHandoffError>
    {
        let VerifiedRetainedSubmission { scope, plan } = self.verify_retained_submission(
            context,
            signature_key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
            obligation_id,
            proposal_id,
            submission_operation_id,
            &local.transactions,
        )?;
        // Dispatch cannot create a new submission intent. The explicitly approved
        // handoff must already have committed this exact original operation.
        if local
            .submission_journal
            .retained_submission_descriptor(submission_operation_id)?
            .as_ref()
            != Some(plan.descriptor())
        {
            return Err(ChainError::SubmissionNotAuthorized.into());
        }
        let retained_consent = CombinedRetentionGate {
            signed: signed_consent,
            transaction: local.transactions.consent,
        };
        let mut authority = HandoffAuthority {
            inner: local.authority,
            retained: &scope,
            retention: &retained_consent,
            consent: local.consent,
        };
        // submit_plan keeps this combined permit alive through the final durable
        // outcome. Rejection/timeouts never clear exposure or permit replacement.
        Ok(wholepact_chain::submit_plan(
            local.submission_journal,
            &plan,
            local.backend,
            &mut authority,
            local.clock,
            local.policy,
        )
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_retained_submission(
        &self,
        context: SignedCandidateContext,
        signature_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        obligation_id: &str,
        proposal_id: &str,
        submission_operation_id: &str,
        transactions: &LocalTransactionCheckpoint<'_>,
    ) -> std::result::Result<VerifiedRetainedSubmission, SubmissionHandoffError> {
        let (scope, signed) = self.verified_completed_transaction_predecessor(
            context,
            signature_key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
        )?;
        let retained_consent = CombinedRetentionGate {
            signed: signed_consent,
            transaction: transactions.consent,
        };
        gate(&retained_consent, &scope)?;
        let encoded =
            Zeroizing::new(serde_json::to_vec(&scope).map_err(|_| RetentionError::InvalidRequest)?);
        if encoded.len() > 16384 {
            return Err(RetentionError::InvalidRequest.into());
        }
        let request = framed(&[b"transaction-checkpoint-v1", &encoded]);
        let id = format!(
            "transaction-{}",
            framed(&[b"transaction-id-v1", scope.signed_result_id.as_bytes()])
        );
        let (bytes, digest, txid) = {
            let c = transactions
                .journal
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let saved: Option<(String, String, Option<Vec<u8>>)> = c.query_row(
                "SELECT substr(signed_result_id,1,72),substr(request_digest,1,65),CASE WHEN length(scope)<=16384 THEN scope ELSE NULL END FROM transaction_intents WHERE checkpoint_id=?1", [&id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db)?;
            let (saved_result_id, saved_request, saved_scope) = saved.ok_or(RetentionError::IntentNotFound)?;
            let saved_scope = Zeroizing::new(saved_scope.ok_or(RetentionError::VerificationFailed)?);
            if saved_result_id != scope.signed_result_id || saved_request != request || saved_scope.as_slice() != encoded.as_slice() {
                return Err(RetentionError::IdempotencyConflict.into());
            }
            let saved: Option<(Option<Vec<u8>>, String, String)> = c.query_row(
                "SELECT CASE WHEN length(bytes)<=1048576 THEN bytes ELSE NULL END,substr(digest,1,65),substr(txid,1,65) FROM transaction_results WHERE checkpoint_id=?1", [&id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db)?;
            let (bytes, digest, txid) = saved.ok_or(RetentionError::RecoveryRequired)?;
            (
                Zeroizing::new(bytes.ok_or(RetentionError::VerificationFailed)?),
                digest,
                txid,
            )
        };
        if hash(&bytes) != digest || verify_saved_transaction(&bytes, &signed, policy)? != txid {
            return Err(RetentionError::VerificationFailed.into());
        }
        gate(&retained_consent, &scope)?;
        let plan =
            SubmissionPlan::new(obligation_id, proposal_id, submission_operation_id, &bytes)?;
        if plan.descriptor().bytes_sha256 != digest || plan.descriptor().transaction_id != txid {
            return Err(RetentionError::VerificationFailed.into());
        }
        Ok(VerifiedRetainedSubmission { scope, plan })
    }
}
struct HandoffAuthority<'a, A> {
    inner: &'a mut A,
    retained: &'a TransactionRetentionScope,
    retention: &'a dyn TransactionRetentionConsent,
    consent: &'a dyn SubmissionHandoffConsent,
}
struct HandoffPermit<'a, P> {
    inner: P,
    retained: &'a TransactionRetentionScope,
    retention: &'a dyn TransactionRetentionConsent,
    consent: &'a dyn SubmissionHandoffConsent,
}
fn check_handoff(
    retained: &TransactionRetentionScope,
    retention: &dyn TransactionRetentionConsent,
    consent: &dyn SubmissionHandoffConsent,
    review: &SubmissionReview<'_>,
) -> std::result::Result<(), ChainError> {
    if !retention.permits(retained)
        || !consent.permits(&SubmissionHandoffScope {
            retained,
            descriptor: review.descriptor,
            backend: review.backend,
            destination_journal_identity: review.journal_identity,
        })
        || !retention.permits(retained)
    {
        return Err(ChainError::SubmissionNotAuthorized);
    }
    Ok(())
}
impl<'a, A: SubmissionAuthority> SubmissionAuthority for HandoffAuthority<'a, A> {
    type Permit = HandoffPermit<'a, A::Permit>;
    fn authorize(
        &mut self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<Self::Permit, ChainError> {
        check_handoff(self.retained, self.retention, self.consent, review)?;
        let inner = self.inner.authorize(review)?;
        check_handoff(self.retained, self.retention, self.consent, review)?;
        Ok(HandoffPermit {
            inner,
            retained: self.retained,
            retention: self.retention,
            consent: self.consent,
        })
    }
}
impl<P: SubmissionPermit> SubmissionPermit for HandoffPermit<'_, P> {
    fn expected_attempt_number(&self) -> Option<u32> {
        self.inner.expected_attempt_number()
    }
    fn valid_until_unix_seconds(&self) -> Option<u64> {
        self.inner.valid_until_unix_seconds()
    }
    fn check_current(
        &mut self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<(), ChainError> {
        check_handoff(self.retained, self.retention, self.consent, review)?;
        self.inner.check_current(review)?;
        check_handoff(self.retained, self.retention, self.consent, review)
    }
}

#[cfg(all(test, feature = "synthetic-qualification", target_os = "linux"))]
mod tests {
    use super::*;
    use orchard::keys::{SpendAuthorizingKey, SpendingKey};
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    struct Consent {
        journal: String,
    }
    impl SignedRetentionConsent for Consent {
        fn permits(&self, s: &SignedRetentionScope) -> bool {
            s.context.principal_id == "synthetic-handoff"
        }
    }
    impl TransactionRetentionConsent for Consent {
        fn permits(&self, s: &TransactionRetentionScope) -> bool {
            SignedRetentionConsent::permits(self, &s.signed_scope)
        }
    }
    impl SubmissionHandoffConsent for Consent {
        fn permits(&self, s: &SubmissionHandoffScope<'_>) -> bool {
            TransactionRetentionConsent::permits(self, s.retained)
                && s.destination_journal_identity == self.journal
                && s.descriptor.obligation_id == "synthetic-obligation-1"
                && s.descriptor.proposal_id == "synthetic-proposal-1"
                && s.backend.trust_profile == "synthetic_never_chain_evidence"
        }
    }
    fn transaction_scope_digest(journal: &SignedResultJournal, id: &str) -> String {
        journal.connection.lock().unwrap().query_row(
            "SELECT digest FROM signed_results WHERE result_id=?1", [id], |r| r.get(0),
        ).unwrap()
    }
    struct Authority;
    struct Permit;
    impl SubmissionAuthority for Authority {
        type Permit = Permit;
        fn authorize(
            &mut self,
            _: &SubmissionReview<'_>,
        ) -> std::result::Result<Permit, ChainError> {
            Ok(Permit)
        }
    }
    impl SubmissionPermit for Permit {
        fn check_current(
            &mut self,
            _: &SubmissionReview<'_>,
        ) -> std::result::Result<(), ChainError> {
            Ok(())
        }
    }
    struct Clock;
    impl SubmissionClock for Clock {
        fn now_unix_seconds(&self) -> std::result::Result<u64, ChainError> {
            Ok(1_800_000_020)
        }
    }
    #[test]
    fn verified_retained_transaction_handoff_replays_and_refuses_swapped_destination() {
        let path = std::env::temp_dir().join(format!(
            "wholepact-handoff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([0x73; 32]);
        let signed_journal = SignedResultJournal::from_encrypted_connection(
            create_encrypted(path.join("signed.db"), &key).unwrap(),
        )
        .unwrap();
        let transactions = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(path.join("transaction.db"), &key).unwrap(),
        )
        .unwrap();
        let submission_path = path.join("submission.db");
        let mut submissions = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(&submission_path, &key).unwrap(),
        )
        .unwrap();
        let consent = Consent {
            journal: submissions.identity().into(),
        };
        let fixture = crate::synthetic::review_fixture_for_submission().unwrap();
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
            principal_id: "synthetic-handoff".into(),
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
            purpose: "Controlled exact journal handoff".into(),
            retention_policy: "Temporary encrypted fixture".into(),
        };
        let signature_key = "synthetic-handoff-signatures";
        signed_journal
            .retain(
                context.clone(),
                signature_key,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &consent,
            )
            .unwrap();
        let transaction = signed_journal
            .checkpoint_transaction(
                context.clone(),
                signature_key,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &consent,
                LocalTransactionCheckpoint {
                    journal: &transactions,
                    consent: &consent,
                },
            )
            .unwrap();
        // Completed-only verification is a read, including all refusal paths.
        // The fixture uses actual encrypted journals and real proved/signed bytes.
        let changes_before = signed_journal.connection.lock().unwrap().total_changes();
        let transaction_changes_before = transactions.connection.lock().unwrap().total_changes();
        let verified = signed_journal.verify_completed_existing(
            context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
            &signatures, limits, &consent,
        ).unwrap();
        assert_eq!(verified.signed_candidate_digest, transaction_scope_digest(&signed_journal, &verified.result_id));
        assert!(matches!(signed_journal.verify_completed_existing(
            context.clone(), "missing-completed-intent", &proof.pczt_bytes,
            &fixture.policy, &signatures, limits, &consent,
        ), Err(RetentionError::IntentNotFound)));
        let unfinished = SignedResultJournal::from_encrypted_connection(
            create_encrypted(path.join("unfinished.db"), &key).unwrap(),
        ).unwrap();
        let row: (String, String, String, String, Vec<u8>, Vec<u8>) = signed_journal.connection.lock().unwrap().query_row(
            "SELECT result_id,principal_id,idem_key,request_digest,scope,signatures FROM signed_intents WHERE result_id=?1",
            [&verified.result_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).unwrap();
        unfinished.connection.lock().unwrap().execute(
            "INSERT INTO signed_intents(result_id,principal_id,idem_key,request_digest,scope,signatures) VALUES (?1,?2,?3,?4,?5,?6)",
            params![row.0,row.1,row.2,row.3,row.4,row.5],
        ).unwrap();
        let unfinished_changes = unfinished.connection.lock().unwrap().total_changes();
        assert!(matches!(unfinished.verify_completed_existing(
            context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
            &signatures, limits, &consent,
        ), Err(RetentionError::RecoveryRequired)));
        assert!(matches!(unfinished.checkpoint_completed_transaction(
            context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
            &signatures, limits, &consent,
            LocalTransactionCheckpoint { journal: &transactions, consent: &consent },
        ), Err(RetentionError::RecoveryRequired)));
        assert!(matches!(unfinished.verify_retained_submission(
            context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
            &signatures, limits, &consent,
            "synthetic-obligation-1", "synthetic-proposal-1", "synthetic-submission-1",
            &LocalTransactionCheckpoint { journal: &transactions, consent: &consent },
        ), Err(SubmissionHandoffError::Retention(RetentionError::RecoveryRequired))));
        assert_eq!(unfinished.connection.lock().unwrap().total_changes(), unfinished_changes);
        assert_eq!(signed_journal.connection.lock().unwrap().total_changes(), changes_before);
        assert_eq!(transactions.connection.lock().unwrap().total_changes(), transaction_changes_before);
        assert_eq!(transactions.extraction_invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(unfinished);
        // Independent copies deliberately damage one original field at a time.
        // These are test-only raw fixture edits, never a production repair API.
        let intent_row: (String,String,String,Vec<u8>) = transactions.connection.lock().unwrap().query_row(
            "SELECT checkpoint_id,signed_result_id,request_digest,scope FROM transaction_intents",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).unwrap();
        let result_row: (Vec<u8>,String,String) = transactions.connection.lock().unwrap().query_row(
            "SELECT bytes,digest,txid FROM transaction_results", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).unwrap();
        for case in 0..5 {
            let copy = TransactionCheckpointJournal::from_encrypted_connection(
                create_encrypted(path.join(format!("transaction-refusal-{case}.db")), &key).unwrap(),
            ).unwrap();
            {
                let c = copy.connection.lock().unwrap();
                c.execute_batch("PRAGMA ignore_check_constraints=ON;").unwrap();
                if case != 0 {
                    let signed_id = if case == 3 { "signed-wrong-original" } else { &intent_row.1 };
                    let encoded = if case == 2 { vec![0;16385] } else { intent_row.3.clone() };
                    c.execute("INSERT INTO transaction_intents(checkpoint_id,signed_result_id,request_digest,scope) VALUES (?1,?2,?3,?4)",
                        params![intent_row.0,signed_id,intent_row.2,encoded]).unwrap();
                    if case != 1 {
                        let bytes = if case == 4 { vec![0;1048577] } else { result_row.0.clone() };
                        c.execute("INSERT INTO transaction_results(checkpoint_id,bytes,digest,txid) VALUES (?1,?2,?3,?4)",
                            params![intent_row.0,bytes,result_row.1,result_row.2]).unwrap();
                    }
                }
            }
            let changes = copy.connection.lock().unwrap().total_changes();
            let result = signed_journal.verify_retained_submission(
                context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
                &signatures, limits, &consent,
                "synthetic-obligation-1", "synthetic-proposal-1", "synthetic-submission-1",
                &LocalTransactionCheckpoint { journal: &copy, consent: &consent },
            );
            let expected = match case { 0 => RetentionError::IntentNotFound,
                1 => RetentionError::RecoveryRequired, 3 => RetentionError::IdempotencyConflict,
                _ => RetentionError::VerificationFailed };
            assert!(matches!(result, Err(SubmissionHandoffError::Retention(error)) if error == expected));
            assert_eq!(copy.connection.lock().unwrap().total_changes(), changes);
            assert_eq!(copy.extraction_invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
        for case in 0..3 {
            let copy = SignedResultJournal::from_encrypted_connection(
                create_encrypted(path.join(format!("signed-refusal-{case}.db")), &key).unwrap(),
            ).unwrap();
            {
                let c = copy.connection.lock().unwrap();
                c.execute_batch("PRAGMA ignore_check_constraints=ON;").unwrap();
                let scope = if case == 0 { vec![0;16385] } else { row.4.clone() };
                let sigs = if case == 1 { vec![0;10241] } else { row.5.clone() };
                c.execute("INSERT INTO signed_intents(result_id,principal_id,idem_key,request_digest,scope,signatures) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![row.0,row.1,row.2,row.3,scope,sigs]).unwrap();
                let bytes: Vec<u8> = if case == 2 { vec![0;1048577] } else { vec![] };
                c.execute("INSERT INTO signed_results(result_id,bytes,digest) VALUES (?1,?2,?3)",
                    params![row.0,bytes,verified.signed_candidate_digest]).unwrap();
            }
            let changes = copy.connection.lock().unwrap().total_changes();
            assert!(matches!(copy.verify_completed_existing(
                context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
                &signatures, limits, &consent,
            ), Err(RetentionError::VerificationFailed)));
            assert_eq!(copy.connection.lock().unwrap().total_changes(), changes);
        }
        struct RevokeAfterVerification(std::cell::Cell<usize>);
        impl SignedRetentionConsent for RevokeAfterVerification {
            fn permits(&self, _: &SignedRetentionScope) -> bool {
                let calls = self.0.get() + 1;
                self.0.set(calls);
                calls < 4
            }
        }
        let revoked = RevokeAfterVerification(std::cell::Cell::new(0));
        assert!(matches!(signed_journal.verify_completed_existing(
            context.clone(), signature_key, &proof.pczt_bytes, &fixture.policy,
            &signatures, limits, &revoked,
        ), Err(RetentionError::ConsentDenied)));
        assert_eq!(revoked.0.get(), 4);
        assert_eq!(signed_journal.connection.lock().unwrap().total_changes(), changes_before);
        assert_eq!(transactions.connection.lock().unwrap().total_changes(), transaction_changes_before);
        let chain =
            wholepact_chain::synthetic_chain_context_for_qualification(1_800_000_020).unwrap();
        let handoff = |journal: &mut EncryptedSubmissionJournal| {
            signed_journal.retain_transaction_for_submission(
                context.clone(),
                signature_key,
                &proof.pczt_bytes,
                &fixture.policy,
                &signatures,
                limits,
                &consent,
                "synthetic-obligation-1",
                "synthetic-proposal-1",
                "synthetic-submission-1",
                LocalSubmissionHandoff {
                    transactions: LocalTransactionCheckpoint {
                        journal: &transactions,
                        consent: &consent,
                    },
                    submission_journal: journal,
                    authority: &mut Authority,
                    backend: chain.source(),
                    chain_context: &chain,
                    clock: &Clock,
                    policy: SubmissionPolicy::default(),
                    consent: &consent,
                },
            )
        };
        let first = handoff(&mut submissions).unwrap();
        assert_eq!(first.transaction_id, transaction.txid);
        assert_eq!(first.bytes_sha256, transaction.transaction_digest);
        assert!(
            submissions
                .submission_attempts(&first.operation_id)
                .unwrap()
                .is_empty()
        );
        drop(submissions);
        let mut submissions = EncryptedSubmissionJournal::from_encrypted_connection(
            open_encrypted(&submission_path, &key).unwrap(),
        )
        .unwrap();
        let replay = handoff(&mut submissions).unwrap();
        assert_eq!(replay, first);
        let mut swapped = EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(path.join("swapped.db"), &key).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            handoff(&mut swapped),
            Err(SubmissionHandoffError::Submission(
                ChainError::SubmissionNotAuthorized
            ))
        ));
        assert!(
            swapped
                .retained_submission_descriptor(&first.operation_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            transactions
                .extraction_invocations
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        drop(swapped);
        drop(submissions);
        drop(transactions);
        drop(signed_journal);
        std::fs::remove_dir_all(path).unwrap();
    }
}
