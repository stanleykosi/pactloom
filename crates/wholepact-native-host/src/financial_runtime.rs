//! Protected exact retained submission composition. The host lends actual opened
//! encrypted journals and holds all account/witness/native authority owners until
//! this awaited operation and its durable outcome return. No HTTP bytes/booleans
//! or restored approval objects can create this runtime.
use crate::authority::submission::{NativeSubmissionConsent, ProductionSubmissionAuthority};
use wholepact_chain::{
    EncryptedSubmissionJournal, LightwalletSubmissionBackend, SubmissionDispatchReport,
    SubmissionPolicy, SystemSubmissionClock,
};
use wholepact_engine::{
    Access, Engine,
    proof_jobs::LocalProofJob,
    signature_intake::{
        AuthenticatedSignatureDelivery, LocalSignedRetention, VerifiedCandidateSubmission,
    },
};
use wholepact_protocol::authorization::retention::transaction::{
    LocalTransactionCheckpoint,
    submission_handoff::{LocalSubmissionDispatch, SubmissionHandoffConsent},
};
use wholepact_signer::authority_bridge::ipc::OriginalHistoryLease;
use wholepact_transport::Timestamp;

pub(crate) struct ProtectedFinancialRuntime<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) access: &'a Access,
    pub(crate) submission_journal: &'a mut EncryptedSubmissionJournal,
    pub(crate) backend: &'a mut LightwalletSubmissionBackend,
}
impl ProtectedFinancialRuntime<'_> {
    /// Commit the exact original retained transaction into the configured submission
    /// journal before dispatch. Uses separate copy consent and the genuine held
    /// native/original signer admissions; this phase never sends transaction bytes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn retain_original_intent<'a>(
        &mut self,
        verified: &'a VerifiedCandidateSubmission,
        signature_key: &str,
        proof: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        originals: &'a [OriginalHistoryLease<'a>],
        admissions: &'a [wholepact_signer::authority_bridge::dispatch_ipc::SignerDispatchAdmission<'a>],
        native_consent: &'a NativeSubmissionConsent,
        handoff_consent: &dyn SubmissionHandoffConsent,
        policy: SubmissionPolicy,
        now: &Timestamp,
    ) -> Result<wholepact_chain::SubmissionDescriptor, wholepact_engine::ApiError> {
        use wholepact_chain::SubmissionBackend;
        let context = tokio::time::timeout(policy.dispatch_timeout, self.backend.fresh_context())
            .await
            .map_err(|_| wholepact_engine::ApiError::new("SUBMISSION_CONTEXT_UNAVAILABLE", "Original submission retention needs a current provider context; no dispatch was attempted"))?
            .map_err(|_| wholepact_engine::ApiError::new("SUBMISSION_CONTEXT_UNAVAILABLE", "Original submission retention needs a current provider context; no dispatch was attempted"))?;
        let backend = self.backend.identity().clone();
        let mut authority =
            ProductionSubmissionAuthority::new(verified, originals, admissions, native_consent);
        self.engine.retain_candidate_for_submission(
            self.access, signature_key, &verified.context().candidate_id,
            &verified.descriptor().operation_id, proof, retention,
            wholepact_protocol::authorization::retention::transaction::submission_handoff::LocalSubmissionHandoff {
                transactions, submission_journal: self.submission_journal,
                authority: &mut authority, backend: &backend, chain_context: &context,
                clock: &SystemSubmissionClock, policy, consent: handoff_consent,
            }, deliveries, now,
        )
    }
    /// Exactly one explicit attempt. A failed/lost return never authorizes new
    /// construction, fresh inputs, a replacement, or removal of prior exposure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn dispatch<'a>(
        &mut self,
        verified: &'a VerifiedCandidateSubmission,
        signature_key: &str,
        proof: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        originals: &'a [OriginalHistoryLease<'a>],
        admissions: &'a [wholepact_signer::authority_bridge::dispatch_ipc::SignerDispatchAdmission<'a>],
        native_consent: &'a NativeSubmissionConsent,
        handoff_consent: &dyn SubmissionHandoffConsent,
        policy: SubmissionPolicy,
        now: &Timestamp,
    ) -> Result<SubmissionDispatchReport, wholepact_engine::ApiError> {
        let descriptor = verified.descriptor();
        let mut authority =
            ProductionSubmissionAuthority::new(verified, originals, admissions, native_consent);
        self.engine
            .dispatch_candidate_submission(
                self.access,
                signature_key,
                &verified.context().candidate_id,
                &descriptor.operation_id,
                proof,
                retention,
                LocalSubmissionDispatch {
                    transactions,
                    submission_journal: self.submission_journal,
                    authority: &mut authority,
                    backend: self.backend,
                    clock: &SystemSubmissionClock,
                    policy,
                    consent: handoff_consent,
                },
                deliveries,
                now,
            )
            .await
    }
}
