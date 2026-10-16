//! Existing candidate → exact retained transaction → encrypted submission intent.
//! Source-only protected composition; no network call or real signer authority.
use super::*;
use wholepact_chain::{SubmissionAuthority, SubmissionClock, SubmissionDescriptor};
use wholepact_protocol::authorization::retention::transaction::submission_handoff::{
    LocalSubmissionDispatch, LocalSubmissionHandoff, SubmissionHandoffError,
};

/// Engine-origin exact transaction evidence, bound to the immutable authenticated
/// candidate and original obligation. It grants neither backend disclosure nor
/// authority to dispatch. Runtime issuers must also hold current signer/native
/// leases and witness admissions for every original account.
pub struct VerifiedCandidateSubmission {
    retained: wholepact_protocol::authorization::retention::transaction::submission_handoff::VerifiedRetainedSubmission,
    agreement_id: String,
    effects_digest: String,
    signature_retention_key: String,
}
impl VerifiedCandidateSubmission {
    pub fn signed_result_id(&self) -> &str {
        self.retained.signed_result_id()
    }
    pub fn signed_request_digest(&self) -> &str {
        self.retained.signed_request_digest()
    }
    pub fn signed_candidate_digest(&self) -> &str {
        self.retained.signed_candidate_digest()
    }
    pub fn checkpoint_id(&self) -> String {
        self.retained.checkpoint_id()
    }
    /// Original journal key independently checked by the real retention verifier.
    pub fn signature_retention_key(&self) -> &str {
        &self.signature_retention_key
    }
    pub fn descriptor(&self) -> &SubmissionDescriptor {
        self.retained.descriptor()
    }
    pub fn context(&self) -> &wholepact_protocol::authorization::retention::SignedCandidateContext {
        self.retained.context()
    }
    pub fn effects_digest(&self) -> &str {
        &self.effects_digest
    }
    pub fn agreement_id(&self) -> &str {
        &self.agreement_id
    }
}

impl Engine {
    /// The obligation and proposal bindings come from the authenticated immutable
    /// candidate, never from caller-supplied labels. The same protected proof,
    /// account association and current read/retention boundaries apply as extraction.
    /// Retention alone is not permission to send; a later dispatch must reacquire
    /// current submission authority and chain evidence for the same exact bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_candidate_for_submission<A: SubmissionAuthority, C: SubmissionClock>(
        &self,
        access: &Access,
        signature_idempotency_key: &str,
        candidate_id: &str,
        submission_operation_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        handoff: LocalSubmissionHandoff<'_, A, C>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<SubmissionDescriptor> {
        if deliveries
            .iter()
            .any(|delivery| delivery.association.is_none())
        {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            true,
        )?;
        retention.journal.retain_transaction_for_submission(
            context,
            signature_idempotency_key,
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &Gate { original: checkpoint.scope(), read: read_consent, retain: retention.consent },
            &candidate.proposal.manifest.agreement.obligation_id,
            &candidate.proposal.proposal_id,
            submission_operation_id,
            handoff,
        ).map_err(|error| {
            let code = match error {
                SubmissionHandoffError::Retention(RetentionError::ConsentDenied) => "SUBMISSION_HANDOFF_CONSENT_DENIED",
                SubmissionHandoffError::Retention(RetentionError::RecoveryRequired) => "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                SubmissionHandoffError::Retention(RetentionError::IntentNotFound) => "TRANSACTION_CHECKPOINT_INTENT_NOT_FOUND",
                SubmissionHandoffError::Retention(RetentionError::IdempotencyConflict) => "SUBMISSION_HANDOFF_CONFLICT",
                SubmissionHandoffError::Retention(_) => "SUBMISSION_HANDOFF_REJECTED",
                SubmissionHandoffError::Submission(wholepact_chain::ChainError::SubmissionRetentionUncertain) => "SUBMISSION_RETENTION_UNCERTAIN",
                SubmissionHandoffError::Submission(wholepact_chain::ChainError::SubmissionNotAuthorized) => "SUBMISSION_NOT_AUTHORIZED",
                SubmissionHandoffError::Submission(_) => "SUBMISSION_HANDOFF_BLOCKED",
            };
            let mut result = ApiError::new(code, "Submission preparation did not return success. Inspect the same operation's retained state; no network dispatch or new transaction was performed. An interrupted or late-denied retention may already exist.");
            result.operation_id = Some(submission_operation_id.into());
            result.safe_actions = vec!["Inspect the exact existing submission operation".into(), "Preserve the original encrypted transaction and submission journals".into()];
            result
        })
    }
    /// Authenticate original deliveries and reverify existing private bytes only.
    /// This never extracts, signs, writes submission intent, or sends a packet.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_candidate_submission(
        &self,
        access: &Access,
        signature_idempotency_key: &str,
        candidate_id: &str,
        submission_operation_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transactions: wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<VerifiedCandidateSubmission> {
        if deliveries
            .iter()
            .any(|delivery| delivery.association.is_none())
        {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            true,
        )?;
        let effects_digest =
            wholepact_protocol::review::verify_review(checkpoint.pczt_bytes(), checkpoint.policy())
                .map_err(|_| {
                    ApiError::new(
                        "SUBMISSION_PREDECESSOR_UNAVAILABLE",
                        "Original effects could not be independently verified",
                    )
                })?
                .shielded_sighash()
                .to_owned();
        let retained = retention.journal.verify_retained_submission(
            context, signature_idempotency_key, checkpoint.pczt_bytes(), checkpoint.policy(),
            &signatures, wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &Gate { original: checkpoint.scope(), read: read_consent, retain: retention.consent },
            &candidate.proposal.manifest.agreement.obligation_id,
            &candidate.proposal.proposal_id, submission_operation_id, &transactions,
        ).map_err(|_| ApiError::new("SUBMISSION_PREDECESSOR_UNAVAILABLE", "The exact original signed proof or completed transaction could not be reverified. Preserve the original journals; do not reconstruct or replace it."))?;
        Ok(VerifiedCandidateSubmission {
            retained,
            effects_digest,
            signature_retention_key: signature_idempotency_key.to_owned(),
            agreement_id: candidate.proposal.manifest.agreement.agreement_id.clone(),
        })
    }

    /// Explicit dispatch/retry of an already retained exact submission. All
    /// predecessor verification and current account association requirements run
    /// again; no transaction bytes or alternate input selection cross this API.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_candidate_submission<
        A: SubmissionAuthority,
        B: wholepact_chain::SubmissionBackend,
        C: SubmissionClock,
    >(
        &self,
        access: &Access,
        signature_idempotency_key: &str,
        candidate_id: &str,
        submission_operation_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        handoff: LocalSubmissionDispatch<'_, A, B, C>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<wholepact_chain::SubmissionDispatchReport> {
        if deliveries
            .iter()
            .any(|delivery| delivery.association.is_none())
        {
            return Err(association_missing());
        }
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            true,
        )?;
        retention.journal.dispatch_retained_transaction(
            context,
            signature_idempotency_key,
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &Gate { original: checkpoint.scope(), read: read_consent, retain: retention.consent },
            &candidate.proposal.manifest.agreement.obligation_id,
            &candidate.proposal.proposal_id,
            submission_operation_id,
            handoff,
        ).await.map_err(|error| {
            let code = match error {
                SubmissionHandoffError::Retention(RetentionError::ConsentDenied) => "SUBMISSION_HANDOFF_CONSENT_DENIED",
                SubmissionHandoffError::Retention(RetentionError::RecoveryRequired) => "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                SubmissionHandoffError::Retention(RetentionError::IntentNotFound) => "TRANSACTION_CHECKPOINT_INTENT_NOT_FOUND",
                SubmissionHandoffError::Retention(RetentionError::IdempotencyConflict) => "SUBMISSION_HANDOFF_CONFLICT",
                SubmissionHandoffError::Retention(_) => "SUBMISSION_HANDOFF_REJECTED",
                SubmissionHandoffError::Submission(wholepact_chain::ChainError::SubmissionRetentionUncertain) => "SUBMISSION_RETENTION_UNCERTAIN",
                SubmissionHandoffError::Submission(wholepact_chain::ChainError::SubmissionNotAuthorized) => "SUBMISSION_NOT_AUTHORIZED",
                SubmissionHandoffError::Submission(_) => "SUBMISSION_HANDOFF_BLOCKED",
            };
            let mut result = ApiError::new(code, "Submission did not return a durable success report. Delivery may have occurred. Inspect the exact original operation and preserve all exposure; never construct a replacement or select new inputs.");
            result.operation_id = Some(submission_operation_id.into());
            result.safe_actions = vec!["Inspect the exact existing submission operation".into(), "Preserve the original encrypted transaction and submission journals".into()];
            result
        })
    }
}
