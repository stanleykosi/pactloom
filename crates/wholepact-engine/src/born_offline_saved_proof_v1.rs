//! First proof of an actual retained manual V5 constructor checkpoint.
//! Separate from ordinary Envelope candidate receipts and construction consent.
use crate::born_offline_checkpoint_original_v1::{
    BornOfflineCheckpointOriginalV1, PreparedBornOfflineCheckpointOriginalV1,
};
use crate::{Access, ApiError, Result};
use wholepact_proof_jobs::{
    CheckpointScope, JobState, JobSummary, LocalAction, LocalProofConsent, ProofJobStore,
};

impl<'engine> PreparedBornOfflineCheckpointOriginalV1<'engine> {
    /// Consumes the actual Engine/Store original. Only queued attempt zero may
    /// enter CPU work; the proof journal atomically repeats that restriction.
    /// A prior Running/Uncertain/Failed/Succeeded row is never reset or retried.
    /// The embedding keeps genuine exact native privacy/CPU consent and actual
    /// Host/financial source ownership for this entire bounded call.
    pub fn prove_original_queued_v1(
        self,
        access: &Access,
        jobs: &ProofJobStore,
        consent: &dyn LocalProofConsent,
    ) -> Result<BornOfflineCheckpointOriginalV1<'engine>> {
        self.check_current(access)?;
        self.historical_provenance()?;
        {
            let gate = ExactProofGate {
                original: &self,
                access,
                consent,
            };
            let before = jobs
                .status_for_key(
                    &access.principal_id,
                    &self.claim().construction_key,
                    &self.claim().request_digest().map_err(crate::store_error)?,
                    &gate,
                )
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            require_original_summary(&self, &before)?;
            if before.state != JobState::Queued
                || before.attempt != 0
                || before.proof_verified
                || before.result_digest.is_some()
            {
                return Err(unavailable());
            }
            // Atomic start mode, not a generic run after this status snapshot.
            let after = jobs
                .run_original_queued(&access.principal_id, &self.receipt().job_id, &gate)
                .map_err(|_| unavailable())?;
            require_original_summary(&self, &after)?;
            if after.state != JobState::Succeeded
                || after.attempt != 1
                || !after.proof_verified
                || after.result_digest.is_none()
            {
                return Err(unavailable());
            }
            self.check_current(access)?;
        }
        // The maintained saved verifier independently checks the actual proof,
        // unsigned predecessor and exact policy before this opaque owner exists.
        self.load_verified(access, jobs, consent)
    }
}
struct ExactProofGate<'a, 'engine> {
    original: &'a PreparedBornOfflineCheckpointOriginalV1<'engine>,
    access: &'a Access,
    consent: &'a dyn LocalProofConsent,
}
impl LocalProofConsent for ExactProofGate<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope == self.original.scope()
            && matches!(
                action,
                LocalAction::InspectStatus
                    | LocalAction::ProveLocally
                    | LocalAction::RetainPrivateWitnesses
                    | LocalAction::ReadPrivateArtifact
            )
            && self.original.check_current(self.access).is_ok()
            && self.consent.permits(scope, action)
            && self.original.check_current(self.access).is_ok()
    }
}
fn require_original_summary(
    original: &PreparedBornOfflineCheckpointOriginalV1<'_>,
    summary: &JobSummary,
) -> Result<()> {
    let r = original.receipt();
    let s = original.scope();
    if summary.job_id != r.job_id
        || summary.scope_digest != r.scope_digest().map_err(crate::store_error)?
        || summary.candidate_id != s.candidate_id
        || summary.input_digest != s.artifact_digest
        || summary.manifest_digest != s.manifest_digest
        || summary.effects_commitment != s.effects_commitment
        || summary.coordination_request_digest != s.coordination_request_digest
        || summary.review_binding != s.review_binding
        || !summary.encrypted_checkpoint_created
        || summary.authorization_allowed
        || summary.distribution_allowed
        || summary.chain_validated
    {
        return Err(unavailable());
    }
    Ok(())
}
fn unavailable() -> ApiError {
    ApiError::new(
        "BORN_ORIGINAL_PROOF_UNAVAILABLE",
        "Only the exact first queued original checkpoint may be proved. Preserve every original claim, journal and uncertain or completed result; no retry, reconstruction, signature, release or dispatch is permitted",
    )
}
