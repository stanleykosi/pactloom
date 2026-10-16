//! Dedicated non-signing exact invocation claim. No ordinary recovered gate is
//! relaxed; no current owner can be recreated from retained audit evidence.
use super::*;
use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3;
pub use wholepact_store::manual_enrollment::{
    ManualRosterConstructionClaimOutcomeV3, ManualRosterConstructionClaimTokenV3,
};

impl Engine {
    pub fn claim_manual_roster_construction_v3<'engine>(
        &'engine self,
        access: &Access,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
    ) -> Result<ManualRosterConstructionClaimOutcomeV3<'engine>> {
        let first = admitted.first().ok_or_else(manual_denied)?;
        let request = first.request().map_err(|_| manual_denied())?;
        let plan = &request.plan;
        let target = self.manual_enrollment_target(access, plan.enrollment())?;
        let envelope = decode(&target.agreement_record)?;
        if plan.proposal.manifest.agreement != envelope.view.agreement
            || plan
                .retained
                .selection
                .scope
                .selection
                .economic_intent
                .candidate_revision
                != target.agreement_revision
            || envelope.view.candidates.iter().any(|candidate| {
                candidate.candidate_id
                    == plan
                        .retained
                        .selection
                        .scope
                        .selection
                        .economic_intent
                        .candidate_id
            })
        {
            return Err(manual_denied());
        }
        for owner in admitted {
            owner.check_completion().map_err(|_| manual_denied())?;
            let request = owner.request().map_err(|_| manual_denied())?;
            let own = self.manual_enrollment_target(access, request.plan.enrollment())?;
            if own.agreement_record != target.agreement_record
                || request.plan.proposal != plan.proposal
            {
                return Err(manual_denied());
            }
            own.check_current(access)?;
        }
        target.check_current(access)?;
        let outcome = self
            .store
            .claim_manual_roster_construction_v3(
                &target.store,
                &target.agreement_record,
                &access.principal_id,
                key,
                maximum_actions,
                admitted,
            )
            .map_err(store_error)?;
        target.check_current(access)?;
        Ok(outcome)
    }
    #[cfg(all(
        feature = "signer-authority-bridge",
        feature = "wallet-sync",
        feature = "local-proof-jobs"
    ))]
    pub fn claim_manual_roster_construction_v3_fail_fast<'engine>(
        &'engine self,
        access: &Access,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
        progress: &crate::manual_roster_construct_v3::ManualRosterConstructionProgressV3,
    ) -> Result<ManualRosterConstructionClaimOutcomeV3<'engine>> {
        let first = admitted.first().ok_or_else(manual_denied)?;
        let request = first.request().map_err(|_| manual_denied())?;
        let plan = &request.plan;
        let target = self.manual_enrollment_target_fail_fast(access, plan.enrollment())?;
        let envelope = decode(&target.agreement_record)?;
        if plan.proposal.manifest.agreement != envelope.view.agreement
            || plan
                .retained
                .selection
                .scope
                .selection
                .economic_intent
                .candidate_revision
                != target.agreement_revision
            || envelope.view.candidates.iter().any(|candidate| {
                candidate.candidate_id
                    == plan
                        .retained
                        .selection
                        .scope
                        .selection
                        .economic_intent
                        .candidate_id
            })
        {
            return Err(manual_denied());
        }
        for owner in admitted {
            owner.check_completion().map_err(|_| manual_denied())?;
            let request = owner.request().map_err(|_| manual_denied())?;
            let own = self.manual_enrollment_target_fail_fast(access, request.plan.enrollment())?;
            if own.agreement_record != target.agreement_record
                || request.plan.proposal != plan.proposal
            {
                return Err(manual_denied());
            }
            own.check_current_fail_fast(access)?;
        }
        target.check_current_fail_fast(access)?;
        let outcome = progress
            .with_claim_attempt(|| {
                self.store.claim_manual_roster_construction_v3_fail_fast(
                    &target.store,
                    &target.agreement_record,
                    &access.principal_id,
                    key,
                    maximum_actions,
                    admitted,
                )
            })
            .map_err(store_error)?;
        target.check_current_fail_fast(access)?;
        Ok(outcome)
    }
}

#[cfg(feature = "local-proof-jobs")]
#[derive(Debug, Serialize)]
pub struct ManualRosterConstructionCheckpointViewV3 {
    pub claim_digest: String,
    pub candidate_id: String,
    pub checkpoint_evidence: &'static str,
    pub checkpoint: Option<wholepact_proof_jobs::JobSummary>,
    pub retry_construction_allowed: bool,
}
#[cfg(feature = "local-proof-jobs")]
impl Engine {
    /// Exact original outcome inspection only. Missing state, permission denial,
    /// corrupted data and restored history never grant randomized re-entry.
    pub fn inspect_manual_roster_construction_checkpoint_v3(
        &self,
        access: &Access,
        agreement: &str,
        key: &str,
        jobs: &wholepact_proof_jobs::ProofJobStore,
        consent: &dyn wholepact_proof_jobs::LocalProofConsent,
    ) -> Result<ManualRosterConstructionCheckpointViewV3> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted {
            return Err(ApiError::new(
                "STORAGE_PROTECTION_REQUIRED",
                "The local proof bridge requires verified encrypted coordination and artifact journals",
            ));
        }
        let envelope = self.load(access, agreement)?;
        let (claim, receipt) = self
            .store
            .manual_roster_construction_evidence_v3(&access.principal_id, key)
            .map_err(store_error)?
            .ok_or_else(|| {
                ApiError::new(
                    "NOT_FOUND",
                    "No original construction claim was retained; absence cannot authorize a retry",
                )
            })?;
        let proposal = claim.validate().map_err(store_error)?;
        if proposal.manifest().agreement.agreement_id != agreement
            || proposal.manifest().agreement.obligation_id != envelope.view.agreement.obligation_id
        {
            return Err(manual_denied());
        }
        let saved = jobs
            .status_for_key(
                &access.principal_id,
                key,
                &claim.request_digest().map_err(store_error)?,
                consent,
            )
            .map_err(|_| {
                ApiError::new(
                    "RECOVERY_REQUIRED",
                    "Original checkpoint inspection failed; preserve both journals",
                )
            })?;
        if let Some(receipt) = &receipt {
            receipt.validate_for(&claim).map_err(store_error)?;
        }
        reconcile_checkpoint_observation_v3(
            claim.digest().map_err(store_error)?,
            claim.candidate_id().into(),
            receipt.as_ref(),
            saved,
        )
    }
}

/// Pure observation reduction. No result of this function carries a builder
/// claim, native owner or retry permission. Production callers validate the
/// receipt against the complete immutable claim before entering this helper.
#[cfg(feature = "local-proof-jobs")]
pub(super) fn reconcile_checkpoint_observation_v3(
    claim_digest: String,
    candidate_id: String,
    receipt: Option<&wholepact_store::manual_enrollment::ManualRosterConstructionCheckpointV3>,
    saved: Option<wholepact_proof_jobs::JobSummary>,
) -> Result<ManualRosterConstructionCheckpointViewV3> {
    let evidence = match (receipt, &saved) {
        (None, None) => "construction_started_outcome_unknown",
        (Some(_), None) => "constructor_receipt_private_checkpoint_unconfirmed",
        (None, Some(_)) => {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Private checkpoint lacks its exact original constructor receipt",
            ));
        }
        (Some(receipt), Some(saved)) => {
            if saved.job_id != receipt.job_id
                || saved.scope_digest != receipt.scope_digest().map_err(store_error)?
                || saved.candidate_id != receipt.scope.candidate_id
                || saved.manifest_digest != receipt.scope.manifest_digest
                || saved.coordination_request_digest != receipt.scope.coordination_request_digest
                || saved.input_digest != receipt.scope.artifact_digest
                || saved.effects_commitment != receipt.scope.effects_commitment
                || saved.review_binding != receipt.scope.review_binding
                || !saved.encrypted_checkpoint_created
            {
                return Err(ApiError::new(
                    "RECOVERY_REQUIRED",
                    "Original constructor receipt and private checkpoint disagree",
                ));
            }
            "exact_original_private_checkpoint_observed"
        }
    };
    Ok(ManualRosterConstructionCheckpointViewV3 {
        claim_digest,
        candidate_id,
        checkpoint_evidence: evidence,
        checkpoint: saved,
        retry_construction_allowed: false,
    })
}

impl Engine {
    /// Absence preflight under current exact Host scope. This is not an issuer;
    /// witness and final Store claim independently enforce the same invocation.
    pub fn require_unused_common_context_invocation(
        &self,
        access: &Access,
        key: &str,
        plan: &wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3,
    ) -> Result<()> {
        plan.validate()?;
        let target = self.manual_enrollment_target(access, plan.enrollment())?;
        target.check_current_fail_fast(access)?;
        self.store
            .require_unused_common_context_invocation(
                &access.principal_id,
                key,
                &plan.retained.selection.scope.selection.invocation,
            )
            .map_err(store_error)?;
        target.check_current_fail_fast(access)
    }
}
