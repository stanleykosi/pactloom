//! Dedicated non-signing exact invocation claim. No ordinary recovered gate is
//! relaxed; no current owner can be recreated from retained audit evidence.
use super::*;
use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV2;
pub use wholepact_store::manual_enrollment::{
    ManualRosterConstructionClaimOutcomeV2, ManualRosterConstructionClaimTokenV2,
};

impl Engine {
    pub fn claim_manual_roster_construction_v2<'engine>(
        &'engine self,
        access: &Access,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV2],
    ) -> Result<ManualRosterConstructionClaimOutcomeV2<'engine>> {
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
            .claim_manual_roster_construction_v2(
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
    pub fn claim_manual_roster_construction_v2_fail_fast<'engine>(
        &'engine self,
        access: &Access,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV2],
        progress: &crate::manual_roster_construct_v2::ManualRosterConstructionProgressV2,
    ) -> Result<ManualRosterConstructionClaimOutcomeV2<'engine>> {
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
                self.store.claim_manual_roster_construction_v2_fail_fast(
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
pub struct ManualRosterConstructionCheckpointViewV2 {
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
    pub fn inspect_manual_roster_construction_checkpoint_v2(
        &self,
        access: &Access,
        agreement: &str,
        key: &str,
        jobs: &wholepact_proof_jobs::ProofJobStore,
        consent: &dyn wholepact_proof_jobs::LocalProofConsent,
    ) -> Result<ManualRosterConstructionCheckpointViewV2> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted {
            return Err(ApiError::new(
                "STORAGE_PROTECTION_REQUIRED",
                "The local proof bridge requires verified encrypted coordination and artifact journals",
            ));
        }
        let envelope = self.load(access, agreement)?;
        let (claim, receipt) = self
            .store
            .manual_roster_construction_evidence_v2(&access.principal_id, key)
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
        reconcile_checkpoint_observation_v2(
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
pub(super) fn reconcile_checkpoint_observation_v2(
    claim_digest: String,
    candidate_id: String,
    receipt: Option<&wholepact_store::manual_enrollment::ManualRosterConstructionCheckpointV2>,
    saved: Option<wholepact_proof_jobs::JobSummary>,
) -> Result<ManualRosterConstructionCheckpointViewV2> {
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
    Ok(ManualRosterConstructionCheckpointViewV2 {
        claim_digest,
        candidate_id,
        checkpoint_evidence: evidence,
        checkpoint: saved,
        retry_construction_allowed: false,
    })
}

#[cfg(all(test, feature = "local-proof-jobs"))]
mod construction_reconciliation_tests {
    use super::*;
    use wholepact_proof_jobs::{CheckpointScope, JobState, JobSummary, job_id_for_key};
    use wholepact_store::manual_enrollment::{
        ManualRosterCheckpointScopeV2, ManualRosterConstructionCheckpointV2,
    };

    fn fixture() -> (ManualRosterConstructionCheckpointV2, JobSummary) {
        // Public synthetic status only. No private bytes, native admission,
        // current owner, builder invocation, worker or proof is fabricated.
        let hash = |c: char| c.to_string().repeat(64);
        let scope = CheckpointScope {
            principal_id: "synthetic-principal".into(),
            candidate_id: "synthetic-candidate".into(),
            manifest_digest: hash('a'),
            artifact_digest: hash('b'),
            effects_commitment: hash('c'),
            coordination_request_digest: hash('d'),
            review_binding: hash('e'),
            account_ids: vec![hash('1'), hash('2')],
            local_operator: "synthetic-local-host".into(),
            purpose: "construct_one_candidate".into(),
            retention_policy: "Retain exact original checkpoint locally".into(),
        };
        let mirror: ManualRosterCheckpointScopeV2 =
            serde_json::from_value(serde_json::to_value(&scope).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_vec(&scope).unwrap(),
            serde_json::to_vec(&mirror).unwrap()
        );
        let receipt = ManualRosterConstructionCheckpointV2 {
            version: 2,
            claim_digest: hash('f'),
            job_id: job_id_for_key(&scope.principal_id, "synthetic-construction-key").unwrap(),
            scope: mirror,
        };
        assert_eq!(
            receipt.job_id,
            "proof-85f28d37bfc9f4c3c309380c4c3571599ad57dc13b2f95c1f0a91cadee020fd1"
        );
        let actual_scope_digest = hex::encode(Sha256::digest(serde_json::to_vec(&scope).unwrap()));
        assert_eq!(receipt.scope_digest().unwrap(), actual_scope_digest);
        let summary = JobSummary {
            job_id: receipt.job_id.clone(),
            scope_digest: actual_scope_digest,
            candidate_id: scope.candidate_id,
            state: JobState::Queued,
            attempt: 0,
            input_digest: scope.artifact_digest,
            manifest_digest: scope.manifest_digest,
            effects_commitment: scope.effects_commitment,
            coordination_request_digest: scope.coordination_request_digest,
            result_digest: None,
            review_binding: scope.review_binding,
            encrypted_checkpoint_created: true,
            proof_verified: false,
            chain_validated: false,
            authorization_allowed: false,
            distribution_allowed: false,
        };
        (receipt, summary)
    }
    fn observe(
        receipt: Option<&ManualRosterConstructionCheckpointV2>,
        saved: Option<JobSummary>,
    ) -> Result<ManualRosterConstructionCheckpointViewV2> {
        reconcile_checkpoint_observation_v2(
            "f".repeat(64),
            "synthetic-candidate".into(),
            receipt,
            saved,
        )
    }
    #[test]
    fn absent_and_exact_checkpoint_outcomes_never_allow_randomized_reentry() {
        let (receipt, saved) = fixture();
        for (r, s, expected) in [
            (None, None, "construction_started_outcome_unknown"),
            (
                Some(&receipt),
                None,
                "constructor_receipt_private_checkpoint_unconfirmed",
            ),
            (
                Some(&receipt),
                Some(saved.clone()),
                "exact_original_private_checkpoint_observed",
            ),
        ] {
            let view = observe(r, s).unwrap();
            assert_eq!(view.checkpoint_evidence, expected);
            assert!(!view.retry_construction_allowed);
        }
        assert!(observe(None, Some(saved)).is_err());
    }
    #[test]
    fn every_checkpoint_identity_mismatch_and_changed_invocation_key_fails_closed() {
        let (receipt, saved) = fixture();
        for field in 0..10 {
            let mut changed = saved.clone();
            match field {
                0 => {
                    changed.job_id =
                        job_id_for_key("synthetic-principal", "synthetic-different-key").unwrap()
                }
                1 => {
                    changed.job_id =
                        job_id_for_key("other-principal", "synthetic-construction-key").unwrap()
                }
                2 => changed.scope_digest = "0".repeat(64),
                3 => changed.candidate_id.push('x'),
                4 => changed.manifest_digest = "0".repeat(64),
                5 => changed.coordination_request_digest = "0".repeat(64),
                6 => changed.input_digest = "0".repeat(64),
                7 => changed.effects_commitment = "0".repeat(64),
                8 => changed.review_binding = "0".repeat(64),
                _ => changed.encrypted_checkpoint_created = false,
            }
            assert!(observe(Some(&receipt), Some(changed)).is_err());
        }
    }
}
