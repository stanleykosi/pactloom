//! Actual retained construction encoding V5 to its exact completed private proof.
//! This purpose-specific read does not populate ordinary candidate receipts,
//! renew a construction, run a prover, grant disclosure, or issue authority.
use crate::manual_enrollment::ManualEnrollmentTarget;
use crate::{Access, ApiError, Engine, Result};
use sha2::{Digest, Sha256};
use wholepact_core::{
    Proposal, common_context_historical_provenance_v1::CommonContextHistoricalProvenanceV1,
};
use wholepact_proof_jobs::{
    CheckpointScope, JobState, JobSummary, LocalAction, LocalProofConsent, ProofJobStore,
    VerifiedCheckpoint,
};
use wholepact_store::manual_enrollment::{
    ManualRosterConstructionCheckpointV3, ManualRosterConstructionClaimV3,
};

/// Actual Engine/Store borrow plus immutable original evidence. No constructor
/// accepts a claim, receipt, successful-status flag, or deserialized owner.
pub struct PreparedBornOfflineCheckpointOriginalV1<'engine> {
    engine: &'engine Engine,
    target: ManualEnrollmentTarget<'engine>,
    claim: ManualRosterConstructionClaimV3,
    receipt: ManualRosterConstructionCheckpointV3,
    proposal: Proposal,
    scope: CheckpointScope,
}

/// The retained Engine original AND maintained proof verification. Native Host
/// ownership/privacy/disclosure remain independent requirements. There is no
/// Clone, Deserialize, public constructor, or conversion into spending authority.
pub struct BornOfflineCheckpointOriginalV1<'engine> {
    original: PreparedBornOfflineCheckpointOriginalV1<'engine>,
    checkpoint: VerifiedCheckpoint,
}

impl Engine {
    /// The embedding must obtain genuine native private-history read consent
    /// before this call and retain its actual Host/journal owners throughout.
    /// Returned evidence alone cannot grant private proof access or export.
    pub fn prepare_born_offline_checkpoint_original_v1<'engine>(
        &'engine self,
        access: &Access,
        agreement_id: &str,
        construction_key: &str,
    ) -> Result<PreparedBornOfflineCheckpointOriginalV1<'engine>> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted
            || !(16..=128).contains(&construction_key.len())
            || !construction_key.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(unavailable());
        }
        // Authenticate selected agreement access before reading the complete
        // bounded construction/audit set. No raw supplied claim is accepted.
        let selected = self.manual_enrollment_intent_target(access, agreement_id)?;
        selected.check_current(access)?;
        let (claim, receipt) = self
            .store
            .manual_roster_construction_evidence_v3(&access.principal_id, construction_key)
            .map_err(crate::store_error)?
            .ok_or_else(unavailable)?;
        // Legacy construction remains inspectable through its historical API,
        // but it cannot enter this purpose-specific born export/proof owner.
        // Never fill a missing original scanner observation with wall time.
        require_historical_provenance(&claim)?;
        let receipt = receipt.ok_or_else(unavailable)?;
        let proposal = claim.validate().map_err(crate::store_error)?;
        receipt.validate_for(&claim).map_err(crate::store_error)?;
        if claim.principal_id != access.principal_id
            || claim.construction_key != construction_key
            || proposal.manifest().agreement.agreement_id != agreement_id
            || &proposal.manifest().agreement != selected.agreement()
        {
            return Err(unavailable());
        }
        let first = claim.consumed.first().ok_or_else(unavailable)?;
        let target = self.manual_enrollment_target(access, first.request.plan.enrollment())?;
        target.require_current_agreement(access, &proposal.manifest().agreement)?;
        // Every original account is tied to this SAME actual current Store and
        // agreement, not an unrelated valid generation or supplied proposal.
        for consumed in &claim.consumed {
            let own = self.manual_enrollment_target(access, consumed.request.plan.enrollment())?;
            own.require_current_agreement(access, &proposal.manifest().agreement)?;
            if own.agreement_record_digest() != target.agreement_record_digest()
                || own.store_destination_identity() != target.store_destination_identity()
            {
                return Err(unavailable());
            }
            own.check_current(access)?;
        }
        let scope = saved_scope(&receipt);
        let prepared = PreparedBornOfflineCheckpointOriginalV1 {
            engine: self,
            target,
            claim,
            receipt,
            proposal,
            scope,
        };
        selected.check_current(access)?;
        prepared.check_current(access)?;
        Ok(prepared)
    }
}

impl PreparedBornOfflineCheckpointOriginalV1<'_> {
    /// Borrowed historical evidence, never a constructor or approval token.
    pub fn claim(&self) -> &ManualRosterConstructionClaimV3 {
        &self.claim
    }
    pub fn receipt(&self) -> &ManualRosterConstructionCheckpointV3 {
        &self.receipt
    }
    /// Exact immutable original/current scanner history from this saved claim.
    /// It is not a fresh observation, native grant or permission to disclose.
    pub fn historical_provenance(&self) -> Result<&CommonContextHistoricalProvenanceV1> {
        require_historical_provenance(&self.claim)
    }
    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    pub fn scope(&self) -> &CheckpointScope {
        &self.scope
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        self.historical_provenance()?;
        self.target.check_current(access)?;
        self.target
            .require_current_agreement(access, &self.proposal.manifest().agreement)?;
        let (claim, receipt) = self
            .engine
            .store
            .manual_roster_construction_evidence_v3(
                &access.principal_id,
                &self.claim.construction_key,
            )
            .map_err(crate::store_error)?
            .ok_or_else(unavailable)?;
        if claim != self.claim || receipt.as_ref() != Some(&self.receipt) {
            return Err(unavailable());
        }
        self.receipt
            .validate_for(&self.claim)
            .map_err(crate::store_error)?;
        self.target.check_current(access)
    }
}

impl<'engine> PreparedBornOfflineCheckpointOriginalV1<'engine> {
    /// Loads only the original completed proof. No run/recover/enqueue call is
    /// reachable here. The Host supplies a nonprompting exact saved-scope gate
    /// while holding its genuine native approval and original journal identity.
    pub fn load_verified(
        self,
        access: &Access,
        jobs: &ProofJobStore,
        consent: &dyn LocalProofConsent,
    ) -> Result<BornOfflineCheckpointOriginalV1<'engine>> {
        self.check_current(access)?;
        let gate = ExactReadGate {
            original: &self,
            access,
            consent,
        };
        let before = jobs
            .status_for_key(
                &access.principal_id,
                &self.claim.construction_key,
                &self.claim.request_digest().map_err(crate::store_error)?,
                &gate,
            )
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        require_summary(&self.receipt, &before)?;
        let checkpoint = jobs
            .load_verified(&access.principal_id, &self.receipt.job_id, &gate)
            .map_err(|_| unavailable())?;
        require_summary(&self.receipt, checkpoint.summary())?;
        if checkpoint.scope() != &self.scope
            || checkpoint.summary() != &before
            || checkpoint.policy().participants.len() != self.claim.consumed.len()
            || checkpoint.policy().inputs.len()
                != self
                    .claim
                    .consumed
                    .iter()
                    .map(|c| c.request.plan.selected_inputs().len())
                    .sum::<usize>()
            || checkpoint.summary().result_digest.as_deref()
                != Some(hex::encode(Sha256::digest(checkpoint.pczt_bytes())).as_str())
        {
            return Err(unavailable());
        }
        // The exact constructor receipt binds the original policy and artifact;
        // additionally authenticate every retained account's real FVK and own
        // nullifier/value set, never merely its label in a copied manifest.
        for consumed in &self.claim.consumed {
            let terms = consumed.request.plan.enrollment();
            let owners: Vec<_> = checkpoint
                .policy()
                .participants
                .iter()
                .enumerate()
                .filter(|(_, p)| p.account_id == terms.identity.account_id)
                .collect();
            if owners.len() != 1 {
                return Err(unavailable());
            }
            let (index, owner) = owners[0];
            if hex::encode(Sha256::digest(owner.fvk.to_bytes()))
                != terms.identity.full_viewing_key_digest
            {
                return Err(unavailable());
            }
            let expected: std::collections::BTreeSet<_> = consumed
                .request
                .plan
                .selected_inputs()
                .iter()
                .map(|i| (i.nullifier.clone(), i.value_zatoshis))
                .collect();
            let actual_inputs: Vec<_> = checkpoint
                .policy()
                .inputs
                .iter()
                .filter(|i| i.participant_index == index)
                .collect();
            let actual: std::collections::BTreeSet<_> = actual_inputs
                .iter()
                .map(|i| (hex::encode(i.nullifier), i.value_zatoshis))
                .collect();
            if expected != actual
                || expected.len() != consumed.request.plan.selected_inputs().len()
                || actual.len() != actual_inputs.len()
            {
                return Err(unavailable());
            }
        }
        if !gate.permits(&self.scope, LocalAction::ReadPrivateArtifact) {
            return Err(unavailable());
        }
        self.check_current(access)?;
        Ok(BornOfflineCheckpointOriginalV1 {
            original: self,
            checkpoint,
        })
    }
}

impl BornOfflineCheckpointOriginalV1<'_> {
    pub fn claim(&self) -> &ManualRosterConstructionClaimV3 {
        self.original.claim()
    }
    pub fn receipt(&self) -> &ManualRosterConstructionCheckpointV3 {
        self.original.receipt()
    }
    pub fn proposal(&self) -> &Proposal {
        self.original.proposal()
    }
    /// Borrowed historical evidence; current wallet/native owners remain separate.
    pub fn historical_provenance(&self) -> Result<&CommonContextHistoricalProvenanceV1> {
        self.original.historical_provenance()
    }
    /// Sensitive local borrow only. This is not permission to disclose bytes.
    pub fn checkpoint(&self) -> &VerifiedCheckpoint {
        &self.checkpoint
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        self.original.check_current(access)
    }
}

struct ExactReadGate<'a, 'engine> {
    original: &'a PreparedBornOfflineCheckpointOriginalV1<'engine>,
    access: &'a Access,
    consent: &'a dyn LocalProofConsent,
}
impl LocalProofConsent for ExactReadGate<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        scope == self.original.scope()
            && matches!(
                action,
                LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
            )
            && self.original.check_current(self.access).is_ok()
            && self.consent.permits(scope, action)
            && self.original.check_current(self.access).is_ok()
    }
}
fn saved_scope(receipt: &ManualRosterConstructionCheckpointV3) -> CheckpointScope {
    let s = &receipt.scope;
    CheckpointScope {
        principal_id: s.principal_id.clone(),
        candidate_id: s.candidate_id.clone(),
        manifest_digest: s.manifest_digest.clone(),
        artifact_digest: s.artifact_digest.clone(),
        effects_commitment: s.effects_commitment.clone(),
        coordination_request_digest: s.coordination_request_digest.clone(),
        review_binding: s.review_binding.clone(),
        account_ids: s.account_ids.clone(),
        local_operator: s.local_operator.clone(),
        purpose: s.purpose.clone(),
        retention_policy: s.retention_policy.clone(),
    }
}
fn require_summary(receipt: &ManualRosterConstructionCheckpointV3, s: &JobSummary) -> Result<()> {
    let r = &receipt.scope;
    if s.job_id != receipt.job_id
        || s.scope_digest != receipt.scope_digest().map_err(crate::store_error)?
        || s.candidate_id != r.candidate_id
        || s.input_digest != r.artifact_digest
        || s.manifest_digest != r.manifest_digest
        || s.effects_commitment != r.effects_commitment
        || s.coordination_request_digest != r.coordination_request_digest
        || s.review_binding != r.review_binding
        || s.state != JobState::Succeeded
        || !s.encrypted_checkpoint_created
        || !s.proof_verified
        || s.result_digest.is_none()
        || s.authorization_allowed
        || s.distribution_allowed
        || s.chain_validated
    {
        return Err(unavailable());
    }
    Ok(())
}
fn unavailable() -> ApiError {
    ApiError::new(
        "BORN_OFFLINE_CHECKPOINT_ORIGINAL_UNAVAILABLE",
        "The exact current-generation retained construction and completed private proof could not be authenticated; preserve original journals and never reconstruct or renew the invocation",
    )
}

/// Restriction on actual saved data, not a constructor for an original owner.
fn require_historical_provenance(
    claim: &ManualRosterConstructionClaimV3,
) -> Result<&CommonContextHistoricalProvenanceV1> {
    claim.require_historical_provenance_v5().map_err(|_| {
        ApiError::new(
            "BORN_ORIGINAL_PROVENANCE_UNAVAILABLE",
            "Exact version-5 original scanner provenance is unavailable. Legacy history remains inspectable, but cannot be upgraded, reconstructed or exported as a born checkpoint original",
        )
    })
}

#[cfg(test)]
mod historical_provenance_tests {
    use super::*;

    #[test]
    fn born_saved_original_requires_actual_v5_provenance_not_legacy_or_missing_defaults() {
        // Malformed inert records only: this test cannot create an Engine,
        // wallet observation, native owner, proof permission or saved original.
        for version in [0, 3, 4, 5, 6] {
            let claim = ManualRosterConstructionClaimV3 {
                version,
                principal_id: "synthetic-principal".into(),
                construction_key: "synthetic-original-construction".into(),
                maximum_actions: 3,
                consumed: Vec::new(),
                reentry_lineages: None,
                historical_provenance: None,
            };
            let error = require_historical_provenance(&claim).err().unwrap();
            assert_eq!(error.code, "BORN_ORIGINAL_PROVENANCE_UNAVAILABLE");
            assert!(!error.retryable);
        }
    }
}
