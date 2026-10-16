//! Original construction metadata from one owned immutable coordination snapshot.
//! This owner never reads a live Store or carries a constructor/wallet permit.
use super::*;
use wholepact_core::manual_enrollment::ManualHostGenerationBinding;
use wholepact_proof_jobs::{CheckpointScope, LocalProofConsent, ProofStatusSnapshot};
use wholepact_store::manual_enrollment::{
    ManualRosterConstructionCheckpointV2, ManualRosterConstructionClaimV2,
};
use wholepact_store::recovery::RecoveredStoreSnapshot;

/// Safe exact review projection. Only the actual prepared owner below creates
/// it. Deserializing metadata never creates that owner or native read consent.
#[derive(Serialize)]
pub struct ManualRosterConstructionInspectionMetadataV2 {
    pub version: u16,
    pub purpose: &'static str,
    pub principal_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub construction_key_digest: String,
    pub claim_digest: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub original_agreement_revision: u64,
    pub current_agreement_revision: u64,
    pub current_agreement_record_digest: String,
    pub original_host: ManualHostGenerationBinding,
    pub checkpoint_destination: String,
    pub coordination_request_digest: String,
    pub constructor_receipt_digest: Option<String>,
    pub saved_checkpoint_scope: Option<CheckpointScope>,
}

/// Private immutable original evidence and actual current read target. No
/// Clone/Deserialize, raw claim escape, builder conversion or mutation method.
pub struct PreparedManualRosterConstructionInspectionV2 {
    snapshot: RecoveredStoreSnapshot,
    owner_client_id: String,
    agreement: wholepact_core::AgreementDraft,
    key: String,
    claim: ManualRosterConstructionClaimV2,
    receipt: Option<ManualRosterConstructionCheckpointV2>,
    metadata: ManualRosterConstructionInspectionMetadataV2,
}
impl Engine {
    /// Consumes an actual source-preserving current-generation Store snapshot,
    /// never a live Engine/Store read. Its opener validates the complete current
    /// coordination history, counters and fences; this then reads the bounded
    /// construction/audit set and selects the exact principal/key. Fresh native
    /// disclosure approval must precede snapshot capture, including absence.
    /// The embedding retains source exclusion locks throughout this owner's life.
    pub fn prepare_manual_roster_construction_inspection_v2(
        snapshot: RecoveredStoreSnapshot,
        access: &Access,
        agreement: &str,
        key: &str,
    ) -> Result<PreparedManualRosterConstructionInspectionV2> {
        require_inspection_key(key)?;
        snapshot.check_source_unchanged().map_err(store_error)?;
        let record = snapshot
            .current_agreement_record(agreement)
            .map_err(store_error)?;
        let envelope = decode(&record)?;
        if !access.permits_agreement(&record.id, &envelope.owner_client_id)
            || record.id != agreement
            || envelope.view.agreement.agreement_id != agreement
            || envelope.view.revision != record.revision
        {
            return Err(inspection_denied());
        }
        envelope.view.agreement.validate()?;
        let destination = snapshot
            .current_store_destination_identity()
            .map_err(store_error)?;
        let (claim, receipt) = snapshot
            .manual_roster_construction_evidence_v2(&access.principal_id, key)
            .map_err(store_error)?.ok_or_else(|| ApiError::new(
                "NOT_FOUND", "No exact original construction claim was retained; absence cannot authorize reconstruction",
            ))?;
        let proposal = claim.validate().map_err(store_error)?;
        let terms = claim
            .consumed
            .first()
            .ok_or_else(inspection_denied)?
            .request
            .plan
            .enrollment();
        require_original_inspection_identity(
            [
                &claim.principal_id,
                &proposal.manifest().agreement.agreement_id,
                &proposal.manifest().agreement.obligation_id,
                &terms.host.generation_id,
                &terms.host.inventory_digest,
                &terms.host.store_destination_identity,
            ],
            [
                &access.principal_id,
                agreement,
                &envelope.view.agreement.obligation_id,
                snapshot.generation().generation_id(),
                snapshot.generation().inventory_digest(),
                &destination,
            ],
        )?;
        if claim.construction_key != key {
            return Err(inspection_denied());
        }
        if let Some(receipt) = &receipt {
            receipt.validate_for(&claim).map_err(store_error)?;
        }
        let saved_checkpoint_scope = receipt.as_ref().map(|r| CheckpointScope {
            principal_id: r.scope.principal_id.clone(),
            candidate_id: r.scope.candidate_id.clone(),
            manifest_digest: r.scope.manifest_digest.clone(),
            artifact_digest: r.scope.artifact_digest.clone(),
            effects_commitment: r.scope.effects_commitment.clone(),
            coordination_request_digest: r.scope.coordination_request_digest.clone(),
            review_binding: r.scope.review_binding.clone(),
            account_ids: r.scope.account_ids.clone(),
            local_operator: r.scope.local_operator.clone(),
            purpose: r.scope.purpose.clone(),
            retention_policy: r.scope.retention_policy.clone(),
        });
        let metadata =
            ManualRosterConstructionInspectionMetadataV2 {
                version: 2,
                purpose: "inspect_original_construction_metadata_only",
                principal_id: access.principal_id.clone(),
                agreement_id: agreement.into(),
                obligation_id: envelope.view.agreement.obligation_id.clone(),
                construction_key_digest: claim.request_identity().map_err(store_error)?,
                claim_digest: claim.digest().map_err(store_error)?,
                candidate_id: claim.candidate_id().into(),
                manifest_digest: proposal.manifest_digest().into(),
                original_agreement_revision: claim.agreement_revision(),
                current_agreement_revision: record.revision,
                current_agreement_record_digest: wholepact_store::request_digest(
                    &serde_json::json!([&record.id, record.revision, &record.payload,]),
                )
                .map_err(store_error)?,
                original_host: terms.host.clone(),
                checkpoint_destination: claim.invocation().checkpoint_destination.clone(),
                coordination_request_digest: claim.request_digest().map_err(store_error)?,
                constructor_receipt_digest: receipt
                    .as_ref()
                    .map(|r| {
                        wholepact_store::request_digest(
                            &serde_json::to_value(r).map_err(|_| inspection_denied())?,
                        )
                        .map_err(store_error)
                    })
                    .transpose()?,
                saved_checkpoint_scope,
            };
        snapshot.check_source_unchanged().map_err(store_error)?;
        let prepared = PreparedManualRosterConstructionInspectionV2 {
            snapshot,
            owner_client_id: envelope.owner_client_id,
            agreement: envelope.view.agreement,
            key: key.into(),
            claim,
            receipt,
            metadata,
        };
        prepared.check_current(access)?;
        Ok(prepared)
    }
}
impl std::fmt::Debug for PreparedManualRosterConstructionInspectionV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedManualRosterConstructionInspectionV2")
            .finish_non_exhaustive()
    }
}
impl PreparedManualRosterConstructionInspectionV2 {
    pub fn metadata(&self) -> &ManualRosterConstructionInspectionMetadataV2 {
        &self.metadata
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        self.snapshot
            .check_source_unchanged()
            .map_err(store_error)?;
        if access.principal_id != self.metadata.principal_id
            || !access.permits_agreement(&self.agreement.agreement_id, &self.owner_client_id)
        {
            return Err(inspection_denied());
        }
        // The captured agreement, exact claim and optional receipt are immutable.
        // Any detected original-path/descriptor drift requires a new preparation,
        // including a newly committed receipt. This is a restriction under held
        // source quiescence, not hostile same-user content-tampering protection.
        self.snapshot.check_source_unchanged().map_err(store_error)
    }
    /// Metadata-only consumer. Actual primary destination and native consent are
    /// independently held by the Host. This cannot mutate a job or issue a token.
    pub fn inspect(
        &self,
        access: &Access,
        jobs: &ProofStatusSnapshot,
        consent: &dyn LocalProofConsent,
    ) -> Result<ManualRosterConstructionCheckpointViewV2> {
        self.check_current(access)?;
        jobs.check_source_unchanged()
            .map_err(|_| inspection_denied())?;
        let saved = jobs
            .status_for_key(
                &access.principal_id,
                &self.key,
                &self.claim.request_digest().map_err(store_error)?,
                consent,
            )
            .map_err(|_| inspection_denied())?;
        if let Some(receipt) = &self.receipt {
            receipt.validate_for(&self.claim).map_err(store_error)?;
        }
        let view = super::roster_construction_claim_v2::reconcile_checkpoint_observation_v2(
            self.claim.digest().map_err(store_error)?,
            self.claim.candidate_id().into(),
            self.receipt.as_ref(),
            saved,
        )?;
        jobs.check_source_unchanged()
            .map_err(|_| inspection_denied())?;
        self.check_current(access)?;
        if view.claim_digest != self.metadata.claim_digest
            || view.candidate_id != self.metadata.candidate_id
            || view.retry_construction_allowed
        {
            return Err(inspection_denied());
        }
        Ok(view)
    }
}
fn require_inspection_key(key: &str) -> Result<()> {
    if !(16..=128).contains(&key.len()) || !key.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(inspection_denied());
    }
    Ok(())
}
fn require_original_inspection_identity(expected: [&str; 6], actual: [&str; 6]) -> Result<()> {
    if expected != actual {
        return Err(inspection_denied());
    }
    Ok(())
}
fn inspection_denied() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Exact current-generation original construction inspection is unavailable; preserve journals and never rebuild",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_identity_rejects_every_scope_and_lineage_substitution() {
        let expected = [
            "principal",
            "agreement",
            "obligation",
            "generation",
            "inventory",
            "destination",
        ];
        let check = |a: [&str; 6]| require_original_inspection_identity(expected, a);
        assert!(check(expected).is_ok());
        for n in 0..6 {
            let mut changed = expected;
            changed[n] = "other";
            assert!(check(changed).is_err());
        }
    }
    #[test]
    fn inspection_keys_are_exact_and_never_normalized() {
        assert!(require_inspection_key("original-construction-key").is_ok());
        for key in [
            "",
            "short",
            " original-construction-key",
            "original-construction-key\n",
        ] {
            assert!(require_inspection_key(key).is_err());
        }
    }
}
