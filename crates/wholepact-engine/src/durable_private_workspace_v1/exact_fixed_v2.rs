//! Closed original-source fixed-proof operations. No generic Engine bypass.
use super::operation_v1::{EffectV2, PrivateWorkspaceEffectV2};
use super::original_job_error_v2 as job_error;
use super::*;
use crate::durable_construction_v1::{
    DurableMaterialActionV1, Intake, LocalDurableMaterialConsentV1, Roster,
};
use crate::proof_jobs::{upsert_link, validate_provenance, validate_summary};
use crate::{CandidateRequest, CandidateView, Envelope};
use diagnostics::{Call, CallState, Observation, Operation, Site};
use serde_json::json;
use sha2::{Digest, Sha256};
use wholepact_proof_jobs::{
    CheckpointScope, FreshOriginalEnqueueV1, JobSummary, LocalAction, LocalProofConsent,
    VerifiedCheckpoint,
};
use wholepact_protocol::construction::{DisclosureAcknowledgement, DisclosureScope};
use wholepact_protocol::proving::ProvingLimits;
use wholepact_signer::authority_bridge::durable_construction_v1::AuthenticatedDurableConstructionDisclosureV1;
use wholepact_wallet::wallet::AccountUuid;
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
    DurableConstructionScopeV1, DurableConstructionWalletSlotV1,
    FreshDurableConstructionObservationV1, HeldDurableConstructionRosterV1,
    with_durable_construction_roster_v1,
};
use wholepact_wallet::wallet::protected_sync::{
    BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
};

/// One synchronous Engine-owned permission invocation. No future, grant or
/// owner may be returned from the higher-ranked callback.
pub type PrivateFixedObservationCallbackV3<'call> = Box<
    dyn for<'g> FnOnce(
            &'g dyn LocalPrivateWorkspaceConsentV1,
            &'g dyn LocalDurableMaterialConsentV1,
            &'g dyn LocalWalletAccess,
        ) -> bool
        + 'call,
>;
pub type PrivateFixedArtifactCallbackV3<'call> = Box<
    dyn for<'g> FnOnce(
            &'g dyn LocalPrivateWorkspaceConsentV1,
            &'g dyn LocalDurableMaterialConsentV1,
            &'g dyn LocalProofConsent,
        ) -> bool
        + 'call,
>;
/// Trusted embedding boundary, never inferred from retained metadata. A
/// concrete provider must audit the original stage before and after the body.
/// Unsupported roles deny without running it; the Engine independently keeps
/// the actual kernel result, so an omitted or false body cannot be approved.
pub trait LocalPrivateFixedPermissionBoundaryV3 {
    fn with_observation<'call>(
        &self,
        _request: &PrivateFixedPermissionRequestV3<'_>,
        _run: PrivateFixedObservationCallbackV3<'call>,
    ) -> bool {
        false
    }
    fn with_artifact<'call>(
        &self,
        _request: &PrivateFixedPermissionRequestV3<'_>,
        _run: PrivateFixedArtifactCallbackV3<'call>,
    ) -> bool {
        false
    }
}
enum PrivateFixedPermissionKindV3<'a> {
    Observation {
        scope: &'a DurableConstructionScopeV1,
        digest: &'a str,
        account: AccountUuid,
        provider: &'a BackendIdentity,
        purpose: WalletAccessPurpose,
    },
    ArtifactCheck,
    ArtifactPermission {
        scope: &'a CheckpointScope,
        action: LocalAction,
    },
}
/// Exact closed comparison data only. Constructors and the kind are private;
/// this object neither contains authority nor permits arbitrary callbacks.
pub struct PrivateFixedPermissionRequestV3<'a> {
    workspace: &'a PrivateWorkspaceScopeV1,
    action: PrivateWorkspaceActionV1,
    materials: [(&'a DurableConstructionScopeV1, &'a str); 2],
    kind: PrivateFixedPermissionKindV3<'a>,
}
impl<'a> PrivateFixedPermissionRequestV3<'a> {
    fn new(
        workspace: &'a PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
        roster: &'a Roster,
        kind: PrivateFixedPermissionKindV3<'a>,
    ) -> Result<Self> {
        let mut values = roster.owners.values();
        let first = values.next().ok_or_else(denied)?;
        let second = values.next().ok_or_else(denied)?;
        if values.next().is_some()
            || first.outbox.request().scope.account_id == second.outbox.request().scope.account_id
        {
            return Err(denied());
        }
        Ok(Self {
            workspace,
            action,
            materials: [
                (
                    &first.outbox.request().scope,
                    first.outbox.material_digest(),
                ),
                (
                    &second.outbox.request().scope,
                    second.outbox.material_digest(),
                ),
            ],
            kind,
        })
    }
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        self.workspace
    }
    pub fn workspace_action(&self) -> PrivateWorkspaceActionV1 {
        self.action
    }
    pub fn materials(&self) -> &[(&'a DurableConstructionScopeV1, &'a str)] {
        &self.materials
    }
    pub fn material_action(&self) -> DurableMaterialActionV1 {
        DurableMaterialActionV1::ReadForExactConstruction
    }
    pub fn observation_input(
        &self,
    ) -> Option<(
        &DurableConstructionScopeV1,
        &str,
        AccountUuid,
        &BackendIdentity,
        WalletAccessPurpose,
    )> {
        match &self.kind {
            PrivateFixedPermissionKindV3::Observation {
                scope,
                digest,
                account,
                provider,
                purpose,
            } => Some((scope, digest, *account, provider, *purpose)),
            _ => None,
        }
    }
    pub fn proof_permission(&self) -> Option<(&CheckpointScope, LocalAction)> {
        match &self.kind {
            PrivateFixedPermissionKindV3::ArtifactPermission { scope, action } => {
                Some((scope, *action))
            }
            _ => None,
        }
    }
    pub fn is_observation(&self) -> bool {
        matches!(self.kind, PrivateFixedPermissionKindV3::Observation { .. })
    }
    pub fn is_artifact_check(&self) -> bool {
        matches!(self.kind, PrivateFixedPermissionKindV3::ArtifactCheck)
    }
    pub fn is_artifact_permission(&self) -> bool {
        matches!(
            self.kind,
            PrivateFixedPermissionKindV3::ArtifactPermission { .. }
        )
    }
}

// Preserve the actual owned Engine error, even when the provider also denies
// at exit. The Option is a single-call completion/result slot, not permission.
fn compound_kernel_result_v3<T>(provider: bool, actual: Option<Result<T>>) -> Result<T> {
    match actual {
        Some(Err(error)) => Err(error),
        Some(Ok(value)) if provider => Ok(value),
        _ => Err(denied()),
    }
}
fn compound_permission_result_v3(provider: bool, actual: Option<bool>) -> bool {
    provider && actual == Some(true)
}
// The held owner brackets the entire provider invocation, including its exit
// audit. An owned inner error remains first; a successful body is not enough.
fn compound_held_result_v3<T>(
    held: impl Fn(Site) -> Result<()>,
    body: impl FnOnce() -> Result<T>,
) -> Result<T> {
    held(Site::GateHeldPre)?;
    let result = body()?;
    held(Site::GateHeldPost)?;
    Ok(result)
}
fn compound_observation_permission_v3(
    boundary: &dyn LocalPrivateFixedPermissionBoundaryV3,
    request: &PrivateFixedPermissionRequestV3<'_>,
    kernel: impl for<'g> FnOnce(
        &'g dyn LocalPrivateWorkspaceConsentV1,
        &'g dyn LocalDurableMaterialConsentV1,
        &'g dyn LocalWalletAccess,
    ) -> bool,
) -> bool {
    let mut actual = None;
    let permitted = boundary.with_observation(
        request,
        Box::new(|consent, material, wallet| {
            let result = kernel(consent, material, wallet);
            actual = Some(result);
            result
        }),
    );
    compound_permission_result_v3(permitted, actual)
}
fn compound_artifact_check_v3(
    boundary: &dyn LocalPrivateFixedPermissionBoundaryV3,
    request: &PrivateFixedPermissionRequestV3<'_>,
    kernel: impl for<'g> FnOnce(
        &'g dyn LocalPrivateWorkspaceConsentV1,
        &'g dyn LocalDurableMaterialConsentV1,
        &'g dyn LocalProofConsent,
    ) -> Result<()>,
) -> Result<()> {
    let mut actual = None;
    let permitted = boundary.with_artifact(
        request,
        Box::new(|consent, material, proof| {
            let result = kernel(consent, material, proof);
            let allowed = result.is_ok();
            actual = Some(result);
            allowed
        }),
    );
    compound_kernel_result_v3(permitted, actual)
}
fn compound_artifact_permission_v3(
    boundary: &dyn LocalPrivateFixedPermissionBoundaryV3,
    request: &PrivateFixedPermissionRequestV3<'_>,
    kernel: impl for<'g> FnOnce(
        &'g dyn LocalPrivateWorkspaceConsentV1,
        &'g dyn LocalDurableMaterialConsentV1,
        &'g dyn LocalProofConsent,
    ) -> bool,
) -> bool {
    let mut actual = None;
    let permitted = boundary.with_artifact(
        request,
        Box::new(|consent, material, proof| {
            let result = kernel(consent, material, proof);
            actual = Some(result);
            result
        }),
    );
    compound_permission_result_v3(permitted, actual)
}

/// Closed review purpose. Values select a data projection, never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PrivateFixedStageV3 {
    Prepare,
    AdmitOriginal,
    ProveOriginal,
    FreezeFixed,
    ReadFixed,
}
/// Original metadata only. No private material bytes or construction authority.
#[derive(Serialize)]
pub struct PrivateFixedMaterialReviewV3 {
    scope: DurableConstructionScopeV1,
    material_digest: String,
}
impl PrivateFixedMaterialReviewV3 {
    pub fn scope(&self) -> &DurableConstructionScopeV1 {
        &self.scope
    }
    pub fn material_digest(&self) -> &str {
        &self.material_digest
    }
}
/// Source-authenticated, current-scope review data. A native issuer must still
/// obtain a genuine new stage decision and recheck every original restriction.
/// There is no public constructor, Deserialize, permission or artifact getter.
#[derive(Serialize)]
pub struct PrivateFixedStageReviewV3 {
    version: u16,
    purpose: &'static str,
    stage: PrivateFixedStageV3,
    workspace_scope: PrivateWorkspaceScopeV1,
    marker_digest: String,
    native_association_digest: String,
    metadata_origin: String,
    proof_origin: String,
    revision: u64,
    materials: Vec<PrivateFixedMaterialReviewV3>,
    checkpoint_scope: Option<CheckpointScope>,
}
impl PrivateFixedStageReviewV3 {
    pub fn stage(&self) -> PrivateFixedStageV3 {
        self.stage
    }
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        &self.workspace_scope
    }
    pub fn marker_digest(&self) -> &str {
        &self.marker_digest
    }
    pub fn native_association_digest(&self) -> &str {
        &self.native_association_digest
    }
    pub fn metadata_origin(&self) -> &str {
        &self.metadata_origin
    }
    pub fn proof_origin(&self) -> &str {
        &self.proof_origin
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn materials(&self) -> &[PrivateFixedMaterialReviewV3] {
        &self.materials
    }
    pub fn checkpoint_scope(&self) -> Option<&CheckpointScope> {
        self.checkpoint_scope.as_ref()
    }
}
const MAX_STAGE_REVIEW_BYTES_V3: usize = 64 * 1024;
#[derive(Clone, Copy)]
enum PrepareModeV3 {
    LegacyCheckpoint,
    StagePreparation,
}
impl PrepareModeV3 {
    fn action(self) -> PrivateWorkspaceActionV1 {
        match self {
            Self::LegacyCheckpoint => PrivateWorkspaceActionV1::CheckpointExactOriginal,
            Self::StagePreparation => PrivateWorkspaceActionV1::PrepareFixedStageV3,
        }
    }
}

/// Exact data-only candidate for the two native disclosure reviews. No Engine,
/// agreement view, existing material, operation or private proof escapes.
pub struct PrivateExactCandidateV2 {
    proposal: wholepact_core::ProposalInput,
    revision: u64,
    replayed: bool,
}
impl PrivateExactCandidateV2 {
    pub fn proposal(&self) -> &wholepact_core::ProposalInput {
        &self.proposal
    }
    pub fn candidate_id(&self) -> &str {
        &self.proposal.proposal_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}
#[derive(Serialize)]
pub struct PrivateFixedStatusV2 {
    pub revision: u64,
    pub state: String,
    pub attempt: u32,
    pub fixed_retained: bool,
    pub proof_verified: bool,
    pub authorization_allowed: bool,
}
/// Only verified commitments, never PCZT, FVK, raw journal rows or native grants.
#[derive(Serialize)]
pub struct PrivateVerifiedFixedV2 {
    pub revision: u64,
    pub source_digest: String,
    pub native_association_digest: String,
    pub marker_digest: String,
    pub metadata_origin: String,
    pub proof_origin: String,
    pub candidate_id: String,
    pub candidate_identity_digest: String,
    pub manifest_digest: String,
    pub original_checkpoint_key_digest: String,
    pub coordination_request_digest: String,
    pub checkpoint_receipt_digest: String,
    pub action_mapping_digest: String,
    pub job_id: String,
    pub job_identity_digest: String,
    pub scope_digest: String,
    pub input_digest: String,
    pub result_digest: String,
    pub fixed_identity_digest: String,
    pub operation_history_digest: String,
    pub proof_event_history_digest: String,
    pub logical_state_digest: String,
    pub state: String,
    pub attempt: u32,
    pub proof_verified: bool,
    pub authorization_allowed: bool,
}
/// Created only from the actual newly committed constructor transaction result.
/// Neither historical receipts nor a successful preflight can construct this.
struct FreshConstructorReceiptCommitV2<'op, 'source> {
    workspace: &'op PrivateDurableCoordinatorV1<'source>,
    receipt_key: String,
    receipt: crate::candidates::CheckpointReceipt,
    original_key: String,
    command: wholepact_store::CommandContext,
}
/// Live correlation owner. Deliberately no Clone/serde/getter/standalone run.
pub struct OriginalProofAttemptV2<'op, 'source> {
    constructor: FreshConstructorReceiptCommitV2<'op, 'source>,
    enqueue: FreshOriginalEnqueueV1<'source>,
    linked_revision: u64,
    // Inert exact original scope, not consent and never another continuation.
    review_scope: CheckpointScope,
}
/// Memory-only original randomized artifact. Its originating API determines
/// whether review has occurred; admission always requires current exact consent. This is
/// not a receipt, proof attempt or permission. No Clone/serde/raw-data getters.
/// It borrows only its original coordinator, never a wallet or observation.
pub struct PreparedOriginalCheckpointV2<'op, 'source> {
    workspace: &'op PrivateDurableCoordinatorV1<'source>,
    ready: ReadyOriginalCheckpointV2,
}
impl<'op, 'source> PreparedOriginalCheckpointV2<'op, 'source> {
    /// Consume before any fallible admission check. A failure cannot be retried
    /// with this owner and never authorizes randomized reconstruction.
    pub fn admit_original_v2(
        self,
        access: &Access,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        let PreparedOriginalCheckpointV2 { workspace, ready } = self;
        let observation = Observation::new(Operation::Checkpoint);
        let result = workspace.admit_ready_original_v2(
            access,
            ready,
            slots,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
}
pub struct OriginalCheckpointOutcomeV2<'op, 'source> {
    status: PrivateWorkspaceStatusV1,
    attempt: Option<OriginalProofAttemptV2<'op, 'source>>,
}
impl<'op, 'source> OriginalCheckpointOutcomeV2<'op, 'source> {
    pub fn status(&self) -> &PrivateWorkspaceStatusV1 {
        &self.status
    }
    pub fn into_attempt(self) -> Option<OriginalProofAttemptV2<'op, 'source>> {
        self.attempt
    }
}
impl<'source> PrivateDurableCoordinatorV1<'source> {
    /// Collect only bounded original metadata under explicit current inspection.
    /// No artifact is read, constructor run, retained effect or token issued.
    pub fn inspect_prepare_stage_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateFixedStageReviewV3> {
        let before = self.inspection_envelope_v3(access, inspection)?;
        let id = sole_candidate_id_v3(&before)?;
        let c = candidate(&before, id)?;
        if !before.checkpoint_receipts.is_empty()
            || !before.durable_proposals_v1.is_empty()
            || !c.proof_jobs.is_empty()
        {
            return Err(damaged());
        }
        crate::candidates::check_current_terms(&before.view, &c.proposal.manifest)?;
        let materials = self.stage_materials_v3(access, &before, id)?;
        self.finish_stage_review_v3(
            access,
            inspection,
            &before,
            PrivateFixedStageV3::Prepare,
            materials,
            None,
        )
    }
    pub fn inspect_freeze_stage_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateFixedStageReviewV3> {
        self.inspect_retained_stage_v3(access, inspection, PrivateFixedStageV3::FreezeFixed)
    }
    pub fn inspect_saved_read_stage_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateFixedStageReviewV3> {
        self.inspect_retained_stage_v3(access, inspection, PrivateFixedStageV3::ReadFixed)
    }
    fn inspection_envelope_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<Envelope> {
        self.operation(
            access,
            inspection,
            PrivateWorkspaceActionV1::InspectFixedStageMetadataV3,
        )?
        .load()
    }
    pub(super) fn stage_materials_v3(
        &self,
        access: &Access,
        before: &Envelope,
        id: &str,
    ) -> Result<Vec<PrivateFixedMaterialReviewV3>> {
        let c = candidate(before, id)?;
        let roster = self.engine.durable_roster(before, id)?;
        if roster.owners.len() != 2 {
            return Err(damaged());
        }
        let expected: BTreeSet<_> = self.source.reviewer_account_ids().into_iter().collect();
        let mut accounts = BTreeSet::new();
        let mut materials = Vec::with_capacity(2);
        for (account, intake) in &roster.owners {
            intake.outbox.validate().map_err(|_| damaged())?;
            let scope = &intake.outbox.request().scope;
            let reviewers: BTreeSet<_> = scope
                .reviewers
                .iter()
                .map(|r| r.account_id().to_string())
                .collect();
            if account != &scope.account_id
                || !accounts.insert(account.clone())
                || intake.principal_id != access.principal_id
                || intake.metadata_origin != hex::encode(self.origin)
                || scope.constructor.principal_id != access.principal_id
                || scope.prover.principal_id != access.principal_id
                || scope.constructor != scope.prover
                || scope.proposal != c.proposal
                || Path::new(&scope.protected_destination) != self.scope.protected_destination()
                || scope.retention_policy != self.scope.retention_policy
                || reviewers != expected
            {
                return Err(denied());
            }
            materials.push(PrivateFixedMaterialReviewV3 {
                scope: scope.clone(),
                material_digest: intake.outbox.material_digest().into(),
            });
        }
        if accounts != expected {
            return Err(denied());
        }
        check_stage_material_ceilings_v3(&materials)?;
        Ok(materials)
    }
    fn inspect_retained_stage_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
        stage: PrivateFixedStageV3,
    ) -> Result<PrivateFixedStageReviewV3> {
        if !matches!(
            stage,
            PrivateFixedStageV3::FreezeFixed | PrivateFixedStageV3::ReadFixed
        ) {
            return Err(denied());
        }
        let before = self.inspection_envelope_v3(access, inspection)?;
        let id = sole_candidate_id_v3(&before)?;
        if before.checkpoint_receipts.len() != 1
            || (stage == PrivateFixedStageV3::ReadFixed
                && (before.durable_proposals_v1.len() != 1
                    || !before.durable_proposals_v1.contains_key(id)))
        {
            return Err(damaged());
        }
        let materials = self.stage_materials_v3(access, &before, id)?;
        let receipt = before
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
        let key = &original.command.idempotency_key;
        validate_original_request_v2(receipt, access, key)?;
        let scope = retained_review_scope_v3(candidate(&before, id)?, receipt, &materials)?;
        let gate = MetadataInspectionGateV3 {
            workspace: self,
            access,
            inspection,
            scope: &scope,
            materials: &materials,
            failure: StageInspectionFailureV3::default(),
        };
        let saved = gate
            .failure
            .finish(
                self.proof
                    .status_for_key(
                        &access.principal_id,
                        key,
                        &receipt.coordination_request_digest,
                        &gate,
                    )
                    .map_err(job_error),
            )?
            .ok_or_else(damaged)?;
        self.validate_original_lineage(&before, access, key, &saved, None)?;
        if saved.state != wholepact_proof_jobs::JobState::Succeeded
            || saved.attempt != 1
            || !saved.proof_verified
        {
            return Err(damaged());
        }
        // The state flag is not proof verification; the later effect/read must
        // independently load_verified under its new exact native stage grant.
        self.finish_stage_review_v3(access, inspection, &before, stage, materials, Some(scope))
    }
    fn finish_stage_review_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
        before: &Envelope,
        stage: PrivateFixedStageV3,
        materials: Vec<PrivateFixedMaterialReviewV3>,
        checkpoint_scope: Option<CheckpointScope>,
    ) -> Result<PrivateFixedStageReviewV3> {
        if materials.len() != 2
            || (stage == PrivateFixedStageV3::Prepare) != checkpoint_scope.is_none()
        {
            return Err(damaged());
        }
        check_stage_material_ceilings_v3(&materials)?;
        let after = self.inspection_envelope_v3(access, inspection)?;
        if crate::encode(before)? != crate::encode(&after)? {
            return Err(damaged());
        }
        let review = PrivateFixedStageReviewV3 {
            version: 3,
            purpose: "original-private-fixed-stage-review-v3",
            stage,
            workspace_scope: self.scope.clone(),
            marker_digest: self.origin_marker_digest()?,
            native_association_digest: self.marker.native_association_digest.clone(),
            metadata_origin: hex::encode(self.origin),
            proof_origin: hex::encode(self.proof_origin),
            revision: before.view.revision,
            materials,
            checkpoint_scope,
        };
        bounded_stage_review_v3(&review)?;
        self.check(
            access,
            inspection,
            PrivateWorkspaceActionV1::InspectFixedStageMetadataV3,
        )?;
        check_stage_material_ceilings_v3(&review.materials)?;
        Ok(review)
    }
}
impl PreparedOriginalCheckpointV2<'_, '_> {
    pub fn inspect_admission_stage_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateFixedStageReviewV3> {
        let workspace = self.workspace;
        let before = workspace.inspection_envelope_v3(access, inspection)?;
        if crate::encode(&before)? != crate::encode(&self.ready.before)? {
            return Err(damaged());
        }
        let materials = workspace.stage_materials_v3(access, &before, &self.ready.candidate_id)?;
        validate_original_request_v2(&self.ready.receipt, access, &self.ready.original_key)?;
        let scope = retained_review_scope_v3(
            candidate(&before, &self.ready.candidate_id)?,
            &self.ready.receipt,
            &materials,
        )?;
        if scope != self.ready.scope
            || scope.artifact_digest != hex::encode(Sha256::digest(&self.ready.built.pczt_bytes))
        {
            return Err(damaged());
        }
        let gate = MetadataInspectionGateV3 {
            workspace,
            access,
            inspection,
            scope: &scope,
            materials: &materials,
            failure: StageInspectionFailureV3::default(),
        };
        let observation = Observation::new(Operation::Checkpoint);
        gate.failure.finish(require_fresh_original_checkpoint_v2(
            &before,
            &self.ready.candidate_id,
            self.ready.revision,
            workspace.proof.status_for_key(
                &access.principal_id,
                &self.ready.original_key,
                &self.ready.command.request_digest,
                &gate,
            ),
            &observation,
        ))?;
        workspace.finish_stage_review_v3(
            access,
            inspection,
            &before,
            PrivateFixedStageV3::AdmitOriginal,
            materials,
            Some(scope),
        )
    }
}
impl OriginalProofAttemptV2<'_, '_> {
    /// Borrow only for exact metadata review. This cannot duplicate, run or
    /// replace the live consuming continuation.
    pub fn inspect_proof_stage_v3(
        &self,
        access: &Access,
        inspection: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateFixedStageReviewV3> {
        let workspace = self.constructor.workspace;
        if !self.enqueue.matches_source(&workspace.proof) {
            return Err(denied());
        }
        let before = workspace.inspection_envelope_v3(access, inspection)?;
        crate::candidates::check_revision(&before, self.linked_revision)?;
        let materials = workspace.stage_materials_v3(
            access,
            &before,
            &self.constructor.receipt.candidate_id,
        )?;
        let scope = retained_review_scope_v3(
            candidate(&before, &self.constructor.receipt.candidate_id)?,
            &self.constructor.receipt,
            &materials,
        )?;
        if scope != self.review_scope {
            return Err(damaged());
        }
        let gate = MetadataInspectionGateV3 {
            workspace,
            access,
            inspection,
            scope: &scope,
            materials: &materials,
            failure: StageInspectionFailureV3::default(),
        };
        let saved = gate
            .failure
            .finish(
                workspace
                    .proof
                    .status_for_key(
                        &access.principal_id,
                        &self.constructor.original_key,
                        &self.constructor.command.request_digest,
                        &gate,
                    )
                    .map_err(job_error),
            )?
            .ok_or_else(damaged)?;
        let receipt = workspace.validate_original_lineage(
            &before,
            access,
            &self.constructor.original_key,
            &saved,
            None,
        )?;
        if !same_original_receipt_v2(receipt, &self.constructor.receipt)?
            || receipt_key(access, &self.constructor.original_key)? != self.constructor.receipt_key
            || &saved != self.enqueue.summary()
            || saved.state != wholepact_proof_jobs::JobState::Queued
            || saved.attempt != 0
        {
            return Err(damaged());
        }
        workspace.finish_stage_review_v3(
            access,
            inspection,
            &before,
            PrivateFixedStageV3::ProveOriginal,
            materials,
            Some(scope),
        )
    }
}
fn sole_candidate_id_v3(before: &Envelope) -> Result<&str> {
    if before.view.candidates.len() != 1 {
        return Err(damaged());
    }
    Ok(&before.view.candidates[0].candidate_id)
}
fn stage_now_v3() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| damaged())
}
fn check_stage_material_ceilings_v3(materials: &[PrivateFixedMaterialReviewV3]) -> Result<()> {
    if materials.len() != 2 {
        return Err(damaged());
    }
    for material in materials {
        material
            .scope
            .check_valid_at(stage_now_v3()?)
            .map_err(|error| {
                let cause = diagnostics::construction(&error);
                preserve_stage_scope_cause_v3(ApiError::from(error), cause)
            })?;
    }
    Ok(())
}
// This optional finite cause is not a complete operation diagnostic. Metadata
// inspection has no proof consumption or persistence CALL facts to invent.
fn preserve_stage_scope_cause_v3(mut error: ApiError, cause: diagnostics::Cause) -> ApiError {
    if !matches!(
        (cause.family, cause.cause),
        ("DurableConstruction", "Invalid" | "Binding" | "Stale")
    ) {
        return error;
    }
    if let Some(details) = error.details.as_object_mut() {
        details
            .entry("private_fixed_stage_cause_v3".to_owned())
            .or_insert_with(|| json!({"family":cause.family,"cause":cause.cause}));
    }
    error
}
fn bounded_stage_review_v3(review: &PrivateFixedStageReviewV3) -> Result<()> {
    if review.version != 3
        || review.purpose != "original-private-fixed-stage-review-v3"
        || review.materials.len() != 2
        || (review.stage == PrivateFixedStageV3::Prepare) != review.checkpoint_scope.is_none()
    {
        return Err(damaged());
    }
    if serde_json::to_vec(review).map_err(|_| damaged())?.len() > MAX_STAGE_REVIEW_BYTES_V3 {
        return Err(denied());
    }
    Ok(())
}
pub(super) fn retained_review_scope_v3(
    c: &CandidateView,
    receipt: &crate::candidates::CheckpointReceipt,
    materials: &[PrivateFixedMaterialReviewV3],
) -> Result<CheckpointScope> {
    if materials.len() != 2 {
        return Err(damaged());
    }
    let first = &materials[0].scope;
    if materials.iter().any(|m| {
        m.scope.purpose != first.purpose || m.scope.retention_policy != first.retention_policy
    }) || receipt.candidate_id != c.candidate_id
        || receipt.manifest_digest != c.manifest_digest
    {
        return Err(damaged());
    }
    let scope = CheckpointScope {
        principal_id: receipt.principal_id.clone(),
        candidate_id: receipt.candidate_id.clone(),
        manifest_digest: receipt.manifest_digest.clone(),
        artifact_digest: receipt.artifact_digest.clone(),
        effects_commitment: receipt.effects_commitment.clone(),
        coordination_request_digest: receipt.coordination_request_digest.clone(),
        review_binding: receipt.review_binding.clone(),
        account_ids: c
            .proposal
            .manifest
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        local_operator: c
            .proposal
            .manifest
            .agreement
            .privacy_profile
            .proving_operator
            .clone()
            .ok_or_else(denied)?,
        purpose: first.purpose.clone(),
        retention_policy: first.retention_policy.clone(),
    };
    if hex::encode(Sha256::digest(
        serde_json::to_vec(&scope).map_err(|_| damaged())?,
    )) != receipt.scope_digest
    {
        return Err(damaged());
    }
    Ok(scope)
}
// Diagnostic data only, local to one actual status lookup. No lock or borrow
// guard survives a callback, and no collected value changes permission.
#[derive(Default)]
struct StageInspectionFailureV3(std::cell::Cell<(bool, Option<diagnostics::Cause>)>);
impl StageInspectionFailureV3 {
    fn observe<T>(&self, result: &Result<T>) {
        if self.0.get().0 {
            return;
        }
        let Err(error) = result else {
            return;
        };
        let cause = error
            .details
            .get("private_fixed_stage_cause_v3")
            .and_then(serde_json::Value::as_object)
            .filter(|object| object.len() == 2)
            .and_then(|object| {
                match (
                    object.get("family")?.as_str()?,
                    object.get("cause")?.as_str()?,
                ) {
                    ("DurableConstruction", "Invalid") => Some(diagnostics::Cause {
                        family: "DurableConstruction",
                        cause: "Invalid",
                    }),
                    ("DurableConstruction", "Binding") => Some(diagnostics::Cause {
                        family: "DurableConstruction",
                        cause: "Binding",
                    }),
                    ("DurableConstruction", "Stale") => Some(diagnostics::Cause {
                        family: "DurableConstruction",
                        cause: "Stale",
                    }),
                    _ => None,
                }
            });
        self.0.set((true, cause));
    }
    fn finish<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Err(error) => Err(match self.0.get().1 {
                Some(cause) => preserve_stage_scope_cause_v3(error, cause),
                None => error,
            }),
            Ok(value) => Ok(value),
        }
    }
}
struct MetadataInspectionGateV3<'a, 'source> {
    workspace: &'a PrivateDurableCoordinatorV1<'source>,
    access: &'a Access,
    inspection: &'a dyn LocalPrivateWorkspaceConsentV1,
    scope: &'a CheckpointScope,
    materials: &'a [PrivateFixedMaterialReviewV3],
    failure: StageInspectionFailureV3,
}
impl MetadataInspectionGateV3<'_, '_> {
    fn check(&self) -> Result<()> {
        check_stage_material_ceilings_v3(self.materials)?;
        self.workspace.check_without_proof_lock(
            self.access,
            self.inspection,
            PrivateWorkspaceActionV1::InspectFixedStageMetadataV3,
        )?;
        check_stage_material_ceilings_v3(self.materials)
    }
}
impl LocalProofConsent for MetadataInspectionGateV3<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        metadata_review_permission_v3(scope, self.scope, action, || {
            let result = self.check();
            self.failure.observe(&result);
            result
        })
    }
}
fn metadata_review_permission_v3(
    actual: &CheckpointScope,
    expected: &CheckpointScope,
    action: LocalAction,
    mut current: impl FnMut() -> Result<()>,
) -> bool {
    action == LocalAction::InspectStatus
        && actual == expected
        && current().is_ok()
        && current().is_ok()
}

fn status(result: &wholepact_store::MutationResult) -> PrivateWorkspaceStatusV1 {
    PrivateWorkspaceStatusV1 {
        revision: result.record.revision,
        replayed: result.replayed,
        rounds: vec![],
        authorization_allowed: false,
    }
}
fn commit_digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(Into::into)
}
pub(super) fn receipt_key(access: &Access, key: &str) -> Result<String> {
    crate::hash_domain(
        b"wholepact:checkpoint-receipt:v1\0",
        &json!({"principal":access.principal_id,"key":key}),
    )
}
fn candidate<'a>(envelope: &'a Envelope, id: &str) -> Result<&'a CandidateView> {
    if envelope.view.candidates.len() != 1 {
        return Err(damaged());
    }
    let candidate = &envelope.view.candidates[0];
    if candidate.candidate_id != id {
        return Err(denied());
    }
    candidate.verified_snapshot()?;
    Ok(candidate)
}
pub(super) fn validate_original_request_v2(
    receipt: &crate::candidates::CheckpointReceipt,
    access: &Access,
    key: &str,
) -> Result<()> {
    let original_request = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
    let exact_command = crate::context(
        access,
        key,
        "private_checkpoint_exact_original_v2",
        &receipt.candidate_id,
        Some(original_request.expected_revision),
        &json!({"local_input_digest":original_request.local_input_digest,"maximum_actions":original_request.maximum_actions}),
    )?;
    if original_request.command.principal_id != access.principal_id
        || original_request.command.idempotency_key != key
        || original_request.command.request_digest != exact_command.request_digest
        || receipt.coordination_request_digest != exact_command.request_digest
        || receipt.prepared_revision
            != original_request
                .expected_revision
                .checked_add(1)
                .ok_or_else(damaged)?
    {
        return Err(damaged());
    }
    if receipt.principal_id != access.principal_id
        || receipt.job_id
            != wholepact_proof_jobs::job_id_for_key(&access.principal_id, key).map_err(job_error)?
        || !(1..=wholepact_protocol::proving::MAX_PROVING_ACTIONS)
            .contains(&original_request.maximum_actions)
        || original_request.local_input_digest.len() != 64
        || !original_request
            .local_input_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(damaged());
    }
    Ok(())
}
impl<'source> PrivateDurableCoordinatorV1<'source> {
    pub fn require_fresh_fixed_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        let envelope = self
            .operation(access, consent, PrivateWorkspaceActionV1::ReadStatus)?
            .load()?;
        if envelope.view.revision != 1
            || !envelope.view.candidates.is_empty()
            || !envelope.durable_construction_v1.is_empty()
            || !envelope.checkpoint_receipts.is_empty()
            || !envelope.durable_proposals_v1.is_empty()
        {
            return Err(damaged());
        }
        Ok(PrivateWorkspaceStatusV1 {
            revision: 1,
            replayed: false,
            rounds: vec![],
            authorization_allowed: false,
        })
    }
    pub fn prepare_exact_candidate_v2(
        &self,
        access: &Access,
        key: &str,
        revision: u64,
        request: CandidateRequest,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateExactCandidateV2> {
        let before = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::PrepareExactCandidate,
            )?
            .load()?;
        crate::planning::check_proposer(&before, access)?;
        crate::candidates::check_current_terms(&before.view, &request.manifest)?;
        if request.previous_candidate_id.is_some() {
            return Err(denied());
        }
        let expected: BTreeSet<_> = self
            .source
            .seed
            .selected_members
            .iter()
            .map(|m| {
                (
                    m.scope.participant_id.clone(),
                    m.identity.account_id.clone(),
                )
            })
            .collect();
        let actual: BTreeSet<_> = request
            .manifest
            .participants
            .iter()
            .map(|p| (p.participant_id.clone(), p.account_id.clone()))
            .collect();
        if actual != expected
            || request.manifest.participants.len() != 2
            || request
                .manifest
                .inputs
                .iter()
                .any(|i| i.ownership_evidence_ref.is_some())
            || request.manifest.outputs.iter().any(|o| {
                matches!(
                    &o.allocation,
                    wholepact_core::proposal::OutputAllocation::Return {
                        ownership_evidence_ref: Some(_),
                        ..
                    }
                )
            })
        {
            return Err(denied());
        }
        let command = crate::context(
            access,
            key,
            "private_prepare_exact_candidate_v2",
            self.source.agreement_id(),
            Some(revision),
            &request,
        )?;
        let effect = PrivateWorkspaceEffectV2::new(
            self,
            access,
            consent,
            EffectV2::PrepareExactCandidate,
            command,
            revision,
        )?;
        if let Some(saved) = effect.replay()? {
            let e = decode_private_record(&saved.record)?;
            let c = e.view.candidates.first().ok_or_else(damaged)?;
            if c.proposal.manifest != request.manifest
                || !c.proof_jobs.is_empty()
                || before.view.candidates.first().map(|c| &c.proposal) != Some(&c.proposal)
            {
                return Err(damaged());
            }
            return Ok(PrivateExactCandidateV2 {
                proposal: c.proposal.clone(),
                revision: saved.record.revision,
                replayed: true,
            });
        }
        crate::candidates::check_revision(&before, revision)?;
        if !before.view.candidates.is_empty() {
            return Err(denied());
        }
        let c = crate::candidates::build_exact_candidate_v2(request)?;
        let proposal = c.proposal.clone();
        let mut after = before.clone();
        after.view.candidates.push(c);
        let saved = effect.commit(&before, after)?;
        Ok(PrivateExactCandidateV2 {
            proposal,
            revision: saved.record.revision,
            replayed: saved.replayed,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn retain_exact_material_v2(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        disclosure: AuthenticatedDurableConstructionDisclosureV1,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        let before = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::RetainExactMaterial,
            )?
            .load()?;
        let c = candidate(&before, candidate_id)?;
        let outbox = disclosure.outbox();
        outbox.validate().map_err(|_| damaged())?;
        let scope = &outbox.request().scope;
        if scope.proposal != c.proposal
            || !self
                .source
                .reviewer_account_ids()
                .contains(&scope.account_id)
        {
            return Err(denied());
        }
        let intake = Intake {
            schema_version: 1,
            principal_id: access.principal_id.clone(),
            metadata_origin: hex::encode(self.origin),
            signer_enrollment_reference: disclosure.signer_enrollment_reference().into(),
            signer_process_instance: disclosure.signer_process_instance().into(),
            outbox: outbox.clone(),
        };
        self.check_intake(
            access,
            &intake,
            material,
            DurableMaterialActionV1::RetainAuthenticatedDisclosure,
        )?;
        let command = crate::context(
            access,
            key,
            "private_retain_exact_material_v2",
            candidate_id,
            Some(revision),
            &(
                &intake.metadata_origin,
                outbox.reference(),
                outbox.request_digest(),
                outbox.material_digest(),
                disclosure.signer_enrollment_reference(),
            ),
        )?;
        let effect = PrivateWorkspaceEffectV2::new(
            self,
            access,
            consent,
            EffectV2::RetainExactMaterial,
            command,
            revision,
        )?;
        if let Some(saved) = effect.replay()? {
            let e = decode_private_record(&saved.record)?;
            let roster = self.engine.durable_roster(&e, candidate_id)?;
            let retained = roster.owners.get(&scope.account_id).ok_or_else(damaged)?;
            // The saved original process identity is never replaced by retry.
            if retained.outbox.reference() != outbox.reference()
                || retained.outbox.request_digest() != outbox.request_digest()
                || retained.outbox.material_digest() != outbox.material_digest()
            {
                return Err(damaged());
            }
            self.check_intake(
                access,
                retained,
                material,
                DurableMaterialActionV1::RetainAuthenticatedDisclosure,
            )?;
            return Ok(status(&saved));
        }
        crate::candidates::check_revision(&before, revision)?;
        let mut roster = self.engine.durable_roster(&before, candidate_id)?;
        if roster.owners.contains_key(&scope.account_id)
            || !before.checkpoint_receipts.is_empty()
            || !before.durable_proposals_v1.is_empty()
        {
            return Err(denied());
        }
        roster.owners.insert(scope.account_id.clone(), intake);
        let mut after = before.clone();
        after.durable_construction_v1.insert(
            candidate_id.into(),
            serde_json::to_value(&roster).map_err(|_| damaged())?,
        );
        let saved = effect.commit(&before, after)?;
        for intake in roster.owners.values() {
            self.check_intake(
                access,
                intake,
                material,
                DurableMaterialActionV1::RetainAuthenticatedDisclosure,
            )?;
        }
        Ok(status(&saved))
    }
    pub(super) fn check_intake(
        &self,
        access: &Access,
        intake: &Intake,
        material: &dyn LocalDurableMaterialConsentV1,
        action: DurableMaterialActionV1,
    ) -> Result<()> {
        self.check_intake_observed(None, access, intake, material, action)
    }
    fn check_intake_observed(
        &self,
        observation: Option<&Observation>,
        access: &Access,
        intake: &Intake,
        material: &dyn LocalDurableMaterialConsentV1,
        action: DurableMaterialActionV1,
    ) -> Result<()> {
        let scope = &intake.outbox.request().scope;
        let reviewers: BTreeSet<_> = scope
            .reviewers
            .iter()
            .map(|r| r.account_id().to_string())
            .collect();
        if scope.constructor.principal_id != access.principal_id
            || scope.prover.principal_id != access.principal_id
            || Path::new(&scope.protected_destination) != self.scope.protected_destination()
            || scope.retention_policy != self.scope.retention_policy
            || reviewers != self.source.reviewer_account_ids().into_iter().collect()
            || !self
                .source
                .reviewer_account_ids()
                .contains(&scope.account_id)
        {
            return Err(denied());
        }
        self.engine
            .check_durable_material_typed_v2(access, intake, material, action)
            .map_err(|error| {
                if let Some(o) = observation {
                    use crate::durable_construction_v1::MaterialCheckErrorV2::*;
                    let cause = match &error {
                        Engine(e) => diagnostics::engine(e),
                        Wallet(e) => diagnostics::construction(e),
                        Store(e) => diagnostics::store(e),
                    };
                    o.record(Site::GateMaterial, cause);
                }
                error.into_api()
            })
    }
    fn checked_roster(
        &self,
        access: &Access,
        envelope: &Envelope,
        candidate_id: &str,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Roster> {
        self.checked_roster_inner(None, access, envelope, candidate_id, material)
    }
    fn checked_roster_observed(
        &self,
        observation: &Observation,
        access: &Access,
        envelope: &Envelope,
        candidate_id: &str,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Roster> {
        self.checked_roster_inner(Some(observation), access, envelope, candidate_id, material)
    }
    fn checked_roster_inner(
        &self,
        observation: Option<&Observation>,
        access: &Access,
        envelope: &Envelope,
        candidate_id: &str,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<Roster> {
        candidate(envelope, candidate_id)?;
        let roster = self.engine.durable_roster(envelope, candidate_id)?;
        if roster.owners.len() != 2 {
            return Err(denied());
        }
        for intake in roster.owners.values() {
            self.check_intake_observed(
                observation,
                access,
                intake,
                material,
                DurableMaterialActionV1::ReadForExactConstruction,
            )?;
        }
        Ok(roster)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn observe_exact_material_v2(
        &self,
        access: &Access,
        candidate_id: &str,
        account_id: &str,
        wallet: &mut ProtectedWalletSync,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        material: &dyn LocalDurableMaterialConsentV1,
        wallet_access: &impl LocalWalletAccess,
    ) -> Result<FreshDurableConstructionObservationV1> {
        self.observe_exact_material_inner_v3(
            access,
            candidate_id,
            account_id,
            wallet,
            consent,
            material,
            wallet_access,
            None,
        )
        .await
    }
    /// The fresh actual scan owner supplies the boundary for this observation
    /// only. No boundary is retained in the returned scanner facts.
    #[allow(clippy::too_many_arguments)]
    pub async fn observe_exact_material_compound_v3(
        &self,
        access: &Access,
        candidate_id: &str,
        account_id: &str,
        wallet: &mut ProtectedWalletSync,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        material: &dyn LocalDurableMaterialConsentV1,
        wallet_access: &impl LocalWalletAccess,
        boundary: &dyn LocalPrivateFixedPermissionBoundaryV3,
    ) -> Result<FreshDurableConstructionObservationV1> {
        self.observe_exact_material_inner_v3(
            access,
            candidate_id,
            account_id,
            wallet,
            consent,
            material,
            wallet_access,
            Some(boundary),
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn observe_exact_material_inner_v3(
        &self,
        access: &Access,
        candidate_id: &str,
        account_id: &str,
        wallet: &mut ProtectedWalletSync,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        material: &dyn LocalDurableMaterialConsentV1,
        wallet_access: &impl LocalWalletAccess,
        boundary: Option<&dyn LocalPrivateFixedPermissionBoundaryV3>,
    ) -> Result<FreshDurableConstructionObservationV1> {
        // One collector per concrete observation future, never shared between
        // the two owners. This path can report causes, not persistence facts.
        let observation = Observation::new(Operation::Checkpoint);
        let result = async {
            observation.stage(Site::WorkspaceLoad);
            let envelope = self
                .operation_observed(
                    access,
                    consent,
                    PrivateWorkspaceActionV1::ObserveExactMaterial,
                    Some(&observation),
                )?
                .load_observed(&observation)?;
            observation.stage(Site::Candidate);
            candidate(&envelope, candidate_id)?;
            observation.stage(Site::MaterialRoster);
            let roster = self.engine.durable_roster(&envelope, candidate_id)?;
            let intake = roster.owners.get(account_id).ok_or_else(damaged)?;
            let gate = ObservationGate {
                workspace: self,
                access,
                consent,
                material,
                intake,
                roster: &roster,
                wallet: wallet_access,
                boundary,
                observation: &observation,
            };
            gate.check()?;
            observation.stage(Site::WalletRosterAcquire);
            let result = wallet
                .observe_durable_material_v1(
                    &intake.outbox.request().material,
                    &intake.outbox.request().scope,
                    &gate,
                )
                .await;
            let result = observation.construction_result(Site::WalletRosterAcquire, result);
            match result {
                Err(error) => Err(error),
                Ok(fresh) => {
                    observation.stage(Site::PostConsent);
                    gate.check()?;
                    Ok(fresh)
                }
            }
        }
        .await;
        observation.finish_cause_only(result)
    }

    /// Prepare exactly once, release all initial wallet locks, then obtain the
    /// real exact artifact review. No retained metadata/proof effects occur.
    /// Existing process-only scan/witness caches are not a no-write claim.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_checkpoint_exact_original_v2<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PreparedOriginalCheckpointV2<'op, 'source>> {
        let observation = Observation::new(Operation::Checkpoint);
        let result = self.prepare_original_observed_v2(
            access,
            key,
            candidate_id,
            revision,
            slots,
            limits,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
    /// New stage-only pure constructor. Its separate workspace purpose cannot
    /// authorize the legacy retained checkpoint path. No native dialog here.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_checkpoint_for_stage_v3<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PreparedOriginalCheckpointV2<'op, 'source>> {
        let observation = Observation::new(Operation::Checkpoint);
        let result = (|| {
            let (_, prepared) = self.prepare_unreviewed_original_v3(
                access,
                key,
                candidate_id,
                revision,
                slots,
                limits,
                consent,
                proof,
                material,
                PrepareModeV3::StagePreparation,
                &observation,
            )?;
            // All held callbacks/postchecks have returned. End this stage under
            // its own current source and permission before any later review.
            self.check_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::PrepareFixedStageV3,
                Some(&observation),
            )?;
            self.finish_preparation_v3(
                access,
                key,
                candidate_id,
                revision,
                prepared,
                limits,
                &observation,
            )
        })();
        observation.finish(result)
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_original_observed_v2<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<PreparedOriginalCheckpointV2<'op, 'source>> {
        let (roster, prepared) = self.prepare_unreviewed_original_v3(
            access,
            key,
            candidate_id,
            revision,
            slots,
            limits,
            consent,
            proof,
            material,
            PrepareModeV3::LegacyCheckpoint,
            observation,
        )?;
        // The entire held kernel, including its postchecks, has returned. The
        // real human review below owns no wallet lock and renews no capability.
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::CheckpointExactOriginal,
            held: None,
            observation: Some(observation),
        };
        observation.stage(Site::PostSource);
        self.proof
            .check_current()
            .map_err(|error| observation.job_error(error))?;
        observation.stage(Site::RetainConsent);
        if !gate.permits(
            &prepared.constructed.scope,
            LocalAction::RetainPrivateWitnesses,
        ) {
            return Err(denied());
        }
        observation.stage(Site::PostSource);
        self.proof
            .check_current()
            .map_err(|error| observation.job_error(error))?;
        self.finish_preparation_v3(
            access,
            key,
            candidate_id,
            revision,
            prepared,
            limits,
            observation,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_unreviewed_original_v3(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        mode: PrepareModeV3,
        observation: &Observation,
    ) -> Result<(Roster, UnreviewedOriginalCheckpointV2)> {
        if !(1..=wholepact_protocol::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
        {
            return Err(denied());
        }
        observation.stage(Site::WorkspaceLoad);
        let envelope = self
            .operation_observed(access, consent, mode.action(), Some(observation))?
            .load_observed(observation)?;
        observation.stage(Site::Candidate);
        let c = candidate(&envelope, candidate_id)?;
        observation.stage(Site::MaterialRoster);
        let roster =
            self.checked_roster_observed(observation, access, &envelope, candidate_id, material)?;
        let declarations = checkpoint_declarations_v2(c, &roster, &slots, observation)?;
        observation.stage(Site::WalletRosterAcquire);
        let callback_returned = std::cell::Cell::new(false);
        let prepared = with_durable_construction_roster_v1(
            slots,
            |held, contributions, context| -> std::result::Result<_, diagnostics::RosterError> {
                let result = (|| -> Result<_> {
                    let gate = ArtifactGate {workspace:self, access, consent, material, proof,
                        roster:&roster, action:mode.action(),
                        held:Some(held), observation:Some(observation)};
                    observation.stage(Site::HeldPrecheck);
                    gate.check()?;
                    observation.stage(Site::ConstructorReload);
                    let before = self.operation_observed(access, consent,
                        mode.action(), Some(observation))?
                        .load_observed(observation)?;
                    observation.stage(Site::Candidate);
                    let candidate = candidate(&before, candidate_id)?.clone();
                    observation.stage(Site::InputRequestDigest);
                    let input_digest = crate::candidates::private_request_digest(context, &contributions, &declarations)?;
                    observation.stage(Site::OriginalRequest);
                    let command = crate::context(access, key, "private_checkpoint_exact_original_v2",
                        candidate_id, Some(revision),
                        &json!({"local_input_digest":input_digest,"maximum_actions":limits.maximum_actions}))?;
                    let receipt_key = receipt_key(access, key)?;
                    observation.stage(Site::OriginalLookup);
                    require_fresh_original_checkpoint_v2(&before, candidate_id, revision,
                        self.proof.status_for_key(&access.principal_id, key, &command.request_digest, &gate), observation)?;
                    let constructed = construct_exact_artifact_v2(access, candidate_id, &candidate, &command,
                        crate::candidates::LocalConstruction {context,contributions,declarations:&declarations},
                        limits, observation)?;
                    observation.stage(Site::HeldPostcheck);
                    gate.check()?;
                    Ok(UnreviewedOriginalCheckpointV2 {before,candidate,command,input_digest,receipt_key,constructed})
                })();
                if let Err(error)=&result { observation.record(observation.site(), diagnostics::engine(error)); }
                callback_returned.set(true);
                result.map_err(diagnostics::RosterError::from)
            },
        ).map_err(|error| error.into_api(observation, if callback_returned.get() {
            Site::WalletRosterRelease
        } else { Site::WalletRosterAcquire }))?;
        Ok((roster, prepared))
    }
    #[allow(clippy::too_many_arguments)]
    fn finish_preparation_v3<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        prepared: UnreviewedOriginalCheckpointV2,
        limits: ProvingLimits,
        observation: &Observation,
    ) -> Result<PreparedOriginalCheckpointV2<'op, 'source>> {
        let UnreviewedOriginalCheckpointV2 {
            before,
            candidate,
            command,
            input_digest,
            receipt_key,
            constructed,
        } = prepared;
        let ConstructedCheckpointV2 { built, scope } = constructed;
        let receipt = prepare_constructor_receipt_v2(
            access,
            key,
            candidate_id,
            revision,
            input_digest,
            &candidate,
            &command,
            &built,
            &scope,
            limits,
            observation,
        )?;
        Ok(PreparedOriginalCheckpointV2 {
            workspace: self,
            ready: ReadyOriginalCheckpointV2 {
                before,
                original_key: key.into(),
                candidate_id: candidate_id.into(),
                revision,
                command,
                receipt_key,
                receipt,
                built,
                scope,
                limits,
            },
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn admit_ready_original_v2<'op>(
        &'op self,
        access: &Access,
        ready: ReadyOriginalCheckpointV2,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        observation.stage(Site::WorkspaceLoad);
        let envelope = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::Candidate);
        let c = candidate(&envelope, &ready.candidate_id)?;
        observation.stage(Site::MaterialRoster);
        let roster = self.checked_roster_observed(
            observation,
            access,
            &envelope,
            &ready.candidate_id,
            material,
        )?;
        let declarations = checkpoint_declarations_v2(c, &roster, &slots, observation)?;
        observation.stage(Site::WalletRosterAcquire);
        let callback_returned = std::cell::Cell::new(false);
        let result = with_durable_construction_roster_v1(
            slots,
            |held, contributions, current| -> std::result::Result<_, diagnostics::RosterError> {
                let result = (|| -> Result<_> {
                    let gate = ArtifactGate {
                        workspace: self,
                        access,
                        consent,
                        material,
                        proof,
                        roster: &roster,
                        action: PrivateWorkspaceActionV1::CheckpointExactOriginal,
                        held: Some(held),
                        observation: Some(observation),
                    };
                    observation.stage(Site::HeldPrecheck);
                    gate.check()?;
                    observation.stage(Site::ConstructorReload);
                    let before = self
                        .operation_observed(
                            access,
                            consent,
                            PrivateWorkspaceActionV1::CheckpointExactOriginal,
                            Some(observation),
                        )?
                        .load_observed(observation)?;
                    observation.stage(Site::OriginalLookup);
                    require_fresh_original_checkpoint_v2(
                        &before,
                        &ready.candidate_id,
                        ready.revision,
                        self.proof.status_for_key(
                            &access.principal_id,
                            &ready.original_key,
                            &ready.command.request_digest,
                            &gate,
                        ),
                        observation,
                    )?;
                    observation.stage(Site::OriginalRequest);
                    let ready = consume_prepared_join_v2(
                        ready,
                        &before,
                        current,
                        &contributions,
                        &declarations,
                    )?;
                    validate_original_request_v2(&ready.receipt, access, &ready.original_key)?;
                    observation.stage(Site::RetainConsent);
                    if !gate.permits(&ready.scope, LocalAction::RetainPrivateWitnesses) {
                        return Err(denied());
                    }
                    // No constructor on this path. The exact reviewed bytes and
                    // request move once into the original retained-effect tail.
                    let outcome = self.persist_original_checkpoint_v2(
                        access,
                        ready,
                        consent,
                        &gate,
                        observation,
                    )?;
                    observation.stage(Site::HeldPostcheck);
                    gate.check()
                        .map_err(|error| checkpoint_committed_error(error, &outcome.status))?;
                    Ok(outcome)
                })();
                if let Err(error) = &result {
                    observation.record(observation.site(), diagnostics::engine(error));
                }
                callback_returned.set(true);
                result.map_err(diagnostics::RosterError::from)
            },
        );
        result.map_err(|error| {
            error.into_api(
                observation,
                if callback_returned.get() {
                    Site::WalletRosterRelease
                } else {
                    Site::WalletRosterAcquire
                },
            )
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_exact_original_v2<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        let observation = Observation::new(Operation::Checkpoint);
        let result = self.checkpoint_exact_original_v2_observed(
            access,
            key,
            candidate_id,
            revision,
            slots,
            limits,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
    fn checkpoint_exact_original_v2_observed<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        slots: Vec<DurableConstructionWalletSlotV1<'_>>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        if !(1..=wholepact_protocol::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
        {
            return Err(denied());
        }
        observation.stage(Site::WorkspaceLoad);
        let envelope = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::Candidate);
        let c = candidate(&envelope, candidate_id)?;
        observation.stage(Site::MaterialRoster);
        let roster =
            self.checked_roster_observed(observation, access, &envelope, candidate_id, material)?;
        let declarations = checkpoint_declarations_v2(c, &roster, &slots, observation)?;
        observation.stage(Site::WalletRosterAcquire);
        let callback_returned = std::cell::Cell::new(false);
        let result = with_durable_construction_roster_v1(
            slots,
            |held, contributions, context| -> std::result::Result<_, diagnostics::RosterError> {
                let result = (|| -> Result<_> {
                    let gate = ArtifactGate {
                        workspace: self,
                        access,
                        consent,
                        material,
                        proof,
                        roster: &roster,
                        action: PrivateWorkspaceActionV1::CheckpointExactOriginal,
                        held: Some(held),
                        observation: Some(observation),
                    };
                    observation.stage(Site::HeldPrecheck);
                    gate.check()?;
                    let outcome = self.construct_checkpoint(
                        access,
                        key,
                        candidate_id,
                        revision,
                        crate::candidates::LocalConstruction {
                            context,
                            contributions,
                            declarations: &declarations,
                        },
                        limits,
                        consent,
                        &gate,
                        observation,
                    );
                    match outcome {
                        Err(error) => Err(error),
                        Ok(outcome) => {
                            observation.stage(Site::HeldPostcheck);
                            gate.check().map_err(|error| {
                                checkpoint_committed_error(error, &outcome.status)
                            })?;
                            Ok(outcome)
                        }
                    }
                })();
                if let Err(error) = &result {
                    observation.record(observation.site(), diagnostics::engine(error));
                }
                callback_returned.set(true);
                result.map_err(diagnostics::RosterError::from)
            },
        );
        result.map_err(|error| {
            error.into_api(
                observation,
                if callback_returned.get() {
                    Site::WalletRosterRelease
                } else {
                    Site::WalletRosterAcquire
                },
            )
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn construct_checkpoint<'op>(
        &'op self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        construction: crate::candidates::LocalConstruction<'_>,
        limits: ProvingLimits,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        observation: &Observation,
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        observation.stage(Site::ConstructorReload);
        let before = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::Candidate);
        let c = candidate(&before, candidate_id)?.clone();
        observation.stage(Site::InputRequestDigest);
        let input_digest = crate::candidates::private_request_digest(
            construction.context,
            &construction.contributions,
            construction.declarations,
        )?;
        observation.stage(Site::OriginalRequest);
        let command = crate::context(
            access,
            key,
            "private_checkpoint_exact_original_v2",
            candidate_id,
            Some(revision),
            &json!({"local_input_digest":input_digest,"maximum_actions":limits.maximum_actions}),
        )?;
        observation.stage(Site::OriginalRequest);
        let receipt_key = receipt_key(access, key)?;
        // Exact request lookup precedes ALL randomized construction. Permission
        // and storage errors never mean absence or authorize reconstruction.
        observation.stage(Site::OriginalLookup);
        let existing = self
            .proof
            .status_for_key(&access.principal_id, key, &command.request_digest, proof)
            .map_err(|error| observation.job_error(error))?;
        if let Some(saved) = existing {
            observation.stage(Site::OriginalLineage);
            let receipt = self
                .validate_original_lineage(&before, access, key, &saved, Some(observation))?
                .clone();
            if receipt.coordination_request_digest != command.request_digest
                || receipt.prepared_revision != revision.checked_add(1).ok_or_else(damaged)?
            {
                return Err(damaged());
            }
            observation.stage(Site::LinkPrepare);
            let effect = PrivateWorkspaceEffectV2::new_observed(
                self,
                access,
                consent,
                EffectV2::MetadataLink,
                command,
                receipt.prepared_revision,
                observation,
            )?;
            observation.stage(Site::ReplayLookup);
            if let Some(replayed) = effect.replay_observed(observation)? {
                self.validate_original_lineage(&before, access, key, &saved, Some(observation))?;
                return Ok(OriginalCheckpointOutcomeV2 {
                    status: status(&replayed),
                    attempt: None,
                });
            }
            observation.stage(Site::Revision);
            crate::candidates::check_revision(&before, receipt.prepared_revision)?;
            observation.stage(Site::OriginalLineage);
            if !c.proof_jobs.is_empty() {
                return Err(damaged());
            }
            observation.stage(Site::LinkUpsert);
            let mut after = before.clone();
            upsert_link(&mut after, &saved)?;
            observation.stage(Site::LinkCommit);
            let linked = effect
                .commit_observed(&before, after, observation)
                .map_err(|e| original_checkpoint_error(e, &saved))?;
            return Ok(OriginalCheckpointOutcomeV2 {
                status: status(&linked),
                attempt: None,
            });
        }
        observation.stage(Site::OriginalLineage);
        if !before.checkpoint_receipts.is_empty()
            || !c.proof_jobs.is_empty()
            || !before.durable_proposals_v1.is_empty()
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Original constructor history exists without its exact private checkpoint; preserve both journals and do not reconstruct",
            ));
        }
        observation.stage(Site::Revision);
        crate::candidates::check_revision(&before, revision)?;
        observation.stage(Site::CurrentTerms);
        crate::candidates::check_current_terms(&before.view, &c.proposal.manifest)?;
        let ConstructedCheckpointV2 { built, scope } = construct_exact_artifact_v2(
            access,
            candidate_id,
            &c,
            &command,
            construction,
            limits,
            observation,
        )?;
        observation.stage(Site::RetainConsent);
        if !proof.permits(&scope, LocalAction::RetainPrivateWitnesses) {
            return Err(denied());
        }
        let receipt = prepare_constructor_receipt_v2(
            access,
            key,
            candidate_id,
            revision,
            input_digest,
            &c,
            &command,
            &built,
            &scope,
            limits,
            observation,
        )?;
        self.persist_original_checkpoint_v2(
            access,
            ReadyOriginalCheckpointV2 {
                before,
                original_key: key.into(),
                candidate_id: candidate_id.into(),
                revision,
                command,
                receipt_key,
                receipt,
                built,
                scope,
                limits,
            },
            consent,
            proof,
            observation,
        )
    }
    fn persist_original_checkpoint_v2<'op>(
        &'op self,
        access: &Access,
        ready: ReadyOriginalCheckpointV2,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        observation: &Observation,
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        let ReadyOriginalCheckpointV2 {
            before,
            original_key,
            candidate_id,
            revision,
            command,
            receipt_key,
            receipt,
            built,
            scope,
            limits,
        } = ready;
        let key = original_key.as_str();
        let candidate_id = candidate_id.as_str();
        let prepared_revision = receipt.prepared_revision;
        observation.stage(Site::ReceiptPrepare);
        let prepare_command = crate::context(
            access,
            &format!("prepare-{receipt_key}"),
            "private_prepare_constructor_receipt_v2",
            candidate_id,
            Some(revision),
            &receipt,
        )?;
        observation.stage(Site::ReceiptPrepare);
        let prepare = PrivateWorkspaceEffectV2::new_observed(
            self,
            access,
            consent,
            EffectV2::ConstructorReceipt,
            prepare_command,
            revision,
            observation,
        )?;
        observation.stage(Site::LinkUpsert);
        let mut after = before.clone();
        after
            .checkpoint_receipts
            .insert(receipt_key.clone(), receipt.clone());
        observation.stage(Site::ReceiptCommit);
        let committed = prepare.commit_observed(&before, after, observation)?;
        // This actual successful transaction Result is the ONLY minting point.
        // Even an exact Store replay cannot issue a live continuation.
        if committed.replayed {
            return Err(damaged());
        }
        let constructor = FreshConstructorReceiptCommitV2 {
            workspace: self,
            receipt_key: receipt_key.clone(),
            receipt: receipt.clone(),
            original_key: key.into(),
            command: command.clone(),
        };
        observation.stage(Site::Enqueue);
        let enqueue=self.proof.enqueue_original_once_v1(&scope,key,&built.pczt_bytes,&built.review_policy,limits,proof).map_err(|error| {
            observation.call(Call::Enqueue, CallState::ReturnedErrUnknown);
            let mut error=observation.job_error(error);
            let category=error.details.get("private_original_job_error_v1").cloned();
            error.details=Box::new(json!({"constructor_receipt_created":true,"prepared_revision":prepared_revision,"coordination_request_digest":command.request_digest,
                "encrypted_checkpoint_status":"not_confirmed","journals_are_atomic_together":false,"private_original_job_error_v1":category})); error
        })?;
        let (saved, fresh) = enqueue.into_parts();
        observation.call(
            Call::Enqueue,
            if fresh.is_some() {
                CallState::ReturnedOkFresh
            } else {
                CallState::ReturnedOkNoContinuation
            },
        );
        observation.stage(Site::ReloadAfterEnqueue);
        let linked_before = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::OriginalLineage);
        self.validate_original_lineage(&linked_before, access, key, &saved, Some(observation))?;
        observation.stage(Site::LinkPrepare);
        let link = PrivateWorkspaceEffectV2::new_observed(
            self,
            access,
            consent,
            EffectV2::MetadataLink,
            command,
            prepared_revision,
            observation,
        )?;
        observation.stage(Site::LinkUpsert);
        let mut linked_after = linked_before.clone();
        upsert_link(&mut linked_after, &saved)?;
        observation.stage(Site::LinkCommit);
        let linked = link
            .commit_observed(&linked_before, linked_after, observation)
            .map_err(|e| original_checkpoint_error(e, &saved))?;
        observation.stage(Site::PostSource);
        self.check_observed(
            access,
            consent,
            PrivateWorkspaceActionV1::CheckpointExactOriginal,
            Some(observation),
        )
        .map_err(|error| checkpoint_committed_error(error, &status(&linked)))?;
        observation.stage(Site::RetainConsent);
        if !proof.permits(&scope, LocalAction::RetainPrivateWitnesses) {
            return Err(checkpoint_committed_error(denied(), &status(&linked)));
        }
        observation.stage(Site::PostConsent);
        let attempt = match fresh {
            Some(enqueue) if !linked.replayed && enqueue.matches_source(&self.proof) => {
                Some(OriginalProofAttemptV2 {
                    constructor,
                    enqueue,
                    linked_revision: linked.record.revision,
                    review_scope: scope.clone(),
                })
            }
            _ => None,
        };
        Ok(OriginalCheckpointOutcomeV2 {
            status: status(&linked),
            attempt,
        })
    }
    /// Full provenance includes the ORIGINAL receipt map key and actual saved
    /// constructor operation, not just candidate ID or a supplied manifest.
    pub(super) fn validate_original_lineage<'e>(
        &self,
        envelope: &'e Envelope,
        access: &Access,
        key: &str,
        summary: &JobSummary,
        observation: Option<&Observation>,
    ) -> Result<&'e crate::candidates::CheckpointReceipt> {
        if let Some(o) = observation {
            o.stage(Site::OriginalLineage);
        }
        let c = candidate(envelope, &summary.candidate_id)?;
        validate_summary(c, summary)?;
        let receipt = validate_provenance(envelope, access, summary)?;
        validate_original_request_v2(receipt, access, key)?;
        let index = receipt_key(access, key)?;
        let indexed = envelope
            .checkpoint_receipts
            .get(&index)
            .ok_or_else(damaged)?;
        if serde_json::to_value(indexed).map_err(|_| damaged())?
            != serde_json::to_value(receipt).map_err(|_| damaged())?
            || receipt.action_mappings_v1.is_none()
            || receipt.job_id
                != wholepact_proof_jobs::job_id_for_key(&access.principal_id, key).map_err(
                    |error| diagnostics::job_error(observation, Site::OriginalLineage, error),
                )?
        {
            return Err(damaged());
        }
        let previous = receipt
            .prepared_revision
            .checked_sub(1)
            .ok_or_else(damaged)?;
        let prepare = crate::context(
            access,
            &format!("prepare-{index}"),
            "private_prepare_constructor_receipt_v2",
            &receipt.candidate_id,
            Some(previous),
            receipt,
        )?;
        if let Some(o) = observation {
            o.stage(Site::OriginalLineage);
        }
        let saved = self
            .engine
            .store
            .find_replay(&prepare)
            .map_err(|error| diagnostics::store_error(observation, Site::OriginalLineage, error))?
            .ok_or_else(damaged)?;
        let original = decode_private_record(&saved.record)?;
        self.require_original_envelope(&original)?;
        if saved.record.revision != receipt.prepared_revision
            || original.checkpoint_receipts.len() != 1
            || serde_json::to_value(original.checkpoint_receipts.get(&index))
                .map_err(|_| damaged())?
                != serde_json::to_value(Some(receipt)).map_err(|_| damaged())?
        {
            return Err(damaged());
        }
        // Candidate and admitted materials are immutable from original receipt
        // through every later outcome and fixed read, including stale summaries.
        let original_candidate = candidate(&original, &receipt.candidate_id)?;
        if original_candidate.proposal != c.proposal
            || original.durable_construction_v1 != envelope.durable_construction_v1
        {
            return Err(damaged());
        }
        if let Some(o) = observation {
            o.stage(Site::OriginalLineage);
        }
        let operation = self
            .engine
            .store
            .get_operation(&saved.operation_id)
            .map_err(|error| diagnostics::store_error(observation, Site::OriginalLineage, error))?
            .ok_or_else(damaged)?;
        let result: wholepact_store::MutationResult =
            serde_json::from_value(operation.result).map_err(|_| damaged())?;
        if operation.principal_id != access.principal_id
            || operation.resource_id != self.source.agreement_id()
            || operation.kind != "private_original_constructor_recorded_v2"
            || operation.status != "succeeded"
            || result.record != saved.record
            || result.operation_id != saved.operation_id
        {
            return Err(damaged());
        }
        Ok(receipt)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prove_original_once_v2(
        &self,
        attempt: OriginalProofAttemptV2<'_, 'source>,
        access: &Access,
        key: &str,
        revision: u64,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        let observation = Observation::new(Operation::Proof);
        let result = self.prove_original_once_v2_observed(
            attempt,
            access,
            key,
            revision,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
    fn prove_original_once_v2_observed(
        &self,
        attempt: OriginalProofAttemptV2<'_, 'source>,
        access: &Access,
        key: &str,
        revision: u64,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<PrivateWorkspaceStatusV1> {
        // Consume the entire continuation BEFORE all fallible checks. Every
        // return, denial, panic or failed proof drops the only live correlation.
        let OriginalProofAttemptV2 {
            constructor,
            enqueue,
            linked_revision,
            review_scope: _,
        } = attempt;
        observation.consumed();
        observation.stage(Site::ContinuationBinding);
        if !std::ptr::eq(self, constructor.workspace)
            || !enqueue.matches_source(&self.proof)
            || revision != linked_revision
        {
            return Err(denied());
        }
        observation.stage(Site::WorkspaceLoad);
        let before = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::ProveOriginalOnce,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::MaterialRoster);
        let roster = self.checked_roster_observed(
            observation,
            access,
            &before,
            &constructor.receipt.candidate_id,
            material,
        )?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::ProveOriginalOnce,
            held: None,
            observation: Some(observation),
        };
        observation.stage(Site::HeldPrecheck);
        gate.check()?;
        observation.stage(Site::OriginalLookup);
        let saved = self
            .proof
            .status_for_key(
                &access.principal_id,
                &constructor.original_key,
                &constructor.command.request_digest,
                &gate,
            )
            .map_err(|error| observation.job_error(error))?
            .ok_or_else(damaged)?;
        observation.stage(Site::OriginalLineage);
        let receipt = self.validate_original_lineage(
            &before,
            access,
            &constructor.original_key,
            &saved,
            Some(observation),
        )?;
        if receipt_key(access, &constructor.original_key)? != constructor.receipt_key
            || !same_original_receipt_v2(receipt, &constructor.receipt)?
            || enqueue.summary() != &saved
        {
            return Err(damaged());
        }
        observation.stage(Site::Revision);
        crate::candidates::check_revision(&before, revision)?;
        observation.stage(Site::OriginalRequest);
        let command = crate::context(
            access,
            key,
            "private_prove_original_once_v2",
            &saved.candidate_id,
            Some(revision),
            &(&saved.job_id, &constructor.command.request_digest),
        )?;
        observation.stage(Site::OutcomePrepare);
        let effect = PrivateWorkspaceEffectV2::new_observed(
            self,
            access,
            consent,
            EffectV2::RecordOriginalProofOutcome,
            command,
            revision,
            observation,
        )?;
        // There can be no lawful replay for a live newly minted continuation.
        observation.stage(Site::ReplayLookup);
        if effect.replay_observed(observation)?.is_some() {
            return Err(damaged());
        }
        observation.stage(Site::ProofRun);
        let summary = enqueue.run_original_queued_v1(&gate).map_err(|error| {
            observation.call(Call::Proof, CallState::ReturnedErrUnknown);
            let mut error = observation.job_error(error);
            error.retryable = false;
            if let Some(details) = error.details.as_object_mut() {
                details.insert("original_proof_attempt_consumed".into(), json!(true));
                details.insert("inspect_original_journal".into(), json!(true));
            }
            error
        })?;
        observation.call(Call::Proof, CallState::ReturnedOk);
        observation.stage(Site::HeldPrecheck);
        gate.check()?;
        observation.stage(Site::ProofResultLineage);
        self.validate_original_lineage(
            &before,
            access,
            &constructor.original_key,
            &summary,
            Some(observation),
        )?;
        observation.stage(Site::LinkUpsert);
        let mut after = before.clone();
        upsert_link(&mut after, &summary)?;
        observation.stage(Site::OutcomeCommit);
        let result = effect
            .commit_observed(&before, after, observation)
            .map_err(|e| original_checkpoint_error(e, &summary))?;
        observation.stage(Site::HeldPrecheck);
        gate.check()?;
        Ok(status(&result))
    }
    pub(super) fn load_original_verified(
        &self,
        envelope: &Envelope,
        access: &Access,
        candidate_id: &str,
        original_key: &str,
        proof: &dyn LocalProofConsent,
        observation: &Observation,
    ) -> Result<VerifiedCheckpoint> {
        observation.stage(Site::OriginalLineage);
        let receipt = envelope
            .checkpoint_receipts
            .get(&receipt_key(access, original_key)?)
            .ok_or_else(damaged)?;
        if receipt.candidate_id != candidate_id {
            return Err(damaged());
        }
        observation.stage(Site::StatusLookup);
        let summary = self
            .proof
            .status_for_key(
                &access.principal_id,
                original_key,
                &receipt.coordination_request_digest,
                proof,
            )
            .map_err(|error| observation.job_error(error))?
            .ok_or_else(damaged)?;
        observation.stage(Site::OriginalLineage);
        self.validate_original_lineage(
            envelope,
            access,
            original_key,
            &summary,
            Some(observation),
        )?;
        observation.stage(Site::LoadVerified);
        let checkpoint = self
            .proof
            .load_verified(&access.principal_id, &summary.job_id, proof)
            .map_err(|error| observation.job_error(error))?;
        observation.stage(Site::OriginalLineage);
        self.validate_original_lineage(
            envelope,
            access,
            original_key,
            checkpoint.summary(),
            Some(observation),
        )?;
        observation.stage(Site::ProofVerifiedState);
        if checkpoint.summary() != &summary
            || summary.state != wholepact_proof_jobs::JobState::Succeeded
            || summary.attempt != 1
            || !summary.proof_verified
        {
            return Err(damaged());
        }
        Ok(checkpoint)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn freeze_verified_fixed_v2(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        original_checkpoint_key: &str,
        revision: u64,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateVerifiedFixedV2> {
        let observation = Observation::new(Operation::Freeze);
        let result = self.freeze_verified_fixed_v2_observed(
            access,
            key,
            candidate_id,
            original_checkpoint_key,
            revision,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
    fn freeze_verified_fixed_v2_observed(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        original_checkpoint_key: &str,
        revision: u64,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<PrivateVerifiedFixedV2> {
        observation.stage(Site::WorkspaceLoad);
        let before = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::FreezeVerifiedFixed,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::MaterialRoster);
        let roster =
            self.checked_roster_observed(observation, access, &before, candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            held: None,
            observation: Some(observation),
        };
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::LoadVerified);
        let checkpoint = self.load_original_verified(
            &before,
            access,
            candidate_id,
            original_checkpoint_key,
            &gate,
            observation,
        )?;
        observation.stage(Site::OriginalLineage);
        let receipt = self
            .validate_original_lineage(
                &before,
                access,
                original_checkpoint_key,
                checkpoint.summary(),
                Some(observation),
            )?
            .clone();
        observation.stage(Site::OriginalRequest);
        let command = crate::context(
            access,
            key,
            "private_freeze_verified_fixed_v2",
            candidate_id,
            Some(revision),
            &(
                original_checkpoint_key,
                &receipt.coordination_request_digest,
                checkpoint.summary(),
            ),
        )?;
        observation.stage(Site::FixedPrepare);
        let effect = PrivateWorkspaceEffectV2::new_observed(
            self,
            access,
            consent,
            EffectV2::FreezeVerifiedFixed,
            command,
            revision,
            observation,
        )?;
        observation.stage(Site::ReplayLookup);
        if effect.replay_observed(observation)?.is_some() {
            observation.stage(Site::FixedReplayRead);
            let identity = crate::durable_proposals_v1::read_private_fixed_observed_v2(
                observation,
                &before,
                access,
                &checkpoint,
                &receipt,
            )?;
            observation.stage(Site::OutputCommitments);
            let output = self.verified_output(
                &before,
                access,
                original_checkpoint_key,
                &checkpoint,
                &identity,
                &gate,
                observation,
            )?;
            observation.stage(Site::FinalGate);
            gate.check()?;
            observation.stage(Site::PostSource);
            self.check_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::FreezeVerifiedFixed,
                Some(observation),
            )?;
            return Ok(output);
        }
        observation.stage(Site::Revision);
        crate::candidates::check_revision(&before, revision)?;
        let mut after = before.clone();
        observation.stage(Site::FixedVerify);
        let identity = crate::durable_proposals_v1::freeze_private_fixed_observed_v2(
            observation,
            &mut after,
            access,
            &checkpoint,
            &receipt,
        )?;
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::FixedCommit);
        let result = effect.commit_observed(&before, after, observation)?;
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::PostSource);
        self.check_observed(
            access,
            consent,
            PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            Some(observation),
        )?;
        observation.stage(Site::SavedDecode);
        let saved = decode_private_record(&result.record)?;
        observation.stage(Site::OutputCommitments);
        let output = self.verified_output(
            &saved,
            access,
            original_checkpoint_key,
            &checkpoint,
            &identity,
            &gate,
            observation,
        )?;
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::PostSource);
        self.check_observed(
            access,
            consent,
            PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            Some(observation),
        )?;
        Ok(output)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn read_verified_fixed_v2(
        &self,
        access: &Access,
        candidate_id: &str,
        original_checkpoint_key: &str,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateVerifiedFixedV2> {
        let observation = Observation::new(Operation::ReadFixed);
        let result = self.read_verified_fixed_v2_observed(
            access,
            candidate_id,
            original_checkpoint_key,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
    fn read_verified_fixed_v2_observed(
        &self,
        access: &Access,
        candidate_id: &str,
        original_checkpoint_key: &str,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<PrivateVerifiedFixedV2> {
        observation.stage(Site::WorkspaceLoad);
        let envelope = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::ReadVerifiedFixed,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::MaterialRoster);
        let roster =
            self.checked_roster_observed(observation, access, &envelope, candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::ReadVerifiedFixed,
            held: None,
            observation: Some(observation),
        };
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::LoadVerified);
        let checkpoint = self.load_original_verified(
            &envelope,
            access,
            candidate_id,
            original_checkpoint_key,
            &gate,
            observation,
        )?;
        observation.stage(Site::OriginalLineage);
        let receipt = self.validate_original_lineage(
            &envelope,
            access,
            original_checkpoint_key,
            checkpoint.summary(),
            Some(observation),
        )?;
        observation.stage(Site::FixedVerify);
        let identity = crate::durable_proposals_v1::read_private_fixed_observed_v2(
            observation,
            &envelope,
            access,
            &checkpoint,
            receipt,
        )?;
        observation.stage(Site::OutputCommitments);
        let output = self.verified_output(
            &envelope,
            access,
            original_checkpoint_key,
            &checkpoint,
            &identity,
            &gate,
            observation,
        )?;
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::PostSource);
        self.check_observed(
            access,
            consent,
            PrivateWorkspaceActionV1::ReadVerifiedFixed,
            Some(observation),
        )?;
        Ok(output)
    }
    pub fn fixed_status_v2(
        &self,
        access: &Access,
        candidate_id: &str,
        original_checkpoint_key: &str,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        _material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateFixedStatusV2> {
        let envelope = self
            .operation(access, consent, PrivateWorkspaceActionV1::ReadStatus)?
            .load()?;
        candidate(&envelope, candidate_id)?;
        let Some(receipt) = envelope
            .checkpoint_receipts
            .get(&receipt_key(access, original_checkpoint_key)?)
        else {
            return Ok(PrivateFixedStatusV2 {
                revision: envelope.view.revision,
                state: "incomplete".into(),
                attempt: 0,
                fixed_retained: false,
                proof_verified: false,
                authorization_allowed: false,
            });
        };
        let Some(summary) = self
            .proof
            .status_for_key(
                &access.principal_id,
                original_checkpoint_key,
                &receipt.coordination_request_digest,
                proof,
            )
            .map_err(job_error)?
        else {
            return Ok(PrivateFixedStatusV2 {
                revision: envelope.view.revision,
                state: "receipt_without_artifact".into(),
                attempt: 0,
                fixed_retained: false,
                proof_verified: false,
                authorization_allowed: false,
            });
        };
        self.validate_original_lineage(&envelope, access, original_checkpoint_key, &summary, None)?;
        self.check(access, consent, PrivateWorkspaceActionV1::ReadStatus)?;
        Ok(PrivateFixedStatusV2 {
            revision: envelope.view.revision,
            state: serde_json::to_value(summary.state)
                .map_err(|_| damaged())?
                .as_str()
                .ok_or_else(damaged)?
                .into(),
            attempt: summary.attempt,
            fixed_retained: envelope.durable_proposals_v1.contains_key(candidate_id),
            proof_verified: summary.proof_verified,
            authorization_allowed: false,
        })
    }
    /// Same-original completed reader discovers only the sole retained purpose
    /// request. It never reconstructs a key or accepts one from a control file.
    pub fn read_only_original_fixed_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateVerifiedFixedV2> {
        let observation = Observation::new(Operation::ReadFixed);
        let result = self.read_only_original_fixed_v2_observed(
            access,
            consent,
            proof,
            material,
            &observation,
        );
        observation.finish(result)
    }
    fn read_only_original_fixed_v2_observed(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        observation: &Observation,
    ) -> Result<PrivateVerifiedFixedV2> {
        observation.stage(Site::WorkspaceLoad);
        let before = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::ReadVerifiedFixed,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::RetainedDiscovery);
        if before.view.candidates.len() != 1
            || before.durable_proposals_v1.len() != 1
            || before.checkpoint_receipts.len() != 1
        {
            return Err(damaged());
        }
        observation.stage(Site::RetainedDiscovery);
        let candidate_id = before.view.candidates[0].candidate_id.clone();
        let receipt = before
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        observation.stage(Site::RetainedKey);
        let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
        let key = original.command.idempotency_key.clone();
        observation.stage(Site::LoadVerified);
        let output = self.read_verified_fixed_v2_observed(
            access,
            &candidate_id,
            &key,
            consent,
            proof,
            material,
            observation,
        )?;
        observation.stage(Site::ReloadAfterRead);
        let after = self
            .operation_observed(
                access,
                consent,
                PrivateWorkspaceActionV1::ReadVerifiedFixed,
                Some(observation),
            )?
            .load_observed(observation)?;
        observation.stage(Site::EnvelopeCompare);
        if crate::encode(&before)? != crate::encode(&after)? {
            return Err(damaged());
        }
        observation.stage(Site::MaterialRoster);
        let roster =
            self.checked_roster_observed(observation, access, &after, &candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::ReadVerifiedFixed,
            held: None,
            observation: Some(observation),
        };
        observation.stage(Site::JournalAfterRead);
        let actual = self
            .proof
            .status_for_key(
                &access.principal_id,
                &key,
                &receipt.coordination_request_digest,
                &gate,
            )
            .map_err(|error| observation.job_error(error))?
            .ok_or_else(damaged)?;
        observation.stage(Site::OriginalLineage);
        self.validate_original_lineage(&after, access, &key, &actual, Some(observation))?;
        observation.stage(Site::OperationHistory);
        let history = self.audit_exact_history_observed(&after, Some(observation))?;
        observation.stage(Site::ProofEventHistory);
        let proof_history = self
            .proof
            .original_attempt_history_digest_v1(&access.principal_id, &actual.job_id, &gate)
            .map_err(|error| observation.job_error(error))?;
        observation.stage(Site::LogicalCompare);
        if output.proof_event_history_digest != proof_history
            || output.logical_state_digest
                != commit_digest(
                    "wholepact:private-fixed-logical-state:v2",
                    &(&after, &actual, &history, &proof_history),
                )?
        {
            return Err(damaged());
        }
        observation.stage(Site::FinalGate);
        gate.check()?;
        observation.stage(Site::FinalProofOrigin);
        self.proof
            .check_current()
            .map_err(|error| observation.job_error(error))?;
        Ok(output)
    }
    fn verified_output(
        &self,
        envelope: &Envelope,
        access: &Access,
        key: &str,
        checkpoint: &VerifiedCheckpoint,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        proof: &dyn LocalProofConsent,
        observation: &Observation,
    ) -> Result<PrivateVerifiedFixedV2> {
        let summary = checkpoint.summary();
        observation.stage(Site::OutputLineage);
        let receipt =
            self.validate_original_lineage(envelope, access, key, summary, Some(observation))?;
        observation.stage(Site::OperationHistory);
        let history = self.audit_exact_history_observed(envelope, Some(observation))?;
        self.verified_output_data_v2(
            envelope,
            access,
            key,
            checkpoint,
            identity,
            proof,
            observation,
            history,
            receipt,
        )
    }
    // The new profile supplies the digest of an actual saved prefix after
    // auditing every original result and the complete current export suffix.
    // No envelope is reconstructed by deleting exports from current state.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verified_output_from_audited_prefix_v2(
        &self,
        envelope: &Envelope,
        access: &Access,
        key: &str,
        checkpoint: &VerifiedCheckpoint,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        proof: &dyn LocalProofConsent,
        observation: &Observation,
        history: String,
    ) -> Result<PrivateVerifiedFixedV2> {
        let summary = checkpoint.summary();
        observation.stage(Site::OutputLineage);
        let receipt =
            self.validate_original_lineage(envelope, access, key, summary, Some(observation))?;
        self.verified_output_data_v2(
            envelope,
            access,
            key,
            checkpoint,
            identity,
            proof,
            observation,
            history,
            receipt,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn verified_output_data_v2(
        &self,
        envelope: &Envelope,
        access: &Access,
        key: &str,
        checkpoint: &VerifiedCheckpoint,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        proof: &dyn LocalProofConsent,
        observation: &Observation,
        history: String,
        receipt: &crate::candidates::CheckpointReceipt,
    ) -> Result<PrivateVerifiedFixedV2> {
        let summary = checkpoint.summary();
        observation.stage(Site::ProofEventHistory);
        let proof_history = self
            .proof
            .original_attempt_history_digest_v1(&access.principal_id, &summary.job_id, proof)
            .map_err(|error| observation.job_error(error))?;
        observation.stage(Site::OutputCommitments);
        Ok(PrivateVerifiedFixedV2 {
            revision: envelope.view.revision,
            source_digest: self.source.source_digest().into(),
            native_association_digest: self.marker.native_association_digest.clone(),
            marker_digest: self.origin_marker_digest()?,
            metadata_origin: hex::encode(self.origin),
            proof_origin: hex::encode(self.proof_origin),
            candidate_id: summary.candidate_id.clone(),
            candidate_identity_digest: commit_digest(
                "wholepact:private-candidate-identity:v2",
                &summary.candidate_id,
            )?,
            manifest_digest: summary.manifest_digest.clone(),
            original_checkpoint_key_digest: commit_digest(
                "wholepact:private-original-checkpoint-key:v2",
                &(access.principal_id.as_str(), key),
            )?,
            coordination_request_digest: summary.coordination_request_digest.clone(),
            checkpoint_receipt_digest: commit_digest(
                "wholepact:private-original-constructor-receipt:v2",
                &(receipt_key(access, key)?, receipt),
            )?,
            action_mapping_digest: identity.action_mapping_digest.clone(),
            job_id: summary.job_id.clone(),
            job_identity_digest: commit_digest(
                "wholepact:private-original-job-identity:v2",
                &summary.job_id,
            )?,
            scope_digest: summary.scope_digest.clone(),
            input_digest: summary.input_digest.clone(),
            result_digest: summary.result_digest.clone().ok_or_else(damaged)?,
            fixed_identity_digest: commit_digest(
                "wholepact:private-verified-fixed-identity:v2",
                identity,
            )?,
            operation_history_digest: history.clone(),
            proof_event_history_digest: proof_history.clone(),
            logical_state_digest: commit_digest(
                "wholepact:private-fixed-logical-state:v2",
                &(envelope, summary, &history, &proof_history),
            )?,
            state: "succeeded".into(),
            attempt: summary.attempt,
            proof_verified: summary.proof_verified,
            authorization_allowed: false,
        })
    }
    /// Audit every saved exact effect and its original result. This also rejects
    /// changed historical markers and unknown future effects during replay/open.
    pub(super) fn audit_exact_history(&self, current: &Envelope) -> Result<String> {
        self.audit_exact_history_observed(current, None)
    }
    pub(super) fn audit_exact_history_observed(
        &self,
        current: &Envelope,
        observation: Option<&Observation>,
    ) -> Result<String> {
        let events = self.engine.store.events_after(0, 9).map_err(|error| {
            diagnostics::store_error(observation, Site::OperationHistory, error)
        })?;
        if events.is_empty() || events.len() > 8 || events.len() as u64 != current.view.revision {
            return Err(damaged());
        }
        let mut previous: Option<Envelope> = None;
        let mut history = Vec::new();
        for (i, event) in events.iter().enumerate() {
            if event.aggregate_type != "agreement"
                || event.aggregate_id != self.source.agreement_id()
                || event.aggregate_revision != (i + 1) as u64
                || event.sequence != (i + 1) as u64
            {
                return Err(damaged());
            }
            let operation = self
                .engine
                .store
                .get_operation(&event.operation_id)
                .map_err(|error| {
                    diagnostics::store_error(observation, Site::OperationHistory, error)
                })?
                .ok_or_else(damaged)?;
            let saved: wholepact_store::MutationResult =
                serde_json::from_value(operation.result.clone()).map_err(|_| damaged())?;
            if operation.kind != event.kind
                || operation.resource_id != event.aggregate_id
                || operation.principal_id != self.source.principal_id()
                || operation.status != "succeeded"
                || saved.operation_id != event.operation_id
                || saved.event_sequence != event.sequence
                || saved.record.revision != event.aggregate_revision
                || saved.replayed
            {
                return Err(damaged());
            }
            let envelope = decode_private_record(&saved.record)?;
            self.require_original_envelope(&envelope)?;
            if let Some(before) = &previous {
                let purpose = match event.kind.as_str() {
                    "private_exact_candidate_prepared_v2" => EffectV2::PrepareExactCandidate,
                    "private_exact_material_retained_v2" => EffectV2::RetainExactMaterial,
                    "private_original_constructor_recorded_v2" => EffectV2::ConstructorReceipt,
                    "private_original_checkpoint_linked_v2" => EffectV2::MetadataLink,
                    "private_original_proof_observed_v2" => EffectV2::RecordOriginalProofOutcome,
                    "private_verified_fixed_frozen_v2" => EffectV2::FreezeVerifiedFixed,
                    _ => return Err(damaged()),
                };
                // require_original_envelope above validates this exact envelope's
                // shape. `previous` is the immutable owned envelope validated on
                // the preceding iteration; neither is mutated before this join.
                operation_v1::validate_delta_after_checked_shapes_v2(before, &envelope, purpose)?;
            } else if event.kind != "agreement.created"
                || !envelope.view.candidates.is_empty()
                || !envelope.durable_construction_v1.is_empty()
                || !envelope.checkpoint_receipts.is_empty()
                || !envelope.durable_proposals_v1.is_empty()
            {
                return Err(damaged());
            }
            history.push((event, operation));
            previous = Some(envelope);
        }
        if crate::encode(previous.as_ref().ok_or_else(damaged)?)? != crate::encode(current)? {
            return Err(damaged());
        }
        commit_digest("wholepact:private-exact-operation-history:v2", &history)
    }
}
struct UnreviewedOriginalCheckpointV2 {
    before: Envelope,
    candidate: CandidateView,
    command: wholepact_store::CommandContext,
    input_digest: String,
    receipt_key: String,
    constructed: ConstructedCheckpointV2,
}
fn require_fresh_original_checkpoint_v2(
    before: &Envelope,
    candidate_id: &str,
    revision: u64,
    actual_lookup: std::result::Result<Option<JobSummary>, wholepact_proof_jobs::JobError>,
    observation: &Observation,
) -> Result<()> {
    // An error or an existing row is never converted into absence. This helper
    // cannot link/replay an existing job, construct bytes, write or mint owners.
    let existing = actual_lookup.map_err(|error| observation.job_error(error))?;
    observation.stage(Site::OriginalLineage);
    let c = candidate(before, candidate_id)?;
    if existing.is_some()
        || !before.checkpoint_receipts.is_empty()
        || !c.proof_jobs.is_empty()
        || !before.durable_proposals_v1.is_empty()
    {
        return Err(damaged());
    }
    observation.stage(Site::Revision);
    crate::candidates::check_revision(before, revision)?;
    observation.stage(Site::CurrentTerms);
    crate::candidates::check_current_terms(&before.view, &c.proposal.manifest)
}
fn validate_prepared_context_v2(
    original: wholepact_protocol::construction::ConstructionContext,
    current: wholepact_protocol::construction::ConstructionContext,
    expiry_height: u32,
) -> Result<()> {
    // Current target eligibility/NU7 and exact note/ancestry/spendability are
    // independently checked by the held Wallet kernel. Only the target may
    // advance here: the original randomized artifact and request stay fixed.
    if current.anchor != original.anchor
        || current.anchor_height != original.anchor_height
        || current.anchor_block_hash != original.anchor_block_hash
        || current.target_height < original.target_height
        || current.target_height > expiry_height
    {
        return Err(denied());
    }
    Ok(())
}
fn consume_prepared_join_v2(
    ready: ReadyOriginalCheckpointV2,
    before: &Envelope,
    current: wholepact_protocol::construction::ConstructionContext,
    contributions: &[wholepact_protocol::construction::OwnedContribution],
    declarations: &[DisclosureAcknowledgement],
) -> Result<ReadyOriginalCheckpointV2> {
    validate_prepared_join_v2(&ready, before, current, contributions, declarations)?;
    Ok(ready)
}
fn validate_prepared_join_v2(
    ready: &ReadyOriginalCheckpointV2,
    before: &Envelope,
    current: wholepact_protocol::construction::ConstructionContext,
    contributions: &[wholepact_protocol::construction::OwnedContribution],
    declarations: &[DisclosureAcknowledgement],
) -> Result<()> {
    if crate::encode(before)? != crate::encode(&ready.before)? {
        return Err(damaged());
    }
    let c = candidate(before, &ready.candidate_id)?;
    validate_prepared_context_v2(
        ready.built.context,
        current,
        c.proposal.manifest.expiry_height,
    )?;
    let request = ready
        .receipt
        .original_request_v2
        .as_ref()
        .ok_or_else(damaged)?;
    // Deliberately bind the immutable ORIGINAL target, not the newer current
    // scan target. No new transaction or replacement request is constructed.
    let actual = crate::candidates::private_request_digest(
        ready.built.context,
        contributions,
        declarations,
    )?;
    if ready.receipt.scope_digest
        != hex::encode(Sha256::digest(
            serde_json::to_vec(&ready.scope).map_err(|_| damaged())?,
        ))
        || ready.scope.artifact_digest != hex::encode(Sha256::digest(&ready.built.pczt_bytes))
        || ready.scope.candidate_id != ready.candidate_id
        || ready.scope.manifest_digest != c.manifest_digest
        || ready.scope.coordination_request_digest != ready.command.request_digest
        || actual != request.local_input_digest
        || request.command.principal_id != ready.command.principal_id
        || request.command.idempotency_key != ready.command.idempotency_key
        || request.command.request_digest != ready.command.request_digest
        || request.expected_revision != ready.revision
        || request.maximum_actions != ready.limits.maximum_actions
    {
        return Err(damaged());
    }
    Ok(())
}
fn checkpoint_declarations_v2(
    c: &CandidateView,
    roster: &Roster,
    slots: &[DurableConstructionWalletSlotV1<'_>],
    observation: &Observation,
) -> Result<Vec<DisclosureAcknowledgement>> {
    observation.stage(Site::SlotBindings);
    if slots.len() != 2 {
        return Err(denied());
    }
    let mut expected = BTreeSet::new();
    let mut declarations = Vec::new();
    for intake in roster.owners.values() {
        let scope = &intake.outbox.request().scope;
        expected.insert((
            intake.outbox.material_digest().to_owned(),
            scope.digest().map_err(|e| {
                observation.record(Site::SlotBindings, diagnostics::construction(&e));
                ApiError::from(e)
            })?,
        ));
        declarations.push(DisclosureAcknowledgement {
            account_id: scope.account_id.clone(),
            manifest_digest: hex::decode(&c.manifest_digest)
                .map_err(|_| damaged())?
                .try_into()
                .map_err(|_| damaged())?,
            operator: scope.prover.principal_id.clone(),
            reviewer_account_ids: scope
                .reviewers
                .iter()
                .map(|r| r.account_id().to_string())
                .collect(),
            purpose: scope.purpose.clone(),
            retention_policy: scope.retention_policy.clone(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        });
    }
    observation.stage(Site::SlotBindings);
    let actual: BTreeSet<_> = slots
        .iter()
        .map(|s| {
            Ok((
                s.material_digest().map_err(|e| {
                    observation.record(Site::SlotBindings, diagnostics::construction(&e));
                    ApiError::from(e)
                })?,
                s.scope_digest().map_err(|e| {
                    observation.record(Site::SlotBindings, diagnostics::construction(&e));
                    ApiError::from(e)
                })?,
            ))
        })
        .collect::<Result<_>>()?;
    if actual.len() != 2 || actual != expected {
        return Err(damaged());
    }
    Ok(declarations)
}
struct ConstructedCheckpointV2 {
    built: wholepact_protocol::construction::ConstructedProposal,
    scope: CheckpointScope,
}
struct ReadyOriginalCheckpointV2 {
    before: Envelope,
    original_key: String,
    candidate_id: String,
    revision: u64,
    command: wholepact_store::CommandContext,
    receipt_key: String,
    receipt: crate::candidates::CheckpointReceipt,
    built: wholepact_protocol::construction::ConstructedProposal,
    scope: CheckpointScope,
    limits: ProvingLimits,
}
#[allow(clippy::too_many_arguments)]
fn construct_exact_artifact_v2(
    access: &Access,
    candidate_id: &str,
    c: &CandidateView,
    command: &wholepact_store::CommandContext,
    construction: crate::candidates::LocalConstruction<'_>,
    limits: ProvingLimits,
    observation: &Observation,
) -> Result<ConstructedCheckpointV2> {
    observation.stage(Site::RetainConsent);
    let first = construction.declarations.first().ok_or_else(denied)?;
    if construction.declarations.len() != 2
        || construction
            .declarations
            .iter()
            .any(|d| d.purpose != first.purpose || d.retention_policy != first.retention_policy)
    {
        return Err(denied());
    }
    observation.stage(Site::ProposalValidation);
    let proposal = c.verified_snapshot()?;
    observation.stage(Site::ProtocolConstruct);
    #[cfg(test)]
    tests::record_original_constructor_v2();
    let built = wholepact_protocol::construction::construct_proposal(
        &proposal,
        construction.context,
        construction.contributions,
        construction.declarations,
    )
    .map_err(|error| {
        observation.record(Site::ProtocolConstruct, diagnostics::protocol(&error));
        ApiError::new(
            "CANDIDATE_VERIFICATION_FAILED",
            "Exact original local construction failed before private retention",
        )
    })?;
    observation.stage(Site::ProtocolInspect);
    if wholepact_protocol::inspect_candidate(&built.pczt_bytes)
        .map_err(|error| {
            observation.record(Site::ProtocolInspect, diagnostics::protocol(&error));
            damaged()
        })?
        .actions
        > limits.maximum_actions
    {
        return Err(denied());
    }
    observation.stage(Site::OriginalRequest);
    let scope = CheckpointScope {
        principal_id: access.principal_id.clone(),
        candidate_id: candidate_id.into(),
        manifest_digest: c.manifest_digest.clone(),
        artifact_digest: hex::encode(Sha256::digest(&built.pczt_bytes)),
        effects_commitment: built.economic_review.shielded_sighash().into(),
        coordination_request_digest: command.request_digest.clone(),
        review_binding: built.economic_review.review_binding().into(),
        account_ids: proposal
            .manifest()
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        local_operator: proposal
            .manifest()
            .agreement
            .privacy_profile
            .proving_operator
            .clone()
            .ok_or_else(denied)?,
        purpose: first.purpose.clone(),
        retention_policy: first.retention_policy.clone(),
    };
    Ok(ConstructedCheckpointV2 { built, scope })
}
#[allow(clippy::too_many_arguments)]
fn prepare_constructor_receipt_v2(
    access: &Access,
    key: &str,
    candidate_id: &str,
    revision: u64,
    input_digest: String,
    c: &CandidateView,
    command: &wholepact_store::CommandContext,
    built: &wholepact_protocol::construction::ConstructedProposal,
    scope: &CheckpointScope,
    limits: ProvingLimits,
    observation: &Observation,
) -> Result<crate::candidates::CheckpointReceipt> {
    observation.stage(Site::ReceiptPrepare);
    let prepared_revision = revision.checked_add(1).ok_or_else(damaged)?;
    let receipt = crate::candidates::CheckpointReceipt {
        original_request_v2: Some(crate::candidates::OriginalCheckpointRequestV2 {
            command: command.clone(),
            expected_revision: revision,
            local_input_digest: input_digest,
            maximum_actions: limits.maximum_actions,
        }),
        action_mappings_v1: Some(json!({
            "inputs":built.input_actions.iter().map(|m|json!({"input_id":m.input_id,"account_id":m.account_id,"action_index":m.action_index})).collect::<Vec<_>>(),
            "outputs":built.output_actions.iter().map(|m|json!({"output_id":m.output_id,"action_index":m.action_index})).collect::<Vec<_>>() })),
        job_id: wholepact_proof_jobs::job_id_for_key(&access.principal_id, key)
            .map_err(|error| observation.job_error(error))?,
        scope_digest: hex::encode(Sha256::digest(
            serde_json::to_vec(&scope).map_err(|_| damaged())?,
        )),
        principal_id: access.principal_id.clone(),
        candidate_id: candidate_id.into(),
        manifest_digest: c.manifest_digest.clone(),
        coordination_request_digest: command.request_digest.clone(),
        artifact_digest: scope.artifact_digest.clone(),
        review_binding: scope.review_binding.clone(),
        effects_commitment: scope.effects_commitment.clone(),
        prepared_revision,
    };
    Ok(receipt)
}
struct ObservationGate<'a, 'source, W> {
    workspace: &'a PrivateDurableCoordinatorV1<'source>,
    access: &'a Access,
    consent: &'a dyn LocalPrivateWorkspaceConsentV1,
    material: &'a dyn LocalDurableMaterialConsentV1,
    intake: &'a Intake,
    roster: &'a Roster,
    wallet: &'a W,
    boundary: Option<&'a dyn LocalPrivateFixedPermissionBoundaryV3>,
    observation: &'a Observation,
}
impl<W> ObservationGate<'_, '_, W> {
    fn check(&self) -> Result<()> {
        self.check_with(self.consent, self.material)
    }
    fn check_with(
        &self,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<()> {
        self.observation.stage(Site::GateWorkspace);
        self.observation.api(
            Site::GateWorkspace,
            self.workspace.check_observed(
                self.access,
                consent,
                PrivateWorkspaceActionV1::ObserveExactMaterial,
                Some(self.observation),
            ),
        )?;
        self.observation.stage(Site::GateMaterial);
        self.observation.api(
            Site::GateMaterial,
            self.workspace.check_intake_observed(
                Some(self.observation),
                self.access,
                self.intake,
                material,
                DurableMaterialActionV1::ReadForExactConstruction,
            ),
        )
    }
}

impl<W: LocalWalletAccess> LocalWalletAccess for ObservationGate<'_, '_, W> {
    fn permits(
        &self,
        account: wholepact_wallet::wallet::AccountUuid,
        provider: &wholepact_wallet::wallet::protected_sync::BackendIdentity,
        purpose: wholepact_wallet::wallet::protected_sync::WalletAccessPurpose,
    ) -> bool {
        let Some(boundary) = self.boundary else {
            return observation_permission_v1(
                || self.check(),
                || self.wallet.permits(account, provider, purpose),
            );
        };
        let Ok(request) = PrivateFixedPermissionRequestV3::new(
            &self.workspace.scope,
            PrivateWorkspaceActionV1::ObserveExactMaterial,
            self.roster,
            PrivateFixedPermissionKindV3::Observation {
                scope: &self.intake.outbox.request().scope,
                digest: self.intake.outbox.material_digest(),
                account,
                provider,
                purpose,
            },
        ) else {
            return false;
        };
        compound_observation_permission_v3(boundary, &request, |consent, material, wallet| {
            observation_permission_v1(
                || self.check_with(consent, material),
                || wallet.permits(account, provider, purpose),
            )
        })
    }
}
// Same short-circuit kernel: no observer borrow survives the actual checks.
fn observation_permission_v1(
    mut check: impl FnMut() -> Result<()>,
    permission: impl FnOnce() -> bool,
) -> bool {
    check().is_ok() && permission() && check().is_ok()
}
struct ArtifactGate<'a, 'source, 'held> {
    workspace: &'a PrivateDurableCoordinatorV1<'source>,
    access: &'a Access,
    consent: &'a dyn LocalPrivateWorkspaceConsentV1,
    material: &'a dyn LocalDurableMaterialConsentV1,
    proof: &'a dyn LocalProofConsent,
    roster: &'a Roster,
    action: PrivateWorkspaceActionV1,
    held: Option<&'a HeldDurableConstructionRosterV1<'held>>,
    observation: Option<&'a Observation>,
}
impl ArtifactGate<'_, '_, '_> {
    fn check(&self) -> Result<()> {
        let Some(boundary) = self.consent.fixed_permission_boundary_v3() else {
            return self.check_raw(self.consent, self.material);
        };
        // Held freshness brackets the COMPLETE compound, not merely the body.
        compound_held_result_v3(
            |site| self.check_held_at(site),
            || {
                let request = PrivateFixedPermissionRequestV3::new(
                    &self.workspace.scope,
                    self.action,
                    self.roster,
                    PrivateFixedPermissionKindV3::ArtifactCheck,
                )?;
                compound_artifact_check_v3(boundary, &request, |consent, material, _proof| {
                    self.check_raw(consent, material)
                })
            },
        )
    }
    fn check_held_at(&self, site: Site) -> Result<()> {
        if let Some(held) = self.held {
            held.check_current().map_err(|error| {
                if let Some(o) = self.observation {
                    o.record(site, diagnostics::construction(&error));
                }
                ApiError::from(error)
            })?;
        }
        Ok(())
    }
    // Original raw validators, including both old held checks. Never dispatch
    // another compound while this is called inside a permission callback.
    fn check_raw(
        &self,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<()> {
        if let Some(held) = self.held {
            held.check_current().map_err(|error| {
                if let Some(o) = self.observation {
                    o.record(Site::GateHeldPre, diagnostics::construction(&error));
                }
                ApiError::from(error)
            })?;
        }
        // The proof mutex may already be held: deliberately no source.check_current here.
        self.workspace
            .check_without_proof_lock_observed(self.access, consent, self.action, self.observation)
            .map_err(|error| {
                if let Some(o) = self.observation {
                    o.record(Site::GateWorkspace, diagnostics::engine(&error));
                }
                error
            })?;
        for intake in self.roster.owners.values() {
            self.workspace.check_intake_observed(
                self.observation,
                self.access,
                intake,
                material,
                DurableMaterialActionV1::ReadForExactConstruction,
            )?;
        }
        if let Some(held) = self.held {
            held.check_current().map_err(|error| {
                if let Some(o) = self.observation {
                    o.record(Site::GateHeldPost, diagnostics::construction(&error));
                }
                ApiError::from(error)
            })?;
        }
        Ok(())
    }
}
impl LocalProofConsent for ArtifactGate<'_, '_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        let exact = scope.principal_id == self.workspace.source.principal_id()
            && scope.local_operator == self.workspace.source.principal_id()
            && scope.retention_policy == self.workspace.scope.retention_policy
            && self.roster.owners.values().all(|intake| {
                intake.outbox.request().scope.purpose == scope.purpose
                    && intake.outbox.request().scope.proposal.proposal_id == scope.candidate_id
            })
            && scope.account_ids.iter().cloned().collect::<BTreeSet<_>>()
                == self
                    .workspace
                    .source
                    .reviewer_account_ids()
                    .into_iter()
                    .collect();
        let Some(boundary) = self.consent.fixed_permission_boundary_v3() else {
            return diagnostics::gate_chain(
                self.observation,
                exact,
                || self.check_raw(self.consent, self.material),
                || self.proof.permits(scope, action),
            );
        };
        if !exact {
            return diagnostics::gate_chain(
                self.observation,
                false,
                || self.check_raw(self.consent, self.material),
                || false,
            );
        }
        compound_held_result_v3(
            |site| self.check_held_at(site),
            || {
                let request = PrivateFixedPermissionRequestV3::new(
                    &self.workspace.scope,
                    self.action,
                    self.roster,
                    PrivateFixedPermissionKindV3::ArtifactPermission { scope, action },
                )?;
                if compound_artifact_permission_v3(
                    boundary,
                    &request,
                    |consent, material, proof| {
                        diagnostics::gate_chain(
                            self.observation,
                            exact,
                            || self.check_raw(consent, material),
                            || proof.permits(scope, action),
                        )
                    },
                ) {
                    Ok(())
                } else {
                    Err(denied())
                }
            },
        )
        .is_ok()
    }
}
// Typed arguments retain the actual lineage receipt, never a stage return value.
fn same_original_receipt_v2(
    actual: &crate::candidates::CheckpointReceipt,
    expected: &crate::candidates::CheckpointReceipt,
) -> Result<bool> {
    Ok(serde_json::to_value(actual).map_err(|_| damaged())?
        == serde_json::to_value(expected).map_err(|_| damaged())?)
}

#[cfg(test)]
#[path = "exact_fixed_v2_tests.rs"]
mod tests;

fn checkpoint_committed_error(mut error: ApiError, status: &PrivateWorkspaceStatusV1) -> ApiError {
    error.retryable = false;
    if !error.details.is_object() {
        error.details = Box::new(json!({}));
    }
    if let Some(details) = error.details.as_object_mut() {
        details.insert("constructor_receipt_created".into(), json!(true));
        details.insert("encrypted_checkpoint_created".into(), json!(true));
        details.insert("coordination_link_committed".into(), json!(true));
        details.insert("saved_revision".into(), json!(status.revision));
        details.insert("journals_are_atomic_together".into(), json!(false));
    }
    error
}

fn original_checkpoint_error(mut error: ApiError, summary: &JobSummary) -> ApiError {
    error.retryable = false;
    if !error.details.is_object() {
        error.details = Box::new(json!({}));
    }
    if let Some(details) = error.details.as_object_mut() {
        details.insert("encrypted_checkpoint_created".into(), json!(true));
        details.insert("proof_job_id".into(), json!(summary.job_id));
        details.insert("journals_are_atomic_together".into(), json!(false));
    }
    error.safe_actions=vec!["Inspect the exact saved original journals; no new randomness or proof attempt is authorized".into()];
    error
}

/// Inert, operation-local error observations. Never consulted by policy or effects.
pub(crate) mod diagnostics {
    use crate::{ApiError, Result};
    use serde::Serialize;
    use std::cell::{Cell, RefCell};
    pub(crate) const KEY: &str = "private_fixed_diagnostic_v1";
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    pub(crate) enum Operation {
        Checkpoint,
        Proof,
        Freeze,
        ReadFixed,
        OpenOriginal,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    pub(crate) enum Site {
        WorkspaceLoad,
        Candidate,
        MaterialRoster,
        SlotBindings,
        WalletRosterAcquire,
        HeldPrecheck,
        ConstructorReload,
        InputRequestDigest,
        OriginalRequest,
        OriginalLookup,
        OriginalLineage,
        ReplayLookup,
        Revision,
        CurrentTerms,
        ProposalValidation,
        ProtocolConstruct,
        ProtocolInspect,
        RetainConsent,
        ReceiptPrepare,
        ReceiptCommit,
        Enqueue,
        ReloadAfterEnqueue,
        LinkPrepare,
        LinkUpsert,
        LinkCommit,
        PostSource,
        PostConsent,
        HeldPostcheck,
        WalletRosterRelease,
        ContinuationBinding,
        ProofRun,
        ProofResultLineage,
        OutcomePrepare,
        OutcomeCommit,
        StatusLookup,
        LoadVerified,
        ProofVerifiedState,
        FixedMappings,
        FixedVerify,
        FixedReplayRead,
        FixedPrepare,
        FixedCommit,
        SavedDecode,
        OutputLineage,
        OperationHistory,
        ProofEventHistory,
        OutputCommitments,
        RetainedDiscovery,
        RetainedKey,
        ReloadAfterRead,
        EnvelopeCompare,
        JournalAfterRead,
        LogicalCompare,
        FinalGate,
        FinalProofOrigin,
        MetadataPreflight,
        MetadataOpen,
        SeedAudit,
        SourcePermission,
        MetadataOrigin,
        Marker,
        ProofOrigin,
        ExactScope,
        GateWorkspace,
        GateMaterial,
        GateHeldPre,
        GateHeldPost,
        GateProofConsent,
        SnapshotOpen,
        SnapshotOrigin,
        SnapshotSchema,
        SnapshotInventory,
        SnapshotSourceUnchanged,
        SeedPlan,
        SeedBinding,
        SeedReplay,
        SeedRecord,
        SeedOperation,
        SeedFinal,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    pub(crate) enum CallState {
        NotApplicable,
        NotCalled,
        ReturnedOk,
        ReturnedOkFresh,
        ReturnedOkReplay,
        ReturnedOkNoContinuation,
        ReturnedErrUnknown,
    }
    #[derive(Clone, Copy)]
    pub(crate) enum Call {
        Receipt,
        Enqueue,
        Link,
        Proof,
        Outcome,
        Freeze,
    }
    #[derive(Clone, Copy, Serialize)]
    struct Calls {
        receipt: CallState,
        enqueue: CallState,
        link: CallState,
        proof: CallState,
        outcome: CallState,
        freeze: CallState,
    }
    #[derive(Clone, Copy)]
    pub(crate) struct Cause {
        pub(crate) family: &'static str,
        pub(crate) cause: &'static str,
    }
    #[derive(Clone, Copy)]
    struct Failure {
        site: Site,
        cause: Cause,
    }
    pub(crate) struct Observation {
        operation: Operation,
        first: RefCell<Option<Failure>>,
        calls: RefCell<Calls>,
        available: Cell<bool>,
        consumed: Cell<bool>,
        current: Cell<Site>,
    }
    impl Observation {
        pub(crate) fn new(operation: Operation) -> Self {
            use CallState::*;
            let mut calls = Calls {
                receipt: NotApplicable,
                enqueue: NotApplicable,
                link: NotApplicable,
                proof: NotApplicable,
                outcome: NotApplicable,
                freeze: NotApplicable,
            };
            match operation {
                Operation::Checkpoint => {
                    calls.receipt = NotCalled;
                    calls.enqueue = NotCalled;
                    calls.link = NotCalled;
                }
                Operation::Proof => {
                    calls.proof = NotCalled;
                    calls.outcome = NotCalled;
                }
                Operation::Freeze => calls.freeze = NotCalled,
                Operation::ReadFixed | Operation::OpenOriginal => {}
            }
            Self {
                operation,
                first: RefCell::new(None),
                calls: RefCell::new(calls),
                available: Cell::new(true),
                consumed: Cell::new(false),
                current: Cell::new(Site::WorkspaceLoad),
            }
        }
        pub(crate) fn stage(&self, site: Site) {
            self.current.set(site);
        }
        pub(crate) fn site(&self) -> Site {
            self.current.get()
        }
        pub(crate) fn job_error(&self, error: wholepact_proof_jobs::JobError) -> ApiError {
            self.record(self.site(), job(&error));
            super::job_error(error)
        }
        pub(crate) fn consumed(&self) {
            self.consumed.set(true);
        }
        pub(crate) fn record(&self, site: Site, cause: Cause) {
            let cause = finite_cause(cause);
            match self.first.try_borrow_mut() {
                Ok(mut first) => {
                    if first.is_none() {
                        *first = Some(Failure { site, cause });
                    }
                }
                Err(_) => self.available.set(false),
            }
        }
        pub(crate) fn api<T>(&self, site: Site, result: Result<T>) -> Result<T> {
            if let Err(error) = &result {
                self.record(site, engine(error));
            }
            result
        }
        pub(crate) fn error(&self, site: Site, error: ApiError) -> ApiError {
            self.record(site, engine(&error));
            error
        }
        pub(crate) fn gate(&self, site: Site, cause: &'static str) {
            self.record(
                site,
                Cause {
                    family: "Gate",
                    cause,
                },
            );
        }
        pub(crate) fn call(&self, call: Call, state: CallState) {
            let valid = match call {
                Call::Receipt | Call::Link | Call::Outcome | Call::Freeze => matches!(
                    state,
                    CallState::ReturnedOkFresh
                        | CallState::ReturnedOkReplay
                        | CallState::ReturnedErrUnknown
                ),
                Call::Enqueue => matches!(
                    state,
                    CallState::ReturnedOkFresh
                        | CallState::ReturnedOkNoContinuation
                        | CallState::ReturnedErrUnknown
                ),
                Call::Proof => {
                    matches!(state, CallState::ReturnedOk | CallState::ReturnedErrUnknown)
                }
            };
            if !valid {
                self.available.set(false);
                return;
            }
            match self.calls.try_borrow_mut() {
                Ok(mut calls) => {
                    let slot = match call {
                        Call::Receipt => &mut calls.receipt,
                        Call::Enqueue => &mut calls.enqueue,
                        Call::Link => &mut calls.link,
                        Call::Proof => &mut calls.proof,
                        Call::Outcome => &mut calls.outcome,
                        Call::Freeze => &mut calls.freeze,
                    };
                    if *slot == CallState::NotCalled {
                        *slot = state;
                    }
                }
                Err(_) => self.available.set(false),
            }
        }
        pub(crate) fn store_call(
            &self,
            site: Site,
            call: Call,
            result: &wholepact_store::Result<wholepact_store::MutationResult>,
        ) {
            match result {
                Ok(saved) => self.call(
                    call,
                    if saved.replayed {
                        CallState::ReturnedOkReplay
                    } else {
                        CallState::ReturnedOkFresh
                    },
                ),
                Err(error) => {
                    self.call(call, CallState::ReturnedErrUnknown);
                    self.record(site, store(error));
                }
            }
        }
        #[cfg(test)]
        pub(super) fn record_while_borrowed_for_test(&self, error: &ApiError) {
            let _held = self.first.borrow_mut();
            self.record(Site::FinalGate, engine(error));
        }
        pub(super) fn construction_result<T>(
            &self,
            site: Site,
            result: std::result::Result<
                T,
                wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError,
            >,
        ) -> Result<T> {
            result.map_err(|error| {
                self.record(site, construction(&error));
                ApiError::from(error)
            })
        }
        /// Observation only: these reads do not execute checkpoint effects.
        /// No CALL or consumed fields may escape from this finish path.
        pub(super) fn finish_cause_only<T>(&self, result: Result<T>) -> Result<T> {
            match result {
                Ok(value) => Ok(value),
                Err(mut error) => {
                    const CAUSE_KEY: &str = "private_fixed_observation_cause_v1";
                    self.record(self.site(), engine(&error));
                    if !self.available.get()
                        || error.details.get(CAUSE_KEY).is_some()
                        || error.details.get(KEY).is_some()
                        || !error.details.is_object()
                    {
                        return Err(error);
                    }
                    let Ok(first) = self.first.try_borrow() else {
                        return Err(error);
                    };
                    let Some(first) = *first else {
                        return Err(error);
                    };
                    let value = serde_json::json!({
                        "schema":1,"operation":self.operation,"site":first.site,
                        "engine_code":engine_code(&error.code),
                        "family":first.cause.family,"cause":first.cause.cause
                    });
                    if serde_json::to_vec(&value)
                        .ok()
                        .is_some_and(|bytes| bytes.len() <= 4096)
                    {
                        if let Some(details) = error.details.as_object_mut() {
                            details.entry(CAUSE_KEY.to_owned()).or_insert(value);
                        }
                    }
                    Err(error)
                }
            }
        }
        pub(crate) fn finish<T>(&self, result: Result<T>) -> Result<T> {
            match result {
                Ok(value) => Ok(value),
                Err(mut error) => {
                    self.record(self.site(), engine(&error));
                    if !self.available.get()
                        || error.details.get(KEY).is_some()
                        || !error.details.is_object()
                    {
                        return Err(error);
                    }
                    let (Ok(first), Ok(calls)) = (self.first.try_borrow(), self.calls.try_borrow())
                    else {
                        return Err(error);
                    };
                    let Some(first) = *first else {
                        return Err(error);
                    };
                    if (self.operation == Operation::Proof) != self.consumed.get() {
                        return Err(error);
                    }
                    let value = serde_json::json!({"schema":1,"operation":self.operation,"site":first.site,"engine_code":engine_code(&error.code),"family":first.cause.family,"cause":first.cause.cause,"calls":*calls,"attempt_consumed":self.consumed.get(),"call_scope":"CurrentInvocation"});
                    if serde_json::to_vec(&value)
                        .ok()
                        .is_some_and(|bytes| bytes.len() <= 4096)
                    {
                        if let Some(details) = error.details.as_object_mut() {
                            details.entry(KEY.to_owned()).or_insert(value);
                        }
                    }
                    Err(error)
                }
            }
        }
    }
    /// Same short-circuit kernel for observed and unobserved permission gates.
    pub(crate) fn gate_chain(
        observation: Option<&Observation>,
        exact: bool,
        mut check: impl FnMut() -> Result<()>,
        permission: impl FnOnce() -> bool,
    ) -> bool {
        if !exact {
            if let Some(o) = observation {
                o.gate(Site::ExactScope, "ExactScopeMismatch");
            }
            return false;
        }
        let before = check();
        if let Err(error) = &before {
            if let Some(o) = observation {
                o.record(Site::GateHeldPre, engine(error));
            }
        }
        if before.is_err() {
            return false;
        }
        if !permission() {
            if let Some(o) = observation {
                o.gate(Site::GateProofConsent, "ProofConsentFalse");
            }
            return false;
        }
        let after = check();
        if let Err(error) = &after {
            if let Some(o) = observation {
                o.record(Site::GateHeldPost, engine(error));
            }
        }
        after.is_ok()
    }
    // A closed vocabulary even if an internal caller accidentally supplies an unknown static label.
    fn finite_cause(value: Cause) -> Cause {
        match (value.family, value.cause) {
            (
                "Engine",
                "DISCLOSURE_DENIED"
                | "DURABLE_CONSTRUCTION_UNAVAILABLE"
                | "DURABLE_PROPOSAL_RECOVERY_REQUIRED"
                | "DURABLE_PROPOSAL_CONFLICT"
                | "DURABLE_PROPOSAL_NOT_FOUND"
                | "DURABLE_PROFILE_UNAVAILABLE"
                | "MANUAL_CONSTRUCTION_DENIED"
                | "RETAINED_INPUT_OBSERVATION_UNAVAILABLE"
                | "CANDIDATE_VERIFICATION_FAILED"
                | "IDEMPOTENCY_CONFLICT"
                | "REVISION_CONFLICT"
                | "NOT_FOUND"
                | "INVALID_REQUEST"
                | "RECOVERY_REQUIRED"
                | "LIVE_AUTHORIZATION_EXISTS"
                | "RESOURCE_EXHAUSTED"
                | "INVALID_TRANSITION"
                | "STORAGE_PROTECTION_REQUIRED"
                | "STORAGE_UNAVAILABLE"
                | "ACCESS_DENIED"
                | "INVALID_TERMS"
                | "UNSUPPORTED_CAPABILITY"
                | "MISSING_EVIDENCE"
                | "INVALID_AMOUNT"
                | "UNKNOWN_PARTICIPANT"
                | "DUPLICATE_IDENTIFIER"
                | "CONSERVATION_FAILURE"
                | "DEBIT_CAP_EXCEEDED"
                | "FEE_CAP_EXCEEDED"
                | "UNVERIFIABLE_MATCH"
                | "PRIVACY_INCOMPATIBLE"
                | "UNSUPPORTED_VERSION"
                | "RESOURCE_LIMIT"
                | "STALE_CHAIN"
                | "OUTSTANDING_EXPOSURE"
                | "USER_REJECTED"
                | "INTERNAL_ERROR"
                | "Unclassified"
                | "PERMISSION_DENIED",
            ) => value,
            (
                "DurableConstruction",
                "Invalid" | "Binding" | "Stale" | "Storage" | "Unclassified",
            ) => value,
            (
                "Sync",
                "AccessDenied"
                | "InvalidRequest"
                | "Interrupted"
                | "ReconciliationRequired"
                | "InvalidResponse"
                | "ResourceLimit"
                | "NoCurrentObservation"
                | "Unclassified",
            ) => value,
            (
                "Wallet",
                "Storage" | "AccountScope" | "AccountMismatch" | "IncompleteSync"
                | "UnsupportedProfile" | "ChainMismatch" | "InsufficientFunds" | "InvalidRequest"
                | "MissingWitness" | "InvalidNote" | "Scan" | "Transport" | "Unclassified",
            ) => value,
            (
                "Chain",
                "InvalidConfiguration"
                | "WrongNetwork"
                | "UnsupportedProxyConfiguration"
                | "WrongBranch"
                | "StaleChain"
                | "ContradictoryChain"
                | "Timeout"
                | "TransportUnavailable"
                | "ObservationInterrupted"
                | "MissingAncestryEvidence"
                | "NotObserved"
                | "ResourceLimit"
                | "MalformedEvidence"
                | "UnsupportedCapability"
                | "BackendFailure"
                | "ClockUnavailable"
                | "IdempotencyConflict"
                | "JournalFailure"
                | "SubmissionNotAuthorized"
                | "SubmissionExpiryMargin"
                | "ObligationConflict"
                | "SubmissionOutcomeUnrecorded"
                | "SubmissionRetentionUncertain"
                | "Unclassified",
            ) => value,
            (
                "Protocol",
                "Manifest"
                | "Disclosure"
                | "Context"
                | "Contribution"
                | "Input"
                | "Output"
                | "Fee"
                | "BuilderInput"
                | "BuilderOutput"
                | "Pczt"
                | "Finalize"
                | "ActionMapping"
                | "FixedBudget"
                | "FixedOwners"
                | "FixedRecipient"
                | "FixedPolicy"
                | "FixedAccounting"
                | "FixedRealInput"
                | "FixedCanonicalAccount"
                | "FixedDistinctAccounts"
                | "FixedUnsignedPredecessor"
                | "FixedUnsignedRealInput"
                | "FixedProofOnlyTransition"
                | "FixedPaddingSignature"
                | "Unclassified",
            ) => value,
            (
                "Store",
                "StorageSecurity"
                | "Database"
                | "Encoding"
                | "Poisoned"
                | "IdempotencyConflict"
                | "RevisionConflict"
                | "NotFound"
                | "AlreadyExists"
                | "InvalidInput"
                | "UnsupportedSchema"
                | "RecoveryRequired"
                | "WriterEpochMismatch"
                | "LiveAuthorizationExists"
                | "InputReserved"
                | "ResourceExhausted"
                | "BudgetExceeded"
                | "InvalidTransition"
                | "File"
                | "Unclassified",
            ) => value,
            (
                "StorageSecurity",
                "UnsupportedPlatform"
                | "QuarantinedDatabase"
                | "RecoveredGeneration"
                | "GenerationArchive"
                | "UninitializedDatabase"
                | "UnsafePath"
                | "AlreadyExists"
                | "MissingDatabase"
                | "PlaintextRefused"
                | "UnqualifiedRuntime"
                | "AuthenticationFailed"
                | "Database"
                | "Io"
                | "SnapshotLimit"
                | "SourceChanged"
                | "Unclassified",
            ) => value,
            (
                "Job",
                "ConsentDenied"
                | "NotFound"
                | "InvalidRequest"
                | "VerificationFailed"
                | "IdempotencyConflict"
                | "RecoveryRequired"
                | "StateConflict"
                | "Storage"
                | "UnsupportedSchema"
                | "ResourceExhausted"
                | "Unclassified",
            ) => value,
            (
                "Gate",
                "ExactScopeMismatch"
                | "WorkspaceConsentFalse"
                | "MaterialConsentFalse"
                | "ProofConsentFalse"
                | "Unclassified",
            ) => value,
            _ => Cause {
                family: "Engine",
                cause: "Unclassified",
            },
        }
    }
    pub(crate) fn engine(error: &ApiError) -> Cause {
        Cause {
            family: "Engine",
            cause: engine_code(&error.code),
        }
    }
    pub(crate) fn engine_code(code: &str) -> &'static str {
        match code {
            "DISCLOSURE_DENIED" => "DISCLOSURE_DENIED",
            "DURABLE_CONSTRUCTION_UNAVAILABLE" => "DURABLE_CONSTRUCTION_UNAVAILABLE",
            "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => "DURABLE_PROPOSAL_RECOVERY_REQUIRED",
            "DURABLE_PROPOSAL_CONFLICT" => "DURABLE_PROPOSAL_CONFLICT",
            "DURABLE_PROPOSAL_NOT_FOUND" => "DURABLE_PROPOSAL_NOT_FOUND",
            "DURABLE_PROFILE_UNAVAILABLE" => "DURABLE_PROFILE_UNAVAILABLE",
            "MANUAL_CONSTRUCTION_DENIED" => "MANUAL_CONSTRUCTION_DENIED",
            "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => "RETAINED_INPUT_OBSERVATION_UNAVAILABLE",
            "CANDIDATE_VERIFICATION_FAILED" => "CANDIDATE_VERIFICATION_FAILED",
            "IDEMPOTENCY_CONFLICT" => "IDEMPOTENCY_CONFLICT",
            "REVISION_CONFLICT" => "REVISION_CONFLICT",
            "NOT_FOUND" => "NOT_FOUND",
            "INVALID_REQUEST" => "INVALID_REQUEST",
            "RECOVERY_REQUIRED" => "RECOVERY_REQUIRED",
            "LIVE_AUTHORIZATION_EXISTS" => "LIVE_AUTHORIZATION_EXISTS",
            "RESOURCE_EXHAUSTED" => "RESOURCE_EXHAUSTED",
            "INVALID_TRANSITION" => "INVALID_TRANSITION",
            "STORAGE_PROTECTION_REQUIRED" => "STORAGE_PROTECTION_REQUIRED",
            "STORAGE_UNAVAILABLE" => "STORAGE_UNAVAILABLE",
            "ACCESS_DENIED" => "ACCESS_DENIED",
            "INVALID_TERMS" => "INVALID_TERMS",
            "UNSUPPORTED_CAPABILITY" => "UNSUPPORTED_CAPABILITY",
            "MISSING_EVIDENCE" => "MISSING_EVIDENCE",
            "INVALID_AMOUNT" => "INVALID_AMOUNT",
            "UNKNOWN_PARTICIPANT" => "UNKNOWN_PARTICIPANT",
            "DUPLICATE_IDENTIFIER" => "DUPLICATE_IDENTIFIER",
            "CONSERVATION_FAILURE" => "CONSERVATION_FAILURE",
            "DEBIT_CAP_EXCEEDED" => "DEBIT_CAP_EXCEEDED",
            "FEE_CAP_EXCEEDED" => "FEE_CAP_EXCEEDED",
            "UNVERIFIABLE_MATCH" => "UNVERIFIABLE_MATCH",
            "PRIVACY_INCOMPATIBLE" => "PRIVACY_INCOMPATIBLE",
            "UNSUPPORTED_VERSION" => "UNSUPPORTED_VERSION",
            "RESOURCE_LIMIT" => "RESOURCE_LIMIT",
            "STALE_CHAIN" => "STALE_CHAIN",
            "OUTSTANDING_EXPOSURE" => "OUTSTANDING_EXPOSURE",
            "USER_REJECTED" => "USER_REJECTED",
            "INTERNAL_ERROR" => "INTERNAL_ERROR",
            "PERMISSION_DENIED" => "PERMISSION_DENIED",
            _ => "Unclassified",
        }
    }
    pub(crate) fn security(error: &wholepact_storage_security::StorageSecurityError) -> Cause {
        use wholepact_storage_security::StorageSecurityError::*;
        match error {
            UnsupportedPlatform => Cause {
                family: "StorageSecurity",
                cause: "UnsupportedPlatform",
            },
            QuarantinedDatabase => Cause {
                family: "StorageSecurity",
                cause: "QuarantinedDatabase",
            },
            RecoveredGeneration => Cause {
                family: "StorageSecurity",
                cause: "RecoveredGeneration",
            },
            GenerationArchive => Cause {
                family: "StorageSecurity",
                cause: "GenerationArchive",
            },
            UninitializedDatabase => Cause {
                family: "StorageSecurity",
                cause: "UninitializedDatabase",
            },
            UnsafePath => Cause {
                family: "StorageSecurity",
                cause: "UnsafePath",
            },
            AlreadyExists => Cause {
                family: "StorageSecurity",
                cause: "AlreadyExists",
            },
            MissingDatabase => Cause {
                family: "StorageSecurity",
                cause: "MissingDatabase",
            },
            PlaintextRefused => Cause {
                family: "StorageSecurity",
                cause: "PlaintextRefused",
            },
            UnqualifiedRuntime => Cause {
                family: "StorageSecurity",
                cause: "UnqualifiedRuntime",
            },
            AuthenticationFailed => Cause {
                family: "StorageSecurity",
                cause: "AuthenticationFailed",
            },
            Database => Cause {
                family: "StorageSecurity",
                cause: "Database",
            },
            Io => Cause {
                family: "StorageSecurity",
                cause: "Io",
            },
            SnapshotLimit => Cause {
                family: "StorageSecurity",
                cause: "SnapshotLimit",
            },
            SourceChanged => Cause {
                family: "StorageSecurity",
                cause: "SourceChanged",
            },
        }
    }
    pub(crate) fn store(error: &wholepact_store::StoreError) -> Cause {
        use wholepact_store::StoreError::*;
        match error {
            StorageSecurity(error) => security(error),
            Database(_) => Cause {
                family: "Store",
                cause: "Database",
            },
            Encoding(_) => Cause {
                family: "Store",
                cause: "Encoding",
            },
            Poisoned => Cause {
                family: "Store",
                cause: "Poisoned",
            },
            IdempotencyConflict => Cause {
                family: "Store",
                cause: "IdempotencyConflict",
            },
            RevisionConflict => Cause {
                family: "Store",
                cause: "RevisionConflict",
            },
            NotFound => Cause {
                family: "Store",
                cause: "NotFound",
            },
            AlreadyExists => Cause {
                family: "Store",
                cause: "AlreadyExists",
            },
            InvalidInput(_) => Cause {
                family: "Store",
                cause: "InvalidInput",
            },
            UnsupportedSchema(_) => Cause {
                family: "Store",
                cause: "UnsupportedSchema",
            },
            RecoveryRequired => Cause {
                family: "Store",
                cause: "RecoveryRequired",
            },
            WriterEpochMismatch => Cause {
                family: "Store",
                cause: "WriterEpochMismatch",
            },
            LiveAuthorizationExists => Cause {
                family: "Store",
                cause: "LiveAuthorizationExists",
            },
            InputReserved => Cause {
                family: "Store",
                cause: "InputReserved",
            },
            ResourceExhausted => Cause {
                family: "Store",
                cause: "ResourceExhausted",
            },
            BudgetExceeded => Cause {
                family: "Store",
                cause: "BudgetExceeded",
            },
            InvalidTransition => Cause {
                family: "Store",
                cause: "InvalidTransition",
            },
            File(_) => Cause {
                family: "Store",
                cause: "File",
            },
        }
    }
    pub(crate) fn job(error: &wholepact_proof_jobs::JobError) -> Cause {
        use wholepact_proof_jobs::JobError::*;
        match error {
            ConsentDenied => Cause {
                family: "Job",
                cause: "ConsentDenied",
            },
            NotFound => Cause {
                family: "Job",
                cause: "NotFound",
            },
            InvalidRequest => Cause {
                family: "Job",
                cause: "InvalidRequest",
            },
            VerificationFailed => Cause {
                family: "Job",
                cause: "VerificationFailed",
            },
            IdempotencyConflict => Cause {
                family: "Job",
                cause: "IdempotencyConflict",
            },
            RecoveryRequired => Cause {
                family: "Job",
                cause: "RecoveryRequired",
            },
            StateConflict => Cause {
                family: "Job",
                cause: "StateConflict",
            },
            Storage => Cause {
                family: "Job",
                cause: "Storage",
            },
            UnsupportedSchema => Cause {
                family: "Job",
                cause: "UnsupportedSchema",
            },
            ResourceExhausted => Cause {
                family: "Job",
                cause: "ResourceExhausted",
            },
        }
    }
    pub(crate) fn wallet(error: &wholepact_wallet::wallet::WalletError) -> Cause {
        use wholepact_wallet::wallet::WalletError::*;
        match error {
            Storage => Cause {
                family: "Wallet",
                cause: "Storage",
            },
            AccountScope => Cause {
                family: "Wallet",
                cause: "AccountScope",
            },
            AccountMismatch => Cause {
                family: "Wallet",
                cause: "AccountMismatch",
            },
            IncompleteSync => Cause {
                family: "Wallet",
                cause: "IncompleteSync",
            },
            UnsupportedProfile => Cause {
                family: "Wallet",
                cause: "UnsupportedProfile",
            },
            ChainMismatch => Cause {
                family: "Wallet",
                cause: "ChainMismatch",
            },
            InsufficientFunds => Cause {
                family: "Wallet",
                cause: "InsufficientFunds",
            },
            InvalidRequest => Cause {
                family: "Wallet",
                cause: "InvalidRequest",
            },
            MissingWitness => Cause {
                family: "Wallet",
                cause: "MissingWitness",
            },
            InvalidNote => Cause {
                family: "Wallet",
                cause: "InvalidNote",
            },
            Scan => Cause {
                family: "Wallet",
                cause: "Scan",
            },
            Transport => Cause {
                family: "Wallet",
                cause: "Transport",
            },
        }
    }
    pub(crate) fn chain(error: &wholepact_chain::ChainError) -> Cause {
        use wholepact_chain::ChainError::*;
        match error {
            InvalidConfiguration => Cause {
                family: "Chain",
                cause: "InvalidConfiguration",
            },
            WrongNetwork => Cause {
                family: "Chain",
                cause: "WrongNetwork",
            },
            UnsupportedProxyConfiguration => Cause {
                family: "Chain",
                cause: "UnsupportedProxyConfiguration",
            },
            WrongBranch => Cause {
                family: "Chain",
                cause: "WrongBranch",
            },
            StaleChain => Cause {
                family: "Chain",
                cause: "StaleChain",
            },
            ContradictoryChain => Cause {
                family: "Chain",
                cause: "ContradictoryChain",
            },
            Timeout => Cause {
                family: "Chain",
                cause: "Timeout",
            },
            TransportUnavailable => Cause {
                family: "Chain",
                cause: "TransportUnavailable",
            },
            ObservationInterrupted => Cause {
                family: "Chain",
                cause: "ObservationInterrupted",
            },
            MissingAncestryEvidence => Cause {
                family: "Chain",
                cause: "MissingAncestryEvidence",
            },
            NotObserved => Cause {
                family: "Chain",
                cause: "NotObserved",
            },
            ResourceLimit => Cause {
                family: "Chain",
                cause: "ResourceLimit",
            },
            MalformedEvidence => Cause {
                family: "Chain",
                cause: "MalformedEvidence",
            },
            UnsupportedCapability => Cause {
                family: "Chain",
                cause: "UnsupportedCapability",
            },
            BackendFailure { .. } => Cause {
                family: "Chain",
                cause: "BackendFailure",
            },
            ClockUnavailable => Cause {
                family: "Chain",
                cause: "ClockUnavailable",
            },
            IdempotencyConflict => Cause {
                family: "Chain",
                cause: "IdempotencyConflict",
            },
            JournalFailure => Cause {
                family: "Chain",
                cause: "JournalFailure",
            },
            SubmissionNotAuthorized => Cause {
                family: "Chain",
                cause: "SubmissionNotAuthorized",
            },
            SubmissionExpiryMargin => Cause {
                family: "Chain",
                cause: "SubmissionExpiryMargin",
            },
            ObligationConflict => Cause {
                family: "Chain",
                cause: "ObligationConflict",
            },
            SubmissionOutcomeUnrecorded => Cause {
                family: "Chain",
                cause: "SubmissionOutcomeUnrecorded",
            },
            SubmissionRetentionUncertain => Cause {
                family: "Chain",
                cause: "SubmissionRetentionUncertain",
            },
        }
    }
    pub(crate) fn sync(error: &wholepact_wallet::wallet::protected_sync::SyncError) -> Cause {
        use wholepact_wallet::wallet::protected_sync::SyncError::*;
        match error {
            Wallet(e) => wallet(e),
            Chain(e) => chain(e),
            AccessDenied => Cause {
                family: "Sync",
                cause: "AccessDenied",
            },
            InvalidRequest => Cause {
                family: "Sync",
                cause: "InvalidRequest",
            },
            Interrupted => Cause {
                family: "Sync",
                cause: "Interrupted",
            },
            ReconciliationRequired => Cause {
                family: "Sync",
                cause: "ReconciliationRequired",
            },
            InvalidResponse => Cause {
                family: "Sync",
                cause: "InvalidResponse",
            },
            ResourceLimit => Cause {
                family: "Sync",
                cause: "ResourceLimit",
            },
            NoCurrentObservation => Cause {
                family: "Sync",
                cause: "NoCurrentObservation",
            },
        }
    }
    pub(crate) fn construction(
        error:&wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError,
    ) -> Cause {
        use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError::*;
        match error {
            Sync(e) => sync(e),
            Invalid => Cause {
                family: "DurableConstruction",
                cause: "Invalid",
            },
            Binding => Cause {
                family: "DurableConstruction",
                cause: "Binding",
            },
            Stale => Cause {
                family: "DurableConstruction",
                cause: "Stale",
            },
            Storage => Cause {
                family: "DurableConstruction",
                cause: "Storage",
            },
        }
    }
    pub(crate) fn protocol(error: &str) -> Cause {
        Cause {
            family: "Protocol",
            cause: match error {
                "Accepted manifest accounting is invalid" => "Manifest",
                "Unsupported construction network profile" => "Manifest",
                "Construction does not qualify manifest extensions or conditional matching" => {
                    "Manifest"
                }
                "Construction does not qualify service charges" => "Manifest",
                "Construction supports at most 64 real inputs/outputs" => "Manifest",
                "Broad-witness construction requires declared operator and dedicated accounts" => {
                    "Manifest"
                }
                "Declared construction/proving operator missing" => "Disclosure",
                "Manifest digest encoding" => "Disclosure",
                "Manifest digest length" => "Disclosure",
                "Every account must have a disclosure declaration" => "Disclosure",
                "Broad-review disclosure requires the exact complete participant reviewer roster" => {
                    "Disclosure"
                }
                "Disclosure declaration is missing, duplicated or differs from accepted scope" => {
                    "Disclosure"
                }
                "Invalid anchor context" => "Context",
                "Expiry must cover target height and be a block-height expiry" => "Context",
                "Target and expiry must remain within the qualified testnet NU7 branch" => {
                    "Context"
                }
                "Invalid Ironwood anchor" => "Context",
                "Exactly one contribution package is required per participant" => "Contribution",
                "Total selected note count exceeds 64" => "Contribution",
                "Contribution lacks an exact disclosure declaration" => "Contribution",
                "Contribution note count outside 1..=64" => "Contribution",
                "Change address is not internal-scope account property" => "Contribution",
                "Same FVK cannot occupy multiple participant accounts" => "Contribution",
                "Duplicate account contribution" => "Contribution",
                "Accepted participant contribution missing" => "Contribution",
                "Every selected note must be value-bearing Ironwood V3" => "Input",
                "Selected note is not owned by declared FVK" => "Input",
                "Selected note witness differs from common anchor" => "Input",
                "Duplicate real note/nullifier" => "Input",
                "Duplicate selected input ID" => "Input",
                "Selected notes do not exactly cover accepted inputs" => "Input",
                "Input account package missing" => "Input",
                "Accepted input does not identify a selected note" => "Input",
                "Actual selected input amount differs from accepted manifest" => "Input",
                "Input participant missing" => "Input",
                "Accepted recipient missing" => "Output",
                "Invalid recipient memo" => "Output",
                "Return account missing" => "Output",
                "Accepted return receiver differs from account internal change" => "Output",
                "Return participant missing" => "Output",
                "Unqualified service charge" => "Output",
                "Output amount range" => "Output",
                "Unable to calculate exact ZIP317 fee" => "Fee",
                "Accepted fee differs from ZIP317 fee for actual padded transaction shape; revise terms explicitly" => {
                    "Fee"
                }
                "Upstream rejected a selected Ironwood input" => "BuilderInput",
                "Upstream rejected an Ironwood output" => "BuilderOutput",
                "Upstream PCZT construction failed" => "Pczt",
                "Unsupported PCZT parts" => "Pczt",
                "PCZT v2 serialization unsupported" => "Pczt",
                "Upstream IO finalization failed" => "Finalize",
                "Missing randomized input action mapping" => "ActionMapping",
                "Missing randomized output action mapping" => "ActionMapping",
                "Durable proving action budget must be in 1..=8" => "FixedBudget",
                "Durable proposal exceeds explicit proving action budget" => "FixedBudget",
                "Durable fixed proposal requires exactly two owners" => "FixedOwners",
                "Durable fixed proposal requires exactly one recipient" => "FixedRecipient",
                "Durable policy allocation limit exceeded" => "FixedPolicy",
                "Durable manifest accounting is invalid" => "FixedAccounting",
                "Each durable owner must have a selected real input" => "FixedRealInput",
                "Durable input action is outside the artifact" => "FixedRealInput",
                "Durable account ID is not canonical for its actual viewing key" => {
                    "FixedCanonicalAccount"
                }
                "Durable accounts must have distinct account IDs and viewing keys" => {
                    "FixedDistinctAccounts"
                }
                "Durable PCZT parse failed" => "Pczt",
                "Durable PCZT canonical encoding failed" => "Pczt",
                "Durable predecessor must be unproved and successor must contain a proof" => {
                    "FixedUnsignedPredecessor"
                }
                "Durable proposal real inputs must be unsigned before proof acceptance" => {
                    "FixedUnsignedRealInput"
                }
                "Durable proved artifact differs from its exact unsigned predecessor" => {
                    "FixedProofOnlyTransition"
                }
                "Padding signature verifier initialization failed" => "FixedPaddingSignature",
                "Fixed proposal is missing a retained padding signature" => "FixedPaddingSignature",
                "Fixed proposal retained padding signature is invalid" => "FixedPaddingSignature",
                "Action mappings differ from the exact fixed proposal" => "ActionMapping",
                _ => "Unclassified",
            },
        }
    }
    pub(crate) fn store_error(
        observation: Option<&Observation>,
        site: Site,
        error: wholepact_store::StoreError,
    ) -> ApiError {
        if let Some(o) = observation {
            o.record(site, store(&error));
        }
        crate::store_error(error)
    }
    pub(crate) fn job_error(
        observation: Option<&Observation>,
        site: Site,
        error: wholepact_proof_jobs::JobError,
    ) -> ApiError {
        if let Some(observation) = observation {
            observation.record(site, job(&error));
        }
        super::job_error(error)
    }
    pub(crate) enum RosterError {
        Engine(ApiError), Wallet(wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError) }
    impl From<ApiError> for RosterError {
        fn from(e: ApiError) -> Self {
            Self::Engine(e)
        }
    }
    impl From<wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError> for RosterError {
    fn from(e:wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError)->Self{Self::Wallet(e)}
}
    impl RosterError {
        pub(crate) fn into_api(self, o: &Observation, site: Site) -> ApiError {
            match self {
                Self::Engine(e) => o.error(site, e),
                Self::Wallet(e) => {
                    o.record(site, construction(&e));
                    e.into()
                }
            }
        }
    }
}
