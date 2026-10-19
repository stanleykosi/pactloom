//! Exclusive source-owned private fixed-proof coordinator.
//! The exact native dependency/consent composition remains required for use.
//! This exclusive facade, not a shared Engine redaction convention,
//! is the privacy boundary. Original association is history, never spending power.
use crate::durable_input_projections_v1::{
    DurableDiscoveryRoundRequestV1, DurableDiscoveryRoundSummaryV1, LocalDurableDiscoveryConsentV1,
};
use crate::manual_enrollment::ManualRosterIntentTarget;
use crate::{Access, ApiError, Engine, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use wholepact_core::{AgreementDraft, ParticipationIntent};
use wholepact_storage_security::DatabaseKey;
use wholepact_store::manual_enrollment::ManualEnrollmentRosterMember;
use wholepact_store::private_workspace_origin_v1::PrivateWorkspaceOriginV1;

mod exact_fixed_v2;
#[path = "durable_private_workspace_v1/operation_v1.rs"]
mod operation_v1;
pub use exact_fixed_v2::{
    OriginalCheckpointOutcomeV2, OriginalProofAttemptV2, PrivateExactCandidateV2,
    PrivateFixedStatusV2, PrivateVerifiedFixedV2,
};

fn denied() -> ApiError {
    ApiError::new(
        "DISCLOSURE_DENIED",
        "Exact original workspace, source principal and current native privacy permission are required",
    )
}
fn damaged() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Preserve the original private dependency, key, directory and journals; no replacement workspace was created",
    )
}

/// Inert private seed. Never deserializable or returned as a generic projection.
/// Previous terms are necessary to preserve the original terms revision, and
/// must be covered by native privacy review. No original candidate, receipt,
/// authority, reservation, proof, operation or exposure history is copied.
#[derive(Serialize)]
struct PrivateWorkspaceSeedV1 {
    agreement: AgreementDraft,
    terms_history: Vec<AgreementDraft>,
    intents: Vec<ParticipationIntent>,
    intent_owners: BTreeMap<String, String>,
    owner_client_id: String,
    roster_binding: wholepact_core::manual_roster_v2::HostRosterAppendBindingV2,
    selected_members: Vec<ManualEnrollmentRosterMember>,
}

/// Nominal actual source ownership. There is no caller-data constructor, Clone,
/// Deserialize, raw Engine/Envelope access, or conversion to financial authority.
pub struct PrivateDurableWorkspaceSourceV1<'source> {
    engine: &'source Engine,
    target: ManualRosterIntentTarget<'source>,
    seed: PrivateWorkspaceSeedV1,
    seed_digest: String,
}
impl Engine {
    /// Public original-only nominal source, deliberately not an Engine getter.
    pub fn original_private_workspace_source_v1<'source>(
        &'source self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<PrivateDurableWorkspaceSourceV1<'source>> {
        self.private_durable_workspace_source_v1(access, agreement_id)
    }
    /// Read-only source getter. Does not admit discovery on this shared Engine.
    pub(crate) fn private_durable_workspace_source_v1<'source>(
        &'source self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<PrivateDurableWorkspaceSourceV1<'source>> {
        let target = self.manual_roster_intent_target(access, agreement_id)?;
        let seed = selected_seed(self, &target, access)?;
        let seed_digest = seed_digest(&seed)?;
        let source = PrivateDurableWorkspaceSourceV1 {
            engine: self,
            target,
            seed,
            seed_digest,
        };
        source.check_current(access)?;
        Ok(source)
    }
}
fn selected_seed(
    engine: &Engine,
    target: &ManualRosterIntentTarget<'_>,
    access: &Access,
) -> Result<PrivateWorkspaceSeedV1> {
    target.check_current(access)?;
    let envelope = engine.load(access, &target.agreement().agreement_id)?;
    crate::planning::check_proposer(&envelope, access)?;
    if target.principal_id() != access.principal_id
        || target.owner_client_id() != access.principal_id
        || envelope.view.agreement != *target.agreement()
        || !envelope.view.roster_selected
        || envelope.view.cancellation_requested
        || envelope
            .view
            .agreement
            .privacy_profile
            .proving_operator
            .as_deref()
            != Some(access.principal_id.as_str())
    {
        return Err(denied());
    }
    crate::terms_revisions::validate_history(&envelope.view)?;
    let intents = crate::planning::preview_intents(&envelope.view)?
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    if intents.len() != 2 {
        return Err(denied());
    }
    // One actual checked roster snapshot, kept alive through all selections.
    let actual_members = target.members(access)?.to_vec();
    let mut members = Vec::new();
    let mut owners = BTreeMap::new();
    let mut accounts = BTreeSet::new();
    for intent in &intents {
        let matching = actual_members
            .iter()
            .filter(|member| {
                member.scope.agreement_id == envelope.view.agreement.agreement_id
                    && member.scope.obligation_id == envelope.view.agreement.obligation_id
                    && member.scope.participant_id == intent.participant_id
                    && member.scope.principal_id == access.principal_id
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 || !accounts.insert(matching[0].identity.account_id.clone()) {
            return Err(denied());
        }
        members.push(matching[0].clone());
        owners.insert(
            intent.intent_id.clone(),
            envelope
                .intent_owners
                .get(&intent.intent_id)
                .ok_or_else(damaged)?
                .clone(),
        );
    }
    members.sort_by(|a, b| a.identity.account_id.cmp(&b.identity.account_id));
    target.check_current(access)?;
    Ok(PrivateWorkspaceSeedV1 {
        agreement: envelope.view.agreement,
        terms_history: envelope.view.terms_history,
        intents,
        intent_owners: owners,
        owner_client_id: envelope.owner_client_id,
        roster_binding: target.binding().clone(),
        selected_members: members,
    })
}
fn seed_digest(seed: &PrivateWorkspaceSeedV1) -> Result<String> {
    wholepact_core::proposal::canonical_digest("wholepact:private-durable-selected-source:v1", seed)
        .map_err(Into::into)
}
impl PrivateDurableWorkspaceSourceV1<'_> {
    /// Pure immutable publication binding, not proof of metadata ownership or
    /// native persistence. Only actual prepared/opened owners can install it.
    #[allow(clippy::too_many_arguments)]
    pub fn seed_binding_original_v1(
        &self,
        access: &Access,
        destination: &Path,
        retention: &str,
        association: &str,
        origin: [u8; 32],
        plan: &PrivateWorkspaceInitializationPlanV1,
    ) -> Result<PrivateWorkspaceSeedBindingV1> {
        self.check_initialization_plan_v1(access, plan)?;
        let scope = scope(self, destination, retention)?;
        let marker = crate::private_workspace_origin_v1::from_source(
            self,
            access,
            &scope,
            association,
            origin,
        )?;
        let envelope = seed_envelope(self, plan, Some(&marker))?;
        let command = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            &plan.seed_key,
            &serde_json::json!((&plan.seed_kind, &self.seed_digest, &scope, &marker, plan)),
        )
        .map_err(crate::store_error)?;
        self.check_current(access)?;
        Ok(PrivateWorkspaceSeedBindingV1 {
            marker_digest: marker.digest().map_err(crate::store_error)?,
            marker,
            operation_kind: "agreement.created".into(),
            resource_id: self.agreement_id().into(),
            command,
            final_seed_payload_digest: seed_payload_digest(&envelope)?,
        })
    }

    pub fn initialization_plan_v1(
        &self,
        access: &Access,
    ) -> Result<PrivateWorkspaceInitializationPlanV1> {
        self.check_current(access)?;
        let timestamp = crate::now();
        let mut plan = PrivateWorkspaceInitializationPlanV1 {
            version: 1,
            source_digest: self.source_digest().into(),
            seed_key: "private-workspace-original-seed-v1".into(),
            seed_kind: "private-workspace-original-seed-v1".into(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            payload_without_marker_digest: String::new(),
        };
        plan.payload_without_marker_digest =
            seed_payload_digest(&seed_envelope(self, &plan, None)?)?;
        self.check_initialization_plan_v1(access, &plan)?;
        Ok(plan)
    }
    pub fn check_initialization_plan_v1(
        &self,
        access: &Access,
        plan: &PrivateWorkspaceInitializationPlanV1,
    ) -> Result<()> {
        self.check_current(access)?;
        if plan.version != 1
            || plan.source_digest != self.source_digest()
            || plan.seed_key != "private-workspace-original-seed-v1"
            || plan.seed_kind != "private-workspace-original-seed-v1"
            || plan.created_at != plan.updated_at
            || time::OffsetDateTime::parse(
                &plan.created_at,
                &time::format_description::well_known::Rfc3339,
            )
            .is_err()
            || plan.payload_without_marker_digest
                != seed_payload_digest(&seed_envelope(self, plan, None)?)?
        {
            return Err(damaged());
        }
        self.check_current(access)
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        require_principal(
            access,
            &self.seed.owner_client_id,
            &self.seed.agreement.agreement_id,
        )?;
        self.target.check_current(access)?;
        if seed_digest(&selected_seed(self.engine, &self.target, access)?)? != self.seed_digest {
            return Err(denied());
        }
        self.target.check_current(access)
    }
    pub fn source_digest(&self) -> &str {
        &self.seed_digest
    }
    pub fn generation_id(&self) -> &str {
        self.target.generation_id()
    }
    pub fn inventory_digest(&self) -> &str {
        self.target.inventory_digest()
    }
    pub fn source_destination_identity(&self) -> &str {
        self.target.store_destination_identity()
    }
    pub fn principal_id(&self) -> &str {
        &self.seed.owner_client_id
    }
    pub fn agreement_id(&self) -> &str {
        &self.seed.agreement.agreement_id
    }
    pub fn obligation_id(&self) -> &str {
        &self.seed.agreement.obligation_id
    }
    pub fn reviewer_account_ids(&self) -> Vec<String> {
        self.seed
            .selected_members
            .iter()
            .map(|m| m.identity.account_id.clone())
            .collect()
    }
}
fn require_principal(access: &Access, principal: &str, agreement: &str) -> Result<()> {
    if access.principal_id != principal || !access.permits_agreement(agreement, principal) {
        return Err(denied());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrivateWorkspaceActionV1 {
    Create,
    Reopen,
    ReadStatus,
    RetainDiscovery,
    RetainProjection,
    FreezeCandidate,
    PrepareExactCandidate,
    RetainExactMaterial,
    ObserveExactMaterial,
    CheckpointExactOriginal,
    ProveOriginalOnce,
    FreezeVerifiedFixed,
    ReadVerifiedFixed,
}

/// Exact privacy scope assembled from real source and destination owners. Values
/// correlate a foreground decision; none is signer or financial authority.
#[derive(Clone, Serialize)]
pub struct PrivateWorkspaceScopeV1 {
    source_digest: String,
    principal_id: String,
    agreement_id: String,
    obligation_id: String,
    reviewer_account_ids: Vec<String>,
    protected_destination: PathBuf,
    retention_policy: String,
}
impl PrivateWorkspaceScopeV1 {
    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
    pub fn agreement_id(&self) -> &str {
        &self.agreement_id
    }
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }
    pub fn reviewer_account_ids(&self) -> &[String] {
        &self.reviewer_account_ids
    }
    pub fn protected_destination(&self) -> &Path {
        &self.protected_destination
    }
    pub fn retention_policy(&self) -> &str {
        &self.retention_policy
    }
}
/// Trusted embedding privacy gate ONLY. Production native composition implements
/// this with actual current Host/foreground owners held for the whole operation.
/// A serialized boolean/old approval is not a production implementation.
pub trait LocalPrivateWorkspaceConsentV1 {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool;
}

/// The only externally serializable command result. No operation identifier,
/// event payload, AgreementView or historical idempotency result can escape.
#[derive(Serialize)]
pub struct PrivateWorkspaceStatusV1 {
    pub revision: u64,
    pub replayed: bool,
    pub rounds: Vec<DurableDiscoveryRoundSummaryV1>,
    pub authorization_allowed: bool,
}

/// Exclusive API ownership of the fresh Engine/Store inside this facade. Not
/// Clone, Debug, Serialize, Deref or AsRef. This does not prevent a trusted key
/// holder or constructor with OS access from independently opening the file.
/// Product privacy comes from the private native composition, which retains the
/// actual Directory owner and never supplies its key or facade to other clients.
pub struct PrivateDurableCoordinatorV1<'source> {
    engine: Engine,
    source: PrivateDurableWorkspaceSourceV1<'source>,
    scope: PrivateWorkspaceScopeV1,
    origin: [u8; 32],
    marker: PrivateWorkspaceOriginV1,
    proof: wholepact_proof_jobs::OriginalProofJobSourceV1<'source>,
    proof_origin: [u8; 32],
}
impl<'source> PrivateDurableCoordinatorV1<'source> {
    /// Open requires the actual original origin from the native authenticated
    /// commit, not a guessed replacement key/file. Missing/empty refuses.
    pub fn open_original(
        source: PrivateDurableWorkspaceSourceV1<'source>,
        access: &Access,
        destination: &Path,
        key: &DatabaseKey,
        expected_origin: [u8; 32],
        retention_policy: &str,
        native_association_digest: &str,
        proof: wholepact_proof_jobs::OriginalProofJobSourceV1<'source>,
        expected_proof_origin: [u8; 32],
        plan: &PrivateWorkspaceInitializationPlanV1,
        binding: &PrivateWorkspaceSeedBindingV1,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<Self> {
        crate::private_workspace_origin_v1::validate_association_digest(native_association_digest)?;
        let scope = scope(&source, destination, retention_policy)?;
        check_source_permission(
            &source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Reopen,
        )?;
        preflight_original_metadata(destination, key, expected_origin)?;
        let store =
            wholepact_store::Store::open_encrypted(destination, key).map_err(crate::store_error)?;
        if store
            .verify_original_encrypted_destination(destination)
            .map_err(crate::store_error)?
            != expected_origin
        {
            return Err(damaged());
        }
        let marker = crate::private_workspace_origin_v1::from_source(
            &source,
            access,
            &scope,
            native_association_digest,
            expected_origin,
        )?;
        proof.check_current().map_err(original_job_error_v2)?;
        if proof.origin_commitment() != expected_proof_origin {
            return Err(damaged());
        }
        let result = Self {
            engine: Engine::from_store(store),
            source,
            scope,
            origin: expected_origin,
            marker,
            proof,
            proof_origin: expected_proof_origin,
        };
        result.audit_original_seed_v1(access, plan, binding)?;
        result.check(access, consent, PrivateWorkspaceActionV1::Reopen)?;
        Ok(result)
    }
    /// Correlation needed by the exact native commit, never raw database access.
    pub fn original_origin(&self) -> [u8; 32] {
        self.origin
    }
    /// Consistency value for an actual native COMMIT, never permission or an
    /// assertion that any native association already exists.
    pub fn origin_marker_digest(&self) -> Result<String> {
        self.marker.digest().map_err(crate::store_error)
    }
    fn check(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        action: PrivateWorkspaceActionV1,
    ) -> Result<()> {
        self.proof.check_current().map_err(original_job_error_v2)?;
        if self.proof.origin_commitment() != self.proof_origin {
            return Err(damaged());
        }
        self.check_without_proof_lock(access, consent, action)?;
        self.proof.check_current().map_err(original_job_error_v2)
    }
    // Used only from proof consent callbacks while its journal mutex is held.
    // Never call the proof owner from here or reacquire that mutex.
    fn check_without_proof_lock(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        action: PrivateWorkspaceActionV1,
    ) -> Result<()> {
        check_source_permission(&self.source, access, &self.scope, consent, action)?;
        if self
            .engine
            .store
            .verify_original_encrypted_destination(&self.scope.protected_destination)
            .map_err(crate::store_error)?
            != self.origin
        {
            return Err(damaged());
        }
        let expected = crate::private_workspace_origin_v1::from_source(
            &self.source,
            access,
            &self.scope,
            &self.marker.native_association_digest,
            self.origin,
        )?;
        if expected != self.marker {
            return Err(damaged());
        }
        let record = self
            .engine
            .store
            .get_agreement(self.source.agreement_id())
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let envelope = decode_private_record(&record)?;
        self.require_original_envelope(&envelope)?;
        self.audit_exact_history(&envelope)?;
        check_source_permission(&self.source, access, &self.scope, consent, action)
    }
    fn require_original_envelope(&self, envelope: &crate::Envelope) -> Result<()> {
        if envelope.private_workspace_origin_v1.as_ref() != Some(&self.marker) {
            return Err(damaged());
        }
        if envelope.owner_client_id != self.source.principal_id()
            || envelope.view.agreement != self.source.seed.agreement
            || envelope.view.terms_history != self.source.seed.terms_history
            || envelope.view.intents != self.source.seed.intents
            || envelope.intent_owners != self.source.seed.intent_owners
            || !envelope.view.roster_selected
            || envelope.view.cancellation_requested
        {
            return Err(denied());
        }
        operation_v1::validate_shape(envelope)?;
        Ok(())
    }
    pub fn status(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        let operation = self.operation(access, consent, PrivateWorkspaceActionV1::ReadStatus)?;
        let envelope = operation.load()?;
        // Stage A has no marked-workspace discovery command activation. Refuse
        // unsupported state rather than disclose through the generic Engine.
        if !envelope.durable_input_projections_v1.is_empty() {
            return Err(ApiError::unsupported());
        }
        Ok(PrivateWorkspaceStatusV1 {
            revision: envelope.view.revision,
            replayed: false,
            rounds: vec![],
            authorization_allowed: false,
        })
    }
    fn operation<'op>(
        &'op self,
        access: &'op Access,
        consent: &'op dyn LocalPrivateWorkspaceConsentV1,
        action: PrivateWorkspaceActionV1,
    ) -> Result<operation_v1::PrivateWorkspaceOperationV1<'op, 'source>> {
        self.check(access, consent, action)?;
        Ok(operation_v1::PrivateWorkspaceOperationV1::new(
            self, access, consent, action,
        ))
    }
    pub fn begin_discovery(
        &self,
        access: &Access,
        key: &str,
        revision: u64,
        request: DurableDiscoveryRoundRequestV1,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        disclosure: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        self.check(access, consent, PrivateWorkspaceActionV1::RetainDiscovery)?;
        let _ = (key, revision, request, disclosure);
        // Explicit Stage A boundary. No generic Engine bypass, native dispatch,
        // receipt admission, or marker-aware discovery activation is provided.
        Err(ApiError::unsupported())
    }
    pub fn retain_projection(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        observation: wholepact_signer_origin::AuthenticatedDurableInputProjectionV1,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        disclosure: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        self.check(access, consent, PrivateWorkspaceActionV1::RetainProjection)?;
        let _ = (key, candidate_id, revision, observation, disclosure);
        // Explicit Stage A boundary. No generic Engine bypass, native dispatch,
        // receipt admission, or marker-aware discovery activation is provided.
        Err(ApiError::unsupported())
    }
    pub fn freeze_candidate(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
        disclosure: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        self.check(access, consent, PrivateWorkspaceActionV1::FreezeCandidate)?;
        let _ = (key, candidate_id, revision, disclosure);
        // Explicit Stage A boundary. No generic Engine bypass, native dispatch,
        // receipt admission, or marker-aware discovery activation is provided.
        Err(ApiError::unsupported())
    }
}
fn scope(
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    destination: &Path,
    retention: &str,
) -> Result<PrivateWorkspaceScopeV1> {
    if !destination.is_absolute()
        || retention.is_empty()
        || retention.len() > 1024
        || retention.chars().any(char::is_control)
    {
        return Err(denied());
    }
    Ok(PrivateWorkspaceScopeV1 {
        source_digest: source.source_digest().into(),
        principal_id: source.principal_id().into(),
        agreement_id: source.agreement_id().into(),
        obligation_id: source.obligation_id().into(),
        reviewer_account_ids: source.reviewer_account_ids(),
        protected_destination: destination.into(),
        retention_policy: retention.into(),
    })
}
fn check_source_permission(
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    access: &Access,
    scope: &PrivateWorkspaceScopeV1,
    consent: &dyn LocalPrivateWorkspaceConsentV1,
    action: PrivateWorkspaceActionV1,
) -> Result<()> {
    source.check_current(access)?;
    require_current_privacy(scope, consent, action)?;
    source.check_current(access)
}
fn require_current_privacy(
    scope: &PrivateWorkspaceScopeV1,
    consent: &dyn LocalPrivateWorkspaceConsentV1,
    action: PrivateWorkspaceActionV1,
) -> Result<()> {
    if !consent.permits_workspace(scope, action) {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_private_workspace_v1_tests.rs"]
mod tests;

impl Engine {
    /// Read-only preflight for the exact two original coordinator claims. This
    /// does not issue owner disclosure, financial consent or a mutation permit.
    pub fn validate_private_workspace_source_selection_v1(
        &self,
        access: &Access,
        target: &ManualRosterIntentTarget<'_>,
        intents: &[ParticipationIntent],
    ) -> Result<()> {
        target.check_current(access)?;
        let mut envelope = self.load(access, &target.agreement().agreement_id)?;
        crate::planning::check_proposer(&envelope, access)?;
        if envelope.view.agreement != *target.agreement()
            || intents.len() != 2
            || envelope
                .view
                .agreement
                .privacy_profile
                .proving_operator
                .as_deref()
                != Some(access.principal_id.as_str())
            || envelope.view.cancellation_requested
            || !envelope.view.candidates.is_empty()
        {
            return Err(denied());
        }
        if intents
            .iter()
            .any(|i| i.status != wholepact_core::IntentStatus::Active)
        {
            return Err(denied());
        }
        envelope.view.intents = intents.to_vec();
        for intent in &mut envelope.view.intents {
            intent.status = wholepact_core::IntentStatus::Selected;
        }
        envelope.view.roster_selected = true;
        if crate::planning::preview_intents(&envelope.view)?.len() != 2 {
            return Err(denied());
        }
        target.check_current(access)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateWorkspaceInitializationPlanV1 {
    pub version: u16,
    pub source_digest: String,
    pub seed_key: String,
    pub seed_kind: String,
    pub created_at: String,
    pub updated_at: String,
    pub payload_without_marker_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateWorkspaceSeedBindingV1 {
    pub marker: PrivateWorkspaceOriginV1,
    pub marker_digest: String,
    pub operation_kind: String,
    pub resource_id: String,
    pub command: wholepact_store::CommandContext,
    pub final_seed_payload_digest: String,
}
/// Empty original schema owner. No source lifetime, reads, material methods or
/// mutation escape. Publication must close the old Host before initialization.
pub struct PreparedPrivateDurableCoordinatorV1 {
    engine: Engine,
    destination: PathBuf,
    origin: [u8; 32],
}
fn seed_envelope(
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    plan: &PrivateWorkspaceInitializationPlanV1,
    marker: Option<&PrivateWorkspaceOriginV1>,
) -> Result<crate::Envelope> {
    let seed = &source.seed;
    let mut payload = serde_json::json!({
        "owner_client_id": seed.owner_client_id, "intent_owners": seed.intent_owners,
        "terms_editing_origin": false,
        "view": { "agreement": seed.agreement, "terms_history": seed.terms_history,
            "revision": 1, "progress": "preparing_proposal", "authorization_exposure": "unknown",
            "chain_observation": "unknown", "intents": seed.intents, "roster_selected": true,
            "proposals": [], "verification_reports": [], "candidates": [],
            "cancellation_requested": false, "created_at": plan.created_at, "updated_at": plan.updated_at }
    });
    if let Some(marker) = marker {
        payload["private_workspace_origin_v1"] =
            serde_json::to_value(marker).map_err(|_| damaged())?;
    }
    let envelope: crate::Envelope = serde_json::from_value(payload).map_err(|_| damaged())?;
    crate::terms_revisions::validate_history(&envelope.view)?;
    Ok(envelope)
}
fn seed_payload_digest(envelope: &crate::Envelope) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:private-workspace-seed-payload:v1",
        envelope,
    )
    .map_err(Into::into)
}
impl PreparedPrivateDurableCoordinatorV1 {
    /// Read-only publication preflight. No writable journal or owner is returned.
    pub fn check_initialized_original_v1(
        destination: &Path,
        key: &DatabaseKey,
        expected: [u8; 32],
    ) -> Result<()> {
        preflight_original_metadata(destination, key, expected)
    }
    pub fn prepare_empty_new(
        source: &PrivateDurableWorkspaceSourceV1<'_>,
        access: &Access,
        destination: &Path,
        key: &DatabaseKey,
        retention: &str,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<Self> {
        let scope = scope(source, destination, retention)?;
        check_source_permission(
            source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Create,
        )?;
        let store = wholepact_store::Store::create_encrypted(destination, key)
            .map_err(crate::store_error)?;
        let origin = store
            .verify_original_encrypted_destination(destination)
            .map_err(crate::store_error)?;
        check_source_permission(
            source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Create,
        )?;
        Ok(Self {
            engine: Engine::from_store(store),
            destination: destination.into(),
            origin,
        })
    }
    pub fn open_uninitialized_original(
        destination: &Path,
        key: &DatabaseKey,
        expected_origin: [u8; 32],
    ) -> Result<Self> {
        preflight_original_metadata(destination, key, expected_origin)?;
        let store =
            wholepact_store::Store::open_encrypted(destination, key).map_err(crate::store_error)?;
        if store
            .verify_original_encrypted_destination(destination)
            .map_err(crate::store_error)?
            != expected_origin
        {
            return Err(damaged());
        }
        Ok(Self {
            engine: Engine::from_store(store),
            destination: destination.into(),
            origin: expected_origin,
        })
    }
    pub fn original_origin(&self) -> [u8; 32] {
        self.origin
    }
    pub fn seed_binding_v1(
        &self,
        source: &PrivateDurableWorkspaceSourceV1<'_>,
        access: &Access,
        retention: &str,
        association: &str,
        plan: &PrivateWorkspaceInitializationPlanV1,
    ) -> Result<PrivateWorkspaceSeedBindingV1> {
        if self
            .engine
            .store
            .verify_original_encrypted_destination(&self.destination)
            .map_err(crate::store_error)?
            != self.origin
        {
            return Err(damaged());
        }
        source.seed_binding_original_v1(
            access,
            &self.destination,
            retention,
            association,
            self.origin,
            plan,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_once_original<'source>(
        self,
        source: PrivateDurableWorkspaceSourceV1<'source>,
        access: &Access,
        retention: &str,
        association: &str,
        plan: &PrivateWorkspaceInitializationPlanV1,
        proof: wholepact_proof_jobs::OriginalProofJobSourceV1<'source>,
        expected_proof_origin: [u8; 32],
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateDurableCoordinatorV1<'source>> {
        let binding = self.seed_binding_v1(&source, access, retention, association, plan)?;
        let scope = scope(&source, &self.destination, retention)?;
        check_source_permission(
            &source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Create,
        )?;
        proof.check_current().map_err(original_job_error_v2)?;
        if proof.origin_commitment() != expected_proof_origin {
            return Err(damaged());
        }
        let marker = crate::private_workspace_origin_v1::from_source(
            &source,
            access,
            &scope,
            association,
            self.origin,
        )?;
        let envelope = seed_envelope(&source, plan, Some(&marker))?;
        // Existing Store first-marker transaction enforces full pristine state.
        // Exact replay observes the SAVED seed and never overwrites later state.
        let saved = self
            .engine
            .store
            .create_agreement(
                &binding.command,
                source.agreement_id(),
                crate::encode(&envelope)?,
            )
            .map_err(crate::store_error)?;
        if saved.record.payload != crate::encode(&envelope)? || saved.record.revision != 1 {
            return Err(damaged());
        }
        let operation = self
            .engine
            .store
            .get_operation(&saved.operation_id)
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let result: wholepact_store::MutationResult =
            serde_json::from_value(operation.result).map_err(|_| damaged())?;
        if operation.principal_id != access.principal_id
            || operation.resource_id != source.agreement_id()
            || result.record != saved.record
            || result.operation_id != saved.operation_id
        {
            return Err(damaged());
        }
        let exact = self
            .engine
            .store
            .find_replay(&binding.command)
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        if exact.record != saved.record || exact.operation_id != saved.operation_id {
            return Err(damaged());
        }
        let workspace = PrivateDurableCoordinatorV1 {
            engine: self.engine,
            source,
            scope,
            origin: self.origin,
            marker,
            proof,
            proof_origin: expected_proof_origin,
        };
        workspace.check(access, consent, PrivateWorkspaceActionV1::Create)?;
        Ok(workspace)
    }
}

/// Authenticate exact original source and initialized v5 schema before any
/// writable Store opener can configure journal mode or consider migration.
fn preflight_original_metadata(
    destination: &Path,
    key: &DatabaseKey,
    expected: [u8; 32],
) -> Result<()> {
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(destination, key)
        .map_err(|_| damaged())?;
    if snapshot
        .source_database_identity()
        .map_err(|_| damaged())?
        .origin_commitment()
        != expected
    {
        return Err(damaged());
    }
    let connection = snapshot.connection();
    let app: i64 = connection
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| damaged())?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| damaged())?;
    if app != 0 || version != 5 {
        return Err(damaged());
    }
    let expected: BTreeSet<String> = [
        include_str!("../../wholepact-store/src/schema.sql"),
        include_str!("../../wholepact-store/src/migration-v2.sql"),
    ]
    .into_iter()
    .flat_map(|sql| sql.split(';'))
    .map(str::trim)
    .filter(|sql| sql.starts_with("CREATE TABLE "))
    .map(str::to_owned)
    .collect();
    let mut statement = connection
        .prepare("SELECT sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name")
        .map_err(|_| damaged())?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| damaged())?;
    let mut actual = BTreeSet::new();
    for row in rows {
        if !actual.insert(row.map_err(|_| damaged())?) {
            return Err(damaged());
        }
    }
    if actual != expected {
        return Err(damaged());
    }
    // Exact source-preserving inventory check: only the bounded agreement and
    // its minimal operation/idempotency/event rows may be present.
    let forbidden:i64=connection.query_row("SELECT (SELECT count(*) FROM authority_accounts)+(SELECT count(*) FROM authority_exposures)+(SELECT count(*) FROM authority_reservations)+(SELECT count(*) FROM authority_events)+(SELECT count(*) FROM effect_intents)",[],|row|row.get(0)).map_err(|_|damaged())?;
    let recovery:i64=connection.query_row("SELECT count(*) FROM store_recovery WHERE singleton=1 AND recovery_required=0 AND restored_at_ms IS NULL AND source_snapshot_digest IS NULL",[],|row|row.get(0)).map_err(|_|damaged())?;
    let records: i64 = connection
        .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
        .map_err(|_| damaged())?;
    let foreign: i64 = connection
        .query_row(
            "SELECT count(*) FROM records WHERE aggregate_type!='agreement'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| damaged())?;
    let revision: i64 = connection
        .query_row("SELECT coalesce(sum(revision),0) FROM records", [], |row| {
            row.get(0)
        })
        .map_err(|_| damaged())?;
    let counts:(i64,i64,i64)=connection.query_row("SELECT (SELECT count(*) FROM operations),(SELECT count(*) FROM idempotency),(SELECT count(*) FROM events)",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(|_|damaged())?;
    let sequences: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_sequence", [], |row| row.get(0))
        .map_err(|_| damaged())?;
    let invalid_sequences: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_sequence WHERE name!='events' OR seq!=?1",
            [revision],
            |row| row.get(0),
        )
        .map_err(|_| damaged())?;
    if sequences != records || invalid_sequences != 0 {
        return Err(damaged());
    }
    if forbidden != 0
        || recovery != 1
        || !(0..=1).contains(&records)
        || foreign != 0
        || !(0..=8).contains(&revision)
        || counts != (revision, revision, revision)
    {
        return Err(damaged());
    }
    snapshot.check_source_unchanged().map_err(|_| damaged())
}

/// The generic decoder normalizes public revision/exposure summaries. A private
/// purpose must reject altered persisted values, not normalize them away.
fn decode_private_record(record: &crate::StoredRecord) -> Result<crate::Envelope> {
    let raw: crate::Envelope =
        serde_json::from_value(record.payload.clone()).map_err(|_| damaged())?;
    if raw.view.revision != record.revision
        || raw.view.authorization_exposure != "unknown"
        || raw.view.chain_observation != "unknown"
    {
        return Err(damaged());
    }
    let decoded = crate::decode_unprojected(record)?;
    if crate::encode(&raw)? != crate::encode(&decoded)? {
        return Err(damaged());
    }
    Ok(decoded)
}
impl PrivateDurableCoordinatorV1<'_> {
    fn audit_original_seed_v1(
        &self,
        access: &Access,
        plan: &PrivateWorkspaceInitializationPlanV1,
        binding: &PrivateWorkspaceSeedBindingV1,
    ) -> Result<()> {
        self.source.check_initialization_plan_v1(access, plan)?;
        let seed = seed_envelope(&self.source, plan, Some(&self.marker))?;
        let command = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            &plan.seed_key,
            &serde_json::json!((
                &plan.seed_kind,
                &self.source.seed_digest,
                &self.scope,
                &self.marker,
                plan
            )),
        )
        .map_err(crate::store_error)?;
        let expected = PrivateWorkspaceSeedBindingV1 {
            marker: self.marker.clone(),
            marker_digest: self.origin_marker_digest()?,
            operation_kind: "agreement.created".into(),
            resource_id: self.source.agreement_id().into(),
            command,
            final_seed_payload_digest: seed_payload_digest(&seed)?,
        };
        if serde_json::to_value(&expected).map_err(|_| damaged())?
            != serde_json::to_value(binding).map_err(|_| damaged())?
        {
            return Err(damaged());
        }
        let saved = self
            .engine
            .store
            .find_replay(&expected.command)
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        if saved.record.revision != 1
            || crate::encode(&decode_private_record(&saved.record)?)? != crate::encode(&seed)?
        {
            return Err(damaged());
        }
        let operation = self
            .engine
            .store
            .get_operation(&saved.operation_id)
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let result: wholepact_store::MutationResult =
            serde_json::from_value(operation.result).map_err(|_| damaged())?;
        if operation.principal_id != access.principal_id
            || operation.resource_id != expected.resource_id
            || operation.kind != expected.operation_kind
            || operation.status != "succeeded"
            || result.record != saved.record
            || result.operation_id != saved.operation_id
            || result.replayed
        {
            return Err(damaged());
        }
        Ok(())
    }
}

/// Preserve only the closed original JobError category before generic API
/// conversion. No private journal payload or uncontrolled error text escapes.
fn original_job_error_v2(error: wholepact_proof_jobs::JobError) -> ApiError {
    use wholepact_proof_jobs::JobError::*;
    let variant = match &error {
        ConsentDenied => "consent_denied",
        NotFound => "not_found",
        InvalidRequest => "invalid_request",
        VerificationFailed => "verification_failed",
        IdempotencyConflict => "idempotency_conflict",
        RecoveryRequired => "recovery_required",
        StateConflict => "state_conflict",
        Storage => "storage",
        UnsupportedSchema => "unsupported_schema",
        ResourceExhausted => "resource_exhausted",
    };
    let mut result = crate::proof_jobs::job_error(error);
    result.details = Box::new(serde_json::json!({"private_original_job_error_v1":variant}));
    result
}
