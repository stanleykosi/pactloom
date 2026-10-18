//! Crate-private compiler foundation, not an activated native Host workspace.
//! The exact native dependency/consent composition remains required for use.
//! This exclusive facade, not a shared Engine redaction convention,
//! is the privacy boundary. Original association is history, never spending power.
use crate::durable_input_projections_v1::{
    DurableDiscoveryRoundRequestV1, DurableDiscoveryRoundSummaryV1, LocalDurableDiscoveryConsentV1,
};
use crate::manual_enrollment::ManualRosterIntentTarget;
use crate::{Access, ApiError, Engine, Mutation, Result};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use wholepact_core::{AgreementDraft, ParticipationIntent};
use wholepact_storage_security::DatabaseKey;
use wholepact_store::manual_enrollment::ManualEnrollmentRosterMember;

fn denied() -> ApiError {
    ApiError::new("DISCLOSURE_DENIED", "Exact original workspace, source principal and current native privacy permission are required")
}
fn damaged() -> ApiError {
    ApiError::new("RECOVERY_REQUIRED", "Preserve the original private dependency, key, directory and journals; no replacement workspace was created")
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
}

/// Exact privacy scope assembled from real source and destination owners. Values
/// correlate a foreground decision; none is signer or financial authority.
#[derive(Serialize)]
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
fn mutation_progress(mutation: Mutation) -> (u64, bool) {
    (mutation.agreement.revision, mutation.replayed)
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
}
impl<'source> PrivateDurableCoordinatorV1<'source> {
    /// Trusted-embedding data API, not proof of native dependency persistence.
    /// Native caller must first durably reserve the purpose-specific wrapped-key
    /// dependency and hold the actual protected Directory. This API never accepts
    /// an injected Engine/Store or borrows a shared private-data Engine.
    pub fn create_new(
        source: PrivateDurableWorkspaceSourceV1<'source>,
        access: &Access,
        destination: &Path,
        key: &DatabaseKey,
        retention_policy: &str,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<Self> {
        let scope = scope(&source, destination, retention_policy)?;
        check_source_permission(
            &source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Create,
        )?;
        // create_encrypted is create-new only. No exists/open-or-create fallback.
        let store = wholepact_store::Store::create_encrypted(destination, key)
            .map_err(crate::store_error)?;
        let origin = store
            .verify_original_encrypted_destination(destination)
            .map_err(crate::store_error)?;
        let engine = Engine::from_store(store);
        // Build ONLY nonspending seed metadata, not the source Envelope/history.
        let seed = &source.seed;
        let payload = serde_json::json!({
            "owner_client_id": seed.owner_client_id, "intent_owners": seed.intent_owners,
            "terms_editing_origin": false,
            "view": { "agreement": seed.agreement, "terms_history": seed.terms_history,
                "revision": 1, "progress": "preparing_proposal", "authorization_exposure": "unknown",
                "chain_observation": "unknown", "intents": seed.intents, "roster_selected": true,
                "proposals": [], "verification_reports": [], "candidates": [],
                "cancellation_requested": false, "created_at": crate::now(), "updated_at": crate::now() }
        });
        let envelope: crate::Envelope = serde_json::from_value(payload).map_err(|_| damaged())?;
        crate::terms_revisions::validate_history(&envelope.view)?;
        let command = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            "private-workspace-original-seed-v1",
            &serde_json::json!((&source.seed_digest, &scope)),
        )
        .map_err(crate::store_error)?;
        check_source_permission(
            &source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Create,
        )?;
        let _private_result = engine
            .store
            .create_agreement(&command, source.agreement_id(), crate::encode(&envelope)?)
            .map_err(crate::store_error)?;
        let result = Self {
            engine,
            source,
            scope,
            origin,
        };
        result.check(access, consent, PrivateWorkspaceActionV1::Create)?;
        Ok(result)
    }
    /// Open requires the actual original origin from the native authenticated
    /// commit, not a guessed replacement key/file. Missing/empty refuses.
    pub fn open_original(
        source: PrivateDurableWorkspaceSourceV1<'source>,
        access: &Access,
        destination: &Path,
        key: &DatabaseKey,
        expected_origin: [u8; 32],
        retention_policy: &str,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<Self> {
        let scope = scope(&source, destination, retention_policy)?;
        check_source_permission(
            &source,
            access,
            &scope,
            consent,
            PrivateWorkspaceActionV1::Reopen,
        )?;
        let store =
            wholepact_store::Store::open_encrypted(destination, key).map_err(crate::store_error)?;
        if store
            .verify_original_encrypted_destination(destination)
            .map_err(crate::store_error)?
            != expected_origin
        {
            return Err(damaged());
        }
        let result = Self {
            engine: Engine::from_store(store),
            source,
            scope,
            origin: expected_origin,
        };
        result.check(access, consent, PrivateWorkspaceActionV1::Reopen)?;
        Ok(result)
    }
    /// Correlation needed by the exact native commit, never raw database access.
    pub fn original_origin(&self) -> [u8; 32] {
        self.origin
    }
    fn check(
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
        let envelope = self.engine.load(access, self.source.agreement_id())?;
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
        check_source_permission(&self.source, access, &self.scope, consent, action)
    }
    pub fn status(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateWorkspaceConsentV1,
    ) -> Result<PrivateWorkspaceStatusV1> {
        self.check(access, consent, PrivateWorkspaceActionV1::ReadStatus)?;
        self.status_after(access, false)
    }
    fn status_after(&self, access: &Access, replayed: bool) -> Result<PrivateWorkspaceStatusV1> {
        let envelope = self.engine.load(access, self.source.agreement_id())?;
        Ok(PrivateWorkspaceStatusV1 {
            revision: envelope.view.revision,
            replayed,
            rounds: self
                .engine
                .durable_discovery_summaries_v1(access, self.source.agreement_id())?,
            authorization_allowed: false,
        })
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
        if Path::new(&request.protected_destination) != self.scope.protected_destination
            || request.retention_policy != self.scope.retention_policy
            || request
                .owners
                .iter()
                .map(|o| o.account_id.clone())
                .collect::<BTreeSet<_>>()
                != self.scope.reviewer_account_ids.iter().cloned().collect()
        {
            return Err(denied());
        }
        let (mutation, _) = self.engine.begin_durable_discovery_v1(
            access,
            key,
            self.source.agreement_id(),
            revision,
            request,
            disclosure,
        )?;
        let (_, replayed) = mutation_progress(mutation);
        self.check(access, consent, PrivateWorkspaceActionV1::RetainDiscovery)?;
        self.status_after(access, replayed)
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
        let mutation = self.engine.intake_durable_input_projection_v1(
            access,
            key,
            self.source.agreement_id(),
            candidate_id,
            revision,
            observation,
            disclosure,
        )?;
        let (_, replayed) = mutation_progress(mutation);
        self.check(access, consent, PrivateWorkspaceActionV1::RetainProjection)?;
        self.status_after(access, replayed)
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
        let mutation = self.engine.freeze_durable_discovery_candidate_v1(
            access,
            key,
            self.source.agreement_id(),
            candidate_id,
            revision,
            disclosure,
        )?;
        let (_, replayed) = mutation_progress(mutation);
        self.check(access, consent, PrivateWorkspaceActionV1::FreezeCandidate)?;
        self.status_after(access, replayed)
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
