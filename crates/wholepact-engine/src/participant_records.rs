//! Protected participant-local records. Agreement read scopes, organizer status
//! text and record/account labels do not grant access to these private objects.
//! Runtime-held account/record leases are required on every read, write and retry.
pub mod disclosure_exports;
pub(crate) mod historical;
pub(crate) mod reconciliation_selection;
#[cfg(all(
    feature = "submission-handoff",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
mod settlement_resolution;

use super::*;
use std::collections::BTreeMap;
use std::fmt;
use wholepact_core::disclosure::{DisclosureMethod, DisclosurePreview, DisclosureSelection};
use wholepact_core::records::{
    ObservationPolicy, ObservationWindow, RecordAssessment, RecordConfidence, RecordEvent,
    SettlementObservationSource, SettlementRecord, SettlementRecordArchive,
};
use wholepact_core::retirement::{
    AccountRecoverySource, AccountRetirementPlan, ReclaimRequest, ResidualInput,
    UserControlledShieldedDestination, VIEWING_KEY_EXPOSURE_STATEMENT,
};
use wholepact_core::{Amount, Proposal};
use wholepact_store::StorageProtection;

const MAX_PARTICIPANT_RECORDS: usize = 32;
const MAX_PRIVATE_PREVIEWS: usize = 64;
const MAX_RETIREMENT_PLANS: usize = 16;

/// An opaque exact open-store binding. Clones of an Engine share it; reopening
/// even the same database requires a newly enrolled runtime binding. No pointer,
/// path, key or stable machine identifier is serialized or exposed to clients.
#[derive(Clone)]
pub struct RecordStoreBinding {
    store: Arc<Store>,
}
impl PartialEq for RecordStoreBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.store, &other.store)
    }
}
impl Eq for RecordStoreBinding {}
impl fmt::Debug for RecordStoreBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordStoreBinding { opaque_open_store }")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipantRecordAction {
    Retain,
    Observe,
    ReadPrivate,
    ReadSummary,
    PreviewDisclosure,
    ExportReceipt,
    PlanRetirement,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantRecordScope {
    pub store: RecordStoreBinding,
    pub profile_id: String,
    pub principal_id: String,
    pub agreement_id: String,
    pub record_id: String,
    pub participant_id: String,
    pub account_id: String,
    pub action: ParticipantRecordAction,
}
/// Trusted runtime-owned guard. Implementations must keep the exact permission
/// valid while the guard is held across the final check and database commit, or
/// reject/cancel the operation. It cannot be obtained from a JSON approval flag.
pub trait ParticipantRecordLease {
    fn scope(&self) -> &ParticipantRecordScope;
    fn expires_at(&self) -> &str;
    fn check_current(&self) -> Result<()>;
}
/// Separate local account/record authority. A production issuer must authenticate
/// account ownership, enrollment, grants, current revocation and store/profile
/// identity. It is intentionally not synthesized from Access::all_agreements.
pub trait ParticipantRecordAuthority: Send + Sync {
    fn acquire<'a>(
        &'a self,
        requested: &ParticipantRecordScope,
        window: &ObservationWindow,
    ) -> Result<Box<dyn ParticipantRecordLease + 'a>>;
}
pub struct ParticipantRecordRuntime<'a> {
    pub profile_id: &'a str,
    pub authority: &'a dyn ParticipantRecordAuthority,
    pub window: &'a ObservationWindow,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainParticipantRecordRequest {
    pub record_id: String,
    pub candidate_id: String,
    pub participant_id: String,
    pub account_id: String,
}
/// Trusted source of the exact retained approved manifest, participant-owned
/// consent/signature/release provenance, extracted transaction and observations.
/// Source code must verify its protected protocol/signature journals; coordinator
/// claims and encrypted-but-unverified input bytes do not implement this boundary.
pub trait RetainedParticipantRecordSource {
    fn source_id(&self) -> &str;
    fn load_retained_record(
        &mut self,
        request: &RetainParticipantRecordRequest,
        candidate: &Proposal,
    ) -> Result<SettlementRecord>;
    /// Ordinary replay is a leased read of an already retained immutable source
    /// snapshot. Sources with separately protected live provenance gates override
    /// this hook and hold their guards until the outer operation returns.
    fn validate_replay(
        &mut self,
        _request: &RetainParticipantRecordRequest,
        _candidate: &Proposal,
        _retained: &SettlementRecord,
    ) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredParticipantRecord {
    owner_principal_id: String,
    profile_id: String,
    candidate_id: String,
    candidate_proposal_digest: String,
    retained_source_id: String,
    record_revision: u64,
    #[serde(default)]
    settlement_invalidated: bool,
    record: SettlementRecordArchive,
    disclosure_previews: BTreeMap<String, StoredDisclosurePreview>,
    #[serde(default)]
    disclosure_exports: BTreeMap<String, disclosure_exports::StoredReceiptExport>,
    retirement_plans: BTreeMap<String, PrivateRetirementPlanView>,
}
impl StoredParticipantRecord {
    pub(crate) fn recovery_archive(&self) -> &SettlementRecordArchive {
        &self.record
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDisclosurePreview {
    selection: DisclosureSelection,
    method: DisclosureMethod,
    preview_digest: String,
    record_digest: String,
    preview_window: ObservationWindow,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveParticipantRecordRequest {
    pub record_id: String,
    pub expected_record_revision: u64,
    pub policy: ObservationPolicy,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewParticipantDisclosureRequest {
    pub record_id: String,
    pub expected_record_revision: u64,
    pub preview_id: String,
    pub selection: DisclosureSelection,
    pub method: DisclosureMethod,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanParticipantRetirementRequest {
    pub record_id: String,
    pub expected_record_revision: u64,
    pub reclaim: ReclaimRequest,
}

/// Private local review view, never an authorization/execution token. Full
/// values must stay in the protected native context and out of ordinary JSON UI.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRetirementPlanView {
    pub plan_digest: String,
    pub request: ReclaimRequest,
    pub destination: UserControlledShieldedDestination,
    pub inputs: Vec<ResidualInput>,
    pub transfer_amount: Amount,
    pub fee: Amount,
    pub maximum_net_debit: Amount,
    pub viewing_key_exposure: String,
    pub status: String,
}
impl fmt::Debug for PrivateRetirementPlanView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateRetirementPlanView { private_contents: [REDACTED], separate_authorization: REQUIRED }")
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantRecordSummary {
    pub record_id: String,
    pub agreement_id: String,
    pub candidate_id: String,
    pub record_revision: u64,
    pub confidence: RecordConfidence,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub observation_sources: Vec<ObservationPolicy>,
    pub recovery_required: bool,
    pub scope: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantRecordStatus {
    pub status: &'static str,
    /// None means inaccessible/unavailable; only a connected authorized query
    /// can produce Some(empty). Neither case establishes zero account exposure.
    pub records: Option<Vec<ParticipantRecordSummary>>,
    pub reason_code: Option<&'static str>,
    pub account_exposure: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantRecordMutation {
    pub record: ParticipantRecordSummary,
    pub agreement_revision: u64,
    pub operation_id: String,
    pub event_sequence: u64,
    pub replayed: bool,
    pub private_artifact_id: Option<String>,
}

impl Engine {
    /// Give this only to the trusted local enrollment/runtime composition.
    pub fn protected_record_store_binding(&self) -> Result<RecordStoreBinding> {
        require_encrypted(self)?;
        Ok(RecordStoreBinding {
            store: self.store.clone(),
        })
    }
    pub fn participant_record_status(
        &self,
        access: &Access,
        runtime: Option<ParticipantRecordRuntime<'_>>,
    ) -> Result<ParticipantRecordStatus> {
        let Some(runtime) = runtime else {
            return Ok(ParticipantRecordStatus {
                status: "unavailable",
                records: None,
                reason_code: Some("PARTICIPANT_RECORD_RUNTIME_NOT_CONNECTED"),
                account_exposure: "unknown_not_established_by_records",
            });
        };
        require_encrypted(self)?;
        runtime.window.validate()?;
        validate_identifier(runtime.profile_id)?;
        let mut summaries = Vec::new();
        for stored in self.store.list_agreements().map_err(store_error)? {
            let envelope = decode(&stored)?;
            if !access.sees(&stored.id, &envelope.owner_client_id) {
                continue;
            }
            for record in envelope.participant_records.values().filter(|r| {
                r.owner_principal_id == access.principal_id && r.profile_id == runtime.profile_id
            }) {
                let scope = make_scope(
                    self,
                    access,
                    &stored.id,
                    record,
                    &runtime,
                    ParticipantRecordAction::ReadSummary,
                );
                let lease = checked_lease(&runtime, &scope)?;
                let summary = summarize(self, &stored.id, record, runtime.window)?;
                check_lease(&*lease, &scope, runtime.window)?;
                summaries.push(summary);
            }
        }
        Ok(ParticipantRecordStatus {
            status: "available",
            records: Some(summaries),
            reason_code: None,
            account_exposure: "unknown_not_established_by_records",
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn retain_participant_record(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: RetainParticipantRecordRequest,
        runtime: ParticipantRecordRuntime<'_>,
        source: &mut impl RetainedParticipantRecordSource,
    ) -> Result<ParticipantRecordMutation> {
        require_mutable_records(self, agreement_id)?;
        for id in [
            &request.record_id,
            &request.candidate_id,
            &request.participant_id,
            &request.account_id,
            source.source_id(),
        ] {
            validate_identifier(id)?;
        }
        let scope = ParticipantRecordScope {
            store: self.protected_record_store_binding()?,
            profile_id: runtime.profile_id.into(),
            principal_id: access.principal_id.clone(),
            agreement_id: agreement_id.into(),
            record_id: request.record_id.clone(),
            participant_id: request.participant_id.clone(),
            account_id: request.account_id.clone(),
            action: ParticipantRecordAction::Retain,
        };
        let lease = checked_lease(&runtime, &scope)?;
        let command = context(
            access,
            key,
            "retain_participant_record",
            agreement_id,
            Some(revision),
            &json!({"request":request,"profile_id":runtime.profile_id,"retained_source_id":source.source_id()}),
        )?;
        let mut envelope = self.load(access, agreement_id)?;
        if let Some(replay) =
            self.record_replay(access, &command, &request.record_id, &runtime, None)?
        {
            let candidate = envelope
                .view
                .candidates
                .iter()
                .find(|c| c.candidate_id == request.candidate_id)
                .ok_or_else(not_found)?
                .verified_snapshot()?;
            let retained = load_private_record(
                self,
                owned_record(&envelope, access, &request.record_id, runtime.profile_id)?,
            )?;
            source.validate_replay(&request, &candidate, &retained)?;
            check_lease(&*lease, &scope, runtime.window)?;
            return Ok(replay);
        }
        candidates::check_revision(&envelope, revision)?;
        if envelope
            .participant_records
            .contains_key(&request.record_id)
        {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Private record ID is already retained; exact replay requires its original operation key",
            ));
        }
        if envelope.participant_records.len() >= MAX_PARTICIPANT_RECORDS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Private participant record limit reached; retain existing safety history",
            ));
        }
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == request.candidate_id)
            .ok_or_else(not_found)?
            .verified_snapshot()?;
        let record = source.load_retained_record(&request, &candidate)?;
        validate_retained_source_record(&record, &candidate, &request)?;
        let record = SettlementRecord::load_retained_archive(record.archive())?;
        envelope.participant_records.insert(
            request.record_id.clone(),
            StoredParticipantRecord {
                owner_principal_id: access.principal_id.clone(),
                profile_id: runtime.profile_id.into(),
                candidate_id: request.candidate_id,
                candidate_proposal_digest: candidate.proposal_digest().into(),
                retained_source_id: source.source_id().into(),
                record_revision: 1,
                settlement_invalidated: self
                    .store
                    .settlement_obligation_requires_recovery(
                        &candidate.manifest().agreement.obligation_id,
                    )
                    .map_err(store_error)?,
                record: record.archive(),
                disclosure_previews: BTreeMap::new(),
                disclosure_exports: BTreeMap::new(),
                retirement_plans: BTreeMap::new(),
            },
        );
        check_lease(&*lease, &scope, runtime.window)?;
        self.commit_private_record(
            access,
            &command,
            revision,
            envelope,
            &request.record_id,
            &runtime,
            None,
            "participant_record_retained",
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn observe_participant_record(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: ObserveParticipantRecordRequest,
        runtime: ParticipantRecordRuntime<'_>,
        source: &mut impl SettlementObservationSource,
    ) -> Result<ParticipantRecordMutation> {
        require_mutable_records(self, agreement_id)?;
        let mut envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::Observe,
        );
        let lease = checked_lease(&runtime, &scope)?;
        let command = context(
            access,
            key,
            "observe_participant_record",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) =
            self.record_replay(access, &command, &request.record_id, &runtime, None)?
        {
            check_lease(&*lease, &scope, runtime.window)?;
            return Ok(replay);
        }
        candidates::check_revision(&envelope, revision)?;
        check_record_revision(stored, request.expected_record_revision)?;
        let current = load_private_record(self, stored)?;
        let (next, event) = current.observe(source, &request.policy, runtime.window)?;
        let target = envelope
            .participant_records
            .get_mut(&request.record_id)
            .ok_or_else(not_found)?;
        target.record = next.archive();
        advance_record_revision(target)?;
        // Existing previews stay as immutable historical review artifacts and
        // reject reads/exports against changed records instead of auto-updating.
        check_lease(&*lease, &scope, runtime.window)?;
        self.commit_private_record(
            access,
            &command,
            revision,
            envelope,
            &request.record_id,
            &runtime,
            None,
            if event == RecordEvent::ReconcileOutstandingExposure {
                "participant_record_reconciliation_required"
            } else {
                "participant_record_observed"
            },
        )
    }
    pub fn read_participant_record(
        &self,
        access: &Access,
        agreement_id: &str,
        record_id: &str,
        runtime: ParticipantRecordRuntime<'_>,
    ) -> Result<SettlementRecord> {
        require_encrypted(self)?;
        let envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::ReadPrivate,
        );
        let lease = checked_lease(&runtime, &scope)?;
        let record = load_private_record(self, stored)?;
        check_lease(&*lease, &scope, runtime.window)?;
        Ok(record)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn preview_participant_disclosure(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: PreviewParticipantDisclosureRequest,
        runtime: ParticipantRecordRuntime<'_>,
    ) -> Result<ParticipantRecordMutation> {
        require_mutable_records(self, agreement_id)?;
        validate_identifier(&request.preview_id)?;
        let mut envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::PreviewDisclosure,
        );
        let lease = checked_lease(&runtime, &scope)?;
        let command = context(
            access,
            key,
            "preview_participant_disclosure",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.record_replay(
            access,
            &command,
            &request.record_id,
            &runtime,
            Some(request.preview_id.clone()),
        )? {
            check_lease(&*lease, &scope, runtime.window)?;
            return Ok(replay);
        }
        candidates::check_revision(&envelope, revision)?;
        check_record_revision(stored, request.expected_record_revision)?;
        if stored.disclosure_previews.len() >= MAX_PRIVATE_PREVIEWS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Private disclosure preview limit reached",
            ));
        }
        if stored.disclosure_previews.contains_key(&request.preview_id) {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Disclosure preview IDs are immutable; use the original retry key or prepare a new preview",
            ));
        }
        let record = load_private_record(self, stored)?;
        let preview = DisclosurePreview::build(
            &record,
            request.selection.clone(),
            request.method.clone(),
            runtime.window,
        )?;
        let target = envelope
            .participant_records
            .get_mut(&request.record_id)
            .ok_or_else(not_found)?;
        target.disclosure_previews.insert(
            request.preview_id.clone(),
            StoredDisclosurePreview {
                selection: request.selection,
                method: request.method,
                preview_digest: preview.digest().into(),
                record_digest: record.content_digest()?,
                preview_window: runtime.window.clone(),
            },
        );
        // Preview creation does not amend the underlying settlement record.
        check_lease(&*lease, &scope, runtime.window)?;
        self.commit_private_record(
            access,
            &command,
            revision,
            envelope,
            &request.record_id,
            &runtime,
            Some(request.preview_id),
            "participant_disclosure_previewed",
        )
    }
    pub fn read_participant_disclosure_preview(
        &self,
        access: &Access,
        agreement_id: &str,
        record_id: &str,
        preview_id: &str,
        runtime: ParticipantRecordRuntime<'_>,
    ) -> Result<DisclosurePreview> {
        require_encrypted(self)?;
        let envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::PreviewDisclosure,
        );
        let lease = checked_lease(&runtime, &scope)?;
        let recipe = stored
            .disclosure_previews
            .get(preview_id)
            .ok_or_else(not_found)?;
        let record = load_private_record(self, stored)?;
        if record.content_digest()? != recipe.record_digest {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Record changed after disclosure preview; prepare a fresh exact preview",
            ));
        }
        let preview = DisclosurePreview::build(
            &record,
            recipe.selection.clone(),
            recipe.method.clone(),
            &recipe.preview_window,
        )?;
        if preview.digest() != recipe.preview_digest {
            return Err(corrupt_record());
        }
        // This is a historical preview. Its embedded assessment time remains
        // literal; actual export must recheck current consent and confidence.
        check_lease(&*lease, &scope, runtime.window)?;
        Ok(preview)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn plan_participant_retirement(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: PlanParticipantRetirementRequest,
        runtime: ParticipantRecordRuntime<'_>,
        source: &mut impl AccountRecoverySource,
    ) -> Result<ParticipantRecordMutation> {
        require_mutable_records(self, agreement_id)?;
        let mut envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, &request.record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::PlanRetirement,
        );
        let lease = checked_lease(&runtime, &scope)?;
        if request.reclaim.account_id != scope.account_id
            || request.reclaim.network_profile_id != stored.record.transaction.network_profile_id
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Reclaim planning must target this leased account and its network",
            ));
        }
        let command = context(
            access,
            key,
            "plan_participant_retirement",
            agreement_id,
            Some(revision),
            &request,
        )?;
        if let Some(replay) = self.record_replay(
            access,
            &command,
            &request.record_id,
            &runtime,
            Some(request.reclaim.plan_id.clone()),
        )? {
            check_lease(&*lease, &scope, runtime.window)?;
            return Ok(replay);
        }
        candidates::check_revision(&envelope, revision)?;
        check_record_revision(stored, request.expected_record_revision)?;
        if stored.retirement_plans.len() >= MAX_RETIREMENT_PLANS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Retirement plan limit reached; prior reviews remain retained",
            ));
        }
        if stored
            .retirement_plans
            .contains_key(&request.reclaim.plan_id)
        {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Retirement plan ID already exists; review a new plan rather than changing it",
            ));
        }
        if self
            .store
            .authority_account(&scope.account_id)
            .map_err(store_error)?
            .is_some_and(|account| account.recovery_required)
            || self
                .store
                .account_exposures(&scope.account_id)
                .map_err(store_error)?
                .iter()
                .any(|exposure| exposure.state.retains_unresolved_exposure())
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Local account journal has unresolved exposure; reconcile it before reclaim planning",
            ));
        }
        let known_record = load_private_record(self, stored)?;
        let mut bound_source = KnownReleaseRecoverySource {
            inner: source,
            known_record: &known_record,
        };
        let plan = AccountRetirementPlan::prepare(
            &mut bound_source,
            request.reclaim.clone(),
            runtime.window,
        )?;
        let view = PrivateRetirementPlanView {
            plan_digest: plan.digest().into(),
            request: plan.request().clone(),
            destination: plan.destination().clone(),
            inputs: plan.inputs().to_vec(),
            transfer_amount: plan.transfer_amount(),
            fee: plan.fee(),
            maximum_net_debit: plan.maximum_net_debit(),
            viewing_key_exposure: plan.viewing_key_exposure().into(),
            status: "unsigned_separate_review_and_authorization_required".into(),
        };
        let target = envelope
            .participant_records
            .get_mut(&request.record_id)
            .ok_or_else(not_found)?;
        target
            .retirement_plans
            .insert(request.reclaim.plan_id.clone(), view);
        check_lease(&*lease, &scope, runtime.window)?;
        self.commit_private_record(
            access,
            &command,
            revision,
            envelope,
            &request.record_id,
            &runtime,
            Some(request.reclaim.plan_id),
            "participant_retirement_planned",
        )
    }
    pub fn read_participant_retirement_plan(
        &self,
        access: &Access,
        agreement_id: &str,
        record_id: &str,
        plan_id: &str,
        runtime: ParticipantRecordRuntime<'_>,
    ) -> Result<PrivateRetirementPlanView> {
        require_encrypted(self)?;
        let envelope = self.load(access, agreement_id)?;
        let stored = owned_record(&envelope, access, record_id, runtime.profile_id)?;
        let scope = make_scope(
            self,
            access,
            agreement_id,
            stored,
            &runtime,
            ParticipantRecordAction::PlanRetirement,
        );
        let lease = checked_lease(&runtime, &scope)?;
        let plan = stored
            .retirement_plans
            .get(plan_id)
            .ok_or_else(not_found)?
            .clone();
        check_lease(&*lease, &scope, runtime.window)?;
        Ok(plan)
    }
    fn record_replay(
        &self,
        access: &Access,
        command: &CommandContext,
        record_id: &str,
        runtime: &ParticipantRecordRuntime<'_>,
        artifact_id: Option<String>,
    ) -> Result<Option<ParticipantRecordMutation>> {
        self.store
            .find_replay(command)
            .map_err(store_error)?
            .map(|result| private_mutation(self, access, record_id, runtime, artifact_id, result))
            .transpose()
    }
    #[allow(clippy::too_many_arguments)]
    fn commit_private_record(
        &self,
        access: &Access,
        command: &CommandContext,
        revision: u64,
        mut envelope: Envelope,
        record_id: &str,
        runtime: &ParticipantRecordRuntime<'_>,
        artifact_id: Option<String>,
        event: &str,
    ) -> Result<ParticipantRecordMutation> {
        let id = envelope.view.agreement.agreement_id.clone();
        require_mutable_records(self, &id)?;
        validate_stored_records(&envelope.participant_records, &id)?;
        envelope.view.revision = revision.checked_add(1).ok_or_else(|| {
            ApiError::new("RESOURCE_EXHAUSTED", "Agreement revision limit reached")
        })?;
        envelope.view.updated_at = now();
        let result = self
            .store
            .update_agreement(command, &id, revision, encode(&envelope)?, event)
            .map_err(store_error)?;
        private_mutation(self, access, record_id, runtime, artifact_id, result)
    }
}

fn require_encrypted(engine: &Engine) -> Result<()> {
    if engine.store.protection() != StorageProtection::Encrypted {
        return Err(ApiError::new(
            "STORAGE_PROTECTION_REQUIRED",
            "Participant records require verified encrypted storage; metadata development and memory stores are not private record stores",
        ));
    }
    Ok(())
}
fn require_mutable_records(engine: &Engine, agreement_id: &str) -> Result<()> {
    require_encrypted(engine)?;
    if engine
        .store
        .runtime_recovery_required()
        .map_err(store_error)?
        || engine
            .store
            .recovery_record_is_historical("agreement", agreement_id)
            .map_err(store_error)?
    {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Restored journal remains quarantined; reconcile writer authority and complete exposure history before new private-record operations",
        ));
    }
    Ok(())
}
fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Private record identifier is invalid",
        ));
    }
    Ok(())
}
fn checked_lease<'a>(
    runtime: &'a ParticipantRecordRuntime<'_>,
    scope: &ParticipantRecordScope,
) -> Result<Box<dyn ParticipantRecordLease + 'a>> {
    runtime.window.validate()?;
    validate_identifier(runtime.profile_id)?;
    let lease = runtime.authority.acquire(scope, runtime.window)?;
    check_lease(&*lease, scope, runtime.window)?;
    Ok(lease)
}
fn check_lease(
    lease: &dyn ParticipantRecordLease,
    scope: &ParticipantRecordScope,
    window: &ObservationWindow,
) -> Result<()> {
    wholepact_core::agreement::validate_timestamp(lease.expires_at())?;
    if lease.scope() != scope || lease.expires_at() <= window.now.as_str() {
        return Err(ApiError::new(
            "PERMISSION_DENIED",
            "Participant record lease is expired or belongs to another exact store/profile/principal/account/action",
        ));
    }
    lease.check_current()
}
fn make_scope(
    engine: &Engine,
    access: &Access,
    agreement_id: &str,
    stored: &StoredParticipantRecord,
    runtime: &ParticipantRecordRuntime<'_>,
    action: ParticipantRecordAction,
) -> ParticipantRecordScope {
    ParticipantRecordScope {
        store: RecordStoreBinding {
            store: engine.store.clone(),
        },
        profile_id: runtime.profile_id.into(),
        principal_id: access.principal_id.clone(),
        agreement_id: agreement_id.into(),
        record_id: stored.record.record_id.clone(),
        participant_id: stored.record.own_authorization.participant_id.clone(),
        account_id: stored.record.own_authorization.account_id.clone(),
        action,
    }
}
fn owned_record<'a>(
    envelope: &'a Envelope,
    access: &Access,
    record_id: &str,
    profile_id: &str,
) -> Result<&'a StoredParticipantRecord> {
    envelope
        .participant_records
        .get(record_id)
        .filter(|record| {
            record.owner_principal_id == access.principal_id && record.profile_id == profile_id
        })
        .ok_or_else(not_found)
}
fn check_record_revision(stored: &StoredParticipantRecord, expected: u64) -> Result<()> {
    if stored.record_revision != expected {
        return Err(ApiError::new(
            "REVISION_CONFLICT",
            "Private record revision changed; refresh its evidence before continuing",
        ));
    }
    Ok(())
}
fn advance_record_revision(stored: &mut StoredParticipantRecord) -> Result<()> {
    stored.record_revision = stored.record_revision.checked_add(1).ok_or_else(|| {
        ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Private record revision limit reached",
        )
    })?;
    Ok(())
}
fn load_private_record(
    engine: &Engine,
    stored: &StoredParticipantRecord,
) -> Result<SettlementRecord> {
    if stored.settlement_invalidated {
        let mut archive = stored.record.clone();
        // Keep historical observations on disk, but never present them as live
        // confidence after a source-bound loss of confidence.
        archive.observations.clear();
        return Ok(SettlementRecord::restore(archive)?);
    }
    if engine
        .store
        .runtime_recovery_required()
        .map_err(store_error)?
        || engine
            .store
            .recovery_record_is_historical(
                "agreement",
                &stored.record.proposal.manifest.agreement.agreement_id,
            )
            .map_err(store_error)?
    {
        Ok(SettlementRecord::restore(stored.record.clone())?)
    } else {
        Ok(SettlementRecord::load_retained_archive(
            stored.record.clone(),
        )?)
    }
}
fn summarize(
    engine: &Engine,
    agreement_id: &str,
    stored: &StoredParticipantRecord,
    window: &ObservationWindow,
) -> Result<ParticipantRecordSummary> {
    let record = load_private_record(engine, stored)?;
    let RecordAssessment {
        confidence,
        confirmations,
        required_confirmations,
        sources,
        exposure_reconciliation_required,
        ..
    } = record.assess(window)?;
    Ok(ParticipantRecordSummary {
        record_id: record.record_id().into(),
        agreement_id: agreement_id.into(),
        candidate_id: stored.candidate_id.clone(),
        record_revision: stored.record_revision,
        confidence,
        confirmations,
        required_confirmations,
        observation_sources: sources,
        recovery_required: exposure_reconciliation_required,
        scope: "participant_local_record_not_account_authority",
    })
}
fn private_mutation(
    engine: &Engine,
    access: &Access,
    record_id: &str,
    runtime: &ParticipantRecordRuntime<'_>,
    artifact_id: Option<String>,
    result: MutationResult,
) -> Result<ParticipantRecordMutation> {
    // Idempotency retains the original operation/event identity, not a license
    // to present its historical confidence as current after a later reorg. The
    // caller still holds the exact current record lease through this read.
    let envelope = if result.replayed {
        engine.load(access, &result.record.id)?
    } else {
        decode(&result.record)?
    };
    if !access.sees(&result.record.id, &envelope.owner_client_id) {
        return Err(not_found());
    }
    let stored = owned_record(&envelope, access, record_id, runtime.profile_id)?;
    Ok(ParticipantRecordMutation {
        record: summarize(engine, &result.record.id, stored, runtime.window)?,
        agreement_revision: envelope.view.revision,
        operation_id: result.operation_id,
        event_sequence: result.event_sequence,
        replayed: result.replayed,
        private_artifact_id: artifact_id,
    })
}
fn validate_retained_source_record(
    record: &SettlementRecord,
    candidate: &Proposal,
    request: &RetainParticipantRecordRequest,
) -> Result<()> {
    let approved = record.proposal();
    if record.record_id() != request.record_id
        || approved.input().proposal_id != request.candidate_id
        || approved.manifest() != candidate.manifest()
        || approved.input().previous_proposal_id != candidate.input().previous_proposal_id
        || approved.input().created_at != candidate.input().created_at
        || record.own_authorization().participant_id != request.participant_id
        || record.own_authorization().account_id != request.account_id
    {
        return Err(ApiError::new(
            "RECORD_SOURCE_REJECTED",
            "Protected source record differs from the exact retained candidate and leased participant/account",
        ));
    }
    // Candidate claims have no effects/artifact commitment. The trusted source
    // supplies those from actual retained approved verification/signature records;
    // the original candidate digest stays separately linked and is never rewritten.
    Ok(())
}
fn corrupt_record() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Private record or review history is inconsistent; preserve the encrypted journal",
    )
}
pub(crate) fn validate_stored_records(
    records: &BTreeMap<String, StoredParticipantRecord>,
    agreement_id: &str,
) -> Result<()> {
    if records.len() > MAX_PARTICIPANT_RECORDS {
        return Err(corrupt_record());
    }
    for (id, stored) in records {
        for value in [
            id,
            &stored.owner_principal_id,
            &stored.profile_id,
            &stored.candidate_id,
            &stored.retained_source_id,
        ] {
            validate_identifier(value).map_err(|_| corrupt_record())?;
        }
        let record = SettlementRecord::load_retained_archive(stored.record.clone())
            .map_err(|_| corrupt_record())?;
        if id != record.record_id()
            || stored.candidate_id != record.proposal().input().proposal_id
            || agreement_id != record.proposal().manifest().agreement.agreement_id
            || stored.record_revision == 0
            || stored.disclosure_previews.len() > MAX_PRIVATE_PREVIEWS
            || stored.retirement_plans.len() > MAX_RETIREMENT_PLANS
        {
            return Err(corrupt_record());
        }
        wholepact_core::proposal::validate_sha256(&stored.candidate_proposal_digest)
            .map_err(|_| corrupt_record())?;
        for (preview_id, preview) in &stored.disclosure_previews {
            validate_identifier(preview_id).map_err(|_| corrupt_record())?;
            preview
                .preview_window
                .validate()
                .map_err(|_| corrupt_record())?;
            wholepact_core::proposal::validate_sha256(&preview.preview_digest)
                .map_err(|_| corrupt_record())?;
            wholepact_core::proposal::validate_sha256(&preview.record_digest)
                .map_err(|_| corrupt_record())?;
        }
        disclosure_exports::validate_exports(stored)?;
        for (plan_id, plan) in &stored.retirement_plans {
            if plan_id != &plan.request.plan_id
                || plan.request.account_id != record.own_authorization().account_id
                || plan.request.network_profile_id != record.transaction().network_profile_id
                || plan.viewing_key_exposure != VIEWING_KEY_EXPOSURE_STATEMENT
                || plan.status != "unsigned_separate_review_and_authorization_required"
                || plan.inputs.is_empty()
                || plan.inputs.len() > 256
                || plan.transfer_amount == Amount::ZERO
                || plan
                    .transfer_amount
                    .checked_add(plan.fee)
                    .map_err(wholepact_core::CoreError::from)?
                    != plan.maximum_net_debit
                || plan.maximum_net_debit > plan.request.maximum_net_debit
                || plan.fee > plan.request.maximum_fee
            {
                return Err(corrupt_record());
            }
            wholepact_core::proposal::validate_sha256(&plan.plan_digest)
                .map_err(|_| corrupt_record())?;
        }
    }
    Ok(())
}

/// A trusted recovery adapter must account for releases this engine already
/// knows. A reconciled empty source view cannot erase a retained authorization.
struct KnownReleaseRecoverySource<'a, S> {
    inner: &'a mut S,
    known_record: &'a SettlementRecord,
}
impl<S: AccountRecoverySource> AccountRecoverySource for KnownReleaseRecoverySource<'_, S> {
    fn read_recovery_view(
        &mut self,
        account_id: &str,
    ) -> wholepact_core::Result<wholepact_core::retirement::AccountRecoveryView> {
        let view = self.inner.read_recovery_view(account_id)?;
        let record = self.known_record;
        if record.own_authorization().exposure.was_released() {
            let expected_inputs: BTreeSet<_> = record
                .proposal()
                .manifest()
                .inputs
                .iter()
                .filter(|input| input.account_id == account_id)
                .map(|input| input.input_id.as_str())
                .collect();
            let exact_debit = record
                .proposal()
                .accounting()
                .participant_net_debits
                .get(&record.own_authorization().participant_id)
                .ok_or_else(|| {
                    wholepact_core::CoreError::new(
                        wholepact_core::ErrorCode::MissingEvidence,
                        "retained account reviewed debit is missing",
                    )
                })?;
            let matching = view
                .revisions
                .iter()
                .find(|revision| revision.proposal_id == record.proposal().input().proposal_id);
            if !matching.is_some_and(|revision| {
                revision.obligation_id == record.proposal().manifest().agreement.obligation_id
                    && revision.maximum_net_debit == *exact_debit
                    && revision.exposure.was_released()
                    && revision
                        .input_ids
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>()
                        == expected_inputs
            }) {
                return Err(wholepact_core::CoreError::new(
                    wholepact_core::ErrorCode::RecoveryRequired,
                    "recovery source omitted or contradicted a retained released authorization; empty history cannot erase known exposure",
                ));
            }
        }
        Ok(view)
    }
    fn verify_destination(
        &mut self,
        request: &wholepact_core::retirement::ReclaimDestinationRequest,
        network: &str,
    ) -> wholepact_core::Result<UserControlledShieldedDestination> {
        self.inner.verify_destination(request, network)
    }
    fn quote_residual_transfer(
        &mut self,
        view: &wholepact_core::retirement::AccountRecoveryView,
        destination: &UserControlledShieldedDestination,
    ) -> wholepact_core::Result<wholepact_core::retirement::ReclaimFeeQuote> {
        self.inner.quote_residual_transfer(view, destination)
    }
}

impl StoredParticipantRecord {
    #[cfg(feature = "submission-handoff")]
    pub(crate) fn settlement_account_id(&self) -> &str {
        &self.record.own_authorization.account_id
    }
    #[cfg(feature = "submission-handoff")]
    pub(crate) fn invalidate_settlement(&mut self) -> Result<bool> {
        if self.settlement_invalidated {
            return Ok(false);
        }
        self.settlement_invalidated = true;
        self.record.exposure_reconciliation_required = true;
        advance_record_revision(self)?;
        Ok(true)
    }
}
