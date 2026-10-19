//! Closed original-source, nonspending fixed-proof composition. There is no
//! financial admission, ordinary viewing-profile attachment or generic Engine
//! escape here. All claims are checked against the actual retained Host owners.
use super::Host;
use crate::files::Directory;
use crate::recovery_generation::manual_target::ManualCommittedTarget;
use crate::terminal::historical::HistoricalApproval;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use wholepact_core::{AgreementDraft, IntentStatus, ParticipationIntent};
use wholepact_engine::manual_enrollment::ManualRosterIntentTarget;
use wholepact_engine::planning::RosterSelectionRequest;
use wholepact_engine::{AgreementView, CandidateRequest, Mutation};

/// Inert claims only. An account label cannot establish participant ownership,
/// an enrollment, a disclosure, a reservation or spending consent.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct PrivateSourceSelectionClaimV1 {
    pub account_id: String,
    pub intent: ParticipationIntent,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct PrivateSourceSelectionV1 {
    pub claims: Vec<PrivateSourceSelectionClaimV1>,
}
#[derive(Serialize)]
pub(in crate::host) struct PrivateSourceSelectionStatusV1 {
    pub revision: u64,
    pub replayed: bool,
    pub nonbinding_coordinator_selection: bool,
    pub participant_approval: bool,
    pub authorization_allowed: bool,
}

fn source_step_keys(key: &str) -> Result<[String; 3]> {
    if !(16..=128).contains(&key.len()) || !key.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Error::Invalid);
    }
    // Bind only the original caller key, not mutable/current record state.
    // A changed request under one key must conflict in the maintained Engine.
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:private-source-selection-subkeys:v1",
        &key,
    )
    .map_err(|_| Error::Invalid)?;
    Ok([
        format!("private-source-{digest}-intent-0"),
        format!("private-source-{digest}-intent-1"),
        format!("private-source-{digest}-select"),
    ])
}

fn same_intent_claim(
    actual: &ParticipationIntent,
    expected: &ParticipationIntent,
    selected: bool,
) -> bool {
    let mut claim = expected.clone();
    if selected {
        claim.status = IntentStatus::Selected;
    }
    actual == &claim
}

fn validate_partial_selection(
    view: &AgreementView,
    original_revision: u64,
    selection: &PrivateSourceSelectionV1,
) -> Result<usize> {
    let stage = view
        .revision
        .checked_sub(original_revision)
        .ok_or(Error::Invalid)?;
    if stage > 3
        || selection.claims.len() != 2
        || view.cancellation_requested
        || !view.candidates.is_empty()
        || !view.proposals.is_empty()
        || !view.verification_reports.is_empty()
        || view.intents.len() != usize::try_from(stage.min(2)).map_err(|_| Error::Invalid)?
        || view.roster_selected != (stage == 3)
    {
        return Err(Error::Invalid);
    }
    for (actual, claim) in view.intents.iter().zip(&selection.claims) {
        if !same_intent_claim(actual, &claim.intent, stage == 3) {
            return Err(Error::Authentication);
        }
    }
    Ok(stage as usize)
}

struct SourceSelectionBindingV1 {
    agreement: AgreementDraft,
    terms_history: Vec<AgreementDraft>,
    roster: wholepact_core::manual_roster_v2::HostRosterAppendBindingV2,
    members: Vec<wholepact_store::manual_enrollment::ManualEnrollmentRosterMember>,
    financial_origin: String,
    source_destination: String,
    principal: String,
}
impl SourceSelectionBindingV1 {
    fn check(
        &self,
        host: &Host,
        committed: &ManualCommittedTarget<'_>,
        target: &ManualRosterIntentTarget<'_>,
    ) -> Result<()> {
        host.require_manual_session()?;
        host.secrets.require_portable_legacy()?;
        host.directory.refuse_private_workspace_files()?;
        committed.check_current()?;
        committed.coverage().require_complete()?;
        target
            .check_current(host.access()?)
            .map_err(observe_engine_source)?;
        let view = host
            .engine
            .get(host.access()?, &self.agreement.agreement_id)
            .map_err(observe_engine_source)?;
        if target.principal_id() != self.principal
            || target.owner_client_id() != self.principal
            || host.access()?.principal_id != self.principal
            || target.agreement() != &self.agreement
            || view.agreement != self.agreement
            || view.terms_history != self.terms_history
            || target.binding() != &self.roster
            || target
                .members(host.access()?)
                .map_err(observe_engine_source)?
                != self.members
            || target.store_destination_identity() != self.source_destination
            || target.generation_id() != committed.generation_id()
            || target.inventory_digest() != committed.inventory_digest()
            || host
                .financial
                .as_ref()
                .ok_or(Error::Locked)?
                .manual_original_primary_origin_digest(&host.directory, &host.secrets)?
                != self.financial_origin
        {
            return Err(Error::Authentication);
        }
        require_operator_principal(&self.agreement, &self.principal)?;
        target
            .check_current(host.access()?)
            .map_err(observe_engine_source)
    }
}
fn require_operator_principal(agreement: &AgreementDraft, principal: &str) -> Result<()> {
    if agreement.organizer_identity != principal
        || agreement.privacy_profile.proving_operator.as_deref() != Some(principal)
    {
        return Err(Error::Permission);
    }
    Ok(())
}

fn validate_claim_accounts(
    target: &ManualRosterIntentTarget<'_>,
    access: &wholepact_engine::Access,
    selection: &PrivateSourceSelectionV1,
) -> Result<()> {
    if selection.claims.len() != 2 {
        return Err(Error::Invalid);
    }
    let mut accounts = BTreeSet::new();
    let mut participants = BTreeSet::new();
    let mut intents = BTreeSet::new();
    let members = target.members(access).map_err(observe_engine_source)?;
    for claim in &selection.claims {
        claim.intent.validate().map_err(|_| Error::Invalid)?;
        if claim.intent.status != IntentStatus::Active
            || claim.intent.agreement_id != target.agreement().agreement_id
            || !accounts.insert(&claim.account_id)
            || !participants.insert(&claim.intent.participant_id)
            || !intents.insert(&claim.intent.intent_id)
        {
            return Err(Error::Invalid);
        }
        let matching = members
            .iter()
            .filter(|member| {
                member.identity.account_id == claim.account_id
                    && member.scope.participant_id == claim.intent.participant_id
                    && member.scope.agreement_id == target.agreement().agreement_id
                    && member.scope.obligation_id == target.agreement().obligation_id
                    && member.scope.principal_id == access.principal_id
            })
            .count();
        if matching != 1 {
            return Err(Error::Authentication);
        }
    }
    target.check_current(access).map_err(observe_engine_source)
}

fn verify_saved_source_operation(host: &Host, mutation: &Mutation, kind: &str) -> Result<()> {
    // Load the actual saved original result by its returned identifier, never
    // independently derive a Store operation ID or adopt matching current rows.
    let mut operation = host
        .engine
        .operation(host.access()?, &mutation.operation_id)
        .map_err(observe_engine_source)?;
    let mut expected = serde_json::to_value(mutation)?;
    // Replay is a presentation bit. The original persisted operation owns the
    // same revision, timestamps, event sequence and complete original result.
    expected["replayed"] = serde_json::Value::Bool(false);
    // This is recomputed caller guidance, not saved operation provenance.
    expected["agreement"]
        .as_object_mut()
        .ok_or(Error::Invalid)?
        .remove("terms_editability");
    operation["result"]["agreement"]
        .as_object_mut()
        .ok_or(Error::Invalid)?
        .remove("terms_editability");
    if operation.get("operation_id").and_then(|v| v.as_str())
        != Some(mutation.operation_id.as_str())
        || operation.get("kind").and_then(|v| v.as_str()) != Some(kind)
        || operation.get("resource_id").and_then(|v| v.as_str())
            != Some(mutation.agreement.agreement.agreement_id.as_str())
        || operation.get("result") != Some(&expected)
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

impl Host {
    pub(in crate::host) fn private_durable_source_select_v1_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let agreement = self.terminal.ask("Exact current agreement ID: ")?;
        let revision: u64 = self
            .terminal
            .ask("Original source-selection starting revision (preserve on retry): ")?
            .parse()
            .map_err(|_| Error::Invalid)?;
        let key = self
            .terminal
            .ask("Stable original source-selection key (preserve unchanged on retry): ")?;
        let selection = self.read_manual_private(
            "Private exact two-account coordinator intent claims JSON file: ",
            "nonbinding original roster source selection",
        )?;
        let status =
            self.private_durable_source_select_v1(&agreement, revision, &key, selection)?;
        self.terminal.json(&status)
    }

    pub(in crate::host) fn private_durable_source_select_v1(
        &self,
        agreement_id: &str,
        original_revision: u64,
        key: &str,
        selection: PrivateSourceSelectionV1,
    ) -> Result<PrivateSourceSelectionStatusV1> {
        begin_private_stage(PrivateBoundaryV2::Source);
        let result = self.private_durable_source_select_inner_v1(
            agreement_id,
            original_revision,
            key,
            selection,
        );
        if let Err(error) = &result {
            observe_host_current(error);
        } else {
            complete_private_stage(PrivateBoundaryV2::Source);
        }
        result
    }
    fn private_durable_source_select_inner_v1(
        &self,
        agreement_id: &str,
        original_revision: u64,
        key: &str,
        selection: PrivateSourceSelectionV1,
    ) -> Result<PrivateSourceSelectionStatusV1> {
        self.require_manual_session()?;
        self.secrets.require_portable_legacy()?;
        self.directory.refuse_private_workspace_files()?;
        let keys = source_step_keys(key)?;
        let prior = self.terminal.approve_historical(
            "Inspect the exact original Host roster, current agreement and complete original terms for nonbinding coordinator source selection. This reads local identity metadata only; it grants no participant approval, ownership, viewing disclosure, financial authority or spending permission."
        )?;
        let mut owners = None;
        prior.effect(&mut || {
            self.require_manual_session()?;
            let committed = ManualCommittedTarget::open(&self.directory, &self.secrets)?;
            committed.coverage().require_complete()?;
            let target = self
                .engine
                .manual_roster_intent_target(self.access()?, agreement_id)
                .map_err(observe_engine_source)?;
            let primary = self.financial.as_ref().ok_or(Error::Locked)?;
            let origin =
                primary.manual_original_primary_origin_digest(&self.directory, &self.secrets)?;
            let entries = crate::financial_inventory::read_current(&self.directory, &self.secrets)?;
            if entries.len() != 1
                || entries[0].role != crate::financial_inventory::AttachmentRole::PrimaryFinancial
                || entries[0].account.is_some()
                || entries[0].directory != primary.current_directory()?
            {
                return Err(Error::RecoveryFinancialUnsupported);
            }
            let view = self
                .engine
                .get(self.access()?, agreement_id)
                .map_err(observe_engine_source)?;
            let binding = SourceSelectionBindingV1 {
                agreement: target.agreement().clone(),
                terms_history: view.terms_history.clone(),
                roster: target.binding().clone(),
                members: target
                    .members(self.access()?)
                    .map_err(observe_engine_current)?
                    .to_vec(),
                financial_origin: origin,
                source_destination: target.store_destination_identity().into(),
                principal: self.access()?.principal_id.clone(),
            };
            binding.check(self, &committed, &target)?;
            validate_claim_accounts(&target, self.access()?, &selection)?;
            validate_partial_selection(&view, original_revision, &selection)?;
            self.engine
                .validate_private_workspace_source_selection_v1(
                    self.access()?,
                    &target,
                    &selection
                        .claims
                        .iter()
                        .map(|c| c.intent.clone())
                        .collect::<Vec<_>>(),
                )
                .map_err(observe_engine_source)?;
            owners = Some((committed, binding));
            Ok(())
        })?;
        let (committed, binding) = owners.ok_or(Error::Authentication)?;
        let review = self.terminal.approve_historical_reviewed(&prior, &format!(
            "Record exactly two NONBINDING coordinator-owned intent claims and select their unchanged amounts on this actual original Host. No participant approval, input/account ownership, disclosure, reservation or spending authority is asserted. Existing incompatible terms are never rewritten. Partial completion is preserved and only these exact original requests may replay.\nPrincipal: {}\nAgreement and original terms: {}\nActual enrolled roster: {}\nExact account and economic claims: {}",
            binding.principal,
            serde_json::to_string_pretty(&(&binding.agreement, &binding.terms_history))?,
            serde_json::to_string_pretty(&binding.members)?,
            serde_json::to_string_pretty(&selection)?,
        ))?;
        let mut replayed = None;
        review.effect(&mut || {
            replayed = Some(run_original_source_steps_v1(
                |index| {
                    let _ = index;
                    review.check()?;
                    // A target pins the complete record and is dropped before any write.
                    let target = self
                        .engine
                        .manual_roster_intent_target(self.access()?, agreement_id)
                        .map_err(observe_engine_source)?;
                    binding.check(self, &committed, &target)?;
                    validate_claim_accounts(&target, self.access()?, &selection)?;
                    validate_partial_selection(
                        &self
                            .engine
                            .get(self.access()?, agreement_id)
                            .map_err(observe_engine_source)?,
                        original_revision,
                        &selection,
                    )?;
                    self.engine
                        .validate_private_workspace_source_selection_v1(
                            self.access()?,
                            &target,
                            &selection
                                .claims
                                .iter()
                                .map(|c| c.intent.clone())
                                .collect::<Vec<_>>(),
                        )
                        .map_err(observe_engine_source)?;
                    Ok(())
                },
                |index| {
                    let expected = original_revision
                        .checked_add(index as u64)
                        .ok_or(Error::Invalid)?;
                    if index < 2 {
                        self.engine
                            .add_intent(
                                self.access()?,
                                &keys[index],
                                agreement_id,
                                expected,
                                selection.claims[index].intent.clone(),
                            )
                            .map_err(observe_engine_source)
                    } else {
                        self.engine
                            .select_roster(
                                self.access()?,
                                &keys[index],
                                agreement_id,
                                expected,
                                RosterSelectionRequest {
                                    selected_intent_ids: selection
                                        .claims
                                        .iter()
                                        .map(|c| c.intent.intent_id.clone())
                                        .collect(),
                                },
                            )
                            .map_err(observe_engine_source)
                    }
                },
                |index, mutation| {
                    verify_saved_source_operation(
                        self,
                        mutation,
                        if index < 2 {
                            "intent_recorded"
                        } else {
                            "nonbinding_roster_selected"
                        },
                    )?;
                    // Reacquire immediately after every real write or replay. The
                    // pre-write target is never reused, even on partial completion.
                    let target = self
                        .engine
                        .manual_roster_intent_target(self.access()?, agreement_id)
                        .map_err(observe_engine_source)?;
                    binding.check(self, &committed, &target)?;
                    validate_claim_accounts(&target, self.access()?, &selection)?;
                    validate_partial_selection(
                        &self
                            .engine
                            .get(self.access()?, agreement_id)
                            .map_err(observe_engine_source)?,
                        original_revision,
                        &selection,
                    )?;
                    review.check()
                },
            )?);
            Ok(())
        })?;
        let replayed = replayed.ok_or(Error::Authentication)?;
        let current = self
            .engine
            .get(self.access()?, agreement_id)
            .map_err(observe_engine_source)?;
        if validate_partial_selection(&current, original_revision, &selection)? != 3 {
            return Err(Error::Authentication);
        }
        // The maintained selected source itself performs the final original
        // intent-owner, account/FVK/policy, proposer and historical terms join.
        let source = self
            .engine
            .original_private_workspace_source_v1(self.access()?, agreement_id)
            .map_err(observe_engine_source)?;
        source
            .check_current(self.access()?)
            .map_err(observe_engine_source)?;
        review.check()?;
        Ok(PrivateSourceSelectionStatusV1 {
            revision: current.revision,
            replayed,
            nonbinding_coordinator_selection: true,
            participant_approval: false,
            authorization_allowed: false,
        })
    }
}

use crate::host::durable_private_workspace_v1::PrivateWorkspaceOwnerV1;
use wholepact_engine::durable_construction_v1::{
    DurableMaterialActionV1, LocalDurableMaterialConsentV1,
};
use wholepact_engine::{
    LocalPrivateWorkspaceConsentV1, PrivateDurableCoordinatorV1, PrivateExactCandidateV2,
    PrivateVerifiedFixedV2, PrivateWorkspaceActionV1, PrivateWorkspaceScopeV1,
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_signer::authority_bridge::{
    durable_construction_v1::{DurableConstructionCaptureRequestV1, DurableConstructionScopeV1},
    ipc::OriginalHistoryClient,
    preconstruction_ipc::PreconstructionRequest,
};
use wholepact_storage_security::{DatabaseFileIdentity, DatabaseKey};
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{
        BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
        durable_construction_v1::{
            DurableConstructionWalletSlotV1, FreshDurableConstructionObservationV1,
            DurableConstructionError,
        },
    },
};

fn material_action_tag(action: DurableMaterialActionV1) -> Option<u8> {
    match action {
        DurableMaterialActionV1::RetainAuthenticatedDisclosure => Some(0),
        DurableMaterialActionV1::ReadForExactConstruction => Some(1),
        // Fixed review export is intentionally not a precursor permission.
        DurableMaterialActionV1::ExportForLocalNativeReview => None,
    }
}
fn wall_seconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Permission)
}

#[derive(Clone, Copy)]
enum CurrentApprovalModeV2 {
    ReviewMissing,
    CachedOnly,
}

/// A missing approval may reach review only in the original foreground path.
/// Cached denials never fall back to review, and every hit rechecks the actual
/// original native approval before current material/source restrictions.
fn current_approval_permission_v2<T>(
    mode: CurrentApprovalModeV2,
    cached: Option<&T>,
    exact: impl FnOnce(&T) -> bool,
    native: impl FnOnce(&T) -> bool,
    current: impl FnOnce() -> bool,
) -> Option<bool> {
    match cached {
        Some(approval) => Some(exact(approval) && native(approval) && current()),
        None => match mode {
            CurrentApprovalModeV2::ReviewMissing => None,
            CurrentApprovalModeV2::CachedOnly => Some(false),
        },
    }
}

/// A real current Host privacy decision, not native owner provenance. The sealed
/// native disclosure still has to be consumed by the maintained Engine intake.
/// Every callback rechecks actual originals without reentering the proof mutex.
struct CurrentMaterialPrivacyV2<'a, 'host> {
    host: &'host Host,
    owner: &'a PrivateWorkspaceOwnerV1<'host>,
    candidate_id: Option<&'a str>,
    exact_proposal: Option<&'a wholepact_core::ProposalInput>,
    allowed: u8,
    approved: Mutex<Vec<(DurableConstructionScopeV1, String, HistoricalApproval)>>,
}
impl<'a, 'host> CurrentMaterialPrivacyV2<'a, 'host> {
    fn new(
        host: &'host Host,
        owner: &'a PrivateWorkspaceOwnerV1<'host>,
        candidate_id: &'a str,
        exact_proposal: Option<&'a wholepact_core::ProposalInput>,
        allowed: u8,
    ) -> Self {
        Self {
            host,
            owner,
            candidate_id: Some(candidate_id),
            exact_proposal,
            allowed,
            approved: Mutex::new(Vec::new()),
        }
    }
    fn scope_current(&self, scope: &DurableConstructionScopeV1) -> Result<()> {
        self.owner.check_current_without_proof_lock_v2()?;
        scope
            .check_valid_at(wall_seconds()?)
            .map_err(|_| Error::Permission)?;
        let target = self
            .host
            .engine
            .manual_roster_intent_target(self.host.access()?, self.owner.agreement_id())
            .map_err(observe_engine_current)?;
        let principal = &self.host.access()?.principal_id;
        require_operator_principal(target.agreement(), principal)?;
        let mut reviewers = scope
            .reviewers
            .iter()
            .map(|r| r.account_id().to_owned())
            .collect::<Vec<_>>();
        reviewers.sort();
        let mut expected = self.owner.reviewer_account_ids().to_vec();
        expected.sort();
        if scope.version != 2
            || self
                .candidate_id
                .is_some_and(|id| scope.proposal.proposal_id != id)
            || scope.proposal.manifest.agreement != *target.agreement()
            || self
                .exact_proposal
                .is_some_and(|proposal| proposal != &scope.proposal)
            || scope.constructor.principal_id != *principal
            || scope.prover.principal_id != *principal
            || scope.constructor != scope.prover
            || scope.protected_destination
                != self
                    .owner
                    .metadata_destination()
                    .to_str()
                    .ok_or(Error::Invalid)?
            || scope.retention_policy != self.owner.retention_policy()
            || reviewers != expected
            || expected.len() != 2
            || !expected.contains(&scope.account_id)
            || scope.purpose
                != wholepact_wallet::wallet::protected_sync::durable_construction_v1::PURPOSE
        {
            return Err(Error::Authentication);
        }
        let matching = target
            .members(self.host.access()?)
            .map_err(observe_engine_current)?
            .iter()
            .filter(|member| {
                member.identity.account_id == scope.account_id
                    && member.scope.participant_id == scope.participant_id
                    && member.scope.privacy_domain == scope.privacy_domain
                    && member.scope.agreement_id == self.owner.agreement_id()
                    && member.scope.obligation_id == scope.proposal.manifest.agreement.obligation_id
                    && member.scope.principal_id == *principal
            })
            .count();
        if matching != 1 {
            return Err(Error::Authentication);
        }
        target
            .check_current(self.host.access()?)
            .map_err(observe_engine_current)?;
        self.owner.check_current_without_proof_lock_v2()
    }
    fn check_complete(&self) -> Result<()> {
        let approved = self.approved.lock().map_err(|_| Error::Permission)?;
        if approved.len() != 2 {
            return Err(Error::Permission);
        }
        let mut accounts = BTreeSet::new();
        for (scope, _, approval) in approved.iter() {
            if !accounts.insert(&scope.account_id) {
                return Err(Error::Permission);
            }
            self.scope_current(scope)?;
            approval.check()?;
        }
        Ok(())
    }
    fn exact_scopes(&self) -> Result<Vec<DurableConstructionScopeV1>> {
        let approved = self.approved.lock().map_err(|_| Error::Permission)?;
        Ok(approved.iter().map(|(scope, _, _)| scope.clone()).collect())
    }
}
impl CurrentMaterialPrivacyV2<'_, '_> {
    fn permits_current(
        &self,
        scope: &DurableConstructionScopeV1,
        material: &str,
        action: DurableMaterialActionV1,
        mode: CurrentApprovalModeV2,
    ) -> bool {
        let Some(action) = material_action_tag(action) else {
            return false;
        };
        if action != self.allowed || !valid_commitment(material) {
            return false;
        }
        if !observed_private_permission_at_v1(
            PrivateDiagnosticSiteV1::HostMaterialScope,
            self.scope_current(scope),
        ) {
            return false;
        }
        let Ok(mut approved) = self.approved.lock() else {
            return false;
        };
        if let Some(allowed) = current_approval_permission_v2(
            mode,
            approved
                .iter()
                .find(|(s, _, _)| s.account_id == scope.account_id),
            |(original, digest, _)| original == scope && digest == material,
            |(_, _, approval)| {
                observed_private_permission_at_v1(
                    PrivateDiagnosticSiteV1::HostMaterialNativeCheck,
                    approval.check(),
                )
            },
            || {
                observed_private_permission_at_v1(
                    PrivateDiagnosticSiteV1::HostMaterialScope,
                    self.scope_current(scope),
                )
            },
        ) {
            return allowed;
        }
        if approved.len() >= 2 {
            return false;
        }
        let Ok(detail) = serde_json::to_string_pretty(scope) else {
            return false;
        };
        let approval = match self.host.terminal.approve_historical(&format!(
            "Allow this exact original private material for {} in this current native command?\n{detail}\nOriginal material commitment: {material}\nThe original absolute privacy ceiling is not renewed. This is local retention/read only, not participant ownership, financial authority, review export, signing or submission.",
            if action == 0 { "sealed initial durable retention" } else { "bounded original construction/proof/fixed verification" },
        )) { Ok(approval) => approval, Err(error) => { observe_private_host_current_at_v1(PrivateDiagnosticSiteV1::HostMaterialApproval,&error);observe_host_current(&error); return false; } };
        if !observed_private_permission_at_v1(
            PrivateDiagnosticSiteV1::HostMaterialScope,
            self.scope_current(scope),
        ) || !observed_private_permission_at_v1(
            PrivateDiagnosticSiteV1::HostMaterialNativeCheck,
            approval.check(),
        ) {
            return false;
        }
        approved.push((scope.clone(), material.into(), approval));
        true
    }
}
impl LocalDurableMaterialConsentV1 for CurrentMaterialPrivacyV2<'_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        material: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        self.permits_current(
            scope,
            material,
            action,
            CurrentApprovalModeV2::ReviewMissing,
        )
    }
}
/// Borrow the original approval cache without any ability to prompt on a miss.
struct CachedMaterialPrivacyV2<'cache, 'a, 'host>(&'cache CurrentMaterialPrivacyV2<'a, 'host>);
impl LocalDurableMaterialConsentV1 for CachedMaterialPrivacyV2<'_, '_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        material: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        self.0
            .permits_current(scope, material, action, CurrentApprovalModeV2::CachedOnly)
    }
}
fn valid_commitment(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct CurrentProofPrivacyV2<'a, 'host> {
    material: &'a CurrentMaterialPrivacyV2<'a, 'host>,
    allowed: Vec<LocalAction>,
    approved: Mutex<Vec<(CheckpointScope, LocalAction, HistoricalApproval)>>,
}
impl CurrentProofPrivacyV2<'_, '_> {
    fn permits_current(
        &self,
        scope: &CheckpointScope,
        action: LocalAction,
        mode: CurrentApprovalModeV2,
    ) -> bool {
        if !self.allowed.contains(&action) {
            return false;
        }
        if !observed_private_permission_at_v1(
            PrivateDiagnosticSiteV1::HostProofScope,
            self.material.check_complete(),
        ) {
            return false;
        }
        let scopes = match self.material.exact_scopes() {
            Ok(scopes) => scopes,
            Err(error) => {
                observe_private_host_current_at_v1(PrivateDiagnosticSiteV1::HostProofScope, &error);
                observe_host_current(&error);
                return false;
            }
        };
        let access = match self.material.host.access() {
            Ok(access) => access,
            Err(error) => {
                observe_private_host_current_at_v1(PrivateDiagnosticSiteV1::HostProofScope, &error);
                observe_host_current(&error);
                return false;
            }
        };
        let mut accounts = scope.account_ids.clone();
        accounts.sort();
        let mut expected = self.material.owner.reviewer_account_ids().to_vec();
        expected.sort();
        if accounts != expected
            || scope.principal_id != access.principal_id
            || self
                .material
                .candidate_id
                .is_some_and(|id| scope.candidate_id != id)
            || scope.local_operator != scope.principal_id
            || scope.retention_policy != self.material.owner.retention_policy()
            || scope.purpose
                != wholepact_wallet::wallet::protected_sync::durable_construction_v1::PURPOSE
            || scopes.iter().any(|s| {
                s.proposal.proposal_id != scope.candidate_id
                    || wholepact_core::Proposal::validate(s.proposal.clone())
                        .map_or(true, |p| p.manifest_digest() != scope.manifest_digest)
            })
        {
            return false;
        }
        let Ok(mut approved) = self.approved.lock() else {
            return false;
        };
        if approved.iter().any(|(prior, _, _)| prior != scope) {
            return false;
        }
        if let Some(allowed) = current_approval_permission_v2(
            mode,
            approved.iter().find(|(_, a, _)| *a == action),
            |(original, approved_action, _)| original == scope && *approved_action == action,
            |(_, _, native)| {
                observed_private_permission_at_v1(
                    PrivateDiagnosticSiteV1::HostProofNativeCheck,
                    native.check(),
                )
            },
            || {
                observed_private_permission_at_v1(
                    PrivateDiagnosticSiteV1::HostProofScope,
                    self.material.check_complete(),
                )
            },
        ) {
            return allowed;
        }
        let Ok(detail) = serde_json::to_string_pretty(scope) else {
            return false;
        };
        let native = match self.material.host.terminal.approve_historical(&format!(
            "Allow {action:?} for this exact original private workspace checkpoint?\n{detail}\nOnly the actual original primary proof journal is used. A first proof attempt consumes its live continuation; interruption never authorizes restart. No remote export, financial admission, signature or submission is allowed."
        )) { Ok(native) => native, Err(error) => { observe_private_host_current_at_v1(PrivateDiagnosticSiteV1::HostProofApproval,&error);observe_host_current(&error); return false; } };
        if !observed_private_permission_at_v1(
            PrivateDiagnosticSiteV1::HostProofNativeCheck,
            native.check(),
        ) || !observed_private_permission_at_v1(
            PrivateDiagnosticSiteV1::HostProofScope,
            self.material.check_complete(),
        ) {
            return false;
        }
        approved.push((scope.clone(), action, native));
        true
    }
}
impl LocalProofConsent for CurrentProofPrivacyV2<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.permits_current(scope, action, CurrentApprovalModeV2::ReviewMissing)
    }
}
struct CachedProofPrivacyV2<'cache, 'a, 'host>(&'cache CurrentProofPrivacyV2<'a, 'host>);
impl LocalProofConsent for CachedProofPrivacyV2<'_, '_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.0
            .permits_current(scope, action, CurrentApprovalModeV2::CachedOnly)
    }
}

struct ScanWalletOwnerV2 {
    wallet: Option<ProtectedWalletSync>,
    key: Option<DatabaseKey>,
    origin: Option<DatabaseFileIdentity>,
    directory: Option<Directory>,
    root: PathBuf,
}
impl ScanWalletOwnerV2 {
    fn check(&self) -> Result<()> {
        let directory = self.directory.as_ref().ok_or(Error::Invalid)?;
        directory.check()?;
        directory.inventory_of(&["wallet.sqlite"], &["profile.lock"])?;
        if let Some(origin) = &self.origin {
            origin
                .check_retained_owner_path()
                .map_err(|_| Error::Authentication)?;
        }
        Ok(())
    }
    fn destination(&self) -> Result<PathBuf> {
        self.directory
            .as_ref()
            .ok_or(Error::Invalid)?
            .path("wallet.sqlite")
    }
    fn create_destination(&mut self) -> Result<wholepact_storage_security::EncryptedConnection> {
        self.check()?;
        if self.origin.is_some() || self.wallet.is_some() || self.key.is_some() {
            return Err(Error::Invalid);
        }
        let key = DatabaseKey::from_bytes(crate::random::<32>()?);
        let connection = wholepact_storage_security::create_encrypted(self.destination()?, &key)
            .map_err(|_| Error::Storage)?;
        let origin = connection
            .database_identity()
            .map_err(|_| Error::Authentication)?;
        origin
            .check_current(connection.connection())
            .map_err(|_| Error::Authentication)?;
        self.key = Some(key);
        self.origin = Some(origin);
        self.check()?;
        Ok(connection)
    }
    fn close_wallet_and_key(&mut self) {
        // Explicit order, also used on error/unwind. No key is ever persisted.
        drop(self.wallet.take());
        drop(self.key.take());
    }
}
impl Drop for ScanWalletOwnerV2 {
    fn drop(&mut self) {
        self.close_wallet_and_key();
    }
}

/// Sole owner of two fresh, process-only protected scans. There is deliberately
/// no open-existing, adoption, serialization, raw key or raw wallet constructor.
struct OriginalConstructionScanCacheV2 {
    wallets: [ScanWalletOwnerV2; 2],
    directory: Option<Directory>,
    root: PathBuf,
}
impl OriginalConstructionScanCacheV2 {
    fn create(host: &Host, workspace: &PrivateWorkspaceOwnerV1<'_>, root: &Path) -> Result<Self> {
        workspace.check_current_without_proof_lock_v2()?;
        for protected in [
            &host.directory,
            &host.financial.as_ref().ok_or(Error::Locked)?.directory,
        ] {
            protected.external_destination(root)?;
            if protected
                .path("profile.lock")?
                .parent()
                .ok_or(Error::Invalid)?
                .starts_with(root)
            {
                return Err(Error::Invalid);
            }
        }
        crate::files::validate_absolute(root)?;
        if root.starts_with(workspace.workspace_root())
            || workspace.workspace_root().starts_with(root)
        {
            return Err(Error::Invalid);
        }
        let directory = Directory::create(root)?;
        let left_root = root.join("owner-0");
        let right_root = root.join("owner-1");
        let left = Directory::create(&left_root)?;
        let right = Directory::create(&right_root)?;
        let cache = Self {
            wallets: [
                ScanWalletOwnerV2 {
                    wallet: None,
                    key: None,
                    origin: None,
                    directory: Some(left),
                    root: left_root,
                },
                ScanWalletOwnerV2 {
                    wallet: None,
                    key: None,
                    origin: None,
                    directory: Some(right),
                    root: right_root,
                },
            ],
            directory: Some(directory),
            root: root.into(),
        };
        cache.check()?;
        Ok(cache)
    }
    fn check(&self) -> Result<()> {
        self.directory.as_ref().ok_or(Error::Invalid)?.check()?;
        let mut entries = std::fs::read_dir(&self.root)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        if entries != ["owner-0", "owner-1", "profile.lock"].map(std::ffi::OsString::from) {
            return Err(Error::Authentication);
        }
        for wallet in &self.wallets {
            wallet.check()?;
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<()> {
        // Nothing is removed until the entire exact owner inventory is checked.
        // Dropped futures/held slots must already be gone before this method.
        self.check()?;
        for wallet in &mut self.wallets {
            wallet.close_wallet_and_key();
        }
        self.check()?;
        for wallet in &mut self.wallets {
            let directory = wallet.directory.as_ref().ok_or(Error::Invalid)?;
            directory.check()?;
            for name in [
                "wallet.sqlite-journal",
                "wallet.sqlite-wal",
                "wallet.sqlite-shm",
                "wallet.sqlite",
            ] {
                let path = directory.path(name)?;
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => std::fs::remove_file(path)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                }
            }
            directory.check()?;
            std::fs::remove_file(directory.path("profile.lock")?)?;
            drop(wallet.directory.take());
            std::fs::remove_dir(&wallet.root)?;
            if wallet.root.try_exists()? {
                return Err(Error::Storage);
            }
        }
        let directory = self.directory.as_ref().ok_or(Error::Invalid)?;
        directory.check()?;
        std::fs::remove_file(directory.path("profile.lock")?)?;
        drop(self.directory.take());
        std::fs::remove_dir(&self.root)?;
        if self.root.try_exists()? {
            return Err(Error::Storage);
        }
        Ok(())
    }
}
impl Drop for OriginalConstructionScanCacheV2 {
    fn drop(&mut self) {
        // Abrupt death/unwind can leave only ciphertext. Never reopen or adopt
        // it, and never broadly delete a root whose exact ownership is uncertain.
        for wallet in &mut self.wallets {
            wallet.close_wallet_and_key();
        }
    }
}

struct CurrentScanAccessV2<'a, 'host> {
    host: &'host Host,
    workspace: &'a PrivateWorkspaceOwnerV1<'host>,
    directory: &'a Directory,
    origin: &'a DatabaseFileIdentity,
    account: AccountUuid,
    backend: &'a BackendIdentity,
    scope: &'a DurableConstructionScopeV1,
    native: &'a HistoricalApproval,
}
impl LocalWalletAccess for CurrentScanAccessV2<'_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        backend: &BackendIdentity,
        _: WalletAccessPurpose,
    ) -> bool {
        self.account == account
            && self.backend == backend
            && observed_host_permission(self.native.check())
            && observed_host_permission(self.host.require_manual_session())
            && observed_host_permission(self.workspace.check_current_without_proof_lock_v2())
            && observed_host_permission(self.directory.check())
            && self.origin.check_retained_owner_path().is_ok()
            && wall_seconds().is_ok_and(|now| self.scope.check_valid_at(now).is_ok())
    }
}

fn check_stage_material_ceiling_v3(scope: &DurableConstructionScopeV1, now: u64) -> Result<()> {
    use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError as E;
    scope.check_valid_at(now).map_err(|error| {
        let cause = match &error {
            E::Invalid => PrivateDiagnosticCauseV1::Invalid,
            E::Binding => PrivateDiagnosticCauseV1::Binding,
            E::Stale => PrivateDiagnosticCauseV1::Stale,
            E::Storage | E::Sync(_) => PrivateDiagnosticCauseV1::Unclassified,
        };
        host_private_primary_v1(
            PrivateDiagnosticOperationV1::OpenOriginal,
            PrivateDiagnosticSiteV1::HostMaterialScope,
            PrivateDiagnosticFamilyV1::DurableConstruction,
            cause,
        );
        Error::Permission
    })
}
/// Reuses the original actual roster/source/material predicates, without any
/// historical permission cache. Both absolute ceilings are checked every time.
pub(in crate::host) fn check_stage_material_review_v3(
    host: &Host,
    owner: &PrivateWorkspaceOwnerV1<'_>,
    review: &wholepact_engine::PrivateFixedStageReviewV3,
) -> Result<()> {
    let materials = review.materials();
    if materials.len() != 2 {
        return Err(Error::Authentication);
    }
    let first = materials[0].scope();
    let current = CurrentMaterialPrivacyV2 {
        host,
        owner,
        candidate_id: Some(&first.proposal.proposal_id),
        exact_proposal: Some(&first.proposal),
        allowed: 1,
        approved: Mutex::new(Vec::new()),
    };
    let mut accounts = BTreeSet::new();
    for material in materials {
        if !valid_commitment(material.material_digest())
            || !accounts.insert(&material.scope().account_id)
        {
            return Err(Error::Authentication);
        }
        check_stage_material_ceiling_v3(material.scope(), wall_seconds()?)?;
        current.scope_current(material.scope())?;
    }
    // Source/roster reads above may take time. Neither original ceiling may
    // expire while the other member is checked.
    let now = wall_seconds()?;
    for material in materials {
        check_stage_material_ceiling_v3(material.scope(), now)?;
    }
    Ok(())
}
#[derive(Clone, Serialize, PartialEq, Eq)]
struct StageScanBindingV3 {
    account_id: String,
    account_uuid: String,
    scope_digest: String,
    backend: BackendIdentity,
    directory_identity: String,
    database_origin: String,
    destination: PathBuf,
}
/// Nominal binding assembled only from retained process-local cache owners.
/// It contains no key/wallet/material and cannot itself grant any permission.
#[derive(Serialize)]
pub(in crate::host) struct StageScanBindingsV3 {
    cache_root: PathBuf,
    cache_directory_identity: String,
    owners: Vec<StageScanBindingV3>,
}
fn stage_scan_scope_digest_v3(scope: &DurableConstructionScopeV1) -> Result<String> {
    wholepact_core::proposal::canonical_digest("wholepact:private-fixed-scan-scope:v3", scope)
        .map_err(|_| Error::Invalid)
}
impl StageScanBindingsV3 {
    fn from_actual(
        cache: &OriginalConstructionScanCacheV2,
        captured: &[Option<(DurableConstructionScopeV1, BackendIdentity)>; 2],
    ) -> Result<Self> {
        cache.check()?;
        let mut owners = Vec::new();
        for (wallet, captured) in cache.wallets.iter().zip(captured) {
            let (scope, backend) = captured.as_ref().ok_or(Error::Invalid)?;
            owners.push(StageScanBindingV3 {
                account_id: scope.account_id.clone(),
                account_uuid: format!(
                    "{:?}",
                    wallet.wallet.as_ref().ok_or(Error::Invalid)?.account_uuid()
                ),
                scope_digest: stage_scan_scope_digest_v3(scope)?,
                backend: backend.clone(),
                directory_identity: wallet
                    .directory
                    .as_ref()
                    .ok_or(Error::Invalid)?
                    .manual_target_identity_digest()?,
                database_origin: hex::encode(
                    wallet
                        .origin
                        .as_ref()
                        .ok_or(Error::Invalid)?
                        .origin_commitment(),
                ),
                destination: wallet.destination()?,
            });
        }
        Ok(Self {
            cache_root: cache.root.clone(),
            cache_directory_identity: cache
                .directory
                .as_ref()
                .ok_or(Error::Invalid)?
                .manual_target_identity_digest()?,
            owners,
        })
    }
    pub(in crate::host) fn check_review(
        &self,
        review: &wholepact_engine::PrivateFixedStageReviewV3,
    ) -> Result<()> {
        if self.owners.len() != 2 || review.materials().len() != 2 {
            return Err(Error::Authentication);
        }
        for owner in &self.owners {
            if review
                .materials()
                .iter()
                .filter(|m| {
                    m.scope().account_id == owner.account_id
                        && stage_scan_scope_digest_v3(m.scope())
                            .is_ok_and(|digest| digest == owner.scope_digest)
                })
                .count()
                != 1
            {
                return Err(Error::Authentication);
            }
        }
        if self.owners[0].account_id == self.owners[1].account_id {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn matches_actual(&self, gate: &CurrentScanAccessV3<'_, '_, '_>) -> Result<()> {
        gate.cache_directory.check()?;
        if gate.cache_directory.manual_target_identity_digest()? != self.cache_directory_identity
            || gate.cache_directory.path("profile.lock")?.parent()
                != Some(self.cache_root.as_path())
        {
            return Err(Error::Authentication);
        }
        gate.directory.check()?;
        gate.directory
            .inventory_of(&["wallet.sqlite"], &["profile.lock"])?;
        gate.origin
            .check_retained_owner_path()
            .map_err(|_| Error::Authentication)?;
        let directory = gate.directory.manual_target_identity_digest()?;
        let destination = gate.directory.path("wallet.sqlite")?;
        let digest = stage_scan_scope_digest_v3(gate.scope)?;
        let account = format!("{:?}", gate.account);
        let origin = hex::encode(gate.origin.origin_commitment());
        let actual = StageScanBindingV3 {
            account_id: gate.scope.account_id.clone(),
            account_uuid: account,
            scope_digest: digest,
            backend: gate.backend.clone(),
            directory_identity: directory,
            database_origin: origin,
            destination,
        };
        if !stage_scan_binding_matches_v3(&self.owners, &actual) {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
fn stage_scan_binding_matches_v3(
    owners: &[StageScanBindingV3],
    actual: &StageScanBindingV3,
) -> bool {
    owners.iter().filter(|owner| *owner == actual).count() == 1
}
/// Consumes the completed stage before any next-stage disclosure can begin.
/// The next operation is called at most once, including on refusal.
fn after_completed_stage_v3<T, R>(previous: T, next: impl FnOnce() -> Result<R>) -> Result<R> {
    drop(previous);
    next()
}
struct CurrentScanAccessV3<'a, 'owner, 'host> {
    stage:
        &'a crate::host::durable_private_workspace_v1::OwnedPrivateWorkspaceStageV3<'owner, 'host>,
    cache_directory: &'a Directory,
    directory: &'a Directory,
    origin: &'a DatabaseFileIdentity,
    account: AccountUuid,
    backend: &'a BackendIdentity,
    scope: &'a DurableConstructionScopeV1,
}
impl LocalWalletAccess for CurrentScanAccessV3<'_, '_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        backend: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        self.account == account
            && self.backend == backend
            && matches!(
                purpose,
                WalletAccessPurpose::SynchronizePublicBlocks
                    | WalletAccessPurpose::SelectPrivateContribution
            )
            && self
                .stage
                .scan_bindings()
                .is_some_and(|bindings| observed_host_permission(bindings.matches_actual(self)))
            && observed_host_permission(self.stage.check_callback())
    }
}

/// Same-thread, single-pass two-owner wave. Both admitted scans are drained
/// before ordered results escape, including failure. No retry or clock reset.
async fn same_thread_two_wallet_wave_v3<T, E>(
    first: impl std::future::Future<Output = std::result::Result<T, E>>,
    second: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> std::result::Result<[T; 2], E> {
    let (first, second) = tokio::join!(first, second);
    Ok([first?, second?])
}

async fn observe_one_original_wallet_v3(
    host: &Host,
    coordinator: &PrivateDurableCoordinatorV1<'_>,
    candidate: &str,
    cache_directory: &Option<Directory>,
    wallet: &mut ScanWalletOwnerV2,
    captured: &Option<(DurableConstructionScopeV1, BackendIdentity)>,
    stage: &crate::host::durable_private_workspace_v1::OwnedPrivateWorkspaceStageV3<'_, '_>,
) -> Result<FreshDurableConstructionObservationV1> {
    let (scope, backend) = private_host_result_at_v1(
        PrivateDiagnosticSiteV1::HostCheckpointSlots,
        captured.as_ref().ok_or(Error::Invalid),
    )?;
    private_host_result_at_v1(PrivateDiagnosticSiteV1::SourcePermission, wallet.check())?;
    let sync = private_host_result_at_v1(
        PrivateDiagnosticSiteV1::HostCheckpointSlots,
        wallet.wallet.as_mut().ok_or(Error::Invalid),
    )?;
    let gate = CurrentScanAccessV3 {
        cache_directory: private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostCheckpointSlots,
            cache_directory.as_ref().ok_or(Error::Invalid),
        )?,
        stage,
        directory: private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostCheckpointSlots,
            wallet.directory.as_ref().ok_or(Error::Invalid),
        )?,
        origin: private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostCheckpointSlots,
            wallet.origin.as_ref().ok_or(Error::Invalid),
        )?,
        account: sync.account_uuid(),
        backend,
        scope,
    };
    private_host_result_at_v1(PrivateDiagnosticSiteV1::SourcePermission, stage.check())?;
    let fresh = coordinator
        .observe_exact_material_v2(
            private_host_result_at_v1(PrivateDiagnosticSiteV1::HostCheckpointEntry, host.access())?,
            candidate,
            &scope.account_id,
            sync,
            stage,
            stage,
            &gate,
        )
        .await
        .map_err(observe_engine_observation)?;
    private_host_result_at_v1(PrivateDiagnosticSiteV1::PostConsent, stage.check())?;
    Ok(fresh)
}

fn original_slot_cause_v3(
    error: &DurableConstructionError,
) -> (PrivateDiagnosticFamilyV1, PrivateDiagnosticCauseV1) {
    use PrivateDiagnosticCauseV1 as C;
    use PrivateDiagnosticFamilyV1 as F;
    use wholepact_wallet::wallet::protected_sync::SyncError as S;
    use wholepact_wallet::wallet::WalletError as W;
    use wholepact_chain::ChainError as H;
    match error {
        DurableConstructionError::Invalid => (F::DurableConstruction, C::Invalid),
        DurableConstructionError::Binding => (F::DurableConstruction, C::Binding),
        DurableConstructionError::Stale => (F::DurableConstruction, C::Stale),
        DurableConstructionError::Storage => (F::DurableConstruction, C::Storage),
        DurableConstructionError::Sync(sync) => match sync {
            S::AccessDenied => (F::Sync, C::AccessDenied),
            S::InvalidRequest => (F::Sync, C::InvalidRequest),
            S::Interrupted => (F::Sync, C::Interrupted),
            S::ReconciliationRequired => (F::Sync, C::ReconciliationRequired),
            S::InvalidResponse => (F::Sync, C::InvalidResponse),
            S::ResourceLimit => (F::Sync, C::ResourceLimit),
            S::NoCurrentObservation => (F::Sync, C::NoCurrentObservation),
            S::Wallet(wallet) => (
                F::Wallet,
                match wallet {
                    W::Storage => C::Storage,
                    W::AccountScope => C::AccountScope,
                    W::AccountMismatch => C::AccountMismatch,
                    W::IncompleteSync => C::IncompleteSync,
                    W::UnsupportedProfile => C::UnsupportedProfile,
                    W::ChainMismatch => C::ChainMismatch,
                    W::InsufficientFunds => C::InsufficientFunds,
                    W::InvalidRequest => C::InvalidRequest,
                    W::MissingWitness => C::MissingWitness,
                    W::InvalidNote => C::InvalidNote,
                    W::Scan => C::Scan,
                    W::Transport => C::Transport,
                },
            ),
            S::Chain(chain) => (
                F::Chain,
                match chain {
                    H::InvalidConfiguration => C::InvalidConfiguration,
                    H::WrongNetwork => C::WrongNetwork,
                    H::UnsupportedProxyConfiguration => C::UnsupportedProxyConfiguration,
                    H::WrongBranch => C::WrongBranch,
                    H::StaleChain => C::StaleChain,
                    H::ContradictoryChain => C::ContradictoryChain,
                    H::Timeout => C::Timeout,
                    H::TransportUnavailable => C::TransportUnavailable,
                    H::ObservationInterrupted => C::ObservationInterrupted,
                    H::MissingAncestryEvidence => C::MissingAncestryEvidence,
                    H::NotObserved => C::NotObserved,
                    H::ResourceLimit => C::ResourceLimit,
                    H::MalformedEvidence => C::MalformedEvidence,
                    H::UnsupportedCapability => C::UnsupportedCapability,
                    H::BackendFailure { .. } => C::BackendFailure,
                    H::ClockUnavailable => C::ClockUnavailable,
                    H::IdempotencyConflict => C::IdempotencyConflict,
                    H::JournalFailure => C::JournalFailure,
                    H::SubmissionNotAuthorized => C::SubmissionNotAuthorized,
                    H::SubmissionExpiryMargin => C::SubmissionExpiryMargin,
                    H::ObligationConflict => C::ObligationConflict,
                    H::SubmissionOutcomeUnrecorded => C::SubmissionOutcomeUnrecorded,
                    H::SubmissionRetentionUncertain => C::SubmissionRetentionUncertain,
                },
            ),
        },
    }
}
fn observe_original_slot_result_v3<T>(
    result: std::result::Result<T, DurableConstructionError>,
) -> Result<T> {
    if let Err(error) = &result {
        let (family, cause) = original_slot_cause_v3(error);
        host_private_primary_v1(
            PrivateDiagnosticOperationV1::Checkpoint,
            PrivateDiagnosticSiteV1::SlotBindings,
            family,
            cause,
        );
    }
    // Keep the original terminal mapping. The actual lower error is observed
    // before it is erased, while the exact live stage/invocation still exists.
    result.map_err(|_| Error::Permission)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::host) enum PrivateCaptureStageV2 {
    BeforeInitial,
    AfterInitial,
    BeforeCapture,
    AfterCapture,
}
/// Bounded original outbox correlation only. No material, FVK or native grant.
pub(in crate::host) struct PrivateCapturedReferenceV2 {
    pub outbox_reference: String,
    pub request_digest: String,
    pub material_digest: String,
}

pub(in crate::host) struct PrivateFixedSessionV2<'host> {
    host: &'host Host,
    owner: PrivateWorkspaceOwnerV1<'host>,
    candidate: PrivateExactCandidateV2,
    key: String,
    revision: u64,
    cache: OriginalConstructionScanCacheV2,
    captured: [Option<(DurableConstructionScopeV1, BackendIdentity)>; 2],
    finish_started: bool,
}
fn fix_step_key(key: &str, stage: &str) -> Result<String> {
    if !(16..=128).contains(&key.len()) || !key.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Error::Invalid);
    }
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:private-fixed-original-step:v2",
        &(key, stage),
    )
    .map_err(|_| Error::Invalid)?;
    Ok(format!("private-fixed-{digest}"))
}
impl Host {
    pub(in crate::host) fn private_fixed_session_v2<'host>(
        &'host self,
        workspace_root: &Path,
        key: &str,
        request: CandidateRequest,
        cache_root: &Path,
    ) -> Result<PrivateFixedSessionV2<'host>> {
        begin_private_stage(PrivateBoundaryV2::Candidate);
        let result = self.private_fixed_session_inner_v2(workspace_root, key, request, cache_root);
        if let Err(error) = &result {
            observe_host_current(error);
        } else {
            complete_private_stage(PrivateBoundaryV2::Candidate);
        }
        result
    }
    fn private_fixed_session_inner_v2<'host>(
        &'host self,
        workspace_root: &Path,
        key: &str,
        request: CandidateRequest,
        cache_root: &Path,
    ) -> Result<PrivateFixedSessionV2<'host>> {
        self.require_manual_session()?;
        let candidate_key = fix_step_key(key, "candidate")?;
        let owner = self.reopen_private_workspace_registered_v1(workspace_root)?;
        owner.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::ReadStatus,
            |coordinator, privacy| {
                coordinator
                    .require_fresh_fixed_v2(self.access()?, privacy)
                    .map_err(observe_engine_candidate)?;
                Ok(())
            },
        )?;
        let target = self
            .engine
            .manual_roster_intent_target(self.access()?, owner.agreement_id())
            .map_err(observe_engine_current)?;
        require_operator_principal(target.agreement(), &self.access()?.principal_id)?;
        let expected = owner.reviewer_account_ids();
        let mut accounts = BTreeSet::new();
        if request.previous_candidate_id.is_some()
            || request.manifest.agreement != *target.agreement()
            || request.manifest.participants.len() != 2
        {
            return Err(Error::Invalid);
        }
        for participant in &request.manifest.participants {
            if !accounts.insert(participant.account_id.as_str())
                || !expected.contains(&participant.account_id)
                || target
                    .members(self.access()?)
                    .map_err(observe_engine_current)?
                    .iter()
                    .filter(|member| {
                        member.identity.account_id == participant.account_id
                            && member.scope.participant_id == participant.participant_id
                            && member.scope.agreement_id == owner.agreement_id()
                            && member.scope.principal_id
                                == self.access().map(|a| a.principal_id.as_str()).unwrap_or("")
                    })
                    .count()
                    != 1
            {
                return Err(Error::Authentication);
            }
        }
        if request
            .manifest
            .inputs
            .iter()
            .any(|input| input.ownership_evidence_ref.is_some())
        {
            return Err(Error::Invalid);
        }
        target
            .check_current(self.access()?)
            .map_err(observe_engine_current)?;
        let native = self.terminal.approve_historical(&format!(
            "Prepare exactly this one claims-only candidate in the fresh initialized original private workspace.\n{}\nProcess-only encrypted scan cache: {}\nThe two exact native owners must independently approve initial viewing disclosure and these wallet destinations next. No participant ownership, financial admission, authorization, signature or submission is asserted. A partial fix is inspect-only and must not be reconstructed.",
            serde_json::to_string_pretty(&request)?, cache_root.display(),
        ))?;
        owner.check_current_without_proof_lock_v2()?;
        native.check()?;
        let candidate = owner.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::PrepareExactCandidate,
            |coordinator, privacy| {
                native.check()?;
                let result = coordinator
                    .prepare_exact_candidate_v2(self.access()?, &candidate_key, 1, request, privacy)
                    .map_err(observe_engine_candidate)?;
                native.check()?;
                if result.replayed() {
                    return Err(Error::RecoveryFinancialUnsupported);
                }
                Ok(result)
            },
        )?;
        let cache = OriginalConstructionScanCacheV2::create(self, &owner, cache_root)?;
        let revision = candidate.revision();
        Ok(PrivateFixedSessionV2 {
            host: self,
            owner,
            candidate,
            key: key.into(),
            revision,
            cache,
            captured: [None, None],
            finish_started: false,
        })
    }
}
impl<'host> PrivateFixedSessionV2<'host> {
    pub(in crate::host) fn proposal(&self) -> &wholepact_core::ProposalInput {
        self.candidate.proposal()
    }
    pub(in crate::host) fn reviewer_account_ids(&self) -> Vec<String> {
        self.owner.reviewer_account_ids().to_vec()
    }
    pub(in crate::host) fn metadata_destination(&self) -> &Path {
        self.owner.metadata_destination()
    }
    pub(in crate::host) fn wallet_destination(&self, index: usize) -> Result<PathBuf> {
        self.cache
            .wallets
            .get(index)
            .ok_or(Error::Invalid)?
            .destination()
    }
    pub(in crate::host) fn principal_id(&self) -> Result<&str> {
        Ok(&self.host.access()?.principal_id)
    }
    pub(in crate::host) fn retention_policy(&self) -> &str {
        self.owner.retention_policy()
    }
    pub(in crate::host) fn original_checkpoint_key(&self) -> Result<String> {
        fix_step_key(&self.key, "checkpoint")
    }

    fn validate_capture(
        &self,
        index: usize,
        initial: &PreconstructionRequest,
        capture: &DurableConstructionCaptureRequestV1,
    ) -> Result<()> {
        self.owner.check_current_without_proof_lock_v2()?;
        self.cache.check()?;
        if index >= 2
            || self.captured[index].is_some()
            || self.cache.wallets[index].wallet.is_some()
        {
            return Err(Error::Invalid);
        }
        initial.validate().map_err(|_| Error::Invalid)?;
        let scope = &initial.scope;
        let material = &capture.scope;
        let expected = self.owner.reviewer_account_ids();
        let mut audience = scope.reviewer_account_ids.clone();
        audience.sort();
        let mut exact = expected.to_vec();
        exact.sort();
        if scope.account_id != expected[index]
            || scope.proposal != *self.proposal()
            || scope.principal_id != self.principal_id()?
            || scope.operator_name != self.principal_id()?
            || scope.profile_id != wholepact_protocol::construction::PROFILE_ID
            || scope.operator_destination
                != self.metadata_destination().to_str().ok_or(Error::Invalid)?
            || scope.wallet_destination
                != self
                    .wallet_destination(index)?
                    .to_str()
                    .ok_or(Error::Invalid)?
            || scope.retention_policy != self.retention_policy()
            || audience != exact
            || initial.sponsor_policy.is_some()
            || capture.enrollment_ref != initial.enrollment_ref
            || capture.accepted_manifest_ref != initial.accepted_manifest_ref
            || material.proposal != scope.proposal
            || material.account_id != scope.account_id
            || material.participant_id != scope.participant_id
            || material.privacy_domain != scope.privacy_domain
            || material.minimum_confirmations != scope.minimum_confirmations
            || material.maximum_scan_blocks != scope.maximum_blocks
        {
            return Err(Error::Authentication);
        }
        CurrentMaterialPrivacyV2::new(
            self.host,
            &self.owner,
            self.candidate.candidate_id(),
            Some(self.candidate.proposal()),
            0,
        )
        .scope_current(material)
    }

    /// The callback can only coordinate the separately installed native process.
    /// It receives no lease, material, wallet, key or approval constructor.
    pub(in crate::host) async fn capture_owner_v2(
        &mut self,
        index: usize,
        client: &OriginalHistoryClient,
        initial: PreconstructionRequest,
        capture: DurableConstructionCaptureRequestV1,
        progress: impl FnMut(PrivateCaptureStageV2) -> Result<()>,
    ) -> Result<PrivateCapturedReferenceV2> {
        begin_private_stage(PrivateBoundaryV2::Capture);
        let result = self
            .capture_owner_inner_v2(index, client, initial, capture, progress)
            .await;
        if let Err(error) = &result {
            observe_host_current(error);
        }
        result
    }
    async fn capture_owner_inner_v2(
        &mut self,
        index: usize,
        client: &OriginalHistoryClient,
        initial: PreconstructionRequest,
        capture: DurableConstructionCaptureRequestV1,
        mut progress: impl FnMut(PrivateCaptureStageV2) -> Result<()>,
    ) -> Result<PrivateCapturedReferenceV2> {
        self.validate_capture(index, &initial, &capture)?;
        let review = self.host.terminal.approve_historical(&format!(
            "Request genuine initial native viewing disclosure and durable capture for this exact original selected owner.\nInitial disclosure: {}\nDurable scope: {}\nThe wallet destination is a new process-only encrypted cache with a random memory-only key. It is never registered, backed up, reopened or adopted. Crash may leave encrypted ciphertext; no secure deletion is promised.",
            serde_json::to_string_pretty(&initial)?, serde_json::to_string_pretty(&capture)?,
        ))?;
        self.validate_capture(index, &initial, &capture)?;
        review.check()?;
        progress(PrivateCaptureStageV2::BeforeInitial)?;
        let lease = client
            .request_preconstruction(&initial)
            .map_err(observe_bridge_capture)?;
        progress(PrivateCaptureStageV2::AfterInitial)?;
        review.check()?;
        self.validate_capture(index, &initial, &capture)?;
        let backend = wholepact_chain::ChainAdapter::testnet(
            &initial.scope.provider.source_id,
            &initial.scope.provider.endpoint,
            wholepact_chain::NetworkPolicy::default(),
        )?;
        let backend_identity = backend.identity().clone();
        if backend_identity.trust_profile != initial.scope.provider.trust_profile {
            return Err(Error::Authentication);
        }
        let destination = self.cache.wallets[index].create_destination()?;
        progress(PrivateCaptureStageV2::BeforeCapture)?;
        review.check()?;
        self.owner.check_current_without_proof_lock_v2()?;
        let original_scope = capture.scope.clone();
        let result = {
            let capture = client.capture_and_request_durable_construction_v1(
                lease,
                destination,
                backend,
                capture,
            );
            tokio::pin!(capture);
            let mut check = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    result = &mut capture => break result.map_err(observe_bridge_capture),
                    _ = check.tick() => {
                        review.check()?;
                        self.owner.check_current_without_proof_lock_v2()?;
                        self.cache.check()?;
                        original_scope.check_valid_at(wall_seconds()?).map_err(|_| Error::Permission)?;
                    }
                }
            }
        }?;
        // The maintained capture future has finished, with its actual initial
        // lease drained. No outstanding task can retain this wallet connection.
        let (wallet, disclosure) = result;
        self.cache.wallets[index].wallet = Some(wallet);
        progress(PrivateCaptureStageV2::AfterCapture)?;
        review.check()?;
        self.owner.check_current_without_proof_lock_v2()?;
        self.cache.check()?;
        if disclosure.outbox().request().scope != original_scope {
            return Err(Error::Authentication);
        }
        let reference = PrivateCapturedReferenceV2 {
            outbox_reference: disclosure.outbox().reference().into(),
            request_digest: disclosure.outbox().request_digest().into(),
            material_digest: disclosure.outbox().material_digest().into(),
        };
        complete_private_stage(PrivateBoundaryV2::Capture);
        begin_private_stage(PrivateBoundaryV2::Intake);
        let material = CurrentMaterialPrivacyV2::new(
            self.host,
            &self.owner,
            self.candidate.candidate_id(),
            Some(self.candidate.proposal()),
            0,
        );
        let key = fix_step_key(&self.key, if index == 0 { "intake-0" } else { "intake-1" })?;
        let status = self.owner.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::RetainExactMaterial,
            |coordinator, privacy| {
                coordinator
                    .retain_exact_material_v2(
                        self.host.access()?,
                        &key,
                        self.candidate.candidate_id(),
                        self.revision,
                        disclosure,
                        privacy,
                        &material,
                    )
                    .map_err(observe_engine_intake)
            },
        )?;
        self.revision = status.revision;
        self.captured[index] = Some((original_scope, backend_identity));
        complete_private_stage(PrivateBoundaryV2::Intake);
        Ok(reference)
    }

    pub(in crate::host) async fn finish_fixed_v2(&mut self) -> Result<PrivateVerifiedFixedV2> {
        if self.finish_started {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        self.finish_started = true;
        let result = self.finish_inner_v2().await;
        if let Err(error) = &result {
            observe_host_current(error);
        }
        // The construction/proof calls return only after held wallet slots and
        // the bounded proof worker have drained. Preserve the first error.
        begin_private_stage(PrivateBoundaryV2::Cleanup);
        let cleanup = self.cache.cleanup();
        if let Err(error) = &cleanup {
            observe_host_current(error);
        } else {
            complete_private_stage(PrivateBoundaryV2::Cleanup);
        }
        if cleanup.is_err() {
            let _ = self.host.terminal.message("The process-only scan cache could not be fully removed. Residual encrypted ciphertext is preserved and must not be reopened or adopted; retained original metadata/proof facts remain unchanged.\n");
        }
        match result {
            Err(error) => Err(error),
            Ok(fixed) => {
                cleanup?;
                Ok(fixed)
            }
        }
    }
    pub(in crate::host) fn close_failed_scan_cache_v2(&mut self) -> Result<()> {
        self.cache.cleanup()
    }

    async fn finish_inner_v2(&mut self) -> Result<PrivateVerifiedFixedV2> {
        self.owner.check_current_without_proof_lock_v2()?;
        self.cache.check()?;
        if self.captured.iter().any(Option::is_none) {
            return Err(Error::Invalid);
        }
        let coordinator = self.owner.stage_coordinator_v3();
        let checkpoint_key = self.original_checkpoint_key()?;
        let checkpoint_diagnostic =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
        begin_private_stage(PrivateBoundaryV2::Observe);
        let inspection = self.owner.inspect_fixed_stage_v3()?;
        let review = coordinator
            .inspect_prepare_stage_v3(self.host.access()?, &inspection)
            .map_err(|error| observe_engine_stage_review_v3(PrivateBoundaryV2::Observe, error))?;
        let prepare = self.owner.approve_fixed_stage_v3(
            inspection,
            review,
            Some(StageScanBindingsV3::from_actual(
                &self.cache,
                &self.captured,
            )?),
            || self.cache.check(),
        )?;
        let fresh = {
            let [left, right] = &mut self.cache.wallets;
            same_thread_two_wallet_wave_v3(
                observe_one_original_wallet_v3(
                    self.host,
                    coordinator,
                    self.candidate.candidate_id(),
                    &self.cache.directory,
                    left,
                    &self.captured[0],
                    &prepare,
                ),
                observe_one_original_wallet_v3(
                    self.host,
                    coordinator,
                    self.candidate.candidate_id(),
                    &self.cache.directory,
                    right,
                    &self.captured[1],
                    &prepare,
                ),
            )
            .await?
        };
        complete_private_stage(PrivateBoundaryV2::Observe);
        begin_private_stage(PrivateBoundaryV2::Checkpoint);
        let prepared = {
            let [left, right] = &mut self.cache.wallets;
            coordinator
                .prepare_checkpoint_for_stage_v3(
                    private_host_result_at_v1(
                        PrivateDiagnosticSiteV1::HostCheckpointEntry,
                        self.host.access(),
                    )?,
                    &checkpoint_key,
                    self.candidate.candidate_id(),
                    self.revision,
                    vec![
                        observe_original_slot_result_v3(DurableConstructionWalletSlotV1::new(
                            left.wallet.as_mut().ok_or(Error::Invalid)?,
                            &fresh[0],
                        ))?,
                        observe_original_slot_result_v3(DurableConstructionWalletSlotV1::new(
                            right.wallet.as_mut().ok_or(Error::Invalid)?,
                            &fresh[1],
                        ))?,
                    ],
                    wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
                    &prepare,
                    &prepare,
                    &prepare,
                )
                .map_err(observe_engine_checkpoint)?
        };
        // All held construction/source postchecks have completed. These are
        // data, not renewed observations or a transferable preparation grant.
        drop(fresh);
        let inspection = after_completed_stage_v3(prepare, || self.owner.inspect_fixed_stage_v3())?;
        let review = prepared
            .inspect_admission_stage_v3(self.host.access()?, &inspection)
            .map_err(|error| {
                observe_engine_stage_review_v3(PrivateBoundaryV2::Checkpoint, error)
            })?;
        let admit = self.owner.approve_fixed_stage_v3(
            inspection,
            review,
            Some(StageScanBindingsV3::from_actual(
                &self.cache,
                &self.captured,
            )?),
            || self.cache.check(),
        )?;
        // Every dialog is complete before this single genuine final scan pass.
        let fresh = {
            let [left, right] = &mut self.cache.wallets;
            same_thread_two_wallet_wave_v3(
                observe_one_original_wallet_v3(
                    self.host,
                    coordinator,
                    self.candidate.candidate_id(),
                    &self.cache.directory,
                    left,
                    &self.captured[0],
                    &admit,
                ),
                observe_one_original_wallet_v3(
                    self.host,
                    coordinator,
                    self.candidate.candidate_id(),
                    &self.cache.directory,
                    right,
                    &self.captured[1],
                    &admit,
                ),
            )
            .await?
        };
        let checkpoint = {
            let [left, right] = &mut self.cache.wallets;
            prepared
                .admit_original_v2(
                    private_host_result_at_v1(
                        PrivateDiagnosticSiteV1::HostCheckpointEntry,
                        self.host.access(),
                    )?,
                    vec![
                        observe_original_slot_result_v3(DurableConstructionWalletSlotV1::new(
                            left.wallet.as_mut().ok_or(Error::Invalid)?,
                            &fresh[0],
                        ))?,
                        observe_original_slot_result_v3(DurableConstructionWalletSlotV1::new(
                            right.wallet.as_mut().ok_or(Error::Invalid)?,
                            &fresh[1],
                        ))?,
                    ],
                    &admit,
                    &admit,
                    &admit,
                )
                .map_err(observe_engine_checkpoint)?
        };
        let revision = checkpoint.status().revision;
        let attempt = private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostCheckpointContinuation,
            checkpoint
                .into_attempt()
                .ok_or(Error::RecoveryFinancialUnsupported),
        )?;
        private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostCheckpointPostcheck,
            admit.check(),
        )?;
        drop(fresh);
        drop(admit);
        complete_private_stage(PrivateBoundaryV2::Checkpoint);
        drop(checkpoint_diagnostic);
        begin_private_stage(PrivateBoundaryV2::Proof);
        let proof_diagnostic =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Proof);
        let inspection = self.owner.inspect_fixed_stage_v3()?;
        let review = attempt
            .inspect_proof_stage_v3(self.host.access()?, &inspection)
            .map_err(|error| observe_engine_stage_review_v3(PrivateBoundaryV2::Proof, error))?;
        let prove = self
            .owner
            .approve_fixed_stage_v3(inspection, review, None, || Ok(()))?;
        let proved = run_original_proof_foreground_v2(
            self.host,
            coordinator,
            attempt,
            &fix_step_key(&self.key, "prove")?,
            revision,
            &prove,
            &prove,
            &prove,
        )?;
        prove.check()?;
        self.revision = proved.revision;
        drop(prove);
        complete_private_stage(PrivateBoundaryV2::Proof);
        drop(proof_diagnostic);
        begin_private_stage(PrivateBoundaryV2::Freeze);
        let freeze_diagnostic =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Freeze);
        let inspection = self.owner.inspect_fixed_stage_v3()?;
        let review = coordinator
            .inspect_freeze_stage_v3(self.host.access()?, &inspection)
            .map_err(|error| observe_engine_stage_review_v3(PrivateBoundaryV2::Freeze, error))?;
        let freeze = self
            .owner
            .approve_fixed_stage_v3(inspection, review, None, || Ok(()))?;
        let frozen = coordinator
            .freeze_verified_fixed_v2(
                self.host.access()?,
                &fix_step_key(&self.key, "freeze")?,
                self.candidate.candidate_id(),
                &checkpoint_key,
                self.revision,
                &freeze,
                &freeze,
                &freeze,
            )
            .map_err(observe_engine_freeze)?;
        freeze.check()?;
        self.revision = frozen.revision;
        drop(freeze);
        complete_private_stage(PrivateBoundaryV2::Freeze);
        drop(freeze_diagnostic);
        begin_private_stage(PrivateBoundaryV2::Read);
        let _read_diagnostic =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::ReadFixed);
        let inspection = self.owner.inspect_fixed_stage_v3()?;
        let review = coordinator
            .inspect_saved_read_stage_v3(self.host.access()?, &inspection)
            .map_err(|error| observe_engine_stage_review_v3(PrivateBoundaryV2::Read, error))?;
        let read = self
            .owner
            .approve_fixed_stage_v3(inspection, review, None, || Ok(()))?;
        let fixed = coordinator
            .read_verified_fixed_v2(
                self.host.access()?,
                self.candidate.candidate_id(),
                &checkpoint_key,
                &read,
                &read,
                &read,
            )
            .map_err(observe_engine_read)?;
        read.check()?;
        Ok(fixed)
    }
}

/// Only data requests cross to the foreground. A response belongs to one exact
/// callback, is never cached, and cannot mint/recreate an original continuation.
enum ForegroundProofRequestV2 {
    Workspace(
        PrivateWorkspaceScopeV1,
        PrivateWorkspaceActionV1,
        std::sync::mpsc::SyncSender<bool>,
    ),
    Material(
        DurableConstructionScopeV1,
        String,
        DurableMaterialActionV1,
        std::sync::mpsc::SyncSender<bool>,
    ),
    Proof(
        CheckpointScope,
        LocalAction,
        std::sync::mpsc::SyncSender<bool>,
    ),
    Finished(
        std::result::Result<wholepact_engine::PrivateWorkspaceStatusV1, wholepact_engine::ApiError>,
    ),
}
struct ForegroundProofBrokerV2 {
    sender: std::sync::mpsc::Sender<ForegroundProofRequestV2>,
    original_deadline: std::time::Instant,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl ForegroundProofBrokerV2 {
    fn ask(
        &self,
        request: impl FnOnce(std::sync::mpsc::SyncSender<bool>) -> ForegroundProofRequestV2,
    ) -> bool {
        use std::sync::atomic::Ordering;
        if self.cancelled.load(Ordering::Acquire)
            || std::time::Instant::now() >= self.original_deadline
        {
            return false;
        }
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        // There is exactly one synchronous worker callback at a time, so the
        // data channel cannot accumulate an unbounded queue of private requests.
        if self.sender.send(request(send)).is_err() {
            return false;
        }
        let remaining = self
            .original_deadline
            .saturating_duration_since(std::time::Instant::now());
        match receive.recv_timeout(remaining) {
            Ok(true) => {
                !self.cancelled.load(Ordering::Acquire)
                    && std::time::Instant::now() < self.original_deadline
            }
            _ => false,
        }
    }
}
impl LocalPrivateWorkspaceConsentV1 for ForegroundProofBrokerV2 {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool {
        self.ask(|response| ForegroundProofRequestV2::Workspace(scope.clone(), action, response))
    }
}
impl LocalDurableMaterialConsentV1 for ForegroundProofBrokerV2 {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        digest: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        self.ask(|response| {
            ForegroundProofRequestV2::Material(scope.clone(), digest.into(), action, response)
        })
    }
}
impl LocalProofConsent for ForegroundProofBrokerV2 {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.ask(|response| ForegroundProofRequestV2::Proof(scope.clone(), action, response))
    }
}
#[allow(clippy::too_many_arguments)]
fn run_original_proof_foreground_v2<'op, 'source>(
    host: &Host,
    coordinator: &'op PrivateDurableCoordinatorV1<'source>,
    attempt: wholepact_engine::OriginalProofAttemptV2<'op, 'source>,
    key: &str,
    revision: u64,
    workspace: &crate::host::durable_private_workspace_v1::OwnedPrivateWorkspaceStageV3<
        '_,
        'source,
    >,
    proof: &dyn LocalProofConsent,
    material: &dyn LocalDurableMaterialConsentV1,
) -> Result<wholepact_engine::PrivateWorkspaceStatusV1> {
    use std::sync::atomic::{AtomicBool, Ordering};
    private_host_result_at_v1(
        PrivateDiagnosticSiteV1::HostProofPrecheck,
        workspace.check(),
    )?;
    let access =
        private_host_result_at_v1(PrivateDiagnosticSiteV1::HostProofAccess, host.access())?.clone();
    let key = key.to_owned();
    let deadline = workspace.deadline();
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let result = std::thread::scope(|scope| {
        let (send, receive) = std::sync::mpsc::channel();
        let broker = ForegroundProofBrokerV2 {
            sender: send.clone(),
            original_deadline: deadline,
            cancelled: cancelled.clone(),
        };
        let worker = scope.spawn(move || {
            // The only work entry consumes the actual live continuation. No
            // status/open/replay response can create this argument.
            let result = coordinator.prove_original_once_v2(
                attempt, &access, &key, revision, &broker, &broker, &broker,
            );
            let _ = send.send(ForegroundProofRequestV2::Finished(result));
        });
        private_worker_start_v1();
        let mut foreground_error = None;
        let result = loop {
            match receive.recv_timeout(Duration::from_secs(1)) {
                Ok(ForegroundProofRequestV2::Finished(result)) => {
                    private_worker_received_v1(&result);
                    break result.map_err(observe_engine_proof);
                }
                Ok(request) => {
                    let current =
                        !cancelled.load(Ordering::Acquire) && std::time::Instant::now() < deadline;
                    let (reply, allowed) = match request {
                        ForegroundProofRequestV2::Workspace(scope, action, reply) => (
                            reply,
                            current && workspace.permits_workspace(&scope, action),
                        ),
                        ForegroundProofRequestV2::Material(scope, digest, action, reply) => (
                            reply,
                            current
                                && LocalDurableMaterialConsentV1::permits(
                                    material, &scope, &digest, action,
                                ),
                        ),
                        ForegroundProofRequestV2::Proof(scope, action, reply) => (
                            reply,
                            current && LocalProofConsent::permits(proof, &scope, action),
                        ),
                        ForegroundProofRequestV2::Finished(_) => unreachable!(),
                    };
                    let allowed = allowed && std::time::Instant::now() < deadline;
                    if !allowed {
                        cancelled.store(true, Ordering::Release);
                    }
                    // This reply cannot block the foreground on an expired or
                    // departed worker. Denial is one-way; never reset it.
                    let _ = reply.send(allowed);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if std::time::Instant::now() >= deadline {
                        cancelled.store(true, Ordering::Release);
                    }
                    if foreground_error.is_none() {
                        if let Err(error) = host.terminal.message("Original local proof work is active; the owned worker will drain. No transaction is being submitted.\n") {
                            observe_private_host_current_at_v1(PrivateDiagnosticSiteV1::HostProofForegroundMessage,&error);
                            observe_host_current(&error);
                            foreground_error = Some(error);
                            cancelled.store(true, Ordering::Release);
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    private_worker_disconnected_v1();
                    observe_private_host_current_at_v1(
                        PrivateDiagnosticSiteV1::HostProofReceive,
                        &Error::Storage,
                    );
                    break Err(Error::Storage);
                }
            }
        };
        // Join on every success/failure/channel outcome. No detached proof can
        // outlive these exact original source/proof owners or cache teardown.
        let joined = worker.join();
        private_worker_joined_v1(joined.is_ok());
        select_original_proof_result_v1(foreground_error, result, joined)
    });
    match result {
        Err(error) => Err(error),
        Ok(status) => {
            private_host_result_at_v1(
                PrivateDiagnosticSiteV1::HostProofFinalCheck,
                workspace.check(),
            )?;
            Ok(status)
        }
    }
}

// Data-only selection shared with component faults; join already happened.
fn select_original_proof_result_v1<T>(
    foreground_error: Option<Error>,
    result: Result<T>,
    joined: std::thread::Result<()>,
) -> Result<T> {
    if let Some(error) = foreground_error {
        return Err(error);
    }
    match result {
        Err(error) => Err(error),
        Ok(status) => match joined {
            Ok(()) => Ok(status),
            Err(_) => {
                observe_private_host_current_at_v1(
                    PrivateDiagnosticSiteV1::HostProofJoin,
                    &Error::Storage,
                );
                Err(Error::Storage)
            }
        },
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateCaptureConfigurationV2 {
    signer_socket: PathBuf,
    initial: PreconstructionRequest,
    capture: DurableConstructionCaptureRequestV1,
}
impl Host {
    pub(in crate::host) fn private_durable_fix_v1_command(&self, root: &Path) -> Result<()> {
        self.require_manual_session()?;
        let key = self.terminal.ask(
            "Stable original private fix key (preserve; partial work cannot be restarted): ",
        )?;
        let request: CandidateRequest = self.read_manual_private(
            "Private exact CandidateRequest claims JSON file: ",
            "one original private fixed candidate",
        )?;
        let cache_root = self.path(
            "NEW process-only private scan-cache root (absolute, outside all protected roots): ",
        )?;
        let mut session = self.private_fixed_session_v2(root, &key, request, &cache_root)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        let result = (|| {
            self.terminal.json(session.proposal())?;
            for index in 0..2 {
                let config: PrivateCaptureConfigurationV2 = self.read_manual_private(
                    "Private exact installed-owner initial/capture request configuration JSON file: ",
                    "independently approved selected-owner initial native disclosure")?;
                session.validate_capture(index, &config.initial, &config.capture)?;
                crate::files::validate_absolute(&config.signer_socket)?;
                let proposal = wholepact_core::Proposal::validate(session.proposal().clone())
                    .map_err(|_| Error::Invalid)?;
                let pair = self.terminal.approve_historical(&format!(
                    "Pair only with the exact separately installed signer for this selected owner and candidate.\nAccount: {}\nSocket: {}\nCandidate: {}\nThis requests no financial admission, history acquire, spending, signatures or export. Initial disclosure still requires that signer's independent native approval.",
                    config.initial.scope.account_id, config.signer_socket.display(), session.proposal().proposal_id,
                ))?;
                pair.check()?;
                let provider =
                    wholepact_signer::authority_bridge::provider::InstalledSignerProvider::load()
                        .map_err(|_| Error::Permission)?;
                let client = OriginalHistoryClient::pair(
                    provider,
                    &config.signer_socket,
                    "wholepact-private-fixed-constructor",
                    wholepact_signer::ipc::PairScope {
                        account_id: config.initial.scope.account_id.clone(),
                        agreement_id: session.proposal().manifest.agreement.agreement_id.clone(),
                        participant_id: config.initial.scope.participant_id.clone(),
                        manifest_digest: proposal.manifest_digest().into(),
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: true,
                    },
                )
                .map_err(observe_bridge_capture)?;
                pair.check()?;
                runtime.block_on(session.capture_owner_v2(
                    index,
                    &client,
                    config.initial,
                    config.capture,
                    |_| Ok(()),
                ))?;
                // The actual initial lease and capture call have drained; close
                // the old paired disclosure association before the next owner.
                drop(client);
            }
            runtime.block_on(session.finish_fixed_v2())
        })();
        match result {
            Ok(fixed) => {
                self.terminal.json(&fixed)?;
                self.terminal.message("One verified fixed artifact is retained in the exact original workspace and primary proof journal. Process-only scan owners and keys are closed and the exact cache is removed. No financial admission, review export, signature or submission occurred.\n")
            }
            Err(error) => {
                if session.cache.directory.is_some()
                    && session.close_failed_scan_cache_v2().is_err()
                {
                    let _ = self.terminal.message("Original work remains partial or uncertain. Residual process-cache ciphertext may remain; it must never be reopened or adopted. Preserve the original workspace and proof journals.\n");
                }
                Err(error)
            }
        }
    }

    pub(in crate::host) fn private_durable_read_fixed_v2(
        &self,
        root: &Path,
    ) -> Result<PrivateVerifiedFixedV2> {
        begin_private_stage(PrivateBoundaryV2::Read);
        let _read_diagnostic =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::ReadFixed);
        let result = self.private_durable_read_fixed_inner_v2(root);
        if let Err(error) = &result {
            observe_host_current(error);
        } else {
            complete_private_stage(PrivateBoundaryV2::Read);
        }
        result
    }
    fn private_durable_read_fixed_inner_v2(&self, root: &Path) -> Result<PrivateVerifiedFixedV2> {
        private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostReadSession,
            self.require_private_workspace_read_session_v1(),
        )?;
        let owner = private_host_result_at_v1(
            PrivateDiagnosticSiteV1::HostReadOpen,
            self.reopen_private_workspace_registered_v1(root),
        )?;
        let coordinator = owner.stage_coordinator_v3();
        let inspection = owner.inspect_fixed_stage_v3()?;
        let review = coordinator
            .inspect_saved_read_stage_v3(self.access()?, &inspection)
            .map_err(|error| observe_engine_stage_review_v3(PrivateBoundaryV2::Read, error))?;
        let read = owner.approve_fixed_stage_v3(inspection, review, None, || Ok(()))?;
        let fixed = coordinator
            .read_only_original_fixed_v2(self.access()?, &read, &read, &read)
            .map_err(observe_engine_read)?;
        read.check()?;
        Ok(fixed)
    }
    pub(in crate::host) fn private_durable_read_fixed_v1_command(&self, root: &Path) -> Result<()> {
        let fixed = self.private_durable_read_fixed_v2(root)?;
        self.terminal.json(&fixed)?;
        self.terminal.message("The same original fixed proof was independently verified read-only under current local privacy consent and both original material ceilings. No scan, capture, reconstruction, proof attempt, metadata repair, financial admission or export occurred.\n")
    }
}

// Closed, data-only private diagnostic wire. These values never authorize work.
const PRIVATE_FIXED_DIAGNOSTIC_MAX_BYTES_V1: usize = 4096;
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticOperationV1 {
    Checkpoint,
    Proof,
    Freeze,
    ReadFixed,
    OpenOriginal,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticSiteV1 {
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
    HostCheckpointEntry,
    HostCheckpointAction,
    HostCheckpointSlots,
    HostCheckpointContinuation,
    HostCheckpointPostcheck,
    HostProofPrecheck,
    HostProofAccess,
    HostProofForegroundMessage,
    HostProofReceive,
    HostProofJoin,
    HostProofFinalCheck,
    HostFreezeEntry,
    HostFreezeAction,
    HostFreezeReturn,
    HostReadSession,
    HostReadOpen,
    HostReadAction,
    HostReadReturn,
    HostMaterialScope,
    HostMaterialNativeCheck,
    HostMaterialApproval,
    HostProofScope,
    HostProofNativeCheck,
    HostProofApproval,
    HostWorkspaceCurrent,
    HostWorkspaceNativeCheck,
    HostWorkspaceSessionCheck,
    HostWorkspaceSourceCheck,
    ReaderProfileDirectory,
    ReaderVaultRead,
    ReaderVaultV3Open,
    ReaderFinalRegistry,
    ReaderSourceOpen,
    ReaderSourceAssociation,
    ReaderFinancialOpen,
    ReaderHostRuntime,
    ReaderEnroll,
    ReaderSavedPrincipal,
    ReaderReadSession,
    ReaderHostReturn,
    ReaderFinancialSnapshot,
    ReaderFinancialOriginal,
    ReaderWorkspaceDirectory,
    ReaderMetadataSnapshot,
    ReaderMetadataOrigin,
    ReaderMetadataInitializedSchema,
    ReaderSourceStore,
    ReaderSourceSelection,
    ReaderSourceSeedPlan,
    ReaderSourceSeedBinding,
    ReaderSourceSeedCompare,
    ReaderSourceCompare,
    ReaderSourceFinalCheck,
    ReaderOriginalFinancialProofSchema,
    ReaderOriginalFinancialHandles,
    ReaderOriginalFinancialLoad,
    ReaderOriginalProofSource,
    ReaderOriginalProofCurrent,
    ReaderProofSnapshotOpen,
    ReaderProofSnapshotOrigin,
    ReaderProofSnapshotUnchanged,
    ReaderControlRead,
    ReaderFinancialCompare,
    ReaderCommitments,
    ReaderComparisonVerify,
    ReaderCompletionWrite,
    ReaderFinalReturn,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticFamilyV1 {
    Engine,
    DurableConstruction,
    Sync,
    Wallet,
    Chain,
    Protocol,
    Store,
    StorageSecurity,
    Job,
    Gate,
    Host,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticCauseV1 {
    DISCLOSURE_DENIED,
    DURABLE_CONSTRUCTION_UNAVAILABLE,
    DURABLE_PROPOSAL_RECOVERY_REQUIRED,
    DURABLE_PROPOSAL_CONFLICT,
    DURABLE_PROPOSAL_NOT_FOUND,
    DURABLE_PROFILE_UNAVAILABLE,
    MANUAL_CONSTRUCTION_DENIED,
    RETAINED_INPUT_OBSERVATION_UNAVAILABLE,
    CANDIDATE_VERIFICATION_FAILED,
    IDEMPOTENCY_CONFLICT,
    REVISION_CONFLICT,
    NOT_FOUND,
    INVALID_REQUEST,
    RECOVERY_REQUIRED,
    LIVE_AUTHORIZATION_EXISTS,
    RESOURCE_EXHAUSTED,
    INVALID_TRANSITION,
    STORAGE_PROTECTION_REQUIRED,
    STORAGE_UNAVAILABLE,
    ACCESS_DENIED,
    INVALID_TERMS,
    UNSUPPORTED_CAPABILITY,
    MISSING_EVIDENCE,
    INVALID_AMOUNT,
    UNKNOWN_PARTICIPANT,
    DUPLICATE_IDENTIFIER,
    CONSERVATION_FAILURE,
    DEBIT_CAP_EXCEEDED,
    FEE_CAP_EXCEEDED,
    UNVERIFIABLE_MATCH,
    PRIVACY_INCOMPATIBLE,
    UNSUPPORTED_VERSION,
    RESOURCE_LIMIT,
    STALE_CHAIN,
    OUTSTANDING_EXPOSURE,
    USER_REJECTED,
    INTERNAL_ERROR,
    Unclassified,
    PERMISSION_DENIED,
    Invalid,
    Binding,
    Stale,
    Storage,
    AccessDenied,
    InvalidRequest,
    Interrupted,
    ReconciliationRequired,
    InvalidResponse,
    ResourceLimit,
    NoCurrentObservation,
    AccountScope,
    AccountMismatch,
    IncompleteSync,
    UnsupportedProfile,
    ChainMismatch,
    InsufficientFunds,
    MissingWitness,
    InvalidNote,
    Scan,
    Transport,
    InvalidConfiguration,
    WrongNetwork,
    UnsupportedProxyConfiguration,
    WrongBranch,
    StaleChain,
    ContradictoryChain,
    Timeout,
    TransportUnavailable,
    ObservationInterrupted,
    MissingAncestryEvidence,
    NotObserved,
    MalformedEvidence,
    UnsupportedCapability,
    BackendFailure,
    ClockUnavailable,
    IdempotencyConflict,
    JournalFailure,
    SubmissionNotAuthorized,
    SubmissionExpiryMargin,
    ObligationConflict,
    SubmissionOutcomeUnrecorded,
    SubmissionRetentionUncertain,
    Manifest,
    Disclosure,
    Context,
    Contribution,
    Input,
    Output,
    Fee,
    BuilderInput,
    BuilderOutput,
    Pczt,
    Finalize,
    ActionMapping,
    FixedBudget,
    FixedOwners,
    FixedRecipient,
    FixedPolicy,
    FixedAccounting,
    FixedRealInput,
    FixedCanonicalAccount,
    FixedDistinctAccounts,
    FixedUnsignedPredecessor,
    FixedUnsignedRealInput,
    FixedProofOnlyTransition,
    FixedPaddingSignature,
    StorageSecurity,
    Database,
    Encoding,
    Poisoned,
    RevisionConflict,
    NotFound,
    AlreadyExists,
    InvalidInput,
    UnsupportedSchema,
    RecoveryRequired,
    WriterEpochMismatch,
    LiveAuthorizationExists,
    InputReserved,
    ResourceExhausted,
    BudgetExceeded,
    InvalidTransition,
    File,
    UnsupportedPlatform,
    QuarantinedDatabase,
    RecoveredGeneration,
    GenerationArchive,
    UninitializedDatabase,
    UnsafePath,
    MissingDatabase,
    PlaintextRefused,
    UnqualifiedRuntime,
    AuthenticationFailed,
    Io,
    SnapshotLimit,
    SourceChanged,
    ConsentDenied,
    VerificationFailed,
    StateConflict,
    ExactScopeMismatch,
    WorkspaceConsentFalse,
    MaterialConsentFalse,
    ProofConsentFalse,
    Platform,
    Terminal,
    Permission,
    Locked,
    Authentication,
    Quarantined,
    Unsupported,
    Receipt,
    RecoverySemantic,
    RecoveryBackupUnsupported,
    RecoveryFinancialUnsupported,
    CompleteOriginRecoveryUnavailable,
    HistoricalExportIncomplete,
    GenerationArchiveIncomplete,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticEngineCodeV1 {
    DISCLOSURE_DENIED,
    DURABLE_CONSTRUCTION_UNAVAILABLE,
    DURABLE_PROPOSAL_RECOVERY_REQUIRED,
    DURABLE_PROPOSAL_CONFLICT,
    DURABLE_PROPOSAL_NOT_FOUND,
    DURABLE_PROFILE_UNAVAILABLE,
    MANUAL_CONSTRUCTION_DENIED,
    RETAINED_INPUT_OBSERVATION_UNAVAILABLE,
    CANDIDATE_VERIFICATION_FAILED,
    IDEMPOTENCY_CONFLICT,
    REVISION_CONFLICT,
    NOT_FOUND,
    INVALID_REQUEST,
    RECOVERY_REQUIRED,
    LIVE_AUTHORIZATION_EXISTS,
    RESOURCE_EXHAUSTED,
    INVALID_TRANSITION,
    STORAGE_PROTECTION_REQUIRED,
    STORAGE_UNAVAILABLE,
    ACCESS_DENIED,
    INVALID_TERMS,
    UNSUPPORTED_CAPABILITY,
    MISSING_EVIDENCE,
    INVALID_AMOUNT,
    UNKNOWN_PARTICIPANT,
    DUPLICATE_IDENTIFIER,
    CONSERVATION_FAILURE,
    DEBIT_CAP_EXCEEDED,
    FEE_CAP_EXCEEDED,
    UNVERIFIABLE_MATCH,
    PRIVACY_INCOMPATIBLE,
    UNSUPPORTED_VERSION,
    RESOURCE_LIMIT,
    STALE_CHAIN,
    OUTSTANDING_EXPOSURE,
    USER_REJECTED,
    INTERNAL_ERROR,
    Unclassified,
    PERMISSION_DENIED,
    NotApplicable,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticCallStateV1 {
    NotApplicable,
    NotCalled,
    ReturnedOk,
    ReturnedOkFresh,
    ReturnedOkReplay,
    ReturnedOkNoContinuation,
    ReturnedErrUnknown,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticWorkerResultV1 {
    NotStarted,
    NotReceived,
    Disconnected,
    ReceivedOk,
    ReceivedErr,
}
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticWorkerJoinV1 {
    NotStarted,
    Joined,
    Panicked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateDiagnosticCallScopeV1 {
    CurrentInvocation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateDiagnosticPrimaryV1 {
    pub(crate) operation: PrivateDiagnosticOperationV1,
    pub(crate) site: PrivateDiagnosticSiteV1,
    pub(crate) engine_code: PrivateDiagnosticEngineCodeV1,
    pub(crate) family: PrivateDiagnosticFamilyV1,
    pub(crate) cause: PrivateDiagnosticCauseV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateDiagnosticCallsV1 {
    pub(crate) receipt: PrivateDiagnosticCallStateV1,
    pub(crate) enqueue: PrivateDiagnosticCallStateV1,
    pub(crate) link: PrivateDiagnosticCallStateV1,
    pub(crate) proof: PrivateDiagnosticCallStateV1,
    pub(crate) outcome: PrivateDiagnosticCallStateV1,
    pub(crate) freeze: PrivateDiagnosticCallStateV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateDiagnosticEvidenceV1 {
    pub(crate) call_scope: PrivateDiagnosticCallScopeV1,
    pub(crate) attempt_consumed: bool,
    pub(crate) calls: PrivateDiagnosticCallsV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateDiagnosticEngineCoreV1 {
    pub(crate) schema: u8,
    pub(crate) operation: PrivateDiagnosticOperationV1,
    pub(crate) site: PrivateDiagnosticSiteV1,
    pub(crate) engine_code: PrivateDiagnosticEngineCodeV1,
    pub(crate) family: PrivateDiagnosticFamilyV1,
    pub(crate) cause: PrivateDiagnosticCauseV1,
    pub(crate) calls: PrivateDiagnosticCallsV1,
    pub(crate) attempt_consumed: bool,
    pub(crate) call_scope: PrivateDiagnosticCallScopeV1,
}
fn required_private_optional_v1<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateDiagnosticWorkerV1 {
    pub(crate) result: PrivateDiagnosticWorkerResultV1,
    pub(crate) join: PrivateDiagnosticWorkerJoinV1,
    #[serde(deserialize_with = "required_private_optional_v1")]
    pub(crate) engine_failure: Option<PrivateDiagnosticEngineCoreV1>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateFixedDiagnosticV1 {
    pub(crate) schema: u8,
    pub(crate) primary: PrivateDiagnosticPrimaryV1,
    #[serde(deserialize_with = "required_private_optional_v1")]
    pub(crate) evidence: Option<PrivateDiagnosticEvidenceV1>,
    #[serde(deserialize_with = "required_private_optional_v1")]
    pub(crate) worker: Option<PrivateDiagnosticWorkerV1>,
    #[serde(deserialize_with = "required_private_optional_v1")]
    pub(crate) stage: Option<PrivateStageCostV1>,
}
// These are optional measurements, never native permission or effect evidence.
const PRIVATE_STAGE_MAX_COUNT_V1: u64 = 1_000_000;
const PRIVATE_STAGE_MAX_US_V1: u64 = 1_080_000_000;
const PRIVATE_STAGE_MAX_MS_V1: u64 = 1_080_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateStageKindV1 {
    Prepare,
    AdmitOriginal,
    ProveOriginal,
    FreezeFixed,
    ReadFixed,
}
impl PrivateStageKindV1 {
    fn operation(self) -> PrivateDiagnosticOperationV1 {
        use PrivateDiagnosticOperationV1 as O;
        match self {
            Self::Prepare | Self::AdmitOriginal => O::Checkpoint,
            Self::ProveOriginal => O::Proof,
            Self::FreezeFixed => O::Freeze,
            Self::ReadFixed => O::ReadFixed,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateStageCostV1 {
    pub(crate) kind: PrivateStageKindV1,
    pub(crate) elapsed_ms: u64,
    pub(crate) callback_count: u64,
    pub(crate) callback_total_us: u64,
    pub(crate) callback_max_us: u64,
}
impl PrivateStageCostV1 {
    fn valid(&self, operation: PrivateDiagnosticOperationV1) -> bool {
        self.kind.operation() == operation
            && self.elapsed_ms <= PRIVATE_STAGE_MAX_MS_V1
            && self.callback_count <= PRIVATE_STAGE_MAX_COUNT_V1
            && self.callback_total_us <= PRIVATE_STAGE_MAX_US_V1
            && self.callback_max_us <= self.callback_total_us
            && self
                .callback_max_us
                .checked_mul(self.callback_count)
                .is_some_and(|maximum| self.callback_total_us <= maximum)
            && (self.callback_count != 0
                || (self.callback_total_us == 0 && self.callback_max_us == 0))
    }
}
impl PrivateDiagnosticPrimaryV1 {
    fn valid(&self) -> bool {
        if self.family == PrivateDiagnosticFamilyV1::Engine
            && self.engine_code == PrivateDiagnosticEngineCodeV1::NotApplicable
        {
            return false;
        }
        use PrivateDiagnosticCauseV1 as C;
        use PrivateDiagnosticFamilyV1 as F;
        match self.family {
            F::Engine => matches!(
                self.cause,
                C::DISCLOSURE_DENIED
                    | C::DURABLE_CONSTRUCTION_UNAVAILABLE
                    | C::DURABLE_PROPOSAL_RECOVERY_REQUIRED
                    | C::DURABLE_PROPOSAL_CONFLICT
                    | C::DURABLE_PROPOSAL_NOT_FOUND
                    | C::DURABLE_PROFILE_UNAVAILABLE
                    | C::MANUAL_CONSTRUCTION_DENIED
                    | C::RETAINED_INPUT_OBSERVATION_UNAVAILABLE
                    | C::CANDIDATE_VERIFICATION_FAILED
                    | C::IDEMPOTENCY_CONFLICT
                    | C::REVISION_CONFLICT
                    | C::NOT_FOUND
                    | C::INVALID_REQUEST
                    | C::RECOVERY_REQUIRED
                    | C::LIVE_AUTHORIZATION_EXISTS
                    | C::RESOURCE_EXHAUSTED
                    | C::INVALID_TRANSITION
                    | C::STORAGE_PROTECTION_REQUIRED
                    | C::STORAGE_UNAVAILABLE
                    | C::ACCESS_DENIED
                    | C::INVALID_TERMS
                    | C::UNSUPPORTED_CAPABILITY
                    | C::MISSING_EVIDENCE
                    | C::INVALID_AMOUNT
                    | C::UNKNOWN_PARTICIPANT
                    | C::DUPLICATE_IDENTIFIER
                    | C::CONSERVATION_FAILURE
                    | C::DEBIT_CAP_EXCEEDED
                    | C::FEE_CAP_EXCEEDED
                    | C::UNVERIFIABLE_MATCH
                    | C::PRIVACY_INCOMPATIBLE
                    | C::UNSUPPORTED_VERSION
                    | C::RESOURCE_LIMIT
                    | C::STALE_CHAIN
                    | C::OUTSTANDING_EXPOSURE
                    | C::USER_REJECTED
                    | C::INTERNAL_ERROR
                    | C::Unclassified
                    | C::PERMISSION_DENIED
            ),
            F::DurableConstruction => matches!(
                self.cause,
                C::Invalid | C::Binding | C::Stale | C::Storage | C::Unclassified
            ),
            F::Sync => matches!(
                self.cause,
                C::AccessDenied
                    | C::InvalidRequest
                    | C::Interrupted
                    | C::ReconciliationRequired
                    | C::InvalidResponse
                    | C::ResourceLimit
                    | C::NoCurrentObservation
                    | C::Unclassified
            ),
            F::Wallet => matches!(
                self.cause,
                C::Storage
                    | C::AccountScope
                    | C::AccountMismatch
                    | C::IncompleteSync
                    | C::UnsupportedProfile
                    | C::ChainMismatch
                    | C::InsufficientFunds
                    | C::InvalidRequest
                    | C::MissingWitness
                    | C::InvalidNote
                    | C::Scan
                    | C::Transport
                    | C::Unclassified
            ),
            F::Chain => matches!(
                self.cause,
                C::InvalidConfiguration
                    | C::WrongNetwork
                    | C::UnsupportedProxyConfiguration
                    | C::WrongBranch
                    | C::StaleChain
                    | C::ContradictoryChain
                    | C::Timeout
                    | C::TransportUnavailable
                    | C::ObservationInterrupted
                    | C::MissingAncestryEvidence
                    | C::NotObserved
                    | C::ResourceLimit
                    | C::MalformedEvidence
                    | C::UnsupportedCapability
                    | C::BackendFailure
                    | C::ClockUnavailable
                    | C::IdempotencyConflict
                    | C::JournalFailure
                    | C::SubmissionNotAuthorized
                    | C::SubmissionExpiryMargin
                    | C::ObligationConflict
                    | C::SubmissionOutcomeUnrecorded
                    | C::SubmissionRetentionUncertain
                    | C::Unclassified
            ),
            F::Protocol => matches!(
                self.cause,
                C::Manifest
                    | C::Disclosure
                    | C::Context
                    | C::Contribution
                    | C::Input
                    | C::Output
                    | C::Fee
                    | C::BuilderInput
                    | C::BuilderOutput
                    | C::Pczt
                    | C::Finalize
                    | C::ActionMapping
                    | C::FixedBudget
                    | C::FixedOwners
                    | C::FixedRecipient
                    | C::FixedPolicy
                    | C::FixedAccounting
                    | C::FixedRealInput
                    | C::FixedCanonicalAccount
                    | C::FixedDistinctAccounts
                    | C::FixedUnsignedPredecessor
                    | C::FixedUnsignedRealInput
                    | C::FixedProofOnlyTransition
                    | C::FixedPaddingSignature
                    | C::Unclassified
            ),
            F::Store => matches!(
                self.cause,
                C::StorageSecurity
                    | C::Database
                    | C::Encoding
                    | C::Poisoned
                    | C::IdempotencyConflict
                    | C::RevisionConflict
                    | C::NotFound
                    | C::AlreadyExists
                    | C::InvalidInput
                    | C::UnsupportedSchema
                    | C::RecoveryRequired
                    | C::WriterEpochMismatch
                    | C::LiveAuthorizationExists
                    | C::InputReserved
                    | C::ResourceExhausted
                    | C::BudgetExceeded
                    | C::InvalidTransition
                    | C::File
                    | C::Unclassified
            ),
            F::StorageSecurity => matches!(
                self.cause,
                C::UnsupportedPlatform
                    | C::QuarantinedDatabase
                    | C::RecoveredGeneration
                    | C::GenerationArchive
                    | C::UninitializedDatabase
                    | C::UnsafePath
                    | C::AlreadyExists
                    | C::MissingDatabase
                    | C::PlaintextRefused
                    | C::UnqualifiedRuntime
                    | C::AuthenticationFailed
                    | C::Database
                    | C::Io
                    | C::SnapshotLimit
                    | C::SourceChanged
                    | C::Unclassified
            ),
            F::Job => matches!(
                self.cause,
                C::ConsentDenied
                    | C::NotFound
                    | C::InvalidRequest
                    | C::VerificationFailed
                    | C::IdempotencyConflict
                    | C::RecoveryRequired
                    | C::StateConflict
                    | C::Storage
                    | C::UnsupportedSchema
                    | C::ResourceExhausted
                    | C::Unclassified
            ),
            F::Gate => matches!(
                self.cause,
                C::ExactScopeMismatch
                    | C::WorkspaceConsentFalse
                    | C::MaterialConsentFalse
                    | C::ProofConsentFalse
                    | C::Unclassified
            ),
            F::Host => matches!(
                self.cause,
                C::Platform
                    | C::Terminal
                    | C::Permission
                    | C::Locked
                    | C::Invalid
                    | C::Authentication
                    | C::Storage
                    | C::Quarantined
                    | C::Unsupported
                    | C::Receipt
                    | C::RecoverySemantic
                    | C::RecoveryBackupUnsupported
                    | C::RecoveryFinancialUnsupported
                    | C::CompleteOriginRecoveryUnavailable
                    | C::HistoricalExportIncomplete
                    | C::GenerationArchiveIncomplete
                    | C::Unclassified
            ),
        }
    }
}
impl PrivateDiagnosticEvidenceV1 {
    fn valid(&self, operation: PrivateDiagnosticOperationV1) -> bool {
        use PrivateDiagnosticCallStateV1 as C;
        use PrivateDiagnosticOperationV1 as O;
        let store = |value| {
            matches!(
                value,
                C::NotCalled | C::ReturnedOkFresh | C::ReturnedOkReplay | C::ReturnedErrUnknown
            )
        };
        let enqueue = |value| {
            matches!(
                value,
                C::NotCalled
                    | C::ReturnedOkFresh
                    | C::ReturnedOkNoContinuation
                    | C::ReturnedErrUnknown
            )
        };
        let proof = |value| matches!(value, C::NotCalled | C::ReturnedOk | C::ReturnedErrUnknown);
        let c = &self.calls;
        match operation {
            O::Checkpoint => {
                !self.attempt_consumed
                    && store(c.receipt)
                    && enqueue(c.enqueue)
                    && store(c.link)
                    && c.proof == C::NotApplicable
                    && c.outcome == C::NotApplicable
                    && c.freeze == C::NotApplicable
            }
            O::Proof => {
                self.attempt_consumed
                    && proof(c.proof)
                    && store(c.outcome)
                    && c.receipt == C::NotApplicable
                    && c.enqueue == C::NotApplicable
                    && c.link == C::NotApplicable
                    && c.freeze == C::NotApplicable
            }
            O::Freeze => {
                !self.attempt_consumed
                    && store(c.freeze)
                    && c.receipt == C::NotApplicable
                    && c.enqueue == C::NotApplicable
                    && c.link == C::NotApplicable
                    && c.proof == C::NotApplicable
                    && c.outcome == C::NotApplicable
            }
            O::ReadFixed | O::OpenOriginal => {
                !self.attempt_consumed
                    && [c.receipt, c.enqueue, c.link, c.proof, c.outcome, c.freeze]
                        .iter()
                        .all(|value| *value == C::NotApplicable)
            }
        }
    }
}
impl PrivateDiagnosticEngineCoreV1 {
    fn primary(&self) -> PrivateDiagnosticPrimaryV1 {
        PrivateDiagnosticPrimaryV1 {
            operation: self.operation,
            site: self.site,
            engine_code: self.engine_code,
            family: self.family,
            cause: self.cause,
        }
    }
    fn evidence(&self) -> PrivateDiagnosticEvidenceV1 {
        PrivateDiagnosticEvidenceV1 {
            call_scope: self.call_scope,
            attempt_consumed: self.attempt_consumed,
            calls: self.calls.clone(),
        }
    }
    fn valid(&self) -> bool {
        self.schema == 1
            && self.engine_code != PrivateDiagnosticEngineCodeV1::NotApplicable
            && self.primary().valid()
            && self.evidence().valid(self.operation)
            && matches!(
                self.site,
                PrivateDiagnosticSiteV1::WorkspaceLoad
                    | PrivateDiagnosticSiteV1::Candidate
                    | PrivateDiagnosticSiteV1::MaterialRoster
                    | PrivateDiagnosticSiteV1::SlotBindings
                    | PrivateDiagnosticSiteV1::WalletRosterAcquire
                    | PrivateDiagnosticSiteV1::HeldPrecheck
                    | PrivateDiagnosticSiteV1::ConstructorReload
                    | PrivateDiagnosticSiteV1::InputRequestDigest
                    | PrivateDiagnosticSiteV1::OriginalRequest
                    | PrivateDiagnosticSiteV1::OriginalLookup
                    | PrivateDiagnosticSiteV1::OriginalLineage
                    | PrivateDiagnosticSiteV1::ReplayLookup
                    | PrivateDiagnosticSiteV1::Revision
                    | PrivateDiagnosticSiteV1::CurrentTerms
                    | PrivateDiagnosticSiteV1::ProposalValidation
                    | PrivateDiagnosticSiteV1::ProtocolConstruct
                    | PrivateDiagnosticSiteV1::ProtocolInspect
                    | PrivateDiagnosticSiteV1::RetainConsent
                    | PrivateDiagnosticSiteV1::ReceiptPrepare
                    | PrivateDiagnosticSiteV1::ReceiptCommit
                    | PrivateDiagnosticSiteV1::Enqueue
                    | PrivateDiagnosticSiteV1::ReloadAfterEnqueue
                    | PrivateDiagnosticSiteV1::LinkPrepare
                    | PrivateDiagnosticSiteV1::LinkUpsert
                    | PrivateDiagnosticSiteV1::LinkCommit
                    | PrivateDiagnosticSiteV1::PostSource
                    | PrivateDiagnosticSiteV1::PostConsent
                    | PrivateDiagnosticSiteV1::HeldPostcheck
                    | PrivateDiagnosticSiteV1::WalletRosterRelease
                    | PrivateDiagnosticSiteV1::ContinuationBinding
                    | PrivateDiagnosticSiteV1::ProofRun
                    | PrivateDiagnosticSiteV1::ProofResultLineage
                    | PrivateDiagnosticSiteV1::OutcomePrepare
                    | PrivateDiagnosticSiteV1::OutcomeCommit
                    | PrivateDiagnosticSiteV1::StatusLookup
                    | PrivateDiagnosticSiteV1::LoadVerified
                    | PrivateDiagnosticSiteV1::ProofVerifiedState
                    | PrivateDiagnosticSiteV1::FixedMappings
                    | PrivateDiagnosticSiteV1::FixedVerify
                    | PrivateDiagnosticSiteV1::FixedReplayRead
                    | PrivateDiagnosticSiteV1::FixedPrepare
                    | PrivateDiagnosticSiteV1::FixedCommit
                    | PrivateDiagnosticSiteV1::SavedDecode
                    | PrivateDiagnosticSiteV1::OutputLineage
                    | PrivateDiagnosticSiteV1::OperationHistory
                    | PrivateDiagnosticSiteV1::ProofEventHistory
                    | PrivateDiagnosticSiteV1::OutputCommitments
                    | PrivateDiagnosticSiteV1::RetainedDiscovery
                    | PrivateDiagnosticSiteV1::RetainedKey
                    | PrivateDiagnosticSiteV1::ReloadAfterRead
                    | PrivateDiagnosticSiteV1::EnvelopeCompare
                    | PrivateDiagnosticSiteV1::JournalAfterRead
                    | PrivateDiagnosticSiteV1::LogicalCompare
                    | PrivateDiagnosticSiteV1::FinalGate
                    | PrivateDiagnosticSiteV1::FinalProofOrigin
                    | PrivateDiagnosticSiteV1::MetadataPreflight
                    | PrivateDiagnosticSiteV1::MetadataOpen
                    | PrivateDiagnosticSiteV1::SeedAudit
                    | PrivateDiagnosticSiteV1::SourcePermission
                    | PrivateDiagnosticSiteV1::MetadataOrigin
                    | PrivateDiagnosticSiteV1::Marker
                    | PrivateDiagnosticSiteV1::ProofOrigin
                    | PrivateDiagnosticSiteV1::ExactScope
                    | PrivateDiagnosticSiteV1::GateWorkspace
                    | PrivateDiagnosticSiteV1::GateMaterial
                    | PrivateDiagnosticSiteV1::GateHeldPre
                    | PrivateDiagnosticSiteV1::GateHeldPost
                    | PrivateDiagnosticSiteV1::GateProofConsent
                    | PrivateDiagnosticSiteV1::SnapshotOpen
                    | PrivateDiagnosticSiteV1::SnapshotOrigin
                    | PrivateDiagnosticSiteV1::SnapshotSchema
                    | PrivateDiagnosticSiteV1::SnapshotInventory
                    | PrivateDiagnosticSiteV1::SnapshotSourceUnchanged
                    | PrivateDiagnosticSiteV1::SeedPlan
                    | PrivateDiagnosticSiteV1::SeedBinding
                    | PrivateDiagnosticSiteV1::SeedReplay
                    | PrivateDiagnosticSiteV1::SeedRecord
                    | PrivateDiagnosticSiteV1::SeedOperation
                    | PrivateDiagnosticSiteV1::SeedFinal
            )
    }
    fn from_error(error: &wholepact_engine::ApiError) -> Option<Self> {
        let value = error.details.get("private_fixed_diagnostic_v1")?;
        let core: Self = serde_json::from_value(value.clone()).ok()?;
        core.valid().then_some(core)
    }
}
impl PrivateFixedDiagnosticV1 {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        if text.len() > PRIVATE_FIXED_DIAGNOSTIC_MAX_BYTES_V1 {
            return None;
        }
        let value: Self = serde_json::from_str(text).ok()?;
        value.valid().then_some(value)
    }
    pub(crate) fn canonical_json(&self) -> Option<String> {
        if !self.valid() {
            return None;
        }
        let value = serde_json::to_string(self).ok()?;
        (value.len() <= PRIVATE_FIXED_DIAGNOSTIC_MAX_BYTES_V1).then_some(value)
    }
    fn valid(&self) -> bool {
        if self.schema != 1
            || !self.primary.valid()
            || self
                .stage
                .as_ref()
                .is_some_and(|value| !value.valid(self.primary.operation))
            || self
                .evidence
                .as_ref()
                .is_some_and(|value| !value.valid(self.primary.operation))
        {
            return false;
        }
        if let Some(worker) = &self.worker {
            use PrivateDiagnosticWorkerJoinV1 as J;
            use PrivateDiagnosticWorkerResultV1 as R;
            if self.primary.operation != PrivateDiagnosticOperationV1::Proof {
                return false;
            }
            if (worker.result == R::NotStarted) != (worker.join == J::NotStarted) {
                return false;
            }
            if worker.engine_failure.is_none() && self.evidence.is_some() {
                return false;
            }
            if let Some(core) = &worker.engine_failure {
                if worker.result != R::ReceivedErr
                    || core.operation != PrivateDiagnosticOperationV1::Proof
                    || !core.valid()
                    || self.evidence.as_ref() != Some(&core.evidence())
                {
                    return false;
                }
            }
        }
        true
    }
}
#[derive(Default)]
struct PrivateDiagnosticLatchV1 {
    operation: Option<PrivateDiagnosticOperationV1>,
    invocation: Option<u64>,
    first_invocation: Option<u64>,
    stage: Option<PrivateStageStateV1>,
    first_stage: Option<(u64, Option<u64>)>,
    first: Option<PrivateFixedDiagnosticV1>,
    boundary: Option<(&'static str, &'static str)>,
    worker: Option<PrivateDiagnosticWorkerV1>,
}
thread_local! {
    static PRIVATE_DIAGNOSTIC_LATCH_V1:std::cell::RefCell<PrivateDiagnosticLatchV1>=std::cell::RefCell::new(PrivateDiagnosticLatchV1::default());
    static PRIVATE_DIAGNOSTIC_ACTIVE_V1:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static PRIVATE_DIAGNOSTIC_UNAVAILABLE_V1:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static PRIVATE_DIAGNOSTIC_SEQUENCE_V1:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
}
fn invalidate_private_diagnostic_v1() {
    let _ = PRIVATE_DIAGNOSTIC_UNAVAILABLE_V1.try_with(|value| value.set(true));
}
fn private_diagnostic_active_v1() -> bool {
    PRIVATE_DIAGNOSTIC_ACTIVE_V1
        .try_with(|value| value.get())
        .unwrap_or(false)
        && !PRIVATE_DIAGNOSTIC_UNAVAILABLE_V1
            .try_with(|value| value.get())
            .unwrap_or(true)
}
fn with_private_diagnostic_v1<T>(f: impl FnOnce(&mut PrivateDiagnosticLatchV1) -> T) -> Option<T> {
    if !private_diagnostic_active_v1() {
        return None;
    }
    match PRIVATE_DIAGNOSTIC_LATCH_V1.try_with(|slot| match slot.try_borrow_mut() {
        Ok(mut state) => Some(f(&mut state)),
        Err(_) => {
            invalidate_private_diagnostic_v1();
            None
        }
    }) {
        Ok(value) => value,
        Err(_) => {
            invalidate_private_diagnostic_v1();
            None
        }
    }
}
struct PrivateStageStateV1 {
    token: u64,
    invocation: u64,
    start: std::time::Instant,
    cost: PrivateStageCostV1,
    callback: Option<u64>,
    unavailable: bool,
}
impl PrivateStageStateV1 {
    fn snapshot(&self) -> Option<PrivateStageCostV1> {
        if self.unavailable {
            return None;
        }
        let mut cost = self.cost.clone();
        cost.elapsed_ms = std::time::Instant::now()
            .checked_duration_since(self.start)?
            .as_millis()
            .try_into()
            .ok()?;
        cost.valid(cost.kind.operation()).then_some(cost)
    }
}
/// Inert thread-local correlation only. It owns no source, key or native grant.
pub(in crate::host) struct PrivateStageObservationV1 {
    token: Option<u64>,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}
fn latch_private_stage_v1(state: &mut PrivateDiagnosticLatchV1) {
    let Some(stage) = state.stage.as_ref() else {
        return;
    };
    let Some(first) = state.first.as_mut() else {
        return;
    };
    if state.invocation == Some(stage.invocation)
        && state.first_invocation == Some(stage.invocation)
        && first.primary.operation == stage.cost.kind.operation()
    {
        state.first_stage = Some((stage.token, stage.callback));
        first.stage = if stage.callback.is_none() {
            stage.snapshot()
        } else {
            None
        };
    }
}
fn private_stage_kind_v1(kind: wholepact_engine::PrivateFixedStageV3) -> PrivateStageKindV1 {
    use wholepact_engine::PrivateFixedStageV3 as S;
    match kind {
        S::Prepare => PrivateStageKindV1::Prepare,
        S::AdmitOriginal => PrivateStageKindV1::AdmitOriginal,
        S::ProveOriginal => PrivateStageKindV1::ProveOriginal,
        S::FreezeFixed => PrivateStageKindV1::FreezeFixed,
        S::ReadFixed => PrivateStageKindV1::ReadFixed,
    }
}
pub(in crate::host) fn begin_private_stage_cost_v1(
    kind: wholepact_engine::PrivateFixedStageV3,
    deadline: std::time::Instant,
) -> PrivateStageObservationV1 {
    let mut result = PrivateStageObservationV1 {
        token: None,
        local: std::marker::PhantomData,
    };
    if !private_diagnostic_active_v1() {
        return result;
    }
    // Every attempted stage reset invalidates the previous inert generation,
    // even when this allocation or start conversion cannot be observed.
    let _ = with_private_diagnostic_v1(|state| state.stage = None);
    let Some(start) = deadline.checked_sub(Duration::from_secs(120)) else {
        return result;
    };
    let token = PRIVATE_DIAGNOSTIC_SEQUENCE_V1
        .try_with(|value| value.get().checked_add(1).inspect(|next| value.set(*next)))
        .ok()
        .flatten();
    if let Some(token) = token {
        let _ = with_private_diagnostic_v1(|state| {
            // Beginning another stage invalidates its predecessor's future updates.
            state.stage = None;
            if let Some(invocation) = state.invocation {
                result.token = Some(token);
                state.stage = Some(PrivateStageStateV1 {
                    token,
                    invocation,
                    start,
                    cost: PrivateStageCostV1 {
                        kind: private_stage_kind_v1(kind),
                        elapsed_ms: 0,
                        callback_count: 0,
                        callback_total_us: 0,
                        callback_max_us: 0,
                    },
                    callback: None,
                    unavailable: false,
                });
            }
        });
    }
    result
}
impl Drop for PrivateStageObservationV1 {
    fn drop(&mut self) {
        if let Some(token) = self.token {
            let _ = with_private_diagnostic_v1(|state| {
                if state
                    .stage
                    .as_ref()
                    .is_some_and(|stage| stage.token == token)
                {
                    state.stage = None;
                }
            });
        }
    }
}
impl PrivateStageObservationV1 {
    fn matches(&self, state: &PrivateDiagnosticLatchV1) -> bool {
        self.token.is_some()
            && state.stage.as_ref().is_some_and(|stage| {
                Some(stage.token) == self.token && state.invocation == Some(stage.invocation)
            })
    }
    /// Return the original owned result; no predicate is evaluated here.
    pub(in crate::host) fn observe<T>(
        &self,
        site: PrivateDiagnosticSiteV1,
        result: Result<T>,
    ) -> Result<T> {
        if let Err(error) = &result {
            if self.token.is_some()
                && with_private_diagnostic_v1(|state| self.matches(state)).unwrap_or(false)
            {
                observe_private_fixed_host_v1(
                    PrivateDiagnosticOperationV1::OpenOriginal,
                    site,
                    error,
                );
            }
        }
        result
    }
    /// This sum covers only this callback, not Engine or outer source work.
    pub(in crate::host) fn callback<T>(&self, call: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.token.is_none() {
            return call();
        }
        let measured = with_private_diagnostic_v1(|state| {
            if !self.matches(state) {
                return None;
            }
            let stage = state.stage.as_mut()?;
            if stage.unavailable || stage.callback.is_some() {
                stage.unavailable = true;
                return None;
            }
            let Some(count) = stage.cost.callback_count.checked_add(1) else {
                stage.unavailable = true;
                return None;
            };
            if count > PRIVATE_STAGE_MAX_COUNT_V1 {
                stage.unavailable = true;
                return None;
            }
            stage.cost.callback_count = count;
            stage.callback = Some(count);
            Some((count, std::time::Instant::now()))
        })
        .flatten();
        let result = call();
        if let Some((callback, started)) = measured {
            let duration = started.elapsed().as_micros().try_into().ok();
            let _ = with_private_diagnostic_v1(|state| {
                if !self.matches(state) {
                    return;
                }
                let Some(stage) = state.stage.as_mut() else {
                    return;
                };
                if stage.callback != Some(callback) {
                    stage.unavailable = true;
                    return;
                }
                stage.callback = None;
                match duration.and_then(|us: u64| {
                    stage
                        .cost
                        .callback_total_us
                        .checked_add(us)
                        .map(|total| (us, total))
                }) {
                    Some((us, total)) if total <= PRIVATE_STAGE_MAX_US_V1 => {
                        stage.cost.callback_total_us = total;
                        stage.cost.callback_max_us = stage.cost.callback_max_us.max(us);
                    }
                    _ => stage.unavailable = true,
                }
                // Supplement only the exact first error raised inside this call.
                if state.first_stage == Some((stage.token, Some(callback))) {
                    if let Some(first) = &mut state.first {
                        first.stage = stage.snapshot();
                    }
                    state.first_stage = Some((stage.token, None));
                }
            });
        }
        result
    }
}
pub(crate) struct PrivateFixedDiagnosticScopeV1 {
    installed: bool,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}
pub(crate) fn begin_private_fixed_diagnostic_scope_v1() -> PrivateFixedDiagnosticScopeV1 {
    let mut installed = false;
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    if !PRIVATE_DIAGNOSTIC_ACTIVE_V1
        .try_with(|value| value.get())
        .unwrap_or(true)
    {
        let _ = PRIVATE_DIAGNOSTIC_LATCH_V1.try_with(|slot| {
            if let Ok(mut state) = slot.try_borrow_mut() {
                *state = PrivateDiagnosticLatchV1::default();
                let _ = PRIVATE_DIAGNOSTIC_UNAVAILABLE_V1.try_with(|value| value.set(false));
                let _ = PRIVATE_DIAGNOSTIC_ACTIVE_V1.try_with(|value| value.set(true));
                installed = true;
            } else {
                invalidate_private_diagnostic_v1();
            }
        });
    }
    PrivateFixedDiagnosticScopeV1 {
        installed,
        local: std::marker::PhantomData,
    }
}
impl Drop for PrivateFixedDiagnosticScopeV1 {
    fn drop(&mut self) {
        if self.installed {
            // Independent Cells invalidate even if the data RefCell is borrowed.
            let _ = PRIVATE_DIAGNOSTIC_ACTIVE_V1.try_with(|value| value.set(false));
            invalidate_private_diagnostic_v1();
            let _ = PRIVATE_DIAGNOSTIC_LATCH_V1.try_with(|slot| {
                if let Ok(mut state) = slot.try_borrow_mut() {
                    *state = PrivateDiagnosticLatchV1::default();
                }
            });
        }
    }
}
struct PrivateDiagnosticInvocationV1 {
    token: Option<u64>,
    previous: Option<u64>,
    operation: Option<PrivateDiagnosticOperationV1>,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}
fn begin_private_diagnostic_invocation_v1(
    operation: PrivateDiagnosticOperationV1,
) -> PrivateDiagnosticInvocationV1 {
    let mut guard = PrivateDiagnosticInvocationV1 {
        token: None,
        previous: None,
        operation: None,
        local: std::marker::PhantomData,
    };
    if !private_diagnostic_active_v1() {
        return guard;
    }
    let token = PRIVATE_DIAGNOSTIC_SEQUENCE_V1
        .try_with(|value| value.get().checked_add(1).inspect(|next| value.set(*next)))
        .ok()
        .flatten();
    let Some(token) = token else {
        invalidate_private_diagnostic_v1();
        return guard;
    };
    let _ = with_private_diagnostic_v1(|state| {
        guard.previous = state.invocation;
        guard.operation = state.operation;
        guard.token = Some(token);
        state.invocation = Some(token);
        state.operation = Some(operation);
    });
    guard
}
impl Drop for PrivateDiagnosticInvocationV1 {
    fn drop(&mut self) {
        if let Some(token) = self.token {
            let _ = with_private_diagnostic_v1(|state| {
                if state.invocation == Some(token) {
                    state.invocation = self.previous;
                    state.operation = self.operation;
                } else {
                    invalidate_private_diagnostic_v1();
                }
            });
        }
    }
}
fn private_diagnostic_operation_v1(operation: PrivateDiagnosticOperationV1) {
    let _ = with_private_diagnostic_v1(|state| state.operation = Some(operation));
}
fn private_root_operation_v1(
    operation: PrivateDiagnosticOperationV1,
) -> PrivateDiagnosticOperationV1 {
    if operation == PrivateDiagnosticOperationV1::OpenOriginal {
        with_private_diagnostic_v1(|state| state.operation)
            .flatten()
            .unwrap_or(operation)
    } else {
        operation
    }
}
pub(crate) fn private_fixed_diagnostic_snapshot_v1() -> Option<PrivateFixedDiagnosticV1> {
    with_private_diagnostic_v1(|state| state.first.clone())
        .flatten()
        .filter(PrivateFixedDiagnosticV1::valid)
}
fn record_private_primary_v1(
    primary: PrivateDiagnosticPrimaryV1,
    evidence: Option<PrivateDiagnosticEvidenceV1>,
) {
    let _ = with_private_diagnostic_v1(|state| {
        if state.first.is_some() {
            return;
        }
        let worker = if primary.operation == PrivateDiagnosticOperationV1::Proof {
            state.worker.clone()
        } else {
            None
        };
        state.first_invocation = state.invocation;
        state.first = Some(PrivateFixedDiagnosticV1 {
            schema: 1,
            primary,
            evidence,
            worker,
            stage: None,
        });
        latch_private_stage_v1(state);
    });
}
fn host_private_primary_v1(
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    family: PrivateDiagnosticFamilyV1,
    cause: PrivateDiagnosticCauseV1,
) {
    record_private_primary_v1(
        PrivateDiagnosticPrimaryV1 {
            operation: private_root_operation_v1(operation),
            site,
            engine_code: PrivateDiagnosticEngineCodeV1::NotApplicable,
            family,
            cause,
        },
        None,
    );
}
pub(crate) fn observe_private_fixed_host_v1(
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    error: &Error,
) {
    use PrivateDiagnosticCauseV1 as C;
    let cause = match error {
        Error::Platform => C::Platform,
        Error::Terminal => C::Terminal,
        Error::Permission => C::Permission,
        Error::Locked => C::Locked,
        Error::Invalid => C::Invalid,
        Error::Authentication => C::Authentication,
        Error::Storage => C::Storage,
        Error::Quarantined => C::Quarantined,
        Error::Unsupported => C::Unsupported,
        Error::Receipt(_) => C::Receipt,
        Error::RecoverySemantic(_) => C::RecoverySemantic,
        Error::RecoveryBackupUnsupported => C::RecoveryBackupUnsupported,
        Error::RecoveryFinancialUnsupported => C::RecoveryFinancialUnsupported,
        Error::CompleteOriginRecoveryUnavailable => C::CompleteOriginRecoveryUnavailable,
        Error::HistoricalExportIncomplete => C::HistoricalExportIncomplete,
        Error::GenerationArchiveIncomplete => C::GenerationArchiveIncomplete,
    };
    host_private_primary_v1(operation, site, PrivateDiagnosticFamilyV1::Host, cause);
}
pub(crate) fn observe_private_fixed_job_v1(
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    error: &wholepact_proof_jobs::JobError,
) {
    use PrivateDiagnosticCauseV1 as C;
    use wholepact_proof_jobs::JobError as E;
    let cause = match error {
        E::ConsentDenied => C::ConsentDenied,
        E::NotFound => C::NotFound,
        E::InvalidRequest => C::InvalidRequest,
        E::VerificationFailed => C::VerificationFailed,
        E::IdempotencyConflict => C::IdempotencyConflict,
        E::RecoveryRequired => C::RecoveryRequired,
        E::StateConflict => C::StateConflict,
        E::Storage => C::Storage,
        E::UnsupportedSchema => C::UnsupportedSchema,
        E::ResourceExhausted => C::ResourceExhausted,
    };
    host_private_primary_v1(operation, site, PrivateDiagnosticFamilyV1::Job, cause);
}
pub(crate) fn observe_private_fixed_storage_v1(
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    error: &wholepact_storage_security::StorageSecurityError,
) {
    use PrivateDiagnosticCauseV1 as C;
    use wholepact_storage_security::StorageSecurityError as E;
    let cause = match error {
        E::UnsupportedPlatform => C::UnsupportedPlatform,
        E::QuarantinedDatabase => C::QuarantinedDatabase,
        E::RecoveredGeneration => C::RecoveredGeneration,
        E::GenerationArchive => C::GenerationArchive,
        E::UninitializedDatabase => C::UninitializedDatabase,
        E::UnsafePath => C::UnsafePath,
        E::AlreadyExists => C::AlreadyExists,
        E::MissingDatabase => C::MissingDatabase,
        E::PlaintextRefused => C::PlaintextRefused,
        E::UnqualifiedRuntime => C::UnqualifiedRuntime,
        E::AuthenticationFailed => C::AuthenticationFailed,
        E::Database => C::Database,
        E::Io => C::Io,
        E::SnapshotLimit => C::SnapshotLimit,
        E::SourceChanged => C::SourceChanged,
    };
    host_private_primary_v1(
        operation,
        site,
        PrivateDiagnosticFamilyV1::StorageSecurity,
        cause,
    );
}
pub(crate) fn observe_private_fixed_store_v1(
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    error: &wholepact_store::StoreError,
) {
    use PrivateDiagnosticCauseV1 as C;
    use wholepact_store::StoreError as E;
    if let E::StorageSecurity(inner) = error {
        observe_private_fixed_storage_v1(operation, site, inner);
        return;
    }
    let cause = match error {
        E::StorageSecurity(_) => C::StorageSecurity,
        E::Database(_) => C::Database,
        E::Encoding(_) => C::Encoding,
        E::Poisoned => C::Poisoned,
        E::IdempotencyConflict => C::IdempotencyConflict,
        E::RevisionConflict => C::RevisionConflict,
        E::NotFound => C::NotFound,
        E::AlreadyExists => C::AlreadyExists,
        E::InvalidInput(_) => C::InvalidInput,
        E::UnsupportedSchema(_) => C::UnsupportedSchema,
        E::RecoveryRequired => C::RecoveryRequired,
        E::WriterEpochMismatch => C::WriterEpochMismatch,
        E::LiveAuthorizationExists => C::LiveAuthorizationExists,
        E::InputReserved => C::InputReserved,
        E::ResourceExhausted => C::ResourceExhausted,
        E::BudgetExceeded => C::BudgetExceeded,
        E::InvalidTransition => C::InvalidTransition,
        E::File(_) => C::File,
    };
    host_private_primary_v1(operation, site, PrivateDiagnosticFamilyV1::Store, cause);
}
pub(crate) fn observe_private_fixed_engine_v1(
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    error: &wholepact_engine::ApiError,
) {
    let operation = private_root_operation_v1(operation);
    let core = PrivateDiagnosticEngineCoreV1::from_error(error);
    if let Some(core) = core {
        let same_operation = core.operation == operation;
        let _ = with_private_diagnostic_v1(|state| {
            let worker = if operation == PrivateDiagnosticOperationV1::Proof {
                state.worker.clone()
            } else {
                None
            };
            if let Some(first) = &mut state.first {
                // Exact current guard, never operation-label equality alone.
                if same_operation
                    && state.invocation.is_some()
                    && state.first_invocation == state.invocation
                    && first.primary.operation == operation
                {
                    first.evidence = Some(core.evidence());
                    first.worker = worker;
                }
            } else {
                let mut primary = core.primary();
                primary.operation = operation;
                state.first_invocation = state.invocation;
                state.first = Some(PrivateFixedDiagnosticV1 {
                    schema: 1,
                    primary,
                    evidence: same_operation.then(|| core.evidence()),
                    worker,
                    stage: None,
                });
                latch_private_stage_v1(state);
            }
        });
    } else {
        let code = match error.code.as_str() {
            "DISCLOSURE_DENIED" => PrivateDiagnosticEngineCodeV1::DISCLOSURE_DENIED,
            "DURABLE_CONSTRUCTION_UNAVAILABLE" => {
                PrivateDiagnosticEngineCodeV1::DURABLE_CONSTRUCTION_UNAVAILABLE
            }
            "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => {
                PrivateDiagnosticEngineCodeV1::DURABLE_PROPOSAL_RECOVERY_REQUIRED
            }
            "DURABLE_PROPOSAL_CONFLICT" => PrivateDiagnosticEngineCodeV1::DURABLE_PROPOSAL_CONFLICT,
            "DURABLE_PROPOSAL_NOT_FOUND" => {
                PrivateDiagnosticEngineCodeV1::DURABLE_PROPOSAL_NOT_FOUND
            }
            "DURABLE_PROFILE_UNAVAILABLE" => {
                PrivateDiagnosticEngineCodeV1::DURABLE_PROFILE_UNAVAILABLE
            }
            "MANUAL_CONSTRUCTION_DENIED" => {
                PrivateDiagnosticEngineCodeV1::MANUAL_CONSTRUCTION_DENIED
            }
            "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => {
                PrivateDiagnosticEngineCodeV1::RETAINED_INPUT_OBSERVATION_UNAVAILABLE
            }
            "CANDIDATE_VERIFICATION_FAILED" => {
                PrivateDiagnosticEngineCodeV1::CANDIDATE_VERIFICATION_FAILED
            }
            "IDEMPOTENCY_CONFLICT" => PrivateDiagnosticEngineCodeV1::IDEMPOTENCY_CONFLICT,
            "REVISION_CONFLICT" => PrivateDiagnosticEngineCodeV1::REVISION_CONFLICT,
            "NOT_FOUND" => PrivateDiagnosticEngineCodeV1::NOT_FOUND,
            "INVALID_REQUEST" => PrivateDiagnosticEngineCodeV1::INVALID_REQUEST,
            "RECOVERY_REQUIRED" => PrivateDiagnosticEngineCodeV1::RECOVERY_REQUIRED,
            "LIVE_AUTHORIZATION_EXISTS" => PrivateDiagnosticEngineCodeV1::LIVE_AUTHORIZATION_EXISTS,
            "RESOURCE_EXHAUSTED" => PrivateDiagnosticEngineCodeV1::RESOURCE_EXHAUSTED,
            "INVALID_TRANSITION" => PrivateDiagnosticEngineCodeV1::INVALID_TRANSITION,
            "STORAGE_PROTECTION_REQUIRED" => {
                PrivateDiagnosticEngineCodeV1::STORAGE_PROTECTION_REQUIRED
            }
            "STORAGE_UNAVAILABLE" => PrivateDiagnosticEngineCodeV1::STORAGE_UNAVAILABLE,
            "ACCESS_DENIED" => PrivateDiagnosticEngineCodeV1::ACCESS_DENIED,
            "INVALID_TERMS" => PrivateDiagnosticEngineCodeV1::INVALID_TERMS,
            "UNSUPPORTED_CAPABILITY" => PrivateDiagnosticEngineCodeV1::UNSUPPORTED_CAPABILITY,
            "MISSING_EVIDENCE" => PrivateDiagnosticEngineCodeV1::MISSING_EVIDENCE,
            "INVALID_AMOUNT" => PrivateDiagnosticEngineCodeV1::INVALID_AMOUNT,
            "UNKNOWN_PARTICIPANT" => PrivateDiagnosticEngineCodeV1::UNKNOWN_PARTICIPANT,
            "DUPLICATE_IDENTIFIER" => PrivateDiagnosticEngineCodeV1::DUPLICATE_IDENTIFIER,
            "CONSERVATION_FAILURE" => PrivateDiagnosticEngineCodeV1::CONSERVATION_FAILURE,
            "DEBIT_CAP_EXCEEDED" => PrivateDiagnosticEngineCodeV1::DEBIT_CAP_EXCEEDED,
            "FEE_CAP_EXCEEDED" => PrivateDiagnosticEngineCodeV1::FEE_CAP_EXCEEDED,
            "UNVERIFIABLE_MATCH" => PrivateDiagnosticEngineCodeV1::UNVERIFIABLE_MATCH,
            "PRIVACY_INCOMPATIBLE" => PrivateDiagnosticEngineCodeV1::PRIVACY_INCOMPATIBLE,
            "UNSUPPORTED_VERSION" => PrivateDiagnosticEngineCodeV1::UNSUPPORTED_VERSION,
            "RESOURCE_LIMIT" => PrivateDiagnosticEngineCodeV1::RESOURCE_LIMIT,
            "STALE_CHAIN" => PrivateDiagnosticEngineCodeV1::STALE_CHAIN,
            "OUTSTANDING_EXPOSURE" => PrivateDiagnosticEngineCodeV1::OUTSTANDING_EXPOSURE,
            "USER_REJECTED" => PrivateDiagnosticEngineCodeV1::USER_REJECTED,
            "INTERNAL_ERROR" => PrivateDiagnosticEngineCodeV1::INTERNAL_ERROR,
            "PERMISSION_DENIED" => PrivateDiagnosticEngineCodeV1::PERMISSION_DENIED,
            _ => PrivateDiagnosticEngineCodeV1::Unclassified,
        };
        let cause = match error.code.as_str() {
            "DISCLOSURE_DENIED" => PrivateDiagnosticCauseV1::DISCLOSURE_DENIED,
            "DURABLE_CONSTRUCTION_UNAVAILABLE" => {
                PrivateDiagnosticCauseV1::DURABLE_CONSTRUCTION_UNAVAILABLE
            }
            "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => {
                PrivateDiagnosticCauseV1::DURABLE_PROPOSAL_RECOVERY_REQUIRED
            }
            "DURABLE_PROPOSAL_CONFLICT" => PrivateDiagnosticCauseV1::DURABLE_PROPOSAL_CONFLICT,
            "DURABLE_PROPOSAL_NOT_FOUND" => PrivateDiagnosticCauseV1::DURABLE_PROPOSAL_NOT_FOUND,
            "DURABLE_PROFILE_UNAVAILABLE" => PrivateDiagnosticCauseV1::DURABLE_PROFILE_UNAVAILABLE,
            "MANUAL_CONSTRUCTION_DENIED" => PrivateDiagnosticCauseV1::MANUAL_CONSTRUCTION_DENIED,
            "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => {
                PrivateDiagnosticCauseV1::RETAINED_INPUT_OBSERVATION_UNAVAILABLE
            }
            "CANDIDATE_VERIFICATION_FAILED" => {
                PrivateDiagnosticCauseV1::CANDIDATE_VERIFICATION_FAILED
            }
            "IDEMPOTENCY_CONFLICT" => PrivateDiagnosticCauseV1::IDEMPOTENCY_CONFLICT,
            "REVISION_CONFLICT" => PrivateDiagnosticCauseV1::REVISION_CONFLICT,
            "NOT_FOUND" => PrivateDiagnosticCauseV1::NOT_FOUND,
            "INVALID_REQUEST" => PrivateDiagnosticCauseV1::INVALID_REQUEST,
            "RECOVERY_REQUIRED" => PrivateDiagnosticCauseV1::RECOVERY_REQUIRED,
            "LIVE_AUTHORIZATION_EXISTS" => PrivateDiagnosticCauseV1::LIVE_AUTHORIZATION_EXISTS,
            "RESOURCE_EXHAUSTED" => PrivateDiagnosticCauseV1::RESOURCE_EXHAUSTED,
            "INVALID_TRANSITION" => PrivateDiagnosticCauseV1::INVALID_TRANSITION,
            "STORAGE_PROTECTION_REQUIRED" => PrivateDiagnosticCauseV1::STORAGE_PROTECTION_REQUIRED,
            "STORAGE_UNAVAILABLE" => PrivateDiagnosticCauseV1::STORAGE_UNAVAILABLE,
            "ACCESS_DENIED" => PrivateDiagnosticCauseV1::ACCESS_DENIED,
            "INVALID_TERMS" => PrivateDiagnosticCauseV1::INVALID_TERMS,
            "UNSUPPORTED_CAPABILITY" => PrivateDiagnosticCauseV1::UNSUPPORTED_CAPABILITY,
            "MISSING_EVIDENCE" => PrivateDiagnosticCauseV1::MISSING_EVIDENCE,
            "INVALID_AMOUNT" => PrivateDiagnosticCauseV1::INVALID_AMOUNT,
            "UNKNOWN_PARTICIPANT" => PrivateDiagnosticCauseV1::UNKNOWN_PARTICIPANT,
            "DUPLICATE_IDENTIFIER" => PrivateDiagnosticCauseV1::DUPLICATE_IDENTIFIER,
            "CONSERVATION_FAILURE" => PrivateDiagnosticCauseV1::CONSERVATION_FAILURE,
            "DEBIT_CAP_EXCEEDED" => PrivateDiagnosticCauseV1::DEBIT_CAP_EXCEEDED,
            "FEE_CAP_EXCEEDED" => PrivateDiagnosticCauseV1::FEE_CAP_EXCEEDED,
            "UNVERIFIABLE_MATCH" => PrivateDiagnosticCauseV1::UNVERIFIABLE_MATCH,
            "PRIVACY_INCOMPATIBLE" => PrivateDiagnosticCauseV1::PRIVACY_INCOMPATIBLE,
            "UNSUPPORTED_VERSION" => PrivateDiagnosticCauseV1::UNSUPPORTED_VERSION,
            "RESOURCE_LIMIT" => PrivateDiagnosticCauseV1::RESOURCE_LIMIT,
            "STALE_CHAIN" => PrivateDiagnosticCauseV1::STALE_CHAIN,
            "OUTSTANDING_EXPOSURE" => PrivateDiagnosticCauseV1::OUTSTANDING_EXPOSURE,
            "USER_REJECTED" => PrivateDiagnosticCauseV1::USER_REJECTED,
            "INTERNAL_ERROR" => PrivateDiagnosticCauseV1::INTERNAL_ERROR,
            "PERMISSION_DENIED" => PrivateDiagnosticCauseV1::PERMISSION_DENIED,
            _ => PrivateDiagnosticCauseV1::Unclassified,
        };
        let job = error
            .details
            .get("private_original_job_error_v1")
            .and_then(serde_json::Value::as_str)
            .and_then(|label| match label {
                "consent_denied" => Some(PrivateDiagnosticCauseV1::ConsentDenied),
                "not_found" => Some(PrivateDiagnosticCauseV1::NotFound),
                "invalid_request" => Some(PrivateDiagnosticCauseV1::InvalidRequest),
                "verification_failed" => Some(PrivateDiagnosticCauseV1::VerificationFailed),
                "idempotency_conflict" => Some(PrivateDiagnosticCauseV1::IdempotencyConflict),
                "recovery_required" => Some(PrivateDiagnosticCauseV1::RecoveryRequired),
                "state_conflict" => Some(PrivateDiagnosticCauseV1::StateConflict),
                "storage" => Some(PrivateDiagnosticCauseV1::Storage),
                "unsupported_schema" => Some(PrivateDiagnosticCauseV1::UnsupportedSchema),
                "resource_exhausted" => Some(PrivateDiagnosticCauseV1::ResourceExhausted),
                _ => None,
            });
        let (family, cause) = job.map_or((PrivateDiagnosticFamilyV1::Engine, cause), |cause| {
            (PrivateDiagnosticFamilyV1::Job, cause)
        });
        record_private_primary_v1(
            PrivateDiagnosticPrimaryV1 {
                operation,
                site,
                engine_code: code,
                family,
                cause,
            },
            None,
        );
    }
}
fn observe_private_host_current_at_v1(site: PrivateDiagnosticSiteV1, error: &Error) {
    if let Some(operation) = with_private_diagnostic_v1(|state| state.operation).flatten() {
        observe_private_fixed_host_v1(operation, site, error);
    }
}
fn private_host_result_at_v1<T>(site: PrivateDiagnosticSiteV1, result: Result<T>) -> Result<T> {
    if let Err(error) = &result {
        observe_private_host_current_at_v1(site, error);
    }
    result
}
fn observed_private_permission_at_v1(site: PrivateDiagnosticSiteV1, result: Result<()>) -> bool {
    if let Err(error) = &result {
        observe_private_host_current_at_v1(site, error);
    }
    observed_host_permission(result)
}
fn private_worker_start_v1() {
    let _ = with_private_diagnostic_v1(|state| {
        state.worker = Some(PrivateDiagnosticWorkerV1 {
            result: PrivateDiagnosticWorkerResultV1::NotReceived,
            join: PrivateDiagnosticWorkerJoinV1::NotStarted,
            engine_failure: None,
        })
    });
}
fn private_worker_received_v1<T>(result: &std::result::Result<T, wholepact_engine::ApiError>) {
    let _ = with_private_diagnostic_v1(|state| {
        if let Some(worker) = &mut state.worker {
            worker.result = if result.is_ok() {
                PrivateDiagnosticWorkerResultV1::ReceivedOk
            } else {
                PrivateDiagnosticWorkerResultV1::ReceivedErr
            };
            worker.engine_failure = result
                .as_ref()
                .err()
                .and_then(PrivateDiagnosticEngineCoreV1::from_error)
                .filter(|core| core.operation == PrivateDiagnosticOperationV1::Proof);
        }
    });
}
fn private_worker_disconnected_v1() {
    let _ = with_private_diagnostic_v1(|state| {
        if let Some(worker) = &mut state.worker {
            worker.result = PrivateDiagnosticWorkerResultV1::Disconnected;
        }
    });
}
fn private_worker_joined_v1(joined: bool) {
    let _ = with_private_diagnostic_v1(|state| {
        if let Some(worker) = &mut state.worker {
            worker.join = if joined {
                PrivateDiagnosticWorkerJoinV1::Joined
            } else {
                PrivateDiagnosticWorkerJoinV1::Panicked
            };
        }
        let worker = state.worker.clone();
        if let Some(first) = &mut state.first {
            if first.primary.operation == PrivateDiagnosticOperationV1::Proof
                && state.first_invocation == state.invocation
            {
                first.worker = worker;
            }
        }
    });
}
pub(crate) fn observe_private_fixed_boundary_v1(boundary: &'static str, outcome: &'static str) {
    let boundary = match boundary {
        "PrivateWorkspaceBootstrap" => "PrivateWorkspaceBootstrap",
        "PrivateSourceSelect" => "PrivateSourceSelect",
        "PrivateWorkspaceReserve" => "PrivateWorkspaceReserve",
        "PrivateWorkspaceAnchor" => "PrivateWorkspaceAnchor",
        "PrivateWorkspacePublish" => "PrivateWorkspacePublish",
        "PrivateWorkspaceInitialize" => "PrivateWorkspaceInitialize",
        "PrivateWorkspaceCandidate" => "PrivateWorkspaceCandidate",
        "PrivateWorkspaceCapture" => "PrivateWorkspaceCapture",
        "PrivateWorkspaceIntake" => "PrivateWorkspaceIntake",
        "PrivateWorkspaceObserve" => "PrivateWorkspaceObserve",
        "PrivateWorkspaceCheckpoint" => "PrivateWorkspaceCheckpoint",
        "PrivateWorkspaceProof" => "PrivateWorkspaceProof",
        "PrivateWorkspaceFreeze" => "PrivateWorkspaceFreeze",
        "PrivateWorkspaceScanCleanup" => "PrivateWorkspaceScanCleanup",
        "PrivateWorkspaceDurableMarker" => "PrivateWorkspaceDurableMarker",
        "PrivateWorkspaceProducerKill" => "PrivateWorkspaceProducerKill",
        "PrivateWorkspaceProducerReap" => "PrivateWorkspaceProducerReap",
        "PrivateWorkspaceReaderOpen" => "PrivateWorkspaceReaderOpen",
        "PrivateWorkspaceReadFixed" => "PrivateWorkspaceReadFixed",
        "PrivateWorkspaceIdentityCompare" => "PrivateWorkspaceIdentityCompare",
        "PrivateWorkspaceReaderReap" => "PrivateWorkspaceReaderReap",
        "PrivateWorkspaceRootCleanup" => "PrivateWorkspaceRootCleanup",
        _ => return,
    };
    let outcome = match outcome {
        "HostPlatform" => "HostPlatform",
        "HostTerminal" => "HostTerminal",
        "HostPermission" => "HostPermission",
        "HostLocked" => "HostLocked",
        "HostInvalid" => "HostInvalid",
        "HostAuthentication" => "HostAuthentication",
        "HostStorage" => "HostStorage",
        "HostQuarantined" => "HostQuarantined",
        "HostUnsupported" => "HostUnsupported",
        "HostReceipt" => "HostReceipt",
        "HostRecoverySemantic" => "HostRecoverySemantic",
        "HostRecoveryBackupUnsupported" => "HostRecoveryBackupUnsupported",
        "HostRecoveryFinancialUnsupported" => "HostRecoveryFinancialUnsupported",
        "HostCompleteOriginRecoveryUnavailable" => "HostCompleteOriginRecoveryUnavailable",
        "HostHistoricalExportIncomplete" => "HostHistoricalExportIncomplete",
        "HostGenerationArchiveIncomplete" => "HostGenerationArchiveIncomplete",
        "EngineManualConstructionDenied" => "EngineManualConstructionDenied",
        "EngineRetainedObservationUnavailable" => "EngineRetainedObservationUnavailable",
        "EngineCandidateVerificationFailed" => "EngineCandidateVerificationFailed",
        "EngineIdempotencyConflict" => "EngineIdempotencyConflict",
        "EngineRevisionConflict" => "EngineRevisionConflict",
        "EngineNotFound" => "EngineNotFound",
        "EngineInvalidRequest" => "EngineInvalidRequest",
        "EngineRecoveryRequired" => "EngineRecoveryRequired",
        "EngineLiveAuthorizationExists" => "EngineLiveAuthorizationExists",
        "EngineResourceExhausted" => "EngineResourceExhausted",
        "EngineInvalidTransition" => "EngineInvalidTransition",
        "EngineStorageProtectionRequired" => "EngineStorageProtectionRequired",
        "EngineStorageUnavailable" => "EngineStorageUnavailable",
        "EngineAccessDenied" => "EngineAccessDenied",
        "EngineUnclassified" => "EngineUnclassified",
        "EngineDisclosureDenied" => "EngineDisclosureDenied",
        "EngineDurableConstructionUnavailable" => "EngineDurableConstructionUnavailable",
        "EngineDurableProposalRecoveryRequired" => "EngineDurableProposalRecoveryRequired",
        "EngineMissingEvidence" => "EngineMissingEvidence",
        "EngineInvalidTerms" => "EngineInvalidTerms",
        "EngineUnsupportedCapability" => "EngineUnsupportedCapability",
        "EngineDebitCapExceeded" => "EngineDebitCapExceeded",
        "EnginePermissionDenied" => "EnginePermissionDenied",
        "EngineInternalError" => "EngineInternalError",
        "JobConsentDenied" => "JobConsentDenied",
        "JobNotFound" => "JobNotFound",
        "JobInvalidRequest" => "JobInvalidRequest",
        "JobVerificationFailed" => "JobVerificationFailed",
        "JobIdempotencyConflict" => "JobIdempotencyConflict",
        "JobRecoveryRequired" => "JobRecoveryRequired",
        "JobStateConflict" => "JobStateConflict",
        "JobStorage" => "JobStorage",
        "JobUnsupportedSchema" => "JobUnsupportedSchema",
        "JobResourceExhausted" => "JobResourceExhausted",
        "BridgeBinding" => "BridgeBinding",
        "BridgeConflict" => "BridgeConflict",
        "BridgeMissing" => "BridgeMissing",
        "BridgeUncertain" => "BridgeUncertain",
        "BridgeLimit" => "BridgeLimit",
        "BridgePermission" => "BridgePermission",
        "BridgeRecoveryRequired" => "BridgeRecoveryRequired",
        "BridgeCompleteOriginRecoveryUnavailable" => "BridgeCompleteOriginRecoveryUnavailable",
        "BridgeVerification" => "BridgeVerification",
        "BridgeSignerOriginUnavailable" => "BridgeSignerOriginUnavailable",
        "BridgeJournal" => "BridgeJournal",
        "BridgeAuthority" => "BridgeAuthority",
        "BridgeWallet" => "BridgeWallet",
        "BridgeIpc" => "BridgeIpc",
        _ => return,
    };
    if outcome.starts_with("Bridge") && boundary != "PrivateWorkspaceCapture" {
        return;
    }
    if (outcome.starts_with("Engine") || outcome.starts_with("Job"))
        && matches!(
            boundary,
            "PrivateWorkspaceScanCleanup"
                | "PrivateWorkspaceDurableMarker"
                | "PrivateWorkspaceProducerKill"
                | "PrivateWorkspaceProducerReap"
                | "PrivateWorkspaceReaderReap"
                | "PrivateWorkspaceRootCleanup"
        )
    {
        return;
    }
    let _ = with_private_diagnostic_v1(|state| {
        if state.boundary.is_none() {
            state.boundary = Some((boundary, outcome));
        }
    });
}
pub(crate) fn first_private_fixed_boundary_v1() -> Option<(&'static str, &'static str)> {
    with_private_diagnostic_v1(|state| state.boundary).flatten()
}

// Product calls evaluate exactly once and preserve the existing error type.
// The test-only observer records finite source categories before wrapper loss;
// it never changes arguments, retries, supplies consent or formats private data.
#[derive(Clone, Copy)]
enum PrivateBoundaryV2 {
    Source,
    Candidate,
    Capture,
    Intake,
    Observe,
    Checkpoint,
    Proof,
    Freeze,
    Cleanup,
    Read,
}
impl PrivateBoundaryV2 {
    fn diagnostic_v1(self) -> Option<(PrivateDiagnosticOperationV1, PrivateDiagnosticSiteV1)> {
        use PrivateDiagnosticOperationV1 as O;
        use PrivateDiagnosticSiteV1 as S;
        match self {
            Self::Observe => Some((O::Checkpoint, S::WalletRosterAcquire)),
            Self::Checkpoint => Some((O::Checkpoint, S::HostCheckpointEntry)),
            Self::Proof => Some((O::Proof, S::HostProofPrecheck)),
            Self::Freeze => Some((O::Freeze, S::HostFreezeReturn)),
            Self::Read => Some((O::ReadFixed, S::HostReadReturn)),
            _ => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Source => "PrivateSourceSelect",
            Self::Candidate => "PrivateWorkspaceCandidate",
            Self::Capture => "PrivateWorkspaceCapture",
            Self::Intake => "PrivateWorkspaceIntake",
            Self::Observe => "PrivateWorkspaceObserve",
            Self::Checkpoint => "PrivateWorkspaceCheckpoint",
            Self::Proof => "PrivateWorkspaceProof",
            Self::Freeze => "PrivateWorkspaceFreeze",
            Self::Cleanup => "PrivateWorkspaceScanCleanup",
            Self::Read => "PrivateWorkspaceReadFixed",
        }
    }
}
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
thread_local! {
    static PRIVATE_FIRST_FAILURE_V2: std::cell::RefCell<Option<(&'static str, &'static str)>> = const { std::cell::RefCell::new(None) };
    static PRIVATE_CURRENT_BOUNDARY_V2: std::cell::Cell<PrivateBoundaryV2> = const { std::cell::Cell::new(PrivateBoundaryV2::Source) };
}
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(in crate::host) fn first_private_failure_v2() -> Option<(&'static str, &'static str)> {
    PRIVATE_FIRST_FAILURE_V2.with(|first| first.try_borrow().ok().and_then(|first| *first))
}
fn observe_failure(boundary: PrivateBoundaryV2, outcome: &'static str) {
    observe_private_fixed_boundary_v1(boundary.label(), outcome);
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    PRIVATE_FIRST_FAILURE_V2.with(|first| {
        let Ok(mut first) = first.try_borrow_mut() else {
            return;
        };
        if first.is_none() {
            *first = Some((boundary.label(), outcome));
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr().lock(),
                "\n[JOINED_DIAGNOSTIC {} {}]",
                boundary.label(),
                outcome
            );
        }
    });
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = (boundary, outcome);
}
fn begin_private_stage(boundary: PrivateBoundaryV2) {
    let action = match boundary {
        PrivateBoundaryV2::Observe => Some(PrivateWorkspaceActionV1::ObserveExactMaterial),
        PrivateBoundaryV2::Checkpoint => Some(PrivateWorkspaceActionV1::CheckpointExactOriginal),
        PrivateBoundaryV2::Proof => Some(PrivateWorkspaceActionV1::ProveOriginalOnce),
        PrivateBoundaryV2::Freeze => Some(PrivateWorkspaceActionV1::FreezeVerifiedFixed),
        PrivateBoundaryV2::Read => Some(PrivateWorkspaceActionV1::ReadVerifiedFixed),
        _ => None,
    };
    if let Some(action) = action {
        crate::host::durable_private_workspace_v1::storage_action_boundary(action);
    }
    if let Some((operation, _)) = boundary.diagnostic_v1() {
        private_diagnostic_operation_v1(operation);
    }
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    {
        PRIVATE_CURRENT_BOUNDARY_V2.with(|stage| stage.set(boundary));
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "\n[JOINED_DIAGNOSTIC {} Begin]",
            boundary.label()
        );
    }
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = boundary;
}
fn complete_private_stage(boundary: PrivateBoundaryV2) {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "\n[JOINED_DIAGNOSTIC {} Complete]",
            boundary.label()
        );
    }
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = boundary;
}
fn engine_category(error: &wholepact_engine::ApiError) -> &'static str {
    // Exact finite source category preserved by the closed original proof
    // facade before the normal Engine-to-Host wrapper loses JobError.
    if let Some(category) = error
        .details
        .get("private_original_job_error_v1")
        .and_then(|value| value.as_str())
    {
        let outcome = match category {
            "consent_denied" => Some("JobConsentDenied"),
            "not_found" => Some("JobNotFound"),
            "invalid_request" => Some("JobInvalidRequest"),
            "verification_failed" => Some("JobVerificationFailed"),
            "idempotency_conflict" => Some("JobIdempotencyConflict"),
            "recovery_required" => Some("JobRecoveryRequired"),
            "state_conflict" => Some("JobStateConflict"),
            "storage" => Some("JobStorage"),
            "unsupported_schema" => Some("JobUnsupportedSchema"),
            "resource_exhausted" => Some("JobResourceExhausted"),
            _ => None,
        };
        if let Some(outcome) = outcome {
            return outcome;
        }
    }
    match error.code.as_str() {
        "DISCLOSURE_DENIED" => "EngineDisclosureDenied",
        "DURABLE_CONSTRUCTION_UNAVAILABLE" => "EngineDurableConstructionUnavailable",
        "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => "EngineDurableProposalRecoveryRequired",
        "MISSING_EVIDENCE" => "EngineMissingEvidence",
        "INVALID_TERMS" => "EngineInvalidTerms",
        "UNSUPPORTED_CAPABILITY" => "EngineUnsupportedCapability",
        "DEBIT_CAP_EXCEEDED" => "EngineDebitCapExceeded",
        "PERMISSION_DENIED" => "EnginePermissionDenied",
        "INTERNAL_ERROR" => "EngineInternalError",
        "MANUAL_CONSTRUCTION_DENIED" => "EngineManualConstructionDenied",
        "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => "EngineRetainedObservationUnavailable",
        "CANDIDATE_VERIFICATION_FAILED" => "EngineCandidateVerificationFailed",
        "IDEMPOTENCY_CONFLICT" => "EngineIdempotencyConflict",
        "REVISION_CONFLICT" => "EngineRevisionConflict",
        "NOT_FOUND" => "EngineNotFound",
        "INVALID_REQUEST" => "EngineInvalidRequest",
        "RECOVERY_REQUIRED" => "EngineRecoveryRequired",
        "LIVE_AUTHORIZATION_EXISTS" => "EngineLiveAuthorizationExists",
        "RESOURCE_EXHAUSTED" => "EngineResourceExhausted",
        "INVALID_TRANSITION" => "EngineInvalidTransition",
        "STORAGE_PROTECTION_REQUIRED" => "EngineStorageProtectionRequired",
        "STORAGE_UNAVAILABLE" => "EngineStorageUnavailable",
        "ACCESS_DENIED" => "EngineAccessDenied",
        _ => "EngineUnclassified",
    }
}
fn observe_engine(boundary: PrivateBoundaryV2, error: wholepact_engine::ApiError) -> Error {
    if let Some((operation, site)) = boundary.diagnostic_v1() {
        observe_private_fixed_engine_v1(operation, site, &error);
    }
    observe_failure(boundary, engine_category(&error));
    Error::from(error)
}
fn stage_review_cause_v3(
    error: &wholepact_engine::ApiError,
) -> Option<(PrivateDiagnosticEngineCodeV1, PrivateDiagnosticCauseV1)> {
    let code = match error.code.as_str() {
        "DURABLE_CONSTRUCTION_UNAVAILABLE" => {
            PrivateDiagnosticEngineCodeV1::DURABLE_CONSTRUCTION_UNAVAILABLE
        }
        "DISCLOSURE_DENIED"
            if error
                .details
                .get("private_original_job_error_v1")
                .and_then(serde_json::Value::as_str)
                == Some("consent_denied") =>
        {
            PrivateDiagnosticEngineCodeV1::DISCLOSURE_DENIED
        }
        _ => return None,
    };
    let detail = error
        .details
        .get("private_fixed_stage_cause_v3")?
        .as_object()?;
    if detail.len() != 2 || detail.get("family")?.as_str()? != "DurableConstruction" {
        return None;
    }
    let cause = match detail.get("cause")?.as_str()? {
        "Invalid" => PrivateDiagnosticCauseV1::Invalid,
        "Binding" => PrivateDiagnosticCauseV1::Binding,
        "Stale" => PrivateDiagnosticCauseV1::Stale,
        _ => return None,
    };
    Some((code, cause))
}
/// New metadata inspection only: finite cause, original call site, no claimed
/// execution snapshot. Ordinary effect diagnostics retain their old path.
fn observe_engine_stage_review_v3(
    boundary: PrivateBoundaryV2,
    error: wholepact_engine::ApiError,
) -> Error {
    if let Some((engine_code, cause)) = stage_review_cause_v3(&error) {
        let (operation, site) = boundary.diagnostic_v1().unwrap_or((
            PrivateDiagnosticOperationV1::Checkpoint,
            PrivateDiagnosticSiteV1::HostCheckpointEntry,
        ));
        record_private_primary_v1(
            PrivateDiagnosticPrimaryV1 {
                operation,
                site,
                engine_code,
                family: PrivateDiagnosticFamilyV1::DurableConstruction,
                cause,
            },
            None,
        );
        observe_failure(boundary, engine_category(&error));
        Error::from(error)
    } else {
        observe_engine(boundary, error)
    }
}
fn observe_engine_current(error: wholepact_engine::ApiError) -> Error {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    PRIVATE_CURRENT_BOUNDARY_V2.with(|stage| {
        let boundary = stage.get();
        if let Some((operation, site)) = boundary.diagnostic_v1() {
            observe_private_fixed_engine_v1(operation, site, &error);
        }
        observe_failure(boundary, engine_category(&error));
    });
    Error::from(error)
}
fn observe_engine_source(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Source, error)
}
fn observe_engine_candidate(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Candidate, error)
}
fn observe_engine_intake(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Intake, error)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateObservationCauseV1 {
    schema: u8,
    operation: PrivateDiagnosticOperationV1,
    site: PrivateDiagnosticSiteV1,
    engine_code: PrivateDiagnosticEngineCodeV1,
    family: PrivateDiagnosticFamilyV1,
    cause: PrivateDiagnosticCauseV1,
}
fn original_observation_cause_v1(
    error: &wholepact_engine::ApiError,
) -> Option<PrivateDiagnosticPrimaryV1> {
    let value = error.details.get("private_fixed_observation_cause_v1")?;
    let cause: PrivateObservationCauseV1 = serde_json::from_value(value.clone()).ok()?;
    let actual_code: PrivateDiagnosticEngineCodeV1 =
        serde_json::from_value(serde_json::Value::String(error.code.clone()))
            .unwrap_or(PrivateDiagnosticEngineCodeV1::Unclassified);
    if cause.schema != 1
        || cause.operation != PrivateDiagnosticOperationV1::Checkpoint
        || cause.engine_code == PrivateDiagnosticEngineCodeV1::NotApplicable
        || cause.engine_code != actual_code
        || cause.family == PrivateDiagnosticFamilyV1::Host
        || !matches!(
            cause.site,
            PrivateDiagnosticSiteV1::WorkspaceLoad
                | PrivateDiagnosticSiteV1::Candidate
                | PrivateDiagnosticSiteV1::MaterialRoster
                | PrivateDiagnosticSiteV1::GateWorkspace
                | PrivateDiagnosticSiteV1::GateMaterial
                | PrivateDiagnosticSiteV1::WalletRosterAcquire
                | PrivateDiagnosticSiteV1::PostConsent
                | PrivateDiagnosticSiteV1::OperationHistory
        )
    {
        return None;
    }
    let primary = PrivateDiagnosticPrimaryV1 {
        operation: cause.operation,
        site: cause.site,
        engine_code: cause.engine_code,
        family: cause.family,
        cause: cause.cause,
    };
    primary.valid().then_some(primary)
}
fn observe_engine_observation(error: wholepact_engine::ApiError) -> Error {
    if let Some(primary) = original_observation_cause_v1(&error) {
        // Same foreground invocation; never infer checkpoint CALL facts from
        // a scan result or overwrite a native/source failure already observed.
        record_private_primary_v1(primary, None);
        observe_failure(PrivateBoundaryV2::Observe, engine_category(&error));
        Error::from(error)
    } else {
        observe_engine(PrivateBoundaryV2::Observe, error)
    }
}
fn observe_engine_checkpoint(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Checkpoint, error)
}
fn observe_engine_proof(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Proof, error)
}
fn observe_engine_freeze(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Freeze, error)
}
fn observe_engine_read(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Read, error)
}
fn observe_bridge_capture(error: wholepact_signer::authority_bridge::BridgeError) -> Error {
    use wholepact_signer::authority_bridge::BridgeError as E;
    let outcome = match &error {
        E::Binding => "BridgeBinding",
        E::Conflict => "BridgeConflict",
        E::Missing => "BridgeMissing",
        E::Uncertain => "BridgeUncertain",
        E::Limit => "BridgeLimit",
        E::Permission => "BridgePermission",
        E::RecoveryRequired => "BridgeRecoveryRequired",
        E::CompleteOriginRecoveryUnavailable => "BridgeCompleteOriginRecoveryUnavailable",
        E::Verification => "BridgeVerification",
        E::SignerOriginUnavailable => "BridgeSignerOriginUnavailable",
        E::Journal(_) => "BridgeJournal",
        E::Authority(_) => "BridgeAuthority",
        E::Wallet(_) => "BridgeWallet",
        E::Ipc => "BridgeIpc",
    };
    observe_failure(PrivateBoundaryV2::Capture, outcome);
    Error::Permission
}
fn host_category(error: &Error) -> &'static str {
    match error {
        Error::Platform => "HostPlatform",
        Error::Terminal => "HostTerminal",
        Error::Permission => "HostPermission",
        Error::Locked => "HostLocked",
        Error::Invalid => "HostInvalid",
        Error::Authentication => "HostAuthentication",
        Error::Storage => "HostStorage",
        Error::Quarantined => "HostQuarantined",
        Error::Unsupported => "HostUnsupported",
        Error::Receipt(_) => "HostReceipt",
        Error::RecoverySemantic(_) => "HostRecoverySemantic",
        Error::RecoveryBackupUnsupported => "HostRecoveryBackupUnsupported",
        Error::RecoveryFinancialUnsupported => "HostRecoveryFinancialUnsupported",
        Error::CompleteOriginRecoveryUnavailable => "HostCompleteOriginRecoveryUnavailable",
        Error::HistoricalExportIncomplete => "HostHistoricalExportIncomplete",
        Error::GenerationArchiveIncomplete => "HostGenerationArchiveIncomplete",
    }
}
fn observed_host_permission(result: Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            observe_host_current(&error);
            false
        }
    }
}
fn observe_host_current(error: &Error) {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    PRIVATE_CURRENT_BOUNDARY_V2.with(|boundary| {
        let boundary = boundary.get();
        if let Some((operation, site)) = boundary.diagnostic_v1() {
            observe_private_fixed_host_v1(operation, site, error);
        }
        observe_failure(boundary, host_category(error));
    });
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = error;
}

fn run_original_source_steps_v1(
    mut before: impl FnMut(usize) -> Result<()>,
    mut write: impl FnMut(usize) -> Result<Mutation>,
    mut after: impl FnMut(usize, &Mutation) -> Result<()>,
) -> Result<bool> {
    let mut replayed = true;
    for index in 0..3 {
        before(index)?;
        let original = write(index)?;
        replayed &= original.replayed;
        after(index, &original)?;
    }
    Ok(replayed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn cached_only_missing_approval_never_reaches_review() {
        let calls = RefCell::new(Vec::new());
        let allowed = current_approval_permission_v2(
            CurrentApprovalModeV2::CachedOnly,
            None::<&()>,
            |_| {
                calls.borrow_mut().push("exact");
                true
            },
            |_| {
                calls.borrow_mut().push("native");
                true
            },
            || {
                calls.borrow_mut().push("current");
                true
            },
        )
        .unwrap_or_else(|| {
            calls.borrow_mut().push("review");
            true
        });
        assert!(!allowed);
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn cached_only_exact_hit_rechecks_every_original_predicate() {
        // Positive control for the shared selection kernel only. These inert
        // predicates cannot manufacture a native approval or workspace owner.
        let original = ("original-scope", "original-material");
        let calls = RefCell::new(Vec::new());
        for _ in 0..2 {
            let allowed = current_approval_permission_v2(
                CurrentApprovalModeV2::CachedOnly,
                Some(&original),
                |saved| {
                    calls.borrow_mut().push("exact");
                    saved == &original
                },
                |_| {
                    calls.borrow_mut().push("native");
                    true
                },
                || {
                    calls.borrow_mut().push("current");
                    true
                },
            )
            .unwrap_or_else(|| {
                calls.borrow_mut().push("review");
                false
            });
            assert!(allowed);
        }
        assert_eq!(
            *calls.borrow(),
            vec!["exact", "native", "current", "exact", "native", "current"]
        );
    }

    #[test]
    fn cached_only_scope_material_or_action_mismatch_never_reaches_review() {
        let saved = (
            "original-scope",
            "original-material",
            LocalAction::RetainPrivateWitnesses,
        );
        for requested in [
            (
                "different-scope",
                "original-material",
                LocalAction::RetainPrivateWitnesses,
            ),
            (
                "original-scope",
                "different-material",
                LocalAction::RetainPrivateWitnesses,
            ),
            (
                "original-scope",
                "original-material",
                LocalAction::InspectStatus,
            ),
        ] {
            let calls = RefCell::new(Vec::new());
            let allowed = current_approval_permission_v2(
                CurrentApprovalModeV2::CachedOnly,
                Some(&saved),
                |original| {
                    calls.borrow_mut().push("exact");
                    original == &requested
                },
                |_| {
                    calls.borrow_mut().push("native");
                    true
                },
                || {
                    calls.borrow_mut().push("current");
                    true
                },
            )
            .unwrap_or_else(|| {
                calls.borrow_mut().push("review");
                true
            });
            assert!(!allowed);
            assert_eq!(*calls.borrow(), vec!["exact"]);
        }
        // This is the actual proof-cache lookup shape. A retained exact artifact
        // does not silently authorize a newly appearing job's status inspection.
        let saved = [LocalAction::RetainPrivateWitnesses];
        assert_eq!(
            current_approval_permission_v2(
                CurrentApprovalModeV2::CachedOnly,
                saved
                    .iter()
                    .find(|action| **action == LocalAction::InspectStatus),
                |_| panic!("missing status approval must not be checked"),
                |_| panic!("missing status approval must not reach native consent"),
                || panic!("missing status approval must not fall through"),
            ),
            Some(false)
        );
    }

    #[test]
    fn cached_only_original_native_expiry_or_disconnect_denies_without_review() {
        for expired in [false, true] {
            let original = HistoricalApproval::denied_for_test(expired);
            let calls = RefCell::new(Vec::new());
            let first_error = RefCell::new(None);
            let allowed = current_approval_permission_v2(
                CurrentApprovalModeV2::CachedOnly,
                Some(&original),
                |_| {
                    calls.borrow_mut().push("exact");
                    true
                },
                |approval| {
                    calls.borrow_mut().push("native");
                    match approval.check() {
                        Ok(()) => true,
                        Err(error) => {
                            *first_error.borrow_mut() = Some(error);
                            false
                        }
                    }
                },
                || {
                    calls.borrow_mut().push("current");
                    true
                },
            )
            .unwrap_or_else(|| {
                calls.borrow_mut().push("review");
                true
            });
            assert!(!allowed);
            assert!(first_error.borrow().is_some());
            if expired {
                assert!(matches!(*first_error.borrow(), Some(Error::Permission)));
            }
            assert_eq!(*calls.borrow(), vec!["exact", "native"]);
        }
    }

    #[test]
    fn cached_only_current_material_failure_preserves_original_check_order() {
        // Inert predicates exercise the shared selection kernel, not a native
        // grant or positive workspace owner. The actual current failure remains
        // the first error and cannot be replaced by a fresh review attempt.
        let calls = RefCell::new(Vec::new());
        let first_error = RefCell::new(None);
        let allowed = current_approval_permission_v2(
            CurrentApprovalModeV2::CachedOnly,
            Some(&()),
            |_| {
                calls.borrow_mut().push("exact");
                true
            },
            |_| {
                calls.borrow_mut().push("native");
                true
            },
            || {
                calls.borrow_mut().push("current");
                *first_error.borrow_mut() = Some(Error::Authentication);
                false
            },
        )
        .unwrap_or_else(|| {
            calls.borrow_mut().push("review");
            *first_error.borrow_mut() = Some(Error::Terminal);
            true
        });
        assert!(!allowed);
        assert_eq!(*calls.borrow(), vec!["exact", "native", "current"]);
        assert!(matches!(*first_error.borrow(), Some(Error::Authentication)));
    }

    #[test]
    fn original_review_mode_never_renews_a_denied_cached_approval() {
        let reviews = Cell::new(0);
        for cached in [Some(&()), None] {
            let allowed = current_approval_permission_v2(
                CurrentApprovalModeV2::ReviewMissing,
                cached,
                |_| true,
                |_| false,
                || panic!("denied native approval must short-circuit current checks"),
            )
            .unwrap_or_else(|| {
                reviews.set(reviews.get() + 1);
                true
            });
            assert_eq!(allowed, cached.is_none());
            assert_eq!(reviews.get(), usize::from(cached.is_none()));
        }
    }

    fn source_component() -> (
        wholepact_engine::Engine,
        wholepact_engine::Access,
        PrivateSourceSelectionV1,
    ) {
        // This is only an actual in-memory metadata/replay component. It cannot
        // issue a ManualRoster target, native consent, material or proof token.
        let engine = wholepact_engine::Engine::in_memory().unwrap();
        let access = wholepact_engine::Access {
            principal_id: "component-source-owner".into(),
            include_owned_agreements: true,
            ..Default::default()
        };
        let mut agreement: AgreementDraft = serde_json::from_slice(include_bytes!(
            "../../../../wholepact-core/tests/fixtures/agreement.json"
        ))
        .unwrap();
        agreement.agreement_id = "component-source".into();
        agreement.organizer_identity = access.principal_id.clone();
        agreement.privacy_profile.mode = wholepact_core::PrivacyMode::DeclaredOperator;
        agreement.privacy_profile.proving_operator = Some(access.principal_id.clone());
        engine
            .create(&access, "component-original-create-key", agreement.clone())
            .unwrap();
        let claims = ["left", "right"]
            .into_iter()
            .map(|name| PrivateSourceSelectionClaimV1 {
                account_id: format!("component-{name}-account"),
                intent: ParticipationIntent {
                    intent_id: format!("component-{name}-intent"),
                    agreement_id: agreement.agreement_id.clone(),
                    participant_id: format!("component-{name}"),
                    desired_contribution: "500000000".parse().unwrap(),
                    maximum_net_debit: "500010000".parse().unwrap(),
                    fee_cap: "10000".parse().unwrap(),
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            })
            .collect();
        (engine, access, PrivateSourceSelectionV1 { claims })
    }
    fn write_step(
        engine: &wholepact_engine::Engine,
        access: &wholepact_engine::Access,
        selected: &PrivateSourceSelectionV1,
        keys: &[String; 3],
        index: usize,
    ) -> Result<Mutation> {
        if index < 2 {
            engine
                .add_intent(
                    access,
                    &keys[index],
                    "component-source",
                    index as u64 + 1,
                    selected.claims[index].intent.clone(),
                )
                .map_err(Error::from)
        } else {
            engine
                .select_roster(
                    access,
                    &keys[index],
                    "component-source",
                    3,
                    RosterSelectionRequest {
                        selected_intent_ids: selected
                            .claims
                            .iter()
                            .map(|c| c.intent.intent_id.clone())
                            .collect(),
                    },
                )
                .map_err(Error::from)
        }
    }
    #[test]
    fn source_selection_reacquires_target_after_each_real_metadata_write() {
        let (engine, access, selected) = source_component();
        let keys = source_step_keys("component-stable-source-selection").unwrap();
        let trace = RefCell::new(Vec::new());
        let pinned_revision = Cell::new(0);
        assert!(
            !run_original_source_steps_v1(
                |index| {
                    let view = engine.get(&access, "component-source")?;
                    validate_partial_selection(&view, 1, &selected)?;
                    pinned_revision.set(view.revision);
                    trace.borrow_mut().push((index, "before"));
                    Ok(())
                },
                |index| {
                    let result = write_step(&engine, &access, &selected, &keys, index)?;
                    assert_ne!(result.agreement.revision, pinned_revision.get());
                    trace.borrow_mut().push((index, "write"));
                    Ok(result)
                },
                |index, original| {
                    let fresh = engine.get(&access, "component-source")?;
                    assert_eq!(fresh.revision, original.agreement.revision);
                    validate_partial_selection(&fresh, 1, &selected)?;
                    trace.borrow_mut().push((index, "after"));
                    Ok(())
                },
            )
            .unwrap()
        );
        assert_eq!(
            *trace.borrow(),
            vec![
                (0, "before"),
                (0, "write"),
                (0, "after"),
                (1, "before"),
                (1, "write"),
                (1, "after"),
                (2, "before"),
                (2, "write"),
                (2, "after")
            ]
        );
    }
    #[test]
    fn source_selection_replay_preserves_exact_partial_requests() {
        let (engine, access, selected) = source_component();
        let keys = source_step_keys("component-stable-source-selection").unwrap();
        let first = write_step(&engine, &access, &selected, &keys, 0).unwrap();
        let saved = engine.operation(&access, &first.operation_id).unwrap();
        run_original_source_steps_v1(
            |_| {
                validate_partial_selection(&engine.get(&access, "component-source")?, 1, &selected)
                    .map(|_| ())
            },
            |index| write_step(&engine, &access, &selected, &keys, index),
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(
            engine.operation(&access, &first.operation_id).unwrap(),
            saved
        );
        let before =
            serde_json::to_value(engine.get(&access, "component-source").unwrap()).unwrap();
        assert!(
            run_original_source_steps_v1(
                |_| Ok(()),
                |index| write_step(&engine, &access, &selected, &keys, index),
                |_, _| Ok(())
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::to_value(engine.get(&access, "component-source").unwrap()).unwrap(),
            before
        );
        let mut conflicting = selected.clone();
        conflicting.claims[0].intent.maximum_net_debit = "500020000".parse().unwrap();
        assert!(write_step(&engine, &access, &conflicting, &keys, 0).is_err());
        assert_eq!(
            engine.operation(&access, &first.operation_id).unwrap(),
            saved
        );
        assert_eq!(
            serde_json::to_value(engine.get(&access, "component-source").unwrap()).unwrap(),
            before
        );
    }
    #[test]
    fn source_selection_rejects_operator_principal_mismatch_before_effect() {
        let (engine, access, _) = source_component();
        let original = engine.get(&access, "component-source").unwrap();
        let mut mismatch = original.agreement.clone();
        mismatch.privacy_profile.proving_operator = Some("another-operator".into());
        let writes = Cell::new(0);
        let result = run_original_source_steps_v1(
            |_| require_operator_principal(&mismatch, &access.principal_id),
            |_| {
                writes.set(writes.get() + 1);
                Err(Error::Invalid)
            },
            |_, _| Ok(()),
        );
        assert!(matches!(result, Err(Error::Permission)));
        assert_eq!(writes.get(), 0);
        assert_eq!(
            serde_json::to_value(engine.get(&access, "component-source").unwrap()).unwrap(),
            serde_json::to_value(original).unwrap()
        );
    }
    #[test]
    fn private_command_allowlist_has_no_generic_or_financial_fallback() {
        use clap::{CommandFactory, Parser};
        let grammar = crate::host::Args::command();
        let mut actual = grammar
            .get_subcommands()
            .map(|command| command.get_name())
            .filter(|name| name.starts_with("durable-private-"))
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(
            actual,
            vec![
                "durable-private-create-v1",
                "durable-private-fix-v1",
                "durable-private-initialize-v1",
                "durable-private-read-fixed-v1"
            ]
        );
        for command in &actual {
            assert!(
                crate::host::Args::try_parse_from([
                    "host",
                    command,
                    "--profile",
                    "/component-profile",
                    "--workspace",
                    "/component-workspace"
                ])
                .is_ok()
            );
        }
        // Source selection belongs only to the ordinary original Host shell;
        // the dedicated workspace executable has no shell/financial fallback.
        for command in [
            "durable-private-source-select-v1",
            "durable-private-fix-v2",
            "shell-v3",
            "durable-private-admission-v1",
            "durable-private-sign-v1",
            "durable-private-retry-v1",
        ] {
            assert!(crate::host::Args::try_parse_from(["host", command]).is_err());
        }
    }
    #[test]
    fn source_sequence_stops_on_original_error_before_next_owner() {
        let (engine, access, selected) = source_component();
        let keys = source_step_keys("component-stable-source-selection").unwrap();
        let calls = RefCell::new(Vec::new());
        let result = run_original_source_steps_v1(
            |index| {
                calls.borrow_mut().push((index, "before"));
                Ok(())
            },
            |index| {
                calls.borrow_mut().push((index, "write"));
                write_step(&engine, &access, &selected, &keys, index)
            },
            |index, _| {
                calls.borrow_mut().push((index, "after"));
                Err(Error::Authentication)
            },
        );
        assert!(matches!(result, Err(Error::Authentication)));
        assert_eq!(
            *calls.borrow(),
            vec![(0, "before"), (0, "write"), (0, "after")]
        );
        assert_eq!(engine.get(&access, "component-source").unwrap().revision, 2);
    }
    #[test]
    fn proof_broker_denial_deadline_and_disconnect_cannot_return_cached_permission() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let broker = ForegroundProofBrokerV2 {
            sender,
            original_deadline: std::time::Instant::now(),
            cancelled,
        };
        let constructed = Cell::new(false);
        assert!(!broker.ask(|_| {
            constructed.set(true);
            panic!("expired owner must not create request")
        }));
        assert!(!constructed.get());
        assert!(receiver.try_recv().is_err());
        let (sender, receiver) = std::sync::mpsc::channel();
        drop(receiver);
        let broker = ForegroundProofBrokerV2 {
            sender,
            original_deadline: std::time::Instant::now() + Duration::from_secs(1),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        assert!(!broker.ask(|_| ForegroundProofRequestV2::Finished(Err(
            wholepact_engine::ApiError::new("INVALID_REQUEST", "private fixture canary")
        ))));
    }
    #[test]
    fn typed_error_categories_never_format_private_source_details() {
        assert_eq!(
            engine_category(&wholepact_engine::ApiError::new(
                "IDEMPOTENCY_CONFLICT",
                "SECRET canary"
            )),
            "EngineIdempotencyConflict"
        );
        assert_eq!(
            engine_category(&wholepact_engine::ApiError::new(
                "unknown-private-code",
                "SECRET canary"
            )),
            "EngineUnclassified"
        );
        let mut original = wholepact_engine::ApiError::new("ACCESS_DENIED", "SECRET canary");
        original.details =
            Box::new(serde_json::json!({"private_original_job_error_v1":"consent_denied"}));
        assert_eq!(engine_category(&original), "JobConsentDenied");
        original.details =
            Box::new(serde_json::json!({"private_original_job_error_v1":"SECRET canary"}));
        assert_eq!(engine_category(&original), "EngineAccessDenied");
        assert_eq!(host_category(&Error::Authentication), "HostAuthentication");
        assert_eq!(host_category(&Error::Permission), "HostPermission");
        assert!(material_action_tag(DurableMaterialActionV1::ExportForLocalNativeReview).is_none());
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    mod private_diagnostics {
        use super::*;
        use PrivateDiagnosticCallStateV1 as C;
        use PrivateDiagnosticOperationV1 as O;
        use PrivateDiagnosticSiteV1 as S;
        fn core(operation: O) -> PrivateDiagnosticEngineCoreV1 {
            let mut calls = PrivateDiagnosticCallsV1 {
                receipt: C::NotApplicable,
                enqueue: C::NotApplicable,
                link: C::NotApplicable,
                proof: C::NotApplicable,
                outcome: C::NotApplicable,
                freeze: C::NotApplicable,
            };
            match operation {
                O::Checkpoint => {
                    calls.receipt = C::ReturnedOkFresh;
                    calls.enqueue = C::ReturnedErrUnknown;
                    calls.link = C::NotCalled;
                }
                O::Proof => {
                    calls.proof = C::ReturnedErrUnknown;
                    calls.outcome = C::NotCalled;
                }
                O::Freeze => calls.freeze = C::ReturnedErrUnknown,
                O::ReadFixed | O::OpenOriginal => {}
            }
            PrivateDiagnosticEngineCoreV1 {
                schema: 1,
                operation,
                site: S::PostConsent,
                engine_code: PrivateDiagnosticEngineCodeV1::DISCLOSURE_DENIED,
                family: PrivateDiagnosticFamilyV1::Sync,
                cause: PrivateDiagnosticCauseV1::NoCurrentObservation,
                calls,
                attempt_consumed: operation == O::Proof,
                call_scope: PrivateDiagnosticCallScopeV1::CurrentInvocation,
            }
        }
        fn error(core: &PrivateDiagnosticEngineCoreV1) -> wholepact_engine::ApiError {
            let mut error =
                wholepact_engine::ApiError::new("DISCLOSURE_DENIED", "private-error-canary");
            error.details = Box::new(serde_json::json!({"private_fixed_diagnostic_v1":core}));
            error
        }
        fn wire(core: &PrivateDiagnosticEngineCoreV1) -> PrivateFixedDiagnosticV1 {
            PrivateFixedDiagnosticV1 {
                schema: 1,
                primary: core.primary(),
                evidence: Some(core.evidence()),
                worker: None,
                stage: None,
            }
        }
        #[test]
        fn private_fixed_diagnostic_required_fields_and_finite_pairs() {
            let value = wire(&core(O::Checkpoint));
            let json = value.canonical_json().unwrap();
            assert_eq!(PrivateFixedDiagnosticV1::parse(&json), Some(value));
            for field in ["schema", "primary", "evidence", "worker", "stage"] {
                let mut missing: serde_json::Value = serde_json::from_str(&json).unwrap();
                missing.as_object_mut().unwrap().remove(field);
                assert!(
                    PrivateFixedDiagnosticV1::parse(&missing.to_string()).is_none(),
                    "{field}"
                );
            }
            for object in ["primary", "evidence"] {
                let original: serde_json::Value = serde_json::from_str(&json).unwrap();
                for field in original[object].as_object().unwrap().keys() {
                    let mut missing = original.clone();
                    missing[object].as_object_mut().unwrap().remove(field);
                    assert!(PrivateFixedDiagnosticV1::parse(&missing.to_string()).is_none());
                }
            }
            let duplicate = json.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
            assert!(PrivateFixedDiagnosticV1::parse(&duplicate).is_none());
            let nested = json.replacen("\"receipt\":", "\"receipt\":\"NotCalled\",\"receipt\":", 1);
            assert!(PrivateFixedDiagnosticV1::parse(&nested).is_none());
            let mut invalid = wire(&core(O::Checkpoint));
            invalid.primary.family = PrivateDiagnosticFamilyV1::Host;
            assert!(invalid.canonical_json().is_none());
            invalid = wire(&core(O::Checkpoint));
            invalid.primary.family = PrivateDiagnosticFamilyV1::Engine;
            invalid.primary.cause = PrivateDiagnosticCauseV1::DISCLOSURE_DENIED;
            invalid.primary.engine_code = PrivateDiagnosticEngineCodeV1::NotApplicable;
            assert!(invalid.canonical_json().is_none());
        }
        #[test]
        fn private_fixed_diagnostic_unknown_and_private_canaries_are_omitted() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let original =
                wholepact_engine::ApiError::new("SECRET/path/pczt/fvk", "SECRET/path/pczt/fvk");
            observe_private_fixed_engine_v1(O::Checkpoint, S::Candidate, &original);
            let value = private_fixed_diagnostic_snapshot_v1()
                .unwrap()
                .canonical_json()
                .unwrap();
            assert!(!value.contains("SECRET"));
            assert!(value.contains("Unclassified"));
            assert_eq!(original.code, "SECRET/path/pczt/fvk");
            assert_eq!(original.message, "SECRET/path/pczt/fvk");
            assert!(
                PrivateFixedDiagnosticV1::parse(&value.replacen(
                    "Unclassified",
                    "SECRET/path/pczt/fvk",
                    1
                ))
                .is_none()
            );
        }
        #[test]
        fn private_fixed_diagnostic_first_observed_survives_cleanup() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _call = begin_private_diagnostic_invocation_v1(O::Checkpoint);
            observe_private_fixed_host_v1(
                O::Checkpoint,
                S::HostMaterialApproval,
                &Error::Permission,
            );
            observe_private_fixed_engine_v1(
                O::Checkpoint,
                S::Candidate,
                &error(&core(O::Checkpoint)),
            );
            observe_private_fixed_host_v1(
                O::Checkpoint,
                S::HostCheckpointPostcheck,
                &Error::Storage,
            );
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert_eq!(first.primary.site, S::HostMaterialApproval);
            assert_eq!(first.primary.cause, PrivateDiagnosticCauseV1::Permission);
            assert_eq!(first.evidence.unwrap().calls.receipt, C::ReturnedOkFresh);
        }
        #[test]
        fn private_fixed_diagnostic_same_operation_replacement_cannot_fill_evidence() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            {
                let _call = begin_private_diagnostic_invocation_v1(O::Checkpoint);
                observe_private_fixed_host_v1(
                    O::Checkpoint,
                    S::HostMaterialApproval,
                    &Error::Permission,
                );
            }
            {
                let _replacement = begin_private_diagnostic_invocation_v1(O::Checkpoint);
                observe_private_fixed_engine_v1(
                    O::Checkpoint,
                    S::Candidate,
                    &error(&core(O::Checkpoint)),
                );
            }
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert!(first.evidence.is_none());
            assert_eq!(first.primary.site, S::HostMaterialApproval);
        }
        #[test]
        fn private_fixed_diagnostic_broker_priority_preserves_received_engine_error() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _call = begin_private_diagnostic_invocation_v1(O::Proof);
            private_worker_start_v1();
            let original = Error::Terminal;
            observe_private_fixed_host_v1(O::Proof, S::HostProofForegroundMessage, &original);
            let received: std::result::Result<(), wholepact_engine::ApiError> =
                Err(error(&core(O::Proof)));
            private_worker_received_v1(&received);
            observe_private_fixed_engine_v1(O::Proof, S::ProofRun, received.as_ref().unwrap_err());
            private_worker_joined_v1(true);
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert_eq!(first.primary.cause, PrivateDiagnosticCauseV1::Terminal);
            assert!(first.worker.unwrap().engine_failure.is_some());
            assert!(received.is_err());
            let chosen: Result<()> = select_original_proof_result_v1(
                Some(original),
                Err(Error::Permission),
                Err(Box::new(())),
            );
            assert!(matches!(chosen, Err(Error::Terminal)));
            let chosen: Result<()> = select_original_proof_result_v1(
                None,
                Err(Error::Authentication),
                Err(Box::new(())),
            );
            assert!(matches!(chosen, Err(Error::Authentication)));
        }
        #[test]
        fn private_fixed_diagnostic_disconnect_and_panic_do_not_invent_engine_error() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _call = begin_private_diagnostic_invocation_v1(O::Proof);
            private_worker_start_v1();
            observe_private_fixed_host_v1(
                O::Proof,
                S::HostProofForegroundMessage,
                &Error::Terminal,
            );
            private_worker_disconnected_v1();
            private_worker_joined_v1(false);
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert!(first.evidence.is_none());
            let worker = first.worker.unwrap();
            assert_eq!(worker.result, PrivateDiagnosticWorkerResultV1::Disconnected);
            assert_eq!(worker.join, PrivateDiagnosticWorkerJoinV1::Panicked);
            assert!(worker.engine_failure.is_none());
        }
        #[test]
        fn private_fixed_diagnostic_same_result_once_without_clone() {
            struct Owned(std::rc::Rc<Cell<usize>>);
            impl Drop for Owned {
                fn drop(&mut self) {
                    self.0.set(self.0.get() + 1);
                }
            }
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _call = begin_private_diagnostic_invocation_v1(O::Proof);
            let dropped = std::rc::Rc::new(Cell::new(0));
            let calls = Cell::new(0);
            let original = private_host_result_at_v1(S::HostProofAccess, {
                calls.set(calls.get() + 1);
                Ok(Owned(dropped.clone()))
            })
            .unwrap();
            assert_eq!(calls.get(), 1);
            assert_eq!(dropped.get(), 0);
            drop(original);
            assert_eq!(dropped.get(), 1);
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
        }
        #[test]
        fn private_fixed_diagnostic_call_relevance_and_nullable_evidence() {
            for op in [
                O::Checkpoint,
                O::Proof,
                O::Freeze,
                O::ReadFixed,
                O::OpenOriginal,
            ] {
                assert!(wire(&core(op)).canonical_json().is_some());
            }
            let mut value = wire(&core(O::Checkpoint));
            value.evidence.as_mut().unwrap().calls.receipt = C::ReturnedOk;
            assert!(value.canonical_json().is_none());
            let mut value = wire(&core(O::Proof));
            value.evidence.as_mut().unwrap().attempt_consumed = false;
            assert!(value.canonical_json().is_none());
            let mut value = wire(&core(O::Proof));
            value.worker = Some(PrivateDiagnosticWorkerV1 {
                result: PrivateDiagnosticWorkerResultV1::ReceivedOk,
                join: PrivateDiagnosticWorkerJoinV1::Joined,
                engine_failure: None,
            });
            assert!(value.canonical_json().is_none());
            value.evidence = None;
            assert!(value.canonical_json().is_some());
            let raw = value.canonical_json().unwrap();
            assert!(
                PrivateFixedDiagnosticV1::parse(&raw.replace(",\"engine_failure\":null", ""))
                    .is_none()
            );
        }
        #[test]
        fn private_fixed_diagnostic_maximal_canonical_wrapper_is_bounded() {
            let mut original = core(O::Proof);
            original.site = S::SnapshotSourceUnchanged;
            original.engine_code =
                PrivateDiagnosticEngineCodeV1::RETAINED_INPUT_OBSERVATION_UNAVAILABLE;
            original.family = PrivateDiagnosticFamilyV1::Engine;
            original.cause = PrivateDiagnosticCauseV1::RETAINED_INPUT_OBSERVATION_UNAVAILABLE;
            original.calls.proof = C::ReturnedErrUnknown;
            original.calls.outcome = C::ReturnedErrUnknown;
            let mut value = wire(&original);
            value.primary.site = S::ReaderOriginalFinancialProofSchema;
            value.worker = Some(PrivateDiagnosticWorkerV1 {
                result: PrivateDiagnosticWorkerResultV1::ReceivedErr,
                join: PrivateDiagnosticWorkerJoinV1::Panicked,
                engine_failure: Some(original),
            });
            let actual = serde_json::to_string(&value).unwrap();
            assert!(actual.len() <= PRIVATE_FIXED_DIAGNOSTIC_MAX_BYTES_V1);
            assert_eq!(PrivateFixedDiagnosticV1::parse(&actual), Some(value));
        }
        #[test]
        fn private_fixed_diagnostic_scope_contention_and_drop_are_unavailable() {
            let scope = begin_private_fixed_diagnostic_scope_v1();
            PRIVATE_DIAGNOSTIC_LATCH_V1.with(|slot| {
                let _held = slot.borrow_mut();
                observe_private_fixed_host_v1(O::ReadFixed, S::HostReadReturn, &Error::Permission);
            });
            observe_private_fixed_host_v1(O::ReadFixed, S::HostReadReturn, &Error::Storage);
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
            PRIVATE_DIAGNOSTIC_LATCH_V1.with(|slot| {
                let _held = slot.borrow_mut();
                drop(scope);
            });
            observe_private_fixed_host_v1(O::ReadFixed, S::HostReadReturn, &Error::Storage);
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
            let _fresh = begin_private_fixed_diagnostic_scope_v1();
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
            observe_private_fixed_host_v1(O::ReadFixed, S::ReaderCompletionWrite, &Error::Storage);
            assert_eq!(
                private_fixed_diagnostic_snapshot_v1().unwrap().primary.site,
                S::ReaderCompletionWrite
            );
        }
        #[test]
        fn private_fixed_diagnostic_invocation_overflow_is_unavailable() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let prior = PRIVATE_DIAGNOSTIC_SEQUENCE_V1.with(|sequence| sequence.replace(u64::MAX));
            let _call = begin_private_diagnostic_invocation_v1(O::Checkpoint);
            observe_private_fixed_host_v1(
                O::Checkpoint,
                S::HostCheckpointEntry,
                &Error::Permission,
            );
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
            PRIVATE_DIAGNOSTIC_SEQUENCE_V1.with(|sequence| sequence.set(prior));
        }
        #[test]
        fn private_fixed_diagnostic_invalid_boundary_pairs_are_never_retained() {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            for (boundary, outcome) in [
                ("SECRET/path", "HostPermission"),
                ("PrivateWorkspaceProof", "SECRET/pczt"),
                ("PrivateWorkspaceRootCleanup", "BridgeBinding"),
                ("PrivateWorkspaceProof", "Begin"),
            ] {
                observe_private_fixed_boundary_v1(boundary, outcome);
                assert!(first_private_fixed_boundary_v1().is_none());
            }
            observe_private_fixed_boundary_v1("PrivateWorkspaceProof", "HostPermission");
            observe_private_fixed_boundary_v1("PrivateWorkspaceRootCleanup", "HostStorage");
            assert_eq!(
                first_private_fixed_boundary_v1(),
                Some(("PrivateWorkspaceProof", "HostPermission"))
            );
        }
    }
}

#[cfg(test)]
mod closed_stage_lifecycle_v3_tests {
    use super::*;
    #[test]
    fn completed_prepare_owner_drops_before_next_review_and_refusal_is_single_call() {
        let trace = std::cell::RefCell::new(Vec::new());
        struct Completed<'a>(&'a std::cell::RefCell<Vec<&'static str>>);
        impl Drop for Completed<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("prepare-dropped");
            }
        }
        let result: Result<()> = after_completed_stage_v3(Completed(&trace), || {
            trace.borrow_mut().push("admission-inspection-review");
            Err(Error::Permission)
        });
        assert!(matches!(result, Err(Error::Permission)));
        assert_eq!(
            *trace.borrow(),
            ["prepare-dropped", "admission-inspection-review"]
        );
    }
    #[test]
    fn actual_scan_binding_match_requires_each_owner_provider_and_scope_field() {
        let binding = StageScanBindingV3 {
            account_id: "account-a".into(),
            account_uuid: "original-uuid".into(),
            scope_digest: "scope-commitment".into(),
            backend: BackendIdentity {
                source_id: "original-source".into(),
                endpoint: "https://example.invalid".into(),
                trust_profile: "original-provider",
            },
            directory_identity: "original-directory".into(),
            database_origin: "original-database".into(),
            destination: PathBuf::from("/inert/original/wallet.sqlite"),
        };
        let owners = [binding.clone()];
        assert!(stage_scan_binding_matches_v3(&owners, &binding));
        assert!(!stage_scan_binding_matches_v3(&[], &binding));
        assert!(!stage_scan_binding_matches_v3(
            &[binding.clone(), binding.clone()],
            &binding
        ));
        for change in [
            |b: &mut StageScanBindingV3| b.account_id.push('x'),
            |b: &mut StageScanBindingV3| b.account_uuid.push('x'),
            |b: &mut StageScanBindingV3| b.scope_digest.push('x'),
            |b: &mut StageScanBindingV3| b.backend.source_id.push('x'),
            |b: &mut StageScanBindingV3| b.backend.endpoint.push('x'),
            |b: &mut StageScanBindingV3| b.backend.trust_profile = "substitute",
            |b: &mut StageScanBindingV3| b.directory_identity.push('x'),
            |b: &mut StageScanBindingV3| b.database_origin.push('x'),
            |b: &mut StageScanBindingV3| b.destination.push("substitute"),
        ] {
            let mut changed = binding.clone();
            change(&mut changed);
            assert!(!stage_scan_binding_matches_v3(&owners, &changed));
        }
    }
}

#[cfg(test)]
mod stage_review_error_v3_tests {
    use super::*;
    fn error(cause: &str) -> wholepact_engine::ApiError {
        let mut error =
            wholepact_engine::ApiError::new("DURABLE_CONSTRUCTION_UNAVAILABLE", "private canary");
        error.details["private_fixed_stage_cause_v3"] =
            serde_json::json!({"family":"DurableConstruction","cause":cause});
        error
    }
    #[test]
    fn stage_review_cause_accepts_only_exact_existing_finite_shape() {
        for (cause, expected) in [
            ("Invalid", PrivateDiagnosticCauseV1::Invalid),
            ("Binding", PrivateDiagnosticCauseV1::Binding),
            ("Stale", PrivateDiagnosticCauseV1::Stale),
        ] {
            assert_eq!(
                stage_review_cause_v3(&error(cause)),
                Some((
                    PrivateDiagnosticEngineCodeV1::DURABLE_CONSTRUCTION_UNAVAILABLE,
                    expected
                ))
            );
        }
        for cause in ["PRIVATE/path", "Permission", "Storage", "Unclassified"] {
            assert!(stage_review_cause_v3(&error(cause)).is_none());
        }
        let mut unknown = error("Stale");
        unknown.details["private_fixed_stage_cause_v3"]["extra"] = serde_json::json!(true);
        assert!(stage_review_cause_v3(&unknown).is_none());
        let mut wrong = error("Stale");
        wrong.details["private_fixed_stage_cause_v3"]["family"] = serde_json::json!("Host");
        assert!(stage_review_cause_v3(&wrong).is_none());
        wrong = error("Stale");
        wrong.code = "INVALID_REQUEST".into();
        assert!(stage_review_cause_v3(&wrong).is_none());
        let mut job = error("Stale");
        job.code = "DISCLOSURE_DENIED".into();
        assert!(stage_review_cause_v3(&job).is_none());
        job.details["private_original_job_error_v1"] = serde_json::json!("verification_failed");
        assert!(stage_review_cause_v3(&job).is_none());
        job.details["private_original_job_error_v1"] = serde_json::json!("consent_denied");
        assert_eq!(
            stage_review_cause_v3(&job),
            Some((
                PrivateDiagnosticEngineCodeV1::DISCLOSURE_DENIED,
                PrivateDiagnosticCauseV1::Stale
            ))
        );
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn stage_review_error_preserves_first_cause_without_execution_evidence() {
        let _scope = begin_private_fixed_diagnostic_scope_v1();
        let _invocation =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Proof);
        let mut original = error("Stale");
        original.code = "DISCLOSURE_DENIED".into();
        original.details["private_original_job_error_v1"] = serde_json::json!("consent_denied");
        let _ = observe_engine_stage_review_v3(PrivateBoundaryV2::Proof, original);
        let first = private_fixed_diagnostic_snapshot_v1().unwrap();
        assert_eq!(first.primary.operation, PrivateDiagnosticOperationV1::Proof);
        assert_eq!(
            first.primary.site,
            PrivateDiagnosticSiteV1::HostProofPrecheck
        );
        assert_eq!(
            first.primary.family,
            PrivateDiagnosticFamilyV1::DurableConstruction
        );
        assert_eq!(first.primary.cause, PrivateDiagnosticCauseV1::Stale);
        assert_eq!(
            first.primary.engine_code,
            PrivateDiagnosticEngineCodeV1::DISCLOSURE_DENIED
        );
        assert!(first.evidence.is_none());
        assert!(first.worker.is_none());
        let _ = observe_engine_stage_review_v3(PrivateBoundaryV2::Read, error("Binding"));
        assert_eq!(private_fixed_diagnostic_snapshot_v1(), Some(first));
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod stage_cost_observation_tests {
    use super::*;
    use wholepact_engine::PrivateFixedStageV3 as S;
    fn stage(kind: S) -> PrivateStageObservationV1 {
        // Inert measurement correlation only, never a native approval.
        begin_private_stage_cost_v1(kind, std::time::Instant::now() + Duration::from_secs(120))
    }
    #[test]
    fn same_owned_callback_result_and_first_failure_complete_once() {
        let _scope = begin_private_fixed_diagnostic_scope_v1();
        let _invocation =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
        let observation = stage(S::Prepare);
        struct Owned(std::rc::Rc<std::cell::Cell<u32>>);
        impl Drop for Owned {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
        let value = observation.callback(|| Ok(Owned(dropped.clone()))).unwrap();
        assert_eq!(dropped.get(), 0);
        drop(value);
        assert_eq!(dropped.get(), 1);
        let mut calls = 0;
        let result: Result<()> = observation.callback(|| {
            calls += 1;
            observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                Err(Error::Permission),
            )
        });
        assert!(matches!(result, Err(Error::Permission)));
        assert_eq!(calls, 1);
        let first = private_fixed_diagnostic_snapshot_v1().unwrap();
        assert_eq!(
            first.primary.site,
            PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck
        );
        let cost = first.stage.as_ref().unwrap();
        assert_eq!(cost.callback_count, 2);
        assert!(cost.callback_max_us <= cost.callback_total_us);
        let _: Result<()> = observation.callback(|| {
            observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
                Err(Error::Authentication),
            )
        });
        assert_eq!(private_fixed_diagnostic_snapshot_v1().unwrap(), first);
    }
    #[test]
    fn actual_negative_native_check_and_distinct_session_source_results() {
        for (site, error) in [
            (
                PrivateDiagnosticSiteV1::HostWorkspaceSessionCheck,
                Error::Permission,
            ),
            (
                PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
                Error::Authentication,
            ),
        ] {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let observation = stage(S::Prepare);
            let result: Result<()> = observation.observe(site, Err(error));
            assert!(result.is_err());
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert_eq!(first.primary.site, site);
            assert_eq!(first.stage.unwrap().callback_count, 0);
        }
        for expired in [true, false] {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let observation = stage(S::Prepare);
            let denied = HistoricalApproval::denied_for_test(expired);
            let result = observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                denied.check(),
            );
            if expired {
                assert!(matches!(result, Err(Error::Permission)));
            } else {
                assert!(matches!(result, Err(Error::Terminal)));
            }
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert_eq!(
                first.primary.cause,
                if expired {
                    PrivateDiagnosticCauseV1::Permission
                } else {
                    PrivateDiagnosticCauseV1::Terminal
                }
            );
        }
    }
    #[test]
    fn replaced_stage_and_replaced_invocation_cannot_supply_evidence() {
        let _scope = begin_private_fixed_diagnostic_scope_v1();
        let invocation =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
        let old = stage(S::Prepare);
        let current = stage(S::AdmitOriginal);
        let _: Result<()> = old.observe(
            PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
            Err(Error::Permission),
        );
        assert!(private_fixed_diagnostic_snapshot_v1().is_none());
        drop(old);
        let _: Result<()> = current.observe(
            PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
            Err(Error::Authentication),
        );
        let first = private_fixed_diagnostic_snapshot_v1().unwrap();
        assert_eq!(
            first.stage.as_ref().unwrap().kind,
            PrivateStageKindV1::AdmitOriginal
        );
        drop(invocation);
        let _replacement =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
        let _: Result<()> = current.callback(|| {
            current.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                Err(Error::Permission),
            )
        });
        assert_eq!(private_fixed_diagnostic_snapshot_v1().unwrap(), first);
    }
    #[test]
    fn proof_stage_spans_existing_worker_observations_but_not_following_freeze() {
        let _scope = begin_private_fixed_diagnostic_scope_v1();
        let proof = begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Proof);
        let observation = stage(S::ProveOriginal);
        let token = observation.token;
        // The actual broker observation helpers share the already installed
        // outer Proof invocation; they do not create a replacement scope.
        observation.callback(|| Ok(())).unwrap();
        private_worker_start_v1();
        let result: std::result::Result<(), wholepact_engine::ApiError> = Ok(());
        private_worker_received_v1(&result);
        private_worker_joined_v1(true);
        assert_eq!(observation.token, token);
        assert!(with_private_diagnostic_v1(|state| observation.matches(state)).unwrap());
        let _: Result<()> = observation.callback(|| {
            observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                Err(Error::Permission),
            )
        });
        let first = private_fixed_diagnostic_snapshot_v1().unwrap();
        assert_eq!(first.primary.operation, PrivateDiagnosticOperationV1::Proof);
        assert_eq!(
            first.stage.as_ref().unwrap().kind,
            PrivateStageKindV1::ProveOriginal
        );
        assert_eq!(first.stage.as_ref().unwrap().callback_count, 2);
        drop(proof);
        let _freeze = begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Freeze);
        let next = stage(S::FreezeFixed);
        assert!(!with_private_diagnostic_v1(|state| observation.matches(state)).unwrap());
        let _: Result<()> = next.callback(|| {
            next.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
                Err(Error::Authentication),
            )
        });
        assert_eq!(private_fixed_diagnostic_snapshot_v1().unwrap(), first);
    }
    #[test]
    fn unavailable_counts_are_null_and_contention_preserves_result() {
        {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let observation = stage(S::Prepare);
            with_private_diagnostic_v1(|state| {
                state.stage.as_mut().unwrap().cost.callback_count = PRIVATE_STAGE_MAX_COUNT_V1
            });
            let _: Result<()> = observation.callback(|| {
                observation.observe(
                    PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                    Err(Error::Permission),
                )
            });
            assert!(
                private_fixed_diagnostic_snapshot_v1()
                    .unwrap()
                    .stage
                    .is_none()
            );
        }
        {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let observation = stage(S::Prepare);
            PRIVATE_DIAGNOSTIC_LATCH_V1.with(|cell| {
                let _held = cell.borrow_mut();
                let result: Result<()> = observation.callback(|| Err(Error::Authentication));
                assert!(matches!(result, Err(Error::Authentication)));
            });
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
        }
    }
    #[test]
    fn panicked_callback_and_failed_stage_allocation_never_reuse_partial_cost() {
        {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let observation = stage(S::Prepare);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observation.callback(|| -> Result<()> {
                    let _: Result<()> = observation.observe(
                        PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                        Err(Error::Permission),
                    );
                    panic!("inert diagnostic callback panic");
                })
            }));
            assert!(panic.is_err());
            assert!(
                private_fixed_diagnostic_snapshot_v1()
                    .unwrap()
                    .stage
                    .is_none()
            );
        }
        {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let _invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let old = stage(S::Prepare);
            let previous = PRIVATE_DIAGNOSTIC_SEQUENCE_V1.with(|value| value.replace(u64::MAX));
            let unavailable = stage(S::AdmitOriginal);
            PRIVATE_DIAGNOSTIC_SEQUENCE_V1.with(|value| value.set(previous));
            assert!(unavailable.token.is_none());
            let _: Result<()> = old.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                Err(Error::Permission),
            );
            assert!(private_fixed_diagnostic_snapshot_v1().is_none());
            observe_private_fixed_host_v1(
                PrivateDiagnosticOperationV1::Checkpoint,
                PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
                &Error::Authentication,
            );
            assert!(
                private_fixed_diagnostic_snapshot_v1()
                    .unwrap()
                    .stage
                    .is_none()
            );
        }
    }
    #[test]
    fn absent_observer_forwards_once_and_stage_schema_is_strict() {
        let observation = PrivateStageObservationV1 {
            token: None,
            local: std::marker::PhantomData,
        };
        let mut calls = 0;
        let result = observation.callback(|| {
            calls += 1;
            Ok(17)
        });
        assert_eq!(result.unwrap(), 17);
        assert_eq!(calls, 1);
        for (kind, operation) in [
            (
                PrivateStageKindV1::Prepare,
                PrivateDiagnosticOperationV1::Checkpoint,
            ),
            (
                PrivateStageKindV1::AdmitOriginal,
                PrivateDiagnosticOperationV1::Checkpoint,
            ),
            (
                PrivateStageKindV1::ProveOriginal,
                PrivateDiagnosticOperationV1::Proof,
            ),
            (
                PrivateStageKindV1::FreezeFixed,
                PrivateDiagnosticOperationV1::Freeze,
            ),
            (
                PrivateStageKindV1::ReadFixed,
                PrivateDiagnosticOperationV1::ReadFixed,
            ),
        ] {
            let cost = PrivateStageCostV1 {
                kind,
                elapsed_ms: 0,
                callback_count: 0,
                callback_total_us: 0,
                callback_max_us: 0,
            };
            assert!(cost.valid(operation));
            assert!(!cost.valid(PrivateDiagnosticOperationV1::OpenOriginal));
            let raw = serde_json::to_string(&cost).unwrap();
            assert!(
                serde_json::from_str::<PrivateStageCostV1>(
                    &raw.replace("\"elapsed_ms\":0", "\"elapsed_ms\":0,\"elapsed_ms\":1")
                )
                .is_err()
            );
            let mut invalid = cost.clone();
            invalid.callback_total_us = 1;
            assert!(!invalid.valid(operation));
            let mut invalid = cost.clone();
            invalid.callback_count = 1;
            invalid.callback_total_us = 2;
            invalid.callback_max_us = 1;
            assert!(!invalid.valid(operation));
            let mut invalid = cost;
            invalid.elapsed_ms = PRIVATE_STAGE_MAX_MS_V1 + 1;
            assert!(!invalid.valid(operation));
        }
    }
}

#[cfg(test)]
mod observation_wave_v3_tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    struct Owned {
        index: usize,
        dropped: Rc<Cell<usize>>,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }

    #[test]
    fn observation_wave_suspends_both_original_futures_before_either_completes() {
        runtime().block_on(async {
            let started = Rc::new(Cell::new(0u8));
            let completed = Rc::new(Cell::new(0));
            let dropped = Rc::new(Cell::new(0));
            let (left_tx, left_rx) = tokio::sync::oneshot::channel();
            let (right_tx, right_rx) = tokio::sync::oneshot::channel();
            let first = async {
                started.set(started.get() | 1);
                left_tx.send(()).unwrap();
                right_rx.await.unwrap();
                assert_eq!(started.get(), 3);
                completed.set(completed.get() + 1);
                Ok::<_, ()>(Owned {
                    index: 0,
                    dropped: dropped.clone(),
                })
            };
            let second = async {
                started.set(started.get() | 2);
                right_tx.send(()).unwrap();
                left_rx.await.unwrap();
                assert_eq!(started.get(), 3);
                completed.set(completed.get() + 1);
                Ok::<_, ()>(Owned {
                    index: 1,
                    dropped: dropped.clone(),
                })
            };
            // Test liveness only, never a production scan/native deadline.
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                same_thread_two_wallet_wave_v3(first, second),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(completed.get(), 2);
            assert_eq!([result[0].index, result[1].index], [0, 1]);
            assert_eq!(dropped.get(), 0);
            drop(result);
            assert_eq!(dropped.get(), 2);
        });
    }

    #[test]
    fn observation_wave_drains_both_and_keeps_first_owner_error_without_retry() {
        runtime().block_on(async {
            for fail_second in [false, true] {
                let calls = Rc::new(Cell::new(0));
                let finished = Rc::new(Cell::new(0));
                let drops = Rc::new(Cell::new(0));
                let (tx, rx) = tokio::sync::oneshot::channel();
                let first = async {
                    calls.set(calls.get() + 1);
                    rx.await.unwrap();
                    finished.set(finished.get() + 1);
                    Err::<Owned, _>(Owned {
                        index: 0,
                        dropped: drops.clone(),
                    })
                };
                let second = async {
                    calls.set(calls.get() + 1);
                    finished.set(finished.get() + 1);
                    tx.send(()).unwrap();
                    let value = Owned {
                        index: 1,
                        dropped: drops.clone(),
                    };
                    if fail_second { Err(value) } else { Ok(value) }
                };
                let result = same_thread_two_wallet_wave_v3(first, second).await;
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("failed wave escaped"),
                };
                assert_eq!(error.index, 0);
                assert_eq!(calls.get(), 2);
                assert_eq!(finished.get(), 2);
                assert_eq!(drops.get(), 1);
                drop(error);
                assert_eq!(drops.get(), 2);
            }
        });
    }

    #[test]
    fn observation_wave_drop_cancels_both_pending_futures_without_output_or_retry() {
        struct Pending {
            polled: Rc<Cell<usize>>,
            dropped: Rc<Cell<usize>>,
        }
        impl std::future::Future for Pending {
            type Output = std::result::Result<(), ()>;
            fn poll(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                self.polled.set(self.polled.get() + 1);
                std::task::Poll::Pending
            }
        }
        impl Drop for Pending {
            fn drop(&mut self) {
                self.dropped.set(self.dropped.get() + 1);
            }
        }
        struct Wake;
        impl std::task::Wake for Wake {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let polled = Rc::new(Cell::new(0));
        let dropped = Rc::new(Cell::new(0));
        let mut wave = Box::pin(same_thread_two_wallet_wave_v3(
            Pending {
                polled: polled.clone(),
                dropped: dropped.clone(),
            },
            Pending {
                polled: polled.clone(),
                dropped: dropped.clone(),
            },
        ));
        let waker = std::task::Waker::from(std::sync::Arc::new(Wake));
        let mut context = std::task::Context::from_waker(&waker);
        assert!(std::future::Future::poll(wave.as_mut(), &mut context).is_pending());
        assert_eq!(polled.get(), 2);
        drop(wave);
        assert_eq!(dropped.get(), 2);
        assert_eq!(polled.get(), 2);
    }

    #[test]
    fn original_slot_mapping_preserves_owned_success_and_closed_lower_error_categories() {
        use wholepact_wallet::wallet::protected_sync::SyncError as S;
        use wholepact_chain::ChainError as H;
        use PrivateDiagnosticFamilyV1 as F;
        use PrivateDiagnosticCauseV1 as C;
        let dropped = Rc::new(Cell::new(0));
        let value = observe_original_slot_result_v3(Ok(Owned {
            index: 7,
            dropped: dropped.clone(),
        }))
        .unwrap();
        assert_eq!(value.index, 7);
        assert_eq!(dropped.get(), 0);
        drop(value);
        assert_eq!(dropped.get(), 1);
        for (error, family, cause) in [
            (
                DurableConstructionError::Invalid,
                F::DurableConstruction,
                C::Invalid,
            ),
            (
                DurableConstructionError::Binding,
                F::DurableConstruction,
                C::Binding,
            ),
            (
                DurableConstructionError::Stale,
                F::DurableConstruction,
                C::Stale,
            ),
            (
                DurableConstructionError::Storage,
                F::DurableConstruction,
                C::Storage,
            ),
            (
                DurableConstructionError::Sync(S::AccessDenied),
                F::Sync,
                C::AccessDenied,
            ),
            (
                DurableConstructionError::Sync(S::InvalidRequest),
                F::Sync,
                C::InvalidRequest,
            ),
            (
                DurableConstructionError::Sync(S::Interrupted),
                F::Sync,
                C::Interrupted,
            ),
            (
                DurableConstructionError::Sync(S::ReconciliationRequired),
                F::Sync,
                C::ReconciliationRequired,
            ),
            (
                DurableConstructionError::Sync(S::InvalidResponse),
                F::Sync,
                C::InvalidResponse,
            ),
            (
                DurableConstructionError::Sync(S::ResourceLimit),
                F::Sync,
                C::ResourceLimit,
            ),
            (
                DurableConstructionError::Sync(S::NoCurrentObservation),
                F::Sync,
                C::NoCurrentObservation,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::InvalidConfiguration)),
                F::Chain,
                C::InvalidConfiguration,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::WrongNetwork)),
                F::Chain,
                C::WrongNetwork,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::UnsupportedProxyConfiguration)),
                F::Chain,
                C::UnsupportedProxyConfiguration,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::WrongBranch)),
                F::Chain,
                C::WrongBranch,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::StaleChain)),
                F::Chain,
                C::StaleChain,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::ContradictoryChain)),
                F::Chain,
                C::ContradictoryChain,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::Timeout)),
                F::Chain,
                C::Timeout,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::TransportUnavailable)),
                F::Chain,
                C::TransportUnavailable,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::ObservationInterrupted)),
                F::Chain,
                C::ObservationInterrupted,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::MissingAncestryEvidence)),
                F::Chain,
                C::MissingAncestryEvidence,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::NotObserved)),
                F::Chain,
                C::NotObserved,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::ResourceLimit)),
                F::Chain,
                C::ResourceLimit,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::MalformedEvidence)),
                F::Chain,
                C::MalformedEvidence,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::UnsupportedCapability)),
                F::Chain,
                C::UnsupportedCapability,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::BackendFailure {
                    grpc_code: i32::MAX,
                })),
                F::Chain,
                C::BackendFailure,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::ClockUnavailable)),
                F::Chain,
                C::ClockUnavailable,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::IdempotencyConflict)),
                F::Chain,
                C::IdempotencyConflict,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::JournalFailure)),
                F::Chain,
                C::JournalFailure,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::SubmissionNotAuthorized)),
                F::Chain,
                C::SubmissionNotAuthorized,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::SubmissionExpiryMargin)),
                F::Chain,
                C::SubmissionExpiryMargin,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::ObligationConflict)),
                F::Chain,
                C::ObligationConflict,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::SubmissionOutcomeUnrecorded)),
                F::Chain,
                C::SubmissionOutcomeUnrecorded,
            ),
            (
                DurableConstructionError::Sync(S::Chain(H::SubmissionRetentionUncertain)),
                F::Chain,
                C::SubmissionRetentionUncertain,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::Storage,
                )),
                F::Wallet,
                C::Storage,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::AccountScope,
                )),
                F::Wallet,
                C::AccountScope,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::AccountMismatch,
                )),
                F::Wallet,
                C::AccountMismatch,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::IncompleteSync,
                )),
                F::Wallet,
                C::IncompleteSync,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::UnsupportedProfile,
                )),
                F::Wallet,
                C::UnsupportedProfile,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::ChainMismatch,
                )),
                F::Wallet,
                C::ChainMismatch,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::InsufficientFunds,
                )),
                F::Wallet,
                C::InsufficientFunds,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::InvalidRequest,
                )),
                F::Wallet,
                C::InvalidRequest,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::MissingWitness,
                )),
                F::Wallet,
                C::MissingWitness,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::InvalidNote,
                )),
                F::Wallet,
                C::InvalidNote,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::Scan,
                )),
                F::Wallet,
                C::Scan,
            ),
            (
                DurableConstructionError::Sync(S::Wallet(
                    wholepact_wallet::wallet::WalletError::Transport,
                )),
                F::Wallet,
                C::Transport,
            ),
        ] {
            assert_eq!(original_slot_cause_v3(&error), (family, cause));
            let result: Result<()> = observe_original_slot_result_v3(Err(error));
            assert!(matches!(result, Err(Error::Permission)));
        }
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn original_slot_failure_is_observed_before_stage_drop_without_engine_call_facts() {
        use wholepact_engine::PrivateFixedStageV3 as S;
        use wholepact_wallet::wallet::protected_sync::SyncError;
        for kind in [S::Prepare, S::AdmitOriginal] {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            let stage = begin_private_stage_cost_v1(
                kind,
                std::time::Instant::now() + Duration::from_secs(120),
            );
            stage.callback(|| Ok(())).unwrap();
            let result: Result<()> = observe_original_slot_result_v3(Err(
                DurableConstructionError::Sync(SyncError::NoCurrentObservation),
            ));
            assert!(matches!(result, Err(Error::Permission)));
            let first = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert_eq!(first.primary.site, PrivateDiagnosticSiteV1::SlotBindings);
            assert_eq!(first.primary.family, PrivateDiagnosticFamilyV1::Sync);
            assert_eq!(
                first.primary.cause,
                PrivateDiagnosticCauseV1::NoCurrentObservation
            );
            assert_eq!(
                first.primary.engine_code,
                PrivateDiagnosticEngineCodeV1::NotApplicable
            );
            assert!(first.evidence.is_none() && first.worker.is_none());
            assert_eq!(
                first.stage.as_ref().unwrap().kind,
                private_stage_kind_v1(kind)
            );
            assert_eq!(first.stage.as_ref().unwrap().callback_count, 1);
            drop(stage);
            drop(invocation);
            observe_private_fixed_host_v1(
                PrivateDiagnosticOperationV1::Checkpoint,
                PrivateDiagnosticSiteV1::HostCheckpointEntry,
                &Error::Permission,
            );
            assert_eq!(private_fixed_diagnostic_snapshot_v1().unwrap(), first);
        }
    }

    #[test]
    #[ignore = "isolated CI only: real localhost TCP, forbidden in local safe gates"]
    fn observation_wave_actual_localhost_requests_overlap_before_responses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        runtime().block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let requested = Rc::new(Cell::new(0u8));
            let serve = async {
                let (mut first, _) = listener.accept().await.unwrap();
                let a = first.read_u8().await.unwrap();
                requested.set(requested.get() | (1 << a));
                let (mut second, _) = listener.accept().await.unwrap();
                let b = second.read_u8().await.unwrap();
                requested.set(requested.get() | (1 << b));
                assert_eq!(requested.get(), 3);
                first.write_u8(a).await.unwrap();
                second.write_u8(b).await.unwrap();
            };
            let request = |index: u8| async move {
                let mut stream = tokio::net::TcpStream::connect(address).await?;
                stream.write_u8(index).await?;
                let result = stream.read_u8().await?;
                Ok::<_, std::io::Error>(result)
            };
            let ((), result) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    serve,
                    same_thread_two_wallet_wave_v3(request(0), request(1))
                )
            })
            .await
            .unwrap();
            assert_eq!(result.unwrap(), [0, 1]);
            assert_eq!(requested.get(), 3);
        });
    }
}

#[cfg(test)]
mod observation_cause_v1_tests {
    use super::*;
    const KEY: &str = "private_fixed_observation_cause_v1";
    fn scan_error() -> wholepact_engine::ApiError {
        let mut error = wholepact_engine::ApiError::new(
            "DURABLE_CONSTRUCTION_UNAVAILABLE",
            "private scanner message",
        );
        error.details = Box::new(serde_json::json!({KEY:{
            "schema":1,"operation":"Checkpoint","site":"WalletRosterAcquire",
            "engine_code":"DURABLE_CONSTRUCTION_UNAVAILABLE","family":"Sync","cause":"NoCurrentObservation"
        }}));
        error
    }
    #[test]
    fn observe_boundary_and_cause_only_parser_are_closed_and_code_correlated() {
        // Observe was absent here, causing the real CI30 UNAVAILABLE record.
        assert_eq!(
            PrivateBoundaryV2::Observe.diagnostic_v1(),
            Some((
                PrivateDiagnosticOperationV1::Checkpoint,
                PrivateDiagnosticSiteV1::WalletRosterAcquire
            ))
        );
        let primary = original_observation_cause_v1(&scan_error()).unwrap();
        assert_eq!(primary.family, PrivateDiagnosticFamilyV1::Sync);
        assert_eq!(
            primary.cause,
            PrivateDiagnosticCauseV1::NoCurrentObservation
        );
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("operation", serde_json::json!("Proof")),
            ("site", serde_json::json!("ReceiptCommit")),
            ("engine_code", serde_json::json!("DISCLOSURE_DENIED")),
            ("engine_code", serde_json::json!("NotApplicable")),
            ("family", serde_json::json!("Host")),
            ("cause", serde_json::json!("private/unbounded/cause")),
            ("calls", serde_json::json!({})),
        ] {
            let mut error = scan_error();
            error.details[KEY][field] = value;
            assert!(original_observation_cause_v1(&error).is_none(), "{field}");
        }
        let mut impossible = scan_error();
        impossible.details[KEY]["family"] = serde_json::json!("Host");
        impossible.details[KEY]["cause"] = serde_json::json!("Permission");
        assert!(original_observation_cause_v1(&impossible).is_none());
        let mut error = scan_error();
        error.details[KEY] = serde_json::json!("malformed");
        assert!(original_observation_cause_v1(&error).is_none());
        let mut error = scan_error();
        error.code = "INTERNAL_ERROR".into();
        assert!(original_observation_cause_v1(&error).is_none());
    }
    #[test]
    fn observation_setup_forwarding_preserves_owned_values_and_original_errors() {
        #[derive(Debug)]
        struct Owned<'a>(&'a std::cell::Cell<u32>);
        impl Drop for Owned<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = std::cell::Cell::new(0);
        let owned =
            private_host_result_at_v1(PrivateDiagnosticSiteV1::SourcePermission, Ok(Owned(&drops)))
                .unwrap();
        assert_eq!(drops.get(), 0);
        drop(owned);
        assert_eq!(drops.get(), 1);
        for error in [
            Error::Invalid,
            Error::Permission,
            Error::Authentication,
            Error::Storage,
        ] {
            let expected = host_category(&error);
            let result: Result<()> =
                private_host_result_at_v1(PrivateDiagnosticSiteV1::HostCheckpointSlots, Err(error));
            assert_eq!(host_category(&result.unwrap_err()), expected);
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn observe_scan_failure_survives_actual_stage_collector_and_wire_roundtrip() {
        for cause_only in [false, true] {
            let _scope = begin_private_fixed_diagnostic_scope_v1();
            let invocation =
                begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
            begin_private_stage(PrivateBoundaryV2::Observe);
            let stage = begin_private_stage_cost_v1(
                wholepact_engine::PrivateFixedStageV3::Prepare,
                std::time::Instant::now() + Duration::from_secs(120),
            );
            stage.callback(|| Ok(())).unwrap();
            let error = if cause_only {
                scan_error()
            } else {
                wholepact_engine::ApiError::new("DURABLE_CONSTRUCTION_UNAVAILABLE", "fallback")
            };
            let _original = observe_engine_observation(error);
            let snapshot = private_fixed_diagnostic_snapshot_v1().unwrap();
            assert_eq!(
                snapshot.primary.operation,
                PrivateDiagnosticOperationV1::Checkpoint
            );
            assert_eq!(
                snapshot.primary.site,
                PrivateDiagnosticSiteV1::WalletRosterAcquire
            );
            assert_eq!(
                snapshot.primary.family,
                if cause_only {
                    PrivateDiagnosticFamilyV1::Sync
                } else {
                    PrivateDiagnosticFamilyV1::Engine
                }
            );
            assert!(snapshot.evidence.is_none() && snapshot.worker.is_none());
            let cost = snapshot.stage.as_ref().unwrap();
            assert_eq!(cost.kind, PrivateStageKindV1::Prepare);
            assert_eq!(cost.callback_count, 1);
            let json = snapshot.canonical_json().unwrap();
            assert!(!json.contains("private scanner"));
            assert_eq!(PrivateFixedDiagnosticV1::parse(&json).unwrap(), snapshot);
            drop(stage);
            drop(invocation);
            assert_eq!(private_fixed_diagnostic_snapshot_v1().unwrap(), snapshot);
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn observation_engine_error_does_not_replace_first_native_source_failure() {
        let _scope = begin_private_fixed_diagnostic_scope_v1();
        let _invocation =
            begin_private_diagnostic_invocation_v1(PrivateDiagnosticOperationV1::Checkpoint);
        let stage = begin_private_stage_cost_v1(
            wholepact_engine::PrivateFixedStageV3::Prepare,
            std::time::Instant::now() + Duration::from_secs(120),
        );
        let result: Result<()> = stage.observe(
            PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
            Err(Error::Permission),
        );
        assert!(matches!(result, Err(Error::Permission)));
        let first = private_fixed_diagnostic_snapshot_v1().unwrap();
        let _ = observe_engine_observation(scan_error());
        assert_eq!(private_fixed_diagnostic_snapshot_v1().unwrap(), first);
        assert!(first.evidence.is_none() && first.worker.is_none());
    }
}
