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
        durable_construction_v1::DurableConstructionWalletSlotV1,
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
impl LocalDurableMaterialConsentV1 for CurrentMaterialPrivacyV2<'_, '_> {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        material: &str,
        action: DurableMaterialActionV1,
    ) -> bool {
        let Some(action) = material_action_tag(action) else {
            return false;
        };
        if action != self.allowed || !valid_commitment(material) {
            return false;
        }
        if !observed_host_permission(self.scope_current(scope)) {
            return false;
        }
        let Ok(mut approved) = self.approved.lock() else {
            return false;
        };
        if let Some((original, digest, approval)) = approved
            .iter()
            .find(|(s, _, _)| s.account_id == scope.account_id)
        {
            return original == scope
                && digest == material
                && observed_host_permission(approval.check())
                && observed_host_permission(self.scope_current(scope));
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
        )) { Ok(approval) => approval, Err(error) => { observe_host_current(&error); return false; } };
        if !observed_host_permission(self.scope_current(scope))
            || !observed_host_permission(approval.check())
        {
            return false;
        }
        approved.push((scope.clone(), material.into(), approval));
        true
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
impl LocalProofConsent for CurrentProofPrivacyV2<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        if !self.allowed.contains(&action) {
            return false;
        }
        if !observed_host_permission(self.material.check_complete()) {
            return false;
        }
        let scopes = match self.material.exact_scopes() {
            Ok(scopes) => scopes,
            Err(error) => {
                observe_host_current(&error);
                return false;
            }
        };
        let access = match self.material.host.access() {
            Ok(access) => access,
            Err(error) => {
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
        if let Some((_, _, native)) = approved.iter().find(|(_, a, _)| *a == action) {
            return observed_host_permission(native.check())
                && observed_host_permission(self.material.check_complete());
        }
        let Ok(detail) = serde_json::to_string_pretty(scope) else {
            return false;
        };
        let native = match self.material.host.terminal.approve_historical(&format!(
            "Allow {action:?} for this exact original private workspace checkpoint?\n{detail}\nOnly the actual original primary proof journal is used. A first proof attempt consumes its live continuation; interruption never authorizes restart. No remote export, financial admission, signature or submission is allowed."
        )) { Ok(native) => native, Err(error) => { observe_host_current(&error); return false; } };
        if !observed_host_permission(native.check())
            || !observed_host_permission(self.material.check_complete())
        {
            return false;
        }
        approved.push((scope.clone(), action, native));
        true
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
        let material = CurrentMaterialPrivacyV2::new(
            self.host,
            &self.owner,
            self.candidate.candidate_id(),
            Some(self.candidate.proposal()),
            1,
        );
        let proof = CurrentProofPrivacyV2 {
            material: &material,
            allowed: vec![
                LocalAction::InspectStatus,
                LocalAction::RetainPrivateWitnesses,
            ],
            approved: Mutex::new(Vec::new()),
        };
        begin_private_stage(PrivateBoundaryV2::Observe);
        let observe = self
            .owner
            .exact_fixed_action_v2(PrivateWorkspaceActionV1::ObserveExactMaterial)?;
        let mut fresh = Vec::new();
        for index in 0..2 {
            let (scope, backend) = self.captured[index].as_ref().ok_or(Error::Invalid)?;
            let wallet = &mut self.cache.wallets[index];
            wallet.check()?;
            let native = self.host.terminal.approve_historical(&format!(
                "Observe this exact retained private construction input through its original process-only wallet and approved public-block provider.\nAccount: {}\nWallet: {}\nProvider: {}\nNo alternate inputs, refreshed material ceiling, financial admission or chain-validity assertion is permitted.",
                scope.account_id, wallet.destination()?.display(), backend.endpoint,
            ))?;
            let sync = wallet.wallet.as_mut().ok_or(Error::Invalid)?;
            let gate = CurrentScanAccessV2 {
                host: self.host,
                workspace: &self.owner,
                directory: wallet.directory.as_ref().ok_or(Error::Invalid)?,
                origin: wallet.origin.as_ref().ok_or(Error::Invalid)?,
                account: sync.account_uuid(),
                backend,
                scope,
                native: &native,
            };
            observe.check()?;
            fresh.push(
                observe
                    .coordinator()
                    .observe_exact_material_v2(
                        self.host.access()?,
                        self.candidate.candidate_id(),
                        &scope.account_id,
                        sync,
                        &observe,
                        &material,
                        &gate,
                    )
                    .await
                    .map_err(observe_engine_observation)?,
            );
            observe.check()?;
            native.check()?;
        }
        drop(observe);
        complete_private_stage(PrivateBoundaryV2::Observe);
        begin_private_stage(PrivateBoundaryV2::Checkpoint);
        material.check_complete()?;
        let checkpoint_key = self.original_checkpoint_key()?;
        let checkpoint_action = self
            .owner
            .exact_fixed_action_v2(PrivateWorkspaceActionV1::CheckpointExactOriginal)?;
        let [left, right] = &mut self.cache.wallets;
        let checkpoint = checkpoint_action
            .coordinator()
            .checkpoint_exact_original_v2(
                self.host.access()?,
                &checkpoint_key,
                self.candidate.candidate_id(),
                self.revision,
                vec![
                    DurableConstructionWalletSlotV1::new(
                        left.wallet.as_mut().ok_or(Error::Invalid)?,
                        &fresh[0],
                    )
                    .map_err(|_| Error::Permission)?,
                    DurableConstructionWalletSlotV1::new(
                        right.wallet.as_mut().ok_or(Error::Invalid)?,
                        &fresh[1],
                    )
                    .map_err(|_| Error::Permission)?,
                ],
                wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
                &checkpoint_action,
                &proof,
                &material,
            )
            .map_err(observe_engine_checkpoint)?;
        let revision = checkpoint.status().revision;
        let attempt = checkpoint
            .into_attempt()
            .ok_or(Error::RecoveryFinancialUnsupported)?;
        checkpoint_action.check()?;
        drop(fresh);
        complete_private_stage(PrivateBoundaryV2::Checkpoint);
        begin_private_stage(PrivateBoundaryV2::Proof);
        let prove_action = self
            .owner
            .exact_fixed_action_v2(PrivateWorkspaceActionV1::ProveOriginalOnce)?;
        let prove_material = CurrentMaterialPrivacyV2::new(
            self.host,
            &self.owner,
            self.candidate.candidate_id(),
            Some(self.candidate.proposal()),
            1,
        );
        let prove_privacy = CurrentProofPrivacyV2 {
            material: &prove_material,
            allowed: vec![
                LocalAction::InspectStatus,
                LocalAction::RetainPrivateWitnesses,
                LocalAction::ProveLocally,
            ],
            approved: Mutex::new(Vec::new()),
        };
        let proved = run_original_proof_foreground_v2(
            self.host,
            prove_action.coordinator(),
            attempt,
            &fix_step_key(&self.key, "prove")?,
            revision,
            &prove_action,
            &prove_privacy,
            &prove_material,
        )?;
        prove_action.check()?;
        self.revision = proved.revision;
        drop(prove_action);
        drop(checkpoint_action);
        complete_private_stage(PrivateBoundaryV2::Proof);
        begin_private_stage(PrivateBoundaryV2::Freeze);
        let freeze_material = CurrentMaterialPrivacyV2::new(
            self.host,
            &self.owner,
            self.candidate.candidate_id(),
            Some(self.candidate.proposal()),
            1,
        );
        let freeze_proof = CurrentProofPrivacyV2 {
            material: &freeze_material,
            allowed: vec![LocalAction::InspectStatus, LocalAction::ReadPrivateArtifact],
            approved: Mutex::new(Vec::new()),
        };
        let frozen = self.owner.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            |coordinator, privacy| {
                coordinator
                    .freeze_verified_fixed_v2(
                        self.host.access()?,
                        &fix_step_key(&self.key, "freeze")?,
                        self.candidate.candidate_id(),
                        &checkpoint_key,
                        self.revision,
                        privacy,
                        &freeze_proof,
                        &freeze_material,
                    )
                    .map_err(observe_engine_freeze)
            },
        )?;
        self.revision = frozen.revision;
        complete_private_stage(PrivateBoundaryV2::Freeze);
        begin_private_stage(PrivateBoundaryV2::Read);
        self.owner.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::ReadVerifiedFixed,
            |coordinator, privacy| {
                coordinator
                    .read_verified_fixed_v2(
                        self.host.access()?,
                        self.candidate.candidate_id(),
                        &checkpoint_key,
                        privacy,
                        &freeze_proof,
                        &freeze_material,
                    )
                    .map_err(observe_engine_read)
            },
        )
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
    workspace: &crate::host::durable_private_workspace_v1::OwnedPrivateWorkspaceActionV2<
        '_,
        'source,
    >,
    proof: &CurrentProofPrivacyV2<'_, '_>,
    material: &CurrentMaterialPrivacyV2<'_, '_>,
) -> Result<wholepact_engine::PrivateWorkspaceStatusV1> {
    use std::sync::atomic::{AtomicBool, Ordering};
    workspace.check()?;
    let access = host.access()?.clone();
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
        let mut foreground_error = None;
        let result = loop {
            match receive.recv_timeout(Duration::from_secs(1)) {
                Ok(ForegroundProofRequestV2::Finished(result)) => {
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
                            observe_host_current(&error);
                            foreground_error = Some(error);
                            cancelled.store(true, Ordering::Release);
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break Err(Error::Storage),
            }
        };
        // Join on every success/failure/channel outcome. No detached proof can
        // outlive these exact original source/proof owners or cache teardown.
        let joined = worker.join();
        if let Some(error) = foreground_error {
            return Err(error);
        }
        match result {
            Err(error) => Err(error),
            Ok(status) => match joined {
                Ok(()) => Ok(status),
                Err(_) => Err(Error::Storage),
            },
        }
    });
    match result {
        Err(error) => Err(error),
        Ok(status) => {
            workspace.check()?;
            Ok(status)
        }
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
        let result = self.private_durable_read_fixed_inner_v2(root);
        if let Err(error) = &result {
            observe_host_current(error);
        } else {
            complete_private_stage(PrivateBoundaryV2::Read);
        }
        result
    }
    fn private_durable_read_fixed_inner_v2(&self, root: &Path) -> Result<PrivateVerifiedFixedV2> {
        self.require_private_workspace_read_session_v1()?;
        let owner = self.reopen_private_workspace_registered_v1(root)?;
        let material = CurrentMaterialPrivacyV2 {
            host: self,
            owner: &owner,
            candidate_id: None,
            exact_proposal: None,
            allowed: 1,
            approved: Mutex::new(Vec::new()),
        };
        let proof = CurrentProofPrivacyV2 {
            material: &material,
            allowed: vec![LocalAction::InspectStatus, LocalAction::ReadPrivateArtifact],
            approved: Mutex::new(Vec::new()),
        };
        owner.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::ReadVerifiedFixed,
            |coordinator, privacy| {
                coordinator
                    .read_only_original_fixed_v2(self.access()?, privacy, &proof, &material)
                    .map_err(observe_engine_read)
            },
        )
    }
    pub(in crate::host) fn private_durable_read_fixed_v1_command(&self, root: &Path) -> Result<()> {
        let fixed = self.private_durable_read_fixed_v2(root)?;
        self.terminal.json(&fixed)?;
        self.terminal.message("The same original fixed proof was independently verified read-only under current local privacy consent and both original material ceilings. No scan, capture, reconstruction, proof attempt, metadata repair, financial admission or export occurred.\n")
    }
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
    observe_failure(boundary, engine_category(&error));
    Error::from(error)
}
fn observe_engine_current(error: wholepact_engine::ApiError) -> Error {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    PRIVATE_CURRENT_BOUNDARY_V2.with(|stage| observe_failure(stage.get(), engine_category(&error)));
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
fn observe_engine_observation(error: wholepact_engine::ApiError) -> Error {
    observe_engine(PrivateBoundaryV2::Observe, error)
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
    PRIVATE_CURRENT_BOUNDARY_V2
        .with(|boundary| observe_failure(boundary.get(), host_category(error)));
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
}
