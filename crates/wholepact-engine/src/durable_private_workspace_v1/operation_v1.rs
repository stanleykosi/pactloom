//! Nominal reads and purpose-bound effects. A read owner cannot mutate or replay.
use super::diagnostics::{Call, Observation, Site};
use super::*;
use crate::{Envelope, StoredRecord};
use wholepact_store::{CommandContext, MutationResult};

pub(super) struct PrivateWorkspaceOperationV1<'op, 'source> {
    workspace: &'op PrivateDurableCoordinatorV1<'source>,
    access: &'op Access,
    consent: &'op dyn LocalPrivateWorkspaceConsentV1,
    action: PrivateWorkspaceActionV1,
}
impl<'op, 'source> PrivateWorkspaceOperationV1<'op, 'source> {
    pub(super) fn new(
        workspace: &'op PrivateDurableCoordinatorV1<'source>,
        access: &'op Access,
        consent: &'op dyn LocalPrivateWorkspaceConsentV1,
        action: PrivateWorkspaceActionV1,
    ) -> Self {
        Self {
            workspace,
            access,
            consent,
            action,
        }
    }
    pub(super) fn load(&self) -> Result<Envelope> {
        self.load_inner(None)
    }
    pub(super) fn load_observed(&self, observation: &Observation) -> Result<Envelope> {
        self.load_inner(Some(observation))
    }
    fn load_inner(&self, observation: Option<&Observation>) -> Result<Envelope> {
        self.workspace
            .check_observed(self.access, self.consent, self.action, observation)?;
        let record = self
            .workspace
            .engine
            .store
            .get_agreement(self.workspace.source.agreement_id())
            .map_err(|error| {
                diagnostics::store_error(
                    observation,
                    observation.map_or(Site::WorkspaceLoad, Observation::site),
                    error,
                )
            })?
            .ok_or_else(damaged)?;
        let envelope = decode(self.workspace, &record)?;
        self.workspace
            .check_observed(self.access, self.consent, self.action, observation)?;
        Ok(envelope)
    }
}
fn decode(workspace: &PrivateDurableCoordinatorV1<'_>, record: &StoredRecord) -> Result<Envelope> {
    if record.id != workspace.source.agreement_id() {
        return Err(damaged());
    }
    let envelope = decode_private_record(record)?;
    workspace.require_original_envelope(&envelope)?;
    Ok(envelope)
}
#[derive(Clone, Copy)]
pub(super) enum EffectV2 {
    PrepareExactCandidate,
    RetainExactMaterial,
    ConstructorReceipt,
    MetadataLink,
    RecordOriginalProofOutcome,
    FreezeVerifiedFixed,
}
impl EffectV2 {
    fn action(self) -> PrivateWorkspaceActionV1 {
        match self {
            Self::PrepareExactCandidate => PrivateWorkspaceActionV1::PrepareExactCandidate,
            Self::RetainExactMaterial => PrivateWorkspaceActionV1::RetainExactMaterial,
            Self::ConstructorReceipt | Self::MetadataLink => {
                PrivateWorkspaceActionV1::CheckpointExactOriginal
            }
            Self::RecordOriginalProofOutcome => PrivateWorkspaceActionV1::ProveOriginalOnce,
            Self::FreezeVerifiedFixed => PrivateWorkspaceActionV1::FreezeVerifiedFixed,
        }
    }
    fn event(self) -> &'static str {
        match self {
            Self::PrepareExactCandidate => "private_exact_candidate_prepared_v2",
            Self::RetainExactMaterial => "private_exact_material_retained_v2",
            Self::ConstructorReceipt => "private_original_constructor_recorded_v2",
            Self::MetadataLink => "private_original_checkpoint_linked_v2",
            Self::RecordOriginalProofOutcome => "private_original_proof_observed_v2",
            Self::FreezeVerifiedFixed => "private_verified_fixed_frozen_v2",
        }
    }
}
/// Not obtainable from the read owner; binds one specific request and revision.
pub(super) struct PrivateWorkspaceEffectV2<'op, 'source> {
    workspace: &'op PrivateDurableCoordinatorV1<'source>,
    access: &'op Access,
    consent: &'op dyn LocalPrivateWorkspaceConsentV1,
    purpose: EffectV2,
    command: CommandContext,
    revision: u64,
}
impl<'op, 'source> PrivateWorkspaceEffectV2<'op, 'source> {
    pub(super) fn new(
        workspace: &'op PrivateDurableCoordinatorV1<'source>,
        access: &'op Access,
        consent: &'op dyn LocalPrivateWorkspaceConsentV1,
        purpose: EffectV2,
        command: CommandContext,
        revision: u64,
    ) -> Result<Self> {
        Self::new_inner(workspace, access, consent, purpose, command, revision, None)
    }
    pub(super) fn new_observed(
        workspace: &'op PrivateDurableCoordinatorV1<'source>,
        access: &'op Access,
        consent: &'op dyn LocalPrivateWorkspaceConsentV1,
        purpose: EffectV2,
        command: CommandContext,
        revision: u64,
        observation: &Observation,
    ) -> Result<Self> {
        Self::new_inner(
            workspace,
            access,
            consent,
            purpose,
            command,
            revision,
            Some(observation),
        )
    }
    fn new_inner(
        workspace: &'op PrivateDurableCoordinatorV1<'source>,
        access: &'op Access,
        consent: &'op dyn LocalPrivateWorkspaceConsentV1,
        purpose: EffectV2,
        command: CommandContext,
        revision: u64,
        observation: Option<&Observation>,
    ) -> Result<Self> {
        workspace.check_observed(access, consent, purpose.action(), observation)?;
        if command.principal_id != access.principal_id {
            return Err(denied());
        }
        Ok(Self {
            workspace,
            access,
            consent,
            purpose,
            command,
            revision,
        })
    }
    pub(super) fn replay(&self) -> Result<Option<MutationResult>> {
        self.replay_inner(None)
    }
    pub(super) fn replay_observed(
        &self,
        observation: &Observation,
    ) -> Result<Option<MutationResult>> {
        self.replay_inner(Some(observation))
    }
    fn replay_inner(&self, observation: Option<&Observation>) -> Result<Option<MutationResult>> {
        self.workspace.check_observed(
            self.access,
            self.consent,
            self.purpose.action(),
            observation,
        )?;
        let result = self
            .workspace
            .engine
            .store
            .find_replay(&self.command)
            .map_err(|error| diagnostics::store_error(observation, Site::ReplayLookup, error))?;
        if let Some(saved) = &result {
            let envelope = decode(self.workspace, &saved.record)?;
            if envelope.view.revision != self.revision.checked_add(1).ok_or_else(damaged)? {
                return Err(damaged());
            }
            let operation = self
                .workspace
                .engine
                .store
                .get_operation(&saved.operation_id)
                .map_err(|error| diagnostics::store_error(observation, Site::ReplayLookup, error))?
                .ok_or_else(damaged)?;
            let original: MutationResult =
                serde_json::from_value(operation.result).map_err(|_| damaged())?;
            if operation.principal_id != self.access.principal_id
                || operation.resource_id != saved.record.id
                || operation.kind != self.purpose.event()
                || operation.status != "succeeded"
                || original.operation_id != saved.operation_id
                || original.record != saved.record
            {
                return Err(damaged());
            }
        }
        self.workspace.check_observed(
            self.access,
            self.consent,
            self.purpose.action(),
            observation,
        )?;
        Ok(result)
    }
    pub(super) fn commit(&self, before: &Envelope, after: Envelope) -> Result<MutationResult> {
        self.commit_inner(before, after, None)
    }
    pub(super) fn commit_observed(
        &self,
        before: &Envelope,
        after: Envelope,
        observation: &Observation,
    ) -> Result<MutationResult> {
        self.commit_inner(before, after, Some(observation))
    }
    fn commit_inner(
        &self,
        before: &Envelope,
        mut after: Envelope,
        observation: Option<&Observation>,
    ) -> Result<MutationResult> {
        self.workspace.check_observed(
            self.access,
            self.consent,
            self.purpose.action(),
            observation,
        )?;
        crate::candidates::check_revision(before, self.revision)?;
        // Exactly one revision/time update. Caller cannot select either value.
        after.view.revision = self.revision.checked_add(1).ok_or_else(damaged)?;
        after.view.updated_at = crate::now();
        validate_delta(before, &after, self.purpose)?;
        self.workspace.require_original_envelope(&after)?;
        let saved = self.workspace.engine.store.update_agreement(
            &self.command,
            self.workspace.source.agreement_id(),
            self.revision,
            crate::encode(&after)?,
            self.purpose.event(),
        );
        if let Some(observation) = observation {
            let call = match self.purpose {
                EffectV2::ConstructorReceipt => Some((Site::ReceiptCommit, Call::Receipt)),
                EffectV2::MetadataLink => Some((Site::LinkCommit, Call::Link)),
                EffectV2::RecordOriginalProofOutcome => Some((Site::OutcomeCommit, Call::Outcome)),
                EffectV2::FreezeVerifiedFixed => Some((Site::FixedCommit, Call::Freeze)),
                _ => None,
            };
            if let Some((site, call)) = call {
                observation.store_call(site, call, &saved);
            }
        }
        let saved = saved.map_err(|error| self.commit_error(crate::store_error(error), None))?;
        // Store is independently original-destination fenced, including inside
        // its transaction. Callbacks are outside Store's mutex.
        let saved_envelope = decode(self.workspace, &saved.record)
            .map_err(|error| self.commit_error(error, Some(&saved)))?;
        if crate::encode(&saved_envelope)? != crate::encode(&after)? {
            return Err(self.commit_error(damaged(), Some(&saved)));
        }
        self.workspace
            .check_observed(
                self.access,
                self.consent,
                self.purpose.action(),
                observation,
            )
            .map_err(|error| self.commit_error(error, Some(&saved)))?;
        Ok(saved)
    }
    fn commit_error(&self, mut error: ApiError, saved: Option<&MutationResult>) -> ApiError {
        error.retryable = false;
        let facts = serde_json::json!({"private_metadata_effect_v2":self.purpose.event(),
            "metadata_commit_status":if saved.is_some(){"committed"}else{"not_confirmed"},
            "saved_revision":saved.map(|s|s.record.revision),"journals_are_atomic_together":false});
        merge_error_details_v2(&mut error, &facts);
        error.safe_actions=vec!["Inspect the same original request and journals; do not reconstruct or create a new proof attempt".into()];
        error
    }
}
fn same<T: Serialize>(a: &T, b: &T) -> Result<bool> {
    Ok(serde_json::to_value(a).map_err(|_| damaged())?
        == serde_json::to_value(b).map_err(|_| damaged())?)
}
pub(super) fn validate_shape(e: &Envelope) -> Result<()> {
    if !e.durable_input_projections_v1.is_empty()
        || !e.sponsor_policies.is_empty()
        || !e.participant_records.is_empty()
        || !e.transport_peer_grants.is_empty()
        || !e.native_requests.is_empty()
        || !e.native_proof_requests.is_empty()
        || !e.native_proof_execution_requests.is_empty()
        || !e.native_artifact_handoff_requests.is_empty()
        || !e.native_settlement_requests.is_empty()
        || !e.native_dispatch_requests.is_empty()
        || !e.native_reconciliation_requests.is_empty()
        || !e.native_account_inspection_requests.is_empty()
        || e.terms_editing_origin
        || !e.view.proposals.is_empty()
        || !e.view.verification_reports.is_empty()
        || e.view.candidates.len() > 1
        || e.checkpoint_receipts.len() > 1
        || e.durable_construction_v1.len() > 1
        || e.durable_proposals_v1.len() > 1
        || e.view.cancellation_requested
        || e.view.authorization_exposure != "unknown"
        || e.view.chain_observation != "unknown"
        || !matches!(
            e.view.progress.as_str(),
            "preparing_proposal" | "awaiting_authorization"
        )
    {
        return Err(damaged());
    }
    for candidate in &e.view.candidates {
        candidate.verified_snapshot()?;
        if !candidate.reviews.is_empty() || candidate.proof_jobs.len() > 1 {
            return Err(damaged());
        }
    }
    crate::durable_construction_v1::validate_private_roster_v2(e)?;
    crate::durable_proposals_v1::validate_private_fixed_v2(e)?;
    Ok(())
}
/// Clone the FULL typed envelope and copy only expressly allowed fields before
/// comparing full canonical serialization. Unknown fields are rejected by its
/// strict decoder; newly added fields remain compared and therefore immutable.
pub(super) fn validate_delta(before: &Envelope, after: &Envelope, purpose: EffectV2) -> Result<()> {
    validate_shape(before)?;
    validate_shape(after)?;
    validate_delta_after_checked_shapes_v2(before, after, purpose)
}
/// Pure delta tail for the closed history reader only. Both exact immutable
/// envelopes must already have passed `validate_shape` in this same traversal.
/// All mutation/default callers use `validate_delta`, including its shape checks.
pub(super) fn validate_delta_after_checked_shapes_v2(
    before: &Envelope,
    after: &Envelope,
    purpose: EffectV2,
) -> Result<()> {
    if after.view.revision != before.view.revision.checked_add(1).ok_or_else(damaged)?
        || time::OffsetDateTime::parse(
            &after.view.updated_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(damaged());
    }
    let mut permitted = before.clone();
    permitted.view.revision = after.view.revision;
    permitted.view.updated_at = after.view.updated_at.clone();
    match purpose {
        EffectV2::PrepareExactCandidate => {
            if !before.view.candidates.is_empty()
                || after.view.candidates.len() != 1
                || !after.view.candidates[0].proof_jobs.is_empty()
                || !before.durable_construction_v1.is_empty()
                || !before.checkpoint_receipts.is_empty()
                || !before.durable_proposals_v1.is_empty()
            {
                return Err(damaged());
            }
            permitted.view.candidates = after.view.candidates.clone();
        }
        EffectV2::RetainExactMaterial => {
            if before.view.candidates.len() != 1
                || !before.checkpoint_receipts.is_empty()
                || !before.durable_proposals_v1.is_empty()
            {
                return Err(damaged());
            }
            crate::durable_construction_v1::validate_private_intake_delta_v2(before, after)?;
            permitted.durable_construction_v1 = after.durable_construction_v1.clone();
        }
        EffectV2::ConstructorReceipt => {
            if !before.checkpoint_receipts.is_empty()
                || after.checkpoint_receipts.len() != 1
                || before.view.candidates.len() != 1
                || !before.view.candidates[0].proof_jobs.is_empty()
                || !before.durable_proposals_v1.is_empty()
            {
                return Err(damaged());
            }
            permitted.checkpoint_receipts = after.checkpoint_receipts.clone();
        }
        EffectV2::MetadataLink | EffectV2::RecordOriginalProofOutcome => {
            if before.view.candidates.len() != 1
                || after.view.candidates.len() != 1
                || before.checkpoint_receipts.len() != 1
                || after.view.candidates[0].proof_jobs.len() != 1
            {
                return Err(damaged());
            }
            let old = &before.view.candidates[0].proof_jobs;
            let new = &after.view.candidates[0].proof_jobs[0];
            if matches!(purpose, EffectV2::RecordOriginalProofOutcome) && old.len() != 1 {
                return Err(damaged());
            }
            if matches!(purpose, EffectV2::MetadataLink) && !old.is_empty() {
                return Err(damaged());
            }
            if let Some(old) = old.first() {
                let mut allowed = old.clone();
                allowed.state = new.state.clone();
                allowed.attempt = new.attempt;
                allowed.result_digest = new.result_digest.clone();
                allowed.proof_verified = new.proof_verified;
                allowed.observed_at = new.observed_at.clone();
                if !same(&allowed, new)? || new.attempt < old.attempt || new.attempt > 1 {
                    return Err(damaged());
                }
            }
            permitted.view.candidates[0].proof_jobs = after.view.candidates[0].proof_jobs.clone();
        }
        EffectV2::FreezeVerifiedFixed => {
            if !before.durable_proposals_v1.is_empty()
                || after.durable_proposals_v1.len() != 1
                || after.view.progress != "awaiting_authorization"
            {
                return Err(damaged());
            }
            permitted.durable_proposals_v1 = after.durable_proposals_v1.clone();
            permitted.view.progress = after.view.progress.clone();
        }
    }
    if !same(&permitted, after)? {
        return Err(damaged());
    }
    Ok(())
}

/// Add observations without erasing the original cause or caller metadata.
pub(super) fn merge_error_details_v2(error: &mut ApiError, facts: &serde_json::Value) {
    if let (Some(details), Some(facts)) = (error.details.as_object_mut(), facts.as_object()) {
        for (key, value) in facts {
            details.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
}
