//! Closed original-source fixed-proof operations. No generic Engine bypass.
use super::operation_v1::{EffectV2, PrivateWorkspaceEffectV2};
use super::original_job_error_v2 as job_error;
use super::*;
use crate::durable_construction_v1::{
    DurableMaterialActionV1, Intake, LocalDurableMaterialConsentV1, Roster,
};
use crate::proof_jobs::{upsert_link, validate_provenance, validate_summary};
use crate::{CandidateRequest, CandidateView, Envelope};
use serde_json::json;
use sha2::{Digest, Sha256};
use wholepact_proof_jobs::{
    CheckpointScope, FreshOriginalEnqueueV1, JobSummary, LocalAction, LocalProofConsent,
    VerifiedCheckpoint,
};
use wholepact_protocol::construction::{DisclosureAcknowledgement, DisclosureScope};
use wholepact_protocol::proving::ProvingLimits;
use wholepact_signer::authority_bridge::durable_construction_v1::AuthenticatedDurableConstructionDisclosureV1;
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
    DurableConstructionWalletSlotV1, FreshDurableConstructionObservationV1,
    HeldDurableConstructionRosterV1, with_durable_construction_roster_v1,
};
use wholepact_wallet::wallet::protected_sync::{LocalWalletAccess, ProtectedWalletSync};

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
fn receipt_key(access: &Access, key: &str) -> Result<String> {
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
    fn check_intake(
        &self,
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
            .check_durable_material(access, intake, material, action)
    }
    fn checked_roster(
        &self,
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
            self.check_intake(
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
        let envelope = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::ObserveExactMaterial,
            )?
            .load()?;
        candidate(&envelope, candidate_id)?;
        let roster = self.engine.durable_roster(&envelope, candidate_id)?;
        let intake = roster.owners.get(account_id).ok_or_else(damaged)?;
        let gate = ObservationGate {
            workspace: self,
            access,
            consent,
            material,
            intake,
            wallet: wallet_access,
        };
        gate.check()?;
        let result = wallet
            .observe_durable_material_v1(
                &intake.outbox.request().material,
                &intake.outbox.request().scope,
                &gate,
            )
            .await
            .map_err(Into::into);
        match result {
            Err(error) => Err(error),
            Ok(fresh) => {
                gate.check()?;
                Ok(fresh)
            }
        }
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
        if !(1..=wholepact_protocol::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
        {
            return Err(denied());
        }
        let envelope = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
            )?
            .load()?;
        let c = candidate(&envelope, candidate_id)?;
        let roster = self.checked_roster(access, &envelope, candidate_id, material)?;
        if slots.len() != 2 {
            return Err(denied());
        }
        let mut expected = BTreeSet::new();
        let mut declarations = Vec::new();
        for intake in roster.owners.values() {
            let scope = &intake.outbox.request().scope;
            expected.insert((intake.outbox.material_digest().to_owned(), scope.digest()?));
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
        let actual: BTreeSet<_> = slots
            .iter()
            .map(|s| Ok((s.material_digest()?, s.scope_digest()?)))
            .collect::<Result<_>>()?;
        if actual.len() != 2 || actual != expected {
            return Err(damaged());
        }
        with_durable_construction_roster_v1(slots, |held, contributions, context| {
            let gate = ArtifactGate {
                workspace: self,
                access,
                consent,
                material,
                proof,
                roster: &roster,
                action: PrivateWorkspaceActionV1::CheckpointExactOriginal,
                held: Some(held),
            };
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
            );
            match outcome {
                Err(error) => Err(error),
                Ok(outcome) => {
                    gate.check()
                        .map_err(|error| checkpoint_committed_error(error, &outcome.status))?;
                    Ok(outcome)
                }
            }
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
    ) -> Result<OriginalCheckpointOutcomeV2<'op, 'source>> {
        let before = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
            )?
            .load()?;
        let c = candidate(&before, candidate_id)?.clone();
        let input_digest = crate::candidates::private_request_digest(
            construction.context,
            &construction.contributions,
            construction.declarations,
        )?;
        let command = crate::context(
            access,
            key,
            "private_checkpoint_exact_original_v2",
            candidate_id,
            Some(revision),
            &json!({"local_input_digest":input_digest,"maximum_actions":limits.maximum_actions}),
        )?;
        let receipt_key = receipt_key(access, key)?;
        // Exact request lookup precedes ALL randomized construction. Permission
        // and storage errors never mean absence or authorize reconstruction.
        let existing = self
            .proof
            .status_for_key(&access.principal_id, key, &command.request_digest, proof)
            .map_err(job_error)?;
        if let Some(saved) = existing {
            let receipt = self
                .validate_original_lineage(&before, access, key, &saved)?
                .clone();
            if receipt.coordination_request_digest != command.request_digest
                || receipt.prepared_revision != revision.checked_add(1).ok_or_else(damaged)?
            {
                return Err(damaged());
            }
            let effect = PrivateWorkspaceEffectV2::new(
                self,
                access,
                consent,
                EffectV2::MetadataLink,
                command,
                receipt.prepared_revision,
            )?;
            if let Some(replayed) = effect.replay()? {
                self.validate_original_lineage(&before, access, key, &saved)?;
                return Ok(OriginalCheckpointOutcomeV2 {
                    status: status(&replayed),
                    attempt: None,
                });
            }
            crate::candidates::check_revision(&before, receipt.prepared_revision)?;
            if !c.proof_jobs.is_empty() {
                return Err(damaged());
            }
            let mut after = before.clone();
            upsert_link(&mut after, &saved)?;
            let linked = effect
                .commit(&before, after)
                .map_err(|e| original_checkpoint_error(e, &saved))?;
            return Ok(OriginalCheckpointOutcomeV2 {
                status: status(&linked),
                attempt: None,
            });
        }
        if !before.checkpoint_receipts.is_empty()
            || !c.proof_jobs.is_empty()
            || !before.durable_proposals_v1.is_empty()
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Original constructor history exists without its exact private checkpoint; preserve both journals and do not reconstruct",
            ));
        }
        crate::candidates::check_revision(&before, revision)?;
        crate::candidates::check_current_terms(&before.view, &c.proposal.manifest)?;
        let first = construction.declarations.first().ok_or_else(denied)?;
        if construction.declarations.len() != 2
            || construction
                .declarations
                .iter()
                .any(|d| d.purpose != first.purpose || d.retention_policy != first.retention_policy)
        {
            return Err(denied());
        }
        let proposal = c.verified_snapshot()?;
        let built = wholepact_protocol::construction::construct_proposal(
            &proposal,
            construction.context,
            construction.contributions,
            construction.declarations,
        )
        .map_err(|_| {
            ApiError::new(
                "CANDIDATE_VERIFICATION_FAILED",
                "Exact original local construction failed before private retention",
            )
        })?;
        if wholepact_protocol::inspect_candidate(&built.pczt_bytes)
            .map_err(|_| damaged())?
            .actions
            > limits.maximum_actions
        {
            return Err(denied());
        }
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
        if !proof.permits(&scope, LocalAction::RetainPrivateWitnesses) {
            return Err(denied());
        }
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
                .map_err(job_error)?,
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
        let prepare_command = crate::context(
            access,
            &format!("prepare-{receipt_key}"),
            "private_prepare_constructor_receipt_v2",
            candidate_id,
            Some(revision),
            &receipt,
        )?;
        let prepare = PrivateWorkspaceEffectV2::new(
            self,
            access,
            consent,
            EffectV2::ConstructorReceipt,
            prepare_command,
            revision,
        )?;
        let mut after = before.clone();
        after
            .checkpoint_receipts
            .insert(receipt_key.clone(), receipt.clone());
        let committed = prepare.commit(&before, after)?;
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
        let enqueue=self.proof.enqueue_original_once_v1(&scope,key,&built.pczt_bytes,&built.review_policy,limits,proof).map_err(|error| {
            let mut error=job_error(error);
            let category=error.details.get("private_original_job_error_v1").cloned();
            error.details=Box::new(json!({"constructor_receipt_created":true,"prepared_revision":prepared_revision,"coordination_request_digest":command.request_digest,
                "encrypted_checkpoint_status":"not_confirmed","journals_are_atomic_together":false,"private_original_job_error_v1":category})); error
        })?;
        let (saved, fresh) = enqueue.into_parts();
        let linked_before = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::CheckpointExactOriginal,
            )?
            .load()?;
        self.validate_original_lineage(&linked_before, access, key, &saved)?;
        let link = PrivateWorkspaceEffectV2::new(
            self,
            access,
            consent,
            EffectV2::MetadataLink,
            command,
            prepared_revision,
        )?;
        let mut linked_after = linked_before.clone();
        upsert_link(&mut linked_after, &saved)?;
        let linked = link
            .commit(&linked_before, linked_after)
            .map_err(|e| original_checkpoint_error(e, &saved))?;
        self.check(
            access,
            consent,
            PrivateWorkspaceActionV1::CheckpointExactOriginal,
        )
        .map_err(|error| checkpoint_committed_error(error, &status(&linked)))?;
        if !proof.permits(&scope, LocalAction::RetainPrivateWitnesses) {
            return Err(checkpoint_committed_error(denied(), &status(&linked)));
        }
        let attempt = match fresh {
            Some(enqueue) if !linked.replayed && enqueue.matches_source(&self.proof) => {
                Some(OriginalProofAttemptV2 {
                    constructor,
                    enqueue,
                    linked_revision: linked.record.revision,
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
    fn validate_original_lineage<'e>(
        &self,
        envelope: &'e Envelope,
        access: &Access,
        key: &str,
        summary: &JobSummary,
    ) -> Result<&'e crate::candidates::CheckpointReceipt> {
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
                != wholepact_proof_jobs::job_id_for_key(&access.principal_id, key)
                    .map_err(job_error)?
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
        let saved = self
            .engine
            .store
            .find_replay(&prepare)
            .map_err(crate::store_error)?
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
        let operation = self
            .engine
            .store
            .get_operation(&saved.operation_id)
            .map_err(crate::store_error)?
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
        // Consume the entire continuation BEFORE all fallible checks. Every
        // return, denial, panic or failed proof drops the only live correlation.
        let OriginalProofAttemptV2 {
            constructor,
            enqueue,
            linked_revision,
        } = attempt;
        if !std::ptr::eq(self, constructor.workspace)
            || !enqueue.matches_source(&self.proof)
            || revision != linked_revision
        {
            return Err(denied());
        }
        let before = self
            .operation(access, consent, PrivateWorkspaceActionV1::ProveOriginalOnce)?
            .load()?;
        let roster =
            self.checked_roster(access, &before, &constructor.receipt.candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::ProveOriginalOnce,
            held: None,
        };
        gate.check()?;
        let saved = self
            .proof
            .status_for_key(
                &access.principal_id,
                &constructor.original_key,
                &constructor.command.request_digest,
                &gate,
            )
            .map_err(job_error)?
            .ok_or_else(damaged)?;
        let receipt =
            self.validate_original_lineage(&before, access, &constructor.original_key, &saved)?;
        if receipt_key(access, &constructor.original_key)? != constructor.receipt_key
            || serde_json::to_value(receipt).map_err(|_| damaged())?
                != serde_json::to_value(&constructor.receipt).map_err(|_| damaged())?
            || enqueue.summary() != &saved
        {
            return Err(damaged());
        }
        crate::candidates::check_revision(&before, revision)?;
        let command = crate::context(
            access,
            key,
            "private_prove_original_once_v2",
            &saved.candidate_id,
            Some(revision),
            &(&saved.job_id, &constructor.command.request_digest),
        )?;
        let effect = PrivateWorkspaceEffectV2::new(
            self,
            access,
            consent,
            EffectV2::RecordOriginalProofOutcome,
            command,
            revision,
        )?;
        // There can be no lawful replay for a live newly minted continuation.
        if effect.replay()?.is_some() {
            return Err(damaged());
        }
        let summary = enqueue.run_original_queued_v1(&gate).map_err(|error| {
            let mut error = job_error(error);
            error.retryable = false;
            if let Some(details) = error.details.as_object_mut() {
                details.insert("original_proof_attempt_consumed".into(), json!(true));
                details.insert("inspect_original_journal".into(), json!(true));
            }
            error
        })?;
        gate.check()?;
        self.validate_original_lineage(&before, access, &constructor.original_key, &summary)?;
        let mut after = before.clone();
        upsert_link(&mut after, &summary)?;
        let result = effect
            .commit(&before, after)
            .map_err(|e| original_checkpoint_error(e, &summary))?;
        gate.check()?;
        Ok(status(&result))
    }
    fn load_original_verified(
        &self,
        envelope: &Envelope,
        access: &Access,
        candidate_id: &str,
        original_key: &str,
        proof: &dyn LocalProofConsent,
    ) -> Result<VerifiedCheckpoint> {
        let receipt = envelope
            .checkpoint_receipts
            .get(&receipt_key(access, original_key)?)
            .ok_or_else(damaged)?;
        if receipt.candidate_id != candidate_id {
            return Err(damaged());
        }
        let summary = self
            .proof
            .status_for_key(
                &access.principal_id,
                original_key,
                &receipt.coordination_request_digest,
                proof,
            )
            .map_err(job_error)?
            .ok_or_else(damaged)?;
        self.validate_original_lineage(envelope, access, original_key, &summary)?;
        let checkpoint = self
            .proof
            .load_verified(&access.principal_id, &summary.job_id, proof)
            .map_err(job_error)?;
        self.validate_original_lineage(envelope, access, original_key, checkpoint.summary())?;
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
        let before = self
            .operation(
                access,
                consent,
                PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            )?
            .load()?;
        let roster = self.checked_roster(access, &before, candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            held: None,
        };
        gate.check()?;
        let checkpoint = self.load_original_verified(
            &before,
            access,
            candidate_id,
            original_checkpoint_key,
            &gate,
        )?;
        let receipt = self
            .validate_original_lineage(
                &before,
                access,
                original_checkpoint_key,
                checkpoint.summary(),
            )?
            .clone();
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
        let effect = PrivateWorkspaceEffectV2::new(
            self,
            access,
            consent,
            EffectV2::FreezeVerifiedFixed,
            command,
            revision,
        )?;
        if effect.replay()?.is_some() {
            let identity = crate::durable_proposals_v1::read_private_fixed_v2(
                &before,
                access,
                &checkpoint,
                &receipt,
            )?;
            let output = self.verified_output(
                &before,
                access,
                original_checkpoint_key,
                &checkpoint,
                &identity,
                &gate,
            )?;
            gate.check()?;
            self.check(
                access,
                consent,
                PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            )?;
            return Ok(output);
        }
        crate::candidates::check_revision(&before, revision)?;
        let mut after = before.clone();
        let identity = crate::durable_proposals_v1::freeze_private_fixed_v2(
            &mut after,
            access,
            &checkpoint,
            &receipt,
        )?;
        gate.check()?;
        let result = effect.commit(&before, after)?;
        gate.check()?;
        self.check(
            access,
            consent,
            PrivateWorkspaceActionV1::FreezeVerifiedFixed,
        )?;
        let saved = decode_private_record(&result.record)?;
        let output = self.verified_output(
            &saved,
            access,
            original_checkpoint_key,
            &checkpoint,
            &identity,
            &gate,
        )?;
        gate.check()?;
        self.check(
            access,
            consent,
            PrivateWorkspaceActionV1::FreezeVerifiedFixed,
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
        let envelope = self
            .operation(access, consent, PrivateWorkspaceActionV1::ReadVerifiedFixed)?
            .load()?;
        let roster = self.checked_roster(access, &envelope, candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::ReadVerifiedFixed,
            held: None,
        };
        gate.check()?;
        let checkpoint = self.load_original_verified(
            &envelope,
            access,
            candidate_id,
            original_checkpoint_key,
            &gate,
        )?;
        let receipt = self.validate_original_lineage(
            &envelope,
            access,
            original_checkpoint_key,
            checkpoint.summary(),
        )?;
        let identity = crate::durable_proposals_v1::read_private_fixed_v2(
            &envelope,
            access,
            &checkpoint,
            receipt,
        )?;
        let output = self.verified_output(
            &envelope,
            access,
            original_checkpoint_key,
            &checkpoint,
            &identity,
            &gate,
        )?;
        gate.check()?;
        self.check(access, consent, PrivateWorkspaceActionV1::ReadVerifiedFixed)?;
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
        self.validate_original_lineage(&envelope, access, original_checkpoint_key, &summary)?;
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
        let before = self
            .operation(access, consent, PrivateWorkspaceActionV1::ReadVerifiedFixed)?
            .load()?;
        if before.view.candidates.len() != 1
            || before.durable_proposals_v1.len() != 1
            || before.checkpoint_receipts.len() != 1
        {
            return Err(damaged());
        }
        let candidate_id = before.view.candidates[0].candidate_id.clone();
        let receipt = before
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
        let key = original.command.idempotency_key.clone();
        let output =
            self.read_verified_fixed_v2(access, &candidate_id, &key, consent, proof, material)?;
        let after = self
            .operation(access, consent, PrivateWorkspaceActionV1::ReadVerifiedFixed)?
            .load()?;
        if crate::encode(&before)? != crate::encode(&after)? {
            return Err(damaged());
        }
        let roster = self.checked_roster(access, &after, &candidate_id, material)?;
        let gate = ArtifactGate {
            workspace: self,
            access,
            consent,
            material,
            proof,
            roster: &roster,
            action: PrivateWorkspaceActionV1::ReadVerifiedFixed,
            held: None,
        };
        let actual = self
            .proof
            .status_for_key(
                &access.principal_id,
                &key,
                &receipt.coordination_request_digest,
                &gate,
            )
            .map_err(job_error)?
            .ok_or_else(damaged)?;
        self.validate_original_lineage(&after, access, &key, &actual)?;
        let history = self.audit_exact_history(&after)?;
        let proof_history = self
            .proof
            .original_attempt_history_digest_v1(&access.principal_id, &actual.job_id, &gate)
            .map_err(job_error)?;
        if output.proof_event_history_digest != proof_history
            || output.logical_state_digest
                != commit_digest(
                    "wholepact:private-fixed-logical-state:v2",
                    &(&after, &actual, &history, &proof_history),
                )?
        {
            return Err(damaged());
        }
        gate.check()?;
        self.proof.check_current().map_err(job_error)?;
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
    ) -> Result<PrivateVerifiedFixedV2> {
        let summary = checkpoint.summary();
        let receipt = self.validate_original_lineage(envelope, access, key, summary)?;
        let history = self.audit_exact_history(envelope)?;
        let proof_history = self
            .proof
            .original_attempt_history_digest_v1(&access.principal_id, &summary.job_id, proof)
            .map_err(job_error)?;
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
        let events = self
            .engine
            .store
            .events_after(0, 9)
            .map_err(crate::store_error)?;
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
                .map_err(crate::store_error)?
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
                operation_v1::validate_delta(before, &envelope, purpose)?;
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
struct ObservationGate<'a, 'source, W> {
    workspace: &'a PrivateDurableCoordinatorV1<'source>,
    access: &'a Access,
    consent: &'a dyn LocalPrivateWorkspaceConsentV1,
    material: &'a dyn LocalDurableMaterialConsentV1,
    intake: &'a Intake,
    wallet: &'a W,
}
impl<W> ObservationGate<'_, '_, W> {
    fn check(&self) -> Result<()> {
        self.workspace.check(
            self.access,
            self.consent,
            PrivateWorkspaceActionV1::ObserveExactMaterial,
        )?;
        self.workspace.check_intake(
            self.access,
            self.intake,
            self.material,
            DurableMaterialActionV1::ReadForExactConstruction,
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
        self.check().is_ok()
            && self.wallet.permits(account, provider, purpose)
            && self.check().is_ok()
    }
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
}
impl ArtifactGate<'_, '_, '_> {
    fn check(&self) -> Result<()> {
        if let Some(held) = self.held {
            held.check_current()?;
        }
        // The proof mutex may already be held: deliberately no source.check_current here.
        self.workspace
            .check_without_proof_lock(self.access, self.consent, self.action)?;
        for intake in self.roster.owners.values() {
            self.workspace.check_intake(
                self.access,
                intake,
                self.material,
                DurableMaterialActionV1::ReadForExactConstruction,
            )?;
        }
        if let Some(held) = self.held {
            held.check_current()?;
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
        exact && self.check().is_ok() && self.proof.permits(scope, action) && self.check().is_ok()
    }
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
