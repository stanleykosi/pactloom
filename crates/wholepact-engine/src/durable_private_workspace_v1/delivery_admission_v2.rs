//! Original-source, admission-only private delivery. There is deliberately no
//! conversion back to the precursor, generic Engine, raw Store or private bytes.
//! The immutable fixed prefix and the append-only export history are distinct.
use super::*;
use crate::Envelope;
use crate::durable_construction_v1::{
    DurableMaterialActionV1, LocalDurableMaterialConsentV1, original_roster_v2,
    review_export_v1::{
        self, DurableReviewExportScopeV1, ExportExposure, ExportIntent,
        LocalDurableReviewExportConsentV1, MAX_EXPORT_INTENTS,
    },
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, VerifiedCheckpoint};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer::authority_bridge::{
    BridgeError,
    durable_review_ipc_v1::{
        DurableReviewOutputActionV1, DurableReviewPayloadV1, PreparedDurableReviewDeliveryV1,
    },
};
use wholepact_store::{CommandContext, MutationResult};

const PREFIX_EVENTS: usize = 8;
const EXPORT_EVENT: &str = "private_durable_admission_review_disclosed_v2";
const EXPORT_COMMAND: &str = "private_durable_admission_review_export_v2";
const PREFIX_KINDS: [&str; PREFIX_EVENTS] = [
    "agreement.created",
    "private_exact_candidate_prepared_v2",
    "private_exact_material_retained_v2",
    "private_exact_material_retained_v2",
    "private_original_constructor_recorded_v2",
    "private_original_checkpoint_linked_v2",
    "private_original_proof_observed_v2",
    "private_verified_fixed_frozen_v2",
];

/// Distinct live original-source inspection permission. This is not old fixed
/// stage consent, financial admission, material export or proof-read permission.
/// The trusted Host must retain its genuine native/source owner for every call.
pub trait LocalPrivateDurableAdmissionConsentV2 {
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool;
}

/// Exclusive same-original owner. No Clone, serde, Deref or caller-data factory.
pub struct PrivateDurableAdmissionCoordinatorV2<'source> {
    original: PrivateDurableCoordinatorV1<'source>,
    // Exact authenticated original request contexts, never authority or keys.
    prefix_commands: BTreeMap<String, CommandContext>,
    seed_command: CommandContext,
}

/// Inert exact inspection metadata. No private artifact/outbox or capability.
#[derive(Serialize)]
pub struct PrivateDurableAdmissionInspectionV2 {
    workspace_scope: PrivateWorkspaceScopeV1,
    materials: Vec<PrivateFixedMaterialReviewV3>,
    checkpoint_scope: CheckpointScope,
    fixed_identity: FixedProposalIdentityV1,
    marker_digest: String,
    native_association_digest: String,
    metadata_origin: String,
    proof_origin: String,
    revision: u64,
    export_count: usize,
}
impl PrivateDurableAdmissionInspectionV2 {
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        &self.workspace_scope
    }
    pub fn materials(&self) -> &[PrivateFixedMaterialReviewV3] {
        &self.materials
    }
    pub fn checkpoint_scope(&self) -> &CheckpointScope {
        &self.checkpoint_scope
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.fixed_identity
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
    pub fn export_count(&self) -> usize {
        self.export_count
    }
}
#[derive(Serialize)]
pub struct PrivateDurableAdmissionStatusV2 {
    /// Calculated from actual saved event eight, never current state with its
    /// exports erased. This remains byte-identical to the completed precursor.
    pub fixed: PrivateVerifiedFixedV2,
    pub export_history_digest: String,
    pub export_count: usize,
    pub revision: u64,
}
#[derive(Serialize)]
pub struct PrivateDurableAdmissionDeliveryV2 {
    pub revision: u64,
    pub replayed: bool,
    pub export_count: usize,
    pub export_history_digest: String,
}
struct History {
    prefix: Envelope,
    prefix_digest: String,
    full_digest: String,
    export_revisions: BTreeMap<String, u64>,
}

impl<'source> PrivateDurableAdmissionCoordinatorV2<'source> {
    /// Read-only exact initialized source preflight, not an authority opener.
    /// Only the concrete combined-v4 Host publication/open path may use this.
    pub fn check_initialized_admission_original_v2(
        destination: &Path,
        key: &DatabaseKey,
        expected: [u8; 32],
    ) -> Result<()> {
        preflight_original_metadata_profile_v2(
            destination,
            key,
            expected,
            None,
            OriginalMetadataProfileV2::Admission,
        )?;
        original_commands(destination, key, expected)?;
        Ok(())
    }

    /// Only actual source owners and original anchored initialization evidence
    /// can open this profile. It never initializes or repairs metadata/proof.
    #[allow(clippy::too_many_arguments)]
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
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<Self> {
        crate::private_workspace_origin_v1::validate_association_digest(native_association_digest)?;
        let scope = scope(&source, destination, retention_policy)?;
        check_source(&source, access, &scope, consent)?;
        let observation = Observation::new(Operation::OpenOriginal);
        preflight_original_metadata_profile_v2(
            destination,
            key,
            expected_origin,
            Some(&observation),
            OriginalMetadataProfileV2::Admission,
        )?;
        let prefix_commands = original_commands(destination, key, expected_origin)?;
        let original = PrivateDurableCoordinatorV1::open_original_storage_v2(
            source,
            access,
            destination,
            key,
            expected_origin,
            scope,
            native_association_digest,
            proof,
            expected_proof_origin,
            &observation,
            OriginalMetadataProfileV2::Admission,
        )?;
        original.audit_original_seed_v1(access, plan, binding)?;
        let result = Self {
            original,
            prefix_commands,
            seed_command: binding.command.clone(),
        };
        result.check(access, consent)?;
        Ok(result)
    }
    pub fn workspace_scope(&self) -> &PrivateWorkspaceScopeV1 {
        &self.original.scope
    }
    pub fn original_origin(&self) -> [u8; 32] {
        self.original.origin
    }
    pub fn origin_marker_digest(&self) -> Result<String> {
        self.original.origin_marker_digest()
    }

    pub fn inspect_original_for_admission_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<PrivateDurableAdmissionInspectionV2> {
        let (current, history) = self.check(access, consent)?;
        let candidate = history.prefix.view.candidates.first().ok_or_else(damaged)?;
        let materials =
            self.original
                .stage_materials_v3(access, &current, &candidate.candidate_id)?;
        let receipt = history
            .prefix
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let checkpoint_scope =
            exact_fixed_v2::retained_review_scope_v3(candidate, receipt, &materials)?;
        let fixed_identity: FixedProposalIdentityV1 = serde_json::from_value(
            history
                .prefix
                .durable_proposals_v1
                .get(&candidate.candidate_id)
                .and_then(|v| v.get("identity"))
                .cloned()
                .ok_or_else(damaged)?,
        )
        .map_err(|_| damaged())?;
        let result = PrivateDurableAdmissionInspectionV2 {
            workspace_scope: self.original.scope.clone(),
            materials,
            checkpoint_scope,
            fixed_identity,
            marker_digest: self.origin_marker_digest()?,
            native_association_digest: self.original.marker.native_association_digest.clone(),
            metadata_origin: hex::encode(self.original.origin),
            proof_origin: hex::encode(self.original.proof_origin),
            revision: current.view.revision,
            export_count: history.export_revisions.len(),
        };
        if serde_json::to_vec(&result).map_err(|_| damaged())?.len() > 64 * 1024 {
            return Err(denied());
        }
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest {
            return Err(damaged());
        }
        Ok(result)
    }

    pub fn read_original_fixed_v2(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateDurableAdmissionStatusV2> {
        let (current, history) = self.check(access, consent)?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action: DurableMaterialActionV1::ReadForExactConstruction,
        };
        gate.check()?;
        let (checkpoint, key, identity) = self.verified(&history, access, &gate)?;
        let observation = Observation::new(Operation::ReadFixed);
        let fixed = self.original.verified_output_from_audited_prefix_v2(
            &history.prefix,
            access,
            &key,
            &checkpoint,
            &identity,
            &gate,
            &observation,
            history.prefix_digest.clone(),
        )?;
        gate.check()?;
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest {
            return Err(damaged());
        }
        Ok(PrivateDurableAdmissionStatusV2 {
            fixed,
            export_history_digest: history.full_digest,
            export_count: history.export_revisions.len(),
            revision: current.view.revision,
        })
    }

    /// Source-owned preview for the exact already prepared live recipient. The
    /// Host reviews this exact metadata, not a caller-supplied scope. Bytes stay
    /// private and are rebuilt/compared when the separately approved send runs.
    pub fn review_original_delivery_v2(
        &self,
        access: &Access,
        recipient: &PreparedDurableReviewDeliveryV1<'_>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<DurableReviewExportScopeV1> {
        recipient.check_current().map_err(|_| denied())?;
        let (_, history) = self.check(access, consent)?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action: DurableMaterialActionV1::ExportForLocalNativeReview,
        };
        let (_, scope) = self.payload(access, recipient, &history, &gate)?;
        gate.check()?;
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest {
            return Err(damaged());
        }
        recipient.check_current().map_err(|_| denied())?;
        Ok(scope)
    }

    /// Commit permanent DisclosedOrUnknown before invoking the only sealed
    /// private-byte transport. Retry identity and request revision are derived
    /// from actual retained history, never selected or renewed by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_original_for_admission_v2(
        &self,
        access: &Access,
        recipient: PreparedDurableReviewDeliveryV1<'_>,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        export: &dyn LocalDurableReviewExportConsentV1,
    ) -> Result<PrivateDurableAdmissionDeliveryV2> {
        recipient.check_current().map_err(|_| denied())?;
        let (before, history) = self.check(access, consent)?;
        let gate = ProofGate {
            owner: self,
            access,
            consent,
            proof,
            material,
            action: DurableMaterialActionV1::ExportForLocalNativeReview,
        };
        let (payload, scope) = self.payload(access, &recipient, &history, &gate)?;
        let delivery_gate = DeliveryGate {
            proof: &gate,
            scope: &scope,
            export,
        };
        delivery_gate.check(false)?;
        recipient.check_current().map_err(|_| denied())?;
        let mut roster = original_roster_v2(&before)?;
        let prior_revision = history
            .export_revisions
            .get(&scope.recipient.request.operation_id)
            .copied();
        let revision = prior_revision
            .map(|n| n - 1)
            .unwrap_or(before.view.revision);
        let command = export_command(access, revision, &scope)?;
        let saved = if let Some(saved_revision) = prior_revision {
            let retained = roster
                .review_exports
                .get(&scope.recipient.request.operation_id)
                .ok_or_else(damaged)?;
            if retained.scope != scope {
                return Err(denied());
            }
            let saved = self
                .original
                .engine
                .store
                .find_replay(&command)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            if saved.record.revision != saved_revision {
                return Err(damaged());
            }
            saved
        } else {
            if roster.review_exports.len() >= MAX_EXPORT_INTENTS {
                return Err(capacity());
            }
            if self
                .original
                .engine
                .store
                .find_replay(&command)
                .map_err(crate::store_error)?
                .is_some()
            {
                return Err(damaged());
            }
            roster.review_exports.insert(
                scope.recipient.request.operation_id.clone(),
                ExportIntent {
                    scope: scope.clone(),
                    exposure: ExportExposure::DisclosedOrUnknown,
                },
            );
            let mut after = before.clone();
            after.durable_construction_v1.insert(
                scope.proposal.proposal_id.clone(),
                serde_json::to_value(&roster).map_err(|_| damaged())?,
            );
            after.view.revision = revision.checked_add(1).ok_or_else(damaged)?;
            after.view.updated_at = crate::now();
            validate_export_delta(&before, &after)?;
            delivery_gate.check(false)?;
            recipient.check_current().map_err(|_| denied())?;
            // No private transport before this original Store transaction.
            self.original
                .engine
                .store
                .update_agreement(
                    &command,
                    self.original.source.agreement_id(),
                    revision,
                    crate::encode(&after)?,
                    EXPORT_EVENT,
                )
                .map_err(|error| disclosure_unknown(crate::store_error(error)))?
        };
        // Reload and authenticate the actual saved operation on fresh AND replay
        // paths; a successful mutation return alone is never send permission.
        let result = (|| {
            delivery_gate.check(true)?;
            let actual = self
                .original
                .engine
                .store
                .find_replay(&command)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            if actual.record != saved.record || actual.operation_id != saved.operation_id {
                return Err(damaged());
            }
            recipient.check_current().map_err(|_| denied())?;
            let check = || {
                delivery_gate
                    .check(true)
                    .map_err(|_| BridgeError::Permission)
            };
            recipient.deliver(&payload, &check).map_err(|_| denied())?;
            delivery_gate.check(true)?;
            let (current, history) = self.check(access, consent)?;
            Ok(PrivateDurableAdmissionDeliveryV2 {
                revision: current.view.revision,
                replayed: saved.replayed,
                export_count: history.export_revisions.len(),
                export_history_digest: history.full_digest,
            })
        })();
        result.map_err(disclosure_unknown)
    }

    fn verified(
        &self,
        history: &History,
        access: &Access,
        gate: &ProofGate<'_, '_>,
    ) -> Result<(VerifiedCheckpoint, String, FixedProposalIdentityV1)> {
        let candidate = history.prefix.view.candidates.first().ok_or_else(damaged)?;
        let receipt = history
            .prefix
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let key = receipt
            .original_request_v2
            .as_ref()
            .ok_or_else(damaged)?
            .command
            .idempotency_key
            .clone();
        let observation = Observation::new(Operation::ReadFixed);
        let checkpoint = self.original.load_original_verified(
            &history.prefix,
            access,
            &candidate.candidate_id,
            &key,
            gate,
            &observation,
        )?;
        let identity = crate::durable_proposals_v1::read_private_fixed_v2(
            &history.prefix,
            access,
            &checkpoint,
            receipt,
        )?;
        gate.check()?;
        Ok((checkpoint, key, identity))
    }
    fn payload(
        &self,
        access: &Access,
        recipient: &PreparedDurableReviewDeliveryV1<'_>,
        history: &History,
        gate: &ProofGate<'_, '_>,
    ) -> Result<(DurableReviewPayloadV1, DurableReviewExportScopeV1)> {
        gate.check()?;
        recipient.check_current().map_err(|_| denied())?;
        let (checkpoint, _, identity) = self.verified(history, access, gate)?;
        let roster = original_roster_v2(&history.prefix)?;
        let receipt = history
            .prefix
            .checkpoint_receipts
            .values()
            .next()
            .ok_or_else(damaged)?;
        let mappings = crate::durable_proposals_v1::original_review_output_actions_v2(
            &history.prefix,
            access,
            &checkpoint,
            receipt,
        )?;
        let payload = DurableReviewPayloadV1 {
            version: 1,
            unsigned_pczt_hex: hex::encode(checkpoint.private_unsigned_pczt_bytes()),
            proved_pczt_hex: hex::encode(checkpoint.pczt_bytes()),
            contributions: roster.owners.values().map(|i| i.outbox.clone()).collect(),
            output_actions: mappings
                .iter()
                .map(|m| DurableReviewOutputActionV1 {
                    output_id: m.output_id.clone(),
                    action_index: m.action_index,
                })
                .collect(),
        };
        let encoded = payload.encode().map_err(|_| damaged())?;
        let scope = DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: access.principal_id.clone(),
            proposal: identity,
            recipient: recipient.descriptor().clone(),
            sources: review_export_v1::sources(&roster)?,
            payload_digest: payload.digest().map_err(|_| damaged())?,
            payload_length: encoded.len().try_into().map_err(|_| damaged())?,
        };
        drop(encoded);
        review_export_v1::validate_recipient(&roster, &history.prefix.view.candidates[0], &scope)?;
        gate.check()?;
        recipient.check_current().map_err(|_| denied())?;
        Ok((payload, scope))
    }

    fn check(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<(Envelope, History)> {
        self.original
            .proof
            .check_current()
            .map_err(original_job_error_v2)?;
        if self.original.proof.origin_commitment() != self.original.proof_origin {
            return Err(damaged());
        }
        let result = self.check_without_proof_lock(access, consent)?;
        self.original
            .proof
            .check_current()
            .map_err(original_job_error_v2)?;
        Ok(result)
    }
    // Proof permission callbacks execute with its mutex held. This path checks
    // the actual independent source/metadata/material owners, never that mutex.
    fn check_without_proof_lock(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
    ) -> Result<(Envelope, History)> {
        let o = &self.original;
        check_source(&o.source, access, &o.scope, consent)?;
        if o.engine
            .store
            .verify_original_encrypted_destination(o.scope.protected_destination())
            .map_err(crate::store_error)?
            != o.origin
        {
            return Err(damaged());
        }
        let marker = crate::private_workspace_origin_v1::from_source(
            &o.source,
            access,
            &o.scope,
            &o.marker.native_association_digest,
            o.origin,
        )?;
        if marker != o.marker {
            return Err(damaged());
        }
        let record = o
            .engine
            .store
            .get_agreement(o.source.agreement_id())
            .map_err(crate::store_error)?
            .ok_or_else(damaged)?;
        let current = decode_private_record(&record)?;
        let history = self.audit(access, &current)?;
        // Always enforce BOTH original immutable material ceilings, including
        // during opening and inspection; historical availability is separate.
        o.stage_materials_v3(access, &current, &current.view.candidates[0].candidate_id)?;
        check_source(&o.source, access, &o.scope, consent)?;
        Ok((current, history))
    }
    fn audit(&self, access: &Access, current: &Envelope) -> Result<History> {
        let o = &self.original;
        let events = o
            .engine
            .store
            .events_after(0, (PREFIX_EVENTS + MAX_EXPORT_INTENTS + 1) as u32)
            .map_err(crate::store_error)?;
        if events.len() < PREFIX_EVENTS
            || events.len() > PREFIX_EVENTS + MAX_EXPORT_INTENTS
            || events.len() as u64 != current.view.revision
        {
            return Err(damaged());
        }
        let mut previous: Option<Envelope> = None;
        let mut history = Vec::with_capacity(events.len());
        let mut prefix = None;
        let mut export_revisions = BTreeMap::new();
        for (i, event) in events.iter().enumerate() {
            if event.aggregate_type != "agreement"
                || event.aggregate_id != o.source.agreement_id()
                || event.aggregate_revision != (i + 1) as u64
                || event.sequence != (i + 1) as u64
                || event.payload
                    != serde_json::json!({"id":o.source.agreement_id(),"revision":i + 1})
                || event.kind
                    != if i < PREFIX_EVENTS {
                        PREFIX_KINDS[i]
                    } else {
                        EXPORT_EVENT
                    }
            {
                return Err(damaged());
            }
            let operation = o
                .engine
                .store
                .get_operation(&event.operation_id)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            let saved: MutationResult =
                serde_json::from_value(operation.result.clone()).map_err(|_| damaged())?;
            if operation.kind != event.kind
                || operation.resource_id != event.aggregate_id
                || operation.principal_id != o.source.principal_id()
                || operation.status != "succeeded"
                || operation.operation_id != event.operation_id
                || saved.operation_id != event.operation_id
                || saved.event_sequence != event.sequence
                || saved.record.revision != event.aggregate_revision
                || saved.record.id != event.aggregate_id
                || saved.replayed
            {
                return Err(damaged());
            }
            let envelope = decode_private_record(&saved.record)?;
            if i < PREFIX_EVENTS {
                o.require_original_envelope(&envelope)?;
                if let Some(before) = &previous {
                    let purpose = match i {
                        1 => operation_v1::EffectV2::PrepareExactCandidate,
                        2 | 3 => operation_v1::EffectV2::RetainExactMaterial,
                        4 => operation_v1::EffectV2::ConstructorReceipt,
                        5 => operation_v1::EffectV2::MetadataLink,
                        6 => operation_v1::EffectV2::RecordOriginalProofOutcome,
                        7 => operation_v1::EffectV2::FreezeVerifiedFixed,
                        _ => return Err(damaged()),
                    };
                    operation_v1::validate_delta_after_checked_shapes_v2(
                        before, &envelope, purpose,
                    )?;
                } else if !envelope.view.candidates.is_empty()
                    || !envelope.durable_construction_v1.is_empty()
                    || !envelope.checkpoint_receipts.is_empty()
                    || !envelope.durable_proposals_v1.is_empty()
                {
                    return Err(damaged());
                }
                let command = self
                    .prefix_commands
                    .get(&event.operation_id)
                    .ok_or_else(damaged)?;
                validate_prefix_command(
                    i,
                    access,
                    &self.seed_command,
                    command,
                    previous.as_ref(),
                    &envelope,
                )?;
                let replay = o
                    .engine
                    .store
                    .find_replay(command)
                    .map_err(crate::store_error)?
                    .ok_or_else(damaged)?;
                if replay.record != saved.record
                    || replay.operation_id != saved.operation_id
                    || replay.event_sequence != saved.event_sequence
                {
                    return Err(damaged());
                }
                if i + 1 == PREFIX_EVENTS {
                    require_completed_prefix(&envelope)?;
                    prefix = Some(envelope.clone());
                }
            } else {
                o.require_original_identity_v2(&envelope)?;
                let before = previous.as_ref().ok_or_else(damaged)?;
                let scope = validate_export_delta(before, &envelope)?;
                if scope.principal_id != access.principal_id
                    || export_revisions
                        .insert(
                            scope.recipient.request.operation_id.clone(),
                            envelope.view.revision,
                        )
                        .is_some()
                {
                    return Err(damaged());
                }
                let command = export_command(access, before.view.revision, &scope)?;
                let replay = o
                    .engine
                    .store
                    .find_replay(&command)
                    .map_err(crate::store_error)?
                    .ok_or_else(damaged)?;
                if replay.record != saved.record
                    || replay.operation_id != saved.operation_id
                    || replay.event_sequence != saved.event_sequence
                {
                    return Err(damaged());
                }
            }
            history.push((event, operation));
            previous = Some(envelope);
        }
        if crate::encode(previous.as_ref().ok_or_else(damaged)?)? != crate::encode(current)? {
            return Err(damaged());
        }
        let prefix_digest = digest(
            "wholepact:private-exact-operation-history:v2",
            &history[..PREFIX_EVENTS],
        )?;
        let full_digest = digest("wholepact:private-admission-export-history:v2", &history)?;
        Ok(History {
            prefix: prefix.ok_or_else(damaged)?,
            prefix_digest,
            full_digest,
            export_revisions,
        })
    }
}

fn check_source(
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    access: &Access,
    scope: &PrivateWorkspaceScopeV1,
    consent: &dyn LocalPrivateDurableAdmissionConsentV2,
) -> Result<()> {
    source.check_current(access)?;
    if !consent.permits_source(scope) {
        return Err(denied());
    }
    source.check_current(access)
}
fn digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String> {
    // Serialize the borrowed slice as its canonical array; the original domain
    // remains exactly the precursor domain for the immutable eight-event prefix.
    wholepact_core::proposal::canonical_digest(domain, &value).map_err(Into::into)
}
fn require_completed_prefix(e: &Envelope) -> Result<()> {
    operation_v1::validate_shape(e)?;
    if e.view.revision != PREFIX_EVENTS as u64
        || e.view.progress != "awaiting_authorization"
        || e.view.candidates.len() != 1
        || e.checkpoint_receipts.len() != 1
        || e.durable_proposals_v1.len() != 1
    {
        return Err(damaged());
    }
    let roster = original_roster_v2(e)?;
    let c = &e.view.candidates[0];
    if roster.owners.len() != 2
        || !roster.review_exports.is_empty()
        || c.proof_jobs.len() != 1
        || c.proof_jobs[0].state != "succeeded"
        || c.proof_jobs[0].attempt != 1
        || !c.proof_jobs[0].proof_verified
        || c.proof_jobs[0].result_digest.is_none()
    {
        return Err(damaged());
    }
    Ok(())
}
fn export_command(
    access: &Access,
    revision: u64,
    scope: &DurableReviewExportScopeV1,
) -> Result<CommandContext> {
    scope.recipient.request.validate().map_err(|_| damaged())?;
    let key = format!(
        "admission-review-{}",
        digest(
            "wholepact:private-admission-export-idempotency:v2",
            &scope.recipient.request.operation_id
        )?
    );
    crate::context(
        access,
        &key,
        EXPORT_COMMAND,
        &scope.proposal.proposal_id,
        Some(revision),
        scope,
    )
}
/// Compare the entire typed envelope, admitting only one exact export-map
/// insertion and the maintained revision/time increment. No historical field is
/// removed or replaced to simulate a precursor. Existing exports stay exact.
fn validate_export_delta(
    before: &Envelope,
    after: &Envelope,
) -> Result<DurableReviewExportScopeV1> {
    for e in [before, after] {
        operation_v1::validate_common_shape(e)?;
        crate::durable_construction_v1::validate_stored(e)?;
        crate::durable_proposals_v1::validate_private_fixed_v2(e)?;
    }
    if after.view.revision != before.view.revision.checked_add(1).ok_or_else(damaged)?
        || time::OffsetDateTime::parse(
            &after.view.updated_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(damaged());
    }
    let old = original_roster_v2(before)?;
    let new = original_roster_v2(after)?;
    if new.owners.len() != 2 {
        return Err(damaged());
    }
    let (id, intent) = added_export(&old.review_exports, &new.review_exports)?;
    let mut allowed_roster = old.clone();
    allowed_roster.review_exports.insert(id, intent.clone());
    if serde_json::to_value(&allowed_roster).map_err(|_| damaged())?
        != serde_json::to_value(&new).map_err(|_| damaged())?
    {
        return Err(damaged());
    }
    let mut permitted = before.clone();
    permitted.view.revision = after.view.revision;
    permitted.view.updated_at = after.view.updated_at.clone();
    permitted.durable_construction_v1.insert(
        intent.scope.proposal.proposal_id.clone(),
        serde_json::to_value(&allowed_roster).map_err(|_| damaged())?,
    );
    if crate::encode(&permitted)? != crate::encode(after)? {
        return Err(damaged());
    }
    Ok(intent.scope.clone())
}

fn added_export(
    old: &BTreeMap<String, ExportIntent>,
    new: &BTreeMap<String, ExportIntent>,
) -> Result<(String, ExportIntent)> {
    if new.len() != old.len() + 1 || new.len() > MAX_EXPORT_INTENTS {
        return Err(damaged());
    }
    let added = new
        .iter()
        .filter(|(key, _)| !old.contains_key(*key))
        .collect::<Vec<_>>();
    if added.len() != 1 {
        return Err(damaged());
    }
    let (id, intent) = added[0];
    let mut expected = old.clone();
    expected.insert(id.clone(), intent.clone());
    if serde_json::to_value(&expected).map_err(|_| damaged())?
        != serde_json::to_value(new).map_err(|_| damaged())?
        || id != &intent.scope.recipient.request.operation_id
    {
        return Err(damaged());
    }
    Ok((id.clone(), intent.clone()))
}
struct ProofGate<'a, 'source> {
    owner: &'a PrivateDurableAdmissionCoordinatorV2<'source>,
    access: &'a Access,
    consent: &'a dyn LocalPrivateDurableAdmissionConsentV2,
    proof: &'a dyn LocalProofConsent,
    material: &'a dyn LocalDurableMaterialConsentV1,
    action: DurableMaterialActionV1,
}
impl ProofGate<'_, '_> {
    fn check(&self) -> Result<()> {
        let (current, _) = self
            .owner
            .check_without_proof_lock(self.access, self.consent)?;
        for intake in original_roster_v2(&current)?.owners.values() {
            self.owner
                .original
                .check_intake(self.access, intake, self.material, self.action)?;
        }
        self.owner
            .check_without_proof_lock(self.access, self.consent)?;
        Ok(())
    }
}
impl LocalProofConsent for ProofGate<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.check().is_ok() && self.proof.permits(scope, action) && self.check().is_ok()
    }
}
struct DeliveryGate<'a, 'source> {
    proof: &'a ProofGate<'a, 'source>,
    scope: &'a DurableReviewExportScopeV1,
    export: &'a dyn LocalDurableReviewExportConsentV1,
}
impl DeliveryGate<'_, '_> {
    fn check(&self, require_committed: bool) -> Result<()> {
        self.proof.check()?;
        let (current, _) = self
            .proof
            .owner
            .check(self.proof.access, self.proof.consent)?;
        let roster = original_roster_v2(&current)?;
        review_export_v1::validate_recipient(&roster, &current.view.candidates[0], self.scope)?;
        if review_export_v1::sources(&roster)? != self.scope.sources {
            return Err(damaged());
        }
        if require_committed
            && roster
                .review_exports
                .get(&self.scope.recipient.request.operation_id)
                .is_none_or(|i| i.scope != *self.scope)
        {
            return Err(damaged());
        }
        let materials = self.proof.owner.original.stage_materials_v3(
            self.proof.access,
            &current,
            &current.view.candidates[0].candidate_id,
        )?;
        let checkpoint_scope = exact_fixed_v2::retained_review_scope_v3(
            &current.view.candidates[0],
            current
                .checkpoint_receipts
                .values()
                .next()
                .ok_or_else(damaged)?,
            &materials,
        )?;
        if !self
            .proof
            .permits(&checkpoint_scope, LocalAction::ReadPrivateArtifact)
            || !self.export.permits(self.scope)
        {
            return Err(denied());
        }
        self.proof.check()
    }
}
fn capacity() -> ApiError {
    ApiError::new(
        "CONFLICT",
        "The bounded original review-export capacity is exhausted; retained exposure cannot be cleared",
    )
}
fn disclosure_unknown(mut cause: ApiError) -> ApiError {
    // Preserve the original cause; the caller must not report a rollback merely
    // because the source, peer or native approval expired after the commit.
    let original_code = cause.code.clone();
    cause.code = "DISCLOSURE_UNKNOWN".into();
    cause.retryable = false;
    cause.message = "The original review-export may be retained or disclosed; preserve its exact identity and audit the original history".into();
    operation_v1::merge_error_details_v2(
        &mut cause,
        &serde_json::json!({
            "original_code": original_code, "disclosure_state": "disclosed_or_unknown",
            "new_recipient_requires_new_review": true,
        }),
    );
    cause
}

fn original_commands(
    destination: &Path,
    key: &DatabaseKey,
    expected: [u8; 32],
) -> Result<BTreeMap<String, CommandContext>> {
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
    let mut statement = snapshot.connection().prepare(
        "SELECT principal_id,idempotency_key,request_digest,result FROM idempotency ORDER BY principal_id,idempotency_key LIMIT 17",
    ).map_err(|_| damaged())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| damaged())?;
    let mut commands = BTreeMap::new();
    let mut count = 0;
    for row in rows {
        count += 1;
        let (principal_id, idempotency_key, request_digest, encoded) =
            row.map_err(|_| damaged())?;
        if count > PREFIX_EVENTS + MAX_EXPORT_INTENTS || encoded.len() > 1024 * 1024 {
            return Err(damaged());
        }
        let saved: MutationResult = serde_json::from_str(&encoded).map_err(|_| damaged())?;
        // Duplicate/unknown fields and alternate encodings cannot disappear in
        // an intermediate Value before this canonical stored-result check.
        if serde_json::to_string(&saved).map_err(|_| damaged())? != encoded || saved.replayed {
            return Err(damaged());
        }
        if saved.record.revision <= PREFIX_EVENTS as u64 {
            let command = CommandContext {
                principal_id,
                idempotency_key,
                request_digest,
            };
            if commands.insert(saved.operation_id, command).is_some() {
                return Err(damaged());
            }
        }
    }
    if commands.len() != PREFIX_EVENTS {
        return Err(damaged());
    }
    snapshot.check_source_unchanged().map_err(|_| damaged())?;
    Ok(commands)
}
fn validate_prefix_command(
    index: usize,
    access: &Access,
    seed: &CommandContext,
    command: &CommandContext,
    before: Option<&Envelope>,
    after: &Envelope,
) -> Result<()> {
    let key = &command.idempotency_key;
    let expected = if index == 0 {
        seed.clone()
    } else {
        let before = before.ok_or_else(damaged)?;
        let c = after.view.candidates.first().ok_or_else(damaged)?;
        let receipt = after.checkpoint_receipts.values().next();
        match index {
            1 => crate::context(
                access,
                key,
                "private_prepare_exact_candidate_v2",
                &after.view.agreement.agreement_id,
                Some(before.view.revision),
                &crate::CandidateRequest {
                    manifest: c.proposal.manifest.clone(),
                    previous_candidate_id: None,
                },
            )?,
            2 | 3 => {
                let new = original_roster_v2(after)?;
                let old: crate::durable_construction_v1::Roster = before
                    .durable_construction_v1
                    .get(&c.candidate_id)
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|_| damaged())?
                    .unwrap_or_default();
                let added = new
                    .owners
                    .iter()
                    .filter(|(account, _)| !old.owners.contains_key(*account))
                    .collect::<Vec<_>>();
                if added.len() != 1 {
                    return Err(damaged());
                }
                let intake = added[0].1;
                crate::context(
                    access,
                    key,
                    "private_retain_exact_material_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(
                        &intake.metadata_origin,
                        intake.outbox.reference(),
                        intake.outbox.request_digest(),
                        intake.outbox.material_digest(),
                        &intake.signer_enrollment_reference,
                    ),
                )?
            }
            4 => {
                let receipt = receipt.ok_or_else(damaged)?;
                let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
                exact_fixed_v2::validate_original_request_v2(
                    receipt,
                    access,
                    &original.command.idempotency_key,
                )?;
                if key
                    != &format!(
                        "prepare-{}",
                        exact_fixed_v2::receipt_key(access, &original.command.idempotency_key)?
                    )
                {
                    return Err(damaged());
                }
                crate::context(
                    access,
                    key,
                    "private_prepare_constructor_receipt_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    receipt,
                )?
            }
            5 => {
                let receipt = receipt.ok_or_else(damaged)?;
                let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
                exact_fixed_v2::validate_original_request_v2(
                    receipt,
                    access,
                    &original.command.idempotency_key,
                )?;
                original.command.clone()
            }
            6 => {
                let receipt = receipt.ok_or_else(damaged)?;
                crate::context(
                    access,
                    key,
                    "private_prove_original_once_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(&receipt.job_id, &receipt.coordination_request_digest),
                )?
            }
            7 => {
                let receipt = receipt.ok_or_else(damaged)?;
                let original = receipt.original_request_v2.as_ref().ok_or_else(damaged)?;
                let link = c.proof_jobs.first().ok_or_else(damaged)?;
                let mut summary = serde_json::to_value(link).map_err(|_| damaged())?;
                let object = summary.as_object_mut().ok_or_else(damaged)?;
                object.remove("observed_at");
                object.remove("observation_source");
                crate::context(
                    access,
                    key,
                    "private_freeze_verified_fixed_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(
                        &original.command.idempotency_key,
                        &receipt.coordination_request_digest,
                        summary,
                    ),
                )?
            }
            _ => return Err(damaged()),
        }
    };
    if command.principal_id != access.principal_id
        || serde_json::to_value(command).map_err(|_| damaged())?
            != serde_json::to_value(expected).map_err(|_| damaged())?
    {
        return Err(damaged());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_signer::authority_bridge::{
        durable_construction_v1::DurableConstructionHistoryRequestV1,
        durable_review_ipc_v1::{DurableReviewDeliveryRequestV1, DurableReviewRecipientV1},
    };
    // Inert request data only. This cannot create a sealed recipient, native
    // consent, original coordinator, verified checkpoint or financial source.
    fn scope(operation: &str) -> DurableReviewExportScopeV1 {
        let h = "ab".repeat(32);
        let identity = FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: "synthetic".into(),
            agreement_id: "agreement".into(),
            obligation_id: "obligation".into(),
            proposal_id: "candidate".into(),
            revision: 1,
            expiry_height: 10,
            proposal_digest: h.clone(),
            manifest_digest: h.clone(),
            unsigned_artifact_digest: h.clone(),
            proved_artifact_digest: h.clone(),
            effects_commitment: h.clone(),
            policy_digest: h.clone(),
            review_binding: h.clone(),
            action_mapping_digest: h.clone(),
            anchor: h.clone(),
            proposal_binding: h.clone(),
        };
        DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: "operator".into(),
            proposal: identity,
            recipient: DurableReviewRecipientV1 {
                version: 1,
                request: DurableReviewDeliveryRequestV1 {
                    operation_id: operation.into(),
                    enrollment_ref: h.clone(),
                    accepted_manifest_ref: h.clone(),
                    own_disclosure: DurableConstructionHistoryRequestV1 {
                        operation_id: "original-material".into(),
                        expected_request_digest: h.clone(),
                    },
                    current_disclosure: None,
                    proposal_binding: h.clone(),
                },
                account_id: h.clone(),
                participant_id: "alice".into(),
                agreement_id: "agreement".into(),
                manifest_digest: h.clone(),
                provider_enrollment_reference: h.clone(),
                signer_process_instance: h.clone(),
                local_grant_id: h.clone(),
                local_channel_digest: h.clone(),
            },
            sources: vec![review_export_v1::DurableReviewSourceV1 {
                account_id: h.clone(),
                outbox_reference: h.clone(),
                request_digest: h.clone(),
                material_digest: h.clone(),
                scope_digest: h.clone(),
            }],
            payload_digest: h,
            payload_length: 123,
        }
    }
    fn intent(operation: &str) -> ExportIntent {
        ExportIntent {
            scope: scope(operation),
            exposure: ExportExposure::DisclosedOrUnknown,
        }
    }
    #[test]
    fn admission_owner_is_nominal_nonclone_and_nonserializable() {
        trait AmbiguousIfClone<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
        let _ = <PrivateDurableAdmissionCoordinatorV2<'static> as AmbiguousIfClone<_>>::marker;
        trait AmbiguousIfSerialize<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: ?Sized + Serialize> AmbiguousIfSerialize<u8> for T {}
        let _ = <PrivateDurableAdmissionCoordinatorV2<'static> as AmbiguousIfSerialize<_>>::marker;
        trait AmbiguousIfDeserialize<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
        impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<u8> for T {}
        let _ =
            <PrivateDurableAdmissionCoordinatorV2<'static> as AmbiguousIfDeserialize<_>>::marker;
    }
    #[test]
    fn admission_metadata_profile_preserves_precursor_eight_event_bound() {
        for revision in -1..=18 {
            assert_eq!(
                OriginalMetadataProfileV2::Precursor.accepts_revision(revision),
                (0..=8).contains(&revision)
            );
            assert_eq!(
                OriginalMetadataProfileV2::Admission.accepts_revision(revision),
                (8..=16).contains(&revision)
            );
        }
        assert_eq!(PREFIX_KINDS.len(), 8);
        assert_eq!(PREFIX_KINDS[7], "private_verified_fixed_frozen_v2");
        assert!(!PREFIX_KINDS.contains(&EXPORT_EVENT));
    }
    #[test]
    fn admission_export_request_binds_revision_recipient_payload_and_sources() {
        let access = Access {
            principal_id: "operator".into(),
            ..Access::default()
        };
        let original = scope("original-review");
        let command = export_command(&access, 8, &original).unwrap();
        assert!(command.idempotency_key.len() <= 128);
        assert_eq!(
            command.idempotency_key,
            export_command(&access, 9, &original)
                .unwrap()
                .idempotency_key
        );
        assert_ne!(
            command.request_digest,
            export_command(&access, 9, &original)
                .unwrap()
                .request_digest
        );
        let mut changes = Vec::new();
        let mut s = original.clone();
        s.payload_digest = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.payload_length += 1;
        changes.push(s);
        let mut s = original.clone();
        s.recipient.local_channel_digest = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.recipient.signer_process_instance = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.recipient.local_grant_id = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.recipient.request.accepted_manifest_ref = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.sources[0].material_digest = "cd".repeat(32);
        changes.push(s);
        let mut s = original.clone();
        s.proposal.proved_artifact_digest = "cd".repeat(32);
        changes.push(s);
        for changed in changes {
            assert_ne!(
                command.request_digest,
                export_command(&access, 8, &changed).unwrap().request_digest
            );
        }
        let long = scope(&"a".repeat(128));
        assert!(export_command(&access, 8, &long).is_ok());
    }
    #[test]
    fn admission_suffix_preserves_every_exposure_and_exact_eight_intent_cap() {
        let mut saved = BTreeMap::new();
        for i in 0..MAX_EXPORT_INTENTS {
            let id = format!("review-{i}");
            let mut next = saved.clone();
            next.insert(id.clone(), intent(&id));
            let (actual, _) = added_export(&saved, &next).unwrap();
            assert_eq!(actual, id);
            assert!(added_export(&next, &next).is_err());
            if i > 0 {
                let mut tampered = next.clone();
                tampered.get_mut("review-0").unwrap().scope.payload_length += 1;
                assert!(added_export(&saved, &tampered).is_err());
            }
            saved = next;
        }
        let mut ninth = saved.clone();
        ninth.insert("review-8".into(), intent("review-8"));
        assert!(added_export(&saved, &ninth).is_err());
        let mut replacement = saved.clone();
        replacement.remove("review-0");
        replacement.insert("review-other".into(), intent("review-other"));
        assert!(added_export(&saved, &replacement).is_err());
        let mut wrong_key = BTreeMap::new();
        wrong_key.insert("different".into(), intent("review"));
        assert!(added_export(&BTreeMap::new(), &wrong_key).is_err());
    }
    #[test]
    fn admission_exposure_cannot_decode_as_recalled_or_cancelled() {
        let encoded = serde_json::to_string(&intent("review")).unwrap();
        assert!(encoded.contains("disclosed_or_unknown"));
        for substitute in ["not_shared", "cancelled", "recalled", "acknowledged"] {
            assert!(
                serde_json::from_str::<ExportIntent>(
                    &encoded.replace("disclosed_or_unknown", substitute)
                )
                .is_err()
            );
        }
        let mut value = serde_json::to_value(intent("review")).unwrap();
        value["extra"] = true.into();
        assert!(serde_json::from_value::<ExportIntent>(value).is_err());
    }
    #[test]
    fn admission_prefix_digest_is_independent_of_export_suffix() {
        let prefix = (0..8)
            .map(|n| serde_json::json!({"original":n}))
            .collect::<Vec<_>>();
        let original = digest("wholepact:private-exact-operation-history:v2", &prefix).unwrap();
        let mut full = prefix.clone();
        let before = digest("wholepact:private-admission-export-history:v2", &full).unwrap();
        full.push(serde_json::json!({"export":"disclosed_or_unknown"}));
        assert_eq!(
            original,
            digest("wholepact:private-exact-operation-history:v2", &full[..8]).unwrap()
        );
        assert_ne!(
            before,
            digest("wholepact:private-admission-export-history:v2", &full).unwrap()
        );
    }
    #[test]
    fn admission_unknown_commit_keeps_cause_and_forbids_blind_retry() {
        let error = disclosure_unknown(ApiError::new("DISCLOSURE_DENIED", "expired after commit"));
        assert_eq!(error.code, "DISCLOSURE_UNKNOWN");
        assert!(!error.retryable);
        assert_eq!(error.details["original_code"], "DISCLOSURE_DENIED");
        assert_eq!(error.details["disclosure_state"], "disclosed_or_unknown");
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod request_history_tests {
    // Inert mathematical/source-row components only. No marked original,
    // native approval, sealed recipient, proof or coordinator is manufactured.
    use super::*;
    use crate::durable_construction_v1::{Intake, Roster};
    use crate::{
        CandidateRequest,
        candidates::{CheckpointReceipt, OriginalCheckpointRequestV2},
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wholepact_core::*;
    use wholepact_proof_jobs::{JobState, JobSummary};
    use wholepact_protocol::construction::{ConstructionContext, OwnedContribution, PROFILE_ID};
    use wholepact_protocol::durable_proposal_v1::canonical_durable_account_id;
    use wholepact_protocol::review::encode_testnet_receiver;
    use wholepact_signer::authority_bridge::durable_construction_v1::{
        DurableConstructionOutboxV1, DurableConstructionRequestV1, HistoricalConstructionMaterialV1,
    };
    use wholepact_signer::consent_journal::TransportIdentityBinding;
    use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
        ConstructionRecipientV1, ConstructionReviewerV1, DurableConstructionScopeV1, PURPOSE,
    };
    use wholepact_wallet::wallet::synthetic_scanned_contributions;
    fn checked<T, E>(r: std::result::Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("inert admission history component failed"),
        }
    }
    fn amount(n: u64) -> Amount {
        Amount::from_zatoshis(n).unwrap()
    }
    fn hash(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }
    struct Fixture {
        agreement: AgreementDraft,
        request: CandidateRequest,
        chain: ConstructionContext,
        packages: Vec<OwnedContribution>,
        account_ids: Vec<String>,
        selection: wholepact_wallet::wallet::SelectionContext,
    }
    fn fixture() -> Fixture {
        let (wallets, selection) = synthetic_scanned_contributions().unwrap();
        let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
        // The scanner fixture's owner-a/owner-b labels are not durable account
        // identities. Derive the same canonical IDs from the actual scanned FVKs
        // before constructing the candidate, policy, receipt, or proof.
        let account_ids: Vec<_> = wallets
            .iter()
            .map(|w| canonical_durable_account_id(w.fvk()))
            .collect();
        let agreement = AgreementDraft {
            schema_version: 1,
            agreement_id: "scanner-to-engine-synthetic".into(),
            obligation_id: "never-funded-obligation".into(),
            revision: 1,
            purpose: "Synthetic scanner to candidate qualification; no network or funds".into(),
            organizer_identity: "fixture-organizer".into(),
            network_profile_id: PROFILE_ID.into(),
            recipients: vec![Recipient {
                recipient_id: "fixture-recipient".into(),
                address: receiver.clone(),
                amount: amount(300_000),
                memo: None,
                instruction_provenance: "Synthetic owner receiver, not a live payment".into(),
            }],
            funding_policy: FundingPolicy::Exact {
                target: amount(300_000),
            },
            fee_policy: FeePolicy::ProRata,
            privacy_profile: PrivacyProfile {
                mode: PrivacyMode::DeclaredOperator,
                proving_operator: Some("synthetic-local-constructor".into()),
                dedicated_accounts_required: true,
            },
            coordination_deadline: None,
            confirmation_policy: ConfirmationPolicy::default(),
            extensions: vec![],
        };
        let participants: Vec<_> = wallets
            .iter()
            .enumerate()
            .map(|(i, w)| ParticipantAllocation {
                participant_id: format!("participant-{i}"),
                account_id: account_ids[i].clone(),
                contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
                fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
                fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
                maximum_net_debit: amount(w.requested_debit_zatoshis()),
                charges: vec![],
            })
            .collect();
        let mut inputs = vec![];
        let mut outputs = vec![ClaimedOutput {
            output_id: "recipient-output".into(),
            address: receiver,
            amount: amount(300_000),
            allocation: OutputAllocation::Recipient {
                recipient_id: "fixture-recipient".into(),
            },
        }];
        for (i, w) in wallets.iter().enumerate() {
            for n in w.notes() {
                inputs.push(ClaimedInput {
                    input_id: n.input_id.clone(),
                    participant_id: participants[i].participant_id.clone(),
                    account_id: account_ids[i].clone(),
                    amount: amount(n.note.value().inner()),
                    ownership_evidence_ref: None,
                });
            }
            outputs.push(ClaimedOutput {
                output_id: format!("change-{i}"),
                address: encode_testnet_receiver(&w.change_address()),
                amount: amount(w.selected_zatoshis() - w.requested_debit_zatoshis()),
                allocation: OutputAllocation::Return {
                    participant_id: participants[i].participant_id.clone(),
                    account_id: account_ids[i].clone(),
                    ownership_evidence_ref: None,
                },
            });
        }
        let request = CandidateRequest {
            manifest: ProposalManifest {
                agreement: agreement.clone(),
                participants: participants.clone(),
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: selection.tip_height + 30,
            },
            previous_candidate_id: None,
        };
        let chain = ConstructionContext {
            anchor: selection.anchor_root,
            anchor_height: selection.anchor_height,
            anchor_block_hash: selection.anchor_hash_protocol,
            target_height: selection.tip_height + 1,
        };
        let packages: Vec<_> = wallets
            .into_iter()
            .map(|w| {
                let mut contribution = w.into_contribution();
                contribution.account_id = canonical_durable_account_id(&contribution.fvk);
                contribution
            })
            .collect();
        Fixture {
            agreement,
            request,
            chain,
            packages,
            account_ids,
            selection,
        }
    }
    fn material(f: &Fixture, index: usize) -> HistoricalConstructionMaterialV1 {
        let owner = &f.packages[index];
        let notes: Vec<_> = owner.notes.iter().map(|n| {
                let mut fields = n.input_id.split(':');
                assert!(fields.next() == Some("ironwood"));
                let mut txid = checked(hex::decode(fields.next().unwrap_or("")));
                txid.reverse();
                let output_index = checked(fields.next().unwrap_or("").parse::<u16>());
                assert!(fields.next().is_none());
                json!({"input_id":n.input_id,"txid_protocol":hex::encode(txid),"output_index":output_index,
                    "recipient":hex::encode(n.note.recipient().to_raw_address_bytes()),
                    "value_zatoshis":n.note.value().inner(),"rho":hex::encode(n.note.rho().to_bytes()),
                    "rseed":hex::encode(n.note.rseed().as_bytes()),
                    "nullifier":hex::encode(n.note.nullifier(&owner.fvk).to_bytes()),
                    "commitment":hex::encode(orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes()),
                    "position":n.witness.position(),
                    "authentication_path":n.witness.auth_path().iter().map(|p|hex::encode(p.to_bytes())).collect::<Vec<_>>()})
            }).collect();
        let c = &f.selection;
        checked(HistoricalConstructionMaterialV1::decode(&checked(
            serde_json::to_vec(&json!({
                "version":1,"account_id":owner.account_id,"fvk_hex":hex::encode(owner.fvk.to_bytes()),
                "fvk_digest":hex::encode(Sha256::digest(owner.fvk.to_bytes())),
                "selected_zatoshis":owner.notes.iter().map(|n|n.note.value().inner()).sum::<u64>(),
                "requested_debit_zatoshis":f.request.manifest.participants[index].maximum_net_debit.as_zatoshis(),
                "change_address":hex::encode(owner.change_address.to_raw_address_bytes()),
                "birthday_height":c.anchor_height,
                "context":{"tip_height":c.tip_height,"tip_hash_protocol":hex::encode(c.tip_hash_protocol),
                    "anchor_height":c.anchor_height,"anchor_hash_protocol":hex::encode(c.anchor_hash_protocol),
                    "anchor_root":hex::encode(c.anchor_root)},
                "source":{"source_id":"inert-engine-math-component","endpoint":"https://component.invalid",
                    "trust_profile":"single_tls_provider_report_not_consensus","network":"test",
                    "branch_id":"0x77190ad9","lightwalletd_version":"synthetic-component",
                    "backend_subversion":"synthetic-no-backend","protocol_version":"synthetic-component-v1",
                    "request_started":1800000000u64,"observed_at":1800000001u64,"valid_until":1800000060u64},
                "notes":notes
            })),
        )))
    }
    fn outbox(
        proposal: &ProposalInput,
        material: HistoricalConstructionMaterialV1,
        index: usize,
        destination: &Path,
        valid_from: u64,
        valid_until: u64,
    ) -> DurableConstructionOutboxV1 {
        let grant = hash(0x20 + index as u8);
        let channel = hash(0x30 + index as u8);
        let grant_id = hash(0x40 + index as u8);
        let principal = "synthetic-local-constructor";
        let scope = DurableConstructionScopeV1 {
            version: 2,
            purpose: PURPOSE.into(),
            proposal: proposal.clone(),
            account_id: proposal.manifest.participants[index].account_id.clone(),
            participant_id: proposal.manifest.participants[index].participant_id.clone(),
            privacy_domain: "inert-private-component".into(),
            constructor: ConstructionRecipientV1 {
                principal_id: principal.into(),
                authenticated_local_grant_digest: grant.clone(),
            },
            prover: ConstructionRecipientV1 {
                principal_id: principal.into(),
                authenticated_local_grant_digest: grant.clone(),
            },
            reviewers: proposal
                .manifest
                .participants
                .iter()
                .map(|p| ConstructionReviewerV1::local_installed_signer(p.account_id.clone()))
                .collect(),
            protected_destination: destination.to_str().unwrap().into(),
            retention_policy: "temporary inert encrypted component".into(),
            valid_from_unix_seconds: valid_from,
            valid_until_unix_seconds: valid_until,
            minimum_confirmations: 1,
            maximum_scan_blocks: 100,
        };
        let verified = checked(Proposal::validate(proposal.clone()));
        let transport = TransportIdentityBinding::LocalProcess {
            transport_identity_id: grant_id.clone(),
            channel_key_digest: grant.clone(),
            channel_binding_digest: channel.clone(),
            uid: 42,
            pid: 100 + index as u32,
            process_instance: hash(0x50 + index as u8),
            signer_generation: 1,
            account_id: scope.account_id.clone(),
            agreement_id: proposal.manifest.agreement.agreement_id.clone(),
            participant_id: scope.participant_id.clone(),
            manifest_digest: verified.manifest_digest().into(),
        };
        let request = DurableConstructionRequestV1 {
            operation_id: format!("inert-math-operation-{index}"),
            enrollment_ref: hash(0x60 + index as u8),
            accepted_manifest_ref: hash(0x70 + index as u8),
            scope,
            material,
        };
        let request_digest = checked(request.digest());
        let material_digest = checked(request.material.digest());
        let review = hash(0x80 + index as u8);
        let entry = hash(0x90 + index as u8);
        let reference = checked(wholepact_core::proposal::canonical_digest(
            "wholepact:durable-construction-consent-outbox:v1",
            &(
                &request_digest,
                &material_digest,
                &review,
                &entry,
                &grant,
                &channel,
                &grant_id,
                &transport,
                Option::<serde_json::Value>::None,
            ),
        ));
        let value = checked(serde_json::from_value(
            json!({"request":request,"request_digest":request_digest,
                "material_digest":material_digest,"native_review_digest":review,"native_entry_digest":entry,
                "recipient_grant_digest":grant,"original_channel_digest":channel,"original_grant_id":grant_id,
                "recipient_transport":transport,"reference":reference}),
        ));
        let value: DurableConstructionOutboxV1 = value;
        checked(value.validate());
        value
    }
    fn advance(e: &Envelope) -> Envelope {
        let mut e = e.clone();
        e.view.revision += 1;
        e.view.updated_at = crate::now();
        e
    }
    struct SavedHistory {
        _dir: tempfile::TempDir,
        path: PathBuf,
        key: DatabaseKey,
        store: wholepact_store::Store,
        origin: [u8; 32],
        access: Access,
        envelopes: Vec<Envelope>,
        commands: Vec<CommandContext>,
        saved: Vec<MutationResult>,
    }
    fn saved_history() -> SavedHistory {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("inert-admission-history.sqlite");
        let key = DatabaseKey::from_bytes([143; 32]);
        let store = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
        let origin = store.verify_original_encrypted_destination(&path).unwrap();
        let access = Access {
            principal_id: "synthetic-local-constructor".into(),
            include_owned_agreements: true,
            ..Access::default()
        };
        let seed_engine = Engine::in_memory().unwrap();
        seed_engine
            .create(&access, "inert-admission-create", f.agreement.clone())
            .unwrap();
        let record = seed_engine
            .store
            .get_agreement(&f.agreement.agreement_id)
            .unwrap()
            .unwrap();
        let mut seed = crate::decode_unprojected(&record).unwrap();
        seed.terms_editing_origin = false;
        seed.view.roster_selected = true;
        seed.view.progress = "preparing_proposal".into();
        assert!(seed.private_workspace_origin_v1.is_none());
        let seed_command = CommandContext::for_request(
            &access.principal_id,
            "inert-admission-seed",
            &json!({"inert_seed":true}),
        )
        .unwrap();
        let mut commands = vec![seed_command];
        let mut envelopes = vec![seed];
        let mut candidate = advance(&envelopes[0]);
        candidate
            .view
            .candidates
            .push(crate::candidates::build_exact_candidate_v2(f.request.clone()).unwrap());
        commands.push(
            crate::context(
                &access,
                "inert-admission-candidate",
                "private_prepare_exact_candidate_v2",
                &f.agreement.agreement_id,
                Some(1),
                &f.request,
            )
            .unwrap(),
        );
        envelopes.push(candidate);
        let c = envelopes[1].view.candidates[0].clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut roster = Roster::default();
        for i in 0..2 {
            let intake = Intake {
                schema_version: 1,
                principal_id: access.principal_id.clone(),
                metadata_origin: hex::encode(origin),
                signer_enrollment_reference: hash(0xa0 + i as u8),
                signer_process_instance: hash(0xb0 + i as u8),
                outbox: outbox(&c.proposal, material(&f, i), i, &path, now - 1, now + 3599),
            };
            let before = envelopes.last().unwrap();
            commands.push(
                crate::context(
                    &access,
                    &format!("inert-admission-intake-{i}"),
                    "private_retain_exact_material_v2",
                    &c.candidate_id,
                    Some(before.view.revision),
                    &(
                        &intake.metadata_origin,
                        intake.outbox.reference(),
                        intake.outbox.request_digest(),
                        intake.outbox.material_digest(),
                        &intake.signer_enrollment_reference,
                    ),
                )
                .unwrap(),
            );
            roster
                .owners
                .insert(intake.outbox.request().scope.account_id.clone(), intake);
            let mut after = advance(before);
            after.durable_construction_v1.insert(
                c.candidate_id.clone(),
                serde_json::to_value(&roster).unwrap(),
            );
            envelopes.push(after);
        }
        let original_key = "inert-admission-original-checkpoint";
        let original_command = crate::context(
            &access,
            original_key,
            "private_checkpoint_exact_original_v2",
            &c.candidate_id,
            Some(4),
            &json!({"local_input_digest":hash(0xc1),"maximum_actions":8}),
        )
        .unwrap();
        let receipt = CheckpointReceipt {
            original_request_v2: Some(OriginalCheckpointRequestV2 {
                command: original_command.clone(),
                expected_revision: 4,
                local_input_digest: hash(0xc1),
                maximum_actions: 8,
            }),
            action_mappings_v1: Some(json!({"inputs":[],"outputs":[]})),
            job_id: wholepact_proof_jobs::job_id_for_key(&access.principal_id, original_key)
                .unwrap(),
            scope_digest: hash(0xc2),
            principal_id: access.principal_id.clone(),
            candidate_id: c.candidate_id.clone(),
            manifest_digest: c.manifest_digest.clone(),
            coordination_request_digest: original_command.request_digest.clone(),
            artifact_digest: hash(0xc3),
            review_binding: hash(0xc4),
            effects_commitment: hash(0xc5),
            prepared_revision: 5,
        };
        let index = exact_fixed_v2::receipt_key(&access, original_key).unwrap();
        commands.push(
            crate::context(
                &access,
                &format!("prepare-{index}"),
                "private_prepare_constructor_receipt_v2",
                &c.candidate_id,
                Some(4),
                &receipt,
            )
            .unwrap(),
        );
        let mut after = advance(envelopes.last().unwrap());
        after.checkpoint_receipts.insert(index, receipt.clone());
        envelopes.push(after);
        let mut summary = JobSummary {
            job_id: receipt.job_id.clone(),
            scope_digest: receipt.scope_digest.clone(),
            candidate_id: c.candidate_id.clone(),
            state: JobState::Queued,
            attempt: 0,
            input_digest: receipt.artifact_digest.clone(),
            manifest_digest: c.manifest_digest.clone(),
            effects_commitment: receipt.effects_commitment.clone(),
            coordination_request_digest: original_command.request_digest.clone(),
            result_digest: None,
            review_binding: receipt.review_binding.clone(),
            encrypted_checkpoint_created: true,
            proof_verified: false,
            chain_validated: false,
            authorization_allowed: false,
            distribution_allowed: false,
        };
        let mut after = advance(envelopes.last().unwrap());
        crate::proof_jobs::upsert_link(&mut after, &summary).unwrap();
        commands.push(original_command.clone());
        envelopes.push(after);
        commands.push(
            crate::context(
                &access,
                "inert-admission-proof",
                "private_prove_original_once_v2",
                &c.candidate_id,
                Some(6),
                &(&summary.job_id, &original_command.request_digest),
            )
            .unwrap(),
        );
        summary.state = JobState::Succeeded;
        summary.attempt = 1;
        summary.proof_verified = true;
        summary.result_digest = Some(hash(0xc6));
        let mut after = advance(envelopes.last().unwrap());
        crate::proof_jobs::upsert_link(&mut after, &summary).unwrap();
        envelopes.push(after);
        commands.push(
            crate::context(
                &access,
                "inert-admission-freeze",
                "private_freeze_verified_fixed_v2",
                &c.candidate_id,
                Some(7),
                &(original_key, &receipt.coordination_request_digest, &summary),
            )
            .unwrap(),
        );
        let identity = FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: PROFILE_ID.into(),
            agreement_id: f.agreement.agreement_id.clone(),
            obligation_id: f.agreement.obligation_id.clone(),
            proposal_id: c.candidate_id.clone(),
            revision: 1,
            expiry_height: f.request.manifest.expiry_height,
            proposal_digest: c.proposal_digest.clone(),
            manifest_digest: c.manifest_digest.clone(),
            unsigned_artifact_digest: receipt.artifact_digest.clone(),
            proved_artifact_digest: hash(0xc6),
            effects_commitment: receipt.effects_commitment.clone(),
            policy_digest: hash(0xc7),
            review_binding: receipt.review_binding.clone(),
            action_mapping_digest: hash(0xc8),
            anchor: hash(0xc9),
            proposal_binding: hash(0xca),
        };
        let mut after = advance(envelopes.last().unwrap());
        after.view.progress = "awaiting_authorization".into();
        after.durable_proposals_v1.insert(c.candidate_id.clone(),json!({"schema_version":1,"principal_id":access.principal_id,
            "proof_job_id":summary.job_id,"identity":identity,"mappings":receipt.action_mappings_v1,"intakes":{},"union":null}));
        envelopes.push(after);
        let mut saved = Vec::new();
        for (i, e) in envelopes.iter().enumerate() {
            operation_v1::validate_shape(e).unwrap();
            validate_prefix_command(
                i,
                &access,
                &commands[0],
                &commands[i],
                i.checked_sub(1).map(|n| &envelopes[n]),
                e,
            )
            .unwrap();
            if i == 0 {
                saved.push(
                    store
                        .create_agreement(
                            &commands[i],
                            &f.agreement.agreement_id,
                            crate::encode(e).unwrap(),
                        )
                        .unwrap(),
                );
            } else {
                saved.push(
                    store
                        .update_agreement(
                            &commands[i],
                            &f.agreement.agreement_id,
                            i as u64,
                            crate::encode(e).unwrap(),
                            PREFIX_KINDS[i],
                        )
                        .unwrap(),
                );
            }
        }
        require_completed_prefix(envelopes.last().unwrap()).unwrap();
        SavedHistory {
            _dir: dir,
            path,
            key,
            store,
            origin,
            access,
            envelopes,
            commands,
            saved,
        }
    }
    #[test]
    fn admission_original_requests_reconstruct_all_eight_saved_contexts() {
        let f = saved_history();
        let read = original_commands(&f.path, &f.key, f.origin).unwrap();
        assert_eq!(read.len(), 8);
        for i in 0..8 {
            let command = read.get(&f.saved[i].operation_id).unwrap();
            assert_eq!(
                serde_json::to_value(command).unwrap(),
                serde_json::to_value(&f.commands[i]).unwrap()
            );
            assert_eq!(
                f.store.find_replay(command).unwrap().unwrap().record,
                f.saved[i].record
            );
            let before = i.checked_sub(1).map(|n| &f.envelopes[n]);
            let mut changed = command.clone();
            changed.request_digest = hash(0xdd);
            assert!(
                validate_prefix_command(
                    i,
                    &f.access,
                    &f.commands[0],
                    &changed,
                    before,
                    &f.envelopes[i]
                )
                .is_err()
            );
            if i > 0 {
                let mut prior = before.unwrap().clone();
                prior.view.revision += 1;
                if i != 5 {
                    assert!(
                        validate_prefix_command(
                            i,
                            &f.access,
                            &f.commands[0],
                            command,
                            Some(&prior),
                            &f.envelopes[i]
                        )
                        .is_err()
                    );
                }
            }
        }
        for i in [0, 4, 5] {
            let mut command = f.commands[i].clone();
            command.idempotency_key.push('x');
            assert!(
                validate_prefix_command(
                    i,
                    &f.access,
                    &f.commands[0],
                    &command,
                    i.checked_sub(1).map(|n| &f.envelopes[n]),
                    &f.envelopes[i]
                )
                .is_err()
            );
        }
        let mut mapping = f.envelopes[4].clone();
        mapping
            .checkpoint_receipts
            .values_mut()
            .next()
            .unwrap()
            .action_mappings_v1 =
            Some(json!({"inputs":[],"outputs":[{"output_id":"changed","action_index":0}]}));
        assert!(
            validate_prefix_command(
                4,
                &f.access,
                &f.commands[0],
                &f.commands[4],
                Some(&f.envelopes[3]),
                &mapping
            )
            .is_err()
        );
        let mut summary = f.envelopes[7].clone();
        summary.view.candidates[0].proof_jobs[0].result_digest = Some(hash(0xee));
        assert!(
            validate_prefix_command(
                7,
                &f.access,
                &f.commands[0],
                &f.commands[7],
                Some(&f.envelopes[6]),
                &summary
            )
            .is_err()
        );
        assert!(original_commands(&f.path, &f.key, [0; 32]).is_err());
    }
    #[test]
    fn admission_real_saved_suffix_changes_only_export_history_not_prefix() {
        use wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1;
        use wholepact_signer::authority_bridge::durable_review_ipc_v1::{
            DurableReviewDeliveryRequestV1, DurableReviewRecipientV1,
        };
        let f = saved_history();
        let before = f.envelopes.last().unwrap();
        let mut roster = original_roster_v2(before).unwrap();
        let own = roster.owners.values().next().unwrap();
        let identity: FixedProposalIdentityV1 = serde_json::from_value(
            before.durable_proposals_v1.values().next().unwrap()["identity"].clone(),
        )
        .unwrap();
        let scope = DurableReviewExportScopeV1 {
            schema_version: 1,
            principal_id: f.access.principal_id.clone(),
            proposal: identity.clone(),
            recipient: DurableReviewRecipientV1 {
                version: 1,
                request: DurableReviewDeliveryRequestV1 {
                    operation_id: "inert-exact-export".into(),
                    enrollment_ref: own.outbox.request().enrollment_ref.clone(),
                    accepted_manifest_ref: own.outbox.request().accepted_manifest_ref.clone(),
                    own_disclosure: DurableConstructionHistoryRequestV1 {
                        operation_id: own.outbox.request().operation_id.clone(),
                        expected_request_digest: own.outbox.request_digest().into(),
                    },
                    current_disclosure: None,
                    proposal_binding: identity.proposal_binding.clone(),
                },
                account_id: own.outbox.request().scope.account_id.clone(),
                participant_id: own.outbox.request().scope.participant_id.clone(),
                agreement_id: identity.agreement_id.clone(),
                manifest_digest: identity.manifest_digest.clone(),
                provider_enrollment_reference: hash(1),
                signer_process_instance: hash(2),
                local_grant_id: hash(3),
                local_channel_digest: hash(4),
            },
            sources: review_export_v1::sources(&roster).unwrap(),
            payload_digest: hash(5),
            payload_length: 123,
        };
        roster.review_exports.insert(
            scope.recipient.request.operation_id.clone(),
            ExportIntent {
                scope: scope.clone(),
                exposure: ExportExposure::DisclosedOrUnknown,
            },
        );
        let mut after = advance(before);
        after.durable_construction_v1.insert(
            identity.proposal_id.clone(),
            serde_json::to_value(roster).unwrap(),
        );
        assert_eq!(
            validate_export_delta(before, &after)
                .unwrap()
                .payload_digest,
            scope.payload_digest
        );
        assert!(operation_v1::validate_shape(&after).is_err());
        let command = export_command(&f.access, 8, &scope).unwrap();
        f.store
            .update_agreement(
                &command,
                &identity.agreement_id,
                8,
                crate::encode(&after).unwrap(),
                EXPORT_EVENT,
            )
            .unwrap();
        assert_eq!(
            original_commands(&f.path, &f.key, f.origin).unwrap().len(),
            8
        );
        assert_eq!(
            f.store.find_replay(&f.commands[7]).unwrap().unwrap().record,
            f.saved[7].record
        );
        assert!(
            PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(
                &f.path, &f.key, f.origin
            )
            .is_err()
        );
        PrivateDurableAdmissionCoordinatorV2::check_initialized_admission_original_v2(
            &f.path, &f.key, f.origin,
        )
        .unwrap();
        let mut altered = after.clone();
        altered
            .checkpoint_receipts
            .values_mut()
            .next()
            .unwrap()
            .artifact_digest = hash(6);
        assert!(validate_export_delta(before, &altered).is_err());
        let mut altered = after.clone();
        altered.view.candidates[0].proof_jobs[0].result_digest = Some(hash(6));
        assert!(validate_export_delta(before, &altered).is_err());
        let mut altered = after;
        altered.view.agreement.purpose.push('x');
        assert!(validate_export_delta(before, &altered).is_err());
    }
}
