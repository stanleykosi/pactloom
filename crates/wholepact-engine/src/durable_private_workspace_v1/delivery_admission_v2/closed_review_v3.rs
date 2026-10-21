//! One exact original allocation, closed recipient review, and one atomic export.
//! Revision observations detect changes; they are never cached consent/authority.
use super::*;
use crate::durable_construction_v1::{Roster, review_export_v3::{self, DurableReviewExportScopeV3, ExportIntentV3, LocalDurableReviewExportConsentV3}};
use std::time::Instant;
use wholepact_proof_jobs::OriginalProofReadRevisionV3;
use wholepact_signer::authority_bridge::durable_review_ipc_v3::{
    DurableDeliveryMaterialScopeRefV2, ImportedDurableReviewSessionV3,
    PreparedDurableReviewRecipientV3,
};
use wholepact_store::{OriginalPrivateRevisionPinV3, OriginalSourceReadRevisionPinV3};

pub(super) const EXPORT_EVENT_V3: &str = "private_durable_admission_review_disclosed_v3";
const EXPORT_COMMAND_V3: &str = "private_durable_admission_review_export_v3";

/// Actual immutable proof/math and transport custody. No raw getters, caller
/// construction, Clone, serialization or permission survives preparation.
pub struct PreparedPrivateDurableAdmissionDeliveryV3<'owner, 'source> {
    owner: &'owner PrivateDurableAdmissionCoordinatorV2<'source>,
    payload: PreparedDurableReviewPayloadV2,
    checkpoint: VerifiedCheckpoint,
    identity: FixedProposalIdentityV1,
    current: Envelope,
    history: History,
    roster: Roster,
    metadata_pin: OriginalPrivateRevisionPinV3<'owner>,
    root_pin: OriginalSourceReadRevisionPinV3<'owner>,
    proof_pin: OriginalProofReadRevisionV3<'source>,
    material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
}
pub struct ClosedPrivateDurableAdmissionReviewV3<'owner, 'source> {
    prepared: PreparedPrivateDurableAdmissionDeliveryV3<'owner, 'source>,
    recipient: PreparedDurableReviewRecipientV3,
    scope: DurableReviewExportScopeV3,
}
#[derive(Serialize)]
pub struct PrivateDurableAdmissionDeliveryV3 {
    pub revision: u64,
    pub replayed: bool,
    pub export_count: usize,
    pub export_history_digest: String,
}
/// Freshly reverified original source and strict V3 historical projections.
/// These records do not recover any native read, receive or admission owner.
#[derive(Serialize)]
pub struct PrivateDurableAdmissionStatusV3 {
    pub version: u16,
    pub source: PrivateDurableAdmissionStatusV2,
    pub review_exports: Vec<DurableReviewExportScopeV3>,
}
impl<'source> PrivateDurableAdmissionCoordinatorV2<'source> {
    /// The complete original audit and real proof verification precede every
    /// recipient/native action. A reopened source must take this path again.
    pub fn prepare_original_delivery_v3<'owner>(
        &'owner self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PreparedPrivateDurableAdmissionDeliveryV3<'owner, 'source>> {
        // Preliminary source-derived selectors are not verification evidence.
        let (initial, _) = self.check(access, consent)?;
        let candidate = initial.view.candidates.first().ok_or_else(damaged)?;
        let materials = self.original.stage_materials_v3(access, &initial, &candidate.candidate_id)?;
        let receipt = initial.checkpoint_receipts.values().next().ok_or_else(damaged)?;
        let scope = exact_fixed_v2::retained_review_scope_v3(candidate, receipt, &materials)?;
        let job = &candidate.proof_jobs.first().ok_or_else(damaged)?.job_id;
        let metadata_pin = self.original.engine.store.pin_original_revision_v3(self.original.source.agreement_id()).map_err(crate::store_error)?;
        let root_pin = self.original.source.engine.store.pin_original_source_read_revision_v3(self.original.source.agreement_id()).map_err(crate::store_error)?;
        let proof_pin = self.original.proof.pin_original_read_revision_v3(&access.principal_id, job, &scope).map_err(original_job_error_v2)?;
        // These actual same-connection observations bracket the full validation.
        let (current, history) = self.check(access, consent)?;
        let gate = ProofGate { owner: self, access, consent, proof, material, action: DurableMaterialActionV1::ReadForExactConstruction, cause: None };
        gate.check()?;
        let (checkpoint, _, identity) = self.verified(&history, access, &gate)?;
        // The pre-audit selector is not proof evidence. Join it to the actual
        // retained checkpoint loaded and verified from this SAME original
        // proof source before allowing the revision observation to guard bytes.
        if checkpoint.scope() != &scope || &checkpoint.summary().job_id != job {
            return Err(damaged());
        }
        let mappings = self.delivery_output_actions(access, &history, &checkpoint, None)?;
        let roster = original_roster_v2(&current)?;
        review_export_v3::validate_capacity(&roster)?;
        if roster.review_exports.len() + roster.review_exports_v3.len() >= MAX_EXPORT_INTENTS { return Err(capacity()); }
        let payload = DurableReviewPayloadV1 {
            version: 1,
            unsigned_pczt_hex: hex::encode(checkpoint.private_unsigned_pczt_bytes()),
            proved_pczt_hex: hex::encode(checkpoint.pczt_bytes()),
            contributions: roster.owners.values().map(|i| i.outbox.clone()).collect(),
            output_actions: mappings,
        }.into_prepared_v2().map_err(|_| damaged())?;
        let material_scopes = review_export_v3::material_scopes(&roster)?;
        gate.check()?;
        metadata_pin.check_current_v3().map_err(crate::store_error)?;
        root_pin.check_current_v3().map_err(crate::store_error)?;
        proof_pin.check_current_v3().map_err(original_job_error_v2)?;
        let prepared = PreparedPrivateDurableAdmissionDeliveryV3 { owner: self, payload, checkpoint, identity, current, history, roster, metadata_pin, root_pin, proof_pin, material_scopes };
        prepared.check_current_v3(access, consent, proof, material)?;
        Ok(prepared)
    }
    /// Reopening is a new full original-source/history/proof audit. Historical
    /// export metadata never reconstructs a recipient or mutation capability.
    pub fn read_original_fixed_v3(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
    ) -> Result<PrivateDurableAdmissionStatusV3> {
        self.read_original_fixed_checked_v3(access, consent, proof, material, |_, _| Ok(()))
    }
    /// Keep actual original revision observations and current read consent alive
    /// through a bounded local display. The borrowed checker is not authority
    /// and cannot outlive this source/read call or reconstruct a native grant.
    pub fn read_original_fixed_checked_v3(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        display: impl FnOnce(&PrivateDurableAdmissionStatusV3, &dyn Fn() -> Result<()>) -> Result<()>,
    ) -> Result<PrivateDurableAdmissionStatusV3> {
        let (initial, _) = self.check(access, consent)?;
        let candidate = initial.view.candidates.first().ok_or_else(damaged)?;
        let materials = self.original.stage_materials_v3(access, &initial, &candidate.candidate_id)?;
        let receipt = initial.checkpoint_receipts.values().next().ok_or_else(damaged)?;
        let scope = exact_fixed_v2::retained_review_scope_v3(candidate, receipt, &materials)?;
        let job = &candidate.proof_jobs.first().ok_or_else(damaged)?.job_id;
        let metadata_pin = self.original.engine.store.pin_original_revision_v3(self.original.source.agreement_id()).map_err(crate::store_error)?;
        let root_pin = self.original.source.engine.store.pin_original_source_read_revision_v3(self.original.source.agreement_id()).map_err(crate::store_error)?;
        let proof_pin = self.original.proof.pin_original_read_revision_v3(&access.principal_id, job, &scope).map_err(original_job_error_v2)?;
        let (current, history) = self.check(access, consent)?;
        let gate = ProofGate { owner: self, access, consent, proof, material, action: DurableMaterialActionV1::ReadForExactConstruction, cause: None };
        gate.check()?;
        let (checkpoint, key, identity) = self.verified(&history, access, &gate)?;
        if checkpoint.scope() != &scope || &checkpoint.summary().job_id != job {
            return Err(damaged());
        }
        let observation = Observation::new(Operation::ReadFixed);
        let fixed = self.original.verified_output_from_audited_prefix_v2(
            &history.prefix, access, &key, &checkpoint, &identity, &gate,
            &observation, history.prefix_digest.clone(),
        )?;
        let roster = original_roster_v2(&current)?;
        review_export_v3::validate_capacity(&roster)?;
        let review_exports = roster.review_exports_v3.values().map(|intent| intent.scope.clone()).collect();
        gate.check()?;
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest { return Err(damaged()); }
        metadata_pin.check_current_v3().map_err(crate::store_error)?;
        root_pin.check_current_v3().map_err(crate::store_error)?;
        proof_pin.check_current_v3().map_err(original_job_error_v2)?;
        let status = PrivateDurableAdmissionStatusV3 {
            version: 3,
            source: PrivateDurableAdmissionStatusV2 {
                fixed, export_history_digest: history.full_digest,
                export_count: history.export_revisions.len(), revision: current.view.revision,
            },
            review_exports,
        };
        let check = || check_live_v3(self, access, consent, proof, material,
            DurableMaterialActionV1::ReadForExactConstruction, checkpoint.scope(),
            &roster, &metadata_pin, &root_pin, &proof_pin);
        check()?;
        display(&status, &check)?;
        check()?;
        Ok(status)
    }
}
impl<'owner, 'source> PreparedPrivateDurableAdmissionDeliveryV3<'owner, 'source> {
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 { &self.identity }
    pub fn payload_digest(&self) -> &str { self.payload.payload_digest() }
    pub fn payload_length(&self) -> u64 { self.payload.payload_bytes() }
    pub fn material_scopes(&self) -> &[DurableDeliveryMaterialScopeRefV2] { &self.material_scopes }
    /// No original journal replay, proof verification, construction or encoding.
    pub fn check_current_v3(&self, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1) -> Result<()> {
        self.check_live(access, consent, proof, material, DurableMaterialActionV1::ReadForExactConstruction, &self.metadata_pin)
    }
    fn check_live(&self, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1, action: DurableMaterialActionV1, metadata: &OriginalPrivateRevisionPinV3<'_>) -> Result<()> {
        check_live_v3(self.owner, access, consent, proof, material, action, self.checkpoint.scope(), &self.roster, metadata, &self.root_pin, &self.proof_pin)
    }
    pub fn bind_prepared_recipient_v3(self, recipient: PreparedDurableReviewRecipientV3, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1) -> Result<ClosedPrivateDurableAdmissionReviewV3<'owner, 'source>> {
        self.check_current_v3(access, consent, proof, material)?;
        let scope = DurableReviewExportScopeV3 {
            schema_version: 3,
            principal_id: access.principal_id.clone(),
            proposal: self.identity.clone(),
            recipient: recipient.intent().clone(),
            sources: review_export_v1::sources(&self.roster)?,
            payload_digest: self.payload_digest().into(),
            payload_length: self.payload_length(),
        };
        review_export_v3::validate_recipient(&self.roster, &self.current.view.candidates[0], &scope)?;
        let operation = &scope.recipient.request.operation_id;
        if self.roster.review_exports.contains_key(operation) || self.roster.review_exports_v3.contains_key(operation) { return Err(denied()); }
        self.check_current_v3(access, consent, proof, material)?;
        Ok(ClosedPrivateDurableAdmissionReviewV3 { prepared: self, recipient, scope })
    }
}
#[allow(clippy::too_many_arguments)]
fn check_live_v3(
    owner: &PrivateDurableAdmissionCoordinatorV2<'_>, access: &Access,
    consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent,
    material: &dyn LocalDurableMaterialConsentV1, action: DurableMaterialActionV1,
    checkpoint: &CheckpointScope, roster: &Roster,
    metadata: &OriginalPrivateRevisionPinV3<'_>, root: &OriginalSourceReadRevisionPinV3<'_>,
    proof_pin: &OriginalProofReadRevisionV3<'_>,
) -> Result<()> {
    let pins = || -> Result<()> {
        metadata.check_current_v3().map_err(crate::store_error)?;
        root.check_current_v3().map_err(crate::store_error)?;
        proof_pin.check_current_v3().map_err(original_job_error_v2)
    };
    pins()?;
    if access.principal_id != owner.original.source.principal_id()
        || !consent.permits_source(&owner.original.scope)
        || !proof.permits(checkpoint, LocalAction::ReadPrivateArtifact)
    { return Err(denied()); }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| denied())?.as_secs();
    // These exact immutable scopes/intakes were validated under the pins. Check
    // CURRENT time and native permission; do not reparse/reverify their material.
    for intake in roster.owners.values() {
        let scope = &intake.outbox.request().scope;
        scope.check_valid_at(now).map_err(|_| denied())?;
        if !material.permits(scope, intake.outbox.material_digest(), action) { return Err(denied()); }
    }
    pins()
}
impl ClosedPrivateDurableAdmissionReviewV3<'_, '_> {
    pub fn scope(&self) -> &DurableReviewExportScopeV3 { &self.scope }
    pub fn check_current_v3(&self, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1) -> Result<()> {
        self.prepared.check_current_v3(access, consent, proof, material)
    }
    /// Consume both owners before fallible action admission. Fresh channel
    /// activation sends metadata only; actual bytes follow the durable append.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_v3(self, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1, export: &dyn LocalDurableReviewExportConsentV3, host_action_deadline: Instant) -> Result<(PrivateDurableAdmissionDeliveryV3, ImportedDurableReviewSessionV3)> {
        let Self { prepared, recipient, scope } = self;
        prepared.check_live(access, consent, proof, material, DurableMaterialActionV1::ExportForLocalNativeReview, &prepared.metadata_pin)?;
        if !export.permits(&scope) || Instant::now() >= host_action_deadline { return Err(denied()); }
        let fresh = recipient.activate(host_action_deadline).map_err(|_| denied())?;
        if fresh.intent() != &scope.recipient { return Err(denied()); }
        fresh.check_current().map_err(|_| denied())?;
        prepared.check_live(access, consent, proof, material, DurableMaterialActionV1::ExportForLocalNativeReview, &prepared.metadata_pin)?;
        let PreparedPrivateDurableAdmissionDeliveryV3 { owner, payload, checkpoint, identity: _, current: before, mut history, mut roster, metadata_pin, root_pin, proof_pin, material_scopes: _ } = prepared;
        let revision = before.view.revision;
        let command = export_command_v3(access, revision, &scope)?;
        let operation = scope.recipient.request.operation_id.clone();
        if history.export_revisions.contains_key(&operation) || roster.review_exports.len() + roster.review_exports_v3.len() >= MAX_EXPORT_INTENTS { return Err(denied()); }
        roster.review_exports_v3.insert(operation.clone(), ExportIntentV3 { scope: scope.clone(), exposure: ExportExposure::DisclosedOrUnknown });
        let mut after = before.clone();
        after.durable_construction_v1.insert(scope.proposal.proposal_id.clone(), serde_json::to_value(&roster).map_err(|_| damaged())?);
        after.view.revision = revision.checked_add(1).ok_or_else(damaged)?;
        after.view.updated_at = crate::now();
        if validate_export_delta_v3(&before, &after)? != scope { return Err(damaged()); }
        check_live_v3(owner, access, consent, proof, material, DurableMaterialActionV1::ExportForLocalNativeReview, checkpoint.scope(), &roster, &metadata_pin, &root_pin, &proof_pin)?;
        if !export.permits(&scope) || Instant::now() >= host_action_deadline { return Err(denied()); }
        fresh.check_current().map_err(|_| denied())?;
        let encoded = crate::encode(&after)?;
        // Existing Store transaction checks this exact consumed pin before
        // replay/CAS/write and returns a new pin ONLY after known success.
        let (saved, committed_pin) = owner.original.engine.store.update_original_agreement_pinned_restricted_v3(metadata_pin, &command, owner.original.source.agreement_id(), revision, encoded, EXPORT_EVENT_V3, &AdmissionCommitRestrictionV3(consent, fresh.original_delivery_deadline_v3())).map_err(|e| disclosure_unknown(crate::store_error(e)))?;
        let result = (|| {
            let check = || -> wholepact_signer::authority_bridge::Result<()> {
                check_live_v3(owner, access, consent, proof, material, DurableMaterialActionV1::ExportForLocalNativeReview, checkpoint.scope(), &roster, &committed_pin, &root_pin, &proof_pin).map_err(|_| BridgeError::Permission)?;
                if Instant::now() >= host_action_deadline || !export.permits(&scope) { return Err(BridgeError::Permission); }
                Ok(())
            };
            check().map_err(|_| denied())?;
            let actual = owner.original.engine.store.find_replay(&command).map_err(crate::store_error)?.ok_or_else(damaged)?;
            if actual.record != saved.record || actual.operation_id != saved.operation_id || actual.event_sequence != saved.event_sequence || saved.replayed { return Err(damaged()); }
            let events = owner.original.engine.store.events_after(revision, 2).map_err(crate::store_error)?;
            if events.len() != 1 { return Err(damaged()); }
            let event = &events[0];
            let retained = owner.original.engine.store.get_operation(&saved.operation_id).map_err(crate::store_error)?.ok_or_else(damaged)?;
            let retained_result: MutationResult = serde_json::from_value(retained.result.clone()).map_err(|_| damaged())?;
            if event.sequence != revision + 1 || event.aggregate_revision != revision + 1 || event.kind != EXPORT_EVENT_V3 || event.operation_id != saved.operation_id || event.aggregate_id != saved.record.id || event.aggregate_type != "agreement" || event.payload != serde_json::json!({"id":saved.record.id,"revision":revision+1}) || retained.kind != EXPORT_EVENT_V3 || retained.operation_id != saved.operation_id || retained.principal_id != access.principal_id || retained.resource_id != saved.record.id || retained.status != "succeeded" || retained_result != saved { return Err(damaged()); }
            history.rows.push((event.clone(), retained));
            let export_history_digest = digest("wholepact:private-admission-export-history:v2", &history.rows)?;
            check().map_err(|_| denied())?;
            let final_restriction = || {
                if consent.check_final_effect_restriction_v1(None) { Ok(()) }
                else { Err(BridgeError::Permission) }
            };
            let imported = fresh.deliver_prepared_restricted_v3(payload, &check, &final_restriction).map_err(|_| denied())?;
            check().map_err(|_| denied())?;
            Ok((PrivateDurableAdmissionDeliveryV3 { revision: saved.record.revision, replayed: false, export_count: history.export_revisions.len() + 1, export_history_digest }, imported))
        })();
        result.map_err(disclosure_unknown)
    }
}
pub(super) fn export_command_v3(access: &Access, revision: u64, scope: &DurableReviewExportScopeV3) -> Result<CommandContext> {
    scope.recipient.validate().map_err(|_| damaged())?;
    let key = format!("closed-admission-review-{}", digest("wholepact:private-admission-export-idempotency:v3", &scope.recipient.request.operation_id)?);
    crate::context(access, &key, EXPORT_COMMAND_V3, &scope.proposal.proposal_id, Some(revision), scope)
}
pub(super) fn validate_export_delta_v3(before: &Envelope, after: &Envelope) -> Result<DurableReviewExportScopeV3> {
    for e in [before, after] {
        operation_v1::validate_common_shape(e)?;
        crate::durable_construction_v1::validate_stored(e)?;
        crate::durable_proposals_v1::validate_private_fixed_v2(e)?;
    }
    if after.view.revision != before.view.revision.checked_add(1).ok_or_else(damaged)? || time::OffsetDateTime::parse(&after.view.updated_at, &time::format_description::well_known::Rfc3339).is_err() { return Err(damaged()); }
    let old = original_roster_v2(before)?;
    let new = original_roster_v2(after)?;
    review_export_v3::validate_capacity(&new)?;
    if new.owners.len() != 2 || new.review_exports_v3.len() != old.review_exports_v3.len() + 1 { return Err(damaged()); }
    let added: Vec<_> = new.review_exports_v3.iter().filter(|(k, _)| !old.review_exports_v3.contains_key(*k)).collect();
    if added.len() != 1 { return Err(damaged()); }
    let (id, intent) = added[0];
    if id != &intent.scope.recipient.request.operation_id || old.review_exports.contains_key(id) { return Err(damaged()); }
    let mut allowed = old.clone();
    allowed.review_exports_v3.insert(id.clone(), intent.clone());
    if serde_json::to_value(&allowed).map_err(|_| damaged())? != serde_json::to_value(&new).map_err(|_| damaged())? { return Err(damaged()); }
    let mut permitted = before.clone();
    permitted.view.revision = after.view.revision;
    permitted.view.updated_at = after.view.updated_at.clone();
    permitted.durable_construction_v1.insert(intent.scope.proposal.proposal_id.clone(), serde_json::to_value(&allowed).map_err(|_| damaged())?);
    if crate::encode(&permitted)? != crate::encode(after)? { return Err(damaged()); }
    Ok(intent.scope.clone())
}
