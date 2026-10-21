//! Coordinated-only original recipient. Shares source/payload/pins and the exact
//! transactional export kernel, never an installed-native authority or intent.
use super::*;
use crate::durable_construction_v1::review_export_coordinated_v1::{self, CoordinatedDurableReviewExportScopeV1, CoordinatedExportIntentV1, LocalCoordinatedDurableReviewExportConsentV1};
use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::{PreparedCoordinatedDurableReviewRecipientV1, FreshCoordinatedDurableReviewDeliveryV1, ImportedCoordinatedDurableReviewSessionV1};

pub(in super::super) const COORDINATED_EXPORT_EVENT_V1: &str = "private_durable_admission_coordinated_review_disclosed_v1";
const COORDINATED_EXPORT_COMMAND_V1: &str = "private_durable_admission_coordinated_review_export_v1";

pub struct ClosedCoordinatedPrivateDurableAdmissionReviewV1<'owner, 'source> {
    prepared: PreparedPrivateDurableAdmissionDeliveryV3<'owner, 'source>,
    recipient: PreparedCoordinatedDurableReviewRecipientV1,
    scope: CoordinatedDurableReviewExportScopeV1,
}
impl<'owner, 'source> PreparedPrivateDurableAdmissionDeliveryV3<'owner, 'source> {
    /// Exact inert original-capture selector from the SAME audited roster that
    /// supplied this payload. It grants no read/disclosure and cannot recover
    /// source or recipient authority; current source/pins are rechecked at bind.
    pub fn original_disclosure_selector_coordinated_v1(&self, account: &str, participant: &str) -> Result<wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1> {
        let intake = self.roster.owners.get(account).ok_or_else(denied)?;
        if intake.outbox.request().scope.participant_id != participant { return Err(denied()); }
        Ok(wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1 {
            operation_id: intake.outbox.request().operation_id.clone(),
            expected_request_digest: intake.outbox.request_digest().to_owned(),
        })
    }
    pub fn bind_prepared_coordinated_recipient_v1(self, recipient: PreparedCoordinatedDurableReviewRecipientV1, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1) -> Result<ClosedCoordinatedPrivateDurableAdmissionReviewV1<'owner, 'source>> {
        self.check_current_v3(access, consent, proof, material)?;
        if !self.roster.review_exports.is_empty() || !self.roster.review_exports_v3.is_empty() { return Err(denied()); }
        let scope = CoordinatedDurableReviewExportScopeV1 {
            schema_version: 1, principal_id: access.principal_id.clone(),
            proposal: self.identity.clone(), recipient: recipient.intent().clone(),
            sources: review_export_v1::sources(&self.roster)?,
            payload_digest: self.payload_digest().into(), payload_length: self.payload_length(),
        };
        review_export_coordinated_v1::validate_recipient(&self.roster, &self.current.view.candidates[0], &scope)?;
        if self.roster.has_export_operation(&scope.recipient.request.operation_id) { return Err(denied()); }
        self.check_current_v3(access, consent, proof, material)?;
        Ok(ClosedCoordinatedPrivateDurableAdmissionReviewV1 { prepared: self, recipient, scope })
    }
}
impl ClosedCoordinatedPrivateDurableAdmissionReviewV1<'_, '_> {
    pub fn scope(&self) -> &CoordinatedDurableReviewExportScopeV1 { &self.scope }
    pub fn check_current_v3(&self, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1) -> Result<()> {
        self.prepared.check_current_v3(access, consent, proof, material)
    }
    /// Consume both owners before fallible action admission. Fresh channel
    /// activation sends metadata only; actual bytes follow the durable append.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_coordinated_v1(self, access: &Access, consent: &dyn LocalPrivateDurableAdmissionConsentV2, proof: &dyn LocalProofConsent, material: &dyn LocalDurableMaterialConsentV1, export: &dyn LocalCoordinatedDurableReviewExportConsentV1, host_action_deadline: Instant) -> Result<(PrivateDurableAdmissionDeliveryV3, ImportedCoordinatedDurableReviewSessionV1)> {
        let Self { prepared, recipient, scope } = self;
        prepared.check_live(access, consent, proof, material, DurableMaterialActionV1::ExportForLocalNativeReview, &prepared.metadata_pin)?;
        if !export.permits(&scope) || Instant::now() >= host_action_deadline { return Err(denied()); }
        let fresh = recipient.activate(host_action_deadline).map_err(|_| denied())?;
        if fresh.intent() != &scope.recipient { return Err(denied()); }
        fresh.check_current().map_err(|_| denied())?;
        prepared.check_live(access, consent, proof, material, DurableMaterialActionV1::ExportForLocalNativeReview, &prepared.metadata_pin)?;
        deliver_activated_v3::<CoordinatedExportProfileV1, _>(prepared, fresh, scope, access, consent, proof, material, &|scope| export.permits(scope), host_action_deadline)
    }
}

impl OriginalDeliveryTransportV3 for FreshCoordinatedDurableReviewDeliveryV1 {
    type Profile = CoordinatedExportProfileV1;
    type Imported = ImportedCoordinatedDurableReviewSessionV1;
    fn check_current(&self) -> wholepact_signer::authority_bridge::Result<()> { self.check_current() }
    fn original_delivery_deadline_v3(&self) -> Instant { self.original_delivery_deadline_v3() }
    fn deliver_prepared_restricted_v3(self, payload: PreparedDurableReviewPayloadV2, check: &dyn Fn() -> wholepact_signer::authority_bridge::Result<()>, restriction: &dyn Fn() -> wholepact_signer::authority_bridge::Result<()>) -> wholepact_signer::authority_bridge::Result<Self::Imported> {
        self.deliver_prepared_restricted_v3(payload, check, restriction)
    }
}
pub(super) struct CoordinatedExportProfileV1;
impl OriginalExportProfileV3 for CoordinatedExportProfileV1 {
    type Scope = CoordinatedDurableReviewExportScopeV1;
    const EVENT: &'static str = COORDINATED_EXPORT_EVENT_V1;
    fn operation(scope: &Self::Scope) -> &str { &scope.recipient.request.operation_id }
    fn proposal(scope: &Self::Scope) -> &str { &scope.proposal.proposal_id }
    fn command(access: &Access, revision: u64, scope: &Self::Scope) -> Result<CommandContext> { coordinated_export_command_v1(access, revision, scope) }
    fn insert(roster: &mut Roster, scope: &Self::Scope) -> Result<()> {
        if (!roster.review_exports.is_empty() || !roster.review_exports_v3.is_empty()) || roster.has_export_operation(Self::operation(scope)) { return Err(denied()); }
        roster.coordinated_review_exports_v1.insert(Self::operation(scope).into(), CoordinatedExportIntentV1 { scope: scope.clone(), exposure: ExportExposure::DisclosedOrUnknown });
        Ok(())
    }
    fn validate_delta(before: &Envelope, after: &Envelope) -> Result<Self::Scope> { validate_coordinated_export_delta_v1(before, after) }
}

pub(in super::super) fn coordinated_export_command_v1(access: &Access, revision: u64, scope: &CoordinatedDurableReviewExportScopeV1) -> Result<CommandContext> {
    scope.recipient.validate().map_err(|_| damaged())?;
    let key = format!("coordinated-admission-review-{}", digest("wholepact:private-admission-coordinated-export-idempotency:v1", &scope.recipient.request.operation_id)?);
    crate::context(access, &key, COORDINATED_EXPORT_COMMAND_V1, &scope.proposal.proposal_id, Some(revision), scope)
}
pub(in super::super) fn validate_coordinated_export_delta_v1(before: &Envelope, after: &Envelope) -> Result<CoordinatedDurableReviewExportScopeV1> {
    for e in [before, after] {
        operation_v1::validate_common_shape(e)?;
        crate::durable_construction_v1::validate_stored(e)?;
        crate::durable_proposals_v1::validate_private_fixed_v2(e)?;
    }
    if after.view.revision != before.view.revision.checked_add(1).ok_or_else(damaged)? || time::OffsetDateTime::parse(&after.view.updated_at, &time::format_description::well_known::Rfc3339).is_err() { return Err(damaged()); }
    let old = original_roster_v2(before)?;
    let new = original_roster_v2(after)?;
    if !old.review_exports.is_empty() || !new.review_exports.is_empty() || !old.review_exports_v3.is_empty() || !new.review_exports_v3.is_empty() { return Err(damaged()); }
    review_export_v3::validate_capacity(&new)?;
    if new.owners.len() != 2 || new.coordinated_review_exports_v1.len() != old.coordinated_review_exports_v1.len() + 1 { return Err(damaged()); }
    let added: Vec<_> = new.coordinated_review_exports_v1.iter().filter(|(k, _)| !old.coordinated_review_exports_v1.contains_key(*k)).collect();
    if added.len() != 1 { return Err(damaged()); }
    let (id, intent) = added[0];
    if id != &intent.scope.recipient.request.operation_id || old.review_exports.contains_key(id) { return Err(damaged()); }
    let mut allowed = old.clone();
    allowed.coordinated_review_exports_v1.insert(id.clone(), intent.clone());
    if serde_json::to_value(&allowed).map_err(|_| damaged())? != serde_json::to_value(&new).map_err(|_| damaged())? { return Err(damaged()); }
    let mut permitted = before.clone();
    permitted.view.revision = after.view.revision;
    permitted.view.updated_at = after.view.updated_at.clone();
    permitted.durable_construction_v1.insert(intent.scope.proposal.proposal_id.clone(), serde_json::to_value(&allowed).map_err(|_| damaged())?);
    if crate::encode(&permitted)? != crate::encode(after)? { return Err(damaged()); }
    Ok(intent.scope.clone())
}

#[derive(Serialize)]
pub struct CoordinatedPrivateDurableAdmissionStatusV1 {
    pub version: u16,
    pub source: PrivateDurableAdmissionStatusV2,
    pub review_exports: Vec<CoordinatedDurableReviewExportScopeV1>,
}
impl<'source> PrivateDurableAdmissionCoordinatorV2<'source> {
    pub fn read_original_coordinated_fixed_checked_v1(
        &self,
        access: &Access,
        consent: &dyn LocalPrivateDurableAdmissionConsentV2,
        proof: &dyn LocalProofConsent,
        material: &dyn LocalDurableMaterialConsentV1,
        display: impl FnOnce(&CoordinatedPrivateDurableAdmissionStatusV1, &dyn Fn() -> Result<()>) -> Result<()>,
    ) -> Result<CoordinatedPrivateDurableAdmissionStatusV1> {
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
        if !roster.review_exports.is_empty() || !roster.review_exports_v3.is_empty() { return Err(denied()); }
        let review_exports = roster.coordinated_review_exports_v1.values().map(|intent| intent.scope.clone()).collect();
        gate.check()?;
        let (_, after) = self.check(access, consent)?;
        if after.full_digest != history.full_digest { return Err(damaged()); }
        metadata_pin.check_current_v3().map_err(crate::store_error)?;
        root_pin.check_current_v3().map_err(crate::store_error)?;
        proof_pin.check_current_v3().map_err(original_job_error_v2)?;
        let status = CoordinatedPrivateDurableAdmissionStatusV1 {
            version: 1,
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
