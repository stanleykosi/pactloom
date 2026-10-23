//! Host-side coordinated export stays on the actual original source/payload.
//! A nominal recipient and a distinct exact consent gate prevent native fallback.
use super::*;
use wholepact_engine::durable_construction_v1::review_export_coordinated_v1::{CoordinatedDurableReviewExportScopeV1, LocalCoordinatedDurableReviewExportConsentV1};
use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::{PreparedCoordinatedDurableReviewRecipientV1, VerifiedImportedCoordinatedDurableReviewSessionV1};

#[derive(Serialize)]
pub(in crate::host::financial) struct CoordinatedOriginalDeliveryExportV1 {
    pub request: DurableDeliveryAdmissionRequestV2,
    pub export_scope: CoordinatedDurableReviewExportScopeV1,
    pub retention: PrivateDurableAdmissionDeliveryV3,
}
struct CoordinatedClosedExportConsentV1<'a, 'host> {
    inner: ClosedConsentV3<'a, 'host>,
    export: &'a CoordinatedDurableReviewExportScopeV1,
}
impl CoordinatedClosedExportConsentV1<'_, '_> {
    fn check(&self) -> Result<()> { self.inner.check() }
}
impl LocalPrivateDurableAdmissionConsentV2 for CoordinatedClosedExportConsentV1<'_, '_> {
    fn check_final_effect_restriction_v1(&self, deadline: Option<std::time::Instant>) -> bool { self.inner.check_final_effect_restriction_v1(deadline) }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool { self.inner.permits_source(scope) }
}
impl LocalProofConsent for CoordinatedClosedExportConsentV1<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool { LocalProofConsent::permits(&self.inner, scope, action) }
}
impl LocalDurableMaterialConsentV1 for CoordinatedClosedExportConsentV1<'_, '_> {
    fn permits(&self, scope: &DurableConstructionScopeV1, digest: &str, action: DurableMaterialActionV1) -> bool {
        matches!(action, DurableMaterialActionV1::ExportForLocalNativeReview)
            && material_matches(self.inner.inspection, scope, digest) && self.check().is_ok()
    }
}
impl LocalCoordinatedDurableReviewExportConsentV1 for CoordinatedClosedExportConsentV1<'_, '_> {
    fn permits(&self, scope: &CoordinatedDurableReviewExportScopeV1) -> bool { self.export == scope && self.check().is_ok() }
}
impl Host {
    pub(in crate::host) fn private_original_coordinated_delivery_export_v1(
        &self, root: &Path, choices: &DeliveryChoicesV2, reviewer: (&str, &str),
        open_recipient: impl FnOnce(&FixedProposalIdentityV1, &str, u64, &DurableDeliveryPlanV2, &[DurableDeliveryMaterialScopeRefV2], &wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1) -> Result<PreparedCoordinatedDurableReviewRecipientV1>,
    ) -> Result<(VerifiedImportedCoordinatedDurableReviewSessionV1, CoordinatedOriginalDeliveryExportV1)> {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        let _observation_scope = semantic_delivery_scope();
        if !crate::terminal::coordinated_restriction_required() { return Err(Error::Permission); }
        host_result(DeliveryObservationSiteV2::NativeCheck, self.require_manual_session())?;
        let owner = host_result(DeliveryObservationSiteV2::SourceOpen, self.original_delivery_admission_owner_v2(root))?;
        let inspection = engine_result(DeliveryObservationSiteV2::SourceInspection, owner.coordinator().inspect_original_for_admission_v2(host_result(DeliveryObservationSiteV2::NativeCheck, self.access())?, &owner))?;
        let plan = host_result(DeliveryObservationSiteV2::SourcePlan, source_plan(&owner, &inspection, choices))?;
        host_result(DeliveryObservationSiteV2::SourcePlan, plan.validate_origins().map_err(|_| Error::Invalid))?;
        // This read decision expires normally and is destroyed after preparation.
        let mut preparation_source_first = true;
        let preparation = source_checked_approval_v2(
            || {
                let site = if preparation_source_first { DeliveryObservationSiteV2::PreparationSourceBefore }
                    else { DeliveryObservationSiteV2::PreparationSourceAfter };
                preparation_source_first = false;
                host_result(site, current_source(self, &owner, &inspection))
            },
            || host_result(DeliveryObservationSiteV2::PreparationApproval, self.terminal.approve_historical("Approve LOCAL exact-byte preparation for closed original delivery. Read and fully verify the selected retained proof and BOTH original materials, and retain one exact encoded private payload in local memory under the ORIGINAL absolute ceilings. No recipient disclosure, transport, signing, submission or admission is authorized.")),
        )?;
        let read = InspectionReadV2 { host: self, owner: &owner, inspection: &inspection, approval: &preparation, export_preview: true };
        let prepared = engine_result(DeliveryObservationSiteV2::ExportPreview, owner.coordinator().prepare_original_delivery_v3(host_result(DeliveryObservationSiteV2::NativeCheck, self.access())?, &read, &read, &read))?;
        let original_disclosure = engine_result(DeliveryObservationSiteV2::OriginalDisclosureSelector,
            prepared.original_disclosure_selector_coordinated_v1(reviewer.0, reviewer.1))?;
        drop(read);
        drop(preparation);
        // Every setup/KDF/redisclosure and genuine ReceiveAndViewExact decision
        // happens in this continuation, before Host's final ExportExact response.
        let recipient = host_result(DeliveryObservationSiteV2::RecipientPrepare,
            open_recipient(prepared.fixed_identity(), prepared.payload_digest(), prepared.payload_length(), &plan, prepared.material_scopes(), &original_disclosure))?;
        // Restore before final inspection, binding, export or commit. The
        // recipient callback above includes the actual capture and Pair prompt.
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        drop(_observation_scope);
        if recipient.intent().delivery != plan || recipient.intent().fixed != *inspection.fixed_identity() { return Err(Error::Authentication); }
        let request = recipient.intent().request.clone();
        // A distinct current metadata-read decision, not renewal of preparation.
        let final_inspection = source_checked_approval_v2(
            || { owner.check_closed_source_v3()?; current_materials(&inspection) },
            || self.terminal.approve_historical("Inspect exact closed original export metadata for the actually prepared coordinated original recipient. Read only the retained source/policy identity and exact payload commitment under both ORIGINAL material ceilings. No private payload export, financial admission, signing or submission is authorized."),
        )?;
        let read = ClosedConsentV3 { host: self, owner: &owner, inspection: &inspection, approval: &final_inspection, export: None };
        let closed = engine_result(DeliveryObservationSiteV2::ExportPreview,
            prepared.bind_prepared_coordinated_recipient_v1(recipient, self.access()?, &read, &read, &read))?;
        let export_scope = closed.scope().clone();
        let detail = format!(
            "EXPORT EXACT COORDINATED ORIGINAL DELIVERY V1\n{}\n{}\nDisclose the full retained private candidate, viewing keys, notes and witnesses ONLY to this prepared coordinated original reviewer and exact original source/process/read context. No transport socket or export grant has waited for this review. After this final response, a one-use prompt-free channel must match the exact preparation. Changed, expired, locked or restarted preparation is refused without fallback. Retain DisclosedOrUnknown before the first private byte; failure cannot undo disclosure. This does not sign, submit, acquire, reserve or activate financial execution. Prospective admission requires its own native decision.",
            serde_json::to_string(&inspection)?, serde_json::to_string(&export_scope)?
        );
        bound_original_delivery_review_v2(&detail)?;
        let prompt_bounds = original_review_prompt_bounds(&final_inspection, &inspection)?;
        let approval = host_result(DeliveryObservationSiteV2::ExportApproval, self.terminal.approve_durable_delivery_original_v3(
            &final_inspection, &detail,
            || { read.check()?; engine_result(DeliveryObservationSiteV2::ExportApproval, closed.check_current_v3(self.access()?, &read, &read, &read)) },
            || { owner.check_closed_source_v3()?; current_materials(&inspection) },
            prompt_bounds.as_ref(),
        ))?;
        drop(read);
        drop(final_inspection);
        let consent = CoordinatedClosedExportConsentV1 { inner: ClosedConsentV3 { host: self, owner: &owner, inspection: &inspection, approval: &approval, export: None }, export: &export_scope };
        consent.check()?;
        let delivered = observed_engine_result(DeliveryObservationSiteV2::ExportCommit,
            closed.deliver_coordinated_v1(self.access()?, &consent, &consent, &consent, &consent, approval.deadline()));
        let (retention, bytes_received) = delivered.map_err(|error| {
            if error.code == "DISCLOSURE_UNKNOWN" { unknown() } else { Error::from(error) }
        })?;
        // Actual coordinated verification is a separate read-bound worker result.
        // A data receipt cannot promote itself into an admission owner.
        let verified = bytes_received.await_verified_v3().map_err(|_| unknown())?;
        // The export action is over. Coordinated verified import is independently
        // bounded by its read permission, not by Host's now-finished action120.
        observe_delivery(DeliveryObservationSiteV2::ExportCommit, DeliveryObservationOutcomeV2::ReturnedOk);
        Ok((verified, CoordinatedOriginalDeliveryExportV1 {
            request: DurableDeliveryAdmissionRequestV2 { version: 2, import_request: request, delivery: plan },
            export_scope, retention,
        }))
    }
}

/// Holds real verified recipient custody alongside this exact H/source borrow.
/// This is not yet an admission owner and exposes no success projection.
pub(in crate::host::financial) struct RetainedCoordinatedVerifiedExportV1<'host> {
    pub(super) host: &'host Host,
    pub(super) workspace: &'host Path,
    pub(super) verified: VerifiedImportedCoordinatedDurableReviewSessionV1,
    pub(super) exported: CoordinatedOriginalDeliveryExportV1,
    pub(super) material_delivery_restriction: retained_result_v1::HostMaterialDeliveryRestrictionV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatedReviewerSelectionV1 {
    import_operation_id: String,
    redisclosure_operation_id: String,
    account_id: String,
    participant_id: String,
    choices: DeliveryChoicesV2,
}

/// The endpoint comes from H's original relay mailbox, never a selected socket
/// or installed-provider fallback. Selected JSON only chooses ordinary review data.
pub(in crate::host::financial) fn begin_original_coordinated_export_v1<'host>(
    host: &'host Host,
    workspace: &'host Path,
    previous: Option<&CoordinatedOriginalDeliveryExportV1>,
    verifier: wholepact_financial_coordinator_origin::OriginalForkSignerVerifier,
    endpoint: wholepact_financial_coordinator_origin::SignerV3PairEndpointV1,
    current_disclosure: impl FnOnce() -> Result<wholepact_financial_coordinator_origin::SignerV3CurrentDisclosureV1>,
) -> Result<RetainedCoordinatedVerifiedExportV1<'host>> {
    use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedOriginalClientV1;
    let selection: CoordinatedReviewerSelectionV1 = host.read_json("Exact coordinated reviewer selection JSON {import_operation_id,redisclosure_operation_id,account_id,participant_id,choices}; source/receipt references are obtained from the actual originals: ")?;
    if previous.is_some_and(|prior| prior.export_scope.recipient.account_id == selection.account_id
        || prior.export_scope.recipient.participant_id == selection.participant_id)
    { return Err(Error::Authentication); }
    endpoint.validate().map_err(|_| Error::Authentication)?;
    crate::id(&selection.import_operation_id)?;
    crate::id(&selection.redisclosure_operation_id)?;
    if selection.import_operation_id == selection.redisclosure_operation_id { return Err(Error::Authentication); }
    let mut material_delivery_restriction = None;
    let (verified, exported) = host.private_original_coordinated_delivery_export_v1(
        workspace, &selection.choices, (&selection.account_id, &selection.participant_id), |fixed, digest, bytes, delivery, materials, original_disclosure| {
            if previous.is_some_and(|prior| prior.request.delivery != *delivery || prior.export_scope.proposal != *fixed)
            { return Err(Error::Authentication); }
            if selection.import_operation_id == original_disclosure.operation_id
                || selection.redisclosure_operation_id == original_disclosure.operation_id
            { return Err(Error::Authentication); }
            material_delivery_restriction = Some(host_result(DeliveryObservationSiteV2::MaterialRestrictionCapture, retained_result_v1::HostMaterialDeliveryRestrictionV1::capture(delivery, materials))?);
            let scope = PairScope {
                account_id: selection.account_id.clone(), participant_id: selection.participant_id.clone(),
                agreement_id: fixed.agreement_id.clone(), manifest_digest: fixed.manifest_digest.clone(),
                history_read: true, authorization_export: false, preconstruction_export: true,
            };
            host_result(DeliveryObservationSiteV2::PairConfirmation, host.terminal.confirm("Pair this exact original coordinated reviewer for independently approved receive/view. No native provider fallback or financial execution is authorized."))?;
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            let mut client = CoordinatedOriginalClientV1::pair_observed(verifier, endpoint, scope)
                .map_err(|failure| {
                    crate::financial_ci_host_failure::pair(&failure);
                    Error::Permission
                })?;
            #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
            let mut client = CoordinatedOriginalClientV1::pair(verifier, endpoint, scope).map_err(|_| Error::Permission)?;
            // Pair must finish before these actual fresh committed observations
            // can exist. The callback consumes the same original H mailbox once.
            let current = current_disclosure()?;
            client.check_current_disclosure_v1(&current).map_err(|_| Error::Authentication)?;
            use wholepact_signer::authority_bridge::durable_construction_v1::{DurableConstructionRedisclosureRequestV1, DurableConstructionRedisclosureSourceV1, DurableConstructionHistoryRequestV1};
            let redisclosed = client.redisclose_durable_construction_v1(DurableConstructionRedisclosureRequestV1 {
                operation_id: selection.redisclosure_operation_id.clone(),
                original: DurableConstructionRedisclosureSourceV1 {
                    operation_id: original_disclosure.operation_id.clone(),
                    expected_request_digest: Some(original_disclosure.expected_request_digest.clone()),
                },
                enrollment_ref: current.current_enrollment_ref.clone(),
                accepted_manifest_ref: current.current_manifest_ref.clone(),
            }).map_err(|_| Error::Permission)?;
            let outbox = redisclosed.outbox();
            let link = outbox.redisclosure().ok_or(Error::Authentication)?;
            if link.original_operation_id != original_disclosure.operation_id
                || link.original_request_digest != original_disclosure.expected_request_digest
                || outbox.request().operation_id != selection.redisclosure_operation_id
                || outbox.request().enrollment_ref != current.current_enrollment_ref
                || outbox.request().accepted_manifest_ref != current.current_manifest_ref
            { return Err(Error::Authentication); }
            let request = DurableReviewDeliveryRequestV1 {
                operation_id: selection.import_operation_id.clone(),
                enrollment_ref: current.current_enrollment_ref,
                accepted_manifest_ref: current.current_manifest_ref,
                own_disclosure: original_disclosure.clone(),
                current_disclosure: Some(DurableConstructionHistoryRequestV1 {
                    operation_id: outbox.request().operation_id.clone(),
                    expected_request_digest: outbox.request_digest().to_owned(),
                }),
                proposal_binding: fixed.proposal_binding.clone(),
            };
            drop(redisclosed);
            client.prepare_closed_recipient_v1(request, fixed.clone(), digest.into(), bytes, delivery.clone(), materials.to_vec()).map_err(|_| Error::Permission)
        },
    )?;
    Ok(RetainedCoordinatedVerifiedExportV1 {
        host, workspace, verified, exported,
        material_delivery_restriction: material_delivery_restriction.ok_or(Error::Permission)?,
    })
}

use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::{PendingCoordinatedDurableDeliveryAdmissionV1, CoordinatedDurableDeliveryAdmissionStatusV1};

impl Host {
    fn private_original_coordinated_delivery_status_checked_v1(
        &self,
        root: &Path,
        display: impl FnOnce(&wholepact_engine::CoordinatedPrivateDurableAdmissionStatusV1, &HistoricalApproval, &dyn Fn() -> Result<()>, (u64, u64)) -> Result<()>,
    ) -> Result<wholepact_engine::CoordinatedPrivateDurableAdmissionStatusV1> {
        self.require_private_workspace_read_session_v1()?;
        let owner = self.original_delivery_admission_owner_v2(root)?;
        let inspection = engine_result(DeliveryObservationSiteV2::SourceInspection,
            owner.coordinator().inspect_original_for_admission_v2(self.access()?, &owner))?;
        let detail = format!(
            "Read, independently verify, and locally display the exact saved ORIGINAL fixed proof summary, BOTH original material scope metadata, and strict V2/V3 append-only export history. If present, display only the separately authenticated prospective admission status linked to that exact retained export.\n{}\nNo export, receive, admission, construction, signing, submission or recovered native permission is authorized.",
            serde_json::to_string(&inspection)?,
        );
        let prompt_bounds = original_review_prompt_bounds(owner.inspection_approval(), &inspection)?;
        let approval = self.terminal.approve_durable_delivery_original_v3(
            owner.inspection_approval(), &detail,
            || { owner.inspection_approval().check()?; current_source(self, &owner, &inspection) },
            || { owner.check_closed_read_source_v3()?; current_materials(&inspection) },
            prompt_bounds.as_ref(),
        )?;
        let read = ClosedHistoricalReadConsentV3 { host: self, owner: &owner, inspection: &inspection, approval: &approval };
        let mut display_error = None;
        let material_clocks = if crate::terminal::coordinated_restriction_required() {
            retained_material_clock_bounds(&inspection)?
        } else { (0, u64::MAX) }; // Never-required legacy adds no new clock failure.
        let result = owner.coordinator().read_original_coordinated_fixed_checked_v1(
            self.access()?, &read, &read, &read, |status, current| {
                let check = || { read.check()?; current().map_err(Error::from)?; read.check() };
                if let Err(error) = display(status, &approval, &check, material_clocks) {
                    display_error = Some(error);
                    return Err(wholepact_engine::ApiError::new("DISCLOSURE_DENIED", "Current exact local display permission is unavailable"));
                }
                Ok(())
            },
        );
        if let Some(error) = display_error { return Err(error); }
        let status = engine_result(DeliveryObservationSiteV2::FixedRead, result)?;
        read.check()?;
        Ok(status)
    }
    fn display_original_coordinated_admission_status_v1(
        &self, root: &Path, export: &CoordinatedDurableReviewExportScopeV1,
        status: &CoordinatedDurableDeliveryAdmissionStatusV1,
    ) -> Result<()> {
        // A new explicit read covers this local output after all remote/human
        // waits. The completed export action and old Signer read are not reused.
        self.private_original_coordinated_delivery_status_checked_v1(root, |source, approval, check, clocks| {
            if !source.review_exports.iter().any(|retained| retained == export) {
                return Err(Error::Authentication);
            }
            validate_coordinated_status_v1(export, status)?;
            let output = self.terminal.historical_output()?;
            approval.effect(&mut || output.json_checked_under(status, check, approval, clocks))
        })?;
        Ok(())
    }
}
fn validate_coordinated_original_audit_v1(scope: &CoordinatedDurableReviewExportScopeV1, status: &DurableDeliveryAdmissionStatusV2) -> Result<()> {
    status.validate().map_err(|_| Error::Authentication)?;
    scope.recipient.validate().map_err(|_| Error::Authentication)?;
    let actual_fixed: FixedProposalIdentityV1 = wholepact_core::parse_typed_json(&serde_json::to_vec(&status.scope.authorization.fixed)?).map_err(|_| Error::Authentication)?;
    if status.version != 2 || !status.witness_committed || status.scope.delivery != scope.recipient.delivery
        || status.scope.accepted_manifest_ref != scope.recipient.request.accepted_manifest_ref
        || actual_fixed != scope.proposal
        || status.scope.authorization.identity.account_id != scope.recipient.account_id
        || status.scope.original_ceilings.material_scopes != scope.recipient.material_scopes
        || status.original_accepted_manifest_ref != scope.recipient.original_manifest_ref
        || status.original_enrollment_ref != scope.recipient.original_enrollment_ref
    { return Err(Error::Authentication); }
    Ok(())
}
fn validate_coordinated_status_v1(scope: &CoordinatedDurableReviewExportScopeV1, status: &CoordinatedDurableDeliveryAdmissionStatusV1) -> Result<()> {
    status.validate().map_err(|_| Error::Authentication)?;
    if status.intent_digest != scope.recipient.digest().map_err(|_| Error::Authentication)? {
        return Err(Error::Authentication);
    }
    let audit = status.verified_audit().map_err(|_| Error::Receipt(
        "The original V3 operation remains pending or unknown: complete authenticated Witness history has not established admission. Preserve the original operation; do not resend it".into(),
    ))?;
    validate_coordinated_original_audit_v1(scope, audit)
}

/// Nominal coordinated Pending custody; the old fixed-fork/native owner is not
/// converted, reconstructed, or accepted here. Original H and source survive
/// every uncertain result until explicit reconciliation or disposal.
pub(in crate::host::financial) struct RetainedOriginalCoordinatedAdmissionV1<'host> {
    host: &'host Host,
    workspace: &'host Path,
    pending: PendingCoordinatedDurableDeliveryAdmissionV1,
    exported: CoordinatedOriginalDeliveryExportV1,
    admitted: Option<CoordinatedDurableDeliveryAdmissionStatusV1>,
    verification_started: bool,
    material_delivery_restriction: retained_result_v1::HostMaterialDeliveryRestrictionV1,
}
impl<'host> RetainedCoordinatedVerifiedExportV1<'host> {
    pub(in crate::host::financial) fn request_admission(self) -> Result<RetainedOriginalCoordinatedAdmissionV1<'host>> {
        let pending = self.verified.request_admission_retained_v1().map_err(|_| unknown())?;
        Ok(RetainedOriginalCoordinatedAdmissionV1 {
            host: self.host, workspace: self.workspace, pending, exported: self.exported,
            admitted: None, verification_started: false,
            material_delivery_restriction: self.material_delivery_restriction,
        })
    }
}
impl RetainedOriginalCoordinatedAdmissionV1<'_> {
    pub(in crate::host::financial) fn checked_admission_status(&self) -> Result<&CoordinatedDurableDeliveryAdmissionStatusV1> {
        self.checked_export()?;
        self.admitted.as_ref().ok_or(Error::Permission)
    }
    pub(in crate::host::financial) fn verify_admission(&mut self) -> Result<()> {
        if self.verification_started { return Err(Error::Permission); }
        self.verification_started = true;
        let status = match self.pending.await_status_v1() {
            Ok(status) if status.verified_audit().is_ok() => status,
            _ => {
                self.host.terminal.message("Coordinated admission is pending or uncertain. Read complete original Witness history under a new decision; no mutation will be resent.\n")?;
                self.pending.read_original_status_retained_v1().map_err(|_| unknown())?
            }
        };
        validate_coordinated_status_v1(&self.exported.export_scope, &status)?;
        if self.exported.request.import_request != self.exported.export_scope.recipient.request
            || self.exported.request.delivery != self.exported.export_scope.recipient.delivery
        { return Err(Error::Authentication); }
        self.host.display_original_coordinated_admission_status_v1(self.workspace, &self.exported.export_scope, &status)?;
        self.admitted = Some(status);
        Ok(())
    }
    fn checked_export(&self) -> Result<&CoordinatedOriginalDeliveryExportV1> {
        let status = self.admitted.as_ref().ok_or(Error::Permission)?;
        validate_coordinated_status_v1(&self.exported.export_scope, status)?;
        if self.pending.status() != Some(status) { return Err(Error::Authentication); }
        Ok(&self.exported)
    }
}

#[path = "coordinated_owner_workflow_wait_v1.rs"]
mod coordinated_owner_workflow_wait_v1;
pub(in crate::host::financial) use coordinated_owner_workflow_wait_v1::RetainedCoordinatedOwnerWorkflowWaitV1;

pub(in crate::host::financial) fn begin_original_coordinated_admission_v1<'host>(
    host: &'host Host,
    workspace: &'host Path,
    previous: Option<&RetainedOriginalCoordinatedAdmissionV1<'_>>,
    verifier: wholepact_financial_coordinator_origin::OriginalForkSignerVerifier,
    endpoint: wholepact_financial_coordinator_origin::SignerV3PairEndpointV1,
    current_disclosure: impl FnOnce() -> Result<wholepact_financial_coordinator_origin::SignerV3CurrentDisclosureV1>,
) -> Result<RetainedOriginalCoordinatedAdmissionV1<'host>> {
    let previous = previous.map(|prior| {
        if !std::ptr::eq(host, prior.host) || workspace != prior.workspace {
            return Err(Error::Authentication);
        }
        prior.checked_export()
    }).transpose()?;
    begin_original_coordinated_export_v1(host, workspace, previous, verifier, endpoint, current_disclosure)?.request_admission()
}

impl RetainedOriginalCoordinatedAdmissionV1<'_> {
    pub(in crate::host::financial) fn prepare_original_result(
        self, host: &Host, workspace: &Path, socket: &Path,
        request: &wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
        history: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    ) -> Result<wholepact_signer::authority_bridge::financial_continuation_v1::PreparedCoordinatedFinancialResultReceiverV1> {
        if !std::ptr::eq(host, self.host) || workspace != self.workspace { return Err(Error::Authentication); }
        self.checked_export()?;
        if self.admitted.as_ref() != self.pending.status() { return Err(Error::Authentication); }
        let (ceiling, restriction) = self.material_delivery_restriction.into_narrowed_original_restriction_v1(history)?;
        host.prepare_retained_original_coordinated_financial_preview_v1(
            workspace, self.pending, socket, request, history, ceiling, restriction,
        )
    }
}
