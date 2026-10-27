//! Explicit V3 closed export. No V2 paired grant is retained after preparation.
use super::*;
use wholepact_engine::durable_construction_v1::review_export_v3::{DurableReviewExportScopeV3, LocalDurableReviewExportConsentV3};
use wholepact_engine::{PrivateDurableAdmissionDeliveryV3, PrivateDurableAdmissionStatusV3};
use wholepact_signer::authority_bridge::durable_delivery_admission_ipc_v3::{DurableDeliveryAdmissionStatusV3, DurableDeliveryHistoryRequestV3, ReopenedDurableDeliveryHistoryClientV3};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer::authority_bridge::durable_review_ipc_v3::{PreparedDurableReviewRecipientV3, VerifiedImportedDurableReviewSessionV3};
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "closed_review_v3/coordinated_export_v1.rs"]
mod coordinated_export_v1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(in crate::host::financial) use coordinated_export_v1::{begin_original_coordinated_admission_v1, RetainedOriginalCoordinatedAdmissionV1, RetainedCoordinatedOwnerWorkflowWaitV1};

#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "closed_review_v3/retained_result_v1.rs"]
mod retained_result_v1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "closed_review_v3/owner_workflow_wait_v1.rs"]
mod owner_workflow_wait_v1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(in crate::host::financial) use owner_workflow_wait_v1::RetainedOwnerWorkflowWaitV1;

#[derive(Serialize)]
pub(in crate::host) struct OriginalDeliveryExportV3 {
    pub request: DurableDeliveryAdmissionRequestV2,
    pub export_scope: DurableReviewExportScopeV3,
    pub retention: PrivateDurableAdmissionDeliveryV3,
}
/// Borrows only the freshly issued read OR exact export decision. It never
/// reaches the owner's original inspection approval or an old recipient grant.
struct ClosedConsentV3<'a, 'host> {
    host: &'a Host,
    owner: &'a OriginalDeliveryAdmissionOwnerV2<'host>,
    inspection: &'a PrivateDurableAdmissionInspectionV2,
    approval: &'a HistoricalApproval,
    export: Option<&'a DurableReviewExportScopeV3>,
}
impl ClosedConsentV3<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.host.require_manual_session()?;
        self.owner.check_closed_source_v3()?;
        current_materials(self.inspection)?;
        if !same(self.owner.workspace_scope(), self.inspection.workspace_scope())?
            || self.host.access()?.principal_id != self.inspection.workspace_scope().principal_id()
        { return Err(Error::Authentication); }
        self.approval.check()
    }
}
impl LocalPrivateDurableAdmissionConsentV2 for ClosedConsentV3<'_, '_> {
    fn check_final_effect_restriction_v1(&self, original_deadline: Option<std::time::Instant>) -> bool {
        if crate::terminal::coordinated_restriction_required()
            && original_deadline.is_some_and(|until| std::time::Instant::now() >= until)
        { return false; }
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clock_bounds(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.inspection.workspace_scope()).unwrap_or(false) && self.check().is_ok()
    }
}
impl LocalProofConsent for ClosedConsentV3<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        proof_matches(self.inspection, scope, action) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedConsentV3<'_, '_> {
    fn permits(&self, scope: &DurableConstructionScopeV1, digest: &str, action: DurableMaterialActionV1) -> bool {
        let expected = if self.export.is_some() { DurableMaterialActionV1::ExportForLocalNativeReview } else { DurableMaterialActionV1::ReadForExactConstruction };
        std::mem::discriminant(&action) == std::mem::discriminant(&expected)
            && material_matches(self.inspection, scope, digest) && self.check().is_ok()
    }
}
impl LocalDurableReviewExportConsentV3 for ClosedConsentV3<'_, '_> {
    fn permits(&self, scope: &DurableReviewExportScopeV3) -> bool {
        self.export.is_some_and(|exact| exact == scope) && self.check().is_ok()
    }
}
/// Separate historical-read role: never implements export consent, and never
/// reinterprets pre-export preparation (whose export scope is also absent).
struct ClosedHistoricalReadConsentV3<'a, 'host> {
    host: &'a Host,
    owner: &'a OriginalDeliveryAdmissionOwnerV2<'host>,
    inspection: &'a PrivateDurableAdmissionInspectionV2,
    approval: &'a HistoricalApproval,
}
impl ClosedHistoricalReadConsentV3<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.owner.check_closed_read_source_v3()?;
        current_materials(self.inspection)?;
        if !same(self.owner.workspace_scope(), self.inspection.workspace_scope())?
            || self.host.access()?.principal_id != self.inspection.workspace_scope().principal_id()
        { return Err(Error::Authentication); }
        self.approval.check()
    }
}
impl LocalPrivateDurableAdmissionConsentV2 for ClosedHistoricalReadConsentV3<'_, '_> {
    fn check_final_effect_restriction_v1(&self, original_deadline: Option<std::time::Instant>) -> bool {
        if crate::terminal::coordinated_restriction_required()
            && original_deadline.is_some_and(|until| std::time::Instant::now() >= until)
        { return false; }
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clock_bounds(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, scope: &PrivateWorkspaceScopeV1) -> bool {
        same(scope, self.inspection.workspace_scope()).unwrap_or(false) && self.check().is_ok()
    }
}
impl LocalProofConsent for ClosedHistoricalReadConsentV3<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        proof_matches(self.inspection, scope, action) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedHistoricalReadConsentV3<'_, '_> {
    fn permits(&self, scope: &DurableConstructionScopeV1, digest: &str, action: DurableMaterialActionV1) -> bool {
        matches!(action, DurableMaterialActionV1::ReadForExactConstruction)
            && material_matches(self.inspection, scope, digest) && self.check().is_ok()
    }
}
fn unknown() -> Error {
    Error::Receipt("DISCLOSURE_UNKNOWN: exact V3 export is retained as disclosed-or-unknown; preserve the original operation and do not resend private bytes".into())
}
fn original_review_prompt_bounds(prior: &HistoricalApproval, inspection: &PrivateDurableAdmissionInspectionV2) -> Result<Option<crate::terminal::OriginalPromptBoundsV1>> {
    if !crate::terminal::coordinated_restriction_required() { return Ok(None); }
    let (from, until) = retained_material_clock_bounds(inspection)?;
    Ok(Some(crate::terminal::OriginalPromptBoundsV1::new(prior.deadline(), (
        from.checked_mul(1000).ok_or(Error::Permission)?, until.checked_mul(1000).ok_or(Error::Permission)?,
    ))?))
}

impl Host {
    pub(in crate::host) fn private_original_delivery_export_v3(
        &self, root: &Path, choices: &DeliveryChoicesV2,
        open_recipient: impl FnOnce(&FixedProposalIdentityV1, &str, u64, &DurableDeliveryPlanV2, &[DurableDeliveryMaterialScopeRefV2]) -> Result<PreparedDurableReviewRecipientV3>,
    ) -> Result<(VerifiedImportedDurableReviewSessionV3, OriginalDeliveryExportV3)> {
        self.require_manual_session()?;
        let owner = host_result(DeliveryObservationSiteV2::SourceOpen, self.original_delivery_admission_owner_v2(root))?;
        let inspection = engine_result(DeliveryObservationSiteV2::SourceInspection, owner.coordinator().inspect_original_for_admission_v2(self.access()?, &owner))?;
        let plan = source_plan(&owner, &inspection, choices)?;
        plan.validate_origins().map_err(|_| Error::Invalid)?;
        // This read decision expires normally and is destroyed after preparation.
        let preparation = source_checked_approval_v2(
            || current_source(self, &owner, &inspection),
            || self.terminal.approve_historical("Approve LOCAL exact-byte preparation for closed original delivery. Read and fully verify the selected retained proof and BOTH original materials, and retain one exact encoded private payload in local memory under the ORIGINAL absolute ceilings. No recipient disclosure, transport, signing, submission or admission is authorized."),
        )?;
        let read = InspectionReadV2 { host: self, owner: &owner, inspection: &inspection, approval: &preparation, export_preview: true };
        let prepared = engine_result(DeliveryObservationSiteV2::ExportPreview, owner.coordinator().prepare_original_delivery_v3(self.access()?, &read, &read, &read))?;
        drop(read);
        drop(preparation);
        // Every setup/KDF/redisclosure and genuine ReceiveAndViewExact decision
        // happens in this continuation, before Host's final ExportExact response.
        let recipient = host_result(DeliveryObservationSiteV2::RecipientPrepare,
            open_recipient(prepared.fixed_identity(), prepared.payload_digest(), prepared.payload_length(), &plan, prepared.material_scopes()))?;
        if recipient.intent().delivery != plan || recipient.intent().fixed != *inspection.fixed_identity() { return Err(Error::Authentication); }
        let request = recipient.intent().request.clone();
        // A distinct current metadata-read decision, not renewal of preparation.
        let final_inspection = source_checked_approval_v2(
            || { owner.check_closed_source_v3()?; current_materials(&inspection) },
            || self.terminal.approve_historical("Inspect exact closed original export metadata for the actually prepared native recipient. Read only the retained source/policy identity and exact payload commitment under both ORIGINAL material ceilings. No private payload export, financial admission, signing or submission is authorized."),
        )?;
        let read = ClosedConsentV3 { host: self, owner: &owner, inspection: &inspection, approval: &final_inspection, export: None };
        let closed = engine_result(DeliveryObservationSiteV2::ExportPreview,
            prepared.bind_prepared_recipient_v3(recipient, self.access()?, &read, &read, &read))?;
        let export_scope = closed.scope().clone();
        let detail = format!(
            "EXPORT EXACT ORIGINAL DELIVERY V3\n{}\n{}\nDisclose the full retained private candidate, viewing keys, notes and witnesses ONLY to this prepared installed reviewer and exact original source/process/read context. No transport socket or export grant has waited for this review. After this final response, a one-use prompt-free channel must match the exact preparation. Changed, expired, locked or restarted preparation is refused without fallback. Retain DisclosedOrUnknown before the first private byte; failure cannot undo disclosure. This does not sign, submit, acquire, reserve or activate financial execution. Prospective admission requires its own native decision.",
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
        let consent = ClosedConsentV3 { host: self, owner: &owner, inspection: &inspection, approval: &approval, export: Some(&export_scope) };
        consent.check()?;
        let delivered = observed_engine_result(DeliveryObservationSiteV2::ExportCommit,
            closed.deliver_v3(self.access()?, &consent, &consent, &consent, &consent, approval.deadline()));
        let (retention, bytes_received) = delivered.map_err(|error| {
            if error.code == "DISCLOSURE_UNKNOWN" { unknown() } else { Error::from(error) }
        })?;
        // Actual native verification is a separate read-bound worker result.
        // A data receipt cannot promote itself into an admission owner.
        let verified = bytes_received.await_verified_v3().map_err(|_| unknown())?;
        // The export action is over. Native verified import is independently
        // bounded by its read permission, not by Host's now-finished action120.
        observe_delivery(DeliveryObservationSiteV2::ExportCommit, DeliveryObservationOutcomeV2::ReturnedOk);
        Ok((verified, OriginalDeliveryExportV3 {
            request: DurableDeliveryAdmissionRequestV2 { version: 2, import_request: request, delivery: plan },
            export_scope, retention,
        }))
    }
    pub(in crate::host) fn private_original_delivery_status_v3(
        &self,
        root: &Path,
    ) -> Result<PrivateDurableAdmissionStatusV3> {
        // This projection is inert. Callers needing a visible disclosure must
        // use the scoped checked path, never treat this DTO as read permission.
        self.private_original_delivery_status_checked_v3(root, |_, _, _, _| Ok(()))
    }
    fn private_original_delivery_status_checked_v3(
        &self,
        root: &Path,
        display: impl FnOnce(&PrivateDurableAdmissionStatusV3, &HistoricalApproval, &dyn Fn() -> Result<()>, (u64, u64)) -> Result<()>,
    ) -> Result<PrivateDurableAdmissionStatusV3> {
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
        let result = owner.coordinator().read_original_fixed_checked_v3(
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
    fn display_original_admission_status_v3(
        &self, root: &Path, export: &DurableReviewExportScopeV3,
        status: &DurableDeliveryAdmissionStatusV3,
    ) -> Result<()> {
        // A new explicit read covers this local output after all remote/human
        // waits. The completed export action and old Signer read are not reused.
        self.private_original_delivery_status_checked_v3(root, |source, approval, check, clocks| {
            if !source.review_exports.iter().any(|retained| retained == export) {
                return Err(Error::Authentication);
            }
            validate_closed_status_v3(export, status)?;
            let output = self.terminal.historical_output()?;
            approval.effect(&mut || output.json_checked_under(status, check, approval, clocks))
        })?;
        Ok(())
    }
}
pub(in crate::host) fn validate_admission_result_v3(export: &OriginalDeliveryExportV3, status: &DurableDeliveryAdmissionStatusV2) -> Result<()> {
    if export.request.import_request != export.export_scope.recipient.request
        || export.request.delivery != export.export_scope.recipient.delivery
    { return Err(Error::Authentication); }
    validate_original_audit_v3(&export.export_scope, status)
}
fn validate_original_audit_v3(scope: &DurableReviewExportScopeV3, status: &DurableDeliveryAdmissionStatusV2) -> Result<()> {
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
fn validate_closed_status_v3(scope: &DurableReviewExportScopeV3, status: &DurableDeliveryAdmissionStatusV3) -> Result<()> {
    status.validate().map_err(|_| Error::Authentication)?;
    if status.intent_digest != scope.recipient.digest().map_err(|_| Error::Authentication)? {
        return Err(Error::Authentication);
    }
    let audit = status.verified_audit().map_err(|_| Error::Receipt(
        "The original V3 operation remains pending or unknown: complete authenticated Witness history has not established admission. Preserve the original operation; do not resend it".into(),
    ))?;
    validate_original_audit_v3(scope, audit)
}
/// Explicit CLI purpose. Input selects the original reviewer, not a source,
/// session or native issuer. All native decisions still occur in the real GUI.
pub(in crate::host) fn admit_original_v3(terminal: Terminal, profile: &Path, workspace: &Path) -> Result<()> {
    let host = Host::open_workspace_dispatcher_registered_v4(terminal, profile, workspace, false)?;
    admit_original_borrowed_v3(&host, workspace, None).map(|_| ())
}
/// Same one-shot admission under a caller-owned original Host. Returned values
/// are inert, already-checked history only, never native source or action owners.
/// A foreground two-owner session keeps this Host process alive after return.
pub(in crate::host) fn admit_original_borrowed_v3(
    host: &Host,
    workspace: &Path,
    previous: Option<&OriginalDeliveryExportV3>,
) -> Result<(OriginalDeliveryExportV3, DurableDeliveryAdmissionStatusV3)> {
    let terminal = &host.terminal;
    let selection: ReviewerRequestV2 = host.read_json("Exact original reviewer request and bounded prospective delivery choices JSON for CLOSED V3: ")?;
    if previous.is_some_and(|prior| prior.export_scope.recipient.account_id == selection.account_id
        || prior.export_scope.recipient.participant_id == selection.participant_id)
    { return Err(Error::Authentication); }
    if !selection.signer_socket.is_absolute() { return Err(Error::Authentication); }
    let (verified, exported) = host.private_original_delivery_export_v3(workspace, &selection.choices, |fixed, digest, bytes, delivery, materials| {
        if fixed.proposal_binding != selection.request.proposal_binding
            || previous.is_some_and(|prior| prior.request.delivery != *delivery
                || prior.export_scope.proposal != *fixed)
        { return Err(Error::Authentication); }
        let pair = PairScope { account_id: selection.account_id.clone(), participant_id: selection.participant_id.clone(), agreement_id: fixed.agreement_id.clone(), manifest_digest: fixed.manifest_digest.clone(), history_read: true, authorization_export: false, preconstruction_export: true };
        terminal.confirm("Pair this installed original reviewer for original setup and independently approved closed V3 receive/view. No financial execution is enabled.")?;
        let client = OriginalHistoryClient::pair(InstalledSignerProvider::load().map_err(|_| Error::Permission)?, &selection.signer_socket, "wholepact-original-delivery-v3", pair).map_err(|_| Error::Permission)?;
        client.prepare_closed_recipient_v3(selection.request.clone(), fixed.clone(), digest.into(), bytes, delivery.clone(), materials.to_vec()).map_err(|_| Error::Permission)
    })?;
    let mut pending = verified.request_admission_retained_v3().map_err(|_| Error::Receipt("No completed V3 admission status is available; preserve the original operation and use read-only history reconciliation".into()))?;
    let status = match pending.await_status_v3() {
        Ok(status) if status.verified_audit().is_ok() => status,
        _ => {
            // Do not disclose a private preliminary DTO outside a current read.
            // This non-private notice never labels pending data as success.
            terminal.message("Admission is pending or uncertain. Request a separately approved read of complete original Witness history; the mutation will not be resent.\n")?;
            pending.read_original_status_v3().map_err(|_| Error::Receipt("The original V3 admission remains pending or unknown. Fresh history was unavailable or not approved; preserve the retained operation and use the V3 status command, never resend admission".into()))?
        }
    };
    validate_closed_status_v3(&exported.export_scope, &status)?;
    validate_admission_result_v3(&exported, status.verified_audit().map_err(|_| Error::Authentication)?)?;
    host.display_original_admission_status_v3(workspace, &exported.export_scope, &status)?;
    Ok((exported, status))
}
/// Actual retained original IPC custody, not an imported success flag. The
/// caller retains this before awaiting status; both the exact original Host
/// borrow and provider/peer continuation survive a refused or uncertain read.
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(in crate::host::financial) struct RetainedCoordinatedAdmissionV1<'host> {
    host: &'host Host,
    workspace: &'host Path,
    pending: wholepact_signer::authority_bridge::durable_delivery_admission_ipc_v3::PendingDurableDeliveryAdmissionV3,
    exported: OriginalDeliveryExportV3,
    admitted: Option<DurableDeliveryAdmissionStatusV3>,
    verification_started: bool,
    material_delivery_restriction: retained_result_v1::HostMaterialDeliveryRestrictionV1,
}

#[cfg(feature = "coordinated-financial-workflow-v1")]
impl RetainedCoordinatedAdmissionV1<'_> {
    /// Checked retained metadata only, never a recovered Read or new effect
    /// permission. The actual Pending/provider/Peer stays owned by this value.
    pub(in crate::host::financial) fn checked_admission_status(&self) -> Result<&DurableDeliveryAdmissionStatusV3> {
        self.checked_export()?;
        self.admitted.as_ref().ok_or(Error::Permission)
    }

    pub(in crate::host::financial) fn verify_admission(&mut self) -> Result<()> {
        if self.verification_started {
            return Err(Error::Permission);
        }
        self.verification_started = true;
        let status = match self.pending.await_status_v3() {
            Ok(status) if status.verified_audit().is_ok() => status,
            _ => {
                self.host.terminal.message("Admission is pending or uncertain. Request a separately approved read of complete original Witness history; the mutation will not be resent.\n")?;
                self.pending.read_original_status_retained_v3().map_err(|_| Error::Receipt("The original V3 admission remains pending or unknown. Fresh history was unavailable or not approved; preserve the retained operation and use the V3 status command, never resend admission".into()))?
            }
        };
        validate_closed_status_v3(&self.exported.export_scope, &status)?;
        validate_admission_result_v3(
            &self.exported,
            status.verified_audit().map_err(|_| Error::Authentication)?,
        )?;
        self.host.display_original_admission_status_v3(self.workspace, &self.exported.export_scope, &status)?;
        self.admitted = Some(status);
        Ok(())
    }

    fn checked_export(&self) -> Result<&OriginalDeliveryExportV3> {
        self.admitted
            .as_ref()
            .ok_or(Error::Permission)?
            .verified_audit()
            .map_err(|_| Error::Authentication)?;
        Ok(&self.exported)
    }
}

/// Separate concrete fixed-fork path. The legacy command above is unchanged.
/// The verifier must come from the one original H; no fallback installation,
/// endpoint discovery, replacement process or caller-claimed peer is accepted.
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(in crate::host::financial) fn begin_original_borrowed_fork_v3<'host>(
    host: &'host Host,
    workspace: &'host Path,
    previous: Option<&RetainedCoordinatedAdmissionV1<'_>>,
    verifier: wholepact_financial_coordinator_origin::OriginalForkSignerVerifier,
) -> Result<RetainedCoordinatedAdmissionV1<'host>> {
    let previous = previous.map(|prior| {
        if !std::ptr::eq(host, prior.host) || workspace != prior.workspace {
            return Err(Error::Authentication);
        }
        // Exact selection equality is not filesystem custody. The maintained
        // original source checks below still reopen and verify that custody.
        prior.checked_export()
    }).transpose()?;
    let terminal = &host.terminal;
    let selection: ReviewerRequestV2 = host.read_json("Exact original reviewer request and bounded prospective delivery choices JSON for CLOSED V3: ")?;
    if previous.is_some_and(|prior| prior.export_scope.recipient.account_id == selection.account_id
        || prior.export_scope.recipient.participant_id == selection.participant_id)
    { return Err(Error::Authentication); }
    if !selection.signer_socket.is_absolute() { return Err(Error::Authentication); }
    let mut material_delivery_restriction = None;
    let (verified, exported) = host.private_original_delivery_export_v3(workspace, &selection.choices, |fixed, digest, bytes, delivery, materials| {
        if fixed.proposal_binding != selection.request.proposal_binding
            || previous.is_some_and(|prior| prior.request.delivery != *delivery
                || prior.export_scope.proposal != *fixed)
        { return Err(Error::Authentication); }
        material_delivery_restriction = Some(retained_result_v1::HostMaterialDeliveryRestrictionV1::capture(delivery, materials)?);
        let pair = PairScope { account_id: selection.account_id.clone(), participant_id: selection.participant_id.clone(), agreement_id: fixed.agreement_id.clone(), manifest_digest: fixed.manifest_digest.clone(), history_read: true, authorization_export: false, preconstruction_export: true };
        terminal.confirm("Pair this installed original reviewer for original setup and independently approved closed V3 receive/view. No financial execution is enabled.")?;
        let provider = InstalledSignerProvider::load_for_original_fork(verifier).map_err(|_| Error::Permission)?;
        let client = OriginalHistoryClient::pair(provider, &selection.signer_socket, "wholepact-original-delivery-v3", pair).map_err(|_| Error::Permission)?;
        client.prepare_closed_recipient_v3(selection.request.clone(), fixed.clone(), digest.into(), bytes, delivery.clone(), materials.to_vec()).map_err(|_| Error::Permission)
    })?;
    let pending = verified.request_admission_retained_v3().map_err(|_| Error::Receipt("No completed V3 admission status is available; preserve the original operation and use read-only history reconciliation".into()))?;
    Ok(RetainedCoordinatedAdmissionV1 {
        host,
        workspace,
        pending,
        exported,
        admitted: None,
        verification_started: false,
        material_delivery_restriction: material_delivery_restriction.ok_or(Error::Permission)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalHistorySelectionV3 {
    signer_socket: PathBuf,
    import_operation_id: String,
}
pub(in crate::host) fn read_original_status_v3(terminal: Terminal, profile: &Path, workspace: &Path) -> Result<()> {
    // New real source opening and full proof/history verification. Only inert
    // original export metadata is selected; no prior native grant is recovered.
    let host = Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let source = host.private_original_delivery_status_checked_v3(workspace, |source, approval, check, clocks| {
        let output = terminal.historical_output()?;
        approval.effect(&mut || output.json_checked_under(source, check, approval, clocks))
    })?;
    let selection: OriginalHistorySelectionV3 = host.read_json("Original Signer socket and retained V3 import_operation_id for fresh read-only reconciliation JSON: ")?;
    if !selection.signer_socket.is_absolute() { return Err(Error::Authentication); }
    let export = source.review_exports.iter().find(|scope| scope.recipient.request.operation_id == selection.import_operation_id).ok_or(Error::Authentication)?;
    let recipient = &export.recipient;
    let authorization_id = recipient.delivery.owners.iter().find(|owner| owner.account_id == recipient.account_id && owner.participant_id == recipient.participant_id).ok_or(Error::Authentication)?.original_authorization_id.clone();
    let request = DurableDeliveryHistoryRequestV3 { intent_digest: recipient.digest().map_err(|_| Error::Authentication)?, authorization_id };
    terminal.confirm("Connect to the installed ORIGINAL reviewer for a separately approved fresh V3 history read. This may read only the retained original operation and complete authenticated Witness history, never pair a V2 grant, resend admission or recover a previous native permission.")?;
    let client = ReopenedDurableDeliveryHistoryClientV3::connect(
        InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
        &selection.signer_socket, recipient.clone(), request,
    ).map_err(|_| Error::Permission)?;
    let status = client.read_original_status_v3().map_err(|_| Error::Receipt("Fresh original V3 history is unavailable or unapproved. The retained operation remains pending or unknown; do not resend admission".into()))?;
    validate_closed_status_v3(export, &status)?;
    host.display_original_admission_status_v3(workspace, export, &status)
}

mod financial_partial_v2;
pub(in crate::host) use financial_partial_v2::admit_original_financial_borrowed_v2;
