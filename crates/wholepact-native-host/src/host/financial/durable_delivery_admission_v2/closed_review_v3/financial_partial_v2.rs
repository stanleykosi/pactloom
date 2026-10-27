//! Versioned partial financial progress export. Every existing fixed-source,
//! recipient, explicit disclosure and pre-effect journal guard remains present.
use super::*;
use crate::host::durable_dispatcher_v2::OriginalFinancialOwnerV2;
use wholepact_engine::{PrivateDurableFinancialInspectionV2, LocalPrivateDurableFinancialConsentV1};
struct ClosedConsentFinancialV2<'a, 'host> {
    host: &'a Host,
    owner: &'a OriginalFinancialOwnerV2<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV2,
    approval: &'a HistoricalApproval,
    export: Option<&'a DurableReviewExportScopeV3>,
}
impl ClosedConsentFinancialV2<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.host.require_manual_session()?;
        self.owner.check_effect_source()?;
        current_materials(self.inspection)?;
        if !same(self.owner.workspace_scope(), self.inspection.workspace_scope())?
            || self.host.access()?.principal_id != self.inspection.workspace_scope().principal_id()
        { return Err(Error::Authentication); }
        self.approval.check()
    }
}
impl LocalPrivateDurableAdmissionConsentV2 for ClosedConsentFinancialV2<'_, '_> {
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
impl LocalProofConsent for ClosedConsentFinancialV2<'_, '_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        proof_matches(self.inspection, scope, action) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for ClosedConsentFinancialV2<'_, '_> {
    fn permits(&self, scope: &DurableConstructionScopeV1, digest: &str, action: DurableMaterialActionV1) -> bool {
        let expected = if self.export.is_some() { DurableMaterialActionV1::ExportForLocalNativeReview } else { DurableMaterialActionV1::ReadForExactConstruction };
        std::mem::discriminant(&action) == std::mem::discriminant(&expected)
            && material_matches(self.inspection, scope, digest) && self.check().is_ok()
    }
}
impl LocalDurableReviewExportConsentV3 for ClosedConsentFinancialV2<'_, '_> {
    fn permits(&self, scope: &DurableReviewExportScopeV3) -> bool {
        self.export.is_some_and(|exact| exact == scope) && self.check().is_ok()
    }
}
fn retained_material_clock_bounds(inspection: &PrivateDurableFinancialInspectionV2) -> Result<(u64, u64)> {
    if inspection.materials().len() != 2 { return Err(Error::Authentication); }
    let from = inspection.materials().iter().map(|m| m.scope().valid_from_unix_seconds).max().ok_or(Error::Authentication)?;
    let until = inspection.materials().iter().map(|m| m.scope().valid_until_unix_seconds).min().ok_or(Error::Authentication)?;
    Ok((from, until))
}
fn original_material_clock_bounds(inspection: &PrivateDurableFinancialInspectionV2) -> Result<(u64, u64)> {
    let (from, until) = retained_material_clock_bounds(inspection)?;
    let now = now_seconds()?;
    if now < from || now >= until { return Err(Error::Permission); }
    Ok((from, until))
}
fn current_materials(inspection: &PrivateDurableFinancialInspectionV2) -> Result<()> {
    let now = now_seconds()?;
    if inspection.materials().len() != 2 {
        return Err(Error::Authentication);
    }
    for material in inspection.materials() {
        material
            .scope()
            .check_valid_at(now)
            .map_err(|_| Error::Permission)?;
    }
    Ok(())
}
/// No proof mutex is acquired: this is also called by the actual held proof
/// reader. The Engine independently rechecks its own retained lineage.
fn current_source(
    host: &Host,
    owner: &OriginalFinancialOwnerV2<'_>,
    inspection: &PrivateDurableFinancialInspectionV2,
) -> Result<()> {
    host.require_private_workspace_read_session_v1()?;
    owner.check_read_source()?;
    current_materials(inspection)?;
    if !same(owner.workspace_scope(), inspection.workspace_scope())?
        || host.access()?.principal_id != inspection.workspace_scope().principal_id()
        || inspection.materials().iter().any(|m| {
            m.scope().proposal.proposal_id != inspection.fixed_identity().proposal_id
                || m.scope().proposal.manifest.agreement.agreement_id
                    != inspection.workspace_scope().agreement_id()
                || m.scope().protected_destination
                    != inspection
                        .workspace_scope()
                        .protected_destination()
                        .to_string_lossy()
                || m.scope().retention_policy != inspection.workspace_scope().retention_policy()
        })
    {
        return Err(Error::Authentication);
    }
    owner.check_read_source()?;
    current_materials(inspection)
}
fn material_matches(
    inspection: &PrivateDurableFinancialInspectionV2,
    scope: &DurableConstructionScopeV1,
    digest: &str,
) -> bool {
    inspection
        .materials()
        .iter()
        .any(|m| m.scope() == scope && m.material_digest() == digest)
}
fn exact_read_proof_role(
    expected: &CheckpointScope,
    scope: &CheckpointScope,
    action: LocalAction,
) -> bool {
    scope == expected
        && matches!(
            action,
            LocalAction::InspectStatus | LocalAction::ReadPrivateArtifact
        )
}
fn proof_matches(
    inspection: &PrivateDurableFinancialInspectionV2,
    scope: &CheckpointScope,
    action: LocalAction,
) -> bool {
    exact_read_proof_role(inspection.checkpoint_scope(), scope, action)
}
struct InspectionReadFinancialV2<'a, 'host> {
    host: &'a Host,
    owner: &'a OriginalFinancialOwnerV2<'host>,
    inspection: &'a PrivateDurableFinancialInspectionV2,
    approval: &'a HistoricalApproval,
    export_preview: bool,
}
impl InspectionReadFinancialV2<'_, '_> {
    fn check_approval(&self) -> Result<()> {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if self.export_preview && SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()) {
            return self.approval.check_observed(|failure, error| {
                use crate::terminal::historical::HistoricalApprovalFailure as F;
                let site = match failure {
                    F::Deadline => DeliveryObservationSiteV2::HistoricalApprovalDeadline,
                    F::Foreground => DeliveryObservationSiteV2::HistoricalApprovalForeground,
                };
                observe_delivery(site, host_outcome(error));
            });
        }
        self.approval.check()
    }
    fn check(&self) -> Result<()> {
        if self.export_preview {
            host_result(
                DeliveryObservationSiteV2::NativeCheck,
                self.host.require_manual_session(),
            )?;
        }
        export_check_result(
            self.export_preview,
            DeliveryObservationSiteV2::NativeCheck,
            self.check_approval(),
        )?;
        export_check_result(
            self.export_preview,
            DeliveryObservationSiteV2::SourceCheck,
            current_source(self.host, self.owner, self.inspection),
        )?;
        export_check_result(
            self.export_preview,
            DeliveryObservationSiteV2::NativeCheck,
            self.check_approval(),
        )
    }
}
impl LocalPrivateDurableAdmissionConsentV2 for InspectionReadFinancialV2<'_, '_> {
    fn check_final_effect_restriction_v1(&self, original_deadline: Option<std::time::Instant>) -> bool {
        if crate::terminal::coordinated_restriction_required()
            && original_deadline.is_some_and(|until| std::time::Instant::now() >= until)
        { return false; }
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clock_bounds(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, s: &PrivateWorkspaceScopeV1) -> bool {
        export_source_scope_result(
            self.export_preview,
            same(s, self.inspection.workspace_scope()),
        )
        .unwrap_or(false)
            && self.check().is_ok()
    }
}
impl LocalProofConsent for InspectionReadFinancialV2<'_, '_> {
    fn permits(&self, s: &CheckpointScope, a: LocalAction) -> bool {
        export_predicate(
            self.export_preview,
            DeliveryObservationSiteV2::ProofRolePredicate,
            proof_matches(self.inspection, s, a),
        ) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for InspectionReadFinancialV2<'_, '_> {
    fn permits(&self, s: &DurableConstructionScopeV1, d: &str, a: DurableMaterialActionV1) -> bool {
        // Inspection and exact local preparation never grant export authority.
        let allowed = matches!(a, DurableMaterialActionV1::ReadForExactConstruction);
        export_predicate(
            self.export_preview,
            DeliveryObservationSiteV2::MaterialActionPredicate,
            allowed,
        ) && export_predicate(
            self.export_preview,
            DeliveryObservationSiteV2::MaterialScopePredicate,
            material_matches(self.inspection, s, d),
        ) && self.check().is_ok()
    }
}
fn source_plan(
    owner: &OriginalFinancialOwnerV2<'_>,
    inspection: &PrivateDurableFinancialInspectionV2,
    choices: &DeliveryChoicesV2,
) -> Result<DurableDeliveryPlanV2> {
    choices.check()?;
    current_materials(inspection)?;
    let host = owner.original_host_generation_binding()?;
    let fixed: DurableFixedCandidateBindingV1 =
        wholepact_core::parse_typed_json(&serde_json::to_vec(inspection.fixed_identity())?)
            .map_err(|_| Error::Authentication)?;
    fixed.validate().map_err(|_| Error::Authentication)?;
    let destinations = owner.original_destinations()?;
    if destinations.len() != 2 {
        return Err(Error::Authentication);
    }
    let mut from = 0u64;
    let mut until = u64::MAX;
    let mut owners = Vec::new();
    for d in &destinations {
        let material = inspection
            .materials()
            .iter()
            .find(|m| m.scope().account_id == d.original_terms.identity.account_id)
            .ok_or(Error::Authentication)?;
        if material.scope().participant_id != d.original_terms.scope.participant_id
            || d.original_terms.host != host
        {
            return Err(Error::Authentication);
        }
        from = from
            .max(
                material
                    .scope()
                    .valid_from_unix_seconds
                    .checked_mul(1000)
                    .ok_or(Error::Invalid)?,
            )
            .max(d.original_terms.issued_at_ms);
        until = until
            .min(
                material
                    .scope()
                    .valid_until_unix_seconds
                    .checked_mul(1000)
                    .ok_or(Error::Invalid)?,
            )
            .min(d.original_terms.scope.expires_at_ms);
        owners.push(DurableDeliveryOwnerLineageV2 {
            account_id: d.original_terms.identity.account_id.clone(),
            participant_id: d.original_terms.scope.participant_id.clone(),
            original_authorization_id: canonical_durable_authorization_id_v2(
                &fixed,
                &d.original_terms.identity,
            )
            .map_err(|_| Error::Authentication)?,
        });
    }
    owners.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    if from == 0
        || from >= until
        || now_seconds()?.checked_mul(1000).ok_or(Error::Invalid)? >= until
    {
        return Err(Error::Permission);
    }
    Ok(DurableDeliveryPlanV2 {
        dispatcher: owner.descriptor()?,
        original_host_generation_binding_digest: original_host_generation_binding_digest_v2(&host)
            .map_err(|_| Error::Authentication)?,
        original_host_profile_id: host.profile_id,
        submission_journal_identity: owner.submission_journal_identity()?,
        submission_operation_id: choices.submission_operation_id.clone(),
        provider: choices.provider.clone(),
        route: choices.route.clone(),
        owners,
        valid_from_ms: from,
        valid_until_ms: until,
        minimum_expiry_margin_blocks: choices.minimum_expiry_margin_blocks,
        maximum_fresh_admission_lifetime_ms: choices.maximum_fresh_admission_lifetime_ms,
        maximum_explicitly_approved_attempts: choices.maximum_explicitly_approved_attempts,
        extraction_rule: DurableDeliveryExtractionRuleV2::FirstDurablyRetainedVerifiedExtraction,
        retry_rule: DurableDeliveryRetryRuleV2::SameRetainedBytesWithFreshAdmission,
        attempt_rule: DurableDeliveryAttemptRuleV2::ExplicitImmediateHostDecision,
    })
}
fn original_review_prompt_bounds(prior: &HistoricalApproval, inspection: &PrivateDurableFinancialInspectionV2) -> Result<Option<crate::terminal::OriginalPromptBoundsV1>> {
    if !crate::terminal::coordinated_restriction_required() { return Ok(None); }
    let (from, until) = retained_material_clock_bounds(inspection)?;
    Ok(Some(crate::terminal::OriginalPromptBoundsV1::new(prior.deadline(), (
        from.checked_mul(1000).ok_or(Error::Permission)?, until.checked_mul(1000).ok_or(Error::Permission)?,
    ))?))
}

impl Host {
    pub(in crate::host) fn private_original_financial_delivery_export_v2(
        &self, root: &Path, choices: &DeliveryChoicesV2,
        open_recipient: impl FnOnce(&FixedProposalIdentityV1, &str, u64, &DurableDeliveryPlanV2, &[DurableDeliveryMaterialScopeRefV2]) -> Result<PreparedDurableReviewRecipientV3>,
    ) -> Result<(VerifiedImportedDurableReviewSessionV3, OriginalDeliveryExportV3)> {
        self.require_manual_session()?;
        let owner = host_result(DeliveryObservationSiteV2::SourceOpen, self.original_financial_owner_v2(root))?;
        let inspection = owner.initial_inspection();
        let plan = source_plan(&owner, &inspection, choices)?;
        plan.validate_origins().map_err(|_| Error::Invalid)?;
        // This read decision expires normally and is destroyed after preparation.
        let preparation = source_checked_approval_v2(
            || current_source(self, &owner, &inspection),
            || self.terminal.approve_historical("Approve LOCAL exact-byte preparation for closed original delivery. Read and fully verify the selected retained proof and BOTH original materials, and retain one exact encoded private payload in local memory under the ORIGINAL absolute ceilings. No recipient disclosure, transport, signing, submission or admission is authorized."),
        )?;
        let read = InspectionReadFinancialV2 { host: self, owner: &owner, inspection: &inspection, approval: &preparation, export_preview: true };
        let prepared = engine_result(DeliveryObservationSiteV2::ExportPreview, owner.coordinator().prepare_original_delivery_v2(self.access()?, &read, &read, &read))?;
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
            || { owner.check_effect_source()?; current_materials(&inspection) },
            || self.terminal.approve_historical("Inspect exact closed original export metadata for the actually prepared native recipient. Read only the retained source/policy identity and exact payload commitment under both ORIGINAL material ceilings. No private payload export, financial admission, signing or submission is authorized."),
        )?;
        let read = ClosedConsentFinancialV2 { host: self, owner: &owner, inspection: &inspection, approval: &final_inspection, export: None };
        let closed = engine_result(DeliveryObservationSiteV2::ExportPreview,
            prepared.bind_prepared_recipient_v2(recipient, self.access()?, &read, &read, &read))?;
        let export_scope = closed.scope().clone();
        let detail = format!(
            "EXPORT EXACT ORIGINAL DELIVERY FOR DURABLE FINANCIAL V2\n{}\n{}\nDisclose the full retained private candidate, viewing keys, notes and witnesses ONLY to this prepared installed reviewer and exact original source/process/read context. No transport socket or export grant has waited for this review. After this final response, a one-use prompt-free channel must match the exact preparation. Changed, expired, locked or restarted preparation is refused without fallback. Retain DisclosedOrUnknown before the first private byte; failure cannot undo disclosure. This does not sign, submit, acquire, reserve or activate financial execution. Prospective admission requires its own native decision.",
            serde_json::to_string(&inspection)?, serde_json::to_string(&export_scope)?
        );
        bound_original_delivery_review_v2(&detail)?;
        let prompt_bounds = original_review_prompt_bounds(&final_inspection, &inspection)?;
        let approval = host_result(DeliveryObservationSiteV2::ExportApproval, self.terminal.approve_durable_delivery_original_v3(
            &final_inspection, &detail,
            || { read.check()?; engine_result(DeliveryObservationSiteV2::ExportApproval, closed.check_current_v2(self.access()?, &read, &read, &read)) },
            || { owner.check_effect_source()?; current_materials(&inspection) },
            prompt_bounds.as_ref(),
        ))?;
        drop(read);
        drop(final_inspection);
        let consent = ClosedConsentFinancialV2 { host: self, owner: &owner, inspection: &inspection, approval: &approval, export: Some(&export_scope) };
        consent.check()?;
        let delivered = observed_engine_result(DeliveryObservationSiteV2::ExportCommit,
            closed.deliver_v2(self.access()?, &consent, &consent, &consent, &consent, approval.deadline()));
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
}
pub(in crate::host) fn admit_original_financial_borrowed_v2(
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
    let (verified, exported) = host.private_original_financial_delivery_export_v2(workspace, &selection.choices, |fixed, digest, bytes, delivery, materials| {
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
    // No raw status is displayed under a completed export permission. The
    // next financial-history/continuation step obtains a separate fresh Read.
    host.terminal.message("Original V2 owner admission was authenticated. No signing or return has occurred; each needs its separate native permission.\n")?;
    Ok((exported, status))
}
