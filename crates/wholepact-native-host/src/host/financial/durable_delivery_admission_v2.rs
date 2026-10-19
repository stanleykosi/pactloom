//! Prospective original-source delivery admission. This purpose is disjoint
//! from the fixed-workspace stage/compound permissions and never grants spend.
use super::Host;
use crate::{
    Error, Result,
    terminal::{Terminal, historical::HistoricalApproval},
};
use crate::host::durable_dispatcher_v2::OriginalDeliveryAdmissionOwnerV2;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_authority::{
    durable_delivery_admission_v2::{
        canonical_durable_authorization_id_v2, original_host_generation_binding_digest_v2,
    },
    durable_delivery_scope_v2::*,
    durable_payment_v1::DurableFixedCandidateBindingV1,
};
use wholepact_engine::{
    PrivateDurableAdmissionInspectionV2, PrivateDurableAdmissionStatusV2,
    PrivateDurableAdmissionDeliveryV2, PrivateWorkspaceScopeV1,
    LocalPrivateDurableAdmissionConsentV2,
};
use wholepact_engine::durable_construction_v1::{
    DurableMaterialActionV1, LocalDurableMaterialConsentV1,
    review_export_v1::{DurableReviewExportScopeV1, LocalDurableReviewExportConsentV1},
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_signer::authority_bridge::{
    ipc::OriginalHistoryClient,
    provider::InstalledSignerProvider,
    durable_construction_v1::DurableConstructionScopeV1,
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    durable_delivery_admission_ipc_v2::{
        DurableDeliveryAdmissionRequestV2, DurableDeliveryAdmissionStatusV2,
    },
};
use wholepact_signer::ipc::PairScope;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::host) enum DeliveryObservationSiteV2 {
    SourceOpen,
    SourceInspection,
    SourcePlan,
    RecipientPrepare,
    ExportPreview,
    ExportApproval,
    ExportCommit,
    ExportPostcheck,
    NativeCheck,
    SourceCheck,
    FixedRead,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::host) enum DeliveryObservationOutcomeV2 {
    ReturnedOk,
    EngineDisclosureUnknown,
    EngineDisclosureDenied,
    EngineRecoveryRequired,
    EngineIdempotencyConflict,
    EngineRevisionConflict,
    EngineDurableProposalConflict,
    EngineDurableConstructionUnavailable,
    EngineDurableProfileUnavailable,
    EngineResourceExhausted,
    EngineUnclassified,
    BridgeBinding,
    BridgeConflict,
    BridgeMissing,
    BridgeUncertain,
    BridgeLimit,
    BridgePermission,
    BridgeRecoveryRequired,
    BridgeCompleteOriginRecoveryUnavailable,
    BridgeVerification,
    BridgeSignerOriginUnavailable,
    BridgeJournal,
    BridgeAuthority,
    BridgeWallet,
    BridgeIpc,
    HostPlatform,
    HostTerminal,
    HostPermission,
    HostLocked,
    HostInvalid,
    HostAuthentication,
    HostStorage,
    HostQuarantined,
    HostUnsupported,
    HostReceipt,
    HostRecoverySemantic,
    HostRecoveryBackupUnsupported,
    HostRecoveryFinancialUnsupported,
    HostCompleteOriginRecoveryUnavailable,
    HostHistoricalExportIncomplete,
    HostGenerationArchiveIncomplete,
    HostUnclassified,
}
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
thread_local! { static DELIVERY_OBSERVER_V2: std::cell::Cell<Option<fn(DeliveryObservationSiteV2,DeliveryObservationOutcomeV2)>> = const { std::cell::Cell::new(None) }; }
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(in crate::host) fn with_delivery_observer_v2<T>(
    observer: fn(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2),
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<fn(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            DELIVERY_OBSERVER_V2.with(|cell| cell.set(self.0));
        }
    }
    let old = DELIVERY_OBSERVER_V2.with(|cell| cell.replace(Some(observer)));
    let _restore = Restore(old);
    f()
}
fn observe_delivery(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    DELIVERY_OBSERVER_V2.with(|cell| {
        if let Some(observer) = cell.get() {
            observer(site, outcome);
        }
    });
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = (site, outcome);
}
fn engine_outcome(error: &wholepact_engine::ApiError) -> DeliveryObservationOutcomeV2 {
    use DeliveryObservationOutcomeV2 as O;
    match error.code.as_str() {
        "DISCLOSURE_UNKNOWN" => O::EngineDisclosureUnknown,
        "DISCLOSURE_DENIED" => O::EngineDisclosureDenied,
        "RECOVERY_REQUIRED" | "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => O::EngineRecoveryRequired,
        "IDEMPOTENCY_CONFLICT" => O::EngineIdempotencyConflict,
        "REVISION_CONFLICT" => O::EngineRevisionConflict,
        "DURABLE_PROPOSAL_CONFLICT" => O::EngineDurableProposalConflict,
        "DURABLE_CONSTRUCTION_UNAVAILABLE" => O::EngineDurableConstructionUnavailable,
        "DURABLE_PROFILE_UNAVAILABLE" => O::EngineDurableProfileUnavailable,
        "RESOURCE_EXHAUSTED" => O::EngineResourceExhausted,
        _ => O::EngineUnclassified,
    }
}
/// Observe only the borrowed error of the result already returned by the
/// existing operation. This kernel does not run, clone or replace that operation.
fn observed_result<T, E>(
    site: DeliveryObservationSiteV2,
    result: std::result::Result<T, E>,
    outcome: impl FnOnce(&E) -> DeliveryObservationOutcomeV2,
) -> std::result::Result<T, E> {
    if let Err(error) = &result {
        observe_delivery(site, outcome(error));
    }
    result
}
fn engine_result<T>(
    site: DeliveryObservationSiteV2,
    result: wholepact_engine::Result<T>,
) -> Result<T> {
    observed_result(site, result, engine_outcome).map_err(Error::from)
}
fn bridge_outcome(
    error: &wholepact_signer::authority_bridge::BridgeError,
) -> DeliveryObservationOutcomeV2 {
    use wholepact_signer::authority_bridge::BridgeError as E;
    use DeliveryObservationOutcomeV2 as O;
    match error {
        E::Binding => O::BridgeBinding,
        E::Conflict => O::BridgeConflict,
        E::Missing => O::BridgeMissing,
        E::Uncertain => O::BridgeUncertain,
        E::Limit => O::BridgeLimit,
        E::Permission => O::BridgePermission,
        E::RecoveryRequired => O::BridgeRecoveryRequired,
        E::CompleteOriginRecoveryUnavailable => O::BridgeCompleteOriginRecoveryUnavailable,
        E::Verification => O::BridgeVerification,
        E::SignerOriginUnavailable => O::BridgeSignerOriginUnavailable,
        E::Journal(_) => O::BridgeJournal,
        E::Authority(_) => O::BridgeAuthority,
        E::Wallet(_) => O::BridgeWallet,
        E::Ipc => O::BridgeIpc,
    }
}
fn bridge_result<T>(
    site: DeliveryObservationSiteV2,
    result: wholepact_signer::authority_bridge::Result<T>,
) -> wholepact_signer::authority_bridge::Result<T> {
    observed_result(site, result, bridge_outcome)
}
fn host_outcome(error: &Error) -> DeliveryObservationOutcomeV2 {
    use DeliveryObservationOutcomeV2 as O;
    match error {
        Error::Platform => O::HostPlatform,
        Error::Terminal => O::HostTerminal,
        Error::Permission => O::HostPermission,
        Error::Locked => O::HostLocked,
        Error::Invalid => O::HostInvalid,
        Error::Authentication => O::HostAuthentication,
        Error::Storage => O::HostStorage,
        Error::Quarantined => O::HostQuarantined,
        Error::Unsupported => O::HostUnsupported,
        Error::Receipt(_) => O::HostReceipt,
        Error::RecoverySemantic(_) => O::HostRecoverySemantic,
        Error::RecoveryBackupUnsupported => O::HostRecoveryBackupUnsupported,
        Error::RecoveryFinancialUnsupported => O::HostRecoveryFinancialUnsupported,
        Error::CompleteOriginRecoveryUnavailable => O::HostCompleteOriginRecoveryUnavailable,
        Error::HistoricalExportIncomplete => O::HostHistoricalExportIncomplete,
        Error::GenerationArchiveIncomplete => O::HostGenerationArchiveIncomplete,
    }
}
fn host_result<T>(site: DeliveryObservationSiteV2, result: Result<T>) -> Result<T> {
    observed_result(site, result, host_outcome)
}
/// Shared read adapters observe an export check only when their existing role
/// is export. Historical reads retain their original behavior and attribution.
fn export_check_result<T>(
    exporting: bool,
    site: DeliveryObservationSiteV2,
    result: Result<T>,
) -> Result<T> {
    if exporting {
        host_result(site, result)
    } else {
        result
    }
}
fn post_export_result(result: Result<()>) -> Result<()> {
    host_result(DeliveryObservationSiteV2::ExportPostcheck, result)
}

/// Explicit future delivery choices only. Original identities, lineage, account
/// IDs and ceilings are NEVER accepted from this caller input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct DeliveryChoicesV2 {
    pub submission_operation_id: String,
    pub provider: wholepact_core::manual_construction::PreconstructionProvider,
    pub route: DurableDeliveryRouteV2,
    pub minimum_expiry_margin_blocks: u32,
    pub maximum_fresh_admission_lifetime_ms: u64,
    pub maximum_explicitly_approved_attempts: u32,
}
impl DeliveryChoicesV2 {
    fn check(&self) -> Result<()> {
        crate::id(&self.submission_operation_id)?;
        crate::id(&self.provider.source_id)?;
        if self.submission_operation_id.len() < 16
            || !(1..=100).contains(&self.minimum_expiry_margin_blocks)
            || !(1..=120_000).contains(&self.maximum_fresh_admission_lifetime_ms)
            || !(1..=128).contains(&self.maximum_explicitly_approved_attempts)
            || self.provider.endpoint.len() > 2048
            || !self.provider.endpoint.starts_with("https://")
            || self.provider.trust_profile != "single_tls_provider_report_not_consensus"
            || matches!(&self.route, DurableDeliveryRouteV2::ExistingHttpConnect { origin } if origin.len()>2048 || !origin.starts_with("http://"))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Serialize)]
pub(in crate::host) struct OriginalDeliveryExportV2 {
    pub request: DurableDeliveryAdmissionRequestV2,
    pub export_scope: DurableReviewExportScopeV1,
    pub retention: PrivateDurableAdmissionDeliveryV2,
}
fn now_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Permission)
}
fn same<T: Serialize>(a: &T, b: &T) -> Result<bool> {
    Ok(serde_json::to_vec(a)? == serde_json::to_vec(b)?)
}
fn current_materials(inspection: &PrivateDurableAdmissionInspectionV2) -> Result<()> {
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
    owner: &OriginalDeliveryAdmissionOwnerV2<'_>,
    inspection: &PrivateDurableAdmissionInspectionV2,
) -> Result<()> {
    host.require_private_workspace_read_session_v1()?;
    owner.check_current_without_proof_lock_v2()?;
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
    owner.check_current_without_proof_lock_v2()?;
    current_materials(inspection)
}
fn material_matches(
    inspection: &PrivateDurableAdmissionInspectionV2,
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
    inspection: &PrivateDurableAdmissionInspectionV2,
    scope: &CheckpointScope,
    action: LocalAction,
) -> bool {
    exact_read_proof_role(inspection.checkpoint_scope(), scope, action)
}
/// Lexical inspection-only adapter. It cannot implement the export-send trait.
struct InspectionReadV2<'a, 'host> {
    host: &'a Host,
    owner: &'a OriginalDeliveryAdmissionOwnerV2<'host>,
    inspection: &'a PrivateDurableAdmissionInspectionV2,
    export_preview: bool,
}
impl InspectionReadV2<'_, '_> {
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
            self.owner.inspection_approval().check(),
        )?;
        export_check_result(
            self.export_preview,
            DeliveryObservationSiteV2::SourceCheck,
            current_source(self.host, self.owner, self.inspection),
        )?;
        export_check_result(
            self.export_preview,
            DeliveryObservationSiteV2::NativeCheck,
            self.owner.inspection_approval().check(),
        )
    }
}
impl LocalPrivateDurableAdmissionConsentV2 for InspectionReadV2<'_, '_> {
    fn permits_source(&self, s: &PrivateWorkspaceScopeV1) -> bool {
        export_check_result(
            self.export_preview,
            DeliveryObservationSiteV2::SourceCheck,
            same(s, self.inspection.workspace_scope()),
        )
        .unwrap_or(false)
            && self.check().is_ok()
    }
}
impl LocalProofConsent for InspectionReadV2<'_, '_> {
    fn permits(&self, s: &CheckpointScope, a: LocalAction) -> bool {
        proof_matches(self.inspection, s, a) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for InspectionReadV2<'_, '_> {
    fn permits(&self, s: &DurableConstructionScopeV1, d: &str, a: DurableMaterialActionV1) -> bool {
        let allowed = if self.export_preview {
            matches!(a, DurableMaterialActionV1::ExportForLocalNativeReview)
        } else {
            matches!(a, DurableMaterialActionV1::ReadForExactConstruction)
        };
        allowed && material_matches(self.inspection, s, d) && self.check().is_ok()
    }
}
/// Privately constructed only after real same-TTY exact review. No caller
/// approval, descriptor-only factory, Clone, serde or compound-boundary getter.
struct OwnedDeliveryConsentV2<'a, 'host> {
    host: &'a Host,
    owner: &'a OriginalDeliveryAdmissionOwnerV2<'host>,
    inspection: &'a PrivateDurableAdmissionInspectionV2,
    approval: HistoricalApproval,
    export: Option<&'a DurableReviewExportScopeV1>,
}
impl OwnedDeliveryConsentV2<'_, '_> {
    fn check(&self) -> Result<()> {
        if self.export.is_some() {
            host_result(
                DeliveryObservationSiteV2::NativeCheck,
                self.host.require_manual_session(),
            )?;
        }
        export_check_result(
            self.export.is_some(),
            DeliveryObservationSiteV2::NativeCheck,
            self.approval.check(),
        )?;
        export_check_result(
            self.export.is_some(),
            DeliveryObservationSiteV2::SourceCheck,
            current_source(self.host, self.owner, self.inspection),
        )?;
        export_check_result(
            self.export.is_some(),
            DeliveryObservationSiteV2::NativeCheck,
            self.approval.check(),
        )
    }
}
impl LocalPrivateDurableAdmissionConsentV2 for OwnedDeliveryConsentV2<'_, '_> {
    fn permits_source(&self, s: &PrivateWorkspaceScopeV1) -> bool {
        export_check_result(
            self.export.is_some(),
            DeliveryObservationSiteV2::SourceCheck,
            same(s, self.inspection.workspace_scope()),
        )
        .unwrap_or(false)
            && self.check().is_ok()
    }
}
impl LocalProofConsent for OwnedDeliveryConsentV2<'_, '_> {
    fn permits(&self, s: &CheckpointScope, a: LocalAction) -> bool {
        proof_matches(self.inspection, s, a) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for OwnedDeliveryConsentV2<'_, '_> {
    fn permits(&self, s: &DurableConstructionScopeV1, d: &str, a: DurableMaterialActionV1) -> bool {
        let expected = if self.export.is_some() {
            DurableMaterialActionV1::ExportForLocalNativeReview
        } else {
            DurableMaterialActionV1::ReadForExactConstruction
        };
        std::mem::discriminant(&a) == std::mem::discriminant(&expected)
            && material_matches(self.inspection, s, d)
            && self.check().is_ok()
    }
}
impl LocalDurableReviewExportConsentV1 for OwnedDeliveryConsentV2<'_, '_> {
    fn permits(&self, s: &DurableReviewExportScopeV1) -> bool {
        self.export.is_some_and(|exact| exact == s) && self.check().is_ok()
    }
}
fn source_plan(
    owner: &OriginalDeliveryAdmissionOwnerV2<'_>,
    inspection: &PrivateDurableAdmissionInspectionV2,
    choices: &DeliveryChoicesV2,
) -> Result<DurableDeliveryPlanV2> {
    choices.check()?;
    current_materials(inspection)?;
    let source = owner.source()?;
    let host = source.original_host_generation_binding()?;
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
        dispatcher: source.descriptor()?,
        original_host_generation_binding_digest: original_host_generation_binding_digest_v2(&host)
            .map_err(|_| Error::Authentication)?,
        original_host_profile_id: host.profile_id,
        submission_journal_identity: source.submission_journal_identity()?,
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
impl Host {
    /// The actual paired recipient is prepared ONCE before the exact native
    /// review. Its original clock is not refreshed by this Host approval.
    pub(in crate::host) fn private_original_delivery_export_v2(
        &self,
        root: &Path,
        client: &OriginalHistoryClient,
        request: DurableReviewDeliveryRequestV1,
        choices: &DeliveryChoicesV2,
    ) -> Result<OriginalDeliveryExportV2> {
        host_result(
            DeliveryObservationSiteV2::SourceOpen,
            self.require_manual_session(),
        )?;
        let owner = host_result(
            DeliveryObservationSiteV2::SourceOpen,
            self.original_delivery_admission_owner_v2(root),
        )?;
        let inspection = engine_result(
            DeliveryObservationSiteV2::SourceInspection,
            owner.coordinator().inspect_original_for_admission_v2(
                host_result(DeliveryObservationSiteV2::SourceInspection, self.access())?,
                &owner,
            ),
        )?;
        let plan = host_result(
            DeliveryObservationSiteV2::SourcePlan,
            source_plan(&owner, &inspection, choices),
        )?;
        // Validate the actual source-derived plan before preparing a recipient
        // or recording exposure. This pure grammar check is not admission.
        host_result(
            DeliveryObservationSiteV2::SourcePlan,
            plan.validate_origins().map_err(|_| Error::Invalid),
        )?;
        let recipient = bridge_result(
            DeliveryObservationSiteV2::RecipientPrepare,
            client.prepare_durable_review_delivery_v1(&request),
        )
        .map_err(|_| Error::Permission)?;
        let read = InspectionReadV2 {
            host: self,
            owner: &owner,
            inspection: &inspection,
            export_preview: true,
        };
        let export_scope = engine_result(
            DeliveryObservationSiteV2::ExportPreview,
            owner.coordinator().review_original_delivery_v2(
                host_result(DeliveryObservationSiteV2::ExportPreview, self.access())?,
                &recipient,
                &read,
                &read,
                &read,
            ),
        )?;
        host_result(DeliveryObservationSiteV2::ExportPreview, read.check())?;
        if export_scope.proposal != *inspection.fixed_identity()
            || export_scope.recipient.request != request
        {
            return host_result(
                DeliveryObservationSiteV2::ExportPreview,
                Err(Error::Authentication),
            );
        }
        let detail = format!(
            "Approve exact original delivery export and prospective admission request.\n{}\n{}\n{}\nDisclose the full retained private candidate, viewing keys, notes and witnesses to ONLY this actual installed reviewer. Retain DisclosedOrUnknown before any byte; failure cannot undo disclosure. Prospective policy names the original dispatcher and provider, one verified retained extraction and same-byte explicit retries, bounded by the original absolute ceilings. Provider receives the entire final transaction and connection metadata; each witness receives final commitments, backend linkage and account/reservation linkage. This operation does not sign, submit, enroll a live dispatcher or authorize any v2 financial execution.",
            host_result(
                DeliveryObservationSiteV2::ExportApproval,
                serde_json::to_string(&inspection).map_err(Error::from),
            )?,
            host_result(
                DeliveryObservationSiteV2::ExportApproval,
                serde_json::to_string(&export_scope).map_err(Error::from),
            )?,
            host_result(
                DeliveryObservationSiteV2::ExportApproval,
                serde_json::to_string(&plan).map_err(Error::from),
            )?
        );
        let approval = host_result(
            DeliveryObservationSiteV2::ExportApproval,
            self.terminal.approve_durable_delivery_v2(
                owner.inspection_approval(),
                &detail,
                || {
                    read.check()?;
                    bridge_result(
                        DeliveryObservationSiteV2::ExportApproval,
                        recipient.check_current(),
                    )
                    .map_err(|_| Error::Permission)
                },
                || {
                    host_result(
                        DeliveryObservationSiteV2::SourceCheck,
                        current_source(self, &owner, &inspection),
                    )?;
                    bridge_result(
                        DeliveryObservationSiteV2::ExportApproval,
                        recipient.check_current(),
                    )
                    .map_err(|_| Error::Permission)
                },
            ),
        )?;
        drop(read);
        let consent = OwnedDeliveryConsentV2 {
            host: self,
            owner: &owner,
            inspection: &inspection,
            approval,
            export: Some(&export_scope),
        };
        host_result(DeliveryObservationSiteV2::ExportCommit, consent.check())?;
        let retention = engine_result(
            DeliveryObservationSiteV2::ExportCommit,
            owner.coordinator().deliver_original_for_admission_v2(
                host_result(DeliveryObservationSiteV2::ExportCommit, self.access())?,
                recipient,
                &consent,
                &consent,
                &consent,
                &consent,
            ),
        )?;
        observe_delivery(
            DeliveryObservationSiteV2::ExportCommit,
            DeliveryObservationOutcomeV2::ReturnedOk,
        );
        post_export_result(consent.check())?;
        Ok(OriginalDeliveryExportV2 {
            request: DurableDeliveryAdmissionRequestV2 {
                version: 2,
                import_request: request,
                delivery: plan,
            },
            export_scope,
            retention,
        })
    }
    pub(in crate::host) fn private_original_delivery_status_v2(
        &self,
        root: &Path,
    ) -> Result<PrivateDurableAdmissionStatusV2> {
        self.require_private_workspace_read_session_v1()?;
        let owner = self.original_delivery_admission_owner_v2(root)?;
        let inspection = engine_result(
            DeliveryObservationSiteV2::SourceInspection,
            owner
                .coordinator()
                .inspect_original_for_admission_v2(self.access()?, &owner),
        )?;
        let detail = format!(
            "Read exact original delivery-admission fixed source and append-only export history.\n{}\nRead and verify ONLY the exact saved proof/material under their ORIGINAL absolute ceilings. No export, new intent, scan, construction, proof execution, admission or financial action.",
            serde_json::to_string(&inspection)?
        );
        let approval = self.terminal.approve_durable_delivery_v2(
            owner.inspection_approval(),
            &detail,
            || {
                owner.inspection_approval().check()?;
                current_source(self, &owner, &inspection)
            },
            || current_source(self, &owner, &inspection),
        )?;
        let consent = OwnedDeliveryConsentV2 {
            host: self,
            owner: &owner,
            inspection: &inspection,
            approval,
            export: None,
        };
        let status = engine_result(
            DeliveryObservationSiteV2::FixedRead,
            owner.coordinator().read_original_fixed_v2(
                self.access()?,
                &consent,
                &consent,
                &consent,
            ),
        )?;
        consent.check()?;
        Ok(status)
    }
}
/// Validate the real returned authenticated status against the exact exported
/// operation. A status is not permission; partial/unknown outcomes stay retained.
pub(in crate::host) fn validate_admission_result_v2(
    export: &OriginalDeliveryExportV2,
    status: &DurableDeliveryAdmissionStatusV2,
) -> Result<()> {
    status.validate().map_err(|_| Error::Authentication)?;
    let actual_fixed: wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1 =
        wholepact_core::parse_typed_json(&serde_json::to_vec(&status.scope.authorization.fixed)?)
            .map_err(|_| Error::Authentication)?;
    if status.version != 2
        || !status.witness_committed
        || status.scope.delivery != export.request.delivery
        || status.scope.accepted_manifest_ref != export.request.import_request.accepted_manifest_ref
        || actual_fixed != export.export_scope.proposal
        || status.scope.authorization.identity.account_id
            != export.export_scope.recipient.account_id
        || status.original_accepted_manifest_ref
            != export.request.import_request.accepted_manifest_ref
        || status.original_enrollment_ref != export.request.import_request.enrollment_ref
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewerRequestV2 {
    signer_socket: PathBuf,
    request: DurableReviewDeliveryRequestV1,
    account_id: String,
    participant_id: String,
    choices: DeliveryChoicesV2,
}
/// Explicit original-profile entry. Inert file inputs select a peer/request,
/// never replace actual paired provenance or the source-derived plan fields.
pub(in crate::host) fn admit_original(
    terminal: Terminal,
    profile: &Path,
    workspace: &Path,
) -> Result<()> {
    let host =
        Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let request: ReviewerRequestV2 = host.read_json(
        "Exact original reviewer request and bounded prospective delivery choices JSON: ",
    )?;
    let owner = host.original_delivery_admission_owner_v2(workspace)?;
    let inspection = engine_result(
        DeliveryObservationSiteV2::SourceInspection,
        owner
            .coordinator()
            .inspect_original_for_admission_v2(host.access()?, &owner),
    )?;
    if !request.signer_socket.is_absolute()
        || !inspection.materials().iter().any(|m| {
            m.scope().account_id == request.account_id
                && m.scope().participant_id == request.participant_id
        })
    {
        return Err(Error::Authentication);
    }
    let pair = PairScope {
        account_id: request.account_id,
        agreement_id: inspection.fixed_identity().agreement_id.clone(),
        participant_id: request.participant_id,
        manifest_digest: inspection.fixed_identity().manifest_digest.clone(),
        history_read: true,
        authorization_export: false,
        preconstruction_export: true,
    };
    drop(inspection);
    drop(owner);
    terminal.confirm("Pair this installed original reviewer for the separately native-approved prospective delivery admission. No financial execution is enabled.")?;
    let client = OriginalHistoryClient::pair(
        InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
        &request.signer_socket,
        "wholepact-original-delivery-v2",
        pair,
    )
    .map_err(|_| Error::Permission)?;
    let exported = host.private_original_delivery_export_v2(
        workspace,
        &client,
        request.request,
        &request.choices,
    )?;
    let status = client
        .request_durable_delivery_admission_v2(&exported.request)
        .map_err(|_| Error::Permission)?;
    validate_admission_result_v2(&exported, &status)?;
    terminal.json(&status)
}
pub(in crate::host) fn read_original_status(
    terminal: Terminal,
    profile: &Path,
    workspace: &Path,
) -> Result<()> {
    let host =
        Host::open_workspace_dispatcher_registered_v4(terminal.clone(), profile, workspace, false)?;
    let status = host.private_original_delivery_status_v2(workspace)?;
    terminal.json(&status)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn choices() -> DeliveryChoicesV2 {
        DeliveryChoicesV2 {
            submission_operation_id: "original-delivery-operation".into(),
            provider: wholepact_core::manual_construction::PreconstructionProvider {
                source_id: "named-provider".into(),
                endpoint: "https://example.test".into(),
                trust_profile: "single_tls_provider_report_not_consensus".into(),
            },
            route: DurableDeliveryRouteV2::Direct {},
            minimum_expiry_margin_blocks: 5,
            maximum_fresh_admission_lifetime_ms: 120_000,
            maximum_explicitly_approved_attempts: 1,
        }
    }
    #[test]
    fn caller_choices_never_supply_original_identity_fields() {
        let mut value = serde_json::to_value(choices()).unwrap();
        value["dispatcher"] = serde_json::json!({});
        assert!(
            wholepact_core::parse_typed_json::<DeliveryChoicesV2>(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn prospective_limits_refuse_zero_excess_and_short_operation() {
        let c = choices();
        assert!(c.check().is_ok());
        for field in 0..4 {
            let mut c = c.clone();
            match field {
                0 => c.maximum_fresh_admission_lifetime_ms = 120_001,
                1 => c.maximum_explicitly_approved_attempts = 0,
                2 => c.minimum_expiry_margin_blocks = 101,
                _ => c.submission_operation_id = "short".into(),
            }
            assert!(c.check().is_err());
        }
    }
    #[test]
    fn source_bound_issuers_do_not_accept_arbitrary_approval_or_compound() {
        let source = include_str!("durable_delivery_admission_v2.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("fn fixed_permission_boundary_v3"));
        assert!(!production.contains("pub fn new("));
        assert!(production.contains("recipient.check_current()"));
        assert!(production.contains("deliver_original_for_admission_v2"));
        assert!(production.contains("source.original_host_generation_binding()"));
        let export = production
            .split("fn private_original_delivery_export_v2(")
            .nth(1)
            .unwrap();
        assert!(
            export.find("plan.validate_origins()").unwrap()
                < export.find("prepare_durable_review_delivery_v1").unwrap()
        );
        assert!(
            export.find("plan.validate_origins()").unwrap()
                < export.find("deliver_original_for_admission_v2").unwrap()
        );
    }
    #[test]
    fn finite_engine_observation_never_formats_private_details() {
        let mut error = wholepact_engine::ApiError::new(
            "DISCLOSURE_UNKNOWN",
            "private material must not escape",
        );
        error.details = Box::new(serde_json::json!({"private":"secret"}));
        assert_eq!(
            engine_outcome(&error),
            DeliveryObservationOutcomeV2::EngineDisclosureUnknown
        );
        error.code = "unrecognized-private-error".into();
        assert_eq!(
            engine_outcome(&error),
            DeliveryObservationOutcomeV2::EngineUnclassified
        );
        struct OwnedOnly(u8);
        assert_eq!(
            engine_result(DeliveryObservationSiteV2::ExportCommit, Ok(OwnedOnly(7)))
                .unwrap()
                .0,
            7
        );
        assert!(matches!(
            engine_result::<()>(DeliveryObservationSiteV2::ExportCommit, Err(error)),
            Err(Error::Permission)
        ));
    }
    #[test]
    fn observed_result_keeps_non_clone_success_and_failure_once_only() {
        use std::cell::Cell;
        struct OwnedOnly(Box<u8>);
        let operations = Cell::new(0);
        let classifications = Cell::new(0);
        let success = OwnedOnly(Box::new(7));
        let success_address = (&*success.0) as *const u8;
        let operation = || {
            operations.set(operations.get() + 1);
            Ok::<_, OwnedOnly>(success)
        };
        let returned = observed_result(
            DeliveryObservationSiteV2::SourceOpen,
            operation(),
            |_| {
                classifications.set(classifications.get() + 1);
                DeliveryObservationOutcomeV2::HostUnclassified
            },
        );
        match returned {
            Ok(owned) => {
                assert_eq!((&*owned.0) as *const u8, success_address);
                assert_eq!(*owned.0, 7);
            }
            Err(_) => panic!("success changed"),
        }
        assert_eq!(operations.get(), 1);
        assert_eq!(classifications.get(), 0);

        let failure = OwnedOnly(Box::new(9));
        let failure_address = (&*failure.0) as *const u8;
        let classifier_capture = OwnedOnly(Box::new(11));
        let operation = || {
            operations.set(operations.get() + 1);
            Err::<OwnedOnly, _>(failure)
        };
        let returned = observed_result(
            DeliveryObservationSiteV2::SourcePlan,
            operation(),
            |error| {
                classifications.set(classifications.get() + 1);
                assert_eq!((&*error.0) as *const u8, failure_address);
                drop(classifier_capture);
                DeliveryObservationOutcomeV2::HostUnclassified
            },
        );
        match returned {
            Err(owned) => {
                assert_eq!((&*owned.0) as *const u8, failure_address);
                assert_eq!(*owned.0, 9);
            }
            Ok(_) => panic!("failure changed"),
        }
        assert_eq!(operations.get(), 2);
        assert_eq!(classifications.get(), 1);
    }
    #[test]
    fn finite_bridge_mapping_preserves_original_error_variants() {
        use wholepact_signer::authority_bridge::BridgeError as E;
        use DeliveryObservationOutcomeV2 as O;
        for (error, expected) in [
            (E::Binding, O::BridgeBinding),
            (E::Conflict, O::BridgeConflict),
            (E::Missing, O::BridgeMissing),
            (E::Uncertain, O::BridgeUncertain),
            (E::Limit, O::BridgeLimit),
            (E::Permission, O::BridgePermission),
            (E::RecoveryRequired, O::BridgeRecoveryRequired),
            (
                E::CompleteOriginRecoveryUnavailable,
                O::BridgeCompleteOriginRecoveryUnavailable,
            ),
            (E::Verification, O::BridgeVerification),
            (E::SignerOriginUnavailable, O::BridgeSignerOriginUnavailable),
            (
                E::Journal(wholepact_signer::consent_journal::JournalError::Expired),
                O::BridgeJournal,
            ),
            (
                E::Authority(wholepact_authority::AuthorityError::InvalidBinding),
                O::BridgeAuthority,
            ),
            (
                E::Wallet(
                    wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError::Permission,
                ),
                O::BridgeWallet,
            ),
            (E::Ipc, O::BridgeIpc),
        ] {
            assert_eq!(bridge_outcome(&error), expected);
            let discriminant = std::mem::discriminant(&error);
            let returned = bridge_result::<()>(
                DeliveryObservationSiteV2::RecipientPrepare,
                Err(error),
            )
            .unwrap_err();
            assert_eq!(std::mem::discriminant(&returned), discriminant);
            assert_eq!(bridge_outcome(&returned), expected);
            assert!(matches!(
                Err::<(), _>(returned).map_err(|_| Error::Permission),
                Err(Error::Permission)
            ));
        }
    }
    #[test]
    fn finite_host_mapping_preserves_original_private_payload() {
        use DeliveryObservationOutcomeV2 as O;
        for (error, expected) in [
            (Error::Platform, O::HostPlatform),
            (Error::Terminal, O::HostTerminal),
            (Error::Permission, O::HostPermission),
            (Error::Locked, O::HostLocked),
            (Error::Invalid, O::HostInvalid),
            (Error::Authentication, O::HostAuthentication),
            (Error::Storage, O::HostStorage),
            (Error::Quarantined, O::HostQuarantined),
            (Error::Unsupported, O::HostUnsupported),
            (Error::Receipt("private receipt".into()), O::HostReceipt),
            (
                Error::RecoverySemantic("private recovery".into()),
                O::HostRecoverySemantic,
            ),
            (Error::RecoveryBackupUnsupported, O::HostRecoveryBackupUnsupported),
            (
                Error::RecoveryFinancialUnsupported,
                O::HostRecoveryFinancialUnsupported,
            ),
            (
                Error::CompleteOriginRecoveryUnavailable,
                O::HostCompleteOriginRecoveryUnavailable,
            ),
            (Error::HistoricalExportIncomplete, O::HostHistoricalExportIncomplete),
            (Error::GenerationArchiveIncomplete, O::HostGenerationArchiveIncomplete),
        ] {
            assert_eq!(host_outcome(&error), expected);
            let discriminant = std::mem::discriminant(&error);
            let returned = host_result::<()>(DeliveryObservationSiteV2::SourcePlan, Err(error))
                .unwrap_err();
            assert_eq!(std::mem::discriminant(&returned), discriminant);
        }
        let private = String::from("private source payload must not be emitted");
        let address = private.as_ptr();
        let returned = host_result::<()>(
            DeliveryObservationSiteV2::SourceOpen,
            Err(Error::Receipt(private)),
        );
        match returned {
            Err(Error::Receipt(payload)) => {
                assert_eq!(payload.as_ptr(), address);
                assert_eq!(host_outcome(&Error::Receipt(payload)), O::HostReceipt);
            }
            _ => panic!("host error payload changed"),
        }
    }
    #[test]
    fn finite_engine_mapping_covers_only_closed_error_codes() {
        use DeliveryObservationOutcomeV2 as O;
        for (code, expected) in [
            ("DISCLOSURE_UNKNOWN", O::EngineDisclosureUnknown),
            ("DISCLOSURE_DENIED", O::EngineDisclosureDenied),
            ("RECOVERY_REQUIRED", O::EngineRecoveryRequired),
            ("DURABLE_PROPOSAL_RECOVERY_REQUIRED", O::EngineRecoveryRequired),
            ("IDEMPOTENCY_CONFLICT", O::EngineIdempotencyConflict),
            ("REVISION_CONFLICT", O::EngineRevisionConflict),
            ("DURABLE_PROPOSAL_CONFLICT", O::EngineDurableProposalConflict),
            (
                "DURABLE_CONSTRUCTION_UNAVAILABLE",
                O::EngineDurableConstructionUnavailable,
            ),
            ("DURABLE_PROFILE_UNAVAILABLE", O::EngineDurableProfileUnavailable),
            ("RESOURCE_EXHAUSTED", O::EngineResourceExhausted),
            ("not-a-public-code", O::EngineUnclassified),
        ] {
            let error = wholepact_engine::ApiError::new(code, "private details");
            assert_eq!(engine_outcome(&error), expected);
            assert!(matches!(
                engine_result::<()>(DeliveryObservationSiteV2::ExportPreview, Err(error)),
                Err(Error::Permission)
            ));
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn export_checks_preserve_short_circuit_and_leave_readonly_unobserved() {
        use std::cell::{Cell, RefCell};
        thread_local! {
            static SEEN: RefCell<Vec<(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)>> =
                const { RefCell::new(Vec::new()) };
        }
        fn record(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
            SEEN.with(|seen| seen.borrow_mut().push((site, outcome)));
        }
        SEEN.with(|seen| seen.borrow_mut().clear());
        with_delivery_observer_v2(record, || {
            let checks = Cell::new(0);
            let matches_scope = false;
            let permitted = matches_scope
                && export_check_result(
                    true,
                    DeliveryObservationSiteV2::SourceCheck,
                    {
                        checks.set(checks.get() + 1);
                        Err::<(), _>(Error::Authentication)
                    },
                )
                .is_ok();
            assert!(!permitted);
            assert_eq!(checks.get(), 0);
            assert!(SEEN.with(|seen| seen.borrow().is_empty()));
            assert!(!export_check_result(
                false,
                DeliveryObservationSiteV2::NativeCheck,
                Err::<(), _>(Error::Terminal),
            )
            .is_ok());
            assert!(!export_check_result(
                true,
                DeliveryObservationSiteV2::SourceCheck,
                Ok(false),
            )
            .unwrap_or(false));
            assert!(SEEN.with(|seen| seen.borrow().is_empty()));
            assert!(!export_check_result(
                true,
                DeliveryObservationSiteV2::NativeCheck,
                {
                    checks.set(checks.get() + 1);
                    Err::<(), _>(Error::Terminal)
                },
            )
            .is_ok());
            assert_eq!(checks.get(), 1);
        });
        SEEN.with(|seen| {
            assert_eq!(
                &*seen.borrow(),
                &[(
                    DeliveryObservationSiteV2::NativeCheck,
                    DeliveryObservationOutcomeV2::HostTerminal,
                )],
            );
        });
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn bridge_cause_is_observed_before_unchanged_host_permission_mapping() {
        thread_local! {
            static SEEN: std::cell::RefCell<Vec<(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)>> =
                const { std::cell::RefCell::new(Vec::new()) };
        }
        fn record(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
            SEEN.with(|seen| seen.borrow_mut().push((site, outcome)));
        }
        SEEN.with(|seen| seen.borrow_mut().clear());
        with_delivery_observer_v2(record, || {
            let result = host_result(
                DeliveryObservationSiteV2::ExportApproval,
                bridge_result::<()>(
                    DeliveryObservationSiteV2::ExportApproval,
                    Err(wholepact_signer::authority_bridge::BridgeError::Binding),
                )
                .map_err(|_| Error::Permission),
            );
            assert!(matches!(result, Err(Error::Permission)));
        });
        SEEN.with(|seen| {
            assert_eq!(
                &*seen.borrow(),
                &[
                    (
                        DeliveryObservationSiteV2::ExportApproval,
                        DeliveryObservationOutcomeV2::BridgeBinding,
                    ),
                    (
                        DeliveryObservationSiteV2::ExportApproval,
                        DeliveryObservationOutcomeV2::HostPermission,
                    ),
                ],
            );
        });
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn committed_return_precedes_postcheck_denial_and_observer_restores() {
        thread_local! { static SEEN:std::cell::RefCell<Vec<(DeliveryObservationSiteV2,DeliveryObservationOutcomeV2)>>=const{std::cell::RefCell::new(Vec::new())}; }
        fn record(s: DeliveryObservationSiteV2, o: DeliveryObservationOutcomeV2) {
            SEEN.with(|v| v.borrow_mut().push((s, o)));
        }
        SEEN.with(|v| v.borrow_mut().clear());
        with_delivery_observer_v2(record, || {
            let saved = engine_result(DeliveryObservationSiteV2::ExportCommit, Ok(())).unwrap();
            observe_delivery(
                DeliveryObservationSiteV2::ExportCommit,
                DeliveryObservationOutcomeV2::ReturnedOk,
            );
            let result = post_export_result(Err(Error::Permission));
            assert!(matches!(result, Err(Error::Permission)));
            let _ = saved;
        });
        assert!(DELIVERY_OBSERVER_V2.with(|c| c.get().is_none()));
        SEEN.with(|v| {
            assert_eq!(
                &*v.borrow(),
                &[
                    (
                        DeliveryObservationSiteV2::ExportCommit,
                        DeliveryObservationOutcomeV2::ReturnedOk
                    ),
                    (
                        DeliveryObservationSiteV2::ExportPostcheck,
                        DeliveryObservationOutcomeV2::HostPermission
                    )
                ]
            )
        });
    }
    #[test]
    fn exact_proof_role_refuses_every_effect_and_each_changed_scope_field() {
        let scope = CheckpointScope {
            principal_id: "principal".into(),
            candidate_id: "candidate".into(),
            manifest_digest: "11".repeat(32),
            artifact_digest: "22".repeat(32),
            effects_commitment: "33".repeat(32),
            coordination_request_digest: "44".repeat(32),
            review_binding: "55".repeat(32),
            account_ids: vec!["66".repeat(32), "77".repeat(32)],
            local_operator: "operator".into(),
            purpose: "review only".into(),
            retention_policy: "original".into(),
        };
        for action in [LocalAction::InspectStatus, LocalAction::ReadPrivateArtifact] {
            assert!(exact_read_proof_role(&scope, &scope, action));
        }
        for action in [
            LocalAction::RetainPrivateWitnesses,
            LocalAction::ProveLocally,
            LocalAction::RecoverInterrupted,
        ] {
            assert!(!exact_read_proof_role(&scope, &scope, action));
        }
        let value = serde_json::to_value(&scope).unwrap();
        for key in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            changed[key] = if key == "account_ids" {
                serde_json::json!(["different"])
            } else {
                serde_json::json!("different")
            };
            let changed: CheckpointScope = serde_json::from_value(changed).unwrap();
            assert!(!exact_read_proof_role(
                &scope,
                &changed,
                LocalAction::ReadPrivateArtifact
            ));
        }
    }
}
