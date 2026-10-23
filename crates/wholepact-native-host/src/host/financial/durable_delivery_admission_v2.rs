//! Prospective original-source delivery admission. This purpose is disjoint
//! from the fixed-workspace stage/compound permissions and never grants spend.
mod closed_review_v3;
pub(in crate::host) use closed_review_v3::{OriginalDeliveryExportV3, validate_admission_result_v3, admit_original_v3, admit_original_borrowed_v3, read_original_status_v3};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub(in crate::host::financial) use closed_review_v3::{
    begin_original_borrowed_fork_v3, RetainedCoordinatedAdmissionV1, RetainedOwnerWorkflowWaitV1,
    begin_original_coordinated_admission_v1, RetainedOriginalCoordinatedAdmissionV1, RetainedCoordinatedOwnerWorkflowWaitV1,
};
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
    PreparationSourceBefore,
    PreparationApproval,
    PreparationSourceAfter,
    HistoricalApprovalDeadline,
    HistoricalApprovalForeground,
    OriginalDisclosureSelector,
    MaterialRestrictionCapture,
    PairConfirmation,
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
    SourceScopePredicate,
    ProofRolePredicate,
    MaterialActionPredicate,
    MaterialScopePredicate,
    ExportScopePredicate,
    ExportProofCurrent,
    ExportProofOrigin,
    ExportSourceBefore,
    ExportSourceAfter,
    ExportMetadataOrigin,
    ExportMarker,
    ExportHistory,
    ExportMaterialCeilings,
    ExportIntake,
    ExportVerifiedProof,
    ExportRoster,
    ExportPayload,
    ExportOutputActions,
    ExportRecipientBinding,
    ExportSources,
    ExportCheckpointScope,
    ExportProofPermission,
    ExportPermission,
    ExportReplayScope,
    ExportCommand,
    ExportReplayLookup,
    ExportDelta,
    ExportEntry,
    RecipientMutex,
    RecipientDeadline,
    RecipientOrigin,
    RecipientObserverClone,
    RecipientWriteSerialize,
    RecipientWriteLimit,
    RecipientWriteDeadline,
    RecipientWriteTimeout,
    RecipientWriteIo,
    RecipientWriteEmpty,
    RecipientFrame,
    RecipientResponseDecode,
    RecipientResponseDigest,
    RecipientResponse,
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
    PredicateDenied,
    OriginPermanentStopUnavailable,
    OriginRetirementEvidenceUnavailable,
    OriginSignerOriginUnavailable,
    OriginPeerLifetimeUnavailable,
    OriginAuthentication,
    OriginBinding,
    OriginConflict,
    OriginPermission,
    OriginInvalidData,
    OriginLocked,
    OriginCrypto,
    OriginIpc,
    OriginLimit,
    OriginIoTimedOut,
    OriginIoWouldBlock,
    OriginIoUnexpectedEof,
    OriginIoBrokenPipe,
    OriginIoConnectionReset,
    OriginIoConnectionAborted,
    OriginIoNotConnected,
    OriginIoInterrupted,
    OriginIoPermissionDenied,
    OriginIoOther,
}
#[cfg(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci))]
thread_local! { static DELIVERY_OBSERVER_V2: std::cell::Cell<Option<fn(DeliveryObservationSiteV2,DeliveryObservationOutcomeV2)>> = const { std::cell::Cell::new(None) }; }
#[cfg(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci))]
struct DeliveryObserverScope {
    previous: Option<fn(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)>,
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    previous_semantic: bool,
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
thread_local! { static SEMANTIC_DELIVERY_SCOPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci))]
impl Drop for DeliveryObserverScope {
    fn drop(&mut self) {
        DELIVERY_OBSERVER_V2.with(|cell| cell.set(self.previous));
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.set(self.previous_semantic));
    }
}
#[cfg(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci))]
fn delivery_observer_scope(observer: fn(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)) -> DeliveryObserverScope {
    DeliveryObserverScope {
        previous: DELIVERY_OBSERVER_V2.with(|cell| cell.replace(Some(observer))),
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        previous_semantic: SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.replace(false)),
    }
}
#[cfg(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci))]
pub(in crate::host) fn with_delivery_observer_v2<T>(
    observer: fn(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2),
    f: impl FnOnce() -> T,
) -> T {
    let _scope = delivery_observer_scope(observer);
    f()
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn semantic_delivery_scope() -> DeliveryObserverScope {
    let scope = delivery_observer_scope(observe_semantic_delivery);
    SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.set(true));
    scope
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn observe_semantic_delivery(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
    if let Some((stage, class)) = semantic_delivery_code(site, outcome) {
        wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::latch_failure(stage, class);
    }
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn semantic_delivery_code(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) -> Option<(
    wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::Stage,
    wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::Class,
)> {
    use DeliveryObservationSiteV2 as S;
    use DeliveryObservationOutcomeV2 as O;
    use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::{Stage, Class};
    // Only the reviewed local preparation/recipient-opening observations are
    // projected here; no final export, commit or delivery hook is activated.
    let stage = match site {
        S::SourceOpen => Stage::DeliverySourceOpen,
        S::SourceInspection => Stage::DeliverySourceInspection,
        S::SourcePlan => Stage::DeliverySourcePlan,
        S::RecipientPrepare => Stage::DeliveryRecipientPrepare,
        S::ExportPreview => Stage::DeliveryExportPreview,
        S::NativeCheck => Stage::DeliveryNativeCheck,
        S::SourceCheck => Stage::DeliverySourceCheck,
        S::SourceScopePredicate => Stage::DeliverySourceScopePredicate,
        S::ProofRolePredicate => Stage::DeliveryProofRolePredicate,
        S::MaterialActionPredicate => Stage::DeliveryMaterialActionPredicate,
        S::MaterialScopePredicate => Stage::DeliveryMaterialScopePredicate,
        S::PreparationSourceBefore => Stage::PreparationSourceBefore,
        S::PreparationApproval => Stage::PreparationApproval,
        S::PreparationSourceAfter => Stage::PreparationSourceAfter,
        S::HistoricalApprovalDeadline => Stage::HistoricalApprovalDeadline,
        S::HistoricalApprovalForeground => Stage::HistoricalApprovalForeground,
        S::OriginalDisclosureSelector => Stage::OriginalDisclosureSelector,
        S::MaterialRestrictionCapture => Stage::MaterialRestrictionCapture,
        S::PairConfirmation => Stage::PairConfirmation,
        _ => return None,
    };
    let class = match outcome {
        O::EngineDisclosureUnknown => Class::EngineDisclosureUnknown,
        O::EngineDisclosureDenied => Class::EngineDisclosureDenied,
        O::EngineRecoveryRequired => Class::EngineRecoveryRequired,
        O::EngineIdempotencyConflict => Class::EngineIdempotencyConflict,
        O::EngineRevisionConflict => Class::EngineRevisionConflict,
        O::EngineDurableProposalConflict => Class::EngineDurableProposalConflict,
        O::EngineDurableConstructionUnavailable => Class::EngineDurableConstructionUnavailable,
        O::EngineDurableProfileUnavailable => Class::EngineDurableProfileUnavailable,
        O::EngineResourceExhausted => Class::EngineResourceExhausted,
        O::EngineUnclassified => Class::EngineUnclassified,
        O::PredicateDenied => Class::PredicateDenied,
        O::HostPlatform => Class::Platform,
        O::HostTerminal => Class::Terminal,
        O::HostPermission => Class::Permission,
        O::HostLocked => Class::Locked,
        O::HostInvalid => Class::Invalid,
        O::HostAuthentication => Class::Authentication,
        O::HostStorage => Class::Storage,
        O::HostQuarantined => Class::Quarantined,
        O::HostUnsupported => Class::Unsupported,
        O::HostReceipt => Class::Receipt,
        O::HostRecoverySemantic => Class::RecoverySemantic,
        O::HostRecoveryBackupUnsupported => Class::RecoveryBackupUnsupported,
        O::HostRecoveryFinancialUnsupported => Class::RecoveryFinancialUnsupported,
        O::HostCompleteOriginRecoveryUnavailable => Class::CompleteOriginRecoveryUnavailable,
        O::HostHistoricalExportIncomplete => Class::HistoricalExportIncomplete,
        O::HostGenerationArchiveIncomplete => Class::GenerationArchiveIncomplete,
        // Success and unrelated Origin/Bridge delivery outcomes do not latch.
        _ => return None,
    };
    Some((stage, class))
}
fn observe_delivery(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
    #[cfg(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci))]
    DELIVERY_OBSERVER_V2.with(|cell| {
        if let Some(observer) = cell.get() {
            observer(site, outcome);
        }
    });
    #[cfg(not(any(all(test, feature = "synthetic-born-joined-qualification"), wholepact_financial_rendered_host_semantic_ci)))]
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
    observed_engine_result(site, result).map_err(Error::from)
}
fn observed_engine_result<T>(
    site: DeliveryObservationSiteV2,
    result: wholepact_engine::Result<T>,
) -> wholepact_engine::Result<T> {
    if site == DeliveryObservationSiteV2::ExportCommit {
        if let Err(error) = &result {
            if let Some((cause_site, cause_outcome)) = export_engine_cause(error) {
                observe_delivery(cause_site, cause_outcome);
            }
        }
    }
    observed_result(site, result, engine_outcome)
}
const EXPORT_CAUSE_KEY: &str = "private_durable_delivery_cause_v2";
const EXPORT_CAUSE_COLLISION_KEY: &str = "private_durable_delivery_cause_collision_v2";

// These tables turn only exact known labels into local enums. No input string,
// error code, message or other metadata is retained by an observation.
macro_rules! export_cause_labels {
    ($parse:ident, $inventory:ident, $kind:ident { $($variant:ident),+ $(,)? }) => {
        fn $parse(value: &str) -> Option<$kind> {
            match value {
                $(stringify!($variant) => Some($kind::$variant),)+
                _ => None,
            }
        }
        #[cfg(test)]
        const $inventory: &[(&str, $kind)] = &[
            $((stringify!($variant), $kind::$variant),)+
        ];
    };
}
export_cause_labels! { parse_export_cause_site, EXPORT_CAUSE_SITES, DeliveryObservationSiteV2 {
    ExportProofCurrent, ExportProofOrigin, ExportSourceBefore, ExportSourceAfter,
    ExportMetadataOrigin, ExportMarker, ExportHistory, ExportMaterialCeilings,
    ExportIntake, ExportVerifiedProof, ExportRoster, ExportPayload,
    ExportOutputActions, ExportRecipientBinding, ExportSources,
    ExportCheckpointScope, ExportProofPermission, ExportPermission,
    ExportReplayScope, ExportCommand, ExportReplayLookup, ExportDelta, ExportEntry,
    RecipientMutex, RecipientDeadline, RecipientOrigin, RecipientObserverClone,
    RecipientWriteSerialize, RecipientWriteLimit, RecipientWriteDeadline,
    RecipientWriteTimeout, RecipientWriteIo, RecipientWriteEmpty, RecipientFrame,
    RecipientResponseDecode, RecipientResponseDigest, RecipientResponse,
} }
export_cause_labels! { parse_export_cause_outcome, EXPORT_CAUSE_OUTCOMES, DeliveryObservationOutcomeV2 {
    EngineDisclosureUnknown, EngineDisclosureDenied, EngineRecoveryRequired,
    EngineIdempotencyConflict, EngineRevisionConflict, EngineDurableProposalConflict,
    EngineDurableConstructionUnavailable, EngineDurableProfileUnavailable,
    EngineResourceExhausted, EngineUnclassified, PredicateDenied,
    BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit,
    BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable,
    BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority,
    BridgeWallet, BridgeIpc,
    OriginPermanentStopUnavailable, OriginRetirementEvidenceUnavailable,
    OriginSignerOriginUnavailable, OriginPeerLifetimeUnavailable, OriginAuthentication,
    OriginBinding, OriginConflict, OriginPermission, OriginInvalidData, OriginLocked,
    OriginCrypto, OriginIpc, OriginLimit, OriginIoTimedOut, OriginIoWouldBlock,
    OriginIoUnexpectedEof, OriginIoBrokenPipe, OriginIoConnectionReset,
    OriginIoConnectionAborted, OriginIoNotConnected, OriginIoInterrupted,
    OriginIoPermissionDenied, OriginIoOther,
} }
fn export_cause_pair_is_valid(
    site: DeliveryObservationSiteV2,
    outcome: DeliveryObservationOutcomeV2,
) -> bool {
    use DeliveryObservationOutcomeV2 as O;
    use DeliveryObservationSiteV2 as S;
    let engine = matches!(outcome,
        O::EngineDisclosureUnknown | O::EngineDisclosureDenied | O::EngineRecoveryRequired
            | O::EngineIdempotencyConflict | O::EngineRevisionConflict
            | O::EngineDurableProposalConflict | O::EngineDurableConstructionUnavailable
            | O::EngineDurableProfileUnavailable | O::EngineResourceExhausted
            | O::EngineUnclassified
    );
    let bridge = matches!(outcome,
        O::BridgeBinding | O::BridgeConflict | O::BridgeMissing | O::BridgeUncertain
            | O::BridgeLimit | O::BridgePermission | O::BridgeRecoveryRequired
            | O::BridgeCompleteOriginRecoveryUnavailable | O::BridgeVerification
            | O::BridgeSignerOriginUnavailable | O::BridgeJournal | O::BridgeAuthority
            | O::BridgeWallet | O::BridgeIpc
    );
    let origin_io = matches!(outcome,
        O::OriginIoTimedOut | O::OriginIoWouldBlock | O::OriginIoUnexpectedEof
            | O::OriginIoBrokenPipe | O::OriginIoConnectionReset | O::OriginIoConnectionAborted
            | O::OriginIoNotConnected | O::OriginIoInterrupted | O::OriginIoPermissionDenied
            | O::OriginIoOther
    );
    let origin = origin_io || matches!(outcome,
        O::OriginPermanentStopUnavailable | O::OriginRetirementEvidenceUnavailable
            | O::OriginSignerOriginUnavailable | O::OriginPeerLifetimeUnavailable
            | O::OriginAuthentication | O::OriginBinding | O::OriginConflict
            | O::OriginPermission | O::OriginInvalidData | O::OriginLocked | O::OriginCrypto
            | O::OriginIpc | O::OriginLimit
    );
    match site {
        S::ExportProofOrigin | S::ExportPermission => outcome == O::PredicateDenied,
        S::ExportSourceBefore | S::ExportMetadataOrigin | S::ExportMarker | S::ExportHistory
        | S::ExportRoster | S::ExportSources | S::ExportProofPermission | S::ExportReplayScope
        | S::ExportReplayLookup | S::ExportDelta => engine || outcome == O::PredicateDenied,
        S::ExportProofCurrent | S::ExportSourceAfter | S::ExportMaterialCeilings
        | S::ExportIntake | S::ExportVerifiedProof | S::ExportPayload | S::ExportOutputActions
        | S::ExportRecipientBinding | S::ExportCheckpointScope | S::ExportCommand
        | S::ExportEntry => engine,
        S::RecipientMutex | S::RecipientWriteEmpty => outcome == O::BridgeIpc,
        S::RecipientDeadline | S::RecipientWriteDeadline | S::RecipientResponse => {
            outcome == O::BridgePermission
        }
        S::RecipientOrigin => bridge,
        S::RecipientObserverClone | S::RecipientWriteTimeout | S::RecipientWriteIo => origin_io,
        S::RecipientWriteSerialize | S::RecipientResponseDecode | S::RecipientResponseDigest => {
            outcome == O::BridgeBinding
        }
        S::RecipientWriteLimit => outcome == O::BridgeLimit,
        S::RecipientFrame => origin,
        _ => false,
    }
}
/// Trust only the exact closed sidecar of this invocation's terminal Engine
/// export error. Other detail fields are untouched and never projected.
fn export_engine_cause(
    error: &wholepact_engine::ApiError,
) -> Option<(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)> {
    let details = error.details.as_object()?;
    // The Engine marks a pre-existing reserved key before considering its
    // current collector. Marker presence always denies projection, even when
    // its value is false, malformed or itself pre-existing. It grants nothing.
    if details.contains_key(EXPORT_CAUSE_COLLISION_KEY) {
        return None;
    }
    let detail = details.get(EXPORT_CAUSE_KEY)?.as_object()?;
    if detail.len() != 3 || detail.get("version")?.as_u64()? != 1 {
        return None;
    }
    let site = parse_export_cause_site(detail.get("site")?.as_str()?)?;
    let outcome = parse_export_cause_outcome(detail.get("outcome")?.as_str()?)?;
    export_cause_pair_is_valid(site, outcome).then_some((site, outcome))
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
/// Observe the original boolean at its existing short-circuit position. No
/// permission, lookup, native approval or source check is rerun here.
fn export_predicate(
    exporting: bool,
    site: DeliveryObservationSiteV2,
    allowed: bool,
) -> bool {
    if exporting && !allowed {
        observe_delivery(site, DeliveryObservationOutcomeV2::PredicateDenied);
    }
    allowed
}
/// A failed serialization is still the original typed source error, not a
/// fabricated predicate denial. Only an actual Ok(false) is a false predicate.
fn export_source_scope_result(exporting: bool, result: Result<bool>) -> Result<bool> {
    let result = export_check_result(exporting, DeliveryObservationSiteV2::SourceCheck, result);
    if let Ok(allowed) = &result {
        export_predicate(exporting, DeliveryObservationSiteV2::SourceScopePredicate, *allowed);
    }
    result
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
fn retained_material_clock_bounds(inspection: &PrivateDurableAdmissionInspectionV2) -> Result<(u64, u64)> {
    if inspection.materials().len() != 2 { return Err(Error::Authentication); }
    let from = inspection.materials().iter().map(|m| m.scope().valid_from_unix_seconds).max().ok_or(Error::Authentication)?;
    let until = inspection.materials().iter().map(|m| m.scope().valid_until_unix_seconds).min().ok_or(Error::Authentication)?;
    Ok((from, until))
}
fn original_material_clock_bounds(inspection: &PrivateDurableAdmissionInspectionV2) -> Result<(u64, u64)> {
    let (from, until) = retained_material_clock_bounds(inspection)?;
    let now = now_seconds()?;
    if now < from || now >= until { return Err(Error::Permission); }
    Ok((from, until))
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
    approval: &'a HistoricalApproval,
    export_preview: bool,
}
impl InspectionReadV2<'_, '_> {
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
impl LocalPrivateDurableAdmissionConsentV2 for InspectionReadV2<'_, '_> {
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
impl LocalProofConsent for InspectionReadV2<'_, '_> {
    fn permits(&self, s: &CheckpointScope, a: LocalAction) -> bool {
        export_predicate(
            self.export_preview,
            DeliveryObservationSiteV2::ProofRolePredicate,
            proof_matches(self.inspection, s, a),
        ) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for InspectionReadV2<'_, '_> {
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
    fn check_final_effect_restriction_v1(&self, original_deadline: Option<std::time::Instant>) -> bool {
        if crate::terminal::coordinated_restriction_required()
            && original_deadline.is_some_and(|until| std::time::Instant::now() >= until)
        { return false; }
        !crate::terminal::coordinated_restriction_required()
            || (original_material_clock_bounds(self.inspection).is_ok() && self.approval.check().is_ok())
    }
    fn permits_source(&self, s: &PrivateWorkspaceScopeV1) -> bool {
        export_source_scope_result(
            self.export.is_some(),
            same(s, self.inspection.workspace_scope()),
        )
        .unwrap_or(false)
            && self.check().is_ok()
    }
}
impl LocalProofConsent for OwnedDeliveryConsentV2<'_, '_> {
    fn permits(&self, s: &CheckpointScope, a: LocalAction) -> bool {
        export_predicate(
            self.export.is_some(),
            DeliveryObservationSiteV2::ProofRolePredicate,
            proof_matches(self.inspection, s, a),
        ) && self.check().is_ok()
    }
}
impl LocalDurableMaterialConsentV1 for OwnedDeliveryConsentV2<'_, '_> {
    fn permits(&self, s: &DurableConstructionScopeV1, d: &str, a: DurableMaterialActionV1) -> bool {
        let expected = if self.export.is_some() {
            DurableMaterialActionV1::ExportForLocalNativeReview
        } else {
            DurableMaterialActionV1::ReadForExactConstruction
        };
        export_predicate(
            self.export.is_some(),
            DeliveryObservationSiteV2::MaterialActionPredicate,
            std::mem::discriminant(&a) == std::mem::discriminant(&expected),
        ) && export_predicate(
            self.export.is_some(),
            DeliveryObservationSiteV2::MaterialScopePredicate,
            material_matches(self.inspection, s, d),
        )
            && self.check().is_ok()
    }
}
impl LocalDurableReviewExportConsentV1 for OwnedDeliveryConsentV2<'_, '_> {
    fn permits(&self, s: &DurableReviewExportScopeV1) -> bool {
        export_predicate(
            self.export.is_some(),
            DeliveryObservationSiteV2::ExportScopePredicate,
            self.export.is_some_and(|exact| exact == s),
        ) && self.check().is_ok()
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
/// Bound the same escaped text and fixed-width challenge that the maintained
/// terminal renders. This rejects oversized metadata; it cannot issue approval.
fn bound_original_delivery_review_v2(detail: &str) -> Result<()> {
    const PROMPT: &str = "\nType APPROVE 0000000000000000 to approve this exact operation, or anything else to reject: ";
    let maximum = wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES;
    let rendered = detail.chars().try_fold(0usize, |length, c| {
        length.checked_add(if c == '\n' || c == ' ' || c.is_ascii_graphic() {
            1
        } else {
            c.escape_default().count()
        })
    });
    if detail.len() > maximum
        || rendered
            .and_then(|length| length.checked_add(PROMPT.len()))
            .is_none_or(|length| length > maximum)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Ordering only. The caller must use the genuine terminal issuer; this kernel
/// cannot create authority or extend either original material ceiling.
fn source_checked_approval_v2<T>(
    mut source: impl FnMut() -> Result<()>,
    issue: impl FnOnce() -> Result<T>,
) -> Result<T> {
    source()?;
    let approval = issue()?;
    source()?;
    Ok(approval)
}
/// The owned local result is complete before the one-shot recipient opener is
/// called. Both values remain opaque to this ordering-only kernel.
fn prepare_before_recipient_v2<P, R>(
    prepare: impl FnOnce() -> Result<P>,
    open_recipient: impl FnOnce() -> Result<R>,
) -> Result<(P, R)> {
    let prepared = prepare()?;
    let recipient = open_recipient()?;
    Ok((prepared, recipient))
}
impl Host {
    /// Lexically own the actual original source and immutable prepared bytes,
    /// then open the recipient exactly once. A qualifier must create a genuinely
    /// new native entry in that continuation. An already-paired CLI caller does
    /// not gain a new native lifetime by adapting to this helper.
    pub(in crate::host) fn private_original_delivery_export_v2(
        &self,
        root: &Path,
        choices: &DeliveryChoicesV2,
        open_recipient: impl FnOnce() -> Result<(OriginalHistoryClient, DurableReviewDeliveryRequestV1)>,
    ) -> Result<(OriginalHistoryClient, OriginalDeliveryExportV2)> {
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
        // This exact source-derived plan is inert, never disclosure admission.
        host_result(
            DeliveryObservationSiteV2::SourcePlan,
            plan.validate_origins().map_err(|_| Error::Invalid),
        )?;
        let (prepared, (client, request)) = prepare_before_recipient_v2(
            || {
                // Fixed purpose text only: protected exact metadata is rendered
                // later under the checked final disclosure approval.
                let detail = "Approve LOCAL exact-byte preparation for original delivery.\nRead and fully verify only the selected retained original proof and both original materials, then encode and retain the exact private review bytes in LOCAL memory under their ORIGINAL absolute ceilings. No recipient disclosure, export, signing, submission, admission or other financial effect is authorized.";
                host_result(
                    DeliveryObservationSiteV2::ExportPreview,
                    bound_original_delivery_review_v2(&detail),
                )?;
                let approval = source_checked_approval_v2(
                    || {
                        host_result(
                            DeliveryObservationSiteV2::SourceCheck,
                            current_source(self, &owner, &inspection),
                        )
                    },
                    || {
                        host_result(
                            DeliveryObservationSiteV2::ExportPreview,
                            self.terminal.approve_historical(&detail),
                        )
                    },
                )?;
                let read = InspectionReadV2 {
                    host: self,
                    owner: &owner,
                    inspection: &inspection,
                    approval: &approval,
                    export_preview: true,
                };
                host_result(DeliveryObservationSiteV2::ExportPreview, read.check())?;
                let prepared = engine_result(
                    DeliveryObservationSiteV2::ExportPreview,
                    owner.coordinator().prepare_original_delivery_v2(
                        host_result(DeliveryObservationSiteV2::ExportPreview, self.access())?,
                        &read,
                        &read,
                        &read,
                    ),
                )?;
                host_result(DeliveryObservationSiteV2::ExportPreview, read.check())?;
                // Neither this read adapter nor its approval escapes preparation.
                Ok(prepared)
            },
            open_recipient,
        )?;
        // This is an unconditional new decision after actual recipient setup,
        // not renewal or fallback to either earlier approval. Source currentness
        // independently checks both original material ceilings before and after.
        let detail = "Inspect fresh original delivery metadata for the actual new recipient.\nInspect the selected original source, fixed proof, both original material scopes and bounded exact prepared review metadata to bind ONLY this actual paired recipient. Read and verify under the ORIGINAL absolute ceilings. No private payload disclosure, export, financial admission, signing or submission is authorized.";
        host_result(
            DeliveryObservationSiteV2::SourceInspection,
            bound_original_delivery_review_v2(&detail),
        )?;
        let final_inspection = source_checked_approval_v2(
            || {
                host_result(
                    DeliveryObservationSiteV2::SourceCheck,
                    current_source(self, &owner, &inspection),
                )
            },
            || {
                host_result(
                    DeliveryObservationSiteV2::SourceInspection,
                    self.terminal.approve_historical(&detail),
                )
            },
        )?;
        let read = InspectionReadV2 {
            host: self,
            owner: &owner,
            inspection: &inspection,
            approval: &final_inspection,
            export_preview: true,
        };
        host_result(DeliveryObservationSiteV2::SourceInspection, read.check())?;
        let recipient = bridge_result(
            DeliveryObservationSiteV2::RecipientPrepare,
            client.prepare_durable_review_delivery_v1(&request),
        )
        .map_err(|_| Error::Permission)?;
        let bound = engine_result(
            DeliveryObservationSiteV2::ExportPreview,
            prepared.bind_current_v2(
                host_result(DeliveryObservationSiteV2::ExportPreview, self.access())?,
                recipient,
                &read,
                &read,
                &read,
            ),
        )?;
        let export_scope = bound.scope().clone();
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
                &final_inspection,
                &detail,
                || {
                    read.check()?;
                    bridge_result(
                        DeliveryObservationSiteV2::ExportApproval,
                        bound.check_current_v2(),
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
                        bound.check_current_v2(),
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
            bound.deliver_v2(
                host_result(DeliveryObservationSiteV2::ExportCommit, self.access())?,
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
        Ok((
            client,
            OriginalDeliveryExportV2 {
                request: DurableDeliveryAdmissionRequestV2 {
                    version: 2,
                    import_request: request,
                    delivery: plan,
                },
                export_scope,
                retention,
            },
        ))
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
    // This route pairs an already-open native entry; unlike the qualifier's
    // opener it makes no claim to move or refresh that original native lifetime.
    let (client, exported) =
        host.private_original_delivery_export_v2(workspace, &request.choices, || {
            Ok((client, request.request))
        })?;
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
    #[cfg(feature = "synthetic-born-joined-qualification")]
    thread_local! {
        static EXPORT_SEEN: std::cell::RefCell<Vec<(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn record_export(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
        EXPORT_SEEN.with(|seen| seen.borrow_mut().push((site, outcome)));
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn take_export_seen() -> Vec<(DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)> {
        EXPORT_SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }
    fn cause_error(site: &str, outcome: &str) -> wholepact_engine::ApiError {
        let mut error = wholepact_engine::ApiError::new("DISCLOSURE_DENIED", "private error");
        error.details = Box::new(serde_json::json!({
            "private_durable_delivery_cause_v2": {
                "version": 1,
                "site": site,
                "outcome": outcome,
            },
            "private": "unchanged",
        }));
        error
    }
    #[test]
    fn export_sidecar_complete_inventory_has_exact_source_stage_category_parity() {
        use std::collections::BTreeSet;
        let engine = [
            "EngineDisclosureUnknown", "EngineDisclosureDenied", "EngineRecoveryRequired",
            "EngineIdempotencyConflict", "EngineRevisionConflict", "EngineDurableProposalConflict",
            "EngineDurableConstructionUnavailable", "EngineDurableProfileUnavailable",
            "EngineResourceExhausted", "EngineUnclassified",
        ];
        let engine_or_predicate: Vec<_> = engine.iter().copied().chain(["PredicateDenied"]).collect();
        let bridge = [
            "BridgeBinding", "BridgeConflict", "BridgeMissing", "BridgeUncertain", "BridgeLimit",
            "BridgePermission", "BridgeRecoveryRequired", "BridgeCompleteOriginRecoveryUnavailable",
            "BridgeVerification", "BridgeSignerOriginUnavailable", "BridgeJournal", "BridgeAuthority",
            "BridgeWallet", "BridgeIpc",
        ];
        let origin_io = [
            "OriginIoTimedOut", "OriginIoWouldBlock", "OriginIoUnexpectedEof", "OriginIoBrokenPipe",
            "OriginIoConnectionReset", "OriginIoConnectionAborted", "OriginIoNotConnected",
            "OriginIoInterrupted", "OriginIoPermissionDenied", "OriginIoOther",
        ];
        let origin: Vec<_> = [
            "OriginPermanentStopUnavailable", "OriginRetirementEvidenceUnavailable",
            "OriginSignerOriginUnavailable", "OriginPeerLifetimeUnavailable", "OriginAuthentication",
            "OriginBinding", "OriginConflict", "OriginPermission", "OriginInvalidData", "OriginLocked",
            "OriginCrypto", "OriginIpc", "OriginLimit",
        ].into_iter().chain(origin_io).collect();
        // Independent contract inventory, not the production validator's result.
        let groups: &[(&[&str], &[&str])] = &[
            (&["ExportProofOrigin", "ExportPermission"], &["PredicateDenied"]),
            (&["ExportSourceBefore", "ExportMetadataOrigin", "ExportMarker", "ExportHistory",
                "ExportRoster", "ExportSources", "ExportProofPermission", "ExportReplayScope",
                "ExportReplayLookup", "ExportDelta"], &engine_or_predicate),
            (&["ExportProofCurrent", "ExportSourceAfter", "ExportMaterialCeilings", "ExportIntake",
                "ExportVerifiedProof", "ExportPayload", "ExportOutputActions", "ExportRecipientBinding",
                "ExportCheckpointScope", "ExportCommand", "ExportEntry"], &engine),
            (&["RecipientMutex", "RecipientWriteEmpty"], &["BridgeIpc"]),
            (&["RecipientDeadline", "RecipientWriteDeadline", "RecipientResponse"], &["BridgePermission"]),
            (&["RecipientOrigin"], &bridge),
            (&["RecipientObserverClone", "RecipientWriteTimeout", "RecipientWriteIo"], &origin_io),
            (&["RecipientWriteSerialize", "RecipientResponseDecode", "RecipientResponseDigest"], &["BridgeBinding"]),
            (&["RecipientWriteLimit"], &["BridgeLimit"]),
            (&["RecipientFrame"], &origin),
        ];
        let expected: BTreeSet<_> = groups.iter().flat_map(|(sites, outcomes)| {
            sites.iter().flat_map(move |site| outcomes.iter().map(move |outcome| (*site, *outcome)))
        }).collect();
        assert_eq!(expected.len(), 298);
        let sites: BTreeSet<_> = EXPORT_CAUSE_SITES.iter().map(|(label, _)| *label).collect();
        let outcomes: BTreeSet<_> = EXPORT_CAUSE_OUTCOMES.iter().map(|(label, _)| *label).collect();
        assert_eq!(EXPORT_CAUSE_SITES.len(), 37);
        assert_eq!(EXPORT_CAUSE_OUTCOMES.len(), 48);
        assert_eq!(sites.len(), 37);
        assert_eq!(outcomes.len(), 48);
        assert_eq!(expected.iter().map(|(site, _)| *site).collect::<BTreeSet<_>>(), sites);
        assert_eq!(expected.iter().map(|(_, outcome)| *outcome).collect::<BTreeSet<_>>(), outcomes);
        for (site_label, site) in EXPORT_CAUSE_SITES {
            assert_eq!(parse_export_cause_site(site_label), Some(*site));
            for (outcome_label, outcome) in EXPORT_CAUSE_OUTCOMES {
                assert_eq!(parse_export_cause_outcome(outcome_label), Some(*outcome));
                let expected = expected.contains(&(*site_label, *outcome_label))
                    .then_some((*site, *outcome));
                assert_eq!(export_engine_cause(&cause_error(site_label, outcome_label)), expected);
            }
        }
        for unknown in ["", "private/path", "recipientdeadline", "DeliveryRecipientDeadline", "RecipientDeadline ", "ReturnedOk", "HostPermission"] {
            assert_eq!(parse_export_cause_site(unknown), None);
            assert_eq!(parse_export_cause_outcome(unknown), None);
        }
    }
    #[test]
    fn strict_export_sidecar_rejects_malformed_unknown_and_wrong_source_categories() {
        use serde_json::json;
        assert_eq!(
            export_engine_cause(&cause_error("RecipientDeadline", "BridgePermission")),
            Some((DeliveryObservationSiteV2::RecipientDeadline, DeliveryObservationOutcomeV2::BridgePermission)),
        );
        for detail in [
            json!(null), json!(false), json!([]), json!("private"), json!(1),
            json!({}), json!({"version": 1}),
            json!({"version": 1, "site": "RecipientDeadline"}),
            json!({"version": 1, "outcome": "BridgePermission"}),
            json!({"site": "RecipientDeadline", "outcome": "BridgePermission"}),
            json!({"version": 1, "site": "RecipientDeadline", "outcome": "BridgePermission", "extra": null}),
            json!({"version": 1, "site": "RecipientDeadline", "outcome": "BridgePermission", "source": "Engine"}),
            json!({"version": 1, "site": "RecipientDeadline", "outcome": "BridgePermission", "committed": false}),
        ] {
            let mut error = cause_error("RecipientDeadline", "BridgePermission");
            error.details[EXPORT_CAUSE_KEY] = detail;
            assert_eq!(export_engine_cause(&error), None);
        }
        for version in [json!(0), json!(2), json!(-1), json!(1.0), json!("1"), json!(null), json!(true)] {
            let mut error = cause_error("RecipientDeadline", "BridgePermission");
            error.details[EXPORT_CAUSE_KEY]["version"] = version;
            assert_eq!(export_engine_cause(&error), None);
        }
        for field in ["site", "outcome"] {
            for invalid in [json!(null), json!(1), json!(true), json!([]), json!({}), json!(""), json!("private unknown")] {
                let mut error = cause_error("RecipientDeadline", "BridgePermission");
                error.details[EXPORT_CAUSE_KEY][field] = invalid;
                assert_eq!(export_engine_cause(&error), None);
            }
        }
        for (site, outcome) in [
            ("RecipientDeadline", "EngineDisclosureDenied"),
            ("RecipientDeadline", "PredicateDenied"),
            ("RecipientDeadline", "OriginIoTimedOut"),
            ("RecipientFrame", "BridgePermission"),
            ("RecipientWriteTimeout", "OriginAuthentication"),
            ("RecipientMutex", "BridgeBinding"),
            ("RecipientOrigin", "OriginAuthentication"),
            ("ExportProofCurrent", "BridgePermission"),
            ("ExportProofCurrent", "PredicateDenied"),
            ("ExportProofOrigin", "EngineDisclosureDenied"),
            ("ExportEntry", "OriginIoTimedOut"),
            ("SourceScopePredicate", "PredicateDenied"),
            ("NativeCheck", "HostPermission"),
            ("ExportCommit", "ReturnedOk"),
            ("ExportProofCurrent", "HostPermission"),
            ("ExportProofCurrent", "DISCLOSURE_DENIED"),
            ("private source path", "EngineDisclosureDenied"),
        ] {
            assert_eq!(export_engine_cause(&cause_error(site, outcome)), None);
        }
        for details in [json!(null), json!([]), json!("private"), json!(false), json!({"other": {"version": 1, "site": "RecipientDeadline", "outcome": "BridgePermission"}})] {
            let mut error = cause_error("RecipientDeadline", "BridgePermission");
            error.details = Box::new(details);
            assert_eq!(export_engine_cause(&error), None);
        }
        for collision in [json!(null), json!(false), json!(true), json!(0), json!(1), json!(1.5), json!("private"), json!([]), json!({}), json!({"version": 1})] {
            let mut error = cause_error("RecipientDeadline", "BridgePermission");
            error.details[EXPORT_CAUSE_COLLISION_KEY] = collision;
            let original = serde_json::to_vec(&error).unwrap();
            assert_eq!(export_engine_cause(&error), None);
            assert_eq!(serde_json::to_vec(&error).unwrap(), original);
        }
    }
    #[test]
    fn export_cause_projection_preserves_owned_engine_error_and_non_clone_success() {
        struct OwnedOnly(Box<u8>);
        let success = OwnedOnly(Box::new(3));
        let address = (&*success.0) as *const u8;
        let returned = observed_engine_result(DeliveryObservationSiteV2::ExportCommit, Ok(success)).unwrap();
        assert_eq!((&*returned.0) as *const u8, address);
        let mut error = cause_error("RecipientDeadline", "BridgePermission");
        error.code = "DISCLOSURE_UNKNOWN".into();
        error.retryable = true;
        error.operation_id = Some("private operation".into());
        error.safe_actions = vec!["private action".into()];
        error.details["original_code"] = serde_json::json!("DISCLOSURE_DENIED");
        error.details["disclosure_state"] = serde_json::json!("DisclosedOrUnknown");
        let expected = serde_json::to_vec(&error).unwrap();
        let details_address = (&*error.details) as *const serde_json::Value;
        let message_address = error.message.as_ptr();
        let returned = observed_engine_result::<()>(DeliveryObservationSiteV2::ExportCommit, Err(error)).unwrap_err();
        assert_eq!((&*returned.details) as *const serde_json::Value, details_address);
        assert_eq!(returned.message.as_ptr(), message_address);
        assert_eq!(serde_json::to_vec(&returned).unwrap(), expected);
        assert!(matches!(Err::<(), _>(returned).map_err(Error::from), Err(Error::Permission)));
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn export_cause_precedes_aggregate_and_other_sources_cannot_impersonate_it() {
        use DeliveryObservationOutcomeV2 as O;
        use DeliveryObservationSiteV2 as S;
        take_export_seen();
        with_delivery_observer_v2(record_export, || {
            assert!(engine_result::<()>(S::ExportCommit, Err(cause_error("RecipientFrame", "OriginAuthentication"))).is_err());
            assert_eq!(take_export_seen(), vec![(S::RecipientFrame, O::OriginAuthentication), (S::ExportCommit, O::EngineDisclosureDenied)]);
            for site in [S::SourceOpen, S::SourceInspection, S::ExportPreview, S::ExportApproval, S::ExportPostcheck, S::FixedRead] {
                assert!(engine_result::<()>(site, Err(cause_error("RecipientDeadline", "BridgePermission"))).is_err());
                assert_eq!(take_export_seen(), vec![(site, O::EngineDisclosureDenied)]);
            }
            assert!(engine_result::<()>(S::ExportCommit, Err(cause_error("RecipientFrame", "BridgePermission"))).is_err());
            assert_eq!(take_export_seen(), vec![(S::ExportCommit, O::EngineDisclosureDenied)]);
            let mut collision = cause_error("RecipientDeadline", "BridgePermission");
            collision.details[EXPORT_CAUSE_COLLISION_KEY] = serde_json::json!(false);
            assert!(engine_result::<()>(S::ExportCommit, Err(collision)).is_err());
            assert_eq!(take_export_seen(), vec![(S::ExportCommit, O::EngineDisclosureDenied)]);
            assert!(host_result::<()>(S::ExportCommit, Err(Error::Receipt("private_durable_delivery_cause_v2 RecipientDeadline BridgePermission".into()))).is_err());
            assert_eq!(take_export_seen(), vec![(S::ExportCommit, O::HostReceipt)]);
            assert!(bridge_result::<()>(S::ExportCommit, Err(wholepact_signer::authority_bridge::BridgeError::Permission)).is_err());
            assert_eq!(take_export_seen(), vec![(S::ExportCommit, O::BridgePermission)]);
            assert!(observed_engine_result(S::ExportCommit, Ok(())).is_ok());
            assert!(take_export_seen().is_empty());
        });
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn export_predicates_are_once_only_short_circuit_and_readonly_silent() {
        use std::cell::Cell;
        use DeliveryObservationOutcomeV2 as O;
        use DeliveryObservationSiteV2 as S;
        take_export_seen();
        with_delivery_observer_v2(record_export, || {
            for exporting in [false, true] {
                for site in [S::SourceScopePredicate, S::ProofRolePredicate, S::MaterialActionPredicate, S::MaterialScopePredicate, S::ExportScopePredicate] {
                    for allowed in [false, true] {
                        let predicates = Cell::new(0);
                        let following = Cell::new(0);
                        let result = export_predicate(exporting, site, {
                            predicates.set(predicates.get() + 1);
                            allowed
                        }) && {
                            following.set(following.get() + 1);
                            true
                        };
                        assert_eq!(result, allowed);
                        assert_eq!(predicates.get(), 1);
                        assert_eq!(following.get(), if allowed { 1 } else { 0 });
                        assert_eq!(take_export_seen(), if exporting && !allowed { vec![(site, O::PredicateDenied)] } else { vec![] });
                    }
                }
            }
            for (members, expected, visits) in [([false, true], true, 2), ([false, false], false, 2), ([true, false], true, 1)] {
                let checked = Cell::new(0);
                assert_eq!(export_predicate(true, S::MaterialScopePredicate, members.into_iter().any(|member| {
                    checked.set(checked.get() + 1);
                    member
                })), expected);
                assert_eq!(checked.get(), visits);
                assert_eq!(take_export_seen(), if expected { vec![] } else { vec![(S::MaterialScopePredicate, O::PredicateDenied)] });
            }
            let lookups = Cell::new(0);
            let checks = Cell::new(0);
            assert!(!(export_predicate(true, S::MaterialActionPredicate, false)
                && export_predicate(true, S::MaterialScopePredicate, {
                    lookups.set(lookups.get() + 1);
                    true
                }) && {
                    checks.set(checks.get() + 1);
                    true
                }));
            assert_eq!(lookups.get(), 0);
            assert_eq!(checks.get(), 0);
            assert_eq!(take_export_seen(), vec![(S::MaterialActionPredicate, O::PredicateDenied)]);
        });
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn source_scope_false_never_fabricates_or_overrides_typed_failure() {
        use DeliveryObservationOutcomeV2 as O;
        use DeliveryObservationSiteV2 as S;
        take_export_seen();
        with_delivery_observer_v2(record_export, || {
            for exporting in [false, true] {
                for allowed in [false, true] {
                    assert_eq!(export_source_scope_result(exporting, Ok(allowed)).unwrap(), allowed);
                    assert_eq!(take_export_seen(), if exporting && !allowed { vec![(S::SourceScopePredicate, O::PredicateDenied)] } else { vec![] });
                }
                let payload = String::from("private serialization error");
                let address = payload.as_ptr();
                match export_source_scope_result(exporting, Err(Error::Receipt(payload))) {
                    Err(Error::Receipt(returned)) => assert_eq!(returned.as_ptr(), address),
                    _ => panic!("original error replaced"),
                }
                assert_eq!(take_export_seen(), if exporting { vec![(S::SourceCheck, O::HostReceipt)] } else { vec![] });
            }
        });
    }
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
        let production = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        assert!(!production.contains("fn fixed_permission_boundary_v3"));
        assert!(!production.contains("pub fn new("));
        assert!(production.contains("bound.check_current_v2()"));
        assert!(production.contains("bound.deliver_v2("));
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
                < export.find("prepare_original_delivery_v2").unwrap()
        );
        let final_phase = export
            .split("// This is an unconditional new decision")
            .nth(1)
            .unwrap()
            .split("pub(in crate::host) fn private_original_delivery_status_v2")
            .next()
            .unwrap();
        let prepare_phase = export
            .split("// This is an unconditional new decision")
            .next()
            .unwrap();
        assert!(!prepare_phase.contains("owner.inspection_approval()"));
        assert!(!prepare_phase.contains("let detail = format!("));
        let fresh_issuance = final_phase
            .split("let read = InspectionReadV2")
            .next()
            .unwrap();
        assert!(!fresh_issuance.contains("let detail = format!("));
        assert!(!final_phase.contains("owner.inspection_approval()"));
        assert!(final_phase.contains("approval: &final_inspection"));
        assert!(final_phase.contains("approve_historical(&detail)"));
        assert!(final_phase.contains("&final_inspection,"));
        assert!(final_phase.contains("prepared.bind_current_v2("));
        assert!(final_phase.contains("bound.deliver_v2("));
        let read = production
            .split("struct InspectionReadV2")
            .nth(1)
            .unwrap()
            .split("struct OwnedDeliveryConsentV2")
            .next()
            .unwrap();
        assert!(read.contains("approval: &'a HistoricalApproval"));
        assert!(read.contains("self.approval.check()"));
        assert!(read.contains("DurableMaterialActionV1::ReadForExactConstruction"));
        assert!(!read.contains("owner.inspection_approval()"));
        assert!(!read.contains("DurableMaterialActionV1::ExportForLocalNativeReview"));
        assert!(!read.contains("impl LocalDurableReviewExportConsentV1"));
    }
    #[test]
    fn prepared_delivery_local_preparation_precedes_one_shot_recipient() {
        use std::cell::RefCell;
        // Inert, non-Clone values only: no native approval is manufactured.
        struct LocalBytes(Box<[u8]>);
        struct CurrentPeer(Box<u8>);
        let events = RefCell::new(Vec::new());
        let original = LocalBytes(vec![3, 7, 11].into_boxed_slice());
        let allocation = original.0.as_ptr();
        let (prepared, peer) = prepare_before_recipient_v2(
            || {
                events.borrow_mut().push("prepare");
                Ok(original)
            },
            || {
                events.borrow_mut().push("open");
                Ok(CurrentPeer(Box::new(13)))
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["prepare", "open"]);
        assert_eq!(prepared.0.as_ptr(), allocation);
        assert_eq!(&*prepared.0, &[3, 7, 11]);
        assert_eq!(*peer.0, 13);
    }
    #[test]
    fn prepared_delivery_denial_never_opens_recipient_and_drops_local_custody() {
        use std::cell::{Cell, RefCell};
        let opened = Cell::new(false);
        let result = prepare_before_recipient_v2(
            || Err::<(), _>(Error::Permission),
            || {
                opened.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::Permission)));
        assert!(!opened.get());

        struct LocalBytes<'a>(&'a RefCell<Vec<&'static str>>);
        impl Drop for LocalBytes<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop");
            }
        }
        let events = RefCell::new(Vec::new());
        let result = prepare_before_recipient_v2(
            || {
                events.borrow_mut().push("prepare");
                Ok(LocalBytes(&events))
            },
            || {
                events.borrow_mut().push("open-denied");
                Err::<(), _>(Error::Authentication)
            },
        );
        assert!(matches!(result, Err(Error::Authentication)));
        assert_eq!(*events.borrow(), ["prepare", "open-denied", "drop"]);
    }
    #[test]
    fn prepared_delivery_issuance_checks_source_before_and_after_exactly_once() {
        use std::cell::RefCell;
        let events = RefCell::new(Vec::new());
        // This is an inert return value, not an approval or authority factory.
        struct InertReview(Box<u8>);
        let review = source_checked_approval_v2(
            || {
                events.borrow_mut().push("source-and-both-ceilings");
                Ok(())
            },
            || {
                events.borrow_mut().push("genuine-issuer-call");
                Ok(InertReview(Box::new(17)))
            },
        )
        .unwrap();
        assert_eq!(*review.0, 17);
        assert_eq!(
            *events.borrow(),
            [
                "source-and-both-ceilings",
                "genuine-issuer-call",
                "source-and-both-ceilings"
            ]
        );
    }
    #[test]
    fn prepared_delivery_issuance_denial_short_circuits_every_later_phase() {
        use std::cell::{Cell, RefCell};
        for deny in 0..3 {
            let calls = Cell::new(0);
            let events = RefCell::new(Vec::new());
            let result = prepare_before_recipient_v2(
                || {
                    source_checked_approval_v2(
                        || {
                            let position = calls.get();
                            calls.set(position + 1);
                            events.borrow_mut().push(if position == 0 {
                                "before"
                            } else {
                                "after"
                            });
                            if deny == position * 2 {
                                Err(Error::Permission)
                            } else {
                                Ok(())
                            }
                        },
                        || {
                            events.borrow_mut().push("issue");
                            if deny == 1 {
                                Err(Error::Authentication)
                            } else {
                                Ok(())
                            }
                        },
                    )?;
                    events.borrow_mut().push("prepare-bytes");
                    Ok(())
                },
                || {
                    events.borrow_mut().push("open-recipient");
                    Ok(())
                },
            );
            assert!(result.is_err());
            let expected: &[&str] = match deny {
                0 => &["before"],
                1 => &["before", "issue"],
                _ => &["before", "issue", "after"],
            };
            assert_eq!(&*events.borrow(), expected);
        }
    }
    #[test]
    fn prepared_delivery_inspection_review_bounds_real_escaped_framing() {
        let maximum = wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES;
        let challenge = "\nType APPROVE 0000000000000000 to approve this exact operation, or anything else to reject: ";
        let exact = "x".repeat(maximum - challenge.len());
        assert!(bound_original_delivery_review_v2(&exact).is_ok());
        assert!(matches!(
            bound_original_delivery_review_v2(&(exact + "x")),
            Err(Error::Invalid)
        ));
        let escaped = "é".repeat(maximum / 4);
        assert!(escaped.len() < maximum);
        assert!(crate::terminal::render_synthetic_expected_prompt(&escaped).len() > maximum);
        assert!(matches!(
            bound_original_delivery_review_v2(&escaped),
            Err(Error::Invalid)
        ));
        assert!(bound_original_delivery_review_v2("Bounded source\nLocal only.").is_ok());
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

#[cfg(all(test, wholepact_financial_rendered_host_semantic_ci))]
mod semantic_preparation_observation_tests {
    use super::*;
    use std::cell::RefCell;
    thread_local! { static EVENTS: RefCell<Vec<(u8, DeliveryObservationSiteV2, DeliveryObservationOutcomeV2)>> = const { RefCell::new(Vec::new()) }; }
    fn outer(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
        EVENTS.with(|events| events.borrow_mut().push((1, site, outcome)));
    }
    fn inner(site: DeliveryObservationSiteV2, outcome: DeliveryObservationOutcomeV2) {
        EVENTS.with(|events| events.borrow_mut().push((2, site, outcome)));
    }
    fn deny() { observe_delivery(DeliveryObservationSiteV2::SourceCheck, DeliveryObservationOutcomeV2::HostPermission); }
    #[test]
    fn lexical_scope_restores_nested_early_return_and_unwind() {
        EVENTS.with(|events| events.borrow_mut().clear());
        deny();
        with_delivery_observer_v2(outer, || {
            deny();
            with_delivery_observer_v2(inner, || { deny(); });
            let _: Result<()> = with_delivery_observer_v2(inner, || { deny(); Err(Error::Invalid) });
            assert!(std::panic::catch_unwind(|| with_delivery_observer_v2(inner, || { deny(); panic!("synthetic scope unwind"); })).is_err());
            deny();
        });
        deny();
        EVENTS.with(|events| assert_eq!(events.borrow().iter().map(|v| v.0).collect::<Vec<_>>(), [1, 2, 2, 2, 1]));
        assert!(!SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()));
    }
    #[test]
    fn semantic_marker_is_lexical_and_nested_qualification_does_not_inherit_it() {
        assert!(!SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()));
        {
            let _scope = semantic_delivery_scope();
            assert!(SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()));
            with_delivery_observer_v2(outer, || assert!(!SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get())));
            assert!(SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()));
            std::thread::spawn(|| {
                assert!(!SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()));
                assert!(DELIVERY_OBSERVER_V2.with(|cell| cell.get().is_none()));
            }).join().unwrap();
        }
        assert!(!SEMANTIC_DELIVERY_SCOPE.with(|cell| cell.get()));
    }
    #[test]
    fn mapped_boundaries_are_distinct_and_success_or_final_effect_is_not_recorded() {
        use DeliveryObservationSiteV2 as S;
        use DeliveryObservationOutcomeV2 as O;
        use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::{Stage, Class};
        let cases = [
            (S::SourceOpen, Stage::DeliverySourceOpen), (S::SourceInspection, Stage::DeliverySourceInspection),
            (S::SourcePlan, Stage::DeliverySourcePlan), (S::RecipientPrepare, Stage::DeliveryRecipientPrepare),
            (S::ExportPreview, Stage::DeliveryExportPreview), (S::NativeCheck, Stage::DeliveryNativeCheck),
            (S::SourceCheck, Stage::DeliverySourceCheck), (S::SourceScopePredicate, Stage::DeliverySourceScopePredicate),
            (S::ProofRolePredicate, Stage::DeliveryProofRolePredicate), (S::MaterialActionPredicate, Stage::DeliveryMaterialActionPredicate),
            (S::MaterialScopePredicate, Stage::DeliveryMaterialScopePredicate),
            (S::PreparationSourceBefore, Stage::PreparationSourceBefore), (S::PreparationApproval, Stage::PreparationApproval),
            (S::PreparationSourceAfter, Stage::PreparationSourceAfter), (S::HistoricalApprovalDeadline, Stage::HistoricalApprovalDeadline),
            (S::HistoricalApprovalForeground, Stage::HistoricalApprovalForeground), (S::OriginalDisclosureSelector, Stage::OriginalDisclosureSelector),
            (S::MaterialRestrictionCapture, Stage::MaterialRestrictionCapture), (S::PairConfirmation, Stage::PairConfirmation),
        ];
        for (site, stage) in cases {
            assert_eq!(semantic_delivery_code(site, O::HostPermission), Some((stage, Class::Permission)));
            assert_eq!(semantic_delivery_code(site, O::ReturnedOk), None);
        }
        assert_eq!(semantic_delivery_code(S::ExportPreview, O::EngineRevisionConflict), Some((Stage::DeliveryExportPreview, Class::EngineRevisionConflict)));
        assert_eq!(semantic_delivery_code(S::ProofRolePredicate, O::PredicateDenied), Some((Stage::DeliveryProofRolePredicate, Class::PredicateDenied)));
        for site in [S::ExportCommit, S::ExportApproval, S::ExportProofCurrent, S::RecipientFrame] {
            assert_eq!(semantic_delivery_code(site, O::HostPermission), None);
        }
    }
    #[test]
    fn borrowed_error_identity_and_single_operation_are_preserved() {
        let calls = std::cell::Cell::new(0);
        let value = Box::new(7u8);
        let pointer = &*value as *const u8;
        let result: std::result::Result<(), Box<u8>> = with_delivery_observer_v2(outer, || {
            observed_result(DeliveryObservationSiteV2::ExportPreview, {
                calls.set(calls.get() + 1);
                Err(value)
            }, |_| DeliveryObservationOutcomeV2::EngineUnclassified)
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(&*result.unwrap_err() as *const u8, pointer);
    }
}
