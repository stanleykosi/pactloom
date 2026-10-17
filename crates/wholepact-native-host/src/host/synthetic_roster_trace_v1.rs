//! Test-only closed diagnostics at actual Host roster effect boundaries.
//! Borrow errors without formatting payloads and return every operation unchanged.
//! No owner, deadline, input, path or external message is exposed or substituted.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]
use crate::Error;
use wholepact_chain::ChainError;
use wholepact_wallet::wallet::{
    WalletError,
    protected_sync::{SyncError, recovery::RecoveryScanError},
    recorded_roster_import_v2::RecordedRosterImportErrorV2,
};
macro_rules! labels {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $name { $($variant),+ }
        impl $name { fn label(self) -> &'static str { match self { $(Self::$variant => stringify!($variant)),+ } } }
    };
}
labels! { Phase { CompletionObservationDenied, CompletionPostReentryCurrent, CompletionReadBinding, CompletionConstructionTime, CompletionCallerBinding, CompletionConstructionRequest, CheckpointEngine, CheckpointWalletUnwind, CheckpointFinish, CheckpointObservations, CheckpointOutput, CheckpointBeforeClaim, CheckpointClaimMayExist, CompletionOriginal, CompletionPairApproval, CompletionPairBegin, CompletionPairFinish, CompletionReentryRequest, CompletionRequestApproval, CompletionReentryBegin, CompletionReentryFinish, CompletionConstructionBegin, CompletionConstructionFinish, CandidateRetainCurrent, CandidateRetainRequest, CandidateRetainBegin, CandidateRetainFinish, ScanAccessAccount, ScanAccessNativeBefore, ScanAccessRequest, ScanAccessTarget, ScanAccessHostAccess, ScanAccessPrincipal, ScanAccessEnrollmentPrincipal, ScanAccessRequestDigest, ScanAccessScopeDigest, ScanAccessImport, ScanAccessNativeAfter, ScanNativeAdmissionDeadline, ScanNativeLease, ScanNativeRemaining, ScanNativePurpose, ScanNativeAccount, ScanNativeProviderSource, ScanNativeProviderEndpoint, ScanNativeProviderTrust, JoinedPairFinish, JoinedRequestBegin, JoinedLeaseFinish, JoinedInventoryCheck, JoinedAuditAppend, JoinedInventoryRun, InventoryPair, InventoryRequest, InventoryLease, InventoryImport, InventoryImportRecord, InventoryScan, InventorySynchronize, InventoryInspect, InventoryDisplay, InventoryFinish, CandidateRun, CandidatePair, CandidateRequest, CandidateLease, CandidateExclusions, CandidateSelect, CandidateDisplay, CandidateRetain, CandidateAttach } }
labels! { Outcome { ExactPermission, ExactLineage, ExactBinding, ExactStorage, ExactRecoveryRequired, ExactStateChanged, ExactProfileChanged, ExactBudget, ExactRoster, OriginPermanentStopUnavailable, OriginRetirementEvidenceUnavailable, OriginSignerOriginUnavailable, OriginPeerLifetimeUnavailable, OriginAuthentication, OriginBinding, OriginConflict, OriginPermission, OriginInvalidData, OriginLocked, OriginCrypto, OriginIpc, OriginLimit, OriginIoTimedOut, OriginIoWouldBlock, OriginIoUnexpectedEof, OriginIoBrokenPipe, OriginIoConnectionReset, OriginIoConnectionAborted, OriginIoNotConnected, OriginIoInterrupted, OriginIoPermissionDenied, OriginIoOther, BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit, BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable, BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority, BridgeWallet, BridgeIpc, Begin, Complete, HostPlatform, HostTerminal, HostPermission, HostLocked, HostInvalid, HostAuthentication, HostStorage, HostQuarantined, HostUnsupported, HostReceipt, HostRecoverySemantic, HostRecoveryBackupUnsupported, HostRecoveryFinancialUnsupported, HostCompleteOriginRecoveryUnavailable, HostHistoricalExportIncomplete, HostGenerationArchiveIncomplete, ImportFreshOwnerRequired, ImportBinding, ImportIncomplete, ImportStorage, SyncAccessDenied, SyncInvalidRequest, SyncInterrupted, SyncReconciliationRequired, SyncInvalidResponse, SyncResourceLimit, SyncNoCurrentObservation, WalletStorage, WalletAccountScope, WalletAccountMismatch, WalletIncompleteSync, WalletUnsupportedProfile, WalletChainMismatch, WalletInsufficientFunds, WalletInvalidRequest, WalletMissingWitness, WalletInvalidNote, WalletScan, WalletTransport, ChainInvalidConfiguration, ChainWrongNetwork, ChainUnsupportedProxyConfiguration, ChainWrongBranch, ChainStaleChain, ChainContradictoryChain, ChainTimeout, ChainTransportUnavailable, ChainObservationInterrupted, ChainMissingAncestryEvidence, ChainNotObserved, ChainResourceLimit, ChainMalformedEvidence, ChainUnsupportedCapability, ChainBackendFailure, ChainClockUnavailable, ChainIdempotencyConflict, ChainJournalFailure, ChainSubmissionNotAuthorized, ChainSubmissionExpiryMargin, ChainObligationConflict, ChainSubmissionOutcomeUnrecorded, ChainSubmissionRetentionUncertain, RecoveryAccessDenied, RecoveryUnsupportedAccountComponents, RecoveryIncompleteScan, RecoveryKnownFundsRemain, RecoveryAdditionalEvidenceRequired } }
fn emit(phase: Phase, outcome: Outcome) {
    eprintln!(
        "\n[JOINED_DIAGNOSTIC {} {}]",
        phase.label(),
        outcome.label()
    );
}
// Successful predicates are intentionally silent, so repeated native checks
// cannot bury the first real denial in the bounded public diagnostic tail.
pub(crate) fn denied_host<T>(phase: Phase, value: &crate::Result<T>) {
    if let Err(error) = value {
        emit(phase, host_error(error));
    }
}
pub(crate) fn denied_predicate(phase: Phase, permitted: &bool) {
    if !permitted {
        emit(phase, Outcome::HostPermission);
    }
}
pub(super) fn begin(phase: Phase) {
    super::synthetic_roster_timing_v1::event(phase.label(), true, false);
    emit(phase, Outcome::Begin);
}
fn result<T, E>(
    phase: Phase,
    value: &std::result::Result<T, E>,
    classify: impl FnOnce(&E) -> Outcome,
) {
    super::synthetic_roster_timing_v1::event(phase.label(), false, value.is_err());
    emit(
        phase,
        value.as_ref().map_or_else(classify, |_| Outcome::Complete),
    );
}
pub(super) fn host<T>(phase: Phase, value: &crate::Result<T>) {
    result(phase, value, host_error);
}
pub(super) fn host_failure(phase: Phase, error: &Error) {
    emit(phase, host_error(error));
}
pub(super) fn observation_failure(
    phase: Phase,
    error: &wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError,
) {
    emit(phase, observation_error(error));
}
fn observation_error(
    error: &wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError,
) -> Outcome {
    use wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError as E;
    match error {
        E::Permission => Outcome::ExactPermission,
        E::Lineage => Outcome::ExactLineage,
        E::Binding => Outcome::ExactBinding,
        E::Storage => Outcome::ExactStorage,
        E::RecoveryRequired => Outcome::ExactRecoveryRequired,
        E::StateChanged => Outcome::ExactStateChanged,
        E::ProfileChanged => Outcome::ExactProfileChanged,
        E::Budget => Outcome::ExactBudget,
        E::Roster => Outcome::ExactRoster,
        E::Sync(error) => sync_error(error),
    }
}
pub(super) fn import<T>(phase: Phase, value: &std::result::Result<T, RecordedRosterImportErrorV2>) {
    result(phase, value, import_error);
}
pub(super) fn sync<T>(phase: Phase, value: &std::result::Result<T, SyncError>) {
    result(phase, value, sync_error);
}
pub(super) fn recovery<T>(phase: Phase, value: &std::result::Result<T, RecoveryScanError>) {
    result(phase, value, recovery_error);
}
// These are the actual returned types before the existing Host conversion.
// Bridge errors may already coarsen a lower origin error; do not reconstruct it.
pub(super) fn origin<T>(phase: Phase, value: &wholepact_signer_origin::Result<T>) {
    result(phase, value, origin_error);
}
pub(super) fn bridge<T>(phase: Phase, value: &wholepact_signer::authority_bridge::Result<T>) {
    result(phase, value, bridge_error);
}
fn origin_error(error: &wholepact_signer_origin::Error) -> Outcome {
    use wholepact_signer_origin::Error as E;
    match error {
        E::PermanentStopUnavailable => Outcome::OriginPermanentStopUnavailable,
        E::RetirementEvidenceUnavailable => Outcome::OriginRetirementEvidenceUnavailable,
        E::SignerOriginUnavailable => Outcome::OriginSignerOriginUnavailable,
        E::PeerLifetimeUnavailable => Outcome::OriginPeerLifetimeUnavailable,
        E::Authentication => Outcome::OriginAuthentication,
        E::Binding => Outcome::OriginBinding,
        E::Conflict => Outcome::OriginConflict,
        E::Permission => Outcome::OriginPermission,
        E::InvalidData => Outcome::OriginInvalidData,
        E::Locked => Outcome::OriginLocked,
        E::Crypto => Outcome::OriginCrypto,
        E::Ipc => Outcome::OriginIpc,
        E::Limit => Outcome::OriginLimit,
        E::Io(error) => match error.kind() {
            std::io::ErrorKind::TimedOut => Outcome::OriginIoTimedOut,
            std::io::ErrorKind::WouldBlock => Outcome::OriginIoWouldBlock,
            std::io::ErrorKind::UnexpectedEof => Outcome::OriginIoUnexpectedEof,
            std::io::ErrorKind::BrokenPipe => Outcome::OriginIoBrokenPipe,
            std::io::ErrorKind::ConnectionReset => Outcome::OriginIoConnectionReset,
            std::io::ErrorKind::ConnectionAborted => Outcome::OriginIoConnectionAborted,
            std::io::ErrorKind::NotConnected => Outcome::OriginIoNotConnected,
            std::io::ErrorKind::Interrupted => Outcome::OriginIoInterrupted,
            std::io::ErrorKind::PermissionDenied => Outcome::OriginIoPermissionDenied,
            _ => Outcome::OriginIoOther,
        },
    }
}
fn bridge_error(error: &wholepact_signer::authority_bridge::BridgeError) -> Outcome {
    use wholepact_signer::authority_bridge::BridgeError as E;
    // This whole module requires synthetic-born-joined-qualification, which
    // explicitly enables the signer's authority-signing (and Wallet variant).
    match error {
        E::Binding => Outcome::BridgeBinding,
        E::Conflict => Outcome::BridgeConflict,
        E::Missing => Outcome::BridgeMissing,
        E::Uncertain => Outcome::BridgeUncertain,
        E::Limit => Outcome::BridgeLimit,
        E::Permission => Outcome::BridgePermission,
        E::RecoveryRequired => Outcome::BridgeRecoveryRequired,
        E::CompleteOriginRecoveryUnavailable => Outcome::BridgeCompleteOriginRecoveryUnavailable,
        E::Verification => Outcome::BridgeVerification,
        E::SignerOriginUnavailable => Outcome::BridgeSignerOriginUnavailable,
        E::Journal(_) => Outcome::BridgeJournal,
        E::Authority(_) => Outcome::BridgeAuthority,
        E::Wallet(_) => Outcome::BridgeWallet,
        E::Ipc => Outcome::BridgeIpc,
    }
}
fn host_error(error: &Error) -> Outcome {
    use crate::Error as E;
    match error {
        E::Platform => Outcome::HostPlatform,
        E::Terminal => Outcome::HostTerminal,
        E::Permission => Outcome::HostPermission,
        E::Locked => Outcome::HostLocked,
        E::Invalid => Outcome::HostInvalid,
        E::Authentication => Outcome::HostAuthentication,
        E::Storage => Outcome::HostStorage,
        E::Quarantined => Outcome::HostQuarantined,
        E::Unsupported => Outcome::HostUnsupported,
        E::Receipt(_) => Outcome::HostReceipt,
        E::RecoverySemantic(_) => Outcome::HostRecoverySemantic,
        E::RecoveryBackupUnsupported => Outcome::HostRecoveryBackupUnsupported,
        E::RecoveryFinancialUnsupported => Outcome::HostRecoveryFinancialUnsupported,
        E::CompleteOriginRecoveryUnavailable => Outcome::HostCompleteOriginRecoveryUnavailable,
        E::HistoricalExportIncomplete => Outcome::HostHistoricalExportIncomplete,
        E::GenerationArchiveIncomplete => Outcome::HostGenerationArchiveIncomplete,
    }
}
fn import_error(error: &RecordedRosterImportErrorV2) -> Outcome {
    use RecordedRosterImportErrorV2 as E;
    match error {
        E::FreshOwnerRequired => Outcome::ImportFreshOwnerRequired,
        E::Binding => Outcome::ImportBinding,
        E::Incomplete => Outcome::ImportIncomplete,
        E::Storage => Outcome::ImportStorage,
    }
}
fn sync_error(error: &SyncError) -> Outcome {
    use SyncError as E;
    match error {
        E::AccessDenied => Outcome::SyncAccessDenied,
        E::InvalidRequest => Outcome::SyncInvalidRequest,
        E::Interrupted => Outcome::SyncInterrupted,
        E::ReconciliationRequired => Outcome::SyncReconciliationRequired,
        E::InvalidResponse => Outcome::SyncInvalidResponse,
        E::ResourceLimit => Outcome::SyncResourceLimit,
        E::NoCurrentObservation => Outcome::SyncNoCurrentObservation,
        E::Wallet(error) => wallet_error(error),
        E::Chain(error) => chain_error(error),
    }
}
fn wallet_error(error: &WalletError) -> Outcome {
    use WalletError as E;
    match error {
        E::Storage => Outcome::WalletStorage,
        E::AccountScope => Outcome::WalletAccountScope,
        E::AccountMismatch => Outcome::WalletAccountMismatch,
        E::IncompleteSync => Outcome::WalletIncompleteSync,
        E::UnsupportedProfile => Outcome::WalletUnsupportedProfile,
        E::ChainMismatch => Outcome::WalletChainMismatch,
        E::InsufficientFunds => Outcome::WalletInsufficientFunds,
        E::InvalidRequest => Outcome::WalletInvalidRequest,
        E::MissingWitness => Outcome::WalletMissingWitness,
        E::InvalidNote => Outcome::WalletInvalidNote,
        E::Scan => Outcome::WalletScan,
        E::Transport => Outcome::WalletTransport,
    }
}
fn chain_error(error: &ChainError) -> Outcome {
    use ChainError as E;
    match error {
        E::InvalidConfiguration => Outcome::ChainInvalidConfiguration,
        E::WrongNetwork => Outcome::ChainWrongNetwork,
        E::UnsupportedProxyConfiguration => Outcome::ChainUnsupportedProxyConfiguration,
        E::WrongBranch => Outcome::ChainWrongBranch,
        E::StaleChain => Outcome::ChainStaleChain,
        E::ContradictoryChain => Outcome::ChainContradictoryChain,
        E::Timeout => Outcome::ChainTimeout,
        E::TransportUnavailable => Outcome::ChainTransportUnavailable,
        E::ObservationInterrupted => Outcome::ChainObservationInterrupted,
        E::MissingAncestryEvidence => Outcome::ChainMissingAncestryEvidence,
        E::NotObserved => Outcome::ChainNotObserved,
        E::ResourceLimit => Outcome::ChainResourceLimit,
        E::MalformedEvidence => Outcome::ChainMalformedEvidence,
        E::UnsupportedCapability => Outcome::ChainUnsupportedCapability,
        E::BackendFailure { .. } => Outcome::ChainBackendFailure,
        E::ClockUnavailable => Outcome::ChainClockUnavailable,
        E::IdempotencyConflict => Outcome::ChainIdempotencyConflict,
        E::JournalFailure => Outcome::ChainJournalFailure,
        E::SubmissionNotAuthorized => Outcome::ChainSubmissionNotAuthorized,
        E::SubmissionExpiryMargin => Outcome::ChainSubmissionExpiryMargin,
        E::ObligationConflict => Outcome::ChainObligationConflict,
        E::SubmissionOutcomeUnrecorded => Outcome::ChainSubmissionOutcomeUnrecorded,
        E::SubmissionRetentionUncertain => Outcome::ChainSubmissionRetentionUncertain,
    }
}
fn recovery_error(error: &RecoveryScanError) -> Outcome {
    use RecoveryScanError as E;
    match error {
        E::AccessDenied => Outcome::RecoveryAccessDenied,
        E::UnsupportedAccountComponents => Outcome::RecoveryUnsupportedAccountComponents,
        E::IncompleteScan => Outcome::RecoveryIncompleteScan,
        E::KnownFundsRemain => Outcome::RecoveryKnownFundsRemain,
        E::AdditionalEvidenceRequired => Outcome::RecoveryAdditionalEvidenceRequired,
        E::Sync(error) => sync_error(error),
        E::Wallet(error) => wallet_error(error),
    }
}
#[test]
fn lower_error_projection_preserves_only_closed_kinds() {
    use wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError as Exact;
    for (error, expected) in [
        (Exact::Permission, "ExactPermission"),
        (Exact::Lineage, "ExactLineage"),
        (Exact::Binding, "ExactBinding"),
        (Exact::Storage, "ExactStorage"),
        (Exact::RecoveryRequired, "ExactRecoveryRequired"),
        (Exact::StateChanged, "ExactStateChanged"),
        (Exact::ProfileChanged, "ExactProfileChanged"),
        (Exact::Budget, "ExactBudget"),
        (Exact::Roster, "ExactRoster"),
    ] {
        assert_eq!(observation_error(&error).label(), expected);
    }
    assert_eq!(
        observation_error(&Exact::Sync(SyncError::Interrupted)).label(),
        "SyncInterrupted"
    );
    for grpc_code in [-1, 0, 12345] {
        assert_eq!(
            observation_error(&Exact::Sync(SyncError::Chain(ChainError::BackendFailure {
                grpc_code,
            }))).label(),
            "ChainBackendFailure"
        );
    }
    use wholepact_signer_origin::Error as Origin;
    use wholepact_signer::authority_bridge::BridgeError as Bridge;
    assert_eq!(origin_error(&Origin::SignerOriginUnavailable).label(), "OriginSignerOriginUnavailable");
    assert_eq!(origin_error(&Origin::Binding).label(), "OriginBinding");
    for (kind, expected) in [
        (std::io::ErrorKind::WouldBlock, "OriginIoWouldBlock"),
        (std::io::ErrorKind::TimedOut, "OriginIoTimedOut"),
        (std::io::ErrorKind::Other, "OriginIoOther"),
    ] {
        let error = Origin::Io(std::io::Error::new(kind, "private path or endpoint never disclosed"));
        assert_eq!(origin_error(&error).label(), expected);
    }
    assert_eq!(bridge_error(&Bridge::Binding).label(), "BridgeBinding");
    assert_eq!(bridge_error(&Bridge::Permission).label(), "BridgePermission");
    assert_eq!(bridge_error(&Bridge::Authority(wholepact_authority::AuthorityError::Conflict)).label(), "BridgeAuthority");
    assert_eq!(
        host_error(&Error::Receipt("private payload never disclosed".into())).label(),
        "HostReceipt"
    );
    assert_eq!(
        host_error(&Error::RecoverySemantic("other private payload".into())).label(),
        "HostRecoverySemantic"
    );
    for grpc_code in [-1, 0, 1, 12345] {
        assert_eq!(
            sync_error(&SyncError::Chain(ChainError::BackendFailure { grpc_code })).label(),
            "ChainBackendFailure"
        );
    }
    assert_eq!(
        sync_error(&SyncError::Interrupted).label(),
        "SyncInterrupted"
    );
    assert_eq!(
        sync_error(&SyncError::Wallet(WalletError::Storage)).label(),
        "WalletStorage"
    );
    assert_eq!(
        import_error(&RecordedRosterImportErrorV2::Binding).label(),
        "ImportBinding"
    );
    assert_eq!(
        recovery_error(&RecoveryScanError::IncompleteScan).label(),
        "RecoveryIncompleteScan"
    );
}

#[test]
fn denial_projection_preserves_single_evaluation_and_short_circuit() {
    let mut evaluated = Vec::new();
    let allowed = crate::host::roster_denial!(denied_predicate, ScanAccessAccount, {
        evaluated.push(1);
        false
    }) && crate::host::roster_denial!(denied_predicate, ScanNativePurpose, {
        evaluated.push(2);
        true
    });
    assert!(!allowed);
    assert_eq!(evaluated, vec![1]);
    let result: crate::Result<()> = crate::host::roster_denial!(denied_host, ScanAccessTarget, {
        evaluated.push(3);
        Err(Error::Authentication)
    });
    assert!(matches!(result, Err(Error::Authentication)));
    assert_eq!(evaluated, vec![1, 3]);
    let result = crate::host::roster_denial!(denied_host, ScanAccessTarget, {
        evaluated.push(4);
        Ok::<_, Error>(7)
    });
    assert_eq!(result.unwrap(), 7);
    assert_eq!(evaluated, vec![1, 3, 4]);
}
