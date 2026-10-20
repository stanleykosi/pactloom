//! Qualification-only finite diagnostics. Never serialize error strings or data.
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinancialStageV1 {


    NativeSourceOpen,
    NativeHistoryRead,
    NativeContinue,
    NativeAdmit,
    NativeAcquire,
    NativeActivate,
    NativeWalletPrepare,
    NativeWalletObserve,
    NativeSignPrepare,
    NativeSign,
    NativeReturnPrepare,
    NativeHostPreparedWait,
    NativeReturnApprove,
    NativeReturnServe,
    NativeReviewStage,
    NativeResultRequest,
    NativeAuthorityHistoryRead,
    NativeFinancialHistoryRead,
    NativeAuthorityAdmit,
    NativeAuthorityAcquire,
    NativeAuthorityActivate,
    NativeAuthorityVerifyActive,
    NativeWalletChain,
    NativeWalletBirthday,
    NativeWalletInitialize,
    NativeWalletImport,
    NativeWalletController,
    NativeWalletVerify,
    NativeWalletStatus,
    NativeWalletMaterial,
    NativeWalletSynchronize,
    NativeWalletTicket,
    NativeWalletReconcile,

    LifecycleHarness,
    WitnessHistoryService,
    WitnessContinuationReview,
    WitnessContinuationCommit,
    WitnessSigningService,
    WitnessCompletedPairService,
    WitnessCompletedAccountService,
    WitnessOriginalReopen,
    WitnessOriginalPreserve,
    WorkerCommand,
    WorkerReply,
    WorkerPhaseWait,
    WorkerReview,
    WorkerSourceOpen,
    WorkerRequest,
    WorkerReturn,
    WorkerDrain,
    InputValidation,
    OriginalSource,
    ReadConsent,
    EffectConsent,
    SourcePreparation,
    RetentionContexts,
    ContinuationBinding,
    ResultPreview,
    SignedRetentionApproval,
    IntakeSetupApproval,
    RetentionFreeze,
    ResultReceive,
    AuthenticatedIntake,
    ResultFinishAcknowledgement,
    UnionRetention,
    TransactionCheckpoint,
    CompletedVerification,
    DispatchReview,
    PairIntentRetention,
    RetainedPairRead,
    AdmissionFirst,
    AdmissionSecond,
    AdmissionReceiptRetention,
    DispatchReverification,
    BackendContext,
    SavedTransactionHandoff,
    DispatchOutcome,
    FinancialHistory,
    AuditSummary,
    StaleRefusal,
    Currentness,
    ResultInstalledProviderVerification,
    ResultHostPreparedWrite,
    ResultReadyWait,
    ResultFetchWrite,
    ResultHeldRead,
    ResultEvidenceValidation,
    ResultPreviewMatch,
    ResultCurrentProviderVerification,
    ResultCurrentWrite,
    ResultCurrentRead,
    ResultCurrentMatch,
    ResultFinishWrite,
    ResultFinishRead,
    ResultCurrentLock,
    ResultCurrentPeer,
    ResultReadyMatch,
    ResultHeldMatch,
    ResultFinishMatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinancialComponentV1 {
    Store,

    Journal,
    StorageSecurity,

    Signer,
    Wallet,
    Sync,
    DurableConstruction,
    WalletKeyUse,

    Authority,
    Host,
    Engine,
    SignerBridge,
    Chain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinancialCommitStateV1 {
    NotEstablished,
    IntakeCommitted,
    OutcomeUncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinancialErrorClassV1 {
    StoreDatabase,
    StoreEncoding,
    StorePoisoned,
    StoreIdempotencyConflict,
    StoreRevisionConflict,
    StoreNotFound,
    StoreAlreadyExists,
    StoreInvalidInput,
    StoreUnsupportedSchema,
    StoreRecoveryRequired,
    StoreWriterEpochMismatch,
    StoreLiveAuthorizationExists,
    StoreInputReserved,
    StoreResourceExhausted,
    StoreBudgetExceeded,
    StoreInvalidTransition,
    StoreFile,

    JournalStorage,
    JournalDatabase,
    JournalPermission,
    JournalExpired,
    JournalRecoveryRequired,
    JournalUnsupportedSchema,
    JournalOfflineHistoryUnsupported,
    JournalNamedRecipientHistoryUnsupported,
    JournalConstructionHistoryUnsupported,
    JournalInvalidBinding,
    JournalConflict,
    JournalNotFound,
    JournalLiveAuthorization,
    JournalInputReserved,
    JournalBudgetExceeded,
    JournalLimit,
    StorageUnsupportedPlatform,
    StorageQuarantinedDatabase,
    StorageRecoveredGeneration,
    StorageGenerationArchive,
    StorageUninitializedDatabase,
    StorageUnsafePath,
    StorageAlreadyExists,
    StorageMissingDatabase,
    StoragePlaintextRefused,
    StorageUnqualifiedRuntime,
    StorageAuthenticationFailed,
    StorageDatabase,
    StorageIo,
    StorageSnapshotLimit,
    StorageSourceChanged,

    Unavailable,
    PeerLifetimeUnavailable,
    Io,
    InvalidData,
    Crypto,
    BackupRequired,
    AlreadyOpen,
    ReviewMismatch,
    ConsentJournal,
    Store,
    Limit,
    CompleteOriginRecoveryUnavailable,
    AuthorityInvalidBinding,
    AuthorityPermission,
    AuthorityStaleHead,
    AuthorityConflict,
    AuthorityInactive,
    AuthorityRecoveryRequired,
    AuthorityExpired,
    AuthorityPolicyDenied,
    AuthorityBudgetExceeded,
    AuthorityInputReserved,
    AuthorityObligationReserved,
    AuthorityLimit,
    AuthorityStorage,
    AuthorityCorruptHistory,
    AuthorityPermanentStopUnavailable,
    AuthorityOfflineHistoryUnsupported,
    AuthorityConstructionHistoryUnsupported,
    AuthorityUnsupportedVersion,
    AuthorityAuthentication,
    AuthorityUncertain,
    AuthorityResolutionUnavailable,
    AuthoritySessionRequired,
    AuthoritySessionPending,
    WalletStorage,
    WalletAccountScope,
    WalletAccountMismatch,
    WalletIncompleteSync,
    WalletUnsupportedProfile,
    WalletChainMismatch,
    WalletInsufficientFunds,
    WalletInvalidRequest,
    WalletMissingWitness,
    WalletInvalidNote,
    WalletScan,
    WalletTransport,
    SyncAccessDenied,
    SyncInvalidRequest,
    SyncInterrupted,
    SyncReconciliationRequired,
    SyncInvalidResponse,
    SyncResourceLimit,
    SyncNoCurrentObservation,
    ChainInvalidConfiguration,
    ChainWrongNetwork,
    ChainUnsupportedProxyConfiguration,
    ChainWrongBranch,
    ChainStaleChain,
    ChainContradictoryChain,
    ChainTimeout,
    ChainTransportUnavailable,
    ChainObservationInterrupted,
    ChainMissingAncestryEvidence,
    ChainNotObserved,
    ChainResourceLimit,
    ChainMalformedEvidence,
    ChainUnsupportedCapability,
    ChainBackendFailure,
    ChainClockUnavailable,
    ChainIdempotencyConflict,
    ChainJournalFailure,
    ChainSubmissionNotAuthorized,
    ChainSubmissionExpiryMargin,
    ChainObligationConflict,
    ChainSubmissionOutcomeUnrecorded,
    ChainSubmissionRetentionUncertain,
    DurableInvalid,
    DurableBinding,
    DurableStale,
    DurableStorage,
    KeyUsePermission,
    KeyUsePolicy,
    KeyUseSelectionExpired,
    KeyUseStorage,
    KeyUseRecoveryRequired,
    KeyUseStateChanged,
    KeyUseExpiry,

    StaleHead,
    Inactive,
    PolicyDenied,
    BudgetExceeded,
    InputReserved,
    ObligationReserved,
    CorruptHistory,
    SessionRequired,
    SessionPending,
    Permission,
    Binding,
    Conflict,
    Missing,
    RecoveryRequired,
    Verification,
    Storage,
    ResourceLimit,
    Expired,
    Uncertain,
    Unsupported,
    Authentication,
    Terminal,
    Invalid,
    Locked,
    Ipc,
    Journal,
    Authority,
    Wallet,
    SignerOriginUnavailable,
    DurableProposalConflict,
    DurableProposalRecoveryRequired,
    SignaturesIncomplete,
    RetentionDenied,
    RetentionConflict,
    OriginalIntentMissing,
    RetentionRecoveryRequired,
    SubmissionUnresolved,
    FinancialOutcomeReconciliation,
    RevisionConflict,
    Timeout,
    Interrupted,
    TransportUnavailable,
    WrongNetwork,
    WrongBranch,
    StaleChain,
    ContradictoryChain,
    BackendFailure,
    ClockUnavailable,
    Other,
    FrameUnclassified,
    FrameDeadline,
    FrameEof,
    FrameCredentialsMissing,
    FrameCredentialsMismatch,
    FrameAncillaryRejected,
    FrameTruncated,
    FramePeerNotLive,
    FrameCurrentCheck,
    FrameIo,
    FrameLimit,
    FrameInvalid,
    FrameInvalidBudget,
}
fn bounded_timing_ms_v1<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u16, D::Error> {
    let value = u16::deserialize(deserializer)?;
    if value > 2001 {
        return Err(serde::de::Error::custom("timing bound"));
    }
    Ok(value)
}
fn bounded_optional_timing_ms_v1<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u16>, D::Error> {
    let value = Option::<u16>::deserialize(deserializer)?;
    if value.is_some_and(|value| value > 2001) {
        return Err(serde::de::Error::custom("timing bound"));
    }
    Ok(value)
}
/// Bounded elapsed invocation observations, not wire latency. 2001 means overrun.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinancialCurrentTimingV1 {
    #[serde(deserialize_with = "bounded_timing_ms_v1")]
    pub budget_ms: u16,
    #[serde(deserialize_with = "bounded_optional_timing_ms_v1")]
    pub provider_elapsed_ms: Option<u16>,
    #[serde(deserialize_with = "bounded_optional_timing_ms_v1")]
    pub remaining_before_write_ms: Option<u16>,
    #[serde(deserialize_with = "bounded_optional_timing_ms_v1")]
    pub remaining_before_read_ms: Option<u16>,
    #[serde(deserialize_with = "bounded_timing_ms_v1")]
    pub roundtrip_elapsed_ms: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinancialDiagnosticV1 {
    pub schema: u16,
    pub stage: FinancialStageV1,
    pub component: FinancialComponentV1,
    pub error_class: FinancialErrorClassV1,
    pub commit_state: FinancialCommitStateV1,
    pub current_timing: Option<FinancialCurrentTimingV1>,
    pub authority_call: Option<wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialAuthorityCallV1>,
}
impl FinancialDiagnosticV1 {
    pub(crate) fn is_valid_v1(&self) -> bool {
        self.schema == 1
            && self.authority_call.as_ref().map_or(true, |call| {
                self.current_timing.is_none()
                    && matches!(self.stage, FinancialStageV1::NativeAuthorityAdmit | FinancialStageV1::NativeAuthorityAcquire | FinancialStageV1::NativeAuthorityActivate | FinancialStageV1::NativeAuthorityVerifyActive)
                    && call.is_valid_v1()
            })
            && self.current_timing.map_or(true, |timing| {
                self.component == FinancialComponentV1::SignerBridge
                    && matches!(
                        self.stage,
                        FinancialStageV1::ResultCurrentLock
                            | FinancialStageV1::ResultCurrentPeer
                            | FinancialStageV1::ResultCurrentProviderVerification
                            | FinancialStageV1::ResultCurrentWrite
                            | FinancialStageV1::ResultCurrentRead
                            | FinancialStageV1::ResultCurrentMatch
                    )
                    && timing.budget_ms <= 2001
                    && timing
                        .provider_elapsed_ms
                        .map_or(true, |value| value <= 2001)
                    && timing
                        .remaining_before_write_ms
                        .map_or(true, |value| value <= 2001)
                    && timing
                        .remaining_before_read_ms
                        .map_or(true, |value| value <= 2001)
                    && timing.roundtrip_elapsed_ms <= 2001
            })
    }
}
static FAILURE: Mutex<Option<FinancialDiagnosticV1>> = Mutex::new(None);
pub(crate) fn reset_operation() {
    if let Ok(mut current) = CURRENT.lock() {
        *current = (
            FinancialStageV1::InputValidation,
            FinancialCommitStateV1::NotEstablished,
        );
    }

    if let Ok(mut slot) = FAILURE.lock() {
        *slot = None;
    }
}
pub(crate) fn capture_first(record: FinancialDiagnosticV1) {
    if !record.is_valid_v1() {
        return;
    }
    if let Ok(mut slot) = FAILURE.lock() {
        if slot.is_none() {
            *slot = Some(record);
        }
    }
}
pub(crate) fn take_operation_failure() -> Option<FinancialDiagnosticV1> {
    FAILURE.lock().ok()?.take()
}
pub(crate) fn emit(record: FinancialDiagnosticV1) {
    if record.is_valid_v1() {
        if let Ok(json) = serde_json::to_string(&record) {
            use std::io::Write;
            let _ = writeln!(std::io::stderr().lock(), "[FINANCIAL_DIAGNOSTIC_V1 {json}]");
        }
    }
}
fn record(
    stage: FinancialStageV1,
    commit_state: FinancialCommitStateV1,
    component: FinancialComponentV1,
    error_class: FinancialErrorClassV1,
) {
    capture_first(FinancialDiagnosticV1 {
        schema: 1,
        stage,
        component,
        error_class,
        commit_state,
        current_timing: None,
        authority_call: None,
    });
}
pub(crate) fn host(stage: FinancialStageV1, state: FinancialCommitStateV1, error: &crate::Error) {
    use crate::Error as E;
    use FinancialErrorClassV1 as C;
    let class = match error {
        E::Platform
        | E::Unsupported
        | E::RecoveryBackupUnsupported
        | E::RecoveryFinancialUnsupported
        | E::CompleteOriginRecoveryUnavailable => C::Unsupported,
        E::Terminal => C::Terminal,
        E::Permission => C::Permission,
        E::Locked => C::Locked,
        E::Invalid => C::Invalid,
        E::Authentication => C::Authentication,
        E::Storage => C::Storage,
        E::Quarantined | E::RecoverySemantic(_) => C::RecoveryRequired,
        E::HistoricalExportIncomplete | E::GenerationArchiveIncomplete => C::Uncertain,
        E::Receipt(_) => C::Other,
    };
    record(stage, state, FinancialComponentV1::Host, class);
}
pub(crate) fn engine(
    stage: FinancialStageV1,
    state: FinancialCommitStateV1,
    error: &wholepact_engine::ApiError,
) {
    use FinancialErrorClassV1 as C;
    let class = match error.code.as_str() {
        "DURABLE_PROPOSAL_CONFLICT" => C::DurableProposalConflict,
        "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => C::DurableProposalRecoveryRequired,
        "DURABLE_SIGNATURES_INCOMPLETE" => C::SignaturesIncomplete,
        "DURABLE_RETENTION_DENIED" => C::RetentionDenied,
        "DURABLE_RETENTION_CONFLICT" => C::RetentionConflict,
        "DURABLE_ORIGINAL_INTENT_MISSING" => C::OriginalIntentMissing,
        "DURABLE_RETENTION_RECOVERY_REQUIRED" => C::RetentionRecoveryRequired,
        "DURABLE_SUBMISSION_UNRESOLVED" => C::SubmissionUnresolved,
        "FINANCIAL_OUTCOME_REQUIRES_RECONCILIATION" => C::FinancialOutcomeReconciliation,
        "REVISION_CONFLICT" => C::RevisionConflict,
        "PERMISSION_DENIED"
        | "ACCESS_DENIED"
        | "PRIVATE_WORKSPACE_CONSENT_DENIED"
        | "DISCLOSURE_DENIED" => C::Permission,
        "RESOURCE_EXHAUSTED" => C::ResourceLimit,
        "RECOVERY_REQUIRED" => C::RecoveryRequired,
        "STORAGE_UNAVAILABLE" | "STORAGE_PROTECTION_REQUIRED" => C::Storage,
        "IDEMPOTENCY_CONFLICT" => C::Conflict,
        "NOT_FOUND" => C::Missing,
        "INVALID_REQUEST" | "INVALID_TRANSITION" => C::Invalid,
        _ => C::Other,
    };
    record(stage, state, FinancialComponentV1::Engine, class);
}
pub(crate) fn bridge(
    stage: FinancialStageV1,
    state: FinancialCommitStateV1,
    error: &wholepact_signer::authority_bridge::BridgeError,
) {
    use wholepact_signer::authority_bridge::BridgeError as E;
    use FinancialErrorClassV1 as C;
    let class = match error {
        E::Binding => C::Binding,
        E::Conflict => C::Conflict,
        E::Missing => C::Missing,
        E::Uncertain => C::Uncertain,
        E::Limit => C::ResourceLimit,
        E::Permission => C::Permission,
        E::RecoveryRequired | E::CompleteOriginRecoveryUnavailable => C::RecoveryRequired,
        E::Verification => C::Verification,
        E::SignerOriginUnavailable => C::SignerOriginUnavailable,
        E::Journal(_) => C::Journal,
        E::Authority(_) => C::Authority,
        E::Wallet(_) => C::Wallet,
        E::Ipc => C::Ipc,
    };
    record(stage, state, FinancialComponentV1::SignerBridge, class);
}
pub(crate) fn chain(
    stage: FinancialStageV1,
    state: FinancialCommitStateV1,
    error: &wholepact_chain::ChainError,
) {
    use wholepact_chain::ChainError as E;
    use FinancialErrorClassV1 as C;
    let class = match error {
        E::InvalidConfiguration => C::Invalid,
        E::WrongNetwork => C::WrongNetwork,
        E::UnsupportedProxyConfiguration | E::UnsupportedCapability => C::Unsupported,
        E::WrongBranch => C::WrongBranch,
        E::StaleChain => C::StaleChain,
        E::ContradictoryChain => C::ContradictoryChain,
        E::Timeout => C::Timeout,
        E::TransportUnavailable => C::TransportUnavailable,
        E::ObservationInterrupted => C::Interrupted,
        E::MissingAncestryEvidence | E::NotObserved => C::Missing,
        E::ResourceLimit => C::ResourceLimit,
        E::MalformedEvidence => C::Verification,
        E::BackendFailure { .. } => C::BackendFailure,
        E::ClockUnavailable => C::ClockUnavailable,
        E::IdempotencyConflict | E::ObligationConflict => C::Conflict,
        E::JournalFailure => C::Journal,
        E::SubmissionNotAuthorized => C::Permission,
        E::SubmissionExpiryMargin => C::Expired,
        E::SubmissionOutcomeUnrecorded | E::SubmissionRetentionUncertain => C::Uncertain,
    };
    record(stage, state, FinancialComponentV1::Chain, class);
}
static CURRENT: Mutex<(FinancialStageV1, FinancialCommitStateV1)> = Mutex::new((
    FinancialStageV1::InputValidation,
    FinancialCommitStateV1::NotEstablished,
));
pub(crate) fn set_stage(stage: FinancialStageV1, state: FinancialCommitStateV1) {
    if let Ok(mut current) = CURRENT.lock() {
        *current = (stage, state);
    }
}
pub(crate) fn host_current(error: &crate::Error) {
    if let Ok(current) = CURRENT.lock() {
        host(current.0, current.1, error);
    }
}

pub(crate) fn signer_result(
    detail:wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultDiagnosticV1,
    state: FinancialCommitStateV1,
) {
    use wholepact_signer::authority_bridge::financial_continuation_v1::{
        FinancialResultErrorClassV1 as E, FinancialResultStageV1 as S,
    };
    use FinancialErrorClassV1 as C;
    use FinancialStageV1 as T;
    let stage = match detail.stage {
        S::InstalledProviderVerification => T::ResultInstalledProviderVerification,
        S::HostPreparedWrite => T::ResultHostPreparedWrite,
        S::ReadyWait => T::ResultReadyWait,
        S::ReadyMatch => T::ResultReadyMatch,
        S::FetchWrite => T::ResultFetchWrite,
        S::HeldRead => T::ResultHeldRead,
        S::EvidenceValidation => T::ResultEvidenceValidation,
        S::PreviewMatch => T::ResultPreviewMatch,
        S::HeldMatch => T::ResultHeldMatch,
        S::CurrentLock => T::ResultCurrentLock,
        S::CurrentPeer => T::ResultCurrentPeer,
        S::CurrentProviderVerification => T::ResultCurrentProviderVerification,
        S::CurrentWrite => T::ResultCurrentWrite,
        S::CurrentRead => T::ResultCurrentRead,
        S::CurrentMatch => T::ResultCurrentMatch,
        S::FinishWrite => T::ResultFinishWrite,
        S::FinishRead => T::ResultFinishRead,
        S::FinishMatch => T::ResultFinishMatch,
    };
    let class = if let Some(cause) = detail.frame_cause {
        use wholepact_signer_origin::framing::FrameReadCause as F;
        match cause {
            F::Unclassified => C::FrameUnclassified,
            F::Deadline => C::FrameDeadline,
            F::Eof => C::FrameEof,
            F::CredentialsMissing => C::FrameCredentialsMissing,
            F::CredentialsMismatch => C::FrameCredentialsMismatch,
            F::AncillaryRejected => C::FrameAncillaryRejected,
            F::Truncated => C::FrameTruncated,
            F::PeerNotLive => C::FramePeerNotLive,
            F::CurrentCheck => C::FrameCurrentCheck,
            F::Io => C::FrameIo,
            F::FrameLimit => C::FrameLimit,
            F::InvalidFrame => C::FrameInvalid,
            F::InvalidBudget => C::FrameInvalidBudget,
        }
    } else {
        match detail.error_class {
            E::Binding => C::Binding,
            E::Conflict => C::Conflict,
            E::Missing => C::Missing,
            E::Uncertain => C::Uncertain,
            E::Limit => C::ResourceLimit,
            E::Permission => C::Permission,
            E::RecoveryRequired | E::CompleteOriginRecoveryUnavailable => C::RecoveryRequired,
            E::Verification => C::Verification,
            E::SignerOriginUnavailable => C::SignerOriginUnavailable,
            E::Journal => C::Journal,
            E::Authority => C::Authority,
            E::Wallet => C::Wallet,
            E::Ipc => C::Ipc,
        }
    };
    capture_first(FinancialDiagnosticV1 {
        schema: 1,
        stage,
        component: FinancialComponentV1::SignerBridge,
        error_class: class,
        commit_state: state,
        current_timing: detail
            .current_timing
            .map(|timing| FinancialCurrentTimingV1 {
                budget_ms: timing.budget_ms,
                provider_elapsed_ms: timing.provider_elapsed_ms,
                remaining_before_write_ms: timing.remaining_before_write_ms,
                remaining_before_read_ms: timing.remaining_before_read_ms,
                roundtrip_elapsed_ms: timing.roundtrip_elapsed_ms,
            }),
        authority_call: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_timing_is_bounded_and_only_valid_for_current_failure() {
        let timing = FinancialCurrentTimingV1 {
            budget_ms: 2000,
            provider_elapsed_ms: Some(2001),
            remaining_before_write_ms: Some(0),
            remaining_before_read_ms: None,
            roundtrip_elapsed_ms: 2001,
        };
        let mut record = FinancialDiagnosticV1 {
            schema: 1,
            stage: FinancialStageV1::ResultCurrentRead,
            component: FinancialComponentV1::SignerBridge,
            error_class: FinancialErrorClassV1::FrameDeadline,
            commit_state: FinancialCommitStateV1::OutcomeUncertain,
            current_timing: Some(timing),
            authority_call: None,
        };
        assert!(record.is_valid_v1());
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(
            serde_json::from_value::<FinancialDiagnosticV1>(value.clone()).unwrap(),
            record
        );
        for field in [
            "budget_ms",
            "provider_elapsed_ms",
            "remaining_before_write_ms",
            "remaining_before_read_ms",
            "roundtrip_elapsed_ms",
        ] {
            let mut invalid = value.clone();
            invalid["current_timing"][field] = serde_json::json!(2002);
            assert!(serde_json::from_value::<FinancialDiagnosticV1>(invalid).is_err());
        }
        let mut invalid = value;
        invalid["current_timing"]["private"] = serde_json::json!(1);
        assert!(serde_json::from_value::<FinancialDiagnosticV1>(invalid).is_err());
        record.stage = FinancialStageV1::ResultFinishRead;
        assert!(!record.is_valid_v1());
        record.current_timing = None;
        assert!(record.is_valid_v1());
    }
    #[test]
    fn operation_capture_discards_expected_refusal_and_preserves_first_inner_failure() {
        reset_operation();
        host(
            FinancialStageV1::AdmissionSecond,
            FinancialCommitStateV1::OutcomeUncertain,
            &crate::Error::Permission,
        );
        let expected = take_operation_failure().unwrap();
        assert_eq!(expected.stage, FinancialStageV1::AdmissionSecond);
        assert!(take_operation_failure().is_none());
        reset_operation();
        let inner = wholepact_engine::ApiError::new(
            "DURABLE_RETENTION_DENIED",
            "private detail never projected",
        );
        engine(
            FinancialStageV1::AuthenticatedIntake,
            FinancialCommitStateV1::OutcomeUncertain,
            &inner,
        );
        host(
            FinancialStageV1::AuditSummary,
            FinancialCommitStateV1::NotEstablished,
            &crate::Error::Receipt("private receipt".into()),
        );
        let actual = take_operation_failure().unwrap();
        assert_eq!(actual.stage, FinancialStageV1::AuthenticatedIntake);
        assert_eq!(actual.component, FinancialComponentV1::Engine);
        assert_eq!(actual.error_class, FinancialErrorClassV1::RetentionDenied);
        let value = serde_json::to_value(actual).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "schema",
                "stage",
                "component",
                "error_class",
                "commit_state",
                "current_timing"
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert!(!serde_json::to_string(&value).unwrap().contains("private"));
        let mut invalid = value.clone();
        invalid["unexpected"] = serde_json::json!("private");
        assert!(serde_json::from_value::<FinancialDiagnosticV1>(invalid).is_err());
        let mut invalid = value;
        invalid["stage"] = serde_json::json!("private arbitrary text");
        assert!(serde_json::from_value::<FinancialDiagnosticV1>(invalid).is_err());
        reset_operation();
    }
}

pub(crate) fn authority(stage: FinancialStageV1, state: FinancialCommitStateV1, error: &wholepact_authority::AuthorityError) {
    use wholepact_authority::AuthorityError as E;
    use FinancialErrorClassV1 as C;
    let class = match error {
        E::InvalidBinding => C::Binding,
        E::Permission => C::Permission,
        E::StaleHead => C::StaleHead,
        E::Conflict => C::Conflict,
        E::Inactive => C::Inactive,
        E::RecoveryRequired => C::RecoveryRequired,
        E::Expired => C::Expired,
        E::PolicyDenied => C::PolicyDenied,
        E::BudgetExceeded => C::BudgetExceeded,
        E::InputReserved => C::InputReserved,
        E::ObligationReserved => C::ObligationReserved,
        E::Limit => C::ResourceLimit,
        E::Storage => C::Storage,
        E::CorruptHistory => C::CorruptHistory,
        E::PermanentStopUnavailable
        | E::OfflineHistoryUnsupported
        | E::ConstructionHistoryUnsupported
        | E::UnsupportedVersion
        | E::ResolutionUnavailable => C::Unsupported,
        E::Authentication => C::Authentication,
        E::Uncertain => C::Uncertain,
        E::SessionRequired => C::SessionRequired,
        E::SessionPending => C::SessionPending,
    };
    record(stage, state, FinancialComponentV1::Authority, class);
}
pub(crate) fn authority_current(error: &wholepact_authority::AuthorityError) {
    if let Ok(current) = CURRENT.lock() {
        authority(current.0, current.1, error);
    }
}
pub(crate) fn engine_current(error: &wholepact_engine::ApiError) {
    if let Ok(current) = CURRENT.lock() {
        engine(current.0, current.1, error);
    }
}

#[cfg(test)]
mod native_join_tests {
    use super::*;
    #[test]
    fn exact_native_job_and_witness_cause_survive_outer_receipt() {
        use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
            FinancialNativeDiagnosticV1 as D, FinancialNativeStageV1 as S,
            FinancialNativeComponentV1 as P, FinancialNativeErrorClassV1 as E,
        };
        reset_operation();
        native_job(D { stage: S::AuthorityAcquire, component: P::Authority, error_class: E::AuthorityExpired, authority_call: None });
        host(FinancialStageV1::WorkerReply, FinancialCommitStateV1::OutcomeUncertain, &crate::Error::Receipt("inert outer label".into()));
        let detail = take_operation_failure().unwrap();
        assert_eq!(detail.stage, FinancialStageV1::NativeAuthorityAcquire);
        assert_eq!(detail.component, FinancialComponentV1::Authority);
        assert_eq!(detail.error_class, FinancialErrorClassV1::AuthorityExpired);
        assert!(detail.current_timing.is_none());
        reset_operation();
        authority(FinancialStageV1::WitnessCompletedPairService, FinancialCommitStateV1::OutcomeUncertain, &wholepact_authority::AuthorityError::Storage);
        host(FinancialStageV1::LifecycleHarness, FinancialCommitStateV1::NotEstablished, &crate::Error::Receipt("inert outer label".into()));
        let detail = take_operation_failure().unwrap();
        assert_eq!(detail.stage, FinancialStageV1::WitnessCompletedPairService);
        assert_eq!(detail.error_class, FinancialErrorClassV1::Storage);
        assert_eq!(detail.commit_state, FinancialCommitStateV1::OutcomeUncertain);
        reset_operation();
        assert!(take_operation_failure().is_none());
    }
}


pub(crate) fn native_job(detail: wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialNativeDiagnosticV1) {
    use wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialNativeStageV1 as S;
    let stage = match detail.stage {
        S::SourceOpen => FinancialStageV1::NativeSourceOpen,
        S::HistoryRead => FinancialStageV1::NativeHistoryRead,
        S::Continue => FinancialStageV1::NativeContinue,
        S::Admit => FinancialStageV1::NativeAdmit,
        S::Acquire => FinancialStageV1::NativeAcquire,
        S::Activate => FinancialStageV1::NativeActivate,
        S::WalletPrepare => FinancialStageV1::NativeWalletPrepare,
        S::WalletObserve => FinancialStageV1::NativeWalletObserve,
        S::SignPrepare => FinancialStageV1::NativeSignPrepare,
        S::Sign => FinancialStageV1::NativeSign,
        S::ReturnPrepare => FinancialStageV1::NativeReturnPrepare,
        S::HostPreparedWait => FinancialStageV1::NativeHostPreparedWait,
        S::ReturnApprove => FinancialStageV1::NativeReturnApprove,
        S::ReturnServe => FinancialStageV1::NativeReturnServe,
        S::ReviewStage => FinancialStageV1::NativeReviewStage,
        S::ResultRequest => FinancialStageV1::NativeResultRequest,
        S::AuthorityHistoryRead => FinancialStageV1::NativeAuthorityHistoryRead,
        S::FinancialHistoryRead => FinancialStageV1::NativeFinancialHistoryRead,
        S::AuthorityAdmit => FinancialStageV1::NativeAuthorityAdmit,
        S::AuthorityAcquire => FinancialStageV1::NativeAuthorityAcquire,
        S::AuthorityActivate => FinancialStageV1::NativeAuthorityActivate,
        S::AuthorityVerifyActive => FinancialStageV1::NativeAuthorityVerifyActive,
        S::WalletChain => FinancialStageV1::NativeWalletChain,
        S::WalletBirthday => FinancialStageV1::NativeWalletBirthday,
        S::WalletInitialize => FinancialStageV1::NativeWalletInitialize,
        S::WalletImport => FinancialStageV1::NativeWalletImport,
        S::WalletController => FinancialStageV1::NativeWalletController,
        S::WalletVerify => FinancialStageV1::NativeWalletVerify,
        S::WalletStatus => FinancialStageV1::NativeWalletStatus,
        S::WalletMaterial => FinancialStageV1::NativeWalletMaterial,
        S::WalletSynchronize => FinancialStageV1::NativeWalletSynchronize,
        S::WalletTicket => FinancialStageV1::NativeWalletTicket,
        S::WalletReconcile => FinancialStageV1::NativeWalletReconcile,
    };
    native_at(stage, FinancialCommitStateV1::OutcomeUncertain, detail);
}
fn native_at(stage: FinancialStageV1, state: FinancialCommitStateV1, detail: wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialNativeDiagnosticV1) {
    use wholepact_signer::native_ui::synthetic_born_joined_qualification::{FinancialNativeComponentV1 as P, FinancialNativeErrorClassV1 as E};
    let component = match detail.component {
        P::Store => FinancialComponentV1::Store,
        P::Signer => FinancialComponentV1::Signer,
        P::SignerBridge => FinancialComponentV1::SignerBridge,
        P::Authority => FinancialComponentV1::Authority,
        P::Wallet => FinancialComponentV1::Wallet,
        P::Sync => FinancialComponentV1::Sync,
        P::Chain => FinancialComponentV1::Chain,
        P::DurableConstruction => FinancialComponentV1::DurableConstruction,
        P::WalletKeyUse => FinancialComponentV1::WalletKeyUse,
        P::Journal => FinancialComponentV1::Journal,
        P::StorageSecurity => FinancialComponentV1::StorageSecurity,
    };
    let class = match detail.error_class {
        E::StoreDatabase => FinancialErrorClassV1::StoreDatabase,
        E::StoreEncoding => FinancialErrorClassV1::StoreEncoding,
        E::StorePoisoned => FinancialErrorClassV1::StorePoisoned,
        E::StoreIdempotencyConflict => FinancialErrorClassV1::StoreIdempotencyConflict,
        E::StoreRevisionConflict => FinancialErrorClassV1::StoreRevisionConflict,
        E::StoreNotFound => FinancialErrorClassV1::StoreNotFound,
        E::StoreAlreadyExists => FinancialErrorClassV1::StoreAlreadyExists,
        E::StoreInvalidInput => FinancialErrorClassV1::StoreInvalidInput,
        E::StoreUnsupportedSchema => FinancialErrorClassV1::StoreUnsupportedSchema,
        E::StoreRecoveryRequired => FinancialErrorClassV1::StoreRecoveryRequired,
        E::StoreWriterEpochMismatch => FinancialErrorClassV1::StoreWriterEpochMismatch,
        E::StoreLiveAuthorizationExists => FinancialErrorClassV1::StoreLiveAuthorizationExists,
        E::StoreInputReserved => FinancialErrorClassV1::StoreInputReserved,
        E::StoreResourceExhausted => FinancialErrorClassV1::StoreResourceExhausted,
        E::StoreBudgetExceeded => FinancialErrorClassV1::StoreBudgetExceeded,
        E::StoreInvalidTransition => FinancialErrorClassV1::StoreInvalidTransition,
        E::StoreFile => FinancialErrorClassV1::StoreFile,
        E::Unavailable => FinancialErrorClassV1::Unavailable,
        E::PeerLifetimeUnavailable => FinancialErrorClassV1::PeerLifetimeUnavailable,
        E::Io => FinancialErrorClassV1::Io,
        E::Authentication => FinancialErrorClassV1::Authentication,
        E::InvalidData => FinancialErrorClassV1::InvalidData,
        E::Crypto => FinancialErrorClassV1::Crypto,
        E::Locked => FinancialErrorClassV1::Locked,
        E::BackupRequired => FinancialErrorClassV1::BackupRequired,
        E::RecoveryRequired => FinancialErrorClassV1::RecoveryRequired,
        E::AlreadyOpen => FinancialErrorClassV1::AlreadyOpen,
        E::ReviewMismatch => FinancialErrorClassV1::ReviewMismatch,
        E::Verification => FinancialErrorClassV1::Verification,
        E::Uncertain => FinancialErrorClassV1::Uncertain,
        E::ConsentJournal => FinancialErrorClassV1::ConsentJournal,
        E::Store => FinancialErrorClassV1::Store,
        E::Binding => FinancialErrorClassV1::Binding,
        E::Conflict => FinancialErrorClassV1::Conflict,
        E::Missing => FinancialErrorClassV1::Missing,
        E::Limit => FinancialErrorClassV1::Limit,
        E::Permission => FinancialErrorClassV1::Permission,
        E::CompleteOriginRecoveryUnavailable => FinancialErrorClassV1::CompleteOriginRecoveryUnavailable,
        E::SignerOriginUnavailable => FinancialErrorClassV1::SignerOriginUnavailable,
        E::Journal => FinancialErrorClassV1::Journal,
        E::Authority => FinancialErrorClassV1::Authority,
        E::Wallet => FinancialErrorClassV1::Wallet,
        E::Ipc => FinancialErrorClassV1::Ipc,
        E::AuthorityInvalidBinding => FinancialErrorClassV1::AuthorityInvalidBinding,
        E::AuthorityPermission => FinancialErrorClassV1::AuthorityPermission,
        E::AuthorityStaleHead => FinancialErrorClassV1::AuthorityStaleHead,
        E::AuthorityConflict => FinancialErrorClassV1::AuthorityConflict,
        E::AuthorityInactive => FinancialErrorClassV1::AuthorityInactive,
        E::AuthorityRecoveryRequired => FinancialErrorClassV1::AuthorityRecoveryRequired,
        E::AuthorityExpired => FinancialErrorClassV1::AuthorityExpired,
        E::AuthorityPolicyDenied => FinancialErrorClassV1::AuthorityPolicyDenied,
        E::AuthorityBudgetExceeded => FinancialErrorClassV1::AuthorityBudgetExceeded,
        E::AuthorityInputReserved => FinancialErrorClassV1::AuthorityInputReserved,
        E::AuthorityObligationReserved => FinancialErrorClassV1::AuthorityObligationReserved,
        E::AuthorityLimit => FinancialErrorClassV1::AuthorityLimit,
        E::AuthorityStorage => FinancialErrorClassV1::AuthorityStorage,
        E::AuthorityCorruptHistory => FinancialErrorClassV1::AuthorityCorruptHistory,
        E::AuthorityPermanentStopUnavailable => FinancialErrorClassV1::AuthorityPermanentStopUnavailable,
        E::AuthorityOfflineHistoryUnsupported => FinancialErrorClassV1::AuthorityOfflineHistoryUnsupported,
        E::AuthorityConstructionHistoryUnsupported => FinancialErrorClassV1::AuthorityConstructionHistoryUnsupported,
        E::AuthorityUnsupportedVersion => FinancialErrorClassV1::AuthorityUnsupportedVersion,
        E::AuthorityAuthentication => FinancialErrorClassV1::AuthorityAuthentication,
        E::AuthorityUncertain => FinancialErrorClassV1::AuthorityUncertain,
        E::AuthorityResolutionUnavailable => FinancialErrorClassV1::AuthorityResolutionUnavailable,
        E::AuthoritySessionRequired => FinancialErrorClassV1::AuthoritySessionRequired,
        E::AuthoritySessionPending => FinancialErrorClassV1::AuthoritySessionPending,
        E::WalletStorage => FinancialErrorClassV1::WalletStorage,
        E::WalletAccountScope => FinancialErrorClassV1::WalletAccountScope,
        E::WalletAccountMismatch => FinancialErrorClassV1::WalletAccountMismatch,
        E::WalletIncompleteSync => FinancialErrorClassV1::WalletIncompleteSync,
        E::WalletUnsupportedProfile => FinancialErrorClassV1::WalletUnsupportedProfile,
        E::WalletChainMismatch => FinancialErrorClassV1::WalletChainMismatch,
        E::WalletInsufficientFunds => FinancialErrorClassV1::WalletInsufficientFunds,
        E::WalletInvalidRequest => FinancialErrorClassV1::WalletInvalidRequest,
        E::WalletMissingWitness => FinancialErrorClassV1::WalletMissingWitness,
        E::WalletInvalidNote => FinancialErrorClassV1::WalletInvalidNote,
        E::WalletScan => FinancialErrorClassV1::WalletScan,
        E::WalletTransport => FinancialErrorClassV1::WalletTransport,
        E::SyncAccessDenied => FinancialErrorClassV1::SyncAccessDenied,
        E::SyncInvalidRequest => FinancialErrorClassV1::SyncInvalidRequest,
        E::SyncInterrupted => FinancialErrorClassV1::SyncInterrupted,
        E::SyncReconciliationRequired => FinancialErrorClassV1::SyncReconciliationRequired,
        E::SyncInvalidResponse => FinancialErrorClassV1::SyncInvalidResponse,
        E::SyncResourceLimit => FinancialErrorClassV1::SyncResourceLimit,
        E::SyncNoCurrentObservation => FinancialErrorClassV1::SyncNoCurrentObservation,
        E::ChainInvalidConfiguration => FinancialErrorClassV1::ChainInvalidConfiguration,
        E::ChainWrongNetwork => FinancialErrorClassV1::ChainWrongNetwork,
        E::ChainUnsupportedProxyConfiguration => FinancialErrorClassV1::ChainUnsupportedProxyConfiguration,
        E::ChainWrongBranch => FinancialErrorClassV1::ChainWrongBranch,
        E::ChainStaleChain => FinancialErrorClassV1::ChainStaleChain,
        E::ChainContradictoryChain => FinancialErrorClassV1::ChainContradictoryChain,
        E::ChainTimeout => FinancialErrorClassV1::ChainTimeout,
        E::ChainTransportUnavailable => FinancialErrorClassV1::ChainTransportUnavailable,
        E::ChainObservationInterrupted => FinancialErrorClassV1::ChainObservationInterrupted,
        E::ChainMissingAncestryEvidence => FinancialErrorClassV1::ChainMissingAncestryEvidence,
        E::ChainNotObserved => FinancialErrorClassV1::ChainNotObserved,
        E::ChainResourceLimit => FinancialErrorClassV1::ChainResourceLimit,
        E::ChainMalformedEvidence => FinancialErrorClassV1::ChainMalformedEvidence,
        E::ChainUnsupportedCapability => FinancialErrorClassV1::ChainUnsupportedCapability,
        E::ChainBackendFailure => FinancialErrorClassV1::ChainBackendFailure,
        E::ChainClockUnavailable => FinancialErrorClassV1::ChainClockUnavailable,
        E::ChainIdempotencyConflict => FinancialErrorClassV1::ChainIdempotencyConflict,
        E::ChainJournalFailure => FinancialErrorClassV1::ChainJournalFailure,
        E::ChainSubmissionNotAuthorized => FinancialErrorClassV1::ChainSubmissionNotAuthorized,
        E::ChainSubmissionExpiryMargin => FinancialErrorClassV1::ChainSubmissionExpiryMargin,
        E::ChainObligationConflict => FinancialErrorClassV1::ChainObligationConflict,
        E::ChainSubmissionOutcomeUnrecorded => FinancialErrorClassV1::ChainSubmissionOutcomeUnrecorded,
        E::ChainSubmissionRetentionUncertain => FinancialErrorClassV1::ChainSubmissionRetentionUncertain,
        E::DurableInvalid => FinancialErrorClassV1::DurableInvalid,
        E::DurableBinding => FinancialErrorClassV1::DurableBinding,
        E::DurableStale => FinancialErrorClassV1::DurableStale,
        E::DurableStorage => FinancialErrorClassV1::DurableStorage,
        E::KeyUsePermission => FinancialErrorClassV1::KeyUsePermission,
        E::KeyUsePolicy => FinancialErrorClassV1::KeyUsePolicy,
        E::KeyUseSelectionExpired => FinancialErrorClassV1::KeyUseSelectionExpired,
        E::KeyUseStorage => FinancialErrorClassV1::KeyUseStorage,
        E::KeyUseRecoveryRequired => FinancialErrorClassV1::KeyUseRecoveryRequired,
        E::KeyUseStateChanged => FinancialErrorClassV1::KeyUseStateChanged,
        E::KeyUseExpiry => FinancialErrorClassV1::KeyUseExpiry,
        E::JournalStorage => FinancialErrorClassV1::JournalStorage,
        E::JournalDatabase => FinancialErrorClassV1::JournalDatabase,
        E::JournalPermission => FinancialErrorClassV1::JournalPermission,
        E::JournalExpired => FinancialErrorClassV1::JournalExpired,
        E::JournalRecoveryRequired => FinancialErrorClassV1::JournalRecoveryRequired,
        E::JournalUnsupportedSchema => FinancialErrorClassV1::JournalUnsupportedSchema,
        E::JournalOfflineHistoryUnsupported => FinancialErrorClassV1::JournalOfflineHistoryUnsupported,
        E::JournalNamedRecipientHistoryUnsupported => FinancialErrorClassV1::JournalNamedRecipientHistoryUnsupported,
        E::JournalConstructionHistoryUnsupported => FinancialErrorClassV1::JournalConstructionHistoryUnsupported,
        E::JournalInvalidBinding => FinancialErrorClassV1::JournalInvalidBinding,
        E::JournalConflict => FinancialErrorClassV1::JournalConflict,
        E::JournalNotFound => FinancialErrorClassV1::JournalNotFound,
        E::JournalLiveAuthorization => FinancialErrorClassV1::JournalLiveAuthorization,
        E::JournalInputReserved => FinancialErrorClassV1::JournalInputReserved,
        E::JournalBudgetExceeded => FinancialErrorClassV1::JournalBudgetExceeded,
        E::JournalLimit => FinancialErrorClassV1::JournalLimit,
        E::StorageUnsupportedPlatform => FinancialErrorClassV1::StorageUnsupportedPlatform,
        E::StorageQuarantinedDatabase => FinancialErrorClassV1::StorageQuarantinedDatabase,
        E::StorageRecoveredGeneration => FinancialErrorClassV1::StorageRecoveredGeneration,
        E::StorageGenerationArchive => FinancialErrorClassV1::StorageGenerationArchive,
        E::StorageUninitializedDatabase => FinancialErrorClassV1::StorageUninitializedDatabase,
        E::StorageUnsafePath => FinancialErrorClassV1::StorageUnsafePath,
        E::StorageAlreadyExists => FinancialErrorClassV1::StorageAlreadyExists,
        E::StorageMissingDatabase => FinancialErrorClassV1::StorageMissingDatabase,
        E::StoragePlaintextRefused => FinancialErrorClassV1::StoragePlaintextRefused,
        E::StorageUnqualifiedRuntime => FinancialErrorClassV1::StorageUnqualifiedRuntime,
        E::StorageAuthenticationFailed => FinancialErrorClassV1::StorageAuthenticationFailed,
        E::StorageDatabase => FinancialErrorClassV1::StorageDatabase,
        E::StorageIo => FinancialErrorClassV1::StorageIo,
        E::StorageSnapshotLimit => FinancialErrorClassV1::StorageSnapshotLimit,
        E::StorageSourceChanged => FinancialErrorClassV1::StorageSourceChanged,
    };
    capture_first(FinancialDiagnosticV1 {
        schema: 1, stage, component, error_class: class, commit_state: state,
        current_timing: None, authority_call: detail.authority_call,
    });
}
pub(crate) fn signer(stage: FinancialStageV1, state: FinancialCommitStateV1, error: &wholepact_signer::Error) {
    use wholepact_signer::native_ui::synthetic_born_joined_qualification::{classify_financial_native_failure_v1, FinancialNativeStageV1};
    if let Some(detail) = classify_financial_native_failure_v1(FinancialNativeStageV1::ReviewStage, error) {
        native_at(stage, state, detail);
    }
}

#[cfg(test)]
mod authority_call_tests {
    use super::*;
    #[test]
    fn authority_call_keeps_original_cause_and_rejects_unrelated_stage() {
        use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
            FinancialNativeDiagnosticV1 as D, FinancialNativeStageV1 as S,
            FinancialNativeComponentV1 as P, FinancialNativeErrorClassV1 as E,
        };
        let call = serde_json::from_value(serde_json::json!({
            "stage":"ExchangeDeadline", "check_site":"AfterResponseRead",
            "checkpoint":"AfterCallback", "selected_limit":"Exchange",
            "selected_budget_us":10000000, "caller_remaining_at_failure_us":100000000,
            "selected_remaining_at_failure_us":0, "exchange_elapsed_us":10000001,
            "exchange_cost":null, "clamped":false, "incomplete":false,
            "pre_budget_callback_calls":1, "pre_budget_callback_us":100
        })).unwrap();
        reset_operation();
        native_job(D {stage:S::AuthorityAdmit, component:P::Authority,
            error_class:E::AuthorityPermission, authority_call:Some(call)});
        let mut value=take_operation_failure().unwrap();
        assert_eq!(value.error_class,FinancialErrorClassV1::AuthorityPermission);
        assert_eq!(value.authority_call,Some(call));
        assert_eq!(value.commit_state,FinancialCommitStateV1::OutcomeUncertain);
        assert!(value.is_valid_v1());
        // Callback-first source errors retain their original component rather
        // than being rewritten as remote permission refusal.
        value.component=FinancialComponentV1::Journal;
        value.error_class=FinancialErrorClassV1::JournalInvalidBinding;
        assert!(value.is_valid_v1());
        value.stage=FinancialStageV1::ResultCurrentRead;
        assert!(!value.is_valid_v1());
        reset_operation();
    }
}
