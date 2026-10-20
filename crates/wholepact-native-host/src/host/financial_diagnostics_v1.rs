//! Qualification-only finite diagnostics. Never serialize error strings or data.
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinancialStageV1 {
    LifecycleHarness,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinancialDiagnosticV1 {
    pub schema: u16,
    pub stage: FinancialStageV1,
    pub component: FinancialComponentV1,
    pub error_class: FinancialErrorClassV1,
    pub commit_state: FinancialCommitStateV1,
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
    if record.schema != 1 {
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
    if record.schema == 1 {
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
    record(stage, state, FinancialComponentV1::SignerBridge, class);
}

#[cfg(test)]
mod tests {
    use super::*;
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
                "commit_state"
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

pub(crate) fn authority_current(error: &wholepact_authority::AuthorityError) {
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
    if let Ok(current) = CURRENT.lock() {
        record(current.0, current.1, FinancialComponentV1::Authority, class);
    }
}
pub(crate) fn engine_current(error: &wholepact_engine::ApiError) {
    if let Ok(current) = CURRENT.lock() {
        engine(current.0, current.1, error);
    }
}
