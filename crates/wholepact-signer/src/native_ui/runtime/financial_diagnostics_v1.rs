//! Inert, thread-local diagnostic custody. Never an authority or retry signal.
use crate::Error;
use std::cell::RefCell;
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialNativeStageV1 {
    SourceOpen,
    HistoryRead,
    Continue,
    Admit,
    Acquire,
    Activate,
    WalletPrepare,
    WalletObserve,
    SignPrepare,
    Sign,
    ReturnPrepare,
    HostPreparedWait,
    ReturnApprove,
    ReturnServe,
    ReviewStage,
    ResultRequest,
    AuthorityHistoryRead,
    FinancialHistoryRead,
    AuthorityAdmit,
    AuthorityAcquire,
    AuthorityActivate,
    AuthorityVerifyActive,
    WalletChain,
    WalletBirthday,
    WalletInitialize,
    WalletImport,
    WalletController,
    WalletVerify,
    WalletStatus,
    WalletMaterial,
    WalletSynchronize,
    WalletTicket,
    WalletReconcile,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialNativeComponentV1 {
    Store,
    Signer,
    SignerBridge,
    Authority,
    Wallet,
    Sync,
    Chain,
    DurableConstruction,
    WalletKeyUse,
    Journal,
    StorageSecurity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialNativeErrorClassV1 {
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

    Unavailable,
    PeerLifetimeUnavailable,
    Io,
    Authentication,
    InvalidData,
    Crypto,
    Locked,
    BackupRequired,
    RecoveryRequired,
    AlreadyOpen,
    ReviewMismatch,
    Verification,
    Uncertain,
    ConsentJournal,
    Store,
    Binding,
    Conflict,
    Missing,
    Limit,
    Permission,
    CompleteOriginRecoveryUnavailable,
    SignerOriginUnavailable,
    Journal,
    Authority,
    Wallet,
    Ipc,
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FinancialNativeDiagnosticV1 {
    pub stage: FinancialNativeStageV1,
    pub component: FinancialNativeComponentV1,
    pub error_class: FinancialNativeErrorClassV1,
}
struct Observer {
    stage: FinancialNativeStageV1,
    failure: Option<FinancialNativeDiagnosticV1>,
}
thread_local! { static ACTIVE: RefCell<Option<Observer>> = const { RefCell::new(None) }; }
pub(in crate::native_ui) struct Scope {
    previous: Option<Observer>,
}
impl Scope {
    pub(in crate::native_ui) fn begin(stage: FinancialNativeStageV1) -> Self {
        let previous = ACTIVE.with(|slot| {
            slot.replace(Some(Observer {
                stage,
                failure: None,
            }))
        });
        Self { previous }
    }
    pub(in crate::native_ui) fn failure(&self) -> Option<FinancialNativeDiagnosticV1> {
        ACTIVE.with(|slot| slot.borrow().as_ref().and_then(|o| o.failure))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|slot| *slot.borrow_mut() = self.previous.take());
    }
}
pub(in crate::native_ui) fn at(stage: FinancialNativeStageV1) {
    ACTIVE.with(|slot| {
        if let Some(o) = slot.borrow_mut().as_mut() {
            o.stage = stage;
        }
    });
}
pub(in crate::native_ui) fn capture(
    component: FinancialNativeComponentV1,
    error_class: FinancialNativeErrorClassV1,
) {
    ACTIVE.with(|slot| {
        if let Some(o) = slot.borrow_mut().as_mut() {
            if o.failure.is_none() {
                o.failure = Some(FinancialNativeDiagnosticV1 {
                    stage: o.stage,
                    component,
                    error_class,
                });
            }
        }
    });
}
pub(in crate::native_ui) fn signer(error: &Error) {
    use FinancialNativeErrorClassV1 as C;
    capture(
        FinancialNativeComponentV1::Signer,
        match error {
            Error::Unavailable => C::Unavailable,
            Error::PeerLifetimeUnavailable => C::PeerLifetimeUnavailable,
            Error::Io(_) => C::Io,
            Error::Authentication => C::Authentication,
            Error::InvalidData => C::InvalidData,
            Error::Crypto => C::Crypto,
            Error::Locked => C::Locked,
            Error::BackupRequired => C::BackupRequired,
            Error::RecoveryRequired => C::RecoveryRequired,
            Error::AlreadyOpen => C::AlreadyOpen,
            Error::ReviewMismatch => C::ReviewMismatch,
            Error::Verification => C::Verification,
            Error::Uncertain => C::Uncertain,
            Error::ConsentJournal(error) => return journal(error),
            Error::Store(error) => return store_error(error),
        },
    );
}
pub(in crate::native_ui) fn bridge(error: &crate::authority_bridge::BridgeError) {
    use crate::authority_bridge::BridgeError as E;
    use FinancialNativeErrorClassV1 as C;
    capture(
        FinancialNativeComponentV1::SignerBridge,
        match error {
            E::Binding => C::Binding,
            E::Conflict => C::Conflict,
            E::Missing => C::Missing,
            E::Uncertain => C::Uncertain,
            E::Limit => C::Limit,
            E::Permission => C::Permission,
            E::RecoveryRequired => C::RecoveryRequired,
            E::CompleteOriginRecoveryUnavailable => C::CompleteOriginRecoveryUnavailable,
            E::Verification => C::Verification,
            E::SignerOriginUnavailable => C::SignerOriginUnavailable,
            E::Journal(error) => return journal(error),
            E::Authority(error) => return authority(error),
            E::Wallet(error) => return wallet_key_use(error),
            E::Ipc => C::Ipc,
        },
    );
}

pub(in crate::native_ui) fn authority(error: &wholepact_authority::AuthorityError) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_authority::AuthorityError as E;
    capture(
        FinancialNativeComponentV1::Authority,
        match error {
            E::InvalidBinding => C::AuthorityInvalidBinding,
            E::Permission => C::AuthorityPermission,
            E::StaleHead => C::AuthorityStaleHead,
            E::Conflict => C::AuthorityConflict,
            E::Inactive => C::AuthorityInactive,
            E::RecoveryRequired => C::AuthorityRecoveryRequired,
            E::Expired => C::AuthorityExpired,
            E::PolicyDenied => C::AuthorityPolicyDenied,
            E::BudgetExceeded => C::AuthorityBudgetExceeded,
            E::InputReserved => C::AuthorityInputReserved,
            E::ObligationReserved => C::AuthorityObligationReserved,
            E::Limit => C::AuthorityLimit,
            E::Storage => C::AuthorityStorage,
            E::CorruptHistory => C::AuthorityCorruptHistory,
            E::PermanentStopUnavailable => C::AuthorityPermanentStopUnavailable,
            E::OfflineHistoryUnsupported => C::AuthorityOfflineHistoryUnsupported,
            E::ConstructionHistoryUnsupported => C::AuthorityConstructionHistoryUnsupported,
            E::UnsupportedVersion => C::AuthorityUnsupportedVersion,
            E::Authentication => C::AuthorityAuthentication,
            E::Uncertain => C::AuthorityUncertain,
            E::ResolutionUnavailable => C::AuthorityResolutionUnavailable,
            E::SessionRequired => C::AuthoritySessionRequired,
            E::SessionPending => C::AuthoritySessionPending,
        },
    );
}

pub(in crate::native_ui) fn wallet(error: &wholepact_wallet::wallet::WalletError) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_wallet::wallet::WalletError as E;
    capture(
        FinancialNativeComponentV1::Wallet,
        match error {
            E::Storage => C::WalletStorage,
            E::AccountScope => C::WalletAccountScope,
            E::AccountMismatch => C::WalletAccountMismatch,
            E::IncompleteSync => C::WalletIncompleteSync,
            E::UnsupportedProfile => C::WalletUnsupportedProfile,
            E::ChainMismatch => C::WalletChainMismatch,
            E::InsufficientFunds => C::WalletInsufficientFunds,
            E::InvalidRequest => C::WalletInvalidRequest,
            E::MissingWitness => C::WalletMissingWitness,
            E::InvalidNote => C::WalletInvalidNote,
            E::Scan => C::WalletScan,
            E::Transport => C::WalletTransport,
        },
    );
}

pub(in crate::native_ui) fn sync(error: &wholepact_wallet::wallet::protected_sync::SyncError) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_wallet::wallet::protected_sync::SyncError as E;
    capture(
        FinancialNativeComponentV1::Sync,
        match error {
            E::AccessDenied => C::SyncAccessDenied,
            E::InvalidRequest => C::SyncInvalidRequest,
            E::Interrupted => C::SyncInterrupted,
            E::ReconciliationRequired => C::SyncReconciliationRequired,
            E::InvalidResponse => C::SyncInvalidResponse,
            E::ResourceLimit => C::SyncResourceLimit,
            E::NoCurrentObservation => C::SyncNoCurrentObservation,
            E::Wallet(error) => return wallet(error),
            E::Chain(error) => return chain(error),
        },
    );
}

pub(in crate::native_ui) fn chain(error: &wholepact_chain::ChainError) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_chain::ChainError as E;
    capture(
        FinancialNativeComponentV1::Chain,
        match error {
            E::InvalidConfiguration => C::ChainInvalidConfiguration,
            E::WrongNetwork => C::ChainWrongNetwork,
            E::UnsupportedProxyConfiguration => C::ChainUnsupportedProxyConfiguration,
            E::WrongBranch => C::ChainWrongBranch,
            E::StaleChain => C::ChainStaleChain,
            E::ContradictoryChain => C::ChainContradictoryChain,
            E::Timeout => C::ChainTimeout,
            E::TransportUnavailable => C::ChainTransportUnavailable,
            E::ObservationInterrupted => C::ChainObservationInterrupted,
            E::MissingAncestryEvidence => C::ChainMissingAncestryEvidence,
            E::NotObserved => C::ChainNotObserved,
            E::ResourceLimit => C::ChainResourceLimit,
            E::MalformedEvidence => C::ChainMalformedEvidence,
            E::UnsupportedCapability => C::ChainUnsupportedCapability,
            E::BackendFailure { .. } => C::ChainBackendFailure,
            E::ClockUnavailable => C::ChainClockUnavailable,
            E::IdempotencyConflict => C::ChainIdempotencyConflict,
            E::JournalFailure => C::ChainJournalFailure,
            E::SubmissionNotAuthorized => C::ChainSubmissionNotAuthorized,
            E::SubmissionExpiryMargin => C::ChainSubmissionExpiryMargin,
            E::ObligationConflict => C::ChainObligationConflict,
            E::SubmissionOutcomeUnrecorded => C::ChainSubmissionOutcomeUnrecorded,
            E::SubmissionRetentionUncertain => C::ChainSubmissionRetentionUncertain,
        },
    );
}

pub(in crate::native_ui) fn durable(
    error:&wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError,
) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError as E;
    capture(
        FinancialNativeComponentV1::DurableConstruction,
        match error {
            E::Invalid => C::DurableInvalid,
            E::Binding => C::DurableBinding,
            E::Stale => C::DurableStale,
            E::Storage => C::DurableStorage,
            E::Sync(error) => return sync(error),
        },
    );
}

pub(in crate::native_ui) fn wallet_key_use(
    error: &wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError,
) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError as E;
    capture(
        FinancialNativeComponentV1::WalletKeyUse,
        match error {
            E::Permission => C::KeyUsePermission,
            E::Policy => C::KeyUsePolicy,
            E::SelectionExpired => C::KeyUseSelectionExpired,
            E::Storage => C::KeyUseStorage,
            E::RecoveryRequired => C::KeyUseRecoveryRequired,
            E::StateChanged => C::KeyUseStateChanged,
            E::Expiry => C::KeyUseExpiry,
            E::Sync(error) => return sync(error),
        },
    );
}

pub(in crate::native_ui) fn journal(error: &crate::consent_journal::JournalError) {
    use crate::consent_journal::JournalError as E;
    use FinancialNativeErrorClassV1 as C;
    capture(
        FinancialNativeComponentV1::Journal,
        match error {
            E::Storage(error) => return storage(error),
            E::Database => C::JournalDatabase,
            E::Permission => C::JournalPermission,
            E::Expired => C::JournalExpired,
            E::RecoveryRequired => C::JournalRecoveryRequired,
            E::UnsupportedSchema => C::JournalUnsupportedSchema,
            E::OfflineHistoryUnsupported => C::JournalOfflineHistoryUnsupported,
            E::NamedRecipientHistoryUnsupported => C::JournalNamedRecipientHistoryUnsupported,
            E::ConstructionHistoryUnsupported => C::JournalConstructionHistoryUnsupported,
            E::InvalidBinding => C::JournalInvalidBinding,
            E::Conflict => C::JournalConflict,
            E::NotFound => C::JournalNotFound,
            E::LiveAuthorization => C::JournalLiveAuthorization,
            E::InputReserved => C::JournalInputReserved,
            E::BudgetExceeded => C::JournalBudgetExceeded,
            E::Limit => C::JournalLimit,
        },
    );
}

pub(in crate::native_ui) fn storage(error: &wholepact_storage_security::StorageSecurityError) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_storage_security::StorageSecurityError as E;
    capture(
        FinancialNativeComponentV1::StorageSecurity,
        match error {
            E::UnsupportedPlatform => C::StorageUnsupportedPlatform,
            E::QuarantinedDatabase => C::StorageQuarantinedDatabase,
            E::RecoveredGeneration => C::StorageRecoveredGeneration,
            E::GenerationArchive => C::StorageGenerationArchive,
            E::UninitializedDatabase => C::StorageUninitializedDatabase,
            E::UnsafePath => C::StorageUnsafePath,
            E::AlreadyExists => C::StorageAlreadyExists,
            E::MissingDatabase => C::StorageMissingDatabase,
            E::PlaintextRefused => C::StoragePlaintextRefused,
            E::UnqualifiedRuntime => C::StorageUnqualifiedRuntime,
            E::AuthenticationFailed => C::StorageAuthenticationFailed,
            E::Database => C::StorageDatabase,
            E::Io => C::StorageIo,
            E::SnapshotLimit => C::StorageSnapshotLimit,
            E::SourceChanged => C::StorageSourceChanged,
        },
    );
}

#[cfg(test)]
#[path = "financial_diagnostics_tests_v1.rs"]
mod tests;

pub(in crate::native_ui) fn store_error(error: &wholepact_store::StoreError) {
    use FinancialNativeErrorClassV1 as C;
    use wholepact_store::StoreError as E;
    capture(
        FinancialNativeComponentV1::Store,
        match error {
            E::StorageSecurity(error) => return storage(error),
            E::Database(_) => C::StoreDatabase,
            E::Encoding(_) => C::StoreEncoding,
            E::Poisoned => C::StorePoisoned,
            E::IdempotencyConflict => C::StoreIdempotencyConflict,
            E::RevisionConflict => C::StoreRevisionConflict,
            E::NotFound => C::StoreNotFound,
            E::AlreadyExists => C::StoreAlreadyExists,
            E::InvalidInput(_) => C::StoreInvalidInput,
            E::UnsupportedSchema(_) => C::StoreUnsupportedSchema,
            E::RecoveryRequired => C::StoreRecoveryRequired,
            E::WriterEpochMismatch => C::StoreWriterEpochMismatch,
            E::LiveAuthorizationExists => C::StoreLiveAuthorizationExists,
            E::InputReserved => C::StoreInputReserved,
            E::ResourceExhausted => C::StoreResourceExhausted,
            E::BudgetExceeded => C::StoreBudgetExceeded,
            E::InvalidTransition => C::StoreInvalidTransition,
            E::File(_) => C::StoreFile,
        },
    );
}
