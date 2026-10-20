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
#[serde(deny_unknown_fields)]
pub struct FinancialNativeDiagnosticV1 {
    pub stage: FinancialNativeStageV1,
    pub component: FinancialNativeComponentV1,
    pub error_class: FinancialNativeErrorClassV1,
    pub authority_call: Option<FinancialAuthorityCallV1>,
}
struct Observer {
    identity: std::rc::Rc<()>,
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
                identity: std::rc::Rc::new(()),
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
                    authority_call: None,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialAuthorityStageV1 {
    CallerDeadline,
    ExchangeDeadline,
    SourceCallback,
    SnapshotConnect,
    SnapshotHandshake,
    SnapshotPeerBinding,
    SnapshotRequestBuild,
    SnapshotRequestWrite,
    SnapshotResponseRead,
    SnapshotResponse,
    SnapshotValidation,
    PageConnect,
    PageHandshake,
    PagePeerBinding,
    PageRequestBuild,
    PageRequestWrite,
    PageResponseRead,
    PageResponse,
    PageValidation,
    EventReplay,
    FinalValidation,
    Bounds,
    AdmissionRequestValidation,
    AdmissionBinding,
    AdmissionConnect,
    AdmissionHandshake,
    AdmissionPeerBinding,
    AdmissionRequestBuild,
    AdmissionRequestWrite,
    AdmissionResponseRead,
    AdmissionResponse,
    AdmissionSnapshotValidation,
    AdmissionCommittedHeadValidation,
    AdmissionFinalValidation,
    FlowRequestValidation,
    FlowBinding,
    FlowSession,
    FlowConnect,
    FlowHandshake,
    FlowPeerBinding,
    FlowRequestBuild,
    FlowRequestWrite,
    FlowResponseRead,
    FlowResponse,
    FlowSnapshotValidation,
    FlowReceiptValidation,
    FlowCommittedHeadValidation,
    FlowFinalValidation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialAuthorityCheckSiteV1 {
    ReplayInitial,
    ReplayAfterSnapshot,
    ReplayBeforePage,
    ReplayAfterPage,
    ReplayFinal,
    ExchangeInitial,
    BeforeConnect,
    AfterConnect,
    BeforeHandshakeIo,
    AfterHandshake,
    AfterPeerBinding,
    AfterRequestBuild,
    BeforeRequestWrite,
    AfterRequestWrite,
    AfterResponseRead,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialAuthorityCheckpointV1 {
    EntryDeadline,
    DeadlineSelection,
    ConnectRemaining,
    BeforeCallback,
    Callback,
    AfterCallback,
    Operation,
    Validation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinancialAuthoritySelectedLimitV1 {
    Caller,
    Exchange,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialAuthorityCostV1 {
    #[serde(deserialize_with = "bounded_count")]
    pub callback_calls: u32,
    #[serde(deserialize_with = "bounded_micros")]
    pub callback_us: u32,
    #[serde(deserialize_with = "bounded_micros")]
    pub callback_max_us: u32,
    #[serde(deserialize_with = "bounded_count")]
    pub connect_calls: u32,
    #[serde(deserialize_with = "bounded_micros")]
    pub connect_us: u32,
    #[serde(deserialize_with = "bounded_count")]
    pub handshake_calls: u32,
    #[serde(deserialize_with = "bounded_micros")]
    pub handshake_us: u32,
    #[serde(deserialize_with = "bounded_count")]
    pub frame_write_calls: u32,
    #[serde(deserialize_with = "bounded_micros")]
    pub frame_write_us: u32,
    #[serde(deserialize_with = "bounded_count")]
    pub frame_read_calls: u32,
    #[serde(deserialize_with = "bounded_micros")]
    pub frame_read_us: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialAuthorityCallV1 {
    pub stage: FinancialAuthorityStageV1,
    pub check_site: Option<FinancialAuthorityCheckSiteV1>,
    pub checkpoint: FinancialAuthorityCheckpointV1,
    pub selected_limit: Option<FinancialAuthoritySelectedLimitV1>,
    #[serde(deserialize_with = "bounded_optional_micros")]
    pub selected_budget_us: Option<u32>,
    #[serde(deserialize_with = "bounded_optional_micros")]
    pub caller_remaining_at_failure_us: Option<u32>,
    #[serde(deserialize_with = "bounded_optional_micros")]
    pub selected_remaining_at_failure_us: Option<u32>,
    #[serde(deserialize_with = "bounded_optional_micros")]
    pub exchange_elapsed_us: Option<u32>,
    pub exchange_cost: Option<FinancialAuthorityCostV1>,
    pub clamped: bool,
    pub incomplete: bool,
    #[serde(deserialize_with = "bounded_pre_budget_count")]
    pub pre_budget_callback_calls: u8,
    #[serde(deserialize_with = "bounded_micros")]
    pub pre_budget_callback_us: u32,
}
#[cfg(feature = "synthetic-qualification")]
impl From<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1>
    for FinancialAuthorityStageV1
{
    fn from(
        value: wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1,
    ) -> Self {
        use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1 as S;
        match value {
            S::CallerDeadline => Self::CallerDeadline,
            S::ExchangeDeadline => Self::ExchangeDeadline,
            S::SourceCallback => Self::SourceCallback,
            S::SnapshotConnect => Self::SnapshotConnect,
            S::SnapshotHandshake => Self::SnapshotHandshake,
            S::SnapshotPeerBinding => Self::SnapshotPeerBinding,
            S::SnapshotRequestBuild => Self::SnapshotRequestBuild,
            S::SnapshotRequestWrite => Self::SnapshotRequestWrite,
            S::SnapshotResponseRead => Self::SnapshotResponseRead,
            S::SnapshotResponse => Self::SnapshotResponse,
            S::SnapshotValidation => Self::SnapshotValidation,
            S::PageConnect => Self::PageConnect,
            S::PageHandshake => Self::PageHandshake,
            S::PagePeerBinding => Self::PagePeerBinding,
            S::PageRequestBuild => Self::PageRequestBuild,
            S::PageRequestWrite => Self::PageRequestWrite,
            S::PageResponseRead => Self::PageResponseRead,
            S::PageResponse => Self::PageResponse,
            S::PageValidation => Self::PageValidation,
            S::EventReplay => Self::EventReplay,
            S::FinalValidation => Self::FinalValidation,
            S::Bounds => Self::Bounds,
            S::AdmissionRequestValidation => Self::AdmissionRequestValidation,
            S::AdmissionBinding => Self::AdmissionBinding,
            S::AdmissionConnect => Self::AdmissionConnect,
            S::AdmissionHandshake => Self::AdmissionHandshake,
            S::AdmissionPeerBinding => Self::AdmissionPeerBinding,
            S::AdmissionRequestBuild => Self::AdmissionRequestBuild,
            S::AdmissionRequestWrite => Self::AdmissionRequestWrite,
            S::AdmissionResponseRead => Self::AdmissionResponseRead,
            S::AdmissionResponse => Self::AdmissionResponse,
            S::AdmissionSnapshotValidation => Self::AdmissionSnapshotValidation,
            S::AdmissionCommittedHeadValidation => Self::AdmissionCommittedHeadValidation,
            S::AdmissionFinalValidation => Self::AdmissionFinalValidation,
            S::FlowRequestValidation => Self::FlowRequestValidation,
            S::FlowBinding => Self::FlowBinding,
            S::FlowSession => Self::FlowSession,
            S::FlowConnect => Self::FlowConnect,
            S::FlowHandshake => Self::FlowHandshake,
            S::FlowPeerBinding => Self::FlowPeerBinding,
            S::FlowRequestBuild => Self::FlowRequestBuild,
            S::FlowRequestWrite => Self::FlowRequestWrite,
            S::FlowResponseRead => Self::FlowResponseRead,
            S::FlowResponse => Self::FlowResponse,
            S::FlowSnapshotValidation => Self::FlowSnapshotValidation,
            S::FlowReceiptValidation => Self::FlowReceiptValidation,
            S::FlowCommittedHeadValidation => Self::FlowCommittedHeadValidation,
            S::FlowFinalValidation => Self::FlowFinalValidation,
        }
    }
}
#[cfg(feature = "synthetic-qualification")]
impl From<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryCheckSiteV1>
    for FinancialAuthorityCheckSiteV1
{
    fn from(
        value: wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryCheckSiteV1,
    ) -> Self {
        use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryCheckSiteV1 as S;
        match value {
            S::ReplayInitial => Self::ReplayInitial,
            S::ReplayAfterSnapshot => Self::ReplayAfterSnapshot,
            S::ReplayBeforePage => Self::ReplayBeforePage,
            S::ReplayAfterPage => Self::ReplayAfterPage,
            S::ReplayFinal => Self::ReplayFinal,
            S::ExchangeInitial => Self::ExchangeInitial,
            S::BeforeConnect => Self::BeforeConnect,
            S::AfterConnect => Self::AfterConnect,
            S::BeforeHandshakeIo => Self::BeforeHandshakeIo,
            S::AfterHandshake => Self::AfterHandshake,
            S::AfterPeerBinding => Self::AfterPeerBinding,
            S::AfterRequestBuild => Self::AfterRequestBuild,
            S::BeforeRequestWrite => Self::BeforeRequestWrite,
            S::AfterRequestWrite => Self::AfterRequestWrite,
            S::AfterResponseRead => Self::AfterResponseRead,
        }
    }
}
#[cfg(feature = "synthetic-qualification")]
impl From<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryCheckpointV1>
    for FinancialAuthorityCheckpointV1
{
    fn from(
        value: wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryCheckpointV1,
    ) -> Self {
        use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryCheckpointV1 as S;
        match value {
            S::EntryDeadline => Self::EntryDeadline,
            S::DeadlineSelection => Self::DeadlineSelection,
            S::ConnectRemaining => Self::ConnectRemaining,
            S::BeforeCallback => Self::BeforeCallback,
            S::Callback => Self::Callback,
            S::AfterCallback => Self::AfterCallback,
            S::Operation => Self::Operation,
            S::Validation => Self::Validation,
        }
    }
}
#[cfg(feature = "synthetic-qualification")]
impl From<wholepact_authority::transport::history_diagnostics_v1::CheckedHistorySelectedLimitV1>
    for FinancialAuthoritySelectedLimitV1
{
    fn from(
        value: wholepact_authority::transport::history_diagnostics_v1::CheckedHistorySelectedLimitV1,
    ) -> Self {
        use wholepact_authority::transport::history_diagnostics_v1::CheckedHistorySelectedLimitV1 as S;
        match value {
            S::Caller => Self::Caller,
            S::Exchange => Self::Exchange,
        }
    }
}

impl FinancialAuthorityCallV1 {
    /// Observational bounds only. This is never authorization or a retry check.
    pub fn is_valid_v1(&self) -> bool {
        self.pre_budget_callback_calls <= 1
            && self
                .selected_budget_us
                .is_none_or(|value| value <= 600_000_000)
            && self
                .caller_remaining_at_failure_us
                .is_none_or(|value| value <= 600_000_000)
            && self
                .selected_remaining_at_failure_us
                .is_none_or(|value| value <= 600_000_000)
            && self
                .exchange_elapsed_us
                .is_none_or(|value| value <= 600_000_000)
            && self.pre_budget_callback_us <= 600_000_000
            && self.exchange_cost.as_ref().is_none_or(|cost| {
                cost.callback_calls <= 1_000_000
                    && cost.callback_us <= 600_000_000
                    && cost.callback_max_us <= 600_000_000
                    && cost.connect_calls <= 1_000_000
                    && cost.connect_us <= 600_000_000
                    && cost.handshake_calls <= 1_000_000
                    && cost.handshake_us <= 600_000_000
                    && cost.frame_write_calls <= 1_000_000
                    && cost.frame_write_us <= 600_000_000
                    && cost.frame_read_calls <= 1_000_000
                    && cost.frame_read_us <= 600_000_000
            })
    }
}

fn bounded_micros<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = <u32 as serde::Deserialize>::deserialize(deserializer)?;
    if value > 600_000_000 {
        return Err(serde::de::Error::custom("diagnostic micros out of bounds"));
    }
    Ok(value)
}
fn bounded_count<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = <u32 as serde::Deserialize>::deserialize(deserializer)?;
    if value > 1_000_000 {
        return Err(serde::de::Error::custom("diagnostic count out of bounds"));
    }
    Ok(value)
}
fn bounded_optional_micros<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u32>, D::Error> {
    let value = <Option<u32> as serde::Deserialize>::deserialize(deserializer)?;
    if value.is_some_and(|value| value > 600_000_000) {
        return Err(serde::de::Error::custom("diagnostic micros out of bounds"));
    }
    Ok(value)
}
/// Only a call entered before any failure may attach its own transport snapshot.
#[cfg(feature = "synthetic-qualification")]
pub(in crate::native_ui) struct CheckedAuthorityObservation {
    entered: Option<(std::rc::Rc<()>, FinancialNativeStageV1)>,
}
#[cfg(feature = "synthetic-qualification")]
pub(in crate::native_ui) fn begin_checked_authority() -> CheckedAuthorityObservation {
    CheckedAuthorityObservation {
        entered: ACTIVE.with(|slot| {
            slot.borrow()
                .as_ref()
                .filter(|o| o.failure.is_none())
                .map(|o| (std::rc::Rc::clone(&o.identity), o.stage))
        }),
    }
}

/// Preserve bounded original evidence, never permission or a retry signal.
#[cfg(feature = "synthetic-qualification")]
pub(in crate::native_ui) fn checked_authority(
    failure: wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1,
    observation: CheckedAuthorityObservation,
) -> wholepact_authority::AuthorityError {
    let measurement = failure.measurement();
    let call = FinancialAuthorityCallV1 {
        stage: failure.stage().into(),
        check_site: measurement.check_site().map(Into::into),
        checkpoint: measurement.checkpoint().into(),
        selected_limit: measurement.selected_limit().map(Into::into),
        selected_budget_us: measurement.selected_budget_us(),
        caller_remaining_at_failure_us: measurement.caller_remaining_at_failure_us(),
        selected_remaining_at_failure_us: measurement.selected_remaining_at_failure_us(),
        exchange_elapsed_us: measurement.exchange_elapsed_us(),
        exchange_cost: measurement
            .exchange_cost()
            .map(|cost| FinancialAuthorityCostV1 {
                callback_calls: cost.callback_calls(),
                callback_us: cost.callback_us(),
                callback_max_us: cost.callback_max_us(),
                connect_calls: cost.connect_calls(),
                connect_us: cost.connect_us(),
                handshake_calls: cost.handshake_calls(),
                handshake_us: cost.handshake_us(),
                frame_write_calls: cost.frame_write_calls(),
                frame_write_us: cost.frame_write_us(),
                frame_read_calls: cost.frame_read_calls(),
                frame_read_us: cost.frame_read_us(),
            }),
        clamped: measurement.clamped(),
        incomplete: measurement.incomplete(),
        pre_budget_callback_calls: measurement.pre_budget_callback_calls(),
        pre_budget_callback_us: measurement.pre_budget_callback_us(),
    };
    // Keep the outer operation and any earlier callback's precise Signer cause.
    authority(&failure.error());
    attach_checked_authority(observation, call);
    // into_error() is the observed cause, not necessarily the kernel return.
    // Any failure after dispatch may already be committed. Never retry here.
    failure.returned_error()
}

#[cfg(feature = "synthetic-qualification")]
fn attach_checked_authority(
    observation: CheckedAuthorityObservation,
    call: FinancialAuthorityCallV1,
) {
    ACTIVE.with(|slot| {
        if let (Some(observer), Some((identity, stage))) =
            (slot.borrow_mut().as_mut(), observation.entered)
        {
            if std::rc::Rc::ptr_eq(&identity, &observer.identity) {
                if let Some(diagnostic) = observer.failure.as_mut() {
                    if stage == diagnostic.stage && diagnostic.authority_call.is_none() {
                        diagnostic.authority_call = Some(call);
                    }
                }
            }
        }
    });
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

fn bounded_pre_budget_count<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u8, D::Error> {
    let value = <u8 as serde::Deserialize>::deserialize(deserializer)?;
    if value > 1 {
        return Err(serde::de::Error::custom(
            "diagnostic pre-budget count out of bounds",
        ));
    }
    Ok(value)
}
