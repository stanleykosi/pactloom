//! Synthetic-only, bounded observations. No authority, source, account, key,
//! journal, listener or native decision is owned here. CALL outcomes never claim
//! SQL commit or rollback. No diagnostic lock is held across operational work.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use wholepact_authority::transport::history_diagnostics_v1::{
    CheckedHistoryFailureV1, CheckedHistoryIoKindV1, CheckedHistoryMeasurementV1,
    CheckedHistoryPhaseV1, CheckedHistoryStageV1,
};

macro_rules! scalars {
    ($($name:ident: $ty:ty),* $(,)?) => { $(pub fn $name(&self) -> $ty { self.$name })* };
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowOperationV1 {
    WriterReconcile,
    FinancialImport,
    InitialSign,
    RetainedRetry,
    ResultService,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowStageV1 {
    FixtureState,
    AcquirePrepare,
    AcquireNative,
    AcquireCall,
    ActivationPrepare,
    ActivationNative,
    ActivationCall,
    ActiveVerification,
    ReconcilePrepare,
    ReconcileNative,
    ReconcileCall,
    Invalidate,
    ImportReceive,
    ImportPairing,
    ImportSource,
    WalletSync,
    WalletSource,
    WitnessHead,
    SpendStage,
    DisclosureDecision,
    SpendDecision,
    SigningLaunch,
    AuthorizationSource,
    Release,
    RequestRetain,
    Reserve,
    PermitRetain,
    WalletGuard,
    KeyUse,
    Derive,
    Sign,
    VerifySigned,
    ResultRetain,
    RetainedLookup,
    RetryInvariant,
    Completion,
    ResultService,
    Close,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowErrorDomainV1 {
    Signer,
    Bridge,
    Authority,
    Journal,
    WalletKeyUse,
    Store,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowErrorCodeV1 {
    SignerUnavailable,
    SignerPeerLifetimeUnavailable,
    SignerIo,
    SignerAuthentication,
    SignerInvalidData,
    SignerCrypto,
    SignerLocked,
    SignerBackupRequired,
    SignerRecoveryRequired,
    SignerAlreadyOpen,
    SignerReviewMismatch,
    SignerVerification,
    SignerUncertain,
    SignerConsentJournal,
    SignerStore,
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
    WalletKeyUsePermission,
    WalletKeyUsePolicy,
    WalletKeyUseSelectionExpired,
    WalletKeyUseStorage,
    WalletKeyUseRecoveryRequired,
    WalletKeyUseStateChanged,
    WalletKeyUseExpiry,
    WalletKeyUseSync,
    StoreStorageSecurity,
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowNestedCodeV1 {
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
    StoreStorageSecurity,
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
    WalletKeyUsePermission,
    WalletKeyUsePolicy,
    WalletKeyUseSelectionExpired,
    WalletKeyUseStorage,
    WalletKeyUseRecoveryRequired,
    WalletKeyUseStateChanged,
    WalletKeyUseExpiry,
    WalletKeyUseSync,
    StorageSecurityUnsupportedPlatform,
    StorageSecurityQuarantinedDatabase,
    StorageSecurityRecoveredGeneration,
    StorageSecurityGenerationArchive,
    StorageSecurityUninitializedDatabase,
    StorageSecurityUnsafePath,
    StorageSecurityAlreadyExists,
    StorageSecurityMissingDatabase,
    StorageSecurityPlaintextRefused,
    StorageSecurityUnqualifiedRuntime,
    StorageSecurityAuthenticationFailed,
    StorageSecurityDatabase,
    StorageSecurityIo,
    StorageSecuritySnapshotLimit,
    StorageSecuritySourceChanged,
    SyncAccessDenied,
    SyncInvalidRequest,
    SyncInterrupted,
    SyncReconciliationRequired,
    SyncInvalidResponse,
    SyncResourceLimit,
    SyncNoCurrentObservation,
    SyncWallet,
    SyncChain,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowAuthorityCodeV1 {
    InvalidBinding,
    Permission,
    StaleHead,
    Conflict,
    Inactive,
    RecoveryRequired,
    Expired,
    PolicyDenied,
    BudgetExceeded,
    InputReserved,
    ObligationReserved,
    Limit,
    Storage,
    CorruptHistory,
    PermanentStopUnavailable,
    OfflineHistoryUnsupported,
    ConstructionHistoryUnsupported,
    UnsupportedVersion,
    Authentication,
    Uncertain,
    ResolutionUnavailable,
    SessionRequired,
    SessionPending,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowResultV1 {
    NotObserved,
    ReturnedOk,
    ReturnedErr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowJobPurposeV1 {
    AcquirePrepare,
    Acquire,
    ActivationPrepare,
    Activate,
    ReconcilePrepare,
    Reconcile,
    Import,
    WalletReview,
    Sign,
    ResultService,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowReceiveV1 {
    NotObserved,
    Pending,
    Received,
    Missing,
    Disconnected,
    Invalidated,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowPresentationV1 {
    NotObserved,
    Accepted,
    Suppressed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowCallOutcomeV1 {
    NotObserved,
    Entered,
    ReturnedOk,
    ReturnedErr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableFlowCallV1 {
    WriterAcquire,
    WriterActivate,
    ActiveVerify,
    Reconciliation,
    SessionInvalidation,
    Release,
    RequestRetention,
    Reservation,
    PermitRetention,
    KeyUse,
    ResultRetention,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowTransportPurposeV1 {
    Acquire,
    Activate,
    Verify,
    Reserve,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowTransportStageV1 {
    RequestValidation,
    Binding,
    Session,
    CallerDeadline,
    ExchangeDeadline,
    SourceCallback,
    Connect,
    Handshake,
    PeerBinding,
    RequestBuild,
    RequestWrite,
    ResponseRead,
    Response,
    SnapshotValidation,
    ReceiptValidation,
    CommittedHeadValidation,
    FinalValidation,
    Bounds,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableFlowCallbackStageV1 {
    WorkspaceCurrent,
    CallerCurrent,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DurableFlowErrorV1 {
    stage: DurableFlowStageV1,
    domain: DurableFlowErrorDomainV1,
    code: DurableFlowErrorCodeV1,
    nested_code: Option<DurableFlowNestedCodeV1>,
}
impl DurableFlowErrorV1 {
    scalars! { stage: DurableFlowStageV1, domain: DurableFlowErrorDomainV1,
    code: DurableFlowErrorCodeV1, nested_code: Option<DurableFlowNestedCodeV1> }
}
#[derive(Clone, Copy)]
pub struct DurableFlowCompletionV1 {
    purpose: Option<DurableFlowJobPurposeV1>,
    result: DurableFlowResultV1,
    receive: DurableFlowReceiveV1,
    presentation: DurableFlowPresentationV1,
}
impl DurableFlowCompletionV1 {
    scalars! { purpose: Option<DurableFlowJobPurposeV1>, result: DurableFlowResultV1,
    receive: DurableFlowReceiveV1, presentation: DurableFlowPresentationV1 }
}
impl Default for DurableFlowCompletionV1 {
    fn default() -> Self {
        Self {
            purpose: None,
            result: DurableFlowResultV1::NotObserved,
            receive: DurableFlowReceiveV1::NotObserved,
            presentation: DurableFlowPresentationV1::NotObserved,
        }
    }
}
#[derive(Clone, Copy)]
pub struct DurableFlowCallOutcomesV1 {
    writer_acquire: DurableFlowCallOutcomeV1,
    writer_activate: DurableFlowCallOutcomeV1,
    active_verify: DurableFlowCallOutcomeV1,
    reconciliation: DurableFlowCallOutcomeV1,
    session_invalidation: DurableFlowCallOutcomeV1,
    release: DurableFlowCallOutcomeV1,
    request_retention: DurableFlowCallOutcomeV1,
    reservation: DurableFlowCallOutcomeV1,
    permit_retention: DurableFlowCallOutcomeV1,
    key_use: DurableFlowCallOutcomeV1,
    result_retention: DurableFlowCallOutcomeV1,
}
impl DurableFlowCallOutcomesV1 {
    scalars! {writer_acquire: DurableFlowCallOutcomeV1, writer_activate: DurableFlowCallOutcomeV1, active_verify: DurableFlowCallOutcomeV1, reconciliation: DurableFlowCallOutcomeV1, session_invalidation: DurableFlowCallOutcomeV1, release: DurableFlowCallOutcomeV1, request_retention: DurableFlowCallOutcomeV1, reservation: DurableFlowCallOutcomeV1, permit_retention: DurableFlowCallOutcomeV1, key_use: DurableFlowCallOutcomeV1, result_retention: DurableFlowCallOutcomeV1}
    fn slot(&mut self, slot: DurableFlowCallV1) -> &mut DurableFlowCallOutcomeV1 {
        match slot {
            DurableFlowCallV1::WriterAcquire => &mut self.writer_acquire,
            DurableFlowCallV1::WriterActivate => &mut self.writer_activate,
            DurableFlowCallV1::ActiveVerify => &mut self.active_verify,
            DurableFlowCallV1::Reconciliation => &mut self.reconciliation,
            DurableFlowCallV1::SessionInvalidation => &mut self.session_invalidation,
            DurableFlowCallV1::Release => &mut self.release,
            DurableFlowCallV1::RequestRetention => &mut self.request_retention,
            DurableFlowCallV1::Reservation => &mut self.reservation,
            DurableFlowCallV1::PermitRetention => &mut self.permit_retention,
            DurableFlowCallV1::KeyUse => &mut self.key_use,
            DurableFlowCallV1::ResultRetention => &mut self.result_retention,
        }
    }
}
impl Default for DurableFlowCallOutcomesV1 {
    fn default() -> Self {
        Self {
            writer_acquire: DurableFlowCallOutcomeV1::NotObserved,
            writer_activate: DurableFlowCallOutcomeV1::NotObserved,
            active_verify: DurableFlowCallOutcomeV1::NotObserved,
            reconciliation: DurableFlowCallOutcomeV1::NotObserved,
            session_invalidation: DurableFlowCallOutcomeV1::NotObserved,
            release: DurableFlowCallOutcomeV1::NotObserved,
            request_retention: DurableFlowCallOutcomeV1::NotObserved,
            reservation: DurableFlowCallOutcomeV1::NotObserved,
            permit_retention: DurableFlowCallOutcomeV1::NotObserved,
            key_use: DurableFlowCallOutcomeV1::NotObserved,
            result_retention: DurableFlowCallOutcomeV1::NotObserved,
        }
    }
}

pub struct DurableFlowTransportFailureV1 {
    purpose: DurableFlowTransportPurposeV1,
    stage: DurableFlowTransportStageV1,
    callback_stage: Option<DurableFlowCallbackStageV1>,
    failure: CheckedHistoryFailureV1,
}
impl DurableFlowTransportFailureV1 {
    scalars! { purpose: DurableFlowTransportPurposeV1, stage: DurableFlowTransportStageV1,
    callback_stage: Option<DurableFlowCallbackStageV1> }
    pub fn authority_code(&self) -> DurableFlowAuthorityCodeV1 {
        authority_code(&self.failure.error())
    }
    pub fn io_kind(&self) -> Option<CheckedHistoryIoKindV1> {
        self.failure.io_kind()
    }
    pub fn measurement(&self) -> &CheckedHistoryMeasurementV1 {
        self.failure.measurement()
    }
}
const LIFECYCLE_BUDGET_US: u32 = 120_000_000;
const LIFECYCLE_CAP_US: u32 = 600_000_000;
const LIFECYCLE_COUNT_CAP: u32 = 1_000_000;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableLifecyclePointV1 {
    NativeOpenComplete,
    PairComplete,
    WitnessSetupComplete,
    AcceptComplete,
    RedisclosureComplete,
    ImportComplete,
    HistoricalLookupComplete,
    AcquirePrepareLaunch,
    AcquirePrepareComplete,
    AcquireNativeApproval,
    AcquireWorkerLaunch,
    FixtureFailure,
    AfterDrain,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurablePendingWaitKindV1 {
    FullPrecheck,
    FullPostcheck,
    Liveness,
    Poll,
}
#[derive(Clone, Copy)]
pub struct DurableLifecyclePointMeasurementV1 {
    age_us: u32,
    remaining_us: u32,
}
impl DurableLifecyclePointMeasurementV1 {
    scalars! { age_us: u32, remaining_us: u32 }
}
#[derive(Clone, Copy, Default)]
pub struct DurablePendingWaitCostV1 {
    calls: u32,
    total_us: u32,
    max_us: u32,
}
impl DurablePendingWaitCostV1 {
    scalars! { calls: u32, total_us: u32, max_us: u32 }
}
pub struct DurableLifecycleDiagnosticV1 {
    operation: DurableFlowOperationV1,
    fixture_result: DurableFlowResultV1,
    owner_budget_us: u32,
    points: [Option<DurableLifecyclePointMeasurementV1>; 13],
    pending_wait: [DurablePendingWaitCostV1; 4],
    worker_purpose: Option<DurableFlowJobPurposeV1>,
    worker_started_to_client_entry_us: Option<u32>,
    worker_started_to_client_return_us: Option<u32>,
    clamped: bool,
    incomplete: bool,
}
impl DurableLifecycleDiagnosticV1 {
    scalars! { operation: DurableFlowOperationV1, fixture_result: DurableFlowResultV1,
    owner_budget_us: u32, worker_purpose: Option<DurableFlowJobPurposeV1>,
    worker_started_to_client_entry_us: Option<u32>,
    worker_started_to_client_return_us: Option<u32>, clamped: bool, incomplete: bool }
    pub fn point(
        &self,
        point: DurableLifecyclePointV1,
    ) -> Option<DurableLifecyclePointMeasurementV1> {
        self.points[point as usize]
    }
    pub fn pending_wait(&self, kind: DurablePendingWaitKindV1) -> DurablePendingWaitCostV1 {
        self.pending_wait[kind as usize]
    }
}
#[derive(Default)]
struct LifecycleDataV1 {
    points: [Option<DurableLifecyclePointMeasurementV1>; 13],
    pending_wait: [DurablePendingWaitCostV1; 4],
    clamped: bool,
}
#[derive(Default)]
struct LifecycleSharedV1 {
    data: Mutex<LifecycleDataV1>,
    incomplete: AtomicBool,
}
/// Fixed-size inert owner measurements. No source, native owner or authority is retained.
#[derive(Clone)]
pub(crate) struct DurableLifecycleObserverV1 {
    original_start: Option<Instant>,
    shared: Arc<LifecycleSharedV1>,
}
impl DurableLifecycleObserverV1 {
    pub(crate) fn new(original_deadline: Instant) -> Self {
        Self {
            original_start: original_deadline.checked_sub(Duration::from_secs(120)),
            shared: Arc::new(LifecycleSharedV1::default()),
        }
    }
    fn update(&self, apply: impl FnOnce(&mut LifecycleDataV1)) {
        if let Ok(mut data) = self.shared.data.try_lock() {
            apply(&mut data);
        } else {
            self.shared.incomplete.store(true, Ordering::Release);
        }
    }
    pub(crate) fn point(&self, point: DurableLifecyclePointV1) {
        self.point_at(point, Instant::now());
    }
    pub(crate) fn point_at(&self, point: DurableLifecyclePointV1, now: Instant) {
        let Some(age) = self
            .original_start
            .and_then(|start| now.checked_duration_since(start))
        else {
            self.shared.incomplete.store(true, Ordering::Release);
            return;
        };
        self.update(|data| {
            if data.points[point as usize].is_some() {
                self.shared.incomplete.store(true, Ordering::Release);
                return;
            }
            let age_us = lifecycle_micros(age, &mut data.clamped);
            data.points[point as usize] = Some(DurableLifecyclePointMeasurementV1 {
                age_us,
                remaining_us: LIFECYCLE_BUDGET_US.saturating_sub(age_us),
            });
        });
    }
    pub(crate) fn cost(&self, kind: DurablePendingWaitKindV1, elapsed: Duration) {
        self.update(|data| {
            let micros = lifecycle_micros(elapsed, &mut data.clamped);
            let value = &mut data.pending_wait[kind as usize];
            if value.calls == LIFECYCLE_COUNT_CAP {
                data.clamped = true;
            } else {
                value.calls += 1;
            }
            let total = u64::from(value.total_us) + u64::from(micros);
            if total > u64::from(LIFECYCLE_CAP_US) {
                data.clamped = true;
            }
            value.total_us = total.min(u64::from(LIFECYCLE_CAP_US)) as u32;
            value.max_us = value.max_us.max(micros);
        });
    }
    fn snapshot(
        &self,
        operation: DurableFlowOperationV1,
        purpose: Option<DurableFlowJobPurposeV1>,
        timing: WorkerTimingV1,
        flow_incomplete: bool,
    ) -> Option<DurableLifecycleDiagnosticV1> {
        if operation != DurableFlowOperationV1::WriterReconcile {
            return None;
        }
        let Ok(data) = self.shared.data.try_lock() else {
            self.shared.incomplete.store(true, Ordering::Release);
            return None;
        };
        Some(DurableLifecycleDiagnosticV1 {
            operation,
            fixture_result: DurableFlowResultV1::ReturnedErr,
            owner_budget_us: LIFECYCLE_BUDGET_US,
            points: data.points,
            pending_wait: data.pending_wait,
            worker_purpose: purpose,
            worker_started_to_client_entry_us: timing.client_entry_us,
            worker_started_to_client_return_us: timing.client_return_us,
            clamped: data.clamped || timing.clamped,
            incomplete: flow_incomplete
                || timing.incomplete
                || self.original_start.is_none()
                || self.shared.incomplete.load(Ordering::Acquire),
        })
    }
}
fn lifecycle_micros(duration: Duration, clamped: &mut bool) -> u32 {
    let micros = duration.as_micros();
    if micros > u128::from(LIFECYCLE_CAP_US) {
        *clamped = true;
    }
    micros.min(u128::from(LIFECYCLE_CAP_US)) as u32
}
fn lifecycle_optional_clock(observed: bool, now: impl FnOnce() -> Instant) -> Option<Instant> {
    observed.then(now)
}
pub(crate) fn observe_pending_wait_v1<T>(
    observer: Option<&DurableLifecycleObserverV1>,
    kind: DurablePendingWaitKindV1,
    call: impl FnOnce() -> T,
) -> T {
    let start = lifecycle_optional_clock(observer.is_some(), Instant::now);
    let original = call();
    if let (Some(observer), Some(start)) = (observer, start) {
        observer.cost(kind, start.elapsed());
    }
    original
}
#[derive(Clone, Copy, Default)]
struct WorkerTimingV1 {
    identity: Option<JobIdentity>,
    thread: Option<std::thread::ThreadId>,
    started: Option<Instant>,
    client_entry_us: Option<u32>,
    client_return_us: Option<u32>,
    clamped: bool,
    incomplete: bool,
}
/// A final-only supplement. Worker return is not UI receipt or acceptance.
pub struct DurableFlowAfterDrainV1 {
    drain_result: DurableFlowResultV1,
    drain_error: Option<DurableFlowErrorV1>,
    worker_purpose: Option<DurableFlowJobPurposeV1>,
    worker_result: DurableFlowResultV1,
    worker_error: Option<DurableFlowErrorV1>,
    call_outcomes: DurableFlowCallOutcomesV1,
    lower_call_measurement: Option<Arc<DurableFlowTransportFailureV1>>,
    clamped: bool,
    incomplete: bool,
}
impl DurableFlowAfterDrainV1 {
    scalars! { drain_result: DurableFlowResultV1,
    worker_purpose: Option<DurableFlowJobPurposeV1>, worker_result: DurableFlowResultV1,
    clamped: bool, incomplete: bool }
    pub fn drain_error(&self) -> Option<&DurableFlowErrorV1> {
        self.drain_error.as_ref()
    }
    pub fn worker_error(&self) -> Option<&DurableFlowErrorV1> {
        self.worker_error.as_ref()
    }
    pub fn call_outcomes(&self) -> &DurableFlowCallOutcomesV1 {
        &self.call_outcomes
    }
    pub fn lower_call_measurement(&self) -> Option<&DurableFlowTransportFailureV1> {
        self.lower_call_measurement.as_deref()
    }
}
pub struct DurableFlowDiagnosticV1 {
    operation: DurableFlowOperationV1,
    first_error: Option<DurableFlowErrorV1>,
    terminal_error: Option<DurableFlowErrorV1>,
    fixture_result: DurableFlowResultV1,
    completion: DurableFlowCompletionV1,
    call_outcomes: DurableFlowCallOutcomesV1,
    lower_call_measurement: Option<Arc<DurableFlowTransportFailureV1>>,
    after_drain: Option<DurableFlowAfterDrainV1>,
    lifecycle: Option<DurableLifecycleDiagnosticV1>,
    clamped: bool,
    incomplete: bool,
}
impl DurableFlowDiagnosticV1 {
    scalars! { operation: DurableFlowOperationV1, fixture_result: DurableFlowResultV1,
    clamped: bool, incomplete: bool }
    pub fn first_error(&self) -> Option<&DurableFlowErrorV1> {
        self.first_error.as_ref()
    }
    pub fn terminal_error(&self) -> Option<&DurableFlowErrorV1> {
        self.terminal_error.as_ref()
    }
    pub fn completion(&self) -> &DurableFlowCompletionV1 {
        &self.completion
    }
    pub fn call_outcomes(&self) -> &DurableFlowCallOutcomesV1 {
        &self.call_outcomes
    }
    pub fn lower_call_measurement(&self) -> Option<&DurableFlowTransportFailureV1> {
        self.lower_call_measurement.as_deref()
    }
    pub fn after_drain(&self) -> Option<&DurableFlowAfterDrainV1> {
        self.after_drain.as_ref()
    }
    pub fn lifecycle(&self) -> Option<&DurableLifecycleDiagnosticV1> {
        self.lifecycle.as_ref()
    }
}
/// Owns the exact fixture error, without cloning, reconstructing or formatting it.
pub struct DurableFlowFailureV1 {
    error: crate::Error,
    diagnostic: Option<DurableFlowDiagnosticV1>,
    pending: Option<(DurableFlowObserverV1, Option<JobIdentity>)>,
}
impl DurableFlowFailureV1 {
    pub(crate) fn new(error: crate::Error, diagnostic: Option<DurableFlowDiagnosticV1>) -> Self {
        Self {
            error,
            diagnostic,
            pending: None,
        }
    }
    pub(crate) fn new_pending(error: crate::Error, observer: DurableFlowObserverV1) -> Self {
        let snapshot = observer.failure_snapshot();
        let (diagnostic, identity) = match snapshot {
            Some((diagnostic, identity)) => (Some(diagnostic), identity),
            None => (None, None),
        };
        Self {
            error,
            diagnostic,
            pending: Some((observer, identity)),
        }
    }
    /// Call only after the original entry was dropped. This reads inert data;
    /// it does not drain, wait, retry, inspect history or change the error.
    pub fn finalize_after_drain(&mut self) {
        let Some((observer, identity)) = self.pending.take() else {
            return;
        };
        let initial_lower = self
            .diagnostic
            .as_ref()
            .is_some_and(|d| d.lower_call_measurement.is_some());
        let initial_result = self
            .diagnostic
            .as_ref()
            .map(|d| d.completion.result)
            .unwrap_or(DurableFlowResultV1::NotObserved);
        let Some(after) = observer.finish_after_drain(identity, initial_lower, initial_result)
        else {
            return;
        };
        if let Some(diagnostic) = self.diagnostic.as_mut() {
            diagnostic.lifecycle = observer.lifecycle.as_ref().and_then(|lifecycle| {
                lifecycle.snapshot(
                    diagnostic.operation,
                    identity.map(|job| job.purpose),
                    after.worker_timing,
                    after.diagnostic.incomplete,
                )
            });
            diagnostic.after_drain = Some(after.diagnostic);
        }
    }
    pub fn error(&self) -> &crate::Error {
        &self.error
    }
    pub fn diagnostic(&self) -> Option<&DurableFlowDiagnosticV1> {
        self.diagnostic.as_ref()
    }
    pub fn into_error(self) -> crate::Error {
        self.error
    }
}
/// Opaque, inert exact-attempt data. It grants no runtime action or permission.
pub struct DurableFlowObservationTokenV1 {
    observer: DurableFlowObserverV1,
}
impl DurableFlowObservationTokenV1 {
    pub(crate) fn new(observer: DurableFlowObserverV1) -> Self {
        Self { observer }
    }
    pub(crate) fn observer(&self) -> &DurableFlowObserverV1 {
        &self.observer
    }
}

pub(crate) trait DurableFlowClassifyV1 {
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1;
}

impl DurableFlowClassifyV1 for crate::Error {
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
        use crate::Error as E;
        let (code, nested_code) = match self {
            E::Unavailable => (DurableFlowErrorCodeV1::SignerUnavailable, None),
            E::PeerLifetimeUnavailable => {
                (DurableFlowErrorCodeV1::SignerPeerLifetimeUnavailable, None)
            }

            E::Io(_) => (DurableFlowErrorCodeV1::SignerIo, None),
            E::Authentication => (DurableFlowErrorCodeV1::SignerAuthentication, None),
            E::InvalidData => (DurableFlowErrorCodeV1::SignerInvalidData, None),
            E::Crypto => (DurableFlowErrorCodeV1::SignerCrypto, None),
            E::Locked => (DurableFlowErrorCodeV1::SignerLocked, None),
            E::BackupRequired => (DurableFlowErrorCodeV1::SignerBackupRequired, None),
            E::RecoveryRequired => (DurableFlowErrorCodeV1::SignerRecoveryRequired, None),
            E::AlreadyOpen => (DurableFlowErrorCodeV1::SignerAlreadyOpen, None),
            E::ReviewMismatch => (DurableFlowErrorCodeV1::SignerReviewMismatch, None),
            E::Verification => (DurableFlowErrorCodeV1::SignerVerification, None),
            E::Uncertain => (DurableFlowErrorCodeV1::SignerUncertain, None),
            E::ConsentJournal(inner) => (
                DurableFlowErrorCodeV1::SignerConsentJournal,
                Some(nested_journal(inner)),
            ),
            E::Store(inner) => (
                DurableFlowErrorCodeV1::SignerStore,
                Some(nested_store(inner)),
            ),
        };
        DurableFlowErrorV1 {
            stage,
            domain: DurableFlowErrorDomainV1::Signer,
            code,
            nested_code,
        }
    }
}

impl DurableFlowClassifyV1 for super::BridgeError {
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
        use super::BridgeError as E;
        let (code, nested_code) = match self {
            E::Binding => (DurableFlowErrorCodeV1::BridgeBinding, None),
            E::Conflict => (DurableFlowErrorCodeV1::BridgeConflict, None),
            E::Missing => (DurableFlowErrorCodeV1::BridgeMissing, None),
            E::Uncertain => (DurableFlowErrorCodeV1::BridgeUncertain, None),
            E::Limit => (DurableFlowErrorCodeV1::BridgeLimit, None),
            E::Permission => (DurableFlowErrorCodeV1::BridgePermission, None),
            E::RecoveryRequired => (DurableFlowErrorCodeV1::BridgeRecoveryRequired, None),
            E::CompleteOriginRecoveryUnavailable => (
                DurableFlowErrorCodeV1::BridgeCompleteOriginRecoveryUnavailable,
                None,
            ),
            E::Verification => (DurableFlowErrorCodeV1::BridgeVerification, None),
            E::SignerOriginUnavailable => {
                (DurableFlowErrorCodeV1::BridgeSignerOriginUnavailable, None)
            }

            E::Journal(inner) => (
                DurableFlowErrorCodeV1::BridgeJournal,
                Some(nested_journal(inner)),
            ),
            E::Authority(inner) => (
                DurableFlowErrorCodeV1::BridgeAuthority,
                Some(nested_authority(inner)),
            ),
            E::Wallet(inner) => (
                DurableFlowErrorCodeV1::BridgeWallet,
                Some(nested_walletkeyuse(inner)),
            ),
            E::Ipc => (DurableFlowErrorCodeV1::BridgeIpc, None),
        };
        DurableFlowErrorV1 {
            stage,
            domain: DurableFlowErrorDomainV1::Bridge,
            code,
            nested_code,
        }
    }
}

impl DurableFlowClassifyV1 for wholepact_authority::AuthorityError {
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
        use wholepact_authority::AuthorityError as E;
        let (code, nested_code) = match self {
            E::InvalidBinding => (DurableFlowErrorCodeV1::AuthorityInvalidBinding, None),
            E::Permission => (DurableFlowErrorCodeV1::AuthorityPermission, None),
            E::StaleHead => (DurableFlowErrorCodeV1::AuthorityStaleHead, None),
            E::Conflict => (DurableFlowErrorCodeV1::AuthorityConflict, None),
            E::Inactive => (DurableFlowErrorCodeV1::AuthorityInactive, None),
            E::RecoveryRequired => (DurableFlowErrorCodeV1::AuthorityRecoveryRequired, None),
            E::Expired => (DurableFlowErrorCodeV1::AuthorityExpired, None),
            E::PolicyDenied => (DurableFlowErrorCodeV1::AuthorityPolicyDenied, None),
            E::BudgetExceeded => (DurableFlowErrorCodeV1::AuthorityBudgetExceeded, None),
            E::InputReserved => (DurableFlowErrorCodeV1::AuthorityInputReserved, None),
            E::ObligationReserved => (DurableFlowErrorCodeV1::AuthorityObligationReserved, None),
            E::Limit => (DurableFlowErrorCodeV1::AuthorityLimit, None),
            E::Storage => (DurableFlowErrorCodeV1::AuthorityStorage, None),
            E::CorruptHistory => (DurableFlowErrorCodeV1::AuthorityCorruptHistory, None),
            E::PermanentStopUnavailable => (
                DurableFlowErrorCodeV1::AuthorityPermanentStopUnavailable,
                None,
            ),
            E::OfflineHistoryUnsupported => (
                DurableFlowErrorCodeV1::AuthorityOfflineHistoryUnsupported,
                None,
            ),
            E::ConstructionHistoryUnsupported => (
                DurableFlowErrorCodeV1::AuthorityConstructionHistoryUnsupported,
                None,
            ),
            E::UnsupportedVersion => (DurableFlowErrorCodeV1::AuthorityUnsupportedVersion, None),
            E::Authentication => (DurableFlowErrorCodeV1::AuthorityAuthentication, None),
            E::Uncertain => (DurableFlowErrorCodeV1::AuthorityUncertain, None),
            E::ResolutionUnavailable => {
                (DurableFlowErrorCodeV1::AuthorityResolutionUnavailable, None)
            }

            E::SessionRequired => (DurableFlowErrorCodeV1::AuthoritySessionRequired, None),
            E::SessionPending => (DurableFlowErrorCodeV1::AuthoritySessionPending, None),
        };
        DurableFlowErrorV1 {
            stage,
            domain: DurableFlowErrorDomainV1::Authority,
            code,
            nested_code,
        }
    }
}

impl DurableFlowClassifyV1 for crate::consent_journal::JournalError {
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
        use crate::consent_journal::JournalError as E;
        let (code, nested_code) = match self {
            E::Storage(inner) => (
                DurableFlowErrorCodeV1::JournalStorage,
                Some(nested_storagesecurity(inner)),
            ),
            E::Database => (DurableFlowErrorCodeV1::JournalDatabase, None),
            E::Permission => (DurableFlowErrorCodeV1::JournalPermission, None),
            E::Expired => (DurableFlowErrorCodeV1::JournalExpired, None),
            E::RecoveryRequired => (DurableFlowErrorCodeV1::JournalRecoveryRequired, None),
            E::UnsupportedSchema => (DurableFlowErrorCodeV1::JournalUnsupportedSchema, None),
            E::OfflineHistoryUnsupported => (
                DurableFlowErrorCodeV1::JournalOfflineHistoryUnsupported,
                None,
            ),
            E::NamedRecipientHistoryUnsupported => (
                DurableFlowErrorCodeV1::JournalNamedRecipientHistoryUnsupported,
                None,
            ),
            E::ConstructionHistoryUnsupported => (
                DurableFlowErrorCodeV1::JournalConstructionHistoryUnsupported,
                None,
            ),
            E::InvalidBinding => (DurableFlowErrorCodeV1::JournalInvalidBinding, None),
            E::Conflict => (DurableFlowErrorCodeV1::JournalConflict, None),
            E::NotFound => (DurableFlowErrorCodeV1::JournalNotFound, None),
            E::LiveAuthorization => (DurableFlowErrorCodeV1::JournalLiveAuthorization, None),
            E::InputReserved => (DurableFlowErrorCodeV1::JournalInputReserved, None),
            E::BudgetExceeded => (DurableFlowErrorCodeV1::JournalBudgetExceeded, None),
            E::Limit => (DurableFlowErrorCodeV1::JournalLimit, None),
        };
        DurableFlowErrorV1 {
            stage,
            domain: DurableFlowErrorDomainV1::Journal,
            code,
            nested_code,
        }
    }
}

impl DurableFlowClassifyV1
    for wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError
{
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
        use wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError as E;
        let (code, nested_code) = match self {
            E::Permission => (DurableFlowErrorCodeV1::WalletKeyUsePermission, None),
            E::Policy => (DurableFlowErrorCodeV1::WalletKeyUsePolicy, None),
            E::SelectionExpired => (DurableFlowErrorCodeV1::WalletKeyUseSelectionExpired, None),
            E::Storage => (DurableFlowErrorCodeV1::WalletKeyUseStorage, None),
            E::RecoveryRequired => (DurableFlowErrorCodeV1::WalletKeyUseRecoveryRequired, None),
            E::StateChanged => (DurableFlowErrorCodeV1::WalletKeyUseStateChanged, None),
            E::Expiry => (DurableFlowErrorCodeV1::WalletKeyUseExpiry, None),
            E::Sync(inner) => (
                DurableFlowErrorCodeV1::WalletKeyUseSync,
                Some(nested_sync(inner)),
            ),
        };
        DurableFlowErrorV1 {
            stage,
            domain: DurableFlowErrorDomainV1::WalletKeyUse,
            code,
            nested_code,
        }
    }
}

impl DurableFlowClassifyV1 for wholepact_store::StoreError {
    fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
        use wholepact_store::StoreError as E;
        let (code, nested_code) = match self {
            E::StorageSecurity(inner) => (
                DurableFlowErrorCodeV1::StoreStorageSecurity,
                Some(nested_storagesecurity(inner)),
            ),
            E::Database(_) => (DurableFlowErrorCodeV1::StoreDatabase, None),
            E::Encoding(_) => (DurableFlowErrorCodeV1::StoreEncoding, None),
            E::Poisoned => (DurableFlowErrorCodeV1::StorePoisoned, None),
            E::IdempotencyConflict => (DurableFlowErrorCodeV1::StoreIdempotencyConflict, None),
            E::RevisionConflict => (DurableFlowErrorCodeV1::StoreRevisionConflict, None),
            E::NotFound => (DurableFlowErrorCodeV1::StoreNotFound, None),
            E::AlreadyExists => (DurableFlowErrorCodeV1::StoreAlreadyExists, None),
            E::InvalidInput(_) => (DurableFlowErrorCodeV1::StoreInvalidInput, None),
            E::UnsupportedSchema(_) => (DurableFlowErrorCodeV1::StoreUnsupportedSchema, None),
            E::RecoveryRequired => (DurableFlowErrorCodeV1::StoreRecoveryRequired, None),
            E::WriterEpochMismatch => (DurableFlowErrorCodeV1::StoreWriterEpochMismatch, None),
            E::LiveAuthorizationExists => {
                (DurableFlowErrorCodeV1::StoreLiveAuthorizationExists, None)
            }

            E::InputReserved => (DurableFlowErrorCodeV1::StoreInputReserved, None),
            E::ResourceExhausted => (DurableFlowErrorCodeV1::StoreResourceExhausted, None),
            E::BudgetExceeded => (DurableFlowErrorCodeV1::StoreBudgetExceeded, None),
            E::InvalidTransition => (DurableFlowErrorCodeV1::StoreInvalidTransition, None),
            E::File(_) => (DurableFlowErrorCodeV1::StoreFile, None),
        };
        DurableFlowErrorV1 {
            stage,
            domain: DurableFlowErrorDomainV1::Store,
            code,
            nested_code,
        }
    }
}

fn nested_journal(error: &crate::consent_journal::JournalError) -> DurableFlowNestedCodeV1 {
    use crate::consent_journal::JournalError as E;
    match error {
        E::Storage(_) => DurableFlowNestedCodeV1::JournalStorage,
        E::Database => DurableFlowNestedCodeV1::JournalDatabase,
        E::Permission => DurableFlowNestedCodeV1::JournalPermission,
        E::Expired => DurableFlowNestedCodeV1::JournalExpired,
        E::RecoveryRequired => DurableFlowNestedCodeV1::JournalRecoveryRequired,
        E::UnsupportedSchema => DurableFlowNestedCodeV1::JournalUnsupportedSchema,
        E::OfflineHistoryUnsupported => DurableFlowNestedCodeV1::JournalOfflineHistoryUnsupported,
        E::NamedRecipientHistoryUnsupported => {
            DurableFlowNestedCodeV1::JournalNamedRecipientHistoryUnsupported
        }

        E::ConstructionHistoryUnsupported => {
            DurableFlowNestedCodeV1::JournalConstructionHistoryUnsupported
        }

        E::InvalidBinding => DurableFlowNestedCodeV1::JournalInvalidBinding,
        E::Conflict => DurableFlowNestedCodeV1::JournalConflict,
        E::NotFound => DurableFlowNestedCodeV1::JournalNotFound,
        E::LiveAuthorization => DurableFlowNestedCodeV1::JournalLiveAuthorization,
        E::InputReserved => DurableFlowNestedCodeV1::JournalInputReserved,
        E::BudgetExceeded => DurableFlowNestedCodeV1::JournalBudgetExceeded,
        E::Limit => DurableFlowNestedCodeV1::JournalLimit,
    }
}

fn nested_store(error: &wholepact_store::StoreError) -> DurableFlowNestedCodeV1 {
    use wholepact_store::StoreError as E;
    match error {
        E::StorageSecurity(_) => DurableFlowNestedCodeV1::StoreStorageSecurity,
        E::Database(_) => DurableFlowNestedCodeV1::StoreDatabase,
        E::Encoding(_) => DurableFlowNestedCodeV1::StoreEncoding,
        E::Poisoned => DurableFlowNestedCodeV1::StorePoisoned,
        E::IdempotencyConflict => DurableFlowNestedCodeV1::StoreIdempotencyConflict,
        E::RevisionConflict => DurableFlowNestedCodeV1::StoreRevisionConflict,
        E::NotFound => DurableFlowNestedCodeV1::StoreNotFound,
        E::AlreadyExists => DurableFlowNestedCodeV1::StoreAlreadyExists,
        E::InvalidInput(_) => DurableFlowNestedCodeV1::StoreInvalidInput,
        E::UnsupportedSchema(_) => DurableFlowNestedCodeV1::StoreUnsupportedSchema,
        E::RecoveryRequired => DurableFlowNestedCodeV1::StoreRecoveryRequired,
        E::WriterEpochMismatch => DurableFlowNestedCodeV1::StoreWriterEpochMismatch,
        E::LiveAuthorizationExists => DurableFlowNestedCodeV1::StoreLiveAuthorizationExists,
        E::InputReserved => DurableFlowNestedCodeV1::StoreInputReserved,
        E::ResourceExhausted => DurableFlowNestedCodeV1::StoreResourceExhausted,
        E::BudgetExceeded => DurableFlowNestedCodeV1::StoreBudgetExceeded,
        E::InvalidTransition => DurableFlowNestedCodeV1::StoreInvalidTransition,
        E::File(_) => DurableFlowNestedCodeV1::StoreFile,
    }
}

fn nested_authority(error: &wholepact_authority::AuthorityError) -> DurableFlowNestedCodeV1 {
    use wholepact_authority::AuthorityError as E;
    match error {
        E::InvalidBinding => DurableFlowNestedCodeV1::AuthorityInvalidBinding,
        E::Permission => DurableFlowNestedCodeV1::AuthorityPermission,
        E::StaleHead => DurableFlowNestedCodeV1::AuthorityStaleHead,
        E::Conflict => DurableFlowNestedCodeV1::AuthorityConflict,
        E::Inactive => DurableFlowNestedCodeV1::AuthorityInactive,
        E::RecoveryRequired => DurableFlowNestedCodeV1::AuthorityRecoveryRequired,
        E::Expired => DurableFlowNestedCodeV1::AuthorityExpired,
        E::PolicyDenied => DurableFlowNestedCodeV1::AuthorityPolicyDenied,
        E::BudgetExceeded => DurableFlowNestedCodeV1::AuthorityBudgetExceeded,
        E::InputReserved => DurableFlowNestedCodeV1::AuthorityInputReserved,
        E::ObligationReserved => DurableFlowNestedCodeV1::AuthorityObligationReserved,
        E::Limit => DurableFlowNestedCodeV1::AuthorityLimit,
        E::Storage => DurableFlowNestedCodeV1::AuthorityStorage,
        E::CorruptHistory => DurableFlowNestedCodeV1::AuthorityCorruptHistory,
        E::PermanentStopUnavailable => DurableFlowNestedCodeV1::AuthorityPermanentStopUnavailable,
        E::OfflineHistoryUnsupported => DurableFlowNestedCodeV1::AuthorityOfflineHistoryUnsupported,
        E::ConstructionHistoryUnsupported => {
            DurableFlowNestedCodeV1::AuthorityConstructionHistoryUnsupported
        }

        E::UnsupportedVersion => DurableFlowNestedCodeV1::AuthorityUnsupportedVersion,
        E::Authentication => DurableFlowNestedCodeV1::AuthorityAuthentication,
        E::Uncertain => DurableFlowNestedCodeV1::AuthorityUncertain,
        E::ResolutionUnavailable => DurableFlowNestedCodeV1::AuthorityResolutionUnavailable,
        E::SessionRequired => DurableFlowNestedCodeV1::AuthoritySessionRequired,
        E::SessionPending => DurableFlowNestedCodeV1::AuthoritySessionPending,
    }
}

fn nested_walletkeyuse(
    error: &wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError,
) -> DurableFlowNestedCodeV1 {
    use wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError as E;
    match error {
        E::Permission => DurableFlowNestedCodeV1::WalletKeyUsePermission,
        E::Policy => DurableFlowNestedCodeV1::WalletKeyUsePolicy,
        E::SelectionExpired => DurableFlowNestedCodeV1::WalletKeyUseSelectionExpired,
        E::Storage => DurableFlowNestedCodeV1::WalletKeyUseStorage,
        E::RecoveryRequired => DurableFlowNestedCodeV1::WalletKeyUseRecoveryRequired,
        E::StateChanged => DurableFlowNestedCodeV1::WalletKeyUseStateChanged,
        E::Expiry => DurableFlowNestedCodeV1::WalletKeyUseExpiry,
        E::Sync(_) => DurableFlowNestedCodeV1::WalletKeyUseSync,
    }
}

fn nested_storagesecurity(
    error: &wholepact_storage_security::StorageSecurityError,
) -> DurableFlowNestedCodeV1 {
    use wholepact_storage_security::StorageSecurityError as E;
    match error {
        E::UnsupportedPlatform => DurableFlowNestedCodeV1::StorageSecurityUnsupportedPlatform,
        E::QuarantinedDatabase => DurableFlowNestedCodeV1::StorageSecurityQuarantinedDatabase,
        E::RecoveredGeneration => DurableFlowNestedCodeV1::StorageSecurityRecoveredGeneration,
        E::GenerationArchive => DurableFlowNestedCodeV1::StorageSecurityGenerationArchive,
        E::UninitializedDatabase => DurableFlowNestedCodeV1::StorageSecurityUninitializedDatabase,
        E::UnsafePath => DurableFlowNestedCodeV1::StorageSecurityUnsafePath,
        E::AlreadyExists => DurableFlowNestedCodeV1::StorageSecurityAlreadyExists,
        E::MissingDatabase => DurableFlowNestedCodeV1::StorageSecurityMissingDatabase,
        E::PlaintextRefused => DurableFlowNestedCodeV1::StorageSecurityPlaintextRefused,
        E::UnqualifiedRuntime => DurableFlowNestedCodeV1::StorageSecurityUnqualifiedRuntime,
        E::AuthenticationFailed => DurableFlowNestedCodeV1::StorageSecurityAuthenticationFailed,
        E::Database => DurableFlowNestedCodeV1::StorageSecurityDatabase,
        E::Io => DurableFlowNestedCodeV1::StorageSecurityIo,
        E::SnapshotLimit => DurableFlowNestedCodeV1::StorageSecuritySnapshotLimit,
        E::SourceChanged => DurableFlowNestedCodeV1::StorageSecuritySourceChanged,
    }
}

fn nested_sync(
    error: &wholepact_wallet::wallet::protected_sync::SyncError,
) -> DurableFlowNestedCodeV1 {
    use wholepact_wallet::wallet::protected_sync::SyncError as E;
    match error {
        E::AccessDenied => DurableFlowNestedCodeV1::SyncAccessDenied,
        E::InvalidRequest => DurableFlowNestedCodeV1::SyncInvalidRequest,
        E::Interrupted => DurableFlowNestedCodeV1::SyncInterrupted,
        E::ReconciliationRequired => DurableFlowNestedCodeV1::SyncReconciliationRequired,
        E::InvalidResponse => DurableFlowNestedCodeV1::SyncInvalidResponse,
        E::ResourceLimit => DurableFlowNestedCodeV1::SyncResourceLimit,
        E::NoCurrentObservation => DurableFlowNestedCodeV1::SyncNoCurrentObservation,
        E::Wallet(_) => DurableFlowNestedCodeV1::SyncWallet,
        E::Chain(_) => DurableFlowNestedCodeV1::SyncChain,
    }
}

fn authority_code(error: &wholepact_authority::AuthorityError) -> DurableFlowAuthorityCodeV1 {
    use wholepact_authority::AuthorityError as E;
    match error {
        E::InvalidBinding => DurableFlowAuthorityCodeV1::InvalidBinding,
        E::Permission => DurableFlowAuthorityCodeV1::Permission,
        E::StaleHead => DurableFlowAuthorityCodeV1::StaleHead,
        E::Conflict => DurableFlowAuthorityCodeV1::Conflict,
        E::Inactive => DurableFlowAuthorityCodeV1::Inactive,
        E::RecoveryRequired => DurableFlowAuthorityCodeV1::RecoveryRequired,
        E::Expired => DurableFlowAuthorityCodeV1::Expired,
        E::PolicyDenied => DurableFlowAuthorityCodeV1::PolicyDenied,
        E::BudgetExceeded => DurableFlowAuthorityCodeV1::BudgetExceeded,
        E::InputReserved => DurableFlowAuthorityCodeV1::InputReserved,
        E::ObligationReserved => DurableFlowAuthorityCodeV1::ObligationReserved,
        E::Limit => DurableFlowAuthorityCodeV1::Limit,
        E::Storage => DurableFlowAuthorityCodeV1::Storage,
        E::CorruptHistory => DurableFlowAuthorityCodeV1::CorruptHistory,
        E::PermanentStopUnavailable => DurableFlowAuthorityCodeV1::PermanentStopUnavailable,
        E::OfflineHistoryUnsupported => DurableFlowAuthorityCodeV1::OfflineHistoryUnsupported,
        E::ConstructionHistoryUnsupported => {
            DurableFlowAuthorityCodeV1::ConstructionHistoryUnsupported
        }
        E::UnsupportedVersion => DurableFlowAuthorityCodeV1::UnsupportedVersion,
        E::Authentication => DurableFlowAuthorityCodeV1::Authentication,
        E::Uncertain => DurableFlowAuthorityCodeV1::Uncertain,
        E::ResolutionUnavailable => DurableFlowAuthorityCodeV1::ResolutionUnavailable,
        E::SessionRequired => DurableFlowAuthorityCodeV1::SessionRequired,
        E::SessionPending => DurableFlowAuthorityCodeV1::SessionPending,
    }
}

struct ActiveObservation {
    attempt: u64,
    operation: DurableFlowOperationV1,
    first_error: Option<DurableFlowErrorV1>,
    terminal_error: Option<DurableFlowErrorV1>,
    completion: DurableFlowCompletionV1,
    calls: DurableFlowCallOutcomesV1,
    invalid_calls: u16,
    lower: Option<Arc<DurableFlowTransportFailureV1>>,
    worker_result: DurableFlowResultV1,
    worker_error: Option<DurableFlowErrorV1>,
    worker_timing: WorkerTimingV1,
    drain: Option<(DurableFlowResultV1, Option<DurableFlowErrorV1>)>,
    next_job: u64,
    job: Option<JobIdentity>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct JobIdentity {
    serial: u64,
    purpose: DurableFlowJobPurposeV1,
    epoch: u64,
}
#[derive(Default)]
struct CollectorData {
    active: Option<ActiveObservation>,
}
#[derive(Default)]
struct SharedData {
    data: Mutex<CollectorData>,
    generation: AtomicU64,
    incomplete_generation: AtomicU64,
}
#[derive(Default)]
pub(crate) struct DurableFlowCollectorV1 {
    shared: Arc<SharedData>,
}
#[derive(Clone)]
pub(crate) struct DurableFlowObserverV1 {
    shared: Arc<SharedData>,
    attempt: Option<u64>,
    operation: DurableFlowOperationV1,
    lifecycle: Option<DurableLifecycleObserverV1>,
}
#[derive(Clone)]
pub(crate) struct DurableFlowJobObservationV1 {
    observer: DurableFlowObserverV1,
    identity: Option<JobIdentity>,
}
impl DurableFlowCollectorV1 {
    pub(crate) fn arm(&self, operation: DurableFlowOperationV1) -> DurableFlowObserverV1 {
        let mut observer = DurableFlowObserverV1 {
            shared: self.shared.clone(),
            attempt: None,
            operation,
            lifecycle: None,
        };
        // Invalidate every preceding token BEFORE attempting the data lock.
        // MAX is a permanent exhausted generation and is never a valid attempt.
        let attempt = match self.shared.generation.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |value| value.checked_add(1),
        ) {
            Ok(previous) => previous + 1,
            Err(_) => {
                observer.mark_incomplete();
                return observer;
            }
        };
        if attempt == u64::MAX {
            observer.mark_incomplete();
            return observer;
        }
        let Ok(mut data) = self.shared.data.try_lock() else {
            observer.mark_incomplete();
            return observer;
        };
        if self.shared.generation.load(Ordering::Acquire) != attempt {
            observer.mark_incomplete();
            return observer;
        }
        data.active = Some(ActiveObservation {
            attempt,
            operation,
            first_error: None,
            terminal_error: None,
            completion: DurableFlowCompletionV1::default(),
            calls: DurableFlowCallOutcomesV1::default(),
            invalid_calls: 0,
            lower: None,
            worker_result: DurableFlowResultV1::NotObserved,
            worker_error: None,
            worker_timing: WorkerTimingV1::default(),
            drain: None,
            next_job: 0,
            job: None,
        });
        observer.attempt = Some(attempt);
        observer
    }
}
impl DurableFlowObserverV1 {
    pub(crate) fn with_lifecycle(mut self, lifecycle: Option<&DurableLifecycleObserverV1>) -> Self {
        self.lifecycle = lifecycle.cloned();
        self
    }
    pub(crate) fn lifecycle_point(&self, point: DurableLifecyclePointV1) {
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.point(point);
        }
    }
    fn client_sample(&self) -> Option<(Instant, std::thread::ThreadId)> {
        self.lifecycle
            .as_ref()
            .map(|_| (Instant::now(), std::thread::current().id()))
    }
    fn client_span(
        &self,
        active: &mut ActiveObservation,
        purpose: DurableFlowJobPurposeV1,
        sample: Option<(Instant, std::thread::ThreadId)>,
        returning: bool,
    ) {
        let Some((now, thread)) = sample else {
            return;
        };
        let timing = &mut active.worker_timing;
        if active.job.is_none()
            || active.job != timing.identity
            || active.job.map(|job| job.purpose) != Some(purpose)
            || timing.thread != Some(thread)
        {
            timing.incomplete = true;
            return;
        }
        let Some(elapsed) = timing
            .started
            .and_then(|started| now.checked_duration_since(started))
        else {
            timing.incomplete = true;
            return;
        };
        if (returning && (timing.client_entry_us.is_none() || timing.client_return_us.is_some()))
            || (!returning && timing.client_entry_us.is_some())
        {
            timing.incomplete = true;
            return;
        }
        let micros = lifecycle_micros(elapsed, &mut timing.clamped);
        if returning {
            if timing.client_entry_us.is_some_and(|entry| micros < entry) {
                timing.incomplete = true;
                return;
            }
            timing.client_return_us = Some(micros);
        } else {
            timing.client_entry_us = Some(micros);
        }
    }
    pub(crate) fn operation(&self) -> DurableFlowOperationV1 {
        self.operation
    }
    pub(crate) fn same_attempt(&self, other: &Self) -> bool {
        self.attempt.is_some()
            && self.attempt == other.attempt
            && self.operation == other.operation
            && Arc::ptr_eq(&self.shared, &other.shared)
            && self.attempt == Some(self.shared.generation.load(Ordering::Acquire))
    }
    pub(crate) fn mark_incomplete(&self) {
        let generation = self.shared.generation.load(Ordering::Acquire);
        self.shared
            .incomplete_generation
            .fetch_max(generation, Ordering::AcqRel);
    }
    fn update<R>(&self, apply: impl FnOnce(&mut ActiveObservation) -> R) -> Option<R> {
        let Ok(mut data) = self.shared.data.try_lock() else {
            self.mark_incomplete();
            return None;
        };
        if self.attempt != Some(self.shared.generation.load(Ordering::Acquire)) {
            self.mark_incomplete();
            return None;
        }
        let Some(active) = data
            .active
            .as_mut()
            .filter(|a| Some(a.attempt) == self.attempt && a.operation == self.operation)
        else {
            self.mark_incomplete();
            return None;
        };
        Some(apply(active))
    }
    pub(crate) fn record_error<E: DurableFlowClassifyV1>(
        &self,
        stage: DurableFlowStageV1,
        error: &E,
    ) {
        let category = error.classify(stage);
        self.update(|active| {
            if active.first_error.is_none() {
                active.first_error = Some(category);
            }
        });
    }
    pub(crate) fn record_terminal(&self, stage: DurableFlowStageV1, error: &crate::Error) {
        let category = error.classify(stage);
        self.update(|active| {
            if let Some(existing) = active.terminal_error {
                if existing != category {
                    self.mark_incomplete();
                }
            } else {
                active.terminal_error = Some(category);
            }
        });
    }
    pub(crate) fn call_enter(&self, slot: DurableFlowCallV1) {
        let purpose = match slot {
            DurableFlowCallV1::WriterAcquire => Some(DurableFlowJobPurposeV1::Acquire),
            DurableFlowCallV1::WriterActivate => Some(DurableFlowJobPurposeV1::Activate),
            DurableFlowCallV1::ActiveVerify => Some(DurableFlowJobPurposeV1::ReconcilePrepare),
            _ => None,
        };
        let sample = purpose.and_then(|_| self.client_sample());
        self.update(|active| {
            let bit = 1u16 << (slot as u8);
            if active.invalid_calls & bit != 0 {
                self.mark_incomplete();
                return;
            }
            let value = active.calls.slot(slot);
            if *value == DurableFlowCallOutcomeV1::NotObserved {
                *value = DurableFlowCallOutcomeV1::Entered;
                if let Some(purpose) = purpose {
                    self.client_span(active, purpose, sample, false);
                }
            } else {
                active.invalid_calls |= bit;
                self.mark_incomplete();
            }
        });
    }
    pub(crate) fn call_return<T, E>(
        &self,
        slot: DurableFlowCallV1,
        result: &std::result::Result<T, E>,
    ) {
        self.update(|active| {
            let bit = 1u16 << (slot as u8);
            if active.invalid_calls & bit != 0 {
                self.mark_incomplete();
                return;
            }
            let value = active.calls.slot(slot);
            if *value == DurableFlowCallOutcomeV1::Entered {
                *value = if result.is_ok() {
                    DurableFlowCallOutcomeV1::ReturnedOk
                } else {
                    DurableFlowCallOutcomeV1::ReturnedErr
                };
            } else {
                active.invalid_calls |= bit;
                self.mark_incomplete();
            }
        });
    }
    /// Only an already-existing fixture branch may report absent output here.
    /// Absence does not create a job or a typed cause, and cannot retract a
    /// previously observed actual Result.
    pub(crate) fn missing_completion(&self) {
        self.update(|active| {
            active.completion.receive = DurableFlowReceiveV1::Missing;
            active.completion.presentation = DurableFlowPresentationV1::NotObserved;
        });
    }
    pub(crate) fn job_start(
        &self,
        purpose: DurableFlowJobPurposeV1,
        epoch: u64,
    ) -> DurableFlowJobObservationV1 {
        let mut job = DurableFlowJobObservationV1 {
            observer: self.clone(),
            identity: None,
        };
        if !job_matches_operation(self.operation, purpose) {
            self.mark_incomplete();
            return job;
        }
        job.identity = self
            .update(|active| {
                let Some(serial) = active.next_job.checked_add(1) else {
                    self.mark_incomplete();
                    return None;
                };
                active.next_job = serial;
                let identity = JobIdentity {
                    serial,
                    purpose,
                    epoch,
                };
                active.job = Some(identity);
                active.worker_result = DurableFlowResultV1::NotObserved;
                active.worker_error = None;
                active.worker_timing = WorkerTimingV1::default();
                active.completion = DurableFlowCompletionV1 {
                    purpose: Some(purpose),
                    result: DurableFlowResultV1::NotObserved,
                    receive: DurableFlowReceiveV1::Pending,
                    presentation: DurableFlowPresentationV1::NotObserved,
                };
                Some(identity)
            })
            .flatten();
        job
    }
    /// First lower cause is data; returned_error is the final ORIGINAL kernel
    /// error and alone may determine the existing operational mapping.
    pub(crate) fn observe_transport<T>(
        &self,
        purpose: DurableFlowTransportPurposeV1,
        stage: DurableFlowStageV1,
        callback_stage: Option<DurableFlowCallbackStageV1>,
        result: std::result::Result<T, CheckedHistoryFailureV1>,
    ) -> std::result::Result<T, wholepact_authority::AuthorityError> {
        let worker_purpose = match purpose {
            DurableFlowTransportPurposeV1::Acquire => Some(DurableFlowJobPurposeV1::Acquire),
            DurableFlowTransportPurposeV1::Activate => Some(DurableFlowJobPurposeV1::Activate),
            DurableFlowTransportPurposeV1::Verify => {
                Some(DurableFlowJobPurposeV1::ReconcilePrepare)
            }
            DurableFlowTransportPurposeV1::Reserve => None,
        };
        if let Some(purpose) = worker_purpose {
            if let Some(sample) = self.client_sample() {
                self.update(|active| self.client_span(active, purpose, Some(sample), true));
            }
        }
        match result {
            Ok(value) => Ok(value),
            Err(failure) => {
                let returned = failure.returned_error();
                self.record_error(stage, &failure.error());
                let Some(projected) = lower_stage(failure.stage()) else {
                    self.mark_incomplete();
                    return Err(returned);
                };
                if !lower_phase_matches(purpose, failure.measurement().phase()) {
                    self.mark_incomplete();
                } else {
                    let lower = DurableFlowTransportFailureV1 {
                        purpose,
                        stage: projected,
                        callback_stage,
                        failure,
                    };
                    self.update(|active| {
                        if active.lower.is_none() {
                            active.lower = Some(Arc::new(lower));
                        }
                    });
                }
                Err(returned)
            }
        }
    }
    pub(crate) fn finish(&self, result: DurableFlowResultV1) -> Option<DurableFlowDiagnosticV1> {
        if result == DurableFlowResultV1::NotObserved {
            self.mark_incomplete();
            return None;
        }
        let Ok(mut data) = self.shared.data.try_lock() else {
            self.mark_incomplete();
            return None;
        };
        if !data
            .active
            .as_ref()
            .is_some_and(|a| Some(a.attempt) == self.attempt && a.operation == self.operation)
        {
            self.mark_incomplete();
            return None;
        }
        let Some(attempt) = self.attempt else {
            self.mark_incomplete();
            return None;
        };
        let Some(sealed) = attempt.checked_add(1) else {
            self.mark_incomplete();
            return None;
        };
        // This CAS is the snapshot linearization point. An arm that already
        // began, including one that lost try_lock, prevents the old snapshot.
        if self
            .shared
            .generation
            .compare_exchange(attempt, sealed, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.mark_incomplete();
            return None;
        }
        let Some(active) = data.active.take() else {
            self.mark_incomplete();
            return None;
        };
        if result == DurableFlowResultV1::ReturnedOk {
            return None;
        }
        Some(self.snapshot_active(&active, result))
    }
    fn snapshot_active(
        &self,
        active: &ActiveObservation,
        result: DurableFlowResultV1,
    ) -> DurableFlowDiagnosticV1 {
        let (clamped, lower_incomplete) = lower_flags(active.lower.as_deref());
        DurableFlowDiagnosticV1 {
            operation: active.operation,
            first_error: active.first_error,
            terminal_error: active.terminal_error,
            fixture_result: result,
            completion: active.completion,
            call_outcomes: active.calls,
            lower_call_measurement: active.lower.clone(),
            after_drain: None,
            lifecycle: None,
            clamped,
            incomplete: lower_incomplete
                || self.shared.incomplete_generation.load(Ordering::Acquire) >= active.attempt,
        }
    }
    /// The early view does not seal or consume the same worker's collector.
    fn failure_snapshot(&self) -> Option<(DurableFlowDiagnosticV1, Option<JobIdentity>)> {
        self.update(|active| {
            let diagnostic = self.snapshot_active(active, DurableFlowResultV1::ReturnedErr);
            if self.attempt != Some(self.shared.generation.load(Ordering::Acquire)) {
                self.mark_incomplete();
                None
            } else {
                Some((diagnostic, active.job))
            }
        })
        .flatten()
    }
    pub(crate) fn record_drain<T>(&self, original: &std::result::Result<T, crate::Error>) {
        let error = original
            .as_ref()
            .err()
            .map(|e| e.classify(DurableFlowStageV1::Close));
        self.update(|active| {
            if active.drain.is_some() {
                self.mark_incomplete();
                return;
            }
            active.drain = Some((
                if original.is_ok() {
                    DurableFlowResultV1::ReturnedOk
                } else {
                    DurableFlowResultV1::ReturnedErr
                },
                error,
            ));
        });
    }
    fn finish_after_drain(
        &self,
        identity: Option<JobIdentity>,
        initial_lower: bool,
        initial_result: DurableFlowResultV1,
    ) -> Option<FinishedAfterDrainV1> {
        let Ok(mut data) = self.shared.data.try_lock() else {
            self.mark_incomplete();
            return None;
        };
        let Some(active) = data
            .active
            .as_ref()
            .filter(|a| Some(a.attempt) == self.attempt && a.operation == self.operation)
        else {
            self.mark_incomplete();
            return None;
        };
        let Some((drain_result, drain_error)) = active.drain else {
            self.mark_incomplete();
            return None;
        };
        let Some(attempt) = self.attempt else {
            self.mark_incomplete();
            return None;
        };
        let Some(sealed) = attempt.checked_add(1) else {
            self.mark_incomplete();
            return None;
        };
        if self
            .shared
            .generation
            .compare_exchange(attempt, sealed, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.mark_incomplete();
            return None;
        }
        let active = data.active.take()?;
        if active.job != identity {
            // A same-attempt replacement job cannot donate any late CALL,
            // lower-transport, worker or timing evidence to the initial job.
            self.mark_incomplete();
            return None;
        }
        let (worker_result, worker_error, worker_timing) = if identity.is_some() {
            (
                active.worker_result,
                active.worker_error,
                active.worker_timing,
            )
        } else {
            (
                DurableFlowResultV1::NotObserved,
                None,
                WorkerTimingV1::default(),
            )
        };
        let consistent = initial_result == DurableFlowResultV1::NotObserved
            || worker_result == DurableFlowResultV1::NotObserved
            || initial_result == worker_result;
        let lower = if initial_lower { None } else { active.lower };
        let (clamped, lower_incomplete) = lower_flags(lower.as_deref());
        Some(FinishedAfterDrainV1 {
            diagnostic: DurableFlowAfterDrainV1 {
                drain_result,
                drain_error,
                worker_purpose: identity.map(|job| job.purpose),
                worker_result: if consistent {
                    worker_result
                } else {
                    DurableFlowResultV1::NotObserved
                },
                worker_error: if consistent { worker_error } else { None },
                call_outcomes: active.calls,
                lower_call_measurement: lower,
                clamped,
                incomplete: !consistent
                    || lower_incomplete
                    || self.shared.incomplete_generation.load(Ordering::Acquire) >= attempt,
            },
            worker_timing,
        })
    }
}
struct FinishedAfterDrainV1 {
    diagnostic: DurableFlowAfterDrainV1,
    worker_timing: WorkerTimingV1,
}
fn lower_flags(lower: Option<&DurableFlowTransportFailureV1>) -> (bool, bool) {
    lower
        .map(|lower| {
            (
                lower.measurement().clamped(),
                lower.measurement().incomplete(),
            )
        })
        .unwrap_or((false, false))
}
fn job_matches_operation(
    operation: DurableFlowOperationV1,
    purpose: DurableFlowJobPurposeV1,
) -> bool {
    use DurableFlowJobPurposeV1 as J;
    match operation {
        DurableFlowOperationV1::WriterReconcile => matches!(
            purpose,
            J::AcquirePrepare
                | J::Acquire
                | J::ActivationPrepare
                | J::Activate
                | J::ReconcilePrepare
                | J::Reconcile
        ),
        DurableFlowOperationV1::FinancialImport => purpose == J::Import,
        DurableFlowOperationV1::InitialSign => matches!(purpose, J::WalletReview | J::Sign),
        DurableFlowOperationV1::RetainedRetry => false,
        DurableFlowOperationV1::ResultService => purpose == J::ResultService,
    }
}
impl DurableFlowJobObservationV1 {
    pub(crate) fn purpose(&self) -> Option<DurableFlowJobPurposeV1> {
        self.identity.map(|identity| identity.purpose)
    }
    pub(crate) fn started(&self) {
        let Some((started, thread)) = self.observer.client_sample() else {
            return;
        };
        self.update(|active| {
            if active.worker_timing.started.is_some() {
                active.worker_timing.incomplete = true;
                return;
            }
            active.worker_timing = WorkerTimingV1 {
                identity: self.identity,
                thread: Some(thread),
                started: Some(started),
                ..WorkerTimingV1::default()
            };
        });
    }
    /// Observe the actual borrowed worker return before its unchanged send.
    /// This never changes receive, presentation, or the fixture's error.
    pub(crate) fn returned<T, E: DurableFlowClassifyV1>(
        &self,
        stage: DurableFlowStageV1,
        original: &std::result::Result<T, E>,
    ) {
        let category = original.as_ref().err().map(|e| e.classify(stage));
        self.update(|active| {
            if active.worker_result != DurableFlowResultV1::NotObserved {
                self.observer.mark_incomplete();
                return;
            }
            active.worker_result = if original.is_ok() {
                DurableFlowResultV1::ReturnedOk
            } else {
                DurableFlowResultV1::ReturnedErr
            };
            active.worker_error = category;
            if active.first_error.is_none() {
                active.first_error = category;
            }
        });
    }
    fn update(&self, apply: impl FnOnce(&mut ActiveObservation)) {
        self.observer.update(|active| {
            if self.identity.is_none() || active.job != self.identity {
                self.observer.mark_incomplete();
                return;
            }
            apply(active);
        });
    }
    pub(crate) fn received<T, E: DurableFlowClassifyV1>(
        &self,
        stage: DurableFlowStageV1,
        result: &std::result::Result<T, E>,
    ) {
        let category = result.as_ref().err().map(|e| e.classify(stage));
        self.update(|active| {
            if active.completion.receive != DurableFlowReceiveV1::Pending
                || active.completion.result != DurableFlowResultV1::NotObserved
            {
                self.observer.mark_incomplete();
                return;
            }
            if let Some(category) = category {
                if active.first_error.is_none() {
                    active.first_error = Some(category);
                }
            }
            complete_job(
                active,
                if result.is_ok() {
                    DurableFlowResultV1::ReturnedOk
                } else {
                    DurableFlowResultV1::ReturnedErr
                },
                &self.observer,
            );
        });
    }
    /// Actual Host command completion, including an original untyped sentinel.
    /// This method deliberately does not create a typed error category.
    pub(crate) fn completed(&self, result: DurableFlowResultV1) {
        self.update(|active| complete_job(active, result, &self.observer));
    }
    pub(crate) fn pending(&self) {
        self.update(|active| {
            if active.completion.receive != DurableFlowReceiveV1::Pending {
                self.observer.mark_incomplete();
            }
        });
    }
    pub(crate) fn disconnected(&self) {
        self.update(|active| {
            if active.completion.result != DurableFlowResultV1::NotObserved
                || active.completion.receive != DurableFlowReceiveV1::Pending
            {
                self.observer.mark_incomplete();
                return;
            }
            active.completion.receive = DurableFlowReceiveV1::Disconnected;
        });
    }
    pub(crate) fn invalidated(&self) {
        self.update(|active| {
            if active.completion.receive == DurableFlowReceiveV1::Invalidated
                || active.completion.presentation == DurableFlowPresentationV1::Accepted
            {
                self.observer.mark_incomplete();
                return;
            }
            active.completion.receive = DurableFlowReceiveV1::Invalidated;
        });
    }
    pub(crate) fn missing(&self) {
        self.update(|active| {
            active.completion.receive = DurableFlowReceiveV1::Missing;
            // A later missing output cannot retract an actually observed result.
            active.completion.presentation = DurableFlowPresentationV1::NotObserved;
        });
    }
    pub(crate) fn presentation(&self, presentation: DurableFlowPresentationV1) {
        self.update(|active| {
            let c = &mut active.completion;
            let allowed = match presentation {
                DurableFlowPresentationV1::NotObserved => {
                    c.presentation == DurableFlowPresentationV1::NotObserved
                }
                DurableFlowPresentationV1::Accepted => {
                    c.receive == DurableFlowReceiveV1::Received
                        && c.result == DurableFlowResultV1::ReturnedOk
                }
                DurableFlowPresentationV1::Suppressed => matches!(
                    c.receive,
                    DurableFlowReceiveV1::Received | DurableFlowReceiveV1::Invalidated
                ),
            };
            if !allowed || c.presentation != DurableFlowPresentationV1::NotObserved {
                self.observer.mark_incomplete();
            } else {
                c.presentation = presentation;
            }
        });
    }
}
fn complete_job(
    active: &mut ActiveObservation,
    result: DurableFlowResultV1,
    observer: &DurableFlowObserverV1,
) {
    if result == DurableFlowResultV1::NotObserved
        || active.completion.result != DurableFlowResultV1::NotObserved
        || active.completion.receive != DurableFlowReceiveV1::Pending
    {
        observer.mark_incomplete();
        return;
    }
    active.completion.result = result;
    active.completion.receive = DurableFlowReceiveV1::Received;
}
/// Borrow before an existing map/discard and move the original non-Clone Result.
pub(crate) fn observe_result<T, E: DurableFlowClassifyV1>(
    observer: Option<&DurableFlowObserverV1>,
    stage: DurableFlowStageV1,
    original: std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    if let (Some(observer), Err(error)) = (observer, &original) {
        observer.record_error(stage, error);
    }
    original
}
/// The production CALL observation kernel. Each actual expression runs once;
/// there is no diagnostic guard, clock or check around it when observer is None.
pub(crate) fn observe_call<T, E: DurableFlowClassifyV1>(
    observer: Option<&DurableFlowObserverV1>,
    slot: DurableFlowCallV1,
    stage: DurableFlowStageV1,
    call: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    if let Some(observer) = observer {
        observer.call_enter(slot);
    }
    let original = call();
    if let Some(observer) = observer {
        observer.call_return(slot, &original);
    }
    observe_result(observer, stage, original)
}
fn lower_phase_matches(
    purpose: DurableFlowTransportPurposeV1,
    phase: Option<CheckedHistoryPhaseV1>,
) -> bool {
    match phase {
        None => true,
        Some(CheckedHistoryPhaseV1::Acquire) => purpose == DurableFlowTransportPurposeV1::Acquire,
        Some(CheckedHistoryPhaseV1::Activate) => purpose == DurableFlowTransportPurposeV1::Activate,
        Some(CheckedHistoryPhaseV1::Verify) => purpose == DurableFlowTransportPurposeV1::Verify,
        Some(CheckedHistoryPhaseV1::Reserve) => purpose == DurableFlowTransportPurposeV1::Reserve,
        Some(
            CheckedHistoryPhaseV1::Snapshot
            | CheckedHistoryPhaseV1::Page
            | CheckedHistoryPhaseV1::Admission,
        ) => false,
    }
}
fn lower_stage(stage: CheckedHistoryStageV1) -> Option<DurableFlowTransportStageV1> {
    use CheckedHistoryStageV1 as S;
    use DurableFlowTransportStageV1 as T;
    Some(match stage {
        S::FlowRequestValidation => T::RequestValidation,
        S::FlowBinding => T::Binding,
        S::FlowSession => T::Session,
        S::CallerDeadline => T::CallerDeadline,
        S::ExchangeDeadline => T::ExchangeDeadline,
        S::SourceCallback => T::SourceCallback,
        S::FlowConnect => T::Connect,
        S::FlowHandshake => T::Handshake,
        S::FlowPeerBinding => T::PeerBinding,
        S::FlowRequestBuild => T::RequestBuild,
        S::FlowRequestWrite => T::RequestWrite,
        S::FlowResponseRead => T::ResponseRead,
        S::FlowResponse => T::Response,
        S::FlowSnapshotValidation => T::SnapshotValidation,
        S::FlowReceiptValidation => T::ReceiptValidation,
        S::FlowCommittedHeadValidation => T::CommittedHeadValidation,
        S::FlowFinalValidation => T::FinalValidation,
        S::Bounds => T::Bounds,
        S::SnapshotConnect
        | S::SnapshotHandshake
        | S::SnapshotPeerBinding
        | S::SnapshotRequestBuild
        | S::SnapshotRequestWrite
        | S::SnapshotResponseRead
        | S::SnapshotResponse
        | S::SnapshotValidation
        | S::PageConnect
        | S::PageHandshake
        | S::PagePeerBinding
        | S::PageRequestBuild
        | S::PageRequestWrite
        | S::PageResponseRead
        | S::PageResponse
        | S::PageValidation
        | S::EventReplay
        | S::FinalValidation
        | S::AdmissionRequestValidation
        | S::AdmissionBinding
        | S::AdmissionConnect
        | S::AdmissionHandshake
        | S::AdmissionPeerBinding
        | S::AdmissionRequestBuild
        | S::AdmissionRequestWrite
        | S::AdmissionResponseRead
        | S::AdmissionResponse
        | S::AdmissionSnapshotValidation
        | S::AdmissionCommittedHeadValidation
        | S::AdmissionFinalValidation => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;

    struct NonCloneError {
        allocation: Box<u8>,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for NonCloneError {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl DurableFlowClassifyV1 for NonCloneError {
        fn classify(&self, stage: DurableFlowStageV1) -> DurableFlowErrorV1 {
            super::super::BridgeError::Ipc.classify(stage)
        }
    }
    fn failed(observer: &DurableFlowObserverV1) -> DurableFlowDiagnosticV1 {
        match observer.finish(DurableFlowResultV1::ReturnedErr) {
            Some(value) => value,
            None => panic!("expected inert failure data"),
        }
    }
    #[test]
    fn durable_flow_pending_snapshot_preserves_original_failure_and_observes_actual_return_after_drain(
    ) {
        for worker_ok in [false, true] {
            let collector = DurableFlowCollectorV1::default();
            let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
            let job = observer.job_start(DurableFlowJobPurposeV1::Acquire, 3);
            observer.call_enter(DurableFlowCallV1::WriterAcquire);
            let original_error = crate::Error::Io(std::io::Error::from_raw_os_error(1761));
            observer.record_terminal(DurableFlowStageV1::AcquireCall, &original_error);
            let mut failure = DurableFlowFailureV1::new_pending(original_error, observer.clone());
            let initial = failure.diagnostic().unwrap();
            assert!(initial.completion().receive() == DurableFlowReceiveV1::Pending);
            assert!(initial.completion().result() == DurableFlowResultV1::NotObserved);
            assert!(initial.first_error().is_none());
            assert!(initial.after_drain().is_none());
            assert!(initial.call_outcomes().writer_acquire() == DurableFlowCallOutcomeV1::Entered);
            let original: std::result::Result<(), crate::Error> = if worker_ok {
                Ok(())
            } else {
                Err(crate::Error::Locked)
            };
            job.invalidated();
            job.returned(DurableFlowStageV1::AcquireCall, &original);
            observer.call_return(DurableFlowCallV1::WriterAcquire, &original);
            observer.record_drain(&Ok::<(), crate::Error>(()));
            failure.finalize_after_drain();
            failure.finalize_after_drain();
            let initial = failure.diagnostic().unwrap();
            assert!(initial.completion().receive() == DurableFlowReceiveV1::Pending);
            assert!(initial.completion().result() == DurableFlowResultV1::NotObserved);
            assert!(initial.completion().presentation() == DurableFlowPresentationV1::NotObserved);
            assert!(initial.first_error().is_none());
            assert!(initial.terminal_error().unwrap().code() == DurableFlowErrorCodeV1::SignerIo);
            assert!(initial.call_outcomes().writer_acquire() == DurableFlowCallOutcomeV1::Entered);
            let after = initial.after_drain().unwrap();
            assert!(
                after.drain_result() == DurableFlowResultV1::ReturnedOk
                    && after.drain_error().is_none()
            );
            assert!(after.worker_purpose() == Some(DurableFlowJobPurposeV1::Acquire));
            assert!(
                after.worker_result()
                    == if worker_ok {
                        DurableFlowResultV1::ReturnedOk
                    } else {
                        DurableFlowResultV1::ReturnedErr
                    }
            );
            assert!(after.worker_error().is_some() == !worker_ok);
            assert!(
                after.call_outcomes().writer_acquire()
                    == if worker_ok {
                        DurableFlowCallOutcomeV1::ReturnedOk
                    } else {
                        DurableFlowCallOutcomeV1::ReturnedErr
                    }
            );
            assert!(!after.incomplete());
            assert!(
                matches!(failure.into_error(), crate::Error::Io(error) if error.raw_os_error() == Some(1761))
            );
        }
    }
    #[test]
    fn durable_flow_worker_borrow_preserves_nonclone_result_once_after_receiver_drop_and_cancel() {
        for cancelled in [false, true] {
            let collector = DurableFlowCollectorV1::default();
            let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
            let job = observer.job_start(DurableFlowJobPurposeV1::Acquire, 9);
            let mut failure =
                DurableFlowFailureV1::new_pending(crate::Error::Locked, observer.clone());
            let drops = Arc::new(AtomicUsize::new(0));
            let error = NonCloneError {
                allocation: Box::new(19),
                drops: drops.clone(),
            };
            let pointer: *const u8 = &*error.allocation;
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            drop(receive);
            let calls = Cell::new(0);
            let work = || {
                calls.set(calls.get() + 1);
                if cancelled {
                    Err(error)
                } else {
                    drop(error);
                    Ok(Box::new(23))
                }
            };
            let original = work();
            job.returned(DurableFlowStageV1::AcquireCall, &original);
            let forwarded = send.send(original).err().unwrap().0;
            assert!(calls.get() == 1);
            if cancelled {
                let Err(original) = forwarded else {
                    panic!("cancelled worker error changed");
                };
                assert!(std::ptr::eq(pointer, &*original.allocation));
                assert!(drops.load(Ordering::Relaxed) == 0);
                drop(original);
            } else {
                assert!(matches!(forwarded, Ok(value) if *value == 23));
            }
            assert!(drops.load(Ordering::Relaxed) == 1);
            observer.record_drain(&Ok::<(), crate::Error>(()));
            failure.finalize_after_drain();
            let diagnostic = failure.diagnostic().unwrap();
            assert!(diagnostic.completion().receive() == DurableFlowReceiveV1::Pending);
            assert!(
                diagnostic.completion().presentation() == DurableFlowPresentationV1::NotObserved
            );
            assert!(
                diagnostic.after_drain().unwrap().worker_result()
                    == if cancelled {
                        DurableFlowResultV1::ReturnedErr
                    } else {
                        DurableFlowResultV1::ReturnedOk
                    }
            );
        }
    }
    #[test]
    fn durable_flow_after_drain_absence_error_and_duplicate_are_honest() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
        let mut absent = DurableFlowFailureV1::new_pending(crate::Error::Locked, observer.clone());
        absent.finalize_after_drain();
        assert!(absent.diagnostic().unwrap().after_drain().is_none());
        assert!(matches!(absent.into_error(), crate::Error::Locked));
        let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
        let mut failure =
            DurableFlowFailureV1::new_pending(crate::Error::Uncertain, observer.clone());
        observer.record_drain(&Err::<(), _>(crate::Error::Authentication));
        observer.record_drain(&Ok::<(), crate::Error>(()));
        failure.finalize_after_drain();
        let after = failure.diagnostic().unwrap().after_drain().unwrap();
        assert!(after.drain_result() == DurableFlowResultV1::ReturnedErr);
        assert!(
            after.drain_error().unwrap().code() == DurableFlowErrorCodeV1::SignerAuthentication
        );
        assert!(after.drain_error().unwrap().stage() == DurableFlowStageV1::Close);
        assert!(after.worker_purpose().is_none());
        assert!(
            after.worker_result() == DurableFlowResultV1::NotObserved
                && after.worker_error().is_none()
        );
        assert!(after.incomplete());
        assert!(matches!(failure.into_error(), crate::Error::Uncertain));
    }
    #[test]
    fn durable_flow_after_drain_rearm_stale_job_contention_and_duplicates_never_attribute_results()
    {
        for mode in 0..5 {
            let collector = DurableFlowCollectorV1::default();
            let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
            let job = observer.job_start(DurableFlowJobPurposeV1::Acquire, 1);
            let mut failure =
                DurableFlowFailureV1::new_pending(crate::Error::Locked, observer.clone());
            match mode {
                0 => {
                    let current = collector.arm(DurableFlowOperationV1::WriterReconcile);
                    job.returned(
                        DurableFlowStageV1::AcquireCall,
                        &Err::<(), _>(crate::Error::Authentication),
                    );
                    observer.record_drain(&Ok::<(), crate::Error>(()));
                    failure.finalize_after_drain();
                    assert!(failure.diagnostic().unwrap().after_drain().is_none());
                    assert!(failed(&current).first_error().is_none());
                }
                1 => {
                    let next = observer.job_start(DurableFlowJobPurposeV1::Acquire, 2);
                    job.returned(
                        DurableFlowStageV1::AcquireCall,
                        &Err::<(), _>(crate::Error::Authentication),
                    );
                    next.returned(DurableFlowStageV1::AcquireCall, &Ok::<(), crate::Error>(()));
                    observer.record_drain(&Ok::<(), crate::Error>(()));
                    failure.finalize_after_drain();
                    assert!(failure.diagnostic().unwrap().after_drain().is_none());
                }
                2 => {
                    let guard = collector.shared.data.lock().unwrap();
                    job.returned(
                        DurableFlowStageV1::AcquireCall,
                        &Err::<(), _>(crate::Error::Authentication),
                    );
                    drop(guard);
                    observer.record_drain(&Ok::<(), crate::Error>(()));
                    failure.finalize_after_drain();
                    let after = failure.diagnostic().unwrap().after_drain().unwrap();
                    assert!(
                        after.worker_result() == DurableFlowResultV1::NotObserved
                            && after.worker_error().is_none()
                    );
                    assert!(after.incomplete());
                }
                3 => {
                    job.returned(DurableFlowStageV1::AcquireCall, &Ok::<(), crate::Error>(()));
                    job.returned(
                        DurableFlowStageV1::AcquireCall,
                        &Err::<(), _>(crate::Error::Authentication),
                    );
                    observer.record_drain(&Ok::<(), crate::Error>(()));
                    failure.finalize_after_drain();
                    let after = failure.diagnostic().unwrap().after_drain().unwrap();
                    assert!(
                        after.worker_result() == DurableFlowResultV1::ReturnedOk
                            && after.worker_error().is_none()
                    );
                    assert!(after.incomplete());
                }
                _ => {
                    let guard = collector.shared.data.lock().unwrap();
                    let mut missing =
                        DurableFlowFailureV1::new_pending(crate::Error::Locked, observer.clone());
                    drop(guard);
                    observer.record_drain(&Ok::<(), crate::Error>(()));
                    missing.finalize_after_drain();
                    assert!(missing.diagnostic().is_none());
                    assert!(matches!(missing.into_error(), crate::Error::Locked));
                }
            }
        }
    }
    #[test]
    fn durable_flow_after_drain_original_received_result_mismatch_is_not_rewritten() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
        let job = observer.job_start(DurableFlowJobPurposeV1::Acquire, 1);
        job.received(DurableFlowStageV1::AcquireCall, &Ok::<(), crate::Error>(()));
        let mut failure = DurableFlowFailureV1::new_pending(crate::Error::Locked, observer.clone());
        job.returned(
            DurableFlowStageV1::AcquireCall,
            &Err::<(), _>(crate::Error::Authentication),
        );
        observer.record_drain(&Ok::<(), crate::Error>(()));
        failure.finalize_after_drain();
        let diagnostic = failure.diagnostic().unwrap();
        assert!(diagnostic.completion().receive() == DurableFlowReceiveV1::Received);
        assert!(diagnostic.completion().result() == DurableFlowResultV1::ReturnedOk);
        let after = diagnostic.after_drain().unwrap();
        assert!(
            after.worker_result() == DurableFlowResultV1::NotObserved
                && after.worker_error().is_none()
        );
        assert!(after.incomplete());
    }
    #[test]
    fn durable_lifecycle_fixed_deadline_cost_caps_first_points_and_none_clock_are_explicit() {
        assert!(lifecycle_optional_clock(false, || panic!("None must not read a clock")).is_none());
        let calls = Cell::new(0);
        let original = observe_pending_wait_v1(None, DurablePendingWaitKindV1::Liveness, || {
            calls.set(calls.get() + 1);
            Err::<(), _>(crate::Error::Locked)
        });
        assert!(calls.get() == 1 && matches!(original, Err(crate::Error::Locked)));
        let start = Instant::now();
        let lifecycle = DurableLifecycleObserverV1::new(start + Duration::from_secs(120));
        lifecycle.point_at(
            DurableLifecyclePointV1::NativeOpenComplete,
            start + Duration::from_secs(2),
        );
        lifecycle.point_at(
            DurableLifecyclePointV1::NativeOpenComplete,
            start + Duration::from_secs(3),
        );
        lifecycle.point_at(
            DurableLifecyclePointV1::AfterDrain,
            start + Duration::from_secs(601),
        );
        lifecycle.cost(DurablePendingWaitKindV1::Poll, Duration::from_micros(7));
        lifecycle.cost(DurablePendingWaitKindV1::Poll, Duration::from_micros(11));
        lifecycle.cost(DurablePendingWaitKindV1::Liveness, Duration::from_secs(601));
        {
            let mut data = lifecycle.shared.data.lock().unwrap();
            data.pending_wait[DurablePendingWaitKindV1::FullPrecheck as usize].calls =
                LIFECYCLE_COUNT_CAP;
        }
        lifecycle.cost(DurablePendingWaitKindV1::FullPrecheck, Duration::ZERO);
        let diagnostic = lifecycle
            .snapshot(
                DurableFlowOperationV1::WriterReconcile,
                None,
                WorkerTimingV1::default(),
                false,
            )
            .unwrap();
        let point = diagnostic
            .point(DurableLifecyclePointV1::NativeOpenComplete)
            .unwrap();
        assert!(point.age_us() == 2_000_000 && point.remaining_us() == 118_000_000);
        let point = diagnostic
            .point(DurableLifecyclePointV1::AfterDrain)
            .unwrap();
        assert!(point.age_us() == LIFECYCLE_CAP_US && point.remaining_us() == 0);
        let cost = diagnostic.pending_wait(DurablePendingWaitKindV1::Poll);
        assert!(cost.calls() == 2 && cost.total_us() == 18 && cost.max_us() == 11);
        assert!(
            diagnostic
                .pending_wait(DurablePendingWaitKindV1::Liveness)
                .total_us()
                == LIFECYCLE_CAP_US
        );
        assert!(
            diagnostic
                .pending_wait(DurablePendingWaitKindV1::FullPrecheck)
                .calls()
                == LIFECYCLE_COUNT_CAP
        );
        assert!(diagnostic.clamped() && diagnostic.incomplete());
        assert!(diagnostic.worker_purpose().is_none());
        assert!(diagnostic.worker_started_to_client_entry_us().is_none());
        assert!(diagnostic.worker_started_to_client_return_us().is_none());
        assert!(lifecycle
            .snapshot(
                DurableFlowOperationV1::InitialSign,
                None,
                WorkerTimingV1::default(),
                false
            )
            .is_none());
    }
    #[test]
    fn durable_lifecycle_actual_worker_thread_job_and_attempt_gate_client_spans() {
        let collector = DurableFlowCollectorV1::default();
        let lifecycle = DurableLifecycleObserverV1::new(Instant::now() + Duration::from_secs(120));
        let observer = collector
            .arm(DurableFlowOperationV1::WriterReconcile)
            .with_lifecycle(Some(&lifecycle));
        let job = observer.job_start(DurableFlowJobPurposeV1::Acquire, 1);
        job.started();
        let wrong_thread = observer.clone();
        std::thread::spawn(move || {
            let sample = wrong_thread.client_sample();
            wrong_thread.update(|active| {
                wrong_thread.client_span(active, DurableFlowJobPurposeV1::Acquire, sample, false)
            });
        })
        .join()
        .unwrap();
        assert!(observer
            .update(|active| active.worker_timing.client_entry_us)
            .flatten()
            .is_none());
        observer.call_enter(DurableFlowCallV1::WriterAcquire);
        let returned = observer.observe_transport(
            DurableFlowTransportPurposeV1::Acquire,
            DurableFlowStageV1::AcquireCall,
            None,
            Ok::<(), CheckedHistoryFailureV1>(()),
        );
        assert!(returned.is_ok());
        observer.call_return(DurableFlowCallV1::WriterAcquire, &returned);
        let mut failure = DurableFlowFailureV1::new_pending(crate::Error::Locked, observer.clone());
        assert!(failure.diagnostic().unwrap().lifecycle().is_none());
        observer.record_drain(&Ok::<(), crate::Error>(()));
        failure.finalize_after_drain();
        let diagnostic = failure.diagnostic().unwrap().lifecycle().unwrap();
        assert!(diagnostic.worker_purpose() == Some(DurableFlowJobPurposeV1::Acquire));
        assert!(diagnostic.worker_started_to_client_entry_us().is_some());
        assert!(
            diagnostic.worker_started_to_client_return_us()
                >= diagnostic.worker_started_to_client_entry_us()
        );
        assert!(diagnostic.incomplete());

        let observer = collector
            .arm(DurableFlowOperationV1::WriterReconcile)
            .with_lifecycle(Some(&lifecycle));
        let old = observer.job_start(DurableFlowJobPurposeV1::Acquire, 2);
        old.started();
        let next = observer.job_start(DurableFlowJobPurposeV1::Acquire, 3);
        let next_worker = next.clone();
        std::thread::spawn(move || next_worker.started())
            .join()
            .unwrap();
        old.started();
        observer.call_enter(DurableFlowCallV1::WriterAcquire);
        assert!(observer
            .update(|active| active.worker_timing.client_entry_us)
            .flatten()
            .is_none());
        old.returned(
            DurableFlowStageV1::AcquireCall,
            &Err::<(), _>(crate::Error::Authentication),
        );
        assert!(
            observer.update(|active| active.worker_result).unwrap()
                == DurableFlowResultV1::NotObserved
        );
        let current = collector
            .arm(DurableFlowOperationV1::WriterReconcile)
            .with_lifecycle(Some(&lifecycle));
        next.started();
        assert!(current
            .update(|active| active.worker_timing.started)
            .flatten()
            .is_none());
    }
    const CALLS: [DurableFlowCallV1; 11] = [
        DurableFlowCallV1::WriterAcquire,
        DurableFlowCallV1::WriterActivate,
        DurableFlowCallV1::ActiveVerify,
        DurableFlowCallV1::Reconciliation,
        DurableFlowCallV1::SessionInvalidation,
        DurableFlowCallV1::Release,
        DurableFlowCallV1::RequestRetention,
        DurableFlowCallV1::Reservation,
        DurableFlowCallV1::PermitRetention,
        DurableFlowCallV1::KeyUse,
        DurableFlowCallV1::ResultRetention,
    ];
    #[test]
    fn durable_flow_original_nonclone_result_is_forwarded_once_even_when_contended() {
        for mode in 0..3 {
            let collector = DurableFlowCollectorV1::default();
            let observer = collector.arm(DurableFlowOperationV1::InitialSign);
            let drops = Arc::new(AtomicUsize::new(0));
            let error = NonCloneError {
                allocation: Box::new(7),
                drops: drops.clone(),
            };
            let pointer: *const u8 = &*error.allocation;
            let calls = Cell::new(0);
            let mappings = Cell::new(0);
            let guard = if mode == 2 {
                Some(collector.shared.data.lock().unwrap())
            } else {
                None
            };
            let result: std::result::Result<(), NonCloneError> = observe_call(
                if mode == 0 { None } else { Some(&observer) },
                DurableFlowCallV1::Release,
                DurableFlowStageV1::Release,
                || {
                    calls.set(calls.get() + 1);
                    Err(error)
                },
            )
            .map_err(|original| {
                mappings.set(mappings.get() + 1);
                original
            });
            assert!(calls.get() == 1 && mappings.get() == 1 && drops.load(Ordering::Relaxed) == 0);
            let original = match result {
                Err(error) => error,
                Ok(()) => panic!("original error changed"),
            };
            assert!(std::ptr::eq(pointer, &*original.allocation));
            drop(guard);
            let diagnostic = failed(&observer);
            if mode == 1 {
                assert!(diagnostic
                    .first_error()
                    .is_some_and(|e| e.code() == DurableFlowErrorCodeV1::BridgeIpc));
                assert!(
                    diagnostic.call_outcomes().release() == DurableFlowCallOutcomeV1::ReturnedErr
                );
                assert!(!diagnostic.incomplete());
            } else {
                assert!(diagnostic.first_error().is_none());
                assert!(
                    diagnostic.call_outcomes().release() == DurableFlowCallOutcomeV1::NotObserved
                );
                assert!(diagnostic.incomplete() == (mode == 2));
            }
            assert!(drops.load(Ordering::Relaxed) == 0);
            drop(original);
            assert!(drops.load(Ordering::Relaxed) == 1);
        }
    }
    #[test]
    fn durable_flow_all_eleven_call_slots_preserve_before_at_after_and_entered() {
        for slot in CALLS {
            for failure_position in 0..4 {
                let collector = DurableFlowCollectorV1::default();
                let observer = collector.arm(DurableFlowOperationV1::InitialSign);
                let calls = Cell::new(0);
                let original: std::result::Result<(), super::super::BridgeError> =
                    match failure_position {
                        0 => observe_result(
                            Some(&observer),
                            DurableFlowStageV1::AuthorizationSource,
                            Err(super::super::BridgeError::Binding),
                        ),
                        1 => {
                            observe_call(Some(&observer), slot, DurableFlowStageV1::KeyUse, || {
                                calls.set(calls.get() + 1);
                                Err(super::super::BridgeError::Ipc)
                            })
                        }
                        2 => {
                            let returned: std::result::Result<(), super::super::BridgeError> =
                                observe_call(
                                    Some(&observer),
                                    slot,
                                    DurableFlowStageV1::KeyUse,
                                    || {
                                        calls.set(calls.get() + 1);
                                        Ok(())
                                    },
                                );
                            assert!(returned.is_ok());
                            observe_result(
                                Some(&observer),
                                DurableFlowStageV1::Completion,
                                Err(super::super::BridgeError::RecoveryRequired),
                            )
                        }
                        _ => {
                            observer.call_enter(slot);
                            Err(super::super::BridgeError::Uncertain)
                        }
                    };
                assert!(original.is_err());
                let mut diagnostic = failed(&observer);
                let expected = match failure_position {
                    0 => DurableFlowCallOutcomeV1::NotObserved,
                    1 => DurableFlowCallOutcomeV1::ReturnedErr,
                    2 => DurableFlowCallOutcomeV1::ReturnedOk,
                    _ => DurableFlowCallOutcomeV1::Entered,
                };
                assert!(*diagnostic.call_outcomes.slot(slot) == expected);
                assert!(calls.get() == usize::from(failure_position == 1 || failure_position == 2));
                assert!(!diagnostic.incomplete());
            }
        }
    }
    #[test]
    fn durable_flow_call_duplicates_are_incomplete_without_erasing_success() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        let first: std::result::Result<(), crate::Error> = observe_call(
            Some(&observer),
            DurableFlowCallV1::PermitRetention,
            DurableFlowStageV1::PermitRetain,
            || Ok(()),
        );
        assert!(first.is_ok());
        observer.call_enter(DurableFlowCallV1::PermitRetention);
        observer.call_return(
            DurableFlowCallV1::PermitRetention,
            &Err::<(), _>(crate::Error::Locked),
        );
        let diagnostic = failed(&observer);
        assert!(
            diagnostic.call_outcomes().permit_retention() == DurableFlowCallOutcomeV1::ReturnedOk
        );
        assert!(diagnostic.incomplete());
    }
    #[test]
    fn durable_flow_first_borrowed_cause_and_terminal_result_stay_distinct() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        let original: std::result::Result<(), crate::consent_journal::JournalError> =
            Err(crate::consent_journal::JournalError::Database);
        let mapped = observe_result(Some(&observer), DurableFlowStageV1::Release, original)
            .map_err(|_| crate::Error::RecoveryRequired);
        observer.record_error(
            DurableFlowStageV1::Completion,
            mapped.as_ref().err().unwrap(),
        );
        observer.record_terminal(
            DurableFlowStageV1::Completion,
            mapped.as_ref().err().unwrap(),
        );
        let diagnostic = failed(&observer);
        assert!(matches!(mapped, Err(crate::Error::RecoveryRequired)));
        assert!(diagnostic
            .first_error()
            .is_some_and(|e| e.code() == DurableFlowErrorCodeV1::JournalDatabase
                && e.stage() == DurableFlowStageV1::Release));
        assert!(diagnostic
            .terminal_error()
            .is_some_and(|e| e.code() == DurableFlowErrorCodeV1::SignerRecoveryRequired));
    }
    #[test]
    fn durable_flow_stale_attempt_job_and_invalid_finish_never_attribute_data() {
        let collector = DurableFlowCollectorV1::default();
        let old = collector.arm(DurableFlowOperationV1::FinancialImport);
        let old_job = old.job_start(DurableFlowJobPurposeV1::Import, 7);
        let current = collector.arm(DurableFlowOperationV1::FinancialImport);
        assert!(!old.same_attempt(&current));
        old.record_error(
            DurableFlowStageV1::ImportReceive,
            &super::super::BridgeError::Ipc,
        );
        old_job.received(
            DurableFlowStageV1::ImportReceive,
            &Err::<(), _>(super::super::BridgeError::Ipc),
        );
        assert!(old.finish(DurableFlowResultV1::ReturnedErr).is_none());
        let diagnostic = failed(&current);
        assert!(diagnostic.incomplete() && diagnostic.first_error().is_none());
        assert!(diagnostic.completion().purpose().is_none());
        assert!(current.finish(DurableFlowResultV1::ReturnedErr).is_none());
        let next = collector.arm(DurableFlowOperationV1::RetainedRetry);
        let wrong_job = next.job_start(DurableFlowJobPurposeV1::Sign, 8);
        wrong_job.completed(DurableFlowResultV1::ReturnedErr);
        let diagnostic = failed(&next);
        assert!(diagnostic.incomplete() && diagnostic.completion().purpose().is_none());
        let invalid = collector.arm(DurableFlowOperationV1::InitialSign);
        assert!(invalid.finish(DurableFlowResultV1::NotObserved).is_none());
        assert!(failed(&invalid).incomplete());
    }
    #[test]
    fn durable_flow_contended_new_arm_invalidates_previous_token_before_lock() {
        let collector = DurableFlowCollectorV1::default();
        let old = collector.arm(DurableFlowOperationV1::FinancialImport);
        let old_job = old.job_start(DurableFlowJobPurposeV1::Import, 9);
        let guard = collector.shared.data.lock().unwrap();
        let unavailable = collector.arm(DurableFlowOperationV1::FinancialImport);
        assert!(!old.same_attempt(&old));
        drop(guard);
        old_job.received(
            DurableFlowStageV1::ImportReceive,
            &Err::<(), _>(super::super::BridgeError::Ipc),
        );
        assert!(old.finish(DurableFlowResultV1::ReturnedErr).is_none());
        assert!(unavailable
            .finish(DurableFlowResultV1::ReturnedErr)
            .is_none());
        let fresh = collector.arm(DurableFlowOperationV1::FinancialImport);
        let result: std::result::Result<(), crate::Error> = observe_result(
            Some(&fresh),
            DurableFlowStageV1::ImportSource,
            Err(crate::Error::Locked),
        );
        assert!(matches!(result, Err(crate::Error::Locked)));
        let diagnostic = failed(&fresh);
        assert!(diagnostic
            .first_error()
            .is_some_and(|e| e.code() == DurableFlowErrorCodeV1::SignerLocked));
        assert!(!diagnostic.incomplete());
    }
    #[test]
    fn durable_flow_duplicate_enter_does_not_reassign_original_inflight_call() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        observer.call_enter(DurableFlowCallV1::Reservation);
        observer.call_enter(DurableFlowCallV1::Reservation);
        observer.call_return(DurableFlowCallV1::Reservation, &Ok::<(), crate::Error>(()));
        let diagnostic = failed(&observer);
        assert!(diagnostic.call_outcomes().reservation() == DurableFlowCallOutcomeV1::Entered);
        assert!(diagnostic.incomplete());
    }
    #[test]
    fn durable_flow_duplicate_receive_does_not_invent_a_late_first_error() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::FinancialImport);
        let job = observer.job_start(DurableFlowJobPurposeV1::Import, 1);
        job.received(
            DurableFlowStageV1::ImportReceive,
            &Ok::<(), crate::Error>(()),
        );
        job.received(
            DurableFlowStageV1::ImportReceive,
            &Err::<(), _>(crate::Error::Locked),
        );
        let diagnostic = failed(&observer);
        assert!(diagnostic.first_error().is_none());
        assert!(diagnostic.completion().result() == DurableFlowResultV1::ReturnedOk);
        assert!(diagnostic.incomplete());
    }
    #[test]
    fn durable_flow_attempt_and_job_counter_exhaustion_never_wraps() {
        let collector = DurableFlowCollectorV1::default();
        collector
            .shared
            .generation
            .store(u64::MAX - 1, Ordering::Relaxed);
        let disabled = collector.arm(DurableFlowOperationV1::InitialSign);
        assert!(disabled.finish(DurableFlowResultV1::ReturnedErr).is_none());
        assert!(collector.shared.generation.load(Ordering::Relaxed) == u64::MAX);
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        collector
            .shared
            .data
            .lock()
            .unwrap()
            .active
            .as_mut()
            .unwrap()
            .next_job = u64::MAX;
        observer
            .job_start(DurableFlowJobPurposeV1::Sign, 1)
            .completed(DurableFlowResultV1::ReturnedOk);
        let diagnostic = failed(&observer);
        assert!(diagnostic.incomplete() && diagnostic.completion().purpose().is_none());
    }
    #[test]
    fn durable_flow_completion_tracks_latest_actual_job_without_losing_first_cause() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::WriterReconcile);
        let earlier = observer.job_start(DurableFlowJobPurposeV1::AcquirePrepare, 3);
        earlier.received(
            DurableFlowStageV1::AcquirePrepare,
            &Err::<(), _>(crate::Error::Authentication),
        );
        earlier.presentation(DurableFlowPresentationV1::Suppressed);
        let current = observer.job_start(DurableFlowJobPurposeV1::Reconcile, 3);
        earlier.missing();
        current.received(
            DurableFlowStageV1::ReconcileCall,
            &Ok::<(), crate::Error>(()),
        );
        current.invalidated();
        current.presentation(DurableFlowPresentationV1::Suppressed);
        let diagnostic = failed(&observer);
        assert!(diagnostic
            .first_error()
            .is_some_and(|e| e.code() == DurableFlowErrorCodeV1::SignerAuthentication));
        assert!(diagnostic.completion().purpose() == Some(DurableFlowJobPurposeV1::Reconcile));
        assert!(diagnostic.completion().result() == DurableFlowResultV1::ReturnedOk);
        assert!(diagnostic.completion().receive() == DurableFlowReceiveV1::Invalidated);
        assert!(diagnostic.completion().presentation() == DurableFlowPresentationV1::Suppressed);
        assert!(diagnostic.incomplete());
    }
    #[test]
    fn durable_flow_disconnected_is_not_an_invented_ipc_error() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::FinancialImport);
        let job = observer.job_start(DurableFlowJobPurposeV1::Import, 4);
        job.pending();
        job.disconnected();
        let diagnostic = failed(&observer);
        assert!(diagnostic.first_error().is_none());
        assert!(diagnostic.completion().result() == DurableFlowResultV1::NotObserved);
        assert!(diagnostic.completion().receive() == DurableFlowReceiveV1::Disconnected);
        assert!(!diagnostic.incomplete());
        let observer = collector.arm(DurableFlowOperationV1::FinancialImport);
        let job = observer.job_start(DurableFlowJobPurposeV1::Import, 4);
        job.received(
            DurableFlowStageV1::ImportReceive,
            &Err::<(), _>(super::super::BridgeError::Ipc),
        );
        assert!(failed(&observer)
            .first_error()
            .is_some_and(|e| e.code() == DurableFlowErrorCodeV1::BridgeIpc));
    }
    #[test]
    fn durable_flow_closed_classifiers_preserve_only_immediate_nested_category() {
        use crate::consent_journal::JournalError;
        use wholepact_storage_security::StorageSecurityError;
        let source = crate::Error::ConsentJournal(JournalError::Storage(
            StorageSecurityError::AuthenticationFailed,
        ));
        let classified = source.classify(DurableFlowStageV1::Release);
        assert!(classified.code() == DurableFlowErrorCodeV1::SignerConsentJournal);
        assert!(classified.nested_code() == Some(DurableFlowNestedCodeV1::JournalStorage));
        let source = JournalError::Storage(StorageSecurityError::AuthenticationFailed);
        assert!(
            source.classify(DurableFlowStageV1::Release).nested_code()
                == Some(DurableFlowNestedCodeV1::StorageSecurityAuthenticationFailed)
        );
        let source =
            wholepact_store::StoreError::InvalidInput("PRIVATE SENTINEL: never inspect or emit");
        let classified = source.classify(DurableFlowStageV1::FixtureState);
        assert!(
            classified.code() == DurableFlowErrorCodeV1::StoreInvalidInput
                && classified.nested_code().is_none()
        );
        let source = wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError::Sync(
            wholepact_wallet::wallet::protected_sync::SyncError::Interrupted,
        );
        assert!(
            source
                .classify(DurableFlowStageV1::WalletGuard)
                .nested_code()
                == Some(DurableFlowNestedCodeV1::SyncInterrupted)
        );
    }
    #[test]
    fn durable_flow_actual_missing_output_preserves_result_without_inventing_job() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::RetainedRetry);
        observer.missing_completion();
        let diagnostic = failed(&observer);
        assert!(diagnostic.completion().purpose().is_none());
        assert!(diagnostic.completion().result() == DurableFlowResultV1::NotObserved);
        assert!(diagnostic.completion().receive() == DurableFlowReceiveV1::Missing);
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        let job = observer.job_start(DurableFlowJobPurposeV1::Sign, 1);
        job.received(DurableFlowStageV1::Sign, &Ok::<(), crate::Error>(()));
        job.presentation(DurableFlowPresentationV1::Accepted);
        observer.missing_completion();
        let diagnostic = failed(&observer);
        assert!(diagnostic.completion().purpose() == Some(DurableFlowJobPurposeV1::Sign));
        assert!(diagnostic.completion().result() == DurableFlowResultV1::ReturnedOk);
        assert!(diagnostic.completion().receive() == DurableFlowReceiveV1::Missing);
        assert!(diagnostic.completion().presentation() == DurableFlowPresentationV1::NotObserved);
        assert!(diagnostic.first_error().is_none());
    }
    #[test]
    fn durable_flow_success_clears_without_failure_record_and_host_sentinel_has_no_cause() {
        let collector = DurableFlowCollectorV1::default();
        let observer = collector.arm(DurableFlowOperationV1::ResultService);
        let job = observer.job_start(DurableFlowJobPurposeV1::ResultService, 0);
        job.completed(DurableFlowResultV1::ReturnedOk);
        assert!(observer.finish(DurableFlowResultV1::ReturnedOk).is_none());
        assert!(observer.finish(DurableFlowResultV1::ReturnedErr).is_none());
        let observer = collector.arm(DurableFlowOperationV1::ResultService);
        observer
            .job_start(DurableFlowJobPurposeV1::ResultService, 0)
            .completed(DurableFlowResultV1::ReturnedErr);
        let diagnostic = failed(&observer);
        assert!(diagnostic.first_error().is_none() && diagnostic.terminal_error().is_none());
        assert!(diagnostic.completion().result() == DurableFlowResultV1::ReturnedErr);
    }
    fn cases_signer() -> Vec<(crate::Error, DurableFlowErrorCodeV1)> {
        use crate::Error as E;
        vec![
            (E::Unavailable, DurableFlowErrorCodeV1::SignerUnavailable),
            (
                E::PeerLifetimeUnavailable,
                DurableFlowErrorCodeV1::SignerPeerLifetimeUnavailable,
            ),
            (
                E::Io(std::io::Error::other("private io sentinel")),
                DurableFlowErrorCodeV1::SignerIo,
            ),
            (
                E::Authentication,
                DurableFlowErrorCodeV1::SignerAuthentication,
            ),
            (E::InvalidData, DurableFlowErrorCodeV1::SignerInvalidData),
            (E::Crypto, DurableFlowErrorCodeV1::SignerCrypto),
            (E::Locked, DurableFlowErrorCodeV1::SignerLocked),
            (
                E::BackupRequired,
                DurableFlowErrorCodeV1::SignerBackupRequired,
            ),
            (
                E::RecoveryRequired,
                DurableFlowErrorCodeV1::SignerRecoveryRequired,
            ),
            (E::AlreadyOpen, DurableFlowErrorCodeV1::SignerAlreadyOpen),
            (
                E::ReviewMismatch,
                DurableFlowErrorCodeV1::SignerReviewMismatch,
            ),
            (E::Verification, DurableFlowErrorCodeV1::SignerVerification),
            (E::Uncertain, DurableFlowErrorCodeV1::SignerUncertain),
            (
                E::ConsentJournal(crate::consent_journal::JournalError::Database),
                DurableFlowErrorCodeV1::SignerConsentJournal,
            ),
            (
                E::Store(wholepact_store::StoreError::InvalidInput(
                    "private store sentinel",
                )),
                DurableFlowErrorCodeV1::SignerStore,
            ),
        ]
    }
    fn cases_bridge() -> Vec<(super::super::BridgeError, DurableFlowErrorCodeV1)> {
        use super::super::BridgeError as E;
        vec![
            (E::Binding, DurableFlowErrorCodeV1::BridgeBinding),
            (E::Conflict, DurableFlowErrorCodeV1::BridgeConflict),
            (E::Missing, DurableFlowErrorCodeV1::BridgeMissing),
            (E::Uncertain, DurableFlowErrorCodeV1::BridgeUncertain),
            (E::Limit, DurableFlowErrorCodeV1::BridgeLimit),
            (E::Permission, DurableFlowErrorCodeV1::BridgePermission),
            (E::RecoveryRequired, DurableFlowErrorCodeV1::BridgeRecoveryRequired),
            (E::CompleteOriginRecoveryUnavailable, DurableFlowErrorCodeV1::BridgeCompleteOriginRecoveryUnavailable),
            (E::Verification, DurableFlowErrorCodeV1::BridgeVerification),
            (E::SignerOriginUnavailable, DurableFlowErrorCodeV1::BridgeSignerOriginUnavailable),
            (E::Journal(crate::consent_journal::JournalError::Database), DurableFlowErrorCodeV1::BridgeJournal),
            (E::Authority(wholepact_authority::AuthorityError::Permission), DurableFlowErrorCodeV1::BridgeAuthority),
            (E::Wallet(wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError::StateChanged), DurableFlowErrorCodeV1::BridgeWallet),
            (E::Ipc, DurableFlowErrorCodeV1::BridgeIpc),
        ]
    }
    fn cases_authority() -> Vec<(wholepact_authority::AuthorityError, DurableFlowErrorCodeV1)> {
        use wholepact_authority::AuthorityError as E;
        vec![
            (
                E::InvalidBinding,
                DurableFlowErrorCodeV1::AuthorityInvalidBinding,
            ),
            (E::Permission, DurableFlowErrorCodeV1::AuthorityPermission),
            (E::StaleHead, DurableFlowErrorCodeV1::AuthorityStaleHead),
            (E::Conflict, DurableFlowErrorCodeV1::AuthorityConflict),
            (E::Inactive, DurableFlowErrorCodeV1::AuthorityInactive),
            (
                E::RecoveryRequired,
                DurableFlowErrorCodeV1::AuthorityRecoveryRequired,
            ),
            (E::Expired, DurableFlowErrorCodeV1::AuthorityExpired),
            (
                E::PolicyDenied,
                DurableFlowErrorCodeV1::AuthorityPolicyDenied,
            ),
            (
                E::BudgetExceeded,
                DurableFlowErrorCodeV1::AuthorityBudgetExceeded,
            ),
            (
                E::InputReserved,
                DurableFlowErrorCodeV1::AuthorityInputReserved,
            ),
            (
                E::ObligationReserved,
                DurableFlowErrorCodeV1::AuthorityObligationReserved,
            ),
            (E::Limit, DurableFlowErrorCodeV1::AuthorityLimit),
            (E::Storage, DurableFlowErrorCodeV1::AuthorityStorage),
            (
                E::CorruptHistory,
                DurableFlowErrorCodeV1::AuthorityCorruptHistory,
            ),
            (
                E::PermanentStopUnavailable,
                DurableFlowErrorCodeV1::AuthorityPermanentStopUnavailable,
            ),
            (
                E::OfflineHistoryUnsupported,
                DurableFlowErrorCodeV1::AuthorityOfflineHistoryUnsupported,
            ),
            (
                E::ConstructionHistoryUnsupported,
                DurableFlowErrorCodeV1::AuthorityConstructionHistoryUnsupported,
            ),
            (
                E::UnsupportedVersion,
                DurableFlowErrorCodeV1::AuthorityUnsupportedVersion,
            ),
            (
                E::Authentication,
                DurableFlowErrorCodeV1::AuthorityAuthentication,
            ),
            (E::Uncertain, DurableFlowErrorCodeV1::AuthorityUncertain),
            (
                E::ResolutionUnavailable,
                DurableFlowErrorCodeV1::AuthorityResolutionUnavailable,
            ),
            (
                E::SessionRequired,
                DurableFlowErrorCodeV1::AuthoritySessionRequired,
            ),
            (
                E::SessionPending,
                DurableFlowErrorCodeV1::AuthoritySessionPending,
            ),
        ]
    }
    fn cases_journal() -> Vec<(crate::consent_journal::JournalError, DurableFlowErrorCodeV1)> {
        use crate::consent_journal::JournalError as E;
        vec![
            (
                E::Storage(wholepact_storage_security::StorageSecurityError::SourceChanged),
                DurableFlowErrorCodeV1::JournalStorage,
            ),
            (E::Database, DurableFlowErrorCodeV1::JournalDatabase),
            (E::Permission, DurableFlowErrorCodeV1::JournalPermission),
            (E::Expired, DurableFlowErrorCodeV1::JournalExpired),
            (
                E::RecoveryRequired,
                DurableFlowErrorCodeV1::JournalRecoveryRequired,
            ),
            (
                E::UnsupportedSchema,
                DurableFlowErrorCodeV1::JournalUnsupportedSchema,
            ),
            (
                E::OfflineHistoryUnsupported,
                DurableFlowErrorCodeV1::JournalOfflineHistoryUnsupported,
            ),
            (
                E::NamedRecipientHistoryUnsupported,
                DurableFlowErrorCodeV1::JournalNamedRecipientHistoryUnsupported,
            ),
            (
                E::ConstructionHistoryUnsupported,
                DurableFlowErrorCodeV1::JournalConstructionHistoryUnsupported,
            ),
            (
                E::InvalidBinding,
                DurableFlowErrorCodeV1::JournalInvalidBinding,
            ),
            (E::Conflict, DurableFlowErrorCodeV1::JournalConflict),
            (E::NotFound, DurableFlowErrorCodeV1::JournalNotFound),
            (
                E::LiveAuthorization,
                DurableFlowErrorCodeV1::JournalLiveAuthorization,
            ),
            (
                E::InputReserved,
                DurableFlowErrorCodeV1::JournalInputReserved,
            ),
            (
                E::BudgetExceeded,
                DurableFlowErrorCodeV1::JournalBudgetExceeded,
            ),
            (E::Limit, DurableFlowErrorCodeV1::JournalLimit),
        ]
    }
    fn cases_walletkeyuse() -> Vec<(
        wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError,
        DurableFlowErrorCodeV1,
    )> {
        use wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError as E;
        vec![
            (
                E::Permission,
                DurableFlowErrorCodeV1::WalletKeyUsePermission,
            ),
            (E::Policy, DurableFlowErrorCodeV1::WalletKeyUsePolicy),
            (
                E::SelectionExpired,
                DurableFlowErrorCodeV1::WalletKeyUseSelectionExpired,
            ),
            (E::Storage, DurableFlowErrorCodeV1::WalletKeyUseStorage),
            (
                E::RecoveryRequired,
                DurableFlowErrorCodeV1::WalletKeyUseRecoveryRequired,
            ),
            (
                E::StateChanged,
                DurableFlowErrorCodeV1::WalletKeyUseStateChanged,
            ),
            (E::Expiry, DurableFlowErrorCodeV1::WalletKeyUseExpiry),
            (
                E::Sync(wholepact_wallet::wallet::protected_sync::SyncError::Interrupted),
                DurableFlowErrorCodeV1::WalletKeyUseSync,
            ),
        ]
    }
    fn cases_store() -> Vec<(wholepact_store::StoreError, DurableFlowErrorCodeV1)> {
        use wholepact_store::StoreError as E;
        vec![
            (
                E::StorageSecurity(wholepact_storage_security::StorageSecurityError::SourceChanged),
                DurableFlowErrorCodeV1::StoreStorageSecurity,
            ),
            (
                E::Database(rusqlite::Error::InvalidQuery),
                DurableFlowErrorCodeV1::StoreDatabase,
            ),
            (
                E::Encoding(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
                DurableFlowErrorCodeV1::StoreEncoding,
            ),
            (E::Poisoned, DurableFlowErrorCodeV1::StorePoisoned),
            (
                E::IdempotencyConflict,
                DurableFlowErrorCodeV1::StoreIdempotencyConflict,
            ),
            (
                E::RevisionConflict,
                DurableFlowErrorCodeV1::StoreRevisionConflict,
            ),
            (E::NotFound, DurableFlowErrorCodeV1::StoreNotFound),
            (E::AlreadyExists, DurableFlowErrorCodeV1::StoreAlreadyExists),
            (
                E::InvalidInput("private input sentinel"),
                DurableFlowErrorCodeV1::StoreInvalidInput,
            ),
            (
                E::UnsupportedSchema(987),
                DurableFlowErrorCodeV1::StoreUnsupportedSchema,
            ),
            (
                E::RecoveryRequired,
                DurableFlowErrorCodeV1::StoreRecoveryRequired,
            ),
            (
                E::WriterEpochMismatch,
                DurableFlowErrorCodeV1::StoreWriterEpochMismatch,
            ),
            (
                E::LiveAuthorizationExists,
                DurableFlowErrorCodeV1::StoreLiveAuthorizationExists,
            ),
            (E::InputReserved, DurableFlowErrorCodeV1::StoreInputReserved),
            (
                E::ResourceExhausted,
                DurableFlowErrorCodeV1::StoreResourceExhausted,
            ),
            (
                E::BudgetExceeded,
                DurableFlowErrorCodeV1::StoreBudgetExceeded,
            ),
            (
                E::InvalidTransition,
                DurableFlowErrorCodeV1::StoreInvalidTransition,
            ),
            (
                E::File(std::io::Error::other("private file sentinel")),
                DurableFlowErrorCodeV1::StoreFile,
            ),
        ]
    }
    fn cases_storagesecurity() -> Vec<(
        wholepact_storage_security::StorageSecurityError,
        DurableFlowNestedCodeV1,
    )> {
        use wholepact_storage_security::StorageSecurityError as E;
        vec![
            (
                E::UnsupportedPlatform,
                DurableFlowNestedCodeV1::StorageSecurityUnsupportedPlatform,
            ),
            (
                E::QuarantinedDatabase,
                DurableFlowNestedCodeV1::StorageSecurityQuarantinedDatabase,
            ),
            (
                E::RecoveredGeneration,
                DurableFlowNestedCodeV1::StorageSecurityRecoveredGeneration,
            ),
            (
                E::GenerationArchive,
                DurableFlowNestedCodeV1::StorageSecurityGenerationArchive,
            ),
            (
                E::UninitializedDatabase,
                DurableFlowNestedCodeV1::StorageSecurityUninitializedDatabase,
            ),
            (
                E::UnsafePath,
                DurableFlowNestedCodeV1::StorageSecurityUnsafePath,
            ),
            (
                E::AlreadyExists,
                DurableFlowNestedCodeV1::StorageSecurityAlreadyExists,
            ),
            (
                E::MissingDatabase,
                DurableFlowNestedCodeV1::StorageSecurityMissingDatabase,
            ),
            (
                E::PlaintextRefused,
                DurableFlowNestedCodeV1::StorageSecurityPlaintextRefused,
            ),
            (
                E::UnqualifiedRuntime,
                DurableFlowNestedCodeV1::StorageSecurityUnqualifiedRuntime,
            ),
            (
                E::AuthenticationFailed,
                DurableFlowNestedCodeV1::StorageSecurityAuthenticationFailed,
            ),
            (
                E::Database,
                DurableFlowNestedCodeV1::StorageSecurityDatabase,
            ),
            (E::Io, DurableFlowNestedCodeV1::StorageSecurityIo),
            (
                E::SnapshotLimit,
                DurableFlowNestedCodeV1::StorageSecuritySnapshotLimit,
            ),
            (
                E::SourceChanged,
                DurableFlowNestedCodeV1::StorageSecuritySourceChanged,
            ),
        ]
    }
    fn cases_sync() -> Vec<(
        wholepact_wallet::wallet::protected_sync::SyncError,
        DurableFlowNestedCodeV1,
    )> {
        use wholepact_wallet::wallet::protected_sync::SyncError as E;
        vec![
            (E::AccessDenied, DurableFlowNestedCodeV1::SyncAccessDenied),
            (
                E::InvalidRequest,
                DurableFlowNestedCodeV1::SyncInvalidRequest,
            ),
            (E::Interrupted, DurableFlowNestedCodeV1::SyncInterrupted),
            (
                E::ReconciliationRequired,
                DurableFlowNestedCodeV1::SyncReconciliationRequired,
            ),
            (
                E::InvalidResponse,
                DurableFlowNestedCodeV1::SyncInvalidResponse,
            ),
            (E::ResourceLimit, DurableFlowNestedCodeV1::SyncResourceLimit),
            (
                E::NoCurrentObservation,
                DurableFlowNestedCodeV1::SyncNoCurrentObservation,
            ),
            (
                E::Wallet(wholepact_wallet::wallet::WalletError::Storage),
                DurableFlowNestedCodeV1::SyncWallet,
            ),
            (
                E::Chain(wholepact_chain::ChainError::BackendFailure { grpc_code: 7 }),
                DurableFlowNestedCodeV1::SyncChain,
            ),
        ]
    }
    #[test]
    fn durable_flow_every_source_discriminant_is_classified_without_text() {
        for (source, expected) in cases_signer() {
            let actual = source.classify(DurableFlowStageV1::Completion);
            assert!(actual.domain() == DurableFlowErrorDomainV1::Signer);
            assert!(actual.code() == expected);
        }
        for (source, expected) in cases_bridge() {
            let actual = source.classify(DurableFlowStageV1::Completion);
            assert!(actual.domain() == DurableFlowErrorDomainV1::Bridge);
            assert!(actual.code() == expected);
        }
        for (source, expected) in cases_authority() {
            let actual = source.classify(DurableFlowStageV1::Completion);
            assert!(actual.domain() == DurableFlowErrorDomainV1::Authority);
            assert!(actual.code() == expected);
        }
        for (source, expected) in cases_journal() {
            let actual = source.classify(DurableFlowStageV1::Completion);
            assert!(actual.domain() == DurableFlowErrorDomainV1::Journal);
            assert!(actual.code() == expected);
        }
        for (source, expected) in cases_walletkeyuse() {
            let actual = source.classify(DurableFlowStageV1::Completion);
            assert!(actual.domain() == DurableFlowErrorDomainV1::WalletKeyUse);
            assert!(actual.code() == expected);
        }
        for (source, expected) in cases_store() {
            let actual = source.classify(DurableFlowStageV1::Completion);
            assert!(actual.domain() == DurableFlowErrorDomainV1::Store);
            assert!(actual.code() == expected);
        }
    }
    fn expected_nested_code(code: DurableFlowErrorCodeV1) -> DurableFlowNestedCodeV1 {
        match code {
            DurableFlowErrorCodeV1::AuthorityInvalidBinding => {
                DurableFlowNestedCodeV1::AuthorityInvalidBinding
            }
            DurableFlowErrorCodeV1::AuthorityPermission => {
                DurableFlowNestedCodeV1::AuthorityPermission
            }
            DurableFlowErrorCodeV1::AuthorityStaleHead => {
                DurableFlowNestedCodeV1::AuthorityStaleHead
            }
            DurableFlowErrorCodeV1::AuthorityConflict => DurableFlowNestedCodeV1::AuthorityConflict,
            DurableFlowErrorCodeV1::AuthorityInactive => DurableFlowNestedCodeV1::AuthorityInactive,
            DurableFlowErrorCodeV1::AuthorityRecoveryRequired => {
                DurableFlowNestedCodeV1::AuthorityRecoveryRequired
            }
            DurableFlowErrorCodeV1::AuthorityExpired => DurableFlowNestedCodeV1::AuthorityExpired,
            DurableFlowErrorCodeV1::AuthorityPolicyDenied => {
                DurableFlowNestedCodeV1::AuthorityPolicyDenied
            }
            DurableFlowErrorCodeV1::AuthorityBudgetExceeded => {
                DurableFlowNestedCodeV1::AuthorityBudgetExceeded
            }
            DurableFlowErrorCodeV1::AuthorityInputReserved => {
                DurableFlowNestedCodeV1::AuthorityInputReserved
            }
            DurableFlowErrorCodeV1::AuthorityObligationReserved => {
                DurableFlowNestedCodeV1::AuthorityObligationReserved
            }
            DurableFlowErrorCodeV1::AuthorityLimit => DurableFlowNestedCodeV1::AuthorityLimit,
            DurableFlowErrorCodeV1::AuthorityStorage => DurableFlowNestedCodeV1::AuthorityStorage,
            DurableFlowErrorCodeV1::AuthorityCorruptHistory => {
                DurableFlowNestedCodeV1::AuthorityCorruptHistory
            }
            DurableFlowErrorCodeV1::AuthorityPermanentStopUnavailable => {
                DurableFlowNestedCodeV1::AuthorityPermanentStopUnavailable
            }
            DurableFlowErrorCodeV1::AuthorityOfflineHistoryUnsupported => {
                DurableFlowNestedCodeV1::AuthorityOfflineHistoryUnsupported
            }
            DurableFlowErrorCodeV1::AuthorityConstructionHistoryUnsupported => {
                DurableFlowNestedCodeV1::AuthorityConstructionHistoryUnsupported
            }
            DurableFlowErrorCodeV1::AuthorityUnsupportedVersion => {
                DurableFlowNestedCodeV1::AuthorityUnsupportedVersion
            }
            DurableFlowErrorCodeV1::AuthorityAuthentication => {
                DurableFlowNestedCodeV1::AuthorityAuthentication
            }
            DurableFlowErrorCodeV1::AuthorityUncertain => {
                DurableFlowNestedCodeV1::AuthorityUncertain
            }
            DurableFlowErrorCodeV1::AuthorityResolutionUnavailable => {
                DurableFlowNestedCodeV1::AuthorityResolutionUnavailable
            }
            DurableFlowErrorCodeV1::AuthoritySessionRequired => {
                DurableFlowNestedCodeV1::AuthoritySessionRequired
            }
            DurableFlowErrorCodeV1::AuthoritySessionPending => {
                DurableFlowNestedCodeV1::AuthoritySessionPending
            }
            DurableFlowErrorCodeV1::JournalStorage => DurableFlowNestedCodeV1::JournalStorage,
            DurableFlowErrorCodeV1::JournalDatabase => DurableFlowNestedCodeV1::JournalDatabase,
            DurableFlowErrorCodeV1::JournalPermission => DurableFlowNestedCodeV1::JournalPermission,
            DurableFlowErrorCodeV1::JournalExpired => DurableFlowNestedCodeV1::JournalExpired,
            DurableFlowErrorCodeV1::JournalRecoveryRequired => {
                DurableFlowNestedCodeV1::JournalRecoveryRequired
            }
            DurableFlowErrorCodeV1::JournalUnsupportedSchema => {
                DurableFlowNestedCodeV1::JournalUnsupportedSchema
            }
            DurableFlowErrorCodeV1::JournalOfflineHistoryUnsupported => {
                DurableFlowNestedCodeV1::JournalOfflineHistoryUnsupported
            }
            DurableFlowErrorCodeV1::JournalNamedRecipientHistoryUnsupported => {
                DurableFlowNestedCodeV1::JournalNamedRecipientHistoryUnsupported
            }
            DurableFlowErrorCodeV1::JournalConstructionHistoryUnsupported => {
                DurableFlowNestedCodeV1::JournalConstructionHistoryUnsupported
            }
            DurableFlowErrorCodeV1::JournalInvalidBinding => {
                DurableFlowNestedCodeV1::JournalInvalidBinding
            }
            DurableFlowErrorCodeV1::JournalConflict => DurableFlowNestedCodeV1::JournalConflict,
            DurableFlowErrorCodeV1::JournalNotFound => DurableFlowNestedCodeV1::JournalNotFound,
            DurableFlowErrorCodeV1::JournalLiveAuthorization => {
                DurableFlowNestedCodeV1::JournalLiveAuthorization
            }
            DurableFlowErrorCodeV1::JournalInputReserved => {
                DurableFlowNestedCodeV1::JournalInputReserved
            }
            DurableFlowErrorCodeV1::JournalBudgetExceeded => {
                DurableFlowNestedCodeV1::JournalBudgetExceeded
            }
            DurableFlowErrorCodeV1::JournalLimit => DurableFlowNestedCodeV1::JournalLimit,
            DurableFlowErrorCodeV1::WalletKeyUsePermission => {
                DurableFlowNestedCodeV1::WalletKeyUsePermission
            }
            DurableFlowErrorCodeV1::WalletKeyUsePolicy => {
                DurableFlowNestedCodeV1::WalletKeyUsePolicy
            }
            DurableFlowErrorCodeV1::WalletKeyUseSelectionExpired => {
                DurableFlowNestedCodeV1::WalletKeyUseSelectionExpired
            }
            DurableFlowErrorCodeV1::WalletKeyUseStorage => {
                DurableFlowNestedCodeV1::WalletKeyUseStorage
            }
            DurableFlowErrorCodeV1::WalletKeyUseRecoveryRequired => {
                DurableFlowNestedCodeV1::WalletKeyUseRecoveryRequired
            }
            DurableFlowErrorCodeV1::WalletKeyUseStateChanged => {
                DurableFlowNestedCodeV1::WalletKeyUseStateChanged
            }
            DurableFlowErrorCodeV1::WalletKeyUseExpiry => {
                DurableFlowNestedCodeV1::WalletKeyUseExpiry
            }
            DurableFlowErrorCodeV1::WalletKeyUseSync => DurableFlowNestedCodeV1::WalletKeyUseSync,
            DurableFlowErrorCodeV1::StoreStorageSecurity => {
                DurableFlowNestedCodeV1::StoreStorageSecurity
            }
            DurableFlowErrorCodeV1::StoreDatabase => DurableFlowNestedCodeV1::StoreDatabase,
            DurableFlowErrorCodeV1::StoreEncoding => DurableFlowNestedCodeV1::StoreEncoding,
            DurableFlowErrorCodeV1::StorePoisoned => DurableFlowNestedCodeV1::StorePoisoned,
            DurableFlowErrorCodeV1::StoreIdempotencyConflict => {
                DurableFlowNestedCodeV1::StoreIdempotencyConflict
            }
            DurableFlowErrorCodeV1::StoreRevisionConflict => {
                DurableFlowNestedCodeV1::StoreRevisionConflict
            }
            DurableFlowErrorCodeV1::StoreNotFound => DurableFlowNestedCodeV1::StoreNotFound,
            DurableFlowErrorCodeV1::StoreAlreadyExists => {
                DurableFlowNestedCodeV1::StoreAlreadyExists
            }
            DurableFlowErrorCodeV1::StoreInvalidInput => DurableFlowNestedCodeV1::StoreInvalidInput,
            DurableFlowErrorCodeV1::StoreUnsupportedSchema => {
                DurableFlowNestedCodeV1::StoreUnsupportedSchema
            }
            DurableFlowErrorCodeV1::StoreRecoveryRequired => {
                DurableFlowNestedCodeV1::StoreRecoveryRequired
            }
            DurableFlowErrorCodeV1::StoreWriterEpochMismatch => {
                DurableFlowNestedCodeV1::StoreWriterEpochMismatch
            }
            DurableFlowErrorCodeV1::StoreLiveAuthorizationExists => {
                DurableFlowNestedCodeV1::StoreLiveAuthorizationExists
            }
            DurableFlowErrorCodeV1::StoreInputReserved => {
                DurableFlowNestedCodeV1::StoreInputReserved
            }
            DurableFlowErrorCodeV1::StoreResourceExhausted => {
                DurableFlowNestedCodeV1::StoreResourceExhausted
            }
            DurableFlowErrorCodeV1::StoreBudgetExceeded => {
                DurableFlowNestedCodeV1::StoreBudgetExceeded
            }
            DurableFlowErrorCodeV1::StoreInvalidTransition => {
                DurableFlowNestedCodeV1::StoreInvalidTransition
            }
            DurableFlowErrorCodeV1::StoreFile => DurableFlowNestedCodeV1::StoreFile,
            _ => panic!("not a nested domain test case"),
        }
    }
    #[test]
    fn durable_flow_every_allowed_immediate_nested_pair_is_preserved() {
        for (source, code) in cases_journal() {
            let expected = expected_nested_code(code);
            let parent = crate::Error::ConsentJournal(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, code) in cases_journal() {
            let expected = expected_nested_code(code);
            let parent = super::super::BridgeError::Journal(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, code) in cases_store() {
            let expected = expected_nested_code(code);
            let parent = crate::Error::Store(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, code) in cases_authority() {
            let expected = expected_nested_code(code);
            let parent = super::super::BridgeError::Authority(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, code) in cases_walletkeyuse() {
            let expected = expected_nested_code(code);
            let parent = super::super::BridgeError::Wallet(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, expected) in cases_storagesecurity() {
            let parent = crate::consent_journal::JournalError::Storage(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, expected) in cases_storagesecurity() {
            let parent = wholepact_store::StoreError::StorageSecurity(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
        for (source, expected) in cases_sync() {
            let parent =
                wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseError::Sync(source);
            assert!(
                parent
                    .classify(DurableFlowStageV1::Completion)
                    .nested_code()
                    == Some(expected)
            );
        }
    }
}
