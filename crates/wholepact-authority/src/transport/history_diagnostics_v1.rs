//! Synthetic, data-only observations of the existing checked-history kernel.
//! A stage or I/O class is not permission or proof of native deadline expiry.
use crate::{AuthorityError, Result};
use std::{
    cell::Cell,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryStageV1 {
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryIoKindV1 {
    Timeout,
    Closed,
    Refused,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryPhaseV1 {
    Snapshot,
    Page,
    Admission,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryCheckSiteV1 {
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryCheckpointV1 {
    EntryDeadline,
    DeadlineSelection,
    ConnectRemaining,
    BeforeCallback,
    Callback,
    AfterCallback,
    Operation,
    Validation,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistorySelectedLimitV1 {
    Caller,
    Exchange,
}

const MAX_MICROS: u32 = 600_000_000;
const MAX_COUNT: u32 = 1_000_000;
const MAX_PAGE_ORDINAL: u16 = 4_096;

macro_rules! scalar_getters {
    ($($name:ident: $ty:ty),* $(,)?) => {
        $(pub fn $name(&self) -> $ty { self.$name })*
    };
}

/// Bounded costs of nonoverlapping callback and complete transport operations.
/// Transport operations include local TLS/framing work, not only network time.
pub struct CheckedHistoryCostV1 {
    callback_calls: u32,
    callback_us: u32,
    callback_max_us: u32,
    connect_calls: u32,
    connect_us: u32,
    handshake_calls: u32,
    handshake_us: u32,
    frame_write_calls: u32,
    frame_write_us: u32,
    frame_read_calls: u32,
    frame_read_us: u32,
}
impl CheckedHistoryCostV1 {
    scalar_getters! {
        callback_calls: u32, callback_us: u32, callback_max_us: u32,
        connect_calls: u32, connect_us: u32, handshake_calls: u32,
        handshake_us: u32, frame_write_calls: u32, frame_write_us: u32,
        frame_read_calls: u32, frame_read_us: u32,
    }
}

/// Inert first-error evidence. Null means unavailable; zero remaining means
/// expired at the observational sample, never permission or a new deadline.
pub struct CheckedHistoryMeasurementV1 {
    phase: Option<CheckedHistoryPhaseV1>,
    page_ordinal: Option<u16>,
    check_site: Option<CheckedHistoryCheckSiteV1>,
    checkpoint: CheckedHistoryCheckpointV1,
    selected_limit: Option<CheckedHistorySelectedLimitV1>,
    selected_budget_us: Option<u32>,
    caller_remaining_at_budget_start_us: Option<u32>,
    caller_remaining_at_failure_us: Option<u32>,
    selected_remaining_at_failure_us: Option<u32>,
    history_elapsed_us: u32,
    exchange_elapsed_us: Option<u32>,
    pre_budget_callback_calls: u8,
    pre_budget_callback_us: u32,
    history_cost: CheckedHistoryCostV1,
    exchange_cost: Option<CheckedHistoryCostV1>,
    clamped: bool,
    incomplete: bool,
}
impl CheckedHistoryMeasurementV1 {
    scalar_getters! {
        phase: Option<CheckedHistoryPhaseV1>, page_ordinal: Option<u16>,
        check_site: Option<CheckedHistoryCheckSiteV1>,
        checkpoint: CheckedHistoryCheckpointV1,
        selected_limit: Option<CheckedHistorySelectedLimitV1>,
        selected_budget_us: Option<u32>,
        caller_remaining_at_budget_start_us: Option<u32>,
        caller_remaining_at_failure_us: Option<u32>,
        selected_remaining_at_failure_us: Option<u32>,
        history_elapsed_us: u32, exchange_elapsed_us: Option<u32>,
        pre_budget_callback_calls: u8, pre_budget_callback_us: u32,
        clamped: bool, incomplete: bool,
    }
    pub fn history_cost(&self) -> &CheckedHistoryCostV1 {
        &self.history_cost
    }
    pub fn exchange_cost(&self) -> Option<&CheckedHistoryCostV1> {
        self.exchange_cost.as_ref()
    }
}

#[derive(Clone, Copy)]
pub(super) enum HistoryOperationV1 {
    Callback = 0,
    Connect = 1,
    Handshake = 2,
    FrameWrite = 3,
    FrameRead = 4,
}
#[derive(Clone, Copy, Default)]
struct CostAccumulator {
    calls: [u64; 5],
    elapsed: [Duration; 5],
    callback_max: Duration,
}
impl CostAccumulator {
    fn add(&mut self, operation: HistoryOperationV1, elapsed: Duration) {
        let index = operation as usize;
        self.calls[index] = self.calls[index].saturating_add(1);
        self.elapsed[index] = self.elapsed[index].saturating_add(elapsed);
        if index == HistoryOperationV1::Callback as usize {
            self.callback_max = self.callback_max.max(elapsed);
        }
    }
    fn bounded(self, clamped: &mut bool) -> CheckedHistoryCostV1 {
        CheckedHistoryCostV1 {
            callback_calls: bounded_count(self.calls[0], clamped),
            callback_us: bounded_micros(self.elapsed[0], clamped),
            callback_max_us: bounded_micros(self.callback_max, clamped),
            connect_calls: bounded_count(self.calls[1], clamped),
            connect_us: bounded_micros(self.elapsed[1], clamped),
            handshake_calls: bounded_count(self.calls[2], clamped),
            handshake_us: bounded_micros(self.elapsed[2], clamped),
            frame_write_calls: bounded_count(self.calls[3], clamped),
            frame_write_us: bounded_micros(self.elapsed[3], clamped),
            frame_read_calls: bounded_count(self.calls[4], clamped),
            frame_read_us: bounded_micros(self.elapsed[4], clamped),
        }
    }
}
fn bounded_count(value: u64, clamped: &mut bool) -> u32 {
    *clamped |= value > u64::from(MAX_COUNT);
    value.min(u64::from(MAX_COUNT)) as u32
}
fn bounded_micros(value: Duration, clamped: &mut bool) -> u32 {
    *clamped |= value > Duration::from_micros(u64::from(MAX_MICROS));
    value.as_micros().min(u128::from(MAX_MICROS)) as u32
}

#[derive(Clone, Copy)]
struct ExchangeObservation {
    phase: CheckedHistoryPhaseV1,
    page_ordinal: Option<u64>,
    started: Option<Instant>,
    selected: Option<Instant>,
    selected_limit: Option<CheckedHistorySelectedLimitV1>,
    pre_budget_callback_calls: u64,
    pre_budget_callback_elapsed: Duration,
    cost: CostAccumulator,
}

pub(super) struct HistoryOperationTokenV1 {
    operation: HistoryOperationV1,
    started: Instant,
}

/// Owns the first original authority error, with no payload or transport detail.
/// No public constructor, serialization, cloning, Debug or Display is exposed.
pub struct CheckedHistoryFailureV1 {
    stage: CheckedHistoryStageV1,
    io_kind: Option<CheckedHistoryIoKindV1>,
    error: AuthorityError,
    measurement: CheckedHistoryMeasurementV1,
}
impl CheckedHistoryFailureV1 {
    pub fn stage(&self) -> CheckedHistoryStageV1 {
        self.stage
    }
    pub fn io_kind(&self) -> Option<CheckedHistoryIoKindV1> {
        self.io_kind
    }
    pub fn measurement(&self) -> &CheckedHistoryMeasurementV1 {
        &self.measurement
    }
    /// The first original observed error, before any existing outer blanket
    /// mapping. Ordinary callers still receive their unchanged mapped error.
    pub fn into_error(self) -> AuthorityError {
        self.error
    }
}

pub(super) struct HistoryObserverV1 {
    stage: Cell<CheckedHistoryStageV1>,
    io_kind: Cell<Option<CheckedHistoryIoKindV1>>,
    first: Cell<Option<CheckedHistoryFailureV1>>,
    started: Instant,
    caller_deadline: Option<Instant>,
    operation_phase: Option<CheckedHistoryPhaseV1>,
    history_cost: Cell<CostAccumulator>,
    exchange: Cell<Option<ExchangeObservation>>,
    pages: Cell<u64>,
    check_site: Cell<Option<CheckedHistoryCheckSiteV1>>,
    checkpoint: Cell<CheckedHistoryCheckpointV1>,
}
impl HistoryObserverV1 {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::new_at(Instant::now(), None)
    }
    pub(super) fn with_caller_deadline(deadline: Instant) -> Self {
        Self::new_at(Instant::now(), Some(deadline))
    }
    pub(super) fn with_admission_deadline(deadline: Instant) -> Self {
        let mut observer = Self::new_at(Instant::now(), Some(deadline));
        observer.operation_phase = Some(CheckedHistoryPhaseV1::Admission);
        observer
    }
    fn new_at(started: Instant, caller_deadline: Option<Instant>) -> Self {
        Self {
            stage: Cell::new(CheckedHistoryStageV1::CallerDeadline),
            io_kind: Cell::new(None),
            first: Cell::new(None),
            started,
            caller_deadline,
            operation_phase: None,
            history_cost: Cell::new(CostAccumulator::default()),
            exchange: Cell::new(None),
            pages: Cell::new(0),
            check_site: Cell::new(None),
            checkpoint: Cell::new(CheckedHistoryCheckpointV1::EntryDeadline),
        }
    }
    pub(super) fn enter(&self, stage: CheckedHistoryStageV1) {
        self.stage.set(stage);
        self.io_kind.set(None);
        self.check_site.set(None);
        self.checkpoint.set(match stage {
            CheckedHistoryStageV1::AdmissionRequestValidation
            | CheckedHistoryStageV1::AdmissionBinding
            | CheckedHistoryStageV1::AdmissionSnapshotValidation
            | CheckedHistoryStageV1::AdmissionCommittedHeadValidation
            | CheckedHistoryStageV1::AdmissionFinalValidation
            | CheckedHistoryStageV1::SnapshotValidation
            | CheckedHistoryStageV1::PageValidation
            | CheckedHistoryStageV1::EventReplay
            | CheckedHistoryStageV1::FinalValidation
            | CheckedHistoryStageV1::Bounds => CheckedHistoryCheckpointV1::Validation,
            _ => CheckedHistoryCheckpointV1::Operation,
        });
    }
    pub(super) fn checkpoint(&self, checkpoint: CheckedHistoryCheckpointV1) {
        self.checkpoint.set(checkpoint);
        if !matches!(
            checkpoint,
            CheckedHistoryCheckpointV1::BeforeCallback
                | CheckedHistoryCheckpointV1::Callback
                | CheckedHistoryCheckpointV1::AfterCallback
        ) {
            self.check_site.set(None);
        }
    }
    pub(super) fn replay_check(&self, site: CheckedHistoryCheckSiteV1) {
        self.end_exchange();
        self.exchange_check(site);
    }
    pub(super) fn exchange_check(&self, site: CheckedHistoryCheckSiteV1) {
        self.check_site.set(Some(site));
        self.checkpoint
            .set(CheckedHistoryCheckpointV1::BeforeCallback);
    }
    pub(super) fn begin_exchange(&self, phase: HistoryPhaseV1) {
        let page_ordinal = if phase == CheckedHistoryPhaseV1::Page {
            let pages = self.pages.get().saturating_add(1);
            self.pages.set(pages);
            Some(pages)
        } else {
            None
        };
        self.exchange.set(Some(ExchangeObservation {
            phase,
            page_ordinal,
            started: None,
            selected: None,
            selected_limit: None,
            pre_budget_callback_calls: 0,
            pre_budget_callback_elapsed: Duration::ZERO,
            cost: CostAccumulator::default(),
        }));
        self.exchange_check(CheckedHistoryCheckSiteV1::ExchangeInitial);
    }
    pub(super) fn select_deadline(&self, started: Instant, selected: Instant) {
        if let Some(mut exchange) = self.exchange.get() {
            exchange.started = Some(started);
            exchange.selected = Some(selected);
            exchange.selected_limit = Some(
                if selected_deadline_stage(selected, self.caller_deadline)
                    == CheckedHistoryStageV1::ExchangeDeadline
                {
                    CheckedHistorySelectedLimitV1::Exchange
                } else {
                    CheckedHistorySelectedLimitV1::Caller
                },
            );
            self.exchange.set(Some(exchange));
        }
    }
    pub(super) fn end_exchange(&self) {
        self.exchange.set(None);
        self.check_site.set(None);
    }
    pub(super) fn start_operation(&self, operation: HistoryOperationV1) -> HistoryOperationTokenV1 {
        HistoryOperationTokenV1 {
            operation,
            started: Instant::now(),
        }
    }
    fn account_operation(&self, operation: HistoryOperationV1, started: Instant, ended: Instant) {
        let elapsed = ended.saturating_duration_since(started);
        let mut history = self.history_cost.get();
        history.add(operation, elapsed);
        self.history_cost.set(history);
        if let Some(mut exchange) = self.exchange.get() {
            if exchange.started.is_some() {
                exchange.cost.add(operation, elapsed);
            } else if matches!(operation, HistoryOperationV1::Callback) {
                exchange.pre_budget_callback_calls =
                    exchange.pre_budget_callback_calls.saturating_add(1);
                exchange.pre_budget_callback_elapsed =
                    exchange.pre_budget_callback_elapsed.saturating_add(elapsed);
            }
            self.exchange.set(Some(exchange));
        }
    }
    fn finish_operation_at<T>(
        &self,
        token: HistoryOperationTokenV1,
        ended: Instant,
        result: Result<T>,
    ) -> Result<T> {
        self.account_operation(token.operation, token.started, ended);
        self.observe_authority_at(result, ended)
    }
    fn capture(&self, now: Instant, incomplete: bool) -> CheckedHistoryMeasurementV1 {
        let mut clamped = false;
        let exchange = self.exchange.get();
        let selected = exchange.and_then(|exchange| exchange.selected);
        let budget_start = exchange.and_then(|exchange| exchange.started);
        let page_ordinal = exchange
            .and_then(|exchange| exchange.page_ordinal)
            .map(|value| {
                clamped |= value > u64::from(MAX_PAGE_ORDINAL);
                value.min(u64::from(MAX_PAGE_ORDINAL)) as u16
            });
        let pre_budget_callback_calls =
            exchange.map_or(0, |exchange| exchange.pre_budget_callback_calls);
        clamped |= pre_budget_callback_calls > 1;
        let history_cost = self.history_cost.get().bounded(&mut clamped);
        let exchange_cost = exchange
            .filter(|exchange| exchange.started.is_some())
            .map(|exchange| exchange.cost.bounded(&mut clamped));
        let selected_budget_us = selected.zip(budget_start).map(|(deadline, started)| {
            bounded_micros(deadline.saturating_duration_since(started), &mut clamped)
        });
        let caller_remaining_at_budget_start_us =
            self.caller_deadline
                .zip(budget_start)
                .map(|(deadline, started)| {
                    bounded_micros(deadline.saturating_duration_since(started), &mut clamped)
                });
        let caller_remaining_at_failure_us = self
            .caller_deadline
            .map(|deadline| bounded_micros(deadline.saturating_duration_since(now), &mut clamped));
        let selected_remaining_at_failure_us = selected
            .map(|deadline| bounded_micros(deadline.saturating_duration_since(now), &mut clamped));
        let history_elapsed_us =
            bounded_micros(now.saturating_duration_since(self.started), &mut clamped);
        let exchange_elapsed_us = budget_start
            .map(|started| bounded_micros(now.saturating_duration_since(started), &mut clamped));
        let pre_budget_callback_us = bounded_micros(
            exchange.map_or(Duration::ZERO, |exchange| {
                exchange.pre_budget_callback_elapsed
            }),
            &mut clamped,
        );
        CheckedHistoryMeasurementV1 {
            phase: exchange
                .map(|exchange| exchange.phase)
                .or(self.operation_phase),
            page_ordinal,
            check_site: self.check_site.get(),
            checkpoint: self.checkpoint.get(),
            selected_limit: exchange.and_then(|exchange| exchange.selected_limit),
            selected_budget_us,
            caller_remaining_at_budget_start_us,
            caller_remaining_at_failure_us,
            selected_remaining_at_failure_us,
            history_elapsed_us,
            exchange_elapsed_us,
            pre_budget_callback_calls: pre_budget_callback_calls.min(1) as u8,
            pre_budget_callback_us,
            history_cost,
            exchange_cost,
            clamped,
            incomplete,
        }
    }
    pub(super) fn record(
        &self,
        stage: CheckedHistoryStageV1,
        io_kind: Option<CheckedHistoryIoKindV1>,
        error: AuthorityError,
    ) {
        // Do not sample a new clock or build new evidence after the first error.
        if let Some(first) = self.first.take() {
            self.first.set(Some(first));
            return;
        }
        self.record_at(stage, io_kind, error, Instant::now());
    }
    fn record_at(
        &self,
        stage: CheckedHistoryStageV1,
        io_kind: Option<CheckedHistoryIoKindV1>,
        error: AuthorityError,
        now: Instant,
    ) {
        match self.first.take() {
            Some(first) => self.first.set(Some(first)),
            None => self.first.set(Some(CheckedHistoryFailureV1 {
                stage,
                io_kind,
                error,
                measurement: self.capture(now, false),
            })),
        }
    }
    pub(super) fn observe_io<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result {
            if self.io_kind.get().is_none() {
                self.io_kind.set(Some(classify_io(error.kind())));
            }
        }
        result
    }
    pub(super) fn observe_authority<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            self.record(self.stage.get(), self.io_kind.get(), *error);
        }
        result
    }
    fn observe_authority_at<T>(&self, result: Result<T>, now: Instant) -> Result<T> {
        if let Err(error) = &result {
            self.record_at(self.stage.get(), self.io_kind.get(), *error, now);
        }
        result
    }
    pub(super) fn into_failure(self, error: AuthorityError) -> CheckedHistoryFailureV1 {
        match self.first.take() {
            Some(first) => first,
            None => CheckedHistoryFailureV1 {
                stage: self.stage.get(),
                io_kind: self.io_kind.get(),
                error,
                measurement: self.capture(Instant::now(), true),
            },
        }
    }
}

/// Only Some takes observational clock samples. The exact callback runs once.
pub(super) fn callback_observed(
    observer: Option<&HistoryObserverV1>,
    callback: impl FnOnce() -> Result<()>,
) -> Result<()> {
    callback_observed_with_clock(observer, callback, Instant::now)
}
fn callback_observed_with_clock(
    observer: Option<&HistoryObserverV1>,
    callback: impl FnOnce() -> Result<()>,
    mut clock: impl FnMut() -> Instant,
) -> Result<()> {
    match observer {
        None => callback(),
        Some(observer) => {
            observer.checkpoint(CheckedHistoryCheckpointV1::Callback);
            let started = clock();
            let result = callback();
            let ended = clock();
            observer.account_operation(HistoryOperationV1::Callback, started, ended);
            if let Err(error) = &result {
                observer.record_at(CheckedHistoryStageV1::SourceCallback, None, *error, ended);
            }
            result
        }
    }
}
pub(super) fn finish_operation_observed<T>(
    observer: Option<&HistoryObserverV1>,
    token: Option<HistoryOperationTokenV1>,
    result: Result<T>,
) -> Result<T> {
    finish_operation_observed_with_clock(observer, token, result, Instant::now)
}
fn finish_operation_observed_with_clock<T>(
    observer: Option<&HistoryObserverV1>,
    token: Option<HistoryOperationTokenV1>,
    result: Result<T>,
    clock: impl FnOnce() -> Instant,
) -> Result<T> {
    match (observer, token) {
        (Some(observer), Some(token)) => observer.finish_operation_at(token, clock(), result),
        _ => result,
    }
}

pub(super) fn classify_io(kind: io::ErrorKind) -> CheckedHistoryIoKindV1 {
    match kind {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => CheckedHistoryIoKindV1::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected => CheckedHistoryIoKindV1::Closed,
        io::ErrorKind::ConnectionRefused => CheckedHistoryIoKindV1::Refused,
        _ => CheckedHistoryIoKindV1::Other,
    }
}

/// Classify only the bound already selected by the unchanged kernel. Neither
/// this label nor an I/O timeout establishes native permission expiry.
pub(super) fn selected_deadline_stage(
    selected: std::time::Instant,
    caller: Option<std::time::Instant>,
) -> CheckedHistoryStageV1 {
    if caller.is_some_and(|caller| selected < caller) {
        CheckedHistoryStageV1::ExchangeDeadline
    } else {
        CheckedHistoryStageV1::CallerDeadline
    }
}

pub(super) type HistoryPhaseV1 = CheckedHistoryPhaseV1;
#[derive(Clone, Copy)]
pub(super) enum HistoryCallStepV1 {
    Connect,
    Handshake,
    PeerBinding,
    RequestBuild,
    RequestWrite,
    ResponseRead,
    Response,
}
impl HistoryPhaseV1 {
    pub(super) fn stage(self, step: HistoryCallStepV1) -> CheckedHistoryStageV1 {
        use CheckedHistoryStageV1 as S;
        use HistoryCallStepV1 as C;
        match (self, step) {
            (Self::Admission, C::Connect) => S::AdmissionConnect,
            (Self::Admission, C::Handshake) => S::AdmissionHandshake,
            (Self::Admission, C::PeerBinding) => S::AdmissionPeerBinding,
            (Self::Admission, C::RequestBuild) => S::AdmissionRequestBuild,
            (Self::Admission, C::RequestWrite) => S::AdmissionRequestWrite,
            (Self::Admission, C::ResponseRead) => S::AdmissionResponseRead,
            (Self::Admission, C::Response) => S::AdmissionResponse,
            (Self::Snapshot, C::Connect) => S::SnapshotConnect,
            (Self::Snapshot, C::Handshake) => S::SnapshotHandshake,
            (Self::Snapshot, C::PeerBinding) => S::SnapshotPeerBinding,
            (Self::Snapshot, C::RequestBuild) => S::SnapshotRequestBuild,
            (Self::Snapshot, C::RequestWrite) => S::SnapshotRequestWrite,
            (Self::Snapshot, C::ResponseRead) => S::SnapshotResponseRead,
            (Self::Snapshot, C::Response) => S::SnapshotResponse,
            (Self::Page, C::Connect) => S::PageConnect,
            (Self::Page, C::Handshake) => S::PageHandshake,
            (Self::Page, C::PeerBinding) => S::PagePeerBinding,
            (Self::Page, C::RequestBuild) => S::PageRequestBuild,
            (Self::Page, C::RequestWrite) => S::PageRequestWrite,
            (Self::Page, C::ResponseRead) => S::PageResponseRead,
            (Self::Page, C::Response) => S::PageResponse,
        }
    }
}

/// Borrows the SAME maintained stream. Override the complete operations used
/// by framing so its specialized methods, retry behavior and flush run once.
/// The wrapper owns no stream, buffer, drop behavior, deadline or permission.
struct ObservedFrameIoV1<'a, S> {
    inner: &'a mut S,
    observer: &'a HistoryObserverV1,
}
impl<S: Read> Read for ObservedFrameIoV1<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.observer.observe_io(self.inner.read(bytes))
    }
    fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.observer.observe_io(self.inner.read_exact(bytes))
    }
}
impl<S: Write> Write for ObservedFrameIoV1<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.observer.observe_io(self.inner.write(bytes))
    }
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.observer.observe_io(self.inner.write_all(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.observer.observe_io(self.inner.flush())
    }
}
pub(super) fn read_frame_observed<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    observer: Option<&HistoryObserverV1>,
) -> Result<T> {
    match observer {
        Some(observer) => {
            let token = observer.start_operation(HistoryOperationV1::FrameRead);
            let result = super::read_frame(&mut ObservedFrameIoV1 {
                inner: stream,
                observer,
            });
            observer.finish_operation_at(token, Instant::now(), result)
        }
        None => super::read_frame(stream),
    }
}
pub(super) fn write_frame_observed<T: serde::Serialize>(
    stream: &mut impl Write,
    message: &T,
    observer: Option<&HistoryObserverV1>,
) -> Result<()> {
    match observer {
        Some(observer) => {
            let token = observer.start_operation(HistoryOperationV1::FrameWrite);
            let result = super::write_frame(
                &mut ObservedFrameIoV1 {
                    inner: stream,
                    observer,
                },
                message,
            );
            observer.finish_operation_at(token, Instant::now(), result)
        }
        None => super::write_frame(stream, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_admission_phase_is_truthful_before_transport_and_during_validation() {
        let observer =
            HistoryObserverV1::with_admission_deadline(Instant::now() + Duration::from_secs(30));
        observer.enter(CheckedHistoryStageV1::AdmissionRequestValidation);
        let result: Result<()> = observer.observe_authority(Err(AuthorityError::Permission));
        assert!(matches!(result, Err(AuthorityError::Permission)));
        let failure = observer.into_failure(AuthorityError::Uncertain);
        assert!(failure.stage() == CheckedHistoryStageV1::AdmissionRequestValidation);
        assert!(failure.measurement().phase() == Some(CheckedHistoryPhaseV1::Admission));
        assert!(failure.measurement().page_ordinal().is_none());
        assert!(failure.measurement().check_site().is_none());
        assert!(failure.measurement().checkpoint() == CheckedHistoryCheckpointV1::Validation);
        assert!(matches!(failure.into_error(), AuthorityError::Permission));
        let observer =
            HistoryObserverV1::with_admission_deadline(Instant::now() + Duration::from_secs(30));
        observer.begin_exchange(HistoryPhaseV1::Admission);
        let started = Instant::now();
        observer.select_deadline(started, started + Duration::from_secs(10));
        // The shared kernel ends its selected transport exchange on success;
        // later original caller-bound validation must not retain that limit.
        observer.end_exchange();
        observer.enter(CheckedHistoryStageV1::AdmissionCommittedHeadValidation);
        let _: Result<()> = observer.observe_authority(Err(AuthorityError::CorruptHistory));
        let failure = observer.into_failure(AuthorityError::Uncertain);
        assert!(failure.measurement().phase() == Some(CheckedHistoryPhaseV1::Admission));
        assert!(failure.measurement().selected_limit().is_none());
        assert!(failure.measurement().selected_budget_us().is_none());
        assert!(failure
            .measurement()
            .selected_remaining_at_failure_us()
            .is_none());
        assert!(failure.measurement().exchange_elapsed_us().is_none());
        assert!(failure.measurement().exchange_cost().is_none());
        assert!(failure
            .measurement()
            .caller_remaining_at_failure_us()
            .is_some());
        assert!(matches!(
            failure.into_error(),
            AuthorityError::CorruptHistory
        ));
    }

    #[test]
    fn pure_admission_transport_stages_are_never_snapshot_or_page() {
        use CheckedHistoryStageV1 as S;
        use HistoryCallStepV1 as C;
        for (step, expected) in [
            (C::Connect, S::AdmissionConnect),
            (C::Handshake, S::AdmissionHandshake),
            (C::PeerBinding, S::AdmissionPeerBinding),
            (C::RequestBuild, S::AdmissionRequestBuild),
            (C::RequestWrite, S::AdmissionRequestWrite),
            (C::ResponseRead, S::AdmissionResponseRead),
            (C::Response, S::AdmissionResponse),
        ] {
            assert!(HistoryPhaseV1::Admission.stage(step) == expected);
        }
    }

    fn callback_at(
        observer: &HistoryObserverV1,
        started: Instant,
        ended: Instant,
        result: Result<()>,
    ) -> Result<()> {
        let mut samples = [started, ended].into_iter();
        let result = callback_observed_with_clock(
            Some(observer),
            || result,
            || samples.next().expect("exactly two observational samples"),
        );
        assert!(samples.next().is_none());
        result
    }

    fn operation_at(
        observer: &HistoryObserverV1,
        operation: HistoryOperationV1,
        started: Instant,
        ended: Instant,
        result: Result<()>,
    ) -> Result<()> {
        observer.finish_operation_at(
            HistoryOperationTokenV1 { operation, started },
            ended,
            result,
        )
    }

    #[test]
    fn measurement_none_callback_keeps_result_and_samples_no_added_clock() {
        let calls = Cell::new(0);
        for original in [Ok(()), Err(AuthorityError::Permission)] {
            let result = callback_observed_with_clock(
                None,
                || {
                    calls.set(calls.get() + 1);
                    original
                },
                || panic!("no observer must never sample an observational clock"),
            );
            assert!(matches!(
                (original, result),
                (Ok(()), Ok(()))
                    | (
                        Err(AuthorityError::Permission),
                        Err(AuthorityError::Permission)
                    )
            ));
        }
        assert_eq!(calls.get(), 2);
        let result: Result<()> = finish_operation_observed_with_clock(
            None,
            None,
            Err(AuthorityError::Authentication),
            || panic!("no observer must not sample a completion clock"),
        );
        assert!(matches!(result, Err(AuthorityError::Authentication)));
    }

    #[test]
    fn measurement_every_failed_complete_operation_counts_its_partial_work() {
        let base = Instant::now();
        for (operation, stage) in [
            (
                HistoryOperationV1::Connect,
                CheckedHistoryStageV1::PageConnect,
            ),
            (
                HistoryOperationV1::Handshake,
                CheckedHistoryStageV1::PageHandshake,
            ),
            (
                HistoryOperationV1::FrameWrite,
                CheckedHistoryStageV1::PageRequestWrite,
            ),
            (
                HistoryOperationV1::FrameRead,
                CheckedHistoryStageV1::PageResponseRead,
            ),
        ] {
            let observer = HistoryObserverV1::new_at(base, Some(base + Duration::from_secs(30)));
            observer.begin_exchange(HistoryPhaseV1::Page);
            observer.select_deadline(base, base + Duration::from_secs(10));
            observer.enter(stage);
            let result = operation_at(
                &observer,
                operation,
                base,
                base + Duration::from_millis(7),
                Err(AuthorityError::Authentication),
            );
            assert!(matches!(result, Err(AuthorityError::Authentication)));
            let failure = observer.into_failure(AuthorityError::Uncertain);
            assert!(failure.stage() == stage);
            let measurement = failure.measurement();
            let cost = measurement.exchange_cost().unwrap();
            assert_eq!(
                cost.connect_calls()
                    + cost.handshake_calls()
                    + cost.frame_write_calls()
                    + cost.frame_read_calls(),
                1
            );
            assert_eq!(
                cost.connect_us()
                    + cost.handshake_us()
                    + cost.frame_write_us()
                    + cost.frame_read_us(),
                7_000
            );
            assert_eq!(cost.callback_calls(), 0);
            assert_eq!(measurement.exchange_elapsed_us(), Some(7_000));
            assert!(!measurement.incomplete());
            assert!(matches!(
                failure.into_error(),
                AuthorityError::Authentication
            ));
        }
    }

    #[test]
    fn measurement_nonoverlapping_spans_include_failed_operation_before_freeze() {
        let base = Instant::now();
        let at = |millis| base + Duration::from_millis(millis);
        let observer = HistoryObserverV1::new_at(base, Some(base + Duration::from_secs(30)));
        observer.replay_check(CheckedHistoryCheckSiteV1::ReplayInitial);
        callback_at(&observer, at(0), at(2), Ok(())).unwrap();
        observer.begin_exchange(HistoryPhaseV1::Snapshot);
        callback_at(&observer, at(2), at(5), Ok(())).unwrap();
        observer.select_deadline(at(5), at(10_005));
        observer.exchange_check(CheckedHistoryCheckSiteV1::BeforeConnect);
        callback_at(&observer, at(5), at(9), Ok(())).unwrap();
        for (operation, start, end) in [
            (HistoryOperationV1::Connect, 9, 11),
            (HistoryOperationV1::Handshake, 11, 14),
            (HistoryOperationV1::FrameWrite, 14, 19),
        ] {
            operation_at(&observer, operation, at(start), at(end), Ok(())).unwrap();
        }
        observer.enter(CheckedHistoryStageV1::SnapshotResponseRead);
        let result = operation_at(
            &observer,
            HistoryOperationV1::FrameRead,
            at(19),
            at(26),
            Err(AuthorityError::Uncertain),
        );
        assert!(matches!(result, Err(AuthorityError::Uncertain)));

        // Later accounting, context changes and errors cannot alter the snapshot.
        observer.begin_exchange(HistoryPhaseV1::Page);
        observer.account_operation(HistoryOperationV1::Callback, at(30), at(300));
        observer.record_at(
            CheckedHistoryStageV1::SourceCallback,
            None,
            AuthorityError::Permission,
            at(400),
        );
        let failure = observer.into_failure(AuthorityError::Permission);
        assert!(failure.stage() == CheckedHistoryStageV1::SnapshotResponseRead);
        let measurement = failure.measurement();
        assert!(measurement.phase() == Some(CheckedHistoryPhaseV1::Snapshot));
        assert!(measurement.checkpoint() == CheckedHistoryCheckpointV1::Operation);
        assert!(measurement.check_site().is_none());
        assert_eq!(measurement.history_elapsed_us(), 26_000);
        assert_eq!(measurement.exchange_elapsed_us(), Some(21_000));
        assert_eq!(measurement.pre_budget_callback_calls(), 1);
        assert_eq!(measurement.pre_budget_callback_us(), 3_000);
        assert_eq!(measurement.selected_budget_us(), Some(10_000_000));
        assert_eq!(
            measurement.caller_remaining_at_budget_start_us(),
            Some(29_995_000)
        );
        assert_eq!(
            measurement.selected_remaining_at_failure_us(),
            Some(9_979_000)
        );
        assert!(measurement.selected_limit() == Some(CheckedHistorySelectedLimitV1::Exchange));
        let history = measurement.history_cost();
        let exchange = measurement.exchange_cost().unwrap();
        assert_eq!(
            (
                history.callback_calls(),
                history.callback_us(),
                history.callback_max_us()
            ),
            (3, 9_000, 4_000)
        );
        assert_eq!(
            (
                exchange.callback_calls(),
                exchange.callback_us(),
                exchange.callback_max_us()
            ),
            (1, 4_000, 4_000)
        );
        assert_eq!(
            (exchange.connect_calls(), exchange.connect_us()),
            (1, 2_000)
        );
        assert_eq!(
            (exchange.handshake_calls(), exchange.handshake_us()),
            (1, 3_000)
        );
        assert_eq!(
            (exchange.frame_write_calls(), exchange.frame_write_us()),
            (1, 5_000)
        );
        assert_eq!(
            (exchange.frame_read_calls(), exchange.frame_read_us()),
            (1, 7_000)
        );
        assert_eq!(
            exchange.callback_us()
                + exchange.connect_us()
                + exchange.handshake_us()
                + exchange.frame_write_us()
                + exchange.frame_read_us(),
            21_000
        );
        assert!(!measurement.clamped());
        assert!(!measurement.incomplete());
        assert!(matches!(failure.into_error(), AuthorityError::Uncertain));
    }

    #[test]
    fn measurement_pre_callback_callback_and_post_callback_are_distinct() {
        let base = Instant::now();
        let caller = base + Duration::from_secs(30);
        let selected = base + Duration::from_secs(10);
        for checkpoint in [
            CheckedHistoryCheckpointV1::BeforeCallback,
            CheckedHistoryCheckpointV1::Callback,
            CheckedHistoryCheckpointV1::AfterCallback,
        ] {
            let observer = HistoryObserverV1::new_at(base, Some(caller));
            observer.begin_exchange(HistoryPhaseV1::Page);
            observer.select_deadline(base, selected);
            observer.exchange_check(CheckedHistoryCheckSiteV1::BeforeHandshakeIo);
            if checkpoint != CheckedHistoryCheckpointV1::BeforeCallback {
                let result = callback_at(
                    &observer,
                    base,
                    selected,
                    if checkpoint == CheckedHistoryCheckpointV1::Callback {
                        Err(AuthorityError::Permission)
                    } else {
                        Ok(())
                    },
                );
                assert_eq!(
                    result.is_err(),
                    checkpoint == CheckedHistoryCheckpointV1::Callback
                );
            }
            observer.checkpoint(checkpoint);
            observer.record_at(
                CheckedHistoryStageV1::ExchangeDeadline,
                None,
                AuthorityError::Permission,
                selected,
            );
            let failure = observer.into_failure(AuthorityError::Uncertain);
            let measurement = failure.measurement();
            assert!(measurement.checkpoint() == checkpoint);
            assert!(measurement.check_site() == Some(CheckedHistoryCheckSiteV1::BeforeHandshakeIo));
            assert!(measurement.phase() == Some(CheckedHistoryPhaseV1::Page));
            assert_eq!(measurement.page_ordinal(), Some(1));
            assert_eq!(measurement.selected_remaining_at_failure_us(), Some(0));
            assert_eq!(
                measurement.caller_remaining_at_failure_us(),
                Some(20_000_000)
            );
            assert_eq!(
                measurement.history_cost().callback_calls(),
                u32::from(checkpoint != CheckedHistoryCheckpointV1::BeforeCallback)
            );
            assert!(!measurement.incomplete());
            assert!(
                failure.stage()
                    == if checkpoint == CheckedHistoryCheckpointV1::Callback {
                        CheckedHistoryStageV1::SourceCallback
                    } else {
                        CheckedHistoryStageV1::ExchangeDeadline
                    }
            );
        }
    }

    #[test]
    fn measurement_initial_callback_and_selection_do_not_invent_a_budget() {
        let base = Instant::now();
        let caller = base + Duration::from_secs(30);
        let observer = HistoryObserverV1::new_at(base, Some(caller));
        observer.begin_exchange(HistoryPhaseV1::Snapshot);
        let result = callback_at(
            &observer,
            base,
            base + Duration::from_millis(3),
            Err(AuthorityError::Permission),
        );
        assert!(result.is_err());
        let failure = observer.into_failure(AuthorityError::Uncertain);
        let measurement = failure.measurement();
        assert!(measurement.phase() == Some(CheckedHistoryPhaseV1::Snapshot));
        assert!(measurement.check_site() == Some(CheckedHistoryCheckSiteV1::ExchangeInitial));
        assert!(measurement.checkpoint() == CheckedHistoryCheckpointV1::Callback);
        assert_eq!(measurement.pre_budget_callback_calls(), 1);
        assert_eq!(measurement.pre_budget_callback_us(), 3_000);
        assert!(measurement.selected_limit().is_none());
        assert!(measurement.selected_budget_us().is_none());
        assert!(measurement.caller_remaining_at_budget_start_us().is_none());
        assert!(measurement.selected_remaining_at_failure_us().is_none());
        assert!(measurement.exchange_cost().is_none());
        assert!(measurement.exchange_elapsed_us().is_none());

        let observer = HistoryObserverV1::new_at(base, Some(caller));
        observer.begin_exchange(HistoryPhaseV1::Page);
        callback_at(&observer, base, caller, Ok(())).unwrap();
        observer.checkpoint(CheckedHistoryCheckpointV1::DeadlineSelection);
        observer.record_at(
            CheckedHistoryStageV1::CallerDeadline,
            None,
            AuthorityError::Permission,
            caller,
        );
        let failure = observer.into_failure(AuthorityError::Uncertain);
        let measurement = failure.measurement();
        assert!(measurement.checkpoint() == CheckedHistoryCheckpointV1::DeadlineSelection);
        assert!(measurement.check_site().is_none());
        assert!(measurement.selected_budget_us().is_none());
        assert_eq!(measurement.caller_remaining_at_failure_us(), Some(0));
        assert!(!measurement.incomplete());
    }

    #[test]
    fn measurement_exchange_reset_and_replay_clear_stale_context() {
        let base = Instant::now();
        let observer = HistoryObserverV1::new_at(base, Some(base + Duration::from_secs(30)));
        observer.begin_exchange(HistoryPhaseV1::Snapshot);
        observer.select_deadline(base, base + Duration::from_secs(10));
        callback_at(&observer, base, base + Duration::from_millis(2), Ok(())).unwrap();
        observer.end_exchange();
        observer.begin_exchange(HistoryPhaseV1::Page);
        observer.select_deadline(
            base + Duration::from_secs(1),
            base + Duration::from_secs(11),
        );
        let measurement = observer.capture(base + Duration::from_secs(1), false);
        assert_eq!(measurement.page_ordinal(), Some(1));
        assert_eq!(measurement.exchange_cost().unwrap().callback_calls(), 0);
        assert_eq!(measurement.history_cost().callback_calls(), 1);
        observer.end_exchange();
        observer.begin_exchange(HistoryPhaseV1::Page);
        assert_eq!(observer.capture(base, false).page_ordinal(), Some(2));
        observer.replay_check(CheckedHistoryCheckSiteV1::ReplayAfterPage);
        let measurement = observer.capture(base + Duration::from_secs(2), false);
        assert!(measurement.phase().is_none());
        assert!(measurement.page_ordinal().is_none());
        assert!(measurement.selected_limit().is_none());
        assert!(measurement.selected_budget_us().is_none());
        assert!(measurement.exchange_cost().is_none());
        assert!(measurement.exchange_elapsed_us().is_none());
        assert!(measurement.check_site() == Some(CheckedHistoryCheckSiteV1::ReplayAfterPage));
        assert_eq!(measurement.history_cost().callback_us(), 2_000);
    }

    #[test]
    fn measurement_caps_all_numeric_fields_and_labels_fallback() {
        let base = Instant::now();
        let caller = base + Duration::from_secs(1_000);
        let observer = HistoryObserverV1::new_at(base, Some(caller));
        observer.pages.set(u64::MAX);
        observer.begin_exchange(HistoryPhaseV1::Page);
        observer.select_deadline(base, caller);
        let mut enormous = CostAccumulator {
            calls: [u64::MAX; 5],
            elapsed: [Duration::MAX; 5],
            callback_max: Duration::MAX,
        };
        enormous.add(HistoryOperationV1::Callback, Duration::MAX);
        observer.history_cost.set(enormous);
        let mut exchange = observer.exchange.get().unwrap();
        exchange.cost = enormous;
        exchange.pre_budget_callback_calls = u64::MAX;
        exchange.pre_budget_callback_elapsed = Duration::MAX;
        observer.exchange.set(Some(exchange));
        let measurement = observer.capture(caller, false);
        assert!(measurement.clamped());
        assert_eq!(measurement.page_ordinal(), Some(MAX_PAGE_ORDINAL));
        assert_eq!(measurement.pre_budget_callback_calls(), 1);
        for value in [
            measurement.pre_budget_callback_us(),
            measurement.history_elapsed_us(),
            measurement.exchange_elapsed_us().unwrap(),
            measurement.selected_budget_us().unwrap(),
            measurement.caller_remaining_at_budget_start_us().unwrap(),
        ] {
            assert_eq!(value, MAX_MICROS);
        }
        for cost in [
            measurement.history_cost(),
            measurement.exchange_cost().unwrap(),
        ] {
            for count in [
                cost.callback_calls(),
                cost.connect_calls(),
                cost.handshake_calls(),
                cost.frame_write_calls(),
                cost.frame_read_calls(),
            ] {
                assert_eq!(count, MAX_COUNT);
            }
            for micros in [
                cost.callback_us(),
                cost.callback_max_us(),
                cost.connect_us(),
                cost.handshake_us(),
                cost.frame_write_us(),
                cost.frame_read_us(),
            ] {
                assert_eq!(micros, MAX_MICROS);
            }
        }
        assert_eq!(measurement.caller_remaining_at_failure_us(), Some(0));
        assert_eq!(measurement.selected_remaining_at_failure_us(), Some(0));
        assert!(measurement.selected_limit() == Some(CheckedHistorySelectedLimitV1::Caller));
        assert!(!measurement.incomplete());

        let failure =
            HistoryObserverV1::new_at(base, None).into_failure(AuthorityError::InvalidBinding);
        assert!(failure.measurement().incomplete());
        assert!(failure
            .measurement()
            .caller_remaining_at_failure_us()
            .is_none());
        assert!(matches!(
            failure.into_error(),
            AuthorityError::InvalidBinding
        ));
    }

    #[test]
    fn selected_deadline_label_uses_only_the_existing_bounds() {
        let selected = std::time::Instant::now();
        assert!(
            selected_deadline_stage(selected, Some(selected))
                == CheckedHistoryStageV1::CallerDeadline
        );
        assert!(
            selected_deadline_stage(selected, Some(selected + std::time::Duration::from_secs(1)))
                == CheckedHistoryStageV1::ExchangeDeadline
        );
        assert!(selected_deadline_stage(selected, None) == CheckedHistoryStageV1::CallerDeadline);
    }

    #[test]
    fn first_failure_retains_original_error_and_classification() {
        let observer = HistoryObserverV1::new();
        observer.record(
            CheckedHistoryStageV1::SourceCallback,
            None,
            AuthorityError::Permission,
        );
        observer.enter(CheckedHistoryStageV1::PageHandshake);
        observer.record(
            CheckedHistoryStageV1::PageHandshake,
            Some(CheckedHistoryIoKindV1::Timeout),
            AuthorityError::Authentication,
        );
        let failure = observer.into_failure(AuthorityError::Uncertain);
        assert!(failure.stage() == CheckedHistoryStageV1::SourceCallback);
        assert!(failure.io_kind().is_none());
        assert!(matches!(failure.into_error(), AuthorityError::Permission));
    }

    #[test]
    fn original_frame_error_survives_the_unchanged_outer_uncertain_mapping() {
        let observer = HistoryObserverV1::new();
        observer.enter(CheckedHistoryStageV1::PageResponseRead);
        // A zero-sized frame is rejected before a body read, exactly as before.
        let mut bytes: &[u8] = &[0, 0, 0, 0];
        let read: Result<u8> = read_frame_observed(&mut bytes, Some(&observer));
        let mapped = read.map_err(|_| AuthorityError::Uncertain);
        assert!(matches!(mapped, Err(AuthorityError::Uncertain)));
        let failure = observer.into_failure(mapped.err().unwrap());
        assert!(failure.stage() == CheckedHistoryStageV1::PageResponseRead);
        assert!(failure.io_kind().is_none());
        assert_eq!(failure.measurement().history_cost().frame_read_calls(), 1);
        assert!(!failure.measurement().incomplete());
        assert!(matches!(failure.into_error(), AuthorityError::Limit));

        let mut bytes: &[u8] = &[0, 0, 0, 0];
        let read: Result<u8> = read_frame_observed(&mut bytes, None);
        assert!(matches!(read, Err(AuthorityError::Limit)));
        assert!(matches!(
            read.map_err(|_| AuthorityError::Uncertain),
            Err(AuthorityError::Uncertain)
        ));
    }

    #[test]
    fn phases_and_io_kinds_have_only_finite_exact_mapping() {
        use CheckedHistoryStageV1 as S;
        use HistoryCallStepV1 as C;
        for (step, snapshot, page) in [
            (C::Connect, S::SnapshotConnect, S::PageConnect),
            (C::Handshake, S::SnapshotHandshake, S::PageHandshake),
            (C::PeerBinding, S::SnapshotPeerBinding, S::PagePeerBinding),
            (
                C::RequestBuild,
                S::SnapshotRequestBuild,
                S::PageRequestBuild,
            ),
            (
                C::RequestWrite,
                S::SnapshotRequestWrite,
                S::PageRequestWrite,
            ),
            (
                C::ResponseRead,
                S::SnapshotResponseRead,
                S::PageResponseRead,
            ),
            (C::Response, S::SnapshotResponse, S::PageResponse),
        ] {
            assert!(HistoryPhaseV1::Snapshot.stage(step) == snapshot);
            assert!(HistoryPhaseV1::Page.stage(step) == page);
        }
        use io::ErrorKind as E;
        use CheckedHistoryIoKindV1 as I;
        for (kind, expected) in [
            (E::TimedOut, I::Timeout),
            (E::WouldBlock, I::Timeout),
            (E::UnexpectedEof, I::Closed),
            (E::BrokenPipe, I::Closed),
            (E::ConnectionAborted, I::Closed),
            (E::ConnectionReset, I::Closed),
            (E::NotConnected, I::Closed),
            (E::ConnectionRefused, I::Refused),
            (E::InvalidData, I::Other),
            (E::Interrupted, I::Other),
        ] {
            assert!(classify_io(kind) == expected);
        }
    }

    #[derive(Default)]
    struct ExactOperations {
        reads: usize,
        writes: usize,
        flushes: usize,
        failure: Option<io::ErrorKind>,
    }
    impl Read for ExactOperations {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("must forward specialized read_exact, not replace its loop")
        }
        fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
            self.reads += 1;
            if let Some(kind) = self.failure {
                return Err(io::Error::from(kind));
            }
            if self.reads == 1 {
                bytes.copy_from_slice(&1_u32.to_be_bytes());
            } else {
                bytes.copy_from_slice(b"0");
            }
            Ok(())
        }
    }
    impl Write for ExactOperations {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("must forward specialized write_all, not replace its loop")
        }
        fn write_all(&mut self, _: &[u8]) -> io::Result<()> {
            self.writes += 1;
            if let Some(kind) = self.failure {
                return Err(io::Error::from(kind));
            }
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn frame_observer_and_none_forward_identical_complete_operations() {
        let observer = HistoryObserverV1::new();
        for optional in [None, Some(&observer)] {
            let mut stream = ExactOperations::default();
            write_frame_observed(&mut stream, &0, optional).unwrap();
            let value: u8 = read_frame_observed(&mut stream, optional).unwrap();
            assert_eq!(value, 0);
            assert_eq!((stream.reads, stream.writes, stream.flushes), (2, 2, 1));
        }
        assert!(observer.io_kind.get().is_none());
        assert!(observer.first.take().is_none());
        let measurement = observer.capture(Instant::now(), false);
        assert_eq!(measurement.history_cost().frame_read_calls(), 1);
        assert_eq!(measurement.history_cost().frame_write_calls(), 1);
        assert_eq!(measurement.history_cost().handshake_calls(), 0);
    }

    #[test]
    fn frame_error_mapping_is_unchanged_with_or_without_observer() {
        let observer = HistoryObserverV1::new();
        observer.enter(CheckedHistoryStageV1::SnapshotResponseRead);
        for optional in [None, Some(&observer)] {
            let mut stream = ExactOperations {
                failure: Some(io::ErrorKind::TimedOut),
                ..Default::default()
            };
            let result: Result<u8> = read_frame_observed(&mut stream, optional);
            assert!(matches!(result, Err(AuthorityError::Uncertain)));
            assert_eq!(stream.reads, 1);
        }
        let failure = observer.into_failure(AuthorityError::Uncertain);
        assert!(failure.stage() == CheckedHistoryStageV1::SnapshotResponseRead);
        assert!(failure.io_kind() == Some(CheckedHistoryIoKindV1::Timeout));
        assert_eq!(failure.measurement().history_cost().frame_read_calls(), 1);
        assert!(!failure.measurement().incomplete());
        assert!(matches!(failure.into_error(), AuthorityError::Uncertain));
    }
}
