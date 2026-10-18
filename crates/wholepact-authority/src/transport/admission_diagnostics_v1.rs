//! Synthetic-only, fixed-size observations. These values own no authority,
//! request, identifier, source, journal, socket, native owner or decision.
use super::history_diagnostics_v1::{classify_io, CheckedHistoryIoKindV1};
use crate::{AuthorityError, Result};
use std::{
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

const MAX_MICROS: u32 = 600_000_000;
const MAX_COUNT: u32 = 1_000_000;
const SPANS: usize = 13;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessStageV1 {
    SourceArm,
    ServerCreate,
    ListenerAccept,
    ResultLookup,
    SocketBinding,
    WaitCurrent,
    TlsSetup,
    TlsHandshake,
    PeerBinding,
    FrameRead,
    SemanticDispatch,
    JournalPreflight,
    ExactRequest,
    Publication,
    Apply,
    Append,
    FinalCurrent,
    Commit,
    ControlledResult,
    SnapshotRecord,
    OutputCheck,
    FrameWrite,
    CloseFlush,
    WorkerDisplay,
    FixtureDrain,
    FixtureReceipt,
    FixtureCorrelation,
}
const STAGES: [AdmissionWitnessStageV1; 27] = {
    use AdmissionWitnessStageV1::*;
    [
        SourceArm,
        ServerCreate,
        ListenerAccept,
        ResultLookup,
        SocketBinding,
        WaitCurrent,
        TlsSetup,
        TlsHandshake,
        PeerBinding,
        FrameRead,
        SemanticDispatch,
        JournalPreflight,
        ExactRequest,
        Publication,
        Apply,
        Append,
        FinalCurrent,
        Commit,
        ControlledResult,
        SnapshotRecord,
        OutputCheck,
        FrameWrite,
        CloseFlush,
        WorkerDisplay,
        FixtureDrain,
        FixtureReceipt,
        FixtureCorrelation,
    ]
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessAttributionV1 {
    SelectedServer,
    ExactRequest,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessResultV1 {
    NotObserved,
    ReturnedOk,
    ReturnedErr,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessCompletionV1 {
    NotObserved,
    Received,
    Disconnected,
    Panicked,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessCommitV1 {
    NotObserved,
    Entered,
    ReturnedOk,
    ReturnedErr,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessReceiptGateV1 {
    NotObserved,
    Unfocused,
    EpochMismatch,
    Revoked,
    Closing,
    ClockRejected,
    Retained,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessCorrelationV1 {
    NotObserved,
    Matched,
    Rejected,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdmissionWitnessSpanV1 {
    Worker,
    SourceArm,
    ServerCreate,
    Accept,
    Connection,
    Handshake,
    FrameRead,
    Dispatch,
    Publication,
    Append,
    Commit,
    FrameWrite,
    FixtureFinish,
}

macro_rules! getters {
    ($($name:ident: $ty:ty),* $(,)?) => { $(pub fn $name(&self) -> $ty { self.$name })* };
}
#[derive(Clone, Copy)]
pub struct AdmissionWitnessErrorV1 {
    stage: AdmissionWitnessStageV1,
    attribution: AdmissionWitnessAttributionV1,
    io_kind: Option<CheckedHistoryIoKindV1>,
    error: AuthorityError,
}
impl AdmissionWitnessErrorV1 {
    getters! { stage: AdmissionWitnessStageV1, attribution: AdmissionWitnessAttributionV1,
    io_kind: Option<CheckedHistoryIoKindV1>, error: AuthorityError }
}
pub struct AdmissionWitnessCostV1 {
    calls: u32,
    elapsed_us: Option<u32>,
}
impl AdmissionWitnessCostV1 {
    getters! { calls: u32, elapsed_us: Option<u32> }
}
/// A missing observation never establishes rollback or absence of durable state.
/// Nested spans include their children and must not be added into a timeline.
pub struct AdmissionWitnessDiagnosticV1 {
    first_semantic: Option<AdmissionWitnessErrorV1>,
    first_connection: Option<AdmissionWitnessErrorV1>,
    worker_result: AdmissionWitnessResultV1,
    fixture_result: AdmissionWitnessResultV1,
    worker_error: Option<AuthorityError>,
    fixture_error: Option<AuthorityError>,
    worker_stage: Option<AdmissionWitnessStageV1>,
    fixture_stage: Option<AdmissionWitnessStageV1>,
    completion: AdmissionWitnessCompletionV1,
    commit: AdmissionWitnessCommitV1,
    controlled_result: Option<bool>,
    snapshot_recorded: Option<bool>,
    receipt_gate: AdmissionWitnessReceiptGateV1,
    final_correlation: AdmissionWitnessCorrelationV1,
    cost: [AdmissionWitnessCostV1; SPANS],
    clamped: bool,
    incomplete: bool,
}
impl AdmissionWitnessDiagnosticV1 {
    pub fn first_semantic(&self) -> Option<&AdmissionWitnessErrorV1> {
        self.first_semantic.as_ref()
    }
    pub fn first_connection(&self) -> Option<&AdmissionWitnessErrorV1> {
        self.first_connection.as_ref()
    }
    pub fn cost(&self, span: AdmissionWitnessSpanV1) -> &AdmissionWitnessCostV1 {
        &self.cost[span as usize]
    }
    getters! {
        worker_result: AdmissionWitnessResultV1, fixture_result: AdmissionWitnessResultV1,
        worker_error: Option<AuthorityError>, fixture_error: Option<AuthorityError>,
        worker_stage: Option<AdmissionWitnessStageV1>, fixture_stage: Option<AdmissionWitnessStageV1>,
        completion: AdmissionWitnessCompletionV1, commit: AdmissionWitnessCommitV1,
        controlled_result: Option<bool>, snapshot_recorded: Option<bool>,
        receipt_gate: AdmissionWitnessReceiptGateV1, final_correlation: AdmissionWitnessCorrelationV1,
        clamped: bool, incomplete: bool,
    }
}
#[derive(Clone, Copy, Default)]
struct Cost {
    calls: u64,
    completed: u64,
    elapsed: Duration,
}
struct State {
    first_semantic: Option<AdmissionWitnessErrorV1>,
    first_connection: Option<AdmissionWitnessErrorV1>,
    worker_result: AdmissionWitnessResultV1,
    fixture_result: AdmissionWitnessResultV1,
    worker_error: Option<AuthorityError>,
    fixture_error: Option<AuthorityError>,
    worker_stage: Option<AdmissionWitnessStageV1>,
    fixture_stage: Option<AdmissionWitnessStageV1>,
    completion: AdmissionWitnessCompletionV1,
    commit: AdmissionWitnessCommitV1,
    controlled_result: Option<bool>,
    snapshot_recorded: Option<bool>,
    receipt_gate: AdmissionWitnessReceiptGateV1,
    final_correlation: AdmissionWitnessCorrelationV1,
    cost: [Cost; SPANS],
}
impl Default for State {
    fn default() -> Self {
        Self {
            first_semantic: None,
            first_connection: None,
            worker_result: AdmissionWitnessResultV1::NotObserved,
            fixture_result: AdmissionWitnessResultV1::NotObserved,
            worker_error: None,
            fixture_error: None,
            worker_stage: None,
            fixture_stage: None,
            completion: AdmissionWitnessCompletionV1::NotObserved,
            commit: AdmissionWitnessCommitV1::NotObserved,
            controlled_result: None,
            snapshot_recorded: None,
            receipt_gate: AdmissionWitnessReceiptGateV1::NotObserved,
            final_correlation: AdmissionWitnessCorrelationV1::NotObserved,
            cost: [Cost::default(); SPANS],
        }
    }
}
struct Shared {
    state: Mutex<State>,
    // Only the synchronous selected worker/connection changes these. Fixture
    // failures use an explicit local stage and cannot overwrite a running worker.
    stage: AtomicU8,
    exact: AtomicBool,
    io_kind: AtomicU8,
    incomplete: AtomicBool,
}
#[derive(Clone)]
pub(crate) struct AdmissionWitnessObserverV1(Arc<Shared>);
impl AdmissionWitnessObserverV1 {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State::default()),
            stage: AtomicU8::new(AdmissionWitnessStageV1::SourceArm as u8),
            exact: AtomicBool::new(false),
            io_kind: AtomicU8::new(0),
            incomplete: AtomicBool::new(false),
        }))
    }
    // Never hold an observation guard while invoking source, journal, native,
    // clock-control, I/O, callback, result delivery or cleanup operations.
    fn update(&self, update: impl FnOnce(&mut State)) {
        if let Ok(mut state) = self.0.state.try_lock() {
            update(&mut state);
        } else {
            self.0.incomplete.store(true, Ordering::Relaxed);
        }
    }
    pub(crate) fn enter(&self, stage: AdmissionWitnessStageV1) {
        self.0.stage.store(stage as u8, Ordering::Relaxed);
        self.0.io_kind.store(0, Ordering::Relaxed);
    }
    fn stage(&self) -> AdmissionWitnessStageV1 {
        STAGES[self.0.stage.load(Ordering::Relaxed) as usize]
    }
    pub(crate) fn begin_connection(&self) {
        self.0.exact.store(false, Ordering::Relaxed);
        self.enter(AdmissionWitnessStageV1::SocketBinding);
    }
    pub(crate) fn end_connection(&self) {
        self.0.exact.store(false, Ordering::Relaxed);
    }
    /// Called ONLY after the original journal-pointer, peer and request equality.
    pub(crate) fn exact_request_matched(&self) {
        self.0.exact.store(true, Ordering::Relaxed);
    }
    pub(crate) fn observe_io<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result {
            let kind = match classify_io(error.kind()) {
                CheckedHistoryIoKindV1::Timeout => 1,
                CheckedHistoryIoKindV1::Closed => 2,
                CheckedHistoryIoKindV1::Refused => 3,
                CheckedHistoryIoKindV1::Other => 4,
            };
            let _ = self
                .0
                .io_kind
                .compare_exchange(0, kind, Ordering::Relaxed, Ordering::Relaxed);
        }
        result
    }
    fn error(&self, error: AuthorityError) -> AdmissionWitnessErrorV1 {
        AdmissionWitnessErrorV1 {
            stage: self.stage(),
            attribution: if self.0.exact.load(Ordering::Relaxed) {
                AdmissionWitnessAttributionV1::ExactRequest
            } else {
                AdmissionWitnessAttributionV1::SelectedServer
            },
            io_kind: match self.0.io_kind.load(Ordering::Relaxed) {
                1 => Some(CheckedHistoryIoKindV1::Timeout),
                2 => Some(CheckedHistoryIoKindV1::Closed),
                3 => Some(CheckedHistoryIoKindV1::Refused),
                4 => Some(CheckedHistoryIoKindV1::Other),
                _ => None,
            },
            error,
        }
    }
    pub(crate) fn observe_semantic<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            let error = self.error(*error);
            self.update(|s| {
                if s.first_semantic.is_none() {
                    s.first_semantic = Some(error);
                }
            });
        }
        result
    }
    pub(crate) fn observe_connection<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            let error = self.error(*error);
            self.update(|s| {
                if s.first_connection.is_none() {
                    s.first_connection = Some(error);
                }
            });
        }
        result
    }
    pub(crate) fn observe_worker_failure<T>(&self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.worker_result(&result);
        }
        result
    }
    pub(crate) fn worker_result<T>(&self, result: &Result<T>) {
        let error = result.as_ref().err().copied();
        let stage = error.map(|_| self.stage());
        self.update(|s| {
            if s.worker_result == AdmissionWitnessResultV1::NotObserved {
                s.worker_result = if error.is_some() {
                    AdmissionWitnessResultV1::ReturnedErr
                } else {
                    AdmissionWitnessResultV1::ReturnedOk
                };
                s.worker_error = error;
                s.worker_stage = stage;
            }
        });
    }
    pub(crate) fn fixture_result<T>(&self, stage: AdmissionWitnessStageV1, result: &Result<T>) {
        let error = result.as_ref().err().copied();
        self.update(|s| {
            if s.fixture_result == AdmissionWitnessResultV1::NotObserved {
                s.fixture_result = if error.is_some() {
                    AdmissionWitnessResultV1::ReturnedErr
                } else {
                    AdmissionWitnessResultV1::ReturnedOk
                };
                s.fixture_error = error;
                s.fixture_stage = error.map(|_| stage);
            }
        });
    }
    pub(crate) fn completion(&self, completion: AdmissionWitnessCompletionV1) {
        self.update(|s| {
            if s.completion != AdmissionWitnessCompletionV1::Panicked
                && (s.completion != AdmissionWitnessCompletionV1::Disconnected
                    || completion == AdmissionWitnessCompletionV1::Panicked)
            {
                s.completion = completion;
            }
        });
    }
    pub(crate) fn commit_entered(&self) {
        self.update(|s| s.commit = AdmissionWitnessCommitV1::Entered);
    }
    pub(crate) fn commit_returned<T, E>(&self, result: &std::result::Result<T, E>) {
        self.update(|s| {
            s.commit = if result.is_ok() {
                AdmissionWitnessCommitV1::ReturnedOk
            } else {
                AdmissionWitnessCommitV1::ReturnedErr
            }
        });
    }
    pub(crate) fn controlled_result(&self, controlled: bool) {
        self.update(|s| s.controlled_result = Some(controlled));
    }
    pub(crate) fn snapshot_recorded(&self) {
        self.update(|s| s.snapshot_recorded = Some(true));
    }
    pub(crate) fn receipt_gate(&self, gate: AdmissionWitnessReceiptGateV1) {
        self.update(|s| s.receipt_gate = gate);
    }
    pub(crate) fn final_correlation(&self, correlation: AdmissionWitnessCorrelationV1) {
        self.update(|s| s.final_correlation = correlation);
    }
    pub(crate) fn start_span(&self, span: AdmissionWitnessSpanV1) -> AdmissionWitnessSpanGuardV1 {
        self.start_span_at(span, Instant::now())
    }
    fn start_span_at(
        &self,
        span: AdmissionWitnessSpanV1,
        started: Instant,
    ) -> AdmissionWitnessSpanGuardV1 {
        self.update(|s| {
            s.cost[span as usize].calls = s.cost[span as usize].calls.saturating_add(1)
        });
        AdmissionWitnessSpanGuardV1 {
            observer: self.clone(),
            span,
            started,
        }
    }
    fn finish_span(&self, span: AdmissionWitnessSpanV1, elapsed: Duration) {
        self.update(|s| {
            let cost = &mut s.cost[span as usize];
            cost.completed = cost.completed.saturating_add(1);
            cost.elapsed = cost.elapsed.saturating_add(elapsed);
        });
    }
    pub(crate) fn snapshot(&self) -> AdmissionWitnessDiagnosticV1 {
        match self.0.state.try_lock() {
            Ok(state) => Self::bounded(&state, self.0.incomplete.load(Ordering::Relaxed)),
            Err(_) => {
                self.0.incomplete.store(true, Ordering::Relaxed);
                Self::bounded(&State::default(), true)
            }
        }
    }
    fn bounded(state: &State, mut incomplete: bool) -> AdmissionWitnessDiagnosticV1 {
        let mut clamped = false;
        incomplete |= state.worker_result == AdmissionWitnessResultV1::NotObserved
            || state.fixture_result == AdmissionWitnessResultV1::NotObserved
            || state.completion != AdmissionWitnessCompletionV1::Received;
        let cost = std::array::from_fn(|index| {
            let cost = state.cost[index];
            clamped |= cost.calls > u64::from(MAX_COUNT)
                || cost.elapsed > Duration::from_micros(u64::from(MAX_MICROS));
            incomplete |= cost.completed != cost.calls;
            AdmissionWitnessCostV1 {
                calls: cost.calls.min(u64::from(MAX_COUNT)) as u32,
                elapsed_us: (cost.calls != 0 && cost.completed == cost.calls)
                    .then(|| cost.elapsed.as_micros().min(u128::from(MAX_MICROS)) as u32),
            }
        });
        AdmissionWitnessDiagnosticV1 {
            first_semantic: state.first_semantic,
            first_connection: state.first_connection,
            worker_result: state.worker_result,
            fixture_result: state.fixture_result,
            worker_error: state.worker_error,
            fixture_error: state.fixture_error,
            worker_stage: state.worker_stage,
            fixture_stage: state.fixture_stage,
            completion: state.completion,
            commit: state.commit,
            controlled_result: state.controlled_result,
            snapshot_recorded: state.snapshot_recorded,
            receipt_gate: state.receipt_gate,
            final_correlation: state.final_correlation,
            cost,
            clamped,
            incomplete,
        }
    }
}
pub(crate) fn reset_observation(slot: &mut Option<AdmissionWitnessObserverV1>) {
    slot.take();
}
pub(crate) fn take_observation(
    slot: &mut Option<AdmissionWitnessObserverV1>,
) -> Option<AdmissionWitnessDiagnosticV1> {
    slot.take().map(|observer| observer.snapshot())
}
pub(crate) fn start_span_observed(
    observer: Option<&AdmissionWitnessObserverV1>,
    span: AdmissionWitnessSpanV1,
) -> Option<AdmissionWitnessSpanGuardV1> {
    start_span_observed_with_clock(observer, span, Instant::now)
}
fn start_span_observed_with_clock(
    observer: Option<&AdmissionWitnessObserverV1>,
    span: AdmissionWitnessSpanV1,
    clock: impl FnOnce() -> Instant,
) -> Option<AdmissionWitnessSpanGuardV1> {
    observer.map(|observer| observer.start_span_at(span, clock()))
}
pub(crate) struct AdmissionWitnessSpanGuardV1 {
    observer: AdmissionWitnessObserverV1,
    span: AdmissionWitnessSpanV1,
    started: Instant,
}
impl Drop for AdmissionWitnessSpanGuardV1 {
    fn drop(&mut self) {
        self.observer.finish_span(
            self.span,
            Instant::now().saturating_duration_since(self.started),
        );
    }
}

struct FrameIo<'a, S> {
    inner: &'a mut S,
    observer: &'a AdmissionWitnessObserverV1,
}
impl<S: Read> Read for FrameIo<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.observer.observe_io(self.inner.read(bytes))
    }
    fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.observer.observe_io(self.inner.read_exact(bytes))
    }
}
impl<S: Write> Write for FrameIo<'_, S> {
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
pub(super) fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    observer: Option<&AdmissionWitnessObserverV1>,
) -> Result<T> {
    match observer {
        Some(observer) => {
            let _span = observer.start_span(AdmissionWitnessSpanV1::FrameRead);
            super::read_frame(&mut FrameIo {
                inner: stream,
                observer,
            })
        }
        None => super::read_frame(stream),
    }
}
pub(super) fn write_frame<T: serde::Serialize>(
    stream: &mut impl Write,
    message: &T,
    observer: Option<&AdmissionWitnessObserverV1>,
) -> Result<()> {
    match observer {
        Some(observer) => {
            let _span = observer.start_span(AdmissionWitnessSpanV1::FrameWrite);
            super::write_frame(
                &mut FrameIo {
                    inner: stream,
                    observer,
                },
                message,
            )
        }
        None => super::write_frame(stream, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn pure_admission_first_errors_keep_independent_original_results() {
        let observer = AdmissionWitnessObserverV1::new();
        observer.begin_connection();
        observer.enter(AdmissionWitnessStageV1::ExactRequest);
        observer.exact_request_matched();
        let first: Result<()> = observer.observe_semantic(Err(AuthorityError::PolicyDenied));
        assert!(matches!(first, Err(AuthorityError::PolicyDenied)));
        observer.enter(AdmissionWitnessStageV1::OutputCheck);
        let connection: Result<()> = observer.observe_connection(Err(AuthorityError::Permission));
        assert!(matches!(connection, Err(AuthorityError::Permission)));
        let _: Result<()> = observer.observe_semantic(Err(AuthorityError::Uncertain));
        let _: Result<()> = observer.observe_connection(Err(AuthorityError::Authentication));
        observer.enter(AdmissionWitnessStageV1::ResultLookup);
        observer.worker_result(&Err::<(), _>(AuthorityError::Expired));
        observer.enter(AdmissionWitnessStageV1::WorkerDisplay);
        observer.worker_result(&Err::<(), _>(AuthorityError::Uncertain));
        observer.fixture_result(
            AdmissionWitnessStageV1::FixtureReceipt,
            &Err::<(), _>(AuthorityError::Permission),
        );
        let value = observer.snapshot();
        assert!(value.first_semantic().unwrap().stage() == AdmissionWitnessStageV1::ExactRequest);
        assert!(value.first_semantic().unwrap().error() == AuthorityError::PolicyDenied);
        assert!(value.first_connection().unwrap().stage() == AdmissionWitnessStageV1::OutputCheck);
        assert!(value.first_connection().unwrap().error() == AuthorityError::Permission);
        assert!(value.worker_error() == Some(AuthorityError::Expired));
        assert!(value.worker_stage() == Some(AdmissionWitnessStageV1::ResultLookup));
        assert!(value.fixture_error() == Some(AuthorityError::Permission));
        assert!(value.fixture_stage() == Some(AdmissionWitnessStageV1::FixtureReceipt));
    }

    #[test]
    fn pure_admission_exact_attribution_never_leaks_to_later_connection() {
        let observer = AdmissionWitnessObserverV1::new();
        observer.begin_connection();
        observer.enter(AdmissionWitnessStageV1::ExactRequest);
        observer.exact_request_matched();
        let _: Result<()> = observer.observe_semantic(Err(AuthorityError::StaleHead));
        observer.end_connection();
        observer.begin_connection();
        observer.enter(AdmissionWitnessStageV1::TlsHandshake);
        let _ = observer.observe_io::<()>(Err(io::Error::from(io::ErrorKind::TimedOut)));
        let _: Result<()> = observer.observe_connection(Err(AuthorityError::Authentication));
        let value = observer.snapshot();
        assert!(
            value.first_semantic().unwrap().attribution()
                == AdmissionWitnessAttributionV1::ExactRequest
        );
        assert!(
            value.first_connection().unwrap().attribution()
                == AdmissionWitnessAttributionV1::SelectedServer
        );
        assert!(
            value.first_connection().unwrap().io_kind() == Some(CheckedHistoryIoKindV1::Timeout)
        );
    }

    #[test]
    fn pure_admission_commit_observations_never_infer_rollback_or_receipt() {
        let observer = AdmissionWitnessObserverV1::new();
        assert!(observer.snapshot().commit() == AdmissionWitnessCommitV1::NotObserved);
        observer.commit_entered();
        assert!(observer.snapshot().commit() == AdmissionWitnessCommitV1::Entered);
        observer.commit_returned(&Err::<(), _>(AuthorityError::Uncertain));
        observer.receipt_gate(AdmissionWitnessReceiptGateV1::ClockRejected);
        let failed = observer.snapshot();
        assert!(failed.commit() == AdmissionWitnessCommitV1::ReturnedErr);
        assert!(failed.controlled_result().is_none());
        assert!(failed.snapshot_recorded().is_none());
        assert!(failed.final_correlation() == AdmissionWitnessCorrelationV1::NotObserved);
        let committed = AdmissionWitnessObserverV1::new();
        committed.commit_entered();
        committed.commit_returned(&Ok::<(), AuthorityError>(()));
        committed.controlled_result(true);
        committed.snapshot_recorded();
        committed.enter(AdmissionWitnessStageV1::FrameWrite);
        let _: Result<()> = committed.observe_connection(Err(AuthorityError::Uncertain));
        committed.receipt_gate(AdmissionWitnessReceiptGateV1::Unfocused);
        let value = committed.snapshot();
        assert!(value.commit() == AdmissionWitnessCommitV1::ReturnedOk);
        assert_eq!(value.snapshot_recorded(), Some(true));
        assert!(value.receipt_gate() == AdmissionWitnessReceiptGateV1::Unfocused);
        assert!(value.first_connection().is_some());
    }

    #[test]
    fn pure_admission_missing_completion_does_not_invent_original_error_or_stage() {
        let observer = AdmissionWitnessObserverV1::new();
        observer.enter(AdmissionWitnessStageV1::Commit);
        observer.completion(AdmissionWitnessCompletionV1::Disconnected);
        observer.completion(AdmissionWitnessCompletionV1::Panicked);
        let value = observer.snapshot();
        assert!(value.completion() == AdmissionWitnessCompletionV1::Panicked);
        assert!(value.worker_result() == AdmissionWitnessResultV1::NotObserved);
        assert!(value.worker_error().is_none());
        assert!(value.worker_stage().is_none());
        assert!(value.fixture_error().is_none());
        assert!(value.fixture_stage().is_none());
        assert!(value.incomplete());
    }

    #[test]
    fn pure_admission_reset_before_preflight_and_take_once_cannot_return_stale_data() {
        let old = AdmissionWitnessObserverV1::new();
        old.commit_entered();
        let mut slot = Some(old);
        reset_observation(&mut slot);
        // A new preflight error occurs before installing a selected Work sidecar.
        let failed_preflight: Result<()> = Err(AuthorityError::Permission);
        assert!(failed_preflight.is_err());
        assert!(take_observation(&mut slot).is_none());
        slot = Some(AdmissionWitnessObserverV1::new());
        let value = take_observation(&mut slot).unwrap();
        assert!(value.commit() == AdmissionWitnessCommitV1::NotObserved);
        assert!(take_observation(&mut slot).is_none());
    }

    #[test]
    fn pure_admission_none_samples_no_clock_and_expression_runs_once() {
        let guard = start_span_observed_with_clock(None, AdmissionWitnessSpanV1::Worker, || {
            panic!("None must not sample a clock")
        });
        assert!(guard.is_none());
        let calls = Cell::new(0);
        let observer: Option<&AdmissionWitnessObserverV1> = None;
        let result: Result<()> = crate::transport::admission_measure!(observer, Worker, {
            calls.set(calls.get() + 1);
            Err(AuthorityError::Permission)
        });
        assert_eq!(calls.get(), 1);
        assert!(matches!(result, Err(AuthorityError::Permission)));
    }

    #[test]
    fn pure_admission_failed_spans_are_accounted_without_retry() {
        let observer = AdmissionWitnessObserverV1::new();
        let calls = Cell::new(0);
        let result: Result<()> = crate::transport::admission_measure!(Some(&observer), Append, {
            calls.set(calls.get() + 1);
            Err(AuthorityError::Storage)
        });
        assert!(matches!(result, Err(AuthorityError::Storage)));
        assert_eq!(calls.get(), 1);
        let value = observer.snapshot();
        assert_eq!(value.cost(AdmissionWitnessSpanV1::Append).calls(), 1);
        assert!(value
            .cost(AdmissionWitnessSpanV1::Append)
            .elapsed_us()
            .is_some());
        assert_eq!(value.cost(AdmissionWitnessSpanV1::Commit).calls(), 0);
        assert!(value
            .cost(AdmissionWitnessSpanV1::Commit)
            .elapsed_us()
            .is_none());
    }

    #[test]
    fn pure_admission_costs_cap_null_zero_and_contention_stays_inert() {
        let observer = AdmissionWitnessObserverV1::new();
        observer.update(|s| {
            s.cost[AdmissionWitnessSpanV1::Worker as usize] = Cost {
                calls: u64::from(MAX_COUNT) + 1,
                completed: u64::from(MAX_COUNT) + 1,
                elapsed: Duration::from_secs(601),
            };
            s.cost[AdmissionWitnessSpanV1::Append as usize] = Cost {
                calls: 1,
                completed: 1,
                elapsed: Duration::ZERO,
            };
            s.cost[AdmissionWitnessSpanV1::Commit as usize] = Cost {
                calls: 1,
                completed: 0,
                elapsed: Duration::ZERO,
            };
        });
        let value = observer.snapshot();
        assert!(value.clamped());
        assert!(value.incomplete());
        assert_eq!(
            value.cost(AdmissionWitnessSpanV1::Worker).calls(),
            MAX_COUNT
        );
        assert_eq!(
            value.cost(AdmissionWitnessSpanV1::Worker).elapsed_us(),
            Some(MAX_MICROS)
        );
        assert_eq!(
            value.cost(AdmissionWitnessSpanV1::Append).elapsed_us(),
            Some(0)
        );
        assert!(value
            .cost(AdmissionWitnessSpanV1::Commit)
            .elapsed_us()
            .is_none());
        let lock = observer.0.state.lock().unwrap();
        let result: Result<()> = observer.observe_semantic(Err(AuthorityError::PolicyDenied));
        assert!(matches!(result, Err(AuthorityError::PolicyDenied)));
        drop(lock);
        assert!(observer.snapshot().incomplete());
    }

    #[test]
    fn pure_admission_frame_wrappers_preserve_specialized_io_counts() {
        struct FailedRead {
            calls: usize,
        }
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("must preserve read_exact override")
            }
            fn read_exact(&mut self, _: &mut [u8]) -> io::Result<()> {
                self.calls += 1;
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            }
        }
        struct Writes {
            calls: usize,
            flushes: usize,
        }
        impl Write for Writes {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("must preserve write_all override")
            }
            fn write_all(&mut self, _: &[u8]) -> io::Result<()> {
                self.calls += 1;
                Ok(())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        for observed in [false, true] {
            let observer = AdmissionWitnessObserverV1::new();
            observer.begin_connection();
            observer.enter(AdmissionWitnessStageV1::FrameRead);
            let selected = observed.then_some(&observer);
            let mut read = FailedRead { calls: 0 };
            let result: Result<u8> = read_frame(&mut read, selected);
            assert!(matches!(result, Err(AuthorityError::Uncertain)));
            assert_eq!(read.calls, 1);
            let mut write = Writes {
                calls: 0,
                flushes: 0,
            };
            assert!(write_frame(&mut write, &7_u8, selected).is_ok());
            assert_eq!(write.calls, 2);
            assert_eq!(write.flushes, 1);
        }
    }
}
