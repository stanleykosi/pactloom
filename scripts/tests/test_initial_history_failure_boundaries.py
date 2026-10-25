#!/usr/bin/env python3
"""P70 actual-monitor extraction regression; never a native authority fixture.

The selected Rust monitor, diagnostic helpers, and worker-owner implementation
are copied byte-for-byte from the checked-out source into a std-only test crate.
Only Origin I/O and the worker are inert doubles. No sockets, TLS, native Finals,
new permissions, or product processes are created. Default invocation requires
the exact pinned compiler and all named Rust tests. --source-only is explicitly
static evidence, never a native-test pass. Nothing writes into the source tree.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MONITOR_PATH = 'crates/wholepact-authority/src/transport/coordinated_initial_history_v1.rs'
OWNER_PATH = 'crates/wholepact-authority/src/transport/coordinated_service_worker_v1.rs'
ORIGIN_PATH = 'crates/wholepact-financial-coordinator-origin/src/financial_history_origin.rs'
AUTHORITY_PATH = 'crates/wholepact-authority/src/lib.rs'
PINNED_RUSTC = 'rustc 1.99.0 (b940084d7 2026-09-28)'
OWNER_SHA = 'f4529b9dc2fb2ce11d249059bf9e27876448a2fa46fa1cbaddb05c03ad7e22c6'
WORKER_TAIL_SHA = '2c00597b8a4f5da01df5a21db3675f0c5c81acae8e30a44e6acde59d88e32b6c'
BASE_MONITOR_SHA = '07b6faeb2fe9e647295b2014db2cc1543617da440b0c82e9863165a908f1d883'
RESTORE_PAIRS = (('        origin\n            .check_original_coordinator_alive()\n            .map_err(|_| AuthorityError::Permission)?;', '        history_io!(origin, HistoryMonitorCheck, origin.check_original_coordinator_alive())\n            .map_err(|_| AuthorityError::Permission)?;'), ('                >= origin\n                    .original_cleanup_deadline()\n                    .map_err(|_| AuthorityError::Permission)?', '                >= history_io!(origin, HistoryCleanupDeadline, origin.original_cleanup_deadline())\n                    .map_err(|_| AuthorityError::Permission)?'), ('                return Err(AuthorityError::Expired);', '                return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryCleanupDeadline, AuthorityError::Expired));'), ('        } else if origin.check_current().is_err() {\n            origin.restrict();', '        } else if let Err(error) = origin.check_current() {\n            origin.observe_history_io_failure_detail_v1(HistoryFailureStageV1::HistoryMonitorCheck, &error);\n            origin.restrict();'), ('            origin\n                .retain_cleanup_deadline(origin.session_deadline())\n                .map_err(|_| AuthorityError::Permission)?;', '            history_io!(origin, HistoryCleanupRetain, origin.retain_cleanup_deadline(origin.session_deadline()))\n                .map_err(|_| AuthorityError::Permission)?;'), ('        match origin\n            .try_receive()\n            .map_err(|_| AuthorityError::Permission)?', '        match history_io!(origin, HistoryRequestReceive, origin.try_receive())\n            .map_err(|_| AuthorityError::Permission)?'), ('                    return Err(AuthorityError::Permission);', '                    return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryRequestOrder, AuthorityError::Permission));'), ('                        .map_err(|_| AuthorityError::Storage)?,', '                        .map_err(|_| history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerStart, AuthorityError::Storage))?,'), ('                    .ok_or(AuthorityError::Permission)?\n                    .try_send(grant)\n                    .map_err(|_| AuthorityError::Permission)?;', '                    .ok_or_else(|| history_authority_error(origin, HistoryFailureStageV1::HistoryServeHandoff, AuthorityError::Permission))?\n                    .try_send(grant)\n                    .map_err(|_| history_authority_error(origin, HistoryFailureStageV1::HistoryServeHandoff, AuthorityError::Permission))?;'), ('                origin\n                    .send_purpose_closed()\n                    .map_err(|_| AuthorityError::Permission)?;', '                history_io!(origin, HistoryPurposeClosedSend, origin.send_purpose_closed())\n                    .map_err(|_| AuthorityError::Permission)?;'), ('                    origin\n                        .send_display(data)\n                        .map_err(|_| AuthorityError::Permission)?;', '                    history_io!(origin, HistoryDisplaySend, origin.send_display(data))\n                        .map_err(|_| AuthorityError::Permission)?;'), ('                    origin\n                        .acknowledge_serving()\n                        .map_err(|_| AuthorityError::Permission)?;', '                    history_io!(origin, HistoryServingSend, origin.acknowledge_serving())\n                        .map_err(|_| AuthorityError::Permission)?;'), ('            Err(TryRecvError::Disconnected) => return Err(AuthorityError::Permission),', '            Err(TryRecvError::Disconnected) => return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryEventOrder, AuthorityError::Permission)),'), ('                .ok_or(AuthorityError::Storage)?\n                .join()\n                .map_err(|_| AuthorityError::Storage)?;', '                .ok_or_else(|| history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerJoin, AuthorityError::Storage))?\n                .join()\n                .map_err(|_| history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerJoin, AuthorityError::Storage))?;'), ('            if result.is_err() && !terminal {\n                origin.restrict();', '            if result.is_err() && !terminal {\n                // Only this existing failure branch may enable the worker detail.\n                // Ordered FinishRead/Cancel deliberately suppress worker errors.\n                origin.observe_history_failure_detail_v1(HistoryFailureStageV1::HistoryWorkerFailure,\n                    history_authority_class(result.as_ref().unwrap_err()));\n                origin.restrict();'), ('                if prepared {\n                    origin.send_service_failed()\n                } else {\n                    origin.send_preparation_failed()\n                }\n                .map_err(|_| AuthorityError::Permission)?;', '                history_io!(origin, HistoryFailureSend, if prepared {\n                    origin.send_service_failed()\n                } else {\n                    origin.send_preparation_failed()\n                })\n                .map_err(|_| AuthorityError::Permission)?;'), ('            if !terminal {\n                return Err(AuthorityError::Permission);\n            }', '            if !terminal {\n                return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerUnexpectedReturn, AuthorityError::Permission));\n            }'), ('            origin\n                .send_disposed()\n                .map_err(|_| AuthorityError::Permission)?;', '            history_io!(origin, HistoryDisposedSend, origin.send_disposed())\n                .map_err(|_| AuthorityError::Permission)?;'))
TEST_NAMES = (
    'finish_stops_joins_disposes_then_closes_cleanly',
    'ordered_cancel_suppresses_worker_error_detail',
    'genuine_worker_error_keeps_class_even_monitor_returns_ok',
    'genuine_worker_error_precedes_later_disposed_send_failure',
    'cleanup_expiry_never_claims_disposal',
    'worker_panic_is_join_storage_detail',
    'disposed_send_failure_preserves_io_detail',
    'purpose_closed_send_failure_preserves_io_detail',
    'unexpected_clean_worker_return_still_fails',
    'authority_mapping_is_complete_and_identity_preserving',
    'history_io_preserves_actual_error_and_calls_once',
    'handled_current_error_then_ordered_cancel_has_no_detail',
    'handled_current_error_does_not_mask_disposed_send_failure',
    'handled_current_error_does_not_mask_purpose_send_failure',
    'handled_current_error_does_not_mask_cleanup_retain_failure',
    'handled_current_error_does_not_mask_request_receive_failure',
    'unordered_current_error_is_promoted_only_at_failure_send',
)


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def item(source, anchor):
    """Extract one selected Rust item without rewriting a byte of its body."""
    if source.count(anchor) != 1:
        raise AssertionError(('nonunique selected item', anchor))
    start = source.index(anchor)
    opening = source.index('{', start)
    depth, block, quoted, escaped = 0, 0, False, False
    i = opening
    while i < len(source):
        if quoted:
            if escaped:
                escaped = False
            elif source[i] == '\\':
                escaped = True
            elif source[i] == '"':
                quoted = False
            i += 1
            continue
        if block:
            if source.startswith('/*', i):
                block += 1
                i += 2
            elif source.startswith('*/', i):
                block -= 1
                i += 2
            else:
                i += 1
            continue
        if source.startswith('//', i):
            end = source.find('\n', i)
            if end < 0:
                break
            i = end + 1
            continue
        if source.startswith('/*', i):
            block = 1
            i += 2
            continue
        c = source[i]
        if c == '"':
            quoted = True
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise AssertionError(('unbalanced selected item', anchor))


def inputs():
    return {name: (ROOT / path).read_text() for name, path in (
        ('monitor', MONITOR_PATH), ('owner', OWNER_PATH),
        ('origin', ORIGIN_PATH), ('authority', AUTHORITY_PATH))}


def variants(enum):
    return re.findall(r'^    ([A-Z][A-Za-z0-9_]*),\s*$', enum, re.M)


def restore_monitor(current):
    corrections = (
        ('    let mut pending_currentness = None;\n', ''),
        ('''            // A later ordered stop can legitimately consume this handled error.
            // Retain only a finite kind until the existing failure-send branch.
            pending_currentness = Some(error.kind());''',
         '            origin.observe_history_io_failure_detail_v1(HistoryFailureStageV1::HistoryMonitorCheck, &error);'),
        ('                pending_currentness = None;\n', ''),
        ('''                if let Some(kind) = pending_currentness.take() {
                    origin.observe_history_io_failure_detail_v1(HistoryFailureStageV1::HistoryMonitorCheck, kind);
                }
''', ''),
    )
    for old, new in corrections:
        if current.count(old) != 1:
            raise AssertionError(('pending-currentness correction changed', old))
        current = current.replace(old, new, 1)
    event = '''                if prepared {
                    return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryEventOrder, AuthorityError::Permission));'''
    request = event.replace('HistoryEventOrder', 'HistoryRequestOrder')
    if current.count(event) != 1:
        raise AssertionError('prepared duplicate boundary changed')
    current = current.replace(event, request, 1)
    for old, new in reversed(RESTORE_PAIRS):
        count = 4 if old == '                    return Err(AuthorityError::Permission);' else (
            2 if old.startswith('                if prepared {') else 1)
        if current.count(new) != count:
            raise AssertionError(('restoration replacement changed', new, count))
        current = current.replace(new, old)
    return current


class SourceContracts(unittest.TestCase):
    def test_selected_monitor_restores_exact_original_bytes(self):
        source = inputs()['monitor']
        self.assertEqual(sha(restore_monitor(item(source, 'fn monitor('))), BASE_MONITOR_SHA)

    def test_actual_worker_and_ownership_code_are_unchanged(self):
        source = inputs()
        self.assertEqual(sha(source['owner']), OWNER_SHA)
        tail = source['monitor'][source['monitor'].index('fn worker_main('):]
        self.assertEqual(sha(tail), WORKER_TAIL_SHA)

    def test_authority_classifier_is_exhaustive_and_identity_preserving(self):
        source = inputs()
        actual = variants(item(source['authority'], 'pub enum AuthorityError'))
        bridge = variants(item(source['origin'], 'pub enum HistoryFailureClassV1'))
        self.assertEqual(len(actual), 23)
        self.assertEqual(actual, bridge)
        classifier = item(source['monitor'], 'fn history_authority_class(')
        mapped = re.findall(r'AuthorityError::(\w+) => HistoryFailureClassV1::(\w+),', classifier)
        self.assertEqual(mapped, list(zip(actual, actual)))

    def test_failure_detail_follows_existing_restriction_only(self):
        source = inputs()['origin']
        for method in ('send_preparation_failed', 'send_service_failed'):
            body = item(source, 'pub fn ' + method + '(')
            operations = ['self.core.restrict();', 'self.failed = true;',
                          'self.observe_reported_history_failure();', 'self.first_cleanup()?;']
            self.assertEqual([body.count(x) for x in operations], [1] * len(operations))
            self.assertEqual(sorted(body.index(x) for x in operations),
                             [body.index(x) for x in operations])
        for method in ('observe_history_failure_detail_v1', 'observe_history_io_failure_detail_v1'):
            body = item(source, 'pub fn ' + method + '(')
            self.assertIn('#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]', body)
            self.assertNotIn('mark_failed', body)
            self.assertNotIn('restrict()', body)

    def test_extracted_items_are_embedded_verbatim_once(self):
        generated, extracted = build_harness()
        for name, value in extracted.items():
            self.assertEqual(generated.count(value), 1, name)
        self.assertEqual(len(set(TEST_NAMES)), 17)
        self.assertEqual(sorted(re.findall(r'#\[test\]\s*fn (\w+)\(', generated)), sorted(TEST_NAMES))
        self.assertNotIn('TcpListener', generated)
        self.assertNotIn('unsafe {', generated)


RUST_STUBS = r'''
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, SyncSender, TryRecvError}};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T, AuthorityError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode { Clean, CancelError, GenuineError, GenuineThenDisposedError, CleanupExpiry,
            WorkerPanic, DisposedError, PurposeError, UnexpectedSuccess,
            CurrentCancelClean, CurrentCancelDisposed, CurrentFinishPurpose,
            CurrentRetainError, CurrentReceiveError, CurrentUnordered }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetailClass { Authority(HistoryFailureClassV1), Io(std::io::ErrorKind) }
type Detail = (HistoryFailureStageV1, DetailClass);
struct State {
    mode: Mode, trace: Vec<&'static str>, details: Vec<Detail>,
    prepare_sent: bool, displayed: bool, serve_sent: bool, serving_ack: bool,
    ordered_sent: bool, disposed: bool, close_sent: bool, worker_finished: bool,
    release: bool, polls: usize, current_error_issued: bool, stop: Option<Arc<AtomicBool>>,
}
type Shared = Arc<Mutex<State>>;
impl State {
    fn new(mode: Mode) -> Self {
        Self { mode, trace: vec![], details: vec![], prepare_sent: false, displayed: false,
            serve_sent: false, serving_ack: false, ordered_sent: false, disposed: false,
            close_sent: false, worker_finished: false, release: false, polls: 0,
            current_error_issued: false, stop: None }
    }
}
struct FakeOrigin { shared: Shared }
struct FakeSetup { shared: Shared }
struct FakeServe;
enum Request { PrepareOnce(FakeSetup), Serve(FakeServe), FinishRead, Cancel, ClosePurpose }
fn io_failure() -> std::io::Error { std::io::Error::from(std::io::ErrorKind::BrokenPipe) }
impl FakeOrigin {
    fn check_original_coordinator_alive(&self) -> std::io::Result<()> {
        let mut s = self.shared.lock().unwrap(); s.polls += 1;
        assert!(s.polls < 1200, "inert harness exceeded bounded monitor iterations");
        Ok(())
    }
    fn check_current(&self) -> std::io::Result<()> {
        let mut s = self.shared.lock().unwrap();
        if s.serving_ack && !s.current_error_issued && matches!(s.mode,
            Mode::CurrentCancelClean | Mode::CurrentCancelDisposed | Mode::CurrentFinishPurpose |
            Mode::CurrentRetainError | Mode::CurrentReceiveError | Mode::CurrentUnordered) {
            s.current_error_issued = true; s.trace.push("handled_current_error");
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }
    fn session_deadline(&self) -> Instant { Instant::now() + Duration::from_secs(10) }
    fn original_cleanup_deadline(&self) -> std::io::Result<Instant> {
        let s = self.shared.lock().unwrap();
        Ok(if s.mode == Mode::CleanupExpiry && s.ordered_sent {
            Instant::now() - Duration::from_secs(1)
        } else { Instant::now() + Duration::from_secs(10) })
    }
    fn retain_cleanup_deadline(&mut self, value: Instant) -> std::io::Result<Instant> {
        let s = self.shared.lock().unwrap();
        if s.mode == Mode::CurrentRetainError && s.current_error_issued { Err(io_failure()) } else { Ok(value) }
    }
    fn restrict(&self) { self.shared.lock().unwrap().trace.push("restrict"); }
    fn observe_history_failure_detail_v1(&self, stage: HistoryFailureStageV1, class: HistoryFailureClassV1) {
        self.shared.lock().unwrap().details.push((stage, DetailClass::Authority(class)));
    }
    fn observe_history_io_failure_detail_v1(&self, stage: HistoryFailureStageV1, kind: std::io::ErrorKind) {
        self.shared.lock().unwrap().details.push((stage, DetailClass::Io(kind)));
    }
    fn try_receive(&mut self) -> std::io::Result<Option<Request>> {
        let mut s = self.shared.lock().unwrap();
        if s.mode == Mode::CurrentReceiveError && s.current_error_issued { return Err(io_failure()); }
        if !s.prepare_sent {
            s.prepare_sent = true; s.trace.push("prepare");
            return Ok(Some(Request::PrepareOnce(FakeSetup { shared: self.shared.clone() })));
        }
        if s.displayed && !s.serve_sent {
            s.serve_sent = true; s.trace.push("serve");
            return Ok(Some(Request::Serve(FakeServe)));
        }
        let autonomous = matches!(s.mode, Mode::GenuineError | Mode::GenuineThenDisposedError |
                                 Mode::WorkerPanic | Mode::UnexpectedSuccess | Mode::CurrentUnordered);
        if s.serving_ack && !s.ordered_sent && !autonomous {
            s.ordered_sent = true;
            if matches!(s.mode, Mode::CancelError | Mode::CurrentCancelClean | Mode::CurrentCancelDisposed) {
                s.trace.push("cancel"); return Ok(Some(Request::Cancel));
            }
            s.trace.push("finish"); return Ok(Some(Request::FinishRead));
        }
        if s.disposed && !s.close_sent {
            s.close_sent = true; s.trace.push("close");
            return Ok(Some(Request::ClosePurpose));
        }
        Ok(None)
    }
    fn send_display(&mut self, _: ()) -> std::io::Result<()> {
        let mut s = self.shared.lock().unwrap(); s.displayed = true; s.trace.push("display"); Ok(())
    }
    fn acknowledge_serving(&mut self) -> std::io::Result<()> {
        let mut s = self.shared.lock().unwrap(); s.serving_ack = true; s.trace.push("serving_ack"); Ok(())
    }
    fn send_service_failed(&mut self) -> std::io::Result<()> {
        self.shared.lock().unwrap().trace.push("service_failed"); Ok(())
    }
    fn send_preparation_failed(&mut self) -> std::io::Result<()> {
        self.shared.lock().unwrap().trace.push("preparation_failed"); Ok(())
    }
    fn send_disposed(&mut self) -> std::io::Result<()> {
        let mut s = self.shared.lock().unwrap();
        assert!(s.worker_finished, "disposal must follow finished worker custody");
        assert!(s.stop.as_ref().unwrap().load(Ordering::Acquire));
        s.trace.push("disposed_attempt");
        if matches!(s.mode, Mode::DisposedError | Mode::GenuineThenDisposedError | Mode::CurrentCancelDisposed) { return Err(io_failure()); }
        s.disposed = true; s.trace.push("disposed"); Ok(())
    }
    fn send_purpose_closed(&mut self) -> std::io::Result<()> {
        let mut s = self.shared.lock().unwrap(); assert!(s.disposed);
        s.trace.push("purpose_closed_attempt");
        if matches!(s.mode, Mode::PurposeError | Mode::CurrentFinishPurpose) { return Err(io_failure()); }
        s.trace.push("purpose_closed"); Ok(())
    }
}
#[derive(Debug)]
struct Completed(Result<()>);
struct FinishedWorker(Shared);
impl Drop for FinishedWorker {
    fn drop(&mut self) {
        let mut s = self.0.lock().unwrap(); s.worker_finished = true; s.trace.push("worker_finished");
    }
}
fn await_condition(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while !ready() {
        assert!(Instant::now() < deadline, "inert worker synchronization timed out");
        thread::sleep(Duration::from_millis(1));
    }
}
'''

RUST_WORKER_TESTS = r'''
fn worker_main(setup: Setup, serve_rx: Receiver<Serve>, events: SyncSender<WorkerEvent>, stopped: Arc<AtomicBool>) -> Result<()> {
    let shared = setup.shared;
    let _finished = FinishedWorker(shared.clone());
    shared.lock().unwrap().trace.push("worker_prepared");
    events.try_send(WorkerEvent::Prepared(())).unwrap();
    serve_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    shared.lock().unwrap().trace.push("worker_serving");
    events.try_send(WorkerEvent::Serving).unwrap();
    await_condition(|| shared.lock().unwrap().serving_ack);
    let mode = shared.lock().unwrap().mode;
    match mode {
        Mode::GenuineError | Mode::GenuineThenDisposedError => return Err(AuthorityError::CorruptHistory),
        Mode::WorkerPanic => panic!("inert worker panic"),
        Mode::UnexpectedSuccess => return Ok(()),
        _ => {}
    }
    await_condition(|| stopped.load(Ordering::Acquire));
    shared.lock().unwrap().trace.push("worker_stop");
    if mode == Mode::CleanupExpiry { await_condition(|| shared.lock().unwrap().release); }
    if mode == Mode::CancelError { Err(AuthorityError::Authentication) } else { Ok(()) }
}
impl super::coordinated_service_worker_v1::ServiceOriginV1 for Origin {
    fn close_failed_worker(&mut self) {
        let mut s = self.shared.lock().unwrap();
        assert!(s.stop.as_ref().unwrap().load(Ordering::Acquire)); s.trace.push("edge_closed");
    }
    fn close_failed_worker_error(&mut self) {
        self.shared.lock().unwrap().trace.push("owned_error"); self.close_failed_worker();
    }
    fn complete_owned(self, result: Result<()>) -> ! {
        self.shared.lock().unwrap().trace.push("completed"); std::panic::panic_any(Completed(result))
    }
}
struct Outcome { result: Result<()>, joined_after_monitor: bool, trace: Vec<&'static str>, details: Vec<Detail> }
fn run_case(mode: Mode) -> Outcome {
    let shared = Arc::new(Mutex::new(State::new(mode)));
    let origin = Origin { shared: shared.clone() };
    let mut owner = super::coordinated_service_worker_v1::ServiceWorkerOwnerV1::new(origin);
    shared.lock().unwrap().stop = Some(owner.stopped.clone());
    let result = monitor(&mut owner);
    let joined_after_monitor = owner.worker.is_none();
    shared.lock().unwrap().release = true;
    let completion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.complete(result))).unwrap_err();
    assert_eq!(completion.downcast_ref::<Completed>().expect("actual owner completion").0, result);
    let s = shared.lock().unwrap();
    Outcome { result, joined_after_monitor, trace: s.trace.clone(), details: s.details.clone() }
}
fn before(trace: &[&str], first: &str, second: &str) {
    assert!(trace.iter().position(|s| *s == first).unwrap() < trace.iter().position(|s| *s == second).unwrap(), "{trace:?}");
}
fn authority_detail(stage: HistoryFailureStageV1, class: HistoryFailureClassV1) -> Detail { (stage, DetailClass::Authority(class)) }
fn io_detail(stage: HistoryFailureStageV1) -> Detail { (stage, DetailClass::Io(std::io::ErrorKind::BrokenPipe)) }
#[test]
fn finish_stops_joins_disposes_then_closes_cleanly() {
    let o = run_case(Mode::Clean); assert_eq!(o.result, Ok(())); assert!(o.joined_after_monitor); assert!(o.details.is_empty());
    for (a, b) in [("prepare", "display"), ("display", "serve"), ("serve", "serving_ack"),
        ("finish", "worker_stop"), ("worker_stop", "worker_finished"), ("worker_finished", "disposed"),
        ("disposed", "close"), ("close", "purpose_closed"), ("purpose_closed", "completed")] { before(&o.trace, a, b); }
    assert!(!o.trace.contains(&"service_failed")); assert!(!o.trace.contains(&"owned_error"));
}
#[test]
fn ordered_cancel_suppresses_worker_error_detail() {
    let o = run_case(Mode::CancelError); assert_eq!(o.result, Ok(())); assert!(o.joined_after_monitor); assert!(o.details.is_empty());
    before(&o.trace, "cancel", "worker_stop"); before(&o.trace, "worker_finished", "disposed");
    assert!(!o.trace.contains(&"service_failed")); assert!(!o.trace.contains(&"owned_error"));
}
#[test]
fn genuine_worker_error_keeps_class_even_monitor_returns_ok() {
    let o = run_case(Mode::GenuineError); assert_eq!(o.result, Ok(())); assert!(o.joined_after_monitor);
    assert_eq!(o.details, [authority_detail(HistoryFailureStageV1::HistoryWorkerFailure, HistoryFailureClassV1::CorruptHistory)]);
    before(&o.trace, "worker_finished", "restrict"); before(&o.trace, "restrict", "service_failed");
    before(&o.trace, "service_failed", "disposed"); before(&o.trace, "disposed", "purpose_closed");
}
#[test]
fn genuine_worker_error_precedes_later_disposed_send_failure() {
    let o = run_case(Mode::GenuineThenDisposedError); assert_eq!(o.result, Err(AuthorityError::Permission));
    assert_eq!(o.details, [authority_detail(HistoryFailureStageV1::HistoryWorkerFailure, HistoryFailureClassV1::CorruptHistory),
                          io_detail(HistoryFailureStageV1::HistoryDisposedSend)]);
    before(&o.trace, "service_failed", "disposed_attempt"); assert!(!o.trace.contains(&"disposed"));
}
#[test]
fn cleanup_expiry_never_claims_disposal() {
    let o = run_case(Mode::CleanupExpiry); assert_eq!(o.result, Err(AuthorityError::Expired)); assert!(!o.joined_after_monitor);
    assert_eq!(o.details, [authority_detail(HistoryFailureStageV1::HistoryCleanupDeadline, HistoryFailureClassV1::Expired)]);
    assert!(!o.trace.contains(&"disposed_attempt")); assert!(!o.trace.contains(&"purpose_closed"));
    before(&o.trace, "worker_finished", "completed");
}
#[test]
fn worker_panic_is_join_storage_detail() {
    let o = run_case(Mode::WorkerPanic); assert_eq!(o.result, Err(AuthorityError::Storage)); assert!(o.joined_after_monitor);
    assert_eq!(o.details, [authority_detail(HistoryFailureStageV1::HistoryWorkerJoin, HistoryFailureClassV1::Storage)]);
    assert!(!o.trace.contains(&"disposed_attempt")); assert!(!o.trace.contains(&"purpose_closed"));
}
#[test]
fn disposed_send_failure_preserves_io_detail() {
    let o = run_case(Mode::DisposedError); assert_eq!(o.result, Err(AuthorityError::Permission)); assert!(o.joined_after_monitor);
    assert_eq!(o.details, [io_detail(HistoryFailureStageV1::HistoryDisposedSend)]);
    assert!(!o.trace.contains(&"disposed")); assert!(!o.trace.contains(&"purpose_closed"));
}
#[test]
fn purpose_closed_send_failure_preserves_io_detail() {
    let o = run_case(Mode::PurposeError); assert_eq!(o.result, Err(AuthorityError::Permission)); assert!(o.joined_after_monitor);
    assert_eq!(o.details, [io_detail(HistoryFailureStageV1::HistoryPurposeClosedSend)]);
    before(&o.trace, "disposed", "purpose_closed_attempt"); assert!(!o.trace.contains(&"purpose_closed"));
}
#[test]
fn unexpected_clean_worker_return_still_fails() {
    let o = run_case(Mode::UnexpectedSuccess); assert_eq!(o.result, Err(AuthorityError::Permission)); assert!(o.joined_after_monitor);
    assert_eq!(o.details, [authority_detail(HistoryFailureStageV1::HistoryWorkerUnexpectedReturn, HistoryFailureClassV1::Permission)]);
    assert!(!o.trace.contains(&"disposed_attempt"));
}
#[test]
fn authority_mapping_is_complete_and_identity_preserving() {
    let shared = Arc::new(Mutex::new(State::new(Mode::Clean))); let origin = Origin { shared: shared.clone() };
    // Generated exhaustively from the actual AuthorityError enum, not a copied list.
    __AUTHORITY_ASSERTIONS__
    assert_eq!(shared.lock().unwrap().details.len(), 23);
}
#[test]
fn history_io_preserves_actual_error_and_calls_once() {
    let shared = Arc::new(Mutex::new(State::new(Mode::Clean))); let origin = Origin { shared: shared.clone() };
    let mut calls = 0;
    let result: std::io::Result<()> = history_io!(&origin, HistoryDisposedSend, { calls += 1; Err(io_failure()) });
    assert_eq!(calls, 1); assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(shared.lock().unwrap().details, [io_detail(HistoryFailureStageV1::HistoryDisposedSend)]);
}
#[test]
fn handled_current_error_then_ordered_cancel_has_no_detail() {
    let o = run_case(Mode::CurrentCancelClean); assert_eq!(o.result, Ok(())); assert!(o.joined_after_monitor);
    assert!(o.details.is_empty()); before(&o.trace, "handled_current_error", "cancel");
    before(&o.trace, "cancel", "disposed"); assert!(!o.trace.contains(&"service_failed"));
}
#[test]
fn handled_current_error_does_not_mask_disposed_send_failure() {
    let o = run_case(Mode::CurrentCancelDisposed); assert_eq!(o.result, Err(AuthorityError::Permission));
    assert_eq!(o.details, [io_detail(HistoryFailureStageV1::HistoryDisposedSend)]);
    before(&o.trace, "handled_current_error", "cancel"); assert!(!o.trace.contains(&"service_failed"));
}
#[test]
fn handled_current_error_does_not_mask_purpose_send_failure() {
    let o = run_case(Mode::CurrentFinishPurpose); assert_eq!(o.result, Err(AuthorityError::Permission));
    assert_eq!(o.details, [io_detail(HistoryFailureStageV1::HistoryPurposeClosedSend)]);
    before(&o.trace, "handled_current_error", "finish"); before(&o.trace, "disposed", "purpose_closed_attempt");
}
#[test]
fn handled_current_error_does_not_mask_cleanup_retain_failure() {
    let o = run_case(Mode::CurrentRetainError); assert_eq!(o.result, Err(AuthorityError::Permission));
    assert_eq!(o.details, [io_detail(HistoryFailureStageV1::HistoryCleanupRetain)]);
    assert!(!o.trace.contains(&"disposed_attempt")); assert!(!o.trace.contains(&"cancel"));
}
#[test]
fn handled_current_error_does_not_mask_request_receive_failure() {
    let o = run_case(Mode::CurrentReceiveError); assert_eq!(o.result, Err(AuthorityError::Permission));
    assert_eq!(o.details, [io_detail(HistoryFailureStageV1::HistoryRequestReceive)]);
    assert!(!o.trace.contains(&"disposed_attempt")); assert!(!o.trace.contains(&"cancel"));
}
#[test]
fn unordered_current_error_is_promoted_only_at_failure_send() {
    let o = run_case(Mode::CurrentUnordered); assert_eq!(o.result, Ok(())); assert!(o.joined_after_monitor);
    assert_eq!(o.details, [(HistoryFailureStageV1::HistoryMonitorCheck, DetailClass::Io(std::io::ErrorKind::PermissionDenied))]);
    before(&o.trace, "handled_current_error", "service_failed"); before(&o.trace, "service_failed", "disposed");
    assert!(!o.trace.contains(&"finish")); assert!(!o.trace.contains(&"cancel"));
}
'''


def build_harness():
    source = inputs()
    extracted = {}
    for anchor in ('macro_rules! history_io', 'fn history_authority_error(',
                   'fn history_authority_class(', 'enum WorkerEvent', 'fn monitor('):
        extracted[anchor] = item(source['monitor'], anchor)
    for anchor in ('pub(super) trait ServiceOriginV1', 'pub(super) struct ServiceWorkerOwnerV1',
                   'impl<O: ServiceOriginV1, G, E> ServiceWorkerOwnerV1<O, G, E>',
                   'impl<O: ServiceOriginV1, G, E> Drop for ServiceWorkerOwnerV1<O, G, E>'):
        extracted[anchor] = item(source['owner'], anchor)
    enums = []
    for anchor in ('pub enum HistoryFailureStageV1', 'pub enum HistoryFailureClassV1'):
        extracted[anchor] = item(source['origin'], anchor)
        enums.append('#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n' + extracted[anchor])
    actual_errors = variants(item(source['authority'], 'pub enum AuthorityError'))
    authority = '#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nenum AuthorityError {\n' + ''.join(
        '    ' + name + ',\n' for name in actual_errors) + '}\n'
    assertions = '\n'.join(
        'assert_eq!(history_authority_error(&origin, HistoryFailureStageV1::HistoryWorkerFailure, '
        'AuthorityError::' + name + '), AuthorityError::' + name + ');\n'
        'assert_eq!(shared.lock().unwrap().details.last().copied(), Some(authority_detail('
        'HistoryFailureStageV1::HistoryWorkerFailure, HistoryFailureClassV1::' + name + ')));'
        for name in actual_errors)
    owner = '\n'.join(value for anchor, value in extracted.items() if anchor.startswith(('pub(super)', 'impl<')))
    selected = '\n'.join(extracted[anchor] for anchor in (
        'macro_rules! history_io', 'fn history_authority_error(', 'fn history_authority_class(',
        'enum WorkerEvent', 'fn monitor('))
    rust = ('#![allow(dead_code)]\n' + authority + '\n'.join(enums) + '\n' + RUST_STUBS +
            '\nmod transport { use super::*;\nmod coordinated_service_worker_v1 { use super::*;\n' + owner +
            '\n}\nmod history { use super::*;\ntype Origin = FakeOrigin; type Setup = FakeSetup; '
            'type Serve = FakeServe; type Presentation = ();\n'
            'const POLL: Duration = Duration::from_millis(5);\n' + selected + '\n' +
            RUST_WORKER_TESTS.replace('__AUTHORITY_ASSERTIONS__', assertions) + '\n}\n}\n')
    return rust, extracted


def native_tests():
    rustc = shutil.which('rustc')
    if rustc is None:
        raise RuntimeError('pinned rustc unavailable: native tests NOT RUN; explicit invocation requires compiler')
    version = subprocess.run([rustc, '--version'], check=True, capture_output=True, text=True, timeout=15).stdout.strip()
    if version != PINNED_RUSTC:
        raise RuntimeError('wrong rustc identity: ' + version)
    source, extracted = build_harness()
    with tempfile.TemporaryDirectory(prefix='p70-history-boundaries-') as directory:
        root = Path(directory)
        src, binary = root / 'history_boundaries.rs', root / 'history_boundaries'
        src.write_text(source)
        command = [rustc, '--edition=2021', '--test', '-C', 'opt-level=0', str(src), '-o', str(binary)]
        compilation = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if compilation.returncode:
            print(compilation.stdout, end='')
            print(compilation.stderr, end='')
            raise AssertionError('actual extracted monitor Rust compilation failed')
        listing = subprocess.run([str(binary), '--list', '--format', 'terse'], check=True,
                                 capture_output=True, text=True, timeout=15).stdout
        observed = sorted(line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test'))
        expected = sorted('transport::history::' + name for name in TEST_NAMES)
        if observed != expected:
            raise AssertionError(('native test inventory mismatch', observed, expected))
        run = subprocess.run([str(binary), '--test-threads=1'], capture_output=True, text=True, timeout=90)
        print(run.stdout, end='')
        if run.returncode:
            print(run.stderr, end='')
            raise AssertionError('actual extracted monitor Rust tests failed')
        expected_result = f'test result: ok. {len(TEST_NAMES)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
        if expected_result not in run.stdout:
            raise AssertionError('Rust result count missing or unexpected')
    return {'rust_monitor_harness_executed': True, 'rust_monitor_tests_passed': len(TEST_NAMES), 'compiler': version,
            'generated_source_sha256': sha(source),
            'extracted_item_sha256': {name: sha(value) for name, value in extracted.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only', action='store_true', help='Static source checks only; native execution explicitly NOT RUN.')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SourceContracts)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    generated, extracted = build_harness()
    evidence = {'source_contract_tests_passed': result.testsRun, 'full_native_qualification': False,
                'native_actor_execution': False, 'native_authority_finals_created': False,
                'execution_kind': 'source-extracted monitor and owner with inert Origin/worker I/O',
                'generated_source_sha256': sha(generated),
                'extracted_item_sha256': {name: sha(value) for name, value in extracted.items()}}
    if args.source_only:
        evidence.update(rust_monitor_harness_executed=False, rust_test_status='NOT RUN (explicit --source-only)')
    else:
        evidence.update(native_tests())
    print('P70_INITIAL_HISTORY_BOUNDARIES ' + json.dumps(evidence, sort_keys=True))


if __name__ == '__main__':
    main()
