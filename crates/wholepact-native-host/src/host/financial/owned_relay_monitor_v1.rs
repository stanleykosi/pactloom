//! Private joined owner for the actual original H relay.
//! No Host, source, TTY approval or native permission crosses into this worker.
//! Joining is mandatory, but kernel-blocked owned child reap is not promised a
//! wall-clock bound. Normal success requires the actual Origin close protocol.
use crate::{Error, Result};
use std::{
    io,
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wholepact_financial_coordinator_origin::HostFinancialWorkflowRelayV1;

pub(super) struct OwnedHostRelayMonitorV1 {
    abort: SyncSender<()>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

/// Preserve the original foreground failure separately from the actual relay
/// result. Neither field says that an earlier physical effect did not happen.
pub(super) struct HostRelayFailureV1 {
    pub(super) foreground: Error,
    pub(super) relay: io::Result<()>,
}

fn aborted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "original Host foreground aborted")
}

impl OwnedHostRelayMonitorV1 {
    pub(super) fn start(relay: HostFinancialWorkflowRelayV1) -> Result<Self> {
        if !crate::terminal::coordinated_restriction_required()
            || crate::terminal::check_original_coordinator_restriction().is_err()
        {
            crate::terminal::fail_original_coordinator_restriction();
            // The genuine origin's first-drop poison precedes its child reap.
            drop(relay);
            return Err(Error::Permission);
        }
        let (abort, receive_abort) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("original-host-relay".into())
            .spawn(move || run_owned_relay(relay, receive_abort))
            .map_err(|error| {
                // Spawn failure also drops the real relay closure. Its sealed
                // origin owner poisons before any potentially blocking reap.
                crate::terminal::fail_original_coordinator_restriction();
                Error::from(error)
            })?;
        Ok(Self { abort, worker: Some(worker) })
    }

    pub(super) fn abort_and_join(mut self, foreground: Error) -> HostRelayFailureV1 {
        // Denial is synchronous in the foreground, not delayed until the
        // worker receives a message or returns from an owned reap.
        crate::terminal::fail_original_coordinator_restriction();
        let _ = self.abort.try_send(());
        let relay = self.join_worker();
        HostRelayFailureV1 { foreground, relay }
    }

    /// The worker can return Ok only from Origin's actual normal close path.
    /// Keeping the abort sender alive while joining is essential: a disconnected
    /// control mailbox is a failure, not a normal-completion request.
    pub(super) fn complete_and_join(mut self) -> io::Result<()> {
        let result = self.join_worker();
        if result.is_err() { crate::terminal::fail_original_coordinator_restriction(); }
        result
    }

    fn join_worker(&mut self) -> io::Result<()> {
        self.worker.take()
            .ok_or_else(|| io::Error::other("original Host relay already joined"))?
            .join()
            .map_err(|_| io::Error::other("original Host relay worker panicked"))?
    }
}

impl Drop for OwnedHostRelayMonitorV1 {
    fn drop(&mut self) {
        if self.worker.is_some() {
            crate::terminal::fail_original_coordinator_restriction();
            let _ = self.abort.try_send(());
            // Never detach the original S reapers. Drop cannot report the
            // result; callers needing it must use abort_and_join instead.
            let _ = self.join_worker();
        }
    }
}

fn run_owned_relay(
    mut relay: HostFinancialWorkflowRelayV1,
    receive_abort: Receiver<()>,
) -> io::Result<()> {
    let original_deadline = relay.session_deadline();
    let failure = loop {
        match receive_abort.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break aborted(),
            Err(mpsc::TryRecvError::Empty) => {},
        }
        if Instant::now() >= original_deadline {
                break io::Error::new(io::ErrorKind::TimedOut, "original Host relay session expired");
        }
        match relay.pump() {
            Err(error) => break error,
            Ok(_) => {},
        }
        match relay.normal_close_ready() {
            Ok(true) => return relay.finish_normal(),
            Ok(false) => {},
            Err(error) => break error,
        }
        // This is only an idle responsiveness cap, not a new session/cleanup
        // clock or a promise that owned teardown returns within ten ms.
        let Some(remaining) = original_deadline.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero()) else {
                break io::Error::new(io::ErrorKind::TimedOut, "original Host relay session expired");
            };
        match receive_abort.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break aborted(),
            Err(RecvTimeoutError::Timeout) => {},
        }
    };
    // The original error is passed unchanged. The real origin must publish
    // permanent local poison before pump/finish drops its child owners.
    relay.finish(Err(failure))
}
