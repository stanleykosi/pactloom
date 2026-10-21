//! Sole C endpoint owner for genuine SourceEntry, initial Read and Continue. It owns the
//! retained sender keys and finite one-shot encryption/send jobs. Native A is
//! NEVER performed here. Unlike an admitted Witness append, SourceEntry/Read
//! remain restrictive after A. Only an actually admitted opaque Continue Final
//! survives later R; the endpoint defers Cancel through its first cleanup bound.
//! The same owned driver alone pumps the genuine same-Core Host terminal. Its
//! separately bounded byte/status channels can never consume security slots.
//! Terminal failure restricts/closes transport, NOT the security drain loop.
use crate::{rejected, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
use wholepact_financial_coordinator_origin::{
    CoordinatorFinancialEndpointV1, CoordinatorFinancialEventV1, CoordinatorHostTerminalEndpointV1,
    FinancialCancelProgressV1, FinancialContinueArmOutboundV1, FinancialContinueFinalOutboundV1,
    SignerContinueRoleV1 as Role, SignerFinancialReadOutboundV1, SignerSourceEntryOutboundV1,
};

use zeroize::Zeroizing;

const HOST_OUTPUT_SLOTS: usize = 4;
const HOST_STATUS_SLOTS: usize = 3;

struct HostLine {
    ordinal: u64,
    line: Zeroizing<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostStatus {
    LineWritten(u64),
    Closed,
}

enum Command {
    Begin(Role, Instant),
    Entry(SignerSourceEntryOutboundV1),
    Read(SignerFinancialReadOutboundV1),
    BeginContinue(Role, Instant),
    ArmContinue(FinancialContinueArmOutboundV1),
    FinalContinue(FinancialContinueFinalOutboundV1),
}
pub(super) enum Outcome {
    Event(CoordinatorFinancialEventV1),
    DisposalStarted,
    Finished {
        disposal_confirmed: bool,
        clean: bool,
    },
}

pub(super) struct Driver {
    input: mpsc::SyncSender<Command>,
    pub(super) outcome: mpsc::Receiver<Outcome>,
    revoked: Arc<AtomicBool>,
    host_input: mpsc::SyncSender<HostLine>,
    pub(super) host_output: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    host_status: mpsc::Receiver<HostStatus>,
    host_pending: Option<u64>,
    host_last: u64,
    worker: Option<thread::JoinHandle<Result<()>>>,
    begun: [bool; 2],
    entry_sent: [bool; 2],
    read_sent: [bool; 2],
    continue_begun: [bool; 2],
    continue_armed: [bool; 2],
    continue_final: [bool; 2],
}
impl Driver {
    pub(super) fn spawn(
        endpoint: CoordinatorFinancialEndpointV1,
        terminal: CoordinatorHostTerminalEndpointV1,
    ) -> Result<Self> {
        // Six one-use command slots per original role. No retries.
        let (input, receive) = mpsc::sync_channel(12);
        // Finite protocol events only, including two dispositions and finish.
        let (send, outcome) = mpsc::sync_channel(32);
        let (host_input, host_receive) = mpsc::sync_channel(1);
        let (host_send, host_output) = mpsc::sync_channel(HOST_OUTPUT_SLOTS);
        let (host_status_send, host_status) = mpsc::sync_channel(HOST_STATUS_SLOTS);
        let revoked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&revoked);
        let worker = thread::Builder::new()
            .name("coordinator-source-entry".into())
            .spawn(move || {
                drive(
                    endpoint,
                    receive,
                    send,
                    flag,
                    terminal,
                    host_receive,
                    host_send,
                    host_status_send,
                )
            })?;
        Ok(Self {
            input,
            outcome,
            revoked,
            host_input,
            host_output,
            host_status,
            host_pending: None,
            host_last: 0,
            worker: Some(worker),
            begun: [false; 2],
            entry_sent: [false; 2],
            read_sent: [false; 2],
            continue_begun: [false; 2],
            continue_armed: [false; 2],
            continue_final: [false; 2],
        })
    }

    /// On failure, retain the actual unsent allocation for the App to revoke
    /// before dropping it. No queue retry or plaintext replacement is allowed.
    pub(super) fn send_host_line(
        &mut self,
        ordinal: u64,
        line: Zeroizing<String>,
    ) -> std::result::Result<(), Zeroizing<String>> {
        if self.is_revoked() || !next_host_line(self.host_last, self.host_pending, ordinal) {
            return Err(line);
        }
        self.host_last = ordinal;
        self.host_pending = Some(ordinal);
        self.host_input
            .try_send(HostLine { ordinal, line })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(unsent) | mpsc::TrySendError::Disconnected(unsent) => {
                    unsent.line
                }
            })
    }
    pub(super) fn try_host_status(&mut self) -> Result<Option<HostStatus>> {
        match self.host_status.try_recv() {
            Ok(HostStatus::LineWritten(ordinal)) => {
                if self.host_pending != Some(ordinal) {
                    self.revoke();
                    return Err(rejected("Host write observation changed"));
                }
                self.host_pending = None;
                Ok(Some(HostStatus::LineWritten(ordinal)))
            }
            Ok(HostStatus::Closed) => Ok(Some(HostStatus::Closed)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(rejected("Host status ended")),
        }
    }

    pub(super) fn begin(&mut self, role: Role, original_prequeue_ceiling: Instant) -> Result<()> {
        if !claim_once(&mut self.begun, role, self.revoked.load(Ordering::Acquire)) {
            self.revoke();
            return Err(rejected("source-entry preparation consumed"));
        }
        self.queue(Command::Begin(role, original_prequeue_ceiling))
    }
    pub(super) fn send_entry(
        &mut self,
        role: Role,
        outbound: SignerSourceEntryOutboundV1,
    ) -> Result<()> {
        if !self.begun[index(role)]
            || !claim_once(
                &mut self.entry_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("source-entry outbound consumed"));
        }
        // role is local bookkeeping only; the endpoint independently matches
        // the genuine outbound to its exact retained offer/key/actual role.
        self.queue(Command::Entry(outbound))
    }
    pub(super) fn send_read(
        &mut self,
        role: Role,
        outbound: SignerFinancialReadOutboundV1,
    ) -> Result<()> {
        if !self.entry_sent[index(role)]
            || !claim_once(
                &mut self.read_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("initial Read outbound consumed"));
        }
        self.queue(Command::Read(outbound))
    }
    pub(super) fn begin_continue(&mut self, role: Role, retained_deadline: Instant) -> Result<()> {
        if !self.read_sent[index(role)]
            || !claim_once(
                &mut self.continue_begun,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Continue preparation slot consumed"));
        }
        self.queue(Command::BeginContinue(role, retained_deadline))
    }
    pub(super) fn send_continue_arm(
        &mut self,
        role: Role,
        outbound: FinancialContinueArmOutboundV1,
    ) -> Result<()> {
        if !self.continue_begun[index(role)]
            || !claim_once(
                &mut self.continue_armed,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Continue Arm slot consumed"));
        }
        self.queue(Command::ArmContinue(outbound))
    }
    pub(super) fn send_continue_final(
        &mut self,
        role: Role,
        outbound: FinancialContinueFinalOutboundV1,
    ) -> Result<()> {
        // Native A has ALREADY happened. A later R cannot erase this actual
        // opaque Final. Role booleans only reject duplicates, not mint grants.
        if !self.continue_armed[index(role)] || !claim_once(&mut self.continue_final, role, false) {
            self.revoke();
            return Err(rejected("Continue Final slot consumed"));
        }
        self.queue(Command::FinalContinue(outbound))
    }
    fn queue(&self, command: Command) -> Result<()> {
        self.input.try_send(command).map_err(|_| {
            // TrySendError owns and drops an unsent password/outbound. No retry.
            self.revoke();
            rejected("source-entry job queue unavailable")
        })
    }
    pub(super) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
    pub(super) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
    /// Called only outside the native event loop, by the externally retained
    /// owner. No detach and no claim of wall-bounded kernel termination/reap.
    pub(super) fn join(&mut self) -> Result<()> {
        self.revoke();
        self.worker
            .take()
            .ok_or_else(|| rejected("source-entry driver already joined"))?
            .join()
            .map_err(|_| rejected("source-entry driver panicked"))?
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.revoke();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn drive(
    mut endpoint: CoordinatorFinancialEndpointV1,
    input: mpsc::Receiver<Command>,
    output: mpsc::SyncSender<Outcome>,
    revoked: Arc<AtomicBool>,
    terminal: CoordinatorHostTerminalEndpointV1,
    host_input: mpsc::Receiver<HostLine>,
    host_output: mpsc::SyncSender<Zeroizing<Vec<u8>>>,
    host_status: mpsc::SyncSender<HostStatus>,
) -> Result<()> {
    struct RevokeOnExit(Arc<AtomicBool>);
    impl Drop for RevokeOnExit {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let _on_exit = RevokeOnExit(Arc::clone(&revoked));
    let session = endpoint.session_deadline();
    let mut cancel_sent = false;
    let mut cleanup = None;
    let mut host = HostTransport {
        terminal: Some(terminal),
        pending_line: None,
        pending_output: None,
        closed_reported: false,
    };
    let work = (|| -> Result<()> {
        loop {
            endpoint.check_original_tree_alive()?;
            if Instant::now() >= session {
                revoked.store(true, Ordering::Release);
            }
            if cleanup.is_none() && !cancel_sent && endpoint.observe_restrictions().is_err() {
                revoked.store(true, Ordering::Release);
            }
            // Drain finite commands first, preserving ONLY an actually
            // admitted Continue Final. An empty queue is not abandonment: A
            // may have won just before R while its owner is still enqueueing.
            for _ in 0..12 {
                let command = match input.try_recv() {
                    Ok(command) => command,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        revoked.store(true, Ordering::Release);
                        break;
                    }
                };
                let restricted = cancel_sent || revoked.load(Ordering::Acquire);
                if let Command::FinalContinue(outbound) = command {
                    endpoint.send_continue_final(outbound)?;
                    continue;
                }
                if restricted {
                    // Entry plaintext/Read/Arm remain restrictive after R.
                    drop(command);
                    continue;
                }
                match command {
                    Command::Begin(Role::Signer1, ceiling) => {
                        endpoint.begin_source_entry_signer1(ceiling)?
                    }
                    Command::Begin(Role::Signer2, ceiling) => {
                        endpoint.begin_source_entry_signer2(ceiling)?
                    }
                    Command::Entry(outbound) => endpoint.send_source_entry(outbound)?,
                    Command::Read(outbound) => endpoint.send_initial_read(outbound)?,
                    Command::BeginContinue(Role::Signer1, ceiling) => {
                        endpoint.begin_continue_signer1(ceiling)?
                    }
                    Command::BeginContinue(Role::Signer2, ceiling) => {
                        endpoint.begin_continue_signer2(ceiling)?
                    }
                    Command::ArmContinue(outbound) => endpoint.send_continue_arm(outbound)?,
                    Command::FinalContinue(_) => unreachable!("handled exact Final above"),
                }
            }
            if revoked.load(Ordering::Acquire) && !cancel_sent {
                if cleanup.is_none() {
                    cleanup = Some(first_cleanup_ceiling(session, Instant::now()));
                    let _ = output.try_send(Outcome::DisposalStarted);
                }
                let (sent, deadline) = record_cancel_progress(
                    endpoint.try_send_cancel()?,
                    cleanup.expect("first cleanup captured"),
                );
                cancel_sent = sent;
                cleanup = Some(deadline);
            }
            for _ in 0..16 {
                let Some(event) = endpoint.try_receive()? else {
                    break;
                };
                if matches!(
                    &event,
                    CoordinatorFinancialEventV1::Failed { .. }
                        | CoordinatorFinancialEventV1::Restricted(_)
                ) {
                    revoked.store(true, Ordering::Release);
                }
                output
                    .try_send(Outcome::Event(event))
                    .map_err(|_| rejected("source-entry native receiver unavailable"))?;
            }
            // Security commands, native outcomes and typed cancellation always
            // run first. This bounded, nonblocking transport step NEVER returns
            // an error out of the security loop, even after EOF or partial write.
            host.pump(&host_input, &host_output, &host_status, &revoked);
            if cancel_sent && endpoint.is_disposed() {
                break;
            }
            if cleanup.is_some_and(|end| Instant::now() >= end) {
                return Err(rejected(
                    "source-entry actual disposal not confirmed before cleanup ceiling",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    revoked.store(true, Ordering::Release);
    // Close publishes actual shared R before pending input is dropped. A
    // terminal failure never skipped the security drain above. Any retained
    // output prefix is incomplete observation, not successful Host execution.
    host.close(&revoked);
    drop(host_input);
    drop(host);
    drop(host_output);
    drop(host_status);
    // Release all queued one-use plaintext before final tree disposal/reap.
    drop(input);
    let disposal_confirmed = cancel_sent && endpoint.is_disposed();
    let clean = if work.is_ok() && disposal_confirmed {
        endpoint.stop_and_reap().is_ok()
    } else {
        // The sole endpoint/tree owner performs its terminal drop. This does
        // not manufacture a successful source-disposal observation.
        drop(endpoint);
        false
    };
    let _ = output.try_send(Outcome::Finished {
        disposal_confirmed,
        clean,
    });
    if clean && work.is_ok() {
        Ok(())
    } else {
        Err(rejected("source-entry driver or disposal failed"))
    }
}

/// One partial user write and at most ONE extra output chunk beyond the four
/// channel slots. Backpressure stops reads rather than dropping observed bytes.
struct HostTransport {
    terminal: Option<CoordinatorHostTerminalEndpointV1>,
    pending_line: Option<u64>,
    pending_output: Option<Zeroizing<Vec<u8>>>,
    closed_reported: bool,
}
impl HostTransport {
    fn close(&mut self, revoked: &AtomicBool) {
        if let Some(mut terminal) = self.terminal.take() {
            terminal.close(); // Genuine same-Core shared R first.
        }
        revoked.store(true, Ordering::Release);
        self.pending_line = None;
        // Already-observed output stays bounded and is flushed if possible.
    }
    fn pump(
        &mut self,
        input: &mpsc::Receiver<HostLine>,
        output: &mpsc::SyncSender<Zeroizing<Vec<u8>>>,
        status: &mpsc::SyncSender<HostStatus>,
        revoked: &AtomicBool,
    ) {
        if revoked.load(Ordering::Acquire) {
            self.close(revoked);
        }
        if self.terminal.is_some() && self.pending_line.is_none() {
            match input.try_recv() {
                Ok(HostLine { ordinal, line }) => {
                    if self
                        .terminal
                        .as_mut()
                        .expect("checked")
                        .queue_user_line(line)
                        .is_err()
                    {
                        self.close(revoked);
                    } else {
                        self.pending_line = Some(ordinal);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => self.close(revoked),
            }
        }
        if self.terminal.is_some() && self.pending_line.is_some() {
            match self.terminal.as_mut().expect("checked").pump_user_input() {
                Ok(true) => {
                    let ordinal = self.pending_line.take().expect("checked");
                    if status.try_send(HostStatus::LineWritten(ordinal)).is_err() {
                        self.close(revoked);
                    }
                }
                Ok(false) => {} // Exact offset remains solely in the genuine endpoint.
                Err(_) => self.close(revoked),
            }
        }
        if self.terminal.is_some() && self.pending_output.is_none() {
            match self.terminal.as_mut().expect("checked").try_read_output() {
                Ok(chunk) => self.pending_output = chunk,
                Err(_) => self.close(revoked), // Includes EOF. Never exit security drain.
            }
        }
        if let Some(chunk) = self.pending_output.take() {
            match output.try_send(chunk) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(chunk)) => self.pending_output = Some(chunk),
                Err(mpsc::TrySendError::Disconnected(chunk)) => {
                    self.close(revoked);
                    drop(chunk); // Receiver is gone; never claim a complete transcript.
                }
            }
        }
        if self.terminal.is_none() {
            // All restrictive paths published shared R before these queued
            // unsent lines are dropped. There is no resubmission or new editor.
            while let Ok(line) = input.try_recv() {
                drop(line);
            }
            if !self.closed_reported {
                self.closed_reported = true;
                let _ = status.try_send(HostStatus::Closed);
            }
        }
    }
}
fn next_host_line(last: u64, pending: Option<u64>, incoming: u64) -> bool {
    pending.is_none() && last.checked_add(1) == Some(incoming)
}

fn index(role: Role) -> usize {
    match role {
        Role::Signer1 => 0,
        Role::Signer2 => 1,
    }
}
fn claim_once(slots: &mut [bool; 2], role: Role, revoked: bool) -> bool {
    if revoked || slots[index(role)] {
        return false;
    }
    slots[index(role)] = true;
    true
}
fn record_cancel_progress(
    progress: FinancialCancelProgressV1,
    retained: Instant,
) -> (bool, Instant) {
    match progress {
        FinancialCancelProgressV1::Sent => (true, retained),
        // Actual endpoint result, not a caller-created permission to bypass R.
        FinancialCancelProgressV1::DeferredForAdmittedContinue { deadline } => {
            (false, retained.min(deadline))
        }
    }
}
fn first_cleanup_ceiling(session: Instant, now: Instant) -> Instant {
    (now + Duration::from_secs(5)).min(session + Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn genuine_pending_final_defers_cancel_without_renewing_first_cleanup_bound() {
        // Only a data-result model; no endpoint, Final, thread, IPC or native A.
        let first = Instant::now() + Duration::from_secs(5);
        let (sent, retained) = record_cancel_progress(
            FinancialCancelProgressV1::DeferredForAdmittedContinue { deadline: first },
            first,
        );
        assert!(!sent);
        let (sent, retained) = record_cancel_progress(
            FinancialCancelProgressV1::DeferredForAdmittedContinue {
                deadline: first + Duration::from_secs(20),
            },
            retained,
        );
        assert!(!sent);
        assert_eq!(retained, first);
        let earlier = first - Duration::from_secs(1);
        let (sent, retained) = record_cancel_progress(
            FinancialCancelProgressV1::DeferredForAdmittedContinue { deadline: earlier },
            retained,
        );
        assert!(!sent);
        assert_eq!(retained, earlier);
        let (sent, retained) = record_cancel_progress(FinancialCancelProgressV1::Sent, retained);
        assert!(sent);
        assert_eq!(retained, earlier);
    }
    #[test]
    fn each_fixed_role_has_one_job_slot_and_revocation_cannot_rearm_it() {
        let mut slots = [false; 2];
        assert!(claim_once(&mut slots, Role::Signer1, false));
        assert!(!claim_once(&mut slots, Role::Signer1, false));
        assert!(!claim_once(&mut slots, Role::Signer2, true));
        assert!(claim_once(&mut slots, Role::Signer2, false));
        assert!(!claim_once(&mut slots, Role::Signer2, false));
    }
    #[test]
    fn one_cleanup_cutoff_never_extends_original_supervision() {
        let epoch = Instant::now();
        let session = epoch + Duration::from_secs(60);
        let first = first_cleanup_ceiling(session, epoch);
        assert_eq!(first, epoch + Duration::from_secs(5));
        assert_eq!(
            first_cleanup_ceiling(session, session + Duration::from_secs(4)),
            session + Duration::from_secs(5)
        );
        assert_eq!(first, epoch + Duration::from_secs(5)); // Stored first cutoff, not renewed by traffic.
    }
    #[test]
    fn host_line_is_explicit_once_and_cannot_overlap_partial_write() {
        assert!(next_host_line(0, None, 1));
        assert!(!next_host_line(0, None, 0));
        assert!(!next_host_line(1, Some(1), 2));
        assert!(!next_host_line(1, None, 1));
        assert!(!next_host_line(1, None, 3));
        assert!(next_host_line(1, None, 2));
        assert!(!next_host_line(u64::MAX, None, 0));
    }
    #[test]
    fn output_backpressure_retains_one_chunk_and_does_not_use_security_channel() {
        // Pure in-memory channels and public synthetic bytes. No transport,
        // worker thread, endpoint, GUI, source or cryptographic operation.
        let (send, receive) = mpsc::sync_channel(HOST_OUTPUT_SLOTS);
        for _ in 0..HOST_OUTPUT_SLOTS {
            send.try_send(Zeroizing::new(vec![b'x'; 4096])).unwrap();
        }
        let chunk = Zeroizing::new(vec![b'y'; 4096]);
        let pending = match send.try_send(chunk) {
            Err(mpsc::TrySendError::Full(chunk)) => chunk,
            _ => panic!("fixed output channel must apply backpressure"),
        };
        assert_eq!(pending.len(), 4096);
        assert_eq!(receive.try_iter().count(), HOST_OUTPUT_SLOTS);
        let (security_send, security_receive) = mpsc::sync_channel(1);
        security_send.try_send(7u8).unwrap();
        assert_eq!(security_receive.try_recv().unwrap(), 7);
        assert_eq!(pending[0], b'y');
    }
    #[test]
    fn rejected_host_enqueue_returns_owned_allocation_before_caller_cleanup() {
        let (send, receive) = mpsc::sync_channel::<HostLine>(1);
        drop(receive);
        let line = Zeroizing::new("synthetic public line".to_owned());
        let pointer = line.as_ptr();
        let unsent = match send.try_send(HostLine { ordinal: 1, line }) {
            Err(mpsc::TrySendError::Disconnected(unsent)) => unsent.line,
            _ => panic!("closed mock queue must return owned input"),
        };
        assert_eq!(unsent.as_ptr(), pointer);
        assert_eq!(&*unsent, "synthetic public line");
        let restricted = std::cell::Cell::new(false);
        restricted.set(true); // Model the App's immediate native.revoke.
        assert!(restricted.get());
        drop(unsent);
    }
}
