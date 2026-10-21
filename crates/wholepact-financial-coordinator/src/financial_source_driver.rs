//! Sole C endpoint owner for genuine SourceEntry, initial Read and Continue. It owns the
//! retained sender keys and finite one-shot encryption/send jobs. Native A is
//! NEVER performed here. Unlike an admitted Witness append, SourceEntry/Read
//! remain restrictive after A. Only an actually admitted opaque Continue Final
//! survives later R; the endpoint defers Cancel through its first cleanup bound.
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
    CoordinatorFinancialEndpointV1, CoordinatorFinancialEventV1, FinancialCancelProgressV1,
    FinancialContinueArmOutboundV1, FinancialContinueFinalOutboundV1, SignerContinueRoleV1 as Role,
    SignerFinancialReadOutboundV1, SignerSourceEntryOutboundV1,
};

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
    worker: Option<thread::JoinHandle<Result<()>>>,
    begun: [bool; 2],
    entry_sent: [bool; 2],
    read_sent: [bool; 2],
    continue_begun: [bool; 2],
    continue_armed: [bool; 2],
    continue_final: [bool; 2],
}
impl Driver {
    pub(super) fn spawn(endpoint: CoordinatorFinancialEndpointV1) -> Result<Self> {
        // Six one-use command slots per original role. No retries.
        let (input, receive) = mpsc::sync_channel(12);
        // Finite protocol events only, including two dispositions and finish.
        let (send, outcome) = mpsc::sync_channel(32);
        let revoked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&revoked);
        let worker = thread::Builder::new()
            .name("coordinator-source-entry".into())
            .spawn(move || drive(endpoint, receive, send, flag))?;
        Ok(Self {
            input,
            outcome,
            revoked,
            worker: Some(worker),
            begun: [false; 2],
            entry_sent: [false; 2],
            read_sent: [false; 2],
            continue_begun: [false; 2],
            continue_armed: [false; 2],
            continue_final: [false; 2],
        })
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
}
