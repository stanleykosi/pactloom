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
    CoordinatorFinancialEndpointV1, CoordinatorFinancialEventV1,
    CoordinatorFinancialHistoryEventV1, CoordinatorFinancialSigningEventV1, FinancialHistoryInputsV1,
    FinancialHistorySetupTicketV1, FinancialHistorySetupOutboundV1,
    FinancialHistoryServeOutboundV1,
    CoordinatorWitnessRetirementTicketV1, CoordinatorWitnessRetirementOutboundV1,
    CoordinatorWitnessRetiredV1,
    CoordinatorFinancialWitnessEventV1, CoordinatorHostTerminalEndpointV1,
    FinancialCancelProgressV1, FinancialSendProgressV1, FinancialContinueArmOutboundV1, FinancialContinueFinalOutboundV1,
    FinancialWitnessArmOutboundV1, FinancialWitnessFinalOutboundV1, FinancialWitnessInputsV1,
    FinancialWitnessSetupOutboundV1, FinancialWitnessSetupTicketV1, SignerAdmitArmOutboundV1,
    SignerAdmitFinalOutboundV1, SignerContinueRoleV1 as Role, SignerFinancialReadOutboundV1,
    SignerSourceEntryOutboundV1,
};

use zeroize::Zeroizing;

const COMMAND_SLOTS: usize = 32;
const SECURITY_SLOTS: usize = 80;
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
    PrepareHistory(Role, FinancialHistoryInputsV1, Instant),
    SetupHistory(FinancialHistorySetupOutboundV1),
    ServeHistory(FinancialHistoryServeOutboundV1),
    RetireHistory(CoordinatorWitnessRetirementOutboundV1),
    BeginContinue(Role, Instant),
    ArmContinue(FinancialContinueArmOutboundV1),
    FinalContinue(FinancialContinueFinalOutboundV1),
    PrepareWitness(Role, FinancialWitnessInputsV1, Instant),
    SetupWitness(FinancialWitnessSetupOutboundV1),
    ArmWitness(FinancialWitnessArmOutboundV1),
    FinalWitness(FinancialWitnessFinalOutboundV1),
    ArmAdmit(SignerAdmitArmOutboundV1),
    FinalAdmit(SignerAdmitFinalOutboundV1),
}
pub(super) enum Outcome {
    Event(CoordinatorFinancialEventV1),
    HistorySetup(Role, FinancialHistorySetupTicketV1),
    History(CoordinatorFinancialHistoryEventV1),
    HistoryRetirement(CoordinatorWitnessRetirementTicketV1),
    HistoryRetired(CoordinatorWitnessRetiredV1),
    HistoryResumed(Role),
    SigningDisposed(Role),
    SigningClosed(Role),
    SigningFailed(Role),
    WitnessSetup(Role, FinancialWitnessSetupTicketV1),
    Witness(CoordinatorFinancialWitnessEventV1),
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
    history_prepared: [bool; 2],
    history_setup: [bool; 2],
    history_serve: [bool; 2],
    history_retirement_sent: [bool; 2],
    continue_begun: [bool; 2],
    continue_armed: [bool; 2],
    continue_final: [bool; 2],
    witness_prepared: [bool; 2],
    witness_setup: [bool; 2],
    witness_armed: [bool; 2],
    witness_final: [bool; 2],
    admit_armed: [bool; 2],
    admit_final: [bool; 2],
}
impl Driver {
    pub(super) fn spawn(
        endpoint: CoordinatorFinancialEndpointV1,
        terminal: CoordinatorHostTerminalEndpointV1,
    ) -> Result<Self> {
        // Sixteen one-use commands per original role. No retries.
        let (input, receive) = mpsc::sync_channel(COMMAND_SLOTS);
        // Finite protocol events only, including two dispositions and finish.
        let (send, outcome) = mpsc::sync_channel(SECURITY_SLOTS);
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
            history_prepared: [false; 2],
            history_setup: [false; 2],
            history_serve: [false; 2],
            history_retirement_sent: [false; 2],
            continue_begun: [false; 2],
            continue_armed: [false; 2],
            continue_final: [false; 2],
            witness_prepared: [false; 2],
            witness_setup: [false; 2],
            witness_armed: [false; 2],
            witness_final: [false; 2],
            admit_armed: [false; 2],
            admit_final: [false; 2],
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
            || !self.history_serve[index(role)]
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
    pub(super) fn prepare_history(
        &mut self, role: Role, inputs: FinancialHistoryInputsV1, ceiling: Instant,
    ) -> Result<()> {
        if !self.entry_sent[index(role)]
            || !claim_once(&mut self.history_prepared, role, self.revoked.load(Ordering::Acquire))
        {
            self.revoke();
            return Err(rejected("initial History Setup preparation consumed"));
        }
        self.queue(Command::PrepareHistory(role, inputs, ceiling))
    }
    pub(super) fn send_history_setup(
        &mut self, role: Role, outbound: FinancialHistorySetupOutboundV1,
    ) -> Result<()> {
        if !self.history_prepared[index(role)]
            || !claim_once(&mut self.history_setup, role, self.revoked.load(Ordering::Acquire))
        {
            self.revoke();
            return Err(rejected("initial History Setup outbound consumed"));
        }
        self.queue(Command::SetupHistory(outbound))
    }
    pub(super) fn send_history_serve(
        &mut self, role: Role, outbound: FinancialHistoryServeOutboundV1,
    ) -> Result<()> {
        if !self.history_setup[index(role)]
            || !claim_once(&mut self.history_serve, role, self.revoked.load(Ordering::Acquire))
        {
            self.revoke();
            return Err(rejected("initial History Serve outbound consumed"));
        }
        self.queue(Command::ServeHistory(outbound))
    }
    pub(super) fn send_history_retirement(
        &mut self, role: Role, outbound: CoordinatorWitnessRetirementOutboundV1,
    ) -> Result<()> {
        if !self.read_sent[index(role)]
            || !claim_once(&mut self.history_retirement_sent, role, self.revoked.load(Ordering::Acquire))
        {
            self.revoke();
            return Err(rejected("initial History retirement outbound consumed"));
        }
        self.queue(Command::RetireHistory(outbound))
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
    pub(super) fn prepare_witness(
        &mut self,
        role: Role,
        inputs: FinancialWitnessInputsV1,
        ceiling: Instant,
    ) -> Result<()> {
        if !self.continue_final[index(role)]
            || !claim_once(
                &mut self.witness_prepared,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Witness Setup preparation consumed"));
        }
        self.queue(Command::PrepareWitness(role, inputs, ceiling))
    }
    pub(super) fn send_witness_setup(
        &mut self,
        role: Role,
        outbound: FinancialWitnessSetupOutboundV1,
    ) -> Result<()> {
        if !self.witness_prepared[index(role)]
            || !claim_once(
                &mut self.witness_setup,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Witness Setup consumed"));
        }
        self.queue(Command::SetupWitness(outbound))
    }
    pub(super) fn send_witness_arm(
        &mut self,
        role: Role,
        outbound: FinancialWitnessArmOutboundV1,
    ) -> Result<()> {
        if !self.witness_setup[index(role)]
            || !claim_once(
                &mut self.witness_armed,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Witness Arm consumed"));
        }
        self.queue(Command::ArmWitness(outbound))
    }
    pub(super) fn send_witness_final(
        &mut self,
        role: Role,
        outbound: FinancialWitnessFinalOutboundV1,
    ) -> Result<()> {
        // Only this genuine already-admitted W Final has the scoped late-R
        // transport exception. A boolean cannot construct or substitute it.
        if !self.witness_armed[index(role)] || !claim_once(&mut self.witness_final, role, false) {
            self.revoke();
            return Err(rejected("Witness Final consumed"));
        }
        self.queue(Command::FinalWitness(outbound))
    }
    pub(super) fn send_admit_arm(
        &mut self,
        role: Role,
        outbound: SignerAdmitArmOutboundV1,
    ) -> Result<()> {
        if !self.continue_final[index(role)]
            || !claim_once(
                &mut self.admit_armed,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Signer Admit Arm consumed"));
        }
        self.queue(Command::ArmAdmit(outbound))
    }
    pub(super) fn send_admit_final(
        &mut self,
        role: Role,
        outbound: SignerAdmitFinalOutboundV1,
    ) -> Result<()> {
        // S transport remains R-sensitive, unlike the admitted local W append.
        if !self.admit_armed[index(role)]
            || !claim_once(
                &mut self.admit_final,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Signer Admit Final consumed"));
        }
        self.queue(Command::FinalAdmit(outbound))
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
    let mut signing_disposed = [false; 2];
    let mut signing_close_sent = [false; 2];
    let mut history_retained = [false; 2];
    let mut history_disposed = [false; 2];
    let mut history_close_sent = [false; 2];
    let mut witness_disposed = [false; 2];
    let mut witness_close_sent = [false; 2];
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
            for _ in 0..COMMAND_SLOTS {
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
                if let Command::FinalWitness(outbound) = command {
                    endpoint.send_witness_final(outbound)?;
                    continue;
                }
                if restricted {
                    // Entry plaintext/Read/Arm remain restrictive after R.
                    drop(command);
                    continue;
                }
                match command {
                    Command::Begin(role, ceiling) => record_send_progress(endpoint.try_begin_source_entry(role, ceiling)?, &revoked),
                    Command::Entry(outbound) => record_send_progress(endpoint.try_send_source_entry(outbound)?, &revoked),
                    Command::Read(outbound) => record_send_progress(endpoint.try_send_initial_read(outbound)?, &revoked),
                    Command::PrepareHistory(role, inputs, ceiling) => {
                        if let Some(ticket) = endpoint.try_prepare_history_setup(role, inputs, ceiling)? {
                            output.try_send(Outcome::HistorySetup(role, ticket))
                                .map_err(|_| rejected("History Setup receiver unavailable"))?;
                        } else { revoked.store(true, Ordering::Release); }
                    }
                    Command::SetupHistory(outbound) => record_send_progress(endpoint.try_send_history_setup(outbound)?, &revoked),
                    Command::ServeHistory(outbound) => record_send_progress(endpoint.try_send_history_serve(outbound)?, &revoked),
                    Command::RetireHistory(_) => return Err(rejected("retirement outside its exclusive owner wait")),
                    Command::BeginContinue(role, ceiling) => record_send_progress(endpoint.try_send_continue_prepare(role, ceiling)?, &revoked),
                    Command::ArmContinue(outbound) => record_send_progress(endpoint.try_send_continue_arm(outbound)?, &revoked),
                    Command::PrepareWitness(role, inputs, ceiling) => {
                        if let Some(ticket) = endpoint.try_prepare_witness_setup(role, inputs, ceiling)? {
                            output.try_send(Outcome::WitnessSetup(role, ticket))
                                .map_err(|_| rejected("Witness Setup receiver unavailable"))?;
                        } else { revoked.store(true, Ordering::Release); }
                    }
                    Command::SetupWitness(outbound) => record_send_progress(endpoint.try_send_witness_setup(outbound)?, &revoked),
                    Command::ArmWitness(outbound) => record_send_progress(endpoint.try_send_witness_arm(outbound)?, &revoked),
                    Command::ArmAdmit(outbound) => record_send_progress(endpoint.try_send_admit_arm(outbound)?, &revoked),
                    Command::FinalAdmit(outbound) => record_send_progress(endpoint.try_send_admit_final(outbound)?, &revoked),
                    Command::FinalContinue(_) | Command::FinalWitness(_) => {
                        unreachable!("handled exact Finals above")
                    }
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
                // The endpoint's authenticated receive has privately latched
                // exact completion. No UI bit, queue order or DTO can do this.
                if let CoordinatorFinancialEventV1::HistoryRetained { role, .. } = &event {
                    history_retained[index(*role)] = true;
                    record_send_progress(endpoint.try_finish_history_read(*role)?, &revoked);
                }
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
            // History service observations remain observable after R. Finish
            // means the actual S retained its complete history/preparation; it
            // never grants retirement or authorizes a later W purpose.
            for _ in 0..16 {
                let Some(event) = endpoint.try_receive_history()? else { break; };
                match &event {
                    CoordinatorFinancialHistoryEventV1::Disposed(role) => {
                        history_disposed[index(*role)] = true;
                    }
                    CoordinatorFinancialHistoryEventV1::PreparationFailed(_)
                    | CoordinatorFinancialHistoryEventV1::ServiceFailed(_)
                    | CoordinatorFinancialHistoryEventV1::Restricted(_) => {
                        revoked.store(true, Ordering::Release);
                    }
                    _ => {}
                }
                let normal_retirement = match &event {
                    CoordinatorFinancialHistoryEventV1::Disposed(role)
                        if !cancel_sent && !revoked.load(Ordering::Acquire) && history_retained[index(*role)] => Some(*role),
                    _ => None,
                };
                output.try_send(Outcome::History(event))
                    .map_err(|_| rejected("History native receiver unavailable"))?;
                if let Some(role) = normal_retirement {
                    let ticket = endpoint.prepare_history_retirement(role)?;
                    retire_history_exclusively(&mut endpoint, &input, &output, &revoked, ticket)?;
                    // The real retirement internally consumed exact PurposeClosed
                    // and normal reap; do not send a second terminal request.
                    history_close_sent[index(role)] = true;
                }
            }
            // W outcomes remain observable after R. Disposal is not retirement.
            // Purpose-close is ONLY global cleanup grammar, never normal progress.
            for _ in 0..16 {
                let Some(event) = endpoint.try_receive_witness()? else {
                    break;
                };
                match &event {
                    CoordinatorFinancialWitnessEventV1::Disposed(role) => {
                        witness_disposed[index(*role)] = true
                    }
                    CoordinatorFinancialWitnessEventV1::FirstFailure { .. }
                    | CoordinatorFinancialWitnessEventV1::PreparationFailed(_)
                    | CoordinatorFinancialWitnessEventV1::Restricted(_) => {
                        revoked.store(true, Ordering::Release)
                    }
                    _ => {}
                }
                output
                    .try_send(Outcome::Witness(event))
                    .map_err(|_| rejected("Witness native receiver unavailable"))?;
            }
            // The full original tree also owns not-yet-started Signing roles.
            // Drain their actual cleanup grammar, but provide no positive UI or
            // setup path here. Unexpected service readiness is never adopted.
            for _ in 0..16 {
                let Some(event) = endpoint.try_receive_signing()? else { break; };
                let observation = match event {
                    CoordinatorFinancialSigningEventV1::Disposed(role) => {
                        signing_disposed[index(role)] = true;
                        Outcome::SigningDisposed(role)
                    }
                    CoordinatorFinancialSigningEventV1::PurposeClosed(role) => Outcome::SigningClosed(role),
                    CoordinatorFinancialSigningEventV1::PreparationFailed(role)
                    | CoordinatorFinancialSigningEventV1::ServiceFailed(role)
                    | CoordinatorFinancialSigningEventV1::Restricted(role) => {
                        revoked.store(true, Ordering::Release);
                        Outcome::SigningFailed(role)
                    }
                    CoordinatorFinancialSigningEventV1::Display(_)
                    | CoordinatorFinancialSigningEventV1::Serving(_) => {
                        return Err(rejected("unsolicited positive Signing service event"));
                    }
                };
                output.try_send(observation).map_err(|_| rejected("Signing cleanup receiver unavailable"))?;
            }
            for role in [Role::Signer1, Role::Signer2] {
                let i = index(role);
                if may_close_witness(cancel_sent, signing_disposed[i], signing_close_sent[i]) {
                    endpoint.close_signing_purpose(role)?;
                    signing_close_sent[i] = true;
                }
                if may_close_witness(cancel_sent, history_disposed[i], history_close_sent[i]) {
                    endpoint.close_history_purpose(role)?;
                    history_close_sent[i] = true;
                }
                if may_close_witness(cancel_sent, witness_disposed[i], witness_close_sent[i]) {
                    endpoint.close_witness_purpose(role)?;
                    witness_close_sent[i] = true;
                }
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

/// Actual fixed History retirement only. No ordinary queue, PTY, or positive
/// source observer runs while the original W is expected to exit. The private
/// endpoint completion record, never a UI acknowledgment, proves resume.
fn retire_history_exclusively(
    endpoint: &mut CoordinatorFinancialEndpointV1,
    input: &mpsc::Receiver<Command>, output: &mpsc::SyncSender<Outcome>,
    revoked: &AtomicBool, ticket: CoordinatorWitnessRetirementTicketV1,
) -> Result<()> {
    let role = ticket.role();
    let original_cutoff = ticket.deadline();
    output.try_send(Outcome::HistoryRetirement(ticket))
        .map_err(|_| rejected("History retirement native receiver unavailable"))?;
    let outbound = loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected("History retirement interrupted before native pause"));
        }
        // No reap can start until this sole owner receives the nominal pause
        // outbound. Ordinary actor checks are still valid before that point.
        endpoint.check_original_tree_alive()?;
        match input.try_recv() {
            Ok(Command::RetireHistory(outbound)) => break outbound,
            Ok(_) => return Err(rejected("unexpected positive command during History retirement")),
            Err(mpsc::TryRecvError::Disconnected) => return Err(rejected("History retirement native owner ended")),
            Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    };
    let completion = endpoint.retire_witness(outbound)?;
    if completion.role() != role { return Err(rejected("History retirement actual role changed")); }
    output.try_send(Outcome::HistoryRetired(completion))
        .map_err(|_| rejected("History retirement completion receiver unavailable"))?;
    loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected("History retirement interrupted before native resume"));
        }
        if endpoint.finish_retirement_resume()? { break; }
        thread::sleep(Duration::from_millis(1));
    }
    output.try_send(Outcome::HistoryResumed(role))
        .map_err(|_| rejected("History resume receiver unavailable"))?;
    Ok(())
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
fn record_send_progress(progress: FinancialSendProgressV1, revoked: &AtomicBool) {
    // Only Origin can classify a validated ordinary-R/no-attempt race. Any
    // other error remains fatal at the concrete callsite; no retry is created.
    if matches!(progress, FinancialSendProgressV1::Restricted) {
        revoked.store(true, Ordering::Release);
    }
}
fn record_cancel_progress(
    progress: FinancialCancelProgressV1,
    retained: Instant,
) -> (bool, Instant) {
    match progress {
        FinancialCancelProgressV1::Sent => (true, retained),
        // Actual endpoint result, not a caller-created permission to bypass R.
        FinancialCancelProgressV1::DeferredForAdmittedContinue { deadline }
        | FinancialCancelProgressV1::DeferredForAdmittedWitness { deadline } => {
            (false, retained.min(deadline))
        }
    }
}
fn may_close_witness(global_cancel_sent: bool, actually_disposed: bool, close_sent: bool) -> bool {
    global_cancel_sent && actually_disposed && !close_sent
}
fn first_cleanup_ceiling(session: Instant, now: Instant) -> Instant {
    (now + Duration::from_secs(5)).min(session + Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_nonfinal_restriction_latches_without_rearming_or_claiming_send() {
        let revoked = AtomicBool::new(false);
        record_send_progress(FinancialSendProgressV1::Sent, &revoked);
        assert!(!revoked.load(Ordering::Acquire));
        record_send_progress(FinancialSendProgressV1::Restricted, &revoked);
        assert!(revoked.load(Ordering::Acquire));
        record_send_progress(FinancialSendProgressV1::Sent, &revoked);
        assert!(revoked.load(Ordering::Acquire));
    }
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
    fn witness_pending_final_uses_same_first_cleanup_not_a_fresh_bound() {
        let first = Instant::now() + Duration::from_secs(5);
        let (sent, deadline) = record_cancel_progress(
            FinancialCancelProgressV1::DeferredForAdmittedWitness {
                deadline: first + Duration::from_secs(30),
            },
            first,
        );
        assert!(!sent);
        assert_eq!(deadline, first);
        let (sent, deadline) = record_cancel_progress(
            FinancialCancelProgressV1::DeferredForAdmittedContinue { deadline: first },
            deadline,
        );
        assert!(!sent);
        assert_eq!(deadline, first);
    }
    #[test]
    fn witness_disposed_is_not_normal_retirement_or_permission_to_close() {
        assert!(!may_close_witness(false, true, false));
        assert!(!may_close_witness(true, false, false));
        assert!(may_close_witness(true, true, false));
        assert!(!may_close_witness(true, true, true));
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
