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
    CompletedPairInputsV1, CoordinatorCompletedPairEventV1,
    FinancialNormalFinishOutboundV1, FinancialNormalCompletionV1,
    FinancialCompletedPairSetupTicketV1, FinancialCompletedPairSetupOutboundV1,
    FinancialCompletedPairServeOutboundV1,
    CoordinatorFinancialHistoryEventV1, CoordinatorFinancialSigningEventV1,
    CoordinatorFinancialWitnessEventV1, CoordinatorHostTerminalEndpointV1,
    CoordinatorWitnessRetiredV1, CoordinatorWitnessRetirementOutboundV1,
    CoordinatorWitnessRetirementTicketV1, FinancialCancelProgressV1,
    FinancialContinueArmOutboundV1, FinancialContinueFinalOutboundV1, FinancialHistoryInputsV1,
    FinancialHistoryServeOutboundV1, FinancialHistorySetupOutboundV1,
    FinancialHistorySetupTicketV1, FinancialSendProgressV1, FinancialSigningInputsV1,
    FinancialSigningServeOutboundV1, FinancialSigningSetupOutboundV1,
    FinancialSigningSetupTicketV1, FinancialSignedResultCustodyV1, FinancialWitnessArmOutboundV1, FinancialWitnessFinalOutboundV1,
    FinancialWitnessInputsV1, FinancialWitnessSetupOutboundV1, FinancialWitnessSetupTicketV1,
    SignerAcquireArmOutboundV1, SignerAcquireFinalOutboundV1, SignerActivateArmOutboundV1,
    SignerActivateFinalOutboundV1, SignerActivateReadOutboundV1, SignerAdmitArmOutboundV1,
    SignerAdmitFinalOutboundV1, SignerContinueRoleV1 as Role, SignerFinancialReadOutboundV1,
    SignerFinancialWriterReadOutboundV1, SignerSourceEntryOutboundV1, SignerV3AdmitArmOutboundV1,
    SignerV3AdmitFinalOutboundV1, SignerV3AdmitReadOutboundV1, SignerV3EnrollmentOutboundV1,
    SignerV3ManifestOutboundV1, SignerV3PairOutboundV1, SignerV3PrepareReadOutboundV1,
    SignerV3ReceiveOutboundV1, SignerV3RediscloseOutboundV1, SignerV3RedisclosureReadOutboundV1,
    SignerV3SourceEntryOutboundV1, SignerV3SourceEntrySelectionV1,
};
use wholepact_financial_coordinator_origin::{
    SignerReturnExactOutboundV1, SignerReturnReadOutboundV1,
};
use wholepact_financial_coordinator_origin::{SignerSignExactOutboundV1, SignerSignReadOutboundV1};
use wholepact_financial_coordinator_origin::{
    SignerWalletObserveOutboundV1, SignerWalletPrepareOutboundV1,
};

use zeroize::Zeroizing;

use wholepact_financial_coordinator_origin::SignerV3AuditOutboundV1;
const COMMAND_SLOTS: usize = 96;
const SECURITY_SLOTS: usize = 128;
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
    NormalFinish(FinancialNormalFinishOutboundV1),
    PrepareCompletedPair(CompletedPairInputsV1, Instant),
    SetupCompletedPair(FinancialCompletedPairSetupOutboundV1),
    ServeCompletedPair(FinancialCompletedPairServeOutboundV1),
    ReturnRead(SignerReturnReadOutboundV1),
    ReturnExact(SignerReturnExactOutboundV1),
    SignRead(SignerSignReadOutboundV1),
    SignExact(SignerSignExactOutboundV1),
    FinancialSetup(Role, String, String),
    WalletPrepare(SignerWalletPrepareOutboundV1),
    WalletObserve(SignerWalletObserveOutboundV1),
    BeginV3(Role, SignerV3SourceEntrySelectionV1, Instant),
    V3Entry(SignerV3SourceEntryOutboundV1),
    V3Pair(SignerV3PairOutboundV1),
    V3Audit(SignerV3AuditOutboundV1),
    V3AdmitFinal(SignerV3AdmitFinalOutboundV1),
    V3AdmitArm(SignerV3AdmitArmOutboundV1),
    V3AdmitRead(SignerV3AdmitReadOutboundV1),
    ActivateFinal(SignerActivateFinalOutboundV1),
    ActivateArm(SignerActivateArmOutboundV1),
    ActivateRead(SignerActivateReadOutboundV1),
    V3Receive(SignerV3ReceiveOutboundV1),
    V3PrepareRead(SignerV3PrepareReadOutboundV1),
    V3OwnerSetup(Role, String),
    V3Redisclose(SignerV3RediscloseOutboundV1),
    V3RedisclosureRead(SignerV3RedisclosureReadOutboundV1),
    V3Manifest(SignerV3ManifestOutboundV1),
    V3Enrollment(SignerV3EnrollmentOutboundV1),
    Begin(Role, Instant),
    Entry(SignerSourceEntryOutboundV1),
    Read(SignerFinancialReadOutboundV1),
    PrepareHistory(Role, FinancialHistoryInputsV1, Instant),
    SetupHistory(FinancialHistorySetupOutboundV1),
    ServeHistory(FinancialHistoryServeOutboundV1),
    RetireHistory(CoordinatorWitnessRetirementOutboundV1),
    RetireSigningPredecessor(CoordinatorWitnessRetirementOutboundV1),
    BeginSigningRetirement(Role),
    RetireSigning(CoordinatorWitnessRetirementOutboundV1),
    BeginContinue(Role, Instant),
    ArmContinue(FinancialContinueArmOutboundV1),
    FinalContinue(FinancialContinueFinalOutboundV1),
    PrepareWitness(Role, FinancialWitnessInputsV1, Instant),
    SetupWitness(FinancialWitnessSetupOutboundV1),
    ArmWitness(FinancialWitnessArmOutboundV1),
    FinalWitness(FinancialWitnessFinalOutboundV1),
    ArmAdmit(SignerAdmitArmOutboundV1),
    FinalAdmit(SignerAdmitFinalOutboundV1),
    PrepareSigning(Role, FinancialSigningInputsV1, Instant),
    SetupSigning(FinancialSigningSetupOutboundV1),
    ServeSigning(FinancialSigningServeOutboundV1),
    WriterRead(SignerFinancialWriterReadOutboundV1),
    ArmAcquire(SignerAcquireArmOutboundV1),
    FinalAcquire(SignerAcquireFinalOutboundV1),
}
pub(super) enum Outcome {
    NormalFinished(FinancialNormalCompletionV1),
    CompletedPairSetup(FinancialCompletedPairSetupTicketV1),
    CompletedPair(CoordinatorCompletedPairEventV1),
    Event(CoordinatorFinancialEventV1),
    HistorySetup(Role, FinancialHistorySetupTicketV1),
    History(CoordinatorFinancialHistoryEventV1),
    HistoryRetirement(CoordinatorWitnessRetirementTicketV1),
    HistoryRetired(CoordinatorWitnessRetiredV1),
    HistoryResumed(Role),
    SigningPredecessorRetirement(CoordinatorWitnessRetirementTicketV1),
    SigningPredecessorRetired(CoordinatorWitnessRetiredV1),
    SigningPredecessorResumed(Role),
    SigningRetirement(CoordinatorWitnessRetirementTicketV1),
    SigningRetired(CoordinatorWitnessRetiredV1),
    SigningResumed(FinancialSignedResultCustodyV1),
    SigningSetup(Role, FinancialSigningSetupTicketV1),
    Signing(CoordinatorFinancialSigningEventV1),
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
    normal_finish_sent: bool,
    normal_finished: Arc<AtomicBool>,
    completed_pair_prepared: bool,
    completed_pair_setup: bool,
    completed_pair_serve: bool,
    input: mpsc::SyncSender<Command>,
    pub(super) outcome: mpsc::Receiver<Outcome>,
    revoked: Arc<AtomicBool>,
    host_input: mpsc::SyncSender<HostLine>,
    pub(super) host_output: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    host_status: mpsc::Receiver<HostStatus>,
    host_pending: Option<u64>,
    host_last: u64,
    worker: Option<thread::JoinHandle<Result<bool>>>,
    v3_begun: [bool; 2],
    v3_entry_sent: [bool; 2],
    v3_pair_sent: [bool; 2],
    v3_receive_sent: [bool; 2],
    v3_prepare_read_sent: [bool; 2],
    v3_owner_selected: [bool; 2],
    v3_redisclose_sent: [bool; 2],
    v3_redisclosure_read_sent: [bool; 2],
    v3_manifest_sent: [bool; 2],
    v3_enrollment_sent: [bool; 2],
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
    signing_predecessor_retirement_sent: [bool; 2],
    signing_retirement_requested: [bool; 2],
    signing_retirement_sent: [bool; 2],
    signing_prepared: [bool; 2],
    signing_setup: [bool; 2],
    signing_serve: [bool; 2],
    writer_read_sent: [bool; 2],
    acquire_armed: [bool; 2],
    acquire_final: [bool; 2],
    v3_audit_sent: [bool; 2],
    v3_admit_final: [bool; 2],
    v3_admit_arm: [bool; 2],
    v3_admit_read: [bool; 2],
    return_read: [bool; 2],
    return_exact: [bool; 2],
    sign_read: [bool; 2],
    sign_exact: [bool; 2],
    financial_setup: [bool; 2],
    wallet_prepare: [bool; 2],
    wallet_observe: [bool; 2],
    activate_final: [bool; 2],
    activate_arm: [bool; 2],
    activate_read: [bool; 2],
}
impl Driver {
    pub(super) fn spawn(
        endpoint: CoordinatorFinancialEndpointV1,
        terminal: CoordinatorHostTerminalEndpointV1,
    ) -> Result<Self> {
        // At most twenty-six one-use commands per original role. No retries.
        let (input, receive) = mpsc::sync_channel(COMMAND_SLOTS);
        // Finite protocol events only, including two dispositions and finish.
        let (send, outcome) = mpsc::sync_channel(SECURITY_SLOTS);
        let (host_input, host_receive) = mpsc::sync_channel(1);
        let (host_send, host_output) = mpsc::sync_channel(HOST_OUTPUT_SLOTS);
        let (host_status_send, host_status) = mpsc::sync_channel(HOST_STATUS_SLOTS);
        let revoked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&revoked);
        let normal_finished = Arc::new(AtomicBool::new(false));
        let normal_flag = Arc::clone(&normal_finished);
        let worker = thread::Builder::new()
            .name("coordinator-source-entry".into())
            .spawn(move || {
                drive(
                    endpoint,
                    receive,
                    send,
                    flag,
                    normal_flag,
                    terminal,
                    host_receive,
                    host_send,
                    host_status_send,
                )
            })?;
        Ok(Self {
            normal_finish_sent: false,
            normal_finished,
            input,
            outcome,
            revoked,
            host_input,
            host_output,
            host_status,
            host_pending: None,
            host_last: 0,
            worker: Some(worker),
            v3_begun: [false; 2],
            v3_entry_sent: [false; 2],
            v3_pair_sent: [false; 2],
            v3_receive_sent: [false; 2],
            v3_prepare_read_sent: [false; 2],
            v3_owner_selected: [false; 2],
            v3_redisclose_sent: [false; 2],
            v3_redisclosure_read_sent: [false; 2],
            v3_manifest_sent: [false; 2],
            v3_enrollment_sent: [false; 2],
            begun: [false; 2],
            entry_sent: [false; 2],
            read_sent: [false; 2],
            history_prepared: [false; 2],
            history_setup: [false; 2],
            history_serve: [false; 2],
            completed_pair_prepared: false,
            completed_pair_setup: false,
            completed_pair_serve: false,
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
            signing_predecessor_retirement_sent: [false; 2],
            signing_retirement_requested: [false; 2],
            signing_retirement_sent: [false; 2],
            signing_prepared: [false; 2],
            signing_setup: [false; 2],
            signing_serve: [false; 2],
            writer_read_sent: [false; 2],
            acquire_armed: [false; 2],
            acquire_final: [false; 2],
            v3_audit_sent: [false; 2],
            v3_admit_final: [false; 2],
            v3_admit_arm: [false; 2],
            v3_admit_read: [false; 2],
            return_read: [false; 2],
            return_exact: [false; 2],
            sign_read: [false; 2],
            sign_exact: [false; 2],
            financial_setup: [false; 2],
            wallet_prepare: [false; 2],
            wallet_observe: [false; 2],
            activate_final: [false; 2],
            activate_arm: [false; 2],
            activate_read: [false; 2],
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

    pub(super) fn begin_v3(
        &mut self,
        role: Role,
        selection: SignerV3SourceEntrySelectionV1,
        deadline: Instant,
    ) -> Result<()> {
        if self.begun[index(role)]
            || !claim_once(
                &mut self.v3_begun,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("V3 initial source entry consumed or out of order"));
        }
        self.queue(Command::BeginV3(role, selection, deadline))
    }
    pub(super) fn send_v3_entry(
        &mut self,
        role: Role,
        outbound: SignerV3SourceEntryOutboundV1,
    ) -> Result<()> {
        if !self.v3_begun[index(role)]
            || self.begun[index(role)]
            || !claim_once(
                &mut self.v3_entry_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "V3 initial source entry outbound consumed or out of order",
            ));
        }
        // This genuine V3 outbound owns its own protected input. No legacy
        // source-entry capability or plaintext adapter is accepted here.
        self.queue(Command::V3Entry(outbound))
    }
    pub(super) fn send_v3_enrollment(
        &mut self,
        role: Role,
        outbound: SignerV3EnrollmentOutboundV1,
    ) -> Result<()> {
        if !self.v3_pair_sent[index(role)]
            || !claim_once(
                &mut self.v3_enrollment_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("fresh enrollment outbound consumed or restricted"));
        }
        // Ordering is bookkeeping only; Origin authenticates actual predecessor and same Core.
        self.queue(Command::V3Enrollment(outbound))
    }
    pub(super) fn send_v3_manifest(
        &mut self,
        role: Role,
        outbound: SignerV3ManifestOutboundV1,
    ) -> Result<()> {
        if !self.v3_enrollment_sent[index(role)]
            || !claim_once(
                &mut self.v3_manifest_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("fresh manifest outbound consumed or restricted"));
        }
        // Ordering is bookkeeping only; Origin authenticates actual predecessor and same Core.
        self.queue(Command::V3Manifest(outbound))
    }
    pub(super) fn send_v3_redisclosure_read(
        &mut self,
        role: Role,
        outbound: SignerV3RedisclosureReadOutboundV1,
    ) -> Result<()> {
        if !self.v3_manifest_sent[index(role)]
            || !claim_once(
                &mut self.v3_redisclosure_read_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "redisclosure_read outbound consumed or restricted",
            ));
        }
        // Bookkeeping only: Origin authenticates actual source/predecessor and same Core.
        self.queue(Command::V3RedisclosureRead(outbound))
    }
    pub(super) fn send_v3_redisclose(
        &mut self,
        role: Role,
        outbound: SignerV3RediscloseOutboundV1,
    ) -> Result<()> {
        if !self.v3_redisclosure_read_sent[index(role)]
            || !claim_once(
                &mut self.v3_redisclose_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("redisclose outbound consumed or restricted"));
        }
        // Bookkeeping only: Origin authenticates actual source/predecessor and same Core.
        self.queue(Command::V3Redisclose(outbound))
    }
    pub(super) fn select_v3_owner_setup(&mut self, role: Role, json: String) -> Result<()> {
        wholepact_financial_coordinator_origin::SignerV3OwnerSetupSelectionV1::parse_json(&json)?;
        if !self.v3_redisclose_sent[index(role)]
            || !claim_once(
                &mut self.v3_owner_selected,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("owner selection consumed or restricted"));
        }
        // Ordinary bytes only. Endpoint binds actual completed source/export and fresh selection challenge.
        self.queue(Command::V3OwnerSetup(role, json))
    }
    pub(super) fn send_v3_prepare_read(
        &mut self,
        role: Role,
        outbound: SignerV3PrepareReadOutboundV1,
    ) -> Result<()> {
        if !self.v3_owner_selected[index(role)]
            || !claim_once(
                &mut self.v3_prepare_read_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("delivery outbound consumed or restricted"));
        }
        self.queue(Command::V3PrepareRead(outbound))
    }
    pub(super) fn send_v3_receive(
        &mut self,
        role: Role,
        outbound: SignerV3ReceiveOutboundV1,
    ) -> Result<()> {
        if !self.v3_prepare_read_sent[index(role)]
            || !claim_once(
                &mut self.v3_receive_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("delivery outbound consumed or restricted"));
        }
        self.queue(Command::V3Receive(outbound))
    }
    pub(super) fn send_v3_pair(
        &mut self,
        role: Role,
        outbound: SignerV3PairOutboundV1,
    ) -> Result<()> {
        if !self.v3_entry_sent[index(role)]
            || !claim_once(
                &mut self.v3_pair_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("V3 Pair outbound consumed or restricted"));
        }
        // Bookkeeping is not pairing authority. Only the original endpoint
        // checks the genuine outbound's same-source and same-Core binding.
        self.queue(Command::V3Pair(outbound))
    }
    pub(super) fn select_financial_setup(
        &mut self,
        role: Role,
        writer: String,
        wallet: String,
    ) -> Result<()> {
        if !self.v3_audit_sent[index(role)]
            || !claim_once(
                &mut self.financial_setup,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("financial setup repeated or restricted"));
        }
        self.queue(Command::FinancialSetup(role, writer, wallet))
    }
    pub(super) fn begin(&mut self, role: Role, original_prequeue_ceiling: Instant) -> Result<()> {
        // Queue ordering is necessary, not proof of Opened. The endpoint
        // independently requires the actual authenticated V3 predecessor state.
        if !self.financial_setup[index(role)]
            || !claim_once(&mut self.begun, role, self.revoked.load(Ordering::Acquire))
        {
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
        &mut self,
        role: Role,
        inputs: FinancialHistoryInputsV1,
        ceiling: Instant,
    ) -> Result<()> {
        if !self.entry_sent[index(role)]
            || !claim_once(
                &mut self.history_prepared,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("initial History Setup preparation consumed"));
        }
        self.queue(Command::PrepareHistory(role, inputs, ceiling))
    }
    pub(super) fn send_history_setup(
        &mut self,
        role: Role,
        outbound: FinancialHistorySetupOutboundV1,
    ) -> Result<()> {
        if !self.history_prepared[index(role)]
            || !claim_once(
                &mut self.history_setup,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("initial History Setup outbound consumed"));
        }
        self.queue(Command::SetupHistory(outbound))
    }
    pub(super) fn send_history_serve(
        &mut self,
        role: Role,
        outbound: FinancialHistoryServeOutboundV1,
    ) -> Result<()> {
        if !self.history_setup[index(role)]
            || !claim_once(
                &mut self.history_serve,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("initial History Serve outbound consumed"));
        }
        self.queue(Command::ServeHistory(outbound))
    }
    pub(super) fn send_history_retirement(
        &mut self,
        role: Role,
        outbound: CoordinatorWitnessRetirementOutboundV1,
    ) -> Result<()> {
        if !self.read_sent[index(role)]
            || !claim_once(
                &mut self.history_retirement_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
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
    pub(super) fn send_signing_predecessor_retirement(
        &mut self,
        role: Role,
        outbound: CoordinatorWitnessRetirementOutboundV1,
    ) -> Result<()> {
        if !self.admit_final[index(role)]
            || !claim_once(
                &mut self.signing_predecessor_retirement_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "Signing predecessor retirement consumed or restricted",
            ));
        }
        self.queue(Command::RetireSigningPredecessor(outbound))
    }
    pub(super) fn send_normal_finish(&mut self, outbound: FinancialNormalFinishOutboundV1) -> Result<()> {
        if self.normal_finish_sent || self.host_pending.is_some() || self.is_revoked() {
            return Err(rejected("normal Finish consumed or transport busy"));
        }
        self.normal_finish_sent = true;
        self.queue(Command::NormalFinish(outbound))
    }
    pub(super) fn finished_normally(&self) -> bool {
        // Private observation is set only after the original endpoint returns
        // its actual all-reaps proof; never a setter or financial admission.
        self.normal_finished.load(Ordering::Acquire)
    }
    pub(super) fn prepare_completed_pair(&mut self, inputs: CompletedPairInputsV1, deadline: Instant) -> Result<()> {
        if self.completed_pair_prepared || self.revoked.load(Ordering::Acquire) {
            return Err(rejected("CompletedPair preparation consumed or restricted"));
        }
        self.completed_pair_prepared = true;
        self.queue(Command::PrepareCompletedPair(inputs, deadline))
    }
    pub(super) fn send_completed_pair_setup(&mut self, outbound: FinancialCompletedPairSetupOutboundV1) -> Result<()> {
        if !self.completed_pair_prepared || self.completed_pair_setup || self.revoked.load(Ordering::Acquire) {
            return Err(rejected("CompletedPair Setup consumed or restricted"));
        }
        self.completed_pair_setup = true;
        self.queue(Command::SetupCompletedPair(outbound))
    }
    pub(super) fn send_completed_pair_serve(&mut self, outbound: FinancialCompletedPairServeOutboundV1) -> Result<()> {
        if !self.completed_pair_setup || self.completed_pair_serve || self.revoked.load(Ordering::Acquire) {
            return Err(rejected("CompletedPair Serve consumed or restricted"));
        }
        self.completed_pair_serve = true;
        self.queue(Command::ServeCompletedPair(outbound))
    }
    pub(super) fn begin_signing_retirement(&mut self, role: Role) -> Result<()> {
        if !self.sign_exact[index(role)] || !claim_once(&mut self.signing_retirement_requested,
            role, self.revoked.load(Ordering::Acquire)) {
            self.revoke();
            return Err(rejected("Signing retirement request consumed or restricted"));
        }
        self.queue(Command::BeginSigningRetirement(role))
    }
    pub(super) fn send_signing_retirement(&mut self, role: Role,
        outbound: CoordinatorWitnessRetirementOutboundV1) -> Result<()> {
        if !self.signing_retirement_requested[index(role)] || !claim_once(
            &mut self.signing_retirement_sent, role, self.revoked.load(Ordering::Acquire)) {
            self.revoke();
            return Err(rejected("Signing retirement native pause consumed or restricted"));
        }
        self.queue(Command::RetireSigning(outbound))
    }
    pub(super) fn prepare_signing(
        &mut self,
        role: Role,
        inputs: FinancialSigningInputsV1,
        ceiling: Instant,
    ) -> Result<()> {
        if !self.signing_predecessor_retirement_sent[index(role)]
            || !claim_once(
                &mut self.signing_prepared,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "Signing original Setup preparation consumed or restricted",
            ));
        }
        self.queue(Command::PrepareSigning(role, inputs, ceiling))
    }
    pub(super) fn send_signing_setup(
        &mut self,
        role: Role,
        outbound: FinancialSigningSetupOutboundV1,
    ) -> Result<()> {
        if !self.signing_prepared[index(role)]
            || !claim_once(
                &mut self.signing_setup,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "send_signing_setup original outbound consumed or restricted",
            ));
        }
        self.queue(Command::SetupSigning(outbound))
    }
    pub(super) fn send_signing_serve(
        &mut self,
        role: Role,
        outbound: FinancialSigningServeOutboundV1,
    ) -> Result<()> {
        if !self.signing_setup[index(role)]
            || !claim_once(
                &mut self.signing_serve,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "send_signing_serve original outbound consumed or restricted",
            ));
        }
        self.queue(Command::ServeSigning(outbound))
    }
    pub(super) fn send_writer_read(
        &mut self,
        role: Role,
        outbound: SignerFinancialWriterReadOutboundV1,
    ) -> Result<()> {
        if !self.signing_serve[index(role)]
            || !claim_once(
                &mut self.writer_read_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "send_writer_read original outbound consumed or restricted",
            ));
        }
        self.queue(Command::WriterRead(outbound))
    }
    pub(super) fn send_return_read(
        &mut self,
        role: Role,
        outbound: SignerReturnReadOutboundV1,
    ) -> Result<()> {
        // Queue bookkeeping cannot establish actual Prepared or Finished custody.
        if !self.sign_exact[index(role)]
            || !claim_once(
                &mut self.return_read,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Return outbound consumed or restricted"));
        }
        self.queue(Command::ReturnRead(outbound))
    }
    pub(super) fn send_return_exact(
        &mut self,
        role: Role,
        outbound: SignerReturnExactOutboundV1,
    ) -> Result<()> {
        // Queue bookkeeping cannot establish actual Prepared or Finished custody.
        if !self.return_read[index(role)]
            || !claim_once(
                &mut self.return_exact,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Return outbound consumed or restricted"));
        }
        self.queue(Command::ReturnExact(outbound))
    }
    pub(super) fn send_sign_read(
        &mut self,
        role: Role,
        outbound: SignerSignReadOutboundV1,
    ) -> Result<()> {
        // Only queue bookkeeping; genuine Origin custody proves actual predecessor.
        if !self.wallet_observe[index(role)]
            || !claim_once(
                &mut self.sign_read,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Sign outbound consumed or restricted"));
        }
        self.queue(Command::SignRead(outbound))
    }
    pub(super) fn send_sign_exact(
        &mut self,
        role: Role,
        outbound: SignerSignExactOutboundV1,
    ) -> Result<()> {
        // Only queue bookkeeping; genuine Origin custody proves actual predecessor.
        if !self.sign_read[index(role)]
            || !claim_once(
                &mut self.sign_exact,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Sign outbound consumed or restricted"));
        }
        self.queue(Command::SignExact(outbound))
    }
    pub(super) fn send_wallet_prepare(
        &mut self,
        role: Role,
        outbound: SignerWalletPrepareOutboundV1,
    ) -> Result<()> {
        // Bookkeeping is not success: Origin checks genuine retained predecessor custody.
        if !self.activate_final[index(role)]
            || !claim_once(
                &mut self.wallet_prepare,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("wallet outbound consumed or restricted"));
        }
        self.queue(Command::WalletPrepare(outbound))
    }
    pub(super) fn send_wallet_observe(
        &mut self,
        role: Role,
        outbound: SignerWalletObserveOutboundV1,
    ) -> Result<()> {
        // Bookkeeping is not success: Origin checks genuine retained predecessor custody.
        if !self.wallet_prepare[index(role)]
            || !claim_once(
                &mut self.wallet_observe,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("wallet outbound consumed or restricted"));
        }
        self.queue(Command::WalletObserve(outbound))
    }
    pub(super) fn send_activate_read(
        &mut self,
        role: Role,
        outbound: SignerActivateReadOutboundV1,
    ) -> Result<()> {
        if !self.acquire_final[index(role)]
            || !claim_once(
                &mut self.activate_read,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Activate outbound consumed or restricted"));
        }
        self.queue(Command::ActivateRead(outbound))
    }
    pub(super) fn send_activate_arm(
        &mut self,
        role: Role,
        outbound: SignerActivateArmOutboundV1,
    ) -> Result<()> {
        if !self.activate_read[index(role)]
            || !claim_once(
                &mut self.activate_arm,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Activate outbound consumed or restricted"));
        }
        self.queue(Command::ActivateArm(outbound))
    }
    pub(super) fn send_activate_final(
        &mut self,
        role: Role,
        outbound: SignerActivateFinalOutboundV1,
    ) -> Result<()> {
        if !self.activate_arm[index(role)]
            || !claim_once(
                &mut self.activate_final,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Activate outbound consumed or restricted"));
        }
        self.queue(Command::ActivateFinal(outbound))
    }
    pub(super) fn send_v3_admit_read(
        &mut self,
        role: Role,
        outbound: SignerV3AdmitReadOutboundV1,
    ) -> Result<()> {
        if !self.v3_receive_sent[index(role)]
            || !claim_once(
                &mut self.v3_admit_read,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("V3 admission outbound consumed or restricted"));
        }
        self.queue(Command::V3AdmitRead(outbound))
    }
    pub(super) fn send_v3_admit_arm(
        &mut self,
        role: Role,
        outbound: SignerV3AdmitArmOutboundV1,
    ) -> Result<()> {
        if !self.v3_admit_read[index(role)]
            || !claim_once(
                &mut self.v3_admit_arm,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("V3 admission outbound consumed or restricted"));
        }
        self.queue(Command::V3AdmitArm(outbound))
    }
    pub(super) fn send_v3_admit_final(
        &mut self,
        role: Role,
        outbound: SignerV3AdmitFinalOutboundV1,
    ) -> Result<()> {
        if !self.v3_admit_arm[index(role)]
            || !claim_once(
                &mut self.v3_admit_final,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("V3 admission outbound consumed or restricted"));
        }
        self.queue(Command::V3AdmitFinal(outbound))
    }
    pub(super) fn send_v3_audit(
        &mut self,
        role: Role,
        outbound: SignerV3AuditOutboundV1,
    ) -> Result<()> {
        if !self.v3_admit_final[index(role)]
            || !claim_once(
                &mut self.v3_audit_sent,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected("Audit outbound consumed or restricted"));
        }
        self.queue(Command::V3Audit(outbound))
    }
    pub(super) fn send_acquire_arm(
        &mut self,
        role: Role,
        outbound: SignerAcquireArmOutboundV1,
    ) -> Result<()> {
        if !self.writer_read_sent[index(role)]
            || !claim_once(
                &mut self.acquire_armed,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "send_acquire_arm original outbound consumed or restricted",
            ));
        }
        self.queue(Command::ArmAcquire(outbound))
    }
    pub(super) fn send_acquire_final(
        &mut self,
        role: Role,
        outbound: SignerAcquireFinalOutboundV1,
    ) -> Result<()> {
        if !self.acquire_armed[index(role)]
            || !claim_once(
                &mut self.acquire_final,
                role,
                self.revoked.load(Ordering::Acquire),
            )
        {
            self.revoke();
            return Err(rejected(
                "send_acquire_final original outbound consumed or restricted",
            ));
        }
        self.queue(Command::FinalAcquire(outbound))
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
    pub(super) fn join(&mut self) -> Result<bool> {
        if !self.finished_normally() { self.revoke(); }
        self.worker
            .take()
            .ok_or_else(|| rejected("source-entry driver already joined"))?
            .join()
            .map_err(|_| rejected("source-entry driver panicked"))?
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        if !self.finished_normally() { self.revoke(); }
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
    normal_finished: Arc<AtomicBool>,
    terminal: CoordinatorHostTerminalEndpointV1,
    host_input: mpsc::Receiver<HostLine>,
    host_output: mpsc::SyncSender<Zeroizing<Vec<u8>>>,
    host_status: mpsc::SyncSender<HostStatus>,
) -> Result<bool> {
    struct RevokeOnExit { revoked: Arc<AtomicBool>, normal_proven: bool }
    impl Drop for RevokeOnExit {
        fn drop(&mut self) {
            if !self.normal_proven { self.revoked.store(true, Ordering::Release); }
        }
    }
    let mut on_exit = RevokeOnExit { revoked: Arc::clone(&revoked), normal_proven: false };
    let session = endpoint.session_deadline();
    let mut cancel_sent = false;
    let mut cleanup = None;
    let mut signing_disposed = [false; 2];
    let mut completed_pair_disposed = false;
    let mut completed_pair_close_sent = false;
    let mut signing_close_sent = [false; 2];
    let mut admission_retained = [false; 2];
    let mut predecessor_retired = [false; 2];
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
    let work = (|| -> Result<Option<FinancialNormalFinishOutboundV1>> {
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
                    Command::BeginV3(role, selection, deadline) => record_send_progress(
                        endpoint.try_begin_v3_source_entry(role, selection, deadline)?,
                        &revoked,
                    ),
                    Command::V3Enrollment(outbound) => {
                        record_send_progress(endpoint.try_send_v3_enrollment(outbound)?, &revoked)
                    }
                    Command::V3Manifest(outbound) => {
                        record_send_progress(endpoint.try_send_v3_manifest(outbound)?, &revoked)
                    }
                    Command::V3RedisclosureRead(outbound) => record_send_progress(
                        endpoint.try_send_v3_redisclosure_read(outbound)?,
                        &revoked,
                    ),
                    Command::V3Redisclose(outbound) => {
                        record_send_progress(endpoint.try_send_v3_redisclose(outbound)?, &revoked)
                    }
                    Command::V3OwnerSetup(role, json) => record_send_progress(
                        endpoint.try_select_v3_owner_setup(role, json)?,
                        &revoked,
                    ),
                    Command::V3PrepareRead(outbound) => {
                        record_send_progress(endpoint.try_send_v3_prepare_read(outbound)?, &revoked)
                    }
                    Command::V3Receive(outbound) => {
                        record_send_progress(endpoint.try_send_v3_receive(outbound)?, &revoked)
                    }
                    Command::ReturnRead(outbound) => {
                        record_send_progress(endpoint.try_send_return_read(outbound)?, &revoked)
                    }
                    Command::ReturnExact(outbound) => {
                        record_send_progress(endpoint.try_send_return_exact(outbound)?, &revoked)
                    }
                    Command::SignRead(outbound) => {
                        record_send_progress(endpoint.try_send_sign_read(outbound)?, &revoked)
                    }
                    Command::SignExact(outbound) => {
                        record_send_progress(endpoint.try_send_sign_exact(outbound)?, &revoked)
                    }
                    Command::WalletPrepare(outbound) => {
                        record_send_progress(endpoint.try_send_wallet_prepare(outbound)?, &revoked)
                    }
                    Command::WalletObserve(outbound) => {
                        record_send_progress(endpoint.try_send_wallet_observe(outbound)?, &revoked)
                    }
                    Command::ActivateRead(outbound) => {
                        record_send_progress(endpoint.try_send_activate_read(outbound)?, &revoked)
                    }
                    Command::ActivateArm(outbound) => {
                        record_send_progress(endpoint.try_send_activate_arm(outbound)?, &revoked)
                    }
                    Command::ActivateFinal(outbound) => {
                        record_send_progress(endpoint.try_send_activate_final(outbound)?, &revoked)
                    }
                    Command::V3AdmitRead(outbound) => {
                        record_send_progress(endpoint.try_send_v3_admit_read(outbound)?, &revoked)
                    }
                    Command::V3AdmitArm(outbound) => {
                        record_send_progress(endpoint.try_send_v3_admit_arm(outbound)?, &revoked)
                    }
                    Command::V3AdmitFinal(outbound) => {
                        record_send_progress(endpoint.try_send_v3_admit_final(outbound)?, &revoked)
                    }
                    Command::V3Audit(outbound) => {
                        record_send_progress(endpoint.try_send_v3_audit(outbound)?, &revoked)
                    }
                    Command::V3Pair(outbound) => {
                        record_send_progress(endpoint.try_send_v3_pair(outbound)?, &revoked)
                    }
                    Command::V3Entry(outbound) => {
                        record_send_progress(endpoint.try_send_v3_source_entry(outbound)?, &revoked)
                    }
                    Command::FinancialSetup(role, writer, wallet) => record_send_progress(
                        endpoint.try_select_financial_setup(role, writer, wallet)?,
                        &revoked,
                    ),
                    Command::Begin(role, ceiling) => record_send_progress(
                        endpoint.try_begin_source_entry(role, ceiling)?,
                        &revoked,
                    ),
                    Command::Entry(outbound) => {
                        record_send_progress(endpoint.try_send_source_entry(outbound)?, &revoked)
                    }
                    Command::Read(outbound) => {
                        record_send_progress(endpoint.try_send_initial_read(outbound)?, &revoked)
                    }
                    Command::PrepareHistory(role, inputs, ceiling) => {
                        if let Some(ticket) =
                            endpoint.try_prepare_history_setup(role, inputs, ceiling)?
                        {
                            output
                                .try_send(Outcome::HistorySetup(role, ticket))
                                .map_err(|_| rejected("History Setup receiver unavailable"))?;
                        } else {
                            revoked.store(true, Ordering::Release);
                        }
                    }
                    Command::SetupHistory(outbound) => {
                        record_send_progress(endpoint.try_send_history_setup(outbound)?, &revoked)
                    }
                    Command::ServeHistory(outbound) => {
                        record_send_progress(endpoint.try_send_history_serve(outbound)?, &revoked)
                    }
                    Command::RetireHistory(_) | Command::RetireSigningPredecessor(_) | Command::RetireSigning(_) => {
                        return Err(rejected("retirement outside its exclusive owner wait"))
                    }
                    Command::BeginContinue(role, ceiling) => record_send_progress(
                        endpoint.try_send_continue_prepare(role, ceiling)?,
                        &revoked,
                    ),
                    Command::ArmContinue(outbound) => {
                        record_send_progress(endpoint.try_send_continue_arm(outbound)?, &revoked)
                    }
                    Command::PrepareWitness(role, inputs, ceiling) => {
                        if let Some(ticket) =
                            endpoint.try_prepare_witness_setup(role, inputs, ceiling)?
                        {
                            output
                                .try_send(Outcome::WitnessSetup(role, ticket))
                                .map_err(|_| rejected("Witness Setup receiver unavailable"))?;
                        } else {
                            revoked.store(true, Ordering::Release);
                        }
                    }
                    Command::SetupWitness(outbound) => {
                        record_send_progress(endpoint.try_send_witness_setup(outbound)?, &revoked)
                    }
                    Command::ArmWitness(outbound) => {
                        record_send_progress(endpoint.try_send_witness_arm(outbound)?, &revoked)
                    }
                    Command::ArmAdmit(outbound) => {
                        record_send_progress(endpoint.try_send_admit_arm(outbound)?, &revoked)
                    }
                    Command::FinalAdmit(outbound) => {
                        record_send_progress(endpoint.try_send_admit_final(outbound)?, &revoked)
                    }
                    Command::NormalFinish(outbound) => {
                        // Leave all ordinary live-actor polling before expected
                        // exits. Only the original typed close owner may reap.
                        return Ok(Some(outbound));
                    }
                    Command::PrepareCompletedPair(inputs, deadline) => {
                        let ticket = endpoint.prepare_completed_pair_setup(inputs, deadline)?;
                        output.try_send(Outcome::CompletedPairSetup(ticket))
                            .map_err(|_| rejected("CompletedPair Setup receiver unavailable"))?;
                    }
                    Command::SetupCompletedPair(outbound) => {
                        record_send_progress(endpoint.try_send_completed_pair_setup(outbound)?, &revoked);
                    }
                    Command::ServeCompletedPair(outbound) => {
                        record_send_progress(endpoint.try_send_completed_pair_serve(outbound)?, &revoked);
                    }
                    Command::BeginSigningRetirement(role) => {
                        // Origin proves the actual signed result and original current
                        // service. This per-role boundary intentionally does not wait
                        // for the other signer, whose shared installation is locked.
                        let ticket = endpoint.prepare_signing_retirement(role)?;
                        retire_signing_exclusively(&mut endpoint, &input, &output, &revoked, ticket)?;
                        signing_disposed[index(role)] = true;
                        signing_close_sent[index(role)] = true;
                    }
                    Command::PrepareSigning(role, inputs, ceiling) => {
                        if let Some(ticket) =
                            endpoint.try_prepare_signing_setup(role, inputs, ceiling)?
                        {
                            output
                                .try_send(Outcome::SigningSetup(role, ticket))
                                .map_err(|_| rejected("Signing Setup receiver unavailable"))?;
                        } else {
                            revoked.store(true, Ordering::Release);
                        }
                    }
                    Command::SetupSigning(outbound) => {
                        record_send_progress(endpoint.try_send_signing_setup(outbound)?, &revoked)
                    }
                    Command::ServeSigning(outbound) => {
                        record_send_progress(endpoint.try_send_signing_serve(outbound)?, &revoked)
                    }
                    Command::WriterRead(outbound) => record_send_progress(
                        endpoint.try_send_writer_read_final(outbound)?,
                        &revoked,
                    ),
                    Command::ArmAcquire(outbound) => {
                        record_send_progress(endpoint.try_send_acquire_arm(outbound)?, &revoked)
                    }
                    Command::FinalAcquire(outbound) => {
                        record_send_progress(endpoint.try_send_acquire_final(outbound)?, &revoked)
                    }
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
                if let CoordinatorFinancialEventV1::AwaitingNextRead { role, .. } = &event {
                    admission_retained[index(*role)] = true;
                }
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
                let Some(event) = endpoint.try_receive_history()? else {
                    break;
                };
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
                        if !cancel_sent
                            && !revoked.load(Ordering::Acquire)
                            && history_retained[index(*role)] =>
                    {
                        Some(*role)
                    }
                    _ => None,
                };
                output
                    .try_send(Outcome::History(event))
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
            // Both authenticated S completion and actual W disposal are necessary.
            // Origin additionally verifies exact matching committed heads and the
            // original fixed-purpose retirement custody, never an ordinary DTO.
            for role in [Role::Signer1, Role::Signer2] {
                let i = index(role);
                if may_retire_signing_predecessor(
                    cancel_sent,
                    revoked.load(Ordering::Acquire),
                    admission_retained[i],
                    witness_disposed[i],
                    predecessor_retired[i],
                ) {
                    let ticket = endpoint.prepare_witness_retirement(role)?;
                    retire_signing_predecessor_exclusively(
                        &mut endpoint,
                        &input,
                        &output,
                        &revoked,
                        ticket,
                    )?;
                    predecessor_retired[i] = true;
                    witness_close_sent[i] = true;
                }
            }
            // Genuine Signing tickets/Serving remain opaque through this driver.
            // The UI alone admits them; cleanup grammar remains observable after R.
            for _ in 0..16 {
                let Some(event) = endpoint.try_receive_signing()? else {
                    break;
                };
                let observation = match event {
                    CoordinatorFinancialSigningEventV1::Disposed(role) => {
                        signing_disposed[index(role)] = true;
                        Outcome::SigningDisposed(role)
                    }
                    CoordinatorFinancialSigningEventV1::PurposeClosed(role) => {
                        Outcome::SigningClosed(role)
                    }
                    CoordinatorFinancialSigningEventV1::PreparationFailed(role)
                    | CoordinatorFinancialSigningEventV1::ServiceFailed(role)
                    | CoordinatorFinancialSigningEventV1::Restricted(role) => {
                        revoked.store(true, Ordering::Release);
                        Outcome::SigningFailed(role)
                    }
                    event @ (CoordinatorFinancialSigningEventV1::Display(_)
                    | CoordinatorFinancialSigningEventV1::Serving(_)) => Outcome::Signing(event),
                };
                output
                    .try_send(observation)
                    .map_err(|_| rejected("Signing cleanup receiver unavailable"))?;
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
            for _ in 0..16 {
                let Some(event) = endpoint.try_receive_completed_pair()? else { break; };
                match &event {
                    CoordinatorCompletedPairEventV1::Disposed => completed_pair_disposed = true,
                    CoordinatorCompletedPairEventV1::PreparationFailed
                    | CoordinatorCompletedPairEventV1::ServiceFailed
                    | CoordinatorCompletedPairEventV1::Restricted => revoked.store(true, Ordering::Release),
                    _ => {}
                }
                output.try_send(Outcome::CompletedPair(event))
                    .map_err(|_| rejected("CompletedPair outcome receiver unavailable"))?;
            }
            if cancel_sent && completed_pair_disposed && !completed_pair_close_sent {
                endpoint.close_completed_pair_purpose()?;
                completed_pair_close_sent = true;
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
        Ok(None)
    })();
    let work = match work {
        Ok(Some(outbound)) => {
            // No queued positive command or unconsumed one-use outbound may
            // survive into normal completion and revoke only after its proof.
            match input.try_recv() {
                Err(mpsc::TryRecvError::Empty) => {},
                _ => return Err(rejected("normal close has queued or lost security input")),
            }
            let deadline = outbound.original_cleanup_deadline();
            let terminal = host.take_for_normal(&host_input, &host_output, &revoked, deadline)?;
            // The original endpoint owns this exact master across Pair disposal,
            // H/S normal ACKs, all owned reaps and the final R-rejecting CAS.
            let completion = endpoint.finish_normal(outbound, terminal)?;
            completion.check_completed()?;
            normal_finished.store(true, Ordering::Release);
            output.try_send(Outcome::NormalFinished(completion))
                .map_err(|_| rejected("normal completion proof receiver unavailable"))?;
            on_exit.normal_proven = true;
            // Any remaining transcript was privately drained by Origin. Channel
            // EOF is not used as evidence; only the proof above is success.
            drop(host_input); drop(host); drop(host_output); drop(host_status); drop(input);
            return Ok(true);
        }
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
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
        Ok(false) // Clean cancellation is never normal financial completion.
    } else {
        Err(rejected("source-entry driver or disposal failed"))
    }
}

/// Actual fixed History retirement only. No ordinary queue, PTY, or positive
/// source observer runs while the original W is expected to exit. The private
/// endpoint completion record, never a UI acknowledgment, proves resume.
fn retire_history_exclusively(
    endpoint: &mut CoordinatorFinancialEndpointV1,
    input: &mpsc::Receiver<Command>,
    output: &mpsc::SyncSender<Outcome>,
    revoked: &AtomicBool,
    ticket: CoordinatorWitnessRetirementTicketV1,
) -> Result<()> {
    let role = ticket.role();
    let original_cutoff = ticket.deadline();
    output
        .try_send(Outcome::HistoryRetirement(ticket))
        .map_err(|_| rejected("History retirement native receiver unavailable"))?;
    let outbound = loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected(
                "History retirement interrupted before native pause",
            ));
        }
        // No reap can start until this sole owner receives the nominal pause
        // outbound. Ordinary actor checks are still valid before that point.
        endpoint.check_original_tree_alive()?;
        match input.try_recv() {
            Ok(Command::RetireHistory(outbound)) => break outbound,
            Ok(_) => {
                return Err(rejected(
                    "unexpected positive command during History retirement",
                ))
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(rejected("History retirement native owner ended"))
            }
            Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    };
    let completion = endpoint.retire_witness(outbound)?;
    if completion.role() != role {
        return Err(rejected("History retirement actual role changed"));
    }
    output
        .try_send(Outcome::HistoryRetired(completion))
        .map_err(|_| rejected("History retirement completion receiver unavailable"))?;
    loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected(
                "History retirement interrupted before native resume",
            ));
        }
        if endpoint.finish_retirement_resume()? {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    output
        .try_send(Outcome::HistoryResumed(role))
        .map_err(|_| rejected("History resume receiver unavailable"))?;
    Ok(())
}

// Fixed-purpose append retirement uses the same exclusive native pause/reap/resume.
fn retire_signing_predecessor_exclusively(
    endpoint: &mut CoordinatorFinancialEndpointV1,
    input: &mpsc::Receiver<Command>,
    output: &mpsc::SyncSender<Outcome>,
    revoked: &AtomicBool,
    ticket: CoordinatorWitnessRetirementTicketV1,
) -> Result<()> {
    let role = ticket.role();
    let original_cutoff = ticket.deadline();
    output
        .try_send(Outcome::SigningPredecessorRetirement(ticket))
        .map_err(|_| rejected("Signing predecessor retirement native receiver unavailable"))?;
    let outbound = loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected(
                "Signing predecessor retirement interrupted before native pause",
            ));
        }
        // No reap can start until this sole owner receives the nominal pause
        // outbound. Ordinary actor checks are still valid before that point.
        endpoint.check_original_tree_alive()?;
        match input.try_recv() {
            Ok(Command::RetireSigningPredecessor(outbound)) => break outbound,
            Ok(_) => {
                return Err(rejected(
                    "unexpected positive command during Signing predecessor retirement",
                ))
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(rejected(
                    "Signing predecessor retirement native owner ended",
                ))
            }
            Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    };
    let completion = endpoint.retire_witness(outbound)?;
    if completion.role() != role {
        return Err(rejected(
            "Signing predecessor retirement actual role changed",
        ));
    }
    output
        .try_send(Outcome::SigningPredecessorRetired(completion))
        .map_err(|_| rejected("Signing predecessor retirement completion receiver unavailable"))?;
    loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected(
                "Signing predecessor retirement interrupted before native resume",
            ));
        }
        if endpoint.finish_retirement_resume()? {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    output
        .try_send(Outcome::SigningPredecessorResumed(role))
        .map_err(|_| rejected("Signing predecessor resume receiver unavailable"))?;
    Ok(())
}

// Actual post-Sign retirement, distinct from predecessor append retirement.
fn retire_signing_exclusively(
    endpoint: &mut CoordinatorFinancialEndpointV1,
    input: &mpsc::Receiver<Command>,
    output: &mpsc::SyncSender<Outcome>,
    revoked: &AtomicBool,
    ticket: CoordinatorWitnessRetirementTicketV1,
) -> Result<()> {
    let role = ticket.role();
    let original_cutoff = ticket.deadline();
    output
        .try_send(Outcome::SigningRetirement(ticket))
        .map_err(|_| rejected("Signing service retirement native receiver unavailable"))?;
    let outbound = loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected(
                "Signing service retirement interrupted before native pause",
            ));
        }
        // No reap can start until this sole owner receives the nominal pause
        // outbound. Ordinary actor checks are still valid before that point.
        endpoint.check_original_tree_alive()?;
        match input.try_recv() {
            Ok(Command::RetireSigning(outbound)) => break outbound,
            Ok(_) => {
                return Err(rejected(
                    "unexpected positive command during Signing service retirement",
                ))
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(rejected(
                    "Signing service retirement native owner ended",
                ))
            }
            Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    };
    let completion = endpoint.retire_witness(outbound)?;
    if completion.role() != role {
        return Err(rejected(
            "Signing service retirement actual role changed",
        ));
    }
    output
        .try_send(Outcome::SigningRetired(completion))
        .map_err(|_| rejected("Signing service retirement completion receiver unavailable"))?;
    loop {
        if revoked.load(Ordering::Acquire) || Instant::now() >= original_cutoff {
            return Err(rejected(
                "Signing service retirement interrupted before native resume",
            ));
        }
        if endpoint.finish_retirement_resume()? {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let custody = endpoint.signed_result_custody(role)?;
    custody.check_current()?;
    if custody.role() != role { return Err(rejected("Signing retired custody role changed")); }
    output
        .try_send(Outcome::SigningResumed(custody))
        .map_err(|_| rejected("Signing service resume receiver unavailable"))?;
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
    fn take_for_normal(&mut self, input: &mpsc::Receiver<HostLine>,
        output: &mpsc::SyncSender<Zeroizing<Vec<u8>>>, revoked: &AtomicBool,
        deadline: Instant) -> Result<CoordinatorHostTerminalEndpointV1> {
        if self.pending_line.is_some() || self.closed_reported || revoked.load(Ordering::Acquire) {
            return Err(rejected("normal close has pending or closed Host transport"));
        }
        match input.try_recv() {
            Err(mpsc::TryRecvError::Empty) => {},
            _ => return Err(rejected("normal close has queued or lost Host input")),
        }
        while let Some(chunk) = self.pending_output.take() {
            if revoked.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(rejected("normal close output drain expired or restricted"));
            }
            match output.try_send(chunk) {
                Ok(()) => {},
                Err(mpsc::TrySendError::Full(chunk)) => {
                    self.pending_output = Some(chunk);
                    thread::sleep(Duration::from_millis(1));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return Err(rejected("normal close output receiver ended")),
            }
        }
        if revoked.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(rejected("normal close handoff expired or restricted"));
        }
        self.terminal.take().ok_or_else(|| rejected("normal close original PTY absent"))
    }
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
fn may_retire_signing_predecessor(
    cancel_sent: bool,
    revoked: bool,
    admitted: bool,
    disposed: bool,
    retired: bool,
) -> bool {
    !cancel_sent && !revoked && admitted && disposed && !retired
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
    fn v3_pair_bookkeeping_is_independent_and_one_use() {
        let entry = [true, false];
        let mut pair = [false; 2];
        assert!(entry[index(Role::Signer1)]);
        assert!(!claim_once(&mut pair, Role::Signer1, true));
        assert!(!pair[index(Role::Signer1)]);
        assert!(claim_once(&mut pair, Role::Signer1, false));
        assert!(!claim_once(&mut pair, Role::Signer1, false));
        assert!(!pair[index(Role::Signer2)]);
        assert_eq!(entry, [true, false]);
    }
    #[test]
    fn v3_initial_entry_bookkeeping_is_distinct_one_use_and_restriction_sensitive() {
        let mut v3_begin = [false; 2];
        let mut v3_entry = [false; 2];
        let mut financial_begin = [false; 2];
        assert!(claim_once(&mut v3_begin, Role::Signer1, false));
        assert_eq!(v3_entry, [false; 2]);
        assert_eq!(financial_begin, [false; 2]);
        assert!(!claim_once(&mut v3_begin, Role::Signer1, false));
        assert!(!claim_once(&mut v3_entry, Role::Signer1, true));
        assert!(claim_once(&mut v3_entry, Role::Signer1, false));
        assert!(!claim_once(&mut v3_entry, Role::Signer1, false));
        assert!(claim_once(&mut financial_begin, Role::Signer1, false));
        assert!(!claim_once(&mut financial_begin, Role::Signer1, false));
        assert!(!claim_once(&mut v3_begin, Role::Signer2, true));
    }
    #[test]
    fn signing_predecessor_retirement_requires_both_actual_observations_and_no_restriction() {
        assert!(may_retire_signing_predecessor(
            false, false, true, true, false
        ));
        for (cancel, revoked, admitted, disposed, retired) in [
            (true, false, true, true, false),
            (false, true, true, true, false),
            (false, false, false, true, false),
            (false, false, true, false, false),
            (false, false, true, true, true),
        ] {
            assert!(!may_retire_signing_predecessor(
                cancel, revoked, admitted, disposed, retired
            ));
        }
    }
    #[test]
    fn writer_and_acquire_commands_are_one_use_per_role_and_cannot_rearm_after_revoke() {
        // Pure bookkeeping only: cannot construct any actual Origin capability.
        let mut writer = [false; 2];
        let mut arm = [false; 2];
        let mut final_action = [false; 2];
        for slots in [&mut writer, &mut arm, &mut final_action] {
            assert!(claim_once(slots, Role::Signer1, false));
            assert!(!claim_once(slots, Role::Signer1, false));
            assert!(!claim_once(slots, Role::Signer2, true));
            assert!(!slots[index(Role::Signer2)]);
        }
    }
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

#[cfg(test)]
mod fresh_receipt_driver_tests {
    use super::*;
    #[test]
    fn fresh_purpose_once_bits_are_separate_and_restrictive() {
        let mut enrollment = [false; 2];
        let mut manifest = [false; 2];
        assert!(claim_once(&mut enrollment, Role::Signer1, false));
        assert!(!claim_once(&mut enrollment, Role::Signer1, false));
        assert!(!manifest[0]);
        assert!(!claim_once(&mut manifest, Role::Signer1, true));
        assert!(claim_once(&mut manifest, Role::Signer2, false));
        assert!(!enrollment[1]);
    }
}

#[cfg(test)]
mod redisclosure_driver_tests {
    use super::*;
    #[test]
    fn read_and_export_bookkeeping_remain_distinct_one_use_and_restrictive() {
        let mut read = [false; 2];
        let mut export = [false; 2];
        assert!(claim_once(&mut read, Role::Signer1, false));
        assert!(!export[0]);
        assert!(!claim_once(&mut read, Role::Signer1, false));
        assert!(!claim_once(&mut export, Role::Signer1, true));
        assert!(claim_once(&mut export, Role::Signer2, false));
        assert!(!read[1]);
    }
}

#[cfg(test)]
mod delivery_driver_tests {
    use super::*;
    #[test]
    fn preparation_and_receive_are_distinct_one_use_and_r_sensitive() {
        let mut read = [false; 2];
        let mut receive = [false; 2];
        assert!(claim_once(&mut read, Role::Signer1, false));
        assert!(!receive[0]);
        assert!(!claim_once(&mut read, Role::Signer1, false));
        assert!(!claim_once(&mut receive, Role::Signer1, true));
        assert!(claim_once(&mut receive, Role::Signer2, false));
        assert!(!read[1]);
    }
}

#[cfg(test)]
mod activate_driver_tests {
    use super::*;
    #[test]
    fn activate_read_arm_and_final_are_separate_one_use_and_r_sensitive() {
        let mut read = [false; 2];
        let mut arm = [false; 2];
        let mut final_once = [false; 2];
        assert!(claim_once(&mut read, Role::Signer1, false));
        assert!(!claim_once(&mut read, Role::Signer1, false));
        assert!(!arm[0]);
        assert!(!final_once[0]);
        assert!(claim_once(&mut arm, Role::Signer1, false));
        assert!(!claim_once(&mut final_once, Role::Signer1, true));
        assert!(claim_once(&mut final_once, Role::Signer2, false));
        assert!(!read[1]);
        assert!(!arm[1]);
    }
}

#[cfg(test)]
mod v3_admission_driver_tests {
    use super::*;
    #[test]
    fn v3_admission_read_arm_final_have_distinct_restrictive_once_bits() {
        let mut read = [false; 2];
        let mut arm = [false; 2];
        let mut final_once = [false; 2];
        assert!(claim_once(&mut read, Role::Signer1, false));
        assert!(!claim_once(&mut read, Role::Signer1, false));
        assert!(!arm[0]);
        assert!(!final_once[0]);
        assert!(claim_once(&mut arm, Role::Signer1, false));
        assert!(!claim_once(&mut final_once, Role::Signer1, true));
        assert!(claim_once(&mut final_once, Role::Signer2, false));
        assert!(!read[1]);
        assert!(!arm[1]);
    }
}

#[cfg(test)]
mod v3_audit_driver_tests {
    use super::*;
    #[test]
    fn audit_is_separate_one_use_metadata_never_claims_completion() {
        let mut audit = [false; 2];
        assert!(!claim_once(&mut audit, Role::Signer1, true));
        assert!(claim_once(&mut audit, Role::Signer2, false));
        assert!(!claim_once(&mut audit, Role::Signer2, false));
    }
}

#[cfg(test)]
mod wallet_driver_tests {
    use super::*;
    #[test]
    fn wallet_purposes_are_separate_once_and_revocation_sensitive() {
        let mut prepare = [false; 2];
        let mut observe = [false; 2];
        assert!(claim_once(&mut prepare, Role::Signer1, false));
        assert!(!observe[0]);
        assert!(!claim_once(&mut prepare, Role::Signer1, false));
        assert!(!claim_once(&mut observe, Role::Signer1, true));
        assert!(claim_once(&mut observe, Role::Signer1, false));
        assert!(!claim_once(&mut observe, Role::Signer1, false));
    }
}

#[cfg(test)]
mod sign_driver_tests {
    use super::*;
    #[test]
    fn sign_read_and_exact_are_distinct_once_and_r_sensitive() {
        let mut read = [false; 2];
        let mut exact = [false; 2];
        assert!(claim_once(&mut read, Role::Signer1, false));
        assert!(!exact[0]);
        assert!(!claim_once(&mut read, Role::Signer1, false));
        assert!(!claim_once(&mut exact, Role::Signer1, true));
        assert!(claim_once(&mut exact, Role::Signer1, false));
        assert!(!claim_once(&mut exact, Role::Signer1, false));
    }
}

#[cfg(test)]
mod return_driver_tests {
    use super::*;
    #[test]
    fn return_read_and_exact_are_distinct_once_and_r_sensitive() {
        let mut read = [false; 2];
        let mut exact = [false; 2];
        assert!(claim_once(&mut read, Role::Signer1, false));
        assert!(!exact[0]);
        assert!(!claim_once(&mut read, Role::Signer1, false));
        assert!(!claim_once(&mut exact, Role::Signer1, true));
        assert!(claim_once(&mut exact, Role::Signer1, false));
        assert!(!claim_once(&mut exact, Role::Signer1, false));
    }
}
