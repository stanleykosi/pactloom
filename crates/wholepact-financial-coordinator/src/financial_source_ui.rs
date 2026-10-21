//! Concrete C-only initial V3 Entry and later financial native controller.
//! Initial V3 selection, review and password use distinct nominal Origin tokens.
//! Source opening alone cannot enter the post-V3 financial source route. Genuine opaque offers/tickets, never DTO
//! casts, reach the final visible event tail. HistoryRetained is waiting custody,
//! not disposal or completed product flow. The separately reviewed Continue uses
//! the same retained Core; a saved continuation is not financial admission.
//!
//! C is a trusted transient password surface. Its owned storage is zeroized;
//! stock GUI undo/input/backend/OS/IME temporaries are dropped, not guaranteed
//! overwritten. Neither this controller nor its input leaf clears OS clipboard.
use wholepact_financial_coordinator_origin::{SignerV3ReceiveTicketV1, SignerV3ReceivePresentationV1, SignerV3ReceivedV1, SignerV3PrepareReadTicketV1, SignerV3PrepareReadPresentationV1, SignerV3PreparedV1};
use crate::{
    financial_source_driver::{Driver, HostStatus, Outcome},
    host_line_input::{HostLineInput, HostLineStatus},
    host_output_text::{HostOutputText, OutputState},
    rejected,
    secret_input::{BoundPassword, InputRole, InputStatus, PasswordInput, RequestBinding},
    Result,
};
use eframe::egui;
use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, Instant},
};
use wholepact_financial_coordinator_origin::{
    CoordinatorFinancialEndpointV1, CoordinatorFinancialEventV1 as Event,
    CoordinatorFinancialHistoryEventV1 as HistoryEvent, CoordinatorFinancialNativeV1,
    CoordinatorFinancialWitnessEventV1 as WitnessEvent, CoordinatorWitnessRetiredV1,
    CoordinatorWitnessRetirementTicketV1, DeliveryFailureV1, FinancialContinueReadyTicketV1,
    FinancialContinueReviewTicketV1, FinancialHistoryInputsV1, FinancialHistoryPresentationV1,
    FinancialHistoryReviewTicketV1, FinancialHistoryServingV1, FinancialHistorySetupTicketV1,
    FinancialWitnessArmedV1, FinancialWitnessInputsV1, FinancialWitnessOutcomeV1,
    FinancialWitnessPresentationV1, FinancialWitnessReadyTicketV1, FinancialWitnessReadyV1,
    FinancialWitnessReviewTicketV1, FinancialWitnessSetupTicketV1, FinancialWorkflowStageV1,
    SignerAdmitCommittedV1, SignerAdmitOutcomeV1, SignerAdmitPresentationV1,
    SignerAdmitReadyTicketV1, SignerAdmitReviewTicketV1, SignerContinuationSavedV1,
    SignerContinueOutcomeV1, SignerContinuePresentationV1, SignerContinueRoleV1 as Role,
    SignerFinancialReadTicketV1, SignerSourceEntryOfferV1,
};
use winit::platform::wayland::EventLoopBuilderExtWayland;
use zeroize::{Zeroize, Zeroizing};

use wholepact_financial_coordinator_origin::{
    CoordinatorFinancialSigningEventV1 as SigningEvent, FinancialSigningInputsV1,
    FinancialSigningPresentationV1, FinancialSigningReviewTicketV1, FinancialSigningServingV1,
    FinancialSigningSetupTicketV1, SignerAcquireCommittedV1, SignerAcquireOutcomeV1,
    SignerAcquirePresentationV1, SignerAcquireReadyTicketV1, SignerAcquireReviewTicketV1,
    SignerActivateCommittedV1, SignerActivateOriginalV1, SignerActivateOutcomeV1,
    SignerActivatePresentationV1, SignerActivateReadPresentationV1, SignerActivateReadTicketV1,
    SignerActivateReadyTicketV1, SignerActivateReviewTicketV1,
    SignerFinancialWriterReadPresentationV1, SignerFinancialWriterReadTicketV1,
};

#[derive(Default)]
struct ActivateFlow {
    read: Option<SignerActivateReadTicketV1>,
    read_display: Option<SignerActivateReadPresentationV1>,
    review: Option<SignerActivateReviewTicketV1>,
    display: Option<SignerActivatePresentationV1>,
    ready: Option<SignerActivateReadyTicketV1>,
    ready_digest: Option<String>,
    attempted: bool,
    committed: Option<SignerActivateCommittedV1>,
    outcome: Option<SignerActivateOutcomeV1>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WriterStage {
    #[default]
    SetupNeeded,
    SetupPreparing,
    SetupReview,
    ServicePreparing,
    ServiceReview,
    ServiceStarting,
    ReadReview,
    Reading,
    AcquireReview,
    AcquireArmed,
    Acquiring,
    Acquired,
}
#[derive(Default)]
struct WriterFlow {
    stage: WriterStage,
    read: Option<SignerFinancialWriterReadTicketV1>,
    read_display: Option<SignerFinancialWriterReadPresentationV1>,
    setup: Option<FinancialSigningSetupTicketV1>,
    review: Option<FinancialSigningReviewTicketV1>,
    serving: Option<FinancialSigningServingV1>,
    service_display: Option<FinancialSigningPresentationV1>,
    acquire: Option<SignerAcquireReviewTicketV1>,
    ready: Option<SignerAcquireReadyTicketV1>,
    display: Option<SignerAcquirePresentationV1>,
    ready_digest: Option<String>,
    acquired: Option<SignerAcquireCommittedV1>,
    outcome: Option<SignerAcquireOutcomeV1>,
    attempted: bool,
}

use wholepact_financial_coordinator_origin::{
    SignerV3SourceEntryOfferV1, SignerV3SourceEntryPresentationV1, SignerV3SourceEntrySelectionV1,
};

use wholepact_financial_coordinator_origin::{
    SignerV3EnrollmentCommittedV1, SignerV3EnrollmentPresentationV1, SignerV3EnrollmentTicketV1,
    SignerV3ManifestCommittedV1, SignerV3ManifestPresentationV1, SignerV3ManifestTicketV1,
    SignerV3OwnerSetupSelectionV1, SignerV3PairEndpointV1, SignerV3PairPresentationV1,
    SignerV3PairTicketV1, SignerV3PairedV1, SignerV3RedisclosePresentationV1,
    SignerV3RediscloseTicketV1, SignerV3RedisclosedV1, SignerV3RedisclosurePreparedV1,
    SignerV3RedisclosureReadPresentationV1, SignerV3RedisclosureReadTicketV1,
    SignerV3SourceOpenedV1,
};

const _: () = assert!(matches!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off));
const READ_PURPOSE: &str = "original-history-and-one-local-continue-preparation-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Selecting,
    ActivateReadReview,
    ActivateReading,
    ActivateReview,
    ActivateArmed,
    ActivateReady,
    Activating,
    Activated,
    V3Configuring,
    V3Preparing,
    V3Review,
    V3Confirm,
    V3Password,
    V3Opening,
    V3Held,
    V3PairReview,
    V3Pairing,
    V3Paired,
    V3ReceiveReview,
    V3Receiving,
    V3Received,
    V3PrepareReadReview,
    V3PrepareReading,
    V3Prepared,
    V3OwnerConfiguring,
    V3OwnerSelected,
    V3RediscloseReview,
    V3Redisclosing,
    V3Redisclosed,
    V3RedisclosureReadReview,
    V3RedisclosureReading,
    V3RedisclosurePrepared,
    V3EnrollmentReview,
    V3Enrolling,
    V3Enrolled,
    V3ManifestReview,
    V3Manifesting,
    V3ManifestAccepted,
    Configuring,
    SetupNeeded,
    SetupPreparing,
    SetupReview,
    AdmissionReview,
    RetirementBlocked,
    WriterFlow,
    Preparing,
    EntryReview,
    EntryConfirm,
    Password,
    Opening,
    HistorySetupNeeded,
    HistorySetupPreparing,
    HistorySetupReview,
    HistoryPreparing,
    HistoryReview,
    HistoryStarting,
    ReadReview,
    ReadConfirm,
    Reading,
    HistoryRetiring,
    HistoryReady,
    ContinuePreparing,
    ContinueReview,
    ContinueConfirm,
    ContinueArmed,
    Continuing,
    Waiting,
    Revoked,
    Finished,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    NotStarted,
    Working,
    SourceRetained,
    HistoryRetained,
    ContinueAdmitted,
    AwaitingAdmission,
    AwaitingNextRead,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContinueEffect {
    None,
    Pending,
    Saved,
    KnownNoEffect,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionEffect {
    None,
    Pending,
    Committed,
    KnownNoEffect,
    Uncertain,
}
#[derive(Clone, Copy, Default)]
struct PairedConsent {
    read: [bool; 2],
    acknowledged: [bool; 2],
}
enum Intent {
    ActivateRead,
    ActivateArm,
    ActivateFinal,
    Configure(Role),
    ConfigureV3(Role),
    ReviewV3Pair(Role),
    FinalV3Pair,
    ReviewV3Receive(Role),
    FinalV3Receive,
    ReviewV3PrepareRead(Role),
    FinalV3PrepareRead,
    ConfigureV3Owner(Role),
    SelectV3Owner,
    ReviewV3Redisclose(Role),
    FinalV3Redisclose,
    ReviewV3RedisclosureRead(Role),
    FinalV3RedisclosureRead,
    ReviewV3Enrollment(Role),
    FinalV3Enrollment,
    ReviewV3Manifest(Role),
    FinalV3Manifest,
    BeginV3(Instant),
    ConfirmV3,
    PasswordV3,
    SelectNextV3,
    PrepareSetup(Instant),
    Setup,
    ArmSigner,
    ArmWitness,
    Begin(Role, Instant),
    EntryConfirm,
    EnterPassword,
    PrepareHistory(Instant),
    SetupHistory,
    ServeHistory,
    ReadConfirm,
    Read,
    BeginContinue,
    ContinueConfirm,
    ArmContinue,
    BeginHostLine,
    WriterAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostEntry {
    Idle,
    Editing(u64),
    Writing(u64),
    Closed,
}

/// Source-only actual App composition. Its one endpoint owner outlives the
/// event loop and is joined after eframe returns, never from a native callback.
pub(super) fn run(
    native: CoordinatorFinancialNativeV1,
    mut endpoint: CoordinatorFinancialEndpointV1,
) -> Result<()> {
    let session_deadline = native.session_deadline();
    if session_deadline != endpoint.session_deadline() {
        return Err(rejected("workflow original session mismatch"));
    }
    // One-shot genuine same-Core custody, before any endpoint thread or App.
    // No descriptor/path importer or terminal I/O occurs in the native tail.
    let terminal = endpoint.take_host_terminal()?;
    let driver = Rc::new(RefCell::new(Driver::spawn(endpoint, terminal)?));
    let app = Window { native, driver: Rc::clone(&driver), session_deadline,
        writer_flow: WriterFlow::default(),
        activate_flow: ActivateFlow::default(),
        v3_selection_text: [String::new(), String::new()], v3_selection: [None, None],
        v3_source_result: [None, None], v3_pair_endpoint: [None, None],
        v3_pair_ticket: [None, None], v3_pair_display: [None, None],
        v3_enrollment_ticket: [None, None], v3_enrollment_display: [None, None],
        v3_enrollment_result: [None, None], v3_enrollment_attempted: [false; 2],
        v3_manifest_ticket: [None, None], v3_manifest_display: [None, None],
        v3_manifest_result: [None, None], v3_manifest_attempted: [false; 2],
        v3_redisclosure_read_ticket: [None, None], v3_redisclosure_read_display: [None, None],
        v3_redisclosure_read_result: [None, None], v3_redisclosure_read_attempted: [false; 2],
        v3_redisclose_ticket: [None, None], v3_redisclose_display: [None, None],
        v3_redisclose_result: [None, None], v3_redisclose_attempted: [false; 2],
        v3_owner_text: [String::new(), String::new()], v3_owner_selected: [false; 2],
        v3_prepare_read_ticket: [None, None], v3_prepare_read_display: [None, None],
        v3_prepare_read_result: [None, None], v3_prepare_read_attempted: [false; 2],
        v3_receive_ticket: [None, None], v3_receive_display: [None, None],
        v3_receive_result: [None, None], v3_receive_attempted: [false; 2],
        v3_pair_result: [None, None], v3_pair_attempted: [false; 2],
        v3_offer: None, v3_display: [None, None], v3_opened: [false; 2], v3_failed: [false; 2],
        phase: Phase::Selecting, active: None, progress: [Progress::NotStarted; 2],
        entry: None, read: None, continuation: None, continue_review: None, continue_ready: None,
        history_setup: None, history_review: None, history_serving: None,
        history_display: [None, None], history_disposed: [false; 2], history_closed: [false; 2],
        history_retirement: None, history_retired: None, retirement_paused: None, history_resume_pending: None,
        signing_disposed: [false; 2], signing_closed: [false; 2],
        continue_deadline: None, continue_expected: [None, None], continue_effect: [ContinueEffect::None; 2], saved: [None, None], password: None, binding: None, request_digest: String::new(),
        selectors: [FinancialWitnessInputsV1::default(), FinancialWitnessInputsV1::default()],
        retained_continue: [None, None], setup: None, signer_review: None, signer_ready: None,
        witness_review: None, witness_armed: None, witness_ready: None,
        signer_display: [None, None], witness_display: [None, None], signer_ready_digest: [None, None], witness_ready_data: [None, None],
        signer_effect: [AdmissionEffect::None; 2], witness_effect: [AdmissionEffect::None; 2],
        signer_committed: [None, None], signer_outcome: [None, None], witness_outcome: [None, None],
        paired: PairedConsent::default(), signer_arm_sent: false, witness_arm_sent: false,
        witness_disposed: [false; 2], witness_closed: [false; 2], witness_failure: [None, None],
        focus_seen: false, focused_last: false, close_when_done: false,
        read_to_end: false, acknowledged: false, phase_frame: 0, last_tail_frame: None,
        intent: None, first_failure: None, disposed: [false; 2],
        host_input: None, host_entry: HostEntry::Idle, host_ordinal: 0,
        host_output: HostOutputText::new(), host_incomplete: false, host_output_ended: false,
        message: "Select and review one original V3 source at a time. Initial Entry unlocks only its actual account/journal; all later V3 and financial actions require separate genuine approvals." };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Wholepact · Original Signer source")
            .with_app_id("org.wholepact.CoordinatorFinancialSource")
            .with_inner_size([1100.0, 900.0])
            .with_min_inner_size([840.0, 720.0])
            .with_drag_and_drop(false),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        event_loop_builder: Some(Box::new(|builder| {
            builder.with_wayland();
        })),
        ..Default::default()
    };
    let window = eframe::run_native(
        "Wholepact original Signer source",
        options,
        Box::new(move |_cc| Ok(Box::new(app))),
    );
    driver.borrow().revoke();
    let cleanup = driver.borrow_mut().join();
    if window.is_err() {
        return Err(rejected("source-entry native window unavailable"));
    }
    cleanup
}

struct Window {
    v3_source_result: [Option<SignerV3SourceOpenedV1>; 2],
    v3_pair_endpoint: [Option<SignerV3PairEndpointV1>; 2],
    v3_pair_ticket: [Option<SignerV3PairTicketV1>; 2],
    v3_pair_display: [Option<SignerV3PairPresentationV1>; 2],
    v3_pair_result: [Option<SignerV3PairedV1>; 2],
    v3_pair_attempted: [bool; 2],
    v3_receive_ticket: [Option<SignerV3ReceiveTicketV1>; 2],
    v3_receive_display: [Option<SignerV3ReceivePresentationV1>; 2],
    v3_receive_result: [Option<SignerV3ReceivedV1>; 2],
    v3_receive_attempted: [bool; 2],
    v3_prepare_read_ticket: [Option<SignerV3PrepareReadTicketV1>; 2],
    v3_prepare_read_display: [Option<SignerV3PrepareReadPresentationV1>; 2],
    v3_prepare_read_result: [Option<SignerV3PreparedV1>; 2],
    v3_prepare_read_attempted: [bool; 2],
    v3_owner_text: [String; 2],
    v3_owner_selected: [bool; 2],
    v3_redisclose_ticket: [Option<SignerV3RediscloseTicketV1>; 2],
    v3_redisclose_display: [Option<SignerV3RedisclosePresentationV1>; 2],
    v3_redisclose_result: [Option<SignerV3RedisclosedV1>; 2],
    v3_redisclose_attempted: [bool; 2],
    v3_redisclosure_read_ticket: [Option<SignerV3RedisclosureReadTicketV1>; 2],
    v3_redisclosure_read_display: [Option<SignerV3RedisclosureReadPresentationV1>; 2],
    v3_redisclosure_read_result: [Option<SignerV3RedisclosurePreparedV1>; 2],
    v3_redisclosure_read_attempted: [bool; 2],
    v3_manifest_ticket: [Option<SignerV3ManifestTicketV1>; 2],
    v3_manifest_display: [Option<SignerV3ManifestPresentationV1>; 2],
    v3_manifest_result: [Option<SignerV3ManifestCommittedV1>; 2],
    v3_manifest_attempted: [bool; 2],
    v3_enrollment_ticket: [Option<SignerV3EnrollmentTicketV1>; 2],
    v3_enrollment_display: [Option<SignerV3EnrollmentPresentationV1>; 2],
    v3_enrollment_result: [Option<SignerV3EnrollmentCommittedV1>; 2],
    v3_enrollment_attempted: [bool; 2],
    v3_selection_text: [String; 2],
    v3_selection: [Option<SignerV3SourceEntrySelectionV1>; 2],
    v3_offer: Option<SignerV3SourceEntryOfferV1>,
    v3_display: [Option<SignerV3SourceEntryPresentationV1>; 2],
    v3_opened: [bool; 2],
    v3_failed: [bool; 2],
    writer_flow: WriterFlow,
    activate_flow: ActivateFlow,
    native: CoordinatorFinancialNativeV1,
    driver: Rc<RefCell<Driver>>,
    session_deadline: Instant,
    phase: Phase,
    active: Option<Role>,
    progress: [Progress; 2],
    entry: Option<SignerSourceEntryOfferV1>,
    read: Option<SignerFinancialReadTicketV1>,
    history_setup: Option<FinancialHistorySetupTicketV1>,
    history_review: Option<FinancialHistoryReviewTicketV1>,
    history_serving: Option<FinancialHistoryServingV1>,
    // Ordinary authenticated observations, never a replacement Serving owner.
    history_display: [Option<FinancialHistoryPresentationV1>; 2],
    history_disposed: [bool; 2],
    history_closed: [bool; 2],
    history_retirement: Option<CoordinatorWitnessRetirementTicketV1>,
    history_retired: Option<CoordinatorWitnessRetiredV1>,
    // Scheduling state set only after actual native pause, never a permission.
    retirement_paused: Option<(Role, Instant)>,
    history_resume_pending: Option<Role>,
    signing_disposed: [bool; 2],
    signing_closed: [bool; 2],
    continuation: Option<SignerContinuePresentationV1>,
    continue_review: Option<FinancialContinueReviewTicketV1>,
    continue_ready: Option<FinancialContinueReadyTicketV1>,
    continue_deadline: Option<Instant>,
    // Observation metadata survives clearing and R. It is never an authority.
    continue_expected: [Option<(String, String)>; 2],
    continue_effect: [ContinueEffect; 2],
    saved: [Option<SignerContinuationSavedV1>; 2],
    selectors: [FinancialWitnessInputsV1; 2],
    retained_continue: [Option<SignerContinuePresentationV1>; 2],
    setup: Option<FinancialWitnessSetupTicketV1>,
    signer_review: Option<SignerAdmitReviewTicketV1>,
    signer_ready: Option<SignerAdmitReadyTicketV1>,
    witness_review: Option<FinancialWitnessReviewTicketV1>,
    witness_armed: Option<FinancialWitnessArmedV1>,
    witness_ready: Option<FinancialWitnessReadyTicketV1>,
    // Actual authenticated observations survive UI clearing and global R.
    signer_display: [Option<SignerAdmitPresentationV1>; 2],
    witness_display: [Option<FinancialWitnessPresentationV1>; 2],
    signer_ready_digest: [Option<String>; 2],
    witness_ready_data: [Option<FinancialWitnessReadyV1>; 2],
    signer_effect: [AdmissionEffect; 2],
    witness_effect: [AdmissionEffect; 2],
    signer_committed: [Option<SignerAdmitCommittedV1>; 2],
    signer_outcome: [Option<SignerAdmitOutcomeV1>; 2],
    witness_outcome: [Option<FinancialWitnessOutcomeV1>; 2],
    paired: PairedConsent,
    signer_arm_sent: bool,
    witness_arm_sent: bool,
    witness_disposed: [bool; 2],
    witness_closed: [bool; 2],
    witness_failure: [Option<DeliveryFailureV1>; 2],
    password: Option<PasswordInput>,
    binding: Option<RequestBinding>,
    request_digest: String,
    focus_seen: bool,
    focused_last: bool,
    close_when_done: bool,
    read_to_end: bool,
    acknowledged: bool,
    phase_frame: u64,
    last_tail_frame: Option<u64>,
    intent: Option<Intent>,
    first_failure: Option<(Role, FinancialWorkflowStageV1)>,
    disposed: [bool; 2],
    message: &'static str,
    // Drop explicitly publishes native/shared R before these input owners are
    // canceled or automatically dropped. Leaf Drop is only best-effort cleanup.
    host_input: Option<HostLineInput>,
    host_entry: HostEntry,
    host_ordinal: u64,
    host_output: HostOutputText,
    host_incomplete: bool,
    host_output_ended: bool,
}
impl Window {
    fn accept_v3_enrollment(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3EnrollmentDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Entry missing"))?;
                let pair = self.v3_pair_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before actual Pair"))?;
                let pair_display = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Pair review missing"))?;
                let f = &p.facts;
                if p.review_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.reviewed_at_ms < pair_display.facts.reviewed_at_ms
                {
                    return Err(rejected("receipt original channel window changed"));
                }
                if self.v3_enrollment_display[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || f.entry_presentation_digest != source.entry_presentation_digest
                    || f.source_identity_digest != source.source_identity_digest
                    || f.pair_grant_id != pair.grant_id
                    || f.pair_key_digest != pair.key_digest
                    || f.pair_channel_digest != pair.channel_digest
                    || f.pair_generation != pair.generation
                    || f.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("fresh receipt source/Pair changed"));
                }
                let selection = self.v3_selection[i]
                    .as_ref()
                    .ok_or_else(|| rejected("original selection missing"))?;
                if f.historical_enrollment_ref != selection.original_enrollment_ref
                    || f.historical_manifest_ref != selection.original_manifest_ref
                {
                    return Err(rejected("historical references changed"));
                }
                self.v3_enrollment_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_enrollment_ticket[i] = Some(ticket);
            }
            Event::V3Enrolled { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_enrollment_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt commit without review"))?;
                if !self.v3_enrollment_attempted[i]
                    || self.v3_enrollment_result[i].is_some()
                    || data.presentation_digest != p.presentation_digest
                    || data.record_reference != p.facts.record_reference
                {
                    return Err(rejected("actual receipt commit changed"));
                }
                self.v3_enrollment_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3Enrolling {
                        return Err(rejected("receipt commit outside attempt"));
                    }
                    self.transition(Phase::V3Enrolled, frame);
                }
            }
            _ => return Err(rejected("wrong receipt event")),
        }
        Ok(())
    }

    fn accept_v3_manifest(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3ManifestDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Entry missing"))?;
                let pair = self.v3_pair_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before actual Pair"))?;
                let pair_display = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Pair review missing"))?;
                let f = &p.facts;
                if p.review_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.reviewed_at_ms < pair_display.facts.reviewed_at_ms
                {
                    return Err(rejected("receipt original channel window changed"));
                }
                if self.v3_manifest_display[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || f.entry_presentation_digest != source.entry_presentation_digest
                    || f.source_identity_digest != source.source_identity_digest
                    || f.pair_grant_id != pair.grant_id
                    || f.pair_key_digest != pair.key_digest
                    || f.pair_channel_digest != pair.channel_digest
                    || f.pair_generation != pair.generation
                    || f.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("fresh receipt source/Pair changed"));
                }
                let enrollment = self.v3_enrollment_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Manifest before actual Enrollment commit"))?;
                let prior = self.v3_enrollment_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Enrollment presentation missing"))?;
                if !v3_manifest_predecessor_matches(
                    &f.current_enrollment_ref,
                    &enrollment.record_reference,
                    &f.coordinated_session_id,
                    &prior.facts.coordinated_session_id,
                    &f.receipt_nonce,
                    &prior.facts.receipt_nonce,
                ) {
                    return Err(rejected(
                        "Manifest current Enrollment/session/nonce changed",
                    ));
                }
                self.v3_manifest_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_manifest_ticket[i] = Some(ticket);
            }
            Event::V3ManifestAccepted { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_manifest_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt commit without review"))?;
                if !self.v3_manifest_attempted[i]
                    || self.v3_manifest_result[i].is_some()
                    || data.presentation_digest != p.presentation_digest
                    || data.record_reference != p.facts.record_reference
                {
                    return Err(rejected("actual receipt commit changed"));
                }
                self.v3_manifest_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3Manifesting {
                        return Err(rejected("receipt commit outside attempt"));
                    }
                    self.transition(Phase::V3ManifestAccepted, frame);
                }
            }
            _ => return Err(rejected("wrong receipt event")),
        }
        Ok(())
    }

    fn accept_v3_redisclosure_read(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3RedisclosureReadDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Entry missing"))?;
                let pair = self.v3_pair_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before actual Pair"))?;
                let pair_display = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Pair review missing"))?;
                let f = &p.facts;
                if p.review_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.reviewed_at_ms < pair_display.facts.reviewed_at_ms
                {
                    return Err(rejected("receipt original channel window changed"));
                }
                if self.v3_redisclosure_read_display[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || f.entry_presentation_digest != source.entry_presentation_digest
                    || f.source_identity_digest != source.source_identity_digest
                    || f.pair_grant_id != pair.grant_id
                    || f.pair_key_digest != pair.key_digest
                    || f.pair_channel_digest != pair.channel_digest
                    || f.pair_generation != pair.generation
                    || f.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("fresh receipt source/Pair changed"));
                }
                let enrollment = self.v3_enrollment_result[i].as_ref().ok_or_else(|| {
                    rejected("redisclosure before actual fresh Enrollment commit")
                })?;
                let manifest = self.v3_manifest_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("redisclosure before actual fresh Manifest commit"))?;
                let prior = self.v3_manifest_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("current Manifest presentation missing"))?;
                if f.current_enrollment_ref != enrollment.record_reference
                    || f.current_manifest_ref != manifest.record_reference
                    || f.coordinated_session_id != prior.facts.coordinated_session_id
                {
                    return Err(rejected(
                        "redisclosure current fresh receipts/session changed",
                    ));
                }
                self.v3_redisclosure_read_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_redisclosure_read_ticket[i] = Some(ticket);
            }
            Event::V3RedisclosurePrepared { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_redisclosure_read_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt commit without review"))?;
                if !self.v3_redisclosure_read_attempted[i]
                    || self.v3_redisclosure_read_result[i].is_some()
                    || !v3_prepared_matches_read(&data, p)
                {
                    return Err(rejected("actual receipt commit changed"));
                }
                self.v3_redisclosure_read_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3RedisclosureReading {
                        return Err(rejected("receipt commit outside attempt"));
                    }
                    self.transition(Phase::V3RedisclosurePrepared, frame);
                }
            }
            _ => return Err(rejected("wrong receipt event")),
        }
        Ok(())
    }

    fn accept_v3_redisclose(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3RediscloseDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Entry missing"))?;
                let pair = self.v3_pair_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before actual Pair"))?;
                let pair_display = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Pair review missing"))?;
                let f = &p.facts;
                if p.review_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.reviewed_at_ms < pair_display.facts.reviewed_at_ms
                {
                    return Err(rejected("receipt original channel window changed"));
                }
                if self.v3_redisclose_display[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || f.entry_presentation_digest != source.entry_presentation_digest
                    || f.source_identity_digest != source.source_identity_digest
                    || f.pair_grant_id != pair.grant_id
                    || f.pair_key_digest != pair.key_digest
                    || f.pair_channel_digest != pair.channel_digest
                    || f.pair_generation != pair.generation
                    || f.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("fresh receipt source/Pair changed"));
                }
                let enrollment = self.v3_enrollment_result[i].as_ref().ok_or_else(|| {
                    rejected("redisclosure before actual fresh Enrollment commit")
                })?;
                let manifest = self.v3_manifest_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("redisclosure before actual fresh Manifest commit"))?;
                let prior = self.v3_manifest_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("current Manifest presentation missing"))?;
                if f.current_enrollment_ref != enrollment.record_reference
                    || f.current_manifest_ref != manifest.record_reference
                    || f.coordinated_session_id != prior.facts.coordinated_session_id
                {
                    return Err(rejected(
                        "redisclosure current fresh receipts/session changed",
                    ));
                }
                let prepared = self.v3_redisclosure_read_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Redisclose before actual Read preparation"))?;
                if &f.prepared != prepared {
                    return Err(rejected(
                        "Redisclose immutable candidate commitment changed",
                    ));
                }
                self.v3_redisclose_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_redisclose_ticket[i] = Some(ticket);
            }
            Event::V3Redisclosed { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_redisclose_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt commit without review"))?;
                if !self.v3_redisclose_attempted[i]
                    || self.v3_redisclose_result[i].is_some()
                    || !v3_redisclosed_matches_candidate(&data, p)
                {
                    return Err(rejected("actual receipt commit changed"));
                }
                self.v3_redisclose_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3Redisclosing {
                        return Err(rejected("receipt commit outside attempt"));
                    }
                    self.transition(Phase::V3Redisclosed, frame);
                }
            }
            _ => return Err(rejected("wrong receipt event")),
        }
        Ok(())
    }

    fn accept_v3_prepare_read(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3PrepareReadDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Entry missing"))?;
                let pair = self.v3_pair_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before actual Pair"))?;
                let pair_display = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Pair review missing"))?;
                let f = &p.facts;
                if p.review_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.reviewed_at_ms < pair_display.facts.reviewed_at_ms
                {
                    return Err(rejected("receipt original channel window changed"));
                }
                if self.v3_prepare_read_display[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || f.entry_presentation_digest != source.entry_presentation_digest
                    || f.source_identity_digest != source.source_identity_digest
                    || f.pair_grant_id != pair.grant_id
                    || f.pair_key_digest != pair.key_digest
                    || f.pair_channel_digest != pair.channel_digest
                    || f.pair_generation != pair.generation
                    || f.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("fresh receipt source/Pair changed"));
                }
                let enrollment = self.v3_enrollment_result[i].as_ref().ok_or_else(|| {
                    rejected("redisclosure before actual fresh Enrollment commit")
                })?;
                let manifest = self.v3_manifest_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("redisclosure before actual fresh Manifest commit"))?;
                let prior = self.v3_manifest_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("current Manifest presentation missing"))?;
                if f.current_enrollment_ref != enrollment.record_reference
                    || f.current_manifest_ref != manifest.record_reference
                    || f.coordinated_session_id != prior.facts.coordinated_session_id
                {
                    return Err(rejected(
                        "redisclosure current fresh receipts/session changed",
                    ));
                }
                let export = self.v3_redisclose_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("delivery before actual Redisclosed"))?;
                if !self.v3_owner_selected[i]
                    || f.current_outbox_reference != export.outbox_reference
                    || f.current_request_digest != export.request_digest
                    || f.original_host_process_instance
                        != pair_display.facts.original_host_process_instance
                    || f.coordinated_provider_reference
                        != pair_display.facts.coordinated_provider_reference
                    || p.service_ceiling_ms > pair_display.channel_ceiling_ms
                    || p.material_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.service_expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.material_expires_at_ms > pair_display.facts.channel_expires_at_ms
                {
                    return Err(rejected(
                        "delivery original export/service/material binding changed",
                    ));
                }
                if f.owner_setup_json != self.v3_owner_text[i]
                    || f.owner_certificate_digest != entry.facts.owner_certificate_digest
                {
                    return Err(rejected("PrepareRead exact selected owner setup changed"));
                }
                self.v3_prepare_read_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_prepare_read_ticket[i] = Some(ticket);
            }
            Event::V3Prepared { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_prepare_read_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt commit without review"))?;
                if !self.v3_prepare_read_attempted[i]
                    || self.v3_prepare_read_result[i].is_some()
                    || !v3_delivery_prepared_matches(&data, p)
                {
                    return Err(rejected("actual receipt commit changed"));
                }
                self.v3_prepare_read_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3PrepareReading {
                        return Err(rejected("receipt commit outside attempt"));
                    }
                    self.transition(Phase::V3Prepared, frame);
                }
            }
            _ => return Err(rejected("wrong receipt event")),
        }
        Ok(())
    }

    fn accept_v3_receive(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3ReceiveDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Entry missing"))?;
                let pair = self.v3_pair_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt before actual Pair"))?;
                let pair_display = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt original Pair review missing"))?;
                let f = &p.facts;
                if p.review_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.reviewed_at_ms < pair_display.facts.reviewed_at_ms
                {
                    return Err(rejected("receipt original channel window changed"));
                }
                if self.v3_receive_display[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || f.entry_presentation_digest != source.entry_presentation_digest
                    || f.source_identity_digest != source.source_identity_digest
                    || f.pair_grant_id != pair.grant_id
                    || f.pair_key_digest != pair.key_digest
                    || f.pair_channel_digest != pair.channel_digest
                    || f.pair_generation != pair.generation
                    || f.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("fresh receipt source/Pair changed"));
                }
                let enrollment = self.v3_enrollment_result[i].as_ref().ok_or_else(|| {
                    rejected("redisclosure before actual fresh Enrollment commit")
                })?;
                let manifest = self.v3_manifest_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("redisclosure before actual fresh Manifest commit"))?;
                let prior = self.v3_manifest_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("current Manifest presentation missing"))?;
                if f.current_enrollment_ref != enrollment.record_reference
                    || f.current_manifest_ref != manifest.record_reference
                    || f.coordinated_session_id != prior.facts.coordinated_session_id
                {
                    return Err(rejected(
                        "redisclosure current fresh receipts/session changed",
                    ));
                }
                let export = self.v3_redisclose_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("delivery before actual Redisclosed"))?;
                if !self.v3_owner_selected[i]
                    || f.current_outbox_reference != export.outbox_reference
                    || f.current_request_digest != export.request_digest
                    || f.original_host_process_instance
                        != pair_display.facts.original_host_process_instance
                    || f.coordinated_provider_reference
                        != pair_display.facts.coordinated_provider_reference
                    || p.service_ceiling_ms > pair_display.channel_ceiling_ms
                    || p.material_ceiling_ms > pair_display.channel_ceiling_ms
                    || f.service_expires_at_ms > pair_display.facts.channel_expires_at_ms
                    || f.material_expires_at_ms > pair_display.facts.channel_expires_at_ms
                {
                    return Err(rejected(
                        "delivery original export/service/material binding changed",
                    ));
                }
                let read = self.v3_prepare_read_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Receive without original PrepareRead"))?;
                let prepared = self.v3_prepare_read_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Receive before actual preparation"))?;
                if !v3_receive_matches_prepared(p, read, prepared) {
                    return Err(rejected("Receive original prepared custody changed"));
                }
                self.v3_receive_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_receive_ticket[i] = Some(ticket);
            }
            Event::V3Received { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_receive_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("receipt commit without review"))?;
                if !self.v3_receive_attempted[i]
                    || self.v3_receive_result[i].is_some()
                    || !v3_delivery_received_matches(&data, p)
                {
                    return Err(rejected("actual receipt commit changed"));
                }
                self.v3_receive_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3Receiving {
                        return Err(rejected("receipt commit outside attempt"));
                    }
                    self.transition(Phase::V3Received, frame);
                }
            }
            _ => return Err(rejected("wrong receipt event")),
        }
        Ok(())
    }

    fn accept_v3_pair(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::V3PairEndpoint { role, data } => {
                data.validate()?;
                let i = index(role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Pair endpoint before actual opened source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Pair endpoint without original Entry"))?;
                if self.v3_pair_endpoint[i].is_some()
                    || data.entry_presentation_digest != source.entry_presentation_digest
                    || data.source_identity_digest != source.source_identity_digest
                    || data.signer_process_instance != entry.actor.signer_process_instance
                    || data.source_expires_at_ms != entry.facts.source_expires_at_ms
                {
                    return Err(rejected("Pair endpoint original source changed"));
                }
                self.v3_pair_endpoint[i] = Some(data); // Ordinary authenticated metadata, never a connect capability.
            }
            Event::V3PairDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let i = index(p.actor.signer_role);
                let source = self.v3_source_result[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Pair display before opened source"))?;
                let entry = self.v3_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Pair original Entry missing"))?;
                let endpoint = self.v3_pair_endpoint[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Pair actual endpoint missing"))?;
                if self.v3_pair_display[i].is_some()
                    || self.v3_pair_ticket[i].is_some()
                    || p.actor != entry.actor
                    || p.source_ceiling_ms != entry.source_ceiling_ms
                    || !v3_pair_matches_source(
                        p,
                        endpoint,
                        source,
                        &entry.facts.original_host_process_instance,
                    )
                {
                    return Err(rejected("Pair source endpoint or original Host changed"));
                }
                // Retain exact ordinary review identity even if R won this batch.
                // The opaque ticket is never resurrected or admitted after R.
                self.v3_pair_display[i] = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                ticket.check_current()?;
                self.v3_pair_ticket[i] = Some(ticket);
                self.message = "An actual pending original Pair review is available. Select and explicitly approve that distinct purpose; opened-source observation is not consent.";
            }
            Event::V3Paired { role, data } => {
                data.validate()?;
                let i = index(role);
                let p = self.v3_pair_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Pair result without actual review"))?;
                if !self.v3_pair_attempted[i]
                    || self.v3_pair_result[i].is_some()
                    || !v3_pair_result_matches(&data, p)
                {
                    return Err(rejected("Pair actual StatusProof result changed"));
                }
                self.v3_pair_result[i] = Some(data);
                if !self.terminal() {
                    if self.active != Some(role) || self.phase != Phase::V3Pairing {
                        return Err(rejected("Pair result outside original attempt"));
                    }
                    self.transition(Phase::V3Paired, frame);
                    self.message = "Original Pair completed only after actual StatusProof. Later Read/receive/admission/audit remain separately unapproved.";
                }
            }
            _ => return Err(rejected("wrong Pair event")),
        }
        Ok(())
    }

    fn accept_v3_entry(&mut self, offer: SignerV3SourceEntryOfferV1, frame: u64) -> Result<()> {
        offer.check_current()?;
        let presentation = offer.presentation();
        presentation.validate()?;
        let role = presentation.actor.signer_role;
        let i = index(role);
        let selection = self.v3_selection[i]
            .as_ref()
            .ok_or_else(|| rejected("unsolicited V3 selection"))?;
        if !self.focused_last
            || self.phase != Phase::V3Preparing
            || self.active != Some(role)
            || self.v3_offer.is_some()
            || self.v3_display[i].is_some()
            || !v3_selection_matches(selection, &presentation.facts)
        {
            return Err(rejected(
                "actual V3 offer differs from exact proposed selection",
            ));
        }
        let digest = offer.request_digest()?;
        let binding = RequestBinding::new(input_role(role), &digest)
            .ok_or_else(|| rejected("V3 input binding invalid"))?;
        self.v3_display[i] = Some(presentation.clone());
        self.request_digest = digest;
        self.binding = Some(binding);
        self.v3_offer = Some(offer);
        self.transition(Phase::V3Review, frame);
        self.message = "Review the actual original V3 public source metadata and complete distinct Entry. Unlocking remains unapproved until your one password submission at the eligible native tail.";
        Ok(())
    }
    fn submit_v3_password(&mut self, input: BoundPassword, frame: u64) -> Result<()> {
        if self.phase != Phase::V3Password {
            return Err(rejected("V3 password outside exact phase"));
        }
        let role = self
            .active
            .ok_or_else(|| rejected("V3 active role missing"))?;
        let binding = self
            .binding
            .take()
            .ok_or_else(|| rejected("V3 input binding consumed"))?;
        let offer = self
            .v3_offer
            .take()
            .ok_or_else(|| rejected("V3 nominal offer consumed"))?;
        let mut password = input
            .into_password_for(&binding)
            .ok_or_else(|| rejected("V3 input expired or changed"))?;
        let bytes = Zeroizing::new(std::mem::take(&mut *password).into_bytes());
        drop(password);
        self.password.take();
        // Same allocation, separate genuine V3 issuer; never a legacy Entry cast.
        let outbound = self
            .native
            .admit_v3_source_entry(offer, bytes, &self.request_digest)?;
        self.request_digest.zeroize();
        self.driver.borrow_mut().send_v3_entry(role, outbound)?;
        self.transition(Phase::V3Opening, frame);
        Ok(())
    }

    fn writer_transition(&mut self, stage: WriterStage, frame: u64) {
        self.writer_flow.stage = stage;
        self.transition(Phase::WriterFlow, frame);
    }
    fn signing_inputs(&self) -> Result<FinancialSigningInputsV1> {
        let role = self
            .active
            .ok_or_else(|| rejected("Signing role missing"))?;
        let p = self.signer_display[index(role)]
            .as_ref()
            .ok_or_else(|| rejected("actual Admit missing"))?;
        let inputs = FinancialSigningInputsV1 {
            selectors: history_inputs(&self.selectors[index(role)])?,
            continuation_operation_id: p.facts.operation_id.clone(),
        };
        inputs.validate()?;
        Ok(inputs)
    }
    fn accept_signing_setup(
        &mut self,
        role: Role,
        ticket: FinancialSigningSetupTicketV1,
        frame: u64,
    ) -> Result<()> {
        ticket.check_current()?;
        if self.terminal()
            || self.active != Some(role)
            || self.phase != Phase::WriterFlow
            || self.writer_flow.stage != WriterStage::SetupPreparing
            || self.writer_flow.setup.is_some()
            || ticket.inputs() != &self.signing_inputs()?
            || ticket.original_binding().actor.signer_role != role
        {
            return Err(rejected("unsolicited Signing setup"));
        }
        self.writer_flow.setup = Some(ticket);
        self.writer_transition(WriterStage::SetupReview, frame);
        Ok(())
    }
    fn accept_signing(&mut self, event: SigningEvent, frame: u64) -> Result<()> {
        match event {
            SigningEvent::Disposed(role) => {
                self.signing_disposed[index(role)] = true;
                return Ok(());
            }
            SigningEvent::PurposeClosed(role) => {
                self.signing_closed[index(role)] = true;
                return Ok(());
            }
            SigningEvent::PreparationFailed(_)
            | SigningEvent::ServiceFailed(_)
            | SigningEvent::Restricted(_) => {
                self.revoke("Signing service failed or restricted. No Writer action or completed disposal is inferred.");
                return Ok(());
            }
            _ => {}
        }
        if self.terminal() {
            drop(event);
            return Ok(());
        }
        match event {
            SigningEvent::Display(ticket) => {
                ticket.check_current()?;
                let p = ticket.presentation();
                p.validate()?;
                let role = p.original.actor.signer_role;
                if self.phase != Phase::WriterFlow
                    || self.writer_flow.stage != WriterStage::ServicePreparing
                    || self.active != Some(role)
                    || self.writer_flow.review.is_some()
                    || self.writer_flow.service_display.is_some()
                    || p.original.admit_presentation_digest
                        != self.signer_display[index(role)]
                            .as_ref()
                            .ok_or_else(|| rejected("missing Admit"))?
                            .presentation_digest
                {
                    return Err(rejected("Signing service display changed"));
                }
                self.writer_flow.service_display = Some(p.clone());
                self.writer_flow.review = Some(ticket);
                self.writer_transition(WriterStage::ServiceReview, frame);
            }
            SigningEvent::Serving(serving) => {
                serving.check_current()?;
                if self.phase != Phase::WriterFlow
                    || self.writer_flow.stage != WriterStage::ServiceStarting
                    || self.writer_flow.serving.is_some()
                    || self.writer_flow.service_display.as_ref() != Some(serving.presentation())
                    || self.active != Some(serving.presentation().original.actor.signer_role)
                {
                    return Err(rejected("Signing Serving changed"));
                }
                self.writer_flow.serving = Some(serving);
                self.writer_transition(WriterStage::ReadReview, frame);
            }
            _ => unreachable!("terminal observations handled"),
        }
        Ok(())
    }
    fn accept_activate(&mut self, event: Event, frame: u64) -> Result<()> {
        match event {
            Event::ActivateReadDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let writer = self
                    .writer_flow
                    .read_display
                    .as_ref()
                    .ok_or_else(|| rejected("Activate missing actual Writer Read"))?;
                let acquired = self
                    .writer_flow
                    .acquired
                    .as_ref()
                    .ok_or_else(|| rejected("Activate before actual Acquire"))?;
                if self.active != Some(p.actor.signer_role)
                    || self.activate_flow.read_display.is_some()
                    || p.actor != writer.actor
                    || p.source_ceiling_ms != writer.source_ceiling_ms
                    || !activate_original_matches(&p.facts.original, &writer.facts, acquired)
                {
                    return Err(rejected("Activate Read original custody changed"));
                }
                self.activate_flow.read_display = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                if self.phase != Phase::WriterFlow
                    || self.writer_flow.stage != WriterStage::Acquired
                {
                    return Err(rejected("Activate Read outside acquired custody"));
                }
                ticket.check_current()?;
                self.writer_flow
                    .serving
                    .as_ref()
                    .ok_or_else(|| rejected("original Signing service missing"))?
                    .check_current()?;
                self.activate_flow.read = Some(ticket);
                self.transition(Phase::ActivateReadReview, frame);
            }
            Event::ActivateDisplay(ticket) => {
                let p = ticket.presentation();
                p.validate()?;
                let read = self
                    .activate_flow
                    .read_display
                    .as_ref()
                    .ok_or_else(|| rejected("Activate without original Read"))?;
                if self.active != Some(p.actor.signer_role)
                    || self.activate_flow.display.is_some()
                    || p.actor != read.actor
                    || p.source_ceiling_ms != read.source_ceiling_ms
                    || p.facts.original != read.facts.original
                    || p.facts.activate_read_presentation_digest != read.presentation_digest
                {
                    return Err(rejected("Activate recipe changed"));
                }
                self.activate_flow.display = Some(p.clone());
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                if self.phase != Phase::ActivateReading {
                    return Err(rejected("Activate recipe outside Read attempt"));
                }
                ticket.check_current()?;
                self.activate_flow.review = Some(ticket);
                self.transition(Phase::ActivateReview, frame);
            }
            Event::ActivateReady(ticket) => {
                ticket.presentation().validate()?;
                if self.activate_flow.display.as_ref() != Some(ticket.presentation())
                    || self.active != Some(ticket.presentation().actor.signer_role)
                    || self.activate_flow.ready_digest.is_some()
                {
                    return Err(rejected("Activate Ready changed"));
                }
                retain_observed_ready_digest(
                    &mut self.activate_flow.ready_digest,
                    ticket.activate_ready_digest(),
                )?;
                if self.terminal() {
                    drop(ticket);
                    return Ok(());
                }
                if self.phase != Phase::ActivateArmed || self.activate_flow.ready.is_some() {
                    return Err(rejected("Activate unsolicited Ready"));
                }
                ticket.check_current()?;
                self.activate_flow.ready = Some(ticket);
                self.transition(Phase::ActivateReady, frame);
            }
            Event::ActivateReadFailed {
                role,
                presentation_digest,
            } => {
                if self.active != Some(role)
                    || self
                        .activate_flow
                        .read_display
                        .as_ref()
                        .is_none_or(|p| p.presentation_digest != presentation_digest)
                {
                    return Err(rejected("Activate Read failure changed"));
                }
                self.revoke("Activate Read failed/restricted. No retry or wallet permission.");
            }
            Event::ActivateOutcome { role, data } => {
                data.validate()?;
                let (digest, ready) = match &data {
                    SignerActivateOutcomeV1::KnownNoEffect {
                        presentation_digest,
                        activate_ready_digest,
                    }
                    | SignerActivateOutcomeV1::Uncertain {
                        presentation_digest,
                        activate_ready_digest,
                    } => (presentation_digest, activate_ready_digest.as_deref()),
                };
                if self.active != Some(role)
                    || self.activate_flow.outcome.is_some()
                    || self
                        .activate_flow
                        .display
                        .as_ref()
                        .is_none_or(|p| &p.presentation_digest != digest)
                    || ready.is_some_and(|d| self.activate_flow.ready_digest.as_deref() != Some(d))
                {
                    return Err(rejected("Activate outcome changed"));
                }
                self.activate_flow.outcome = Some(data);
                self.revoke("Activate ended without confirmed success. Any admitted or partial effect remains uncertain; no retry or replacement session.");
            }
            Event::AwaitingWalletPrepare { role, data } => {
                data.validate()?;
                let p = self
                    .activate_flow
                    .display
                    .as_ref()
                    .ok_or_else(|| rejected("Activated without review"))?;
                let acquired = self
                    .writer_flow
                    .acquired
                    .as_ref()
                    .ok_or_else(|| rejected("Activated without actual receipt"))?;
                if self.active != Some(role)
                    || !self.activate_flow.attempted
                    || self.activate_flow.committed.is_some()
                    || data.presentation_digest != p.presentation_digest
                    || self.activate_flow.ready_digest.as_deref()
                        != Some(data.activate_ready_digest.as_str())
                    || data.activation_request_digest != p.facts.activation_request_digest
                    || data.session_id != acquired.session_id
                    || data.signing_service_digest != acquired.signing_service_digest
                    || data.writer_epoch != acquired.writer_epoch
                    || !activate_head_progression(
                        p.facts.expected_head_sequence,
                        &p.facts.expected_head_digest,
                        data.head_sequence,
                        &data.head_digest,
                    )
                {
                    return Err(rejected("Activated actual receipt/session/service changed"));
                }
                self.activate_flow.committed = Some(data);
                if !self.terminal() {
                    if self.phase != Phase::Activating {
                        return Err(rejected("Activated outside original Final"));
                    }
                    self.transition(Phase::Activated, frame);
                }
            }
            _ => return Err(rejected("wrong Activate event")),
        }
        Ok(())
    }
    fn accept_writer(&mut self, event: Event, frame: u64) -> Result<()> {
        if self.terminal()
            && matches!(
                &event,
                Event::WriterReadDisplay(_) | Event::AcquireDisplay(_) | Event::AcquireReady(_)
            )
        {
            // The endpoint already authenticated these original observations.
            // Keep ordinary commitments after R, never their actionable tickets.
            match &event {
                Event::WriterReadDisplay(t) => {
                    let p = t.presentation();
                    p.validate()?;
                    if self.active != Some(p.actor.signer_role)
                        || self
                            .writer_flow
                            .read_display
                            .as_ref()
                            .is_some_and(|old| old != p)
                    {
                        return Err(rejected("terminal Writer Read metadata changed"));
                    }
                    self.writer_flow.read_display = Some(p.clone());
                }
                Event::AcquireDisplay(t) => {
                    let p = t.presentation();
                    p.validate()?;
                    if self.active != Some(p.actor.signer_role)
                        || self
                            .writer_flow
                            .display
                            .as_ref()
                            .is_some_and(|old| old != p)
                    {
                        return Err(rejected("terminal Acquire metadata changed"));
                    }
                    self.writer_flow.display = Some(p.clone());
                }
                Event::AcquireReady(t) => {
                    let p = t.presentation();
                    p.validate()?;
                    if self.active != Some(p.actor.signer_role)
                        || self
                            .writer_flow
                            .display
                            .as_ref()
                            .is_some_and(|old| old != p)
                        || self
                            .writer_flow
                            .ready_digest
                            .as_deref()
                            .is_some_and(|old| old != t.acquire_ready_digest())
                    {
                        return Err(rejected("terminal Acquire Ready metadata changed"));
                    }
                    self.writer_flow.display = Some(p.clone());
                    retain_observed_ready_digest(
                        &mut self.writer_flow.ready_digest,
                        t.acquire_ready_digest(),
                    )?;
                }
                _ => unreachable!("matched ordinary writer observations"),
            }
            drop(event);
            return Ok(());
        }
        match event {
            Event::WriterReadDisplay(ticket) => {
                ticket.check_current()?;
                let p = ticket.presentation();
                p.validate()?;
                let role = p.actor.signer_role;
                if self.terminal()
                    || self.active != Some(role)
                    || self.writer_flow.read.is_some()
                    || self.writer_flow.read_display.is_some()
                    || self.signer_effect[index(role)] != AdmissionEffect::Committed
                    || !matches!(
                        self.phase,
                        Phase::AdmissionReview | Phase::RetirementBlocked | Phase::WriterFlow
                    )
                    || self.signer_display[index(role)]
                        .as_ref()
                        .is_none_or(|a| a.presentation_digest != p.facts.admit_presentation_digest)
                {
                    return Err(rejected("Writer Read original source changed"));
                }
                self.writer_flow.read_display = Some(p.clone());
                self.writer_flow.read = Some(ticket);
                // Keep waiting for real predecessor retirement, never use PurposeClosed as proof.
                if self.phase == Phase::WriterFlow {
                    self.writer_transition(WriterStage::SetupNeeded, frame);
                }
            }
            Event::AcquireDisplay(ticket) => {
                ticket.check_current()?;
                let p = ticket.presentation();
                p.validate()?;
                if self.terminal()
                    || self.phase != Phase::WriterFlow
                    || self.writer_flow.stage != WriterStage::Reading
                    || self.active != Some(p.actor.signer_role)
                    || self.writer_flow.display.is_some()
                    || self.writer_flow.read_display.as_ref().is_none_or(|r| {
                        r.presentation_digest != p.facts.writer_read_presentation_digest
                    })
                {
                    return Err(rejected("Acquire recipe changed"));
                }
                self.writer_flow.display = Some(p.clone());
                self.writer_flow.acquire = Some(ticket);
                self.writer_transition(WriterStage::AcquireReview, frame);
            }
            Event::AcquireReady(ticket) => {
                ticket.check_current()?;
                if self.terminal()
                    || self.phase != Phase::WriterFlow
                    || self.writer_flow.stage != WriterStage::AcquireArmed
                    || self.writer_flow.ready.is_some()
                    || self.writer_flow.display.as_ref() != Some(ticket.presentation())
                {
                    return Err(rejected("Acquire Ready changed"));
                }
                retain_observed_ready_digest(
                    &mut self.writer_flow.ready_digest,
                    ticket.acquire_ready_digest(),
                )?;
                self.writer_flow.ready = Some(ticket);
            }
            Event::AwaitingActivateRead { role, data } => {
                data.validate()?;
                let p = self
                    .writer_flow
                    .display
                    .as_ref()
                    .ok_or_else(|| rejected("Acquire report without presentation"))?;
                if !self.writer_flow.attempted
                    || self.active != Some(role)
                    || self.writer_flow.acquired.is_some()
                    || data.presentation_digest != p.presentation_digest
                    || data.recipe_digest != p.recipe_digest
                    || self.writer_flow.ready_digest.as_deref()
                        != Some(data.acquire_ready_digest.as_str())
                {
                    return Err(rejected("Acquire actual report changed"));
                }
                self.writer_flow.acquired = Some(data);
                if !self.terminal() {
                    self.writer_transition(WriterStage::Acquired, frame);
                }
                self.message = "Authenticated Acquire receipt retained. Activate requires a separate Read and separate native approval; no retry or next action is authorized.";
            }
            Event::AcquireOutcome { role, data } => {
                data.validate()?;
                let (digest, ready) = match &data {
                    SignerAcquireOutcomeV1::KnownNoEffect {
                        presentation_digest,
                        acquire_ready_digest,
                    }
                    | SignerAcquireOutcomeV1::Uncertain {
                        presentation_digest,
                        acquire_ready_digest,
                    } => (presentation_digest, acquire_ready_digest),
                };
                if self.active != Some(role)
                    || self.writer_flow.outcome.is_some()
                    || self
                        .writer_flow
                        .display
                        .as_ref()
                        .is_none_or(|p| &p.presentation_digest != digest)
                    || ready
                        .as_ref()
                        .is_some_and(|r| self.writer_flow.ready_digest.as_ref() != Some(r))
                {
                    return Err(rejected("Acquire terminal outcome changed"));
                }
                self.writer_flow.outcome = Some(data);
                self.revoke("Acquire ended without confirmed success. Actual evidence and custody remain; no retry or rollback claim.");
            }
            Event::WriterReadFailed {
                role,
                presentation_digest,
            } => {
                if self.active != Some(role)
                    || self
                        .writer_flow
                        .read_display
                        .as_ref()
                        .is_none_or(|p| p.presentation_digest != presentation_digest)
                {
                    return Err(rejected("Writer Read failure changed"));
                }
                self.revoke("Writer Read failed; no Acquire was approved.");
            }
            _ => return Err(rejected("wrong writer event")),
        }
        Ok(())
    }
    fn writer_display(&self) -> (String, Option<&'static str>, bool) {
        let json = |v: serde_json::Value| serde_json::to_string_pretty(&v).unwrap_or_default();
        match self.writer_flow.stage {
            WriterStage::SetupNeeded => ("Prepare the original Signing service from the retained Witness selectors. This does not approve credential reading, serving, Writer Read or Acquire.".into(), self.writer_flow.read.as_ref().map(|_| "Prepare Signing Setup review"), false),
            WriterStage::SetupReview => (self.writer_flow.setup.as_ref().map(|t| json(serde_json::json!({"purpose":"Signing Setup only: protected source reads and listener preparation", "inputs":t.inputs(), "original":t.original_binding()}))).unwrap_or_default(), Some("Approve Signing Setup only"), true),
            WriterStage::ServiceReview => (self.writer_flow.service_display.as_ref().map(|p| json(serde_json::json!(p))).unwrap_or_default(), Some("Approve original Signing service only"), true),
            WriterStage::ReadReview => (self.writer_flow.read_display.as_ref().map(|p| json(serde_json::json!(p))).unwrap_or_default(), Some("Approve Writer Read and one Acquire preparation only"), true),
            WriterStage::AcquireReview => (self.writer_flow.display.as_ref().map(|p| json(serde_json::json!(p))).unwrap_or_default(), Some("Approve and arm this one exact Acquire"), true),
            WriterStage::AcquireArmed => (self.writer_flow.display.as_ref().map(|p| json(serde_json::json!(p))).unwrap_or_default(), None, false),
            WriterStage::Acquired => (self.writer_flow.acquired.as_ref().map(|p| format!("Actual authenticated receipt; not Activate approval:\n{}",json(serde_json::json!(p)))).unwrap_or_default(), None, false),
            _ => ("Waiting for the actual original operation. No automatic consent, retry, replacement key or deadline renewal is allowed.".into(), None, false),
        }
    }
    fn writer_action(&mut self, frame: u64) -> Result<()> {
        let role = self.active.ok_or_else(|| rejected("writer role missing"))?;
        if self.writer_flow.stage != WriterStage::SetupNeeded && !self.acknowledged {
            return Err(rejected("writer consent missing"));
        }
        match self.writer_flow.stage {
            WriterStage::SetupNeeded => {
                let read = self
                    .writer_flow
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("Writer Read missing"))?;
                read.check_current()?;
                let deadline = (Instant::now() + Duration::from_secs(120))
                    .min(read.native_deadline())
                    .min(self.session_deadline);
                self.driver
                    .borrow_mut()
                    .prepare_signing(role, self.signing_inputs()?, deadline)?;
                self.writer_transition(WriterStage::SetupPreparing, frame);
            }
            WriterStage::SetupReview => {
                let t = self
                    .writer_flow
                    .setup
                    .take()
                    .ok_or_else(|| rejected("Signing setup consumed"))?;
                let o = self.native.admit_signing_setup(t)?;
                self.driver.borrow_mut().send_signing_setup(role, o)?;
                self.writer_transition(WriterStage::ServicePreparing, frame);
            }
            WriterStage::ServiceReview => {
                let t = self
                    .writer_flow
                    .review
                    .take()
                    .ok_or_else(|| rejected("Signing serve consumed"))?;
                let o = self.native.admit_signing_serve(t)?;
                self.driver.borrow_mut().send_signing_serve(role, o)?;
                self.writer_transition(WriterStage::ServiceStarting, frame);
            }
            WriterStage::ReadReview => {
                let t = self
                    .writer_flow
                    .read
                    .take()
                    .ok_or_else(|| rejected("Writer Read consumed"))?;
                let service = self
                    .writer_flow
                    .serving
                    .as_ref()
                    .ok_or_else(|| rejected("genuine Signing Serving missing"))?;
                let o = self.native.admit_writer_read(t, service)?;
                self.driver.borrow_mut().send_writer_read(role, o)?;
                self.writer_transition(WriterStage::Reading, frame);
            }
            WriterStage::AcquireReview => {
                let t = self
                    .writer_flow
                    .acquire
                    .take()
                    .ok_or_else(|| rejected("Acquire review consumed"))?;
                let o = self.native.arm_acquire(t)?;
                self.driver.borrow_mut().send_acquire_arm(role, o)?;
                self.writer_transition(WriterStage::AcquireArmed, frame);
            }
            _ => return Err(rejected("writer action wrong phase")),
        }
        Ok(())
    }
    fn writer_final(&mut self, frame: u64) -> Result<()> {
        let role = self
            .active
            .ok_or_else(|| rejected("Acquire role missing"))?;
        let ticket = self
            .writer_flow
            .ready
            .take()
            .ok_or_else(|| rejected("Acquire Ready consumed"))?;
        let service = self
            .writer_flow
            .serving
            .as_ref()
            .ok_or_else(|| rejected("genuine Signing Serving missing"))?;
        let outbound = self.native.admit_acquire(ticket, service)?;
        self.writer_flow.attempted = true; // Native Final precedes enqueue; send failure is not rollback.
        self.writer_transition(WriterStage::Acquiring, frame);
        self.driver.borrow_mut().send_acquire_final(role, outbound)
    }

    fn terminal(&self) -> bool {
        matches!(self.phase, Phase::Revoked | Phase::Finished)
    }
    fn transition(&mut self, phase: Phase, frame: u64) {
        self.phase = phase;
        self.phase_frame = frame;
        self.intent = None;
        self.read_to_end = false;
        self.acknowledged = false;
    }
    fn clear_review(&mut self) {
        for ticket in &mut self.v3_enrollment_ticket {
            ticket.take();
        }
        for ticket in &mut self.v3_manifest_ticket {
            ticket.take();
        }
        for ticket in &mut self.v3_redisclosure_read_ticket {
            ticket.take();
        }
        for ticket in &mut self.v3_redisclose_ticket {
            ticket.take();
        }
        for ticket in &mut self.v3_prepare_read_ticket {
            ticket.take();
        }
        for ticket in &mut self.v3_receive_ticket {
            ticket.take();
        }
        self.v3_offer.take();
        for ticket in &mut self.v3_pair_ticket {
            ticket.take();
        }
        // Ordinary result evidence survives R; only genuine unconsumed grants drop.
        self.activate_flow.read.take();
        self.activate_flow.review.take();
        self.activate_flow.ready.take();
        self.writer_flow.read.take();
        self.writer_flow.setup.take();
        self.writer_flow.review.take();
        self.writer_flow.serving.take();
        self.writer_flow.acquire.take();
        self.writer_flow.ready.take();
        self.history_setup.take();
        self.history_review.take();
        self.history_serving.take();
        self.history_retirement.take();
        self.history_retired.take();
        self.retirement_paused = None;
        self.history_resume_pending = None;
        self.setup.take();
        self.signer_review.take();
        self.signer_ready.take();
        self.witness_review.take();
        self.witness_armed.take();
        self.witness_ready.take();
        self.paired = PairedConsent::default();
        self.entry.take();
        self.read.take();
        self.continue_review.take();
        self.continue_ready.take();
        self.continuation.take();
        self.continue_deadline = None;
        self.binding = None;
        self.request_digest.zeroize();
        self.intent = None;
        self.read_to_end = false;
        self.acknowledged = false;
    }
    fn revoke(&mut self, message: &'static str) {
        if self.phase == Phase::Finished {
            return;
        }
        self.native.revoke();
        self.driver.borrow().revoke();
        if let Some(input) = &mut self.host_input {
            input.cancel(&mut || self.native.revoke());
        }
        self.host_entry = HostEntry::Closed;
        self.host_incomplete = true;
        // Keep the closed input guard until raw_input_hook has also scrubbed
        // the ORIGINAL mutable raw batch. Dropping it first would miss that copy.
        if let Some(input) = &mut self.password {
            input.cancel();
        }
        self.clear_review();
        self.phase = Phase::Revoked;
        self.message = message;
    }
    fn check_current(&mut self) {
        if self.terminal() {
            return;
        }
        let driver_revoked = self.driver.borrow().is_revoked();
        if let Some((_, cutoff)) = self.retirement_paused {
            // Ordinary Core root checks would falsely reject the actual target
            // during its exclusive normal reap. Raw interruption still runs,
            // and the nominal retirement owner checks all other original actors.
            if driver_revoked
                || self.native.is_revoked()
                || Instant::now() >= cutoff
                || Instant::now() >= self.session_deadline
                || self
                    .continue_deadline
                    .is_some_and(|end| Instant::now() >= end)
            {
                self.revoke("Original retirement was interrupted or expired. No resumed action or completed disposal is inferred.");
            }
            return;
        }
        if driver_revoked
            || self
                .v3_enrollment_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .v3_manifest_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .v3_redisclosure_read_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .v3_redisclose_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .v3_prepare_read_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .v3_receive_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .activate_flow
                .read
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .activate_flow
                .review
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .activate_flow
                .ready
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self.native.check_current().is_err()
            || self
                .v3_pair_ticket
                .iter()
                .any(|t| t.as_ref().is_some_and(|t| t.check_current().is_err()))
            || self
                .v3_offer
                .as_ref()
                .is_some_and(|o| o.check_current().is_err())
            || Instant::now() >= self.session_deadline
            || self
                .entry
                .as_ref()
                .is_some_and(|offer| offer.check_current().is_err())
            || self
                .read
                .as_ref()
                .is_some_and(|ticket| ticket.check_current().is_err())
            || self
                .writer_flow
                .read
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .writer_flow
                .setup
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .writer_flow
                .review
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .writer_flow
                .serving
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .writer_flow
                .acquire
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .writer_flow
                .ready
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .history_setup
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .history_review
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .history_serving
                .as_ref()
                .is_some_and(|s| s.check_current().is_err())
            || self
                .continue_review
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .continue_ready
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .setup
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .signer_review
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .signer_ready
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .witness_review
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .witness_armed
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .witness_ready
                .as_ref()
                .is_some_and(|t| t.check_current().is_err())
            || self
                .continue_deadline
                .is_some_and(|end| Instant::now() >= end)
        {
            self.revoke("An original actor, source or review is no longer current. No new approval is possible; disposal is pending.");
        }
    }
    fn interrupt(&mut self, facts: Option<RawFacts>, ctx: &egui::Context) {
        let Some(facts) = facts else {
            self.revoke("The original root viewport is unavailable. Disposal is pending.");
            return;
        };
        if must_revoke(
            self.focus_seen,
            self.focused_last,
            facts.focused,
            facts.blur,
            facts.escape,
        ) {
            self.revoke("Native interruption permanently restricted this workflow. Returning focus cannot restore it.");
        }
        self.focus_seen |= facts.focused;
        self.focused_last = facts.focused;
        if facts.close && (self.phase != Phase::Finished || !self.host_output_ended) {
            self.close_when_done = true;
            if self.phase != Phase::Finished {
                self.revoke(
                    "Close requested. Waiting for actual source disposal and owned cleanup.",
                );
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }
    fn poll_driver(&mut self, ctx: &egui::Context) {
        for _ in 0..32 {
            let outcome = self.driver.borrow().outcome.try_recv();
            match outcome {
                Ok(Outcome::Event(Event::Disposed(role))) => self.disposed[index(role)] = true,
                Ok(Outcome::Finished {
                    disposal_confirmed,
                    clean,
                }) => {
                    self.native.revoke();
                    if let Some(input) = &mut self.host_input {
                        input.cancel(&mut || self.native.revoke());
                    }
                    self.host_entry = HostEntry::Closed;
                    self.host_incomplete = true;
                    if let Some(input) = &mut self.password {
                        input.cancel();
                    }
                    self.clear_review();
                    self.phase = Phase::Finished;
                    self.message = if clean
                        && disposal_confirmed
                        && self.disposed == [true; 2]
                        && self.witness_closed == [true; 2]
                        && self.history_closed == [true; 2]
                        && self.signing_closed == [true; 2]
                    {
                        "Both original Signer sources reported disposal and the owned tree cleanup completed. This is not a payment outcome."
                    } else {
                        "Cleanup ended without complete confirmed source disposal. Do not retry or assume all source work was rolled back."
                    };
                }
                Ok(Outcome::DisposalStarted) => self
                    .revoke("Source disposal is pending. Cancel does not prove completed cleanup."),
                Ok(Outcome::Event(Event::Failed { role, stage })) => {
                    self.first_failure.get_or_insert((role, stage));
                    self.revoke("The original role reported a bounded failure. Disposal is pending; there is no automatic retry.");
                }
                Ok(Outcome::Event(Event::Restricted(_))) => {
                    self.revoke("An original role observed a restriction. Disposal is pending.")
                }
                Ok(Outcome::Event(Event::AwaitingAdmission { role, data })) => {
                    if self
                        .observe_saved(role, data, ctx.cumulative_frame_nr())
                        .is_err()
                    {
                        self.revoke("The actual saved-continuation observation did not match this role's admitted request.");
                    }
                }
                Ok(Outcome::Event(Event::ContinueOutcome { role, data })) => {
                    if self.observe_continue_outcome(role, data).is_err() {
                        self.revoke("The actual Continue outcome was inconsistent. No retry or new approval is allowed.");
                    } else {
                        self.revoke("An actual Continue outcome was received. See the retained role outcome; cancellation does not imply rollback.");
                    }
                }
                Ok(Outcome::Event(Event::AwaitingNextRead { role, data })) => {
                    if self
                        .observe_admitted(role, data, ctx.cumulative_frame_nr())
                        .is_err()
                    {
                        self.revoke("The authenticated Signer admission result changed. No retry is allowed.");
                    }
                }
                Ok(Outcome::Event(Event::AdmitOutcome { role, data })) => {
                    if self.observe_admit_outcome(role, data).is_err() {
                        self.revoke("The authenticated Signer admission outcome changed.");
                    } else {
                        self.revoke("Signer admission ended without a confirmed commit. Its actual outcome is retained separately from cleanup.");
                    }
                }
                Ok(Outcome::SigningDisposed(role)) => self.signing_disposed[index(role)] = true,
                Ok(Outcome::SigningClosed(role)) => self.signing_closed[index(role)] = true,
                Ok(Outcome::SigningFailed(_)) => self.revoke("An original Signing role reported failure or restriction during cleanup. This is not a service-ready or financial outcome."),
                Ok(Outcome::SigningPredecessorRetirement(ticket)) => {
                    let role = ticket.role();
                    if self.terminal() { drop(ticket); }
                    else if self.active != Some(role) || !self.witness_disposed[index(role)]
                        || !matches!(self.phase, Phase::AdmissionReview | Phase::RetirementBlocked)
                        || self.history_retirement.is_some() || self.retirement_paused.is_some() {
                        self.revoke("Unexpected Signing predecessor retirement ticket."); drop(ticket);
                    } else {
                        self.transition(Phase::RetirementBlocked, ctx.cumulative_frame_nr());
                        self.history_retirement = Some(ticket);
                    }
                }
                Ok(Outcome::SigningPredecessorRetired(completion)) => {
                    let role = completion.role();
                    if self.terminal() { drop(completion); }
                    else if self.phase != Phase::RetirementBlocked || self.active != Some(role)
                        || self.retirement_paused.is_none_or(|(expected, _)| expected != role)
                        || self.history_retired.is_some() {
                        self.revoke("Unexpected Signing predecessor completion."); drop(completion);
                    } else { self.history_retired = Some(completion); }
                }
                Ok(Outcome::SigningPredecessorResumed(role)) => {
                    if !self.terminal() {
                        if self.phase != Phase::RetirementBlocked || self.active != Some(role)
                            || self.retirement_paused.is_some() || self.history_resume_pending != Some(role) {
                            self.revoke("Signing predecessor resume changed.");
                        } else {
                            self.history_resume_pending = None;
                            self.witness_closed[index(role)] = true;
                            self.writer_transition(WriterStage::SetupNeeded, ctx.cumulative_frame_nr());
                            self.message = "The actual predecessor is retired. Signing Setup, serving, Writer Read and Acquire each remain separate explicit approvals.";
                        }
                    }
                }
                Ok(Outcome::HistoryRetirement(ticket)) => {
                    let role = ticket.role();
                    if self.terminal() { drop(ticket); }
                    else if self.phase != Phase::HistoryRetiring || self.active != Some(role)
                        || !self.history_disposed[index(role)] || self.history_retirement.is_some()
                        || self.retirement_paused.is_some() || self.history_resume_pending.is_some()
                    {
                        self.revoke("Unexpected original History retirement ticket.");
                        drop(ticket);
                    } else { self.history_retirement = Some(ticket); }
                }
                Ok(Outcome::HistoryRetired(completion)) => {
                    let role = completion.role();
                    if self.terminal() { drop(completion); }
                    else if self.phase != Phase::HistoryRetiring || self.active != Some(role)
                        || self.retirement_paused.is_none_or(|(expected, _)| expected != role)
                        || self.history_retired.is_some()
                    {
                        self.revoke("Unexpected original History retirement completion.");
                        drop(completion);
                    } else { self.history_retired = Some(completion); }
                }
                Ok(Outcome::HistoryResumed(role)) => {
                    if !self.terminal() {
                        if self.phase != Phase::HistoryRetiring || self.active != Some(role)
                            || self.retirement_paused.is_some() || self.history_resume_pending != Some(role)
                        { self.revoke("History resume did not match actual native completion."); }
                        else {
                            self.history_resume_pending = None;
                            self.history_closed[index(role)] = true;
                            self.transition(Phase::HistoryReady, ctx.cumulative_frame_nr());
                            self.message = "The original History service was disposed and normally retired, with matching Host and native resume. The already-prepared Continue remains a separate approval under its unchanged deadline.";
                        }
                    }
                }
                Ok(Outcome::History(event)) => {
                    if self.accept_history_event(event, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("The exact original History service event changed. No Read or retry is allowed.");
                    }
                }
                Ok(Outcome::HistorySetup(_, ticket)) if self.terminal() => { drop(ticket); }
                Ok(Outcome::HistorySetup(role, ticket)) => {
                    if self.accept_history_setup(role, ticket, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("The original History Setup selection or Read binding changed.");
                    }
                }
                Ok(Outcome::Witness(event)) => {
                    if self
                        .accept_witness_event(event, ctx.cumulative_frame_nr())
                        .is_err()
                    {
                        self.revoke("The exact Witness event could not be matched. Any admitted append remains unconfirmed until its authenticated outcome.");
                    }
                }
                Ok(Outcome::WitnessSetup(_, ticket)) if self.terminal() => {
                    drop(ticket);
                }
                Ok(Outcome::WitnessSetup(role, ticket)) => {
                    if self
                        .accept_setup(role, ticket, ctx.cumulative_frame_nr())
                        .is_err()
                    {
                        self.revoke("The original Witness Setup selection changed or expired.");
                    }
                }
                Ok(Outcome::Event(event @ (Event::WriterReadDisplay(_) | Event::WriterReadFailed { .. }
                    | Event::AcquireDisplay(_) | Event::AcquireReady(_) | Event::AcquireOutcome { .. }
                    | Event::AwaitingActivateRead { .. }))) => {
                    if self.accept_writer(event, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("Original Writer Read / Acquire event changed. No retry is permitted.");
                    }
                }
                Ok(Outcome::Event(Event::V3SourceOpened { role, data })) => {
                    let i = index(role);
                    if data.validate().is_err() || self.v3_opened[i] || self.v3_source_result[i].is_some() || self.v3_display[i].as_ref().is_none_or(|p| p.presentation_digest != data.entry_presentation_digest) {
                        self.revoke("Original V3 source-open observation changed.");
                    } else {
                        self.v3_source_result[i] = Some(data);
                        self.v3_opened[i] = true;
                        if !self.terminal() {
                            if self.phase != Phase::V3Opening || self.active != Some(role) {
                                self.revoke("V3 source opened outside its actual admitted attempt.");
                            } else {
                                self.transition(Phase::V3Held, ctx.cumulative_frame_nr());
                                self.message = "Original V3 account and journal opened under the distinct Entry. No Prepare Read, receive, admission, history audit or financial Entry has been approved.";
                            }
                        }
                    }
                }
                Ok(Outcome::Event(Event::V3SourceEntryFailed { role, presentation_digest })) => {
                    let i = index(role);
                    if self.v3_selection[i].is_none() || presentation_digest.as_ref().is_some_and(|d| self.v3_display[i].as_ref().is_some_and(|p| &p.presentation_digest != d)) {
                        self.revoke("Original V3 source failure binding changed.");
                    } else {
                        self.v3_failed[i] = true;
                        self.revoke("Original V3 Entry failed or was restricted. No retry, completed source disposal or later authority is inferred.");
                    }
                }
                Ok(Outcome::Event(event @ (Event::V3PairEndpoint { .. } | Event::V3PairDisplay(_) | Event::V3Paired { .. }))) => {
                    if self.accept_v3_pair(event, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("Original V3 Pair binding changed. No retry or historical grant substitution.");
                    }
                }
                Ok(Outcome::Event(event @ (Event::V3EnrollmentDisplay(_) | Event::V3Enrolled { .. }))) => {
                    if self.accept_v3_enrollment(event, ctx.cumulative_frame_nr()).is_err() { self.revoke("Fresh enrollment binding changed; no retry or rollback inferred."); }
                }
                Ok(Outcome::Event(event @ (Event::V3ManifestDisplay(_) | Event::V3ManifestAccepted { .. }))) => {
                    if self.accept_v3_manifest(event, ctx.cumulative_frame_nr()).is_err() { self.revoke("Fresh manifest binding changed; no retry or rollback inferred."); }
                }
                Ok(Outcome::Event(event @ (Event::V3RedisclosureReadDisplay(_) | Event::V3RedisclosurePrepared { .. }))) => {
                    if self.accept_v3_redisclosure_read(event, ctx.cumulative_frame_nr()).is_err() { self.revoke("Original redisclosure binding changed; no retry or rollback inferred."); }
                }
                Ok(Outcome::Event(event @ (Event::V3RediscloseDisplay(_) | Event::V3Redisclosed { .. }))) => {
                    if self.accept_v3_redisclose(event, ctx.cumulative_frame_nr()).is_err() { self.revoke("Original redisclosure binding changed; no retry or rollback inferred."); }
                }
                Ok(Outcome::Event(event @ (Event::V3PrepareReadDisplay(_) | Event::V3Prepared { .. }))) => {
                    if self.accept_v3_prepare_read(event, ctx.cumulative_frame_nr()).is_err() { self.revoke("Original delivery binding changed; no retry or rollback inferred."); }
                }
                Ok(Outcome::Event(event @ (Event::V3ReceiveDisplay(_) | Event::V3Received { .. }))) => {
                    if self.accept_v3_receive(event, ctx.cumulative_frame_nr()).is_err() { self.revoke("Original delivery binding changed; no retry or rollback inferred."); }
                }
                Ok(Outcome::Event(event @ (Event::ActivateReadDisplay(_) | Event::ActivateReadFailed { .. } | Event::ActivateDisplay(_) | Event::ActivateReady(_) | Event::ActivateOutcome { .. } | Event::AwaitingWalletPrepare { .. }))) => {
                    if self.accept_activate(event,ctx.cumulative_frame_nr()).is_err() { self.revoke("Original Activate custody/binding changed; no retry or wallet grant."); }
                }
                Ok(Outcome::Event(event)) if self.terminal() => {
                    drop(event);
                }
                Ok(Outcome::Event(Event::AdmitDisplay(ticket))) => {
                    if self.accept_admit(ticket).is_err() {
                        self.revoke("The exact separate Signer Admit display changed or expired.");
                    }
                }
                Ok(Outcome::Event(Event::AdmitReady(ticket))) => {
                    if self.accept_admit_ready(ticket).is_err() {
                        self.revoke("The original Signer Admit Ready changed or expired.");
                    }
                }
                Ok(Outcome::Event(Event::V3SourceEntryOffer(offer))) => {
                    if self.accept_v3_entry(offer, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("The exact original V3 Entry offer changed or expired.");
                    }
                }
                Ok(Outcome::Event(Event::SourceEntryOffer(offer))) => {
                    if self.accept_entry(offer, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("The exact original source-entry offer could not be accepted.");
                    }
                }
                Ok(Outcome::Event(Event::SourceRetained(role))) => {
                    if self.active != Some(role)
                        || self.phase != Phase::Opening
                        || self.progress[index(role)] != Progress::Working
                    {
                        self.revoke(
                            "Unexpected source-retention observation. No new review is allowed.",
                        );
                    } else {
                        self.progress[index(role)] = Progress::SourceRetained;
                        self.message = "The original source is open. Owner history Read plus one immutable local Continue preparation still require their own exact review and approval.";
                    }
                }
                Ok(Outcome::Event(Event::InitialReadOffer(ticket))) => {
                    if self.accept_read(ticket, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("The exact original history-Read / local-preparation offer could not be accepted.");
                    }
                }
                Ok(Outcome::Event(Event::HistoryRetained {
                    role,
                    continue_deadline,
                })) => {
                    if self.active != Some(role) || self.phase != Phase::Reading {
                        self.revoke(
                            "Unexpected history-retention observation. No new action is allowed.",
                        );
                    } else {
                        self.progress[index(role)] = Progress::HistoryRetained;
                        self.clear_review();
                        self.continue_deadline = Some(continue_deadline);
                        self.transition(Phase::HistoryRetiring, ctx.cumulative_frame_nr());
                        self.message = "The Signer retained history and one immutable Continue preparation. Waiting for the original History service's actual disposal and owned retirement; Continue is not yet enabled.";
                    }
                }
                Ok(Outcome::Event(Event::ContinueDisplay(ticket))) => {
                    if self
                        .accept_continue(ticket, ctx.cumulative_frame_nr())
                        .is_err()
                    {
                        self.revoke(
                            "The exact retained Continue presentation was unavailable or changed.",
                        );
                    }
                }
                Ok(Outcome::Event(Event::ContinueReady(ticket))) => {
                    if self.accept_ready(ticket).is_err() {
                        self.revoke(
                            "The exact retained Continue Ready was unavailable or changed.",
                        );
                    }
                }
                Ok(Outcome::SigningSetup(role, ticket)) => {
                    if self.accept_signing_setup(role, ticket, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("Original Signing Setup changed or expired.");
                    }
                }
                Ok(Outcome::Signing(event)) => {
                    if self.accept_signing(event, ctx.cumulative_frame_nr()).is_err() {
                        self.revoke("Original Signing service changed or expired.");
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if self.phase != Phase::Finished {
                        self.revoke(
                            "The owned driver ended without a complete cleanup observation.",
                        );
                    }
                    break;
                }
            }
        }
        self.poll_host();
        if self.close_when_done && self.phase == Phase::Finished && self.host_output_ended {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
    fn poll_host(&mut self) {
        // The security channel was processed first. Hidden Host observations
        // remain bounded/retained; no review phase discards them as success.
        if !self.host_output_ended {
            for _ in 0..4 {
                let chunk = self.driver.borrow().host_output.try_recv();
                match chunk {
                    Ok(chunk) => {
                        if self.host_output.state() == OutputState::Open {
                            if self.host_output.push_chunk(chunk).is_err() {
                                self.revoke("Host output exceeded its fixed safe bounds. The retained prefix is incomplete; no Host effect is established.");
                                self.host_incomplete = true;
                            }
                        } else {
                            drop(chunk);
                        } // Already visibly failed, never a complete stream.
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.host_output_ended = true;
                        if self.host_output.state() == OutputState::Open
                            && self.host_output.finish_eof().is_err()
                        {
                            self.host_incomplete = true;
                        }
                        if !self.terminal() {
                            self.revoke("Host transport ended. Its output is incomplete observation, not an action result; original security cleanup remains separate.");
                        }
                        break;
                    }
                }
            }
        }
        for _ in 0..3 {
            let status = self.driver.borrow_mut().try_host_status();
            match status {
                Ok(Some(HostStatus::LineWritten(ordinal))) => {
                    if self.host_entry == HostEntry::Writing(ordinal) && !self.terminal() {
                        // Completion only means bytes were accepted by the
                        // genuine PTY. It is NOT a Host effect/approval outcome.
                        self.host_entry = HostEntry::Idle;
                        self.host_input.take(); // Already submitted/empty; no live editor.
                    } else if !self.terminal() {
                        self.revoke("Unexpected Host write observation. No new input or approval is possible.");
                    }
                }
                Ok(Some(HostStatus::Closed)) => {
                    self.host_incomplete = true;
                    if !self.terminal() {
                        self.revoke("Host terminal closed or failed. The security driver is still responsible for admitted outcomes and bounded disposal.");
                    }
                    self.host_entry = HostEntry::Closed;
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    if !self.terminal() {
                        self.revoke("Host transport status ended. Do not infer success, rollback or retry from its retained output.");
                    }
                    self.host_entry = HostEntry::Closed;
                    break;
                }
            }
        }
    }
    fn draw_host(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        ui.heading("Actual Host terminal · observation only");
        ui.label("Host text cannot approve a coordinator review. Controls, invalid bytes and literal backslashes are shown as escapes; no terminal sequences are executed.");
        if self.host_incomplete {
            ui.strong("INCOMPLETE HOST OUTPUT: this prefix is not proof of an effect, rollback, disposal or successful completion.");
        }
        egui::ScrollArea::vertical()
            .id_salt("original-host-output")
            .max_height(240.0)
            .show(ui, |ui| {
                ui.monospace(self.host_output.text());
            });
        match self.host_entry {
            HostEntry::Idle if host_phase_allows_input(self.phase) => {
                ui.label("Enter only your own next Host line. Every line is protected, including empty/short replies; there is no prompt inference, history, automatic answer or local echo.");
                if ui
                    .button("Enter one Host line")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.intent = Some(Intent::BeginHostLine);
                }
            }
            HostEntry::Editing(ordinal) => {
                ui.label("The coordinator briefly sees this line. Owned input is zeroized; complete GUI/OS/IME/clipboard erasure is not guaranteed. Source controls are unavailable until this line ends.");
                if let Some(input) = &mut self.host_input {
                    input.show(ui, ordinal, &mut || self.native.revoke());
                }
                if self.host_input.as_ref().is_none_or(|input| {
                    !matches!(
                        input.status(),
                        HostLineStatus::WaitingForFocus | HostLineStatus::Editing
                    )
                }) {
                    self.revoke("Host line entry was interrupted or invalid. The original workflow is restricted; there is no resubmission.");
                }
            }
            HostEntry::Writing(_) => {
                ui.label("One exact user line is still being written. Source controls and another line remain unavailable; already accepted bytes cannot be recalled.");
            }
            _ => {}
        }
    }
    fn accept_entry(&mut self, offer: SignerSourceEntryOfferV1, frame: u64) -> Result<()> {
        offer.check_current()?;
        offer.presentation().validate()?;
        let role = offer.presentation().actor.signer_role;
        if !self.focused_last
            || self.phase != Phase::Preparing
            || self.active != Some(role)
            || self.entry.is_some()
        {
            return Err(rejected("unsolicited source-entry offer"));
        }
        let digest = offer.request_digest()?;
        let binding = RequestBinding::new(input_role(role), &digest)
            .ok_or_else(|| rejected("source-entry input digest invalid"))?;
        self.entry = Some(offer);
        self.binding = Some(binding);
        self.request_digest = digest;
        self.transition(Phase::EntryReview, frame);
        self.message = "Review the complete original source, role, disclosure and expiry before entering its password.";
        Ok(())
    }
    fn accept_read(&mut self, ticket: SignerFinancialReadTicketV1, frame: u64) -> Result<()> {
        ticket.check_current()?;
        ticket.presentation().validate()?;
        if !read_scope_matches(
            ticket.presentation().version,
            &ticket.presentation().purpose,
        ) {
            return Err(rejected("unsupported initial Read consent scope"));
        }
        let role = ticket.presentation().actor.signer_role;
        if !self.focused_last
            || self.phase != Phase::Opening
            || self.active != Some(role)
            || self.progress[index(role)] != Progress::SourceRetained
            || self.read.is_some()
        {
            return Err(rejected("unsolicited initial Read offer"));
        }
        self.read = Some(ticket);
        self.transition(Phase::HistorySetupNeeded, frame);
        self.message = "Unlocking did not authorize history Read. The original Witness first needs separate exact Setup and owner-only Serve approvals; the Signer Read approval remains separate.";
        Ok(())
    }
    fn accept_history_setup(
        &mut self,
        role: Role,
        ticket: FinancialHistorySetupTicketV1,
        frame: u64,
    ) -> Result<()> {
        ticket.check_current()?;
        let read = self
            .read
            .as_ref()
            .ok_or_else(|| rejected("History Setup without Read"))?;
        read.check_current()?;
        if !self.focused_last
            || self.active != Some(role)
            || self.phase != Phase::HistorySetupPreparing
            || self.history_setup.is_some()
            || ticket.inputs() != &history_inputs(&self.selectors[index(role)])?
            || ticket.read_binding().read != *read.presentation()
            || ticket.native_deadline() > read.native_deadline()
        {
            return Err(rejected("History Setup original selection changed"));
        }
        self.history_setup = Some(ticket);
        self.transition(Phase::HistorySetupReview, frame);
        Ok(())
    }
    fn accept_history_event(&mut self, event: HistoryEvent, frame: u64) -> Result<()> {
        // Terminal observations remain visible after cancellation. They never
        // establish reaping or make a later Witness purpose available.
        match event {
            HistoryEvent::Disposed(role) => {
                self.history_disposed[index(role)] = true;
                return Ok(());
            }
            HistoryEvent::PurposeClosed(role) => {
                self.history_closed[index(role)] = true;
                return Ok(());
            }
            HistoryEvent::PreparationFailed(_)
            | HistoryEvent::ServiceFailed(_)
            | HistoryEvent::Restricted(_) => {
                self.revoke("The original History service failed or became restricted. Actual source disposal and owned retirement remain separate.");
                return Ok(());
            }
            _ => {}
        }
        if self.terminal() {
            drop(event);
            return Ok(());
        }
        match event {
            HistoryEvent::Display(ticket) => {
                ticket.check_current()?;
                let p = ticket.presentation();
                p.validate()?;
                let role = p.read_binding.read.actor.signer_role;
                let read = self
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("History display without Read"))?;
                read.check_current()?;
                if !self.focused_last
                    || self.active != Some(role)
                    || self.phase != Phase::HistoryPreparing
                    || self.history_review.is_some()
                    || self.history_display[index(role)].is_some()
                    || p.read_binding.read != *read.presentation()
                    || p.network_profile_id != self.selectors[index(role)].network_profile_id
                    || ticket.native_deadline() > read.native_deadline()
                {
                    return Err(rejected("History display original Read changed"));
                }
                self.history_display[index(role)] = Some(p.clone());
                self.history_review = Some(ticket);
                self.transition(Phase::HistoryReview, frame);
            }
            HistoryEvent::Serving(serving) => {
                serving.check_current()?;
                let p = serving.presentation();
                let role = p.read_binding.read.actor.signer_role;
                let read = self
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("History Serving without Read"))?;
                read.check_current()?;
                if !self.focused_last
                    || self.active != Some(role)
                    || self.phase != Phase::HistoryStarting
                    || self.history_serving.is_some()
                    || self.history_display[index(role)].as_ref() != Some(p)
                    || p.read_binding.read != *read.presentation()
                    || serving.native_deadline() > read.native_deadline()
                {
                    return Err(rejected("History Serving original review changed"));
                }
                self.history_serving = Some(serving);
                self.transition(Phase::ReadReview, frame);
                self.message = "The actual original Witness is serving this one owner-only history. Review and approve the distinct Signer Read plus one local Continue preparation; no mutation is approved.";
            }
            _ => unreachable!("terminal History observations handled above"),
        }
        Ok(())
    }
    fn accept_continue(
        &mut self,
        ticket: FinancialContinueReviewTicketV1,
        frame: u64,
    ) -> Result<()> {
        ticket.check_current()?;
        let p = ticket.presentation();
        p.validate()?;
        let role = p.review.signer_role;
        if !self.focused_last
            || self.phase != Phase::ContinuePreparing
            || self.active != Some(role)
            || self.progress[index(role)] != Progress::HistoryRetained
            || self.continuation.is_some()
            || self.continue_expected[index(role)].is_some()
            || !retained_deadline_accepts(self.continue_deadline, ticket.native_deadline())
        {
            return Err(rejected("unsolicited full Continue display"));
        }
        self.continue_expected[index(role)] =
            Some((p.presentation_digest.clone(), p.prepared_digest.clone()));
        self.retained_continue[index(role)] = Some(p.clone()); // Exact request bytes for later Setup, never an authority.
        self.continuation = Some(p.clone()); // Public display data, not a ticket or grant.
        self.continue_deadline = Some(ticket.native_deadline());
        self.continue_review = Some(ticket);
        self.transition(Phase::ContinueReview, frame);
        self.message = "Review this one immutable local Continue request. Its original preparation-time deadline is not renewed here; Admit is separate.";
        Ok(())
    }
    fn accept_ready(&mut self, ticket: FinancialContinueReadyTicketV1) -> Result<()> {
        ticket.check_current()?;
        if !self.focused_last
            || self.phase != Phase::ContinueArmed
            || self.continue_ready.is_some()
            || self.active != Some(ticket.presentation().review.signer_role)
            || self.continuation.as_ref() != Some(ticket.presentation())
            || self.continue_deadline != Some(ticket.native_deadline())
        {
            return Err(rejected("full Continue Ready changed"));
        }
        self.continue_ready = Some(ticket);
        Ok(())
    }
    fn observe_saved(
        &mut self,
        role: Role,
        data: SignerContinuationSavedV1,
        frame: u64,
    ) -> Result<()> {
        data.validate()?;
        let i = index(role);
        if self.continue_effect[i] != ContinueEffect::Pending
            || self.saved[i].is_some()
            || !matches_commitment(
                self.continue_expected[i].as_ref(),
                &data.presentation_digest,
                &data.prepared_digest,
            )
        {
            return Err(rejected("unsolicited saved continuation"));
        }
        self.saved[i] = Some(data);
        self.continue_effect[i] = ContinueEffect::Saved;
        self.progress[i] = Progress::AwaitingAdmission;
        if !self.terminal() {
            if self.active != Some(role) || self.phase != Phase::Continuing {
                return Err(rejected("saved continuation outside active role"));
            }
            self.clear_review();
            self.transition(Phase::SetupNeeded, frame);
            self.message = "The original Signer reports its continuation saved. This is nonterminal custody awaiting separate financial Admit, not payment completion.";
        }
        Ok(())
    }
    fn observe_continue_outcome(
        &mut self,
        role: Role,
        data: SignerContinueOutcomeV1,
    ) -> Result<()> {
        let (effect, presentation, prepared) = match data {
            SignerContinueOutcomeV1::KnownNoEffect {
                presentation_digest,
                prepared_digest,
            } => (
                ContinueEffect::KnownNoEffect,
                presentation_digest,
                prepared_digest,
            ),
            SignerContinueOutcomeV1::Uncertain {
                presentation_digest,
                prepared_digest,
            } => (
                ContinueEffect::Uncertain,
                presentation_digest,
                prepared_digest,
            ),
            SignerContinueOutcomeV1::Continued { .. } => {
                return Err(rejected(
                    "saved continuation requires actual saved observation",
                ))
            }
        };
        let i = index(role);
        if !matches!(
            self.continue_effect[i],
            ContinueEffect::None | ContinueEffect::Pending
        ) || self.continue_expected[i].as_ref().is_some_and(|_| {
            !matches_commitment(self.continue_expected[i].as_ref(), &presentation, &prepared)
        }) {
            return Err(rejected("duplicate or changed Continue outcome"));
        }
        // Endpoint authenticated the original binding even if R caused its
        // queued display to be dropped before this window accepted it.
        self.continue_expected[i] = Some((presentation, prepared));
        self.continue_effect[i] = effect;
        Ok(())
    }
    fn accept_setup(
        &mut self,
        role: Role,
        ticket: FinancialWitnessSetupTicketV1,
        frame: u64,
    ) -> Result<()> {
        ticket.check_current()?;
        let retained = self.retained_continue[index(role)]
            .as_ref()
            .ok_or_else(|| rejected("Setup has no exact Continue"))?;
        let mut expected = self.selectors[index(role)].clone();
        expected.request_json = retained.request_json.clone();
        if self.active != Some(role)
            || self.phase != Phase::SetupPreparing
            || self.setup.is_some()
            || ticket.inputs() != &expected
            || ticket.continuation().actor.signer_role != role
            || ticket.continuation().continue_presentation_digest != retained.presentation_digest
            || ticket.continuation().prepared_digest != retained.prepared_digest
            || ticket.continuation().request_json != retained.request_json
        {
            return Err(rejected("Setup selection or actual request changed"));
        }
        self.setup = Some(ticket);
        self.transition(Phase::SetupReview, frame);
        Ok(())
    }
    fn accept_admit(&mut self, ticket: SignerAdmitReviewTicketV1) -> Result<()> {
        ticket.check_current()?;
        let p = ticket.presentation();
        p.validate()?;
        let role = p.actor.signer_role;
        let i = index(role);
        let c = self.retained_continue[i]
            .as_ref()
            .ok_or_else(|| rejected("Admit without retained Continue"))?;
        if self.active != Some(role)
            || self.progress[i] != Progress::AwaitingAdmission
            || self.signer_display[i].is_some()
            || self.signer_review.is_some()
            || p.continue_presentation_digest != c.presentation_digest
            || p.prepared_digest != c.prepared_digest
            || p.facts.request_json != c.request_json
            || p.facts.request_digest != c.request_digest
        {
            return Err(rejected("Admit exact retained request changed"));
        }
        self.signer_display[i] = Some(p.clone());
        self.signer_review = Some(ticket);
        Ok(())
    }
    fn accept_admit_ready(&mut self, ticket: SignerAdmitReadyTicketV1) -> Result<()> {
        ticket.check_current()?;
        let role = ticket.presentation().actor.signer_role;
        let i = index(role);
        if self.phase != Phase::AdmissionReview
            || self.active != Some(role)
            || !self.signer_arm_sent
            || self.signer_ready.is_some()
            || self.signer_ready_digest[i].is_some()
            || self.signer_display[i].as_ref() != Some(ticket.presentation())
        {
            return Err(rejected("Signer Ready changed"));
        }
        self.signer_ready_digest[i] = Some(ticket.admission_ready_digest().to_owned());
        self.signer_ready = Some(ticket);
        Ok(())
    }
    fn accept_witness_event(&mut self, event: WitnessEvent, frame: u64) -> Result<()> {
        // Authenticated terminal observations remain live after UI clearing/R.
        match event {
            WitnessEvent::Outcome { role, data } => {
                return self.observe_witness_outcome(role, data, frame)
            }
            WitnessEvent::Disposed(role) => {
                self.witness_disposed[index(role)] = true;
                return Ok(());
            }
            WitnessEvent::PurposeClosed(role) => {
                self.witness_closed[index(role)] = true;
                return Ok(());
            }
            WitnessEvent::FirstFailure { role, data } => {
                if self.witness_failure[index(role)].is_some() {
                    return Err(rejected("duplicate Witness failure"));
                }
                self.witness_failure[index(role)] = Some(data);
                self.revoke("The original Witness reported a typed first failure. Its actual effect and cleanup remain separate.");
                return Ok(());
            }
            WitnessEvent::PreparationFailed(_) | WitnessEvent::Restricted(_) => {
                self.revoke("The original Witness reported failure or restriction. Its actual effect outcome and disposal remain separate.");
                return Ok(());
            }
            event if self.terminal() => {
                drop(event);
                return Ok(());
            }
            WitnessEvent::Display(ticket) => {
                ticket.check_current()?;
                let p = ticket.presentation();
                p.validate()?;
                let role = p.continuation.actor.signer_role;
                let i = index(role);
                let c = self.retained_continue[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Witness has no retained Continue"))?;
                if self.phase != Phase::AdmissionReview
                    || self.active != Some(role)
                    || self.witness_display[i].is_some()
                    || p.continuation.continue_presentation_digest != c.presentation_digest
                    || p.continuation.prepared_digest != c.prepared_digest
                    || p.continuation.request_json != c.request_json
                    || p.continuation.request_digest != c.request_digest
                {
                    return Err(rejected("Witness actual display changed"));
                }
                self.witness_display[i] = Some(p.clone());
                self.witness_review = Some(ticket);
                // Both displays must have been painted at least once before Arm.
                self.phase_frame = frame;
            }
            WitnessEvent::Armed(armed) => {
                armed.check_current()?;
                let role = armed.presentation().continuation.actor.signer_role;
                if self.phase != Phase::AdmissionReview
                    || self.active != Some(role)
                    || !self.witness_arm_sent
                    || self.witness_armed.is_some()
                    || self.witness_display[index(role)].as_ref() != Some(armed.presentation())
                {
                    return Err(rejected("Witness Armed changed"));
                }
                self.witness_armed = Some(armed);
            }
            WitnessEvent::Ready(ticket) => {
                ticket.check_current()?;
                let role = ticket.presentation().continuation.actor.signer_role;
                let i = index(role);
                if self.phase != Phase::AdmissionReview
                    || self.active != Some(role)
                    || self.signer_effect[i] != AdmissionEffect::Pending
                    || !self.witness_arm_sent
                    || self.witness_ready.is_some()
                    || self.witness_ready_data[i].is_some()
                    || self.witness_display[i].as_ref() != Some(ticket.presentation())
                {
                    return Err(rejected("Witness Ready changed"));
                }
                self.witness_ready_data[i] = Some(ticket.ready().clone());
                self.witness_ready = Some(ticket);
            }
        }
        Ok(())
    }
    fn draw_admission(
        &mut self,
        ui: &mut egui::Ui,
        visible: bool,
        later: bool,
        consent: &mut PairedConsent,
    ) {
        let Some(role) = self.active else {
            return;
        };
        let i = index(role);
        ui.heading(format!(
            "{} · Separate Signer Admit and Witness append",
            role_name(role)
        ));
        ui.label("Read both complete exact actions. Each requires its own explicit approval. Neither saved Continue nor Setup approves either action. After both approvals, the actual matching Ready rendezvous may proceed on this visible surface without another prompt during the original accepted TLS interval.");
        ui.columns(2, |columns| {
            columns[0].heading("Signer Admit · owner-authenticated transport");
            if let Some(p) = &self.signer_display[i] {
                columns[0].label(format!(
                    "Original Admit expiry (Unix ms): {}",
                    p.facts.expires_at_ms
                ));
                let full = format!(
                    "{}\n\nComplete authenticated Signer Admit presentation:\n{p:#?}",
                    p.facts.display
                );
                if review_display(&mut columns[0], &full, visible) {
                    consent.read[0] = true;
                }
            } else {
                columns[0].label("Awaiting the actual original Signer Admit display.");
            }
            columns[1].heading("Witness · one exact local append");
            if let Some(p) = &self.witness_display[i] {
                columns[1].label(format!(
                    "Original Witness review expiry (Unix ms): {}",
                    p.expires_at_ms
                ));
                if review_display(&mut columns[1], &witness_display(p), visible) {
                    consent.read[1] = true;
                }
            } else {
                columns[1].label("Awaiting actual protected Setup and Witness display.");
            }
        });
        if let Some(ready) = &self.witness_ready_data[i] {
            ui.strong(format!("Original accepted TLS expiry (Unix ms): {}. No renewed interval or extra human prompt.", ready.accepted_tls_expires_at_ms));
            ui.label(format!(
                "Exact accepted effect commitment: {}",
                ready.effect_commitment
            ));
        }
        if self.phase == Phase::RetirementBlocked {
            ui.strong("Authenticated admission outcomes are retained. Normal continuation is blocked until actual prior-purpose disposal, foreground quiescence and owned retirement are joined. PurposeClosed alone is not retirement. Later writer-configuration Read is separately authorized.");
            return;
        }
        ui.add_enabled_ui(!self.signer_arm_sent, |ui| {
            ui.checkbox(&mut consent.acknowledged[0], "I reviewed the complete original Signer Admit request, owner/disclosure, exact head, source and expiry. I approve only this separate owner-authenticated admission transport.");
        });
        ui.add_enabled_ui(!self.witness_arm_sent, |ui| {
            ui.checkbox(&mut consent.acknowledged[1], "I reviewed the complete Witness request, owner, local storage/head and expiry. I approve this one exact append; later Cancel cannot promise rollback after native append admission.");
        });
        let both = paired_approved(self.paired)
            && later
            && self.signer_display[i].is_some()
            && self.witness_display[i].is_some();
        // Distinct buttons and one intent: one physical gesture never arms both.
        if ui
            .add_enabled(
                both && !self.signer_arm_sent,
                egui::Button::new("Approve this exact Signer Admit"),
            )
            .clicked_by(egui::PointerButton::Primary)
        {
            self.intent = Some(Intent::ArmSigner);
        }
        if ui
            .add_enabled(
                both && !self.witness_arm_sent,
                egui::Button::new("Approve this exact Witness append"),
            )
            .clicked_by(egui::PointerButton::Primary)
            && self.intent.is_none()
        {
            self.intent = Some(Intent::ArmWitness);
        }
        if self.signer_arm_sent || self.witness_arm_sent {
            ui.label("Original approvals are one-use. Actual matching Armed/Ready, clocks and same-cell restrictions are independently checked by the issuer, not these UI indicators.");
        }
    }
    fn admit_rendezvous(&mut self, _frame: u64) -> Result<()> {
        let role = self
            .active
            .ok_or_else(|| rejected("admission role missing"))?;
        let i = index(role);
        if !paired_approved(self.paired) || !self.signer_arm_sent || !self.witness_arm_sent {
            return Ok(());
        }
        if self.signer_ready.is_some()
            && self.witness_armed.is_some()
            && self.signer_effect[i] == AdmissionEffect::None
        {
            let ticket = self.signer_ready.take().expect("checked actual Ready");
            let outbound = self.native.admit_signer(
                ticket,
                self.witness_armed.as_ref().expect("checked actual Armed"),
            )?;
            // Ready legitimately replaces W Armed. This handle was check-only;
            // retaining it would spuriously restrict on that real transition.
            self.witness_armed.take();
            self.signer_effect[i] = AdmissionEffect::Pending;
            self.driver.borrow_mut().send_admit_final(role, outbound)?;
        }
        if let Some(ticket) = self.witness_ready.take() {
            let outbound = self.native.admit_witness(ticket)?;
            self.witness_effect[i] = AdmissionEffect::Pending; // Native A precedes queue; late R is not rollback.
            self.driver
                .borrow_mut()
                .send_witness_final(role, outbound)?;
        }
        Ok(())
    }
    fn observe_admitted(
        &mut self,
        role: Role,
        data: SignerAdmitCommittedV1,
        frame: u64,
    ) -> Result<()> {
        let i = index(role);
        let p = self.signer_display[i]
            .as_ref()
            .ok_or_else(|| rejected("Signer commit without display"))?;
        if self.signer_effect[i] != AdmissionEffect::Pending
            || self.signer_committed[i].is_some()
            || data.presentation_digest != p.presentation_digest
            || Some(&data.admission_ready_digest) != self.signer_ready_digest[i].as_ref()
            || data.request_digest != p.facts.request_digest
            || p.facts.expected_head_sequence.checked_add(1) != Some(data.head_sequence)
        {
            return Err(rejected("Signer authenticated commit mismatch"));
        }
        if let Some(FinancialWitnessOutcomeV1::Committed {
            head_sequence,
            head_digest,
            ..
        }) = &self.witness_outcome[i]
        {
            if *head_sequence != data.head_sequence || head_digest != &data.head_digest {
                return Err(rejected("authenticated role result heads differ"));
            }
        }
        self.signer_committed[i] = Some(data);
        self.signer_effect[i] = AdmissionEffect::Committed;
        self.progress[i] = Progress::AwaitingNextRead;
        self.maybe_wait_retirement(role, frame);
        Ok(())
    }
    fn observe_admit_outcome(&mut self, role: Role, data: SignerAdmitOutcomeV1) -> Result<()> {
        let i = index(role);
        let (presentation, ready, effect) = match &data {
            SignerAdmitOutcomeV1::KnownNoEffect {
                presentation_digest,
                admission_ready_digest,
            } => (
                presentation_digest,
                admission_ready_digest,
                AdmissionEffect::KnownNoEffect,
            ),
            SignerAdmitOutcomeV1::Uncertain {
                presentation_digest,
                admission_ready_digest,
            } => (
                presentation_digest,
                admission_ready_digest,
                AdmissionEffect::Uncertain,
            ),
        };
        if self.signer_outcome[i].is_some()
            || self.signer_committed[i].is_some()
            || self.signer_display[i]
                .as_ref()
                .is_some_and(|p| &p.presentation_digest != presentation)
            || self.signer_ready_digest[i]
                .as_ref()
                .is_some_and(|r| ready.as_ref() != Some(r))
        {
            return Err(rejected("Signer outcome changed"));
        }
        self.signer_outcome[i] = Some(data);
        self.signer_effect[i] = effect;
        Ok(())
    }
    fn observe_witness_outcome(
        &mut self,
        role: Role,
        data: FinancialWitnessOutcomeV1,
        frame: u64,
    ) -> Result<()> {
        let i = index(role);
        if self.witness_outcome[i].is_some() {
            return Err(rejected("duplicate Witness outcome"));
        }
        let (presentation, commitment, effect) = match &data {
            FinancialWitnessOutcomeV1::Committed {
                presentation_digest,
                effect_commitment,
                head_sequence,
                head_digest,
            } => {
                let p = self.witness_display[i]
                    .as_ref()
                    .ok_or_else(|| rejected("Witness commit without display"))?;
                if self.witness_effect[i] != AdmissionEffect::Pending
                    || p.expected_head_sequence.checked_add(1) != Some(*head_sequence)
                {
                    return Err(rejected("Witness commit without exact A"));
                }
                if let Some(committed) = &self.signer_committed[i] {
                    if committed.head_sequence != *head_sequence
                        || &committed.head_digest != head_digest
                    {
                        return Err(rejected("authenticated role result heads differ"));
                    }
                }
                (
                    presentation_digest,
                    Some(effect_commitment),
                    AdmissionEffect::Committed,
                )
            }
            FinancialWitnessOutcomeV1::KnownNoEffect {
                presentation_digest,
                effect_commitment,
            } => (
                presentation_digest,
                effect_commitment.as_ref(),
                AdmissionEffect::KnownNoEffect,
            ),
            FinancialWitnessOutcomeV1::Uncertain {
                presentation_digest,
                effect_commitment,
            } => (
                presentation_digest,
                effect_commitment.as_ref(),
                AdmissionEffect::Uncertain,
            ),
        };
        if self.witness_display[i]
            .as_ref()
            .is_some_and(|p| &p.presentation_digest != presentation)
            || self.witness_ready_data[i]
                .as_ref()
                .is_some_and(|r| commitment != Some(&r.effect_commitment))
        {
            return Err(rejected("Witness actual outcome changed"));
        }
        self.witness_outcome[i] = Some(data);
        self.witness_effect[i] = effect;
        if effect != AdmissionEffect::Committed {
            self.revoke("The actual Witness reported known-no-effect or uncertainty. Its outcome is retained; do not retry or infer rollback from cleanup.");
        }
        self.maybe_wait_retirement(role, frame);
        Ok(())
    }
    fn maybe_wait_retirement(&mut self, role: Role, frame: u64) {
        let i = index(role);
        if !self.terminal()
            && self.active == Some(role)
            && self.signer_effect[i] == AdmissionEffect::Committed
            && self.witness_effect[i] == AdmissionEffect::Committed
        {
            self.transition(Phase::RetirementBlocked, frame);
            self.message = "Actual matching Signer and Witness committed outcomes were observed. This is not final full-flow success; later Read and owned retirement remain separate.";
        }
    }
    fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let facts = ctx.input(|input| {
            raw_facts(&input.raw).map(|mut facts| {
                facts.focused &= input.focused;
                facts.blur |= input.events.iter().any(is_blur);
                facts.escape |= input.events.iter().any(is_escape);
                facts
            })
        });
        self.interrupt(facts, &ctx);
        self.check_current();
        self.poll_driver(&ctx);
        let frame = ctx.cumulative_frame_nr();
        let visible = ui.is_enabled() && ui.is_visible() && !ui.is_sizing_pass();
        let painted_phase = self.phase;
        // Consent progress is speculative until the final eligible tail. A
        // discarded/sizing/hidden/repeated pass cannot prime a later approval.
        let mut painted_to_end = self.read_to_end;
        let mut acknowledged_in_pass = self.acknowledged;
        let mut paired_in_pass = self.paired;
        let mut owner_in_pass = if self.phase == Phase::V3OwnerConfiguring {
            self.active
                .map(|role| self.v3_owner_text[index(role)].clone())
        } else {
            None
        };
        let mut v3_in_pass = if self.phase == Phase::V3Configuring {
            self.active
                .map(|role| self.v3_selection_text[index(role)].clone())
        } else {
            None
        };
        let mut selectors_in_pass = if self.phase == Phase::Configuring {
            self.active.map(|role| self.selectors[index(role)].clone())
        } else {
            None
        };
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Wholepact coordinator · Original Signer source");
            ui.label(self.message);
            for role in [Role::Signer1, Role::Signer2] {
                let i = index(role);
                let status = if self.v3_failed[i] { "Entry failure/restriction observed; no retry" }
                    else if self.v3_opened[i] { "actual account/journal open observed; later V3 work unapproved" }
                    else if self.v3_selection[i].is_some() { "exact initial selection sent; source-open result unconfirmed" }
                    else { "initial V3 source not selected" };
                ui.label(format!("{} V3: {}", role_name(role), status));
                if self.v3_enrollment_result[i].is_some() { ui.label("Fresh enrollment: actual committed result retained; no later permission."); } else if self.v3_enrollment_attempted[i] { ui.label("Fresh enrollment: admitted once, commit unconfirmed; no retry or rollback inferred."); }
                if self.v3_manifest_result[i].is_some() { ui.label("Fresh manifest: actual committed result retained; no later permission."); } else if self.v3_manifest_attempted[i] { ui.label("Fresh manifest: admitted once, commit unconfirmed; no retry or rollback inferred."); }
                if self.v3_redisclosure_read_result[i].is_some() { ui.label("RedisclosureRead: actual bound result retained; no later permission."); } else if self.v3_redisclosure_read_attempted[i] { ui.label("RedisclosureRead: Final admitted, result unconfirmed; no retry or rollback inferred."); }
                if self.v3_redisclose_result[i].is_some() { ui.label("Redisclose: actual bound result retained; no later permission."); } else if self.v3_redisclose_attempted[i] { ui.label("Redisclose: Final admitted, result unconfirmed; no retry or rollback inferred."); }
                if self.v3_prepare_read_result[i].is_some() { ui.label("PrepareRead: actual bound result retained; no later permission."); } else if self.v3_prepare_read_attempted[i] { ui.label("PrepareRead: admitted once, effect unconfirmed; no retry or rollback."); }
                if self.v3_receive_result[i].is_some() { ui.label("Receive: actual bound result retained; no later permission."); } else if self.v3_receive_attempted[i] { ui.label("Receive: admitted once, effect unconfirmed; no retry or rollback."); }
                if self.v3_pair_result[i].is_some() { ui.label("Original Pair: actual authenticated StatusProof retained; later actions remain unapproved."); }
                else if self.v3_pair_attempted[i] { ui.label("Original Pair: Final admitted; completion unconfirmed. Cancel is not rollback; no retry."); }
                else if self.v3_pair_display[i].is_some() { ui.label("Original Pair: exact pending review observed; no Pair consent yet."); }

            }
            for role in [Role::Signer1, Role::Signer2] { ui.label(format!("{}: {} · {}", role_name(role), progress_text(self.progress[index(role)]), effect_text(self.continue_effect[index(role)]))); }
            for role in [Role::Signer1, Role::Signer2] {
                ui.label(format!("{} admission: Signer {} · Witness {}", role_name(role), admission_effect_text(self.signer_effect[index(role)]), admission_effect_text(self.witness_effect[index(role)])));
            }
            for role in [Role::Signer1, Role::Signer2] {
                if let Some(failure) = &self.witness_failure[index(role)] { ui.label(format!("{} Witness first failure: {:?}", role_name(role), failure)); }
            }
            if self.writer_flow.attempted && self.writer_flow.acquired.is_none() { ui.label("Acquire Final admitted: actual effect remains unconfirmed. Cancel is not rollback; no retry."); }
            if self.activate_flow.committed.is_some() { ui.label("Actual authenticated Activate retained. Wallet preparation, observation, Sign and Return remain unavailable and unapproved."); }
            else if self.activate_flow.attempted { ui.label("Activate Final admitted once: completion unconfirmed; Cancel is not rollback, no retry."); }
            if self.activate_flow.outcome.is_some() { ui.label("Original Activate terminal outcome retained."); }
            if self.writer_flow.acquired.is_some() { ui.label("Actual authenticated Acquire receipt retained; this does not approve Activate or establish completed disposal."); }
            if self.writer_flow.outcome.is_some() { ui.label("Original Acquire terminal outcome retained. No replacement attempt or key is permitted."); }
            if let Some(role) = self.active {
                if let Some(p) = &self.signer_display[index(role)] { ui.label(format!("Original Signer Admit expiry (Unix ms), never renewed by Setup: {}", p.facts.expires_at_ms)); }
            }
            if let Some((role, stage)) = self.first_failure { ui.label(format!("First role failure: {} / {}", role_name(role), stage_name(stage))); }
            // All global cancellation widgets precede the credential widget.
            if self.phase != Phase::Finished && ui.button("Cancel and dispose sources").clicked_by(egui::PointerButton::Primary) {
                self.revoke("Cancelled locally. Waiting for actual role disposal and original-tree cleanup.");
            }
            if !self.focused_last { ui.label("Private source and review details are hidden while unfocused."); return; }
            if host_phase_allows_input(self.phase) || self.terminal() { self.draw_host(ui); }
            if host_entry_blocks_source(self.host_entry) { return; }
            let later_frame = frame > self.phase_frame;
                if matches!(self.phase, Phase::Selecting | Phase::V3Held | Phase::V3Paired | Phase::V3Enrolled | Phase::V3ManifestAccepted | Phase::V3RedisclosurePrepared | Phase::V3Redisclosed) {
                    for role in [Role::Signer1, Role::Signer2] {
                        if self.v3_enrollment_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} fresh enrollment only", role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3Enrollment(role)); }
                    }
                }
                if matches!(self.phase, Phase::Selecting | Phase::V3Held | Phase::V3Paired | Phase::V3Enrolled | Phase::V3ManifestAccepted | Phase::V3RedisclosurePrepared | Phase::V3Redisclosed) {
                    for role in [Role::Signer1, Role::Signer2] {
                        if self.v3_manifest_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} fresh manifest only", role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3Manifest(role)); }
                    }
                }
            if matches!(self.phase, Phase::Selecting | Phase::V3ManifestAccepted | Phase::V3RedisclosurePrepared | Phase::V3Redisclosed) {
                for role in [Role::Signer1, Role::Signer2] {
                    if self.v3_redisclosure_read_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} distinct RedisclosureRead", role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3RedisclosureRead(role)); }
                }
            }
            if matches!(self.phase, Phase::Selecting | Phase::V3ManifestAccepted | Phase::V3RedisclosurePrepared | Phase::V3Redisclosed) {
                for role in [Role::Signer1, Role::Signer2] {
                    if self.v3_redisclose_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} distinct Redisclose", role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3Redisclose(role)); }
                }
            }
            if matches!(self.phase, Phase::Selecting | Phase::V3Redisclosed) {
                for role in [Role::Signer1, Role::Signer2] {
                    if v3_owner_selection_eligible(self.v3_redisclose_result[index(role)].is_some(), self.v3_owner_selected[index(role)], self.native.is_revoked()) && ui.add_enabled(later_frame, egui::Button::new(format!("Select {} existing owner TLS setup · ordinary paths only",role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ConfigureV3Owner(role)); }
                }
            }
            if matches!(self.phase, Phase::Selecting | Phase::V3OwnerSelected | Phase::V3Prepared | Phase::V3Received) {
                for role in [Role::Signer1, Role::Signer2] { if self.v3_prepare_read_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} distinct PrepareRead",role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3PrepareRead(role)); } }
            }
            if matches!(self.phase, Phase::Selecting | Phase::V3OwnerSelected | Phase::V3Prepared | Phase::V3Received) {
                for role in [Role::Signer1, Role::Signer2] { if self.v3_receive_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} distinct Receive",role_name(role)))).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3Receive(role)); } }
            }
            match self.phase {
                Phase::ActivateReadReview | Phase::ActivateReview | Phase::ActivateReady => {
                    let text=if self.phase==Phase::ActivateReadReview { self.activate_flow.read_display.as_ref().and_then(|p|serde_json::to_string_pretty(p).ok()) } else { self.activate_flow.display.as_ref().and_then(|p|serde_json::to_string_pretty(p).ok()) };
                    if let Some(text)=text { if review_display(ui,&text,visible && !ctx.will_discard()) { painted_to_end=true; } }
                    if let Some(d)=&self.activate_flow.ready_digest { ui.label(format!("Exact original Activate Ready: {d}")); }
                    let (notice,label,intent)=match self.phase {
                        Phase::ActivateReadReview=>("Read original owner history and prepare this exact activation only; no Activate effect or wallet permission.","Approve separate Activate Read",Intent::ActivateRead),
                        Phase::ActivateReview=>("Arm only this exact Activate recipe for one local preflight; no effect before separate Final.","Arm exact Activate recipe",Intent::ActivateArm),
                        _=>("Activate only this exact Ready session once using the same original Signing service. No wallet, Sign or Return permission.","Final: activate this exact session once",Intent::ActivateFinal),
                    };
                    ui.checkbox(&mut acknowledged_in_pass,notice);
                    if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame,egui::Button::new(label)).clicked_by(egui::PointerButton::Primary) { self.intent=Some(intent); }
                }
                Phase::ActivateReading=>{ui.label("Separate Activate Read in progress; no activation effect approved.");}
                Phase::ActivateArmed=>{ui.label("Exact Activate Arm sent; waiting for authenticated Ready. Final remains unapproved.");}
                Phase::Activating=>{ui.label("Activate Final consumed once; actual result pending. No retry; Cancel is not rollback.");}
                Phase::Activated=>{ui.label("Actual activation confirmed. Sealed AwaitingWalletPrepare only: no automatic wallet preparation, observation, Sign or Return.");}
                Phase::Selecting => {
                    for role in [Role::Signer1, Role::Signer2] {
                        if self.v3_pair_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new(format!("Review {} exact original Pair", role_name(role))))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3Pair(role)); }
                    }

                    ui.label("Start with the actual original V3 enrollment/manifest metadata. Selecting public paths or seeing an opened account never proves completed V3 receive/admission/audit and cannot unlock the post-V3 financial route.");
                    for role in [Role::Signer1, Role::Signer2] {
                        if self.v3_selection[index(role)].is_none()
                            && ui.button(format!("Select {} original V3 source", role_name(role))).clicked_by(egui::PointerButton::Primary) {
                            self.intent = Some(Intent::ConfigureV3(role));
                        }
                    }
                }
                Phase::V3Configuring => {
                    ui.heading("Initial V3 selection · ordinary metadata only");
                    ui.label("Paste the exact original selection JSON. Do not put a password, private key or credential bytes here. This sends only public selectors; the Signer observes the actual original public files before offering a separate Entry review.");
                    ui.label("Required fields: canonical_root, account_id, original_enrollment_ref, original_manifest_ref, owner_certificate_digest, witness_disclosure_json, witness_disclosure_digest, session_digest, display, source_expires_at_ms. Original references and expiry must come from your actual original enrollment/manifest; no defaults are inferred.");
                    if let Some(text) = &mut v3_in_pass {
                        ui.add(egui::TextEdit::multiline(text).desired_rows(12).desired_width(f32::INFINITY));
                        let valid = parse_v3_selection(text).is_ok();
                        if !valid { ui.label("Selection is incomplete or invalid. Exact bounds/schema must pass; input is not normalized or repaired."); }
                        if ui.add_enabled(valid && later_frame, egui::Button::new("Request exact V3 Entry review · no unlock yet"))
                            .clicked_by(egui::PointerButton::Primary) {
                            self.intent = Some(Intent::BeginV3((Instant::now() + Duration::from_secs(120)).min(self.session_deadline)));
                        }
                    }
                }
                Phase::V3Preparing => { ui.label("The original Signer is observing public source metadata only. No password, KDF or source unlock is approved."); }
                Phase::V3Review | Phase::V3Confirm => {
                    if let Some(offer) = &self.v3_offer {
                        let display = serde_json::to_string_pretty(offer.presentation()).unwrap_or_default();
                        ui.heading("Distinct initial V3 Source Entry");
                        if review_display(ui, &display, visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.label(format!("Original V3 Entry ceiling remaining: {:?}", offer.native_deadline().saturating_duration_since(Instant::now())));
                        if self.phase == Phase::V3Review {
                            if ui.add_enabled(self.read_to_end && later_frame, egui::Button::new("Confirm this exact V3 source disclosure"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ConfirmV3); }
                        } else {
                            ui.checkbox(&mut acknowledged_in_pass, "I approve only unlocking and auditing this exact original V3 account/journal with one encrypted password. No Prepare Read, receive, admission, history audit, financial Entry or signing is approved.");
                            if ui.add_enabled(self.acknowledged && later_frame, egui::Button::new("Enter password for this V3 Entry only"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::PasswordV3); }
                        }
                    }
                }
                Phase::V3Password => {
                    ui.label("One password for the exact initial V3 Entry. Submission is the distinct native Final, only at this visible final event tail.");
                    ui.label("Owned password storage is zeroized. GUI/OS/IME/clipboard erasure is not guaranteed.");
                    if let (Some(input), Some(binding)) = (&mut self.password, &self.binding) { input.show(ui, binding); }
                    if self.password.as_ref().is_none_or(|input| !matches!(input.status(), InputStatus::WaitingForFocus | InputStatus::Editing)) {
                        self.revoke("V3 password entry ended without submission. This exact Entry cannot be retried.");
                    }
                }
                Phase::V3Opening => { ui.label("One actual V3 source-open attempt is in progress. Cancellation stays restrictive through KDF and audit; no retry or completed cleanup is implied."); }
                Phase::V3Held => {
                    if let Some(role) = self.active {
                        if self.v3_pair_ticket[index(role)].is_some() && ui.add_enabled(later_frame, egui::Button::new("Review exact original Host Pair"))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReviewV3Pair(role)); }
                    }

                    ui.label("Original V3 account and journal custody retained. Prepare Read / receive / admission / audit need separate genuine issuers; the financial SourceEntry route remains unavailable.");
                    if self.v3_selection.iter().any(Option::is_none) && ui.add_enabled(later_frame, egui::Button::new("Select the other original V3 role"))
                        .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3EnrollmentReview => {
                    ui.heading("Distinct fresh enrollment receipt · no later permission");
                    if let Some(role) = self.active { if let Some(p) = &self.v3_enrollment_display[index(role)] {
                        let text = serde_json::to_string_pretty(p).unwrap_or_default();
                        if review_display(ui, &text, visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.checkbox(&mut acknowledged_in_pass, "I approve only this complete fresh enrollment record, exact source, Pair, current session, nonce and original window. No export, redisclosure or financial action is approved.");
                        if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame, egui::Button::new("Approve this fresh enrollment only")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3Enrollment); }
                    } }
                }
                Phase::V3Enrolling => { ui.label("Fresh enrollment Final consumed once; waiting for actual committed record. No retry. Cancel is not rollback."); }
                Phase::V3Enrolled => {
                    ui.label("Actual fresh enrollment commit observed. No later purpose is approved.");
                    if let Some(role) = self.active { if let Some(data) = &self.v3_enrollment_result[index(role)] { ui.monospace(serde_json::to_string_pretty(data).unwrap_or_default()); } }
                    if ui.add_enabled(later_frame, egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3ManifestReview => {
                    ui.heading("Distinct fresh manifest receipt · no later permission");
                    if let Some(role) = self.active { if let Some(p) = &self.v3_manifest_display[index(role)] {
                        let text = serde_json::to_string_pretty(p).unwrap_or_default();
                        if review_display(ui, &text, visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.checkbox(&mut acknowledged_in_pass, "I approve only this complete fresh manifest record, exact source, Pair, current session, nonce and original window. No export, redisclosure or financial action is approved.");
                        if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame, egui::Button::new("Approve this fresh manifest only")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3Manifest); }
                    } }
                }
                Phase::V3Manifesting => { ui.label("Fresh manifest Final consumed once; waiting for actual committed record. No retry. Cancel is not rollback."); }
                Phase::V3ManifestAccepted => {
                    ui.label("Actual fresh manifest commit observed. No later purpose is approved.");
                    if let Some(role) = self.active { if let Some(data) = &self.v3_manifest_result[index(role)] { ui.monospace(serde_json::to_string_pretty(data).unwrap_or_default()); } }
                    if ui.add_enabled(later_frame, egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3RedisclosureReadReview => {
                    ui.heading("Distinct RedisclosureRead · exact current source and paired recipient");
                    if let Some(role) = self.active { if let Some(p) = &self.v3_redisclosure_read_display[index(role)] {
                        let text = serde_json::to_string_pretty(p).unwrap_or_default();
                        if review_display(ui, &text, visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.checkbox(&mut acknowledged_in_pass, "Read only this exact historical outbox selector and prepare one immutable candidate; no append or export. I approve only this distinct purpose and original window.");
                        if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame, egui::Button::new("Approve this RedisclosureRead only")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3RedisclosureRead); }
                    } }
                }
                Phase::V3RedisclosureReading => { ui.label("RedisclosureRead Final consumed once; awaiting actual source result. Partial send/effect remains uncertain. No retry; Cancel is not rollback."); }
                Phase::V3RedisclosurePrepared => {
                    ui.label("Actual RedisclosureRead result retained; no later PrepareRead, delivery or financial authority.");
                    if let Some(role) = self.active { if let Some(data) = &self.v3_redisclosure_read_result[index(role)] { ui.monospace(serde_json::to_string_pretty(data).unwrap_or_default()); } }
                    if ui.add_enabled(later_frame, egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3RediscloseReview => {
                    ui.heading("Distinct Redisclose · exact current source and paired recipient");
                    if let Some(role) = self.active { if let Some(p) = &self.v3_redisclose_display[index(role)] {
                        let text = serde_json::to_string_pretty(p).unwrap_or_default();
                        if review_display(ui, &text, visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.checkbox(&mut acknowledged_in_pass, "Append and export only this exact prepared candidate once to the actual original paired recipient; no delivery preparation, admission or financial effect. I approve only this distinct purpose and original window.");
                        if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame, egui::Button::new("Approve this Redisclose only")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3Redisclose); }
                    } }
                }
                Phase::V3Redisclosing => { ui.label("Redisclose Final consumed once; awaiting actual source result. Partial send/effect remains uncertain. No retry; Cancel is not rollback."); }
                Phase::V3Redisclosed => {
                    ui.label("Actual Redisclose result retained; no later PrepareRead, delivery or financial authority.");
                    if let Some(role) = self.active { if let Some(data) = &self.v3_redisclose_result[index(role)] { ui.monospace(serde_json::to_string_pretty(data).unwrap_or_default()); } }
                    if ui.add_enabled(later_frame, egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3OwnerConfiguring => {
                    ui.heading("Select existing owner TLS setup · no Read consent");
                    ui.label("Paste the exact existing owner setup JSON, at most 16 KiB. Use your actual paths/public configuration only; never paste private-key bytes or credentials. This only fixes ordinary selectors for the actual retained source and completed Redisclose. It does not read a key, connect, approve PrepareRead, or renew any original deadline.");
                    if let Some(role) = self.active { if let Some(data) = &self.v3_redisclose_result[index(role)] { ui.monospace(serde_json::to_string_pretty(data).unwrap_or_default()); } }
                    if let Some(text) = &mut owner_in_pass {
                        ui.add(egui::TextEdit::multiline(text).desired_rows(12).desired_width(f32::INFINITY));
                        let valid = parse_v3_owner_selection(text).is_ok();
                        if !valid { ui.label("Exact strict owner setup schema and 16 KiB bound must pass. No defaults, normalization or truncation."); }
                        if ui.add_enabled(valid && later_frame,egui::Button::new("Fix these ordinary owner setup selectors once · no approval")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectV3Owner); }
                    }
                }
                Phase::V3OwnerSelected => {
                    ui.label("Owner setup selectors submitted once, not native consent. Waiting for a separately authenticated PrepareRead review; no private read, connection or later action is inferred, and no retry is allowed.");
                    if ui.add_enabled(later_frame, egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3PrepareReadReview => {
                    ui.heading("Distinct PrepareRead · original source, service and material windows");
                    if let Some(role) = self.active { if let Some(p) = &self.v3_prepare_read_display[index(role)] {
                        let text = serde_json::to_string_pretty(p).unwrap_or_default();
                        if review_display(ui,&text,visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.checkbox(&mut acknowledged_in_pass,"Read only this exact selected private source and owner client key to prepare immutable local recipient custody. No owner history, Receive, admission or financial effect is approved.");
                        if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame,egui::Button::new("Approve this PrepareRead only")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3PrepareRead); }
                    } }
                }
                Phase::V3PrepareReading => { ui.label("PrepareRead Final admitted once. Awaiting actual authenticated source outcome; partial effects are uncertain. No retry or rollback inferred."); }
                Phase::V3Prepared => {
                    ui.label("Actual PrepareRead result retained; no later history, admission or financial approval.");
                    if let Some(role) = self.active { if let Some(d) = &self.v3_prepare_read_result[index(role)] { ui.monospace(serde_json::to_string_pretty(d).unwrap_or_default()); } }
                    if ui.add_enabled(later_frame,egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3ReceiveReview => {
                    ui.heading("Distinct Receive · original source, service and material windows");
                    if let Some(role) = self.active { if let Some(p) = &self.v3_receive_display[index(role)] {
                        let text = serde_json::to_string_pretty(p).unwrap_or_default();
                        if review_display(ui,&text,visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.checkbox(&mut acknowledged_in_pass,"Receive and verify only this exact bounded payload on the original authenticated paired channel with the displayed immutable preparation. No owner history, admission or financial effect is approved.");
                        if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame,egui::Button::new("Approve this Receive only")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3Receive); }
                    } }
                }
                Phase::V3Receiving => { ui.label("Receive Final admitted once. Awaiting actual authenticated source outcome; partial effects are uncertain. No retry or rollback inferred."); }
                Phase::V3Received => {
                    ui.label("Actual Receive result retained; no later history, admission or financial approval.");
                    if let Some(role) = self.active { if let Some(d) = &self.v3_receive_result[index(role)] { ui.monospace(serde_json::to_string_pretty(d).unwrap_or_default()); } }
                    if ui.add_enabled(later_frame,egui::Button::new("Return to original role selection")).clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::V3PairReview => {
                    ui.heading("Distinct V3 Pair · exact fresh original Host channel");
                    if let Some(role) = self.active {
                        if let (Some(endpoint), Some(p)) = (&self.v3_pair_endpoint[index(role)], &self.v3_pair_display[index(role)]) {
                            let text = serde_json::to_string_pretty(&serde_json::json!({"actual_original_endpoint":endpoint,"exact_pair_presentation":p})).unwrap_or_default();
                            if review_display(ui, &text, visible && !ctx.will_discard()) { painted_to_end = true; }
                            ui.label(format!("Original Pair action expiry (Unix ms): {}. Separate original channel expiry: {}. Neither is renewed here.", p.facts.expires_at_ms, p.facts.channel_expires_at_ms));
                            ui.checkbox(&mut acknowledged_in_pass, "I approve only this exact fresh Pair with the displayed original Host process, actual source identity and pending review digest. No journal Read, enrollment, manifest, export, receive, admission or financial action is approved.");
                            if ui.add_enabled(self.read_to_end && self.acknowledged && later_frame, egui::Button::new("Approve this one original Pair only"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::FinalV3Pair); }
                        }
                    }
                }
                Phase::V3Pairing => { ui.label("Pair Final admitted once. Waiting for actual authenticated StatusProof; issuing a grant or sending Final alone is not Pair completion. No retry."); }
                Phase::V3Paired => {
                    ui.label("Actual fresh StatusProof was authenticated and Pair result retained. This is not preparation Read, enrollment, manifest, receive or financial approval.");
                    if let Some(role) = self.active {
                        if let Some(data) = &self.v3_pair_result[index(role)] { ui.monospace(serde_json::to_string_pretty(data).unwrap_or_default()); }
                    }
                    if ui.add_enabled(later_frame, egui::Button::new("Return to original role selection"))
                        .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SelectNextV3); }
                }
                Phase::Configuring => {
                    ui.heading("Select existing Witness configuration · ordinary data only");
                    ui.label("This step does not read files, import keys, probe storage or open a listener. Select existing paths and public configuration only. The later exact Setup requires its own complete disclosure and explicit approval.");
                    if let (Some(role), Some(inputs)) = (self.active, &mut selectors_in_pass) {
                        draw_selectors(ui, inputs);
                        if ui.add_enabled(selectors_valid(inputs) && later_frame, egui::Button::new("Keep these selectors and review Signer source"))
                            .clicked_by(egui::PointerButton::Primary) {
                            let ceiling = (Instant::now() + Duration::from_secs(120)).min(self.session_deadline);
                            self.intent = Some(Intent::Begin(role, ceiling));
                        }
                    }
                }
                Phase::SetupNeeded => {
                    ui.heading("Saved continuation · separate Witness Setup");
                    ui.label("The exact authenticated Continue request will be reused without retyping or source reread. Setup may read the selected namespace/storage/TLS files and open the named listener; append and Signer Admit still require separate approvals. Runtime activation also requires the separately qualified prior-purpose retirement boundary.");
                    if ui.add_enabled(later_frame, egui::Button::new("Review the exact Witness Setup disclosure"))
                        .clicked_by(egui::PointerButton::Primary) {
                        self.intent = Some(Intent::PrepareSetup((Instant::now() + Duration::from_secs(120)).min(self.session_deadline)));
                    }
                }
                Phase::SetupPreparing => { ui.label("Preparing the original data-bound Setup ticket. No protected file or listener approval has been sent."); }
                Phase::SetupReview => {
                    if let Some(ticket) = &self.setup {
                        ui.heading("Separate Witness Setup · protected reads and listener");
                        ui.label("Approval permits the named original Witness to read these existing namespace/storage/TLS key and trust files and open this exact listener for one request. It does not authorize an append or Signer transport. Private key material remains in its original role.");
                        if review_display(ui, &setup_display(ticket), visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.label(format!("Original native Setup ceiling remaining: {:?}", ticket.native_deadline().saturating_duration_since(Instant::now())));
                        ui.checkbox(&mut acknowledged_in_pass, "I reviewed all exact paths, namespace, owner/request, TLS pin, key reads and listener opening. I approve only this Setup.");
                        if ui.add_enabled(self.read_to_end && acknowledged_in_pass && later_frame, egui::Button::new("Approve this exact Witness Setup"))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::Setup); }
                    }
                }
                Phase::AdmissionReview | Phase::RetirementBlocked => {
                    self.draw_admission(ui, visible && !ctx.will_discard(), later_frame, &mut paired_in_pass);
                }
                Phase::EntryReview | Phase::EntryConfirm | Phase::Password => {
                    if let Some(offer) = &self.entry {
                        let p = offer.presentation();
                        ui.heading(format!("{} · Unlock this exact source only", role_name(p.actor.signer_role)));
                        ui.label(format!("Account: {}\nSelected source: {}\nOriginal review expiry (Unix ms): {}", p.facts.account_id, p.facts.selection_digest, p.facts.expires_at_ms));
                        ui.label(&p.notice);
                        let display = format!("{}\n\nComplete authenticated presentation:\n{p:#?}", p.facts.display);
                        if review_display(ui, &display, visible && !ctx.will_discard()) { painted_to_end = true; }
                    }
                    match self.phase {
                        Phase::EntryReview => {
                            if ui.add_enabled(self.read_to_end && later_frame, egui::Button::new("Continue to source confirmation"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::EntryConfirm); }
                        }
                        Phase::EntryConfirm => {
                            ui.checkbox(&mut acknowledged_in_pass, "I reviewed the complete exact Signer source, disclosure, purpose and original expiry. Unlocking does not approve Read, Continue or Admit.");
                            if ui.add_enabled(acknowledged_in_pass && later_frame, egui::Button::new("Enter password for this source"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::EnterPassword); }
                        }
                        Phase::Password => {
                            ui.label("This coordinator sees the password briefly. Owned input is zeroized; complete GUI/OS/IME/clipboard erasure is not guaranteed.");
                            if let (Some(input), Some(binding)) = (&mut self.password, &self.binding) { input.show(ui, binding); }
                            if self.password.as_ref().is_none_or(|input| !matches!(input.status(), InputStatus::WaitingForFocus | InputStatus::Editing)) {
                                self.revoke("Password entry ended without submission. The exact request cannot be restarted here.");
                            }
                        }
                        _ => {}
                    }
                }
                Phase::HistorySetupNeeded => {
                    ui.heading("Separate original Witness history Setup");
                    ui.label("The retained Signer Read ticket does not authorize Witness file/key reads or listener opening. Review a separate Setup bound to that exact original Read, using the existing selectors. No deadline is renewed.");
                    if ui.add_enabled(later_frame, egui::Button::new("Review exact History Setup disclosure"))
                        .clicked_by(egui::PointerButton::Primary) {
                        if let Some(read) = &self.read {
                            self.intent = Some(Intent::PrepareHistory((Instant::now() + Duration::from_secs(120)).min(read.native_deadline()).min(self.session_deadline)));
                        }
                    }
                }
                Phase::HistorySetupPreparing => { ui.label("Preparing the data-bound History Setup ticket. No protected file, key or listener operation is approved."); }
                Phase::HistorySetupReview => {
                    if let Some(ticket) = &self.history_setup {
                        ui.heading("History Setup · exact protected files and listener");
                        ui.label("Approval permits only the original Witness's named storage, TLS key and trust-file reads and this listener preparation. Owner-only Serve and Signer Read each remain separately unapproved.");
                        if review_display(ui, &history_setup_display(ticket), visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.label(format!("Original Setup ceiling remaining: {:?}", ticket.native_deadline().saturating_duration_since(Instant::now())));
                        ui.checkbox(&mut acknowledged_in_pass, "I reviewed every exact path, source/owner binding, TLS pin, protected read and listener. I approve only this History Setup.");
                        if ui.add_enabled(self.read_to_end && acknowledged_in_pass && later_frame, egui::Button::new("Approve exact History Setup"))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::SetupHistory); }
                    }
                }
                Phase::HistoryPreparing => { ui.label("The separately approved original History Setup is in progress. Awaiting its authenticated actual source review; no Serve or Signer Read is approved."); }
                Phase::HistoryReview => {
                    if let Some(ticket) = &self.history_review {
                        ui.heading("Original Witness · serve one exact owner history");
                        ui.label("This distinct approval permits only the displayed original owner-only history service. It does not approve Signer Read, Continue, append, signing or payment. Historical delivery head and actual current source head are distinct.");
                        if review_display(ui, &history_display(ticket.presentation()), visible && !ctx.will_discard()) { painted_to_end = true; }
                        ui.label(format!("Original history ceiling remaining: {:?}", ticket.native_deadline().saturating_duration_since(Instant::now())));
                        ui.checkbox(&mut acknowledged_in_pass, "I reviewed this complete actual source, owner, disclosure, historical/current heads and original expiry. I approve only this one owner-history service.");
                        if ui.add_enabled(self.read_to_end && acknowledged_in_pass && later_frame, egui::Button::new("Approve this exact History Serve"))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ServeHistory); }
                    }
                }
                Phase::HistoryStarting => { ui.label("Waiting for the actual original Witness Serving acknowledgment. Native approval, a queued command or a UI phase does not establish readiness."); }
                Phase::ReadReview | Phase::ReadConfirm => {
                    if let Some(ticket) = &self.read {
                        let p = ticket.presentation();
                        ui.heading(format!("{} · Owner history Read + one local Continue preparation", role_name(p.actor.signer_role)));
                        ui.label(format!("Account: {}\nSource: {}\nOriginal review expiry (Unix ms): {}", p.facts.account_id, p.facts.source_identity_digest, p.facts.expires_at_ms));
                        ui.label(&p.notice);
                        let display = format!("{}\n\nComplete authenticated presentation:\n{p:#?}", p.facts.display);
                        if review_display(ui, &display, visible && !ctx.will_discard()) { painted_to_end = true; }
                    }
                    if self.phase == Phase::ReadReview {
                        if ui.add_enabled(self.read_to_end && later_frame, egui::Button::new("Continue to Read confirmation"))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ReadConfirm); }
                    } else {
                        ui.checkbox(&mut acknowledged_in_pass, "I approve this complete original owner history Read PLUS exactly one immutable local Continue preparation from this same Signer source, with the displayed disclosure and original expiry. I do not approve Continue, Admit or any mutation.");
                        if ui.add_enabled(acknowledged_in_pass && later_frame, egui::Button::new("Approve this Read and one local preparation"))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::Read); }
                    }
                }
                Phase::HistoryRetiring => {
                    ui.label("The original History service is ending. Actual disposal, exclusive Host quiescence, normal owned reap and matching native resume must finish under the existing cleanup cutoff. No new prompt, timeout allowance or source action is created. Cancel remains active.");
                }
                Phase::HistoryReady => {
                    ui.label("Read and exactly one immutable local preparation completed. Reviewing that prepared Continue is a separate action; its original deadline is already running.");
                    if ui.add_enabled(later_frame, egui::Button::new("Review this prepared Continue"))
                        .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::BeginContinue); }
                }
                Phase::ContinueReview | Phase::ContinueConfirm | Phase::ContinueArmed | Phase::Continuing => {
                    if let Some(p) = &self.continuation {
                        ui.heading(format!("{} · This exact immutable Continue only", role_name(p.review.signer_role)));
                        ui.label(format!("Source: {}\nOriginal Continue expiry (Unix ms): {}", p.review.source_identity_digest, p.review.expires_at_ms));
                        ui.label("Continue commits this one prepared local continuation. It does not approve financial Admit or payment. Later Cancel cannot promise rollback after native admission.");
                        let display = format!("{}\n\nComplete authenticated Continue presentation and request:\n{p:#?}", p.display);
                        if review_display(ui, &display, visible && !ctx.will_discard()) { painted_to_end = true; }
                    }
                    match self.phase {
                        Phase::ContinueReview => {
                            if ui.add_enabled(self.read_to_end && later_frame, egui::Button::new("Continue to exact confirmation"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ContinueConfirm); }
                        }
                        Phase::ContinueConfirm => {
                            ui.checkbox(&mut acknowledged_in_pass, "I reviewed the complete immutable request, original Signer/source and expiry. I approve only this local Continue, not Admit or payment; cancellation after admission may not undo it.");
                            if ui.add_enabled(acknowledged_in_pass && later_frame, egui::Button::new("Approve this exact Continue"))
                                .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::ArmContinue); }
                        }
                        Phase::ContinueArmed => { ui.label("Awaiting the original Signer's exact Ready. This same visible review will admit it only after the complete cancellation batch; no new clock or second approval is created."); }
                        Phase::Continuing => { ui.label("Native Continue admission occurred. Waiting for the actual saved/no-effect/uncertain outcome; do not assume rollback or retry."); }
                        _ => {}
                    }
                }
                Phase::ContinuePreparing => { ui.label("Retrieving the already-prepared immutable Continue. No fresh Read, source or review deadline is created."); }
                Phase::WriterFlow => {
                    let (text, button, consent) = self.writer_display();
                    ui.heading("Separate original Writer Read and Acquire");
                    if let Some(t) = &self.writer_flow.setup { ui.label(format!("Original Signing Setup ceiling remaining: {:?}", t.native_deadline().saturating_duration_since(Instant::now()))); }
                    if let Some(t) = &self.writer_flow.review { ui.label(format!("Original Signing Serve review ceiling remaining: {:?}", t.native_deadline().saturating_duration_since(Instant::now()))); }
                    if let Some(t) = &self.writer_flow.read { ui.label(format!("Original Writer Read ceiling remaining: {:?}", t.native_deadline().saturating_duration_since(Instant::now()))); }
                    if let Some(t) = &self.writer_flow.acquire { ui.label(format!("Original Acquire ceiling remaining: {:?}", t.native_deadline().saturating_duration_since(Instant::now()))); }
                    if review_display(ui, &text, visible) { painted_to_end = true; }
                    if consent { ui.checkbox(&mut acknowledged_in_pass, "I reviewed this complete exact purpose and original expiry. I approve only the action named below, not a later action or retry."); }
                    if let Some(label) = button {
                        if ui.add_enabled(visible && later_frame && self.read_to_end && (!consent || self.acknowledged), egui::Button::new(label))
                            .clicked_by(egui::PointerButton::Primary) { self.intent = Some(Intent::WriterAction); }
                    }
                }
                Phase::Preparing => { ui.label("Waiting for the authenticated original source-entry offer. No password or source-entry approval has been sent."); }
                Phase::Opening => { ui.label("One source-entry attempt is in progress. Cancellation remains restrictive through decrypt, KDF and source audit; completed cleanup is not yet confirmed."); }
                Phase::Reading => { ui.label("The approved owner history Read and one immutable local Continue preparation are in progress. Continue, Admit and mutation remain unapproved."); }
                Phase::Waiting => { ui.label("Both original Signers report saved continuations and await separate financial Admit. No Admit action or payment is enabled by this slice."); }
                Phase::Revoked => { ui.label("This workflow is permanently restricted. Owned cleanup is pending; no automatic retry or role replacement is allowed."); }
                Phase::Finished => { if ui.add_enabled(self.host_output_ended, egui::Button::new("Close")).clicked_by(egui::PointerButton::Primary) { ctx.send_viewport_cmd(egui::ViewportCommand::Close); } }
            }
        });
        // This is the ONLY SourceEntry/Read/Continue native Arm/A site. Every original raw
        // event and every Cancel widget has been processed before this tail.
        self.check_current();
        let host_line = match (&mut self.host_input, self.host_entry) {
            (Some(input), HostEntry::Editing(ordinal)) => {
                input.finish_frame(ordinal, &mut || self.native.revoke())
            }
            _ => None,
        };
        self.check_current(); // Internal terminal validation may have revoked.
        let intent = self.intent.take();
        let eligible = tail_eligible(frame, self.last_tail_frame, visible, ctx.will_discard())
            && self.focused_last
            && !self.terminal();
        (self.read_to_end, self.acknowledged) = review_progress_after_pass(
            (self.read_to_end, self.acknowledged),
            (painted_to_end, acknowledged_in_pass),
            eligible,
            self.phase == painted_phase,
        );
        self.paired = paired_progress_after_pass(
            self.paired,
            paired_in_pass,
            eligible,
            self.phase == painted_phase,
        );
        if eligible && self.phase == painted_phase {
            if let (Some(role), Some(inputs)) = (self.active, selectors_in_pass) {
                if selectors_bounded(&inputs) {
                    self.selectors[index(role)] = inputs;
                } else {
                    self.revoke("Witness selector input exceeded its exact ordinary-data bounds. No normalization or truncation is accepted.");
                }
            }
        }
        if eligible && self.phase == painted_phase {
            if let (Some(role), Some(text)) = (self.active, v3_in_pass) {
                if v3_text_bounded(&text) {
                    self.v3_selection_text[index(role)] = text;
                } else {
                    self.revoke("V3 public selection exceeded its exact bounds. No truncation or normalization is permitted.");
                }
            }
        }
        if eligible && self.phase == painted_phase {
            if let (Some(role), Some(text)) = (self.active, owner_in_pass) {
                if v3_owner_text_bounded(&text) {
                    self.v3_owner_text[index(role)] = text;
                } else {
                    self.revoke("Owner setup ordinary selection exceeded exact bounds; no truncation or retry.");
                }
            }
        }
        if matches!(
            painted_phase,
            Phase::Configuring | Phase::V3Configuring | Phase::V3OwnerConfiguring
        ) {
            ctx.input_mut(|input| {
                scrub_unrequested_payloads(&mut input.events);
                scrub_unrequested_payloads(&mut input.raw.events);
            });
        }
        let password = match (&mut self.password, &self.binding) {
            (Some(input), Some(binding)) => input.finish_frame(binding),
            _ => None,
        };
        if !eligible || self.terminal() {
            if host_line.is_some() {
                self.revoke("Host submission did not reach an eligible visible final tail. The one-use line is discarded, never retried.");
            }
            drop(host_line);
            drop(password);
            return;
        }
        self.last_tail_frame = Some(frame);
        if matches!(
            self.phase,
            Phase::HistoryRetiring | Phase::RetirementBlocked
        ) {
            if host_line.is_some()
                || password.is_some()
                || host_entry_blocks_source(self.host_entry)
            {
                self.revoke("Protected input cannot overlap exclusive History retirement.");
                return;
            }
            if self.history_retirement_tail().is_err() {
                self.revoke("Original History retirement could not pause or resume. No new action or successful disposal is inferred.");
            }
            return;
        }
        if let Some(submitted) = host_line {
            let ordinal = match self.host_entry {
                HostEntry::Editing(ordinal) => ordinal,
                _ => {
                    self.revoke("Host input phase changed.");
                    return;
                }
            };
            if let Some(line) = submitted.into_line_for(ordinal, &mut || self.native.revoke()) {
                self.host_entry = HostEntry::Writing(ordinal);
                let queued = self.driver.borrow_mut().send_host_line(ordinal, line);
                if let Err(unsent) = queued {
                    self.revoke("The one-use Host line could not be queued. Do not resubmit; accepted input or effects may be unconfirmed.");
                    drop(unsent); // Actual native/shared R preceded owned cleanup.
                }
            } else {
                self.revoke("The original Host line expired or changed before its final tail.");
            }
        } else if host_entry_blocks_source(self.host_entry) {
            // No source native Arm/A or Begin while editing/partially writing.
        } else if let Some(password) = password {
            if self.submit_password(password, frame).is_err() {
                self.revoke("The exact source-entry input could not be admitted or queued. No retry is allowed.");
            }
        } else if let Some(intent) = intent {
            if self.apply_intent(intent, frame, &ctx).is_err() {
                self.revoke("The exact source action could not proceed. Disposal is pending.");
            }
        }
        // The real Arm click is already committed. A newly received exact
        // Ready needs no second click, but may only reach A at this visible tail.
        if !host_entry_blocks_source(self.host_entry)
            && may_admit_continue(
                self.phase,
                self.continue_ready.is_some(),
                self.focused_last,
                self.native.is_revoked(),
                frame > self.phase_frame,
            )
        {
            if let Some(ticket) = self.continue_ready.take() {
                let result = (|| -> Result<()> {
                    let role = self
                        .active
                        .ok_or_else(|| rejected("Continue active role missing"))?;
                    let outbound = self.native.admit_continue(ticket)?;
                    self.continue_effect[index(role)] = ContinueEffect::Pending;
                    self.progress[index(role)] = Progress::ContinueAdmitted;
                    self.message = "Continue native admission occurred. Its actual result is unconfirmed; later cancellation does not establish rollback.";
                    self.transition(Phase::Continuing, frame);
                    self.driver.borrow_mut().send_continue_final(role, outbound)
                })();
                if result.is_err() {
                    self.revoke("The exact Continue could not be completed or transported. Any native admission remains recorded; outcome may be unconfirmed.");
                }
            }
        }
        if !host_entry_blocks_source(self.host_entry)
            && paired_tail_eligible(
                self.phase,
                self.focused_last,
                self.native.is_revoked(),
                frame > self.phase_frame,
            )
        {
            if self.admit_rendezvous(frame).is_err() {
                self.revoke("The exact Signer/Witness rendezvous could not proceed. Any actual native append admission remains recorded; no retry is allowed.");
            }
        }
        if !host_entry_blocks_source(self.host_entry)
            && writer_final_eligible(
                self.phase,
                self.writer_flow.stage,
                self.writer_flow.ready.is_some(),
                self.focused_last,
                self.native.is_revoked(),
                frame > self.phase_frame,
            )
        {
            if self.writer_final(frame).is_err() {
                self.revoke(
                    "Acquire Final could not complete. Any admitted effect is uncertain; no retry.",
                );
            }
        }
        ctx.request_repaint_after(Duration::from_millis(20));
    }
    fn apply_intent(&mut self, intent: Intent, frame: u64, ctx: &egui::Context) -> Result<()> {
        if host_entry_blocks_source(self.host_entry) {
            return Err(rejected("protected Host input owns this phase"));
        }
        match intent {
            Intent::ActivateRead
                if activate_tail_eligible(
                    self.phase,
                    Phase::ActivateReadReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Activate role missing"))?;
                let ticket = self
                    .activate_flow
                    .read
                    .take()
                    .ok_or_else(|| rejected("Activate Read consumed"))?;
                let serving = self
                    .writer_flow
                    .serving
                    .as_ref()
                    .ok_or_else(|| rejected("original Signing service missing"))?;
                let out = self.native.admit_activate_read(ticket, serving)?;
                self.transition(Phase::ActivateReading, frame);
                self.driver.borrow_mut().send_activate_read(role, out)?;
            }
            Intent::ActivateArm
                if activate_tail_eligible(
                    self.phase,
                    Phase::ActivateReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Activate role missing"))?;
                let ticket = self
                    .activate_flow
                    .review
                    .take()
                    .ok_or_else(|| rejected("Activate review consumed"))?;
                let out = self.native.arm_activate(ticket)?;
                self.transition(Phase::ActivateArmed, frame);
                self.driver.borrow_mut().send_activate_arm(role, out)?;
            }
            Intent::ActivateFinal
                if activate_tail_eligible(
                    self.phase,
                    Phase::ActivateReady,
                    self.read_to_end,
                    self.acknowledged,
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Activate role missing"))?;
                if self.activate_flow.attempted {
                    return Err(rejected("Activate Final already attempted"));
                }
                let ticket = self
                    .activate_flow
                    .ready
                    .take()
                    .ok_or_else(|| rejected("Activate Ready consumed"))?;
                let serving = self
                    .writer_flow
                    .serving
                    .as_ref()
                    .ok_or_else(|| rejected("original Signing service missing"))?;
                let out = self.native.admit_activate(ticket, serving)?;
                self.activate_flow.attempted = true;
                self.transition(Phase::Activating, frame);
                self.driver.borrow_mut().send_activate_final(role, out)?;
            }

            Intent::ReviewV3Enrollment(role)
                if matches!(
                    self.phase,
                    Phase::Selecting
                        | Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.v3_enrollment_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt ticket missing"))?
                    .check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3EnrollmentReview, frame);
            }
            Intent::FinalV3Enrollment
                if v3_receipt_final_eligible(
                    self.phase,
                    Phase::V3EnrollmentReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|r| self.v3_enrollment_ticket[index(r)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("receipt active role missing"))?;
                let i = index(role);
                if self.v3_enrollment_attempted[i] {
                    return Err(rejected("fresh receipt already attempted"));
                }
                let ticket = self.v3_enrollment_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("fresh nominal receipt ticket missing"))?;
                let outbound = self.native.admit_v3_enrollment(ticket)?;
                self.v3_enrollment_attempted[i] = true;
                self.transition(Phase::V3Enrolling, frame);
                self.driver
                    .borrow_mut()
                    .send_v3_enrollment(role, outbound)?;
            }
            Intent::ReviewV3Manifest(role)
                if matches!(
                    self.phase,
                    Phase::Selecting
                        | Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.v3_manifest_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt ticket missing"))?
                    .check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3ManifestReview, frame);
            }
            Intent::FinalV3Manifest
                if v3_receipt_final_eligible(
                    self.phase,
                    Phase::V3ManifestReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|r| self.v3_manifest_ticket[index(r)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("receipt active role missing"))?;
                let i = index(role);
                if self.v3_manifest_attempted[i] {
                    return Err(rejected("fresh receipt already attempted"));
                }
                let ticket = self.v3_manifest_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("fresh nominal receipt ticket missing"))?;
                let outbound = self.native.admit_v3_manifest(ticket)?;
                self.v3_manifest_attempted[i] = true;
                self.transition(Phase::V3Manifesting, frame);
                self.driver.borrow_mut().send_v3_manifest(role, outbound)?;
            }
            Intent::ReviewV3RedisclosureRead(role)
                if matches!(
                    self.phase,
                    Phase::Selecting
                        | Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.v3_redisclosure_read_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt ticket missing"))?
                    .check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3RedisclosureReadReview, frame);
            }
            Intent::FinalV3RedisclosureRead
                if v3_redisclosure_final_eligible(
                    self.phase,
                    Phase::V3RedisclosureReadReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|r| self.v3_redisclosure_read_ticket[index(r)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("receipt active role missing"))?;
                let i = index(role);
                if self.v3_redisclosure_read_attempted[i] {
                    return Err(rejected("fresh receipt already attempted"));
                }
                let ticket = self.v3_redisclosure_read_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("fresh nominal receipt ticket missing"))?;
                let outbound = self.native.admit_v3_redisclosure_read(ticket)?;
                self.v3_redisclosure_read_attempted[i] = true;
                self.transition(Phase::V3RedisclosureReading, frame);
                self.driver
                    .borrow_mut()
                    .send_v3_redisclosure_read(role, outbound)?;
            }
            Intent::ReviewV3Redisclose(role)
                if matches!(
                    self.phase,
                    Phase::Selecting
                        | Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.v3_redisclose_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt ticket missing"))?
                    .check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3RediscloseReview, frame);
            }
            Intent::FinalV3Redisclose
                if v3_redisclosure_final_eligible(
                    self.phase,
                    Phase::V3RediscloseReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|r| self.v3_redisclose_ticket[index(r)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("receipt active role missing"))?;
                let i = index(role);
                if self.v3_redisclose_attempted[i] {
                    return Err(rejected("fresh receipt already attempted"));
                }
                let ticket = self.v3_redisclose_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("fresh nominal receipt ticket missing"))?;
                let outbound = self.native.admit_v3_redisclose(ticket)?;
                self.v3_redisclose_attempted[i] = true;
                self.transition(Phase::V3Redisclosing, frame);
                self.driver
                    .borrow_mut()
                    .send_v3_redisclose(role, outbound)?;
            }
            Intent::ConfigureV3Owner(role)
                if matches!(self.phase, Phase::Selecting | Phase::V3Redisclosed)
                    && v3_owner_selection_eligible(
                        self.v3_redisclose_result[index(role)].is_some(),
                        self.v3_owner_selected[index(role)],
                        self.native.is_revoked(),
                    ) =>
            {
                self.active = Some(role);
                self.transition(Phase::V3OwnerConfiguring, frame);
            }
            Intent::SelectV3Owner
                if self.phase == Phase::V3OwnerConfiguring
                    && self.focused_last
                    && !self.native.is_revoked()
                    && frame > self.phase_frame =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("owner setup active role missing"))?;
                let i = index(role);
                if !v3_owner_selection_eligible(
                    self.v3_redisclose_result[i].is_some(),
                    self.v3_owner_selected[i],
                    self.native.is_revoked(),
                ) {
                    return Err(rejected(
                        "owner selection before actual Redisclosed or already consumed",
                    ));
                }
                let selected = parse_v3_owner_selection(&self.v3_owner_text[i])?;
                let source = self.v3_selection[i]
                    .as_ref()
                    .ok_or_else(|| rejected("owner selection original source missing"))?;
                if selected.account_id != source.account_id {
                    return Err(rejected("owner setup account changed"));
                }
                self.v3_owner_selected[i] = true; // Ordinary attempt only; no native capability and no retry on uncertainty.
                self.transition(Phase::V3OwnerSelected, frame);
                self.driver
                    .borrow_mut()
                    .select_v3_owner_setup(role, self.v3_owner_text[i].clone())?;
            }
            Intent::ReviewV3PrepareRead(role)
                if matches!(
                    self.phase,
                    Phase::Selecting
                        | Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.v3_prepare_read_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt ticket missing"))?
                    .check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3PrepareReadReview, frame);
            }
            Intent::FinalV3PrepareRead
                if v3_delivery_final_eligible(
                    self.phase,
                    Phase::V3PrepareReadReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|r| self.v3_prepare_read_ticket[index(r)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("receipt active role missing"))?;
                let i = index(role);
                if self.v3_prepare_read_attempted[i] {
                    return Err(rejected("fresh receipt already attempted"));
                }
                let ticket = self.v3_prepare_read_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("fresh nominal receipt ticket missing"))?;
                let outbound = self.native.admit_v3_prepare_read(ticket)?;
                self.v3_prepare_read_attempted[i] = true;
                self.transition(Phase::V3PrepareReading, frame);
                self.driver
                    .borrow_mut()
                    .send_v3_prepare_read(role, outbound)?;
            }
            Intent::ReviewV3Receive(role)
                if matches!(
                    self.phase,
                    Phase::Selecting
                        | Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.v3_receive_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt ticket missing"))?
                    .check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3ReceiveReview, frame);
            }
            Intent::FinalV3Receive
                if v3_delivery_final_eligible(
                    self.phase,
                    Phase::V3ReceiveReview,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|r| self.v3_receive_ticket[index(r)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("receipt active role missing"))?;
                let i = index(role);
                if self.v3_receive_attempted[i] {
                    return Err(rejected("fresh receipt already attempted"));
                }
                let ticket = self.v3_receive_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("fresh nominal receipt ticket missing"))?;
                let outbound = self.native.admit_v3_receive(ticket)?;
                self.v3_receive_attempted[i] = true;
                self.transition(Phase::V3Receiving, frame);
                self.driver.borrow_mut().send_v3_receive(role, outbound)?;
            }
            Intent::ReviewV3Pair(role)
                if matches!(
                    self.phase,
                    Phase::Selecting | Phase::V3Held | Phase::V3Paired
                ) =>
            {
                let ticket = self.v3_pair_ticket[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("actual Pair ticket missing"))?;
                ticket.check_current()?;
                self.active = Some(role);
                self.transition(Phase::V3PairReview, frame);
            }
            Intent::FinalV3Pair
                if v3_pair_final_eligible(
                    self.phase,
                    self.read_to_end,
                    self.acknowledged,
                    self.active
                        .is_some_and(|role| self.v3_pair_ticket[index(role)].is_some()),
                    self.focused_last,
                    self.native.is_revoked(),
                    frame > self.phase_frame,
                ) =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Pair active role missing"))?;
                let i = index(role);
                if self.v3_pair_attempted[i] {
                    return Err(rejected("Pair one-use Final consumed"));
                }
                let ticket = self.v3_pair_ticket[i]
                    .take()
                    .ok_or_else(|| rejected("Pair nominal ticket missing"))?;
                let outbound = self.native.admit_v3_pair(ticket)?;
                self.v3_pair_attempted[i] = true; // Native A before enqueue; no rollback claim on send failure.
                self.transition(Phase::V3Pairing, frame);
                self.driver.borrow_mut().send_v3_pair(role, outbound)?;
            }
            Intent::ConfigureV3(role)
                if self.phase == Phase::Selecting && self.v3_selection[index(role)].is_none() =>
            {
                self.active = Some(role);
                self.transition(Phase::V3Configuring, frame);
            }
            Intent::BeginV3(ceiling) if self.phase == Phase::V3Configuring => {
                let role = self.active.ok_or_else(|| rejected("V3 role missing"))?;
                let selection = parse_v3_selection(&self.v3_selection_text[index(role)])?;
                if self.v3_selection[index(role)].is_some() {
                    return Err(rejected("V3 selection consumed"));
                }
                self.driver
                    .borrow_mut()
                    .begin_v3(role, selection.clone(), ceiling)?;
                self.v3_selection[index(role)] = Some(selection);
                self.transition(Phase::V3Preparing, frame);
            }
            Intent::ConfirmV3 if self.phase == Phase::V3Review && self.read_to_end => {
                self.transition(Phase::V3Confirm, frame)
            }
            Intent::PasswordV3 if self.phase == Phase::V3Confirm && self.acknowledged => {
                let offer = self
                    .v3_offer
                    .as_ref()
                    .ok_or_else(|| rejected("V3 offer missing"))?;
                offer.check_current()?;
                let binding = self
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("V3 password binding missing"))?;
                self.password = Some(
                    PasswordInput::new(ctx, *binding, offer.native_deadline())
                        .ok_or_else(|| rejected("V3 protected input unavailable"))?,
                );
                self.transition(Phase::V3Password, frame);
            }
            Intent::SelectNextV3
                if matches!(
                    self.phase,
                    Phase::V3Held
                        | Phase::V3Paired
                        | Phase::V3Enrolled
                        | Phase::V3ManifestAccepted
                        | Phase::V3RedisclosurePrepared
                        | Phase::V3Redisclosed
                        | Phase::V3OwnerSelected
                        | Phase::V3Prepared
                        | Phase::V3Received
                ) =>
            {
                self.active = None;
                self.transition(Phase::Selecting, frame);
            }
            Intent::WriterAction if self.phase == Phase::WriterFlow && self.read_to_end => {
                self.writer_action(frame)?;
            }
            Intent::BeginHostLine
                if host_phase_allows_input(self.phase)
                    && self.host_entry == HostEntry::Idle
                    && self.password.is_none() =>
            {
                let ordinal = self
                    .host_ordinal
                    .checked_add(1)
                    .ok_or_else(|| rejected("Host line ordinal exhausted"))?;
                self.host_input = Some(
                    HostLineInput::new(ctx, ordinal, self.session_deadline)
                        .ok_or_else(|| rejected("protected Host line unavailable"))?,
                );
                self.host_ordinal = ordinal;
                self.host_entry = HostEntry::Editing(ordinal);
            }
            Intent::Configure(role)
                if self.phase == Phase::Selecting
                    && self.progress[index(role)] == Progress::NotStarted =>
            {
                self.active = Some(role);
                self.transition(Phase::Configuring, frame);
            }
            Intent::Begin(role, ceiling)
                if self.phase == Phase::Configuring
                    && self.active == Some(role)
                    && selectors_valid(&self.selectors[index(role)])
                    && self.progress[index(role)] == Progress::NotStarted =>
            {
                self.active = Some(role);
                self.progress[index(role)] = Progress::Working;
                self.driver.borrow_mut().begin(role, ceiling)?;
                self.transition(Phase::Preparing, frame);
            }
            Intent::EntryConfirm if self.phase == Phase::EntryReview && self.read_to_end => {
                self.transition(Phase::EntryConfirm, frame)
            }
            Intent::EnterPassword if self.phase == Phase::EntryConfirm && self.acknowledged => {
                let offer = self
                    .entry
                    .as_ref()
                    .ok_or_else(|| rejected("source-entry offer missing"))?;
                offer.check_current()?;
                let binding = self
                    .binding
                    .ok_or_else(|| rejected("source-entry input binding missing"))?;
                self.password = Some(
                    PasswordInput::new(ctx, binding, offer.native_deadline())
                        .ok_or_else(|| rejected("source-entry input unavailable"))?,
                );
                self.transition(Phase::Password, frame);
            }
            Intent::PrepareHistory(ceiling) if self.phase == Phase::HistorySetupNeeded => {
                let role = self
                    .active
                    .ok_or_else(|| rejected("History Setup role missing"))?;
                let read = self
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("History Setup Read missing"))?;
                read.check_current()?;
                if ceiling > read.native_deadline() {
                    return Err(rejected("History Setup clock widened"));
                }
                let inputs = history_inputs(&self.selectors[index(role)])?;
                self.driver
                    .borrow_mut()
                    .prepare_history(role, inputs, ceiling)?;
                self.transition(Phase::HistorySetupPreparing, frame);
            }
            Intent::SetupHistory
                if self.phase == Phase::HistorySetupReview
                    && self.read_to_end
                    && self.acknowledged =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("History Setup role missing"))?;
                let ticket = self
                    .history_setup
                    .take()
                    .ok_or_else(|| rejected("History Setup consumed"))?;
                let outbound = self.native.admit_history_setup(ticket)?;
                self.driver
                    .borrow_mut()
                    .send_history_setup(role, outbound)?;
                self.transition(Phase::HistoryPreparing, frame);
            }
            Intent::ServeHistory
                if self.phase == Phase::HistoryReview && self.read_to_end && self.acknowledged =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("History Serve role missing"))?;
                let ticket = self
                    .history_review
                    .take()
                    .ok_or_else(|| rejected("History Serve consumed"))?;
                let outbound = self.native.admit_history_serve(ticket)?;
                self.driver
                    .borrow_mut()
                    .send_history_serve(role, outbound)?;
                self.transition(Phase::HistoryStarting, frame);
            }
            Intent::ReadConfirm if self.phase == Phase::ReadReview && self.read_to_end => {
                self.transition(Phase::ReadConfirm, frame)
            }
            Intent::Read if self.phase == Phase::ReadConfirm && self.acknowledged => {
                let role = self
                    .active
                    .ok_or_else(|| rejected("initial Read role missing"))?;
                let ticket = self
                    .read
                    .take()
                    .ok_or_else(|| rejected("initial Read ticket missing"))?;
                let serving = self
                    .history_serving
                    .take()
                    .ok_or_else(|| rejected("initial Read actual History Serving missing"))?;
                let outbound = self.native.admit_initial_read(ticket, &serving)?;
                // The genuine outbound retains its own same-Core service lease
                // through send. This check-only handle is not later ancestry.
                drop(serving);
                self.driver.borrow_mut().send_read(role, outbound)?;
                self.transition(Phase::Reading, frame);
            }
            Intent::BeginContinue if self.phase == Phase::HistoryReady => {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Continue role missing"))?;
                let ceiling = self
                    .continue_deadline
                    .ok_or_else(|| rejected("original Continue deadline missing"))?;
                // Authenticated HistoryRetained supplied this immutable clock;
                // the endpoint independently caps against the same original.
                self.driver.borrow_mut().begin_continue(role, ceiling)?;
                self.transition(Phase::ContinuePreparing, frame);
            }
            Intent::ContinueConfirm if self.phase == Phase::ContinueReview && self.read_to_end => {
                self.transition(Phase::ContinueConfirm, frame);
            }
            Intent::ArmContinue if self.phase == Phase::ContinueConfirm && self.acknowledged => {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Continue role missing"))?;
                let ticket = self
                    .continue_review
                    .take()
                    .ok_or_else(|| rejected("Continue review consumed"))?;
                let outbound = self.native.arm_continue(ticket)?;
                self.driver.borrow_mut().send_continue_arm(role, outbound)?;
                self.transition(Phase::ContinueArmed, frame);
                self.message = "This exact Continue was approved locally. Waiting for its original Ready and final eligible native admission; Admit remains separate.";
            }
            Intent::PrepareSetup(ceiling) if self.phase == Phase::SetupNeeded => {
                let role = self.active.ok_or_else(|| rejected("Setup role missing"))?;
                let p = self.retained_continue[index(role)]
                    .as_ref()
                    .ok_or_else(|| rejected("authenticated Continue request missing"))?;
                let mut inputs = self.selectors[index(role)].clone();
                inputs.request_json = p.request_json.clone(); // ONLY exact actual authenticated bytes.
                inputs.validate()?;
                self.driver
                    .borrow_mut()
                    .prepare_witness(role, inputs, ceiling)?;
                self.transition(Phase::SetupPreparing, frame);
            }
            Intent::Setup
                if self.phase == Phase::SetupReview && self.read_to_end && self.acknowledged =>
            {
                let role = self.active.ok_or_else(|| rejected("Setup role missing"))?;
                let ticket = self
                    .setup
                    .take()
                    .ok_or_else(|| rejected("Setup ticket consumed"))?;
                let outbound = self.native.admit_witness_setup(ticket)?;
                self.driver
                    .borrow_mut()
                    .send_witness_setup(role, outbound)?;
                self.transition(Phase::AdmissionReview, frame);
                self.message = "Setup admitted only protected reads/listener preparation. Review both complete exact actions, then approve each separately.";
            }
            Intent::ArmSigner
                if self.phase == Phase::AdmissionReview
                    && paired_approved(self.paired)
                    && !self.signer_arm_sent =>
            {
                let role = self.active.ok_or_else(|| rejected("Admit role missing"))?;
                let ticket = self
                    .signer_review
                    .take()
                    .ok_or_else(|| rejected("Signer Admit review consumed"))?;
                let outbound = self.native.arm_admit(ticket)?;
                self.signer_arm_sent = true;
                self.driver.borrow_mut().send_admit_arm(role, outbound)?;
            }
            Intent::ArmWitness
                if self.phase == Phase::AdmissionReview
                    && paired_approved(self.paired)
                    && !self.witness_arm_sent =>
            {
                let role = self
                    .active
                    .ok_or_else(|| rejected("Witness role missing"))?;
                let ticket = self
                    .witness_review
                    .take()
                    .ok_or_else(|| rejected("Witness review consumed"))?;
                let outbound = self.native.arm_witness(ticket)?;
                self.witness_arm_sent = true;
                self.driver.borrow_mut().send_witness_arm(role, outbound)?;
            }
            _ => return Err(rejected("stale source-action intent")),
        }
        Ok(())
    }
    fn history_retirement_tail(&mut self) -> Result<()> {
        if !matches!(
            self.phase,
            Phase::HistoryRetiring | Phase::RetirementBlocked
        ) || !self.focused_last
            || self.native.is_revoked()
        {
            return Err(rejected("History retirement outside eligible native tail"));
        }
        if let Some(ticket) = self.history_retirement.take() {
            let role = ticket.role();
            let cutoff = ticket.deadline();
            if self.active != Some(role) || self.retirement_paused.is_some() {
                return Err(rejected("History retirement already paused"));
            }
            let outbound = self.native.pause_for_witness_retirement(ticket)?;
            self.retirement_paused = Some((role, cutoff));
            if self.phase == Phase::RetirementBlocked {
                self.driver
                    .borrow_mut()
                    .send_signing_predecessor_retirement(role, outbound)?;
            } else {
                self.driver
                    .borrow_mut()
                    .send_history_retirement(role, outbound)?;
            }
        } else if let Some(completion) = self.history_retired.take() {
            let role = completion.role();
            if self
                .retirement_paused
                .is_none_or(|(expected, _)| expected != role)
            {
                return Err(rejected("History retirement completion changed"));
            }
            self.native.resume_after_witness_retirement(completion)?;
            self.retirement_paused = None;
            self.history_resume_pending = Some(role);
            // The sole endpoint still must consume its private actual resume
            // observation before its driver can report HistoryResumed.
        }
        Ok(())
    }
    fn submit_password(&mut self, input: BoundPassword, frame: u64) -> Result<()> {
        if self.phase == Phase::V3Password {
            return self.submit_v3_password(input, frame);
        }
        if self.phase != Phase::Password {
            return Err(rejected("password outside exact credential phase"));
        }
        let role = self
            .active
            .ok_or_else(|| rejected("source-entry role missing"))?;
        let binding = self
            .binding
            .take()
            .ok_or_else(|| rejected("source-entry binding consumed"))?;
        let offer = self
            .entry
            .take()
            .ok_or_else(|| rejected("source-entry offer consumed"))?;
        let mut password = input
            .into_password_for(&binding)
            .ok_or_else(|| rejected("source-entry input expired or changed"))?;
        // Transfer the String's SAME owned allocation, without a plaintext clone.
        // Both old wrapper and new bytes remain zeroizing owners throughout.
        let bytes = Zeroizing::new(std::mem::take(&mut *password).into_bytes());
        drop(password);
        self.password.take();
        let outbound = self
            .native
            .admit_source_entry(offer, bytes, &self.request_digest)?;
        self.request_digest.zeroize();
        self.driver.borrow_mut().send_entry(role, outbound)?;
        self.transition(Phase::Opening, frame);
        Ok(())
    }
}
impl eframe::App for Window {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        self.intent = None;
        // Do not scrub before the whole original interruption history is latched.
        self.interrupt(raw_facts(raw), ctx);
        self.check_current();
        self.poll_driver(ctx);
        if self.host_input.is_some() && self.password.is_some() {
            self.revoke("Protected Host and Signer input cannot share an event batch.");
        }
        if let Some(input) = &mut self.host_input {
            input.raw_input_hook(raw, &mut || self.native.revoke());
        } else if let Some(input) = &mut self.password {
            input.raw_input_hook(raw);
        } else if self.phase == Phase::V3OwnerConfiguring
            && self.focused_last
            && !self.native.is_revoked()
        {
            if !v3_owner_events_bounded(&raw.events) {
                self.revoke("Owner setup public event exceeded exact bounds.");
                scrub_unrequested_payloads(&mut raw.events);
            }
        } else if self.phase == Phase::V3Configuring
            && self.focused_last
            && !self.native.is_revoked()
        {
            if !v3_events_bounded(&raw.events) {
                self.revoke("V3 public selection event exceeded fixed bounds.");
                scrub_unrequested_payloads(&mut raw.events);
            }
        } else if self.phase == Phase::Configuring && self.focused_last && !self.native.is_revoked()
        {
            if !selector_events_bounded(&raw.events) {
                self.revoke("Ordinary selector input contained invalid or oversized text. No altered line is accepted.");
                scrub_unrequested_payloads(&mut raw.events);
            }
        } else {
            scrub_unrequested_payloads(&mut raw.events);
        }
        self.check_current();
        ctx.request_repaint_after(Duration::from_millis(20));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}
impl Drop for Window {
    fn drop(&mut self) {
        self.native.revoke();
        self.driver.borrow().revoke();
        if let Some(input) = &mut self.host_input {
            input.cancel(&mut || self.native.revoke());
        }
        if let Some(input) = &mut self.password {
            input.cancel();
        }
        self.clear_review();
        self.host_output.clear_and_close();
    }
}

fn paired_progress_after_pass(
    current: PairedConsent,
    painted: PairedConsent,
    eligible: bool,
    same_phase: bool,
) -> PairedConsent {
    if eligible && same_phase {
        painted
    } else {
        current
    }
}
fn paired_tail_eligible(phase: Phase, focused: bool, revoked: bool, later: bool) -> bool {
    phase == Phase::AdmissionReview && focused && !revoked && later
}
fn paired_approved(consent: PairedConsent) -> bool {
    consent.read == [true; 2] && consent.acknowledged == [true; 2]
}
fn admission_effect_text(effect: AdmissionEffect) -> &'static str {
    match effect {
        AdmissionEffect::None => "no actual admission result",
        AdmissionEffect::Pending => "native admission recorded; result unconfirmed",
        AdmissionEffect::Committed => "authenticated committed outcome observed",
        AdmissionEffect::KnownNoEffect => "authenticated known-no-effect outcome observed",
        AdmissionEffect::Uncertain => "authenticated uncertain outcome; do not retry",
    }
}
fn selector_text_bounded(value: &str, limit: usize) -> bool {
    value.len() <= limit && !value.chars().any(|ch| ch.is_control())
}
fn selector_fields(p: &FinancialWitnessInputsV1) -> [(&str, &str, usize); 11] {
    [
        ("Listener endpoint", &p.endpoint, 4096),
        ("TLS server name", &p.server_name, 4096),
        ("Witness / namespace ID", &p.witness_id, 4096),
        (
            "Pinned server certificate digest (lowercase hex)",
            &p.pinned_server_certificate_digest,
            64,
        ),
        ("Network profile ID", &p.network_profile_id, 4096),
        (
            "Expected account ID (lowercase hex)",
            &p.expected_account_id,
            64,
        ),
        (
            "Public owner certificate DER hex, NOT a private key",
            &p.owner_certificate_der_hex,
            32768,
        ),
        ("Existing storage key FILE PATH", &p.storage_key_file, 4096),
        (
            "Existing server certificate DER FILE PATH",
            &p.server_certificate_der,
            4096,
        ),
        (
            "Existing server private key PKCS8 DER FILE PATH, NOT key bytes",
            &p.server_private_key_pkcs8_der,
            4096,
        ),
        (
            "Existing trusted client root DER FILE PATH",
            &p.trusted_client_root_der,
            4096,
        ),
    ]
}
fn selectors_bounded(p: &FinancialWitnessInputsV1) -> bool {
    p.request_json.is_empty()
        && selector_fields(p)
            .iter()
            .all(|(_, value, limit)| selector_text_bounded(value, *limit))
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn selectors_valid(p: &FinancialWitnessInputsV1) -> bool {
    selectors_bounded(p)
        && selector_fields(p)
            .iter()
            .all(|(_, value, _)| !value.is_empty())
        && p.pinned_server_certificate_digest.len() == 64
        && lower_hex(&p.pinned_server_certificate_digest)
        && p.expected_account_id.len() == 64
        && lower_hex(&p.expected_account_id)
        && p.owner_certificate_der_hex.len() % 2 == 0
        && lower_hex(&p.owner_certificate_der_hex)
        && [
            &p.storage_key_file,
            &p.server_certificate_der,
            &p.server_private_key_pkcs8_der,
            &p.trusted_client_root_der,
        ]
        .iter()
        .all(|v| v.starts_with('/'))
}
fn selector_events_bounded(events: &[egui::Event]) -> bool {
    let mut bytes = 0usize;
    for event in events {
        let value = match event {
            egui::Event::Text(text)
            | egui::Event::Paste(text)
            | egui::Event::Ime(egui::ImeEvent::Preedit { text, .. })
            | egui::Event::Ime(egui::ImeEvent::Commit(text)) => text,
            _ => continue,
        };
        bytes = match bytes.checked_add(value.len()) {
            Some(n) => n,
            None => return false,
        };
        // Reject before stock single-line TextEdit can normalize CR/LF. These
        // are ordinary selectors, but no altered selector is silently accepted.
        if bytes > 32768 || !selector_text_bounded(value, 32768) {
            return false;
        }
    }
    true
}
fn draw_selectors(ui: &mut egui::Ui, p: &mut FinancialWitnessInputsV1) {
    let fields = [
        ("Listener endpoint", &mut p.endpoint),
        ("TLS server name", &mut p.server_name),
        ("Witness / namespace ID", &mut p.witness_id),
        (
            "Pinned server certificate digest",
            &mut p.pinned_server_certificate_digest,
        ),
        ("Network profile ID", &mut p.network_profile_id),
        ("Expected account ID", &mut p.expected_account_id),
        (
            "Public owner certificate DER hex",
            &mut p.owner_certificate_der_hex,
        ),
        ("Existing storage key FILE PATH", &mut p.storage_key_file),
        (
            "Existing server certificate DER FILE PATH",
            &mut p.server_certificate_der,
        ),
        (
            "Existing server private key PKCS8 DER FILE PATH, NOT key bytes",
            &mut p.server_private_key_pkcs8_der,
        ),
        (
            "Existing trusted client root DER FILE PATH",
            &mut p.trusted_client_root_der,
        ),
    ];
    egui::ScrollArea::vertical()
        .id_salt("ordinary-witness-selectors")
        .max_height(470.0)
        .show(ui, |ui| {
            for (ordinal, (label, value)) in fields.into_iter().enumerate() {
                ui.label(label);
                ui.add(
                    egui::TextEdit::singleline(value)
                        .id(egui::Id::new(("ordinary-witness-selector", ordinal))),
                );
            }
        });
}
fn history_inputs(p: &FinancialWitnessInputsV1) -> Result<FinancialHistoryInputsV1> {
    if !selectors_valid(p) {
        return Err(rejected(
            "History selectors changed or contain a request override",
        ));
    }
    let inputs = FinancialHistoryInputsV1 {
        endpoint: p.endpoint.clone(),
        server_name: p.server_name.clone(),
        witness_id: p.witness_id.clone(),
        pinned_server_certificate_digest: p.pinned_server_certificate_digest.clone(),
        network_profile_id: p.network_profile_id.clone(),
        expected_account_id: p.expected_account_id.clone(),
        owner_certificate_der_hex: p.owner_certificate_der_hex.clone(),
        storage_key_file: p.storage_key_file.clone(),
        server_certificate_der: p.server_certificate_der.clone(),
        server_private_key_pkcs8_der: p.server_private_key_pkcs8_der.clone(),
        trusted_client_root_der: p.trusted_client_root_der.clone(),
    };
    inputs.validate()?;
    Ok(inputs)
}
fn history_setup_display(ticket: &FinancialHistorySetupTicketV1) -> String {
    let p = ticket.inputs();
    format!("Complete exact History Setup selectors (quoted values preserve distinctions):\nListener endpoint: {:?}\nTLS server name: {:?}\nWitness / namespace ID: {:?}\nPinned server certificate: {}\nNetwork: {:?}\nExpected account: {}\nPublic owner certificate DER hex: {:?}\nExisting storage key FILE PATH: {:?}\nExisting server certificate FILE PATH: {:?}\nExisting server private key FILE PATH: {:?}\nExisting trusted client root FILE PATH: {:?}\n\nComplete original Signer Read binding, not a grant:\n{:#?}", p.endpoint, p.server_name, p.witness_id, p.pinned_server_certificate_digest, p.network_profile_id, p.expected_account_id, p.owner_certificate_der_hex, p.storage_key_file, p.server_certificate_der, p.server_private_key_pkcs8_der, p.trusted_client_root_der, ticket.read_binding().read)
}
fn history_display(p: &FinancialHistoryPresentationV1) -> String {
    format!("{}\n\nComplete authenticated owner-only History presentation:\nVersion: {}\nPurpose: {:?}\nMode: {:?}\nBackend review: {}\nPresentation: {}\nPrepared Unix ms: {}\nExpires Unix ms: {}\nAccount: {}\nNetwork: {:?}\nSource commitment: {}\nPolicy: {}\nOwner certificate: {}\nActual current head sequence: {}\nActual current head digest: {}\n\nComplete original Signer Read binding (delivery head is historical):\n{:#?}", p.display, p.version, p.purpose, p.mode, p.backend_review_digest, p.presentation_digest, p.prepared_at_ms, p.expires_at_ms, p.account_id, p.network_profile_id, p.source_commitment, p.policy_digest, p.owner_certificate_digest, p.expected_head_sequence, p.expected_head_digest, p.read_binding.read)
}
fn setup_display(ticket: &FinancialWitnessSetupTicketV1) -> String {
    let mut text = String::from(
        "Complete exact Setup selectors (quoted values preserve control/format distinctions):\n",
    );
    for (label, value, _) in selector_fields(ticket.inputs()) {
        text.push_str(&format!("{label}: {value:?}\n"));
    }
    let c = ticket.continuation();
    text.push_str(&format!("Exact authenticated request bytes: {:?}\nActual actor: {:#?}\nContinue presentation: {}\nPrepared: {}\nSigner source: {}\nAdmission terms: {}\nRequest digest: {}\nOriginal source ceiling offset ms: {}\nSource expiry Unix ms: {}\n", ticket.inputs().request_json, c.actor, c.continue_presentation_digest, c.prepared_digest, c.signer_source_identity_digest, c.admission_terms_digest, c.request_digest, c.source_ceiling_ms, c.source_expires_at_ms));
    text
}
fn witness_display(p: &FinancialWitnessPresentationV1) -> String {
    let c = &p.continuation;
    format!("{}\n\nComplete authenticated Witness presentation:\nVersion: {}\nPurpose: {:?}\nMode: {:?}\nBackend review: {}\nPresentation: {}\nPrepared Unix ms: {}\nExpires Unix ms: {}\nAccount: {}\nOperation: {:?}\nRequest commitment: {}\nSource commitment: {}\nOwner certificate: {}\nExpected head sequence: {}\nExpected head digest: {}\nActual actor: {:#?}\nContinue presentation: {}\nPrepared commitment: {}\nSigner source: {}\nAdmission terms: {}\nExact request bytes: {:?}\nRequest digest: {}\nOriginal source ceiling offset ms: {}\nSource expiry Unix ms: {}\n", p.display, p.version, p.purpose, p.mode, p.backend_review_digest, p.presentation_digest, p.prepared_at_ms, p.expires_at_ms, p.account_id, p.operation_id, p.request_commitment, p.source_commitment, p.owner_certificate_digest, p.expected_head_sequence, p.expected_head_digest, c.actor, c.continue_presentation_digest, c.prepared_digest, c.signer_source_identity_digest, c.admission_terms_digest, c.request_json, c.request_digest, c.source_ceiling_ms, c.source_expires_at_ms)
}
fn host_phase_allows_input(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Selecting | Phase::HistoryReady | Phase::Waiting
    )
}
fn host_entry_blocks_source(entry: HostEntry) -> bool {
    matches!(entry, HostEntry::Editing(_) | HostEntry::Writing(_))
}
fn review_display(ui: &mut egui::Ui, display: &str, eligible: bool) -> bool {
    let mut end_visible = false;
    egui::ScrollArea::vertical()
        .max_height(390.0)
        .show(ui, |ui| {
            ui.monospace(display);
            let end = ui.label("End of the complete authenticated review");
            end_visible = eligible && ui.is_rect_visible(end.rect);
        });
    end_visible
}
fn index(role: Role) -> usize {
    match role {
        Role::Signer1 => 0,
        Role::Signer2 => 1,
    }
}
fn input_role(role: Role) -> InputRole {
    match role {
        Role::Signer1 => InputRole::Signer1,
        Role::Signer2 => InputRole::Signer2,
    }
}
fn role_name(role: Role) -> &'static str {
    match role {
        Role::Signer1 => "Signer 1",
        Role::Signer2 => "Signer 2",
    }
}
fn stage_name(stage: FinancialWorkflowStageV1) -> &'static str {
    match stage {
        FinancialWorkflowStageV1::SourceEntry => "source entry",
        FinancialWorkflowStageV1::InitialRead => "history Read and one local preparation",
        FinancialWorkflowStageV1::Continue => "local Continue",
    }
}
fn progress_text(progress: Progress) -> &'static str {
    match progress {
        Progress::NotStarted => "not started",
        Progress::Working => "review or source entry pending",
        Progress::SourceRetained => "source retained; Read not yet completed",
        Progress::HistoryRetained => {
            "history and one local preparation retained; Continue not admitted"
        }
        Progress::ContinueAdmitted => "Continue admitted; actual outcome pending",
        Progress::AwaitingAdmission => "continuation saved; awaiting separate financial Admit",
        Progress::AwaitingNextRead => {
            "authenticated admission observed; later Read remains separate"
        }
    }
}
fn effect_text(effect: ContinueEffect) -> &'static str {
    match effect {
        ContinueEffect::None => "no Continue result",
        ContinueEffect::Pending => "Continue admitted; actual result unconfirmed",
        ContinueEffect::Saved => "actual saved continuation observed",
        ContinueEffect::KnownNoEffect => "actual known-no-effect outcome observed",
        ContinueEffect::Uncertain => "actual uncertain outcome observed; do not retry",
    }
}
fn retained_deadline_accepts(retained: Option<Instant>, incoming: Instant) -> bool {
    retained.is_some_and(|original| incoming <= original)
}
fn may_admit_continue(
    phase: Phase,
    ready: bool,
    focused: bool,
    revoked: bool,
    later_frame: bool,
) -> bool {
    phase == Phase::ContinueArmed && ready && focused && !revoked && later_frame
}
fn matches_commitment(
    expected: Option<&(String, String)>,
    presentation: &str,
    prepared: &str,
) -> bool {
    expected.is_some_and(|(p, e)| p == presentation && e == prepared)
}
fn read_scope_matches(version: u16, purpose: &str) -> bool {
    version == 2 && purpose == READ_PURPOSE
}
fn tail_eligible(frame: u64, previous: Option<u64>, visible: bool, discarded: bool) -> bool {
    visible && !discarded && previous != Some(frame)
}
fn review_progress_after_pass(
    current: (bool, bool),
    painted: (bool, bool),
    eligible: bool,
    same_phase: bool,
) -> (bool, bool) {
    if eligible && same_phase {
        painted
    } else {
        current
    }
}
fn must_revoke(seen: bool, previous: bool, focused: bool, blur: bool, escape: bool) -> bool {
    blur || escape || (seen && previous && !focused)
}
struct RawFacts {
    focused: bool,
    blur: bool,
    escape: bool,
    close: bool,
}
fn is_blur(event: &egui::Event) -> bool {
    matches!(event, egui::Event::WindowFocused(false))
}
fn is_escape(event: &egui::Event) -> bool {
    matches!(
        event,
        egui::Event::Key {
            key: egui::Key::Escape,
            pressed: true,
            ..
        }
    )
}
fn raw_facts(raw: &egui::RawInput) -> Option<RawFacts> {
    if raw.viewport_id != egui::ViewportId::ROOT || raw.viewports.len() != 1 {
        return None;
    }
    let viewport = raw.viewports.get(&egui::ViewportId::ROOT)?;
    Some(RawFacts {
        focused: raw.focused && viewport.focused == Some(true),
        blur: raw.events.iter().any(is_blur),
        escape: raw.events.iter().any(is_escape),
        close: viewport.close_requested(),
    })
}
fn scrub_unrequested_payloads(events: &mut Vec<egui::Event>) {
    events.retain_mut(|event| match event {
        egui::Event::Text(text)
        | egui::Event::Paste(text)
        | egui::Event::Ime(egui::ImeEvent::Preedit { text, .. })
        | egui::Event::Ime(egui::ImeEvent::Commit(text)) => {
            text.zeroize();
            false
        }
        egui::Event::Ime(_) => false,
        _ => true,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paired_consent_requires_two_complete_reviews_and_separate_acknowledgments() {
        let mut p = PairedConsent::default();
        assert!(!paired_approved(p));
        p.read = [true; 2];
        p.acknowledged[0] = true;
        assert!(!paired_approved(p));
        p.acknowledged[1] = true;
        assert!(paired_approved(p));
        p.read[1] = false;
        assert!(!paired_approved(p));
    }
    #[test]
    fn discarded_paired_pass_cannot_prime_later_arms() {
        let current = PairedConsent::default();
        let painted = PairedConsent {
            read: [true; 2],
            acknowledged: [true; 2],
        };
        assert!(!paired_approved(paired_progress_after_pass(
            current, painted, false, true
        )));
        assert!(!paired_approved(paired_progress_after_pass(
            current, painted, true, false
        )));
        assert!(paired_approved(paired_progress_after_pass(
            current, painted, true, true
        )));
    }
    #[test]
    fn paired_ready_tail_never_survives_cancel_hidden_or_wrong_phase() {
        assert!(paired_tail_eligible(
            Phase::AdmissionReview,
            true,
            false,
            true
        ));
        assert!(!paired_tail_eligible(
            Phase::AdmissionReview,
            true,
            true,
            true
        ));
        assert!(!paired_tail_eligible(
            Phase::AdmissionReview,
            false,
            false,
            true
        ));
        assert!(!paired_tail_eligible(
            Phase::AdmissionReview,
            true,
            false,
            false
        ));
        for phase in [
            Phase::SetupReview,
            Phase::RetirementBlocked,
            Phase::Revoked,
            Phase::Finished,
        ] {
            assert!(!paired_tail_eligible(phase, true, false, true));
        }
    }
    #[test]
    fn ordinary_selector_batch_rejects_line_normalization_and_oversized_payloads() {
        for value in ["public\npath", "public\rpath", "public\0path"] {
            assert!(!selector_events_bounded(&[egui::Event::Paste(
                value.into()
            )]));
        }
        assert!(selector_events_bounded(&[egui::Event::Text(
            "/public/example".into()
        )]));
        assert!(!selector_events_bounded(&[egui::Event::Text(
            "x".repeat(32769)
        )]));
        assert!(!selector_events_bounded(&[
            egui::Event::Text("x".repeat(20000)),
            egui::Event::Paste("y".repeat(20000))
        ]));
    }
    #[test]
    fn ordinary_selectors_cannot_supply_or_replace_authenticated_request() {
        let mut p = FinancialWitnessInputsV1::default();
        assert!(selectors_bounded(&p));
        assert!(!selectors_valid(&p));
        p.request_json = "{\"public\":true}".into();
        assert!(!selectors_bounded(&p));
        p.request_json.clear();
        p.server_name = "x".repeat(4097);
        assert!(!selectors_bounded(&p));
    }
    #[test]
    fn initial_history_selectors_are_exact_ordinary_data_without_request_override() {
        let p = FinancialWitnessInputsV1 {
            endpoint: "127.0.0.1:10001".into(),
            server_name: "public.example".into(),
            witness_id: "public-witness".into(),
            pinned_server_certificate_digest: "1".repeat(64),
            network_profile_id: "public-network".into(),
            expected_account_id: "2".repeat(64),
            owner_certificate_der_hex: "aabb".into(),
            storage_key_file: "/public/storage".into(),
            server_certificate_der: "/public/certificate".into(),
            server_private_key_pkcs8_der: "/public/key-path".into(),
            trusted_client_root_der: "/public/root".into(),
            request_json: String::new(),
        };
        let h = history_inputs(&p).unwrap();
        let mut expected = serde_json::to_value(&p).unwrap();
        expected.as_object_mut().unwrap().remove("request_json");
        assert!(serde_json::to_value(&h).unwrap() == expected);
        let mut injected = p.clone();
        injected.request_json = "{}".into();
        assert!(history_inputs(&injected).is_err());
        let mut changed = p.clone();
        changed.storage_key_file.push('\n');
        assert!(history_inputs(&changed).is_err());
    }
    #[test]
    fn initial_history_approval_phases_are_distinct_and_exclude_host_input() {
        let phases = [
            Phase::HistorySetupNeeded,
            Phase::HistorySetupPreparing,
            Phase::HistorySetupReview,
            Phase::HistoryPreparing,
            Phase::HistoryReview,
            Phase::HistoryStarting,
            Phase::ReadReview,
            Phase::ReadConfirm,
            Phase::Reading,
            Phase::HistoryRetiring,
        ];
        for (i, phase) in phases.iter().enumerate() {
            assert!(!host_phase_allows_input(*phase));
            for other in &phases[i + 1..] {
                assert_ne!(phase, other);
            }
        }
    }
    #[test]
    fn pending_admission_and_missing_outcome_are_never_displayed_as_no_effect() {
        assert!(admission_effect_text(AdmissionEffect::Pending).contains("unconfirmed"));
        assert!(!admission_effect_text(AdmissionEffect::None).contains("known-no-effect"));
        assert!(admission_effect_text(AdmissionEffect::KnownNoEffect).contains("authenticated"));
    }
    #[test]
    fn continue_ticket_cannot_renew_authenticated_preparation_deadline() {
        let original = Instant::now() + Duration::from_secs(60);
        assert!(retained_deadline_accepts(Some(original), original));
        assert!(retained_deadline_accepts(
            Some(original),
            original - Duration::from_millis(1)
        ));
        assert!(!retained_deadline_accepts(
            Some(original),
            original + Duration::from_millis(1)
        ));
        assert!(!retained_deadline_accepts(None, original));
    }
    #[test]
    fn continue_ready_never_admits_before_arm_or_after_same_batch_cancel() {
        assert!(may_admit_continue(
            Phase::ContinueArmed,
            true,
            true,
            false,
            true
        ));
        for phase in [
            Phase::ContinueReview,
            Phase::ContinueConfirm,
            Phase::Continuing,
            Phase::Revoked,
            Phase::Finished,
        ] {
            assert!(!may_admit_continue(phase, true, true, false, true));
        }
        assert!(!may_admit_continue(
            Phase::ContinueArmed,
            false,
            true,
            false,
            true
        ));
        assert!(!may_admit_continue(
            Phase::ContinueArmed,
            true,
            false,
            false,
            true
        ));
        assert!(!may_admit_continue(
            Phase::ContinueArmed,
            true,
            true,
            true,
            true
        ));
        assert!(!may_admit_continue(
            Phase::ContinueArmed,
            true,
            true,
            false,
            false
        ));
    }
    #[test]
    fn saved_outcome_binding_is_exact_and_not_a_payment_result() {
        let expected = ("a".repeat(64), "b".repeat(64));
        assert!(matches_commitment(
            Some(&expected),
            &expected.0,
            &expected.1
        ));
        assert!(!matches_commitment(None, &expected.0, &expected.1));
        assert!(!matches_commitment(
            Some(&expected),
            &expected.1,
            &expected.0
        ));
        assert_ne!(ContinueEffect::Pending, ContinueEffect::Saved);
        assert_ne!(ContinueEffect::KnownNoEffect, ContinueEffect::Uncertain);
        assert!(effect_text(ContinueEffect::Pending).contains("unconfirmed"));
        assert!(progress_text(Progress::AwaitingAdmission)
            .contains("awaiting separate financial Admit"));
    }
    #[test]
    fn combined_read_scope_never_reinterprets_history_only_or_unknown_versions() {
        assert!(read_scope_matches(2, READ_PURPOSE));
        assert!(!read_scope_matches(1, READ_PURPOSE));
        assert!(!read_scope_matches(3, READ_PURPOSE));
        assert!(!read_scope_matches(2, "original-history-only-v1"));
        assert!(!read_scope_matches(
            2,
            "original-history-and-automatic-continue-v2"
        ));
    }
    #[test]
    fn raw_false_then_true_still_restricts_before_payload_scrub() {
        let mut raw = egui::RawInput::default();
        raw.focused = true;
        raw.viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .focused = Some(true);
        raw.events = vec![
            egui::Event::Text("fabricated-only".into()),
            egui::Event::WindowFocused(false),
            egui::Event::WindowFocused(true),
        ];
        let facts = raw_facts(&raw).unwrap();
        assert!(must_revoke(
            false,
            false,
            facts.focused,
            facts.blur,
            facts.escape
        ));
        scrub_unrequested_payloads(&mut raw.events);
        assert_eq!(
            raw.events,
            vec![
                egui::Event::WindowFocused(false),
                egui::Event::WindowFocused(true)
            ]
        );
    }
    #[test]
    fn native_tail_rejects_hidden_discarded_and_repeated_passes() {
        assert!(tail_eligible(7, None, true, false));
        assert!(!tail_eligible(7, None, false, false));
        assert!(!tail_eligible(7, None, true, true));
        assert!(!tail_eligible(7, Some(7), true, false));
    }
    #[test]
    fn discarded_first_pass_cannot_prime_acknowledgment_or_read_progress() {
        let empty = (false, false);
        let painted = (true, true);
        let discarded = review_progress_after_pass(empty, painted, false, true);
        assert_eq!(discarded, empty);
        assert_eq!(
            review_progress_after_pass(discarded, empty, true, true),
            empty
        );
        assert_eq!(
            review_progress_after_pass(empty, painted, true, true),
            painted
        );
        // Never restore speculative consent over an actual cancellation/phase change.
        assert_eq!(
            review_progress_after_pass(empty, painted, true, false),
            empty
        );
    }
    #[test]
    fn history_retained_is_not_a_terminal_or_financial_result() {
        assert!(progress_text(Progress::HistoryRetained).contains("Continue not admitted"));
        assert!(progress_text(Progress::AwaitingAdmission).contains("separate financial Admit"));
        assert_ne!(Phase::Waiting, Phase::Finished);
        assert_ne!(Phase::ReadReview, Phase::Reading);
        assert_ne!(Phase::Opening, Phase::ReadConfirm);
    }
    #[test]
    fn missing_or_extra_viewport_is_not_a_root_review() {
        let mut raw = egui::RawInput::default();
        raw.viewports.clear();
        assert!(raw_facts(&raw).is_none());
        raw.viewports
            .insert(egui::ViewportId::ROOT, Default::default());
        raw.viewports.insert(
            egui::ViewportId::from_hash_of("unexpected"),
            Default::default(),
        );
        assert!(raw_facts(&raw).is_none());
    }
    #[test]
    fn protected_host_editor_and_partial_write_exclude_source_controls() {
        assert!(host_entry_blocks_source(HostEntry::Editing(1)));
        assert!(host_entry_blocks_source(HostEntry::Writing(1)));
        assert!(!host_entry_blocks_source(HostEntry::Idle));
        for phase in [Phase::Selecting, Phase::HistoryReady, Phase::Waiting] {
            assert!(host_phase_allows_input(phase));
        }
        for phase in [
            Phase::Password,
            Phase::Preparing,
            Phase::EntryReview,
            Phase::EntryConfirm,
            Phase::Opening,
            Phase::ReadReview,
            Phase::ReadConfirm,
            Phase::Reading,
            Phase::ContinuePreparing,
            Phase::ContinueReview,
            Phase::ContinueConfirm,
            Phase::ContinueArmed,
            Phase::Continuing,
            Phase::Revoked,
            Phase::Finished,
        ] {
            assert!(!host_phase_allows_input(phase));
        }
    }
}

// Ordinary endpoint-authenticated observation only; never a grant or Final issuer.
fn retain_observed_ready_digest(slot: &mut Option<String>, incoming: &str) -> Result<()> {
    if slot.as_deref().is_some_and(|old| old != incoming) {
        return Err(rejected("observed Ready changed"));
    }
    *slot = Some(incoming.to_owned());
    Ok(())
}

fn writer_final_eligible(
    phase: Phase,
    stage: WriterStage,
    ready: bool,
    focused: bool,
    revoked: bool,
    later: bool,
) -> bool {
    phase == Phase::WriterFlow
        && stage == WriterStage::AcquireArmed
        && ready
        && focused
        && !revoked
        && later
}
#[cfg(test)]
mod writer_ui_tests {
    use super::*;
    #[test]
    fn terminal_ready_retains_only_metadata_without_rearming() {
        let mut digest = None;
        retain_observed_ready_digest(&mut digest, "original").unwrap();
        assert_eq!(digest.as_deref(), Some("original"));
        assert!(retain_observed_ready_digest(&mut digest, "replacement").is_err());
        assert!(!writer_final_eligible(
            Phase::Revoked,
            WriterStage::AcquireArmed,
            true,
            true,
            true,
            true
        ));
    }

    #[test]
    fn acquire_requires_real_arm_ready_and_later_visible_tail() {
        assert!(writer_final_eligible(
            Phase::WriterFlow,
            WriterStage::AcquireArmed,
            true,
            true,
            false,
            true
        ));
        for stage in [
            WriterStage::ReadReview,
            WriterStage::Reading,
            WriterStage::AcquireReview,
            WriterStage::Acquiring,
            WriterStage::Acquired,
        ] {
            assert!(!writer_final_eligible(
                Phase::WriterFlow,
                stage,
                true,
                true,
                false,
                true
            ));
        }
        for (ready, focus, revoked, later) in [
            (false, true, false, true),
            (true, false, false, true),
            (true, true, true, true),
            (true, true, false, false),
        ] {
            assert!(!writer_final_eligible(
                Phase::WriterFlow,
                WriterStage::AcquireArmed,
                ready,
                focus,
                revoked,
                later
            ));
        }
        assert!(!writer_final_eligible(
            Phase::Revoked,
            WriterStage::AcquireArmed,
            true,
            true,
            false,
            true
        ));
    }
}

fn v3_text_bounded(text: &str) -> bool {
    text.len() <= 32 * 1024
        && !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
fn parse_v3_selection(text: &str) -> Result<SignerV3SourceEntrySelectionV1> {
    if !v3_text_bounded(text) {
        return Err(rejected("V3 selection input bounds"));
    }
    let value: SignerV3SourceEntrySelectionV1 =
        serde_json::from_str(text).map_err(|_| rejected("V3 selection schema"))?;
    value.validate()?;
    Ok(value)
}
fn v3_events_bounded(events: &[egui::Event]) -> bool {
    events.len() <= 256
        && events.iter().all(|event| match event {
            egui::Event::Text(t)
            | egui::Event::Paste(t)
            | egui::Event::Ime(egui::ImeEvent::Preedit { text: t, .. })
            | egui::Event::Ime(egui::ImeEvent::Commit(t)) => v3_text_bounded(t),
            _ => true,
        })
}
fn v3_selection_matches(
    s: &SignerV3SourceEntrySelectionV1,
    f: &wholepact_financial_coordinator_origin::SignerV3SourceEntryFactsV1,
) -> bool {
    s.canonical_root == f.canonical_root
        && s.account_id == f.account_id
        && s.original_enrollment_ref == f.original_enrollment_ref
        && s.original_manifest_ref == f.original_manifest_ref
        && s.owner_certificate_digest == f.owner_certificate_digest
        && s.witness_disclosure_json == f.witness_disclosure_json
        && s.witness_disclosure_digest == f.witness_disclosure_digest
        && s.session_digest == f.session_digest
        && s.display == f.display
        && s.source_expires_at_ms == f.source_expires_at_ms
}
#[cfg(test)]
mod v3_ui_tests {
    use super::*;
    #[test]
    fn initial_v3_selection_requires_exact_schema_and_no_invented_metadata() {
        assert!(parse_v3_selection("").is_err());
        assert!(parse_v3_selection("{}").is_err());
        assert!(parse_v3_selection("{\"canonical_root\":\"/tmp\"}").is_err());
        assert!(!v3_text_bounded(&"x".repeat(32 * 1024 + 1)));
        assert!(!v3_text_bounded("ordinary\0selection"));
        assert!(v3_text_bounded("{\n\t\"ordinary\": 1\n}"));
    }
    #[test]
    fn initial_v3_password_never_is_a_writer_final_or_legacy_phase() {
        assert_ne!(Phase::V3Password, Phase::Password);
        assert_ne!(Phase::V3Opening, Phase::Opening);
        assert!(!writer_final_eligible(
            Phase::V3Password,
            WriterStage::AcquireArmed,
            true,
            true,
            false,
            true
        ));
        assert!(!host_phase_allows_input(Phase::V3Password));
    }
}

fn v3_pair_final_eligible(
    phase: Phase,
    read: bool,
    acknowledged: bool,
    ticket: bool,
    focused: bool,
    revoked: bool,
    later: bool,
) -> bool {
    phase == Phase::V3PairReview && read && acknowledged && ticket && focused && !revoked && later
}
fn v3_pair_matches_source(
    p: &SignerV3PairPresentationV1,
    e: &SignerV3PairEndpointV1,
    s: &SignerV3SourceOpenedV1,
    host: &str,
) -> bool {
    let f = &p.facts;
    f.entry_presentation_digest == s.entry_presentation_digest
        && f.source_identity_digest == s.source_identity_digest
        && f.entry_presentation_digest == e.entry_presentation_digest
        && f.source_identity_digest == e.source_identity_digest
        && f.endpoint_digest == e.endpoint_digest
        && f.signer_process_instance == e.signer_process_instance
        && f.coordinated_provider_reference == e.coordinated_provider_reference
        && f.source_expires_at_ms == e.source_expires_at_ms
        && f.original_host_process_instance == host
}
fn v3_pair_result_matches(data: &SignerV3PairedV1, p: &SignerV3PairPresentationV1) -> bool {
    data.presentation_digest == p.presentation_digest
        && data.source_identity_digest == p.facts.source_identity_digest
        && data.original_host_process_instance == p.facts.original_host_process_instance
        && data.channel_digest == p.facts.pairing_review_digest
        && data.generation == p.facts.generation
}
#[cfg(test)]
mod v3_pair_ui_tests {
    use super::*;
    #[test]
    fn pair_final_is_a_distinct_explicit_phase_not_open_observation() {
        assert!(v3_pair_final_eligible(
            Phase::V3PairReview,
            true,
            true,
            true,
            true,
            false,
            true
        ));
        for phase in [
            Phase::V3Held,
            Phase::V3Opening,
            Phase::V3Pairing,
            Phase::V3Paired,
            Phase::Revoked,
        ] {
            assert!(!v3_pair_final_eligible(
                phase, true, true, true, true, false, true
            ));
        }
        for (read, ack, ticket, focus, revoked, later) in [
            (false, true, true, true, false, true),
            (true, false, true, true, false, true),
            (true, true, false, true, false, true),
            (true, true, true, false, false, true),
            (true, true, true, true, true, true),
            (true, true, true, true, false, false),
        ] {
            assert!(!v3_pair_final_eligible(
                Phase::V3PairReview,
                read,
                ack,
                ticket,
                focus,
                revoked,
                later
            ));
        }
        assert_ne!(Phase::V3Held, Phase::V3PairReview);
        assert_ne!(Phase::V3Pairing, Phase::V3Paired);
        for phase in [
            Phase::V3Held,
            Phase::V3PairReview,
            Phase::V3Pairing,
            Phase::V3Paired,
        ] {
            assert!(!writer_final_eligible(
                phase,
                WriterStage::AcquireArmed,
                true,
                true,
                false,
                true
            ));
            assert!(!host_phase_allows_input(phase));
        }
    }
    #[test]
    fn paired_observation_binds_actual_pending_channel_not_just_grant_id() {
        // Pure ordinary data; no issuer, endpoint, socket or grant constructor.
        let f = wholepact_financial_coordinator_origin::SignerV3PairFactsV1 {
            channel_expires_at_ms: 300,
            entry_presentation_digest: "11".repeat(32),
            source_identity_digest: "22".repeat(32),
            endpoint_digest: "33".repeat(32),
            pairing_review_digest: "44".repeat(32),
            scope_json: "{}".into(),
            generation: 1,
            original_host_uid: 1,
            original_host_pid: 2,
            original_host_process_instance: "55".repeat(32),
            signer_process_instance: "66".repeat(32),
            coordinated_provider_reference: "77".repeat(32),
            reviewed_at_ms: 100,
            expires_at_ms: 200,
            source_expires_at_ms: 300,
            display: "synthetic public Pair".into(),
        };
        let actor = wholepact_financial_coordinator_origin::FinancialActorContextV1 {
            profile: "synthetic".into(),
            coordinator_process_instance: "aa".repeat(32),
            coordinator_focus_epoch: 1,
            signer_role: Role::Signer1,
            signer_process_instance: f.signer_process_instance.clone(),
            common_image_measurement: "bb".repeat(32),
            session_challenge: "cc".repeat(32),
        };
        let p = SignerV3PairPresentationV1 {
            actor,
            facts: f,
            notice: "ordinary comparison fixture".into(),
            challenge: "dd".repeat(32),
            source_ceiling_ms: 300,
            pair_ceiling_ms: 200,
            channel_ceiling_ms: 300,
            presentation_digest: "ee".repeat(32),
        };
        let endpoint = SignerV3PairEndpointV1 {
            entry_presentation_digest: p.facts.entry_presentation_digest.clone(),
            source_identity_digest: p.facts.source_identity_digest.clone(),
            endpoint_path: "/tmp/synthetic-only/socket".into(),
            endpoint_digest: p.facts.endpoint_digest.clone(),
            signer_process_instance: p.facts.signer_process_instance.clone(),
            coordinated_provider_reference: p.facts.coordinated_provider_reference.clone(),
            source_expires_at_ms: p.facts.source_expires_at_ms,
        };
        let mut opened = SignerV3SourceOpenedV1 {
            entry_presentation_digest: p.facts.entry_presentation_digest.clone(),
            source_identity_digest: p.facts.source_identity_digest.clone(),
        };
        assert!(v3_pair_matches_source(
            &p,
            &endpoint,
            &opened,
            &p.facts.original_host_process_instance
        ));
        assert!(!v3_pair_matches_source(
            &p,
            &endpoint,
            &opened,
            "different original Host"
        ));
        opened.source_identity_digest = "99".repeat(32);
        assert!(!v3_pair_matches_source(
            &p,
            &endpoint,
            &opened,
            &p.facts.original_host_process_instance
        ));
        let mut result = SignerV3PairedV1 {
            presentation_digest: p.presentation_digest.clone(),
            source_identity_digest: p.facts.source_identity_digest.clone(),
            original_host_process_instance: p.facts.original_host_process_instance.clone(),
            grant_id: "01".repeat(32),
            key_digest: "02".repeat(32),
            channel_digest: p.facts.pairing_review_digest.clone(),
            generation: 1,
        };
        assert!(v3_pair_result_matches(&result, &p));
        result.channel_digest = "03".repeat(32);
        assert!(!v3_pair_result_matches(&result, &p));
        result.channel_digest = p.facts.pairing_review_digest.clone();
        result.source_identity_digest = "04".repeat(32);
        assert!(!v3_pair_result_matches(&result, &p));
    }
}

fn v3_receipt_final_eligible(
    phase: Phase,
    expected: Phase,
    read: bool,
    ack: bool,
    ticket: bool,
    focused: bool,
    revoked: bool,
    later: bool,
) -> bool {
    matches!(
        expected,
        Phase::V3EnrollmentReview | Phase::V3ManifestReview
    ) && phase == expected
        && read
        && ack
        && ticket
        && focused
        && !revoked
        && later
}
fn v3_manifest_predecessor_matches(
    current: &str,
    committed: &str,
    session: &str,
    prior_session: &str,
    nonce: &str,
    prior_nonce: &str,
) -> bool {
    current == committed && session == prior_session && nonce != prior_nonce
}
#[cfg(test)]
mod v3_receipt_ui_tests {
    use super::*;
    #[test]
    fn fresh_purposes_never_cross_cast_or_auto_approve() {
        for phase in [Phase::V3EnrollmentReview, Phase::V3ManifestReview] {
            assert!(v3_receipt_final_eligible(
                phase, phase, true, true, true, true, false, true
            ));
            assert!(!v3_receipt_final_eligible(
                Phase::V3Paired,
                phase,
                true,
                true,
                true,
                true,
                false,
                true
            ));
            assert!(!v3_receipt_final_eligible(
                phase, phase, true, false, true, true, false, true
            ));
            assert!(!v3_receipt_final_eligible(
                phase, phase, true, true, true, true, true, true
            ));
            assert!(!v3_receipt_final_eligible(
                phase, phase, true, true, true, true, false, false
            ));
        }
        assert!(!v3_receipt_final_eligible(
            Phase::V3EnrollmentReview,
            Phase::V3ManifestReview,
            true,
            true,
            true,
            true,
            false,
            true
        ));
    }
    #[test]
    fn manifest_requires_exact_committed_enrollment_session_and_fresh_nonce() {
        assert!(v3_manifest_predecessor_matches(
            "commit", "commit", "session", "session", "new", "old"
        ));
        assert!(!v3_manifest_predecessor_matches(
            "historical",
            "commit",
            "session",
            "session",
            "new",
            "old"
        ));
        assert!(!v3_manifest_predecessor_matches(
            "commit", "commit", "other", "session", "new", "old"
        ));
        assert!(!v3_manifest_predecessor_matches(
            "commit", "commit", "session", "session", "old", "old"
        ));
    }
}

fn v3_redisclosure_final_eligible(
    phase: Phase,
    expected: Phase,
    read: bool,
    ack: bool,
    ticket: bool,
    focused: bool,
    revoked: bool,
    later: bool,
) -> bool {
    matches!(
        expected,
        Phase::V3RedisclosureReadReview | Phase::V3RediscloseReview
    ) && phase == expected
        && read
        && ack
        && ticket
        && focused
        && !revoked
        && later
}
fn v3_prepared_matches_read(
    data: &SignerV3RedisclosurePreparedV1,
    p: &SignerV3RedisclosureReadPresentationV1,
) -> bool {
    data.read_presentation_digest == p.presentation_digest
        && data.source_identity_digest == p.facts.source_identity_digest
        && data.current_enrollment_ref == p.facts.current_enrollment_ref
        && data.current_manifest_ref == p.facts.current_manifest_ref
        && data.coordinated_session_id == p.facts.coordinated_session_id
}
fn v3_redisclosed_matches_candidate(
    data: &SignerV3RedisclosedV1,
    p: &SignerV3RedisclosePresentationV1,
) -> bool {
    data.presentation_digest == p.presentation_digest
        && v3_redisclosed_request_matches(
            &data.request_digest,
            &p.facts.prepared.next_request_digest,
            &data.outbox_reference,
            &p.facts.prepared.original_outbox_reference,
        )
}
fn v3_redisclosed_request_matches(
    actual: &str,
    expected: &str,
    outbox: &str,
    original: &str,
) -> bool {
    actual == expected && outbox != original
}
#[cfg(test)]
mod v3_redisclosure_ui_tests {
    use super::*;
    #[test]
    fn read_and_export_are_separate_explicit_native_purposes() {
        for phase in [Phase::V3RedisclosureReadReview, Phase::V3RediscloseReview] {
            assert!(v3_redisclosure_final_eligible(
                phase, phase, true, true, true, true, false, true
            ));
            for prior in [
                Phase::V3ManifestAccepted,
                Phase::V3RedisclosurePrepared,
                Phase::V3Redisclosed,
            ] {
                assert!(!v3_redisclosure_final_eligible(
                    prior, phase, true, true, true, true, false, true
                ));
            }
            assert!(!v3_redisclosure_final_eligible(
                phase, phase, true, false, true, true, false, true
            ));
            assert!(!v3_redisclosure_final_eligible(
                phase, phase, false, true, true, true, false, true
            ));
            assert!(!v3_redisclosure_final_eligible(
                phase, phase, true, true, false, true, false, true
            ));
            assert!(!v3_redisclosure_final_eligible(
                phase, phase, true, true, true, false, false, true
            ));
            assert!(!v3_redisclosure_final_eligible(
                phase, phase, true, true, true, true, true, true
            ));
            assert!(!v3_redisclosure_final_eligible(
                phase, phase, true, true, true, true, false, false
            ));
        }
        assert!(!v3_redisclosure_final_eligible(
            Phase::V3RedisclosureReadReview,
            Phase::V3RediscloseReview,
            true,
            true,
            true,
            true,
            false,
            true
        ));
    }
    #[test]
    fn successful_export_requires_exact_new_request_and_new_outbox() {
        assert!(v3_redisclosed_request_matches("next", "next", "new", "old"));
        assert!(!v3_redisclosed_request_matches(
            "old-request",
            "next",
            "new",
            "old"
        ));
        assert!(!v3_redisclosed_request_matches(
            "next", "next", "old", "old"
        ));
    }
}

fn v3_owner_selection_eligible(redisclosed: bool, attempted: bool, revoked: bool) -> bool {
    redisclosed && !attempted && !revoked
}
fn v3_owner_text_bounded(text: &str) -> bool {
    text.len() <= 16 * 1024 && v3_text_bounded(text)
}
fn parse_v3_owner_selection(text: &str) -> Result<SignerV3OwnerSetupSelectionV1> {
    if !v3_owner_text_bounded(text) {
        return Err(rejected("owner setup selector bounds"));
    }
    SignerV3OwnerSetupSelectionV1::parse_json(text)
}
fn v3_owner_events_bounded(events: &[egui::Event]) -> bool {
    v3_events_bounded(events)
        && events.iter().all(|e| match e {
            egui::Event::Text(t)
            | egui::Event::Paste(t)
            | egui::Event::Ime(egui::ImeEvent::Preedit { text: t, .. })
            | egui::Event::Ime(egui::ImeEvent::Commit(t)) => v3_owner_text_bounded(t),
            _ => true,
        })
}
#[cfg(test)]
mod v3_owner_selection_tests {
    use super::*;
    #[test]
    fn metadata_requires_actual_export_and_is_one_shot_restrictive() {
        assert!(v3_owner_selection_eligible(true, false, false));
        assert!(!v3_owner_selection_eligible(false, false, false));
        assert!(!v3_owner_selection_eligible(true, true, false));
        assert!(!v3_owner_selection_eligible(true, false, true));
    }
    #[test]
    fn owner_setup_is_bounded_strict_metadata_not_credentials() {
        assert!(!v3_owner_text_bounded(&"x".repeat(16 * 1024 + 1)));
        assert!(!v3_owner_text_bounded("a\0b"));
        assert!(parse_v3_owner_selection(r#"{"private_key_bytes":"not-allowed"}"#).is_err());
        assert!(parse_v3_owner_selection("{}").is_err());
    }
}

fn v3_delivery_final_eligible(
    phase: Phase,
    expected: Phase,
    read: bool,
    ack: bool,
    ticket: bool,
    focused: bool,
    revoked: bool,
    later: bool,
) -> bool {
    matches!(
        expected,
        Phase::V3PrepareReadReview | Phase::V3ReceiveReview
    ) && phase == expected
        && read
        && ack
        && ticket
        && focused
        && !revoked
        && later
}
fn v3_delivery_prepared_matches(
    d: &SignerV3PreparedV1,
    p: &SignerV3PrepareReadPresentationV1,
) -> bool {
    d.prepare_read_presentation_digest == p.presentation_digest
        && d.read_session_digest == p.presentation_digest
        && d.preparation_digest == p.facts.preparation_digest
        && d.source_identity_digest == p.facts.source_identity_digest
}
fn v3_receive_matches_prepared(
    p: &SignerV3ReceivePresentationV1,
    r: &SignerV3PrepareReadPresentationV1,
    d: &SignerV3PreparedV1,
) -> bool {
    let f = &p.facts;
    let prior = &r.facts;
    f.prepare_read_presentation_digest == r.presentation_digest
        && f.prepare_read_presentation_digest == d.prepare_read_presentation_digest
        && f.owner_service_digest == d.owner_service_digest
        && f.read_session_digest == d.read_session_digest
        && f.preparation_digest == d.preparation_digest
        && p.service_ceiling_ms == r.service_ceiling_ms
        && p.material_ceiling_ms == r.material_ceiling_ms
        && f.preparation_digest == prior.preparation_digest
        && f.owner_selection_digest == prior.owner_selection_digest
        && f.owner_certificate_digest == prior.owner_certificate_digest
        && f.disclosure_digest == prior.disclosure_digest
        && f.payload_digest == prior.payload_digest
        && f.payload_bytes == prior.payload_bytes
        && f.fixed_identity_digest == prior.fixed_identity_digest
        && f.material_scopes_digest == prior.material_scopes_digest
        && f.service_expires_at_ms == prior.service_expires_at_ms
        && f.material_expires_at_ms == prior.material_expires_at_ms
}
fn v3_delivery_received_matches(d: &SignerV3ReceivedV1, p: &SignerV3ReceivePresentationV1) -> bool {
    d.receive_presentation_digest == p.presentation_digest
        && d.prepare_read_presentation_digest == p.facts.prepare_read_presentation_digest
        && d.source_identity_digest == p.facts.source_identity_digest
        && d.owner_service_digest == p.facts.owner_service_digest
        && d.payload_digest == p.facts.payload_digest
        && d.fixed_identity_digest == p.facts.fixed_identity_digest
        && d.payload_bytes == p.facts.payload_bytes
}
#[cfg(test)]
mod v3_delivery_ui_tests {
    use super::*;
    #[test]
    fn local_preparation_and_receive_never_share_consent() {
        for phase in [Phase::V3PrepareReadReview, Phase::V3ReceiveReview] {
            assert!(v3_delivery_final_eligible(
                phase, phase, true, true, true, true, false, true
            ));
            for prior in [Phase::V3OwnerSelected, Phase::V3Prepared, Phase::V3Received] {
                assert!(!v3_delivery_final_eligible(
                    prior, phase, true, true, true, true, false, true
                ));
            }
            assert!(!v3_delivery_final_eligible(
                phase, phase, true, false, true, true, false, true
            ));
            assert!(!v3_delivery_final_eligible(
                phase, phase, true, true, true, false, false, true
            ));
            assert!(!v3_delivery_final_eligible(
                phase, phase, true, true, true, true, true, true
            ));
            assert!(!v3_delivery_final_eligible(
                phase, phase, true, true, true, true, false, false
            ));
        }
        assert!(!v3_delivery_final_eligible(
            Phase::V3PrepareReadReview,
            Phase::V3ReceiveReview,
            true,
            true,
            true,
            true,
            false,
            true
        ));
    }
}

fn activate_tail_eligible(
    phase: Phase,
    expected: Phase,
    read: bool,
    ack: bool,
    focused: bool,
    revoked: bool,
    later: bool,
) -> bool {
    matches!(
        expected,
        Phase::ActivateReadReview | Phase::ActivateReview | Phase::ActivateReady
    ) && phase == expected
        && read
        && ack
        && focused
        && !revoked
        && later
}
fn activate_original_matches(
    o: &SignerActivateOriginalV1,
    w: &wholepact_financial_coordinator_origin::SignerFinancialWriterReadFactsV1,
    a: &SignerAcquireCommittedV1,
) -> bool {
    &o.acquired == a
        && o.source_identity_digest == w.source_identity_digest
        && o.terms_digest == w.terms_digest
        && o.continuation_request_json == w.continuation_request_json
        && o.continuation_request_digest == w.continuation_request_digest
        && o.original_host_process_instance == w.original_host_process_instance
        && o.owner_certificate_digest == w.owner_certificate_digest
        && o.owner_disclosure_digest == w.owner_disclosure_digest
        && o.writer_selection_digest == w.writer_selection_digest
        && o.source_expires_at_ms == w.source_expires_at_ms
}
#[cfg(test)]
mod activate_ui_tests {
    use super::*;
    #[test]
    fn read_arm_and_final_are_distinct_explicit_visible_tail_decisions() {
        for p in [
            Phase::ActivateReadReview,
            Phase::ActivateReview,
            Phase::ActivateReady,
        ] {
            assert!(activate_tail_eligible(p, p, true, true, true, false, true));
            assert!(!activate_tail_eligible(
                p, p, true, false, true, false, true
            ));
            assert!(!activate_tail_eligible(
                p, p, false, true, true, false, true
            ));
            assert!(!activate_tail_eligible(
                p, p, true, true, false, false, true
            ));
            assert!(!activate_tail_eligible(p, p, true, true, true, true, true));
            assert!(!activate_tail_eligible(
                p, p, true, true, true, false, false
            ));
            for prior in [
                Phase::WriterFlow,
                Phase::ActivateReading,
                Phase::ActivateArmed,
                Phase::Activating,
                Phase::Activated,
            ] {
                assert!(!activate_tail_eligible(
                    prior, p, true, true, true, false, true
                ));
            }
        }
        assert!(!activate_tail_eligible(
            Phase::ActivateReview,
            Phase::ActivateReady,
            true,
            true,
            true,
            false,
            true
        ));
    }
}

fn activate_head_progression(
    old_sequence: u64,
    old_digest: &str,
    new_sequence: u64,
    new_digest: &str,
) -> bool {
    old_sequence.checked_add(1) == Some(new_sequence) && old_digest != new_digest
}
#[cfg(test)]
mod activate_result_tests {
    use super::*;
    #[test]
    fn activation_requires_actual_next_authenticated_head() {
        assert!(activate_head_progression(7, "old", 8, "new"));
        assert!(!activate_head_progression(7, "old", 7, "new"));
        assert!(!activate_head_progression(7, "old", 9, "new"));
        assert!(!activate_head_progression(7, "old", 8, "old"));
        assert!(!activate_head_progression(u64::MAX, "old", 0, "new"));
    }
}
