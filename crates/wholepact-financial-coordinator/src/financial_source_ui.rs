//! Concrete C-only SourceEntry/initial-Read native controller. No bootstrap or
//! binary route calls this leaf yet. Genuine opaque offers/tickets, never DTO
//! casts, reach the final visible event tail. HistoryRetained is waiting custody,
//! not disposal or completed product flow. The separately reviewed Continue uses
//! the same retained Core; a saved continuation is not financial admission.
//!
//! C is a trusted transient password surface. Its owned storage is zeroized;
//! stock GUI undo/input/backend/OS/IME temporaries are dropped, not guaranteed
//! overwritten. Neither this controller nor its input leaf clears OS clipboard.
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
    CoordinatorFinancialNativeV1, CoordinatorFinancialWitnessEventV1 as WitnessEvent,
    DeliveryFailureV1, FinancialContinueReadyTicketV1, FinancialContinueReviewTicketV1,
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

const _: () = assert!(matches!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off));
const READ_PURPOSE: &str = "original-history-and-one-local-continue-preparation-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Selecting,
    Configuring,
    SetupNeeded,
    SetupPreparing,
    SetupReview,
    AdmissionReview,
    RetirementBlocked,
    Preparing,
    EntryReview,
    EntryConfirm,
    Password,
    Opening,
    ReadReview,
    ReadConfirm,
    Reading,
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
    Configure(Role),
    PrepareSetup(Instant),
    Setup,
    ArmSigner,
    ArmWitness,
    Begin(Role, Instant),
    EntryConfirm,
    EnterPassword,
    ReadConfirm,
    Read,
    BeginContinue,
    ContinueConfirm,
    ArmContinue,
    BeginHostLine,
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
        phase: Phase::Selecting, active: None, progress: [Progress::NotStarted; 2],
        entry: None, read: None, continuation: None, continue_review: None, continue_ready: None,
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
        message: "Review one original Signer source at a time. Unlock and the combined history Read / local preparation require separate approval." };
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
    native: CoordinatorFinancialNativeV1,
    driver: Rc<RefCell<Driver>>,
    session_deadline: Instant,
    phase: Phase,
    active: Option<Role>,
    progress: [Progress; 2],
    entry: Option<SignerSourceEntryOfferV1>,
    read: Option<SignerFinancialReadTicketV1>,
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
        if driver_revoked
            || self.native.check_current().is_err()
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
                        self.transition(Phase::HistoryReady, ctx.cumulative_frame_nr());
                        self.message = "The original Signer retains the authenticated history and one immutable local Continue preparation. Continue and financial admission have not been approved.";
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
        self.transition(Phase::ReadReview, frame);
        self.message =
            "Unlocking did not authorize owner history Read or local Continue preparation. Review this separate combined action; it does not approve Continue or mutation.";
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
        let mut selectors_in_pass = if self.phase == Phase::Configuring {
            self.active.map(|role| self.selectors[index(role)].clone())
        } else {
            None
        };
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Wholepact coordinator · Original Signer source");
            ui.label(self.message);
            for role in [Role::Signer1, Role::Signer2] { ui.label(format!("{}: {} · {}", role_name(role), progress_text(self.progress[index(role)]), effect_text(self.continue_effect[index(role)]))); }
            for role in [Role::Signer1, Role::Signer2] {
                ui.label(format!("{} admission: Signer {} · Witness {}", role_name(role), admission_effect_text(self.signer_effect[index(role)]), admission_effect_text(self.witness_effect[index(role)])));
            }
            for role in [Role::Signer1, Role::Signer2] {
                if let Some(failure) = &self.witness_failure[index(role)] { ui.label(format!("{} Witness first failure: {:?}", role_name(role), failure)); }
            }
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
            match self.phase {
                Phase::Selecting => {
                    ui.label("The existing sealed source selection stays with each original Signer. This window does not import or create role keys.");
                    for role in [Role::Signer1, Role::Signer2] {
                        if self.progress[index(role)] == Progress::NotStarted
                            && ui.button(format!("Review {} source", role_name(role))).clicked_by(egui::PointerButton::Primary) {
                            self.intent = Some(Intent::Configure(role));
                        }
                    }
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
        if painted_phase == Phase::Configuring {
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
        ctx.request_repaint_after(Duration::from_millis(20));
    }
    fn apply_intent(&mut self, intent: Intent, frame: u64, ctx: &egui::Context) -> Result<()> {
        if host_entry_blocks_source(self.host_entry) {
            return Err(rejected("protected Host input owns this phase"));
        }
        match intent {
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
                let outbound = self.native.admit_initial_read(ticket)?;
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
    fn submit_password(&mut self, input: BoundPassword, frame: u64) -> Result<()> {
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
