//! Genuine native pending-account continuation. Reopen authenticates the pending
//! vault; all decisions originate in this UI's exact two-click review. Worker
//! handoffs own real vault/owner Arcs, never borrowed/self-referential state.
mod export;
mod history;
use super::{
    NativeDecision,
    authority::{ExactNativeReview, PendingAccountNativeAuthority},
    pending_owner_signing::PreparedPendingOwnerSignature,
    runtime::PendingBirthEntry,
    state::inert_text,
};
use crate::{
    Error, Result,
    account::birth::{
        PendingBirthVault, PreparedPendingBirthAcknowledgement,
        request::PreparedPendingOwnerRequest,
        request_recovery::PreparedPendingOwnerRequestRecovery,
    },
};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wholepact_authority::pending_birth_signature::PendingBirthOwnerSignature;
use zeroize::{Zeroize, Zeroizing};

struct Opened {
    pending: Arc<PendingBirthVault>,
    display: Zeroizing<String>,
    retained: bool,
    staged: bool,
    acknowledgement_staged: bool,
}
impl Opened {
    fn inspect(pending: Arc<PendingBirthVault>) -> Result<Self> {
        let retained = pending.retained_owner_request()?;
        let staged = pending.staged_owner_request()?;
        let anchor = pending.anchor();
        let request = if let Some(retained) = &retained {
            retained.recheck_for_acknowledgement()?;
            serde_json::to_string_pretty(retained.request()).map_err(|_| Error::InvalidData)?
        } else if let Some(staged) = &staged {
            staged.recheck_original()?;
            serde_json::to_string_pretty(staged.request()).map_err(|_| Error::InvalidData)?
        } else {
            "No retained request. Preparing one starts its single original deadline; retries never renew it.".into()
        };
        let display = Zeroizing::new(format!(
            "AUTHENTICATED PENDING ENVELOPE\nAccount: {}\nBirth: {}\nOperation: {}\nOriginal terms: {}\nOriginal witness: {} at {} ({})\nPinned server: {}\n\nOriginal request / authenticated stage:\n{request}\n\nPending state grants no financial capability. Existing request times are immutable. A signature made before expiry can only be retried with the original exported envelope; expired unsigned requests cannot be renewed or reset. Authenticated history acknowledgement remains available after expiry if the original witness already committed.",
            anchor.identity().account_id(),
            anchor.birth_digest(),
            anchor.operation_id(),
            anchor.original_policy_terms_digest(),
            anchor.witness_origin().witness_id(),
            anchor.witness_origin().endpoint(),
            anchor.witness_origin().server_name(),
            anchor.witness_origin().pinned_server_certificate_digest()
        ));
        let acknowledgement_staged = pending.has_staged_born_acknowledgement()?;
        let has_retained = retained.is_some();
        let has_staged = staged.is_some();
        drop(staged);
        Ok(Self {
            pending,
            display,
            retained: has_retained,
            staged: has_staged,
            acknowledgement_staged,
        })
    }
}
enum Step {
    Retain(Box<PreparedPendingOwnerRequest>),
    Recover(Box<PreparedPendingOwnerRequestRecovery>),
    Sign(Box<PreparedPendingOwnerSignature>),
    Export(Box<export::PreparedRequestExport>),
    History(Box<history::PreparedHistoryRead>),
    Acknowledge(Box<PreparedPendingBirthAcknowledgement>),
}
struct Prepared {
    step: Step,
    digest: String,
    display: String,
}
impl Prepared {
    fn new(step: Step) -> Result<Self> {
        let (digest, display) = match &step {
            Step::Retain(value) => (
                value.reviewed_digest().into(),
                format!(
                    "RETAIN THE EXACT PENDING REQUEST\n{}\n\nThis saves one immutable encrypted request in the authenticated pending vault. The original issue time and first-commit deadline begin now and will never be regenerated. This does not sign, export, enroll or activate the account.",
                    value.review_json()?
                ),
            ),
            Step::Recover(value) => (value.reviewed_digest().into(), value.review_json()?),
            Step::Sign(value) => (value.reviewed_digest().into(), value.display().into()),
            Step::Export(value) => (value.digest().into(), value.display().into()),
            Step::History(value) => (value.digest().into(), value.display().into()),
            Step::Acknowledge(value) => (value.reviewed_digest().into(), value.review_json()?),
        };
        Ok(Self {
            step,
            digest,
            display,
        })
    }
}
struct Review {
    step: Step,
    exact: ExactNativeReview,
    displayed_to_end: bool,
}
// All payloads are owned and one-shot. No public generic worker callback exists.
enum Work {
    Reopen(PathBuf, Zeroizing<String>),
    PrepareRequest(Arc<PendingBirthVault>),
    PrepareRecovery(Arc<PendingBirthVault>),
    PrepareSignature(Arc<PendingBirthVault>, PathBuf, PathBuf),
    PrepareExport(
        Arc<PendingBirthVault>,
        Box<PendingBirthOwnerSignature>,
        PathBuf,
    ),
    PrepareHistory(Arc<PendingBirthVault>, Zeroizing<String>),
    Commit(Step, NativeDecision, Arc<PendingBirthVault>),
}
enum Output {
    Opened(Box<Opened>),
    Prepared(Box<Prepared>),
    Signed(Box<PendingBirthOwnerSignature>),
    Exported,
    Acknowledged,
}
fn run(work: Work, owner: &PendingAccountNativeAuthority) -> Result<Output> {
    owner.check_current()?;
    let output = match work {
        Work::Reopen(path, password) => Output::Opened(Box::new(Opened::inspect(Arc::new(
            PendingBirthVault::reopen(&path, password.as_bytes())?,
        ))?)),
        Work::PrepareRequest(pending) => Output::Prepared(Box::new(Prepared::new(Step::Retain(
            Box::new(pending.prepare_owner_request(owner)?),
        ))?)),
        Work::PrepareRecovery(pending) => {
            Output::Prepared(Box::new(Prepared::new(Step::Recover(Box::new(
                pending.prepare_staged_owner_request_recovery(owner)?,
            )))?))
        }
        Work::PrepareSignature(pending, certificate, key) => {
            let retained = pending
                .retained_owner_request()?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Sign(Box::new(
                PreparedPendingOwnerSignature::prepare(retained, owner, &certificate, &key)?,
            )))?))
        }
        Work::PrepareExport(pending, envelope, destination) => {
            let retained = pending
                .retained_owner_request()?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Export(Box::new(
                export::PreparedRequestExport::prepare(retained, *envelope, &destination, owner)?,
            )))?))
        }
        Work::PrepareHistory(pending, setup) => {
            Output::Prepared(Box::new(Prepared::new(Step::History(Box::new(
                history::PreparedHistoryRead::prepare(pending, &setup, owner)?,
            )))?))
        }
        Work::Commit(step, decision, pending) => match step {
            Step::Retain(value) => {
                value.retain(decision, owner)?;
                Output::Opened(Box::new(Opened::inspect(pending)?))
            }
            Step::Recover(value) => {
                value.preserve_exact(decision, owner)?;
                Output::Opened(Box::new(Opened::inspect(pending)?))
            }
            Step::Sign(value) => Output::Signed(Box::new(value.approve_and_sign(decision, owner)?)),
            Step::Export(value) => {
                value.publish(decision, owner)?;
                Output::Exported
            }
            Step::History(value) => Output::Prepared(Box::new(Prepared::new(Step::Acknowledge(
                Box::new(value.fetch(decision, owner)?),
            ))?)),
            Step::Acknowledge(value) => {
                value.approve_and_publish(decision, owner)?;
                Output::Acknowledged
            }
        },
    };
    owner.check_current()?;
    Ok(output)
}
struct Job {
    receive: mpsc::Receiver<Result<Output>>,
    thread: JoinHandle<()>,
}
impl Job {
    fn start(work: Work, owner: Arc<PendingAccountNativeAuthority>) -> Result<Self> {
        let (send, receive) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wholepact-pending-continuation".into())
            .spawn(move || {
                let outcome = run(work, &owner);
                let _ = send.send(outcome);
            })?;
        Ok(Self { receive, thread })
    }
    fn finish(self) -> Result<Output> {
        // Called only after is_finished, so the event thread never waits for I/O.
        if self.thread.join().is_err() {
            return Err(Error::Uncertain);
        }
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}
enum Action {
    None,
    Request,
    Recover,
    Sign,
    Export,
    History,
    Continue,
    Confirm,
    Cancel,
}
#[derive(Default)]
pub(super) struct PendingEnrollmentUi {
    owner: Option<Arc<PendingAccountNativeAuthority>>,
    opened: Option<Opened>,
    review: Option<Review>,
    envelope: Option<Box<PendingBirthOwnerSignature>>,
    job: Option<Job>,
    certificate: Zeroizing<String>,
    key: Zeroizing<String>,
    destination: Zeroizing<String>,
    history_setup: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    message: &'static str,
}
impl PendingEnrollmentUi {
    pub(super) fn is_active(&self) -> bool {
        self.owner.is_some() || self.job.is_some()
    }
    pub(super) fn begin(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        if self.is_active()
            || !path.is_absolute()
            || path.as_os_str().len() > 4096
            || !(12..=1024).contains(&password.len())
        {
            return Err(Error::ReviewMismatch);
        }
        // Original continuation lifetime begins before native entry/KDF and is
        // shared by request/sign/export/history/acknowledgement worker bindings.
        let deadline = Instant::now() + Duration::from_secs(120);
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry, deadline,
        )?);
        let work = Work::Reopen(path.to_path_buf(), Zeroizing::new(password.into()));
        self.job = Some(Job::start(work, owner.clone())?);
        self.owner = Some(owner);
        self.message = "Authenticating the selected pending envelope. No credentials are signed and no witness is contacted.";
        Ok(())
    }
    pub(super) fn clear(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.revoke_pending_now();
        }
        self.opened = None;
        self.review = None;
        self.envelope = None;
        self.certificate.zeroize();
        self.key.zeroize();
        self.destination.zeroize();
        self.history_setup.zeroize();
        self.confirmation.zeroize();
        // Keep the bounded job slot until it finishes. An already-admitted local
        // publication or disclosure may drain. Never claim that it was undone.
        self.message = "Pending continuation closed. An already-admitted write or disclosure may have completed. Preserve all files unchanged and reopen to inspect exact retained state; no deadline was renewed.";
    }
    fn current_owner(&self, epoch: u64) -> Result<Arc<PendingAccountNativeAuthority>> {
        let owner = self.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        if owner.focus_epoch() != epoch {
            return Err(Error::ReviewMismatch);
        }
        Ok(owner.clone())
    }
    fn start(&mut self, work: Work, epoch: u64) -> Result<()> {
        if self.job.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let owner = self.current_owner(epoch)?;
        self.job = Some(Job::start(work, owner)?);
        self.message = "Processing this exact native step. Lock, navigation and focus loss close further admission; an admitted operation may drain.";
        Ok(())
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        if self.owner.is_some()
            && (!focused
                || self.current_owner(epoch).is_err()
                || self.review.as_ref().is_some_and(|r| r.exact.expired()))
        {
            self.clear();
        }
        if !self
            .job
            .as_ref()
            .is_some_and(|job| job.thread.is_finished())
        {
            return;
        }
        let outcome = self.job.take().expect("finished job present").finish();
        if self.current_owner(epoch).is_err() {
            return;
        }
        let result = outcome.and_then(|output| self.accept(output, epoch));
        if result.is_err() {
            self.clear();
            self.message = "Pending step failed or its result is uncertain. Preserve the original vault, request and export files. Reopen exact retained state; do not reset the operation, origin or deadline.";
        }
    }
    fn accept(&mut self, output: Output, epoch: u64) -> Result<()> {
        let owner = self.current_owner(epoch)?;
        match output {
            Output::Opened(opened) => {
                self.opened = Some(*opened);
                self.message = "Authenticated pending state loaded. Each signing, export, witness disclosure and acknowledgement needs its own review.";
            }
            Output::Prepared(prepared) => {
                let Prepared {
                    step,
                    digest,
                    display,
                } = *prepared;
                self.review = Some(Review {
                    step,
                    exact: ExactNativeReview::stage(owner.native(), &digest, display, epoch)?,
                    displayed_to_end: false,
                });
                self.confirmation.zeroize();
            }
            Output::Signed(envelope) => {
                self.envelope = Some(envelope);
                self.message = "Exact existing-owner signature is held only in this native session. Review a private export destination separately and preserve that file for witness retries.";
            }
            Output::Exported => {
                self.message = "Exact signed request exported to the reviewed private file. No witness was contacted. Preserve it for the independent witness-owner review and exact retries.";
            }
            Output::Acknowledged => {
                self.clear();
                self.message = "Authenticated original witness acknowledgement retained in the born envelope. Financial authority and generic account/journal activation remain blocked.";
            }
        }
        Ok(())
    }
    fn consume_review(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.current_owner(epoch)?;
        let review = self.review.take().ok_or(Error::ReviewMismatch)?;
        if !review.displayed_to_end {
            return Err(Error::ReviewMismatch);
        }
        let decision = review
            .exact
            .consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        let pending = self.opened.as_ref().ok_or(Error::Locked)?.pending.clone();
        self.start(Work::Commit(review.step, decision, pending), epoch)
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> Option<&'static str> {
        self.poll_lifecycle(focused, epoch);
        if !focused {
            return Some(self.message);
        }
        ui.heading("Continue an authenticated pending account");
        ui.label(self.message);
        if self.job.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(50));
            ui.label("A bounded worker is running. New steps wait until it drains. Cancellation cannot recall disclosed bytes or undo a previously admitted publication.");
            if ui
                .button("Cancel pending continuation")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.clear();
            }
            return Some(self.message);
        }
        if self.owner.is_none() {
            return Some(self.message);
        }
        let mut action = Action::None;
        if let Some(review) = &mut self.review {
            let scroll = egui::ScrollArea::vertical()
                .id_salt("pending-continuation-exact-review")
                .max_height(440.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(review.exact.display()).monospace())
                });
            if scroll.state.offset.y + scroll.inner_rect.height() + 1.0 >= scroll.content_size.y {
                review.displayed_to_end = true;
            }
            if review.exact.confirming() {
                let phrase = format!("AUTHORIZE {}", &review.exact.digest()[..12]);
                ui.label(format!("Type {phrase} for this exact step"));
                ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(64));
                if ui
                    .add_enabled(
                        *self.confirmation == phrase,
                        egui::Button::new("Approve this exact step"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                {
                    action = Action::Confirm;
                }
            } else if ui
                .add_enabled(
                    review.displayed_to_end,
                    egui::Button::new("Continue after reviewing every term"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Continue;
            }
        } else if let Some(opened) = &self.opened {
            egui::ScrollArea::vertical()
                .id_salt("pending-retained-audit")
                .max_height(300.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(inert_text(&opened.display)).monospace())
                });
            if !opened.retained
                && !opened.staged
                && ui
                    .button("Prepare the one original request")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Request;
            }
            if opened.staged
                && ui
                    .button("Review preservation of the exact interrupted request")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Recover;
            }
            if opened.retained {
                ui.label("Existing owner public certificate DER file (absolute private path)");
                ui.add(egui::TextEdit::singleline(&mut *self.certificate).char_limit(4096));
                ui.label(
                    "Existing owner private credential PKCS#8 DER file (path only; no key bytes)",
                );
                ui.add(egui::TextEdit::singleline(&mut *self.key).char_limit(4096));
                if ui
                    .add_enabled(
                        !opened.acknowledgement_staged,
                        egui::Button::new("Review exact request and existing-owner signing"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                {
                    action = Action::Sign;
                }
                if opened.acknowledgement_staged {
                    ui.label("An exact authenticated acknowledgement envelope was staged before interruption. Signing/export remain blocked. Fetch original witness history and review acknowledgement to preserve that same stage.");
                }
                if self.envelope.is_some() && !opened.acknowledgement_staged {
                    ui.label("Existing private local export directory");
                    ui.add(egui::TextEdit::singleline(&mut *self.destination).char_limit(4096));
                    if ui
                        .button("Review exact signed-file disclosure destination")
                        .clicked_by(egui::PointerButton::Primary)
                    {
                        action = Action::Export;
                    }
                }
                ui.separator();
                ui.label("Original witness history setup JSON: trusted_server_root_der, owner_certificate_der, owner_private_key_pkcs8_der, operator_name, retention_statement. Paths and descriptive text only. Origin/account/policy are taken exclusively from the retained request. No private key bytes, password or history JSON.");
                ui.add(egui::TextEdit::multiline(&mut *self.history_setup).char_limit(16 * 1024));
                if ui
                    .button("Review disclosure to original pinned witness")
                    .clicked_by(egui::PointerButton::Primary)
                {
                    action = Action::History;
                }
            }
        }
        if ui
            .button("Reject / close pending continuation")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = Action::Cancel;
        }
        let result = match action {
            Action::None => return Some(self.message),
            Action::Cancel => {
                self.clear();
                return Some(self.message);
            }
            Action::Continue => self
                .review
                .as_mut()
                .ok_or(Error::ReviewMismatch)
                .and_then(|r| {
                    if !r.displayed_to_end {
                        return Err(Error::ReviewMismatch);
                    }
                    r.exact.continue_from_native_click(focused, epoch)
                }),
            Action::Confirm => self.consume_review(focused, epoch),
            _ => self.prepare_action(action, epoch),
        };
        if result.is_err() {
            self.clear();
        }
        Some(self.message)
    }
}

impl PendingEnrollmentUi {
    fn prepare_action(&mut self, action: Action, epoch: u64) -> Result<()> {
        let pending = self.opened.as_ref().ok_or(Error::Locked)?.pending.clone();
        let work = match action {
            Action::Request => Work::PrepareRequest(pending),
            Action::Recover => Work::PrepareRecovery(pending),
            Action::Sign => Work::PrepareSignature(
                pending,
                PathBuf::from(self.certificate.as_str()),
                PathBuf::from(self.key.as_str()),
            ),
            Action::Export => Work::PrepareExport(
                pending,
                self.envelope.take().ok_or(Error::ReviewMismatch)?,
                PathBuf::from(self.destination.as_str()),
            ),
            Action::History => Work::PrepareHistory(
                pending,
                std::mem::replace(&mut self.history_setup, Zeroizing::new(String::new())),
            ),
            _ => return Err(Error::ReviewMismatch),
        };
        self.start(work, epoch)
    }
}
impl Drop for PendingEnrollmentUi {
    fn drop(&mut self) {
        self.clear();
    }
}
#[cfg(test)]
mod tests;
