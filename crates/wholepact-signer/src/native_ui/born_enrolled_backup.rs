//! Separate focused audit/backup of an acknowledged born envelope. Never a
//! fallback from failed pending unlock, never ordinary runtime activation.
use super::{
    NativeDecision,
    authority::{ExactNativeReview, PendingAccountNativeAuthority},
    runtime::PendingBirthEntry,
    state::inert_text,
};
use crate::{
    Error, Result,
    account::{
        AccountVault,
        birth::enrollment_backup::{
            PreparedBornEnrolledBackup, PreparedBornEnrolledRecoveryDisclosure,
            PreparedBornEnrolledRestore, VerifiedBornEnrolledBackup,
            audit_born_roster_enrollment_history_v2, audit_restored_enrolled_history,
        },
    },
};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy)]
enum BackupKind {
    OriginalV1,
    RosterV2,
}
struct Opened {
    vault: Arc<AccountVault>,
    kind: BackupKind,
    display: Zeroizing<String>,
}
enum Operation {
    Backup(Box<PreparedBornEnrolledBackup>),
    ReadBackup(Box<PreparedBornEnrolledRecoveryDisclosure>),
    Restore(Box<PreparedBornEnrolledRestore>),
}
struct Prepared {
    operation: Operation,
    digest: String,
    display: String,
}
impl Prepared {
    fn new(operation: Operation) -> Result<Self> {
        let (digest, display) = match &operation {
            Operation::Backup(value) => (value.reviewed_digest().into(), value.review_json()?),
            Operation::ReadBackup(value) => (value.reviewed_digest().into(), value.review_json()?),
            Operation::Restore(value) => (value.reviewed_digest().into(), value.review_json()?),
        };
        Ok(Self {
            operation,
            digest,
            display,
        })
    }
}
struct Review {
    operation: Operation,
    exact: ExactNativeReview,
    displayed_to_end: bool,
}
struct Verified {
    backup: Box<VerifiedBornEnrolledBackup>,
    display: Zeroizing<String>,
}
enum Work {
    Reopen(PathBuf, Zeroizing<String>, BackupKind),
    AuditRestored(PathBuf, Zeroizing<String>),
    ReviewBackup(PathBuf, Zeroizing<String>),
    Prepare(Arc<AccountVault>, PathBuf, Zeroizing<String>, BackupKind),
    PrepareRestore(Box<VerifiedBornEnrolledBackup>, PathBuf, Zeroizing<String>),
    Commit(Operation, NativeDecision),
}
enum Output {
    Opened(Box<Opened>),
    Audited(Zeroizing<String>),
    Prepared(Box<Prepared>),
    Verified(Box<Verified>),
    Written,
    Restored,
}
fn run(work: Work, owner: &PendingAccountNativeAuthority) -> Result<Output> {
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    let output = match work {
        Work::AuditRestored(path, password) => Output::Audited(Zeroizing::new(
            audit_restored_enrolled_history(&path, password.as_bytes(), owner)?,
        )),
        Work::Reopen(path, password, kind) => {
            let vault = Arc::new(match kind {
                BackupKind::OriginalV1 => AccountVault::unlock_born_for_manual_enrollment(
                    &path,
                    password.as_bytes(),
                    owner,
                )?,
                BackupKind::RosterV2 => AccountVault::unlock_born_for_manual_roster_enrollment_v2(
                    &path,
                    password.as_bytes(),
                    owner,
                )?,
            });
            let display = Zeroizing::new(match kind {
                BackupKind::OriginalV1 => vault.born_origin_audit_json(owner)?,
                BackupKind::RosterV2 => audit_born_roster_enrollment_history_v2(&vault, owner)?,
            });
            Output::Opened(Box::new(Opened {
                vault,
                kind,
                display,
            }))
        }
        Work::ReviewBackup(path, password) => {
            Output::Prepared(Box::new(Prepared::new(Operation::ReadBackup(Box::new(
                PreparedBornEnrolledRecoveryDisclosure::prepare(&path, password.as_bytes(), owner)?,
            )))?))
        }
        Work::Prepare(vault, destination, password, kind) => {
            vault.born_origin_audit_json(owner)?;
            let prepared = match kind {
                BackupKind::OriginalV1 => PreparedBornEnrolledBackup::prepare(
                    vault,
                    &destination,
                    password.as_bytes(),
                    owner,
                )?,
                BackupKind::RosterV2 => PreparedBornEnrolledBackup::prepare_roster_v2(
                    vault,
                    &destination,
                    password.as_bytes(),
                    owner,
                )?,
            };
            Output::Prepared(Box::new(Prepared::new(Operation::Backup(Box::new(
                prepared,
            )))?))
        }
        Work::PrepareRestore(backup, target, password) => {
            backup.check_disclosure(owner)?;
            Output::Prepared(Box::new(Prepared::new(Operation::Restore(Box::new(
                backup.prepare_restore(&target, password.as_bytes(), owner)?,
            )))?))
        }
        Work::Commit(operation, decision) => match operation {
            Operation::Backup(backup) => {
                backup.approve_and_write(decision, owner)?;
                Output::Written
            }
            Operation::ReadBackup(prepared) => {
                let backup = Box::new(prepared.approve_read(decision, owner)?);
                backup.check_disclosure(owner)?;
                let display = Zeroizing::new(backup.audit_json(owner)?);
                Output::Verified(Box::new(Verified { backup, display }))
            }
            Operation::Restore(prepared) => {
                prepared.approve_and_restore(decision, owner)?;
                Output::Restored
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
            .name("wholepact-born-enrolled-backup".into())
            .spawn(move || {
                let _ = send.send(run(work, &owner));
            })?;
        Ok(Self { receive, thread })
    }
    fn finish(self) -> Result<Output> {
        if self.thread.join().is_err() {
            return Err(Error::Uncertain);
        }
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}
#[derive(Default)]
pub(super) struct BornEnrolledBackupUi {
    owner: Option<Arc<PendingAccountNativeAuthority>>,
    opened: Option<Opened>,
    verified: Option<Verified>,
    restored_audit: Option<Zeroizing<String>>,
    review: Option<Review>,
    job: Option<Job>,
    privacy_deadline: Option<Instant>,
    destination: Zeroizing<String>,
    password: Zeroizing<String>,
    repeat: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    message: &'static str,
}
impl BornEnrolledBackupUi {
    pub(super) fn is_active(&self) -> bool {
        self.owner.is_some() || self.job.is_some()
    }
    pub(super) fn begin(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        self.begin_exact(entry, path, password, BackupKind::OriginalV1)
    }
    /// Explicit roster selection; failure never falls back to a V1 decoder.
    pub(super) fn begin_roster_v2(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        self.begin_exact(entry, path, password, BackupKind::RosterV2)
    }
    fn begin_exact(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
        kind: BackupKind,
    ) -> Result<()> {
        if self.is_active()
            || !path.is_absolute()
            || path.as_os_str().len() > 4096
            || !(12..=1024).contains(&password.len())
        {
            return Err(Error::ReviewMismatch);
        }
        let privacy_deadline = Instant::now() + Duration::from_secs(120);
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry,
            privacy_deadline,
        )?);
        if Instant::now() >= privacy_deadline {
            return Err(Error::ReviewMismatch);
        }
        self.privacy_deadline = Some(privacy_deadline);
        self.job = Some(Job::start(
            Work::Reopen(path.to_path_buf(), Zeroizing::new(password.into()), kind),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message = "Authenticating the selected acknowledged born envelope for private audit only. The exact retained enrollment inventory is authenticated. No application or witness connection is opened.";
        Ok(())
    }
    /// Separate explicit native entry. A backup path never becomes a pending
    /// or active vault, and no plaintext is opened before the first review.
    pub(super) fn begin_recovery(
        &mut self,
        entry: PendingBirthEntry,
        package: &Path,
        password: &str,
    ) -> Result<()> {
        if self.is_active()
            || !package.is_absolute()
            || package.as_os_str().len() > 4096
            || !(12..=1024).contains(&password.len())
        {
            return Err(Error::ReviewMismatch);
        }
        let privacy_deadline = Instant::now() + Duration::from_secs(120);
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry,
            privacy_deadline,
        )?);
        if Instant::now() >= privacy_deadline {
            return Err(Error::ReviewMismatch);
        }
        self.privacy_deadline = Some(privacy_deadline);
        self.job = Some(Job::start(
            Work::ReviewBackup(package.to_path_buf(), Zeroizing::new(password.into())),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message = "Inspecting only the selected encrypted backup package. Private recovery contents need a separate disclosure review; restore needs another exact target review.";
        Ok(())
    }
    pub(super) fn begin_restored_audit(
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
        let deadline = Instant::now() + Duration::from_secs(120);
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry, deadline,
        )?);
        self.privacy_deadline = Some(deadline);
        self.job = Some(Job::start(
            Work::AuditRestored(path.to_path_buf(), Zeroizing::new(password.into())),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message =
            "Authenticating complete private restored enrollment history for bounded audit only.";
        Ok(())
    }
    pub(super) fn clear(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.revoke_pending_now();
        }
        self.opened = None;
        self.verified = None;
        self.restored_audit = None;
        self.review = None;
        self.privacy_deadline = None;
        self.destination.zeroize();
        self.password.zeroize();
        self.repeat.zeroize();
        self.confirmation.zeroize();
        // Preserve occupied slot until terminal worker completion. An admitted
        // backup may finish; never report cancellation as deletion/rollback.
        self.message = "Acknowledged-origin audit closed. Any previously admitted backup or restore may have completed; preserve partial or complete output and inspect it before retrying. Enrollment remains unavailable.";
    }
    fn owner(&self, epoch: u64) -> Result<Arc<PendingAccountNativeAuthority>> {
        let owner = self.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        if self
            .privacy_deadline
            .is_none_or(|deadline| Instant::now() >= deadline)
            || owner.focus_epoch() != epoch
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(owner.clone())
    }
    fn start(&mut self, work: Work, epoch: u64) -> Result<()> {
        if self.job.is_some() {
            return Err(Error::ReviewMismatch);
        }
        self.job = Some(Job::start(work, self.owner(epoch)?)?);
        self.message = "Processing the exact private audit/backup step; cancellation closes further admission while a previously admitted write may drain.";
        Ok(())
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        if self
            .privacy_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            || (self.owner.is_some()
                && (!focused
                    || self.owner(epoch).is_err()
                    || self.review.as_ref().is_some_and(|r| r.exact.expired())))
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
        let result = self.job.take().expect("finished job present").finish();
        if self.owner(epoch).is_err() {
            return;
        }
        let result = result.and_then(|output| {
            match output {
                Output::Audited(display) => { self.restored_audit = Some(display); self.message = "Original full enrolled history authenticated in its inert recovery capsule. No writable journal or writer/session was restored."; }
                Output::Opened(opened) => { self.opened = Some(*opened); self.message = "Acknowledged origin authenticated for private audit. Enrollment and financial operations remain unavailable."; }
                Output::Prepared(prepared) => {
                    let Prepared { operation, digest, display } = *prepared;
                    self.confirmation.zeroize();
                    self.review = Some(Review { operation, exact: ExactNativeReview::stage(self.owner(epoch)?.native(), &digest, display, epoch)?, displayed_to_end: false });
                }
                Output::Verified(verified) => {
                    let deadline = self.privacy_deadline.ok_or(Error::Locked)?
                        .min(verified.backup.disclosure_deadline()?);
                    if Instant::now() >= deadline { return Err(Error::ReviewMismatch); }
                    self.privacy_deadline = Some(deadline);
                    self.verified = Some(*verified);
                    self.message = "Exact backup authenticated for local private review. Choose a separate new target and password, then review restoration; original birth and witness identity will remain unchanged.";
                }
                Output::Restored => {
                    self.clear();
                    self.message = "Original born origin restored into the reviewed private target as recovered and financially denied. All original journal ciphertexts and immutable enrollment evidence are preserved in an inert history capsule. No writable journal or financial authority was created.";
                }
                Output::Written => { self.message = "Exact password-encrypted full-enrollment backup written to the reviewed private destination. Independent witness history/storage is separate; enrollment remains unavailable."; }
            }
            Ok(())
        });
        if result.is_err() {
            self.clear();
            self.message = "Private audit/backup failed or its result is uncertain. Preserve original and output directories unchanged. No fallback account, journal or financial authority was created.";
        }
    }
    fn prepare(&mut self, epoch: u64) -> Result<()> {
        if !(12..=1024).contains(&self.password.len()) || *self.password != *self.repeat {
            return Err(Error::InvalidData);
        }
        let destination = PathBuf::from(self.destination.as_str());
        let password = std::mem::replace(&mut self.password, Zeroizing::new(String::new()));
        self.repeat.zeroize();
        let work = if let Some(verified) = self.verified.take() {
            Work::PrepareRestore(verified.backup, destination, password)
        } else {
            let opened = self.opened.as_ref().ok_or(Error::Locked)?;
            Work::Prepare(opened.vault.clone(), destination, password, opened.kind)
        };
        self.start(work, epoch)
    }

    fn approve(&mut self, focused: bool, epoch: u64) -> Result<()> {
        self.owner(epoch)?;
        let review = self.review.take().ok_or(Error::ReviewMismatch)?;
        if !review.displayed_to_end {
            return Err(Error::ReviewMismatch);
        }
        let decision = review
            .exact
            .consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        self.start(Work::Commit(review.operation, decision), epoch)
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
        ui.heading("Born manual enrollment: complete private backup and inert restore");
        ui.label(self.message);
        ui.label("This private audit session expires at its original short deadline. Expiry hides the audit and drops held account/recovery material; continuing requires a new explicit reopen.");
        ui.label("Financial enrollment is unavailable. This view reads the exact initial encrypted journal snapshot for backup only. It cannot activate a writer, release keys or call the ordinary signer runtime. Any later journal activity is rejected until complete later-history backup is implemented.");
        if self.job.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(50));
            if ui
                .button("Cancel private audit / backup")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.clear();
            }
            return Some(self.message);
        }
        if self.owner.is_none() {
            return Some(self.message);
        }
        enum Action {
            None,
            Prepare,
            Continue,
            Approve,
            Cancel,
        }
        let mut action = Action::None;
        if let Some(review) = &mut self.review {
            let scroll = egui::ScrollArea::vertical()
                .id_salt("born-enrolled-backup-exact-review")
                .max_height(440.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(review.exact.display()).monospace())
                });
            if scroll.state.offset.y + scroll.inner_rect.height() + 1.0 >= scroll.content_size.y {
                review.displayed_to_end = true;
            }
            if review.exact.confirming() {
                let phrase = format!("AUTHORIZE {}", &review.exact.digest()[..12]);
                ui.label(format!(
                    "Type {phrase} to approve this exact private-origin step"
                ));
                ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(64));
                if ui
                    .add_enabled(
                        *self.confirmation == phrase,
                        egui::Button::new("Approve this exact private-origin step"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                {
                    action = Action::Approve;
                }
            } else if ui
                .add_enabled(
                    review.displayed_to_end,
                    egui::Button::new("Continue after reviewing every backup term"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Continue;
            }
        } else if self.opened.is_some() || self.verified.is_some() {
            let restoring = self.verified.is_some();
            let display = if let Some(verified) = &self.verified {
                verified.display.as_str()
            } else {
                self.opened
                    .as_ref()
                    .ok_or(Error::Locked)
                    .map(|v| v.display.as_str())
                    .unwrap_or("")
            };
            egui::ScrollArea::vertical()
                .id_salt("born-enrolled-private-audit")
                .max_height(320.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(inert_text(display)).monospace())
                });
            if restoring {
                ui.label("Restore preserves the original anchor, witness origin and recorded lifetime history. The result remains recovered and financially denied. The entire source journal remains encrypted in an inert history capsule; no writer/session is reinstated. No new birth, witness replacement or financial activation is permitted.");
                ui.label("New private restored-vault target directory");
            } else {
                ui.label("Separate complete enrolled backup includes spending recovery secrets, immutable birth/witness metadata, exact enrollment intent and completion marker, and every encrypted journal file. Never send it to a coordinator. This cannot back up, replace or reset the independently administered witness.");
                ui.label("New private backup destination directory");
            }
            ui.add(egui::TextEdit::singleline(&mut *self.destination).char_limit(4096));
            ui.label(if restoring {
                "New restored-vault password (at least 12 characters)"
            } else {
                "New backup recovery password (at least 12 characters)"
            });
            ui.add(
                egui::TextEdit::singleline(&mut *self.password)
                    .password(true)
                    .char_limit(1024),
            );
            ui.label("Repeat the new password");
            ui.add(
                egui::TextEdit::singleline(&mut *self.repeat)
                    .password(true)
                    .char_limit(1024),
            );
            if ui
                .button(if restoring {
                    "Prepare exact original-origin restore review"
                } else {
                    "Prepare exact full-origin backup review"
                })
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Prepare;
            }
        }
        if let Some(display) = &self.restored_audit {
            egui::ScrollArea::vertical()
                .id_salt("restored-enrollment-capsule-audit")
                .max_height(420.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(inert_text(display)).monospace());
                });
        }
        if ui
            .button("Close enrolled-origin audit")
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
            Action::Prepare => self.prepare(epoch),
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
            Action::Approve => self.approve(focused, epoch),
        };
        if result.is_err() {
            self.clear();
        }
        Some(self.message)
    }
}
impl Drop for BornEnrolledBackupUi {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_clears_private_backup_inputs_without_native_authority() {
        let mut ui = BornEnrolledBackupUi::default();
        ui.destination.push_str("modeled private output");
        ui.password.push_str("synthetic password only");
        ui.repeat.push_str("synthetic password only");
        ui.confirmation.push_str("modeled phrase");
        ui.clear();
        assert!(
            ui.destination.is_empty()
                && ui.password.is_empty()
                && ui.repeat.is_empty()
                && ui.confirmation.is_empty()
        );
        assert!(!ui.is_active());
    }
    #[test]
    fn expired_private_session_clears_buffers_without_a_new_deadline() {
        let mut ui = BornEnrolledBackupUi::default();
        ui.privacy_deadline = Some(Instant::now() - Duration::from_secs(1));
        ui.password.push_str("synthetic sensitive buffer");
        ui.repeat.push_str("synthetic sensitive buffer");
        ui.confirmation.push_str("modeled confirmation");
        ui.poll_lifecycle(true, 0);
        assert!(ui.password.is_empty() && ui.repeat.is_empty() && ui.confirmation.is_empty());
        assert!(ui.privacy_deadline.is_none());
        assert!(ui.opened.is_none() && ui.verified.is_none() && ui.review.is_none());
    }
    #[test]
    fn missing_owner_cannot_prepare_or_approve_backup() {
        let mut ui = BornEnrolledBackupUi::default();
        assert!(ui.owner(0).is_err());
        assert!(ui.prepare(0).is_err());
        assert!(ui.approve(true, 0).is_err());
        assert!(ui.job.is_none());
    }
}
