//! Synthetic-only event delivery to the actual original-born roster controller.
//! This child of `born_manual_roster_v2` neither constructs an opaque owner/peer
//! nor changes an existing birth policy. The V2 policy must predate birth.

#[path = "born_manual_roster_continuation.rs"]
pub(in crate::native_ui) mod continuation_fixture;

use super::*;
use crate::native_ui::pending_enrollment::born_pending_continuation::{
    AcknowledgedBornFixture, EphemeralOwnerCredentials,
};
use sha2::{Digest, Sha256};
use wholepact_signer_origin::manual_roster_v2::HostManualRosterEnrollmentRequestV2;
use wholepact_signer_origin::PairScope;

// Retain both concrete temporary installations inside the draining guard,
// including destructuring/error paths where outer argument drop order differs.
struct DrainingRosterController(
    BornManualRosterUiV2,
    Arc<tempfile::TempDir>,
    EphemeralOwnerCredentials,
);
impl DrainingRosterController {
    fn new(ui: BornManualRosterUiV2, original: &AcknowledgedBornFixture) -> Self {
        Self(ui, original.temporary.clone(), original.credentials.clone())
    }
}
impl std::ops::Deref for DrainingRosterController {
    type Target = BornManualRosterUiV2;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DrainingRosterController {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for DrainingRosterController {
    fn drop(&mut self) {
        self.0.clear();
        if let Some(job) = self.0.job.take() {
            drop(job.finish());
        }
        self.0.clear();
        for cleanup in self.0.cleanup.drain(..) {
            let _ = cleanup.join();
        }
    }
}

/// The same finite initial-export entry is kept alive for inspection only.
/// It can never acquire a writer or upgrade itself into the enrollment entry.
pub(in crate::native_ui) struct ExportedOriginalRoster {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    pub(in crate::native_ui) signed_extension_file: PathBuf,
    pub(in crate::native_ui) original_policy_file: PathBuf,
    pub(in crate::native_ui) enrollment_request: HostManualRosterEnrollmentRequestV2,
}

fn drain(ui: &mut BornManualRosterUiV2, epoch: u64) -> Result<()> {
    let ceiling = Instant::now() + Duration::from_secs(120);
    while ui.job.is_some() {
        ui.poll_lifecycle(true, epoch);
        ui.owner(epoch)?;
        if Instant::now() >= ceiling {
            return Err(Error::Uncertain);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    ui.owner(epoch)?;
    Ok(())
}

fn approve_current(ui: &mut BornManualRosterUiV2, epoch: u64) -> Result<()> {
    ui.owner(epoch)?;
    let review = ui.review.as_mut().ok_or(Error::ReviewMismatch)?;
    if review.exact.display().is_empty() || review.exact.confirming() {
        return Err(Error::ReviewMismatch);
    }
    // Explicit synthetic scroll/continue/confirm delivery, not human evidence.
    review.displayed_to_end = true;
    if review
        .exact
        .continue_from_native_click(false, epoch)
        .is_ok()
        || review
            .exact
            .continue_from_native_click(true, epoch.wrapping_add(1))
            .is_ok()
    {
        return Err(Error::ReviewMismatch);
    }
    review.exact.continue_from_native_click(true, epoch)?;
    ui.confirmation = Zeroizing::new(format!("AUTHORIZE {}", &review.exact.digest()[..12]));
    ui.approve(true, epoch)?;
    drain(ui, epoch)
}

/// A genuine open, finite initial-export controller. The separate real Host
/// owns the client and emits the intent; this owner only polls actual IPC events.
pub(in crate::native_ui) struct InitialRosterFixture {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    intent: HostIntent,
    scope: PairScope,
    epoch: u64,
    retained: bool,
}
impl InitialRosterFixture {
    pub(in crate::native_ui) fn open(
        ui: BornManualRosterUiV2,
        original: AcknowledgedBornFixture,
        intent: HostIntent,
    ) -> Result<Self> {
        let mut ui = DrainingRosterController::new(ui, &original);
        if !original.root.starts_with(original.temporary.path()) {
            return Err(Error::ReviewMismatch);
        }
        intent.validate().map_err(|_| Error::InvalidData)?;
        let epoch = ui.owner.as_ref().ok_or(Error::Locked)?.focus_epoch();
        drain(&mut ui, epoch)?;
        let open = ui.opened.as_ref().ok_or(Error::Locked)?;
        if open.account_id != original.account_id
            || open.retained_reference.is_some()
            || open.attempted
            || !ui.bootstrap.initial_export()
            || ui.bootstrap.can_acquire()
        {
            return Err(Error::ReviewMismatch);
        }
        let anchor = open.account.historical_birth_anchor()?;
        if anchor.anchor().birth_digest() != original.birth_digest {
            return Err(Error::ReviewMismatch);
        }
        anchor.anchor().recipient_policy_v2()?;
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: intent.account_intent.scope.agreement_id.clone(),
            participant_id: intent.account_intent.scope.participant_id.clone(),
            manifest_digest: intent.digest().map_err(|_| Error::InvalidData)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        Ok(Self {
            controller: ui,
            original,
            intent,
            scope,
            epoch,
            retained: false,
        })
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.controller.owner(self.epoch)?;
        let open = self.controller.opened.as_ref().ok_or(Error::Locked)?;
        let ipc = open.ipc.lock().map_err(|_| Error::Locked)?;
        Ok(ipc.socket_path().to_path_buf())
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.controller
            .owner(self.epoch)?
            .native()
            .binding()
            .bounded_deadline()
    }
    /// One bounded poll. Only the predeclared exact Host intent can be approved.
    pub(in crate::native_ui) fn poll_intent(&mut self) -> Result<bool> {
        self.controller.poll_lifecycle(true, self.epoch);
        self.controller.owner(self.epoch)?;
        if self.controller.job.is_some() {
            return Ok(false);
        }
        if let Some(review) = self.controller.review.as_ref() {
            let is_retain = match &review.step {
                Step::Pair(pair) if !self.retained && pair.scope == self.scope => false,
                Step::Retain(_)
                    if !self.retained
                        && self
                            .controller
                            .peer
                            .as_ref()
                            .is_some_and(|p| p.scope == self.scope) =>
                {
                    true
                }
                _ => return Err(Error::ReviewMismatch),
            };
            approve_current(&mut self.controller, self.epoch)?;
            self.retained |= is_retain;
        }
        if self.retained {
            let retained = self
                .controller
                .opened
                .as_ref()
                .ok_or(Error::Locked)?
                .account
                .retained_born_manual_roster_enrollment_v2(
                    self.controller.owner(self.epoch)?.as_ref(),
                )?
                .ok_or(Error::RecoveryRequired)?;
            if retained.record().intent()? != self.intent {
                return Err(Error::ReviewMismatch);
            }
        }
        Ok(self.retained)
    }
    /// The exact retained intent is signed/exported by separate real reviews.
    pub(in crate::native_ui) fn export(self, destination: &Path) -> Result<ExportedOriginalRoster> {
        let Self {
            controller,
            original,
            intent,
            epoch,
            retained,
            ..
        } = self;
        if !retained || !destination.starts_with(original.temporary.path()) {
            return Err(Error::ReviewMismatch);
        }
        let owner = controller.owner(epoch)?;
        let retained = controller
            .opened
            .as_ref()
            .ok_or(Error::Locked)?
            .account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        if retained.record().intent()? != intent {
            return Err(Error::ReviewMismatch);
        }
        let enrollment_request = retained.record().request()?;
        drop(retained);
        export_retained(controller, original, enrollment_request, destination, epoch)
    }
}

fn export_retained(
    mut ui: DrainingRosterController,
    original: AcknowledgedBornFixture,
    enrollment_request: HostManualRosterEnrollmentRequestV2,
    destination: &Path,
    epoch: u64,
) -> Result<ExportedOriginalRoster> {
    let credentials = &original.credentials;
    let context = ui.context()?;
    ui.start(
        Work::PrepareSignature(
            context,
            credentials.certificate_der.clone(),
            credentials.private_key_pkcs8_der.clone(),
        ),
        epoch,
    )?;
    drain(&mut ui, epoch)?;
    if !matches!(ui.review.as_ref().map(|r| &r.step), Some(Step::Sign(_))) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut ui, epoch)?;
    let bytes = Zeroizing::new(
        serde_json::to_vec_pretty(&**ui.signed.as_ref().ok_or(Error::ReviewMismatch)?)
            .map_err(|_| Error::InvalidData)?,
    );
    let signed_extension_file = destination.join(format!(
        "manual-roster-owner-extension-v2-{}.json",
        hex::encode(Sha256::digest(bytes.as_slice()))
    ));
    let context = ui.context()?;
    let signed = ui.signed.take().ok_or(Error::ReviewMismatch)?;
    ui.start(
        Work::PrepareExport(context, signed, destination.to_path_buf()),
        epoch,
    )?;
    drain(&mut ui, epoch)?;
    if !matches!(ui.review.as_ref().map(|r| &r.step), Some(Step::Export(_))) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut ui, epoch)?;
    if std::fs::read(&signed_extension_file)?.as_slice() != bytes.as_slice() {
        return Err(Error::ReviewMismatch);
    }

    let retained = ui
        .opened
        .as_ref()
        .ok_or(Error::Locked)?
        .account
        .retained_born_manual_roster_enrollment_v2(ui.owner(epoch)?.as_ref())?
        .ok_or(Error::RecoveryRequired)?;
    let policy = retained.original_recipient_policy_export_v2(ui.owner(epoch)?.as_ref())?;
    let policy_bytes =
        Zeroizing::new(serde_json::to_vec_pretty(&policy).map_err(|_| Error::InvalidData)?);
    let original_policy_file = destination.join(format!(
        "original-born-policy-v2-{}.json",
        hex::encode(Sha256::digest(policy_bytes.as_slice()))
    ));
    drop(retained);
    let context = ui.context()?;
    ui.start(
        Work::PreparePolicyExport(context, destination.to_path_buf()),
        epoch,
    )?;
    drain(&mut ui, epoch)?;
    if !matches!(
        ui.review.as_ref().map(|r| &r.step),
        Some(Step::PolicyExport(_))
    ) {
        return Err(Error::ReviewMismatch);
    }
    approve_current(&mut ui, epoch)?;
    if std::fs::read(&original_policy_file)?.as_slice() != policy_bytes.as_slice()
        || !ui.bootstrap.initial_export()
        || ui.bootstrap.can_acquire()
        || ui.writer.is_some()
        || ui.receipt.is_some()
        || ui.enrolled.is_some()
        || original.root.join("authority.sqlite").exists()
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(ExportedOriginalRoster {
        controller: ui,
        original,
        signed_extension_file,
        original_policy_file,
        enrollment_request,
    })
}

impl ExportedOriginalRoster {
    /// Close and join the export-only owner before a distinct actual reentry.
    /// The original encrypted account, birth, retained intent and deadlines stay.
    pub(in crate::native_ui) fn close_for_independent_witness_review(
        self,
    ) -> AcknowledgedBornFixture {
        let Self {
            controller,
            original,
            ..
        } = self;
        drop(controller);
        original
    }
}

/// Fresh actual reentry for one exact initial publication. It retains the real
/// born owner, writer workspaces, vault/journal and later enrolled source. None
/// are converted into the ordinary runtime's unrelated OpenAccount owner.
pub(in crate::native_ui) struct PublicationRosterFixture {
    controller: DrainingRosterController,
    original: AcknowledgedBornFixture,
    request: HostPublication,
    scope: PairScope,
    epoch: u64,
}
impl PublicationRosterFixture {
    pub(in crate::native_ui) fn open(
        ui: BornManualRosterUiV2,
        original: AcknowledgedBornFixture,
        request: HostPublication,
    ) -> Result<Self> {
        request.validate().map_err(|_| Error::InvalidData)?;
        if !matches!(
            request.attempt,
            ManualRosterPublicationAttemptV2::InitialV2 {}
        ) {
            return Err(Error::Unavailable);
        }
        let mut controller = DrainingRosterController::new(ui, &original);
        let epoch = controller
            .owner
            .as_ref()
            .ok_or(Error::Locked)?
            .focus_epoch();
        drain(&mut controller, epoch)?;
        let owner = controller.owner(epoch)?;
        let open = controller.opened.as_ref().ok_or(Error::Locked)?;
        if open.account_id != original.account_id
            || open.attempted
            || open.retained_reference.is_none()
            || controller.bootstrap.initial_export()
            || open
                .account
                .historical_birth_anchor()?
                .anchor()
                .birth_digest()
                != original.birth_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let retained = open
            .account
            .retained_born_manual_roster_enrollment_v2(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        let original_request = retained.record().request()?;
        if original_request.enrollment != request.enrollment
            || original_request.roster != request.roster
        {
            return Err(Error::ReviewMismatch);
        }
        drop(retained);
        let terms = &request.enrollment.terms;
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: request.digest().map_err(|_| Error::InvalidData)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        Ok(Self {
            controller,
            original,
            request,
            scope,
            epoch,
        })
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.controller.owner(self.epoch)?;
        let open = self.controller.opened.as_ref().ok_or(Error::Locked)?;
        let ipc = open.ipc.lock().map_err(|_| Error::Locked)?;
        Ok(ipc.socket_path().to_path_buf())
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.controller
            .owner(self.epoch)?
            .native()
            .binding()
            .bounded_deadline()
    }
    /// One actual lifecycle poll and at most one exact synthetic decision.
    /// The independently owned Host client performs ordinary lease/append work.
    pub(in crate::native_ui) fn poll_publication(&mut self) -> Result<bool> {
        let ui = &mut self.controller;
        ui.poll_lifecycle(true, self.epoch);
        ui.owner(self.epoch)?;
        if ui.job.is_some() {
            return Ok(false);
        }
        if let Some(queued) = ui.queued.as_ref() {
            if queued.request.digest().map_err(|_| Error::InvalidData)?
                != self.request.digest().map_err(|_| Error::InvalidData)?
                || queued.peer.scope != self.scope
            {
                return Err(Error::ReviewMismatch);
            }
        }
        if let Some(review) = ui.review.as_ref() {
            match &review.step {
                Step::Pair(pair) if pair.scope == self.scope && ui.peer.is_none() => {}
                Step::Reentry(_)
                | Step::Witness(_)
                | Step::Acquire(_)
                | Step::Activate(_)
                | Step::Admit(_)
                | Step::Publish(_)
                | Step::Serve(_)
                    if ui
                        .peer
                        .as_ref()
                        .is_some_and(|peer| peer.scope == self.scope) => {}
                _ => return Err(Error::ReviewMismatch),
            }
            let serving = matches!(&review.step, Step::Serve(_));
            approve_current(ui, self.epoch)?;
            return Ok(serving && ui.enrolled.is_some() && ui.job.is_none() && ui.review.is_none());
        }
        // Match the unchanged production button actions. Each prepares a review;
        // no writer acquisition/activation/admission is committed here directly.
        if ui.reentry.is_some() && ui.writer.is_none() {
            let context = ui.context()?;
            ui.start(
                Work::PrepareWitness(context, self.original.credentials.roster_setup_json()?),
                self.epoch,
            )?;
        } else if ui.writer.is_some() && ui.receipt.is_none() {
            if ui.acquire_retry.is_some() {
                return Err(Error::Uncertain);
            }
            ui.bootstrap.begin_acquire()?;
            let context = ui.context()?;
            ui.start(Work::PrepareAcquire(context), self.epoch)?;
        } else if ui.receipt.is_some() && !ui.activated {
            if ui.activation_retry.is_some() {
                return Err(Error::Uncertain);
            }
            let context = ui.context()?;
            let receipt = Box::new(ui.receipt.clone().ok_or(Error::Locked)?);
            ui.start(Work::PrepareActivate(context, receipt), self.epoch)?;
        } else if ui.activated && ui.enrolled.is_none() {
            if ui.admission_retry.is_some() {
                return Err(Error::Uncertain);
            }
            let context = ui.context()?;
            ui.start(Work::PreparePublication(context), self.epoch)?;
        }
        Ok(ui.enrolled.is_some() && ui.queued.is_none() && ui.job.is_none() && ui.review.is_none())
    }
}
