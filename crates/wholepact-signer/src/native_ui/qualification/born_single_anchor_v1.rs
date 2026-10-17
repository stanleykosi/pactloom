//! Actual first-account born-manual anchor controller for an empty Host.
//! Synthetic-only; no predecessor row, native owner, history or lease is built.
//! The resulting V1 anchor is NOT a V2/V3 roster participant or a migration.

use super::*;
use crate::native_ui::pending_enrollment::born_pending_continuation::{
    AcknowledgedBornFixture, EphemeralOwnerCredentials,
};
use sha2::{Digest, Sha256};
use wholepact_signer_origin::PairScope;
use wholepact_signer_origin::manual::HostManualEnrollmentRequest;

// Closed static error projection for the confined synthetic PTY transcript.
// Never format the error payload, source path, credential or private artifact.
fn error_label(error: &Error) -> &'static str {
    match error {
        Error::Unavailable => "SignerUnavailable",
        Error::PeerLifetimeUnavailable => "SignerPeerLifetimeUnavailable",
        Error::Io(_) => "SignerIo",
        Error::Authentication => "SignerAuthentication",
        Error::InvalidData => "SignerInvalidData",
        Error::Crypto => "SignerCrypto",
        Error::Locked => "SignerLocked",
        Error::BackupRequired => "SignerBackupRequired",
        Error::RecoveryRequired => "SignerRecoveryRequired",
        Error::AlreadyOpen => "SignerAlreadyOpen",
        Error::ReviewMismatch => "SignerReviewMismatch",
        Error::Verification => "SignerVerification",
        Error::Uncertain => "SignerUncertain",
        Error::ConsentJournal(_) => "SignerConsentJournal",
        Error::Store(_) => "SignerStore",
    }
}
pub(super) fn report_controller_error(error: &Error) {
    let label = error_label(error);
    eprintln!("\n[JOINED_DIAGNOSTIC SignerSingleController {label}]");
}

// Operation names are selected from the actual owned Work/Step before it moves
// into its worker. Neither values nor error payloads enter these diagnostics.
#[derive(Clone, Copy)]
pub(super) enum WorkerOperation {
    Open,
    PrepareIntent,
    PrepareSignature,
    PrepareExport,
    PrepareReentry,
    PrepareWitness,
    PrepareAcquire,
    PrepareActivate,
    PreparePublication,
    PrepareServe,
    CommitPair,
    CommitRetain,
    CommitSignature,
    CommitExport,
    CommitReentry,
    CommitWitness,
    CommitAcquire,
    CommitActivate,
    CommitAdmission,
    CommitPublication,
    CommitServe,
    RetryAcquire,
    RetryActivate,
    RetryAdmission,
    Other,
    AdoptOutput,
}
impl WorkerOperation {
    pub(super) fn from_work(work: &Work) -> Self {
        match work {
            Work::Open(..) => Self::Open,
            Work::PrepareIntent(..) => Self::PrepareIntent,
            Work::PrepareSignature(..) => Self::PrepareSignature,
            Work::PrepareExport(..) => Self::PrepareExport,
            Work::PrepareReentry(..) => Self::PrepareReentry,
            Work::PrepareWitness(..) => Self::PrepareWitness,
            Work::PrepareAcquire(..) => Self::PrepareAcquire,
            Work::PrepareActivate(..) => Self::PrepareActivate,
            Work::PreparePublication(..) => Self::PreparePublication,
            Work::PrepareServe(..) => Self::PrepareServe,
            Work::RetryAcquire(..) => Self::RetryAcquire,
            Work::RetryActivate(..) => Self::RetryActivate,
            Work::RetryAdmission(..) => Self::RetryAdmission,
            Work::Commit(_, step, _) => match step {
                Step::Pair(_) => Self::CommitPair,
                Step::Retain(_) => Self::CommitRetain,
                Step::Sign(_) => Self::CommitSignature,
                Step::Export(_) => Self::CommitExport,
                Step::Reentry(_) => Self::CommitReentry,
                Step::Witness(_) => Self::CommitWitness,
                Step::Acquire(_) => Self::CommitAcquire,
                Step::Activate(_) => Self::CommitActivate,
                Step::Admit(_) => Self::CommitAdmission,
                Step::Publish(_) => Self::CommitPublication,
                Step::Serve(_) => Self::CommitServe,
                _ => Self::Other,
            },
            _ => Self::Other,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Open => "SingleWorkOpen",
            Self::PrepareIntent => "SingleWorkPrepareIntent",
            Self::PrepareSignature => "SingleWorkPrepareSignature",
            Self::PrepareExport => "SingleWorkPrepareExport",
            Self::PrepareReentry => "SingleWorkPrepareReentry",
            Self::PrepareWitness => "SingleWorkPrepareWitness",
            Self::PrepareAcquire => "SingleWorkPrepareAcquire",
            Self::PrepareActivate => "SingleWorkPrepareActivate",
            Self::PreparePublication => "SingleWorkPreparePublication",
            Self::PrepareServe => "SingleWorkPrepareServe",
            Self::CommitPair => "SingleWorkCommitPair",
            Self::CommitRetain => "SingleWorkCommitRetain",
            Self::CommitSignature => "SingleWorkCommitSignature",
            Self::CommitExport => "SingleWorkCommitExport",
            Self::CommitReentry => "SingleWorkCommitReentry",
            Self::CommitWitness => "SingleWorkCommitWitness",
            Self::CommitAcquire => "SingleWorkCommitAcquire",
            Self::CommitActivate => "SingleWorkCommitActivate",
            Self::CommitAdmission => "SingleWorkCommitAdmission",
            Self::CommitPublication => "SingleWorkCommitPublication",
            Self::CommitServe => "SingleWorkCommitServe",
            Self::RetryAcquire => "SingleWorkRetryAcquire",
            Self::RetryActivate => "SingleWorkRetryActivate",
            Self::RetryAdmission => "SingleWorkRetryAdmission",
            Self::Other => "SingleWorkOther",
            Self::AdoptOutput => "SingleWorkAdoptOutput",
        }
    }
}
pub(super) fn report_worker_begin(operation: WorkerOperation) {
    eprintln!("\n[JOINED_DIAGNOSTIC {} Begin]", operation.label());
}
pub(super) fn report_worker_result<T>(operation: WorkerOperation, result: &Result<T>) {
    let label = result
        .as_ref()
        .map_or_else(|error| error_label(error), |_| "Complete");
    eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", operation.label(), label);
}
pub(super) fn report_worker_output(operation: WorkerOperation, result: &Result<Output>) {
    // These existing variants retain uncertain effects as nested results rather
    // than failing the worker. Classify that exact result without changing it.
    match result {
        Ok(Output::Acquired(_, nested)) => report_worker_result(operation, nested),
        Ok(Output::Activated(_, nested)) => report_worker_result(operation, nested),
        Ok(Output::Admitted(_, nested)) | Ok(Output::ContinuedAdmitted(_, nested)) => {
            report_worker_result(operation, nested)
        }
        _ => report_worker_result(operation, result),
    }
}

#[derive(Clone, Copy)]
pub(super) enum OpenOperation {
    AccountUnlock,
    RetainedRead,
    AcquireState,
    AttemptedSource,
    AttemptsRead,
    RetainedReopen,
    Preacquire,
    Reference,
    AccountId,
    Audit,
    EndpointCreate,
    DirectoryOpen,
    IpcBind,
    EndpointPublish,
}
impl OpenOperation {
    fn label(self) -> &'static str {
        match self {
            Self::AccountUnlock => "SingleAccountUnlock",
            Self::RetainedRead => "SingleRetainedRead",
            Self::AcquireState => "SingleAcquireState",
            Self::AttemptedSource => "SingleAttemptedSource",
            Self::AttemptsRead => "SingleAttemptsRead",
            Self::RetainedReopen => "SingleRetainedReopen",
            Self::Preacquire => "SinglePreacquire",
            Self::Reference => "SingleReference",
            Self::AccountId => "SingleAccountId",
            Self::Audit => "SingleAudit",
            Self::EndpointCreate => "SingleEndpointCreate",
            Self::DirectoryOpen => "SingleDirectoryOpen",
            Self::IpcBind => "SingleIpcBind",
            Self::EndpointPublish => "SingleEndpointPublish",
        }
    }
}
pub(super) fn report_open_begin(operation: OpenOperation) {
    eprintln!("\n[JOINED_DIAGNOSTIC {} Begin]", operation.label());
}
pub(super) fn report_open_result<T>(operation: OpenOperation, result: &Result<T>) {
    let label = result
        .as_ref()
        .map_or_else(|error| error_label(error), |_| "Complete");
    eprintln!("\n[JOINED_DIAGNOSTIC {} {}]", operation.label(), label);
    if let Err(Error::Io(error)) = result {
        // Do not format error/source/path. Unknown future ErrorKind variants
        // remain a closed Other class; the actual numeric errno is preserved.
        let kind = match error.kind() {
            std::io::ErrorKind::NotFound => "NotFound",
            std::io::ErrorKind::PermissionDenied => "PermissionDenied",
            std::io::ErrorKind::AlreadyExists => "AlreadyExists",
            std::io::ErrorKind::InvalidInput => "InvalidInput",
            std::io::ErrorKind::InvalidData => "InvalidData",
            std::io::ErrorKind::AddrInUse => "AddrInUse",
            std::io::ErrorKind::AddrNotAvailable => "AddrNotAvailable",
            std::io::ErrorKind::WouldBlock => "WouldBlock",
            std::io::ErrorKind::TimedOut => "TimedOut",
            std::io::ErrorKind::Interrupted => "Interrupted",
            std::io::ErrorKind::Unsupported => "Unsupported",
            _ => "Other",
        };
        let errno = error
            .raw_os_error()
            .map_or_else(|| "none".into(), |n| n.to_string());
        eprintln!("\n[JOINED_IO {} {} {}]", operation.label(), kind, errno);
    }
}

// Retain both concrete temporary installations inside the draining guard,
// including destructuring/error paths where outer argument drop order differs.
struct DrainingSingleController(
    BornManualUi,
    Arc<tempfile::TempDir>,
    EphemeralOwnerCredentials,
);
impl DrainingSingleController {
    fn new(ui: BornManualUi, original: &AcknowledgedBornFixture) -> Self {
        Self(ui, original.temporary.clone(), original.credentials.clone())
    }
}
impl std::ops::Deref for DrainingSingleController {
    type Target = BornManualUi;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DrainingSingleController {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for DrainingSingleController {
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
pub(in crate::native_ui) struct ExportedSingleAnchor {
    controller: DrainingSingleController,
    original: AcknowledgedBornFixture,
    pub(in crate::native_ui) signed_extension_file: PathBuf,
    pub(in crate::native_ui) enrollment_request: HostManualEnrollmentRequest,
}

fn drain(ui: &mut BornManualUi, epoch: u64) -> Result<()> {
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

fn approve_current(ui: &mut BornManualUi, epoch: u64) -> Result<()> {
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
pub(in crate::native_ui) struct InitialSingleFixture {
    controller: DrainingSingleController,
    original: AcknowledgedBornFixture,
    intent: HostIntent,
    scope: PairScope,
    epoch: u64,
    retained: bool,
}
impl InitialSingleFixture {
    pub(in crate::native_ui) fn open(
        ui: BornManualUi,
        original: AcknowledgedBornFixture,
        intent: HostIntent,
    ) -> Result<Self> {
        let mut ui = DrainingSingleController::new(ui, &original);
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
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: intent.scope.agreement_id.clone(),
            participant_id: intent.scope.participant_id.clone(),
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
                .retained_born_manual_enrollment(self.controller.owner(self.epoch)?.as_ref())?
                .ok_or(Error::RecoveryRequired)?;
            if record_intent(retained.record()) != self.intent {
                return Err(Error::ReviewMismatch);
            }
        }
        Ok(self.retained)
    }
    /// The exact retained intent is signed/exported by separate real reviews.
    pub(in crate::native_ui) fn export(self, destination: &Path) -> Result<ExportedSingleAnchor> {
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
            .retained_born_manual_enrollment(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        if record_intent(retained.record()) != intent {
            return Err(Error::ReviewMismatch);
        }
        let enrollment_request = HostManualEnrollmentRequest {
            terms: retained.record().terms.clone(),
        };
        drop(retained);
        export_retained(controller, original, enrollment_request, destination, epoch)
    }
}

fn export_retained(
    mut ui: DrainingSingleController,
    original: AcknowledgedBornFixture,
    enrollment_request: HostManualEnrollmentRequest,
    destination: &Path,
    epoch: u64,
) -> Result<ExportedSingleAnchor> {
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
        "manual-owner-extension-{}.json",
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

    if !ui.bootstrap.initial_export()
        || ui.bootstrap.can_acquire()
        || ui.writer.is_some()
        || ui.receipt.is_some()
        || ui.enrolled.is_some()
        || original.root.join("authority.sqlite").exists()
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(ExportedSingleAnchor {
        controller: ui,
        original,
        signed_extension_file,
        enrollment_request,
    })
}

impl ExportedSingleAnchor {
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
pub(in crate::native_ui) struct SinglePublicationFixture {
    controller: DrainingSingleController,
    original: AcknowledgedBornFixture,
    request: HostManualEnrollmentRequest,
    scope: PairScope,
    epoch: u64,
}
impl SinglePublicationFixture {
    pub(in crate::native_ui) fn close(self) -> AcknowledgedBornFixture {
        let Self {
            controller,
            original,
            ..
        } = self;
        drop(controller);
        original
    }
    pub(in crate::native_ui) fn open(
        ui: BornManualUi,
        original: AcknowledgedBornFixture,
        request: HostManualEnrollmentRequest,
    ) -> Result<Self> {
        request.validate().map_err(|_| Error::InvalidData)?;
        let mut controller = DrainingSingleController::new(ui, &original);
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
            .retained_born_manual_enrollment(&owner)?
            .ok_or(Error::RecoveryRequired)?;
        if retained.record().terms != request.terms {
            return Err(Error::ReviewMismatch);
        }
        drop(retained);
        let terms = &request.terms;
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: publication_intent_digest(&request)?,
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

// Initial V1 publication pairs to the original request-only intent, just as
// the actual Host and PreparedBornManualReentry do. The full queued
// request is still independently compared in poll_publication above.
fn publication_intent_digest(request: &HostManualEnrollmentRequest) -> Result<String> {
    request.validate().map_err(|_| Error::InvalidData)?;
    HostIntent {
        version: 1,
        operation_id: request.terms.operation_id.clone(),
        host: request.terms.host.clone(),
        scope: request.terms.scope.clone(),
    }
    .digest()
    .map_err(|_| Error::InvalidData)
}

fn record_intent(
    record: &crate::account::birth::enrollment::BornManualEnrollmentRecord,
) -> HostIntent {
    HostIntent {
        version: 1,
        operation_id: record.terms.operation_id.clone(),
        host: record.terms.host.clone(),
        scope: record.terms.scope.clone(),
    }
}

#[cfg(test)]
mod endpoint_tests {
    #[test]
    fn single_endpoint_creation_satisfies_unchanged_private_directory_gate() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = super::super::private_temporary_endpoint().unwrap();
        let metadata = std::fs::symlink_metadata(temporary.path()).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        let private = crate::files::PrivateDirectory::open(temporary.path()).unwrap();
        drop(private);
        drop(temporary);
    }
}

#[cfg(test)]
mod publication_scope_tests {
    use super::*;
    use wholepact_core::manual_enrollment::{
        BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
        ManualHostGenerationBinding,
    };

    // Inert validated terms only. No native, account, pairing or witness owner
    // is manufactured, and these records are never submitted or persisted.
    fn request() -> HostManualEnrollmentRequest {
        let h = || "a".repeat(64);
        HostManualEnrollmentRequest {
            terms: BornManualEnrollmentTerms {
                version: 1,
                operation_id: "synthetic-first-enrollment".into(),
                identity: ManualAccountIdentity {
                    account_id: h(),
                    full_viewing_key_digest: h(),
                    network_profile_id: "synthetic-testnet".into(),
                    derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
                },
                birth_request_digest: h(),
                birth_commit_digest: h(),
                native_birth_digest: h(),
                original_policy_digest: h(),
                account_use_genesis_digest: h(),
                original_witness_origin_digest: h(),
                host: ManualHostGenerationBinding {
                    generation_id: h(),
                    inventory_digest: h(),
                    generation_plan_digest: h(),
                    financial_journal_origin_digest: h(),
                    store_destination_identity: "synthetic-store".into(),
                    profile_id: "synthetic-profile".into(),
                    canonical_root: "/synthetic/profile".into(),
                    destination_identity_digest: h(),
                    inherited_identity_digest: h(),
                    scope_predecessor_digest: None,
                },
                signer: BornManualSignerBinding {
                    enrollment_generation_id: h(),
                    signer_target_digest: h(),
                    original_envelope_digest: h(),
                    owner_certificate_digest: h(),
                    writer_certificate_digest: h(),
                    writer_epoch: 1,
                    native_signer_measurement: h(),
                },
                scope: BornManualScope {
                    agreement_id: "synthetic-agreement".into(),
                    obligation_id: "synthetic-obligation".into(),
                    participant_id: "synthetic-participant".into(),
                    principal_id: "synthetic-host-principal".into(),
                    privacy_domain: "synthetic-domain".into(),
                    recipient_scope_digests: vec![h()],
                    aggregate_budget_zatoshis: 100,
                    per_operation_limit_zatoshis: 80,
                    maximum_fee_share_zatoshis: 5,
                    maximum_transaction_fee_zatoshis: 10,
                    maximum_permit_lifetime_ms: 1000,
                    expires_at_ms: 200000,
                },
                transport_binding_digest: h(),
                issued_at_ms: 10,
            },
        }
    }

    #[test]
    fn single_publication_pairs_to_original_intent_not_full_request() {
        let request = request();
        request.validate().unwrap();
        let intent = HostIntent {
            version: 1,
            operation_id: request.terms.operation_id.clone(),
            host: request.terms.host.clone(),
            scope: request.terms.scope.clone(),
        };
        intent.matches_terms(&request.terms).unwrap();
        let expected = intent.digest().unwrap();
        assert_eq!(publication_intent_digest(&request).unwrap(), expected);
        assert_ne!(request.digest().unwrap(), expected);

        // Signer-derived fields do not redefine the original pairing scope,
        // but the separate complete queued-request comparison still sees them.
        let mut changed = request.clone();
        changed.terms.signer.signer_target_digest = "b".repeat(64);
        changed.validate().unwrap();
        assert_eq!(publication_intent_digest(&changed).unwrap(), expected);
        assert_ne!(changed.digest().unwrap(), request.digest().unwrap());

        // Every original intent component remains committed, with no new scope.
        for field in 0..3 {
            let mut changed = request.clone();
            match field {
                0 => changed.terms.operation_id.push_str("-other"),
                1 => changed.terms.host.inventory_digest = "c".repeat(64),
                _ => changed.terms.scope.participant_id.push_str("-other"),
            }
            assert_ne!(publication_intent_digest(&changed).unwrap(), expected);
        }
        let mut malformed = request;
        malformed.terms.version = 2;
        assert!(publication_intent_digest(&malformed).is_err());
    }
}
