//! Connected native lifecycle for the one-way restriction flow. Ordinary
//! enrollment admission is closed and drained before the born owner moves.
use super::permanent_stop::{
    PreparedPermanentStopReadV1, PreparedPermanentStopSignatureV1, ReadOutcome,
};
use super::permanent_stop_export::PreparedPermanentStopExportV1;
use super::permanent_stop_publication::PreparedPermanentStopPublicationV1;
use super::*;
use crate::account::birth::enrollment::roster_v2::permanent_stop::{
    BornPermanentStopSourceV1, PreparedBornPermanentStopV1,
};
use crate::ipc::permanent_stop::{AuthenticatedPermanentStopRequestV1, PermanentStopCancellation};
pub(super) struct StopOpened {
    source: Option<BornPermanentStopSourceV1>,
    pub(super) ipc: Arc<Mutex<LocalIpc>>,
    revocation: IpcRevocation,
    _temporary: tempfile::TempDir,
    cancellation: Option<PermanentStopCancellation>,
}
impl StopOpened {
    pub(super) fn revoke(&self) {
        self.revocation.close_pending_now();
        if let Some(c) = &self.cancellation {
            c.cancel();
        }
    }
}
pub(super) enum StopPreparation {
    Read(Box<PreparedPermanentStopReadV1>),
    Local(Box<PreparedBornPermanentStopV1>),
    Signature(Box<PreparedPermanentStopSignatureV1>),
    Export(Box<PreparedPermanentStopExportV1>),
    Publication(Box<PreparedPermanentStopPublicationV1>),
}
impl StopPreparation {
    pub(super) fn display(&self) -> Result<(String, String)> {
        Ok(match self {
            Self::Read(p) => (p.reviewed_digest().into(), p.review_json()?),
            Self::Local(p) => (p.reviewed_digest().into(), p.review_json()?),
            Self::Signature(p) => (p.reviewed_digest().into(), p.review_json()?),
            Self::Export(p) => (p.digest().into(), p.display().into()),
            Self::Publication(p) => (p.reviewed_digest().into(), p.review_json()?),
        })
    }
}
pub(super) enum StopWork {
    Open(PathBuf, Zeroizing<String>),
    Transition(
        Box<BornManualRosterUiV2>,
        Arc<BornManualRosterEnrolledSignerV2>,
    ),
    Local(Box<BornPermanentStopSourceV1>),
    Read(Box<BornPermanentStopSourceV1>, Zeroizing<String>),
    Signature(Box<BornPermanentStopSourceV1>, PathBuf, PathBuf),
    Export(Box<BornPermanentStopSourceV1>, PathBuf),
    Publication(
        Box<BornPermanentStopSourceV1>,
        Box<AuthenticatedPermanentStopRequestV1>,
    ),
    Commit(Arc<Mutex<LocalIpc>>, Step, NativeDecision),
}
pub(super) enum StopOutput {
    Opened(Box<StopOpened>),
    Source(Box<BornPermanentStopSourceV1>),
    Published(Box<BornPermanentStopSourceV1>),
}
fn open_source(
    source: BornPermanentStopSourceV1,
    owner: &PendingAccountNativeAuthority,
) -> Result<Output> {
    source.check(owner)?;
    let temporary = tempfile::tempdir()?;
    let ipc = LocalIpc::bind_permanent_stop_v1(
        crate::files::PrivateDirectory::open(temporary.path())?,
        source.genesis().identity.account_id.clone(),
    )?;
    owner.publish_pending_endpoint(ipc.socket_path())?;
    Ok(Output::Stop(StopOutput::Opened(Box::new(StopOpened {
        source: Some(source),
        revocation: ipc.revocation(),
        ipc: Arc::new(Mutex::new(ipc)),
        _temporary: temporary,
        cancellation: None,
    }))))
}
fn prepared(value: StopPreparation) -> Result<Output> {
    Ok(Output::Prepared(Box::new(Prepared::new(Step::Stop(
        Box::new(value),
    ))?)))
}
pub(super) fn run(work: StopWork, owner: &PendingAccountNativeAuthority) -> Result<Output> {
    match work {
        StopWork::Open(path, password) => {
            let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
                &path,
                password.as_bytes(),
                owner,
            )?);
            open_source(BornPermanentStopSourceV1::reopen(account, owner)?, owner)
        }
        StopWork::Transition(mut retired, enrolled) => {
            // No worker/review may exist at transition. Remove every ordinary
            // shared vault/journal owner and join cleanup before try_unwrap.
            if retired.job.is_some() || retired.review.is_some() || retired.owner.is_some() {
                return Err(Error::Locked);
            }
            retired.clear();
            for thread in retired.cleanup.drain(..) {
                thread.join().map_err(|_| Error::Uncertain)?;
            }
            drop(retired);
            open_source(
                BornPermanentStopSourceV1::from_enrolled(enrolled, owner)?,
                owner,
            )
        }
        StopWork::Local(source) => prepared(StopPreparation::Local(Box::new(
            PreparedBornPermanentStopV1::prepare(*source, owner)?,
        ))),
        StopWork::Read(source, setup) => prepared(StopPreparation::Read(Box::new(
            PreparedPermanentStopReadV1::prepare(*source, &setup, owner)?,
        ))),
        StopWork::Signature(source, certificate, key) => {
            prepared(StopPreparation::Signature(Box::new(
                PreparedPermanentStopSignatureV1::prepare(*source, &certificate, &key, owner)?,
            )))
        }
        StopWork::Export(source, destination) => prepared(StopPreparation::Export(Box::new(
            PreparedPermanentStopExportV1::prepare(*source, &destination, owner)?,
        ))),
        StopWork::Publication(source, request) => prepared(StopPreparation::Publication(Box::new(
            PreparedPermanentStopPublicationV1::prepare(*source, *request, owner)?,
        ))),
        StopWork::Commit(ipc, step, decision) => match step {
            Step::Pair(pair) => {
                ipc.lock().map_err(|_| Error::Locked)?.approve_pairing(
                    *pair,
                    decision,
                    owner.native(),
                )?;
                Ok(Output::Paired)
            }
            Step::Stop(p) => match *p {
                StopPreparation::Read(p) => match p.approve_and_read(decision, owner)? {
                    ReadOutcome::LocalReview(p) => prepared(StopPreparation::Local(p)),
                    ReadOutcome::Stopped(source) => Ok(Output::Stop(StopOutput::Source(source))),
                },
                StopPreparation::Local(p) => Ok(Output::Stop(StopOutput::Source(Box::new(
                    p.approve_and_retain(decision, owner)?,
                )))),
                StopPreparation::Signature(p) => Ok(Output::Stop(StopOutput::Source(Box::new(
                    p.approve_and_sign(decision, owner)?,
                )))),
                StopPreparation::Export(p) => Ok(Output::Stop(StopOutput::Source(Box::new(
                    p.publish(decision, owner)?,
                )))),
                StopPreparation::Publication(p) => Ok(Output::Stop(StopOutput::Published(
                    Box::new(p.approve_and_publish(decision, owner)?),
                ))),
            },
            _ => Err(Error::Unavailable),
        },
    }
}
impl BornManualRosterUiV2 {
    pub(in crate::native_ui) fn begin_permanent_stop(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        wholepact_signer_origin::permanent_stop_v1::require_activation_v1()
            .map_err(|_| Error::Unavailable)?;
        if self.is_active() || !path.is_absolute() || !(12..=1024).contains(&password.len()) {
            return Err(Error::Locked);
        }
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry,
            Instant::now() + Duration::from_secs(120),
        )?);
        self.job = Some(Job::start(
            Work::Stop(StopWork::Open(path.into(), Zeroizing::new(password.into()))),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message = "Opening the actual original born V2 vault for one-way routine-use restriction. No ordinary signer is activated.";
        Ok(())
    }
    pub(super) fn transition_permanent_stop(&mut self, epoch: u64) -> Result<()> {
        // Gate first: even an unavailable click cannot revoke or move an owner.
        wholepact_signer_origin::permanent_stop_v1::require_activation_v1()
            .map_err(|_| Error::Unavailable)?;
        if self.job.is_some()
            || self.review.is_some()
            || !self.cleanup.is_empty()
            || self.stop_opened.is_some()
            || self.completion_opened.is_some()
        {
            return Err(Error::Locked);
        }
        let owner = self.owner(epoch)?;
        if self.enrolled.is_none() {
            return Err(Error::Locked);
        }
        if let Some(open) = &self.opened {
            open.revoke();
        }
        if let Some(peer) = &self.peer {
            peer.retire_now();
        }
        let mut retired = std::mem::take(self);
        retired.owner = None;
        let enrolled = retired.enrolled.take().ok_or(Error::Locked)?;
        // The old peer remains only inside the retiring enrolled owner and is
        // already revoked. Fresh endpoint pairing uses this actual native owner.
        self.owner = Some(owner.clone());
        self.job = Some(Job::start(
            Work::Stop(StopWork::Transition(Box::new(retired), enrolled)),
            owner,
        )?);
        self.message = "Ordinary admission closed. Draining exact original vault owners before fresh restriction-only pairing.";
        Ok(())
    }
    pub(super) fn accept_stop_output(&mut self, out: StopOutput) -> Result<()> {
        match out {
            StopOutput::Opened(open) => {
                self.stop_opened = Some(*open);
                self.message = "Original born source held. The first native restriction review works locally; witness read and propagation remain separate.";
            }
            StopOutput::Source(source) => {
                let open = self.stop_opened.as_mut().ok_or(Error::Locked)?;
                open.source = Some(*source);
                open.cancellation = None;
                self.message = "Original restriction state retained. Pending exposure remains. Independent witness commit and exact Host propagation may still be pending.";
            }
            StopOutput::Published(source) => {
                let open = self.stop_opened.as_mut().ok_or(Error::Locked)?;
                open.source = Some(*source);
                open.cancellation = None;
                if let Some(peer) = self.peer.take() {
                    peer.retire_now();
                }
                open.ipc.lock().map_err(|_| Error::Locked)?.revoke_all();
                self.message = "Exact Host durable acknowledgment retained. Local and witnessed restrictions remain one-way; pending exposure and observation history are preserved. No account emptiness or funds recovery is claimed.";
            }
        }
        Ok(())
    }
    pub(super) fn poll_stop_event(&mut self, epoch: u64) -> Result<()> {
        let event = self
            .stop_opened
            .as_ref()
            .and_then(|o| o.ipc.try_lock().ok().and_then(|ipc| ipc.next_event()));
        match event {
            Some(LocalEvent::Pairing(pair)) => {
                if self.peer.is_some() {
                    return Err(Error::Authentication);
                }
                let open = self.stop_opened.as_ref().ok_or(Error::Locked)?;
                let source = open.source.as_ref().ok_or(Error::Locked)?;
                if pair.scope.account_id != source.genesis().identity.account_id
                    || pair.scope.history_read
                    || pair.scope.authorization_export
                    || pair.scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
                let digest =
                    pair.review_digest(open.ipc.lock().map_err(|_| Error::Locked)?.generation())?;
                let display = format!(
                    "FRESH RESTRICTION-ONLY PAIRING\nOriginal born account: {}\nActual local UID/PID: {}/{}\nActual process instance: {}\n{}\n\nThis exact manifest commits a Host permanent-stop request. The Host must independently verify its original encrypted enrollment. Pairing grants no evidence release, witness action, account keys, financial permission or recovery source. Separate exact publication review is required. Old enrollment grants remain revoked.",
                    source.genesis().identity.account_id,
                    pair.uid(),
                    pair.pid(),
                    pair.instance(),
                    serde_json::to_string_pretty(&pair.scope).map_err(|_| Error::InvalidData)?
                );
                self.review = Some(Review {
                    step: Step::Pair(Box::new(pair)),
                    exact: ExactNativeReview::stage(
                        self.owner(epoch)?.native(),
                        &digest,
                        display,
                        epoch,
                    )?,
                    displayed_to_end: false,
                });
            }
            Some(LocalEvent::Request {
                peer,
                request: crate::ipc::AppRequest::Status {},
            }) => {
                let owner = self.owner(epoch)?;
                let source = self
                    .stop_opened
                    .as_ref()
                    .and_then(|o| o.source.as_ref())
                    .ok_or(Error::Locked)?;
                if peer.native_origin != owner.native().binding()
                    || peer.scope.account_id != source.genesis().identity.account_id
                {
                    return Err(Error::Authentication);
                }
                if let Some(old) = &self.peer {
                    old.require_same_grant(&peer)?;
                }
                self.peer = Some(peer);
            }
            Some(LocalEvent::BornPermanentStopV1(request)) => {
                self.peer
                    .as_ref()
                    .ok_or(Error::Authentication)?
                    .require_same_grant(request.peer())?;
                let open = self.stop_opened.as_mut().ok_or(Error::Locked)?;
                open.cancellation = Some(request.cancellation()?);
                let source = open.source.take().ok_or(Error::Locked)?;
                self.start(
                    Work::Stop(StopWork::Publication(Box::new(source), request)),
                    epoch,
                )?;
            }
            None => {}
            Some(_) => return Err(Error::Unavailable),
        }
        Ok(())
    }
    pub(super) fn stop_controls(&mut self, ui: &mut egui::Ui, epoch: u64) -> Result<()> {
        ui.heading("Permanent stop of routine reuse");
        ui.label("Local exclusion is durable first. Witness commit, fresh authenticated read and named Host acknowledgment are separate steps. Existing pending exposure remains visible in each complete review. Activation is unavailable until attended native/kernel qualification.");
        ui.label("Existing original witness credential-selection JSON");
        ui.add(egui::TextEdit::multiline(&mut *self.witness_setup).char_limit(16 * 1024));
        let mut action = 0;
        if ui
            .button("Review durable local stop now (remote exposure may remain unknown)")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = 4;
        }
        if ui
            .button("Review complete witness history / original witness acknowledgment")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = 1;
        }
        ui.label("Existing owner certificate DER and private PKCS8 file paths");
        ui.add(egui::TextEdit::singleline(&mut *self.certificate).char_limit(4096));
        ui.add(egui::TextEdit::singleline(&mut *self.key).char_limit(4096));
        if ui
            .button("Review signing exact local permanent exclusion")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = 2;
        }
        ui.label("Existing separate private export directory");
        ui.add(egui::TextEdit::singleline(&mut *self.destination).char_limit(4096));
        if ui
            .button("Review exact signed exclusion export for independent witness owner")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = 3;
        }
        if ui
            .button("Cancel and retain permanent restrictions")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.clear();
            return Ok(());
        }
        if action > 0 {
            let source = self
                .stop_opened
                .as_mut()
                .and_then(|o| o.source.take())
                .ok_or(Error::Locked)?;
            let work = match action {
                4 => StopWork::Local(Box::new(source)),
                1 => StopWork::Read(
                    Box::new(source),
                    Zeroizing::new(self.witness_setup.to_string()),
                ),
                2 => StopWork::Signature(
                    Box::new(source),
                    PathBuf::from(self.certificate.as_str()),
                    PathBuf::from(self.key.as_str()),
                ),
                _ => StopWork::Export(Box::new(source), PathBuf::from(self.destination.as_str())),
            };
            self.start(Work::Stop(work), epoch)?;
        }
        Ok(())
    }
}
