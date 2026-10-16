//! Separate restricted native informational entry. The public availability gate
//! precedes source opening, credential preparation and runtime directory effects.
//! No ordinary OpenAccount, vault, journal/session or financial owner is retained.
use super::{
    NativeAuthority, NativeDecision,
    authority::ExactNativeReview,
    informational_witness::{NativeInformationalWitness, PreparedInformationalWitnessSetup},
    quarantined_v5::{
        CompletedQuarantinedContinuityV5, PreparedQuarantinedContinuityV5,
        PreparedQuarantinedPublicationV5,
    },
};
use crate::{
    Error, Result,
    account::informational::QuarantinedInformationalAccount,
    authority_bridge::host_recovery_ipc::v5::{
        V5TransferDialect, require_quarantined_informational_endpoint,
    },
    files::PrivateDirectory,
    ipc::{AuthenticatedPeer, IpcRevocation, LocalEvent, LocalIpc, PairScope, PendingPairing},
    native_launch::ParentChannel,
};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const NATIVE_WINDOW: Duration = Duration::from_secs(120);

// This mailbox contains restriction-only data, never native/source/peer/TLS
// ownership. Its atomic state linearizes completion against blur/cancellation;
// the GUI never waits for its mutex. Only the successful serve path supplies T.
const HANDOFF_PENDING: u8 = 0;
const HANDOFF_COMPLETED: u8 = 1;
const HANDOFF_CANCELLED: u8 = 2;
struct CompletionMailbox<T> {
    phase: AtomicU8,
    value: Mutex<Option<T>>,
}
impl<T> Default for CompletionMailbox<T> {
    fn default() -> Self {
        Self {
            phase: AtomicU8::new(HANDOFF_PENDING),
            value: Mutex::new(None),
        }
    }
}
impl<T> CompletionMailbox<T> {
    fn complete(&self, value: T) -> Result<()> {
        let mut slot = self.value.lock().map_err(|_| Error::Locked)?;
        if self.phase.load(Ordering::Acquire) != HANDOFF_PENDING || slot.is_some() {
            return Err(Error::ReviewMismatch);
        }
        *slot = Some(value);
        if self
            .phase
            .compare_exchange(
                HANDOFF_PENDING,
                HANDOFF_COMPLETED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            *slot = None;
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn cancel(&self) {
        self.phase.store(HANDOFF_CANCELLED, Ordering::Release);
    }
    fn preserve_completed_on_blur(&self) -> bool {
        matches!(
            self.phase.compare_exchange(
                HANDOFF_PENDING,
                HANDOFF_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Err(HANDOFF_COMPLETED)
        )
    }
    fn with_completed<R>(&self, read: impl FnOnce(&T) -> Result<R>) -> Result<R> {
        let slot = self.value.try_lock().map_err(|_| Error::Locked)?;
        if self.phase.load(Ordering::Acquire) != HANDOFF_COMPLETED {
            return Err(Error::Locked);
        }
        read(slot.as_ref().ok_or(Error::Locked)?)
    }
    fn take(&self) -> Result<T> {
        let mut slot = self.value.try_lock().map_err(|_| Error::Locked)?;
        self.phase
            .compare_exchange(
                HANDOFF_COMPLETED,
                HANDOFF_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::Locked)?;
        slot.take().ok_or(Error::Locked)
    }
}
struct DormantHandoff {
    root: PathBuf,
    archive: PathBuf,
    runtime: PathBuf,
    socket: Option<PathBuf>,
    completion: Arc<CompletionMailbox<CompletedQuarantinedContinuityV5>>,
}
impl DormantHandoff {
    fn deadline(&self) -> Result<Instant> {
        self.completion.with_completed(|completed| {
            let deadline = completed.deadline();
            if Instant::now() >= deadline {
                return Err(Error::Locked);
            }
            Ok(deadline)
        })
    }
}
fn handoff_deadline(original: Instant, now: Instant) -> Result<Instant> {
    if now >= original {
        return Err(Error::Locked);
    }
    Ok(original.min(now + NATIVE_WINDOW))
}
fn require_handoff_paths(
    root: &Path,
    archive: &Path,
    original_root: &Path,
    original_archive: &Path,
) -> Result<()> {
    if root != original_root || archive != original_archive {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

/// Pure lifecycle predicate, never an entry or approval factory.
fn require_lifecycle(
    focused: bool,
    current_epoch: u64,
    original_epoch: u64,
    cancelled: bool,
    now: Instant,
    deadline: Instant,
) -> Result<()> {
    if !focused || current_epoch != original_epoch || cancelled || now >= deadline {
        return Err(Error::Locked);
    }
    Ok(())
}
fn require_pair_scope(scope: &PairScope, account_id: &str) -> Result<()> {
    scope.validate()?;
    if scope.account_id != account_id
        || !scope.history_read
        || !scope.authorization_export
        || scope.preconstruction_export
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Public process association data only. Authentication still requires the
/// actual PendingPairing/AuthenticatedPeer and their live kernel handles.
#[derive(Clone, PartialEq, Eq)]
struct PairIdentity {
    uid: u32,
    pid: u32,
    instance: String,
    generation: u64,
    channel_digest: String,
    scope: PairScope,
}
impl PairIdentity {
    fn pending(pair: &PendingPairing, generation: u64) -> Result<Self> {
        pair.check_current()?;
        Ok(Self {
            uid: pair.uid(),
            pid: pair.pid(),
            instance: pair.instance().into(),
            generation,
            channel_digest: pair.review_digest(generation)?,
            scope: pair.scope.clone(),
        })
    }
    fn require_peer(&self, peer: &AuthenticatedPeer) -> Result<()> {
        peer.check_current()?;
        let observed = Self {
            uid: peer.peer.uid(),
            pid: peer.peer.pid(),
            instance: peer.peer.instance().into(),
            generation: peer.generation,
            channel_digest: peer.channel_digest.clone(),
            scope: peer.scope.clone(),
        };
        if self != &observed {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Lifetime {
    authority: Arc<NativeAuthority>,
    parent_channel: Option<ParentChannel>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    epoch: u64,
}
impl Lifetime {
    fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        self.authority.check_current()?;
        if let Some(parent) = &self.parent_channel {
            parent.check_connected()?;
        }
        self.authority.check_current()
    }
    fn revoke_now(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.authority.revoke_informational_now();
    }
}
struct State {
    lifetime: Lifetime,
    publication_only: bool,
    publication_completion: Option<CompletedQuarantinedContinuityV5>,
    source: Option<Arc<QuarantinedInformationalAccount>>,
    ipc: Option<Arc<Mutex<LocalIpc>>>,
    revocation: Option<IpcRevocation>,
    witness: Option<Arc<NativeInformationalWitness>>,
    approved_pair: Option<PairIdentity>,
    first_peer: Option<AuthenticatedPeer>,
}
impl State {
    fn bind_first_peer(&mut self, peer: &AuthenticatedPeer) -> Result<()> {
        self.lifetime.check()?;
        let source = self.source.as_ref().ok_or(Error::Locked)?;
        require_pair_scope(&peer.scope, source.account_id())?;
        self.approved_pair
            .as_ref()
            .ok_or(Error::Authentication)?
            .require_peer(peer)?;
        if peer.native_origin != self.lifetime.authority.binding()
            || self
                .ipc
                .as_ref()
                .ok_or(Error::Locked)?
                .try_lock()
                .map_err(|_| Error::Locked)?
                .generation()
                != peer.generation
        {
            return Err(Error::Authentication);
        }
        if let Some(first) = &self.first_peer {
            first.check_current()?;
            first.peer.same_live_process(&peer.peer)?;
            if first.grant_id != peer.grant_id
                || first.key_digest != peer.key_digest
                || first.channel_digest != peer.channel_digest
                || first.generation != peer.generation
                || first.scope != peer.scope
            {
                return Err(Error::Authentication);
            }
        } else {
            self.first_peer = Some(peer.clone());
        }
        Ok(())
    }
}

enum Operation {
    Witness(Box<PreparedInformationalWitnessSetup>),
    Pair(Box<PendingPairing>, PairIdentity),
    Continuity(Box<PreparedQuarantinedContinuityV5>),
    Publication(Box<PreparedQuarantinedPublicationV5>),
}
struct PreparedReview {
    operation: Operation,
    digest: String,
    display: String,
}
impl PreparedReview {
    fn from_operation(operation: Operation) -> Result<Self> {
        let (digest, display) = match &operation {
            Operation::Witness(value) => (value.digest().into(), value.display()?),
            Operation::Continuity(value) => (value.digest().into(), value.display()?),
            Operation::Publication(value) => (value.digest().into(), value.display()?),
            Operation::Pair(pair, identity) => (
                identity.channel_digest.clone(),
                format!(
                    "PAIR ONE LOCAL PROCESS FOR QUARANTINED INFORMATION ONLY\n\nUnverified application label: {}\nObserved UID: {}\nObserved PID: {}\nObserved process-instance binding: {}\nListener generation: {}\nAccount: {}\nAgreement association: {}\nParticipant association: {}\nExact Host inventory manifest: {}\n\nOnly bounded V5 informational continuity and separately reviewed informational publication requests are accepted. The history_read and authorization_export wire flags identify this restricted request scope; this listener cannot deliver signatures, viewing keys or financial capabilities. Preconstruction export is disabled.\n\nThe first authenticated request must prove this exact grant/channel and process. It remains the only admitted peer for this source lifetime. Another grant, process, generation or channel is refused. Lock, focus change, parent disconnect and original expiry revoke new admission. This authenticates a local process association, not a software publisher or real-world identity.",
                    pair.label,
                    identity.uid,
                    identity.pid,
                    identity.instance,
                    identity.generation,
                    pair.scope.account_id,
                    pair.scope.agreement_id,
                    pair.scope.participant_id,
                    pair.scope.manifest_digest,
                ),
            ),
        };
        Ok(Self {
            operation,
            digest,
            display,
        })
    }
}
struct PendingReview {
    operation: Operation,
    exact: ExactNativeReview,
}
enum Output {
    Opened(
        Arc<QuarantinedInformationalAccount>,
        Arc<Mutex<LocalIpc>>,
        Option<Box<CompletedQuarantinedContinuityV5>>,
    ),
    Prepared(Box<PreparedReview>),
    Witness(Arc<NativeInformationalWitness>),
    Paired(PairIdentity),
    Served,
}
struct Job {
    receive: mpsc::Receiver<Result<Output>>,
    thread: JoinHandle<()>,
}
impl Job {
    fn finish(self) -> Result<Output> {
        if self.thread.join().is_err() {
            return Err(Error::Uncertain);
        }
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}

#[derive(Default)]
pub(super) struct QuarantinedHistoryUi {
    state: Option<State>,
    pending: Option<PendingReview>,
    job: Option<Job>,
    closing: Vec<Arc<AtomicBool>>,
    handoff: Option<DormantHandoff>,
    witness_json: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    message: String,
}
impl QuarantinedHistoryUi {
    pub(super) fn has_dormant_continuity(&self) -> bool {
        self.state.is_none()
            && self
                .handoff
                .as_ref()
                .is_some_and(|handoff| handoff.deadline().is_ok())
    }
    pub(super) fn is_active(&self) -> bool {
        self.state.is_some()
            || self.job.is_some()
            || self
                .closing
                .iter()
                .any(|done| !done.load(Ordering::Acquire))
    }
    pub(super) fn clear(&mut self) {
        if let Some(handoff) = self.handoff.take() {
            handoff.completion.cancel();
        }
        self.revoke_and_drain();
    }
    /// A focus handoff preserves only an already completed, inert restriction.
    /// It revokes every actual owner exactly like clear. Partial/late completion
    /// is cancelled; this is never inferred from a Host acknowledgement.
    pub(super) fn blur(&mut self) {
        if self
            .handoff
            .as_ref()
            .is_some_and(|handoff| !handoff.completion.preserve_completed_on_blur())
        {
            self.handoff = None;
        }
        self.revoke_and_drain();
    }
    fn revoke_and_drain(&mut self) {
        if let Some(state) = &self.state {
            state.lifetime.revoke_now();
            if let Some(revoke) = &state.revocation {
                revoke.close_informational_now();
            }
        }
        self.pending = None;
        self.witness_json.zeroize();
        self.confirmation.zeroize();
        let state = self.state.take();
        let job = self.job.take();
        if state.is_none() && job.is_none() {
            return;
        }
        self.message = "Informational access is revoked. If disclosure was transmitted or publication was already admitted, its outcome is uncertain and cancellation cannot recall it. Original source locks remain held while work drains.".into();
        // Keep the source, both directory locks and all worker handles alive
        // until the worker is finished. GUI cancellation never joins, waits on
        // publication/grant locks or drops a listener that might be draining.
        let done = Arc::new(AtomicBool::new(false));
        self.closing.push(done.clone());
        std::thread::spawn(move || {
            if let Some(job) = job {
                let _ = job.finish();
            }
            if let Some(state) = state {
                state.lifetime.authority.invalidate();
                drop(state);
            }
            done.store(true, Ordering::Release);
        });
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin(
        &mut self,
        root: &Path,
        password: &[u8],
        archive: &Path,
        recovery_password: &[u8],
        runtime_directory: &Path,
        focused: bool,
        epoch: u64,
        parent_channel: Option<ParentChannel>,
    ) -> Result<()> {
        // Must remain before any source open, native entry, credential read or
        // runtime-directory effect. No ordinary listener fallback is allowed.
        require_quarantined_informational_endpoint().map_err(|_| Error::Unavailable)?;
        if !focused || self.is_active() {
            return Err(Error::Locked);
        }
        // Taking the dormant record is one-use. Even a failed native reentry
        // cannot restore it or retry publication implicitly.
        let handoff = self.handoff.take();
        let publication_only = handoff.is_some();
        let (completion, original_socket, deadline) = if let Some(handoff) = handoff {
            let completed = handoff.completion.take()?;
            require_handoff_paths(root, archive, &handoff.root, &handoff.archive)?;
            if runtime_directory != handoff.runtime {
                return Err(Error::ReviewMismatch);
            }
            let deadline = handoff_deadline(completed.deadline(), Instant::now())?;
            (
                Some(completed),
                Some(handoff.socket.ok_or(Error::ReviewMismatch)?),
                deadline,
            )
        } else {
            (None, None, Instant::now() + NATIVE_WINDOW)
        };
        validate_paths(root, archive, runtime_directory)?;
        if let Some(parent) = &parent_channel {
            parent.check_connected()?;
        }
        let authority = Arc::new(NativeAuthority::entered_native_window()?);
        self.state = Some(State {
            publication_only,
            publication_completion: None,
            lifetime: Lifetime {
                authority,
                parent_channel,
                cancelled: Arc::new(AtomicBool::new(false)),
                deadline,
                epoch,
            },
            source: None,
            ipc: None,
            revocation: None,
            witness: None,
            approved_pair: None,
            first_peer: None,
        });
        if !publication_only {
            self.handoff = Some(DormantHandoff {
                root: root.to_path_buf(),
                archive: archive.to_path_buf(),
                runtime: runtime_directory.to_path_buf(),
                socket: None,
                completion: Arc::new(CompletionMailbox::default()),
            });
        }
        let root = root.to_path_buf();
        let archive = archive.to_path_buf();
        let runtime = runtime_directory.to_path_buf();
        let password = Zeroizing::new(password.to_vec());
        let recovery_password = Zeroizing::new(recovery_password.to_vec());
        self.message = "Authenticating the exact original source and backup within the original bounded native lifetime.".into();
        if let Err(error) = self.start_job(move |lifetime| {
            let source = Arc::new(QuarantinedInformationalAccount::open_existing_until(
                &root,
                &password,
                &archive,
                &recovery_password,
                lifetime.deadline,
            )?);
            lifetime.check()?;
            if let Some(completion) = &completion {
                completion.require_source(&source)?;
            }
            validate_paths(&root, &archive, &runtime)?;
            require_quarantined_informational_endpoint().map_err(|_| Error::Unavailable)?;
            // The explicit pre-entry endpoint is inside an already verified
            // private runtime directory. This route never provisions one.
            let directory = PrivateDirectory::open(&runtime)?;
            lifetime.check()?;
            let ipc = match original_socket {
                Some(path) => LocalIpc::bind_quarantined_v5_at(directory, &source, &path)?,
                None => LocalIpc::bind_quarantined_v5(directory, &source)?,
            };
            lifetime.check()?;
            if let Some(parent) = &lifetime.parent_channel {
                parent.publish_endpoint(ipc.socket_path())?;
            }
            lifetime.check()?;
            Ok(Output::Opened(
                source,
                Arc::new(Mutex::new(ipc)),
                completion.map(Box::new),
            ))
        }) {
            self.clear();
            return Err(error);
        }
        Ok(())
    }
    fn start_job(
        &mut self,
        run: impl FnOnce(&Lifetime) -> Result<Output> + Send + 'static,
    ) -> Result<()> {
        if self.job.is_some() {
            return Err(Error::Locked);
        }
        let lifetime = self.state.as_ref().ok_or(Error::Locked)?.lifetime.clone();
        let (send, receive) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wholepact-quarantined-information".into())
            .spawn(move || {
                let result = (|| {
                    lifetime.check()?;
                    let output = run(&lifetime)?;
                    lifetime.check()?;
                    Ok(output)
                })();
                let _ = send.send(result);
            })?;
        self.job = Some(Job { receive, thread });
        Ok(())
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        if !focused {
            self.blur();
            return;
        }
        if self.state.is_none()
            && self.job.is_none()
            && self
                .handoff
                .as_ref()
                .is_some_and(|handoff| handoff.deadline().is_err())
        {
            self.clear();
        }
        self.closing.retain(|done| !done.load(Ordering::Acquire));
        let valid = self.state.as_ref().map(|state| {
            require_lifecycle(
                focused,
                epoch,
                state.lifetime.epoch,
                state.lifetime.cancelled.load(Ordering::Acquire),
                Instant::now(),
                state.lifetime.deadline,
            )
            .and_then(|()| state.lifetime.check())
            .and_then(|()| match &state.first_peer {
                Some(peer) => peer.check_current(),
                None => Ok(()),
            })
        });
        if valid.is_some_and(|result| result.is_err()) {
            self.clear();
            self.message = "Informational access was revoked. Any already transmitted disclosure or publication result is uncertain and cannot be recalled. Source locks remain held while outstanding work drains.".into();
            return;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.exact.expired())
        {
            self.clear();
            self.message = "The exact native review expired. No new admission is available.".into();
            return;
        }
        if self
            .job
            .as_ref()
            .is_some_and(|job| job.thread.is_finished())
        {
            let outcome = self.job.take().expect("finished job is present").finish();
            if self.accept_output(outcome, epoch).is_err() {
                self.clear();
                self.message = "The bounded informational operation failed or its outcome is uncertain. No financial authority was created; already disclosed data or an admitted publication cannot be recalled.".into();
                return;
            }
        }
        if self.state.is_some()
            && self.pending.is_none()
            && self.job.is_none()
            && self.poll_events(epoch).is_err()
        {
            self.clear();
            self.message = "The exact local peer, source or witness scope no longer matches. Informational admission is closed.".into();
        }
    }
    fn accept_output(&mut self, output: Result<Output>, epoch: u64) -> Result<()> {
        if self
            .state
            .as_ref()
            .is_none_or(|state| state.lifetime.check().is_err())
        {
            // A late listener-bearing output is disposed off the GUI thread;
            // dropping LocalIpc may wait for its bounded listener worker.
            std::thread::spawn(move || drop(output));
            return Err(Error::Locked);
        }
        let state = self.state.as_mut().ok_or(Error::Locked)?;
        match output? {
            Output::Opened(source, ipc, completion) => {
                let held = ipc.try_lock().map_err(|_| Error::Locked)?;
                state.revocation = Some(held.revocation());
                if let Some(handoff) = &mut self.handoff {
                    handoff.socket = Some(held.socket_path().to_path_buf());
                }
                drop(held);
                state.publication_completion = completion.map(|completed| *completed);
                state.source = Some(source);
                state.ipc = Some(ipc);
                self.message = if state.publication_only {
                    "The identical original source is reauthenticated for one publication attempt. Its original deadline was not renewed. Select and separately approve the existing read-only witness again."
                } else {
                    "Original source authenticated as historical information. Select the existing pinned witness configuration for its separate exact read-only review."
                }.into();
            }
            Output::Prepared(prepared) => {
                let exact = ExactNativeReview::stage(
                    &state.lifetime.authority,
                    &prepared.digest,
                    prepared.display,
                    epoch,
                )?;
                self.pending = Some(PendingReview {
                    operation: prepared.operation,
                    exact,
                });
            }
            Output::Witness(witness) => {
                state.witness = Some(witness);
                self.message = "Read-only witness selection approved. Waiting for one fresh, separately reviewed local-process pairing.".into();
            }
            Output::Paired(identity) => {
                state.approved_pair = Some(identity);
                self.message = "Exact local process paired for restricted requests. Every continuity disclosure and informational publication still needs its own native review.".into();
            }
            Output::Served => {
                self.message = "The exact bounded informational operation completed. This creates no signer activation, writer session or financial authority.".into();
            }
        }
        Ok(())
    }
    fn prepare_witness(&mut self) -> Result<()> {
        let state = self.state.as_ref().ok_or(Error::Locked)?;
        if state.witness.is_some() || self.pending.is_some() || self.job.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let source = state.source.clone().ok_or(Error::Locked)?;
        let json = std::mem::take(&mut self.witness_json);
        self.start_job(move |lifetime| {
            let prepared = PreparedInformationalWitnessSetup::prepare(
                &json,
                &source,
                &lifetime.authority,
                lifetime.deadline,
            )?;
            Ok(Output::Prepared(Box::new(PreparedReview::from_operation(
                Operation::Witness(Box::new(prepared)),
            )?)))
        })
    }
    fn poll_events(&mut self, epoch: u64) -> Result<()> {
        let continuity_pending = self.handoff.as_ref().is_some_and(|handoff| {
            handoff.completion.phase.load(Ordering::Acquire) == HANDOFF_PENDING
        });
        let state = self.state.as_mut().ok_or(Error::Locked)?;
        if state.witness.is_none() || state.source.is_none() {
            return Ok(());
        }
        // Bound each GUI pass. Other operation families are dropped, with no
        // fallback to ordinary dispatch, exports, signer journals or sessions.
        for _ in 0..8 {
            let event = state
                .ipc
                .as_ref()
                .ok_or(Error::Locked)?
                .try_lock()
                .map_err(|_| Error::Locked)?
                .next_event();
            let Some(event) = event else {
                break;
            };
            match event {
                LocalEvent::Pairing(pair) => {
                    if state.approved_pair.is_some() || state.first_peer.is_some() {
                        continue;
                    }
                    require_pair_scope(
                        &pair.scope,
                        state.source.as_ref().ok_or(Error::Locked)?.account_id(),
                    )?;
                    let identity = PairIdentity::pending(
                        &pair,
                        state
                            .ipc
                            .as_ref()
                            .ok_or(Error::Locked)?
                            .try_lock()
                            .map_err(|_| Error::Locked)?
                            .generation(),
                    )?;
                    let prepared =
                        PreparedReview::from_operation(Operation::Pair(Box::new(pair), identity))?;
                    let exact = ExactNativeReview::stage(
                        &state.lifetime.authority,
                        &prepared.digest,
                        prepared.display,
                        epoch,
                    )?;
                    self.pending = Some(PendingReview {
                        operation: prepared.operation,
                        exact,
                    });
                    break;
                }
                LocalEvent::HostRecoveryContinuityV5 {
                    peer,
                    stream,
                    request,
                    transfer_dialect,
                } => {
                    if transfer_dialect != V5TransferDialect::BoundedV1 {
                        continue;
                    }
                    if state.publication_only || !continuity_pending {
                        return Err(Error::ReviewMismatch);
                    }
                    state.bind_first_peer(&peer)?;
                    let source = state.source.clone().ok_or(Error::Locked)?;
                    let witness = state.witness.clone().ok_or(Error::Locked)?;
                    self.start_job(move |lifetime| {
                        let prepared = PreparedQuarantinedContinuityV5::prepare(
                            *request,
                            peer,
                            stream,
                            source,
                            lifetime.authority.binding(),
                            witness,
                            lifetime.cancelled.clone(),
                            transfer_dialect,
                            lifetime.parent_channel.clone(),
                        )?;
                        Ok(Output::Prepared(Box::new(PreparedReview::from_operation(
                            Operation::Continuity(Box::new(prepared)),
                        )?)))
                    })?;
                    break;
                }
                LocalEvent::HostRecoveryPublicationV5 {
                    peer,
                    stream,
                    request,
                    transfer_dialect,
                } => {
                    if transfer_dialect != V5TransferDialect::BoundedV1 {
                        continue;
                    }
                    if !state.publication_only {
                        return Err(Error::ReviewMismatch);
                    }
                    let completion = state
                        .publication_completion
                        .take()
                        .ok_or(Error::ReviewMismatch)?;
                    completion.require_source(state.source.as_ref().ok_or(Error::Locked)?)?;
                    completion.require_publication(&request)?;
                    state.bind_first_peer(&peer)?;
                    let source = state.source.clone().ok_or(Error::Locked)?;
                    let witness = state.witness.clone().ok_or(Error::Locked)?;
                    self.start_job(move |lifetime| {
                        let prepared = PreparedQuarantinedPublicationV5::prepare(
                            *request,
                            peer,
                            stream,
                            source,
                            lifetime.authority.binding(),
                            witness,
                            lifetime.cancelled.clone(),
                            transfer_dialect,
                            lifetime.parent_channel.clone(),
                            completion,
                        )?;
                        Ok(Output::Prepared(Box::new(PreparedReview::from_operation(
                            Operation::Publication(Box::new(prepared)),
                        )?)))
                    })?;
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn approve(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let pending = self.pending.take().ok_or(Error::ReviewMismatch)?;
        let decision: NativeDecision =
            pending
                .exact
                .consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        let state = self.state.as_mut().ok_or(Error::Locked)?;
        state.lifetime.check()?;
        match pending.operation {
            Operation::Witness(prepared) => {
                let source = state.source.clone().ok_or(Error::Locked)?;
                self.start_job(move |lifetime| {
                    Ok(Output::Witness(Arc::new(prepared.approve(
                        decision,
                        &lifetime.authority,
                        source,
                    )?)))
                })
            }
            Operation::Pair(pair, identity) => {
                if state.approved_pair.is_some() || state.first_peer.is_some() {
                    return Err(Error::Authentication);
                }
                let source = state.source.clone().ok_or(Error::Locked)?;
                let ipc = state.ipc.clone().ok_or(Error::Locked)?;
                self.start_job(move |lifetime| {
                    source.check_source_unchanged_until(lifetime.deadline)?;
                    pair.check_current()?;
                    let ipc = ipc.lock().map_err(|_| Error::Locked)?;
                    if PairIdentity::pending(&pair, ipc.generation())? != identity {
                        return Err(Error::Authentication);
                    }
                    ipc.approve_pairing(*pair, decision, &lifetime.authority)?;
                    lifetime.check()?;
                    source.check_source_unchanged_until(lifetime.deadline)?;
                    Ok(Output::Paired(identity))
                })
            }
            Operation::Continuity(prepared) => {
                // Fast exact binding checks only. Capture the original 30-second
                // operation deadline at this native click, before scheduling.
                let approved = prepared.approve(decision, &state.lifetime.authority)?;
                let completion = self
                    .handoff
                    .as_ref()
                    .ok_or(Error::Locked)?
                    .completion
                    .clone();
                self.start_job(move |lifetime| {
                    let completed = approved
                        .serve()
                        .map_err(|_| Error::Uncertain)?
                        .ok_or(Error::ReviewMismatch)?;
                    lifetime.check()?;
                    completion.complete(completed)?;
                    Ok(Output::Served)
                })
            }
            Operation::Publication(prepared) => {
                let approved = prepared.approve(decision, &state.lifetime.authority)?;
                self.start_job(move |_| {
                    approved.serve().map_err(|_| Error::Uncertain)?;
                    Ok(Output::Served)
                })
            }
        }
    }
    pub(super) fn ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        self.poll_lifecycle(focused, epoch);
        if self.is_active() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
        ui.label("Quarantined source: bounded historical information only");
        ui.label(&self.message);
        if !self.closing.is_empty() {
            ui.label("Revoked work is draining in the background. Original source locks remain held until it finishes.");
        } else if self.job.is_some() {
            ui.label("The bounded source or witness operation is running. Lock revokes further admission; previously disclosed output cannot be recalled.");
        } else if let Some(pending) = &self.pending {
            let confirming = pending.exact.confirming();
            let digest = pending.exact.digest().to_owned();
            egui::ScrollArea::vertical()
                .max_height(430.0)
                .show(ui, |ui| {
                    ui.label(pending.exact.display());
                });
            ui.label(format!("Exact review digest: {digest}"));
            if confirming {
                ui.label(format!("Type AUTHORIZE {}", &digest[..12]));
                ui.add(egui::TextEdit::singleline(&mut *self.confirmation));
                if ui
                    .add_enabled(
                        focused,
                        egui::Button::new("Approve only this exact informational step"),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                    && self.approve(focused, epoch).is_err()
                {
                    self.clear();
                    self.message = "Exact approval failed or expired. Any already transmitted result is uncertain; no replacement was authorized.".into();
                }
            } else if ui
                .add_enabled(
                    focused,
                    egui::Button::new("Continue after reading this exact step"),
                )
                .clicked_by(egui::PointerButton::Primary)
                && self.pending.as_mut().is_none_or(|pending| {
                    pending
                        .exact
                        .continue_from_native_click(focused, epoch)
                        .is_err()
                })
            {
                self.clear();
            }
            if ui
                .button("Cancel this informational review and lock")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.clear();
            }
        } else if self
            .state
            .as_ref()
            .is_some_and(|state| state.witness.is_none() && state.source.is_some())
        {
            ui.label("Existing pinned witness configuration JSON. Select private credential files; do not paste credential bytes.");
            ui.add(egui::TextEdit::multiline(&mut *self.witness_json).char_limit(16_384));
            if ui
                .add_enabled(
                    focused,
                    egui::Button::new("Review the exact read-only witness selection"),
                )
                .clicked_by(egui::PointerButton::Primary)
                && self.prepare_witness().is_err()
            {
                self.clear();
                self.message =
                    "Read-only witness selection failed. The source remains quarantined.".into();
            }
        }
        if self.state.is_some()
            && ui
                .button("Lock informational source")
                .clicked_by(egui::PointerButton::Primary)
        {
            self.clear();
        }
    }
}
impl Drop for QuarantinedHistoryUi {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Read-only path preflight. The runtime is explicitly selected and disjoint
/// from both immutable source trees; it is never inferred under either tree.
fn validate_paths(root: &Path, archive: &Path, runtime: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for path in [root, archive, runtime] {
        if !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(Error::InvalidData);
        }
    }
    if std::fs::canonicalize(root)? != root || std::fs::canonicalize(archive)? != archive {
        return Err(Error::InvalidData);
    }
    require_disjoint(root, archive, runtime)?;
    let uid = unsafe { libc::geteuid() };
    if runtime.exists() {
        if std::fs::canonicalize(runtime)? != runtime {
            return Err(Error::InvalidData);
        }
        let metadata = std::fs::symlink_metadata(runtime)?;
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(Error::InvalidData);
        }
        for entry in std::fs::read_dir(runtime)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if entry.file_name() != "signer.lock"
                || !metadata.is_file()
                || metadata.uid() != uid
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(Error::InvalidData);
            }
        }
    } else {
        return Err(Error::InvalidData);
    }
    Ok(())
}
fn require_disjoint(root: &Path, archive: &Path, runtime: &Path) -> Result<()> {
    for (first, second) in [(root, archive), (root, runtime), (archive, runtime)] {
        if first.starts_with(second) || second.starts_with(first) {
            return Err(Error::InvalidData);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> PairScope {
        PairScope {
            account_id: "synthetic-account".into(),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "synthetic-participant".into(),
            manifest_digest: "11".repeat(32),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        }
    }
    #[test]
    fn quarantined_ui_lifecycle_requires_same_focus_epoch_and_original_deadline() {
        let now = Instant::now();
        let deadline = now + NATIVE_WINDOW;
        require_lifecycle(true, 4, 4, false, now, deadline).unwrap();
        for mode in 0..5 {
            assert!(
                require_lifecycle(
                    mode != 0,
                    if mode == 1 { 5 } else { 4 },
                    4,
                    mode == 2,
                    if mode == 3 {
                        deadline
                    } else if mode == 4 {
                        deadline + Duration::from_secs(1)
                    } else {
                        now
                    },
                    deadline
                )
                .is_err()
            );
        }
    }
    #[test]
    fn quarantined_ui_pair_scope_never_admits_financial_or_other_account_scope() {
        let original = scope();
        require_pair_scope(&original, "synthetic-account").unwrap();
        for mode in 0..4 {
            let mut changed = original.clone();
            match mode {
                0 => changed.account_id = "other-account".into(),
                1 => changed.history_read = false,
                2 => changed.authorization_export = false,
                3 => changed.preconstruction_export = true,
                _ => unreachable!(),
            }
            assert!(require_pair_scope(&changed, "synthetic-account").is_err());
        }
    }
    #[test]
    fn quarantined_ui_requires_separate_nonoverlapping_runtime_path() {
        require_disjoint(
            Path::new("/private/source"),
            Path::new("/private/archive"),
            Path::new("/private/runtime"),
        )
        .unwrap();
        for runtime in [
            "/private/source",
            "/private/source/runtime",
            "/private/archive",
            "/private/archive/runtime",
            "/private",
        ] {
            assert!(
                require_disjoint(
                    Path::new("/private/source"),
                    Path::new("/private/archive"),
                    Path::new(runtime)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn quarantined_ui_entry_refuses_invalid_paths_and_focus_before_native_creation() {
        // Negative preflight only: no valid native entry, credential read,
        // source decoder, listener or approval is constructed.
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let archive = root.path().join("archive");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&archive).unwrap();
        let nested_runtime = source.join("runtime");
        let mut ui = QuarantinedHistoryUi::default();
        assert!(matches!(
            ui.begin(
                &source,
                b"synthetic",
                &archive,
                b"synthetic",
                &nested_runtime,
                false,
                1,
                None
            ),
            Err(Error::Locked)
        ));
        assert!(matches!(
            ui.begin(
                &source,
                b"synthetic",
                &archive,
                b"synthetic",
                &nested_runtime,
                true,
                1,
                None
            ),
            Err(Error::InvalidData)
        ));
        assert!(matches!(
            ui.begin(
                Path::new("relative-source"),
                b"synthetic",
                &archive,
                b"synthetic",
                &nested_runtime,
                true,
                1,
                None
            ),
            Err(Error::InvalidData)
        ));
        let absent_runtime = root.path().join("absent-runtime");
        assert!(matches!(
            ui.begin(
                &source,
                b"synthetic",
                &archive,
                b"synthetic",
                &absent_runtime,
                true,
                1,
                None
            ),
            Err(Error::InvalidData)
        ));
        assert!(!absent_runtime.exists());
        assert!(!ui.is_active());
        assert_eq!(std::fs::read_dir(&source).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&archive).unwrap().count(), 0);
        assert!(ui.state.is_none() && ui.pending.is_none() && ui.job.is_none());
        assert!(require_quarantined_informational_endpoint().is_ok());
        assert!(crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint().is_err());
    }
    #[test]
    fn quarantined_ui_clear_wipes_data_without_native_entry_or_worker() {
        let mut ui = QuarantinedHistoryUi::default();
        *ui.witness_json = "synthetic-path-selection".into();
        *ui.confirmation = "AUTHORIZE synthetic".into();
        ui.clear();
        assert!(!ui.is_active());
        assert!(ui.witness_json.is_empty() && ui.confirmation.is_empty());
        assert!(ui.pending.is_none() && ui.job.is_none() && ui.state.is_none());
    }
    #[test]
    fn quarantined_ui_handoff_completed_before_blur_is_one_use() {
        // Inert integer exercises scheduling only, never a native completion.
        let mailbox = CompletionMailbox::default();
        mailbox.complete(7_u8).unwrap();
        assert!(mailbox.preserve_completed_on_blur());
        assert_eq!(mailbox.with_completed(|value| Ok(*value)).unwrap(), 7);
        assert_eq!(mailbox.take().unwrap(), 7);
        assert!(mailbox.take().is_err());
        assert!(!mailbox.preserve_completed_on_blur());
        assert!(mailbox.complete(8).is_err());
    }
    #[test]
    fn quarantined_ui_handoff_blur_before_completion_refuses_late_result() {
        let mailbox = CompletionMailbox::default();
        assert!(!mailbox.preserve_completed_on_blur());
        assert!(mailbox.complete(7_u8).is_err());
        assert!(mailbox.take().is_err());
    }
    #[test]
    fn quarantined_ui_handoff_explicit_cancel_always_erases_eligibility() {
        for completed in [false, true] {
            let mailbox = CompletionMailbox::default();
            if completed {
                mailbox.complete(7_u8).unwrap();
            }
            mailbox.cancel();
            assert!(!mailbox.preserve_completed_on_blur());
            assert!(mailbox.take().is_err());
            assert!(mailbox.complete(8).is_err());
        }
    }
    #[test]
    fn quarantined_ui_handoff_source_path_switch_is_rejected() {
        let root = Path::new("/private/source");
        let archive = Path::new("/private/archive");
        require_handoff_paths(root, archive, root, archive).unwrap();
        for (changed_root, changed_archive) in [
            (Path::new("/private/replacement"), archive),
            (root, Path::new("/private/replacement")),
            (archive, root),
        ] {
            assert!(require_handoff_paths(changed_root, changed_archive, root, archive).is_err());
        }
    }
    #[test]
    fn quarantined_ui_handoff_original_deadline_never_renews() {
        let started = Instant::now();
        let original = started + NATIVE_WINDOW;
        assert_eq!(handoff_deadline(original, started).unwrap(), original);
        assert_eq!(
            handoff_deadline(original, started + Duration::from_secs(119)).unwrap(),
            original
        );
        assert!(handoff_deadline(original, original).is_err());
        assert!(handoff_deadline(original, original + Duration::from_secs(1)).is_err());
    }
}
