//! Dedicated, activation-gated native entry. One worker owns both actual vaults,
//! the source eligibility journal, the fresh endpoint/grant registry and the
//! original authenticated reply through pairing, both exact evidence reviews,
//! bounded delivery and drain. No ordinary account/session is transferred.
#![allow(dead_code)] // Installed activation remains deliberately unavailable.

use super::{
    NativeAuthority, NativeDecision, authority::ExactNativeReview,
    retirement_delivery::PreparedRetirementEvidenceV1,
};
use crate::{
    Error, Result,
    account::AccountVault,
    consent_journal::SignerConsentJournal,
    files::PrivateDirectory,
    ipc::{
        PendingPairing,
        retirement_evidence::{
            AuthenticatedRetirementEvidenceRequestV1, RetirementEndpointCancellation,
            RetirementEndpointEvent, RetirementEvidenceCancellation, RetirementEvidenceEndpoint,
            RetirementEvidenceReplyBinding,
        },
    },
    native_launch::ParentChannel,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use wholepact_signer_origin::retirement_evidence::require_native_transport_activation_v1;
use zeroize::{Zeroize, Zeroizing};

const ENTRY_BUDGET: Duration = Duration::from_secs(120);
const DECISION_POLL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReviewPhase {
    Pairing,
    Source,
    Destination,
}
pub(super) struct SessionReview {
    pub(super) phase: ReviewPhase,
    pub(super) exact: ExactNativeReview,
}
struct PhaseDecision {
    phase: ReviewPhase,
    decision: NativeDecision,
}

pub(super) struct RetirementSessionInputs {
    pub(super) source_root: PathBuf,
    pub(super) destination_root: PathBuf,
    pub(super) runtime_directory: PathBuf,
    pub(super) source_password: Zeroizing<Vec<u8>>,
    pub(super) destination_password: Zeroizing<Vec<u8>>,
}

/// Monotone worker progress. Entry/pairing never imply an authenticated reply;
/// Evidence requires the original request restrictions without an optional skip.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SessionStage {
    Entry = 0,
    Pairing = 1,
    Evidence = 2,
}

// No fake socket or authenticated-reply constructor is needed by unit tests.
// The synthetic variant exercises restriction/channel ordering only.
enum Cancellation {
    Request(RetirementEvidenceCancellation),
    #[cfg(test)]
    SyntheticRestrictionOnly,
}
struct RequestRestrictions {
    channel: Cancellation,
    reply: RetirementEvidenceReplyBinding,
}
impl RequestRestrictions {
    fn cancel(&self) {
        match &self.channel {
            Cancellation::Request(channel) => channel.cancel(),
            #[cfg(test)]
            Cancellation::SyntheticRestrictionOnly => self.reply.cancel_for_test(),
        }
    }
}
struct SessionControls {
    cancelled: AtomicBool,
    stage: AtomicU8,
    request: OnceLock<RequestRestrictions>,
    endpoint: OnceLock<RetirementEndpointCancellation>,
    source_account_id: OnceLock<String>,
    source_native: Arc<NativeAuthority>,
    destination_native: Arc<NativeAuthority>,
    parent_channel: Option<ParentChannel>,
    deadline: Instant,
    focus_epoch: u64,
}
impl SessionControls {
    fn cancel(&self) {
        // Close admission and revoke the actual native owners before touching
        // any channel/registry. Every following cancellation is nonblocking.
        self.cancelled.swap(true, Ordering::SeqCst);
        self.source_native.revoke_informational_now();
        self.destination_native.revoke_informational_now();
        if let Some(endpoint) = self.endpoint.get() {
            endpoint.cancel();
        }
        if let Some(request) = self.request.get() {
            request.cancel();
        }
    }
    fn register_endpoint(&self, endpoint: RetirementEndpointCancellation) -> Result<()> {
        if let Err(duplicate) = self.endpoint.set(endpoint) {
            duplicate.cancel();
            self.cancel();
            return Err(Error::Locked);
        }
        // Registration racing cancellation either appears to cancel(), or sees
        // its release flag here and immediately shuts down the original handle.
        if self.finish_registration().is_err() {
            self.cancel();
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn register_request(&self, request: RequestRestrictions) -> Result<()> {
        if let Err(duplicate) = self.request.set(request) {
            duplicate.cancel();
            self.cancel();
            return Err(Error::Locked);
        }
        if self.finish_registration().is_err()
            || self
                .advance_stage(SessionStage::Pairing, SessionStage::Evidence)
                .is_err()
            || self.check_current().is_err()
        {
            self.cancel();
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn finish_registration(&self) -> Result<()> {
        // RMWs, rather than two unrelated loads, order cancellation against
        // single-assignment publication. If this RMW precedes cancel's swap,
        // cancel acquires the published slot; otherwise we see cancellation.
        if self.cancelled.fetch_or(false, Ordering::SeqCst) {
            return Err(Error::Locked);
        }
        self.check_entry_current()
    }
    fn stage(&self) -> Result<SessionStage> {
        match self.stage.load(Ordering::Acquire) {
            0 => Ok(SessionStage::Entry),
            1 => Ok(SessionStage::Pairing),
            2 => Ok(SessionStage::Evidence),
            _ => Err(Error::Locked),
        }
    }
    fn advance_stage(&self, from: SessionStage, to: SessionStage) -> Result<()> {
        if !matches!(
            (from, to),
            (SessionStage::Entry, SessionStage::Pairing)
                | (SessionStage::Pairing, SessionStage::Evidence)
        ) {
            return Err(Error::ReviewMismatch);
        }
        self.stage
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(())
    }
    fn check_entry_current(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        self.source_native.check_current()?;
        self.destination_native.check_current()?;
        if let Some(parent) = &self.parent_channel {
            parent.check_connected()?;
        }
        Ok(())
    }
    fn check_reply_current(&self) -> Result<()> {
        self.request
            .get()
            .ok_or(Error::Authentication)?
            .reply
            .check_current()
    }
    fn check_current(&self) -> Result<()> {
        self.check_entry_current()?;
        match self.stage()? {
            SessionStage::Entry | SessionStage::Pairing => Ok(()),
            SessionStage::Evidence => self.check_reply_current(),
        }
    }
    fn require_phase(&self, phase: ReviewPhase) -> Result<()> {
        self.check_current()?;
        if !matches!(
            (self.stage()?, phase),
            (SessionStage::Pairing, ReviewPhase::Pairing)
                | (
                    SessionStage::Evidence,
                    ReviewPhase::Source | ReviewPhase::Destination
                )
        ) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn native(&self, phase: ReviewPhase) -> &NativeAuthority {
        match phase {
            ReviewPhase::Pairing | ReviewPhase::Source => &self.source_native,
            ReviewPhase::Destination => &self.destination_native,
        }
    }
    fn require_decision(&self, phase: ReviewPhase, decision: &NativeDecision) -> Result<()> {
        self.require_phase(phase)?;
        if decision.binding() != &self.native(phase).binding() {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn completion(&self, result: Result<()>) -> Result<()> {
        result?;
        // Successful delivery closes the reply. Its presence and Evidence stage
        // remain mandatory; terminal close cannot hide cancellation/expiry.
        if self.stage()? != SessionStage::Evidence
            || self
                .request
                .get()
                .is_none_or(|request| Instant::now() >= request.reply.deadline())
            || self.check_entry_current().is_err()
        {
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}

// A panic must close admission even when the GUI has not polled yet. This
// guard carries restriction only and cannot turn unwinding into a successful
// response. Successful delivery keeps the explicit cancellation flag untouched.
struct WorkerFailureGuard<'a> {
    controls: &'a SessionControls,
    succeeded: bool,
}
impl Drop for WorkerFailureGuard<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.controls.cancel();
        }
    }
}

/// The GUI owns this join handle until completion or shutdown. `cancel` is
/// nonblocking; ordinary GUI clearing must retain this owner in its drain list.
/// Drop is only the last-resort cancel/join path, never detach-and-forget.
pub(super) struct RetirementEvidenceSession {
    controls: Arc<SessionControls>,
    reviews: Receiver<SessionReview>,
    decisions: SyncSender<PhaseDecision>,
    next_review: Option<ReviewPhase>,
    pending_review: Option<(ReviewPhase, String)>,
    worker: Option<JoinHandle<Result<()>>>,
}
impl RetirementEvidenceSession {
    pub(super) fn start(
        entry: super::runtime::RetirementNativeEntry,
        mut inputs: RetirementSessionInputs,
    ) -> Result<Self> {
        // No path lookup, KDF, native owner, endpoint or publication before the
        // installed-client activation gate. This source connection is not a
        // claim of attended native/kernel qualification.
        require_native_transport_activation_v1().map_err(|_| Error::Unavailable)?;
        let (focus_epoch, parent_channel, deadline) = entry.into_parts();
        require_entry_ceiling(deadline)?;
        if let Some(parent) = &parent_channel {
            parent.check_connected()?;
        }
        validate_input_paths(&mut inputs)?;
        let source_native =
            NativeAuthority::entered_retirement_window(deadline, parent_channel.clone())?;
        let destination_native =
            NativeAuthority::entered_retirement_window(deadline, parent_channel.clone())?;
        let controls = Arc::new(SessionControls {
            cancelled: AtomicBool::new(false),
            stage: AtomicU8::new(SessionStage::Entry as u8),
            request: OnceLock::new(),
            endpoint: OnceLock::new(),
            source_account_id: OnceLock::new(),
            source_native: Arc::new(source_native),
            destination_native: Arc::new(destination_native),
            parent_channel,
            deadline,
            focus_epoch,
        });
        controls.check_entry_current()?;
        let (review_sender, reviews) = mpsc::sync_channel(1);
        let (decisions, decision_receiver) = mpsc::sync_channel(1);
        let retained = Arc::clone(&controls);
        let worker = match thread::Builder::new()
            .name("retirement-evidence".into())
            .spawn(move || {
                let mut guard = WorkerFailureGuard {
                    controls: &retained,
                    succeeded: false,
                };
                let result =
                    run_connected_worker(inputs, &retained, review_sender, decision_receiver);
                let result = retained.completion(result);
                guard.succeeded = result.is_ok();
                result
            }) {
            Ok(worker) => worker,
            Err(error) => {
                controls.cancel();
                return Err(error.into());
            }
        };
        Ok(Self {
            controls,
            reviews,
            decisions,
            next_review: Some(ReviewPhase::Pairing),
            pending_review: None,
            worker: Some(worker),
        })
    }
    pub(super) fn try_review(&mut self) -> Result<Option<SessionReview>> {
        self.check_current()?;
        if self.pending_review.is_some() {
            return Ok(None);
        }
        match self.reviews.try_recv() {
            Ok(review) => {
                if Some(review.phase) != self.next_review {
                    self.cancel();
                    return Err(Error::ReviewMismatch);
                }
                self.check_current()?;
                self.pending_review = Some((review.phase, review.exact.digest().into()));
                Ok(Some(review))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Error::Locked),
        }
    }
    pub(super) fn submit_decision(
        &mut self,
        phase: ReviewPhase,
        decision: NativeDecision,
    ) -> Result<()> {
        let result = (|| {
            self.check_current()?;
            let (expected, digest) = self.pending_review.as_ref().ok_or(Error::ReviewMismatch)?;
            if phase != *expected || decision.reviewed_digest() != digest {
                return Err(Error::ReviewMismatch);
            }
            self.controls.require_decision(phase, &decision)?;
            self.decisions
                .try_send(PhaseDecision { phase, decision })
                .map_err(|_| Error::ReviewMismatch)?;
            self.pending_review = None;
            self.next_review = match phase {
                ReviewPhase::Pairing => Some(ReviewPhase::Source),
                ReviewPhase::Source => Some(ReviewPhase::Destination),
                ReviewPhase::Destination => None,
            };
            Ok(())
        })();
        if result.is_err() {
            self.cancel();
        }
        result
    }
    pub(super) fn cancel(&self) {
        self.controls.cancel();
    }
    /// Restriction-only GUI check. The worker independently rechecks the actual
    /// retained reply, concrete preparations, vaults and grant on each wait.
    pub(super) fn check_current(&self) -> Result<()> {
        self.controls.check_current()
    }
    /// GUI polling may overlap a successful sender's terminal channel close
    /// before the JoinHandle becomes finished. Only after this session has
    /// submitted both exact decisions can polling tolerate that closed binding.
    /// This is not completion evidence: the owned worker still must be drained.
    /// Worker, review reception and decision submission keep the full checks.
    pub(super) fn check_ui_poll_current(&self) -> Result<()> {
        self.controls.check_entry_current()?;
        match self.controls.stage()? {
            SessionStage::Entry | SessionStage::Pairing => Ok(()),
            SessionStage::Evidence => {
                // Even after the destination click, a missing request cannot be
                // confused with an already-delivered terminal channel.
                let request = self.controls.request.get().ok_or(Error::Authentication)?;
                if Instant::now() >= request.reply.deadline() {
                    return Err(Error::Locked);
                }
                if self.next_review.is_some() || self.pending_review.is_some() {
                    self.controls.check_reply_current()?;
                }
                Ok(())
            }
        }
    }
    pub(super) fn focus_epoch(&self) -> u64 {
        self.controls.focus_epoch
    }
    pub(super) fn source_account_id(&self) -> Option<&str> {
        self.controls.source_account_id.get().map(String::as_str)
    }
    pub(super) fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
    /// Nonblocking drain. A premature call leaves the owned worker intact;
    /// consuming `self` here would accidentally invoke blocking Drop on error.
    pub(super) fn finish(&mut self) -> Result<()> {
        if !self.is_finished() {
            return Err(Error::Locked);
        }
        let worker = self.worker.take().ok_or(Error::Locked)?;
        let result = worker.join().map_err(|_| Error::Uncertain)?;
        self.controls.completion(result)
    }
}
impl Drop for RetirementEvidenceSession {
    fn drop(&mut self) {
        self.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn require_entry_ceiling(deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Locked)?;
    if remaining.is_zero() || remaining > ENTRY_BUDGET {
        return Err(Error::Locked);
    }
    Ok(())
}

fn canonical_existing_directory(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || !std::fs::symlink_metadata(path)?.is_dir() {
        return Err(Error::InvalidData);
    }
    let canonical = path.canonicalize()?;
    if !canonical.is_absolute() || !std::fs::symlink_metadata(&canonical)?.is_dir() {
        return Err(Error::InvalidData);
    }
    Ok(canonical)
}
fn disjoint_trees(left: &Path, right: &Path) -> bool {
    !left.starts_with(right) && !right.starts_with(left)
}
fn validate_input_paths(inputs: &mut RetirementSessionInputs) -> Result<()> {
    let source = canonical_existing_directory(&inputs.source_root)?;
    let destination = canonical_existing_directory(&inputs.destination_root)?;
    let runtime = canonical_existing_directory(&inputs.runtime_directory)?;
    if !disjoint_trees(&source, &destination)
        || !disjoint_trees(&runtime, &source)
        || !disjoint_trees(&runtime, &destination)
    {
        return Err(Error::InvalidData);
    }
    inputs.source_root = source;
    inputs.destination_root = destination;
    inputs.runtime_directory = runtime;
    Ok(())
}

fn require_source_eligibility(vault: &AccountVault, journal: &SignerConsentJournal) -> Result<()> {
    if vault.account().recovery_required() || journal.account_state()?.recovery_required {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
fn unlock_source(
    root: &Path,
    password: &[u8],
    controls: &SessionControls,
) -> Result<(AccountVault, SignerConsentJournal)> {
    controls.check_entry_current()?;
    let vault = AccountVault::unlock(root, password)?;
    retain_source_journal(vault, controls)
}
fn retain_source_journal(
    mut vault: AccountVault,
    controls: &SessionControls,
) -> Result<(AccountVault, SignerConsentJournal)> {
    // The KDF may outlive entry. Check its actual original controls before
    // admitting journal IO, which can quarantine an ineligible source.
    controls.check_entry_current()?;
    // Match ordinary native unlock eligibility, including born-origin and
    // missing-journal refusal, without activation or a new consent session.
    let journal = vault.open_authority_journal()?;
    controls.check_entry_current()?;
    require_source_eligibility(&vault, &journal)?;
    Ok((vault, journal))
}
fn require_destination_eligibility(
    source: &AccountVault,
    destination: &AccountVault,
) -> Result<()> {
    if destination.account().recovery_required() {
        return Err(Error::RecoveryRequired);
    }
    if source.account_id()? == destination.account_id()?
        || source.account().fvk()?.to_bytes() == destination.account().fvk()?.to_bytes()
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

fn pairing_display(pending: &PendingPairing) -> String {
    format!(
        "PAIR LOCAL PROCESS FOR ONE RETIREMENT DESTINATION OBSERVATION\nUnverified application label: {}\nObserved Unix UID: {}\nObserved process PID: {}\nSigner process-instance binding: {}\nActual unlocked source account: {}\nRestricted agreement: {}\nRestricted participant: {}\nExact retirement request commitment: {}\nThis fresh grant permits one exact evidence request only. Separate source identity and destination ownership decisions are still required. No ordinary status/review, history, retained signatures, viewing-key export, wallet access, signing, retirement completion or fund movement is authorized.\nThe original 120-second entry ceiling includes unlock and every review; no phase renews it. Lock, focus loss, parent/process exit and signer exit revoke this session. This does not authenticate a publisher or real-world participant.",
        pending.label,
        pending.uid(),
        pending.pid(),
        pending.instance(),
        pending.scope.account_id,
        pending.scope.agreement_id,
        pending.scope.participant_id,
        pending.scope.manifest_digest,
    )
}

fn run_connected_worker(
    mut inputs: RetirementSessionInputs,
    controls: &SessionControls,
    reviews: SyncSender<SessionReview>,
    decisions: Receiver<PhaseDecision>,
) -> Result<()> {
    controls.check_entry_current()?;
    // Repeat canonical/disjoint validation before any vault work. No directory
    // is created; the separately selected runtime directory must already exist.
    validate_input_paths(&mut inputs)?;
    controls.check_entry_current()?;
    let (source_vault, source_journal) =
        unlock_source(&inputs.source_root, &inputs.source_password, controls)?;
    inputs.source_password.zeroize();
    controls.check_entry_current()?;
    let destination_vault =
        AccountVault::unlock(&inputs.destination_root, &inputs.destination_password)?;
    inputs.destination_password.zeroize();
    controls.check_entry_current()?;
    require_destination_eligibility(&source_vault, &destination_vault)?;
    let source_id = source_vault.account_id()?;
    controls
        .source_account_id
        .set(source_id.clone())
        .map_err(|_| Error::Locked)?;
    let directory = PrivateDirectory::open(&inputs.runtime_directory)?;
    controls.check_entry_current()?;
    let mut endpoint = RetirementEvidenceEndpoint::bind(
        directory,
        &controls.source_native,
        source_id,
        controls.deadline,
    )?;
    controls.register_endpoint(endpoint.cancellation_handle())?;
    controls.advance_stage(SessionStage::Entry, SessionStage::Pairing)?;
    controls.check_current()?;
    if let Some(parent) = &controls.parent_channel {
        parent.publish_endpoint(endpoint.socket_path())?;
    }
    controls.check_current()?;
    let reply = loop {
        controls.check_current()?;
        endpoint.check_current()?;
        match endpoint.next_event()? {
            Some(RetirementEndpointEvent::Pairing(pending)) => {
                let digest = pending.review_digest(endpoint.generation())?;
                endpoint.check_pairing_current(&pending)?;
                publish_review(
                    ReviewPhase::Pairing,
                    controls,
                    &reviews,
                    &digest,
                    pairing_display(&pending),
                )?;
                let decision = loop {
                    endpoint.check_pairing_current(&pending)?;
                    let decision = wait_step(
                        ReviewPhase::Pairing,
                        controls,
                        &decisions,
                        controls.deadline,
                    )?;
                    // A live process may abandon/half-close this exact pairing
                    // socket while the UI waits. Check even on timeout steps.
                    endpoint.check_pairing_current(&pending)?;
                    if let Some(decision) = decision {
                        break decision;
                    }
                };
                endpoint.approve_pairing(pending, decision, &controls.source_native)?;
                controls.check_current()?;
            }
            Some(RetirementEndpointEvent::Evidence(reply)) => {
                reply.check_current()?;
                controls.register_request(RequestRestrictions {
                    channel: Cancellation::Request(reply.cancellation_handle()?),
                    reply: reply.binding()?,
                })?;
                break *reply;
            }
            None => thread::sleep(DECISION_POLL),
        }
    };
    require_source_eligibility(&source_vault, &source_journal)?;
    require_destination_eligibility(&source_vault, &destination_vault)?;
    // Call the original borrowed-preparation path on this SAME worker stack.
    // The fresh endpoint/Grant map and source journal remain owned until the
    // original reply has completed or failed. No vault/reply bundle is returned.
    let result = run_worker(
        reply,
        source_vault,
        destination_vault,
        controls,
        reviews,
        decisions,
    );
    drop(endpoint);
    drop(source_journal);
    result
}

fn run_worker(
    reply: AuthenticatedRetirementEvidenceRequestV1,
    source_vault: AccountVault,
    destination_vault: AccountVault,
    controls: &SessionControls,
    reviews: SyncSender<SessionReview>,
    decisions: Receiver<PhaseDecision>,
) -> Result<()> {
    controls.check_current()?;
    // AccountVault is never cloned or placed in a self-referential GUI object.
    // These borrows remain valid until the exact delivery owner is consumed.
    let prepared = PreparedRetirementEvidenceV1::prepare(
        reply,
        &source_vault,
        &destination_vault,
        &controls.source_native,
        &controls.destination_native,
    )?;
    prepared.check_current()?;
    publish_review(
        ReviewPhase::Source,
        controls,
        &reviews,
        prepared.digest(),
        prepared.display()?,
    )?;
    let decision = loop {
        prepared.check_current()?;
        if let Some(decision) = wait_step(
            ReviewPhase::Source,
            controls,
            &decisions,
            prepared.deadline(),
        )? {
            prepared.check_current()?;
            break decision;
        }
    };
    let prepared = prepared.approve_source(
        &controls.source_native,
        decision,
        &controls.destination_native,
    )?;
    prepared.check_current()?;
    publish_review(
        ReviewPhase::Destination,
        controls,
        &reviews,
        prepared.digest(),
        prepared.display()?,
    )?;
    let decision = loop {
        prepared.check_current()?;
        if let Some(decision) = wait_step(
            ReviewPhase::Destination,
            controls,
            &decisions,
            prepared.deadline(),
        )? {
            prepared.check_current()?;
            break decision;
        }
    };
    // This consumes the original nonce-bearing destination preparation, never
    // a reconstructed object with a display-equivalent request.
    let approved = prepared.approve_destination(&controls.destination_native, decision)?;
    controls.check_current()?;
    approved.check_current()?;
    approved.deliver()
}

fn publish_review(
    phase: ReviewPhase,
    controls: &SessionControls,
    reviews: &SyncSender<SessionReview>,
    digest: &str,
    display: String,
) -> Result<()> {
    controls.require_phase(phase)?;
    let exact = ExactNativeReview::stage(
        controls.native(phase),
        digest,
        display,
        controls.focus_epoch,
    )?;
    controls.check_current()?;
    reviews
        .try_send(SessionReview { phase, exact })
        .map_err(|_| Error::Locked)?;
    controls.check_current()
}

/// One bounded restriction/channel step, not an approval or delivery adapter.
/// Production callers recheck their concrete retained preparation around every
/// step; this helper accepts no callback, replacement reply, or authority DTO.
fn wait_step(
    phase: ReviewPhase,
    controls: &SessionControls,
    decisions: &Receiver<PhaseDecision>,
    preparation_deadline: Instant,
) -> Result<Option<NativeDecision>> {
    controls.require_phase(phase)?;
    let deadline = controls.deadline.min(preparation_deadline);
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::ReviewMismatch)?;
    let received = decisions.recv_timeout(remaining.min(DECISION_POLL));
    controls.check_current()?;
    if Instant::now() >= deadline {
        return Err(Error::ReviewMismatch);
    }
    match received {
        Ok(received) => {
            if received.phase != phase {
                return Err(Error::ReviewMismatch);
            }
            controls.require_decision(phase, &received.decision)?;
            Ok(Some(received.decision))
        }
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Err(Error::Locked),
    }
}

#[cfg(test)]
mod tests;
