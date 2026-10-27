//! Explicit result-only native profile. No signing, writer, wallet or original
//! material owner is reconstructed. Saved selectors remain inert metadata.
use super::*;
use std::{sync::mpsc, time::Instant, os::unix::net::UnixStream};
use crate::account::birth::enrollment::roster_v2::financial_source_v1::RecoveredFinancialResultSourceV2;
use crate::authority_bridge::financial_continuation_v1::{DurableFinancialResultRequestV2, PreparedDurableFinancialReturnV2};
use crate::native_ui::durable_result_authority_v2::{DurableFinancialResultReadV2, DurableFinancialResultReturnV2};
use crate::native_ui::financial_authority_v1::{FinancialPurposeV1, PreparedFinancialReviewV1, FinancialNativeRevocationV1};
use crate::native_peer::PeerProcess;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Decision { Read, Return }
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::native_ui) enum Phase { Opening, AwaitingRequest, ReadReview, Preparing, ReturnReview, Returning, Complete, Aborted }
enum Outcome {
    Opened(Arc<RecoveredFinancialResultSourceV2>),
    Prepared(PreparedDurableFinancialReturnV2, UnixStream),
    Complete,
}
struct Job { rx: mpsc::Receiver<Result<Outcome>>, worker: std::thread::JoinHandle<()> }
pub(super) struct DurableResultRuntimeV2 {
    phase: Phase,
    epoch: u64,
    // Cancels construction AND every retained source check, including worker I/O.
    owner: Arc<crate::native_ui::PendingAccountNativeAuthority>,
    ipc: LocalIpc,
    _directory: tempfile::TempDir,
    source: Option<Arc<RecoveredFinancialResultSourceV2>>,
    target: Option<(PeerProcess, UnixStream, DurableFinancialResultRequestV2)>,
    prepared: Option<(PreparedDurableFinancialReturnV2, UnixStream)>,
    review: Option<PreparedFinancialReviewV1>,
    revocations: Vec<FinancialNativeRevocationV1>,
    job: Option<Job>,
}
impl DurableResultRuntimeV2 {
    fn spawn(&mut self, work: impl FnOnce() -> Result<Outcome> + Send + 'static) -> Result<()> {
        if self.job.is_some() || self.phase == Phase::Aborted { return Err(Error::Unavailable); }
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || { let _ = tx.send(work()); });
        self.job = Some(Job { rx, worker });
        Ok(())
    }
    fn revoke(&mut self) {
        self.owner.revoke_pending_now();
        if let Some(source) = &self.source { source.revoke_v2(); }
        for revocation in &self.revocations { revocation.invalidate(); }
        self.ipc.revoke_all();
        self.review = None;
        self.target = None;
        self.prepared = None;
        self.source = None;
        self.phase = Phase::Aborted;
    }
}
impl Drop for DurableResultRuntimeV2 {
    fn drop(&mut self) {
        self.revoke();
        if let Some(job) = self.job.take() { let _ = job.worker.join(); }
    }
}

impl NativeRuntime {
    pub(in crate::native_ui) fn begin_durable_result_v2(&mut self, focused: bool, epoch: u64) -> Result<()> {
        if !focused || epoch == 0 || self.open.is_some() || self.closed_delivery_v3.is_some()
            || self.financial_v1.is_some() || self.durable_result_v2.is_some() || self.pending.is_some()
            || self.signing_job.is_some() || !self.closing_accounts.is_empty()
            || self.durable_entry_job.is_some() || self.durable_delivery_entry_job.is_some()
            || self.pending_account.is_some() || self.birth.is_active() || self.pending_enrollment.is_active()
            || self.born_origin.is_active() || self.born_manual.is_active()
            || self.born_manual_roster_v2.is_active() || self.born_enrolled_backup.is_active()
        { return Err(Error::Unavailable); }
        self.retirement_evidence_session.before_account_replacement()?;
        let owner = Arc::new(crate::native_ui::PendingAccountNativeAuthority::enter_bounded(
            PendingBirthEntry { focus_epoch: epoch, parent_channel: self.parent_channel.clone() },
            Instant::now() + Duration::from_secs(120),
        )?);
        let root = std::path::PathBuf::from(&self.root);
        let password = Zeroizing::new(self.password.as_bytes().to_vec());
        self.password.zeroize();
        let endpoint = super::durable_entry_v1::create_durable_endpoint_v1(&root).map_err(|(_, e)| e)?;
        let worker_owner = owner.clone();
        let mut state = DurableResultRuntimeV2 {
            phase: Phase::Opening, epoch, owner, ipc: endpoint.ipc, _directory: endpoint.temporary,
            source: None, target: None, prepared: None, review: None, revocations: Vec::new(), job: None,
        };
        state.spawn(move || Ok(Outcome::Opened(Arc::new(RecoveredFinancialResultSourceV2::open_original20(
            &root, &password, worker_owner,
        )?))))?;
        self.durable_result_v2 = Some(state);
        self.message = "Opening only an independently completed exact result. No saved authority is revived.";
        Ok(())
    }
    pub(super) fn revoke_durable_result_v2(&mut self) {
        if let Some(state) = self.durable_result_v2.as_mut() { state.revoke(); }
        self.pending = None;
        self.confirmation.zeroize();
    }
    pub(super) fn close_durable_result_v2(&mut self) {
        let Some(mut state) = self.durable_result_v2.take() else { return; };
        state.revoke();
        self.pending = None;
        self.confirmation.zeroize();
        let done = Arc::new(AtomicBool::new(false));
        let complete = done.clone();
        std::thread::spawn(move || { drop(state); complete.store(true, Ordering::Release); });
        self.closing_accounts.push(done);
    }
    fn stage_durable_result_v2(&mut self, operation: Decision, digest: &str, display: String, epoch: u64) -> Result<()> {
        let state = self.durable_result_v2.as_mut().ok_or(Error::Unavailable)?;
        if state.epoch != epoch || state.job.is_some() || state.phase == Phase::Aborted { return Err(Error::ReviewMismatch); }
        let source = state.source.as_ref().ok_or(Error::Unavailable)?;
        source.check_custody()?;
        let purpose = match operation { Decision::Read => FinancialPurposeV1::ReadOriginal, Decision::Return => FinancialPurposeV1::ReturnExact };
        let review = PreparedFinancialReviewV1::enter(
            PendingBirthEntry { focus_epoch: epoch, parent_channel: self.parent_channel.clone() },
            source.identity_digest(), digest, purpose, source.original_ceiling_ms(), source.original_deadline(),
        )?;
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(review.native(), review.digest(), display, epoch)?,
            operation: Operation::DurableResultV2(operation),
        });
        state.review = Some(review);
        state.phase = match operation { Decision::Read => Phase::ReadReview, Decision::Return => Phase::ReturnReview };
        Ok(())
    }
    pub(super) fn poll_durable_result_v2(&mut self, epoch: u64) {
        let result = self.poll_durable_result_inner_v2(epoch);
        if result.is_err() {
            self.revoke_durable_result_v2();
            self.message = "Durable result action refused or uncertain. Exact saved result remains unchanged; do not re-sign.";
        }
    }
    fn poll_durable_result_inner_v2(&mut self, epoch: u64) -> Result<()> {
        let Some(state) = self.durable_result_v2.as_mut() else { return Ok(()); };
        if state.phase == Phase::Aborted { return Ok(()); }
        if state.epoch != epoch || self.pending.as_ref().is_some_and(|p| p.review.expired()) { return Err(Error::Locked); }
        if let Some(job) = state.job.as_ref() {
            let result = match job.rx.try_recv() {
                Ok(value) => value,
                Err(mpsc::TryRecvError::Empty) => return Ok(()),
                Err(_) => Err(Error::Unavailable),
            };
            if let Some(job) = state.job.take() { let _ = job.worker.join(); }
            match result? {
                Outcome::Opened(source) => {
                    source.check_custody()?;
                    state.source = Some(source);
                    state.phase = Phase::AwaitingRequest;
                    self.message = "Completed exact result opened. A new local recipient must request and receive separate fresh Read and Return decisions.";
                }
                Outcome::Prepared(prepared, stream) => {
                    let digest = prepared.reviewed_digest().to_owned();
                    let display = prepared.display();
                    state.prepared = Some((prepared, stream));
                    self.stage_durable_result_v2(Decision::Return, &digest, display, epoch)?;
                    return Ok(());
                }
                Outcome::Complete => {
                    state.phase = Phase::Complete;
                    self.message = "This owner's exact result transfer acknowledged. This is not two-owner completion, payment submission or a new signature.";
                }
            }
        }
        let state = self.durable_result_v2.as_mut().ok_or(Error::Unavailable)?;
        if state.phase != Phase::AwaitingRequest || self.pending.is_some() { return Ok(()); }
        let Some(event) = state.ipc.next_event() else { return Ok(()); };
        // All legacy and signing events are dropped by this isolated endpoint.
        let LocalEvent::DurableFinancialResultV2 { peer, stream, request } = event else { return Ok(()); };
        let source = state.source.as_ref().ok_or(Error::Unavailable)?;
        source.check_custody()?;
        if source.selection_v2()? != request { return Err(Error::ReviewMismatch); }
        peer.check_alive()?;
        let observed = PeerProcess::observe(&stream)?;
        peer.same_live_process(&observed)?;
        let digest = request.read_review_digest(source.identity_digest(), peer.instance()).map_err(|_| Error::ReviewMismatch)?;
        let display = format!("FRESH LOCAL RECIPIENT READ — DURABLE RESULT V2\nCurrent local process UID {} PID {} instance {}\nThis process is observed, NOT already approved or a verified publisher. Approve only your intended current Host.\nAccount/proposal/exact completed result and historical lineage:\n{}\nRead exact retained result privately and disclose its bounded authorization, continuation/history, result/outbox/signature-set commitments to THIS connected process. No exact signature/outbox bytes leave until a separate Return decision. No new signature, writer or payment.\nRead commitment: {}\nAudited original audience and permission scope:\n{}",
            peer.uid(), peer.pid(), peer.instance(), serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?, digest, source.review_scope_v2()?);
        state.target = Some((peer, stream, request));
        self.stage_durable_result_v2(Decision::Read, &digest, display, epoch)
    }
    pub(super) fn approve_durable_result_v2(&mut self, operation: Decision, decision: crate::native_ui::NativeDecision, epoch: u64) -> Result<()> {
        let state = self.durable_result_v2.as_mut().ok_or(Error::Unavailable)?;
        if state.epoch != epoch || state.job.is_some() { return Err(Error::ReviewMismatch); }
        let review = state.review.take().ok_or(Error::Unavailable)?;
        let source = state.source.as_ref().ok_or(Error::Unavailable)?.clone();
        source.check_custody()?;
        match operation {
            Decision::Read => {
                if state.phase != Phase::ReadReview { return Err(Error::ReviewMismatch); }
                let (peer, mut stream, request) = state.target.take().ok_or(Error::Unavailable)?;
                let read = DurableFinancialResultReadV2::approve(review, decision, &request, source.identity_digest(), &peer)?;
                state.revocations.push(read.revocation());
                state.phase = Phase::Preparing;
                state.spawn(move || {
                    let prepared = PreparedDurableFinancialReturnV2::prepare(source, read, peer, &request, &mut stream).map_err(|_| Error::ReviewMismatch)?;
                    let prepared = prepared.await_host_prepared(&stream).map_err(|_| Error::Uncertain)?;
                    Ok(Outcome::Prepared(prepared, stream))
                })
            }
            Decision::Return => {
                if state.phase != Phase::ReturnReview { return Err(Error::ReviewMismatch); }
                let (prepared, stream) = state.prepared.take().ok_or(Error::Unavailable)?;
                let action = DurableFinancialResultReturnV2::approve(review, decision, prepared.request(), prepared.source_identity(), prepared.peer(), prepared.signature_set_digest())?;
                state.revocations.push(action.revocation());
                state.phase = Phase::Returning;
                state.spawn(move || {
                    prepared.approve(action).map_err(|_| Error::ReviewMismatch)?.serve(stream).map_err(|_| Error::Uncertain)?;
                    Ok(Outcome::Complete)
                })
            }
        }
    }
    pub(in crate::native_ui) fn durable_result_selection_v2(&self) -> Result<String> {
        let state = self.durable_result_v2.as_ref().ok_or(Error::Unavailable)?;
        if state.phase != Phase::AwaitingRequest { return Err(Error::Unavailable); }
        let request = state.source.as_ref().ok_or(Error::Unavailable)?.selection_v2()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "version":2,"signer_socket":state.ipc.socket_path(),"request":request,
        })).map_err(|_| Error::InvalidData)
    }
    pub(super) fn durable_result_ui_v2(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        if !focused { self.revoke_durable_result_v2(); ui.label("Durable result profile locked while unfocused."); return; }
        self.poll_durable_result_v2(epoch);
        ui.label("Durable completed-result V2 — fresh local recipient decisions only");
        if let Ok(selection) = self.durable_result_selection_v2() {
            ui.label("Inert exact selector for the intended current Host; this does not authorize it.");
            ui.label(egui::RichText::new(&selection).monospace());
            if ui.button("Copy exact durable result selector").clicked_by(egui::PointerButton::Primary) { ui.ctx().copy_text(selection); }
        }
        self.exact_review_ui(ui, focused, epoch);
        ui.label(self.message);
        if ui.button("Lock durable result profile").clicked_by(egui::PointerButton::Primary) { self.lock(); }
    }
}

// Qualification may observe finite state/data and deliver the same real native
// click. These accessors cannot mint a decision or expose the source owner.
#[cfg(feature = "synthetic-born-joined-qualification")]
impl NativeRuntime {
    pub(in crate::native_ui) fn durable_result_phase_for_qualification_v2(&self) -> Option<Phase> {
        self.durable_result_v2.as_ref().map(|state| state.phase)
    }
    pub(in crate::native_ui) fn durable_result_custody_for_qualification_v2(&self)
        -> Result<(DurableFinancialResultRequestV2, std::path::PathBuf, Instant)>
    {
        let state = self.durable_result_v2.as_ref().ok_or(Error::Unavailable)?;
        if state.phase == Phase::Aborted { return Err(Error::Locked); }
        let source = state.source.as_ref().ok_or(Error::Unavailable)?;
        let request = source.selection_v2()?;
        Ok((request, state.ipc.socket_path().into(), source.original_deadline()))
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableResultGrantProbeV2 {
    WrongRequestRead, WrongRecipientRead, RevokedRead, RevokedReturn, ExpiredReturn, WrongSignatureSetReturn,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableResultGrantProbeOutcomeV2 {
    DeniedAsIntended, CompoundSourceOrPeerFailure, InsufficientOriginalExpiryBudget,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl NativeRuntime {
    /// Private qualification consumer of the SAME actual prepared review and
    /// actual native click-issued decision. No token/clock constructor or
    /// production controlflow hook is exposed by this method.
    pub(in crate::native_ui) fn probe_durable_result_grant_v2(
        &mut self, probe: DurableResultGrantProbeV2, decision: crate::native_ui::NativeDecision,
        other_stream: Option<UnixStream>, stop: &AtomicBool,
    ) -> Result<DurableResultGrantProbeOutcomeV2> {
        use DurableResultGrantProbeV2 as P;
        use DurableResultGrantProbeOutcomeV2 as O;
        let result = (|| {
            let state = self.durable_result_v2.as_mut().ok_or(Error::Unavailable)?;
            if state.job.is_some() || stop.load(Ordering::Acquire) { return Err(Error::Locked); }
            if other_stream.is_some() != (probe == P::WrongRecipientRead) { return Err(Error::ReviewMismatch); }
            let source = state.source.as_ref().ok_or(Error::Unavailable)?.clone();
            let before = source.selection_v2()?;
            let review = state.review.take().ok_or(Error::Unavailable)?;
            if matches!(probe, P::WrongRequestRead | P::WrongRecipientRead | P::RevokedRead) {
                if state.phase != Phase::ReadReview { return Err(Error::ReviewMismatch); }
                let (peer, mut stream, mut request) = state.target.take().ok_or(Error::Unavailable)?;
                let read = DurableFinancialResultReadV2::approve(review, decision, &request, source.identity_digest(), &peer)?;
                let mut attempted_peer = peer.clone();
                if probe == P::WrongRequestRead {
                    // Valid but different commitment, not malformed-input denial.
                    let replacement = if request.result_digest.starts_with('0') { "1" } else { "0" };
                    request.result_digest.replace_range(..1, replacement);
                    request.validate().map_err(|_| Error::ReviewMismatch)?;
                }
                if let Some(other) = other_stream {
                    let actual = PeerProcess::observe(&other)?;
                    actual.check_alive()?;
                    if actual.pid() == peer.pid() || actual.instance() == peer.instance() {
                        return Err(Error::ReviewMismatch);
                    }
                    attempted_peer = actual;
                    stream = other;
                }
                let observed_peer = attempted_peer.clone();
                if probe == P::RevokedRead { read.revocation().invalidate(); }
                else { read.check_current()?; }
                source.check_custody()?;
                observed_peer.check_alive()?;
                let attempted = PreparedDurableFinancialReturnV2::prepare(source.clone(), read, attempted_peer, &request, &mut stream);
                if !matches!(attempted, Err(crate::authority_bridge::BridgeError::Permission)) { return Err(Error::ReviewMismatch); }
                if source.check_custody().is_err() || observed_peer.check_alive().is_err() { return Ok(O::CompoundSourceOrPeerFailure); }
                if source.selection_v2()? != before { return Err(Error::ReviewMismatch); }
                Ok(O::DeniedAsIntended)
            } else {
                if state.phase != Phase::ReturnReview { return Err(Error::ReviewMismatch); }
                let (prepared, stream) = state.prepared.take().ok_or(Error::Unavailable)?;
                let peer = prepared.peer().clone();
                if probe == P::WrongSignatureSetReturn {
                    source.check_custody()?;
                    peer.check_alive()?;
                    let mut signature_set = prepared.signature_set_digest().to_owned();
                    let replacement = if signature_set.starts_with('0') { "1" } else { "0" };
                    signature_set.replace_range(..1, replacement);
                    // Same actual Return review/decision, only a valid inert
                    // commitment differs. No preview or authority is fabricated.
                    let attempted = DurableFinancialResultReturnV2::approve(
                        review, decision, prepared.request(), prepared.source_identity(), &peer, &signature_set,
                    );
                    if !matches!(attempted, Err(Error::ReviewMismatch)) { return Err(Error::ReviewMismatch); }
                    if source.check_custody().is_err() || peer.check_alive().is_err() { return Ok(O::CompoundSourceOrPeerFailure); }
                    if source.selection_v2()? != before { return Err(Error::ReviewMismatch); }
                    return Ok(O::DeniedAsIntended);
                }
                let action = DurableFinancialResultReturnV2::approve(review, decision, prepared.request(), prepared.source_identity(), &peer, prepared.signature_set_digest())?;
                let actual_grant_deadline = action.original_deadline()?;
                let revoke = action.revocation();
                let approved = prepared.approve(action).map_err(|_| Error::ReviewMismatch)?;
                if probe == P::ExpiredReturn {
                    if actual_grant_deadline >= source.original_deadline() { return Ok(O::InsufficientOriginalExpiryBudget); }
                    // The actual unchanged action bound, not a synthetic clock
                    // or shortened permission. Parent retains original1800 bound.
                    while Instant::now() < actual_grant_deadline {
                        if stop.load(Ordering::Acquire) { return Err(Error::Locked); }
                        std::thread::sleep(Duration::from_millis(5).min(actual_grant_deadline.saturating_duration_since(Instant::now())));
                    }
                } else { revoke.invalidate(); }
                if source.check_custody().is_err() || peer.check_alive().is_err() { return Ok(O::CompoundSourceOrPeerFailure); }
                let attempted = approved.serve(stream);
                if !matches!(attempted, Err(crate::authority_bridge::BridgeError::Permission)) { return Err(Error::ReviewMismatch); }
                if source.check_custody().is_err() || peer.check_alive().is_err() { return Ok(O::CompoundSourceOrPeerFailure); }
                if source.selection_v2()? != before { return Err(Error::ReviewMismatch); }
                Ok(O::DeniedAsIntended)
            }
        })();
        // A denied probe never returns the source to a usable phase. A later
        // probe must explicitly drain and freshly reopen the same original.
        self.revoke_durable_result_v2();
        result
    }
}
