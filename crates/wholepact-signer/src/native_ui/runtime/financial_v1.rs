//! Closed original financial runtime. Every effect receives a different final
//! native decision; immutable retained data is never converted into authority.
use super::*;
#[path = "financial_diagnostics_v1.rs"]
pub(in crate::native_ui) mod diagnostics;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::PreparedOriginalFinancialSourceV1;
use crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1;
use crate::native_ui::financial_authority_v1::{
    FinancialNativeRevocationV1, FinancialPurposeV1, PreparedFinancialReviewV1,
};
use crate::native_ui::wallet_workspace::financial_v1::{
    FinancialWalletCustodyV1, PreparedFinancialWalletV1,
};
use crate::native_ui::witness_workspace::financial_continuation_v1::{
    FinancialWitnessCustodyV1, financial_acquire_digest, financial_activation_digest,
};
use diagnostics::{FinancialNativeDiagnosticV1, FinancialNativeStageV1 as Stage};
use std::{sync::mpsc, time::Instant};
use wholepact_authority::durable_financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, FinancialContinuationTermsV1,
};
use wholepact_authority::{OwnerControl, OwnerControlRequest, ReconciledAuthorityHistory};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::native_ui) enum FinancialPhaseV1 {
    Opening,
    ReadReview,
    ContinueReview,
    AwaitingAdmission,
    AdmitReview,
    AcquireReview,
    ActivateReview,
    WalletReview,
    SignReview,
    ReturnReview,
    AwaitingReturn,
    Working,
    Complete,
    Aborted,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Continue,
    Acquire,
    Activate,
    Sign,
    Return,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FinancialDecisionV1 {
    Read,
    Continue,
    Admit,
    Acquire,
    Activate,
    Wallet,
    Sign,
    Return,
}
struct Context {
    source: Arc<PreparedOriginalFinancialSourceV1>,
    original_peer: Option<crate::native_peer::PeerProcess>,
    owner: FinancialWitnessCustodyV1,
    writer: Option<FinancialWitnessCustodyV1>,
    writer_setup: Zeroizing<String>,
    terms: FinancialContinuationTermsV1,
    material: Option<Arc<VerifiedDurableEconomicsV1>>,
    wallet_setup: Zeroizing<String>,
    prepared_wallet: Option<PreparedFinancialWalletV1>,
    wallet: Option<FinancialWalletCustodyV1>,
    inputs: Option<crate::manifest::ReviewInputs>,
    prepared_spend: Option<crate::consent_journal::PreparedFinancialSpendV1>,
    active: Option<wholepact_authority::AuthenticatedWriterSession>,
    original_history: Option<ReconciledAuthorityHistory>,
    history: Option<AuthenticatedFinancialContinuationHistoryV1>,
    activation: Option<OwnerControlRequest>,
    result_request:
        Option<crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1>,
    next: Next,
}
enum Outcome {
    AwaitingAdmission(
        Context,
        crate::consent_journal::PendingFinancialContinuationAdmissionV1,
    ),
    ReadReady(Context),
    ContinueReady(Context),
    AcquireReady(Context),
    ActivateReady(Context),
    WalletReady(Context),
    SignReady(Context),
    AwaitingReturn(Context),
    ReturnReady(
        Context,
        crate::authority_bridge::financial_continuation_v1::PreparedFinancialReturnV1,
        std::os::unix::net::UnixStream,
    ),
    Complete(Context),
}
struct Job {
    stage: Stage,
    rx: mpsc::Receiver<(Result<Outcome>, Option<FinancialNativeDiagnosticV1>)>,
    worker: std::thread::JoinHandle<()>,
}
pub(super) struct FinancialRuntimeV1 {
    phase: FinancialPhaseV1,
    context: Option<Context>,
    review: Option<PreparedFinancialReviewV1>,
    pending_continuation: Option<crate::consent_journal::PendingFinancialContinuationAdmissionV1>,
    ipc: LocalIpc,
    _directory: tempfile::TempDir,
    return_target: Option<(
        crate::native_peer::PeerProcess,
        std::os::unix::net::UnixStream,
        crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
    )>,
    prepared_return:
        Option<crate::authority_bridge::financial_continuation_v1::PreparedFinancialReturnV1>,
    return_stream: Option<std::os::unix::net::UnixStream>,
    job: Option<Job>,
    revocations: Vec<FinancialNativeRevocationV1>,
    failure: Option<Error>,
    diagnostic: Option<FinancialNativeDiagnosticV1>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    progress: diagnostics::FinancialNativeProgressObserverV1,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    next_job: Option<u32>,
    epoch: u64,
}
impl FinancialRuntimeV1 {
    fn spawn(
        &mut self,
        stage: Stage,
        work: impl FnOnce() -> Result<Outcome> + Send + 'static,
    ) -> Result<()> {
        if self.job.is_some() {
            return Err(Error::Unavailable);
        }
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let progress = {
            let id = self.next_job;
            self.next_job = id.and_then(|id| id.checked_add(1));
            self.progress.start(id, stage)
        };
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let scope = diagnostics::Scope::begin(stage);
            #[cfg(feature = "synthetic-born-joined-qualification")]
            scope.attach_progress(progress);
            let result = work();
            if let Err(error) = &result {
                diagnostics::signer(error);
            }
            let diagnostic = if result.is_err() {
                scope.failure()
            } else {
                None
            };
            let _ = tx.send((result, diagnostic));
        });
        self.diagnostic = None;
        self.job = Some(Job { rx, worker, stage });
        self.phase = FinancialPhaseV1::Working;
        Ok(())
    }
    fn revoke(&mut self) {
        for handle in &self.revocations {
            handle.invalidate();
        }
        self.ipc.revoke_all();
        self.review = None;
        self.pending_continuation = None;
        self.context = None;
        self.return_target = None;
        self.prepared_return = None;
        self.return_stream = None;
        self.phase = FinancialPhaseV1::Aborted;
    }
}
impl Drop for FinancialRuntimeV1 {
    fn drop(&mut self) {
        self.revoke();
        if let Some(job) = self.job.take() {
            let _ = job.worker.join();
        }
    }
}
fn digest<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::InvalidData)
}
fn deadline(c: &Context) -> Instant {
    c.source
        .original_deadline()
        .min(Instant::now() + Duration::from_secs(120))
}

impl NativeRuntime {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn financial_progress_observer_v1(
        &self,
    ) -> Option<diagnostics::FinancialNativeProgressObserverV1> {
        self.financial_v1
            .as_ref()
            .map(|runtime| runtime.progress.clone())
    }

    pub(in crate::native_ui) fn financial_phase_v1(&self) -> Option<FinancialPhaseV1> {
        self.financial_v1.as_ref().map(|f| f.phase)
    }
    pub(in crate::native_ui) fn financial_diagnostic_v1(
        &self,
    ) -> Option<FinancialNativeDiagnosticV1> {
        self.financial_v1.as_ref().and_then(|f| f.diagnostic)
    }
    pub(in crate::native_ui) fn take_financial_failure_v1(&mut self) -> Option<Error> {
        self.financial_v1.as_mut()?.failure.take()
    }
    pub(in crate::native_ui) fn financial_activation_request_v1(
        &self,
    ) -> Option<&OwnerControlRequest> {
        self.financial_v1
            .as_ref()?
            .context
            .as_ref()?
            .activation
            .as_ref()
    }
    pub(in crate::native_ui) fn begin_financial_original_v1(
        &mut self,
        focused: bool,
        epoch: u64,
        terms: FinancialContinuationTermsV1,
    ) -> Result<()> {
        if !focused
            || epoch == 0
            || self.open.is_some()
            || self.financial_v1.is_some()
            || self.pending.is_some()
            || self.signing_job.is_some()
            || !self.closing_accounts.is_empty()
        {
            return Err(Error::Unavailable);
        }
        let (material, peer) = self.detach_financial_material_v1()?;
        self.begin_financial_open_v1(epoch, Some((terms, material, peer)))
    }
    pub(in crate::native_ui) fn begin_financial_result_reopen_v1(
        &mut self,
        focused: bool,
        epoch: u64,
    ) -> Result<()> {
        if !focused
            || epoch == 0
            || self.open.is_some()
            || self.closed_delivery_v3.is_some()
            || self.financial_v1.is_some()
            || self.pending.is_some()
            || self.signing_job.is_some()
            || !self.closing_accounts.is_empty()
        {
            return Err(Error::Unavailable);
        }
        self.begin_financial_open_v1(epoch, None)
    }
    fn begin_financial_open_v1(
        &mut self,
        epoch: u64,
        original: Option<(
            FinancialContinuationTermsV1,
            VerifiedDurableEconomicsV1,
            crate::native_peer::PeerProcess,
        )>,
    ) -> Result<()> {
        if self.durable_entry_job.is_some()
            || self.durable_delivery_entry_job.is_some()
            || self.pending_account.is_some()
            || self.birth.is_active()
            || self.pending_enrollment.is_active()
            || self.born_origin.is_active()
            || self.born_manual.is_active()
            || self.born_manual_roster_v2.is_active()
            || self.born_enrolled_backup.is_active()
        {
            return Err(Error::Unavailable);
        }
        self.retirement_evidence_session
            .before_account_replacement()?;
        let owner = Arc::new(
            crate::native_ui::PendingAccountNativeAuthority::enter_bounded(
                PendingBirthEntry {
                    focus_epoch: epoch,
                    parent_channel: self.parent_channel.clone(),
                },
                Instant::now() + Duration::from_secs(120),
            )?,
        );
        let root = std::path::PathBuf::from(&self.root);
        let password = Zeroizing::new(self.password.as_bytes().to_vec());
        self.password.zeroize();
        let wallet_setup = Zeroizing::new(self.wallet_setup.to_string());
        let owner_setup = Zeroizing::new(self.owner_witness_setup.to_string());
        let writer_setup = Zeroizing::new(self.witness_setup.to_string());
        let endpoint =
            super::durable_entry_v1::create_durable_endpoint_v1(&root).map_err(|(_, e)| e)?;
        let mut runtime = FinancialRuntimeV1 {
            pending_continuation: None,
            ipc: endpoint.ipc,
            _directory: endpoint.temporary,
            return_target: None,
            prepared_return: None,
            return_stream: None,
            phase: FinancialPhaseV1::Opening,
            context: None,
            review: None,
            job: None,
            revocations: Vec::new(),
            failure: None,
            diagnostic: None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            progress: diagnostics::FinancialNativeProgressObserverV1::new(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            next_job: Some(1),
            epoch,
        };
        runtime.spawn(Stage::SourceOpen, move || {
            let (source, terms, material, original_peer, next) = match original {
                Some((terms, material, peer)) => {
                    let source = PreparedOriginalFinancialSourceV1::open_original19(
                        &root, &password, owner, &terms,
                    )?;
                    (
                        source,
                        terms,
                        Some(Arc::new(material)),
                        Some(peer),
                        Next::Continue,
                    )
                }
                None => {
                    let source = PreparedOriginalFinancialSourceV1::open_original20(
                        &root, &password, owner,
                    )?;
                    let request = source.continuation_request()?;
                    let OwnerControl::AdmitFinancialContinuationV1 { record } = request.control
                    else {
                        return Err(Error::ReviewMismatch);
                    };
                    (source, record.terms, None, None, Next::Return)
                }
            };
            let owner = FinancialWitnessCustodyV1::prepare_owner(
                &owner_setup,
                &source,
                &terms.scope.witness,
            )?;
            let writer = None;
            let context = Context {
                source: Arc::new(source),
                original_peer,
                owner,
                writer,
                writer_setup,
                terms,
                material,
                wallet_setup,
                prepared_wallet: None,
                wallet: None,
                inputs: None,
                prepared_spend: None,
                active: None,
                original_history: None,
                history: None,
                activation: None,
                result_request: None,
                next,
            };
            Ok(if next == Next::Return {
                Outcome::AwaitingReturn(context)
            } else {
                Outcome::ReadReady(context)
            })
        })?;
        self.financial_v1 = Some(runtime);
        Ok(())
    }
    pub(super) fn revoke_financial_v1(&mut self) {
        if let Some(f) = self.financial_v1.as_mut() {
            f.revoke();
        }
        self.pending = None;
        self.confirmation.zeroize();
    }
    pub(super) fn close_financial_v1(&mut self) {
        let Some(mut f) = self.financial_v1.take() else {
            return;
        };
        f.revoke();
        self.pending = None;
        self.confirmation.zeroize();
        let done = Arc::new(AtomicBool::new(false));
        let complete = done.clone();
        std::thread::spawn(move || {
            drop(f);
            complete.store(true, Ordering::Release);
        });
        self.closing_accounts.push(done);
    }
    fn stage_financial_v1(
        &mut self,
        c: Context,
        action: FinancialDecisionV1,
        terms_digest: String,
        display: String,
        epoch: u64,
    ) -> Result<()> {
        c.source.check_custody()?;
        let purpose = match action {
            FinancialDecisionV1::Read => FinancialPurposeV1::ReadOriginal,
            FinancialDecisionV1::Continue => FinancialPurposeV1::ContinueExact,
            FinancialDecisionV1::Admit => FinancialPurposeV1::AdmitExact,
            FinancialDecisionV1::Acquire => FinancialPurposeV1::AcquireExact,
            FinancialDecisionV1::Activate => FinancialPurposeV1::ActivateExact,
            FinancialDecisionV1::Wallet => FinancialPurposeV1::WalletExact,
            FinancialDecisionV1::Sign => FinancialPurposeV1::SignExact,
            FinancialDecisionV1::Return => FinancialPurposeV1::ReturnExact,
        };
        let review = PreparedFinancialReviewV1::enter(
            PendingBirthEntry {
                focus_epoch: epoch,
                parent_channel: self.parent_channel.clone(),
            },
            c.source.identity_digest(),
            &terms_digest,
            purpose,
            c.source.original_ceiling_ms(),
            c.source.original_deadline(),
        )?;
        let pending = PendingDecision {
            review: ExactNativeReview::stage(review.native(), review.digest(), display, epoch)?,
            operation: Operation::FinancialV1(action),
        };
        let runtime = self.financial_v1.as_mut().ok_or(Error::Unavailable)?;
        if runtime.epoch != epoch || runtime.job.is_some() {
            return Err(Error::ReviewMismatch);
        }
        runtime.context = Some(c);
        runtime.review = Some(review);
        runtime.phase = match action {
            FinancialDecisionV1::Read => FinancialPhaseV1::ReadReview,
            FinancialDecisionV1::Continue => FinancialPhaseV1::ContinueReview,
            FinancialDecisionV1::Admit => FinancialPhaseV1::AdmitReview,
            FinancialDecisionV1::Acquire => FinancialPhaseV1::AcquireReview,
            FinancialDecisionV1::Activate => FinancialPhaseV1::ActivateReview,
            FinancialDecisionV1::Wallet => FinancialPhaseV1::WalletReview,
            FinancialDecisionV1::Sign => FinancialPhaseV1::SignReview,
            FinancialDecisionV1::Return => FinancialPhaseV1::ReturnReview,
        };
        self.pending = Some(pending);
        Ok(())
    }
    pub(super) fn poll_financial_v1(&mut self, epoch: u64) {
        {
            let scope = diagnostics::Scope::begin(Stage::ResultRequest);
            if let Err(error) = self.poll_financial_request_v1(epoch) {
                diagnostics::signer(&error);
                self.revoke_financial_v1();
                if let Some(f) = self.financial_v1.as_mut() {
                    f.diagnostic = scope.failure();
                    f.failure = Some(error);
                }
                return;
            }
        }
        if self.pending.as_ref().is_some_and(|p| p.review.expired()) {
            self.revoke_financial_v1();
            return;
        }
        let Some(f) = self.financial_v1.as_mut() else {
            return;
        };
        if f.epoch != epoch {
            self.revoke_financial_v1();
            return;
        }
        let Some(job) = f.job.as_ref() else {
            return;
        };
        let (result, diagnostic) = match job.rx.try_recv() {
            Ok(v) => v,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(_) => (
                Err(Error::Unavailable),
                Some(FinancialNativeDiagnosticV1 {
                    authority_call: None,
                    stage: job.stage,
                    component: diagnostics::FinancialNativeComponentV1::Signer,
                    error_class: diagnostics::FinancialNativeErrorClassV1::Unavailable,
                }),
            ),
        };
        f.diagnostic = diagnostic;
        if let Some(job) = f.job.take() {
            let _ = job.worker.join();
        }
        if f.phase == FinancialPhaseV1::Aborted {
            return;
        }
        let scope = diagnostics::Scope::begin(Stage::ReviewStage);
        let staged = (|| match result? {
            Outcome::AwaitingAdmission(c, pending) => {
                let f = self.financial_v1.as_mut().ok_or(Error::Unavailable)?;
                f.context = Some(c);
                f.pending_continuation = Some(pending);
                f.phase = FinancialPhaseV1::AwaitingAdmission;
                self.message = "Exact continuation retained locally; its action has ended. After independent Witness review, a separate fresh AdmitExact decision may send only this saved request before the original expiry.";
                Ok(())
            }
            Outcome::ReadReady(c) => {
                let d = digest(
                    "wholepact:read-original-financial-history:v1",
                    &(c.source.identity_digest(), &c.terms),
                )?;
                let display = format!(
                    "READ ORIGINAL FINANCIAL HISTORY\n\n{}\n\nRead only. No writer, signature or dispatch permission. Every subsequent effect requires a separate fresh native decision. Original expiry is unchanged.",
                    serde_json::to_string_pretty(&c.terms).map_err(|_| Error::InvalidData)?
                );
                self.stage_financial_v1(c, FinancialDecisionV1::Read, d, display, epoch)
            }
            Outcome::ContinueReady(c) => {
                let d = c
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?;
                let display = format!(
                    "APPROVE EXACT FINANCIAL CONTINUATION\n\n{}\n\nApprove this exact payment and bounded future dispatch, not a replacement payment. Final signature still requires a separate SignExact decision. After both signatures a fresh Host decision may send only the saved final transaction before the ORIGINAL expiry, including after a signer restart. It cannot create another signature or change any term.",
                    serde_json::to_string_pretty(&c.terms).map_err(|_| Error::InvalidData)?
                );
                self.stage_financial_v1(c, FinancialDecisionV1::Continue, d, display, epoch)
            }
            Outcome::AcquireReady(c) => {
                let history = c.history.as_ref().ok_or(Error::Unavailable)?;
                let d = financial_acquire_digest(history)?;
                let display = format!(
                    "ACQUIRE EXACT FINANCIAL WRITER\n\n{}\n\nThis permits only the displayed original continuation under the original ceiling. It does not sign or dispatch.",
                    serde_json::to_string_pretty(history.continuation_request())
                        .map_err(|_| Error::InvalidData)?
                );
                self.stage_financial_v1(c, FinancialDecisionV1::Acquire, d, display, epoch)
            }
            Outcome::WalletReady(c) => {
                let prepared = c.prepared_wallet.as_ref().ok_or(Error::Unavailable)?;
                let d = prepared.reviewed_digest().to_owned();
                let display = prepared.display()?;
                self.stage_financial_v1(c, FinancialDecisionV1::Wallet, d, display, epoch)
            }
            Outcome::SignReady(c) => {
                let prepared = c.prepared_spend.as_ref().ok_or(Error::Unavailable)?;
                let d = prepared.reviewed_digest().to_owned();
                let display = prepared.display()?;
                self.stage_financial_v1(c, FinancialDecisionV1::Sign, d, display, epoch)
            }
            Outcome::AwaitingReturn(c) => {
                let f = self.financial_v1.as_mut().ok_or(Error::Unavailable)?;
                f.context = Some(c);
                f.phase = FinancialPhaseV1::AwaitingReturn;
                self.message = "Exact retained signature is ready for a fresh recipient request and native ReturnExact review.";
                Ok(())
            }
            Outcome::ReturnReady(c, prepared, stream) => {
                self.financial_v1
                    .as_mut()
                    .ok_or(Error::Unavailable)?
                    .return_stream = Some(stream);
                let d = prepared.reviewed_digest().to_owned();
                let display = prepared.display();
                self.financial_v1
                    .as_mut()
                    .ok_or(Error::Unavailable)?
                    .prepared_return = Some(prepared);
                self.stage_financial_v1(c, FinancialDecisionV1::Return, d, display, epoch)
            }
            Outcome::Complete(c) => {
                let f = self.financial_v1.as_mut().ok_or(Error::Unavailable)?;
                f.context = Some(c);
                f.phase = FinancialPhaseV1::Complete;
                self.message = "Exact retained financial result delivered. No new signature or payment was created.";
                Ok(())
            }
            Outcome::ActivateReady(c) => {
                let request = c.activation.as_ref().ok_or(Error::Unavailable)?;
                let d = financial_activation_digest(
                    c.history.as_ref().ok_or(Error::Unavailable)?,
                    request,
                )?;
                let display = format!(
                    "ACTIVATE EXACT FINANCIAL WRITER\n\n{}\n\nActivate only this independently acquired session. No replacement epoch, refreshed expiry, signature or dispatch is approved.",
                    serde_json::to_string_pretty(request).map_err(|_| Error::InvalidData)?
                );
                self.stage_financial_v1(c, FinancialDecisionV1::Activate, d, display, epoch)
            }
        })();
        if let Err(error) = staged {
            diagnostics::signer(&error);
            if let Some(f) = self.financial_v1.as_mut() {
                if f.diagnostic.is_none() {
                    f.diagnostic = scope.failure();
                }
            }
            self.revoke_financial_v1();
            if let Some(f) = self.financial_v1.as_mut() {
                f.failure = Some(error);
            }
            self.message = "Financial operation refused. Preserve exact original history and any uncertain exposure; no automatic retry or replacement approval.";
        }
    }
}

impl NativeRuntime {
    pub(super) fn approve_financial_v1(
        &mut self,
        operation: FinancialDecisionV1,
        decision: crate::native_ui::NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let stage = match operation {
            FinancialDecisionV1::Read => Stage::HistoryRead,
            FinancialDecisionV1::Continue => Stage::Continue,
            FinancialDecisionV1::Admit => Stage::Admit,
            FinancialDecisionV1::Acquire => Stage::Acquire,
            FinancialDecisionV1::Activate => Stage::Activate,
            FinancialDecisionV1::Wallet => Stage::WalletObserve,
            FinancialDecisionV1::Sign => Stage::SignPrepare,
            FinancialDecisionV1::Return => Stage::ReturnApprove,
        };
        let scope = diagnostics::Scope::begin(stage);
        let result = self.approve_financial_inner_v1(operation, decision, epoch);
        if let Err(error) = &result {
            diagnostics::signer(error);
            if let Some(f) = self.financial_v1.as_mut() {
                f.diagnostic = scope.failure();
            }
        }
        result
    }
    fn approve_financial_inner_v1(
        &mut self,
        operation: FinancialDecisionV1,
        decision: crate::native_ui::NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let f = self.financial_v1.as_mut().ok_or(Error::Unavailable)?;
        if epoch != f.epoch || f.job.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let review = f.review.take().ok_or(Error::Unavailable)?;
        let mut c = f.context.take().ok_or(Error::Unavailable)?;
        c.source.check_custody()?;
        match operation {
            FinancialDecisionV1::Read => {
                let read = review.approve_read(decision)?;
                f.revocations.push(read.revocation());
                let target = if c.next == Next::Return {
                    Some(f.return_target.take().ok_or(Error::Unavailable)?)
                } else {
                    None
                };
                if let Some((peer, mut stream, request)) = target {
                    f.spawn(Stage::ReturnPrepare,move||{let prepared=crate::authority_bridge::financial_continuation_v1::PreparedFinancialReturnV1::prepare(c.source.clone(),read,peer,&request,&mut stream).map_err(|e|{diagnostics::bridge(&e);Error::ReviewMismatch})?;diagnostics::at(Stage::HostPreparedWait);let prepared=prepared.await_host_prepared(&stream).map_err(|e|{diagnostics::bridge(&e);Error::Uncertain})?;Ok(Outcome::ReturnReady(c,prepared,stream))})
                } else {
                    f.spawn(Stage::HistoryRead, move || {
                        let until = deadline(&c);
                        if c.next == Next::Continue {
                            c.original_history =
                                Some(c.owner.read_history(&c.source, &read, until)?);
                            drop(read);
                            return Ok(Outcome::ContinueReady(c));
                        }
                        let history = c.owner.financial_history(&c.source, &read, until)?;
                        diagnostics::at(Stage::HistoryRead);
                        match c.next {
                            Next::Acquire => {
                                c.history = Some(history);
                                drop(read);
                                Ok(Outcome::AcquireReady(c))
                            }
                            Next::Activate => {
                                let snapshot = history.snapshot();
                                let receipt = snapshot
                                    .pending_writer_session
                                    .as_ref()
                                    .ok_or(Error::ReviewMismatch)?;
                                let operation_id = digest(
                                    "wholepact:financial-native-activation-operation:v1",
                                    &(history.continuation_request(), &receipt.session_id),
                                )?;
                                c.activation = Some(OwnerControlRequest {
                                    operation_id,
                                    account_id: snapshot.account_id.clone(),
                                    network_profile_id: snapshot.network_profile_id.clone(),
                                    expected_head: snapshot.head.clone(),
                                    writer_epoch: snapshot.writer_epoch,
                                    control: OwnerControl::ActivateWriter {
                                        session_id: receipt.session_id.clone(),
                                    },
                                });
                                c.history = Some(history);
                                drop(read);
                                Ok(Outcome::ActivateReady(c))
                            }
                            Next::Sign => {
                                diagnostics::at(Stage::SignPrepare);
                                let writer = c.writer.as_ref().ok_or(Error::Unavailable)?;
                                let active =
                                    writer.verify_active(&c.source, &read, &history, until)?;
                                diagnostics::at(Stage::SignPrepare);
                                let inputs = c.inputs.take().ok_or(Error::Unavailable)?;
                                let material = c.material.as_ref().ok_or(Error::Unavailable)?;
                                c.prepared_spend = Some(c.source.prepare_spend(
                                    &read,
                                    material.verified().clone(),
                                    inputs,
                                    &history,
                                )?);
                                c.active = Some(active);
                                c.history = Some(history);
                                drop(read);
                                Ok(Outcome::SignReady(c))
                            }
                            _ => Err(Error::Unavailable),
                        }
                    })
                }
            }
            FinancialDecisionV1::Continue => {
                let action = review.approve_continuation(decision)?;
                f.revocations.push(action.revocation());
                f.spawn(Stage::Continue, move || {
                    let history = c.original_history.take().ok_or(Error::Unavailable)?;
                    let prepared =
                        c.source
                            .prepare_continuation(c.terms.clone(), action, &history)?;
                    let source = Arc::try_unwrap(c.source).map_err(|_| Error::Unavailable)?;
                    let (source, pending) = source.commit_continuation(prepared)?;
                    c.source = Arc::new(source);
                    c.source.bind_original_financial_recipient_v1(
                        c.original_peer.take().ok_or(Error::Authentication)?,
                    )?;
                    Ok(Outcome::AwaitingAdmission(c, pending))
                })
            }
            FinancialDecisionV1::Admit => {
                let action = review.approve_admit(decision)?;
                f.revocations.push(action.revocation());
                let pending = f.pending_continuation.take().ok_or(Error::Unavailable)?;
                c.source.check_pending(&pending)?;
                f.spawn(Stage::Admit, move || {
                    let until = deadline(&c);
                    c.owner.admit(&c.source, pending, action, until)?;
                    // Admission succeeded; following work is local writer setup.
                    diagnostics::at(Stage::Admit);
                    c.writer = Some(FinancialWitnessCustodyV1::prepare_writer(
                        &c.writer_setup,
                        &c.source,
                        &c.terms.scope.witness,
                    )?);
                    c.writer_setup.zeroize();
                    c.next = Next::Acquire;
                    Ok(Outcome::ReadReady(c))
                })
            }
            FinancialDecisionV1::Acquire => {
                let action = review.approve_acquire(decision)?;
                f.revocations.push(action.revocation());
                f.spawn(Stage::Acquire, move || {
                    let history = c.history.take().ok_or(Error::Unavailable)?;
                    c.writer.as_ref().ok_or(Error::Unavailable)?.acquire(
                        &c.source,
                        &history,
                        action,
                        deadline(&c),
                    )?;
                    c.next = Next::Activate;
                    Ok(Outcome::ReadReady(c))
                })
            }
            FinancialDecisionV1::Activate => {
                let action = review.approve_activation(decision)?;
                f.revocations.push(action.revocation());
                f.spawn(Stage::Activate, move || {
                    let history = c.history.take().ok_or(Error::Unavailable)?;
                    let request = c.activation.take().ok_or(Error::Unavailable)?;
                    c.owner
                        .activate(&c.source, &history, &request, action, deadline(&c))?;
                    diagnostics::at(Stage::WalletPrepare);
                    c.prepared_wallet = Some(PreparedFinancialWalletV1::prepare(
                        c.source.clone(),
                        c.material.as_ref().ok_or(Error::Unavailable)?.clone(),
                        &c.wallet_setup,
                    )?);
                    c.wallet_setup.zeroize();
                    Ok(Outcome::WalletReady(c))
                })
            }
            FinancialDecisionV1::Return => {
                let action = review.approve_return(decision)?;
                f.revocations.push(action.revocation());
                let prepared = f.prepared_return.take().ok_or(Error::Unavailable)?;
                let stream = f.return_stream.take().ok_or(Error::Unavailable)?;
                f.spawn(Stage::ReturnApprove, move || {
                    let approved = prepared.approve(action).map_err(|e| {
                        diagnostics::bridge(&e);
                        Error::ReviewMismatch
                    })?;
                    diagnostics::at(Stage::ReturnServe);
                    approved.serve(stream).map_err(|e| {
                        diagnostics::bridge(&e);
                        Error::Uncertain
                    })?;
                    Ok(Outcome::Complete(c))
                })
            }
            FinancialDecisionV1::Wallet => {
                let action = review.approve_wallet(decision)?;
                f.revocations.push(action.revocation());
                let prepared = c.prepared_wallet.take().ok_or(Error::Unavailable)?;
                f.spawn(Stage::WalletObserve, move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| Error::Unavailable)?;
                    let (wallet, inputs) = runtime.block_on(prepared.observe(action))?;
                    c.wallet = Some(wallet);
                    c.inputs = Some(inputs);
                    c.next = Next::Sign;
                    Ok(Outcome::ReadReady(c))
                })
            }
            FinancialDecisionV1::Sign => {
                let action = review.approve_sign(decision)?;
                f.revocations.push(action.revocation());
                let prepared = c.prepared_spend.take().ok_or(Error::Unavailable)?;
                let approved = prepared.approve(action)?;
                f.spawn(Stage::Sign,move||{let wallet=c.wallet.take().ok_or(Error::Unavailable)?;let history=c.history.take().ok_or(Error::Unavailable)?;let active=c.active.take().ok_or(Error::Unavailable)?;let commit=wallet.sign(c.writer.as_ref().ok_or(Error::Unavailable)?,approved,&history,&active,deadline(&c)).map_err(|e|{diagnostics::bridge(&e);Error::Uncertain})?;c.result_request=Some(crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1{account_id:c.terms.scope.authorization.identity.account_id.clone(),authorization_id:commit.authorization_id,original_consent_ref:commit.original_consent_ref,fixed:c.material.as_ref().ok_or(Error::Unavailable)?.verified().identity().clone()});c.material=None;c.next=Next::Return;Ok(Outcome::AwaitingReturn(c))})
            }
        }
    }
}

impl NativeRuntime {
    pub(in crate::native_ui) fn financial_result_endpoint_v1(&self) -> Result<std::path::PathBuf> {
        let f = self.financial_v1.as_ref().ok_or(Error::Unavailable)?;
        if f.phase == FinancialPhaseV1::Aborted {
            return Err(Error::Locked);
        }
        Ok(f.ipc.socket_path().to_path_buf())
    }
    fn poll_financial_request_v1(&mut self, epoch: u64) -> Result<()> {
        let Some(f) = self.financial_v1.as_mut() else {
            return Ok(());
        };
        if f.epoch != epoch {
            return Err(Error::ReviewMismatch);
        }
        if f.phase != FinancialPhaseV1::AwaitingReturn || f.job.is_some() || self.pending.is_some()
        {
            return Ok(());
        }
        let Some(event) = f.ipc.next_event() else {
            return Ok(());
        };
        // All other endpoint operations are dropped, not routed to a legacy
        // OpenAccount or accepted under an old host pairing grant.
        let LocalEvent::FinancialResultV1 {
            peer,
            stream,
            request,
        } = event
        else {
            return Ok(());
        };
        peer.check_alive()?;
        let c = f.context.take().ok_or(Error::Unavailable)?;
        c.source.check_custody()?;
        if request.account_id != c.terms.scope.authorization.identity.account_id
            || request.authorization_id != c.terms.scope.authorization.authorization_id
        {
            return Err(Error::ReviewMismatch);
        }
        let d = digest(
            "wholepact:read-retained-financial-result:v1",
            &(c.source.identity_digest(), &request, peer.instance()),
        )?;
        let display = format!(
            "READ ALREADY RETAINED FINANCIAL RESULT\n\nAccount: {}\nAuthorization: {}\nRequest: {}\nObserved recipient process: {}\n\nRead only for a subsequent separate ReturnExact review. Never re-sign an uncertain Started operation or change the payment.",
            request.account_id,
            request.authorization_id,
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            peer.instance()
        );
        f.return_target = Some((peer, stream, request));
        self.stage_financial_v1(c, FinancialDecisionV1::Read, d, display, epoch)
    }
}
impl NativeRuntime {
    pub(in crate::native_ui) fn financial_result_request_v1(
        &self,
    ) -> Result<crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1> {
        self.financial_v1
            .as_ref()
            .and_then(|f| f.context.as_ref())
            .and_then(|c| c.result_request.clone())
            .ok_or(Error::Unavailable)
    }
    pub(in crate::native_ui) fn financial_pending_continuation_v1(
        &self,
    ) -> Option<&OwnerControlRequest> {
        Some(
            self.financial_v1
                .as_ref()?
                .pending_continuation
                .as_ref()?
                .request(),
        )
    }
    pub(in crate::native_ui) fn send_financial_continuation_v1(&mut self) -> Result<()> {
        let scope = diagnostics::Scope::begin(Stage::Admit);
        let result = self.prepare_financial_admission_review_v1();
        if let Err(error) = &result {
            diagnostics::signer(error);
            if let Some(f) = self.financial_v1.as_mut() {
                f.diagnostic = scope.failure();
            }
        }
        result
    }
    fn prepare_financial_admission_review_v1(&mut self) -> Result<()> {
        let f = self.financial_v1.as_mut().ok_or(Error::Unavailable)?;
        if f.phase != FinancialPhaseV1::AwaitingAdmission || f.job.is_some() {
            return Err(Error::Unavailable);
        }
        let pending = f.pending_continuation.as_ref().ok_or(Error::Unavailable)?;
        let c = f.context.take().ok_or(Error::Unavailable)?;
        c.source.check_pending(pending)?;
        let digest = pending.admission_terms_digest(c.source.identity_digest())?;
        let display = format!(
            "ADMIT ONLY THE EXACT RETAINED CONTINUATION\n\n{}\n\nThe previous ContinueExact action has ended. This new decision may submit only this already-saved request after independent Witness review. No new request, changed head, refreshed original expiry, signature or dispatch is permitted. A lost response remains uncertain and requires read-only reconciliation, not another admission attempt.",
            serde_json::to_string_pretty(pending.request()).map_err(|_| Error::InvalidData)?
        );
        let epoch = f.epoch;
        self.stage_financial_v1(c, FinancialDecisionV1::Admit, digest, display, epoch)
    }
}
