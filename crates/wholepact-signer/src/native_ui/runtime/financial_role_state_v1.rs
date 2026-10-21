//! Signer-private custody and effects for the exact financial role.
//! Native focus, review staging and decision issuance stay in the concrete
//! adapter. This owner accepts only its existing purpose-bound NativeDecision;
//! retained context, sources, wallets, workers and peers never leave Signer.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Next {
    Continue,
    Acquire,
    Activate,
    Sign,
    Return,
}
pub(super) struct Context {
    pub(super) source: Arc<PreparedOriginalFinancialSourceV1>,
    pub(super) original_peer: Option<crate::native_peer::PeerProcess>,
    pub(super) owner: FinancialWitnessCustodyV1,
    pub(super) writer: Option<FinancialWitnessCustodyV1>,
    pub(super) writer_setup: Zeroizing<String>,
    pub(super) terms: FinancialContinuationTermsV1,
    pub(super) material: Option<Arc<VerifiedDurableEconomicsV1>>,
    pub(super) wallet_setup: Zeroizing<String>,
    pub(super) prepared_wallet: Option<PreparedFinancialWalletV1>,
    pub(super) wallet: Option<FinancialWalletCustodyV1>,
    pub(super) inputs: Option<crate::manifest::ReviewInputs>,
    pub(super) prepared_spend: Option<crate::consent_journal::PreparedFinancialSpendV1>,
    pub(super) active: Option<wholepact_authority::AuthenticatedWriterSession>,
    pub(super) original_history: Option<ReconciledAuthorityHistory>,
    pub(super) history: Option<AuthenticatedFinancialContinuationHistoryV1>,
    pub(super) activation: Option<OwnerControlRequest>,
    pub(super) result_request:
        Option<crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1>,
    pub(super) next: Next,
}
pub(super) enum Outcome {
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
pub(super) struct Job {
    pub(super) stage: Stage,
    pub(super) rx: mpsc::Receiver<(Result<Outcome>, Option<FinancialNativeDiagnosticV1>)>,
    pub(super) worker: std::thread::JoinHandle<()>,
}
pub(in crate::native_ui::runtime) struct FinancialRuntimeV1 {
    pub(super) phase: FinancialPhaseV1,
    pub(super) context: Option<Context>,
    pub(super) review: Option<PreparedFinancialReviewV1>,
    pub(super) pending_continuation: Option<crate::consent_journal::PendingFinancialContinuationAdmissionV1>,
    pub(super) ipc: LocalIpc,
    pub(super) _directory: tempfile::TempDir,
    pub(super) return_target: Option<(
        crate::native_peer::PeerProcess,
        std::os::unix::net::UnixStream,
        crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
    )>,
    pub(super) prepared_return:
        Option<crate::authority_bridge::financial_continuation_v1::PreparedFinancialReturnV1>,
    pub(super) return_stream: Option<std::os::unix::net::UnixStream>,
    pub(super) job: Option<Job>,
    pub(super) revocations: Vec<FinancialNativeRevocationV1>,
    pub(super) failure: Option<Error>,
    pub(super) diagnostic: Option<FinancialNativeDiagnosticV1>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) progress: diagnostics::FinancialNativeProgressObserverV1,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) next_job: Option<u32>,
    pub(super) epoch: u64,
}
impl FinancialRuntimeV1 {
    pub(super) fn spawn(
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
    pub(super) fn revoke(&mut self) {
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

impl FinancialRuntimeV1 {
    pub(super) fn approve_exact(
        &mut self,
        operation: FinancialDecisionV1,
        decision: crate::native_ui::NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let f = self;
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
