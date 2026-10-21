//! Signer-private state for closed V3 receive, admission and history.
//! The concrete adapter still owns native focus and review presentation. Actual
//! sources, grants, peers and workers remain here; retained DTOs are only data.
//! Declaration order and the existing revoke/join paths are unchanged.
use super::*;

pub(super) struct SetupV3 {
    pub(super) source: PreparedOriginalDeliverySourceV3,
    pub(super) witness: PreparedDeliveryWitnessV3,
    pub(super) original: Option<crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1>,
    pub(super) enrollment: AccountEnrollmentRecord,
    pub(super) manifest: AcceptedManifestRecord,
    pub(super) intent: RecipientIntentV3,
    pub(super) peer: Option<PeerProcess>,
    pub(super) material_deadline: Instant,
}
pub(super) struct ActiveV3 {
    pub(super) history_only: bool,
    pub(super) source: ActivePreparedDeliverySourceV3,
    pub(super) witness: DeliveryWitnessV3,
    pub(super) original: Option<crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1>,
    pub(super) enrollment: AccountEnrollmentRecord,
    pub(super) manifest: AcceptedManifestRecord,
    pub(super) intent: RecipientIntentV3,
    pub(super) peer: Option<PeerProcess>,
}
impl ActiveV3 {
    pub(super) fn check(&self) -> Result<()> {
        self.source.check_current()?;
        if !self.history_only { self.source.read().check_recipient(&self.intent)?; }
        if let Some(peer)=&self.peer {
            peer.check_alive()?;
            if peer.instance() != self.intent.authorized_host_process_instance {return Err(Error::Authentication);}
        } else if !self.history_only {return Err(Error::Authentication);}
        let time = unix_ms()?;
        for scope in &self.intent.material_scopes {
            if time < scope.valid_from_unix_seconds.saturating_mul(1000) || time >= scope.valid_until_unix_seconds.saturating_mul(1000) {return Err(Error::Locked);}
        }
        self.witness.require_original(self.source.witness()?, &self.source.record()?.account_record.terms.signer.owner_certificate_digest)
    }
    pub(super) fn check_admission_progress(&self)->Result<()> {
        self.source.check_data_current()?;
        self.source.read().check_recipient(&self.intent)?;
        self.peer.as_ref().ok_or(Error::Authentication)?.check_alive()?;
        let now=unix_ms()?;
        if self.intent.material_scopes.iter().any(|scope|now<scope.valid_from_unix_seconds.saturating_mul(1000)||now>=scope.valid_until_unix_seconds.saturating_mul(1000)){return Err(Error::Locked);}
        self.witness.check_current()
    }
    pub(super) fn deadline(&self) -> Result<Instant> {self.check()?; self.source.read().deadline()}
}
pub(crate) struct VerifiedImportV3 { pub(super) active: Arc<ActiveV3>, pub(super) fixed: VerifiedDurableEconomicsV1, pub(super) receipt: VerifiedDurableReviewReceiptV3 }
pub(super) struct PreparedAdmissionV3 {
    pub(super) imported: Arc<VerifiedImportV3>,
    pub(super) request: OwnerControlRequest,
    pub(super) prepared: crate::consent_journal::PreparedDurableDeliveryAdmissionIntentV3,
}
pub(super) struct AwaitingAuditV3 {
    pub(super) retained: crate::consent_journal::RetainedDurableDeliveryAdmissionIntentV3,
    pub(super) controlled: Option<wholepact_authority::AccountSnapshot>,
    pub(super) lower_error: Option<wholepact_authority::AuthorityError>,
}
pub(super) enum OutcomeV3 { ReceiveFailed(authority_bridge::BridgeError,Option<Error>), AdmissionFailed(wholepact_authority::AuthorityError), Setup(SetupV3), HistorySetup(SetupV3), Received(Zeroizing<Vec<u8>>), Verified(VerifiedImportV3), Prepared(PreparedAdmissionV3), Awaiting(AwaitingAuditV3), Audited(DurableDeliveryAdmissionStatusV3,wholepact_authority::AuthorityHead) }
pub(super) struct JobV3 { pub(super) receive: mpsc::Receiver<Result<OutcomeV3>>, pub(super) worker: std::thread::JoinHandle<()> }
pub(in crate::native_ui::runtime) struct DurableDeliveryRuntimeV3 {
    pub(super) phase: DurableDeliveryPhaseV3,
    pub(super) ipc: LocalIpc,
    pub(super) _directory: Option<tempfile::TempDir>,
    pub(super) preparation: PrepareClosedRecipientRequestV3,
    pub(super) peer: Option<PeerProcess>,
    pub(super) setup: Option<SetupV3>,
    pub(super) read_review: Option<PreparedDeliveryReadReviewV3>,
    pub(super) active: Option<Arc<ActiveV3>>,
    pub(super) imported: Option<Arc<VerifiedImportV3>>,
    pub(super) financial_material: Option<VerifiedDurableEconomicsV1>,
    pub(super) financial_admitted_head: Option<wholepact_authority::AuthorityHead>,
    pub(super) prepared: Option<PreparedAdmissionV3>,
    pub(super) awaiting: Option<AwaitingAuditV3>,
    pub(super) job: Option<JobV3>,
    pub(super) status: Option<DurableDeliveryAdmissionStatusV3>,
    pub(super) failure: Option<Error>,
    pub(super) epoch: u64,
    pub(super) history_requested: bool,
    pub(super) history_selector: Option<DurableDeliveryHistoryRequestV3>,
    pub(super) admitting: Arc<AtomicBool>,
    pub(super) lower_receive_error: Option<authority_bridge::BridgeError>,
    pub(super) lower_admission_error: Option<wholepact_authority::AuthorityError>,
    pub(super) retired_origin: Option<crate::native_ui::NativeAuthorityBinding>,
    pub(super) retired_peer: Option<AuthenticatedPeer>,
    pub(super) history_recipient: Option<(PeerProcess,String)>,
    pub(super) exact_pending_operation: Option<OwnerControlRequest>,
}
impl DurableDeliveryRuntimeV3 {
    pub(super) fn abort(&mut self, error:Error) {
        if let Some(active)=&self.active {active.source.read().invalidate();}
        self.read_review=None; self.setup=None; self.imported=None; self.financial_material=None; self.prepared=None; self.history_recipient=None;
        self.phase=if self.phase==DurableDeliveryPhaseV3::Complete {DurableDeliveryPhaseV3::Complete}else if self.awaiting.is_some() {DurableDeliveryPhaseV3::AwaitingAudit}else{DurableDeliveryPhaseV3::Aborted};
        self.failure=Some(error);
    }
    pub(super) fn spawn(&mut self, work:impl FnOnce()->Result<OutcomeV3>+Send+'static) -> Result<()> {
        if self.job.is_some() {return Err(Error::Unavailable);}
        let (send,receive)=mpsc::channel();
        #[cfg(feature="synthetic-born-joined-qualification")]
        let stage=match self.phase {
            DurableDeliveryPhaseV3::HistoryReview => crate::native_ui::runtime::delivery_diagnostics_v2::Stage::DeliveryHistoricalRead,
            DurableDeliveryPhaseV3::ImportedVerified|DurableDeliveryPhaseV3::AdmissionReview|DurableDeliveryPhaseV3::AwaitingWitnessReady|DurableDeliveryPhaseV3::Admitting => crate::native_ui::runtime::delivery_diagnostics_v2::Stage::DeliveryNativeAdmission,
            _ if self.history_selector.is_some()=>crate::native_ui::runtime::delivery_diagnostics_v2::Stage::DeliveryHistoricalRead,
            _=>crate::native_ui::runtime::delivery_diagnostics_v2::Stage::DeliveryArtifactImport,
        };
        let worker=std::thread::spawn(move || {
            let result=work();
            #[cfg(feature="synthetic-born-joined-qualification")]
            let result=crate::native_ui::runtime::delivery_diagnostics_v2::signer_result(stage,result);
            let _=send.send(result);
        });
        self.job=Some(JobV3 {receive,worker}); Ok(())
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.phase==DurableDeliveryPhaseV3::Aborted {return Err(Error::Locked);}
        if let Some(setup)=&self.setup {setup.source.check_custody()?; if let Some(peer)=&setup.peer {peer.check_alive()?;}}
        if let Some(active)=&self.active {
            if matches!(self.phase,DurableDeliveryPhaseV3::AwaitingAudit|DurableDeliveryPhaseV3::Complete) { active.source.check_retained_custody()?; } else if matches!(self.phase,DurableDeliveryPhaseV3::AwaitingWitnessReady|DurableDeliveryPhaseV3::Admitting) { active.check_admission_progress()?; } else { active.check()?; }
        }
        Ok(())
    }
}
impl Drop for DurableDeliveryRuntimeV3 {
    fn drop(&mut self) {
        if let Some(active)=&self.active {active.source.read().invalidate();}
        self.ipc.revoke_all();
        if let Some(job)=self.job.take() {let _=job.worker.join();}
    }
}

impl DurableDeliveryRuntimeV3 {
    pub(super) fn approve_receive(&mut self, decision:crate::native_ui::NativeDecision)->Result<()> {
        let closed=self;
        if closed.phase!=DurableDeliveryPhaseV3::ReceiveReview {return Err(Error::ReviewMismatch);}
        let setup=closed.setup.take().ok_or(Error::Unavailable)?;
        setup.source.check_custody()?; if let Some(peer)=&setup.peer {peer.check_alive()?;}
        let read=Arc::new(closed.read_review.take().ok_or(Error::Unavailable)?.approve(decision)?);
        let mut intent=setup.intent;
        intent.read_session_digest=read.binding().entry_digest().into();
        intent.receive_decision_digest=read.receive_decision_digest().into();
        read.check_recipient(&intent)?;
        let identity=setup.source.identity().to_owned();
        let source=setup.source.activate(read.clone())?;
        let witness=setup.witness.activate(read,&identity)?;
        let active=Arc::new(ActiveV3 {history_only:false,source,witness,original:setup.original,enrollment:setup.enrollment,manifest:setup.manifest,intent,peer:setup.peer});
        active.check()?; closed.active=Some(active); closed.phase=DurableDeliveryPhaseV3::Ready;
        Ok(())
    }
    pub(super) fn approve_admit(&mut self, decision:crate::native_ui::NativeDecision)->Result<()> {
        let closed=self;
        if closed.phase!=DurableDeliveryPhaseV3::AdmissionReview {return Err(Error::ReviewMismatch);}
        let prepared=closed.prepared.take().ok_or(Error::Unavailable)?;
        let active=prepared.imported.active.clone(); active.check()?;
        let conditional=active.source.read().approve_conditional_admission(decision,prepared.prepared.digest(),prepared.request.clone())?;
        closed.exact_pending_operation=Some(prepared.request.clone());
        closed.phase=DurableDeliveryPhaseV3::AwaitingWitnessReady;
        let admitting=closed.admitting.clone();
        closed.spawn(move || {
            use wholepact_authority::transport::durable_delivery_admission_v3::PrepareDurableAdmissionErrorV3;
            let deadline=active.deadline()?;
            let ready=loop {
                active.check()?; conditional.check_current()?;
                match active.witness.prepare_admission(&prepared.request,deadline,||{active.check()?;conditional.check_current()}) {
                    Ok(ready)=>break ready,
                    Err(PrepareDurableAdmissionErrorV3::NotListening)=> {
                        if Instant::now()+Duration::from_millis(100)>=deadline {return Err(Error::Locked);}
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(PrepareDurableAdmissionErrorV3::Aborted(error))=>return Ok(OutcomeV3::AdmissionFailed(observe_authority_failure(error))),
                }
            };
            admitting.store(true,Ordering::Release);
            let action=conditional.activate(&ready)?;
            active.check()?;
            let journal=active.source.journal()?.clone();
            let (retained,pin,action)=journal.retain_durable_delivery_admission_intent_v3(prepared.prepared,&active.source,action)?;
            active.source.install_committed_revision(pin)?;
            // A discarded Interrupted I/O postcheck may have failed.
            // A selected Source cause terminates on its own callback,
            // so retain that latest owned error, not an earlier anomaly.
            #[cfg(feature="synthetic-born-joined-qualification")]
            let mut latest_source_error = None;
            let mut current = || {
                active.check().and_then(|_| action.check_current()).map_err(|_error| {
                    #[cfg(feature="synthetic-born-joined-qualification")]
                    { latest_source_error = Some(_error); }
                    wholepact_authority::AuthorityError::Permission
                })
            };
            #[cfg(feature="synthetic-born-joined-qualification")]
            let (outcome, observation) = ready.send_retained_exact_observed(
                retained.request(), action.deadline(), &mut current,
            );
            #[cfg(not(feature="synthetic-born-joined-qualification"))]
            let outcome = ready.send_retained_exact(
                retained.request(), action.deadline(), &mut current,
            );
            #[cfg(feature="synthetic-born-joined-qualification")]
            if let (Err(_), Some(observation)) = (&outcome, observation.as_ref()) {
                crate::native_ui::runtime::delivery_diagnostics_v2::admission_failure_v3(
                    observation, latest_source_error.as_ref(),
                );
            }
            let (controlled,lower_error)=match outcome {Ok(snapshot)=>(Some(snapshot),None),Err(error)=>(None,Some(observe_authority_failure(error)))};
            // The local intent is final even for a lost response. Drop
            // action and same-stream transport before any later review.
            drop(action);
            Ok(OutcomeV3::Awaiting(AwaitingAuditV3 {retained,controlled,lower_error}))
        })?;
        Ok(())
    }
    pub(super) fn approve_history_recipient(&mut self, decision:crate::native_ui::NativeDecision)->Result<()> {
        let closed=self;
        let active=closed.active.as_ref().ok_or(Error::Unavailable)?;
        active.check()?;
        let (peer,digest)=closed.history_recipient.take().ok_or(Error::Unavailable)?;
        peer.check_alive()?;
        if !active.history_only || closed.peer.is_some() || decision.binding()!=&active.source.read().binding() || decision.reviewed_digest()!=digest {return Err(Error::ReviewMismatch);}
        closed.peer=Some(peer);
        Ok(())
    }
    pub(super) fn approve_history(&mut self,decision:crate::native_ui::NativeDecision,epoch:u64)->Result<()> {
        let closed=self;
        if closed.phase!=DurableDeliveryPhaseV3::HistoryReview || epoch!=closed.epoch {return Err(Error::ReviewMismatch);}
        let setup=closed.setup.take().ok_or(Error::Unavailable)?;
        setup.source.check_custody()?;
        let read=Arc::new(closed.read_review.take().ok_or(Error::Unavailable)?.approve(decision)?.restrict_history_only());
        let identity=setup.source.identity().to_owned();
        let source=setup.source.activate(read.clone())?;
        let witness=setup.witness.activate(read,&identity)?;
        let active=Arc::new(ActiveV3 {history_only:true,source,witness,original:setup.original,enrollment:setup.enrollment,manifest:setup.manifest,intent:setup.intent,peer:setup.peer});
        active.check()?;
        // Retained historical data stays in the controller even if this
        // read-only network audit fails. No action owner is cloned or revived.
        let awaiting=closed.awaiting.as_ref().map(|a|(a.retained.clone(),a.controlled.clone()));
        let expected_intent=active.intent.clone();
        let selector=if let Some(selector)=&closed.history_selector {selector.clone()} else {
            let retained=&awaiting.as_ref().ok_or(Error::Unavailable)?.0;
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record}=&retained.request().control else {return Err(Error::ReviewMismatch);};
            DurableDeliveryHistoryRequestV3 {intent_digest:retained.recipient_intent_digest()?,authorization_id:record.scope.authorization.authorization_id.clone()}
        };
        closed.active=Some(active.clone());
        closed.spawn(move|| {
            let original=active.source.journal()?.durable_delivery_admission_intent_v3(&selector.authorization_id,&active.source)?.ok_or(Error::RecoveryRequired)?;
            if original.recipient_intent()!=&expected_intent || original.recipient_intent_digest()?!=selector.intent_digest || awaiting.as_ref().is_some_and(|a|original!=a.0) {return Err(Error::ReviewMismatch);}
            let history=active.witness.history(HistoryReadPurposeV3::ReadOriginalHistory,active.deadline()?,||active.check())?;
            let remote=history.durable_delivery_admission_v2(&original.request().operation_id).map_err(|_|Error::RecoveryRequired)?;
            if remote!=Some(original.request()) || history.disclosure()!=original.disclosure() || history.account_policy().owner_certificate_digest!=original.owner_certificate_digest() {return Err(Error::Uncertain);}
            if awaiting.as_ref().and_then(|a|a.1.as_ref()).is_some_and(|controlled|controlled!=history.snapshot()) {return Err(Error::Uncertain);}
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record}=&original.request().control else{return Err(Error::ReviewMismatch);};
            let audit=authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2 {version:2,request:original.request().clone(),scope:record.scope.clone(),original_enrollment_ref:original.enrollment_ref().into(),original_accepted_manifest_ref:original.manifest_ref().into(),original_local_intent_digest:original.history_digest()?,authenticated_witness_history_digest:history.history_digest().map_err(|_|Error::ReviewMismatch)?,witness_committed:true,current_fixed_material_source:"unchecked".into()};
            let completed=DurableDeliveryAdmissionStatusV3 {version:3,intent_digest:selector.intent_digest,request:original.request().clone(),original_local_intent_digest:original.history_digest()?,state:DurableDeliveryAdmissionStateV3::Verified,audit:Some(audit)};
            completed.validate().map_err(|_|Error::ReviewMismatch)?;
            active.check()?;
            Ok(OutcomeV3::Audited(completed,history.snapshot().head.clone()))
        })?;
        Ok(())
    }
}
