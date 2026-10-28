//! Explicit new-profile native acceptance. Never invoked on the restricted local runner.
//! Real source setup, exact first result, actual death, original writer expiry,
//! and unfinished-counterpart recovery are distinct evidence boundaries.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
use wholepact_authority::native_witness_owner::{
    EphemeralNativeWitnessV1, EphemeralPartialFinancialWitnessV2, EphemeralHistoryServerV1, EphemeralWitnessOriginV1,
};
use wholepact_authority::{OwnerControl, OwnerControlRequest};
use wholepact_signer::authority_bridge::financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, DurableFinancialResultRequestV2,
};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::{FinancialQualificationPhaseV1 as Phase, PreservedDurablePairV2, StartedFinancialCustodyV2};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use crate::host::financial::durable_delivery_admission_v2::DeliveryChoicesV2;

const READY: &[u8] = b"durable-result-v2-partial.json\0";
const FINISHED: &[u8] = b"durable-result-v2-finished.json\0";
const DEATH: &str = "SYNTHETIC_DURABLE_RESULT_PARTIAL_V2=1";
const INTAKE_DEATH: &str = "SYNTHETIC_DURABLE_RESULT_INTAKE_ACK_PENDING_V2=1";
const STARTED_READY: &[u8] = b"durable-result-v2-started.json\0";
const STARTED_FINISHED: &[u8] = b"durable-result-v2-started-finished.json\0";
const STARTED_DEATH: &str = "DURABLE_STARTED_COMMITTED_BEFORE_KEY_USE_V2";
const LIMIT: Duration = Duration::from_secs(1800);

trait Witness {
    fn bootstrap(&mut self, account:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>;
    fn start_delivery(&mut self, account:&str, request:&OwnerControlRequest)->wholepact_authority::Result<()>;
    fn finish_delivery(&mut self)->wholepact_authority::Result<()>;
    fn delivery_history(&mut self, operation:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>;
    fn start_financial(&mut self, account:&str, request:&OwnerControlRequest)->wholepact_authority::Result<()>;
    fn finish_financial(&mut self)->wholepact_authority::Result<()>;
    fn signing(&mut self, operation:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>;
    fn completed(&mut self, operation:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>;
}
macro_rules! witness_forward {
    ($ty:ty) => { impl Witness for $ty {
        fn bootstrap(&mut self,a:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_original_delivery_bootstrap_history_v2(a)}
        fn start_delivery(&mut self,a:&str,r:&OwnerControlRequest)->wholepact_authority::Result<()>{self.start_exact_durable_delivery_admission_v2(a,r)}
        fn finish_delivery(&mut self)->wholepact_authority::Result<()>{self.finish_exact_durable_delivery_admission_v2()}
        fn delivery_history(&mut self,o:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_committed_durable_delivery_history_v2(o)}
        fn start_financial(&mut self,a:&str,r:&OwnerControlRequest)->wholepact_authority::Result<()>{self.start_exact_financial_continuation_v1(a,r)}
        fn finish_financial(&mut self)->wholepact_authority::Result<()>{self.finish_exact_financial_continuation_v1()}
        fn signing(&mut self,o:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_committed_financial_signing_v1(o)}
        fn completed(&mut self,o:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_exact_completed_history_v2(o)}
    }};
}
witness_forward!(EphemeralPartialFinancialWitnessV2);
impl Witness for EphemeralNativeWitnessV1 {
    fn bootstrap(&mut self,a:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_original_delivery_bootstrap_history_v2(a)}
    fn start_delivery(&mut self,a:&str,r:&OwnerControlRequest)->wholepact_authority::Result<()>{self.start_exact_durable_delivery_admission_v2(a,r)}
    fn finish_delivery(&mut self)->wholepact_authority::Result<()>{self.finish_exact_durable_delivery_admission_v2()}
    fn delivery_history(&mut self,o:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_committed_durable_delivery_history_v2(o)}
    fn start_financial(&mut self,a:&str,r:&OwnerControlRequest)->wholepact_authority::Result<()>{self.start_exact_financial_continuation_v1(a,r)}
    fn finish_financial(&mut self)->wholepact_authority::Result<()>{self.finish_exact_financial_continuation_v1()}
    fn signing(&mut self,o:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_committed_financial_signing_v1(o)}
    fn completed(&mut self,o:&str)->wholepact_authority::Result<EphemeralHistoryServerV1>{self.serve_committed_completed_dispatch_v1(o)}
}
fn authority(e:wholepact_authority::AuthorityError)->Error {witness_error(B::DeliveryHistoricalRead,e)}

fn delivery_peer_command(index:usize,proposal:&wholepact_core::ProposalInput,already_open:bool)->C {
    if already_open {C::DeliveryPeer(index)} else {C::OpenDelivery(index,proposal.clone())}
}

#[allow(clippy::too_many_arguments)]
fn export_owner(terminal:&crate::terminal::Terminal, host:&Host, signers:&worker::JoinedSignerWorkerV1,
    witness:&mut impl Witness, workspace:&Path, proposal:&wholepact_core::ProposalInput,
    disclosures:&[OriginalDisclosureV2], identity:&FixedProposalIdentityV1, choices:&DeliveryChoicesV2,
    index:usize, account_id:&str, already_open:bool)->Result<DurableDeliveryAdmissionStatusV3> {
                let mut import_complete = None;
                let export_result = at(B::DeliverySourceExport, || {
                    host.private_original_financial_delivery_export_v2(&workspace, &choices, |prepared_fixed, payload_digest, payload_bytes, delivery, materials| {
                // Both fresh and reopened sources require one descriptor reply
                // before pair_owner receives; startup does not enqueue one.
                signers.send(delivery_peer_command(index,proposal,already_open)).map_err(worker_error)?;
                let client = pair_owner(signers, index, true)?;
                signers
                    .send(C::AcceptDelivery(index))
                    .map_err(worker_error)?;
                let records = match signers.receive().map_err(worker_error)? {
                    R::Records {
                        index: actual,
                        records,
                    } if actual == index => records,
                    _ => return Err(Error::Authentication),
                };
                signers
                    .send(C::ConfigureDeliveryWitness(index))
                    .map_err(worker_error)?;
                done(signers, index)?;
                let original_disclosure = disclosures
                    .iter()
                    .find(|source| source.account_id == account_id)
                    .ok_or(Error::Authentication)?;
                let own_disclosure = original_disclosure.history.clone();
                // These are the actual capture and fresh native receipt pairs.
                // Reusing the capture refs would conceal the lineage bug this
                // restarted-recipient route must exercise.
                if original_disclosure.enrollment_ref == records.enrollment_ref
                    || original_disclosure.accepted_manifest_ref == records.accepted_manifest_ref
                {
                    return Err(Error::Authentication);
                }
                let redisclosure_request = DurableConstructionRedisclosureRequestV1 {
                    operation_id: format!("synthetic-original-current-recipient-v2-{index}"),
                    original: DurableConstructionRedisclosureSourceV1 {
                        operation_id: own_disclosure.operation_id.clone(),
                        expected_request_digest: Some(
                            own_disclosure.expected_request_digest.clone(),
                        ),
                    },
                    enrollment_ref: records.enrollment_ref.clone(),
                    accepted_manifest_ref: records.accepted_manifest_ref.clone(),
                };
                let review = terminal.approve_historical(&format!("Request one native-approved redisclosure of this exact original material to this current paired recipient. No capture, reconstruction or validity renewal.\nOriginal immutable scope: {}\nOriginal material digest: {}\nExact current-recipient request: {}",serde_json::to_string_pretty(&original_disclosure.scope)?,original_disclosure.material_digest,serde_json::to_string_pretty(&redisclosure_request)?))?;
                review.check()?;
                let stop = Arc::new(AtomicBool::new(false));
                signers
                    .send(C::PollDeliveryRedisclosure(
                        index,
                        redisclosure_request.clone(),
                        stop.clone(),
                    ))
                    .map_err(worker_error)?;
                let received = at(B::DeliveryRedisclosure, || {
                    client
                        .redisclose_durable_construction_v1(&redisclosure_request)
                        .map_err(|error| bridge_error_at(B::DeliveryRedisclosure, error))
                });
                stop.store(true, Ordering::Release);
                let stopped = done(signers, index);
                let received = received?;
                stopped?;
                let outbox = received.outbox();
                let link = outbox.redisclosure().ok_or(Error::Authentication)?;
                // The returned value is the actual authenticated current-peer
                // response, not a reconstructed DTO. Normalize only the new
                // recipient grant; every original audience/material/clock field
                // must still match the completed capture byte-for-byte.
                let mut expected_scope = original_disclosure.scope.clone();
                expected_scope.constructor.authenticated_local_grant_digest =
                    outbox.recipient_grant_digest().into();
                expected_scope.prover.authenticated_local_grant_digest =
                    outbox.recipient_grant_digest().into();
                if outbox.request().operation_id != redisclosure_request.operation_id
                    || outbox.request().enrollment_ref != records.enrollment_ref
                    || outbox.request().accepted_manifest_ref != records.accepted_manifest_ref
                    || outbox.request().scope != expected_scope
                    || outbox.material_digest() != original_disclosure.material_digest
                    || link.original_operation_id != own_disclosure.operation_id
                    || link.original_request_digest != own_disclosure.expected_request_digest
                    || link.original_outbox_reference != original_disclosure.outbox_reference
                {
                    return Err(Error::Authentication);
                }
                let current_disclosure = DurableConstructionHistoryRequestV1 {
                    operation_id: outbox.request().operation_id.clone(),
                    expected_request_digest: outbox.request_digest().into(),
                };
                drop(received);
                let request = DurableReviewDeliveryRequestV1 {
                    operation_id: format!("synthetic-original-delivery-export-v2-{index}"),
                    enrollment_ref: records.enrollment_ref,
                    accepted_manifest_ref: records.accepted_manifest_ref,
                    own_disclosure,
                    current_disclosure: Some(current_disclosure),
                    proposal_binding: identity.proposal_binding.clone(),
                };
                if prepared_fixed != identity { return Err(Error::Authentication); }
                let prepared_complete = Arc::new(AtomicBool::new(false));
                signers.send(C::PrepareClosedDelivery(index, request.clone(), prepared_fixed.clone(), payload_digest.into(), payload_bytes, delivery.clone(), materials.to_vec(), prepared_complete.clone())).map_err(worker_error)?;
                let expected_request = request.clone();
                let prepared_result = client.prepare_closed_recipient_v3(request, prepared_fixed.clone(), payload_digest.into(), payload_bytes, delivery.clone(), materials.to_vec()).map_err(bridge_error);
                prepared_complete.store(true, Ordering::Release);
                let prepared_stopped = done(signers, index);
                let prepared = prepared_result?;
                prepared_stopped?;
                // Inspect only the actual sealed recipient's inert descriptor.
                // Its retained admission refs are CURRENT; own_disclosure still
                // names the exact original capture, whose payload never changes.
                let actual = prepared.intent();
                if actual.request != expected_request
                    || actual.request.own_disclosure != original_disclosure.history
                    || actual.original_enrollment_ref != expected_request.enrollment_ref
                    || actual.original_manifest_ref != expected_request.accepted_manifest_ref
                    || actual.original_enrollment_ref == original_disclosure.enrollment_ref
                    || actual.original_manifest_ref == original_disclosure.accepted_manifest_ref
                {
                    return Err(Error::Authentication);
                }
                // Keep the real closed controller responsive through Host review,
                // activation, exact receive, and actual proof verification.
                let complete = Arc::new(AtomicBool::new(false));
                signers.send(C::PollClosedDeliveryImport(index, prepared_fixed.clone(), complete.clone())).map_err(worker_error)?;
                import_complete = Some(complete);
                Ok(prepared)
                    })
                });
                let import_stopped = if let Some(complete) = import_complete {
                    complete.store(true, Ordering::Release);
                    done(signers, index)
                } else { Ok(()) };
                let (client, exported) = export_result?;
                import_stopped?;
                // The original independent witness serves the pristine bootstrap
                // only while the signer derives its genuine pending native review.
                let history = witness
                    .bootstrap(&account_id)
                    .map_err(|error| witness_error(B::DeliveryHistoricalRead, error))?;
                signers.send(C::PollClosedDeliveryAdmission(index)).map_err(worker_error)?;
                let status = std::thread::scope(|scope| -> Result<DurableDeliveryAdmissionStatusV3> {
                    let response_complete = Arc::new(AtomicBool::new(false));
                    let exchange_complete = response_complete.clone();
                    let exchange = scope.spawn(move || {
                        let result = (|| {
                            let mut pending = client.request_admission_retained_v3()?;
                            let status = pending.await_status_v3()?;
                            Ok::<_, wholepact_signer::authority_bridge::BridgeError>((pending, status))
                        })();
                        exchange_complete.store(true, Ordering::Release);
                        result
                    });
                    let request = match signers.receive().map_err(worker_error)? {
                        R::DurableAdmissionRequest { index: actual, request } if actual == index => request,
                        _ => return Err(Error::Authentication),
                    };
                    drop(history);
                    // Signer review is conditional and completes before Witness
                    // arms its unchanged native/CAS action. No request/intent has
                    // been sent. Only connection-refused discovery may wait.
                    signers.send(C::ApproveClosedDelivery(index)).map_err(worker_error)?;
                    done(signers, index)?;
                    signers.send(C::AwaitClosedDeliveryResponse(index, response_complete)).map_err(worker_error)?;
                    at(B::DeliveryNativeAdmission, || witness.start_delivery(&account_id, &request).map_err(|error| witness_error(B::DeliveryNativeAdmission, error)))?;
                    at(B::DeliveryNativeAdmission, || witness.finish_delivery().map_err(|error| witness_error(B::DeliveryNativeAdmission, error)))?;
                    let native_pending = match signers.receive().map_err(worker_error)? {
                        R::ClosedDeliveryStatus { index: actual, status } if actual == index => status,
                        _ => return Err(Error::Authentication),
                    };
                    let (pending, returned_pending) = exchange.join().map_err(|_| Error::Authentication)?.map_err(bridge_error)?;
                    if native_pending != returned_pending || returned_pending.request != request || returned_pending.verified_audit().is_ok() {
                        return Err(Error::Authentication);
                    }
                    // Drop the transport/action phase before a distinct fresh
                    // read-only native review. Its inert retained operation is
                    // never admission authority or a resend instruction.
                    let committed_history = witness.delivery_history(&request.operation_id).map_err(|error| witness_error(B::DeliveryHistoricalRead, error))?;
                    let audit_complete = Arc::new(AtomicBool::new(false));
                    signers.send(C::AwaitClosedDeliveryAudit(index, audit_complete.clone())).map_err(worker_error)?;
                    let returned = pending.read_original_status_v3().map_err(bridge_error);
                    audit_complete.store(true, Ordering::Release);
                    let native_result = signers.receive().map_err(worker_error);
                    let returned = returned?;
                    let native = match native_result? {
                        R::ClosedDeliveryStatus { index: actual, status } if actual == index => status,
                        _ => return Err(Error::Authentication),
                    };
                    drop(committed_history);
                    if native != returned { return Err(Error::Authentication); }
                    returned.verified_audit().map_err(bridge_error)?;
                    Ok(returned)
                })?;
                let audited = status.verified_audit().map_err(bridge_error)?;
                crate::host::financial::durable_delivery_admission_v2::validate_admission_result_v3(&exported, audited)?;
                if status.intent_digest != exported.export_scope.recipient.digest().map_err(bridge_error)? { return Err(Error::Authentication); }
    Ok(status)
}

fn wait_phase(signers:&worker::JoinedSignerWorkerV1,index:usize,target:Phase)->Result<()> {
    let deadline=private_fixed_v2::child_original_cutoff()?;
    loop {
        if Instant::now()>=deadline {return Err(Error::Permission);}
        signers.send(C::PollFinancialContinuation(index)).map_err(worker_error)?;
        let R::FinancialPhase{index:actual,phase}=signers.receive().map_err(worker_error)? else {return Err(Error::Authentication)};
        if actual!=index {return Err(Error::Authentication);}
        if phase==target {return Ok(());}
        if !matches!(phase,Phase::Working|Phase::Opening){return Err(Error::Authentication);}
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn approve(signers:&worker::JoinedSignerWorkerV1,index:usize)->Result<()> {
    signers.send(C::ApproveFinancialContinuation(index)).map_err(worker_error)?; done(signers,index)
}
fn preserved(signers:&worker::JoinedSignerWorkerV1,index:usize)->Result<worker::DeliveryReopenV2>{
    match signers.receive().map_err(worker_error)? {
        R::DeliveryPreserved{index:actual,original} if actual==index=>Ok(original),
        _=>Err(Error::Authentication),
    }
}
// This projection consumes only the typed reply of this worker command. The
// descriptor is dropped without pairing; neither scope nor digest grants access.
fn unpaired_delivery_receipt(reply:R)->Option<(usize,wholepact_signer_origin::PairScope,String)> {
    match reply {
        R::DurablePeer{index,peer:_,scope,entry_digest}=>Some((index,scope,entry_digest)),
        _=>None,
    }
}
fn validate_unpaired_delivery_receipt(receipt:Option<(usize,wholepact_signer_origin::PairScope,String)>,
    expected:&wholepact_signer_origin::PairScope)->Result<()> {
    match receipt {
        Some((2,scope,entry_digest)) if scope==*expected && scope.validate().is_ok() && hash(&entry_digest)=>Ok(()),
        _=>Err(Error::Authentication),
    }
}
fn expected_unpaired_delivery_scope(proposal:&wholepact_core::ProposalInput,account:&str)
    ->Result<wholepact_signer_origin::PairScope> {
    let validated=wholepact_core::Proposal::validate(proposal.clone()).map_err(|_|Error::Authentication)?;
    let participant=validated.manifest().participants.iter().find(|p|p.account_id==account).ok_or(Error::Authentication)?;
    Ok(wholepact_signer_origin::PairScope {
        account_id:account.into(),agreement_id:validated.manifest().agreement.agreement_id.clone(),
        participant_id:participant.participant_id.clone(),manifest_digest:validated.manifest_digest().into(),
        history_read:true,authorization_export:false,preconstruction_export:true,
    })
}
fn validate_unpaired_delivery_selector(original:&worker::DeliveryReopenV2,
    proposal:&wholepact_core::ProposalInput,account:&str)->Result<()> {
    if original.version!=2 || original.proposal!=*proposal || original.account_id!=account
        || original.aggregate_budget_zatoshis!=1_000_000 || original.original_directory_preserved
    {return Err(Error::Authentication);}
    Ok(())
}
fn now_ms()->Result<u64>{SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|Error::Invalid)?.as_millis().try_into().map_err(|_|Error::Invalid)}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedOwnerV2 {
    continuation:OwnerControlRequest,
    original:worker::DeliveryReopenV2,
    result:DurableFinancialResultRequestV2,
    original_writer_expiry_ms:u64,
    reservation_digest:String,
    authenticated_history_digest:String,
}
fn writer_evidence(history:&AuthenticatedFinancialContinuationHistoryV1)->Result<(u64,String)>{
    let snapshot=history.snapshot();
    let receipt=snapshot.active_writer_session.as_ref().ok_or(Error::Authentication)?;
    let permit=history.reservation().map_err(authority)?.ok_or(Error::Authentication)?;
    let terms=&history.continuation_record().terms;
    if receipt.session_id!=permit.writer_session_id
        || receipt.writer_epoch!=permit.request.writer_epoch
        || receipt.writer_certificate_digest!=terms.scope.authorization.writer_certificate_digest
        || receipt.disclosure.account_id!=permit.request.account_id
        || permit.request.account_id!=history.continuation_request().account_id
        || permit.request.authorization_id!=terms.scope.authorization.authorization_id
        || receipt.expires_at_ms<=receipt.acquired_at_ms
        || permit.request.transaction_expiry_height!=terms.scope.authorization.fixed.expiry_height
    {return Err(Error::Authentication);}
    Ok((receipt.expires_at_ms,digest(permit)?))
}

// Existing first-error collector, promoted before stopping/draining the worker.
// Only closed enum labels leave this operation; timing and nested call details
// are deliberately omitted. This has no effect on the returned Result.
static RESULT_FAILURE_EMITTED_V2: AtomicBool = AtomicBool::new(false);
fn finite_result_failure_v2(record:Option<crate::host::financial_diagnostics_v1::FinancialDiagnosticV1>,
    failed:bool,emitted:&AtomicBool)->Option<crate::host::financial_diagnostics_v1::FinancialDiagnosticV1> {
    let mut record=record.filter(|record|record.is_valid_v1())?;
    if !failed || emitted.swap(true,Ordering::SeqCst){return None;}
    record.current_timing=None;record.authority_call=None;
    Some(record)
}
fn promote_result_failure_v2<T>(result:&Result<T>) {
    use crate::host::financial_diagnostics_v1 as fd;
    let captured=fd::take_operation_failure();
    if let Err(error)=result {
        let captured=captured.or_else(|| {
            fd::host(fd::FinancialStageV1::LifecycleHarness,fd::FinancialCommitStateV1::NotEstablished,error);
            fd::take_operation_failure()
        });
        if let Some(record)=finite_result_failure_v2(captured,true,&RESULT_FAILURE_EMITTED_V2){fd::emit(record);}
    }
}

fn return_exact(host:&Host,workspace:&Path,signers:&worker::JoinedSignerWorkerV1,index:usize,
    original:worker::DeliveryReopenV2,history:&AuthenticatedFinancialContinuationHistoryV1,
    expected:Option<&DurableFinancialResultRequestV2>,pair:Option<&Arc<PreservedDurablePairV2>>)->Result<(worker::DeliveryReopenV2,DurableFinancialResultRequestV2)>{
    let open=match pair {Some(pair)=>C::OpenDurableResultInPairV2(index,original,pair.clone()),None=>C::OpenDurableResultV2(index,original)};
    signers.send(open).map_err(worker_error)?;done(signers,index)?;
    signers.send(C::ReadDurableResultPeerV2(index)).map_err(worker_error)?;
    let (peer,request)=match signers.receive().map_err(worker_error)? {
        R::DurableResultPeerV2{index:actual,peer,request} if actual==index=>(peer,request),
        _=>return Err(Error::Authentication),
    };
    request.validate().map_err(bridge_error)?;
    if expected.is_some_and(|e| e!=&request)
        || request.request.account_id!=history.continuation_request().account_id
        || request.continuation_request_digest!=history.continuation_record().request_digest(history.continuation_request()).map_err(authority)?
    {return Err(Error::Authentication);}
    let stop=Arc::new(AtomicBool::new(false));
    crate::host::financial_diagnostics_v1::reset_operation();
    signers.send(C::ServeDurableResultV2(index,stop.clone())).map_err(worker_error)?;
    let result=(||{
        let receiver=host.prepare_durable_financial_preview_with_provider_v2(
            workspace,&peer.endpoint,&request,history,peer.provider)?;
        host.intake_original_financial_result_v2(workspace,&format!("durable-v2-intake-{index}"),receiver,history)
    })();
    promote_result_failure_v2(&result);
    stop.store(true,Ordering::Release);
    let returned=done(signers,index);result?;returned?;
    signers.send(C::PreserveDurableResultV2(index)).map_err(worker_error)?;
    Ok((preserved(signers,index)?,request))
}

// Real click-issued grants are consumed by the production prepare/serve
// gates. Receiver errors alone are NOT attributed to grant denial; the worker
// separately proves Permission with the actual source and peer still current.
// This is source-proven pre-disclosure protocol refusal, NOT a wire-byte count.
// WrongRequestRead may fail the exact source selector before the Read scope;
// WrongRecipientRead holds that selector fixed and exercises actual peer scope.
fn probe_result_grants(host:&Host,workspace:&Path,signers:&worker::JoinedSignerWorkerV1,
    original:&worker::DeliveryReopenV2,history:&AuthenticatedFinancialContinuationHistoryV1,
    expected:&DurableFinancialResultRequestV2)->Result<()> {
    use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
        DurableResultGrantProbeV2 as Probe,DurableResultGrantProbeOutcomeV2 as Outcome,
    };
    for probe in [Probe::WrongRequestRead,Probe::WrongRecipientRead,Probe::RevokedRead,Probe::WrongSignatureSetReturn,Probe::RevokedReturn,Probe::ExpiredReturn] {
        let before=host.inspect_original_financial_progress_v2(workspace)?;
        let before_history=host.qualification_original_financial_history_commitment_v2(workspace)?;
        if before_history.0!=before.revision{return Err(Error::Authentication);}
        signers.send(C::OpenDurableResultV2(1,original.clone())).map_err(worker_error)?;done(signers,1)?;
        signers.send(C::ReadDurableResultPeerV2(1)).map_err(worker_error)?;
        let (peer,request)=match signers.receive().map_err(worker_error)? {
            R::DurableResultPeerV2{index:1,peer,request}=>(peer,request),
            _=>return Err(Error::Authentication),
        };
        if &request!=expected{return Err(Error::Authentication);}
        let (other_owner,other_stream)=if probe==Probe::WrongRecipientRead {
            let (owner,stream)=DistinctPeerV2::open(private_fixed_v2::child_original_cutoff()?)?;
            (Some(owner),Some(stream))
        } else {(None,None)};
        let stop=Arc::new(AtomicBool::new(false));
        signers.send(C::ProbeDurableResultGrantV2(1,probe,other_stream,stop.clone())).map_err(worker_error)?;
        let receiver=host.prepare_durable_financial_preview_with_provider_v2(workspace,&peer.endpoint,&request,history,peer.provider);
        let read_probe=matches!(probe,Probe::WrongRequestRead|Probe::WrongRecipientRead|Probe::RevokedRead);
        let receiver_denied=if read_probe {
            matches!(receiver,Err(Error::Receipt(ref text)) if text.starts_with("FINANCIAL_V2_RESULT_PREVIEW:"))
        } else {
            let receiver=receiver?;
            use crate::host::financial_diagnostics_v1 as fd;
            fd::reset_operation();
            let intake=host.intake_original_financial_result_v2(workspace,"durable-v2-intake-1",receiver,history);
            let failure=fd::take_operation_failure().ok_or(Error::Authentication)?;
            intake.is_err() && failure.stage==fd::FinancialStageV1::ResultReceive
                && failure.component==fd::FinancialComponentV1::SignerBridge
                && failure.commit_state==fd::FinancialCommitStateV1::NotEstablished
        };
        let outcome=signers.receive().map_err(worker_error)?;
        stop.store(true,Ordering::Release);
        if let Some(owner)=other_owner{owner.finish()?;}
        if !receiver_denied || !matches!(outcome,R::DurableResultGrantProbeV2{index:1,outcome:Outcome::DeniedAsIntended}) {
            return Err(Error::Authentication);
        }
        let after=host.inspect_original_financial_progress_v2(workspace)?;
        if digest(&before)?!=digest(&after)?
            || host.qualification_original_financial_history_commitment_v2(workspace)?!=before_history
        {return Err(Error::Authentication);}
    }
    Ok(())
}

// Open the actual result-only source to obtain its audited inert selection.
// No Host preview, Read grant, Return, signature intake or Finish is requested.
fn select_without_intake(signers:&worker::JoinedSignerWorkerV1,index:usize,
    original:worker::DeliveryReopenV2,history:&AuthenticatedFinancialContinuationHistoryV1)
    ->Result<(worker::DeliveryReopenV2,DurableFinancialResultRequestV2)> {
    signers.send(C::OpenDurableResultV2(index,original)).map_err(worker_error)?;done(signers,index)?;
    signers.send(C::ReadDurableResultPeerV2(index)).map_err(worker_error)?;
    let request=match signers.receive().map_err(worker_error)? {
        R::DurableResultPeerV2{index:actual,peer:_,request} if actual==index=>request,
        _=>return Err(Error::Authentication),
    };
    request.validate().map_err(bridge_error)?;
    if request.request.account_id!=history.continuation_request().account_id
        || request.continuation_request_digest!=history.continuation_record().request_digest(history.continuation_request()).map_err(authority)?
    {return Err(Error::Authentication);}
    signers.send(C::PreserveDurableResultV2(index)).map_err(worker_error)?;
    Ok((preserved(signers,index)?,request))
}

#[allow(clippy::too_many_arguments)]
fn sign_and_intake(host:&Host,workspace:&Path,signers:&worker::JoinedSignerWorkerV1,
    witness:&mut impl Witness,index:usize,admission:&DurableDeliveryAdmissionStatusV3,wallet_setup:&str,
    cold:Option<(EphemeralWitnessOriginV1,Arc<PreservedDurablePairV2>)>,intake_now:bool,
    started_checkpoint:Option<(&Path,&FixedProposalIdentityV1)>)->Result<RetainedOwnerV2>{
    let pair=cold.as_ref().map(|(_,pair)|pair.clone());
    let history=witness.delivery_history(&admission.request.operation_id).map_err(authority)?;
    let begin=match cold {Some((origin,pair))=>C::BeginReopenedFinancialContinuationV2(index,wallet_setup.into(),origin,pair),
        None=>C::BeginFinancialContinuation(index,wallet_setup.into())};
    signers.send(begin).map_err(worker_error)?;done(signers,index)?;
    for phase in [Phase::ReadReview,Phase::ContinueReview]{wait_phase(signers,index,phase)?;approve(signers,index)?;}
    wait_phase(signers,index,Phase::AwaitingAdmission)?;
    signers.send(C::ReadFinancialContinuationRequest(index)).map_err(worker_error)?;
    let request=match signers.receive().map_err(worker_error)? {
        R::FinancialRequest{index:actual,request:Some(request)} if actual==index=>request,
        _=>return Err(Error::Authentication),
    };
    let OwnerControl::AdmitFinancialContinuationV1{record}=&request.control else{return Err(Error::Authentication)};
    if record.terms.original_delivery_operation_id!=admission.request.operation_id
        || record.terms.original_delivery_request_digest!=wholepact_authority::durable_financial_continuation_v1::original_delivery_request_digest_v1(&admission.request).map_err(authority)?
    {return Err(Error::Authentication);}
    drop(history);
    witness.start_financial(&request.account_id,&request).map_err(authority)?;
    signers.send(C::SendFinancialContinuation(index)).map_err(worker_error)?;done(signers,index)?;
    wait_phase(signers,index,Phase::AdmitReview)?;approve(signers,index)?;
    witness.finish_financial().map_err(authority)?;
    // Persist the authentic continuation BEFORE starting the first key-use flow.
    // The next result wait cannot turn a lost bind ACK into a new admission.
    let history_server=witness.completed(&request.operation_id).map_err(authority)?;
    let before=host.read_original_financial_history_v2(workspace,&request.account_id,&request.operation_id)?;
    if before.continuation_request()!=&request || before.reservation().map_err(authority)?.is_some(){return Err(Error::Authentication);}
    host.bind_original_financial_owner_v2(workspace,&format!("durable-v2-bind-{index}"),&before)?;
    drop(before);drop(history_server);
    let signing=witness.signing(&request.operation_id).map_err(authority)?;
    for phase in [Phase::ReadReview,Phase::AcquireReview,Phase::ReadReview,Phase::ActivateReview,
        Phase::WalletReview,Phase::ReadReview]{wait_phase(signers,index,phase)?;approve(signers,index)?;}
    wait_phase(signers,index,Phase::SignReview)?;
    if let Some((scenario,fixed))=started_checkpoint {
        if intake_now || pair.is_some(){return Err(Error::Authentication);}
        signers.send(C::CaptureAndArmStartedV2(index,private_fixed_v2::child_original_cutoff()?)).map_err(worker_error)?;
        let custody=match signers.receive().map_err(worker_error)? {
            R::FinancialStartedCustodyV2{index:actual,custody} if actual==index=>custody,
            _=>return Err(Error::Authentication),
        };
        let ready=StartedReadyV2{version:2,custody,fixed:fixed.clone(),continuation:request.clone()};
        ready.validate(scenario)?;write_record(scenario,STARTED_READY,&ready)?;
        // Only this unchanged native click starts key use. The source hook parks
        // after durable Started, before the fence/key operation; parent kills it.
        approve(signers,index)?;
        wait_phase(signers,index,Phase::AwaitingReturn)?;
        return Err(Error::Authentication);
    }
    approve(signers,index)?;
    wait_phase(signers,index,Phase::AwaitingReturn)?;
    drop(signing);
    signers.send(if pair.is_some(){C::PreserveReopenedFinancialContinuationV2(index)}else{C::PreserveFinancialContinuation(index)}).map_err(worker_error)?;
    let original=preserved(signers,index)?;
    let history_server=witness.completed(&request.operation_id).map_err(authority)?;
    let history=host.read_original_financial_history_v2(workspace,&request.account_id,&request.operation_id)?;
    let (original_writer_expiry_ms,reservation_digest)=writer_evidence(&history)?;
    let authenticated_history_digest=history.history_digest().to_owned();
    let (original,result)=if intake_now {
        return_exact(host,workspace,signers,index,original,&history,None,pair.as_ref())?
    } else {
        if pair.is_some(){return Err(Error::Authentication);}
        select_without_intake(signers,index,original,&history)?
    };
    // Same actual authoritative reservation after result/return, no release,
    // new key use or exposure reset is inferred from transport completion.
    let after=host.read_original_financial_history_v2(workspace,&request.account_id,&request.operation_id)?;
    // Compare without claiming that a fresh read reissued the old writer.
    if writer_evidence(&after)?!=(original_writer_expiry_ms,reservation_digest.clone()){return Err(Error::Authentication);}
    if after.history_digest()!=authenticated_history_digest{return Err(Error::Authentication);}
    drop(after);drop(history);drop(history_server);
    Ok(RetainedOwnerV2{continuation:request,original,result,original_writer_expiry_ms,reservation_digest,authenticated_history_digest})
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialReadyV2 {
    version:u16,profile:PathBuf,workspace:PathBuf,financial:PathBuf,
    proposal:wholepact_core::ProposalInput,identity:FixedProposalIdentityV1,choices:DeliveryChoicesV2,
    disclosures:Vec<OriginalDisclosureV2>,wallet_setup:String,
    first:RetainedOwnerV2,second_original:worker::DeliveryReopenV2,
    witness_reopen:Vec<u8>,provider_reopen:Vec<u8>,saved_at_ms:u64,
    preintake_revision:u64,preintake_progress_digest:String,preintake_history_digest:String,
}
fn validate_owned_paths(root:&Path,paths:[&Path;5],preserved:[bool;2])->io::Result<()> {
    if !root.is_absolute() || root.parent().is_none()
        || !root.components().all(|part|matches!(part,Component::RootDir|Component::Normal(_)))
        || preserved.into_iter().filter(|v|*v).count()!=1
    {return Err(invalid());}
    for path in paths {
        let relative=path.strip_prefix(root).map_err(|_|invalid())?;
        if !path.is_absolute() || path.as_os_str().len()>4096 || relative.as_os_str().is_empty()
            || !relative.components().all(|part|matches!(part,Component::Normal(_)))
        {return Err(invalid());}
    }
    for (i,path) in paths.iter().enumerate(){
        if paths[..i].contains(path){return Err(invalid());}
    }
    if paths[3].parent()!=paths[4].parent(){return Err(invalid());}
    Ok(())
}
impl PartialReadyV2 {
    fn validate(&self,root:&Path)->io::Result<()> {
        if self.version!=2 || self.witness_reopen.is_empty() || self.provider_reopen.is_empty()
            || self.witness_reopen.len()>MAX_CONTROL as usize || self.provider_reopen.len()>MAX_CONTROL as usize
            || self.first.original_writer_expiry_ms==0 || self.saved_at_ms==0
            || self.preintake_revision==0 || !hash(&self.preintake_progress_digest) || !hash(&self.preintake_history_digest)
            || self.first.result.request.fixed!=self.identity
            || self.first.original.account_id!=self.first.result.request.account_id
            || self.first.continuation.account_id!=self.first.original.account_id
            || self.first.original.account_id==self.second_original.account_id
            || self.first.original.proposal!=self.proposal || self.second_original.proposal!=self.proposal
            || self.proposal.proposal_id!=self.identity.proposal_id
            || self.first.original.version!=20 || self.second_original.version!=2
            || !self.first.original.original_directory_preserved
            || self.disclosures.len()!=2
        {return Err(invalid());}
        validate_owned_paths(root,[&self.profile,&self.workspace,&self.financial,&self.first.original.root,&self.second_original.root],
            [self.first.original.original_directory_preserved,self.second_original.original_directory_preserved])?;
        let roster=self.proposal.manifest.participants.iter().map(|p|p.account_id.as_str()).collect::<std::collections::BTreeSet<_>>();
        if self.proposal.manifest.participants.len()!=2
            || roster!=std::collections::BTreeSet::from([self.first.original.account_id.as_str(),self.second_original.account_id.as_str()])
        {return Err(invalid());}
        let OwnerControl::AdmitFinancialContinuationV1{record}=&self.first.continuation.control else{return Err(invalid())};
        record.validate_request(&self.first.continuation,&record.terms.scope.witness).map_err(|_|invalid())?;
        if serde_json::to_value(&record.terms.scope.authorization.fixed).map_err(|_|invalid())?
            !=serde_json::to_value(&self.identity).map_err(|_|invalid())?
            || record.terms.scope.authorization.authorization_id!=self.first.result.request.authorization_id
        {return Err(invalid());}
        self.first.result.validate().map_err(|_|invalid())?;
        Ok(())
    }
}
#[test]
fn partial_ready_paths_reject_escape_alias_and_unpreserved_container(){
    // A1/A2 do more than inspection: intake/completion requires the unchanged
    // manual-effect guard. Re-enroll this fresh OWNED native-only session;
    // do not restore an old grant or skip any exact per-action review.
    for (inputs,count) in [(intake_inputs_v2(),23),(reader_inputs_v2(),147)] {
        assert_eq!(inputs.len(),count);
        assert!(matches!(&inputs[3],Input::Text{prompt:"Local application principal ID: ",response:"synthetic-roster-host"}));
        assert!(matches!(&inputs[4],Input::Text{prompt:"Scope choice: type SELECTED",response:"OWNED"}));
        assert!(matches!(&inputs[5],Input::Text{prompt:"Additional shared agreement IDs, comma-separated; blank for none: ",response:""}));
        assert!(matches!(&inputs[6],Input::Text{prompt:"Grant READ only, or PREPARE",response:"PREPARE"}));
        assert!(matches!(&inputs[7],Input::Text{prompt:"Optional exact browser origin for this session",response:""}));
        assert!(matches!(&inputs[9],Input::ExactReview{detail:"Grant this session until lock/restart/revoke.",approve:true}));
    }
    let intake=intake_inputs_v2();
    assert!(matches!(&intake[20],Input::ExactReview{detail:"Verify and retain one actual authenticated original signer result",approve:true}));
    assert!(matches!(&intake[21],Input::ExactReview{detail:"Approve retain exact usable signatures for this EXACT scope?",approve:true}));
    assert!(matches!(&intake[22],Input::ExactReview{detail:"Prepare this ONE EXACT local signature intake",approve:true}));

    // Inert reply metadata only: no provider, native grant, socket or pairing.
    let expected=wholepact_signer_origin::PairScope {
        account_id:"owner-two".into(),agreement_id:"agreement".into(),participant_id:"participant-two".into(),
        manifest_digest:"a".repeat(64),history_read:true,authorization_export:false,preconstruction_export:true,
    };
    let receipt=||Some((2,expected.clone(),"b".repeat(64)));
    assert!(validate_unpaired_delivery_receipt(receipt(),&expected).is_ok());
    assert!(validate_unpaired_delivery_receipt(None,&expected).is_err());
    assert!(validate_unpaired_delivery_receipt(unpaired_delivery_receipt(R::Done{index:2}),&expected).is_err());
    for index in [0,1,3,usize::MAX] {
        assert!(validate_unpaired_delivery_receipt(Some((index,expected.clone(),"b".repeat(64))),&expected).is_err());
    }
    for field in 0..7 {
        let mut scope=expected.clone();
        match field {0=>scope.account_id="other".into(),1=>scope.agreement_id="other".into(),
            2=>scope.participant_id="other".into(),3=>scope.manifest_digest="c".repeat(64),
            4=>scope.history_read=false,5=>scope.authorization_export=true,_=>scope.preconstruction_export=false}
        assert!(validate_unpaired_delivery_receipt(Some((2,scope,"b".repeat(64))),&expected).is_err());
    }
    for bad in [String::new(),"b".repeat(63),"B".repeat(64),"g".repeat(64)] {
        assert!(validate_unpaired_delivery_receipt(Some((2,expected.clone(),bad)),&expected).is_err());
    }

    let proposal:wholepact_core::ProposalInput=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../wholepact-signer/src/native_ui/synthetic-proposal.json"))).unwrap();
    for index in [1,2] {
        assert!(matches!(delivery_peer_command(index,&proposal,true),C::DeliveryPeer(actual) if actual==index));
        assert!(matches!(delivery_peer_command(index,&proposal,false),C::OpenDelivery(actual,ref input) if actual==index && input==&proposal));
    }
    let account=proposal.manifest.participants[1].account_id.clone();
    let scope=expected_unpaired_delivery_scope(&proposal,&account).unwrap();
    assert_eq!(scope.account_id,account);
    assert_eq!(scope.participant_id,proposal.manifest.participants[1].participant_id);
    assert!(scope.history_read && !scope.authorization_export && scope.preconstruction_export);
    assert!(expected_unpaired_delivery_scope(&proposal,"absent-owner").is_err());
    let mut invalid_proposal=proposal.clone();invalid_proposal.proposal_id.clear();
    assert!(expected_unpaired_delivery_scope(&invalid_proposal,&account).is_err());
    let selector=worker::DeliveryReopenV2{version:2,root:PathBuf::from("/owned/synthetic/signers/two"),
        proposal:proposal.clone(),aggregate_budget_zatoshis:1_000_000,account_id:account.clone(),
        owner_setup_json:String::new(),original_directory_preserved:false};
    assert!(validate_unpaired_delivery_selector(&selector,&proposal,&account).is_ok());
    for field in 0..5 {
        let mut changed=selector.clone();
        match field {0=>changed.version=20,1=>changed.account_id="other".into(),
            2=>changed.proposal.proposal_id="other".into(),3=>changed.aggregate_budget_zatoshis+=1,
            _=>changed.original_directory_preserved=true}
        assert!(validate_unpaired_delivery_selector(&changed,&proposal,&account).is_err());
    }
    let root=Path::new("/owned/synthetic");
    let paths=[root.join("profile"),root.join("workspace"),root.join("financial"),root.join("signers/one"),root.join("signers/two")];
    assert!(validate_owned_paths(root,paths.each_ref().map(|p|p.as_path()),[true,false]).is_ok());
    for index in 0..5 {
        for bad in [root.to_path_buf(),root.join("../outside"),PathBuf::from("relative"),PathBuf::from("/other/place"),root.join("x".repeat(4097))] {
            let mut changed=paths.clone();changed[index]=bad;
            assert!(validate_owned_paths(root,changed.each_ref().map(|p|p.as_path()),[true,false]).is_err());
        }
    }
    let mut changed=paths.clone();changed[4]=changed[0].clone();
    assert!(validate_owned_paths(root,changed.each_ref().map(|p|p.as_path()),[true,false]).is_err());
    let mut changed=paths.clone();changed[4]=root.join("other/two");
    assert!(validate_owned_paths(root,changed.each_ref().map(|p|p.as_path()),[true,false]).is_err());
    for flags in [[false,false],[true,true]]{
        assert!(validate_owned_paths(root,paths.each_ref().map(|p|p.as_path()),flags).is_err());
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn continue_original_preexport(terminal:crate::terminal::Terminal,host:Host,
    mut original:initial::PrivateWorkspaceInitialV1,proposal:wholepact_core::ProposalInput,
    runtime:tokio::runtime::Runtime,provider:synthetic_born_provider_v1::SyntheticBornProviderV1,
    profile:PathBuf,workspace:PathBuf,financial:PathBuf,disclosures:Vec<OriginalDisclosureV2>,
    identity:FixedProposalIdentityV1,choices:DeliveryChoicesV2,wallet_setup:String)->Result<()> {
    let scenario=scenario_root()?;
    original.signers.send(C::DropUnselectedAnchor(0)).map_err(worker_error)?;done(&original.signers,0)?;
    let accounts=[original.born[1].account_id.clone(),original.born[2].account_id.clone()];
    let admission=export_owner(&terminal,&host,&original.signers,&mut original.witness,&workspace,&proposal,&disclosures,&identity,&choices,1,&accounts[0],false)?;
    // Open/close Owner2's genuine original source solely to preserve the exact
    // selector. It has NO reviewer export, delivery admission or signing result.
    let expected=expected_unpaired_delivery_scope(&proposal,&accounts[1])?;
    original.signers.send(C::OpenDelivery(2,proposal.clone())).map_err(worker_error)?;
    validate_unpaired_delivery_receipt(unpaired_delivery_receipt(original.signers.receive().map_err(worker_error)?),&expected)?;
    original.signers.send(C::PreserveDelivery(2)).map_err(worker_error)?;
    let second_original=preserved(&original.signers,2)?;
    validate_unpaired_delivery_selector(&second_original,&proposal,&accounts[1])?;
    let first=sign_and_intake(&host,&workspace,&original.signers,&mut original.witness,1,&admission,&wallet_setup,None,false,None)?;
    let progress=host.inspect_original_financial_progress_v2(&workspace)?;
    if progress.fixed_identity!=identity || progress.bound_accounts!=vec![accounts[0].clone()]
        || !progress.intaken_accounts.is_empty() || progress.exported_accounts!=vec![accounts[0].clone()]
        || progress.authorization_allowed || progress.distribution_allowed {return Err(Error::Authentication);}
    let (preintake_revision,preintake_history_digest)=host.qualification_original_financial_history_commitment_v2(&workspace)?;
    if preintake_revision!=progress.revision{return Err(Error::Authentication);}
    let provider_reopen=provider.preserve_financial_original_v2()?;
    original.signers.shutdown().map_err(worker_error)?;
    runtime.block_on(provider.shutdown()).map_err(Error::from)?;drop(runtime);
    let witness_reopen=original.witness.preserve_partial_financial_originals_v2(&accounts).map_err(authority)?;
    let ready=PartialReadyV2{version:2,profile,workspace,financial,proposal,identity,choices,disclosures,wallet_setup,
        first,second_original,witness_reopen,provider_reopen,saved_at_ms:now_ms()?,
        preintake_revision,preintake_progress_digest:digest(&progress)?,preintake_history_digest};
    let approval=terminal.approve_historical("SYNTHETIC DURABLE RESULT V2: only Owner1 has an exact retained result/outbox; NO Host intake or Return has happened; Owner2 is still unexported and unsigned. Preserve these same original encrypted sources and permit verified producer process death. No old writer or native grant is retained as authority.")?;
    approval.effect(&mut ||{ready.validate(&scenario)?;write_record(&scenario,READY,&ready)?;Ok(())})?;
    terminal.message(&format!("{DEATH}\n"))?;
    let _keep_originals=(&host,&original.temporary);
    loop{std::thread::park();}
}

#[allow(clippy::too_many_arguments)]
pub(super) fn continue_original_preexport_started(terminal:crate::terminal::Terminal,host:Host,
    mut original:initial::PrivateWorkspaceInitialV1,proposal:wholepact_core::ProposalInput,
    runtime:tokio::runtime::Runtime,provider:synthetic_born_provider_v1::SyntheticBornProviderV1,
    profile:PathBuf,workspace:PathBuf,financial:PathBuf,disclosures:Vec<OriginalDisclosureV2>,
    identity:FixedProposalIdentityV1,choices:DeliveryChoicesV2,wallet_setup:String)->Result<()> {
    let scenario=scenario_root()?;
    original.signers.send(C::DropUnselectedAnchor(0)).map_err(worker_error)?;done(&original.signers,0)?;
    let account=original.born[1].account_id.clone();
    let admission=export_owner(&terminal,&host,&original.signers,&mut original.witness,&workspace,&proposal,
        &disclosures,&identity,&choices,1,&account,false)?;
    // These original owners remain live until actual process death. No orderly
    // preservation claim or serialized service/grant is used for this case.
    let _keep_original_environment=(&runtime,&provider,&profile,&financial);
    let _unexpected=sign_and_intake(&host,&workspace,&original.signers,&mut original.witness,1,&admission,
        &wallet_setup,None,false,Some((&scenario,&identity)))?;
    Err(Error::Authentication)
}

// This process owns ONLY the first genuine Return/intake. Its armed Host
// hook parks after the real intake commit but before sending Finish ACK.
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn read_original_partial_intake_child(terminal:crate::terminal::Terminal)->Result<()> {
    let scenario=scenario_root()?;
    let ready:PartialReadyV2=read_record(&scenario,READY)?;ready.validate(&scenario)?;
    terminal.message(&format!("SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",scenario.join("durable-result-v2-intake-session.token").display()))?;
    let host=Host::open_workspace_dispatcher_registered_v4(terminal.clone(),&ready.profile,&ready.workspace,false)?;
    if host.financial.as_ref().ok_or(Error::Locked)?.current_directory()?!=ready.financial{return Err(Error::Authentication);}
    let mut witness=EphemeralNativeWitnessV1::reopen_partial_financial_originals_v2(&ready.witness_reopen).map_err(authority)?;
    let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let _provider=runtime.block_on(synthetic_born_provider_v1::SyntheticBornProviderV1::reopen_financial_original_v2(
        &ready.provider_reopen,synthetic_provider_tls_v1::child_server_config()?,private_fixed_v2::child_original_cutoff()?))?;
    let signers=worker::JoinedSignerWorkerV1::reopen_result_v2([
        Some(ready.first.original.clone()),Some(ready.second_original.clone())]).map_err(worker_error)?;
    let progress=host.inspect_original_financial_progress_v2(&ready.workspace)?;
    let first_account=&ready.first.result.request.account_id;
    if progress.fixed_identity!=ready.identity || !progress.intaken_accounts.is_empty()
        || progress.bound_accounts!=vec![first_account.clone()] || progress.exported_accounts!=vec![first_account.clone()]
        || progress.authorization_allowed || progress.distribution_allowed
        || progress.revision!=ready.preintake_revision || digest(&progress)?!=ready.preintake_progress_digest
    {return Err(Error::Authentication);}
    if host.qualification_original_financial_history_commitment_v2(&ready.workspace)?
        !=(ready.preintake_revision,ready.preintake_history_digest.clone()) {return Err(Error::Authentication);}
    let _server=witness.serve_completed_owner_history_v2().map_err(authority)?;
    let history=host.read_original_financial_history_v2(&ready.workspace,first_account,&ready.first.continuation.operation_id)?;
    if history.continuation_request()!=&ready.first.continuation
        || history.history_digest()!=ready.first.authenticated_history_digest
        || writer_evidence(&history)?!=(ready.first.original_writer_expiry_ms,ready.first.reservation_digest.clone())
    {return Err(Error::Authentication);}
    host.arm_durable_intake_ack_fault_v2(first_account,"durable-v2-intake-1",private_fixed_v2::child_original_cutoff()?)?;
    let _unexpected=return_exact(&host,&ready.workspace,&signers,1,ready.first.original.clone(),&history,Some(&ready.first.result),None)?;
    // A successful normal return would mean that the exact death boundary was
    // not taken; never report this as the ACK-loss subcase.
    Err(Error::Authentication)
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
// Local IPC Finish/Host intake only; NOT an independent recipient receipt.
struct CompletionV2 {
    version:u16,original_ready_digest:String,first_result_digest:String,first_outbox_digest:String,
    second_result_digest:String,transaction_digest:String,transaction_id:String,
    writer_expiry_observed_ms:u64,first_reservation_unchanged:bool,
    duplicate_intake_unchanged:bool,partial_completion_refused:bool,
    exact_two_owner_completion:bool,local_return_intake_finish_verified:bool,
    six_scoped_protocol_refusals_verified:bool,economic_proposal_verifier_succeeded:bool,
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn read_original_partial_child(terminal:crate::terminal::Terminal)->Result<()> {
    let scenario=scenario_root()?;
    let ready:PartialReadyV2=read_record(&scenario,READY)?;ready.validate(&scenario)?;
    let observed=now_ms()?;
    if observed<=ready.first.original_writer_expiry_ms{return Err(Error::Permission);}
    terminal.message(&format!("SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",scenario.join("durable-result-v2-reader-session.token").display()))?;
    let host=Host::open_workspace_dispatcher_registered_v4(terminal.clone(),&ready.profile,&ready.workspace,false)?;
    if host.financial.as_ref().ok_or(Error::Locked)?.current_directory()?!=ready.financial{return Err(Error::Authentication);}
    let mut witness=EphemeralNativeWitnessV1::reopen_partial_financial_originals_v2(&ready.witness_reopen).map_err(authority)?;
    let pair=Arc::new(PreservedDurablePairV2::verify([ready.first.original.clone(),ready.second_original.clone()])
        .map_err(|_|Error::Authentication)?);
    let cold_origin=witness.unfinished_origin_v2().map_err(authority)?;
    let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let provider=runtime.block_on(synthetic_born_provider_v1::SyntheticBornProviderV1::reopen_financial_original_v2(
        &ready.provider_reopen,synthetic_provider_tls_v1::child_server_config()?,private_fixed_v2::child_original_cutoff()?))?;
    let signers=worker::JoinedSignerWorkerV1::reopen_result_v2([
        Some(ready.first.original.clone()),Some(ready.second_original.clone())]).map_err(worker_error)?;
    let progress=host.inspect_original_financial_progress_v2(&ready.workspace)?;
    let first_account=&ready.first.result.request.account_id;
    if progress.fixed_identity!=ready.identity || progress.intaken_accounts!=vec![first_account.clone()]
        || progress.bound_accounts!=vec![first_account.clone()] || progress.exported_accounts!=vec![first_account.clone()]
        || progress.authorization_allowed || progress.distribution_allowed{return Err(Error::Authentication);}
    let revision=progress.revision;
    if revision!=ready.preintake_revision.checked_add(1).ok_or(Error::Authentication)? {
        return Err(Error::Authentication);
    }
    let committed_progress_digest=digest(&progress)?;
    let committed_history=host.qualification_original_financial_history_commitment_v2(&ready.workspace)?;
    if committed_history.0!=revision || committed_history.1==ready.preintake_history_digest{return Err(Error::Authentication);}
    // Genuine source-owned partial state reaches the real completed-only guard.
    // A one-owner signature set cannot be completed by a new read/effect grant.
    use crate::host::financial_diagnostics_v1 as fd;
    fd::reset_operation();
    let refused=host.complete_original_financial_transaction_v2(&ready.workspace,"durable-v2-premature-complete");
    let failure=fd::take_operation_failure().ok_or(Error::Authentication)?;
    if !matches!(refused,Err(Error::Receipt(ref message)) if message.starts_with("FINANCIAL_RETENTION_CONTEXTS:"))
        || failure.stage!=fd::FinancialStageV1::RetentionContexts
        || failure.component!=fd::FinancialComponentV1::Engine
        || failure.error_class!=fd::FinancialErrorClassV1::SignaturesIncomplete
        || failure.commit_state!=fd::FinancialCommitStateV1::NotEstablished
    {return Err(Error::Authentication);}
    let unchanged=host.inspect_original_financial_progress_v2(&ready.workspace)?;
    if unchanged.revision!=revision || unchanged.intaken_accounts!=progress.intaken_accounts{return Err(Error::Authentication);}
    let server=witness.serve_completed_owner_history_v2().map_err(authority)?;
    let history=host.read_original_financial_history_v2(&ready.workspace,first_account,&ready.first.continuation.operation_id)?;
    if history.continuation_request()!=&ready.first.continuation
        || history.history_digest()!=ready.first.authenticated_history_digest
        || writer_evidence(&history)?!=(ready.first.original_writer_expiry_ms,ready.first.reservation_digest.clone())
    {return Err(Error::Authentication);}
    // Re-deliver the same committed result under fresh separate Read/Return.
    // It is exact duplicate reconciliation, NOT a second Sign/Acquire attempt.
    let (first_selector,first_again)=return_exact(&host,&ready.workspace,&signers,1,ready.first.original.clone(),&history,Some(&ready.first.result),None)?;
    let duplicate=host.inspect_original_financial_progress_v2(&ready.workspace)?;
    if duplicate.revision!=revision || digest(&duplicate)?!=committed_progress_digest
        || host.qualification_original_financial_history_commitment_v2(&ready.workspace)?!=committed_history
    {return Err(Error::Authentication);}
    probe_result_grants(&host,&ready.workspace,&signers,&first_selector,&history,&first_again)?;
    let audited_after_probes=host.read_original_financial_history_v2(&ready.workspace,first_account,&ready.first.continuation.operation_id)?;
    if audited_after_probes.history_digest()!=ready.first.authenticated_history_digest
        || writer_evidence(&audited_after_probes)?!=(ready.first.original_writer_expiry_ms,ready.first.reservation_digest.clone())
    {return Err(Error::Authentication);}
    drop(audited_after_probes);drop(history);drop(server);
    let second_account=&ready.second_original.account_id;
    let admission=export_owner(&terminal,&host,&signers,&mut witness,&ready.workspace,&ready.proposal,
        &ready.disclosures,&ready.identity,&ready.choices,2,second_account,true)?;
    let second=sign_and_intake(&host,&ready.workspace,&signers,&mut witness,2,&admission,&ready.wallet_setup,Some((cold_origin,pair.clone())),true,None)?;
    if second.result.request.fixed!=ready.identity || second.result.request.account_id==*first_account
        || second.result.result_digest==first_again.result_digest{return Err(Error::Authentication);}
    let progress=host.inspect_original_financial_progress_v2(&ready.workspace)?;
    let expected=std::collections::BTreeSet::from([first_account.clone(),second_account.clone()]);
    if progress.intaken_accounts.iter().cloned().collect::<std::collections::BTreeSet<_>>()!=expected
        || progress.intaken_accounts.len()!=2 || progress.bound_accounts.len()!=2
        || progress.fixed_identity!=ready.identity{return Err(Error::Authentication);}
    let completed=host.complete_original_financial_transaction_v2(&ready.workspace,"durable-v2-exact-final-completion")?;
    if completed.exact_replay || !completed.cryptographic_transaction_verified || !completed.transaction_extracted
        || completed.chain_validated || completed.authorization_allowed || completed.distribution_allowed || completed.release_allowed
    {return Err(Error::Authentication);}
    let summary=host.verify_completed_private_financial_summary_v2(&ready.workspace,&ready.choices.submission_operation_id)?;
    if summary.fixed_identity!=serde_json::to_value(&ready.identity)?
        || summary.checkpoint_id!=completed.checkpoint_id || summary.transaction_digest!=completed.transaction_digest
        || summary.transaction_id!=completed.txid{return Err(Error::Authentication);}
    let pair=witness.serve_committed_completed_dispatch_pair_v1().map_err(authority)?;
    let original_history=host.read_original_financial_history_v2(&ready.workspace,first_account,&ready.first.continuation.operation_id)?;
    if original_history.history_digest()!=ready.first.authenticated_history_digest
        || writer_evidence(&original_history)?!=(ready.first.original_writer_expiry_ms,ready.first.reservation_digest.clone())
    {return Err(Error::Authentication);}
    drop(original_history);drop(pair);
    signers.shutdown().map_err(worker_error)?;
    runtime.block_on(provider.shutdown()).map_err(Error::from)?;drop(runtime);drop(witness);
    let result=CompletionV2{version:2,original_ready_digest:digest(&ready)?,first_result_digest:first_again.result_digest,
        first_outbox_digest:first_again.outbox_digest,second_result_digest:second.result.result_digest,
        transaction_digest:completed.transaction_digest,transaction_id:completed.txid,writer_expiry_observed_ms:observed,
        first_reservation_unchanged:true,duplicate_intake_unchanged:true,partial_completion_refused:true,
        exact_two_owner_completion:true,local_return_intake_finish_verified:true,
        six_scoped_protocol_refusals_verified:true,economic_proposal_verifier_succeeded:true};
    write_record(&scenario,FINISHED,&result)?;
    // Bounded public statement only; no private descriptor, PCZT or signatures.
    terminal.message("SYNTHETIC_DURABLE_RESULT_V2_READER_COMPLETE=1\n")
}

fn owner_inputs(inputs:&mut Vec<Input<'static>>){inputs.push(review("Inspect this exact original financial continuation and saved proof"));}
fn history_inputs(inputs:&mut Vec<Input<'static>>){owner_inputs(inputs);inputs.push(review("Read the complete authenticated original financial Witness history through the planned dispatcher"));}
fn progress_inputs(inputs:&mut Vec<Input<'static>>){owner_inputs(inputs);inputs.push(review("Read the exact original durable V2 progress only."));}
fn commitment_inputs(inputs:&mut Vec<Input<'static>>){
    owner_inputs(inputs);inputs.push(review("Read the exact original durable V2 history commitment only."));
}
fn export_inputs(inputs:&mut Vec<Input<'static>>){
    owner_inputs(inputs);
    inputs.push(review("Approve LOCAL exact-byte preparation for closed original delivery."));
    inputs.push(review("Request one native-approved redisclosure of this exact original material to this current paired recipient. No capture, reconstruction or validity renewal."));
    inputs.push(review("Inspect exact closed original export metadata for the actually prepared native recipient."));
    inputs.push(review("EXPORT EXACT ORIGINAL DELIVERY FOR DURABLE FINANCIAL V2"));
}
fn return_inputs(inputs:&mut Vec<Input<'static>>){
    owner_inputs(inputs);inputs.push(review("Read ONLY exact V2 retained-result preview metadata"));
    owner_inputs(inputs);inputs.push(review("Read the exact original financial fixed proof and existing intake lineage"));
    inputs.push(review("Verify and retain one actual authenticated original signer result"));
    inputs.push(review("Approve retain exact usable signatures for this EXACT scope?"));
    inputs.push(review("Prepare this ONE EXACT local signature intake"));
}
fn sign_inputs(inputs:&mut Vec<Input<'static>>,intake_now:bool){
    history_inputs(inputs);owner_inputs(inputs);
    inputs.push(review("Read this exact original saved fixed proof and the selected original financial continuation record."));
    inputs.push(review("Record this one authenticated owner financial continuation"));
    history_inputs(inputs);if intake_now{return_inputs(inputs);}history_inputs(inputs);
}
fn complete_inputs(inputs:&mut Vec<Input<'static>>, complete:bool){
    owner_inputs(inputs);inputs.push(review("Read and verify the exact two retained financial signer results and original proof."));
    inputs.push(review("Combine only the two exact retained original signature subsets"));
    if complete {
        for _ in 0..3{inputs.push(review("Approve retain exact usable signatures for this EXACT scope?"));}
        inputs.push(review("Approve extract/read and retain exact complete transaction for this EXACT scope?"));
    }
}
fn audit_inputs(inputs:&mut Vec<Input<'static>>){
    owner_inputs(inputs);inputs.push(review("Read and verify the exact completed original financial transaction and retained dispatch lineage"));
    for _ in 0..3{inputs.push(review("Approve retain exact usable signatures for this EXACT scope?"));}
    inputs.push(review("Approve extract/read and retain exact complete transaction for this EXACT scope?"));
}
fn preexport_inputs_v2()->Vec<Input<'static>>{
    let mut inputs=private_fixed_v2::producer_inputs();inputs.pop();
    for detail in [
        "Read exact current selected original source and complete historical terms for NONSPENDING private coordination.",
        "Open ONLY the exact initialized original private workspace.","Inspect exact original private V3 stage metadata.",
        "Approve V3 private fixed stage ReadFixed.","Store this exact new dispatcher credential only",
        "Inspect all original source/workspace/proof/financial/submission identities",
        "Authenticate the same final-v4 original workspace",
    ]{inputs.push(review(detail));}
    private_fixed_v2::session_inputs(&mut inputs,false);
    inputs.push(review("Inspect original fixed-prefix and bounded admission-export history metadata"));inputs
}
fn started_producer_inputs_v2()->Vec<Input<'static>>{
    let mut inputs=preexport_inputs_v2();export_inputs(&mut inputs);
    history_inputs(&mut inputs);owner_inputs(&mut inputs);
    inputs.push(review("Read this exact original saved fixed proof and the selected original financial continuation record."));
    inputs.push(review("Record this one authenticated owner financial continuation"));inputs
}
fn producer_inputs_v2()->Vec<Input<'static>>{
    let mut inputs=preexport_inputs_v2();
    export_inputs(&mut inputs);sign_inputs(&mut inputs,false);progress_inputs(&mut inputs);commitment_inputs(&mut inputs);
    inputs.push(review("SYNTHETIC DURABLE RESULT V2: only Owner1 has an exact retained result"));inputs
}
fn intake_inputs_v2()->Vec<Input<'static>>{
    let mut inputs=vec![Input::Text{prompt:"Storage passphrase: ",response:"synthetic-recovery-review-password"},
        Input::Text{prompt:"Original primary financial passphrase: ",response:"synthetic-recovery-review-password"},
        review("Authenticate the same final-v4 original workspace")];
    // Fresh OWNED non-signing session: this path performs separately approved local effects.
    private_fixed_v2::session_inputs(&mut inputs,false);
    progress_inputs(&mut inputs);commitment_inputs(&mut inputs);history_inputs(&mut inputs);return_inputs(&mut inputs);inputs
}
fn reader_inputs_v2()->Vec<Input<'static>>{
    let mut inputs=vec![Input::Text{prompt:"Storage passphrase: ",response:"synthetic-recovery-review-password"},
        Input::Text{prompt:"Original primary financial passphrase: ",response:"synthetic-recovery-review-password"},
        review("Authenticate the same final-v4 original workspace")];
    // Fresh OWNED non-signing session: this path performs separately approved local effects.
    private_fixed_v2::session_inputs(&mut inputs,false);
    progress_inputs(&mut inputs);commitment_inputs(&mut inputs);complete_inputs(&mut inputs,false);progress_inputs(&mut inputs);
    history_inputs(&mut inputs);return_inputs(&mut inputs);progress_inputs(&mut inputs);commitment_inputs(&mut inputs);
    for read_probe in [true,true,true,false,false,false] {
        progress_inputs(&mut inputs);commitment_inputs(&mut inputs);
        if read_probe {owner_inputs(&mut inputs);inputs.push(review("Read ONLY exact V2 retained-result preview metadata"));}
        else {return_inputs(&mut inputs);}
        progress_inputs(&mut inputs);commitment_inputs(&mut inputs);
    }
    history_inputs(&mut inputs);
    export_inputs(&mut inputs);sign_inputs(&mut inputs,true);progress_inputs(&mut inputs);
    complete_inputs(&mut inputs,true);audit_inputs(&mut inputs);history_inputs(&mut inputs);inputs
}

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn death_marker_v2(tail:&str,producer:bool,complete:bool,terminal:bool)->io::Result<bool>{
    if tail.lines().any(|line|matches!(line.trim_end_matches('\r'),
        "SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1"|"SYNTHETIC_DURABLE_DELIVERY_ADMITTED_V2=1"|"SYNTHETIC_DURABLE_FINANCIAL_COMPLETED_V1=1")){
        return Err(invalid());
    }
    let count=tail.split_inclusive('\n').filter(|line|line.ends_with('\n')&&line.trim_end_matches(['\r','\n'])==DEATH).count();
    if count>1 || (count==1&&(!producer||!complete)){return Err(invalid());}
    if terminal&&producer {
        let remainder=tail.rsplit_once('\n').map_or(tail,|(_,rest)|rest);
        if count!=1 || (!remainder.is_empty()&&(DEATH.starts_with(remainder)||remainder.starts_with(DEATH))){return Err(invalid());}
    }
    Ok(count==1)
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn intake_death_marker_v2(tail:&str,complete:bool,terminal:bool)->io::Result<bool>{
    if tail.lines().any(|line|matches!(line.trim_end_matches('\r'),
        "SYNTHETIC_DURABLE_RESULT_PARTIAL_V2=1"|"SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1"|
        "SYNTHETIC_DURABLE_DELIVERY_ADMITTED_V2=1"|"SYNTHETIC_DURABLE_FINANCIAL_COMPLETED_V1=1")){
        return Err(invalid());
    }
    let count=tail.split_inclusive('\n').filter(|line|line.ends_with('\n')&&line.trim_end_matches(['\r','\n'])==INTAKE_DEATH).count();
    if count>1 || (count==1&&!complete){return Err(invalid());}
    if terminal {
        let remainder=tail.rsplit_once('\n').map_or(tail,|(_,rest)|rest);
        if count!=1 || (!remainder.is_empty()&&(INTAKE_DEATH.starts_with(remainder)||remainder.starts_with(INTAKE_DEATH))){return Err(invalid());}
    }
    Ok(count==1)
}
#[test]
fn intake_death_marker_requires_exact_committed_ack_boundary(){
    assert!(!intake_death_marker_v2(INTAKE_DEATH,true,false).unwrap());
    assert!(intake_death_marker_v2(INTAKE_DEATH,true,true).is_err());
    let line=format!("{INTAKE_DEATH}\n");
    assert!(intake_death_marker_v2(&line,true,true).unwrap());
    assert!(intake_death_marker_v2(&line,false,false).is_err());
    assert!(intake_death_marker_v2(&line.repeat(2),true,true).is_err());
    assert!(intake_death_marker_v2(&format!("{DEATH}\n"),true,true).is_err());
}
#[test]
fn partial_death_marker_cannot_promote_old_profile_or_partial_line(){
    assert!(!death_marker_v2(DEATH,true,true,false).unwrap());
    assert!(death_marker_v2(DEATH,true,true,true).is_err());
    let line=format!("{DEATH}\n");
    assert!(death_marker_v2(&line,true,true,true).unwrap());
    assert!(death_marker_v2(&line,false,true,false).is_err());
    assert!(death_marker_v2(&line,true,false,false).is_err());
    assert!(death_marker_v2(&line.repeat(2),true,true,true).is_err());
    assert!(death_marker_v2("SYNTHETIC_DURABLE_FINANCIAL_COMPLETED_V1=1\n",true,true,true).is_err());
}
// Failure-only projection of already returned controller data. No source reads,
// clock observations, authority decisions, raw error strings or PTY text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all="kebab-case")]
enum FailureCaseV2 { DurableResume, DurableStarted }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all="snake_case")]
enum FailureSiteV2 {
    CorePolicy, ChildWaitPolicy, Cutoff, TemporaryRoot, TlsPrepare,
    A0Producer, A0ReadyRead, A0ReadyValidate, A1Intake, WriterExpiryWait,
    A2Reader, A2ReadyRead, A2CompletionRead, A2FinalVerify,
    BProducer, BReadyRead, BReadyValidate, BReader, BReadyReread,
    BCompletionRead, BFinalVerify, TemporaryCleanup, PublicReceipt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all="snake_case")]
enum FailureReasonV2 { IoError, StageCallError, StageOutcomeError, ProcessCleanupUnverified,
    ExpectedProcessStatus, StageDeadline, Verification, CleanupUnverified }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all="snake_case")]
enum FailureCleanupV2 { NotStarted, RootUnavailable, ClosedAbsent, CloseUnverified }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all="snake_case")]
enum ExpectedProcessV2 { Sigkill, Success }
#[derive(Clone, Serialize)]
struct FailureDeliveryV2 { boundary:&'static str, outcome:&'static str }
#[derive(Clone, Serialize)]
struct FailureFinancialV2 {
    stage:crate::host::financial_diagnostics_v1::FinancialStageV1,
    component:crate::host::financial_diagnostics_v1::FinancialComponentV1,
    error_class:crate::host::financial_diagnostics_v1::FinancialErrorClassV1,
    commit_state:crate::host::financial_diagnostics_v1::FinancialCommitStateV1,
}
#[derive(Clone, Serialize)]
struct FailureStageV2 {
    failure_reason:&'static str, next:usize, expected:usize, expected_process:ExpectedProcessV2,
    group_signal:&'static str, group_absence:&'static str, direct_child:&'static str,
    status_kind:&'static str, status_value:Option<i32>, diagnostic_state:&'static str,
    private_fixed_primary:Option<crate::host::financial::private_durable_fixed_v2::PrivateDiagnosticPrimaryV1>,
    delivery_first_failure:Option<FailureDeliveryV2>,
    financial_first_failure:Option<FailureFinancialV2>,
    fatal_observation:fatal_output_v2::Observation,
}
#[derive(Clone, Serialize)]
struct FailureRecordV2 {
    schema:u8, case:FailureCaseV2, callsite:FailureSiteV2, reason:FailureReasonV2,
    io_kind:&'static str, stage:Option<FailureStageV2>, cleanup:FailureCleanupV2,
}
struct FailureTrackerV2 {
    case:FailureCaseV2, current:FailureSiteV2, reason:FailureReasonV2,
    first:Option<FailureRecordV2>, cleanup:FailureCleanupV2,
}
fn failure_io_kind_v2(error:&io::Error)->&'static str {
    use io::ErrorKind as K;
    match error.kind() {
        K::NotFound=>"not_found",K::PermissionDenied=>"permission_denied",
        K::ConnectionRefused|K::ConnectionReset|K::ConnectionAborted|K::NotConnected|K::BrokenPipe=>"connection",
        K::InvalidInput=>"invalid_input",K::InvalidData=>"invalid_data",K::TimedOut=>"timed_out",
        K::Interrupted=>"interrupted",K::UnexpectedEof=>"unexpected_eof",K::WouldBlock=>"would_block",
        _=>"other",
    }
}
fn harness_reason_v2(reason:HarnessFailureReason)->&'static str {
    use HarnessFailureReason::*;
    match reason {
        Unclassified=>"Unclassified",Deadline=>"Deadline",ChildObservation=>"ChildObservation",
        ChildExit=>"ChildExit",PollIo=>"PollIo",ReadIo=>"ReadIo",OutputLimit=>"OutputLimit",
        IncompleteUtf8=>"IncompleteUtf8",InvalidUtf8=>"InvalidUtf8",MultilineInput=>"MultilineInput",
        WriteIo=>"WriteIo",FlushIo=>"FlushIo",MissingPathMarker=>"MissingPathMarker",
        InvalidPath=>"InvalidPath",InvalidChallenge=>"InvalidChallenge",OutcomeRead=>"OutcomeRead",
        CleanupUnverified=>"CleanupUnverified",FinancialPhaseDeadline=>"FinancialPhaseDeadline",
        FinancialProgressInvalid=>"FinancialProgressInvalid",
    }
}
fn failure_stage_v2(stage:&PrivateWorkspaceStageResultV1, expected:ExpectedProcessV2)->FailureStageV2 {
    use owned_test_process_group_v1::{GroupSignalV1 as S,GroupAbsenceV1 as A,DirectChildV1 as C};
    let (status_kind,status_value)=match stage.process.status.as_ref() {
        None=>("absent",None),
        Some(status)=>match (status.code(),status.signal()) {
            (Some(code),_) if (0..=255).contains(&code)=>("exit",Some(code)),
            (_,Some(signal)) if (1..=64).contains(&signal)=>("signal",Some(signal)),
            _=>("other",None),
        },
    };
    // The unchanged shared controller already validates and gates this value.
    // Revalidation is pure and never makes an unverified process diagnostic public.
    let trusted=stage.process.verified();
    let primary=if trusted && !stage.diagnostic_withheld {
        stage.private_fixed_diagnostic.as_ref().filter(|d|d.canonical_json().is_some()).map(|d|d.primary.clone())
    } else {None};
    let delivery_first_failure=if trusted {stage.delivery_first_failure.map(|d|{
        let (boundary,outcome)=d.labels();FailureDeliveryV2{boundary,outcome}
    })} else {None};
    let financial_first_failure=if trusted && !stage.diagnostic_withheld {
        stage.financial_diagnostic.as_ref().filter(|d|d.is_valid_v1()).map(|d|FailureFinancialV2 {
            stage:d.stage,component:d.component,error_class:d.error_class,commit_state:d.commit_state,
        })
    } else {None};
    let diagnostic_state=if primary.is_some() || financial_first_failure.is_some(){"validated"}
        else if !trusted || stage.diagnostic_withheld || stage.private_fixed_diagnostic.is_some() || stage.financial_diagnostic.is_some(){"withheld"}
        else {"unavailable"};
    FailureStageV2 {
        failure_reason:harness_reason_v2(stage.failure_reason),next:stage.next,expected:stage.expected,
        expected_process:expected,
        group_signal:match stage.process.group_signal {S::SentWhileLeaderOwned=>"SentWhileLeaderOwned",S::AlreadyAbsentWhileLeaderOwned=>"AlreadyAbsentWhileLeaderOwned",S::Unverified=>"Unverified"},
        group_absence:match stage.process.group_absence {A::OriginalGroupAbsentObserved=>"OriginalGroupAbsentObserved",A::Unverified=>"Unverified"},
        direct_child:match stage.process.direct_child {C::Reaped=>"Reaped",C::Unverified=>"Unverified"},
        status_kind,status_value,diagnostic_state,private_fixed_primary:primary,delivery_first_failure,financial_first_failure,
        fatal_observation:stage.fatal_observation.for_process(trusted),
    }
}
impl FailureTrackerV2 {
    fn new(case:FailureCaseV2)->Self {Self{case,current:FailureSiteV2::CorePolicy,
        reason:FailureReasonV2::IoError,first:None,cleanup:FailureCleanupV2::NotStarted}}
    fn enter(&mut self,site:FailureSiteV2,reason:FailureReasonV2){self.current=site;self.reason=reason;}
    fn record(&mut self,site:FailureSiteV2,reason:FailureReasonV2,error:&io::Error,stage:Option<FailureStageV2>){
        if self.first.is_none(){self.first=Some(FailureRecordV2{schema:1,case:self.case,callsite:site,
            reason,io_kind:failure_io_kind_v2(error),stage,cleanup:self.cleanup});}
    }
    fn observe<T>(&mut self,site:FailureSiteV2,result:io::Result<T>)->io::Result<T>{
        if let Err(error)=&result{self.record(site,FailureReasonV2::IoError,error,None);}result
    }
    fn stage_call(&mut self,site:FailureSiteV2,result:io::Result<PrivateWorkspaceStageResultV1>)->io::Result<PrivateWorkspaceStageResultV1>{
        if let Err(error)=&result{self.record(site,FailureReasonV2::StageCallError,error,None);}result
    }
    fn capture<T>(&mut self,result:&io::Result<T>){
        if let Err(error)=result{self.record(self.current,self.reason,error,None);}
    }
    fn check_stage(&mut self,site:FailureSiteV2,stage:&PrivateWorkspaceStageResultV1,
        expected:ExpectedProcessV2,expired:impl FnOnce()->bool)->io::Result<()> {
        // Exactly the old predicate order. In particular the existing reader
        // clock is called only after outcome/cleanup/status checks succeeded.
        let reason=if stage.outcome.is_err(){Some(FailureReasonV2::StageOutcomeError)}
        else if !stage.process.verified(){Some(FailureReasonV2::ProcessCleanupUnverified)}
        else if match expected {
            ExpectedProcessV2::Sigkill=>stage.process.group_signal!=owned_test_process_group_v1::GroupSignalV1::SentWhileLeaderOwned
                || !stage.process.status.as_ref().is_some_and(|s|s.signal()==Some(libc::SIGKILL)),
            ExpectedProcessV2::Success=>!stage.process.status.as_ref().is_some_and(|s|s.success()),
        } {Some(FailureReasonV2::ExpectedProcessStatus)}
        else if expired(){Some(FailureReasonV2::StageDeadline)}else{None};
        if let Some(reason)=reason{
            let error=invalid();
            // Preserve the returned controller error KIND without exposing its
            // message; the outer Result remains the same original invalid().
            let cause=stage.outcome.as_ref().err().unwrap_or(&error);
            self.record(site,reason,cause,Some(failure_stage_v2(stage,expected)));Err(error)
        }else{Ok(())}
    }
    fn closed(&mut self,outcome:TemporaryRootCleanupV1){
        self.cleanup=match outcome {
            TemporaryRootCleanupV1::ClosedAndAbsenceVerified=>FailureCleanupV2::ClosedAbsent,
            TemporaryRootCleanupV1::RetainedForUnverifiedProcess=>FailureCleanupV2::RootUnavailable,
            TemporaryRootCleanupV1::CloseOrAbsenceUnverified=>FailureCleanupV2::CloseUnverified,
        };
        if let Some(first)=self.first.as_mut(){first.cleanup=self.cleanup;}
    }
    fn emit(&self,output:&mut impl io::Write){
        if let Some(first)=&self.first {
            if let Ok(json)=serde_json::to_string(first){
                let _=writeln!(output,"CI_SYNTHETIC_DURABLE_FAILURE_V2 {json}");
            }
        }
    }
}
fn failure_boundary_v2<T>(case:FailureCaseV2,output:&mut impl io::Write,
    operation:impl FnOnce(&mut FailureTrackerV2)->io::Result<T>)->io::Result<T>{
    let mut report=FailureTrackerV2::new(case);let result=operation(&mut report);
    report.capture(&result);if result.is_err(){report.emit(output);}result
}

#[derive(Serialize)]
struct PublicV2 {
    profile:&'static str,producer_killed_reaped_group_absent:bool,
    signer_result_preintake_checkpoint_verified:bool,intake_ack_child_killed_reaped_group_absent:bool,
    observed_original_writer_expiry:bool,first_result_outbox_unchanged:bool,
    first_exposure_unchanged:bool,counterpart_unsigned_at_death:bool,
    fresh_second_owner_completed:bool,exact_union_extraction_verified:bool,
    local_read_return_intake_finish_verified:bool,reader_reaped_group_absent:bool,
    six_scoped_protocol_refusals_verified:bool,economic_proposal_verifier_succeeded:bool,
    cleanup_verified:bool,native_runtime_executed:bool,live_funds:bool,
}
#[test]
#[ignore="Approved capable isolated Linux native runner only; local AF_UNIX is unavailable"]
fn original_two_owner_durable_results_resume_unfinished_counterpart_v2(){
    run_process_lifecycle_v2().expect("exact first result survives actual writer expiry and producer death before genuine counterpart completion; no network submission");
}
fn run_process_lifecycle_v2()->io::Result<()> {
    failure_boundary_v2(FailureCaseV2::DurableResume, &mut io::stdout(), run_process_lifecycle_v2_observed)
}
fn run_process_lifecycle_v2_observed(report:&mut FailureTrackerV2)->io::Result<()> {
    report.observe(FailureSiteV2::CorePolicy,process_containment_v1::require_and_report_core_policy())?;
    report.observe(FailureSiteV2::ChildWaitPolicy,owned_test_process_group_v1::require_default_child_wait_policy())?;
    let deadline=Instant::now()+LIMIT;
    let cutoff=report.observe(FailureSiteV2::Cutoff,(||{
        monotonic_now_ns()?.checked_add(deadline.saturating_duration_since(Instant::now()).as_nanos().try_into().map_err(|_|invalid())?).ok_or_else(invalid)
    })())?;
    let mut root=Some(report.observe(FailureSiteV2::TemporaryRoot,tempfile::Builder::new().prefix(CHILD_TEMPORARY_PREFIX).permissions(std::fs::Permissions::from_mode(0o700)).tempdir())?);
    let mut public=PublicV2{profile:"durable-result-lifecycle-v2",producer_killed_reaped_group_absent:false,
        signer_result_preintake_checkpoint_verified:false,intake_ack_child_killed_reaped_group_absent:false,
        observed_original_writer_expiry:false,first_result_outbox_unchanged:false,first_exposure_unchanged:false,
        counterpart_unsigned_at_death:false,fresh_second_owner_completed:false,exact_union_extraction_verified:false,
        local_read_return_intake_finish_verified:false,reader_reaped_group_absent:false,
        six_scoped_protocol_refusals_verified:false,economic_proposal_verifier_succeeded:false,cleanup_verified:false,native_runtime_executed:false,live_funds:false};
    let workflow=(||->io::Result<()>{
        let tls=report.observe(FailureSiteV2::TlsPrepare,synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(root.as_ref().unwrap().path()))?;
        let mut producer=report.stage_call(FailureSiteV2::A0Producer,private_workspace_stage_v1(root.take().unwrap(),Some(&tls),PrivateWorkspaceStageV1::DurableResultProducer,&producer_inputs_v2(),deadline,cutoff))?;
        root=producer.root.take();
        report.check_stage(FailureSiteV2::A0Producer,&producer,ExpectedProcessV2::Sigkill,||false)?;
        public.producer_killed_reaped_group_absent=true;
        public.native_runtime_executed=true;
        report.enter(FailureSiteV2::A0ReadyRead,FailureReasonV2::IoError);
        let ready:PartialReadyV2=read_record(root.as_ref().ok_or_else(invalid)?.path(),READY)?;
        report.enter(FailureSiteV2::A0ReadyValidate,FailureReasonV2::Verification);
        ready.validate(root.as_ref().unwrap().path())?;
        public.counterpart_unsigned_at_death=true; // actual producer+pristine source audit, not a count
        public.signer_result_preintake_checkpoint_verified=true;
        // Same genuine originals, now commit the first Host intake but lose its
        // Finish ACK through actual supervised process death. No Sign is called.
        let mut intake=report.stage_call(FailureSiteV2::A1Intake,private_workspace_stage_v1(root.take().unwrap(),Some(&tls),PrivateWorkspaceStageV1::DurableResultIntake,&intake_inputs_v2(),deadline,cutoff))?;
        root=intake.root.take();
        report.check_stage(FailureSiteV2::A1Intake,&intake,ExpectedProcessV2::Sigkill,||false)?;
        public.intake_ack_child_killed_reaped_group_absent=true;
        // The only deliberate human-delay simulation is AFTER authenticated
        // writer expiry was captured and the original group was killed/reaped.
        report.enter(FailureSiteV2::WriterExpiryWait,FailureReasonV2::IoError);
        loop {
            if Instant::now()>=deadline{return Err(invalid());}
            let now=now_ms().map_err(|_|invalid())?;
            if now>ready.first.original_writer_expiry_ms{break;}
            std::thread::sleep(Duration::from_millis((ready.first.original_writer_expiry_ms-now+1).min(100)));
        }
        let mut reader=report.stage_call(FailureSiteV2::A2Reader,private_workspace_stage_v1(root.take().unwrap(),Some(&tls),PrivateWorkspaceStageV1::DurableResultReader,&reader_inputs_v2(),deadline,cutoff))?;
        root=reader.root.take();
        report.check_stage(FailureSiteV2::A2Reader,&reader,ExpectedProcessV2::Success,||Instant::now()>=deadline)?;
        public.reader_reaped_group_absent=true;
        report.enter(FailureSiteV2::A2ReadyRead,FailureReasonV2::IoError);
        let path=root.as_ref().ok_or_else(invalid)?.path();
        let after:PartialReadyV2=read_record(path,READY)?;
        report.enter(FailureSiteV2::A2CompletionRead,FailureReasonV2::IoError);
        let finished:CompletionV2=read_record(path,FINISHED)?;
        report.enter(FailureSiteV2::A2FinalVerify,FailureReasonV2::Verification);
        if digest(&ready).map_err(|_|invalid())?!=digest(&after).map_err(|_|invalid())?
            || finished.version!=2 || finished.original_ready_digest!=digest(&ready).map_err(|_|invalid())?
            || finished.first_result_digest!=ready.first.result.result_digest || finished.first_outbox_digest!=ready.first.result.outbox_digest
            || finished.writer_expiry_observed_ms<=ready.first.original_writer_expiry_ms
            || !finished.first_reservation_unchanged || !finished.duplicate_intake_unchanged || !finished.partial_completion_refused
            || !finished.exact_two_owner_completion || !finished.local_return_intake_finish_verified
            || !finished.six_scoped_protocol_refusals_verified || !finished.economic_proposal_verifier_succeeded
            || !hash(&finished.second_result_digest) || !hash(&finished.transaction_digest) || !hash(&finished.transaction_id)
        {return Err(invalid());}
        public.observed_original_writer_expiry=true;public.first_result_outbox_unchanged=true;
        public.first_exposure_unchanged=true;public.fresh_second_owner_completed=true;
        public.exact_union_extraction_verified=true;public.local_read_return_intake_finish_verified=true;
        public.six_scoped_protocol_refusals_verified=true;public.economic_proposal_verifier_succeeded=true;
        drop(tls);Ok(())
    })();
    report.capture(&workflow);
    if let Some(root)=root.take(){let closed=close_owned_temporary_root(root);public.cleanup_verified=matches!(closed,TemporaryRootCleanupV1::ClosedAndAbsenceVerified);report.closed(closed);}
    else {report.closed(TemporaryRootCleanupV1::RetainedForUnverifiedProcess);}
    report.enter(FailureSiteV2::PublicReceipt,FailureReasonV2::IoError);
    println!("CI_SYNTHETIC_DURABLE_RESULT_V2 {}",serde_json::to_string(&public).map_err(|_|invalid())?);
    workflow?;
    report.enter(FailureSiteV2::TemporaryCleanup,FailureReasonV2::CleanupUnverified);
    if !public.cleanup_verified{return Err(invalid());}Ok(())
}

// The unrelated peer owns no source, review, credential or private payload.
// It is an exact separately spawned child, never another same-PID socket.
struct DistinctPeerV2 {
    group:Option<owned_test_process_group_v1::OwnedTestProcessGroupV1>,
    // PDEATHSIG follows the spawning thread: this owner cannot move to another
    // thread, and its actual caller remains alive through explicit cleanup.
    _same_thread:std::marker::PhantomData<std::rc::Rc<()>>,
}
impl DistinctPeerV2 {
    fn open(deadline:Instant)->io::Result<(Self,std::os::unix::net::UnixStream)> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let scenario=scenario_root().map_err(|_|invalid())?;
        let root=tempfile::Builder::new().prefix("peer-").permissions(std::fs::Permissions::from_mode(0o700)).tempdir_in(&scenario)?;
        let socket=root.path().join("peer.sock");
        let listener=std::os::unix::net::UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        let cutoff=std::env::var("WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS").map_err(|_|invalid())?;
        let mut command=std::process::Command::new(std::env::current_exe()?);
        command.args(["--exact",CHILD,"--ignored","--nocapture","--test-threads=1"])
            .env(CHILD_ENV,"durable-result-v2-peer").env("TMPDIR",root.path())
            .env("WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS",cutoff)
            .env_remove("DISPLAY").env_remove("WAYLAND_DISPLAY")
            .env_remove("SSL_CERT_FILE").env_remove("SSL_CERT_DIR")
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        let expected_parent=std::process::id() as libc::pid_t;
        unsafe { command.pre_exec(move || {
            if libc::getppid()!=expected_parent{return Err(io::Error::from_raw_os_error(libc::ECHILD));}
            if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong,0 as libc::c_ulong)!=0{return Err(io::Error::last_os_error());}
            if libc::getppid()!=expected_parent{return Err(io::Error::from_raw_os_error(libc::ECHILD));}
            if libc::setsid()<0 {return Err(io::Error::last_os_error());}Ok(())
        }); }
        if Instant::now()>=deadline{return Err(invalid());}
        let child=match owned_test_process_group_v1::spawn_with_checked_wait_policy(&mut command) {
            Ok(child)=>child,
            Err(error)=>{drop(listener);let _=root.keep();return Err(error);}
        };
        let pid=child.id();drop(command);
        let mut owner=Self{group:Some(owned_test_process_group_v1::OwnedTestProcessGroupV1::from_spawned_session(child,root)),
            _same_thread:std::marker::PhantomData};
        let accepted=(||->io::Result<std::os::unix::net::UnixStream>{
            let mut stream=loop {
                if Instant::now()>=deadline || owner.group.as_mut().ok_or_else(invalid)?.observe_exit()?.is_some(){return Err(invalid());}
                match listener.accept(){Ok((stream,_))=>break stream,Err(e) if e.kind()==io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(2)),Err(e)=>return Err(e)}
            };
            let mut credentials=std::mem::MaybeUninit::<libc::ucred>::uninit();
            let mut size=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if unsafe{libc::getsockopt(stream.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,credentials.as_mut_ptr().cast(),&mut size)}!=0
                || size as usize!=std::mem::size_of::<libc::ucred>() {return Err(invalid());}
            let credentials=unsafe{credentials.assume_init()};
            if credentials.pid<=0 || credentials.pid as u32!=pid || pid==std::process::id(){return Err(invalid());}
            // Existing owned-child wait retains its PID anchor; the real native
            // probe independently observes the stream's pidfd/process instance.
            if owner.group.as_mut().ok_or_else(invalid)?.observe_exit()?.is_some(){return Err(invalid());}
            stream.set_read_timeout(Some(deadline.checked_duration_since(Instant::now()).ok_or_else(invalid)?))?;
            let mut hello=[0u8;1];stream.read_exact(&mut hello)?;
            if hello!=[0x7e]{return Err(invalid());}
            stream.set_read_timeout(None)?;
            Ok(stream)
        })();
        drop(listener);
        match accepted {Ok(stream)=>Ok((owner,stream)),Err(error)=>{owner.finish()?;Err(error)}}
    }
    fn finish(mut self)->io::Result<()> {
        let finished=self.group.take().ok_or_else(invalid)?.finish();
        if !finished.process.verified(){return Err(invalid());}
        let root=finished.root_for_explicit_close.ok_or_else(invalid)?;
        if !matches!(close_owned_temporary_root(root),TemporaryRootCleanupV1::ClosedAndAbsenceVerified){return Err(invalid());}
        Ok(())
    }
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn hold_distinct_peer_child()->Result<()> {
    use std::io::Write;
    let root=scenario_root()?;
    let deadline=private_fixed_v2::child_original_cutoff()?;
    if Instant::now()>=deadline{return Err(Error::Permission);}
    let mut stream=std::os::unix::net::UnixStream::connect(root.join("peer.sock"))?;
    stream.set_write_timeout(Some(deadline.checked_duration_since(Instant::now()).ok_or(Error::Permission)?))?;
    stream.write_all(&[0x7e])?;
    while Instant::now()<deadline {std::thread::sleep(Duration::from_millis(5));}
    // Peer liveness beyond the original bound is not available to the probe.
    Err(Error::Permission)
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct StartedReadyV2 {
    version:u16,custody:StartedFinancialCustodyV2,fixed:FixedProposalIdentityV1,continuation:OwnerControlRequest,
}
impl StartedReadyV2 {
    fn validate(&self,root:&Path)->io::Result<()> {
        self.custody.validate_owned_root(root).map_err(|_|invalid())?;
        if self.version!=2 || self.custody.account_id!=self.continuation.account_id
            || self.custody.proposal.proposal_id!=self.fixed.proposal_id {return Err(invalid());}
        let OwnerControl::AdmitFinancialContinuationV1{record}=&self.continuation.control else{return Err(invalid())};
        record.validate_request(&self.continuation,&record.terms.scope.witness).map_err(|_|invalid())?;
        if self.custody.authorization_id!=record.terms.scope.authorization.authorization_id
            || serde_json::to_value(&record.terms.scope.authorization.fixed).map_err(|_|invalid())?
                !=serde_json::to_value(&self.fixed).map_err(|_|invalid())? {return Err(invalid());}
        Ok(())
    }
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct StartedAuditV2 {
    account_id:String,authorization_id:String,original_rows_digest:String,continuation_history_digest:String,
    started_count:u64,result_count:u64,outbox_count:u64,retained_exposure_state:String,
}
impl StartedAuditV2 {
    fn validate(&self,ready:&StartedReadyV2)->Result<()> {
        if self.account_id!=ready.custody.account_id || self.authorization_id!=ready.custody.authorization_id
            || !hash(&self.original_rows_digest) || !hash(&self.continuation_history_digest)
            || self.started_count!=1 || self.result_count!=0 || self.outbox_count!=0
            || self.retained_exposure_state!="outstanding_uncertain" {return Err(Error::Authentication);}
        Ok(())
    }
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct StartedCompletionV2 {version:u16,original_ready_digest:String,audit:StartedAuditV2}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn read_started_original_child(terminal:crate::terminal::Terminal)->Result<()> {
    let root=scenario_root()?;
    let ready:StartedReadyV2=read_record(&root,STARTED_READY)?;ready.validate(&root)?;
    let audit=wholepact_signer::native_ui::synthetic_born_joined_qualification::audit_started_after_restart_v2(
        ready.custody.clone(),private_fixed_v2::child_original_cutoff()?).map_err(|_|Error::Authentication)?;
    if audit.is_empty() || audit.len()>64*1024{return Err(Error::Invalid);}
    let audit:StartedAuditV2=serde_json::from_str(&audit)?;audit.validate(&ready)?;
    // The actual native reopen/source helper itself checks exact Uncertain
    // selection and identical protected rows before/after that failed read.
    let finished=StartedCompletionV2{version:2,original_ready_digest:digest(&ready)?,audit};
    write_record(&root,STARTED_FINISHED,&finished)?;
    terminal.message("SYNTHETIC_DURABLE_STARTED_UNCERTAIN_REOPEN_V2=1\n")
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn started_death_marker_v2(tail:&str,producer:bool,complete:bool,terminal:bool)->io::Result<bool>{
    if tail.lines().any(|line|matches!(line.trim_end_matches('\r'),
        "SYNTHETIC_DURABLE_RESULT_PARTIAL_V2=1"|"SYNTHETIC_DURABLE_RESULT_INTAKE_ACK_PENDING_V2=1"|
        "SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1"|"SYNTHETIC_DURABLE_DELIVERY_ADMITTED_V2=1"|
        "SYNTHETIC_DURABLE_FINANCIAL_COMPLETED_V1=1")) {return Err(invalid());}
    let count=tail.split_inclusive('\n').filter(|line|line.ends_with('\n')&&line.trim_end_matches(['\r','\n'])==STARTED_DEATH).count();
    if count>1 || (count==1&&(!producer||!complete)){return Err(invalid());}
    if terminal&&producer {
        let remainder=tail.rsplit_once('\n').map_or(tail,|(_,rest)|rest);
        if count!=1 || (!remainder.is_empty()&&(STARTED_DEATH.starts_with(remainder)||remainder.starts_with(STARTED_DEATH))){return Err(invalid());}
    }
    Ok(count==1)
}
#[test]
fn started_death_marker_cannot_claim_result_or_unterminated_line(){
    assert!(!started_death_marker_v2(STARTED_DEATH,true,true,false).unwrap());
    assert!(started_death_marker_v2(STARTED_DEATH,true,true,true).is_err());
    let line=format!("{STARTED_DEATH}\n");
    assert!(started_death_marker_v2(&line,true,true,true).unwrap());
    assert!(started_death_marker_v2(&line,false,true,false).is_err());
    assert!(started_death_marker_v2(&line,true,false,false).is_err());
    assert!(started_death_marker_v2(&line.repeat(2),true,true,true).is_err());
    assert!(started_death_marker_v2(&format!("{DEATH}\n"),true,true,true).is_err());
}
#[test]
#[ignore="Approved capable isolated Linux native runner only; local AF_UNIX is unavailable"]
fn original_financial_started_without_result_remains_uncertain_after_process_death_v2(){
    run_started_process_lifecycle_v2().expect("genuine Started commit survives actual death as uncertainty with no result/outbox or repeat signing");
}
fn run_started_process_lifecycle_v2()->io::Result<()> {
    failure_boundary_v2(FailureCaseV2::DurableStarted, &mut io::stdout(), run_started_process_lifecycle_v2_observed)
}
fn run_started_process_lifecycle_v2_observed(report:&mut FailureTrackerV2)->io::Result<()> {
    report.observe(FailureSiteV2::CorePolicy,process_containment_v1::require_and_report_core_policy())?;
    report.observe(FailureSiteV2::ChildWaitPolicy,owned_test_process_group_v1::require_default_child_wait_policy())?;
    let deadline=Instant::now()+LIMIT;
    let cutoff=report.observe(FailureSiteV2::Cutoff,(||{
        monotonic_now_ns()?.checked_add(deadline.saturating_duration_since(Instant::now()).as_nanos().try_into().map_err(|_|invalid())?).ok_or_else(invalid)
    })())?;
    let mut root=Some(report.observe(FailureSiteV2::TemporaryRoot,tempfile::Builder::new().prefix(CHILD_TEMPORARY_PREFIX).permissions(std::fs::Permissions::from_mode(0o700)).tempdir())?);
    let mut died=false;let mut audited=false;let mut reader_reaped=false;let mut cleanup=false;
    let workflow=(||->io::Result<()>{
        let tls=report.observe(FailureSiteV2::TlsPrepare,synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(root.as_ref().unwrap().path()))?;
        let mut producer=report.stage_call(FailureSiteV2::BProducer,private_workspace_stage_v1(root.take().unwrap(),Some(&tls),PrivateWorkspaceStageV1::DurableResultStartedProducer,&started_producer_inputs_v2(),deadline,cutoff))?;
        root=producer.root.take();
        report.check_stage(FailureSiteV2::BProducer,&producer,ExpectedProcessV2::Sigkill,||false)?;
        died=true;
        report.enter(FailureSiteV2::BReadyRead,FailureReasonV2::IoError);
        let ready:StartedReadyV2=read_record(root.as_ref().ok_or_else(invalid)?.path(),STARTED_READY)?;
        report.enter(FailureSiteV2::BReadyValidate,FailureReasonV2::Verification);
        ready.validate(root.as_ref().unwrap().path())?;
        let mut reader=report.stage_call(FailureSiteV2::BReader,private_workspace_stage_v1(root.take().unwrap(),None,PrivateWorkspaceStageV1::DurableResultStartedReader,&[],deadline,cutoff))?;
        root=reader.root.take();
        report.check_stage(FailureSiteV2::BReader,&reader,ExpectedProcessV2::Success,||Instant::now()>=deadline)?;
        reader_reaped=true;
        report.enter(FailureSiteV2::BReadyReread,FailureReasonV2::IoError);
        let path=root.as_ref().ok_or_else(invalid)?.path();
        let after:StartedReadyV2=read_record(path,STARTED_READY)?;
        report.enter(FailureSiteV2::BCompletionRead,FailureReasonV2::IoError);
        let finished:StartedCompletionV2=read_record(path,STARTED_FINISHED)?;
        report.enter(FailureSiteV2::BFinalVerify,FailureReasonV2::Verification);
        if finished.version!=2 || digest(&ready).map_err(|_|invalid())?!=digest(&after).map_err(|_|invalid())?
            || finished.original_ready_digest!=digest(&ready).map_err(|_|invalid())? {return Err(invalid());}
        finished.audit.validate(&ready).map_err(|_|invalid())?;audited=true;
        drop(tls);Ok(())
    })();
    report.capture(&workflow);
    if let Some(root)=root.take(){let closed=close_owned_temporary_root(root);cleanup=matches!(closed,TemporaryRootCleanupV1::ClosedAndAbsenceVerified);report.closed(closed);}
    else {report.closed(TemporaryRootCleanupV1::RetainedForUnverifiedProcess);}
    report.enter(FailureSiteV2::PublicReceipt,FailureReasonV2::IoError);
    println!("CI_SYNTHETIC_DURABLE_STARTED_V2 {}",serde_json::json!({
        "profile":"durable-result-started-uncertainty-v2","producer_killed_reaped_group_absent":died,
        "actual_native_reopen_source_kernel_uncertain":audited,"started_one_result_zero_outbox_zero_unchanged":audited,
        "exposure_outstanding_uncertain":audited,"reader_reaped_group_absent":reader_reaped,
        "cleanup_verified":cleanup,"native_runtime_executed":died,"live_funds":false,
        "not_full_v2_result_opener_or_return_success":true}));
    workflow?;
    report.enter(FailureSiteV2::TemporaryCleanup,FailureReasonV2::CleanupUnverified);
    if !cleanup{return Err(invalid());}Ok(())
}

// Pure tests of the exact failure-only wrappers used above. Returned-stage
// values here are inert controller observations, not native/source authority.
#[derive(Debug)]
struct FailureIdentitySentinelV2;
impl std::fmt::Display for FailureIdentitySentinelV2 {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("PRIVATE_TEST_ERROR_DO_NOT_FORWARD")}
}
impl std::error::Error for FailureIdentitySentinelV2 {}
fn failure_test_record_v2(bytes:&[u8])->serde_json::Value {
    let text=std::str::from_utf8(bytes).unwrap();assert_eq!(text.lines().count(),1);assert!(bytes.len()<4096);
    assert!(!text.contains("PRIVATE_TEST_ERROR_DO_NOT_FORWARD"));
    assert!(!text.contains("PRIVATE_TEST_TRANSCRIPT_DO_NOT_FORWARD"));
    serde_json::from_str(text.strip_prefix("CI_SYNTHETIC_DURABLE_FAILURE_V2 ").unwrap().trim_end()).unwrap()
}
fn failure_test_stage_v2(expected:usize,status:std::process::ExitStatus)->PrivateWorkspaceStageResultV1 {
    use owned_test_process_group_v1::{GroupSignalV1,GroupAbsenceV1,DirectChildV1,ProcessCleanupV1};
    let mut transcript=rolling_transcript_v1::Transcript::new([]).unwrap();
    transcript.enable_fatal_output_v2();
    PrivateWorkspaceStageResultV1 {
        coordinated_post_input_phase:None,child_pid:1,pristine_first_failure:None,
        financial_progress_failure:None,financial_progress_timing:None,financial_diagnostic:None,
        delivery_first_failure:None,private_fixed_diagnostic:None,diagnostic_withheld:false,
        fatal_observation:transcript.fatal_observation_v2(true),
        outcome:Ok(()),process:ProcessCleanupV1{group_signal:GroupSignalV1::SentWhileLeaderOwned,
            group_absence:GroupAbsenceV1::OriginalGroupAbsentObserved,direct_child:DirectChildV1::Reaped,status:Some(status)},
        root:None,summary:"PRIVATE_TEST_TRANSCRIPT_DO_NOT_FORWARD".into(),
        failure_reason:HarnessFailureReason::Unclassified,next:expected,expected,
    }
}
#[test]
fn durable_failure_v2_preserves_setup_and_tls_errors_without_private_text(){
    use FailureSiteV2 as S;
    for case in [FailureCaseV2::DurableResume,FailureCaseV2::DurableStarted] {
        for site in [S::CorePolicy,S::ChildWaitPolicy,S::Cutoff,S::TemporaryRoot,S::TlsPrepare] {
            for (kind,label) in [(io::ErrorKind::PermissionDenied,"permission_denied"),(io::ErrorKind::TimedOut,"timed_out"),
                (io::ErrorKind::InvalidData,"invalid_data"),(io::ErrorKind::NotFound,"not_found"),
                (io::ErrorKind::ConnectionReset,"connection"),(io::ErrorKind::InvalidInput,"invalid_input"),
                (io::ErrorKind::Interrupted,"interrupted"),(io::ErrorKind::UnexpectedEof,"unexpected_eof"),
                (io::ErrorKind::WouldBlock,"would_block"),(io::ErrorKind::Other,"other")] {
                let error=io::Error::new(kind,FailureIdentitySentinelV2);
                let identity=error.get_ref().unwrap() as *const _ as *const ();
                let mut bytes=Vec::new();let returned=failure_boundary_v2(case,&mut bytes,|r|r.observe::<()>(site,Err(error))).unwrap_err();
                assert_eq!(returned.kind(),kind);assert_eq!(returned.get_ref().unwrap() as *const _ as *const (),identity);
                let record=failure_test_record_v2(&bytes);assert_eq!(record["io_kind"],label);
                assert_eq!(record["callsite"],serde_json::to_value(site).unwrap());
                assert_eq!(record["reason"],"io_error");assert_eq!(record["cleanup"],"not_started");assert!(record["stage"].is_null());
            }
        }
        let mut bytes=Vec::new();assert_eq!(failure_boundary_v2(case,&mut bytes,|r|r.observe(S::TlsPrepare,Ok(37))).unwrap(),37);assert!(bytes.is_empty());
    }
    struct FailedOutput;
    impl io::Write for FailedOutput {
        fn write(&mut self,_:&[u8])->io::Result<usize>{Err(io::Error::from_raw_os_error(libc::EPIPE))}
        fn flush(&mut self)->io::Result<()>{Ok(())}
    }
    let returned=failure_boundary_v2(FailureCaseV2::DurableResume,&mut FailedOutput,|r|r.observe::<()>(S::TlsPrepare,Err(io::Error::from_raw_os_error(libc::EPERM)))).unwrap_err();
    assert_eq!(returned.raw_os_error(),Some(libc::EPERM));
}
#[test]
fn durable_failure_v2_projects_each_returned_stage_rejection_and_healthy_status(){
    use std::os::unix::process::ExitStatusExt;
    use owned_test_process_group_v1::{GroupSignalV1 as G,GroupAbsenceV1 as A,DirectChildV1 as C};
    // Exact source plans, not a permissive generic counter bound.
    assert_eq!(producer_inputs_v2().len(),127);
    assert_eq!(intake_inputs_v2().len(),23);
    assert_eq!(reader_inputs_v2().len(),147);
    assert_eq!(started_producer_inputs_v2().len(),118);
    let cases=[(FailureCaseV2::DurableResume,FailureSiteV2::A0Producer,ExpectedProcessV2::Sigkill,127),
        (FailureCaseV2::DurableResume,FailureSiteV2::A1Intake,ExpectedProcessV2::Sigkill,23),
        (FailureCaseV2::DurableResume,FailureSiteV2::A2Reader,ExpectedProcessV2::Success,147),
        (FailureCaseV2::DurableStarted,FailureSiteV2::BProducer,ExpectedProcessV2::Sigkill,118),
        (FailureCaseV2::DurableStarted,FailureSiteV2::BReader,ExpectedProcessV2::Success,0)];
    for (case,site,expected,count) in cases {
        let good_raw=if expected==ExpectedProcessV2::Sigkill{libc::SIGKILL}else{0};
        let mut bytes=Vec::new();let error=io::Error::new(io::ErrorKind::PermissionDenied,FailureIdentitySentinelV2);
        let identity=error.get_ref().unwrap() as *const _ as *const ();
        let result=failure_boundary_v2(case,&mut bytes,|r|r.stage_call(site,Err(error)).map(|_|()));
        let returned=result.unwrap_err();assert_eq!(returned.kind(),io::ErrorKind::PermissionDenied);
        assert_eq!(returned.get_ref().unwrap() as *const _ as *const (),identity);let wire=failure_test_record_v2(&bytes);
        assert_eq!(wire["reason"],"stage_call_error");assert!(wire["stage"].is_null());
        for mode in 0..9 {
            // Only actual reader callsites evaluate the original cutoff.
            if mode==8 && expected==ExpectedProcessV2::Sigkill{continue;}
            let mut stage=failure_test_stage_v2(count,std::process::ExitStatus::from_raw(good_raw));
            let reason=match mode {
                0=>{stage.outcome=Err(io::Error::new(io::ErrorKind::TimedOut,FailureIdentitySentinelV2));stage.failure_reason=HarnessFailureReason::ChildExit;"stage_outcome_error"},
                1=>{stage.process.group_signal=G::Unverified;"process_cleanup_unverified"},
                2=>{stage.process.group_absence=A::Unverified;"process_cleanup_unverified"},
                3=>{stage.process.direct_child=C::Unverified;"process_cleanup_unverified"},
                4=>{stage.process.status=None;"process_cleanup_unverified"},
                5=>{stage.process.status=Some(std::process::ExitStatus::from_raw(1<<8));"expected_process_status"},
                6=>{stage.process.status=Some(std::process::ExitStatus::from_raw(libc::SIGTERM));"expected_process_status"},
                7=>{stage.process.status=Some(std::process::ExitStatus::from_raw(0x7f));"expected_process_status"},
                _=>"stage_deadline",
            };
            let observed=std::cell::Cell::new(0);let mut bytes=Vec::new();
            let result=failure_boundary_v2(case,&mut bytes,|r|r.check_stage(site,&stage,expected,||{observed.set(observed.get()+1);true}));
            assert!(result.is_err());assert_eq!(observed.get(),usize::from(mode==8));
            let wire=failure_test_record_v2(&bytes);assert_eq!(wire["reason"],reason);
            assert_eq!(wire["stage"]["expected"],count);assert_eq!(wire["stage"]["next"],count);
            assert_eq!(wire["stage"]["expected_process"],serde_json::to_value(expected).unwrap());
            if mode==0{assert_eq!(wire["io_kind"],"timed_out");assert_eq!(wire["stage"]["failure_reason"],"ChildExit");}
        }
        let mut stage=failure_test_stage_v2(count,std::process::ExitStatus::from_raw(good_raw));
        stage.process.group_signal=G::AlreadyAbsentWhileLeaderOwned;
        let mut bytes=Vec::new();let result=failure_boundary_v2(case,&mut bytes,|r|r.check_stage(site,&stage,expected,||false));
        if expected==ExpectedProcessV2::Sigkill{assert!(result.is_err());assert_eq!(failure_test_record_v2(&bytes)["reason"],"expected_process_status");}
        else{assert!(result.is_ok());assert!(bytes.is_empty());}
        stage.process.group_signal=G::SentWhileLeaderOwned;let mut bytes=Vec::new();
        assert!(failure_boundary_v2(case,&mut bytes,|r|r.check_stage(site,&stage,expected,||false)).is_ok());assert!(bytes.is_empty());
    }
}
#[test]
fn durable_failure_v2_preserves_first_failure_through_all_cleanup_modes(){
    for cleanup in [None,Some(TemporaryRootCleanupV1::ClosedAndAbsenceVerified),Some(TemporaryRootCleanupV1::RetainedForUnverifiedProcess),Some(TemporaryRootCleanupV1::CloseOrAbsenceUnverified)] {
        let mut bytes=Vec::new();let original=io::Error::new(io::ErrorKind::TimedOut,FailureIdentitySentinelV2);
        let identity=original.get_ref().unwrap() as *const _ as *const ();
        let returned=failure_boundary_v2(FailureCaseV2::DurableResume,&mut bytes,|r|{
            let workflow=r.observe::<()>(FailureSiteV2::TlsPrepare,Err(original));r.capture(&workflow);
            if let Some(cleanup)=cleanup{r.closed(cleanup);}
            let _=r.observe::<()>(FailureSiteV2::PublicReceipt,Err(io::Error::from_raw_os_error(libc::EIO)));
            workflow
        }).unwrap_err();
        assert_eq!(returned.get_ref().unwrap() as *const _ as *const (),identity);
        let wire=failure_test_record_v2(&bytes);assert_eq!(wire["callsite"],"tls_prepare");assert_eq!(wire["io_kind"],"timed_out");
        assert_eq!(wire["cleanup"],match cleanup {None=>"not_started",Some(TemporaryRootCleanupV1::ClosedAndAbsenceVerified)=>"closed_absent",Some(TemporaryRootCleanupV1::RetainedForUnverifiedProcess)=>"root_unavailable",Some(TemporaryRootCleanupV1::CloseOrAbsenceUnverified)=>"close_unverified"});
    }
    for closed in [TemporaryRootCleanupV1::RetainedForUnverifiedProcess,TemporaryRootCleanupV1::CloseOrAbsenceUnverified] {
        let mut bytes=Vec::new();let result=failure_boundary_v2(FailureCaseV2::DurableStarted,&mut bytes,|r|{
            let workflow=Ok(());r.capture(&workflow);r.closed(closed);workflow?;
            r.enter(FailureSiteV2::TemporaryCleanup,FailureReasonV2::CleanupUnverified);Err::<(),_>(invalid())
        });assert!(result.is_err());let wire=failure_test_record_v2(&bytes);
        assert_eq!(wire["callsite"],"temporary_cleanup");assert_eq!(wire["reason"],"cleanup_unverified");
    }
    let mut bytes=Vec::new();assert!(failure_boundary_v2(FailureCaseV2::DurableResume,&mut bytes,|r|{r.closed(TemporaryRootCleanupV1::ClosedAndAbsenceVerified);Ok(())}).is_ok());assert!(bytes.is_empty());
}
#[test]
fn durable_failure_v2_covers_all_final_boundaries_and_diagnostic_states(){
    use crate::host::financial_diagnostics_v1 as fd;
    // Inert records only: no provider, socket, source owner or native grant.
    use wholepact_signer::authority_bridge::financial_continuation_v1::{
        FinancialResultDiagnosticV1 as Detail, FinancialResultStageV1 as Stage,
        FinancialResultErrorClassV1 as Class, FinancialResultCurrentTimingV1 as Timing,
    };
    use wholepact_signer_origin::framing::FrameReadCause as Frame;
    use fd::{FinancialStageV1 as FS,FinancialErrorClassV1 as FC,FinancialCommitStateV1 as CS};
    let stages=[
        (Stage::InstalledProviderVerification,FS::ResultInstalledProviderVerification),
        (Stage::HostPreparedWrite,FS::ResultHostPreparedWrite),
        (Stage::ReadyWait,FS::ResultReadyWait),
        (Stage::ReadyMatch,FS::ResultReadyMatch),
        (Stage::FetchWrite,FS::ResultFetchWrite),
        (Stage::HeldRead,FS::ResultHeldRead),
        (Stage::EvidenceValidation,FS::ResultEvidenceValidation),
        (Stage::PreviewMatch,FS::ResultPreviewMatch),
        (Stage::HeldMatch,FS::ResultHeldMatch),
        (Stage::CurrentLock,FS::ResultCurrentLock),
        (Stage::CurrentPeer,FS::ResultCurrentPeer),
        (Stage::CurrentProviderVerification,FS::ResultCurrentProviderVerification),
        (Stage::CurrentWrite,FS::ResultCurrentWrite),
        (Stage::CurrentRead,FS::ResultCurrentRead),
        (Stage::CurrentMatch,FS::ResultCurrentMatch),
        (Stage::FinishWrite,FS::ResultFinishWrite),
        (Stage::FinishRead,FS::ResultFinishRead),
        (Stage::FinishMatch,FS::ResultFinishMatch),
    ];
    let causes=[(None,FC::Ipc),
        (Some(Frame::Unclassified),FC::FrameUnclassified),
        (Some(Frame::Deadline),FC::FrameDeadline),
        (Some(Frame::Eof),FC::FrameEof),
        (Some(Frame::CredentialsMissing),FC::FrameCredentialsMissing),
        (Some(Frame::CredentialsMismatch),FC::FrameCredentialsMismatch),
        (Some(Frame::AncillaryRejected),FC::FrameAncillaryRejected),
        (Some(Frame::Truncated),FC::FrameTruncated),
        (Some(Frame::PeerNotLive),FC::FramePeerNotLive),
        (Some(Frame::CurrentCheck),FC::FrameCurrentCheck),
        (Some(Frame::Io),FC::FrameIo),
        (Some(Frame::FrameLimit),FC::FrameLimit),
        (Some(Frame::InvalidFrame),FC::FrameInvalid),
        (Some(Frame::InvalidBudget),FC::FrameInvalidBudget),
    ];
    for (stage,expected_stage) in stages {
        for (frame_cause,expected_class) in causes {
            fd::reset_operation();
            fd::signer_result(Detail{stage,error_class:Class::Ipc,frame_cause,current_timing:None},CS::NotEstablished);
            // This is the real outer generic mapping, which must not replace first detail.
            fd::bridge(FS::ResultReceive,CS::NotEstablished,
                &wholepact_signer::authority_bridge::BridgeError::Ipc);
            let captured=fd::take_operation_failure().unwrap();
            assert_eq!(captured.stage,expected_stage);assert_eq!(captured.error_class,expected_class);
            assert_eq!(captured.component,fd::FinancialComponentV1::SignerBridge);
            let finite=finite_result_failure_v2(Some(captured),true,&AtomicBool::new(false)).unwrap();
            assert!(finite.current_timing.is_none() && finite.authority_call.is_none());
            let mut observed=failure_test_stage_v2(23,std::process::ExitStatus::from_raw(101<<8));
            observed.financial_diagnostic=Some(finite);
            let value=serde_json::to_value(failure_stage_v2(&observed,ExpectedProcessV2::Sigkill)).unwrap();
            let projection=&value["financial_first_failure"];
            assert_eq!(projection.as_object().unwrap().len(),4);
            assert_eq!(projection["stage"],serde_json::to_value(expected_stage).unwrap());
            assert_eq!(projection["error_class"],serde_json::to_value(expected_class).unwrap());
            assert_eq!(projection["component"],"SignerBridge");
            assert_eq!(projection["commit_state"],"NotEstablished");
        }
    }
    for (error_class,expected_class) in [
        (Class::Binding,FC::Binding),
        (Class::Conflict,FC::Conflict),
        (Class::Missing,FC::Missing),
        (Class::Uncertain,FC::Uncertain),
        (Class::Limit,FC::ResourceLimit),
        (Class::Permission,FC::Permission),
        (Class::RecoveryRequired,FC::RecoveryRequired),
        (Class::CompleteOriginRecoveryUnavailable,FC::RecoveryRequired),
        (Class::Verification,FC::Verification),
        (Class::SignerOriginUnavailable,FC::SignerOriginUnavailable),
        (Class::Journal,FC::Journal),
        (Class::Authority,FC::Authority),
        (Class::Wallet,FC::Wallet),
        (Class::Ipc,FC::Ipc),
    ] {
        fd::reset_operation();
        fd::signer_result(Detail{stage:Stage::InstalledProviderVerification,error_class,frame_cause:None,current_timing:None},CS::NotEstablished);
        fd::bridge(FS::ResultReceive,CS::NotEstablished,&wholepact_signer::authority_bridge::BridgeError::Ipc);
        let finite=finite_result_failure_v2(fd::take_operation_failure(),true,&AtomicBool::new(false)).unwrap();
        assert_eq!(finite.stage,FS::ResultInstalledProviderVerification);
        assert_eq!(finite.error_class,expected_class);
        let mut observed=failure_test_stage_v2(23,std::process::ExitStatus::from_raw(101<<8));
        observed.financial_diagnostic=Some(finite);
        let value=serde_json::to_value(failure_stage_v2(&observed,ExpectedProcessV2::Sigkill)).unwrap();
        let projection=&value["financial_first_failure"];
        assert_eq!(projection.as_object().unwrap().len(),4);
        assert_eq!(projection["error_class"],serde_json::to_value(expected_class).unwrap());
    }
    fd::reset_operation();
    fd::signer_result(Detail{stage:Stage::CurrentRead,error_class:Class::Ipc,frame_cause:Some(Frame::Deadline),
        current_timing:Some(Timing{budget_ms:1000,provider_elapsed_ms:Some(1),remaining_before_write_ms:Some(999),
            remaining_before_read_ms:Some(998),roundtrip_elapsed_ms:2})},CS::NotEstablished);
    let captured=fd::take_operation_failure().unwrap();assert!(captured.current_timing.is_some());
    let stripped=finite_result_failure_v2(Some(captured),true,&AtomicBool::new(false)).unwrap();
    assert_eq!(stripped.stage,FS::ResultCurrentRead);assert_eq!(stripped.error_class,FC::FrameDeadline);
    assert!(stripped.current_timing.is_none() && stripped.authority_call.is_none());
    fd::reset_operation();
    let first=fd::FinancialDiagnosticV1{schema:1,stage:fd::FinancialStageV1::AuthenticatedIntake,
        component:fd::FinancialComponentV1::Engine,error_class:fd::FinancialErrorClassV1::Permission,
        commit_state:fd::FinancialCommitStateV1::OutcomeUncertain,current_timing:None,authority_call:None};
    let emitted=AtomicBool::new(false);
    assert!(finite_result_failure_v2(Some(first),false,&emitted).is_none());
    assert!(!emitted.load(Ordering::SeqCst));
    let mut invalid_record=first;invalid_record.schema=2;
    assert!(finite_result_failure_v2(Some(invalid_record),true,&emitted).is_none());
    assert!(!emitted.load(Ordering::SeqCst));
    assert_eq!(finite_result_failure_v2(Some(first),true,&emitted),Some(first));
    let mut later=first;later.stage=fd::FinancialStageV1::WorkerDrain;
    assert!(finite_result_failure_v2(Some(later),true,&emitted).is_none());
    let mut timed=first;timed.stage=fd::FinancialStageV1::ResultCurrentRead;
    timed.component=fd::FinancialComponentV1::SignerBridge;
    timed.current_timing=Some(fd::FinancialCurrentTimingV1{budget_ms:1000,provider_elapsed_ms:Some(1),
        remaining_before_write_ms:Some(999),remaining_before_read_ms:Some(998),roundtrip_elapsed_ms:2});
    assert!(timed.is_valid_v1());
    let stripped=finite_result_failure_v2(Some(timed),true,&AtomicBool::new(false)).unwrap();
    assert!(stripped.current_timing.is_none() && stripped.authority_call.is_none());
    assert_eq!(stripped.stage,timed.stage);assert_eq!(stripped.error_class,timed.error_class);
    let mut invalid_nested=timed;invalid_nested.component=fd::FinancialComponentV1::Engine;
    assert!(finite_result_failure_v2(Some(invalid_nested),true,&AtomicBool::new(false)).is_none());
    let mut call=first;call.stage=fd::FinancialStageV1::NativeAuthorityAdmit;
    call.authority_call=Some(serde_json::from_value(serde_json::json!({
        "stage":"ExchangeDeadline","check_site":"AfterResponseRead","checkpoint":"AfterCallback",
        "selected_limit":"Exchange","selected_budget_us":10000000,"caller_remaining_at_failure_us":100000000,
        "selected_remaining_at_failure_us":0,"exchange_elapsed_us":10000001,"exchange_cost":null,
        "clamped":false,"incomplete":false,"pre_budget_callback_calls":1,"pre_budget_callback_us":100
    })).unwrap());
    assert!(call.is_valid_v1());
    let stripped=finite_result_failure_v2(Some(call),true,&AtomicBool::new(false)).unwrap();
    assert!(stripped.current_timing.is_none() && stripped.authority_call.is_none());
    call.stage=fd::FinancialStageV1::ResultCurrentRead;
    assert!(finite_result_failure_v2(Some(call),true,&AtomicBool::new(false)).is_none());
    let line=format!("[FINANCIAL_DIAGNOSTIC_V1 {}]\n",serde_json::to_string(&first).unwrap());
    for split in 0..line.len() {
        let mut transcript=rolling_transcript_v1::Transcript::new([]).unwrap();
        transcript.append(&line.as_bytes()[..split],Path::new("/tmp/owned")).unwrap();
        assert!(transcript.financial_diagnostic().is_none());
        transcript.append(&line.as_bytes()[split..],Path::new("/tmp/owned")).unwrap();
        transcript.finish_private_fixed_diagnostic();
        assert_eq!(transcript.financial_diagnostic(),Some(&first));
    }
    for changed in [line.replace("AuthenticatedIntake","UNRECOGNIZED"),line.replace("\"schema\":1","\"extra\":true,\"schema\":1"),line.trim_end().into(),line.repeat(2)] {
        let mut transcript=rolling_transcript_v1::Transcript::new([]).unwrap();
        transcript.append(changed.as_bytes(),Path::new("/tmp/owned")).unwrap();
        transcript.finish_private_fixed_diagnostic();assert!(transcript.financial_diagnostic().is_none());
    }
    for (verified,valid,withheld) in [(true,true,false),(false,true,false),(true,false,false),(true,true,true)] {
        let mut stage=failure_test_stage_v2(23,std::process::ExitStatus::from_raw(101<<8));
        stage.financial_diagnostic=Some(if valid{first}else{invalid_record});
        stage.diagnostic_withheld=withheld;
        if !verified{stage.process.direct_child=owned_test_process_group_v1::DirectChildV1::Unverified;}
        let projected=failure_stage_v2(&stage,ExpectedProcessV2::Sigkill);
        let value=serde_json::to_value(projected).unwrap();
        let diagnostic=&value["financial_first_failure"];
        assert_eq!(diagnostic.is_null(),!verified || !valid || withheld);
        if verified && valid && !withheld {
            assert_eq!(value["diagnostic_state"],"validated");
            assert_eq!(diagnostic.as_object().unwrap().len(),4);
            assert_eq!(diagnostic["stage"],"AuthenticatedIntake");
            assert_eq!(diagnostic["component"],"Engine");
            assert_eq!(diagnostic["error_class"],"Permission");
            assert_eq!(diagnostic["commit_state"],"OutcomeUncertain");
        }
    }

    use FailureSiteV2 as S;
    use crate::host::financial::private_durable_fixed_v2 as D;
    use std::os::unix::process::ExitStatusExt;
    for (case,sites) in [(FailureCaseV2::DurableResume,&[S::A0ReadyRead,S::A0ReadyValidate,S::WriterExpiryWait,S::A2ReadyRead,S::A2CompletionRead,S::A2FinalVerify,S::PublicReceipt][..]),
        (FailureCaseV2::DurableStarted,&[S::BReadyRead,S::BReadyValidate,S::BReadyReread,S::BCompletionRead,S::BFinalVerify,S::PublicReceipt][..])] {
        for &site in sites {
            let mut bytes=Vec::new();let returned=failure_boundary_v2(case,&mut bytes,|r|{
                r.enter(site,FailureReasonV2::Verification);let workflow=Err::<(),_>(io::Error::from_raw_os_error(libc::EINVAL));
                r.capture(&workflow);r.closed(TemporaryRootCleanupV1::ClosedAndAbsenceVerified);workflow
            }).unwrap_err();assert_eq!(returned.raw_os_error(),Some(libc::EINVAL));
            let wire=failure_test_record_v2(&bytes);assert_eq!(wire["callsite"],serde_json::to_value(site).unwrap());assert!(wire["stage"].is_null());
        }
    }
    let diagnostic=D::PrivateFixedDiagnosticV1{schema:1,primary:D::PrivateDiagnosticPrimaryV1{
        operation:D::PrivateDiagnosticOperationV1::Checkpoint,site:D::PrivateDiagnosticSiteV1::WorkspaceLoad,
        engine_code:D::PrivateDiagnosticEngineCodeV1::NotApplicable,family:D::PrivateDiagnosticFamilyV1::Host,cause:D::PrivateDiagnosticCauseV1::Invalid,
    },evidence:None,worker:None,stage:None};assert!(diagnostic.canonical_json().is_some());
    let mut delivery=safe_diagnostics_v1::DeliveryFailureCapture::default();
    delivery.capture_complete_line(b"[JOINED_DIAGNOSTIC DeliveryAdmissionRetainedBinding HostInvalid]",4096);assert!(delivery.value().is_some());
    for mode in 0..5 {
        let mut stage=failure_test_stage_v2(127,std::process::ExitStatus::from_raw(libc::SIGKILL));
        stage.outcome=Err(invalid());stage.delivery_first_failure=delivery.value();
        let expected=match mode {
            0=>"unavailable",
            1=>{stage.private_fixed_diagnostic=Some(diagnostic.clone());"validated"},
            2=>{stage.private_fixed_diagnostic=Some(diagnostic.clone());stage.diagnostic_withheld=true;"withheld"},
            3=>{let mut bad=diagnostic.clone();bad.schema=2;stage.private_fixed_diagnostic=Some(bad);"withheld"},
            _=>{stage.private_fixed_diagnostic=Some(diagnostic.clone());stage.process.group_absence=owned_test_process_group_v1::GroupAbsenceV1::Unverified;"withheld"},
        };
        let mut bytes=Vec::new();assert!(failure_boundary_v2(FailureCaseV2::DurableResume,&mut bytes,|r|r.check_stage(S::A0Producer,&stage,ExpectedProcessV2::Sigkill,||panic!("must short circuit"))).is_err());
        let wire=failure_test_record_v2(&bytes);assert_eq!(wire["stage"]["diagnostic_state"],expected);
        assert_eq!(wire["stage"]["private_fixed_primary"].is_null(),expected!="validated");
        if expected=="validated"{assert_eq!(wire["stage"]["private_fixed_primary"],serde_json::to_value(&diagnostic.primary).unwrap());}
        assert_eq!(wire["stage"]["delivery_first_failure"].is_null(),mode==4);
    }
}

#[test]
fn durable_failure_v2_fatal_observations_all_stages_keep_error_order_and_withhold() {
    use std::os::unix::process::ExitStatusExt;
    let cases=[(FailureCaseV2::DurableResume,FailureSiteV2::A0Producer,ExpectedProcessV2::Sigkill,127),
        (FailureCaseV2::DurableResume,FailureSiteV2::A1Intake,ExpectedProcessV2::Sigkill,23),
        (FailureCaseV2::DurableResume,FailureSiteV2::A2Reader,ExpectedProcessV2::Success,147),
        (FailureCaseV2::DurableStarted,FailureSiteV2::BProducer,ExpectedProcessV2::Sigkill,118),
        (FailureCaseV2::DurableStarted,FailureSiteV2::BReader,ExpectedProcessV2::Success,0)];
    for (case,site,expected,count) in cases {
        for drained in [false,true] { for verified in [false,true] { for mask in 0..16u8 {
            let mut transcript=rolling_transcript_v1::Transcript::new([]).unwrap();
            transcript.enable_fatal_output_v2();
            for (bit,line) in [(1,b"fatal runtime error: stack overflow, aborting\n".as_slice()),
                (2,b"thread 'PRIVATE_NAME' (12345) panicked at /PRIVATE_PATH:12:34:\n"),
                (4,b"memory allocation of 987654321 bytes failed\n"),
                (8,b"thread caused non-unwinding panic. aborting.\n")] {
                if mask & bit != 0 {transcript.append(line,Path::new("/tmp/owned")).unwrap();}
            }
            transcript.finish_fatal_output_v2(drained);
            let raw=if expected==ExpectedProcessV2::Sigkill{libc::SIGKILL}else{0};
            let mut stage=failure_test_stage_v2(count,std::process::ExitStatus::from_raw(raw));
            stage.fatal_observation=transcript.fatal_observation_v2(true);
            if !verified {stage.process.direct_child=owned_test_process_group_v1::DirectChildV1::Unverified;}
            let error=io::Error::new(io::ErrorKind::TimedOut,FailureIdentitySentinelV2);
            let identity=error.get_ref().unwrap() as *const _ as *const ();
            stage.outcome=Err(error);
            let mut bytes=Vec::new();
            assert!(failure_boundary_v2(case,&mut bytes,|r|r.check_stage(site,&stage,expected,
                ||panic!("outcome failure must short circuit the existing clock"))).is_err());
            assert_eq!(stage.outcome.as_ref().unwrap_err().get_ref().unwrap() as *const _ as *const (),identity);
            let wire=failure_test_record_v2(&bytes);
            assert_eq!(wire["reason"],"stage_outcome_error");assert_eq!(wire["io_kind"],"timed_out");
            assert_eq!(wire["stage"]["fatal_observation"],if verified {
                serde_json::json!({"state":if drained{"complete"}else{"incomplete"},"observed_bits":mask})
            } else {serde_json::json!({"state":"withheld","observed_bits":null})});
            let text=std::str::from_utf8(&bytes).unwrap();
            for private in ["PRIVATE_NAME","PRIVATE_PATH","12345","987654321"] {assert!(!text.contains(private));}
            // Observation is not an acceptance predicate, including incomplete.
            stage.outcome=Ok(());stage.process.direct_child=owned_test_process_group_v1::DirectChildV1::Reaped;
            let mut output=Vec::new();
            assert!(failure_boundary_v2(case,&mut output,|r|r.check_stage(site,&stage,expected,||false)).is_ok());
            assert!(output.is_empty());
        }}}
    }
}
