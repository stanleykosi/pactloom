//! Closed B1 custody: setup is consumed before READ120; transfer and admission
//! have separate one-use owners, and no OpenAccount survives this transition.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::{PreparedOriginalDeliverySourceV3, ActivePreparedDeliverySourceV3};
use crate::authority_bridge::{durable_review_ipc_v1::{self as wire, DurableReviewPayloadV1}, durable_review_ipc_v3::*, durable_delivery_admission_ipc_v3::*};
use crate::native_ui::{authority::PreparedDeliveryReadReviewV3, PreparedReceiveAndViewAuthorityV3, durable_proposal_v1::VerifiedDurableEconomicsV1};
use crate::native_ui::witness_workspace::durable_delivery_v3::{PreparedDeliveryWitnessV3, DeliveryWitnessV3, HistoryReadPurposeV3};
use crate::ipc::durable_receive_v3 as inbound;
use crate::native_peer::PeerProcess;
use wholepact_authority::{OwnerControl, OwnerControlRequest, ReconciledAuthorityHistory, durable_delivery_scope_v2::*, durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1}};
use std::{os::unix::net::UnixStream, sync::mpsc, time::{Instant, SystemTime, UNIX_EPOCH}};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::native_ui) enum DurableDeliveryPhaseV3 { PreparingRead, ReceiveReview, Ready, Receiving, Verifying, ImportedVerified, AdmissionReview, AwaitingWitnessReady, Admitting, AwaitingAudit, HistoryReview, Complete, Aborted }
struct SetupV3 {
    source: PreparedOriginalDeliverySourceV3,
    witness: PreparedDeliveryWitnessV3,
    original: Option<crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1>,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    intent: RecipientIntentV3,
    peer: Option<PeerProcess>,
    material_deadline: Instant,
}
struct ActiveV3 {
    history_only: bool,
    source: ActivePreparedDeliverySourceV3,
    witness: DeliveryWitnessV3,
    original: Option<crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1>,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    intent: RecipientIntentV3,
    peer: Option<PeerProcess>,
}
impl ActiveV3 {
    fn check(&self) -> Result<()> {
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
    fn check_admission_progress(&self)->Result<()> {
        self.source.check_data_current()?;
        self.source.read().check_recipient(&self.intent)?;
        self.peer.as_ref().ok_or(Error::Authentication)?.check_alive()?;
        let now=unix_ms()?;
        if self.intent.material_scopes.iter().any(|scope|now<scope.valid_from_unix_seconds.saturating_mul(1000)||now>=scope.valid_until_unix_seconds.saturating_mul(1000)){return Err(Error::Locked);}
        self.witness.check_current()
    }
    fn deadline(&self) -> Result<Instant> {self.check()?; self.source.read().deadline()}
}
pub(crate) struct VerifiedImportV3 { active: Arc<ActiveV3>, fixed: VerifiedDurableEconomicsV1, receipt: VerifiedDurableReviewReceiptV3 }
struct PreparedAdmissionV3 {
    imported: Arc<VerifiedImportV3>,
    request: OwnerControlRequest,
    prepared: crate::consent_journal::PreparedDurableDeliveryAdmissionIntentV3,
}
struct AwaitingAuditV3 {
    retained: crate::consent_journal::RetainedDurableDeliveryAdmissionIntentV3,
    controlled: Option<wholepact_authority::AccountSnapshot>,
    lower_error: Option<wholepact_authority::AuthorityError>,
}
enum OutcomeV3 { ReceiveFailed(authority_bridge::BridgeError,Option<Error>), AdmissionFailed(wholepact_authority::AuthorityError), Setup(SetupV3), HistorySetup(SetupV3), Received(Zeroizing<Vec<u8>>), Verified(VerifiedImportV3), Prepared(PreparedAdmissionV3), Awaiting(AwaitingAuditV3), Audited(DurableDeliveryAdmissionStatusV3,wholepact_authority::AuthorityHead) }
struct JobV3 { receive: mpsc::Receiver<Result<OutcomeV3>>, worker: std::thread::JoinHandle<()> }
pub(super) struct DurableDeliveryRuntimeV3 {
    phase: DurableDeliveryPhaseV3,
    ipc: LocalIpc,
    _directory: Option<tempfile::TempDir>,
    preparation: PrepareClosedRecipientRequestV3,
    peer: Option<PeerProcess>,
    setup: Option<SetupV3>,
    read_review: Option<PreparedDeliveryReadReviewV3>,
    active: Option<Arc<ActiveV3>>,
    imported: Option<Arc<VerifiedImportV3>>,
    financial_material: Option<VerifiedDurableEconomicsV1>,
    financial_admitted_head: Option<wholepact_authority::AuthorityHead>,
    prepared: Option<PreparedAdmissionV3>,
    awaiting: Option<AwaitingAuditV3>,
    job: Option<JobV3>,
    status: Option<DurableDeliveryAdmissionStatusV3>,
    failure: Option<Error>,
    epoch: u64,
    history_requested: bool,
    history_selector: Option<DurableDeliveryHistoryRequestV3>,
    admitting: Arc<AtomicBool>,
    lower_receive_error: Option<authority_bridge::BridgeError>,
    lower_admission_error: Option<wholepact_authority::AuthorityError>,
    retired_origin: Option<crate::native_ui::NativeAuthorityBinding>,
    retired_peer: Option<AuthenticatedPeer>,
    history_recipient: Option<(PeerProcess,String)>,
    exact_pending_operation: Option<OwnerControlRequest>,
}
impl DurableDeliveryRuntimeV3 {
    fn abort(&mut self, error:Error) {
        if let Some(active)=&self.active {active.source.read().invalidate();}
        self.read_review=None; self.setup=None; self.imported=None; self.financial_material=None; self.prepared=None; self.history_recipient=None;
        self.phase=if self.phase==DurableDeliveryPhaseV3::Complete {DurableDeliveryPhaseV3::Complete}else if self.awaiting.is_some() {DurableDeliveryPhaseV3::AwaitingAudit}else{DurableDeliveryPhaseV3::Aborted};
        self.failure=Some(error);
    }
    fn spawn(&mut self, work:impl FnOnce()->Result<OutcomeV3>+Send+'static) -> Result<()> {
        if self.job.is_some() {return Err(Error::Unavailable);}
        let (send,receive)=mpsc::channel();
        #[cfg(feature="synthetic-born-joined-qualification")]
        let stage=match self.phase {
            DurableDeliveryPhaseV3::HistoryReview => super::delivery_diagnostics_v2::Stage::DeliveryHistoricalRead,
            DurableDeliveryPhaseV3::ImportedVerified|DurableDeliveryPhaseV3::AdmissionReview|DurableDeliveryPhaseV3::AwaitingWitnessReady|DurableDeliveryPhaseV3::Admitting => super::delivery_diagnostics_v2::Stage::DeliveryNativeAdmission,
            _ if self.history_selector.is_some()=>super::delivery_diagnostics_v2::Stage::DeliveryHistoricalRead,
            _=>super::delivery_diagnostics_v2::Stage::DeliveryArtifactImport,
        };
        let worker=std::thread::spawn(move || {
            let result=work();
            #[cfg(feature="synthetic-born-joined-qualification")]
            let result=super::delivery_diagnostics_v2::signer_result(stage,result);
            let _=send.send(result);
        });
        self.job=Some(JobV3 {receive,worker}); Ok(())
    }
    fn check(&self) -> Result<()> {
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
fn unix_ms()->Result<u64> {u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|Error::Locked)?.as_millis()).map_err(|_|Error::Locked)}
fn canonical<T:serde::Serialize>(domain:&str, value:&T)->Result<String> {wholepact_core::proposal::canonical_digest(domain,value).map_err(|_|Error::InvalidData)}
fn bridge_error(_: impl std::fmt::Display)->authority_bridge::BridgeError {authority_bridge::BridgeError::Permission}
fn remaining(deadline:Instant)->Result<u64> {let value=u64::try_from(deadline.saturating_duration_since(Instant::now()).as_millis()).map_err(|_|Error::Locked)?; if value==0 {Err(Error::Locked)}else{Ok(value.min(120_000))}}

impl NativeRuntime {
    pub(super) fn begin_prepared_delivery_v3(&mut self, mut stream:UnixStream, peer:AuthenticatedPeer, preparation:PrepareClosedRecipientRequestV3, epoch:u64)->Result<()> {
        preparation.validate().map_err(|_|Error::InvalidData)?;
        if self.closed_delivery_v3.is_some() || self.pending.is_some() || self.signing_job.is_some() {return Err(Error::Unavailable);}
        let open=self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?.peer.require_same_grant(&peer)?;
        if open.durable_delivery_entry.is_none() || open.wallet.is_some() || open.wallet_job.is_some() || open.witness_job.is_some() || open.writer_receipt.is_some() || open.writer_retry.is_some() || open.activation_retry.is_some() || open.durable_import_job.is_some() || open.durable_wallet_job.is_some() {return Err(Error::Unavailable);}
        let digest=preparation.digest().map_err(|_|Error::InvalidData)?;
        inbound::send_staged_v3(&mut stream,&digest).map_err(|_|Error::Uncertain)?;
        drop(stream);
        let mut open=self.open.take().ok_or(Error::Locked)?;
        let source=open.durable_delivery_entry.take().ok_or(Error::Unavailable)?;
        let owner=open.owner_witness.take().ok_or(Error::Unavailable)?;
        let session=open.session.take().ok_or(Error::Locked)?;
        let enrollment=open.enrollment.take().ok_or(Error::ReviewMismatch)?;
        let manifest=open.manifest.take().ok_or(Error::ReviewMismatch)?;
        let generation=open.ipc.generation();
        let original_peer=peer.peer.clone();
        let setup_request=preparation.clone();
        let ipc=open.ipc;
        let directory=open.durable_ipc_directory;
        let closed_peer=original_peer.clone();
        let mut closed=DurableDeliveryRuntimeV3 {peer:Some(closed_peer),phase:DurableDeliveryPhaseV3::PreparingRead,ipc,_directory:directory,preparation,setup:None,read_review:None,active:None,imported:None,financial_material:None,financial_admitted_head:None,prepared:None,awaiting:None,job:None,status:None,failure:None,epoch,history_requested:false,history_selector:None,admitting:Arc::new(AtomicBool::new(false)),lower_receive_error:None,lower_admission_error:None,retired_origin:Some(peer.native_origin.clone()),retired_peer:Some(peer.clone()),history_recipient:None,exact_pending_operation:None};
        closed.spawn(move || {
            // Every prior reader is joined before its journal/session/source is
            // consumed. A pending old capability is never copied into V3.
            for worker in open.history_workers {worker.join().map_err(|_|Error::Unavailable)?;}
            for done in open.revocations {while !done.load(Ordering::Acquire) {std::thread::sleep(Duration::from_millis(20));}}
            source.check_current()?; peer.check_current()?;
            let setup_pin=source.journal().prepare_delivery_journal_revision_v3(source.genesis(),enrollment.reference(),manifest.reference())?;
            if enrollment.reference()!=setup_request.request.enrollment_ref || manifest.reference()!=setup_request.request.accepted_manifest_ref || manifest.enrollment_ref()!=enrollment.reference() || crate::consent_journal::validated_delivery_manifest_proposal_v3(&manifest)?.proposal_digest()!=setup_request.fixed.proposal_digest {return Err(Error::ReviewMismatch);}
            let original=source.journal().durable_construction_history_v1(&setup_request.request.own_disclosure,&session)?;
            if original.redisclosure().is_some() {return Err(Error::ReviewMismatch);}
            let current=if let Some(request)=&setup_request.request.current_disclosure {
                let value=source.journal().durable_construction_history_v1(request,&session)?;
                value.validate_redisclosure_of(&original).map_err(|_|Error::ReviewMismatch)?; value
            }else{original.clone()};
            if !authority_bridge::ipc::exact_local_recipient(current.recipient_transport(),&peer) || !peer.scope.history_read || !peer.scope.preconstruction_export || peer.native_origin!=source.native_binding() {return Err(Error::Authentication);}
            original.request().material.verify_owner(&source.account().fvk()?).map_err(|_|Error::ReviewMismatch)?;
            let lease=source.journal().acquire_preconstruction_records(&setup_request.request.enrollment_ref,&setup_request.request.accepted_manifest_ref,&session)?;
            lease.require_native_origin(&source.native_binding())?;
            source.check_current_under_preconstruction_lease(&lease)?;
            lease.require_current_durable_disclosure_receipts_v1()?;
            if lease.enrollment()!=&enrollment || lease.manifest()!=&manifest || original.request().scope.proposal!=*crate::consent_journal::validated_delivery_manifest_proposal_v3(&manifest)?.input() || !original.request().scope.permits_local_reviewer_account(enrollment.account_id()).map_err(|_|Error::ReviewMismatch)? {return Err(Error::ReviewMismatch);}
            let own=setup_request.material_scopes.iter().find(|s|s.account_id==enrollment.account_id()).ok_or(Error::ReviewMismatch)?;
            if own.original_scope_digest!=original.request().scope.digest().map_err(|_|Error::ReviewMismatch)? || own.valid_from_unix_seconds!=original.request().scope.valid_from_unix_seconds || own.valid_until_unix_seconds!=original.request().scope.valid_until_unix_seconds {return Err(Error::ReviewMismatch);}
            drop(lease);
            let owner=Arc::try_unwrap(owner).map_err(|_|Error::Unavailable)?.into_prepared_delivery_v3(&source.native_binding(),&source.original_witness_disclosure_data_v1()?,&source.record().account_record.terms.signer.owner_certificate_digest)?;
            // This invalidates only the old session, not historical original rows.
            session.invalidate()?; drop(session); drop(open.pairing); drop(open.witness);
            let source=Arc::try_unwrap(source).map_err(|_|Error::Unavailable)?.into_prepared_v3(enrollment.reference(),manifest.reference(),setup_pin)?;
            drop(open.authority); drop(open.vault); drop(open.journal);
            let now=unix_ms()?;
            let ceiling=setup_request.material_scopes.iter().map(|s|s.valid_until_unix_seconds.saturating_mul(1000)).min().ok_or(Error::ReviewMismatch)?;
            if setup_request.material_scopes.iter().any(|s|now<s.valid_from_unix_seconds.saturating_mul(1000)) || ceiling<=now {return Err(Error::Locked);}
            let material_deadline=Instant::now()+Duration::from_millis(ceiling-now);
            let intent=RecipientIntentV3 {version:3,request:setup_request.request.clone(),fixed:setup_request.fixed.clone(),payload_digest:setup_request.payload_digest.clone(),payload_bytes:setup_request.payload_bytes,delivery:setup_request.delivery.clone(),material_scopes:setup_request.material_scopes.clone(),account_id:peer.scope.account_id.clone(),participant_id:peer.scope.participant_id.clone(),agreement_id:peer.scope.agreement_id.clone(),manifest_digest:peer.scope.manifest_digest.clone(),provider_enrollment_reference:setup_request.provider_enrollment_reference.clone(),signer_process_instance:setup_request.signer_process_instance.clone(),authorized_host_process_instance:original_peer.instance().into(),source_identity_digest:source.identity().into(),source_generation:generation,read_session_digest:"00".repeat(32),receive_decision_digest:"00".repeat(32),original_enrollment_ref:enrollment.reference().into(),original_manifest_ref:manifest.reference().into()};
            intent.validate().map_err(|_|Error::ReviewMismatch)?;
            Ok(OutcomeV3::Setup(SetupV3 {source,witness:owner,original:Some(original),enrollment,manifest,intent,peer:Some(original_peer),material_deadline}))
        })?;
        self.closed_delivery_v3=Some(closed);
        Ok(())
    }
    pub(super) fn durable_delivery_v3_phase(&self)->Option<DurableDeliveryPhaseV3> {self.closed_delivery_v3.as_ref().map(|c|c.phase)}
    pub(super) fn durable_delivery_v3_preparation(&self)->Option<&PrepareClosedRecipientRequestV3> {self.closed_delivery_v3.as_ref().map(|c|&c.preparation)}
    pub(super) fn durable_delivery_v3_intent(&self)->Option<&RecipientIntentV3> {self.closed_delivery_v3.as_ref()?.active.as_ref().map(|a|&a.intent)}
    pub(super) fn durable_delivery_v3_deadline(&self)->Option<Instant> {self.closed_delivery_v3.as_ref()?.active.as_ref()?.deadline().ok()}
    pub(super) fn durable_delivery_v3_pending_owner_request(&self)->Option<&OwnerControlRequest> {let closed=self.closed_delivery_v3.as_ref()?;closed.prepared.as_ref().map(|p|&p.request).or(closed.exact_pending_operation.as_ref())}
    pub(super) fn durable_delivery_v3_status(&self)->Option<&DurableDeliveryAdmissionStatusV3> {let closed=self.closed_delivery_v3.as_ref()?;closed.active.as_ref()?.check().ok()?;closed.status.as_ref()}
    pub(super) fn take_durable_delivery_v3_failure(&mut self)->Option<Error> {self.closed_delivery_v3.as_mut()?.failure.take()}
    pub(super) fn check_durable_delivery_v3(&self)->Result<()> {if self.open.is_some(){return Err(Error::ReviewMismatch);}self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?.check()}
    pub(super) fn require_durable_delivery_financial_denied_v3(&mut self)->Result<()> {
        self.check_durable_delivery_v3()?;
        if self.open.is_some() || self.signing_job.is_some() || self.incoming_pczt.is_some() {return Err(Error::ReviewMismatch);}
        // No OpenAccount means no generic session/writer/wallet can be reached.
        if self.stage_enrollment(1).is_ok() || self.stage_manifest(1).is_ok() || self.stage_wallet_setup(1).is_ok() {return Err(Error::ReviewMismatch);}
        Ok(())
    }
}

fn verify_import(active:Arc<ActiveV3>, bytes:Zeroizing<Vec<u8>>)->Result<VerifiedImportV3> {
    active.check()?;
    if bytes.len() as u64!=active.intent.payload_bytes || hex::encode(Sha256::digest(bytes.as_slice()))!=active.intent.payload_digest {return Err(Error::ReviewMismatch);}
    let payload:DurableReviewPayloadV1=wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes,wire::MAX_PAYLOAD).map_err(|_|Error::InvalidData)?;
    if payload.encode().map_err(|_|Error::InvalidData)?.as_slice()!=bytes.as_slice() {return Err(Error::ReviewMismatch);}
    let own=payload.contributions.iter().find(|c|c.request().scope.account_id==active.intent.account_id).ok_or(Error::ReviewMismatch)?;
    if active.original.as_ref()!=Some(own) {return Err(Error::ReviewMismatch);}
    let mut materials=Vec::new();
    for contribution in &payload.contributions {
        let scope=&contribution.request().scope;
        scope.check_valid_at(unix_ms()?/1000).map_err(|_|Error::Locked)?;
        if scope.proposal!=*crate::consent_journal::validated_delivery_manifest_proposal_v3(&active.manifest)?.input() {return Err(Error::ReviewMismatch);}
        materials.push(DurableDeliveryMaterialScopeRefV2 {account_id:scope.account_id.clone(),original_scope_digest:scope.digest().map_err(|_|Error::ReviewMismatch)?,valid_from_unix_seconds:scope.valid_from_unix_seconds,valid_until_unix_seconds:scope.valid_until_unix_seconds});
    }
    materials.sort_by(|a,b|a.account_id.cmp(&b.account_id));
    if materials!=active.intent.material_scopes {return Err(Error::ReviewMismatch);}
    let unsigned=Zeroizing::new(hex::decode(&payload.unsigned_pczt_hex).map_err(|_|Error::InvalidData)?);
    let proved=Zeroizing::new(hex::decode(&payload.proved_pczt_hex).map_err(|_|Error::InvalidData)?);
    active.check()?;
    // This is the sole independent proof/economics verification of the actual
    // received allocation. A bytes-received receipt cannot enter this branch.
    let fixed=VerifiedDurableEconomicsV1::verify(&crate::consent_journal::validated_delivery_manifest_proposal_v3(&active.manifest)?,&unsigned,&proved,&payload.contributions,&active.intent.account_id,payload.output_actions.iter().map(|m|wholepact_protocol::construction::OutputActionMapping {output_id:m.output_id.clone(),action_index:m.action_index}).collect(),wholepact_protocol::proving::ProvingLimits {maximum_actions:8})?;
    if fixed.verified().identity()!=&active.intent.fixed {return Err(Error::ReviewMismatch);}
    active.check()?;
    let receipt=VerifiedDurableReviewReceiptV3 {version:3,intent_digest:active.intent.digest().map_err(|_|Error::ReviewMismatch)?,payload_digest:active.intent.payload_digest.clone(),payload_bytes:active.intent.payload_bytes,verified_fixed_identity_digest:verified_fixed_identity_digest_v3(&active.intent.fixed).map_err(|_|Error::ReviewMismatch)?,state:"verified_import_for_review".into()};
    Ok(VerifiedImportV3 {active,fixed,receipt})
}
fn exact_scope(imported:&VerifiedImportV3,history:&ReconciledAuthorityHistory)->Result<DurableDeliveryScopeV2> {
    let active=&imported.active;
    active.check()?;
    let entry=&active.source;
    let extension=entry.record()?.extension()?;
    let old=&extension.account_extension;
    let economics=&imported.fixed;
    let fixed=economics.verified();
    let proposal=economics.proposal();
    let account=entry.account()?.account_id()?;
    let owner=proposal.manifest().participants.iter().find(|p|p.account_id==account).ok_or(Error::ReviewMismatch)?;
    let recipient_policy_scope_digest=authority_bridge::validate_prepared_delivery_policy_v3(entry.record()?,entry.original_policy()?,entry.account()?,&active.enrollment,&active.manifest,fixed,economics.input_actions(),economics.output_actions()).map_err(|_|Error::ReviewMismatch)?;
    let fixed_binding:DurableFixedCandidateBindingV1=wholepact_core::parse_typed_json(&serde_json::to_vec(fixed.identity()).map_err(|_|Error::InvalidData)?).map_err(|_|Error::InvalidData)?;
    let inputs=economics.input_actions().iter().filter(|i|i.account_id==account).map(|map| {
        let input=fixed.private_review_policy().inputs.iter().find(|i|i.action_index==map.action_index).ok_or(Error::ReviewMismatch)?;
        Ok(wholepact_authority::InputReservation {input_id:map.input_id.clone(),nullifier:hex::encode(input.nullifier),action_index:map.action_index as u64,value_zatoshis:input.value_zatoshis})
    }).collect::<Result<Vec<_>>>()?;
    let terms=DurablePaymentAdmissionTermsV1 {version:1,identity:old.terms.identity.clone(),original_policy_digest:old.terms.original_policy_digest.clone(),original_genesis_digest:entry.record()?.account_record.genesis.digest().map_err(|_|Error::ReviewMismatch)?,original_birth_commit_digest:old.terms.birth_commit_digest.clone(),original_roster_extension_digest:extension.digest().map_err(|_|Error::ReviewMismatch)?,original_enrollment_ref:old.enrollment_ref.clone(),writer_certificate_digest:old.terms.signer.writer_certificate_digest.clone(),fixed:fixed_binding.clone(),authorization_id:authority_bridge::durable_proposal_v1::manual_authorization_id(fixed.identity(),&account).map_err(|_|Error::ReviewMismatch)?,recipient_policy_scope_digest,concrete_recipient_scope_digest:wholepact_core::manual_construction::construction_recipient_scope_digest(proposal).map_err(|_|Error::ReviewMismatch)?,inputs:inputs.clone(),maximum_debit_zatoshis:proposal.accounting().participant_net_debits.get(&owner.participant_id).ok_or(Error::ReviewMismatch)?.as_zatoshis(),fee_share_zatoshis:owner.fee_share.as_zatoshis(),transaction_fee_zatoshis:proposal.manifest().transaction_fee.as_zatoshis(),valid_from_ms:active.intent.delivery.valid_from_ms,valid_until_ms:active.intent.delivery.valid_until_ms};
    terms.validate().map_err(|_|Error::ReviewMismatch)?;
    let witness=entry.witness()?.clone();
    if history.disclosure()!=&witness || history.account_policy().policy_digest().map_err(|_|Error::ReviewMismatch)?!=entry.record()?.account_record.terms.original_policy_digest {return Err(Error::Authentication);}
    let scope=DurableDeliveryScopeV2 {version:2,accepted_manifest_ref:active.manifest.reference().into(),original_writer_epoch:old.terms.signer.writer_epoch,original_ceilings:DurableDeliveryOriginalCeilingsV2 {payment_valid_from_ms:terms.valid_from_ms,payment_valid_until_ms:terms.valid_until_ms,enrollment_expires_at_ms:old.terms.scope.expires_at_ms,policy_expires_at_ms:history.account_policy().policy_expires_at_ms,material_scopes:active.intent.material_scopes.clone()},authorization:terms,delivery:active.intent.delivery.clone(),witness:witness.clone(),disclosure_rule:DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness};
    scope.matches_original_claims(history.account_policy(),&extension,proposal,&fixed_binding,active.manifest.reference(),old.terms.signer.writer_epoch,&witness,&inputs,&active.intent.material_scopes).map_err(|_|Error::ReviewMismatch)?;
    active.check()?; Ok(scope)
}
fn prepare_admission(imported:Arc<VerifiedImportV3>)->Result<PreparedAdmissionV3> {
    let active=&imported.active;
    let history=active.witness.history(HistoryReadPurposeV3::PrepareAdmission,active.deadline()?,||active.check())?;
    let scope=exact_scope(&imported,&history)?;
    let request=wholepact_authority::durable_delivery_admission_v2::prepare_durable_delivery_admission_request_v2(scope,&history).map_err(|_|Error::ReviewMismatch)?;
    let prepared=active.source.journal()?.prepare_durable_delivery_admission_intent_v3(&imported,&active.source,active.source.read(),&active.intent,request.clone(),active.source.witness()?.clone(),&active.source.record()?.account_record.terms.signer.owner_certificate_digest)?;
    active.check()?;
    Ok(PreparedAdmissionV3 {imported,request,prepared})
}

impl NativeRuntime {
    pub(super) fn approve_closed_delivery_v3(&mut self, operation:ClosedDeliveryDecisionV3,decision:crate::native_ui::NativeDecision,epoch:u64)->Result<()> {
        let closed=self.closed_delivery_v3.as_mut().ok_or(Error::Unavailable)?;
        if epoch!=closed.epoch {return Err(Error::ReviewMismatch);}
        match operation {
            ClosedDeliveryDecisionV3::Receive => {
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
                self.message="Exact receive/read approved. No transfer socket exists while the Host reviews its export.";
            }
            ClosedDeliveryDecisionV3::Admit => {
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
                        super::delivery_diagnostics_v2::admission_failure_v3(
                            observation, latest_source_error.as_ref(),
                        );
                    }
                    let (controlled,lower_error)=match outcome {Ok(snapshot)=>(Some(snapshot),None),Err(error)=>(None,Some(observe_authority_failure(error)))};
                    // The local intent is final even for a lost response. Drop
                    // action and same-stream transport before any later review.
                    drop(action);
                    Ok(OutcomeV3::Awaiting(AwaitingAuditV3 {retained,controlled,lower_error}))
                })?;
            }
            ClosedDeliveryDecisionV3::History => return self.approve_history_delivery_v3(decision,epoch),
            ClosedDeliveryDecisionV3::HistoryRecipient => {
                let active=closed.active.as_ref().ok_or(Error::Unavailable)?;
                active.check()?;
                let (peer,digest)=closed.history_recipient.take().ok_or(Error::Unavailable)?;
                peer.check_alive()?;
                if !active.history_only || closed.peer.is_some() || decision.binding()!=&active.source.read().binding() || decision.reviewed_digest()!=digest {return Err(Error::ReviewMismatch);}
                closed.peer=Some(peer);
            },
        }
        Ok(())
    }
    pub(super) fn poll_closed_delivery_v3(&mut self,epoch:u64) {
        let Some(mut closed)=self.closed_delivery_v3.take() else{return;};
        if closed.epoch!=epoch {closed.abort(Error::ReviewMismatch);self.pending=None;self.confirmation.zeroize();}
        if closed.phase==DurableDeliveryPhaseV3::AwaitingWitnessReady && closed.admitting.load(Ordering::Acquire) {closed.phase=DurableDeliveryPhaseV3::Admitting;}
        if !matches!(closed.phase,DurableDeliveryPhaseV3::AwaitingAudit|DurableDeliveryPhaseV3::HistoryReview|DurableDeliveryPhaseV3::Complete|DurableDeliveryPhaseV3::Aborted) {
            if let Err(error)=closed.check() {closed.abort(error);self.pending=None;self.confirmation.zeroize();}
        }
        // Complete retains inert historical custody, not display authority. Its
        // separate recipient disclosure review must still redact immediately
        // on read expiry/revocation; never silently restage the same candidate.
        let recipient_review=self.pending.as_ref().is_some_and(|p|matches!(&p.operation,Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::HistoryRecipient)));
        if recipient_review {
            let current=closed.active.as_ref().ok_or(Error::Unavailable).and_then(|active|active.check());
            if let Err(error)=current {closed.abort(error);self.pending=None;self.confirmation.zeroize();}
        }
        if self.pending.as_ref().is_some_and(|p|p.review.expired()) && (recipient_review || matches!(closed.phase,DurableDeliveryPhaseV3::ReceiveReview|DurableDeliveryPhaseV3::AdmissionReview|DurableDeliveryPhaseV3::HistoryReview)) {closed.abort(Error::Locked);self.pending=None;self.confirmation.zeroize();}
        let result=closed.job.as_ref().and_then(|job|match job.receive.try_recv(){Ok(result)=>Some(result),Err(mpsc::TryRecvError::Empty)=>None,Err(mpsc::TryRecvError::Disconnected)=>Some(Err(Error::Unavailable))});
        if let Some(result)=result {
            if let Some(job)=closed.job.take(){let _=job.worker.join();}
            if closed.phase!=DurableDeliveryPhaseV3::Aborted || matches!(&result,Ok(OutcomeV3::Awaiting(_))) {
                let update=(||->Result<()> {
                    match result? {
                        OutcomeV3::ReceiveFailed(error,source)=> {closed.lower_receive_error=Some(error);return Err(source.unwrap_or(Error::Verification));}
                        OutcomeV3::AdmissionFailed(error)=> {closed.lower_admission_error=Some(error);return Err(Error::Authentication);}
                        OutcomeV3::Setup(mut setup)=> {
                            let original_generation=setup.intent.source_generation;
                            if closed.ipc.generation()!=original_generation {return Err(Error::ReviewMismatch);}
                            let closed_generation=original_generation.checked_add(1).ok_or(Error::ReviewMismatch)?;
                            closed.ipc.revoke_legacy_grants_for_closed_delivery_v3()?;
                            if closed.ipc.generation()!=closed_generation {return Err(Error::ReviewMismatch);}
                            setup.intent.source_generation=closed.ipc.generation();
                            setup.source.check_custody()?;
                            let digest=crate::native_ui::authority::receive_review_digest_v3(&setup.intent)?;
                            setup.intent.receive_decision_digest=digest.clone();
                            let review=PreparedDeliveryReadReviewV3::enter(PendingBirthEntry {focus_epoch:epoch,parent_channel:self.parent_channel.clone()},setup.source.identity(),&digest,setup.material_deadline)?;
                            self.pending=Some(PendingDecision {review:ExactNativeReview::stage(review.native(),&digest,format!("RECEIVE AND VIEW EXACT V3\n\nAccount: {}\nFixed proposal: {}\nPayload commitment: {}\nBytes: {}\nOriginal Host process: {}\nPrepared source: {}\n\nA new, revocable read session starts only when you approve. Its 120-second maximum is capped by BOTH original material ceilings. This allows only the displayed one-time inbound proof and private review; no writer, spending, acquisition, signature, extraction or dispatch permission is issued. The Host must separately approve its final exact export.",setup.intent.account_id,setup.intent.fixed.proposal_digest,setup.intent.payload_digest,setup.intent.payload_bytes,setup.intent.authorized_host_process_instance,setup.intent.source_identity_digest) + "\n\nExact public preparation and recipient binding:\n" + &serde_json::to_string_pretty(&setup.intent).map_err(|_|Error::InvalidData)? + "\n\nThe complete private candidate may disclose viewing-key-derived account activity, selected notes, nullifiers, values, witnesses, change ownership, memos and participant linkage to this Signer. No spending key is received. Both original material validity intervals shown above remain absolute limits.",epoch)?,operation:Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::Receive)});
                            closed.setup=Some(setup);closed.read_review=Some(review);closed.phase=DurableDeliveryPhaseV3::ReceiveReview;
                        }
                        OutcomeV3::HistorySetup(setup)=> {
                            setup.source.check_custody()?;
                            let selector=closed.history_selector.as_ref().ok_or(Error::Unavailable)?;
                            let digest=canonical("wholepact:read-reopened-original-admission-history:v3",&(selector,&setup.intent,setup.source.identity()))?;
                            let review=PreparedDeliveryReadReviewV3::enter(PendingBirthEntry {focus_epoch:epoch,parent_channel:self.parent_channel.clone()},setup.source.identity(),&digest,setup.material_deadline)?;
                            self.pending=Some(PendingDecision {review:ExactNativeReview::stage(review.native(),&digest,format!("READ REOPENED ORIGINAL ADMISSION HISTORY\n\n{}\n\nExact historical recipient metadata:\n{}\n\nThis newly unlocked original source has completed its KDF, encrypted history and selected credential validation. A separate fresh read-only session starts after this decision, bounded by both original material ceilings. Authenticate the complete original Witness history for this exact retained operation only. Never resend admission or restore prior receive, admission or financial grants.",serde_json::to_string_pretty(selector).map_err(|_|Error::InvalidData)?,serde_json::to_string_pretty(&setup.intent).map_err(|_|Error::InvalidData)?),epoch)?,operation:Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::History)});
                            closed.setup=Some(setup);closed.read_review=Some(review);closed.phase=DurableDeliveryPhaseV3::HistoryReview;
                        }
                        OutcomeV3::Received(bytes)=> {
                            let active=closed.active.clone().ok_or(Error::Unavailable)?;
                            closed.phase=DurableDeliveryPhaseV3::Verifying;
                            closed.spawn(move||verify_import(active,bytes).map(OutcomeV3::Verified))?;
                        }
                        OutcomeV3::Verified(imported)=> {imported.active.check()?;closed.imported=Some(Arc::new(imported));closed.phase=DurableDeliveryPhaseV3::ImportedVerified;}
                        OutcomeV3::Prepared(prepared)=> {
                            prepared.imported.active.check()?;
                            self.pending=Some(PendingDecision {review:ExactNativeReview::stage(prepared.imported.active.source.read().native(),prepared.prepared.digest(),format!("CONDITIONAL ADMIT EXACT V3\n\n{}\n\nThis is one-use conditional consent only. No action grant or socket is held while the independent Witness reviews. Only actual same-stream mutual-TLS READY for this unchanged request/head can activate the bounded admission action. Acquire, reserve, signing, extraction and dispatch remain disabled.",prepared.prepared.display()?),epoch)?,operation:Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::Admit)});
                            closed.prepared=Some(prepared);closed.phase=DurableDeliveryPhaseV3::AdmissionReview;
                        }
                        OutcomeV3::Awaiting(awaiting)=> {
                            let status=DurableDeliveryAdmissionStatusV3 {version:3,intent_digest:closed.active.as_ref().ok_or(Error::Unavailable)?.intent.digest().map_err(|_|Error::ReviewMismatch)?,request:awaiting.retained.request().clone(),original_local_intent_digest:awaiting.retained.history_digest()?,state:if awaiting.controlled.is_some(){DurableDeliveryAdmissionStateV3::AwaitingAudit}else{DurableDeliveryAdmissionStateV3::Unknown},audit:None};
                            status.validate().map_err(|_|Error::ReviewMismatch)?;
                            let imported=closed.imported.take().ok_or(Error::Unavailable)?;
                            let imported=Arc::try_unwrap(imported).map_err(|_|Error::Unavailable)?;
                            closed.financial_material=Some(imported.fixed);drop(imported.active);
                            closed.prepared=None;closed.awaiting=Some(awaiting);closed.status=Some(status);closed.phase=DurableDeliveryPhaseV3::AwaitingAudit;
                        }
                        OutcomeV3::Audited(status,head)=> {
                            #[cfg(feature="synthetic-born-joined-qualification")]
                            require_completed_v2_entry_refusal_v3(closed.active.as_ref().ok_or(Error::Unavailable)?)?;
                            closed.financial_admitted_head=Some(head);closed.status=Some(status);closed.phase=DurableDeliveryPhaseV3::Complete;
                        }
                    }
                    Ok(())
                })();
                if let Err(error)=update {closed.abort(error);self.pending=None;self.confirmation.zeroize();}
            }
        }
        for _ in 0..8 {
            let Some(event)=closed.ipc.next_event() else{break;};
            if let LocalEvent::DurableReceiveV3(request)=event {
                if let Err(error)=handle_inbound(&mut closed,request) {closed.abort(error);self.pending=None;self.confirmation.zeroize();break;}
            }
            // Every other event, including ordinary pairing and financial
            // operations, is dropped in this structurally closed endpoint.
        }
        if closed.phase==DurableDeliveryPhaseV3::Complete && self.pending.is_none() {
            if let (Some((peer,digest)),Some(active))=(&closed.history_recipient,&closed.active) {
                let staged=(||->Result<PendingDecision> {
                    active.check()?;peer.check_alive()?;
                    Ok(PendingDecision {review:ExactNativeReview::stage(active.source.read().native(),digest,format!("DISCLOSE EXACT ORIGINAL ADMISSION HISTORY TO THIS LOCAL PROCESS\n\nAuthenticated kernel peer UID: {}\nPID: {}\nProcess-instance commitment: {}\nExact historical request:\n{}\n\nThis fresh process may receive only the displayed original prospective admission and authenticated complete-history status. It receives no generic pairing key, private candidate, writer, admission resend or financial grant. The existing fresh read deadline is not renewed.",peer.uid(),peer.pid(),peer.instance(),serde_json::to_string_pretty(closed.history_selector.as_ref().ok_or(Error::Unavailable)?).map_err(|_|Error::InvalidData)?),epoch)?,operation:Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::HistoryRecipient)})
                })();
                match staged {Ok(pending)=>self.pending=Some(pending),Err(error)=>{closed.abort(error);self.confirmation.zeroize();}}
            }
        }
        let history_requested=closed.history_requested;
        closed.history_requested=false;
        self.closed_delivery_v3=Some(closed);
        if history_requested { if let Err(error)=self.begin_durable_delivery_history_audit_v3(epoch) { if let Some(closed)=&mut self.closed_delivery_v3 {closed.failure=Some(error);} } }
    }
}
#[derive(Clone,Copy)]
pub(super) enum ClosedDeliveryDecisionV3 {Receive,Admit,History,HistoryRecipient}
fn handle_inbound(closed:&mut DurableDeliveryRuntimeV3,request:inbound::AuthenticatedDurableReceiveRequestV3)->Result<()> {
    let (mut stream,peer,command)=request.into_parts();
    if let Some(expected)=&closed.peer {expected.same_live_process(&peer)?;} else {
        let ClosedRecipientCommandV3::History {intent_digest,authorization_id,nonce}=&command else {inbound::send_denied_v3(&mut stream).map_err(|_|Error::Uncertain)?;return Ok(());};
        let selector=closed.history_selector.as_ref().ok_or(Error::Unavailable)?;
        if &selector.intent_digest!=intent_digest || &selector.authorization_id!=authorization_id || !matches!(closed.phase,DurableDeliveryPhaseV3::PreparingRead|DurableDeliveryPhaseV3::HistoryReview|DurableDeliveryPhaseV3::Complete) {inbound::send_denied_v3(&mut stream).map_err(|_|Error::Uncertain)?;return Ok(());}
        if let Some((candidate,_))=&closed.history_recipient {candidate.same_live_process(&peer)?;} else {
            let digest=canonical("wholepact:reopened-history-recipient:v3",&(selector,peer.uid(),peer.pid(),peer.instance()))?;
            closed.history_recipient=Some((peer,digest));
        }
        inbound::send_response_v3(&mut stream,&ClosedRecipientResponseV3::Preparing {nonce:nonce.clone()}).map_err(|_|Error::Uncertain)?;
        return Ok(());
    }
    match command {
        ClosedRecipientCommandV3::PreparationStatus {request_digest,nonce}=> {
            if request_digest!=closed.preparation.digest().map_err(|_|Error::ReviewMismatch)? {return Err(Error::ReviewMismatch);}
            if matches!(closed.phase,DurableDeliveryPhaseV3::PreparingRead|DurableDeliveryPhaseV3::ReceiveReview) {inbound::send_response_v3(&mut stream,&ClosedRecipientResponseV3::Preparing {nonce}).map_err(|_|Error::Uncertain)?;}
            else if closed.phase==DurableDeliveryPhaseV3::Ready {
                let active=closed.active.as_ref().ok_or(Error::Unavailable)?;let deadline=active.deadline()?;
                inbound::send_prepared_v3(&mut stream,&nonce,&active.intent,remaining(deadline)?,deadline,||active.check().map_err(bridge_error)).map_err(|_|Error::Uncertain)?;
            }else{return Err(Error::ReviewMismatch);}
        }
        ClosedRecipientCommandV3::Activate {intent_digest,nonce}=> {
            if closed.phase!=DurableDeliveryPhaseV3::Ready {return Err(Error::ReviewMismatch);}
            let active=closed.active.clone().ok_or(Error::Unavailable)?;
            active.check()?;if intent_digest!=active.intent.digest().map_err(|_|Error::ReviewMismatch)? {return Err(Error::ReviewMismatch);}
            let action=active.source.read().consume_receive()?;let deadline=action.deadline();
            inbound::send_ready_v3(&mut stream,&intent_digest,&nonce,remaining(deadline)?,deadline,||active.check().and_then(|_|action.check_current()).map_err(bridge_error)).map_err(|_|Error::Uncertain)?;
            closed.phase=DurableDeliveryPhaseV3::Receiving;
            closed.spawn(move|| {
                let callback_error=std::sync::Mutex::new(None);
                #[cfg(feature="synthetic-born-joined-qualification")]
                let collector=super::durable_delivery_admission_v2::receiver_diagnostics_v2::Collector::default();
                let received=inbound::receive_payload_v3(stream,peer,&active.intent,deadline,||active.check().and_then(|_|action.check_current()).map_err(|error| {
                    #[cfg(feature="synthetic-born-joined-qualification")]
                    collector.source(&error);
                    if let Ok(mut saved)=callback_error.lock() {if saved.is_none(){*saved=Some(error);}}
                    authority_bridge::BridgeError::Permission
                }), |error| {
                    #[cfg(feature="synthetic-born-joined-qualification")]
                    collector.frame(error);
                    #[cfg(not(feature="synthetic-born-joined-qualification"))]
                    let _=error;
                }, |error| {
                    #[cfg(feature="synthetic-born-joined-qualification")]
                    {
                        collector.emit_terminal(error);
                    }
                    #[cfg(not(feature="synthetic-born-joined-qualification"))]
                    let _=error;
                });
                let (bytes,_)=match received {Ok(received)=>received,Err(error)=>return Ok(OutcomeV3::ReceiveFailed(error,callback_error.into_inner().ok().flatten()))};
                drop(action);active.check()?;Ok(OutcomeV3::Received(bytes))
            })?;
        }
        ClosedRecipientCommandV3::VerifyImport {intent_digest,nonce}=> {
            let active=closed.active.as_ref().ok_or(Error::Unavailable)?;active.check()?;
            if intent_digest!=active.intent.digest().map_err(|_|Error::ReviewMismatch)? || !matches!(closed.phase,DurableDeliveryPhaseV3::Receiving|DurableDeliveryPhaseV3::Verifying|DurableDeliveryPhaseV3::ImportedVerified) {return Err(Error::ReviewMismatch);}
            inbound::send_verification_v3(&mut stream,&nonce,closed.imported.as_ref().map(|i|&i.receipt),active.deadline()?,||active.check().map_err(bridge_error)).map_err(|_|Error::Uncertain)?;
        }
        ClosedRecipientCommandV3::Admit {intent_digest,nonce}=> {
            if closed.phase!=DurableDeliveryPhaseV3::ImportedVerified {return Err(Error::ReviewMismatch);}
            let imported=closed.imported.clone().ok_or(Error::Unavailable)?;imported.active.check()?;
            if intent_digest!=imported.active.intent.digest().map_err(|_|Error::ReviewMismatch)? {return Err(Error::ReviewMismatch);}
            inbound::send_response_v3(&mut stream,&ClosedRecipientResponseV3::Admitting {nonce}).map_err(|_|Error::Uncertain)?;
            drop(stream);
            closed.spawn(move||prepare_admission(imported).map(OutcomeV3::Prepared))?;
        }
        ClosedRecipientCommandV3::AdmissionStatus {intent_digest,nonce}=> {
            let active=closed.active.as_ref().ok_or(Error::Unavailable)?;
            let during_effect=matches!(closed.phase,DurableDeliveryPhaseV3::AwaitingWitnessReady|DurableDeliveryPhaseV3::Admitting);
            let check=||if during_effect {active.check_admission_progress()}else{active.check()};
            check()?;
            if intent_digest!=active.intent.digest().map_err(|_|Error::ReviewMismatch)? {return Err(Error::ReviewMismatch);}
            let response=if let Some(status)=&closed.status {ClosedRecipientResponseV3::Admission {nonce,admission:status.clone()}}else{ClosedRecipientResponseV3::Admitting {nonce}};
            inbound::send_response_checked_v3(&mut stream,&response,active.source.read().deadline()?,||check().map_err(bridge_error)).map_err(|_|Error::Uncertain)?;
        }
        ClosedRecipientCommandV3::History {intent_digest,authorization_id,nonce}=> {
            let expected=closed.status.as_ref().ok_or(Error::Unavailable)?;
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record}=&expected.request.control else{return Err(Error::ReviewMismatch);};
            if expected.intent_digest!=intent_digest || record.scope.authorization.authorization_id!=authorization_id {return Err(Error::ReviewMismatch);}
            if closed.phase==DurableDeliveryPhaseV3::Complete {
                let active=closed.active.as_ref().ok_or(Error::Unavailable)?;
                inbound::send_response_checked_v3(&mut stream,&ClosedRecipientResponseV3::Admission {nonce,admission:expected.clone()},active.deadline()?,||active.check().map_err(bridge_error)).map_err(|_|Error::Uncertain)?;
            } else if matches!(closed.phase,DurableDeliveryPhaseV3::AwaitingAudit|DurableDeliveryPhaseV3::HistoryReview) {
                inbound::send_response_v3(&mut stream,&ClosedRecipientResponseV3::Preparing {nonce}).map_err(|_|Error::Uncertain)?;
                if closed.phase==DurableDeliveryPhaseV3::AwaitingAudit {closed.history_requested=true;}
            } else {return Err(Error::Unavailable);}
        },
    }
    Ok(())
}

impl NativeRuntime {
    pub(super) fn close_closed_delivery_v3(&mut self) {
        self.closed_history_prior_v3.zeroize();self.closed_history_selector_v3.zeroize();
        let Some(mut closed)=self.closed_delivery_v3.take() else{return;};
        if let Some(active)=&closed.active {active.source.read().invalidate();}
        closed.ipc.revoke_all();
        self.pending=None;self.confirmation.zeroize();
        let done=Arc::new(AtomicBool::new(false));let finished=done.clone();
        std::thread::spawn(move||{drop(closed);finished.store(true,Ordering::Release);});
        self.closing_accounts.push(done);
    }
    pub(super) fn revoke_closed_delivery_v3(&mut self) {
        self.closed_history_prior_v3.zeroize();self.closed_history_selector_v3.zeroize();
        if let Some(closed)=&mut self.closed_delivery_v3 {
            if let Some(active)=&closed.active {active.source.read().invalidate();}
            closed.read_review=None;closed.setup=None;closed.prepared=None;closed.imported=None;closed.financial_material=None;closed.history_recipient=None;
            if closed.awaiting.is_none() && closed.phase!=DurableDeliveryPhaseV3::Complete {closed.phase=DurableDeliveryPhaseV3::Aborted;}
        }
        self.pending=None;self.confirmation.zeroize();
    }
    pub(super) fn begin_durable_delivery_history_audit_v3(&mut self,epoch:u64)->Result<()> {
        let closed=self.closed_delivery_v3.as_mut().ok_or(Error::Unavailable)?;
        if closed.phase!=DurableDeliveryPhaseV3::AwaitingAudit || closed.job.is_some() || self.pending.is_some() || epoch!=closed.epoch {return Err(Error::Unavailable);}
        let awaiting=closed.awaiting.as_ref().ok_or(Error::Unavailable)?;
        let active=closed.active.as_ref().ok_or(Error::Unavailable)?;
        active.source.check_retained_custody()?;
        let digest=canonical("wholepact:read-exact-original-admission-history:v3",&(awaiting.retained.history_digest()?,awaiting.retained.request(),active.source.identity()))?;
        let time=unix_ms()?;
        let ceiling=active.intent.material_scopes.iter().map(|s|s.valid_until_unix_seconds.saturating_mul(1000)).min().ok_or(Error::Locked)?;
        if time>=ceiling {return Err(Error::Locked);}
        let material_deadline=Instant::now()+Duration::from_millis(ceiling-time);
        let active=match Arc::try_unwrap(closed.active.take().ok_or(Error::Unavailable)?) {Ok(active)=>active,Err(active)=>{closed.active=Some(active);return Err(Error::Unavailable);}};
        let source=active.source.into_history_preparation()?;
        let witness=active.witness.into_history_preparation();
        let review=PreparedDeliveryReadReviewV3::enter(PendingBirthEntry {focus_epoch:epoch,parent_channel:self.parent_channel.clone()},source.identity(),&digest,material_deadline)?;
        self.pending=Some(PendingDecision {review:ExactNativeReview::stage(review.native(),&digest,format!("READ EXACT ORIGINAL ADMISSION HISTORY\n\nOperation: {}\nRetained intent: {}\n\nA fresh read-only session will authenticate complete history from the original Witness and compare this exact immutable operation. It will not resend admission, change the request/head, or acquire any financial permission. The prior action and transfer are closed.",awaiting.retained.request().operation_id,awaiting.retained.history_digest()?),epoch)?,operation:Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::History)});
        closed.setup=Some(SetupV3 {source,witness,original:active.original,enrollment:active.enrollment,manifest:active.manifest,intent:active.intent,peer:active.peer,material_deadline});
        closed.read_review=Some(review);closed.phase=DurableDeliveryPhaseV3::HistoryReview;
        Ok(())
    }
    fn approve_history_delivery_v3(&mut self,decision:crate::native_ui::NativeDecision,epoch:u64)->Result<()> {
        let closed=self.closed_delivery_v3.as_mut().ok_or(Error::Unavailable)?;
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

impl NativeRuntime {
    /// Explicit fresh original-file V3 history entry. The prior DTO selects
    /// exact immutable records only; neither an old grant nor its proof of
    /// approval survives. No V2 source opener or general OpenAccount is used.
    pub(super) fn begin_durable_delivery_history_entry_v3(
        &mut self, focused:bool, epoch:u64, prior:RecipientIntentV3,
        history:DurableDeliveryHistoryRequestV3,
    )->Result<()> {
        #[cfg(feature="offline-review-foundation")]
        if self.named_recipient.final_active() {return Err(Error::Locked);}
        if !focused || epoch==0 || self.open.is_some() || self.closed_delivery_v3.is_some() || self.pending.is_some() || self.signing_job.is_some() || self.pending_account.is_some() || !self.closing_accounts.is_empty() {return Err(Error::Unavailable);}
        if self.durable_entry_job.is_some() || self.durable_delivery_entry_job.is_some() || self.birth.is_active() || self.pending_enrollment.is_active() || self.born_origin.is_active() || self.born_manual.is_active() || self.born_manual_roster_v2.is_active() || self.born_enrolled_backup.is_active() {return Err(Error::Unavailable);}
        prior.validate().map_err(|_|Error::InvalidData)?;history.validate().map_err(|_|Error::InvalidData)?;
        if history.intent_digest!=prior.digest().map_err(|_|Error::InvalidData)? {return Err(Error::ReviewMismatch);}
        self.retirement_evidence_session.before_account_replacement()?;
        let owner=Arc::new(super::super::PendingAccountNativeAuthority::enter_bounded(PendingBirthEntry {focus_epoch:epoch,parent_channel:self.parent_channel.clone()},Instant::now()+Duration::from_secs(120))?);
        let root=std::path::PathBuf::from(&self.root);
        let password=Zeroizing::new(self.password.as_bytes().to_vec());self.password.zeroize();
        let owner_setup=Zeroizing::new(self.owner_witness_setup.to_string());
        let endpoint=super::durable_entry_v1::create_durable_endpoint_v1(&root).map_err(|(_,error)|error)?;
        let preparation=prior.preparation();
        let mut closed=DurableDeliveryRuntimeV3 {phase:DurableDeliveryPhaseV3::PreparingRead,ipc:endpoint.ipc,_directory:Some(endpoint.temporary),preparation,peer:None,setup:None,read_review:None,active:None,imported:None,financial_material:None,financial_admitted_head:None,prepared:None,awaiting:None,job:None,status:None,failure:None,epoch,history_requested:false,history_selector:Some(history),admitting:Arc::new(AtomicBool::new(false)),lower_receive_error:None,lower_admission_error:None,retired_origin:None,retired_peer:None,history_recipient:None,exact_pending_operation:None};
        closed.spawn(move|| {
            let source=PreparedOriginalDeliverySourceV3::open_history(&root,&password,owner,&prior)?;
            let (enrollment,manifest,descriptor,certificate)=source.history_setup_metadata()?;
            let witness=PreparedDeliveryWitnessV3::prepare_history(&owner_setup,&descriptor,&certificate)?;
            let now=unix_ms()?;
            let ceiling=prior.material_scopes.iter().map(|s|s.valid_until_unix_seconds.saturating_mul(1000)).min().ok_or(Error::Locked)?;
            if now>=ceiling {return Err(Error::Locked);}
            source.check_custody()?;
            Ok(OutcomeV3::HistorySetup(SetupV3 {source,witness,original:None,enrollment,manifest,intent:prior,peer:None,material_deadline:Instant::now()+Duration::from_millis(ceiling-now)}))
        })?;
        self.closed_delivery_v3=Some(closed);
        Ok(())
    }
}

impl NativeRuntime {
    /// Deny-only probes against the actual production owner, not a synthetic
    /// source, substitute issuer or inert permission model. These never consume
    /// the still-unused positive receive/admission consent.
    #[cfg(feature="synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn require_closed_delivery_controls_v3(&mut self)->Result<()> {
        self.require_durable_delivery_financial_denied_v3()?;
        let closed=self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?;
        let active=closed.active.as_ref().ok_or(Error::Unavailable)?;
        if closed.retired_origin.as_ref().is_some_and(|origin|origin.check_current().is_ok()) || closed.retired_peer.as_ref().is_some_and(|peer|peer.check_current().is_ok()) {return Err(Error::ReviewMismatch);}
        let read=active.source.read();
        if read.check_source(&"ff".repeat(32)).is_ok() {return Err(Error::ReviewMismatch);}
        if !active.history_only {
            for mutation in 0..11 {
                let mut changed=active.intent.clone();
                match mutation {
                    0=>changed.payload_digest="ff".repeat(32),
                    1=>changed.payload_bytes=changed.payload_bytes.saturating_add(1),
                    2=>changed.source_generation=changed.source_generation.saturating_add(1),
                    3=>changed.provider_enrollment_reference="ff".repeat(32),
                    4=>changed.authorized_host_process_instance="ff".repeat(32),
                    5=>changed.signer_process_instance="ff".repeat(32),
                    6=>changed.read_session_digest="ff".repeat(32),
                    7=>changed.source_identity_digest="ff".repeat(32),
                    8=>changed.receive_decision_digest="ff".repeat(32),
                    9=>changed.source_generation=changed.source_generation.saturating_sub(1),
                    _=>changed.source_generation=u64::MAX,
                }
                if read.check_recipient(&changed).is_ok(){return Err(Error::ReviewMismatch);}
            }
            if matches!(closed.phase,DurableDeliveryPhaseV3::ImportedVerified|DurableDeliveryPhaseV3::AdmissionReview|DurableDeliveryPhaseV3::AwaitingAudit) && read.consume_receive().is_ok() {return Err(Error::ReviewMismatch);}
        } else if read.consume_receive().is_ok() {return Err(Error::ReviewMismatch);}

        Ok(())
    }
}

// One-shot qualification of the genuine producer/fresh-reader audited result.
// This is old V2 entry eligibility refusal, not an attempted V2 mutation. The
// same source's actual revision pin is checked before and after the read-only
// audit, without retaining its mutex across the old checker's transaction.
#[cfg(feature="synthetic-born-joined-qualification")]
fn require_completed_v2_entry_refusal_v3(active: &ActiveV3) -> Result<()> {
    active.source.check_current()?;
    let journal = active.source.journal()?;
    let genesis = &active.source.record()?.account_record.genesis;
    let old_entry = journal.check_durable_delivery_entry_v2(genesis);
    let after = active.source.check_current();
    after?;
    if !matches!(old_entry, Err(crate::consent_journal::JournalError::RecoveryRequired)) {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

fn observe_authority_failure(error:wholepact_authority::AuthorityError)->wholepact_authority::AuthorityError {
    #[cfg(feature="synthetic-born-joined-qualification")]
    {
        let result:authority_bridge::Result<()>=super::delivery_diagnostics_v2::bridge_result(super::delivery_diagnostics_v2::Stage::DeliveryNativeAdmission,Err(authority_bridge::BridgeError::Authority(error)));
        if let Err(authority_bridge::BridgeError::Authority(error))=result {return error;}
        unreachable!("observer returns the same owned result")
    }
    #[cfg(not(feature="synthetic-born-joined-qualification"))]
    {error}
}

impl NativeRuntime {
    pub(in crate::native_ui) fn durable_delivery_v3_endpoint(&self)->Result<std::path::PathBuf> {
        let closed=self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?;
        if closed.phase==DurableDeliveryPhaseV3::Aborted {return Err(Error::Locked);}
        Ok(closed.ipc.socket_path().to_path_buf())
    }
}

impl VerifiedImportV3 {
    pub(crate) fn require_journal_binding_v3(&self,source:&ActivePreparedDeliverySourceV3,read:&Arc<PreparedReceiveAndViewAuthorityV3>,intent:&RecipientIntentV3)->Result<()> {
        self.active.check()?;
        if !std::ptr::eq(&self.active.source,source) || !Arc::ptr_eq(self.active.source.read(),read) || &self.active.intent!=intent || self.fixed.verified().identity()!=&intent.fixed || self.receipt.intent_digest!=intent.digest().map_err(|_|Error::ReviewMismatch)? || self.receipt.verified_fixed_identity_digest!=verified_fixed_identity_digest_v3(&intent.fixed).map_err(|_|Error::ReviewMismatch)? {return Err(Error::ReviewMismatch);}
        Ok(())
    }
}

impl NativeRuntime {
    pub(super) fn closed_history_entry_ui_v3(&mut self,ui:&mut egui::Ui,focused:bool,epoch:u64)->bool {
        let mut entered=false;
        ui.collapsing("Reopen exact V3 admission history",|ui| {
            ui.label("Original-file historical read only. These retained selectors are untrusted data, not permission. The actual original vault, complete encrypted history and selected Witness credentials must authenticate before a new exact native read decision. No admission can be resent.");
            ui.label("Exact original RecipientIntentV3 JSON");
            ui.add(egui::TextEdit::multiline(&mut *self.closed_history_prior_v3).char_limit(65_536).desired_rows(3));
            ui.label("Exact HistoryRequestV3 JSON");
            ui.add(egui::TextEdit::multiline(&mut *self.closed_history_selector_v3).char_limit(4_096).desired_rows(2));
            ui.label("Selected original owner Witness client setup, local only");
            ui.add(egui::TextEdit::multiline(&mut *self.owner_witness_setup).char_limit(16_384).desired_rows(3));
            if ui.button("Unlock originals for exact V3 historical read").clicked_by(egui::PointerButton::Primary) && focused {
                let result=(||->Result<()> {
                    if self.closed_history_prior_v3.len()>65_536 || self.closed_history_selector_v3.len()>4_096 {return Err(Error::InvalidData);}
                    let prior=wholepact_core::strict_json::parse_typed_json_with_byte_limit(self.closed_history_prior_v3.as_bytes(),65_536).map_err(|_|Error::InvalidData)?;
                    let selector=wholepact_core::strict_json::parse_typed_json_with_byte_limit(self.closed_history_selector_v3.as_bytes(),4_096).map_err(|_|Error::InvalidData)?;
                    self.begin_durable_delivery_history_entry_v3(focused,epoch,prior,selector)
                })();
                self.closed_history_prior_v3.zeroize();self.closed_history_selector_v3.zeroize();self.password.zeroize();
                entered=result.is_ok();
                self.message=if entered {"Authenticating original files before a separate exact read-only review."}else{"Original historical entry refused. No old native, pairing, admission or financial authority was restored."};
            }
            if ui.button("Clear historical selectors and credentials").clicked_by(egui::PointerButton::Primary) {
                self.closed_history_prior_v3.zeroize();self.closed_history_selector_v3.zeroize();self.owner_witness_setup.zeroize();self.password.zeroize();
            }
        });
        entered
    }
    pub(in crate::native_ui) fn is_closed_history_review_v3(&self)->bool {
        self.pending.as_ref().is_some_and(|pending|matches!(&pending.operation,Operation::ClosedDeliveryV3(ClosedDeliveryDecisionV3::History|ClosedDeliveryDecisionV3::HistoryRecipient)))
    }
    #[cfg(feature="synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_delivery_v3_provider(&self)->Result<wholepact_signer_origin::InstalledSignerProvider> {
        self.check_durable_delivery_v3()?;
        self.durable_delivery_v3_endpoint()?;
        wholepact_signer_origin::InstalledSignerProvider::qualification_current_process().map_err(|_|Error::Authentication)
    }
}

impl NativeRuntime {
    /// A one-way data-only handoff after successful original admission. No V3
    /// session, IPC grant, source owner or native authority survives this call.
    pub(super) fn detach_financial_material_v1(&mut self)->Result<(crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1,PeerProcess)> {
        let closed=self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?;
        if closed.phase!=DurableDeliveryPhaseV3::Complete||closed.job.is_some()||self.pending.is_some(){return Err(Error::Unavailable);}
        closed.active.as_ref().ok_or(Error::Unavailable)?.source.check_retained_custody()?;
        let mut closed=self.closed_delivery_v3.take().ok_or(Error::Unavailable)?;
        if let Some(active)=&closed.active{active.source.read().invalidate();}
        closed.ipc.revoke_all();closed.prepared=None;closed.setup=None;
        let fixed=closed.financial_material.take().ok_or(Error::Unavailable)?;
        let peer=closed.active.as_ref().and_then(|a|a.peer.clone()).ok_or(Error::Authentication)?;peer.check_alive()?;
        drop(closed);
        self.confirmation.zeroize();
        Ok((fixed,peer))
    }
}

impl NativeRuntime {
    /// Inert proposal from actual admitted V3 history, never a financial grant.
    pub(in crate::native_ui) fn financial_continuation_terms_v1(&self)->Result<wholepact_authority::durable_financial_continuation_v1::FinancialContinuationTermsV1> {
        use wholepact_authority::durable_financial_continuation_v1::{FinancialContinuationTermsV1,original_delivery_request_digest_v1};
        let closed=self.closed_delivery_v3.as_ref().ok_or(Error::Unavailable)?;
        if closed.phase!=DurableDeliveryPhaseV3::Complete||closed.financial_material.is_none()||closed.job.is_some(){return Err(Error::Unavailable);}
        closed.active.as_ref().ok_or(Error::Unavailable)?.source.check_retained_custody()?;
        let status=closed.status.as_ref().ok_or(Error::Unavailable)?;let audit=status.verified_audit().map_err(|_|Error::ReviewMismatch)?;
        let terms=FinancialContinuationTermsV1{scope:audit.scope.clone(),original_delivery_operation_id:status.request.operation_id.clone(),original_delivery_request_digest:original_delivery_request_digest_v1(&status.request).map_err(|_|Error::ReviewMismatch)?,original_delivery_committed_head:closed.financial_admitted_head.clone().ok_or(Error::Unavailable)?,original_local_intent_digest:status.original_local_intent_digest.clone(),original_recipient_intent_digest:status.intent_digest.clone(),original_recipient_enrollment_ref:audit.original_enrollment_ref.clone(),original_recipient_manifest_ref:audit.original_accepted_manifest_ref.clone(),valid_from_ms:audit.scope.delivery.valid_from_ms,valid_until_ms:audit.scope.delivery.valid_until_ms};
        terms.validate().map_err(|_|Error::ReviewMismatch)?;Ok(terms)
    }
}
