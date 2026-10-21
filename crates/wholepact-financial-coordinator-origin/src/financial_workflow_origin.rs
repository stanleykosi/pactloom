//! Genuine full-profile SourceEntry and initial Read paths. No binary activates
//! these yet; the pinned Signer source/UI callsites still require separate review.
use crate::{bootstrap::{self,InertTreeV1,LeafCustody,PhaseDeadlinesV1},rejected,Result,HostOriginV1,
    signer_continue_channel::SignerContinueRoleV1 as Target,
    signer_continue_origin::SignerBirthContext,
    signer_continue_state::{self as state,Core,Phases,PENDING},
    financial_workflow_clock::{FullWorkflowClocksV1,PROFILE,SUPERVISION_MS},
    financial_workflow_channel::{self as wire,Packet,Start,EntryOffer,FinancialActorContextV1,
        SignerSourceEntryFactsV1,SignerSourceEntryPresentationV1,SignerFinancialReadFactsV1,
        SignerFinancialReadPresentationV1,FinancialWorkflowStageV1},
    financial_workflow_source::*,source_entry_envelope as crypto};
use std::{marker::PhantomData,rc::Rc,sync::{Arc,atomic::{AtomicBool,AtomicU8,Ordering}},time::Instant};
use zeroize::Zeroizing;
use crate::FinancialSendProgressV1;
use crate::financial_workflow_continue::*;
use crate::{SignerContinueArmV1,SignerContinueFinalV1,SignerContinueSourceFactsV1,SignerContinueReviewDataV1,
    SignerContinuePresentationV1,SignerContinueOutcomeV1};
use crate::signer_continue_state::SENT;

#[path="financial_normal_completion_origin.rs"]
mod normal_completion;
pub use normal_completion::{FinancialNormalFinishTicketV1,FinancialNormalFinishOutboundV1,FinancialNormalCompletionV1,SignerNormalCloseV1};
#[path="financial_selector_origin.rs"]
mod financial_selector;

#[path="original_signer_host_peer.rs"]
mod original_host_peer;
pub use original_host_peer::OriginalSignerHostPeerV1;

#[path="signer_v3_source_entry_origin.rs"]
mod v3_entry;
use v3_entry::{SV3Entry,CV3Entry,HV3Entry};
pub(super) use v3_entry::V3EntryOffer;
pub use v3_entry::{SignerV3AuditTicketV1,SignerV3AuditOutboundV1,SignerV3AuditFinalV1,SignerV3CompletedLifetimeV1,SignerV3AdmitTicketV1,SignerV3AdmitArmOutboundV1,SignerV3AdmitArmV1,SignerV3AdmitReadyTicketV1,SignerV3AdmitFinalOutboundV1,SignerV3AdmitFinalV1,SignerV3AdmitReadTicketV1,SignerV3AdmitReadOutboundV1,SignerV3AdmitReadFinalV1,SignerV3PrepareReadTicketV1,SignerV3PrepareReadOutboundV1,SignerV3PrepareReadFinalV1,SignerV3PreparedLifetimeV1,SignerV3ReceiveTicketV1,SignerV3ReceiveOutboundV1,SignerV3ReceiveFinalV1,SignerV3RedisclosureReadTicketV1,SignerV3RedisclosureReadOutboundV1,SignerV3RedisclosureReadFinalV1,SignerV3RediscloseTicketV1,SignerV3RediscloseOutboundV1,SignerV3RediscloseFinalV1,SignerV3EnrollmentTicketV1,SignerV3EnrollmentOutboundV1,SignerV3EnrollmentFinalV1,SignerV3ManifestTicketV1,SignerV3ManifestOutboundV1,SignerV3ManifestFinalV1,SignerV3PairTicketV1,SignerV3PairOutboundV1,SignerV3PairFinalV1,SignerV3PairLifetimeV1,SignerV3SourceEntryOfferV1,SignerV3SourceEntryOutboundV1,SignerV3SourceEntryFinalV1,SignerV3SourceEntryInputV1,SignerV3SourceLifetimeV1};

#[path="signer_admit_origin.rs"]
mod admit;
#[path="signer_writer_read_acquire_origin.rs"]
mod writer_acquire;
use writer_acquire::{SWritAcquire,CWritAcquire,HWritAcquire};
#[path="signer_return_origin.rs"]
mod returning;
pub use returning::{SignerReturnReadTicketV1,SignerReturnReadOutboundV1,SignerReturnReadFinalV1,SignerReturnReadCompletedV1,SignerReturnExactTicketV1,SignerReturnExactOutboundV1,SignerReturnExactFinalV1};
#[path="signer_sign_origin.rs"]
mod sign;
pub use sign::{SignerSignReadTicketV1,SignerSignReadOutboundV1,SignerSignReadFinalV1,SignerSignExactTicketV1,SignerSignExactOutboundV1,SignerSignExactFinalV1};
#[path="signer_wallet_origin.rs"]
mod wallet;
pub use wallet::{SignerWalletPrepareTicketV1,SignerWalletPrepareOutboundV1,SignerWalletPrepareFinalV1,SignerWalletObserveTicketV1,SignerWalletObserveOutboundV1,SignerWalletObserveFinalV1};
#[path="signer_activate_wallet_origin.rs"]
mod activate;
use activate::{SActivate,CActivate,HActivate};
pub use activate::{SignerActivateReadTicketV1,SignerActivateReadOutboundV1,SignerActivateReadFinalV1,
    SignerActivateReviewTicketV1,SignerActivateArmOutboundV1,SignerActivateArmV1,SignerActivateReadyTicketV1,SignerActivateFinalV1,SignerActivateFinalOutboundV1};
pub use writer_acquire::{SignerFinancialWriterReadTicketV1,SignerFinancialWriterReadOutboundV1,SignerFinancialWriterReadFinalV1,
    SignerAcquireReviewTicketV1,SignerAcquireArmOutboundV1,SignerAcquireArmV1,SignerAcquireReadyTicketV1,SignerAcquireFinalV1,SignerAcquireFinalOutboundV1};
#[path="financial_witness_coordinator.rs"]
mod witness;
#[path="financial_history_coordinator.rs"]
mod history;
pub(super) use history::HistoryServiceLease;
pub use history::{FinancialHistorySetupTicketV1,FinancialHistorySetupOutboundV1,FinancialHistoryReviewTicketV1,FinancialHistoryServeOutboundV1,FinancialHistoryServingV1,CoordinatorFinancialHistoryEventV1};
#[path="financial_signing_coordinator.rs"]
mod signing;
pub use signing::{FinancialSigningSetupTicketV1,FinancialSigningSetupOutboundV1,FinancialSigningReviewTicketV1,FinancialSigningServeOutboundV1,FinancialSigningServingV1,CoordinatorFinancialSigningEventV1};
#[path="completed_pair_coordinator.rs"]
mod completed_pair;
pub use completed_pair::{FinancialCompletedPairSetupTicketV1,FinancialCompletedPairSetupOutboundV1,FinancialCompletedPairReviewTicketV1,FinancialCompletedPairServeOutboundV1,FinancialCompletedPairServingV1,CoordinatorCompletedPairEventV1};
#[path="signed_result_custody.rs"]
mod signed_custody;
pub use signed_custody::FinancialSignedResultCustodyV1;
#[path="witness_retirement.rs"]
mod retirement;
pub use retirement::{CoordinatorWitnessRetirementTicketV1,CoordinatorWitnessRetirementOutboundV1,CoordinatorWitnessRetiredV1};
pub use witness::{FinancialWitnessSetupTicketV1,FinancialWitnessSetupOutboundV1,FinancialWitnessReviewTicketV1,
    FinancialWitnessArmOutboundV1,FinancialWitnessArmedV1,FinancialWitnessReadyTicketV1,FinancialWitnessFinalOutboundV1,CoordinatorFinancialWitnessEventV1};
pub use admit::{SignerAdmitArmV1,SignerAdmitFinalV1,SignerAdmitReviewTicketV1,SignerAdmitReadyTicketV1,
    SignerAdmitArmOutboundV1,SignerAdmitFinalOutboundV1};
use admit::{SAdmit,CAdmit,HAdmit};

pub enum SignerFinancialWorkflowRequestV1 {
    NormalClose{action:SignerNormalCloseV1},
    V3Enrollment{final_action:SignerV3EnrollmentFinalV1},
    V3Manifest{final_action:SignerV3ManifestFinalV1},
    V3RedisclosureRead{final_action:SignerV3RedisclosureReadFinalV1},
    V3AdmitArm{arm:SignerV3AdmitArmV1},
    V3AdmitFinal{final_action:SignerV3AdmitFinalV1},
    V3AdmitRead{final_action:SignerV3AdmitReadFinalV1},
    V3Audit{final_action:SignerV3AuditFinalV1},
    FinancialSetupSelection{selection:crate::SignerFinancialSetupSelectionV1},
    V3OwnerSelection{owner_setup_json:String,owner_selection_challenge:String},
    V3PrepareRead{final_action:SignerV3PrepareReadFinalV1},
    V3Receive{final_action:SignerV3ReceiveFinalV1},
    V3Redisclose{final_action:SignerV3RediscloseFinalV1},
    OriginalHostPeer(OriginalSignerHostPeerV1),
    V3Pair{final_action:SignerV3PairFinalV1},
    V3SourceEntryRequested{selection:crate::SignerV3SourceEntrySelectionV1},
    V3SourceEntry{input:SignerV3SourceEntryInputV1,final_action:SignerV3SourceEntryFinalV1},
    ReturnRead{final_action:SignerReturnReadFinalV1},ReturnExact{final_action:SignerReturnExactFinalV1},
    SignRead{final_action:SignerSignReadFinalV1},SignExact{final_action:SignerSignExactFinalV1},
    WalletPrepare{final_action:SignerWalletPrepareFinalV1},WalletObserve{final_action:SignerWalletObserveFinalV1},
    ActivateRead(SignerActivateReadFinalV1),ActivateArm(SignerActivateArmV1),ActivateFinal(SignerActivateFinalV1),
    WriterRead(SignerFinancialWriterReadFinalV1),AcquireArm(SignerAcquireArmV1),AcquireFinal(SignerAcquireFinalV1),
    SourceEntryRequested,
    SourceEntry { input:SignerSourceEntryInputV1, final_action:SignerSourceEntryFinalV1 },
    InitialRead(SignerFinancialReadFinalV1), ContinueRequested,
    ContinueArm(SignerContinueArmV1), ContinueFinal(SignerContinueFinalV1), AdmitArm(SignerAdmitArmV1), AdmitFinal(SignerAdmitFinalV1), Cancel,
}
pub struct SignerFinancialWorkflowOriginV1 {
    normal:normal_completion::NormalSState,
    core:Arc<Core>,clocks:FullWorkflowClocksV1,leaf:Option<LeafCustody>,target:Target,instance:String,image:String,
    host_peer_seen:bool,host_peer_deadline:Instant,host_peer_instance:Option<String>,v3_entry:SV3Entry,
    start:Option<Start>,entry:Option<Arc<EntryReviewed>>,recipient:Option<crypto::RecipientKey>,
    read:Option<Arc<ReadReviewed>>,offer_started:bool,read_started:bool,source_reported:bool,history_reported:bool,
    continuation:SContinue,admission:SAdmit,writer_acquire:SWritAcquire,activate:SActivate,failed:bool,cancel_seen:bool,disposed:bool,cleanup:Option<Instant>,
}
impl SignerFinancialWorkflowOriginV1 {
    pub(super) fn from_signer(leaf:LeafCustody,birth:SignerBirthContext)->Result<Self>{
        let target=Target::from_role(leaf.origin.role())?;let clocks=leaf.clocks.workflow();
        let core=Arc::new(Core{retired_roots:std::sync::atomic::AtomicU32::new(0),witness_outbound:[AtomicU8::new(PENDING),AtomicU8::new(PENDING)],phase:Phases::new(),signer_restriction:Some(birth.restriction),peer:leaf.origin.continue_observer()?,roots:Vec::new(),coordinator:Some(birth.coordinator),
            owner_pid:unsafe{libc::getpid()},owner_uid:unsafe{libc::geteuid()},epoch:clocks.epoch(),session:clocks.supervision(),
            alive:AtomicBool::new(true),outbound:[AtomicU8::new(PENDING),AtomicU8::new(PENDING)]});
        core.check()?;crate::channel::require_time(clocks.supervision())?;
        Ok(Self{normal:normal_completion::NormalSState::default(),v3_entry:SV3Entry::default(),host_peer_instance:None,host_peer_seen:false,host_peer_deadline:(Instant::now()+std::time::Duration::from_secs(120)).min(clocks.supervision()),core,clocks,leaf:Some(leaf),target,instance:state::nonce()?,image:birth.image.measurement().to_owned(),start:None,entry:None,
            recipient:None,read:None,offer_started:false,read_started:false,source_reported:false,history_reported:false,
            continuation:SContinue::default(),admission:SAdmit::default(),writer_acquire:SWritAcquire::default(),activate:SActivate::default(),failed:false,cancel_seen:false,disposed:false,cleanup:None})
    }
    pub fn session_deadline(&self)->Instant{self.clocks.supervision()}
    pub fn check_original_actors_alive(&self)->Result<()>{self.core.check()}
    /// Restricts the original terminal cleanup only; no action clock changes.
    pub fn retain_cleanup_deadline(&mut self,original:Instant)->Result<Instant>{
        let retained=self.clocks.retain_cleanup(self.cleanup,original,Instant::now())?;
        self.cleanup=Some(retained);Ok(retained)
    }
    /// No actor check and no initialization: failure cleanup may still read it.
    pub fn original_cleanup_deadline(&self)->Result<Instant>{
        self.cleanup.ok_or_else(||rejected("Signer original cleanup not started"))
    }
    /// Failure-only teardown before joining an owned worker. Publish denial and
    /// close the original H edge even if its first cleanup capture has expired.
    /// This records neither disposal nor successful purpose completion.
    pub fn close_for_failed_worker_v1(&mut self){
        self.failed=true;
        let _=self.restrict();
        self.core.close();
        self.leaf.take();
    }

    fn transport_check(&self)->Result<()>{crate::channel::require_time(self.cleanup.unwrap_or(self.clocks.hard_cleanup()))?;self.core.check()}
    fn send(&self,packet:&Packet)->Result<()>{self.transport_check()?;let r=self.leaf.as_ref().ok_or_else(||rejected("workflow Signer consumed"))?.origin.workflow_send(packet);if r.is_err(){self.core.close();}r}
    fn restrict(&mut self)->Result<()> {
        self.core.phase.revoke();self.recipient.take();self.v3_entry.recipient.take();
        if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}Ok(())
    }
    pub fn try_receive(&mut self)->Result<Option<SignerFinancialWorkflowRequestV1>>{
        let result=self.receive_inner();if result.is_err(){self.core.close();}result
    }
    fn receive_inner(&mut self)->Result<Option<SignerFinancialWorkflowRequestV1>>{
        self.transport_check()?;
        if !self.host_peer_seen {crate::channel::require_time(self.host_peer_deadline)?;}
        let Some(packet)=self.leaf.as_ref().ok_or_else(||rejected("workflow Signer consumed"))?.origin.workflow_receive()? else{return Ok(None)};
        if let Packet::NormalClose{context}=packet{return self.receive_normal_close(context).map(Some);}
        if self.normal.context.is_some()&&!matches!(packet,Packet::Cancel{..}){return Err(rejected("new Source command during normal close"));}
        if let Packet::OriginalHostPeer{role,host_instance} = &packet {
            crate::channel::require_time(self.host_peer_deadline)?;
            if !original_host_peer::first_handshake_allowed(self.host_peer_seen,self.start.is_some(),self.target,*role) {return Err(rejected("original H handshake repeated or reordered"));}
            self.core.check_action_restrictions()?;
            let (uid,pid)=self.leaf.as_ref().ok_or_else(||rejected("original S custody consumed"))?.origin.original_host_identity()?;
            self.host_peer_seen=true;self.host_peer_instance=Some(host_instance.clone());
            let peer=OriginalSignerHostPeerV1::from_authenticated_first_packet(Arc::clone(&self.core),uid,pid,host_instance.clone())?;
            return Ok(Some(SignerFinancialWorkflowRequestV1::OriginalHostPeer(peer)));
        }
        if !self.host_peer_seen && !matches!(packet,Packet::Cancel{..}) {return Err(rejected("original H handshake must precede source workflow"));}
        if !matches!(packet,Packet::Cancel{..}) {
            crate::channel::require_time(self.clocks.supervision())?;
            if self.core.phase.revoked()&&!matches!(packet,Packet::ContinueFinal{..}){return Err(rejected("workflow command after restriction"));}
            // An already C-admitted local Continue Final precedes ordered Cancel
            // and retains its narrow exception. Every other new purpose denies R.
            if !matches!(packet,Packet::ContinueFinal{..}) { self.core.check_action_restrictions()?; }
        }
        if matches!(packet,Packet::V3AdmitArm{..}|Packet::V3AdmitFinal{..}){return self.receive_v3_admission(packet).map(Some);}
        if matches!(packet,Packet::V3AdmitReadFinal{..}){return self.receive_v3_admit_read(packet).map(Some);}
        if matches!(packet,Packet::V3AuditFinal{..}){return self.receive_v3_audit(packet).map(Some);}
        if matches!(packet,Packet::FinancialSetupSelection{..}){return self.receive_financial_setup(packet).map(Some);}
        if matches!(packet,Packet::V3OwnerSelection{..}){return self.receive_v3_owner_selection(packet).map(Some);}
        if matches!(packet,Packet::V3PrepareReadFinal{..}|Packet::V3ReceiveFinal{..}){return self.receive_v3_delivery(packet).map(Some);}
        if matches!(packet,Packet::V3RedisclosureReadFinal{..}|Packet::V3RediscloseFinal{..}){return self.receive_v3_redisclosure(packet).map(Some);}
        if matches!(packet,Packet::V3EnrollmentFinal{..}|Packet::V3ManifestFinal{..}){return self.receive_v3_receipt(packet).map(Some);}
        if matches!(packet,Packet::V3PairFinal{..}){return self.receive_v3_pair(packet).map(Some);}
        if matches!(packet,Packet::V3StartEntry{..}|Packet::V3EntryCipher{..}){return self.receive_v3_entry(packet).map(Some);}
        if matches!(packet,Packet::ReturnReadFinal{..}|Packet::ReturnExactFinal{..}){return self.receive_return(packet).map(Some);}
        if matches!(packet,Packet::SignReadFinal{..}|Packet::SignExactFinal{..}){return self.receive_sign(packet).map(Some);}
        if matches!(packet,Packet::WalletPrepareFinal{..}|Packet::WalletObserveFinal{..}){return self.receive_wallet(packet).map(Some);}
        if matches!(packet,Packet::ActivateReadFinal{..}|Packet::ActivateArm{..}|Packet::ActivateFinal{..}){return self.receive_activate(packet).map(Some);}
        if matches!(packet,Packet::WriterReadFinal{..}|Packet::AcquireArm{..}|Packet::AcquireFinal{..}){return self.receive_writer_acquire(packet).map(Some);}
        if matches!(packet,Packet::AdmitArm{..}|Packet::AdmitFinal{..}) { return self.receive_admit(packet).map(Some); }
        let request=match packet {
            Packet::StartEntry{start}=>{
                start.validate()?;if !self.v3_entry.has_financial_setup()||self.start.is_some()||start.role!=self.target{return Err(rejected("workflow source-entry start repeated or wrong role"));}
                self.clocks.restrict_received(&start.profile,start.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;
                self.core.phase.step(self.target.index(),V3_HELD,ENTRY_PREPARING)?;self.start=Some(start);SignerFinancialWorkflowRequestV1::SourceEntryRequested
            }
            Packet::EntryCipher{envelope}=>{
                // Consume private key before decode/match/decrypt can fail. The
                // actual Input constructor exists only in this original receive.
                let recipient=self.recipient.take().ok_or_else(||rejected("source-entry recipient consumed"))?;
                let entry=self.entry.as_ref().ok_or_else(||rejected("source-entry offer missing"))?;
                let encrypted=crypto::Envelope::decode(envelope.as_bytes())?;
                if encrypted.binding()!=&entry.wire.crypto{return Err(rejected("source-entry ciphertext binding mismatch"));}
                entry.check_action()?;self.core.phase.step(self.target.index(),ENTRY_REVIEW,ENTRY_ADMITTED)?;
                SignerFinancialWorkflowRequestV1::SourceEntry{
                    input:SignerSourceEntryInputV1{entry:Arc::clone(entry),recipient:Some(recipient),envelope:Some(encrypted),consumed:false},
                    final_action:SignerSourceEntryFinalV1{entry:Arc::clone(entry),consumed:false}}
            }
            Packet::ReadFinal{start,presentation_digest,read_digest,read_challenge}=>{
                let read=self.read.as_ref().ok_or_else(||rejected("initial Read offer missing"))?;
                if self.start.as_ref()!=Some(&start)||read.wire.presentation_digest!=presentation_digest
                    ||read.wire.facts.read_digest!=read_digest||read.wire.read_challenge!=read_challenge
                {return Err(rejected("initial Read Final binding mismatch"));}
                read.check()?;self.core.phase.step(self.target.index(),READ_REVIEW,READ_ADMITTED)?;
                SignerFinancialWorkflowRequestV1::InitialRead(SignerFinancialReadFinalV1{read:Arc::clone(read),consumed:false})
            }
            Packet::ContinuePrepare{context}=>{
                context.validate()?;let read=self.read.as_ref().ok_or_else(||rejected("Continue before original Read"))?;
                if !self.history_reported||self.continuation.context.is_some()||!context.matches_read(&read.entry.wire.start,&read.wire){return Err(rejected("full Continue start mismatch"));}
                let draft=self.continuation.draft.as_ref().ok_or_else(||rejected("cached Continue draft missing"))?;
                let retained=self.clocks.restrictive_offset(draft.original_review,read.entry.original_source)?;
                if context.native_ceiling_ms>retained{return Err(rejected("Continue request extended prepared ceiling"));}
                read.entry.check_custody()?;self.clocks.restrict_received(PROFILE,context.native_ceiling_ms,read.entry.original_source,Instant::now())?;
                self.core.phase.step(self.target.index(),HISTORY_RETAINED,CONT_PREPARING)?;self.continuation.context=Some(context);SignerFinancialWorkflowRequestV1::ContinueRequested
            }
            Packet::ContinueArm{context,presentation_digest,prepared_digest}=>{
                let b=self.continuation.binding.as_ref().ok_or_else(||rejected("Continue Arm before display"))?;
                if self.continuation.outcome||!b.wire.matches(&context,&presentation_digest,&prepared_digest){return Err(rejected("full Continue Arm mismatch"));}
                b.check(false)?;self.core.phase.step(self.target.index(),CONT_REVIEW,CONT_ARMED)?;
                SignerFinancialWorkflowRequestV1::ContinueArm(SignerContinueArmV1::from_retained_workflow(Arc::clone(b)))
            }
            Packet::ContinueFinal{context,presentation_digest,prepared_digest,ready_challenge}=>{
                let b=self.continuation.binding.as_ref().ok_or_else(||rejected("Continue Final before display"))?;
                // Consume the actual retained Ready before any fallible final
                // validation. Shared-R observation is not received Cancel.
                let ready=self.continuation.ready.take();
                if self.cancel_seen||self.failed||self.continuation.outcome
                    ||!b.wire.matches(&context,&presentation_digest,&prepared_digest)
                    ||ready.as_ref()!=Some(&ready_challenge){return Err(rejected("full Continue Final mismatch"));}
                b.check(true)?;
                self.core.phase.observe_received_workflow_continue_final(self.target.index())?;
                SignerFinancialWorkflowRequestV1::ContinueFinal(SignerContinueFinalV1::from_retained_workflow(Arc::clone(b),ready_challenge))
            }
            Packet::Cancel{coordinator,session}=>{
                if self.cancel_seen||!state::hash(&coordinator)||!state::hash(&session)
                    ||self.start.as_ref().is_some_and(|s|s.coordinator!=coordinator||s.session!=session)
                    ||!self.v3_entry.cancel_matches(&coordinator,&session)
                {return Err(rejected("workflow Cancel mismatch"));}
                self.cancel_seen=true;self.restrict()?;
                if self.start.is_none(){self.start=Some(Start{profile:PROFILE.into(),coordinator,session,role:self.target,
                    request_challenge:String::new(),native_ceiling_ms:0,sender_public_key:String::new()});}
                SignerFinancialWorkflowRequestV1::Cancel
            }
            _=>return Err(rejected("wrong original Signer workflow command")),
        };Ok(Some(request))
    }
    /// Ordinary source facts only. Actual sealed V3 selection, peer and original
    /// material/source clocks must be supplied by the separately reviewed owner.
    pub fn offer_source_entry(&mut self,facts:SignerSourceEntryFactsV1,original_source_deadline:Instant,original_entry_deadline:Instant)->Result<SignerSourceEntryPresentationV1>{
        if std::mem::replace(&mut self.offer_started,true){self.core.phase.revoke();return Err(rejected("source-entry offer attempted twice"));}
        let result=self.offer_entry_inner(facts,original_source_deadline,original_entry_deadline);
        if result.is_err(){self.core.phase.revoke();self.recipient.take();}result
    }
    fn offer_entry_inner(&mut self,facts:SignerSourceEntryFactsV1,source:Instant,entry_deadline:Instant)->Result<SignerSourceEntryPresentationV1>{
        self.core.check_action_restrictions()?;facts.validate()?;
        if self.core.phase.revoked()||self.core.phase.phase(self.target.index())!=ENTRY_PREPARING{return Err(rejected("source-entry offer phase"));}
        let start=self.start.clone().ok_or_else(||rejected("source-entry request missing"))?;
        self.clocks.restrict_received(&start.profile,start.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;
        let recipient=crypto::RecipientKey::generate()?;let public=recipient.public_key();
        let sender: [u8;32]=hex::decode(&start.sender_public_key).map_err(|_|rejected("sender public key"))?.try_into().map_err(|_|rejected("sender public key length"))?;
        let actor=FinancialActorContextV1{profile:PROFILE.into(),coordinator_process_instance:start.coordinator.clone(),coordinator_focus_epoch:1,
            signer_role:self.target,signer_process_instance:self.instance.clone(),common_image_measurement:self.image.clone(),session_challenge:start.session.clone()};
        let mut presentation=SignerSourceEntryPresentationV1{actor,facts,notice:wire::ENTRY_NOTICE.into(),sender_key_fingerprint:crypto::fingerprint(&sender),
            recipient_key_fingerprint:crypto::fingerprint(&public),request_challenge:start.request_challenge.clone(),offer_challenge:state::nonce()?,
            native_ceiling_ms:start.native_ceiling_ms,entry_ceiling_ms:self.clocks.restrictive_offset(entry_deadline,source)?,
            source_ceiling_ms:self.clocks.restrictive_offset(source,self.clocks.supervision())?,presentation_digest:String::new()};
        presentation.presentation_digest=presentation.calculate_presentation_digest()?;
        let p=&presentation;let f=&p.facts;
        let binding=crypto::Binding{version:1,purpose:"original-signer-source-entry-unlock".into(),suite:"HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305".into(),
            supervision_profile:PROFILE.into(),coordinator_process_instance:start.coordinator.clone(),coordinator_focus_epoch:1,
            signer_role:match self.target{Target::Signer1=>crypto::SourceEntryRole::Signer1,Target::Signer2=>crypto::SourceEntryRole::Signer2},
            signer_process_instance:self.instance.clone(),original_host_process_instance:f.original_host_process_instance.clone(),common_image_measurement:self.image.clone(),
            session_challenge:start.session.clone(),selection_digest:f.selection_digest.clone(),presentation_digest:p.presentation_digest.clone(),account_id:f.account_id.clone(),
            owner_certificate_digest:f.owner_certificate_digest.clone(),disclosure_digest:f.disclosure_digest.clone(),terms_digest:f.terms_digest.clone(),
            request_challenge:start.request_challenge.clone(),offer_challenge:p.offer_challenge.clone(),sender_public_key:start.sender_public_key.clone(),
            sender_key_fingerprint:p.sender_key_fingerprint.clone(),recipient_public_key:hex::encode(public),recipient_key_fingerprint:p.recipient_key_fingerprint.clone(),
            reviewed_at_ms:f.reviewed_at_ms,expires_at_ms:f.expires_at_ms,source_expires_at_ms:f.source_expires_at_ms,
            native_ceiling_ms:start.native_ceiling_ms,entry_ceiling_ms:p.entry_ceiling_ms,source_ceiling_ms:p.source_ceiling_ms,session_ceiling_ms:SUPERVISION_MS};
        let offer=EntryOffer{start,presentation:presentation.clone(),crypto:binding};
        let reviewed=EntryReviewed::new(Arc::clone(&self.core),self.clocks,offer,source,entry_deadline)?;
        self.core.phase.step(self.target.index(),ENTRY_PREPARING,ENTRY_REVIEW)?;
        self.recipient=Some(recipient);self.entry=Some(Arc::clone(&reviewed));
        self.send(&Packet::EntryOffer{offer:reviewed.wire.clone()})?;Ok(presentation)
    }
    /// After the actual worker has completed its full audit and consumed Final
    /// into original custody. No source lock may be held while sending.
    pub fn source_opened(&mut self)->Result<()> {
        self.core.check_action_restrictions()?;
        if self.source_reported||self.core.phase.phase(self.target.index())!=SOURCE_RETAINED||self.core.phase.revoked(){return Err(rejected("source retention phase"));}
        let entry=self.entry.as_ref().ok_or_else(||rejected("source-entry missing"))?;entry.check_custody()?;
        self.source_reported=true;self.send(&Packet::SourceRetained{start:entry.wire.start.clone(),presentation_digest:entry.wire.presentation.presentation_digest.clone()})
    }
    pub fn offer_initial_read(&mut self,facts:SignerFinancialReadFactsV1,original_read_deadline:Instant,original_source_deadline:Instant)->Result<SignerFinancialReadPresentationV1>{
        if std::mem::replace(&mut self.read_started,true){self.core.phase.revoke();return Err(rejected("initial Read attempted twice"));}
        let result=(||{
            if !self.source_reported||self.core.phase.phase(self.target.index())!=SOURCE_RETAINED||self.core.phase.revoked(){return Err(rejected("initial Read offer phase"));}
            let entry=self.entry.as_ref().ok_or_else(||rejected("original entry missing"))?;
            if original_source_deadline!=entry.original_source||!facts.matches_entry(&entry.wire.presentation.facts){return Err(rejected("initial Read changed original source"));}
            entry.check_custody()?;facts.validate()?;
            let mut presentation=SignerFinancialReadPresentationV1{version:2,purpose:wire::READ_PURPOSE.into(),actor:entry.wire.presentation.actor.clone(),facts,notice:wire::READ_NOTICE.into(),
                selection_digest:entry.wire.presentation.facts.selection_digest.clone(),source_entry_presentation_digest:entry.wire.presentation.presentation_digest.clone(),
                read_challenge:state::nonce()?,source_ceiling_ms:entry.wire.presentation.source_ceiling_ms,
                read_ceiling_ms:self.clocks.restrictive_offset(original_read_deadline,entry.original_source)?,presentation_digest:String::new()};
            presentation.presentation_digest=presentation.calculate_presentation_digest()?;
            let read=ReadReviewed::new(Arc::clone(entry),presentation.clone(),original_read_deadline,original_source_deadline)?;
            self.core.phase.step(self.target.index(),SOURCE_RETAINED,READ_REVIEW)?;self.read=Some(read);
            self.send(&Packet::ReadOffer{start:entry.wire.start.clone(),presentation:presentation.clone()})?;Ok(presentation)
        })();if result.is_err(){self.core.phase.revoke();}result
    }
    pub fn history_read(&mut self)->Result<()> {
        self.core.check_action_restrictions()?;
        if self.history_reported||self.core.phase.phase(self.target.index())!=HISTORY_RETAINED||self.core.phase.revoked()||self.continuation.draft.is_none(){return Err(rejected("history and immutable preparation retention phase"));}
        let read=self.read.as_ref().ok_or_else(||rejected("Read missing"))?;read.entry.check_custody()?;
        let draft=self.continuation.draft.as_ref().ok_or_else(||rejected("frozen Continue draft missing"))?;
        let continue_review_ceiling_ms=self.clocks.restrictive_offset(draft.original_review,read.entry.original_source)?;
        self.clocks.restrict_received(PROFILE,continue_review_ceiling_ms,read.entry.original_source,Instant::now())?;self.history_reported=true;
        self.send(&Packet::HistoryRetained{start:read.entry.wire.start.clone(),presentation_digest:read.wire.presentation_digest.clone(),read_digest:read.wire.facts.read_digest.clone(),continue_review_ceiling_ms})
    }
    pub fn begin_continue_review(&mut self,read_final:&SignerFinancialReadFinalV1,facts:SignerContinueSourceFactsV1,original_source_deadline:Instant,original_review_deadline:Instant)->Result<SignerContinueReviewDataV1>{
        if std::mem::replace(&mut self.continuation.attempted,true){self.core.phase.revoke();return Err(rejected("full Continue review attempted twice"));}
        let result=(||{
            if self.core.phase.revoked()||self.core.phase.phase(self.target.index())!=READ_ADMITTED{return Err(rejected("full Continue preparation requires live Read"));}
            let read=self.read.as_ref().ok_or_else(||rejected("completed original Read missing"))?;
            if !Arc::ptr_eq(read,&read_final.read){return Err(rejected("Continue preparation changed original Read grant"));}
            read_final.check_current()?;let f=&read.wire.facts;
            if facts.reviewed_at_ms<f.reviewed_at_ms{return Err(rejected("Continue review predates retained Read"));}
            if original_source_deadline!=read.entry.original_source||facts.source_identity_digest!=f.source_identity_digest
                ||facts.original_host_process_instance!=f.original_host_process_instance||facts.terms_digest!=f.terms_digest
                ||facts.session_digest!=f.session_digest||facts.session_expires_at_ms!=f.source_expires_at_ms{return Err(rejected("Continue substituted completed Read source"));}
            let now=Instant::now();
            if original_review_deadline<=now||original_review_deadline>now+std::time::Duration::from_secs(120){return Err(rejected("Continue original operation ceiling invalid"));}
            crate::channel::require_time(original_source_deadline.min(original_review_deadline).min(self.clocks.supervision()))?;
            let a=&read.wire.actor;
            let review=SignerContinueReviewDataV1{coordinator_process_instance:a.coordinator_process_instance.clone(),coordinator_focus_epoch:a.coordinator_focus_epoch,
                signer_role:a.signer_role,signer_process_instance:a.signer_process_instance.clone(),signer_image_measurement:a.common_image_measurement.clone(),
                original_host_process_instance:facts.original_host_process_instance,signer_principal_id:facts.signer_principal_id,
                source_identity_digest:facts.source_identity_digest,terms_digest:facts.terms_digest,session_digest:facts.session_digest,
                review_challenge:state::nonce()?,review_digest:facts.review_digest,reviewed_at_ms:facts.reviewed_at_ms,expires_at_ms:facts.expires_at_ms,
                session_expires_at_ms:facts.session_expires_at_ms};
            review.validate()?;wall_ceiling(now,state::wall_ms()?,review.reviewed_at_ms,review.expires_at_ms)?;
            read_final.check_current()?;
            self.continuation.draft=Some(ContinueDraft{review:review.clone(),original_review:original_review_deadline});Ok(review)
        })();if result.is_err(){self.core.phase.revoke();}result
    }
    pub fn send_continue_display(&mut self,presentation:SignerContinuePresentationV1)->Result<()>{
        let result=(||{
            if !self.history_reported||self.core.phase.phase(self.target.index())!=CONT_PREPARING{return Err(rejected("Continue display before completed authorized Read/preparation"));}
            let draft=self.continuation.draft.take().ok_or_else(||rejected("full Continue draft consumed"))?;
            if presentation.review!=draft.review||self.continuation.binding.is_some(){return Err(rejected("full Continue display mismatch"));}
            let read=self.read.as_ref().ok_or_else(||rejected("full Continue retained Read missing"))?;
            let wire=ContinueWire{context:self.continuation.context.clone().ok_or_else(||rejected("full Continue context missing"))?,presentation,
                source_ceiling_ms:read.wire.source_ceiling_ms,review_ceiling_ms:self.clocks.restrictive_offset(draft.original_review,read.entry.original_source)?};
            let b=FullContinueReviewed::new(Arc::clone(read),wire,read.entry.original_source,draft.original_review)?;
            self.core.phase.step(self.target.index(),CONT_PREPARING,CONT_REVIEW)?;self.continuation.binding=Some(Arc::clone(&b));
            self.send(&Packet::ContinueDisplay{binding:b.wire.clone()})
        })();if result.is_err(){self.core.phase.revoke();}result
    }
    pub fn send_continue_ready(&mut self,arm:SignerContinueArmV1)->Result<()>{
        let b=self.continuation.binding.as_ref().ok_or_else(||rejected("full Continue display missing"))?;
        if !arm.matches_retained_workflow(b)||self.continuation.ready.is_some()||self.continuation.outcome{return Err(rejected("full Continue Arm mismatch"));}
        arm.check_current()?;let challenge=state::nonce()?;
        self.core.phase.step(self.target.index(),CONT_ARMED,CONT_READY)?;self.continuation.ready=Some(challenge.clone());
        self.send(&Packet::ContinueReady{context:b.wire.context.clone(),presentation_digest:b.wire.presentation.presentation_digest.clone(),
            prepared_digest:b.wire.presentation.prepared_digest.clone(),ready_challenge:challenge})
    }
    /// Actual local commit has returned source20 + Context/Pending to this same
    /// role. This is nonterminal observation, not permission for a fresh Admit.
    pub fn continuation_saved(&mut self,data:SignerContinuationSavedV1)->Result<()>{
        data.validate()?;let b=self.continuation.binding.as_ref().ok_or_else(||rejected("saved Continue without display"))?;
        if self.continuation.outcome||!data.matches(&b.wire.presentation){return Err(rejected("saved Continue binding mismatch"));}
        self.core.phase.observe_workflow_continue_saved(self.target.index())?;self.continuation.outcome=true;self.continuation.saved=Some(data.clone());
        self.send(&Packet::ContinuationSaved{context:b.wire.context.clone(),data})
    }
    pub fn send_continue_outcome(&mut self,data:SignerContinueOutcomeV1)->Result<()>{
        let b=self.continuation.binding.as_ref().ok_or_else(||rejected("Continue outcome without display"))?;
        if self.continuation.outcome||!failed_outcome(&data,&b.wire.presentation){return Err(rejected("Continue terminal observation mismatch"));}
        let context=b.wire.context.clone();self.continuation.outcome=true;self.restrict()?;
        self.send(&Packet::ContinueOutcome{context,data})
    }
    pub fn send_failed(&mut self,stage:FinancialWorkflowStageV1)->Result<()> {
        if self.failed||self.disposed{return Err(rejected("workflow failure repeated"));}
        let start=self.start.clone().ok_or_else(||rejected("workflow failure before request"))?;
        let phase=self.core.phase.phase(self.target.index());
        if (stage==FinancialWorkflowStageV1::SourceEntry&&!matches!(phase,ENTRY_PREPARING|ENTRY_REVIEW|ENTRY_ADMITTED))
            ||(stage==FinancialWorkflowStageV1::InitialRead&&!matches!(phase,SOURCE_RETAINED|READ_REVIEW|READ_ADMITTED))
            ||(stage==FinancialWorkflowStageV1::Continue&&phase!=CONT_PREPARING)
        {return Err(rejected("workflow failure phase mismatch"));}
        self.failed=true;self.restrict()?;self.send(&Packet::Failed{start,stage})
    }
    /// Observation only, after actual worker join and source/key/input drop.
    pub fn send_disposed(&mut self)->Result<()> {
        if self.disposed||!self.cancel_seen||!self.v3_entry.disposal_allowed()||!self.admission.disposal_allowed()||!self.writer_acquire.disposal_allowed()||!self.activate.disposal_allowed()||(self.continuation.binding.is_some()&&!self.continuation.outcome){return Err(rejected("workflow disposal before Cancel/outcome"));}
        let start=self.start.as_ref().ok_or_else(||rejected("workflow disposal context missing"))?;
        self.disposed=true;self.send(&Packet::Disposed{coordinator:start.coordinator.clone(),session:start.session.clone(),role:self.target})
    }
    pub fn complete(mut self,work:Result<()>)->! {
        let work=work.and_then(|()|if self.cancel_seen&&self.disposed{Ok(())}else{Err(rejected("workflow actual disposal missing"))});
        self.recipient.take();self.core.phase.revoke();self.core.alive.store(false,Ordering::Release);
        let result=match self.leaf.take(){Some(leaf)=>bootstrap::finish_leaf_capped(leaf,work,self.cleanup),None=>Err(rejected("workflow Signer consumed"))};
        self.core.close();bootstrap::child_exit(result)
    }
}
impl Drop for SignerFinancialWorkflowOriginV1{fn drop(&mut self){self.core.close();}}

/// Whole pinned-image native controller only. No bool/event importer, key work,
/// lock, transport or source acquisition occurs in these two native A methods.
pub struct CoordinatorFinancialNativeV1{core:Arc<Core>,_thread:PhantomData<Rc<()>>}
impl CoordinatorFinancialNativeV1 {
    pub fn revoke(&self){self.core.phase.revoke();}
    pub fn is_revoked(&self)->bool{self.core.phase.revoked()}
    pub fn session_deadline(&self)->Instant{self.core.session}
    pub fn check_current(&self)->Result<()>{
        let result=(||{self.core.check()?;crate::channel::require_time(self.core.session)?;
            if self.core.phase.revoked(){return Err(rejected("native workflow restricted"));}Ok(())})();
        if result.is_err(){self.revoke();}result
    }
    pub fn admit_source_entry(&self,mut offer:SignerSourceEntryOfferV1,password:Zeroizing<Vec<u8>>,input_request_digest:&str)->Result<SignerSourceEntryOutboundV1>{
        let entry=&offer.entry;
        if !Arc::ptr_eq(&self.core,&entry.core)||!(12..=1024).contains(&password.len())||input_request_digest!=entry.wire.crypto.request_digest()?{
            self.revoke();return Err(rejected("source-entry native input binding mismatch"));}
        entry.check_action()?;self.core.phase.step(entry.slot(),ENTRY_REVIEW,ENTRY_ADMITTED)?;
        offer.consumed=true;Ok(SignerSourceEntryOutboundV1{entry:Arc::clone(entry),password:Some(password),consumed:false})
    }
    pub fn arm_continue(&self,mut ticket:FinancialContinueReviewTicketV1)->Result<FinancialContinueArmOutboundV1>{
        if !Arc::ptr_eq(&self.core,ticket.binding.core()){self.revoke();return Err(rejected("foreign full Continue review"));}
        ticket.check_current()?;self.core.phase.step(ticket.binding.slot(),CONT_REVIEW,CONT_ARMED)?;
        ticket.consumed=true;Ok(FinancialContinueArmOutboundV1{binding:Arc::clone(&ticket.binding),consumed:false})
    }
    pub fn admit_continue(&self,mut ticket:FinancialContinueReadyTicketV1)->Result<FinancialContinueFinalOutboundV1>{
        let b=&ticket.binding.review;
        if !Arc::ptr_eq(&self.core,b.core()){self.revoke();return Err(rejected("foreign full Continue Ready"));}
        ticket.check_current()?;self.core.phase.step(b.slot(),CONT_READY,CONT_ADMITTED)?;
        ticket.consumed=true;Ok(FinancialContinueFinalOutboundV1{binding:Arc::clone(&ticket.binding),consumed:false})
    }
    pub fn admit_initial_read(&self,mut ticket:SignerFinancialReadTicketV1,serving:&FinancialHistoryServingV1)->Result<SignerFinancialReadOutboundV1>{
        let read=&ticket.read;
        if !Arc::ptr_eq(&self.core,&read.entry.core){self.revoke();return Err(rejected("foreign initial Read ticket"));}
        read.check()?;serving.matches_read(&self.core,read)?;let service=serving.retain()?;self.core.phase.step(read.entry.slot(),READ_REVIEW,READ_ADMITTED)?;
        ticket.consumed=true;Ok(SignerFinancialReadOutboundV1{read:Arc::clone(read),service,consumed:false})
    }
}
impl Drop for CoordinatorFinancialNativeV1{fn drop(&mut self){if self.core.phase.normal_phase()!=5{self.revoke();}}}
pub enum CoordinatorFinancialEventV1 {
    NormalCompletionReview(FinancialNormalFinishTicketV1),
    FinancialResultSelector{role:Target,data:crate::SignerFinancialResultSelectorV1},
    V3PairEndpoint{role:Target,data:crate::SignerV3PairEndpointV1},
    V3PairDisplay(SignerV3PairTicketV1),
    V3Paired{role:Target,data:crate::SignerV3PairedV1},
    V3EnrollmentDisplay(SignerV3EnrollmentTicketV1),
    V3ManifestDisplay(SignerV3ManifestTicketV1),
    V3Enrolled{role:Target,data:crate::SignerV3EnrollmentCommittedV1},
    V3ManifestAccepted{role:Target,data:crate::SignerV3ManifestCommittedV1},
    V3RedisclosureReadDisplay(SignerV3RedisclosureReadTicketV1),
    V3AdmitDisplay(SignerV3AdmitTicketV1),
    V3AdmitReady(SignerV3AdmitReadyTicketV1),
    V3Admitted{role:Target,data:crate::SignerV3AdmittedV1},
    V3AdmitReadDisplay(SignerV3AdmitReadTicketV1),
    V3AdmitReadRetained{role:Target,data:crate::SignerV3AdmitReadRetainedV1},
    V3AuditDisplay(SignerV3AuditTicketV1),
    V3Audited{role:Target,data:crate::SignerV3AuditedV1},
    V3PrepareReadDisplay(SignerV3PrepareReadTicketV1),
    V3ReceiveDisplay(SignerV3ReceiveTicketV1),
    V3Prepared{role:Target,data:crate::SignerV3PreparedV1},
    V3Received{role:Target,data:crate::SignerV3ReceivedV1},
    V3RediscloseDisplay(SignerV3RediscloseTicketV1),
    V3RedisclosurePrepared{role:Target,data:crate::SignerV3RedisclosurePreparedV1},
    V3Redisclosed{role:Target,data:crate::SignerV3RedisclosedV1},
    V3SourceEntryOffer(SignerV3SourceEntryOfferV1),
    V3SourceOpened{role:Target,data:crate::SignerV3SourceOpenedV1},
    V3SourceEntryFailed{role:Target,presentation_digest:Option<String>},
    ReturnReadDisplay(SignerReturnReadTicketV1),ReturnExactDisplay(SignerReturnExactTicketV1),ReturnPrepared{role:Target,data:crate::SignerReturnPreparedV1},ReturnCompleted{role:Target,data:crate::SignerReturnCompletedV1},ReturnFailed{role:Target,data:crate::SignerReturnFailureV1},
    SignReadDisplay(SignerSignReadTicketV1),SignExactDisplay(SignerSignExactTicketV1),SignPrepared{role:Target,data:crate::SignerSignPreparedV1},SignCommitted{role:Target,data:crate::SignerSignCommittedV1},SignFailed{role:Target,data:crate::SignerSignFailureV1},
    WalletPrepareDisplay(SignerWalletPrepareTicketV1),WalletObserveDisplay(SignerWalletObserveTicketV1),WalletPrepared{role:Target,data:crate::SignerWalletPreparedV1},WalletObserved{role:Target,data:crate::SignerWalletObservedV1},WalletFailed{role:Target,data:crate::SignerWalletFailureV1},
    ActivateReadDisplay(SignerActivateReadTicketV1),ActivateReadFailed{role:Target,presentation_digest:String},
    ActivateDisplay(SignerActivateReviewTicketV1),ActivateReady(SignerActivateReadyTicketV1),ActivateOutcome{role:Target,data:crate::SignerActivateOutcomeV1},
    AwaitingWalletPrepare{role:Target,data:crate::SignerActivateCommittedV1},
    WriterReadDisplay(SignerFinancialWriterReadTicketV1),WriterReadFailed{role:Target,presentation_digest:String},
    AcquireDisplay(SignerAcquireReviewTicketV1),AcquireReady(SignerAcquireReadyTicketV1),AcquireOutcome{role:Target,data:crate::SignerAcquireOutcomeV1},
    AwaitingActivateRead{role:Target,data:crate::SignerAcquireCommittedV1},
    AdmitDisplay(SignerAdmitReviewTicketV1), AdmitReady(SignerAdmitReadyTicketV1),
    AwaitingNextRead{role:Target,data:crate::SignerAdmitCommittedV1}, AdmitOutcome{role:Target,data:crate::SignerAdmitOutcomeV1},
    SourceEntryOffer(SignerSourceEntryOfferV1), SourceRetained(Target), InitialReadOffer(SignerFinancialReadTicketV1),
    HistoryRetained{role:Target,continue_deadline:Instant}, ContinueDisplay(FinancialContinueReviewTicketV1), ContinueReady(FinancialContinueReadyTicketV1),
    AwaitingAdmission{role:Target,data:SignerContinuationSavedV1}, ContinueOutcome{role:Target,data:SignerContinueOutcomeV1}, Failed{role:Target,stage:FinancialWorkflowStageV1}, Disposed(Target), Restricted(Target),
}
struct CSlot{start:Start,sender:Option<crypto::SenderKey>,entry:Option<Arc<EntryReviewed>>,read:Option<Arc<ReadReviewed>>,wire_phase:u8,continue_deadline:Option<Instant>,continue_review_ms:Option<u64>,continuation:Option<CContinue>,admission:CAdmit,writer_acquire:CWritAcquire,activate:CActivate,failed:bool}
pub struct CoordinatorFinancialEndpointV1{
    normal:normal_completion::NormalCState,
    v3_entries:[CV3Entry;2],
    core:Arc<Core>,clocks:FullWorkflowClocksV1,tree:Option<InertTreeV1>,coordinator:String,session:String,image:String,
    host_terminal:Option<crate::CoordinatorHostTerminalEndpointV1>,retirement_resume:Option<Instant>,
    witnesses:[witness::CWSlot;2],histories:[history::CHSlot;2],signing_services:[signing::CGSlot;2],pair_service:completed_pair::CPState,slots:[Option<CSlot>;2],cancel_sent:bool,disposed:[bool;2],cleanup:Option<Instant>,
}
pub(super) fn split_coordinator(tree:InertTreeV1,phases:PhaseDeadlinesV1,
    host_restriction:crate::host_restriction::CoordinatorHostRestrictionV1,
    host_terminal:crate::CoordinatorHostTerminalEndpointV1,
)->Result<(CoordinatorFinancialNativeV1,CoordinatorFinancialEndpointV1)>{
    // Install the C writer before any fallible lookup/duplication. Its local
    // Drop then publishes R before the tree parameter can enter a reaper.
    let phase=Phases::coordinator(host_restriction);
    let clocks=phases.workflow();let image=tree.workflow_image();
    let core=Arc::new(Core{retired_roots:std::sync::atomic::AtomicU32::new(0),witness_outbound:[AtomicU8::new(PENDING),AtomicU8::new(PENDING)],phase,signer_restriction:None,peer:tree.continue_host()?.continue_observer()?,roots:tree.continue_pidfds()?,coordinator:None,
        owner_pid:unsafe{libc::getpid()},owner_uid:unsafe{libc::geteuid()},epoch:clocks.epoch(),session:clocks.supervision(),
        alive:AtomicBool::new(true),outbound:[AtomicU8::new(PENDING),AtomicU8::new(PENDING)]});
    core.check()?;crate::channel::require_time(clocks.supervision())?;
    // Finish fallible setup before moving tree custody into a partial tuple.
    // On error the local Core/writer drops before the tree parameter's reapers.
    let coordinator=state::nonce()?;let session=state::nonce()?;
    Ok((CoordinatorFinancialNativeV1{core:Arc::clone(&core),_thread:PhantomData},CoordinatorFinancialEndpointV1{
        normal:normal_completion::NormalCState::default(),v3_entries:std::array::from_fn(|_|CV3Entry::default()),core,clocks,tree:Some(tree),coordinator,session,image,host_terminal:Some(host_terminal),retirement_resume:None,witnesses:std::array::from_fn(|_|witness::CWSlot::default()),histories:std::array::from_fn(|_|history::CHSlot::default()),signing_services:std::array::from_fn(|_|signing::CGSlot::default()),pair_service:completed_pair::CPState::default(),slots:[None,None],cancel_sent:false,disposed:[false;2],cleanup:None}))
}
impl CoordinatorFinancialEndpointV1 {
    /// One C-only transport handoff to the sole owned driver, never authority.
    /// The terminal is privately bound to this same Core before it can escape.
    pub fn take_host_terminal(&mut self)->Result<crate::CoordinatorHostTerminalEndpointV1>{
        let terminal=self.host_terminal.take().ok_or_else(||rejected("original Host terminal already consumed"))?;
        let result=(||{
            self.core.check()?;crate::channel::require_time(self.clocks.supervision())?;
            if self.core.phase.revoked(){return Err(rejected("workflow permanently restricted"));}
            terminal.bind_workflow(Arc::clone(&self.core))
        })();
        if result.is_err(){self.core.phase.revoke();}result
    }
    pub fn session_deadline(&self)->Instant{self.clocks.supervision()}
    pub fn check_original_tree_alive(&self)->Result<()>{self.core.check()}
    /// Restriction-only ongoing supervision, not source or action authority.
    /// Completed stages retain source clocks, never an expired prior action cap.
    pub fn observe_restrictions(&self)->Result<()>{
        let result=(||{
            self.core.check()?;crate::channel::require_time(self.clocks.supervision())?;
            if self.core.phase.revoked(){return Err(rejected("workflow permanently restricted"));}
            for (i,slot) in self.v3_entries.iter().enumerate(){slot.observe_active(self.core.phase.phase(i),self.clocks)?;}
            for (i,slot) in self.slots.iter().enumerate(){
                let Some(slot)=slot else{continue};let phase=self.core.phase.phase(i);
                if phase==ENTRY_PREPARING {
                    self.clocks.restrict_received(PROFILE,slot.start.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;
                }
                if let Some(entry)=&slot.entry {
                    entry.check_custody()?;
                    if matches!(phase,ENTRY_REVIEW|ENTRY_ADMITTED){entry.check_action()?;}
                }
                if phase==CONT_PREPARING{
                    let c=slot.continuation.as_ref().ok_or_else(||rejected("Continue context missing"))?;
                    self.clocks.restrict_received(PROFILE,c.context.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;
                }
                if matches!(phase,CONT_REVIEW|CONT_ARMED|CONT_READY|CONT_ADMITTED){
                    slot.continuation.as_ref().and_then(|c|c.binding.as_ref()).ok_or_else(||rejected("active Continue binding missing"))?.check(false)?;
                }
                if matches!(phase,READ_REVIEW|READ_ADMITTED){
                    slot.read.as_ref().ok_or_else(||rejected("active Read binding missing"))?.check()?;
                }
                slot.admission.observe_active(phase)?;slot.writer_acquire.observe_active(phase)?;slot.activate.observe_active(phase)?;
            }
            for (i,w) in self.witnesses.iter().enumerate(){w.observe_active(&self.core,i)?;}
            for(i,h)in self.histories.iter().enumerate(){h.observe_active(&self.core,i)?;}
            for(i,g)in self.signing_services.iter().enumerate(){g.observe_active(&self.core,i)?;}
            self.pair_service.observe_active(&self.core)?;
            Ok(())
        })();if result.is_err(){self.core.phase.revoke();}result
    }
    fn transport_check(&self)->Result<()>{crate::channel::require_time(self.cleanup.unwrap_or(self.clocks.hard_cleanup()))?;self.core.check()}
    fn send(&self,packet:&Packet)->Result<()>{self.transport_check()?;let r=self.tree.as_ref().ok_or_else(||rejected("workflow tree consumed"))?.continue_host()?.workflow_send(packet);if r.is_err(){self.core.close();}r}
    fn send_positive(&self,packet:&Packet,deadline:Instant)->Result<FinancialSendProgressV1>{
        self.transport_check()?;
        let result=self.tree.as_ref().ok_or_else(||rejected("workflow tree consumed"))?.continue_host()?.workflow_send_positive(packet,&self.core.phase,deadline);
        if result.is_err(){self.core.close();}result
    }
    pub fn begin_source_entry_signer1(&mut self,deadline:Instant)->Result<()>{self.try_begin_source_entry(Target::Signer1,deadline)?.require_sent()}
    pub fn begin_source_entry_signer2(&mut self,deadline:Instant)->Result<()>{self.try_begin_source_entry(Target::Signer2,deadline)?.require_sent()}
    pub fn try_begin_source_entry(&mut self,target:Target,original:Instant)->Result<FinancialSendProgressV1>{
        let result=(||{
            self.core.check()?;let i=target.index();
            if self.slots[i].is_some()||!self.v3_entries[i].has_financial_setup(){return Err(rejected("source-entry preparation repeated or ordinary setup absent"));}
            let now=Instant::now();let ceiling=original.min(self.clocks.supervision()).min(now+std::time::Duration::from_secs(120));
            crate::channel::require_time(ceiling)?;
            if self.core.phase.source_send_restricted(i,V3_HELD)?{return Ok(FinancialSendProgressV1::Restricted);}
            if let Err(error)=self.core.phase.step(i,V3_HELD,ENTRY_PREPARING){
                if self.core.phase.source_send_restricted(i,V3_HELD)?{return Ok(FinancialSendProgressV1::Restricted);}return Err(error);
            }
            let sender=crypto::SenderKey::generate()?;
            let start=Start{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),role:target,
                request_challenge:state::nonce()?,native_ceiling_ms:self.clocks.restrictive_offset(ceiling,original)?,sender_public_key:hex::encode(sender.public_key())};
            self.slots[i]=Some(CSlot{start:start.clone(),sender:Some(sender),entry:None,read:None,wire_phase:ENTRY_PREPARING,continue_deadline:None,continue_review_ms:None,continuation:None,admission:CAdmit::default(),writer_acquire:CWritAcquire::default(),activate:CActivate::default(),failed:false});
            self.core.check()?;self.clocks.restrict_received(&start.profile,start.native_ceiling_ms,original,Instant::now())?;
            if self.core.phase.source_send_restricted(i,ENTRY_PREPARING)?{return Ok(FinancialSendProgressV1::Restricted);}
            self.send_positive(&Packet::StartEntry{start},ceiling)
        })();
        if !matches!(&result,Ok(FinancialSendProgressV1::Sent)){if result.is_err(){self.core.phase.revoke();}if let Some(slot)=&mut self.slots[target.index()]{slot.sender.take();}}
        result
    }
    pub fn send_source_entry(&mut self,outbound:SignerSourceEntryOutboundV1)->Result<()>{self.try_send_source_entry(outbound)?.require_sent()}
    pub fn try_send_source_entry(&mut self,mut outbound:SignerSourceEntryOutboundV1)->Result<FinancialSendProgressV1>{
        let entry=Arc::clone(&outbound.entry);let i=entry.slot();
        let key=self.slots[i].as_mut().and_then(|s|s.sender.take());let password=outbound.password.take();
        let result=(||{
            if !Arc::ptr_eq(&self.core,&entry.core)||self.slots[i].as_ref().and_then(|s|s.entry.as_ref()).is_none_or(|b|!Arc::ptr_eq(b,&entry))
                ||self.slots[i].as_ref().is_none_or(|s|s.wire_phase!=ENTRY_REVIEW){return Err(rejected("foreign or repeated source-entry outbound"));}
            entry.check_action_bounds()?;
            if self.core.phase.source_send_restricted(i,ENTRY_ADMITTED)?{return Ok(FinancialSendProgressV1::Restricted);}
            let encrypted=key.ok_or_else(||rejected("sender key consumed"))?.seal(entry.wire.crypto.clone(),password.ok_or_else(||rejected("source-entry input consumed"))?)?;
            let envelope=String::from_utf8(encrypted.encode()?).map_err(|_|rejected("source-entry ciphertext encoding"))?;
            entry.check_action_bounds()?;
            if self.core.phase.source_send_restricted(i,ENTRY_ADMITTED)?{return Ok(FinancialSendProgressV1::Restricted);}
            let progress=self.send_positive(&Packet::EntryCipher{envelope},entry.ceiling)?;
            if progress==FinancialSendProgressV1::Sent{self.slots[i].as_mut().unwrap().wire_phase=ENTRY_ADMITTED;}Ok(progress)
        })();outbound.consumed=true;if result.is_err(){self.core.phase.revoke();}result
    }
    pub fn send_initial_read(&mut self,outbound:SignerFinancialReadOutboundV1)->Result<()>{self.try_send_initial_read(outbound)?.require_sent()}
    pub fn try_send_initial_read(&mut self,mut outbound:SignerFinancialReadOutboundV1)->Result<FinancialSendProgressV1>{
        let read=&outbound.read;let i=read.entry.slot();
        if !Arc::ptr_eq(&self.core,&read.entry.core)||self.slots[i].as_ref().and_then(|s|s.read.as_ref()).is_none_or(|r|!Arc::ptr_eq(r,read))
            ||self.slots[i].as_ref().is_none_or(|s|s.wire_phase!=READ_REVIEW){self.core.phase.revoke();return Err(rejected("foreign or repeated Read outbound"));}
        read.check_bounds()?;outbound.service.check_bounds()?;
        if self.core.phase.source_send_restricted(i,READ_ADMITTED)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}
        let progress=self.send_positive(&Packet::ReadFinal{start:read.entry.wire.start.clone(),presentation_digest:read.wire.presentation_digest.clone(),read_digest:read.wire.facts.read_digest.clone(),read_challenge:read.wire.read_challenge.clone()},read.ceiling.min(outbound.service.deadline()))?;
        if progress==FinancialSendProgressV1::Sent{self.slots[i].as_mut().unwrap().wire_phase=READ_ADMITTED;}outbound.consumed=true;Ok(progress)
    }
    pub fn begin_continue_signer1(&mut self,deadline:Instant)->Result<()>{self.try_send_continue_prepare(Target::Signer1,deadline)?.require_sent()}
    pub fn begin_continue_signer2(&mut self,deadline:Instant)->Result<()>{self.try_send_continue_prepare(Target::Signer2,deadline)?.require_sent()}
    pub fn try_send_continue_prepare(&mut self,target:Target,original:Instant)->Result<FinancialSendProgressV1>{
        let result=(||{
            self.core.check()?;let i=target.index();
            if !self.histories[i].retirement_completed(){return Err(rejected("Continue before actual History retirement"));}
            let slot=self.slots[i].as_mut().ok_or_else(||rejected("Continue original slot missing"))?;
            if slot.wire_phase!=HISTORY_RETAINED||slot.continuation.is_some(){return Err(rejected("full Continue already attempted"));}
            let read=slot.read.as_ref().ok_or_else(||rejected("Continue completed Read missing"))?;read.entry.check_custody()?;
            let retained=slot.continue_deadline.ok_or_else(||rejected("cached Continue deadline missing"))?;
            let now=Instant::now();let ceiling=original.min(retained).min(read.entry.original_source).min(self.clocks.supervision()).min(now+std::time::Duration::from_secs(120));
            crate::channel::require_time(ceiling)?;
            if self.core.phase.source_send_restricted(i,HISTORY_RETAINED)?{return Ok(FinancialSendProgressV1::Restricted);}
            let context=ContinueStart{start:slot.start.clone(),entry_presentation_digest:read.wire.source_entry_presentation_digest.clone(),
                read_presentation_digest:read.wire.presentation_digest.clone(),challenge:state::nonce()?,native_ceiling_ms:self.clocks.restrictive_offset(ceiling,original)?};
            context.validate()?;read.entry.check_custody()?;crate::channel::require_time(ceiling)?;
            if let Err(error)=self.core.phase.step(i,HISTORY_RETAINED,CONT_PREPARING){
                if self.core.phase.source_send_restricted(i,HISTORY_RETAINED)?{return Ok(FinancialSendProgressV1::Restricted);}return Err(error);
            }
            slot.continuation=Some(CContinue{context:context.clone(),wire:None,binding:None,ready:None,outcome:false,saved:None});
            let progress=self.send_positive(&Packet::ContinuePrepare{context},ceiling)?;
            if progress==FinancialSendProgressV1::Sent{self.slots[i].as_mut().unwrap().wire_phase=CONT_PREPARING;}Ok(progress)
        })();if result.is_err(){self.core.phase.revoke();}result
    }
    pub fn send_continue_arm(&mut self,outbound:FinancialContinueArmOutboundV1)->Result<()>{self.try_send_continue_arm(outbound)?.require_sent()}
    pub fn try_send_continue_arm(&mut self,mut outbound:FinancialContinueArmOutboundV1)->Result<FinancialSendProgressV1>{
        let b=&outbound.binding;let i=b.slot();
        let c=self.slots[i].as_ref().and_then(|s|s.continuation.as_ref()).ok_or_else(||rejected("Continue outbound before review"))?;
        if !Arc::ptr_eq(&self.core,b.core())||c.binding.as_ref().is_none_or(|r|!Arc::ptr_eq(r,b))
            ||self.slots[i].as_ref().is_none_or(|s|s.wire_phase!=CONT_REVIEW){self.core.phase.revoke();return Err(rejected("foreign full Continue Arm"));}
        b.check(true)?;
        if self.core.phase.source_send_restricted(i,CONT_ARMED)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}
        let progress=self.send_positive(&Packet::ContinueArm{context:b.wire.context.clone(),presentation_digest:b.wire.presentation.presentation_digest.clone(),prepared_digest:b.wire.presentation.prepared_digest.clone()},b.ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.slots[i].as_mut().unwrap().wire_phase=CONT_ARMED;}outbound.consumed=true;Ok(progress)
    }
    pub fn send_continue_final(&mut self,mut outbound:FinancialContinueFinalOutboundV1)->Result<()>{
        let ready=&outbound.binding;let b=&ready.review;let i=b.slot();
        let c=self.slots[i].as_ref().and_then(|s|s.continuation.as_ref()).ok_or_else(||rejected("Continue Final before Ready"))?;
        if !Arc::ptr_eq(&self.core,b.core())||c.ready.as_ref().is_none_or(|r|!Arc::ptr_eq(r,ready))||self.core.phase.phase(i)!=CONT_ADMITTED
            ||self.slots[i].as_ref().is_none_or(|s|s.wire_phase!=CONT_READY){self.core.close();return Err(rejected("foreign full Continue Final"));}
        b.check_final()?;self.core.outbound[i].compare_exchange(PENDING,SENT,Ordering::AcqRel,Ordering::Acquire).map_err(|_|rejected("full Continue Final consumed"))?;
        self.slots[i].as_mut().unwrap().wire_phase=CONT_ADMITTED;outbound.consumed=true;
        self.send(&Packet::ContinueFinal{context:b.wire.context.clone(),presentation_digest:b.wire.presentation.presentation_digest.clone(),prepared_digest:b.wire.presentation.prepared_digest.clone(),ready_challenge:ready.challenge.clone()})
    }
    /// R can race between native A and enqueue. A temporarily empty driver
    /// queue is not abandonment of the genuine already-admitted outbound.
    pub fn try_send_cancel(&mut self)->Result<FinancialCancelProgressV1>{
        self.core.phase.revoke();
        if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}
        let deadline=self.cleanup.ok_or_else(||rejected("workflow cleanup missing"))?;
        crate::channel::require_time(deadline)?;self.core.check()?;
        if pending(&self.core){return Ok(FinancialCancelProgressV1::DeferredForAdmittedContinue{deadline});}
        if witness::witness_pending(&self.core){return Ok(FinancialCancelProgressV1::DeferredForAdmittedWitness{deadline});}
        if self.cancel_sent { return Ok(FinancialCancelProgressV1::Sent); }
        self.send_cancel()?;Ok(FinancialCancelProgressV1::Sent)
    }
    pub fn send_cancel(&mut self)->Result<()>{
        self.core.phase.revoke();
        if pending(&self.core)||witness::witness_pending(&self.core){return Err(rejected("admitted exact Final must precede Cancel"));}
        for slot in self.slots.iter_mut().flatten(){slot.sender.take();}
        if self.cancel_sent{return Err(rejected("workflow Cancel consumed"));}self.cancel_sent=true;
        if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}
        self.cancel_witnesses()?;self.cancel_histories()?;self.cancel_signing_services()?;self.cancel_completed_pair()?;
        self.send(&Packet::Cancel{coordinator:self.coordinator.clone(),session:self.session.clone()})
    }
    pub fn try_receive(&mut self)->Result<Option<CoordinatorFinancialEventV1>>{
        let result=self.receive_inner();if result.is_err(){self.core.close();}result
    }
    fn receive_inner(&mut self)->Result<Option<CoordinatorFinancialEventV1>>{
        self.transport_check()?;let Some(packet)=self.tree.as_ref().ok_or_else(||rejected("workflow tree consumed"))?.continue_host()?.workflow_receive()? else{return Ok(None)};
        if let Packet::NormalCompletionNotice{notice}=packet{return self.receive_normal_notice(notice).map(Some);}
        let role=packet.target()?.ok_or_else(||rejected("workflow response without role"))?;let i=role.index();
        if let Packet::Disposed{coordinator,session,..}=&packet{
            if !self.cancel_sent||self.disposed[i]||coordinator!=&self.coordinator||session!=&self.session{return Err(rejected("workflow disposal mismatch"));}
            if self.slots[i].as_ref().and_then(|s|s.continuation.as_ref()).is_some_and(|c|c.wire.is_some()&&!c.outcome){return Err(rejected("Continue disposal before exact outcome"));}
            if self.slots[i].as_ref().is_some_and(|s|!s.admission.disposal_allowed()){return Err(rejected("Signer Admit disposal before outcome"));}
            if self.slots[i].as_ref().is_some_and(|s|!s.writer_acquire.disposal_allowed()){return Err(rejected("Writer Read/Acquire disposal before actual terminal outcome"));}
            if !self.v3_entries[i].disposal_allowed(){return Err(rejected("V3 disposal before actual source disposition"));}
            if self.slots[i].as_ref().is_some_and(|s|!s.activate.disposal_allowed()){return Err(rejected("Activate disposal before actual terminal outcome"));}
            self.disposed[i]=true;return Ok(Some(CoordinatorFinancialEventV1::Disposed(role)));
        }
        if matches!(packet,Packet::V3AdmitDisplay{..}|Packet::V3AdmitReady{..}|Packet::V3Admitted{..}){return self.receive_v3_admission_event(packet).map(Some);}
        if matches!(packet,Packet::V3AdmitReadDisplay{..}|Packet::V3AdmitReadRetained{..}){return self.receive_v3_admit_read_event(packet).map(Some);}
        if matches!(packet,Packet::V3AuditDisplay{..}|Packet::V3Audited{..}){return self.receive_v3_audit_event(packet).map(Some);}
        if matches!(packet,Packet::V3PrepareReadDisplay{..}|Packet::V3ReceiveDisplay{..}|Packet::V3Prepared{..}|Packet::V3Received{..}){return self.receive_v3_delivery_event(packet).map(Some);}
        if matches!(packet,Packet::V3RedisclosureReadDisplay{..}|Packet::V3RediscloseDisplay{..}|Packet::V3RedisclosurePrepared{..}|Packet::V3Redisclosed{..}){return self.receive_v3_redisclosure_event(packet).map(Some);}
        if matches!(packet,Packet::V3EnrollmentDisplay{..}|Packet::V3ManifestDisplay{..}|Packet::V3Enrolled{..}|Packet::V3ManifestAccepted{..}){return self.receive_v3_receipt_event(packet).map(Some);}
        if matches!(packet,Packet::V3PairEndpoint{..}|Packet::V3PairDisplay{..}|Packet::V3Paired{..}){return self.receive_v3_pair_event(packet).map(Some);}
        if matches!(packet,Packet::V3EntryOffer{..}|Packet::V3SourceOpened{..}|Packet::V3SourceFailed{..}){return self.receive_v3_entry_event(packet).map(Some);}
        if matches!(packet,Packet::FinancialResultSelector{..}){return self.receive_financial_result_selector(packet).map(Some);}
        if matches!(packet,Packet::ReturnReadDisplay{..}|Packet::ReturnExactDisplay{..}|Packet::ReturnPrepared{..}|Packet::ReturnCompleted{..}|Packet::ReturnFailed{..}){return self.receive_return_event(packet).map(Some);}
        if matches!(packet,Packet::SignReadDisplay{..}|Packet::SignExactDisplay{..}|Packet::SignPrepared{..}|Packet::SignCommitted{..}|Packet::SignFailed{..}){return self.receive_sign_event(packet).map(Some);}
        if matches!(packet,Packet::WalletPrepareDisplay{..}|Packet::WalletObserveDisplay{..}|Packet::WalletPrepared{..}|Packet::WalletObserved{..}|Packet::WalletFailed{..}){return self.receive_wallet_event(packet).map(Some);}
        if matches!(packet,Packet::ActivateReadDisplay{..}|Packet::ActivateReadFailed{..}|Packet::ActivateDisplay{..}|Packet::ActivateReady{..}|Packet::ActivateOutcome{..}|Packet::Activated{..}){return self.receive_activate_event(packet).map(Some);}
        if matches!(packet,Packet::WriterReadDisplay{..}|Packet::WriterReadFailed{..}|Packet::AcquireDisplay{..}|Packet::AcquireReady{..}|Packet::AcquireOutcome{..}|Packet::Acquired{..}){return self.receive_writer_acquire_event(packet).map(Some);}
        if matches!(packet,Packet::AdmitDisplay{..}|Packet::AdmitReady{..}|Packet::Admitted{..}|Packet::AdmitOutcome{..}) { return self.receive_admit_event(packet).map(Some); }
        let mut retained_history=None;
        let slot=self.slots[i].as_mut().ok_or_else(||rejected("workflow unsolicited response"))?;
        if slot.failed{return Err(rejected("workflow response after failure"));}
        let event=match packet{
            Packet::EntryOffer{offer}=>{
                offer.validate()?;
                if slot.wire_phase!=ENTRY_PREPARING||slot.start!=offer.start||offer.presentation.actor.common_image_measurement!=self.image{return Err(rejected("workflow entry offer mismatch"));}
                slot.wire_phase=ENTRY_REVIEW;

                    let now=Instant::now();let source=self.clocks.restrict_received(PROFILE,offer.presentation.source_ceiling_ms,self.clocks.supervision(),now)?;
                    let entry=self.clocks.restrict_received(PROFILE,offer.presentation.entry_ceiling_ms,self.clocks.supervision(),now)?;
                    let reviewed=EntryReviewed::from_received_bounds(Arc::clone(&self.core),self.clocks,offer,source,entry)?;
                    slot.entry=Some(Arc::clone(&reviewed));
                    if !received_workflow_progress(&self.core.phase,i,ENTRY_PREPARING,ENTRY_REVIEW)?{return Ok(Some(CoordinatorFinancialEventV1::Restricted(role)));}
                    CoordinatorFinancialEventV1::SourceEntryOffer(SignerSourceEntryOfferV1{entry:reviewed,consumed:false})
            }
            Packet::SourceRetained{start,presentation_digest}=>{
                let entry=slot.entry.as_ref().ok_or_else(||rejected("source retention before offer"))?;
                if start!=slot.start||slot.wire_phase!=ENTRY_ADMITTED||presentation_digest!=entry.wire.presentation.presentation_digest{return Err(rejected("source retention binding"));}
                slot.wire_phase=SOURCE_RETAINED;
                entry.check_custody()?;if !received_workflow_progress(&self.core.phase,i,ENTRY_ADMITTED,SOURCE_RETAINED)?{CoordinatorFinancialEventV1::Restricted(role)}else{CoordinatorFinancialEventV1::SourceRetained(role)}
            }
            Packet::ReadOffer{start,presentation}=>{
                let entry=slot.entry.as_ref().ok_or_else(||rejected("Read before source entry"))?;presentation.validate()?;
                if start!=slot.start||slot.wire_phase!=SOURCE_RETAINED||!presentation.matches_entry(&entry.wire.presentation){return Err(rejected("Read offer changed source binding"));}
                slot.wire_phase=READ_REVIEW;

                    let deadline=self.clocks.restrict_received(PROFILE,presentation.read_ceiling_ms,entry.original_source,Instant::now())?;
                    let read=ReadReviewed::from_received_bounds(Arc::clone(entry),presentation,deadline,entry.original_source)?;
                    slot.read=Some(Arc::clone(&read));
                    if !received_workflow_progress(&self.core.phase,i,SOURCE_RETAINED,READ_REVIEW)?{return Ok(Some(CoordinatorFinancialEventV1::Restricted(role)));}
                    CoordinatorFinancialEventV1::InitialReadOffer(SignerFinancialReadTicketV1{read,consumed:false})
            }
            Packet::HistoryRetained{start,presentation_digest,read_digest,continue_review_ceiling_ms}=>{
                let read=slot.read.as_ref().ok_or_else(||rejected("history retention before Read"))?;
                if start!=slot.start||slot.wire_phase!=READ_ADMITTED||presentation_digest!=read.wire.presentation_digest||read_digest!=read.wire.facts.read_digest{return Err(rejected("history retention binding"));}
                retained_history=Some(Arc::clone(read));
                slot.wire_phase=HISTORY_RETAINED;

                    read.entry.check_custody()?;
                    let continue_deadline=self.clocks.restrict_received(PROFILE,continue_review_ceiling_ms,read.entry.original_source,Instant::now())?;
                    slot.continue_deadline=Some(continue_deadline);slot.continue_review_ms=Some(continue_review_ceiling_ms);
                    if !received_workflow_progress(&self.core.phase,i,READ_ADMITTED,HISTORY_RETAINED)?{CoordinatorFinancialEventV1::Restricted(role)}else{CoordinatorFinancialEventV1::HistoryRetained{role,continue_deadline}}

            }
            Packet::ContinueDisplay{binding}=>{
                binding.validate()?;let read=slot.read.as_ref().ok_or_else(||rejected("Continue display without Read"))?;
                let c=slot.continuation.as_mut().ok_or_else(||rejected("unsolicited full Continue display"))?;
                if slot.wire_phase!=CONT_PREPARING||c.context!=binding.context||c.wire.is_some()||slot.continue_review_ms!=Some(binding.review_ceiling_ms)||!binding.matches_read(&slot.start,&read.wire){return Err(rejected("full Continue display changed source"));}
                slot.wire_phase=CONT_REVIEW;c.wire=Some(binding.clone());

                    let deadline=self.clocks.restrict_received(PROFILE,binding.review_ceiling_ms,read.entry.original_source,Instant::now())?;
                    let b=FullContinueReviewed::from_received_bounds(Arc::clone(read),binding,read.entry.original_source,deadline)?;
                    c.binding=Some(Arc::clone(&b));
                    if !received_workflow_progress(&self.core.phase,i,CONT_PREPARING,CONT_REVIEW)?{return Ok(Some(CoordinatorFinancialEventV1::Restricted(role)));}
                    CoordinatorFinancialEventV1::ContinueDisplay(FinancialContinueReviewTicketV1{binding:b,consumed:false})
            }
            Packet::ContinueReady{context,presentation_digest,prepared_digest,ready_challenge}=>{
                let c=slot.continuation.as_mut().ok_or_else(||rejected("Continue Ready before prepare"))?;
                let b=c.binding.as_ref().ok_or_else(||rejected("Continue Ready before display"))?;
                if slot.wire_phase!=CONT_ARMED||c.ready.is_some()||!state::hash(&ready_challenge)||!b.wire.matches(&context,&presentation_digest,&prepared_digest){return Err(rejected("full Continue Ready mismatch"));}
                slot.wire_phase=CONT_READY;let ready=Arc::new(FullReady{review:Arc::clone(b),challenge:ready_challenge});c.ready=Some(Arc::clone(&ready));
                b.check(true)?;if !received_workflow_progress(&self.core.phase,i,CONT_ARMED,CONT_READY)?{CoordinatorFinancialEventV1::Restricted(role)}else{
                    CoordinatorFinancialEventV1::ContinueReady(FinancialContinueReadyTicketV1{binding:ready,consumed:false})}
            }
            Packet::ContinuationSaved{context,data}=>{
                data.validate()?;let c=slot.continuation.as_mut().ok_or_else(||rejected("saved Continue before prepare"))?;
                let b=c.wire.as_ref().ok_or_else(||rejected("saved Continue before display"))?;
                if c.outcome||c.context!=context||!data.matches(&b.presentation)||slot.wire_phase!=CONT_ADMITTED||self.core.outbound[i].load(Ordering::Acquire)!=SENT{return Err(rejected("saved Continue binding/phase mismatch"));}
                self.core.phase.observe_workflow_continue_saved(i)?;slot.wire_phase=AWAITING_ADMISSION;c.outcome=true;c.saved=Some(data.clone());
                CoordinatorFinancialEventV1::AwaitingAdmission{role,data}
            }
            Packet::ContinueOutcome{context,data}=>{
                let c=slot.continuation.as_mut().ok_or_else(||rejected("Continue outcome before prepare"))?;
                let b=c.wire.as_ref().ok_or_else(||rejected("Continue outcome before display"))?;
                if c.outcome||c.context!=context||!failed_outcome(&data,&b.presentation){return Err(rejected("full Continue outcome mismatch"));}
                c.outcome=true;self.core.phase.revoke();if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}
                CoordinatorFinancialEventV1::ContinueOutcome{role,data}
            }
            Packet::Failed{start,stage}=>{
                if start!=slot.start||!failure_phase(stage,slot.wire_phase){return Err(rejected("workflow failure mismatch"));}
                slot.failed=true;self.core.phase.revoke();if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}
                CoordinatorFinancialEventV1::Failed{role,stage}
            }
            _=>return Err(rejected("wrong coordinator workflow response")),
        };if let Some(read)=retained_history{self.note_history_retained(role,&read)?;}Ok(Some(event))
    }
    pub fn is_disposed(&self)->bool{self.disposed==[true;2]&&self.witnesses.iter().all(witness::CWSlot::closed)&&self.histories.iter().all(history::CHSlot::closed)&&self.signing_services.iter().all(signing::CGSlot::closed)&&self.pair_service.closed()}
    pub fn stop_and_reap(mut self)->Result<()>{
        if !self.cancel_sent||!self.is_disposed(){return Err(rejected("workflow actual source disposal unconfirmed"));}
        let cutoff=self.cleanup.ok_or_else(||rejected("workflow cleanup missing"))?;
        self.core.phase.revoke();self.core.alive.store(false,Ordering::Release);
        let result=self.tree.take().ok_or_else(||rejected("workflow tree consumed"))?.stop_and_reap(cutoff);
        self.core.close();result
    }
}
impl Drop for CoordinatorFinancialEndpointV1{fn drop(&mut self){if self.core.phase.normal_phase()!=5{self.core.close();}}}
fn failure_phase(stage:FinancialWorkflowStageV1,phase:u8)->bool{match stage{
    FinancialWorkflowStageV1::SourceEntry=>matches!(phase,ENTRY_PREPARING|ENTRY_REVIEW|ENTRY_ADMITTED),
    FinancialWorkflowStageV1::InitialRead=>matches!(phase,SOURCE_RETAINED|READ_REVIEW|READ_ADMITTED),
    FinancialWorkflowStageV1::Continue=>phase==CONT_PREPARING,
}}

struct HSlot{start:Start,phase:u8,entry:Option<EntryOffer>,read:Option<SignerFinancialReadPresentationV1>,continue_review_ms:Option<u64>,continuation:Option<HContinue>,admission:HAdmit,writer_acquire:HWritAcquire,activate:HActivate,last_wall:u64,failed:bool}
/// Exact original H is a trusted finite relay, not a direct-C authentication
/// proof at S. It retains sole S reapers, no plaintext/private keys or issuer.
pub struct HostFinancialWorkflowRelayV1{
    normal:normal_completion::NormalHState,
    v3_entries:[HV3Entry;2],host_peer_instance:String,
    lifecycle:Arc<crate::host_interstage::HostLifecycle>,
    pair:crate::host_interstage::HostPairReceiveState,
    retirement:Option<crate::host_interstage::RetirementRequest>,quiescent_sent:bool,retired:[[bool;2];3],
    host:Option<HostOriginV1>,clocks:FullWorkflowClocksV1,image:String,coordinator:Option<String>,session:Option<String>,
    slots:[Option<HSlot>;2],restricted:bool,cancel_seen:bool,disposed:[bool;2],cleanup:Option<Instant>,
}
impl HostFinancialWorkflowRelayV1 {
    pub(super) fn from_host(host:HostOriginV1)->Result<Self>{
        host.continue_check()?;let clocks=host.continue_clocks().workflow();let image=host.workflow_image()?;
        // The only first H->S data handshake. A partial pair send is a failed
        // original session: `host` is consumed/dropped, never retried/reentered.
        let host_instance=state::nonce()?;
        for role in [Target::Signer1,Target::Signer2] {
            crate::channel::require_time(clocks.supervision())?;
            host.continue_check()?;
            host.continue_child(role)?.workflow_send(&Packet::OriginalHostPeer{role,host_instance:host_instance.clone()})?;
        }
        Ok(Self{normal:normal_completion::NormalHState::default(),v3_entries:std::array::from_fn(|_|HV3Entry::default()),host_peer_instance:host_instance,lifecycle:host.workflow_lifecycle(),pair:crate::host_interstage::HostPairReceiveState::default(),retirement:None,quiescent_sent:false,retired:[[false;2];3],host:Some(host),clocks,image,coordinator:None,session:None,slots:[None,None],restricted:false,cancel_seen:false,disposed:[false;2],cleanup:None})
    }
    pub fn session_deadline(&self)->Instant{self.clocks.supervision()}
    fn restrict(&mut self)->Result<()>{self.restricted=true;if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}Ok(())}
    pub fn pump(&mut self)->Result<bool>{let result=self.pump_inner();if result.is_err(){self.lifecycle.poison();drop(self.host.take());}result}
    fn pump_inner(&mut self)->Result<bool>{
        self.lifecycle.check_not_poisoned()?;
        crate::channel::require_time(self.cleanup.unwrap_or(self.clocks.hard_cleanup()))?;
        self.host.as_ref().ok_or_else(||rejected("workflow Host consumed"))?.continue_check_lifetimes()?;
        let mut progress=false;
        if let Some(packet)=self.host.as_ref().unwrap().workflow_receive_c()?{
            if self.normal_control(&packet)?||self.completed_pair_control(&packet)?||self.retirement_control(&packet)?{progress=true;}else{
            self.down(&packet)?;let host=self.host.as_ref().unwrap();
            if matches!(packet,Packet::Cancel{..}){
                host.continue_child(Target::Signer1)?.workflow_send(&packet)?;host.continue_child(Target::Signer2)?.workflow_send(&packet)?;
            }else{host.continue_child(packet.target()?.ok_or_else(||rejected("workflow target missing"))?)?.workflow_send(&packet)?;}
            progress=true;}
        }
        progress|=self.retirement_observation()?;
        progress|=self.normal_observation()?;
        for target in [Target::Signer1,Target::Signer2]{
            if self.disposed[target.index()]{continue;}
            if let Some(packet)=self.host.as_ref().unwrap().continue_child(target)?.workflow_receive()?{
                let forward=self.up(target,&packet)?;
                if forward{self.host.as_ref().unwrap().workflow_send_c(&packet)?;}progress=true;
            }
        }
        self.host.as_ref().unwrap().continue_check_lifetimes()?;self.lifecycle.check_not_poisoned()?;Ok(progress)
    }
    fn completed_pair_control(&mut self,packet:&Packet)->Result<bool>{
        let Packet::CompletedPairServing{data,witness_instance,serve_challenge,service_ceiling_ms}=packet else{return Ok(false)};
        if self.restricted||self.cancel_seen||self.retirement.is_some(){return Err(rejected("Host Pair receive during restriction or retirement"));}
        let mut originals=Vec::with_capacity(2);
        for i in 0..2{
            let slot=self.slots[i].as_mut().ok_or_else(||rejected("Host Pair before original owner"))?;
            if slot.failed||self.disposed[i]{return Err(rejected("Host Pair owner failed or disposed"));}
            relay_source_current(slot,self.clocks)?;
            let (_,_,service,_)=slot.writer_acquire.retained_result()?;
            let original=service.correlation().original.clone();
            if self.coordinator.as_deref()!=Some(original.actor.coordinator_process_instance.as_str())
                ||self.session.as_deref()!=Some(original.actor.session_challenge.as_str())
                ||original.actor.common_image_measurement!=self.image{return Err(rejected("Host Pair original actor mismatch"));}
            originals.push(original);
        }
        let expected=originals.try_into().map_err(|_|rejected("Host Pair owner cardinality"))?;
        self.pair.receive(&self.lifecycle,data.clone(),witness_instance.clone(),serve_challenge.clone(),*service_ceiling_ms,expected)?;Ok(true)
    }
    fn retirement_control(&mut self,packet:&Packet)->Result<bool>{
        match packet{
            Packet::RetireRequest{request}=>{
                request.validate(self.clocks)?;
                if self.restricted||self.cancel_seen||self.retirement.is_some()||self.retired[request.purpose.index()][request.target.index()]
                    ||self.coordinator.as_deref()!=Some(request.coordinator.as_str())||self.session.as_deref()!=Some(request.session.as_str()){
                    return Err(rejected("Host retirement request binding"));}
                let slot=self.slots[request.target.index()].as_ref().ok_or_else(||rejected("Host retirement before actual owner"))?;
                match request.purpose{
                    crate::host_interstage::RetirementPurpose::InitialHistory=>{
                        let read=slot.read.as_ref().ok_or_else(||rejected("Host history retirement before actual Read"))?;
                        if slot.phase!=HISTORY_RETAINED||slot.continue_review_ms.is_none()||request.binding_digest!=read.presentation_digest{return Err(rejected("Host retirement before actual history retention"));}
                    },
                    crate::host_interstage::RetirementPurpose::FinancialSigning=>{
                        if slot.phase!=67{return Err(rejected("Host Signing retirement before actual Sign"));}
                        let(_,signed)=slot.activate.wallet.sign.return_predecessor()?;
                        let(_,_,service,_)=slot.writer_acquire.retained_result()?;
                        let binding=request.signing.as_ref().ok_or_else(||rejected("Host Signing retirement lacks actual result"))?;
                        if binding.signed!=*signed||binding.original_commitment!=service.correlation().original.commitment()?||request.witness_instance!=service.correlation().witness_instance||binding.commitment()?!=request.binding_digest{return Err(rejected("Host Signing retirement original/result mismatch"));}
                    },
                    crate::host_interstage::RetirementPurpose::FinancialContinuation=>{
                        let(p,_)=slot.admission.retained_result()?;
                        if (slot.phase!=admit::AWAITING_NEXT_READ&&!slot.writer_acquire.signing_setup_pending(slot.phase))||request.binding_digest!=p.presentation_digest{return Err(rejected("Host retirement before actual admitted response"));}
                    }
                }
                self.lifecycle.request(request.clone())?;self.retirement=Some(request.clone());self.quiescent_sent=false;Ok(true)
            }
            Packet::RetireResume{request}=>{
                if !self.quiescent_sent||self.retirement.as_ref()!=Some(request){return Err(rejected("Host Resume without exact quiescence"));}
                self.lifecycle.receive_resume(request)?;Ok(true)
            }
            _=>Ok(false),
        }
    }
    fn retirement_observation(&mut self)->Result<bool>{
        let Some(request)=self.retirement.as_ref() else{return Ok(false)};
        if !self.quiescent_sent{
            if self.lifecycle.quiescent()?.as_ref()==Some(request){
                self.host.as_ref().ok_or_else(||rejected("Host consumed"))?.workflow_send_c(&Packet::RetireQuiescent{request:request.clone()})?;
                self.quiescent_sent=true;return Ok(true);
            }
        }else if self.lifecycle.resumed()?.as_ref()==Some(request){
            self.host.as_ref().ok_or_else(||rejected("Host consumed"))?.workflow_send_c(&Packet::RetireResumed{request:request.clone()})?;
            if request.purpose==crate::host_interstage::RetirementPurpose::FinancialSigning{self.pair.record_signing_retired(request)?;}
            self.lifecycle.acknowledge_resumed(request)?;self.retired[request.purpose.index()][request.target.index()]=true;self.retirement=None;return Ok(true);
        }
        Ok(false)
    }
    fn down(&mut self,packet:&Packet)->Result<()>{
        if let Packet::Cancel{coordinator,session}=packet{
            if self.cancel_seen||!state::hash(coordinator)||!state::hash(session)||self.coordinator.as_ref().is_some_and(|v|v!=coordinator)
                ||self.session.as_ref().is_some_and(|v|v!=session){return Err(rejected("workflow relay Cancel mismatch"));}
            self.coordinator=Some(coordinator.clone());self.session=Some(session.clone());self.cancel_seen=true;self.restrict()?;return Ok(());
        }
        if self.restricted{return Err(rejected("workflow command after relay restriction"));}
        crate::channel::require_time(self.clocks.supervision())?;
        if matches!(packet,Packet::V3AdmitArm{..}|Packet::V3AdmitFinal{..}){return self.down_v3_admission(packet);}
        if matches!(packet,Packet::V3AdmitReadFinal{..}){return self.down_v3_admit_read(packet);}
        if matches!(packet,Packet::V3AuditFinal{..}){return self.down_v3_audit(packet);}
        if matches!(packet,Packet::FinancialSetupSelection{..}){return self.down_financial_setup(packet);}
        if matches!(packet,Packet::V3OwnerSelection{..}){return self.down_v3_owner_selection(packet);}
        if matches!(packet,Packet::V3PrepareReadFinal{..}|Packet::V3ReceiveFinal{..}){return self.down_v3_delivery(packet);}
        if matches!(packet,Packet::V3RedisclosureReadFinal{..}|Packet::V3RediscloseFinal{..}){return self.down_v3_redisclosure(packet);}
        if matches!(packet,Packet::V3EnrollmentFinal{..}|Packet::V3ManifestFinal{..}){return self.down_v3_receipt(packet);}
        if matches!(packet,Packet::V3PairFinal{..}){return self.down_v3_pair(packet);}
        if matches!(packet,Packet::V3StartEntry{..}|Packet::V3EntryCipher{..}){return self.down_v3_entry(packet);}
        if matches!(packet,Packet::ReturnReadFinal{..}|Packet::ReturnExactFinal{..}){return self.down_return(packet);}
        if matches!(packet,Packet::SignReadFinal{..}|Packet::SignExactFinal{..}){return self.down_sign(packet);}
        if matches!(packet,Packet::WalletPrepareFinal{..}|Packet::WalletObserveFinal{..}){return self.down_wallet(packet);}
        if matches!(packet,Packet::ActivateReadFinal{..}|Packet::ActivateArm{..}|Packet::ActivateFinal{..}){return self.down_activate(packet);}
        if matches!(packet,Packet::WriterReadFinal{..}|Packet::AcquireArm{..}|Packet::AcquireFinal{..}){return self.down_writer_acquire(packet);}
        if matches!(packet,Packet::AdmitArm{..}|Packet::AdmitFinal{..}) { return self.down_admit(packet); }
        match packet{
            Packet::StartEntry{start}=>{
                start.validate()?;let i=start.role.index();
                if !self.v3_entries[i].allows_financial_entry(){return Err(rejected("financial Entry before actual completed V3"));}
                if self.slots[i].is_some()||self.coordinator.as_ref().is_some_and(|s|s!=&start.coordinator)||self.session.as_ref().is_some_and(|s|s!=&start.session){return Err(rejected("workflow relay start replay"));}
                self.clocks.restrict_received(&start.profile,start.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;
                self.coordinator=Some(start.coordinator.clone());self.session=Some(start.session.clone());
                self.slots[i]=Some(HSlot{start:start.clone(),phase:ENTRY_PREPARING,entry:None,read:None,continue_review_ms:None,continuation:None,admission:HAdmit::default(),writer_acquire:HWritAcquire::default(),activate:HActivate::default(),last_wall:0,failed:false});Ok(())
            }
            Packet::EntryCipher{envelope}=>{
                let encrypted=crypto::Envelope::decode(envelope.as_bytes())?;
                let role=packet.target()?.ok_or_else(||rejected("workflow relay ciphertext target"))?;
                let slot=self.slots[role.index()].as_mut().ok_or_else(||rejected("workflow relay ciphertext before offer"))?;
                if slot.phase!=ENTRY_REVIEW||slot.failed||slot.entry.as_ref().is_none_or(|entry|&entry.crypto!=encrypted.binding()){return Err(rejected("workflow relay ciphertext substitution"));}
                entry_current(slot,self.clocks)?;slot.phase=ENTRY_ADMITTED;Ok(())
            }
            Packet::ReadFinal{start,presentation_digest,read_digest,read_challenge}=>{
                let slot=self.slots[start.role.index()].as_mut().ok_or_else(||rejected("workflow relay Read before offer"))?;
                let read=slot.read.as_ref().ok_or_else(||rejected("workflow relay Read missing"))?;
                if slot.phase!=READ_REVIEW||slot.failed||start!=&slot.start||presentation_digest!=&read.presentation_digest
                    ||read_digest!=&read.facts.read_digest||read_challenge!=&read.read_challenge{return Err(rejected("workflow relay Read final substitution"));}
                read_current(slot,self.clocks)?;slot.phase=READ_ADMITTED;Ok(())
            }
            Packet::ContinuePrepare{context}=>{
                context.validate()?;if !self.retired[crate::host_interstage::RetirementPurpose::InitialHistory.index()][context.start.role.index()]{return Err(rejected("Continue relay before actual History Resume"));}
                let slot=self.slots[context.start.role.index()].as_mut().ok_or_else(||rejected("Continue relay before original source"))?;
                let read=slot.read.as_ref().ok_or_else(||rejected("Continue relay before original Read"))?;
                if slot.phase!=HISTORY_RETAINED||slot.continuation.is_some()||slot.failed||!context.matches_read(&slot.start,read){return Err(rejected("Continue relay changed original Read"));}
                let retained=slot.continue_review_ms.ok_or_else(||rejected("relay cached Continue ceiling missing"))?;
                if context.native_ceiling_ms>retained{return Err(rejected("Continue prepare extended cached ceiling"));}
                self.clocks.restrict_received(PROFILE,context.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;
                relay_source_current(slot,self.clocks)?;
                slot.continuation=Some(HContinue{context:context.clone(),binding:None,ready:None,outcome:false,display_forwarded:false,saved:None});slot.phase=CONT_PREPARING;Ok(())
            }
            Packet::ContinueArm{context,presentation_digest,prepared_digest}=>{
                let slot=self.slots[context.start.role.index()].as_mut().ok_or_else(||rejected("Continue relay Arm before prepare"))?;
                let c=slot.continuation.as_ref().ok_or_else(||rejected("Continue relay context missing"))?;
                let b=c.binding.as_ref().ok_or_else(||rejected("Continue relay display missing"))?;
                if slot.phase!=CONT_REVIEW||c.outcome||!b.matches(context,presentation_digest,prepared_digest){return Err(rejected("Continue relay Arm mismatch"));}
                full_continue_current(slot,self.clocks)?;slot.phase=CONT_ARMED;Ok(())
            }
            Packet::ContinueFinal{context,presentation_digest,prepared_digest,ready_challenge}=>{
                let slot=self.slots[context.start.role.index()].as_mut().ok_or_else(||rejected("Continue relay Final before prepare"))?;
                let c=slot.continuation.as_ref().ok_or_else(||rejected("Continue relay context missing"))?;
                let b=c.binding.as_ref().ok_or_else(||rejected("Continue relay display missing"))?;
                if slot.phase!=CONT_READY||c.outcome||!b.matches(context,presentation_digest,prepared_digest)||c.ready.as_ref()!=Some(ready_challenge){return Err(rejected("Continue relay Final mismatch"));}
                full_continue_current(slot,self.clocks)?;slot.phase=CONT_ADMITTED;Ok(())
            }
            _=>Err(rejected("wrong workflow relay command")),
        }
    }
    fn up(&mut self,target:Target,packet:&Packet)->Result<bool>{
        if matches!(packet,Packet::NormalDisposed{..}){return self.up_normal_disposed(target,packet);}
        if packet.target()?!=Some(target){return Err(rejected("workflow actual Signer target mismatch"));}
        let i=target.index();
        if let Packet::Disposed{coordinator,session,..}=packet{
            if !self.cancel_seen||self.disposed[i]||self.coordinator.as_ref()!=Some(coordinator)||self.session.as_ref()!=Some(session){return Err(rejected("workflow relay disposal mismatch"));}
            if self.slots[i].as_ref().and_then(|s|s.continuation.as_ref()).is_some_and(|c|c.binding.is_some()&&!c.outcome){return Err(rejected("Continue relay disposal before outcome"));}
            if self.slots[i].as_ref().is_some_and(|s|!s.admission.disposal_allowed()){return Err(rejected("Signer Admit relay disposal before outcome"));}
            if self.slots[i].as_ref().is_some_and(|s|!s.writer_acquire.disposal_allowed()){return Err(rejected("Writer Read/Acquire disposal before actual terminal outcome"));}
            if !self.v3_entries[i].disposal_allowed(){return Err(rejected("V3 relay disposal before actual source disposition"));}
            if self.slots[i].as_ref().is_some_and(|s|!s.activate.disposal_allowed()){return Err(rejected("Activate disposal before actual terminal outcome"));}
            self.disposed[i]=true;return Ok(true);
        }
        if matches!(packet,Packet::V3AdmitDisplay{..}|Packet::V3AdmitReady{..}|Packet::V3Admitted{..}){return self.up_v3_admission(target,packet);}
        if matches!(packet,Packet::V3AdmitReadDisplay{..}|Packet::V3AdmitReadRetained{..}){return self.up_v3_admit_read(target,packet);}
        if matches!(packet,Packet::V3AuditDisplay{..}|Packet::V3Audited{..}){return self.up_v3_audit(target,packet);}
        if matches!(packet,Packet::V3PrepareReadDisplay{..}|Packet::V3ReceiveDisplay{..}|Packet::V3Prepared{..}|Packet::V3Received{..}){return self.up_v3_delivery(target,packet);}
        if matches!(packet,Packet::V3RedisclosureReadDisplay{..}|Packet::V3RediscloseDisplay{..}|Packet::V3RedisclosurePrepared{..}|Packet::V3Redisclosed{..}){return self.up_v3_redisclosure(target,packet);}
        if matches!(packet,Packet::V3EnrollmentDisplay{..}|Packet::V3ManifestDisplay{..}|Packet::V3Enrolled{..}|Packet::V3ManifestAccepted{..}){return self.up_v3_receipt(target,packet);}
        if matches!(packet,Packet::V3PairEndpoint{..}|Packet::V3PairDisplay{..}|Packet::V3Paired{..}){return self.up_v3_pair(target,packet);}
        if matches!(packet,Packet::V3EntryOffer{..}|Packet::V3SourceOpened{..}|Packet::V3SourceFailed{..}){return self.up_v3_entry(target,packet);}
        if matches!(packet,Packet::FinancialResultSelector{..}){return self.up_financial_result_selector(target,packet);}
        if matches!(packet,Packet::ReturnReadDisplay{..}|Packet::ReturnExactDisplay{..}|Packet::ReturnPrepared{..}|Packet::ReturnCompleted{..}|Packet::ReturnFailed{..}){return self.up_return(target,packet);}
        if matches!(packet,Packet::SignReadDisplay{..}|Packet::SignExactDisplay{..}|Packet::SignPrepared{..}|Packet::SignCommitted{..}|Packet::SignFailed{..}){return self.up_sign(target,packet);}
        if matches!(packet,Packet::WalletPrepareDisplay{..}|Packet::WalletObserveDisplay{..}|Packet::WalletPrepared{..}|Packet::WalletObserved{..}|Packet::WalletFailed{..}){return self.up_wallet(target,packet);}
        if matches!(packet,Packet::ActivateReadDisplay{..}|Packet::ActivateReadFailed{..}|Packet::ActivateDisplay{..}|Packet::ActivateReady{..}|Packet::ActivateOutcome{..}|Packet::Activated{..}){return self.up_activate(target,packet);}
        if matches!(packet,Packet::WriterReadDisplay{..}|Packet::WriterReadFailed{..}|Packet::AcquireDisplay{..}|Packet::AcquireReady{..}|Packet::AcquireOutcome{..}|Packet::Acquired{..}){return self.up_writer_acquire(target,packet);}
        if matches!(packet,Packet::AdmitDisplay{..}|Packet::AdmitReady{..}|Packet::Admitted{..}|Packet::AdmitOutcome{..}) { return self.up_admit(target,packet); }
        let slot=self.slots[i].as_mut().ok_or_else(||rejected("workflow unsolicited Signer response"))?;
        if slot.failed{return Err(rejected("workflow response after recorded failure"));}
        let terminal=matches!(packet,Packet::Failed{..}|Packet::ContinuationSaved{..}|Packet::ContinueOutcome{..});
        if !terminal&&!self.restricted{crate::channel::require_time(self.clocks.supervision())?;}
        match packet{
            Packet::EntryOffer{offer}=>{
                offer.validate()?;
                if slot.phase!=ENTRY_PREPARING||offer.start!=slot.start||offer.presentation.actor.common_image_measurement!=self.image{return Err(rejected("workflow relay offer substitution"));}
                slot.entry=Some(offer.clone());slot.phase=ENTRY_REVIEW;
                if !self.restricted{entry_current(slot,self.clocks)?;}
            }
            Packet::SourceRetained{start,presentation_digest}=>{
                let entry=slot.entry.as_ref().ok_or_else(||rejected("workflow relay source before offer"))?;
                if slot.phase!=ENTRY_ADMITTED||start!=&slot.start||presentation_digest!=&entry.presentation.presentation_digest{return Err(rejected("workflow relay source-retained mismatch"));}
                slot.phase=SOURCE_RETAINED;
            }
            Packet::ReadOffer{start,presentation}=>{
                presentation.validate()?;let entry=slot.entry.as_ref().ok_or_else(||rejected("workflow relay original entry missing"))?;
                if slot.phase!=SOURCE_RETAINED||start!=&slot.start||!presentation.matches_entry(&entry.presentation){return Err(rejected("workflow relay Read changed source"));}
                slot.read=Some(presentation.clone());slot.phase=READ_REVIEW;if !self.restricted{read_current(slot,self.clocks)?;}
            }
            Packet::HistoryRetained{start,presentation_digest,read_digest,continue_review_ceiling_ms}=>{
                let read=slot.read.as_ref().ok_or_else(||rejected("workflow relay history before Read"))?;
                if slot.phase!=READ_ADMITTED||start!=&slot.start||presentation_digest!=&read.presentation_digest||read_digest!=&read.facts.read_digest{return Err(rejected("workflow relay history-retained mismatch"));}
                if *continue_review_ceiling_ms==0||*continue_review_ceiling_ms>SUPERVISION_MS{return Err(rejected("relay cached Continue ceiling invalid"));}
                if !self.restricted{self.clocks.restrict_received(PROFILE,*continue_review_ceiling_ms,self.clocks.supervision(),Instant::now())?;relay_source_current(slot,self.clocks)?;}
                slot.continue_review_ms=Some(*continue_review_ceiling_ms);slot.phase=HISTORY_RETAINED;
            }
            Packet::ContinueDisplay{binding}=>{
                binding.validate()?;let read=slot.read.as_ref().ok_or_else(||rejected("Continue relay display without Read"))?;
                let c=slot.continuation.as_mut().ok_or_else(||rejected("Continue relay display before prepare"))?;
                if slot.phase!=CONT_PREPARING||c.binding.is_some()||c.context!=binding.context||slot.continue_review_ms!=Some(binding.review_ceiling_ms)||!binding.matches_read(&slot.start,read){return Err(rejected("Continue relay display changed original binding"));}
                c.binding=Some(binding.clone());c.display_forwarded=!self.restricted;slot.phase=CONT_REVIEW;
                if !self.restricted{full_continue_current(slot,self.clocks)?;}
            }
            Packet::ContinueReady{context,presentation_digest,prepared_digest,ready_challenge}=>{
                let c=slot.continuation.as_mut().ok_or_else(||rejected("Continue relay Ready before prepare"))?;
                let b=c.binding.as_ref().ok_or_else(||rejected("Continue relay Ready before display"))?;
                if slot.phase!=CONT_ARMED||c.ready.is_some()||c.outcome||!state::hash(ready_challenge)||!b.matches(context,presentation_digest,prepared_digest){return Err(rejected("Continue relay Ready mismatch"));}
                c.ready=Some(ready_challenge.clone());slot.phase=CONT_READY;if !self.restricted{full_continue_current(slot,self.clocks)?;}
            }
            Packet::ContinuationSaved{context,data}=>{
                data.validate()?;let c=slot.continuation.as_mut().ok_or_else(||rejected("Continue saved before prepare"))?;
                let b=c.binding.as_ref().ok_or_else(||rejected("Continue saved before display"))?;
                if slot.phase!=CONT_ADMITTED||c.outcome||context!=&c.context||!data.matches(&b.presentation)||!c.display_forwarded{return Err(rejected("Continue relay saved mismatch"));}
                c.outcome=true;c.saved=Some(data.clone());slot.phase=AWAITING_ADMISSION;return Ok(true);
            }
            Packet::ContinueOutcome{context,data}=>{
                let c=slot.continuation.as_mut().ok_or_else(||rejected("Continue outcome before prepare"))?;
                let b=c.binding.as_ref().ok_or_else(||rejected("Continue outcome before display"))?;
                if c.outcome||context!=&c.context||!failed_outcome(data,&b.presentation){return Err(rejected("Continue relay outcome mismatch"));}
                c.outcome=true;let forward=c.display_forwarded;self.restrict()?;return Ok(forward);
            }
            Packet::Failed{start,stage}=>{
                if start!=&slot.start||!failure_phase(*stage,slot.phase){return Err(rejected("workflow relay failure mismatch"));}
                slot.failed=true;self.restrict()?;return Ok(true);
            }
            _=>return Err(rejected("wrong workflow relay response")),
        }
        // Queued pre-R progress is validated/drained, not new authority. C is
        // already cleaning up and needs only actual failure/disposal records.
        Ok(!self.restricted)
    }
    pub fn is_disposed(&self)->bool{self.disposed==[true;2]}
    /// Joinable terminal drain for the sole H relay owner. The foreground role
    /// joins this result and drops its actual authority before final branch exit.
    /// This method neither exits the process nor transfers/replaces the S reapers.
    pub fn finish(mut self,work:Result<()>)->Result<()>{
        self.lifecycle.poison();
        let result=work.and_then(|()|if self.cancel_seen&&self.is_disposed(){Ok(())}else{Err(rejected("workflow relay actual disposal missing"))})
            .and_then(|()|bootstrap::finish_host_capped(self.host.take().ok_or_else(||rejected("workflow Host consumed"))?,self.cleanup));
        drop(self.host.take());result
    }
    pub fn complete(self,work:Result<()>)->!{bootstrap::child_exit(self.finish(work))}
}
fn entry_current(slot:&mut HSlot,clocks:FullWorkflowClocksV1)->Result<()>{
    let entry=slot.entry.as_ref().ok_or_else(||rejected("relay entry binding missing"))?;
    let p=&entry.presentation;let now=Instant::now();
    for ms in [p.native_ceiling_ms,p.entry_ceiling_ms,p.source_ceiling_ms]{clocks.restrict_received(PROFILE,ms,clocks.supervision(),now)?;}
    relay_wall(&mut slot.last_wall,p.facts.reviewed_at_ms,p.facts.expires_at_ms,p.facts.source_expires_at_ms)
}
fn read_current(slot:&mut HSlot,clocks:FullWorkflowClocksV1)->Result<()>{
    let p=slot.read.as_ref().ok_or_else(||rejected("relay Read binding missing"))?;let now=Instant::now();
    for ms in [p.read_ceiling_ms,p.source_ceiling_ms]{clocks.restrict_received(PROFILE,ms,clocks.supervision(),now)?;}
    relay_wall(&mut slot.last_wall,p.facts.reviewed_at_ms,p.facts.expires_at_ms,p.facts.source_expires_at_ms)
}
fn relay_wall(last:&mut u64,start:u64,end:u64,source:u64)->Result<()>{
    let now=state::wall_ms()?;if now<*last||now<start||now>=end||now>=source{return Err(rejected("workflow relay original wall bounds"));}*last=now;Ok(())
}

fn relay_source_current(slot:&mut HSlot,clocks:FullWorkflowClocksV1)->Result<()>{
    let read=slot.read.as_ref().ok_or_else(||rejected("relay original Read missing"))?;
    clocks.restrict_received(PROFILE,read.source_ceiling_ms,clocks.supervision(),Instant::now())?;
    let wall=state::wall_ms()?;
    if wall<slot.last_wall||wall<read.facts.reviewed_at_ms||wall>=read.facts.source_expires_at_ms{return Err(rejected("relay original source expired"));}
    slot.last_wall=wall;Ok(())
}
fn full_continue_current(slot:&mut HSlot,clocks:FullWorkflowClocksV1)->Result<()>{
    let b=slot.continuation.as_ref().and_then(|c|c.binding.as_ref()).ok_or_else(||rejected("relay full Continue binding missing"))?;
    let now=Instant::now();for offset in [b.context.native_ceiling_ms,b.source_ceiling_ms,b.review_ceiling_ms]{clocks.restrict_received(PROFILE,offset,clocks.supervision(),now)?;}
    let r=&b.presentation.review;relay_wall(&mut slot.last_wall,r.reviewed_at_ms,r.expires_at_ms,r.session_expires_at_ms)
}

// C receive progress is not native admission. Exact immutable/actor/clock
// validation precedes this call; only the expected phase losing to ordinary R
// is a restrictive observation rather than a fatal endpoint failure.
fn received_workflow_progress(phase:&Phases,slot:usize,from:u8,to:u8)->Result<bool>{
    if phase.source_send_restricted(slot,from)?{return Ok(false);}
    match phase.step(slot,from,to){
        Ok(())=>Ok(!phase.source_send_restricted(slot,to)?),
        Err(error)=>{if phase.source_send_restricted(slot,from)?{Ok(false)}else{Err(error)}}
    }
}
#[cfg(test)] mod receive_race_tests{
    use super::*;
    #[test]
    fn exact_older_receive_races_restrict_without_advancing_or_masking_protocol_errors(){
        for (from,to) in [(ENTRY_PREPARING,ENTRY_REVIEW),(ENTRY_ADMITTED,SOURCE_RETAINED),
            (SOURCE_RETAINED,READ_REVIEW),(READ_ADMITTED,HISTORY_RETAINED),
            (CONT_PREPARING,CONT_REVIEW),(CONT_ARMED,CONT_READY)]{
            let p=Phases::new();p.step(0,0,from).unwrap();p.revoke();
            assert!(!received_workflow_progress(&p,0,from,to).unwrap());
            assert_eq!(p.phase(0),from);assert!(p.revoked());
            assert!(received_workflow_progress(&p,0,to,from).is_err());
            let p=Phases::new();p.step(1,0,from).unwrap();
            assert!(received_workflow_progress(&p,1,from,to).unwrap());
            assert!(received_workflow_progress(&p,1,from,to).is_err());
        }
    }
    #[test]
    fn unrelated_admitted_continue_and_witness_survive_ordinary_receive_restriction(){
        let p=Phases::new();p.step(0,0,CONT_ADMITTED).unwrap();p.step(1,0,READ_REVIEW).unwrap();
        p.witness_step(0,0,witness::W_ADMITTED).unwrap();p.revoke();
        assert!(!received_workflow_progress(&p,1,READ_REVIEW,READ_ADMITTED).unwrap());
        assert_eq!(p.phase(0),CONT_ADMITTED);assert_eq!(p.witness_phase(0),witness::W_ADMITTED);
        assert!(p.step(1,READ_REVIEW,READ_ADMITTED).is_err());
    }
}

impl Drop for HostFinancialWorkflowRelayV1{fn drop(&mut self){self.lifecycle.poison();}}

#[cfg(test)]mod positive_receive_snapshot_tests{
    use super::*;
    #[test]fn workflow_receive_q_and_wrong_phase_are_fatal_even_after_r(){
        let p=Phases::new();p.step(0,0,ENTRY_PREPARING).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
        assert!(received_workflow_progress(&p,0,ENTRY_PREPARING,ENTRY_REVIEW).is_err());
        let p=Phases::new();p.step(0,0,ENTRY_PREPARING).unwrap();p.revoke();
        assert!(!received_workflow_progress(&p,0,ENTRY_PREPARING,ENTRY_REVIEW).unwrap());
        assert!(received_workflow_progress(&p,0,ENTRY_REVIEW,ENTRY_REVIEW).is_err());
    }
}
