//! Same retained full-profile Continue binding; no new origin or source owner.
use crate::{rejected,Result,financial_workflow_clock::{PROFILE,SUPERVISION_MS},
    financial_workflow_channel::{Start,SignerFinancialReadPresentationV1},
    financial_workflow_source::{ReadReviewed,wall_ceiling},
    signer_continue_channel::{SignerContinuePresentationV1,SignerContinueReviewDataV1,SignerContinueOutcomeV1},
    signer_continue_state::{self as state,Core,PENDING,ABANDONED}};
use serde::{Serialize,Deserialize};
use std::{sync::{Arc,atomic::{AtomicU64,Ordering}},time::Instant};
/// Restriction/cleanup observation only; never an outbound grant.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum FinancialCancelProgressV1{DeferredForAdmittedContinue{deadline:Instant},DeferredForAdmittedWitness{deadline:Instant},Sent}
pub(super) const CONT_PREPARING:u8=24;
pub(super) const CONT_REVIEW:u8=25;
pub(super) const CONT_ARMED:u8=26;
pub(super) const CONT_READY:u8=27;
pub(super) const CONT_ADMITTED:u8=28;
pub(super) const AWAITING_ADMISSION:u8=29;

#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContinueStart {
    pub start:Start,pub entry_presentation_digest:String,pub read_presentation_digest:String,
    pub challenge:String,pub native_ceiling_ms:u64,
}
impl ContinueStart {
    pub(super) fn validate(&self)->Result<()>{
        self.start.validate()?;
        if ![&self.entry_presentation_digest,&self.read_presentation_digest,&self.challenge].iter().all(|v|state::hash(v))
            ||self.native_ceiling_ms==0||self.native_ceiling_ms>SUPERVISION_MS{return Err(rejected("full Continue context invalid"));}Ok(())
    }
    pub(super) fn matches_read(&self,start:&Start,read:&SignerFinancialReadPresentationV1)->bool{
        &self.start==start&&self.entry_presentation_digest==read.source_entry_presentation_digest
            &&self.read_presentation_digest==read.presentation_digest
    }
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContinueWire {
    pub context:ContinueStart,pub presentation:SignerContinuePresentationV1,
    pub source_ceiling_ms:u64,pub review_ceiling_ms:u64,
}
impl ContinueWire {
    pub(super) fn validate(&self)->Result<()>{
        self.context.validate()?;self.presentation.validate()?;
        let r=&self.presentation.review;
        if r.coordinator_process_instance!=self.context.start.coordinator||r.signer_role!=self.context.start.role
            ||![self.source_ceiling_ms,self.review_ceiling_ms].iter().all(|v|*v>0&&*v<=SUPERVISION_MS){return Err(rejected("full Continue binding invalid"));}Ok(())
    }
    pub(super) fn matches_read(&self,start:&Start,read:&SignerFinancialReadPresentationV1)->bool{
        let r=&self.presentation.review;let f=&read.facts;let a=&read.actor;
        self.context.matches_read(start,read)&&self.source_ceiling_ms==read.source_ceiling_ms
            &&r.coordinator_process_instance==a.coordinator_process_instance&&r.coordinator_focus_epoch==a.coordinator_focus_epoch
            &&r.signer_role==a.signer_role&&r.signer_process_instance==a.signer_process_instance
            &&r.signer_image_measurement==a.common_image_measurement&&r.original_host_process_instance==f.original_host_process_instance
            &&r.source_identity_digest==f.source_identity_digest&&r.terms_digest==f.terms_digest
            &&r.session_digest==f.session_digest&&r.session_expires_at_ms==f.source_expires_at_ms
            &&r.reviewed_at_ms>=f.reviewed_at_ms
    }
    pub(super) fn matches(&self,c:&ContinueStart,p:&str,e:&str)->bool{
        &self.context==c&&self.presentation.presentation_digest==p&&self.presentation.prepared_digest==e
    }
}
/// Observation after actual local commit, not a pending Admit grant.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerContinuationSavedV1 {
    pub presentation_digest:String,pub prepared_digest:String,
    pub source_identity_digest:String,pub admission_terms_digest:String,
}
impl SignerContinuationSavedV1 {
    pub fn validate(&self)->Result<()>{
        if ![&self.presentation_digest,&self.prepared_digest,&self.source_identity_digest,&self.admission_terms_digest].iter().all(|v|state::hash(v))
        {return Err(rejected("continuation saved data invalid"));}Ok(())
    }
    pub(super) fn matches(&self,p:&SignerContinuePresentationV1)->bool{
        self.presentation_digest==p.presentation_digest&&self.prepared_digest==p.prepared_digest
    }
}
pub(super) struct FullContinueReviewed {
    pub read:Arc<ReadReviewed>,pub wire:ContinueWire,pub original_review:Instant,pub ceiling:Instant,last_wall:AtomicU64,
}
impl FullContinueReviewed {
    pub(super) fn new(read:Arc<ReadReviewed>,wire:ContinueWire,original_source:Instant,original_review:Instant)->Result<Arc<Self>>{
        let binding=Self::from_received_bounds(read,wire,original_source,original_review)?;
        binding.check(false)?;Ok(binding)
    }
    pub(super) fn from_received_bounds(read:Arc<ReadReviewed>,wire:ContinueWire,original_source:Instant,original_review:Instant)->Result<Arc<Self>>{
        wire.validate()?;
        if !same_original_source(read.entry.original_source,original_source)||!wire.matches_read(&read.entry.wire.start,&read.wire){return Err(rejected("Continue changed retained original source"));}
        let clocks=read.entry.clocks;let now=Instant::now();let wall=state::wall_ms()?;let r=&wire.presentation.review;
        let native=clocks.restrict_received(PROFILE,wire.context.native_ceiling_ms,original_source,now)?;
        let review=clocks.restrict_received(PROFILE,wire.review_ceiling_ms,original_review,now)?;
        let source=clocks.restrict_received(PROFILE,wire.source_ceiling_ms,original_source,now)?;
        let ceiling=native.min(review).min(source).min(wall_ceiling(now,wall,r.reviewed_at_ms,r.expires_at_ms)?);
        let b=Arc::new(Self{read,wire,original_review,ceiling,last_wall:AtomicU64::new(wall)});b.check(true)?;Ok(b)
    }
    pub(super) fn core(&self)->&Arc<Core>{&self.read.entry.core}
    pub(super) fn slot(&self)->usize{self.read.entry.slot()}
    pub(super) fn review(&self)->&SignerContinueReviewDataV1{&self.wire.presentation.review}
    pub(super) fn original_source(&self)->Instant{self.read.entry.original_source}
    pub(super) fn check(&self,allow_revoked:bool)->Result<()>{
        let result=(||{
            self.read.entry.check_custody()?;let now=Instant::now();let wall=state::wall_ms()?;
            let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);let r=self.review();
            if (!allow_revoked&&self.core().phase.revoked())||now>=self.original_review||now>=self.ceiling
                ||wall<prior||wall<r.reviewed_at_ms||wall>=r.expires_at_ms||wall>=r.session_expires_at_ms{
                return Err(rejected("retained Continue restriction observed"));}
            if !allow_revoked { self.core().check_action_restrictions()?; } Ok(())
        })();if result.is_err(){self.core().phase.revoke();}result
    }
    pub(super) fn check_arm(&self)->Result<()>{self.check(false)?;if self.core().phase.phase(self.slot())!=CONT_ARMED{return Err(rejected("full Continue Arm consumed"));}Ok(())}
    pub(super) fn check_final(&self)->Result<()>{self.check(true)?;if self.core().phase.phase(self.slot())!=CONT_ADMITTED{return Err(rejected("full Continue Final consumed"));}Ok(())}
}
pub(super) struct FullReady {pub review:Arc<FullContinueReviewed>,pub challenge:String}
pub struct FinancialContinueReviewTicketV1{pub(super) binding:Arc<FullContinueReviewed>,pub(super) consumed:bool}
pub struct FinancialContinueReadyTicketV1{pub(super) binding:Arc<FullReady>,pub(super) consumed:bool}
pub struct FinancialContinueArmOutboundV1{pub(super) binding:Arc<FullContinueReviewed>,pub(super) consumed:bool}
pub struct FinancialContinueFinalOutboundV1{pub(super) binding:Arc<FullReady>,pub(super) consumed:bool}
impl FinancialContinueReviewTicketV1{
    pub fn presentation(&self)->&SignerContinuePresentationV1{&self.binding.wire.presentation}
    pub fn native_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.check(false)?;if self.binding.core().phase.phase(self.binding.slot())!=CONT_REVIEW{return Err(rejected("full Continue review consumed"));}Ok(())}
}
impl FinancialContinueReadyTicketV1{
    pub fn presentation(&self)->&SignerContinuePresentationV1{&self.binding.review.wire.presentation}
    pub fn native_deadline(&self)->Instant{self.binding.review.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.review.check(false)?;if self.binding.review.core().phase.phase(self.binding.review.slot())!=CONT_READY{return Err(rejected("full Continue Ready consumed"));}Ok(())}
}
impl Drop for FinancialContinueReviewTicketV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
impl Drop for FinancialContinueReadyTicketV1{fn drop(&mut self){if !self.consumed{self.binding.review.core().phase.revoke();}}}
impl Drop for FinancialContinueArmOutboundV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
impl Drop for FinancialContinueFinalOutboundV1{fn drop(&mut self){if !self.consumed{
    let b=&self.binding.review;b.core().outbound[b.slot()].compare_exchange(PENDING,ABANDONED,Ordering::AcqRel,Ordering::Acquire).ok();b.core().phase.revoke();
}}}
pub(super) fn pending_phase(phase:u8,status:u8)->bool{phase==CONT_ADMITTED&&status==PENDING}
pub(super) fn pending(core:&Core)->bool{(0..2).any(|i|pending_phase(core.phase.phase(i),core.outbound[i].load(Ordering::Acquire)))}
pub(super) fn failed_outcome(data:&SignerContinueOutcomeV1,p:&SignerContinuePresentationV1)->bool{
    !matches!(data,SignerContinueOutcomeV1::Continued{..})&&data.matches(p)
}
pub(super) struct ContinueDraft{pub review:SignerContinueReviewDataV1,pub original_review:Instant}
#[derive(Default)]
pub(super) struct SContinue{
    pub context:Option<ContinueStart>,pub draft:Option<ContinueDraft>,pub binding:Option<Arc<FullContinueReviewed>>,
    pub ready:Option<String>,pub attempted:bool,pub outcome:bool,pub saved:Option<SignerContinuationSavedV1>,
}
pub(super) struct CContinue{pub context:ContinueStart,pub wire:Option<ContinueWire>,pub binding:Option<Arc<FullContinueReviewed>>,pub ready:Option<Arc<FullReady>>,pub outcome:bool,pub saved:Option<SignerContinuationSavedV1>}
pub(super) struct HContinue{pub context:ContinueStart,pub binding:Option<ContinueWire>,pub ready:Option<String>,pub outcome:bool,pub display_forwarded:bool,pub saved:Option<SignerContinuationSavedV1>}

pub(super) fn same_original_source(retained:Instant,supplied:Instant)->bool{retained==supplied}

#[cfg(test)] mod tests{
    use super::*;
    use crate::{financial_workflow_channel::{sample_entry,sample_read},signer_continue_state::{Phases,SENT},financial_workflow_source::{ENTRY_ADMITTED,READ_ADMITTED,HISTORY_RETAINED}};
    fn sample()->(ContinueWire,SignerFinancialReadPresentationV1){
        let entry=sample_entry();let read=sample_read(&entry);let mut p=crate::signer_continue_channel::sample_binding().presentation;
        let a=&read.actor;let f=&read.facts;let r=&mut p.review;
        r.coordinator_process_instance=a.coordinator_process_instance.clone();r.coordinator_focus_epoch=a.coordinator_focus_epoch;
        r.signer_role=a.signer_role;r.signer_process_instance=a.signer_process_instance.clone();r.signer_image_measurement=a.common_image_measurement.clone();
        r.original_host_process_instance=f.original_host_process_instance.clone();r.source_identity_digest=f.source_identity_digest.clone();
        r.terms_digest=f.terms_digest.clone();r.session_digest=f.session_digest.clone();r.session_expires_at_ms=f.source_expires_at_ms;
        r.reviewed_at_ms=140000;r.expires_at_ms=240000;p.presentation_digest=p.calculate_presentation_digest().unwrap();
        (ContinueWire{context:ContinueStart{start:entry.start,entry_presentation_digest:read.source_entry_presentation_digest.clone(),
            read_presentation_digest:read.presentation_digest.clone(),challenge:"6".repeat(64),native_ceiling_ms:240000},
            presentation:p,source_ceiling_ms:read.source_ceiling_ms,review_ceiling_ms:read.read_ceiling_ms},read)
    }
    #[test]
    fn full_continue_binding_cannot_replace_completed_read_actor_source_or_clocks(){
        let (b,read)=sample();b.validate().unwrap();assert!(b.matches_read(&b.context.start,&read));
        for n in 0..10{let mut x=b.clone();match n{
            0=>x.presentation.review.source_identity_digest="0".repeat(64),1=>x.presentation.review.terms_digest="0".repeat(64),
            2=>x.presentation.review.session_digest="0".repeat(64),3=>x.presentation.review.original_host_process_instance="0".repeat(64),
            4=>x.presentation.review.signer_process_instance="0".repeat(64),5=>x.presentation.review.signer_image_measurement="0".repeat(64),
            6=>x.context.entry_presentation_digest="0".repeat(64),7=>x.context.read_presentation_digest="0".repeat(64),
            8=>x.source_ceiling_ms-=1,_=>x.presentation.review.session_expires_at_ms+=1,}
            assert!(!x.matches_read(&b.context.start,&read));}
    }
    #[test]
    fn full_continue_offsets_do_not_relax_narrow_three_hundred_second_validator(){
        let (mut b,_)=sample();b.context.native_ceiling_ms=400000;b.review_ceiling_ms=400000;b.source_ceiling_ms=500000;b.validate().unwrap();
        let mut narrow=crate::signer_continue_channel::sample_binding();narrow.context.native_deadline_ms=400000;assert!(narrow.validate().is_err());
        b.context.start.profile="coordinated-signer-continue".into();assert!(b.validate().is_err());
        b.context.start.profile=PROFILE.into();b.review_ceiling_ms=SUPERVISION_MS+1;assert!(b.validate().is_err());
    }
    #[test]
    fn full_continue_phase_completion_preserves_restriction_without_rearming(){
        let p=Phases::new();p.step(0,0,HISTORY_RETAINED).unwrap();
        for(a,b)in[(HISTORY_RETAINED,CONT_PREPARING),(CONT_PREPARING,CONT_REVIEW),(CONT_REVIEW,CONT_ARMED),(CONT_ARMED,CONT_READY),(CONT_READY,CONT_ADMITTED)]{
            p.step(0,a,b).unwrap();assert!(p.step(0,a,b).is_err());}
        p.revoke();p.observe_workflow_continue_saved(0).unwrap();assert!(p.revoked());assert_eq!(p.phase(0),AWAITING_ADMISSION);
        assert!(p.observe_workflow_continue_saved(0).is_err());assert!(p.step(0,AWAITING_ADMISSION,0).is_err());
        let p=Phases::new();p.step(1,0,CONT_READY).unwrap();p.revoke();assert!(p.step(1,CONT_READY,CONT_ADMITTED).is_err());
        assert!(p.observe_workflow_continue_saved(1).is_err());
    }
    #[test]
    fn received_prior_continue_final_preserves_r_without_new_native_admission(){
        let p=Phases::new();p.step(0,0,CONT_READY).unwrap();p.revoke();
        // Ordinary native C A is still forbidden after R.
        assert!(p.step(0,CONT_READY,CONT_ADMITTED).is_err());
        // Only the genuine receiver calls this after exact ordered frame/Ready
        // validation. The pure state test creates no origin, peer or Final.
        p.observe_received_workflow_continue_final(0).unwrap();
        assert!(p.revoked());assert_eq!(p.phase(0),CONT_ADMITTED);
        assert!(p.observe_received_workflow_continue_final(0).is_err());
        assert!(p.observe_received_workflow_continue_final(1).is_err());
        assert!(p.observe_received_workflow_continue_final(2).is_err());
        for phase in [ENTRY_ADMITTED,READ_ADMITTED,CONT_ARMED,AWAITING_ADMISSION]{
            let p=Phases::new();p.step(1,0,phase).unwrap();p.revoke();
            assert!(p.observe_received_workflow_continue_final(1).is_err());
            assert!(p.revoked());assert_eq!(p.phase(1),phase);
        }
    }
    #[test]
    fn final_before_cancel_pending_is_specific_to_full_continue_not_entry_or_read(){
        assert!(pending_phase(CONT_ADMITTED,PENDING));
        for phase in [ENTRY_ADMITTED,READ_ADMITTED,CONT_READY,AWAITING_ADMISSION,state::ADMITTED]{assert!(!pending_phase(phase,PENDING));}
        assert!(!pending_phase(CONT_ADMITTED,SENT));assert!(!pending_phase(CONT_ADMITTED,ABANDONED));
    }
    #[test]
    fn cached_continue_clock_can_outlive_read_without_restarting_at_request(){
        use crate::financial_workflow_clock::FullWorkflowClocksV1;
        use std::time::Duration;
        let epoch=Instant::now();let clocks=FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();
        let read_end=epoch+Duration::from_secs(100);let captured=epoch+Duration::from_micros(150_000_999);
        let source=epoch+Duration::from_secs(600);let offset=clocks.restrictive_offset(captured,source).unwrap();
        let restored=clocks.restrict_received(PROFILE,offset,source,read_end+Duration::from_secs(1)).unwrap();
        assert_eq!(restored,epoch+Duration::from_secs(150));assert!(restored<=captured);
        let late_caller=epoch+Duration::from_secs(250);assert_eq!(late_caller.min(restored),restored);
        assert!(clocks.restrict_received(PROFILE,offset,source,restored).is_err());
    }
    #[test]
    fn original_source_instant_is_exact_not_a_refreshed_or_shortened_replacement(){
        let original=Instant::now();assert!(same_original_source(original,original));
        assert!(!same_original_source(original,original+std::time::Duration::from_nanos(1)));
        assert!(!same_original_source(original+std::time::Duration::from_nanos(1),original));
    }
    #[test]
    fn saved_and_failed_observations_keep_exact_original_prepared_presentation(){
        let (b,_)=sample();let p=&b.presentation;
        let mut saved=SignerContinuationSavedV1{presentation_digest:p.presentation_digest.clone(),prepared_digest:p.prepared_digest.clone(),source_identity_digest:"7".repeat(64),admission_terms_digest:"8".repeat(64)};
        saved.validate().unwrap();assert!(saved.matches(p));saved.prepared_digest="0".repeat(64);assert!(!saved.matches(p));
        let continued=SignerContinueOutcomeV1::Continued{presentation_digest:p.presentation_digest.clone(),prepared_digest:p.prepared_digest.clone()};assert!(!failed_outcome(&continued,p));
        let uncertain=SignerContinueOutcomeV1::Uncertain{presentation_digest:p.presentation_digest.clone(),prepared_digest:p.prepared_digest.clone()};assert!(failed_outcome(&uncertain,p));
        let wrong=SignerContinueOutcomeV1::KnownNoEffect{presentation_digest:"0".repeat(64),prepared_digest:p.prepared_digest.clone()};assert!(!failed_outcome(&wrong,p));
    }
    #[test]
    fn full_continue_context_and_saved_data_reject_unknown_or_duplicate_fields(){
        let (b,_)=sample();let encoded=serde_json::to_string(&b.context).unwrap();
        let mut duplicate=encoded.clone();duplicate.insert_str(1,"\"challenge\":\"x\",");assert!(serde_json::from_str::<ContinueStart>(&duplicate).is_err());
        let mut unknown=encoded;unknown.insert_str(1,"\"raw_fd\":4,");assert!(serde_json::from_str::<ContinueStart>(&unknown).is_err());
        let data=SignerContinuationSavedV1{presentation_digest:"a".repeat(64),prepared_digest:"b".repeat(64),source_identity_digest:"c".repeat(64),admission_terms_digest:"d".repeat(64)};
        let mut value=serde_json::to_value(data).unwrap();value["permit"]=serde_json::json!(true);assert!(serde_json::from_value::<SignerContinuationSavedV1>(value).is_err());
    }
}
