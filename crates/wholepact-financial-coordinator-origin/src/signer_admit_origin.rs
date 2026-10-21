//! Finite same-Core Signer Admit. H is the trusted original relay, not a direct
//! C/S edge. No Continue token or ordinary presentation creates an Admit grant.
use super::*;
use crate::signer_admit_data::{SignerAdmitFactsV1,SignerAdmitPresentationV1,SignerAdmitCommittedV1,SignerAdmitOutcomeV1,ADMIT_PURPOSE};
use std::sync::atomic::AtomicU64;
pub(super) const ADMIT_REVIEW:u8=32;
pub(super) const ADMIT_ARMED:u8=33;
pub(super) const ADMIT_READY:u8=34;
pub(super) const ADMIT_ADMITTED:u8=35;
pub(super) const AWAITING_NEXT_READ:u8=36;
struct Reviewed {read:Arc<ReadReviewed>,wire:SignerAdmitPresentationV1,original_admit:Instant,ceiling:Instant,last_wall:AtomicU64}
impl Reviewed {
    fn new(read:Arc<ReadReviewed>,wire:SignerAdmitPresentationV1,original_admit:Instant)->Result<Arc<Self>>{
        wire.validate()?;let now=Instant::now();let wall=state::wall_ms()?;
        let cap=read.entry.clocks.restrict_received(PROFILE,wire.admit_ceiling_ms,original_admit,now)?
            .min(wall_ceiling(now,wall,wire.facts.reviewed_at_ms,wire.facts.expires_at_ms)?);
        let result=Arc::new(Self{read,wire,original_admit,ceiling:cap,last_wall:AtomicU64::new(wall)});result.check_bounds()?;Ok(result)
    }
    fn core(&self)->&Arc<Core>{&self.read.entry.core}
    fn slot(&self)->usize{self.read.entry.slot()}
    fn check_bounds(&self)->Result<()>{
        self.read.entry.check_custody()?;crate::channel::require_time(self.original_admit.min(self.ceiling))?;
        let wall=state::wall_ms()?;let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<prior||wall<self.wire.facts.reviewed_at_ms||wall>=self.wire.facts.expires_at_ms{return Err(rejected("Signer Admit original review clock"));}
        Ok(())
    }
    fn check(&self)->Result<()>{self.check_bounds()?;self.core().check_action_restrictions()}
}
struct Ready {review:Arc<Reviewed>,challenge:String,digest:String}
/// Genuine matching H receive only. All checks remain R-sensitive.
pub struct SignerAdmitArmV1 {binding:Arc<Reviewed>}
impl SignerAdmitArmV1 {
    pub fn presentation(&self)->&SignerAdmitPresentationV1{&self.binding.wire}
    pub fn original_source_deadline(&self)->Instant{self.binding.read.entry.original_source}
    pub fn original_admit_deadline(&self)->Instant{self.binding.original_admit}
    pub fn check_current(&self)->Result<()>{self.binding.check()?;
        if self.binding.core().phase.phase(self.binding.slot())!=ADMIT_ARMED{return Err(rejected("Signer Admit Arm consumed"));}Ok(())}
}
pub struct SignerAdmitFinalV1 {binding:Arc<Ready>,witness_presentation:String}
impl SignerAdmitFinalV1 {
    pub fn presentation(&self)->&SignerAdmitPresentationV1{&self.binding.review.wire}
    pub fn original_source_deadline(&self)->Instant{self.binding.review.read.entry.original_source}
    pub fn original_admit_deadline(&self)->Instant{self.binding.review.original_admit}
    pub fn admission_ready_digest(&self)->&str{&self.binding.digest}
    pub fn witness_presentation_digest(&self)->&str{&self.witness_presentation}
    pub fn check_current(&self)->Result<()>{self.binding.review.check()?;
        if self.binding.review.core().phase.phase(self.binding.review.slot())!=ADMIT_ADMITTED{return Err(rejected("Signer Admit Final consumed"));}Ok(())}
}
pub struct SignerAdmitReviewTicketV1 {binding:Arc<Reviewed>,consumed:bool}
impl SignerAdmitReviewTicketV1 {
    pub fn presentation(&self)->&SignerAdmitPresentationV1{&self.binding.wire}
    pub fn native_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.check()?;
        if self.binding.core().phase.phase(self.binding.slot())!=ADMIT_REVIEW{return Err(rejected("Signer Admit review consumed"));}Ok(())}
}
impl Drop for SignerAdmitReviewTicketV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
pub struct SignerAdmitReadyTicketV1 {binding:Arc<Ready>,consumed:bool}
impl SignerAdmitReadyTicketV1 {
    pub fn admission_ready_digest(&self)->&str{&self.binding.digest}
    pub fn presentation(&self)->&SignerAdmitPresentationV1{&self.binding.review.wire}
    pub fn native_deadline(&self)->Instant{self.binding.review.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.review.check()?;
        if self.binding.review.core().phase.phase(self.binding.review.slot())!=ADMIT_READY{return Err(rejected("Signer Admit Ready consumed"));}Ok(())}
}
impl Drop for SignerAdmitReadyTicketV1{fn drop(&mut self){if !self.consumed{self.binding.review.core().phase.revoke();}}}
pub struct SignerAdmitArmOutboundV1 {binding:Arc<Reviewed>,consumed:bool}
impl Drop for SignerAdmitArmOutboundV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
pub struct SignerAdmitFinalOutboundV1 {binding:Arc<Ready>,witness_presentation:String,consumed:bool}
impl Drop for SignerAdmitFinalOutboundV1{fn drop(&mut self){if !self.consumed{self.binding.review.core().phase.revoke();}}}
#[derive(Default)]
pub(super) struct SAdmit{review:Option<Arc<Reviewed>>,ready:Option<Arc<Ready>>,attempted:bool,outcome:bool,committed:Option<SignerAdmitCommittedV1>}
#[derive(Default)]
pub(super) struct CAdmit{wire:Option<SignerAdmitPresentationV1>,observed_ready:Option<String>,review:Option<Arc<Reviewed>>,ready:Option<Arc<Ready>>,outcome:bool,committed:Option<SignerAdmitCommittedV1>}
#[derive(Default)]
pub(super) struct HAdmit{wire:Option<SignerAdmitPresentationV1>,ready:Option<(String,String)>,outcome:bool,forwarded:bool,committed:Option<SignerAdmitCommittedV1>}
fn link(p:&SignerAdmitPresentationV1,read:&SignerFinancialReadPresentationV1,c:&SignerContinuePresentationV1,saved:&SignerContinuationSavedV1)->bool{
    let f=&p.facts;let r=&read.facts;
    p.actor==read.actor&&p.owner_selection_digest==r.owner_selection_digest&&p.source_ceiling_ms==read.source_ceiling_ms
        &&p.continue_presentation_digest==c.presentation_digest&&p.prepared_digest==c.prepared_digest
        &&saved.matches(c)&&f.source_identity_digest==saved.source_identity_digest&&f.admission_terms_digest==saved.admission_terms_digest
        &&f.request_json==c.request_json&&f.request_digest==c.request_digest&&f.original_host_process_instance==r.original_host_process_instance
        &&f.owner_certificate_digest==r.owner_certificate_digest&&f.disclosure_digest==r.disclosure_digest
        &&f.account_id==r.account_id&&f.terms_digest==r.terms_digest&&f.source_expires_at_ms==r.source_expires_at_ms
}
fn committed_matches(p:&SignerAdmitPresentationV1,r:&Ready,data:&SignerAdmitCommittedV1)->bool{
    data.presentation_digest==p.presentation_digest&&data.admission_ready_digest==r.digest&&data.request_digest==p.facts.request_digest
        &&p.facts.expected_head_sequence.checked_add(1)==Some(data.head_sequence)
}
fn outcome_matches(p:&SignerAdmitPresentationV1,digest:Option<&str>,data:&SignerAdmitOutcomeV1)->bool{
    match data{SignerAdmitOutcomeV1::KnownNoEffect{presentation_digest,admission_ready_digest}|SignerAdmitOutcomeV1::Uncertain{presentation_digest,admission_ready_digest}=>
        presentation_digest==&p.presentation_digest&&admission_ready_digest.as_deref()==digest}
}
impl SignerFinancialWorkflowOriginV1 {
    /// Data must be prepared from cached actual Context/Pending; this method
    /// grants no private pre-review journal/key read.
    pub fn offer_admit_review(&mut self,facts:SignerAdmitFactsV1,original_source:Instant,original_admit:Instant)->Result<SignerAdmitPresentationV1>{
        if self.admission.review.is_some()||self.core.phase.phase(self.target.index())!=AWAITING_ADMISSION||self.cancel_seen||self.failed{return Err(rejected("Signer Admit offer phase"));}
        self.core.check_action_restrictions()?;facts.validate()?;
        let read=self.read.as_ref().ok_or_else(||rejected("Signer Admit original Read missing"))?;
        let c=self.continuation.binding.as_ref().ok_or_else(||rejected("Signer Admit original Continue missing"))?;
        let saved=self.continuation.saved.as_ref().ok_or_else(||rejected("Signer Admit saved source missing"))?;
        if original_source!=read.entry.original_source{return Err(rejected("Signer Admit source Instant replaced"));}
        let now=Instant::now();if original_admit<=now||original_admit>now+std::time::Duration::from_secs(120){return Err(rejected("Signer Admit operation deadline"));}
        let mut wire=SignerAdmitPresentationV1{version:1,purpose:ADMIT_PURPOSE.into(),actor:read.wire.actor.clone(),facts,
            owner_selection_digest:read.wire.facts.owner_selection_digest.clone(),continue_presentation_digest:c.wire.presentation.presentation_digest.clone(),
            prepared_digest:c.wire.presentation.prepared_digest.clone(),admit_challenge:state::nonce()?,source_ceiling_ms:read.wire.source_ceiling_ms,
            admit_ceiling_ms:self.clocks.restrictive_offset(original_admit,original_source)?,presentation_digest:String::new()};
        wire.presentation_digest=wire.calculate_presentation_digest()?;wire.validate()?;
        if !link(&wire,&read.wire,&c.wire.presentation,saved){return Err(rejected("Signer Admit changed retained source/owner/request"));}
        let b=Reviewed::new(Arc::clone(read),wire.clone(),original_admit)?;b.check()?;
        self.core.phase.step(self.target.index(),AWAITING_ADMISSION,ADMIT_REVIEW)?;self.admission.review=Some(b);
        self.send(&Packet::AdmitDisplay{data:wire.clone()})?;Ok(wire)
    }
    pub fn send_admit_ready(&mut self,arm:SignerAdmitArmV1,admission_ready_digest:String)->Result<()>{
        let b=self.admission.review.as_ref().ok_or_else(||rejected("Signer Admit missing review"))?;
        if !Arc::ptr_eq(&arm.binding,b)||self.admission.ready.is_some()||self.admission.outcome||!state::hash(&admission_ready_digest){return Err(rejected("Signer Admit Ready reused"));}
        arm.check_current()?;let ready=Arc::new(Ready{review:Arc::clone(b),challenge:state::nonce()?,digest:admission_ready_digest});
        self.core.phase.step(self.target.index(),ADMIT_ARMED,ADMIT_READY)?;self.admission.ready=Some(Arc::clone(&ready));
        self.send(&Packet::AdmitReady{actor:b.wire.actor.clone(),presentation_digest:b.wire.presentation_digest.clone(),ready_challenge:ready.challenge.clone(),admission_ready_digest:ready.digest.clone()})
    }
    pub fn report_admitted(&mut self,data:SignerAdmitCommittedV1)->Result<()>{
        data.validate()?;let r=self.admission.ready.as_ref().ok_or_else(||rejected("Signer Admit commit before Ready"))?;
        if self.admission.outcome||!self.admission.attempted||!committed_matches(&r.review.wire,r,&data){return Err(rejected("Signer Admit committed binding"));}
        // Observation after maintained authenticated response. Preserve R; no
        // new Read or writer key opening is created by this transition.
        self.core.phase.observe_workflow_admit_saved(self.target.index())?;self.admission.outcome=true;self.admission.committed=Some(data.clone());
        self.send(&Packet::Admitted{actor:r.review.wire.actor.clone(),data})
    }
    pub fn send_admit_outcome(&mut self,data:SignerAdmitOutcomeV1)->Result<()>{
        data.validate()?;let b=self.admission.review.as_ref().ok_or_else(||rejected("Signer Admit outcome before review"))?;
        if self.admission.outcome||!outcome_matches(&b.wire,self.admission.ready.as_ref().map(|r|r.digest.as_str()),&data){return Err(rejected("Signer Admit outcome mismatch"));}
        let actor=b.wire.actor.clone();self.admission.outcome=true;self.restrict()?;self.send(&Packet::AdmitOutcome{actor,data})
    }
    pub(super) fn receive_admit(&mut self,p:Packet)->Result<SignerFinancialWorkflowRequestV1>{
        if self.cancel_seen||self.failed||self.disposed||self.admission.outcome{return Err(rejected("Signer Admit command after terminal"));}
        let b=self.admission.review.as_ref().ok_or_else(||rejected("Signer Admit command before review"))?;
        match p{
            Packet::AdmitArm{actor,presentation_digest}=>{
                if actor!=b.wire.actor||presentation_digest!=b.wire.presentation_digest{return Err(rejected("Signer Admit Arm mismatch"));}
                b.check()?;self.core.phase.step(self.target.index(),ADMIT_REVIEW,ADMIT_ARMED)?;
                Ok(SignerFinancialWorkflowRequestV1::AdmitArm(SignerAdmitArmV1{binding:Arc::clone(b)}))
            }
            Packet::AdmitFinal{actor,presentation_digest,ready_challenge,admission_ready_digest,witness_presentation_digest}=>{
                if self.admission.attempted{return Err(rejected("Signer Admit Final reused"));}self.admission.attempted=true;
                let r=self.admission.ready.as_ref().ok_or_else(||rejected("Signer Admit Final before Ready"))?;
                if actor!=b.wire.actor||presentation_digest!=b.wire.presentation_digest||ready_challenge!=r.challenge||admission_ready_digest!=r.digest||!state::hash(&witness_presentation_digest){return Err(rejected("Signer Admit Final mismatch"));}
                b.check()?;self.core.phase.step(self.target.index(),ADMIT_READY,ADMIT_ADMITTED)?;
                Ok(SignerFinancialWorkflowRequestV1::AdmitFinal(SignerAdmitFinalV1{binding:Arc::clone(r),witness_presentation:witness_presentation_digest}))
            }
            _=>Err(rejected("wrong Signer Admit request")),
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn arm_admit(&self,mut ticket:SignerAdmitReviewTicketV1)->Result<SignerAdmitArmOutboundV1>{
        if !Arc::ptr_eq(&self.core,ticket.binding.core()){self.revoke();return Err(rejected("foreign Signer Admit review"));}
        ticket.check_current()?;self.core.phase.step(ticket.binding.slot(),ADMIT_REVIEW,ADMIT_ARMED)?;
        ticket.consumed=true;Ok(SignerAdmitArmOutboundV1{binding:Arc::clone(&ticket.binding),consumed:false})
    }
    /// Visible native tail only, after whole interruption batch. The matching
    /// W Armed value was created only by actual original W acknowledgement.
    pub fn admit_signer(&self,mut ticket:SignerAdmitReadyTicketV1,witness:&crate::FinancialWitnessArmedV1)->Result<SignerAdmitFinalOutboundV1>{
        let b=&ticket.binding.review;
        if !Arc::ptr_eq(&self.core,b.core()){self.revoke();return Err(rejected("foreign Signer Admit Ready"));}
        witness.matches_admit(&self.core,&b.wire)?;ticket.check_current()?;
        self.core.phase.step(b.slot(),ADMIT_READY,ADMIT_ADMITTED)?;ticket.consumed=true;
        Ok(SignerAdmitFinalOutboundV1{binding:Arc::clone(&ticket.binding),witness_presentation:witness.presentation().presentation_digest.clone(),consumed:false})
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_admit_arm(&mut self,outbound:SignerAdmitArmOutboundV1)->Result<()>{self.try_send_admit_arm(outbound)?.require_sent()}
    pub fn try_send_admit_arm(&mut self,mut outbound:SignerAdmitArmOutboundV1)->Result<FinancialSendProgressV1>{
        let b=&outbound.binding;
        if !Arc::ptr_eq(&self.core,b.core()){return Err(rejected("foreign Signer Admit Arm outbound"));}
        b.check_bounds()?;let slot=self.slots[b.slot()].as_mut().ok_or_else(||rejected("Signer Admit slot missing"))?;
        if slot.wire_phase!=ADMIT_REVIEW||self.core.phase.phase(b.slot())!=ADMIT_ARMED{return Err(rejected("Signer Admit Arm transport phase"));}
        if self.core.phase.source_send_restricted(b.slot(),ADMIT_ARMED)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}outbound.consumed=true;
        let progress=self.send_positive(&Packet::AdmitArm{actor:b.wire.actor.clone(),presentation_digest:b.wire.presentation_digest.clone()},b.ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.slots[b.slot()].as_mut().unwrap().wire_phase=ADMIT_ARMED;}Ok(progress)
    }
    pub fn send_admit_final(&mut self,outbound:SignerAdmitFinalOutboundV1)->Result<()>{self.try_send_admit_final(outbound)?.require_sent()}
    pub fn try_send_admit_final(&mut self,mut outbound:SignerAdmitFinalOutboundV1)->Result<FinancialSendProgressV1>{
        let r=&outbound.binding;let b=&r.review;
        if !Arc::ptr_eq(&self.core,b.core()){return Err(rejected("foreign Signer Admit Final outbound"));}
        b.check_bounds()?;let slot=self.slots[b.slot()].as_mut().ok_or_else(||rejected("Signer Admit slot missing"))?;
        if slot.wire_phase!=ADMIT_READY||self.core.phase.phase(b.slot())!=ADMIT_ADMITTED{return Err(rejected("Signer Admit Final transport phase"));}
        if self.core.phase.source_send_restricted(b.slot(),ADMIT_ADMITTED)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}outbound.consumed=true;
        let progress=self.send_positive(&Packet::AdmitFinal{actor:b.wire.actor.clone(),presentation_digest:b.wire.presentation_digest.clone(),ready_challenge:r.challenge.clone(),
            admission_ready_digest:r.digest.clone(),witness_presentation_digest:outbound.witness_presentation.clone()},b.ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.slots[b.slot()].as_mut().unwrap().wire_phase=ADMIT_ADMITTED;}Ok(progress)
    }
    pub(super) fn receive_admit_event(&mut self,p:Packet)->Result<CoordinatorFinancialEventV1>{
        let role=p.target()?.ok_or_else(||rejected("Signer Admit missing target"))?;let i=role.index();
        let slot=self.slots[i].as_mut().ok_or_else(||rejected("Signer Admit unsolicited response"))?;
        if slot.failed{return Err(rejected("Signer Admit response after failure"));}
        match p{
            Packet::AdmitDisplay{data}=>{
                data.validate()?;let read=slot.read.as_ref().ok_or_else(||rejected("Signer Admit Read missing"))?;
                let c=slot.continuation.as_ref().ok_or_else(||rejected("Signer Admit Continue missing"))?;
                if slot.wire_phase!=AWAITING_ADMISSION||slot.admission.wire.is_some()
                    ||!link(&data,&read.wire,&c.wire.as_ref().ok_or_else(||rejected("Signer Admit Continue display missing"))?.presentation,
                        c.saved.as_ref().ok_or_else(||rejected("Signer Admit saved source missing"))?){return Err(rejected("Signer Admit display retained binding"));}
                slot.wire_phase=ADMIT_REVIEW;slot.admission.wire=Some(data.clone());
                let deadline=self.clocks.restrict_received(PROFILE,data.admit_ceiling_ms,read.entry.original_source,Instant::now())?;
                let b=Reviewed::new(Arc::clone(read),data,deadline)?;
                slot.admission.review=Some(Arc::clone(&b));
                if !received_admit_progress(&self.core.phase,i,AWAITING_ADMISSION,ADMIT_REVIEW)?{return Ok(CoordinatorFinancialEventV1::Restricted(role));}
                Ok(CoordinatorFinancialEventV1::AdmitDisplay(SignerAdmitReviewTicketV1{binding:b,consumed:false}))
            }
            Packet::AdmitReady{actor,presentation_digest,ready_challenge,admission_ready_digest}=>{
                let wire=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit Ready before Display"))?;
                if slot.wire_phase!=ADMIT_ARMED||slot.admission.observed_ready.is_some()||slot.admission.outcome||actor!=wire.actor||presentation_digest!=wire.presentation_digest
                    ||!state::hash(&ready_challenge)||!state::hash(&admission_ready_digest){return Err(rejected("Signer Admit Ready mismatch"));}
                slot.wire_phase=ADMIT_READY;slot.admission.observed_ready=Some(admission_ready_digest.clone());
                let b=slot.admission.review.as_ref().ok_or_else(||rejected("Signer Admit positive review missing"))?;
                b.check_bounds()?;let r=Arc::new(Ready{review:Arc::clone(b),challenge:ready_challenge,digest:admission_ready_digest});
                slot.admission.ready=Some(Arc::clone(&r));
                if !received_admit_progress(&self.core.phase,i,ADMIT_ARMED,ADMIT_READY)?{return Ok(CoordinatorFinancialEventV1::Restricted(role));}
                Ok(CoordinatorFinancialEventV1::AdmitReady(SignerAdmitReadyTicketV1{binding:r,consumed:false}))
            }
            Packet::Admitted{actor,data}=>{
                data.validate()?;let r=slot.admission.ready.as_ref().ok_or_else(||rejected("Signer Admit response before Ready"))?;
                if slot.wire_phase!=ADMIT_ADMITTED||slot.admission.outcome||actor!=r.review.wire.actor||!committed_matches(&r.review.wire,r,&data){return Err(rejected("Signer Admit authenticated result mismatch"));}
                self.core.phase.observe_workflow_admit_saved(i)?;slot.wire_phase=AWAITING_NEXT_READ;slot.admission.outcome=true;slot.admission.committed=Some(data.clone());
                Ok(CoordinatorFinancialEventV1::AwaitingNextRead{role,data})
            }
            Packet::AdmitOutcome{actor,data}=>{
                data.validate()?;let b=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit outcome before Display"))?;
                if slot.admission.outcome||actor!=b.actor||!terminal_outcome_matches(b,slot.admission.observed_ready.as_deref(),slot.wire_phase,self.core.phase.revoked(),&data){return Err(rejected("Signer Admit outcome binding"));}
                slot.admission.outcome=true;self.core.phase.revoke();if self.cleanup.is_none(){self.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);}
                Ok(CoordinatorFinancialEventV1::AdmitOutcome{role,data})
            }
            _=>Err(rejected("wrong Signer Admit event")),
        }
    }
}
// Positive receive progress only. R cannot turn a terminal observation into
// authority, and cannot close unrelated already-admitted custody merely by
// winning this exact phase CAS. Wrong phase remains a fatal protocol error.
fn received_admit_progress(phase:&Phases,slot:usize,from:u8,to:u8)->Result<bool>{
    if phase.source_send_restricted(slot,from)?{return Ok(false);}
    match phase.step(slot,from,to){
        Ok(())=>Ok(!phase.source_send_restricted(slot,to)?),
        Err(error)=>{if phase.source_send_restricted(slot,from)?{Ok(false)}else{Err(error)}}
    }
}

impl HostFinancialWorkflowRelayV1 {
    pub(super) fn down_admit(&mut self,p:&Packet)->Result<()>{
        let role=p.target()?.ok_or_else(||rejected("Signer Admit relay target missing"))?;let slot=self.slots[role.index()].as_mut().ok_or_else(||rejected("Signer Admit relay slot missing"))?;
        if slot.failed||slot.admission.outcome{return Err(rejected("Signer Admit relay terminal"));}
        let b=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit relay Display missing"))?;
        match p{
            Packet::AdmitArm{actor,presentation_digest}=>{
                if slot.phase!=ADMIT_REVIEW||actor!=&b.actor||presentation_digest!=&b.presentation_digest{return Err(rejected("Signer Admit relay Arm binding"));}
                admit_current(slot,self.clocks)?;slot.phase=ADMIT_ARMED;Ok(())
            }
            Packet::AdmitFinal{actor,presentation_digest,ready_challenge,admission_ready_digest,witness_presentation_digest}=>{
                if slot.phase!=ADMIT_READY||actor!=&b.actor||presentation_digest!=&b.presentation_digest||!state::hash(witness_presentation_digest)
                    ||slot.admission.ready.as_ref()!=Some(&(ready_challenge.clone(),admission_ready_digest.clone())){return Err(rejected("Signer Admit relay Final binding"));}
                admit_current(slot,self.clocks)?;slot.phase=ADMIT_ADMITTED;Ok(())
            }
            _=>Err(rejected("wrong Signer Admit relay command")),
        }
    }
    pub(super) fn up_admit(&mut self,role:Target,p:&Packet)->Result<bool>{
        let slot=self.slots[role.index()].as_mut().ok_or_else(||rejected("Signer Admit relay source missing"))?;
        if slot.failed||slot.admission.outcome{return Err(rejected("Signer Admit relay response after terminal"));}
        match p{
            Packet::AdmitDisplay{data}=>{
                data.validate()?;let read=slot.read.as_ref().ok_or_else(||rejected("Signer Admit relay Read missing"))?;
                let c=slot.continuation.as_ref().ok_or_else(||rejected("Signer Admit relay Continue missing"))?;
                if slot.phase!=AWAITING_ADMISSION||slot.admission.wire.is_some()||!link(data,read,&c.binding.as_ref().ok_or_else(||rejected("Signer Admit relay Continue display missing"))?.presentation,
                    c.saved.as_ref().ok_or_else(||rejected("Signer Admit relay saved source missing"))?){return Err(rejected("Signer Admit relay Display mismatch"));}
                slot.admission.wire=Some(data.clone());slot.admission.forwarded=!self.restricted;slot.phase=ADMIT_REVIEW;
                if !self.restricted{admit_current(slot,self.clocks)?;}Ok(!self.restricted)
            }
            Packet::AdmitReady{actor,presentation_digest,ready_challenge,admission_ready_digest}=>{
                let b=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit relay Ready before display"))?;
                if slot.phase!=ADMIT_ARMED||slot.admission.ready.is_some()||actor!=&b.actor||presentation_digest!=&b.presentation_digest
                    ||!state::hash(ready_challenge)||!state::hash(admission_ready_digest){return Err(rejected("Signer Admit relay Ready mismatch"));}
                slot.admission.ready=Some((ready_challenge.clone(),admission_ready_digest.clone()));slot.phase=ADMIT_READY;
                if !self.restricted{admit_current(slot,self.clocks)?;}Ok(!self.restricted)
            }
            Packet::Admitted{actor,data}=>{
                data.validate()?;let b=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit relay result before review"))?;
                if slot.phase!=ADMIT_ADMITTED||actor!=&b.actor||data.presentation_digest!=b.presentation_digest||data.request_digest!=b.facts.request_digest
                    ||slot.admission.ready.as_ref().map(|r|r.1.as_str())!=Some(data.admission_ready_digest.as_str())
                    ||b.facts.expected_head_sequence.checked_add(1)!=Some(data.head_sequence)||!slot.admission.forwarded{return Err(rejected("Signer Admit relay result mismatch"));}
                slot.admission.outcome=true;slot.admission.committed=Some(data.clone());slot.phase=AWAITING_NEXT_READ;Ok(true)
            }
            Packet::AdmitOutcome{actor,data}=>{
                data.validate()?;let b=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit relay outcome before review"))?;
                if actor!=&b.actor||!outcome_matches(b,slot.admission.ready.as_ref().map(|r|r.1.as_str()),data){return Err(rejected("Signer Admit relay outcome mismatch"));}
                slot.admission.outcome=true;let forward=slot.admission.forwarded;self.restrict()?;Ok(forward)
            }
            _=>Err(rejected("wrong Signer Admit relay response")),
        }
    }
}
fn admit_current(slot:&mut HSlot,clocks:FullWorkflowClocksV1)->Result<()>{
    let p=slot.admission.wire.as_ref().ok_or_else(||rejected("Signer Admit relay binding missing"))?;
    let now=Instant::now();for ms in [p.admit_ceiling_ms,p.source_ceiling_ms]{clocks.restrict_received(PROFILE,ms,clocks.supervision(),now)?;}
    relay_wall(&mut slot.last_wall,p.facts.reviewed_at_ms,p.facts.expires_at_ms,p.facts.source_expires_at_ms)
}

// H may validate a Ready after R but intentionally not forward positive progress.
// Its subsequent terminal observation can carry that exact pin digest. Accept
// only terminal data in the already-Armed restricted phase, never mint a ticket.
fn terminal_outcome_matches(p:&SignerAdmitPresentationV1,seen:Option<&str>,phase:u8,revoked:bool,data:&SignerAdmitOutcomeV1)->bool{
    let (presentation,digest)=match data{SignerAdmitOutcomeV1::KnownNoEffect{presentation_digest,admission_ready_digest}|SignerAdmitOutcomeV1::Uncertain{presentation_digest,admission_ready_digest}=>(presentation_digest,admission_ready_digest.as_deref())};
    presentation==&p.presentation_digest&&match (seen,digest){
        (Some(a),Some(b))=>a==b,(None,None)=>true,
        (None,Some(b))=>revoked&&phase==ADMIT_ARMED&&state::hash(b),_=>false,
    }
}
impl SAdmit{pub(super) fn disposal_allowed(&self)->bool{self.review.is_none()||self.outcome}}
impl CAdmit{pub(super) fn disposal_allowed(&self)->bool{self.wire.is_none()||self.outcome}}
impl HAdmit{pub(super) fn disposal_allowed(&self)->bool{self.wire.is_none()||self.outcome||!self.forwarded}}

impl CAdmit { pub(super) fn observe_active(&self,phase:u8)->Result<()> {
    if matches!(phase,ADMIT_REVIEW|ADMIT_ARMED|ADMIT_READY|ADMIT_ADMITTED) {
        self.review.as_ref().ok_or_else(||rejected("active Admit review missing"))?.check()?;
    } Ok(())
}}
#[cfg(test)] mod tests{
    use super::*;
    fn sample()->SignerAdmitPresentationV1{
        let h="a".repeat(64);let request="{\"public_test\":1}".to_string();
        let facts=SignerAdmitFactsV1{display:"Public test only".into(),source_identity_digest:h.clone(),admission_terms_digest:h.clone(),request_digest:SignerContinuePresentationV1::calculate_request_digest(&request),
            request_json:request,original_host_process_instance:h.clone(),owner_certificate_digest:h.clone(),disclosure_json:"{\"public\":1}".into(),disclosure_digest:h.clone(),account_id:h.clone(),network_profile_id:"test".into(),operation_id:"operation".into(),expected_head_sequence:1,expected_head_digest:h.clone(),terms_digest:h.clone(),reviewed_at_ms:1000,expires_at_ms:121000,source_expires_at_ms:300000};
        let mut p=SignerAdmitPresentationV1{version:1,purpose:ADMIT_PURPOSE.into(),actor:wire::sample_entry().presentation.actor,facts,owner_selection_digest:h.clone(),continue_presentation_digest:h.clone(),prepared_digest:h.clone(),admit_challenge:h,source_ceiling_ms:300000,admit_ceiling_ms:121000,presentation_digest:String::new()};
        p.presentation_digest=p.calculate_presentation_digest().unwrap();p.validate().unwrap();p
    }
    #[test]
    fn admit_receive_race_preserves_r_without_advancing_or_masking_wrong_phase(){
        let p=Phases::new();p.step(0,0,AWAITING_ADMISSION).unwrap();p.revoke();
        assert!(!received_admit_progress(&p,0,AWAITING_ADMISSION,ADMIT_REVIEW).unwrap());
        assert_eq!(p.phase(0),AWAITING_ADMISSION);assert!(p.revoked());
        assert!(received_admit_progress(&p,0,ADMIT_ARMED,ADMIT_READY).is_err());
        let p=Phases::new();p.step(1,0,ADMIT_ARMED).unwrap();p.revoke();
        assert!(!received_admit_progress(&p,1,ADMIT_ARMED,ADMIT_READY).unwrap());
        assert!(p.step(1,ADMIT_READY,ADMIT_ADMITTED).is_err());
        let p=Phases::new();p.step(0,0,ADMIT_ARMED).unwrap();
        assert!(received_admit_progress(&p,0,ADMIT_ARMED,ADMIT_READY).unwrap());
        assert!(received_admit_progress(&p,0,ADMIT_ARMED,ADMIT_READY).is_err());
    }
    #[test]
    fn admit_receive_quiescence_wins_even_when_global_r_is_also_set(){
        for from in [AWAITING_ADMISSION,ADMIT_ARMED]{
            let p=Phases::new();p.step(0,0,from).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
            let to=if from==AWAITING_ADMISSION{ADMIT_REVIEW}else{ADMIT_READY};
            assert!(received_admit_progress(&p,0,from,to).is_err());
            assert_eq!(p.phase(0),from);assert!(p.quiescent());assert!(p.revoked());
        }
    }
    #[test]
    fn restricted_admit_terminal_bookkeeping_does_not_manufacture_ready(){
        let p=sample();let digest="b".repeat(64);
        let none=SignerAdmitOutcomeV1::KnownNoEffect{presentation_digest:p.presentation_digest.clone(),admission_ready_digest:None};
        // Display was authenticated before local R, with no positive ticket.
        assert!(terminal_outcome_matches(&p,None,ADMIT_REVIEW,true,&none));
        let later=SignerAdmitOutcomeV1::Uncertain{presentation_digest:p.presentation_digest.clone(),admission_ready_digest:Some(digest.clone())};
        // H validated Ready after R and suppressed only that positive progress.
        assert!(terminal_outcome_matches(&p,None,ADMIT_ARMED,true,&later));
        assert!(!terminal_outcome_matches(&p,None,ADMIT_ARMED,false,&later));
        assert!(!terminal_outcome_matches(&p,None,ADMIT_REVIEW,true,&later));
        assert!(terminal_outcome_matches(&p,Some(&digest),ADMIT_READY,true,&later));
        assert!(!terminal_outcome_matches(&p,Some(&"c".repeat(64)),ADMIT_READY,true,&later));
        let state=Phases::new();state.step(0,0,ADMIT_READY).unwrap();state.revoke();assert!(state.step(0,ADMIT_READY,ADMIT_ADMITTED).is_err());
    }
    #[test]
    fn admit_completion_is_observation_only_and_preserves_restriction(){
        let p=Phases::new();p.step(0,0,ADMIT_ADMITTED).unwrap();p.revoke();p.observe_workflow_admit_saved(0).unwrap();
        assert_eq!(p.phase(0),AWAITING_NEXT_READ);assert!(p.revoked());assert!(p.observe_workflow_admit_saved(0).is_err());assert!(p.step(0,AWAITING_NEXT_READ,0).is_err());
        let p=Phases::new();p.step(1,0,ADMIT_READY).unwrap();assert!(p.observe_workflow_admit_saved(1).is_err());
    }
    #[test]
    fn admit_links_exact_saved_source_request_and_retained_owner_without_new_custody(){
        let entry=wire::sample_entry();let read=wire::sample_read(&entry);let c=crate::signer_continue_channel::sample_binding().presentation;
        let saved=SignerContinuationSavedV1{presentation_digest:c.presentation_digest.clone(),prepared_digest:c.prepared_digest.clone(),
            source_identity_digest:"b".repeat(64),admission_terms_digest:"c".repeat(64)};
        let mut p=sample();p.actor=read.actor.clone();p.owner_selection_digest=read.facts.owner_selection_digest.clone();
        p.source_ceiling_ms=read.source_ceiling_ms;p.continue_presentation_digest=c.presentation_digest.clone();p.prepared_digest=c.prepared_digest.clone();
        p.facts.source_identity_digest=saved.source_identity_digest.clone();p.facts.admission_terms_digest=saved.admission_terms_digest.clone();
        p.facts.request_json=c.request_json.clone();p.facts.request_digest=c.request_digest.clone();
        p.facts.original_host_process_instance=read.facts.original_host_process_instance.clone();p.facts.owner_certificate_digest=read.facts.owner_certificate_digest.clone();
        p.facts.disclosure_digest=read.facts.disclosure_digest.clone();p.facts.account_id=read.facts.account_id.clone();p.facts.terms_digest=read.facts.terms_digest.clone();p.facts.source_expires_at_ms=read.facts.source_expires_at_ms;
        assert!(link(&p,&read,&c,&saved));
        for n in 0..9{let mut q=p.clone();match n{0=>q.actor.signer_role=Target::Signer2,1=>q.owner_selection_digest="d".repeat(64),
            2=>q.facts.request_json.push(' '),3=>q.facts.source_identity_digest="d".repeat(64),4=>q.facts.admission_terms_digest="d".repeat(64),
            5=>q.facts.disclosure_digest="d".repeat(64),6=>q.facts.original_host_process_instance="d".repeat(64),7=>q.source_ceiling_ms+=1,_=>q.prepared_digest="d".repeat(64)}
            assert!(!link(&q,&read,&c,&saved));}
    }

}

impl SAdmit{pub(super) fn retained_result(&self)->Result<(&SignerAdmitPresentationV1,&SignerAdmitCommittedV1)>{
    if !self.outcome{return Err(rejected("Admit observation not completed"));}
    Ok((&self.review.as_ref().ok_or_else(||rejected("retained Admit presentation missing"))?.wire,
        self.committed.as_ref().ok_or_else(||rejected("retained Admit response missing"))?))
}}
impl CAdmit{pub(super) fn retained_result(&self)->Result<(&SignerAdmitPresentationV1,&SignerAdmitCommittedV1)>{
    if !self.outcome{return Err(rejected("Admit observation not completed"));}
    Ok((self.wire.as_ref().ok_or_else(||rejected("retained Admit presentation missing"))?,
        self.committed.as_ref().ok_or_else(||rejected("retained Admit response missing"))?))
}}
impl HAdmit{pub(super) fn retained_result(&self)->Result<(&SignerAdmitPresentationV1,&SignerAdmitCommittedV1)>{
    if !self.outcome{return Err(rejected("Admit observation not completed"));}
    Ok((self.wire.as_ref().ok_or_else(||rejected("retained Admit presentation missing"))?,
        self.committed.as_ref().ok_or_else(||rejected("retained Admit response missing"))?))
}}
