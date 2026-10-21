//! C-only original W custody/tickets. Whole pinned native image is trusted;
//! driver transports already-consumed native grants, never performs Arm or A.
use super::*;
use crate::financial_witness_channel::{self as fw,Packet as WP,Setup,FinancialWitnessInputsV1,
    FinancialWitnessContinuationV1,FinancialWitnessPresentationV1,FinancialWitnessReadyV1,FinancialWitnessOutcomeV1};
use std::sync::atomic::AtomicU64;
use crate::signer_continue_state::{ABANDONED,SENT};
pub(super) const W_SETUP_REVIEW:u8=1;pub(super) const W_SETUP_ADMITTED:u8=2;
pub(super) const W_REVIEW:u8=3;pub(super) const W_ARMED:u8=4;pub(super) const W_READY:u8=5;pub(super) const W_ADMITTED:u8=6;
struct SetupReview{entry:Arc<EntryReviewed>,wire:Setup,ceiling:Instant}
impl SetupReview{
    fn core(&self)->&Arc<Core>{&self.entry.core}
    fn slot(&self)->usize{self.entry.slot()}
    fn check(&self)->Result<()>{self.entry.check_custody()?;crate::channel::require_time(self.ceiling)?;self.core().check_action_restrictions()}
}
struct WReview{setup:Arc<SetupReview>,data:FinancialWitnessPresentationV1,instance:String,challenge:String,ceiling:Instant,last_wall:AtomicU64}
impl WReview{
    fn core(&self)->&Arc<Core>{self.setup.core()}
    fn slot(&self)->usize{self.setup.slot()}
    fn check(&self,admitted:bool)->Result<()>{self.setup.entry.check_custody()?;crate::channel::require_time(self.ceiling)?;
        let wall=state::wall_ms()?;let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<prior||wall<self.data.prepared_at_ms||wall>=self.data.expires_at_ms{return Err(rejected("financial Witness native review clock"));}
        if !admitted{self.core().check_action_restrictions()?;}Ok(())}
}
struct WReady{review:Arc<WReview>,data:FinancialWitnessReadyV1,challenge:String,ceiling:Instant}
impl WReady{fn check(&self,admitted:bool)->Result<()>{self.review.check(admitted)?;crate::channel::require_time(self.ceiling)?;
    let wall=state::wall_ms()?;if wall<self.data.accepted_at_ms||wall>=self.data.accepted_tls_expires_at_ms{return Err(rejected("financial Witness native accepted clock"));}Ok(())}}
/// Ordinary selected inputs are bound by the endpoint to the actual completed
/// Continue slot. The separate native Setup consumes this exact private ticket.
pub struct FinancialWitnessSetupTicketV1{binding:Arc<SetupReview>,consumed:bool}
impl FinancialWitnessSetupTicketV1{
    pub fn inputs(&self)->&FinancialWitnessInputsV1{&self.binding.wire.inputs}
    pub fn continuation(&self)->&FinancialWitnessContinuationV1{&self.binding.wire.continuation}
    pub fn native_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.check()?;
        if self.binding.core().phase.witness_phase(self.binding.slot())!=W_SETUP_REVIEW{return Err(rejected("financial Witness Setup ticket consumed"));}Ok(())}
}
impl Drop for FinancialWitnessSetupTicketV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
pub struct FinancialWitnessSetupOutboundV1{binding:Arc<SetupReview>,consumed:bool}
impl Drop for FinancialWitnessSetupOutboundV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
pub struct FinancialWitnessReviewTicketV1{binding:Arc<WReview>,consumed:bool}
impl FinancialWitnessReviewTicketV1{
    pub fn presentation(&self)->&FinancialWitnessPresentationV1{&self.binding.data}
    pub fn native_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.check(false)?;
        if self.binding.core().phase.witness_phase(self.binding.slot())!=W_REVIEW{return Err(rejected("financial Witness review consumed"));}Ok(())}
}
impl Drop for FinancialWitnessReviewTicketV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
pub struct FinancialWitnessArmOutboundV1{binding:Arc<WReview>,consumed:bool}
impl Drop for FinancialWitnessArmOutboundV1{fn drop(&mut self){if !self.consumed{self.binding.core().phase.revoke();}}}
/// Only actual original W Armed acknowledgement constructs this check-only
/// rendezvous. It is not a Signer grant and cannot be imported from a DTO.
pub struct FinancialWitnessArmedV1{binding:Arc<WReview>}
impl FinancialWitnessArmedV1{
    pub fn presentation(&self)->&FinancialWitnessPresentationV1{&self.binding.data}
    pub fn native_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.check(false)?;
        if self.binding.core().phase.witness_phase(self.binding.slot())!=W_ARMED{return Err(rejected("original financial Witness not Armed"));}Ok(())}
    pub(in crate::financial_workflow_origin) fn matches_admit(&self,core:&Arc<Core>,p:&crate::SignerAdmitPresentationV1)->Result<()>{
        self.check_current()?;let w=&self.binding.data;
        if !Arc::ptr_eq(core,self.binding.core())||!admit_witness_binding_matches(p,w)
        {return Err(rejected("Signer Admit and Armed original W do not match"));}Ok(())
    }
}
fn admit_witness_binding_matches(p:&crate::SignerAdmitPresentationV1,w:&FinancialWitnessPresentationV1)->bool{
    let f=&w.continuation;
    p.actor==f.actor&&p.continue_presentation_digest==f.continue_presentation_digest&&p.prepared_digest==f.prepared_digest
        &&p.facts.source_identity_digest==f.signer_source_identity_digest&&p.facts.admission_terms_digest==f.admission_terms_digest
        &&p.facts.request_json==f.request_json&&p.facts.request_digest==f.request_digest&&p.source_ceiling_ms==f.source_ceiling_ms
        &&p.facts.source_expires_at_ms==f.source_expires_at_ms&&p.facts.account_id==w.account_id&&p.facts.operation_id==w.operation_id
        &&p.facts.owner_certificate_digest==w.owner_certificate_digest&&p.facts.expected_head_sequence==w.expected_head_sequence
        &&p.facts.expected_head_digest==w.expected_head_digest
}
pub struct FinancialWitnessReadyTicketV1{binding:Arc<WReady>,consumed:bool}
impl FinancialWitnessReadyTicketV1{
    pub fn ready(&self)->&FinancialWitnessReadyV1{&self.binding.data}
    pub fn presentation(&self)->&FinancialWitnessPresentationV1{&self.binding.review.data}
    pub fn native_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.check(false)?;
        if self.binding.review.core().phase.witness_phase(self.binding.review.slot())!=W_READY{return Err(rejected("financial Witness Ready consumed"));}Ok(())}
}
impl Drop for FinancialWitnessReadyTicketV1{fn drop(&mut self){if !self.consumed{self.binding.review.core().phase.revoke();}}}
pub struct FinancialWitnessFinalOutboundV1{binding:Arc<WReady>,consumed:bool}
impl Drop for FinancialWitnessFinalOutboundV1{fn drop(&mut self){if !self.consumed{
    self.binding.review.core().witness_outbound[self.binding.review.slot()].store(ABANDONED,Ordering::Release);self.binding.review.core().phase.revoke();}}}
pub enum CoordinatorFinancialWitnessEventV1{
    Display(FinancialWitnessReviewTicketV1),Armed(FinancialWitnessArmedV1),Ready(FinancialWitnessReadyTicketV1),
    Outcome{role:Target,data:FinancialWitnessOutcomeV1},FirstFailure{role:Target,data:crate::DeliveryFailureV1},
    PreparationFailed(Target),Disposed(Target),PurposeClosed(Target),Restricted(Target),
}
#[derive(Default)]
pub(super) struct CWSlot{
    setup:Option<Arc<SetupReview>>,display:Option<FinancialWitnessPresentationV1>,identity:Option<(String,String)>,observed_ready:Option<FinancialWitnessReadyV1>,review:Option<Arc<WReview>>,ready:Option<Arc<WReady>>,wire_phase:u8,
    armed_ack:bool,outcome:bool,first_failure:bool,failed:bool,disposed:bool,cancel_sent:bool,close_sent:bool,closed:bool,cleanup:Option<Instant>,
}
impl CoordinatorFinancialNativeV1{
    /// Called only on the separate focused primary Setup gesture after complete
    /// exact protected-source/key/listener disclosure, never by a worker.
    pub fn admit_witness_setup(&self,mut ticket:FinancialWitnessSetupTicketV1)->Result<FinancialWitnessSetupOutboundV1>{
        if !Arc::ptr_eq(&self.core,ticket.binding.core()){self.revoke();return Err(rejected("foreign financial Witness Setup"));}
        ticket.check_current()?;self.core.phase.witness_step(ticket.binding.slot(),W_SETUP_REVIEW,W_SETUP_ADMITTED)?;
        ticket.consumed=true;Ok(FinancialWitnessSetupOutboundV1{binding:Arc::clone(&ticket.binding),consumed:false})
    }
    pub fn arm_witness(&self,mut ticket:FinancialWitnessReviewTicketV1)->Result<FinancialWitnessArmOutboundV1>{
        if !Arc::ptr_eq(&self.core,ticket.binding.core()){self.revoke();return Err(rejected("foreign financial Witness review"));}
        ticket.check_current()?;self.core.phase.witness_step(ticket.binding.slot(),W_REVIEW,W_ARMED)?;
        ticket.consumed=true;Ok(FinancialWitnessArmOutboundV1{binding:Arc::clone(&ticket.binding),consumed:false})
    }
    pub fn admit_witness(&self,mut ticket:FinancialWitnessReadyTicketV1)->Result<FinancialWitnessFinalOutboundV1>{
        let b=&ticket.binding.review;
        if !Arc::ptr_eq(&self.core,b.core()){self.revoke();return Err(rejected("foreign financial Witness Ready"));}
        ticket.check_current()?;self.core.phase.witness_step(b.slot(),W_READY,W_ADMITTED)?;
        ticket.consumed=true;Ok(FinancialWitnessFinalOutboundV1{binding:Arc::clone(&ticket.binding),consumed:false})
    }
}
impl CoordinatorFinancialEndpointV1{
    /// Binding and challenge work on the sole driver, not the native event tail.
    /// These ordinary paths do not open or inspect the selected role's source.
    pub fn prepare_witness_setup(&mut self,role:Target,inputs:FinancialWitnessInputsV1,original_native_ceiling:Instant)->Result<FinancialWitnessSetupTicketV1>{
        self.core.check_action_restrictions()?;inputs.validate()?;let i=role.index();
        let slot=self.slots[i].as_ref().ok_or_else(||rejected("financial Witness before original Signer"))?;
        if slot.wire_phase!=AWAITING_ADMISSION&&slot.wire_phase!=admit::ADMIT_REVIEW&&slot.wire_phase!=admit::ADMIT_ARMED&&slot.wire_phase!=admit::ADMIT_READY{return Err(rejected("financial Witness before saved continuation"));}
        let entry=slot.entry.as_ref().ok_or_else(||rejected("financial Witness Entry missing"))?;
        let read=slot.read.as_ref().ok_or_else(||rejected("financial Witness Read missing"))?;
        let c=slot.continuation.as_ref().ok_or_else(||rejected("financial Witness Continue missing"))?;
        let p=&c.wire.as_ref().ok_or_else(||rejected("financial Witness Continue display missing"))?.presentation;
        let saved=c.saved.as_ref().ok_or_else(||rejected("financial Witness saved source missing"))?;
        if self.witnesses[i].setup.is_some()||inputs.request_json!=p.request_json{return Err(rejected("financial Witness Setup reused or request changed"));}
        entry.check_custody()?;let now=Instant::now();let cap=original_native_ceiling.min(entry.original_source).min(self.core.session);
        if cap<=now||cap>now+std::time::Duration::from_secs(120){return Err(rejected("financial Witness original Setup ceiling"));}
        let flow=FinancialWitnessContinuationV1{actor:read.wire.actor.clone(),continue_presentation_digest:p.presentation_digest.clone(),prepared_digest:p.prepared_digest.clone(),
            signer_source_identity_digest:saved.source_identity_digest.clone(),admission_terms_digest:saved.admission_terms_digest.clone(),
            request_json:p.request_json.clone(),request_digest:p.request_digest.clone(),source_ceiling_ms:read.wire.source_ceiling_ms,source_expires_at_ms:read.wire.facts.source_expires_at_ms};
        let setup=Setup{continuation:flow,inputs,setup_challenge:state::nonce()?,setup_ceiling_ms:self.clocks.restrictive_offset(cap,entry.original_source)?};setup.validate()?;
        let b=Arc::new(SetupReview{entry:Arc::clone(entry),wire:setup,ceiling:cap});b.check()?;
        self.core.phase.witness_step(i,0,W_SETUP_REVIEW)?;self.witnesses[i].setup=Some(Arc::clone(&b));self.witnesses[i].wire_phase=W_SETUP_REVIEW;
        Ok(FinancialWitnessSetupTicketV1{binding:b,consumed:false})
    }
    fn send_witness(&self,role:Target,p:&WP)->Result<()>{self.transport_check()?;
        self.tree.as_ref().ok_or_else(||rejected("financial Witness tree consumed"))?.financial_witness(role)?.financial_witness_send(p)}
    pub fn send_witness_setup(&mut self,mut outbound:FinancialWitnessSetupOutboundV1)->Result<()>{
        let b=&outbound.binding;let i=b.slot();if !Arc::ptr_eq(&self.core,b.core()){return Err(rejected("foreign financial Witness Setup outbound"));}
        b.check()?;if self.witnesses[i].wire_phase!=W_SETUP_REVIEW||self.core.phase.witness_phase(i)!=W_SETUP_ADMITTED{return Err(rejected("financial Witness Setup send phase"));}
        self.witnesses[i].wire_phase=W_SETUP_ADMITTED;outbound.consumed=true;
        self.send_witness(b.wire.continuation.actor.signer_role,&WP::PrepareOnce{setup:b.wire.clone()})
    }
    pub fn send_witness_arm(&mut self,mut outbound:FinancialWitnessArmOutboundV1)->Result<()>{
        let b=&outbound.binding;let i=b.slot();if !Arc::ptr_eq(&self.core,b.core()){return Err(rejected("foreign financial Witness Arm outbound"));}
        b.check(false)?;if self.witnesses[i].wire_phase!=W_REVIEW||self.core.phase.witness_phase(i)!=W_ARMED{return Err(rejected("financial Witness Arm send phase"));}
        self.witnesses[i].wire_phase=W_ARMED;outbound.consumed=true;
        self.send_witness(b.data.continuation.actor.signer_role,&WP::Arm{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:b.instance.clone(),review_challenge:b.challenge.clone(),presentation_digest:b.data.presentation_digest.clone()})
    }
    pub fn send_witness_final(&mut self,mut outbound:FinancialWitnessFinalOutboundV1)->Result<()>{
        let r=&outbound.binding;let b=&r.review;let i=b.slot();
        if !Arc::ptr_eq(&self.core,b.core()){return Err(rejected("foreign financial Witness Final outbound"));}
        r.check(true)?;if self.witnesses[i].cancel_sent||self.witnesses[i].wire_phase!=W_READY||self.core.phase.witness_phase(i)!=W_ADMITTED{return Err(rejected("financial Witness Final send phase"));}
        // Consume before one nonblocking attempt. An error may be uncertain.
        self.core.witness_outbound[i].compare_exchange(PENDING,SENT,Ordering::AcqRel,Ordering::Acquire).map_err(|_|rejected("financial Witness Final already transported"))?;
        self.witnesses[i].wire_phase=W_ADMITTED;outbound.consumed=true;
        self.send_witness(b.data.continuation.actor.signer_role,&WP::FinalAdmit{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:b.instance.clone(),review_challenge:b.challenge.clone(),ready_challenge:r.challenge.clone(),effect_commitment:r.data.effect_commitment.clone()})
    }
    pub fn try_receive_witness(&mut self)->Result<Option<CoordinatorFinancialWitnessEventV1>>{
        let result=self.receive_witness_inner();if result.is_err(){self.core.close();}result
    }
    fn receive_witness_inner(&mut self)->Result<Option<CoordinatorFinancialWitnessEventV1>>{
        self.transport_check()?;
        for role in [Target::Signer1,Target::Signer2]{let i=role.index();if self.witnesses[i].closed{continue;}
            let Some(p)=self.tree.as_ref().ok_or_else(||rejected("financial Witness tree consumed"))?.financial_witness(role)?.financial_witness_receive()? else{continue};
            let slot=&mut self.witnesses[i];
            if let Some(deadline)=slot.cleanup { crate::channel::require_time(deadline)?; }
            let event=match p{
                WP::Display{setup_challenge,witness_instance,review_challenge,review_ceiling_ms,data}=>{
                    data.validate()?;let setup=slot.setup.as_ref().ok_or_else(||rejected("financial Witness unsolicited Display"))?;
                    if slot.wire_phase!=W_SETUP_ADMITTED||slot.review.is_some()||setup_challenge!=setup.wire.setup_challenge||data.continuation!=setup.wire.continuation
                        ||!state::hash(&witness_instance)||!state::hash(&review_challenge){return Err(rejected("financial Witness Display binding"));}
                    slot.wire_phase=W_REVIEW;slot.display=Some(data.clone());slot.identity=Some((witness_instance.clone(),review_challenge.clone()));
                    if self.core.phase.revoked(){return Ok(Some(CoordinatorFinancialWitnessEventV1::Restricted(role)));}
                    let now=Instant::now();let wall=state::wall_ms()?;
                    let ceiling=self.clocks.restrict_received(PROFILE,review_ceiling_ms,setup.entry.original_source,now)?.min(wall_ceiling(now,wall,data.prepared_at_ms,data.expires_at_ms)?);
                    let b=Arc::new(WReview{setup:Arc::clone(setup),data,instance:witness_instance,challenge:review_challenge,ceiling,last_wall:AtomicU64::new(wall)});slot.review=Some(Arc::clone(&b));
                    b.check(true)?;
                    if !received_witness_progress(&self.core.phase,i,W_SETUP_ADMITTED,W_REVIEW)?{CoordinatorFinancialWitnessEventV1::Restricted(role)}else{
                        CoordinatorFinancialWitnessEventV1::Display(FinancialWitnessReviewTicketV1{binding:b,consumed:false})}
                }
                WP::Armed{setup_challenge,witness_instance,presentation_digest}=>{
                    let b=slot.review.as_ref().ok_or_else(||rejected("financial Witness Armed before Display"))?;
                    if slot.wire_phase!=W_ARMED||slot.armed_ack||setup_challenge!=b.setup.wire.setup_challenge||witness_instance!=b.instance||presentation_digest!=b.data.presentation_digest{return Err(rejected("financial Witness Armed binding"));}
                    slot.armed_ack=true;if self.core.phase.revoked(){CoordinatorFinancialWitnessEventV1::Restricted(role)}else{
                        b.check(true)?;
                        if self.core.phase.witness_phase(i)!=W_ARMED{return Err(rejected("financial Witness Armed native phase"));}
                        if self.core.phase.revoked(){CoordinatorFinancialWitnessEventV1::Restricted(role)}else{CoordinatorFinancialWitnessEventV1::Armed(FinancialWitnessArmedV1{binding:Arc::clone(b)})}}
                }
                WP::Ready{setup_challenge,witness_instance,review_challenge,ready_challenge,accepted_ceiling_ms,data}=>{
                    let b=slot.review.as_ref().ok_or_else(||rejected("financial Witness Ready before Display"))?;
                    if slot.wire_phase!=W_ARMED||!slot.armed_ack||slot.ready.is_some()||setup_challenge!=b.setup.wire.setup_challenge||witness_instance!=b.instance||review_challenge!=b.challenge||!state::hash(&ready_challenge)||!data.matches(&b.data){return Err(rejected("financial Witness Ready binding"));}
                    slot.observed_ready=Some(data.clone());slot.wire_phase=W_READY;
                    if self.core.phase.revoked(){return Ok(Some(CoordinatorFinancialWitnessEventV1::Restricted(role)));}
                    let now=Instant::now();let wall=state::wall_ms()?;
                    let ceiling=self.clocks.restrict_received(PROFILE,accepted_ceiling_ms,b.ceiling,now)?.min(wall_ceiling(now,wall,data.accepted_at_ms,data.accepted_tls_expires_at_ms)?);
                    let r=Arc::new(WReady{review:Arc::clone(b),data,challenge:ready_challenge,ceiling});slot.ready=Some(Arc::clone(&r));slot.wire_phase=W_READY;
                    r.check(true)?;
                    if !received_witness_progress(&self.core.phase,i,W_ARMED,W_READY)?{CoordinatorFinancialWitnessEventV1::Restricted(role)}else{
                        CoordinatorFinancialWitnessEventV1::Ready(FinancialWitnessReadyTicketV1{binding:r,consumed:false})}
                }
                WP::Outcome{setup_challenge,witness_instance,data}=>{
                    let p=slot.display.as_ref().ok_or_else(||rejected("financial Witness outcome before Display"))?;
                    if slot.outcome||slot.setup.as_ref().is_none_or(|b|setup_challenge!=b.wire.setup_challenge)
                        ||slot.identity.as_ref().is_none_or(|b|witness_instance!=b.0)||!data.matches(p,slot.observed_ready.as_ref())
                        ||matches!(data,FinancialWitnessOutcomeV1::Committed{..})&&slot.wire_phase!=W_ADMITTED{return Err(rejected("financial Witness outcome binding"));}
                    slot.outcome=true;CoordinatorFinancialWitnessEventV1::Outcome{role,data}
                }
                WP::FirstFailure{setup_challenge,data}=>{
                    if slot.first_failure||slot.outcome||slot.disposed||slot.setup.as_ref().is_none_or(|b|b.wire.setup_challenge!=setup_challenge){return Err(rejected("financial Witness first failure binding"));}
                    slot.first_failure=true;CoordinatorFinancialWitnessEventV1::FirstFailure{role,data}
                }
                WP::PreparationFailed{setup_challenge}=>{
                    if slot.failed||slot.display.is_some()||slot.disposed||slot.setup.as_ref().is_none_or(|b|b.wire.setup_challenge!=setup_challenge){return Err(rejected("financial Witness preparation failure binding"));}
                    slot.failed=true;CoordinatorFinancialWitnessEventV1::PreparationFailed(role)
                }
                WP::Disposed{coordinator,session}=>{
                    if slot.disposed||coordinator!=self.coordinator||session!=self.session||slot.display.is_some()&&!slot.outcome
                        ||slot.display.is_none()&&!slot.failed&&!slot.cancel_sent{return Err(rejected("financial Witness disposal binding"));}
                    slot.disposed=true;CoordinatorFinancialWitnessEventV1::Disposed(role)
                }
                WP::PurposeClosed{coordinator,session}=>{
                    if !slot.disposed||!slot.close_sent||slot.closed||coordinator!=self.coordinator||session!=self.session{return Err(rejected("financial Witness close binding"));}
                    slot.closed=true;CoordinatorFinancialWitnessEventV1::PurposeClosed(role)
                }
                _=>return Err(rejected("unexpected financial Witness response")),
            };return Ok(Some(event));
        }Ok(None)
    }
    /// Grammar close only. This is NOT retirement, normal reap, namespace
    /// absence or permission to relax any original root's live-pidfd check.
    pub fn close_witness_purpose(&mut self,role:Target)->Result<()>{
        let slot=&mut self.witnesses[role.index()];
        if !slot.disposed||slot.close_sent{return Err(rejected("financial Witness close before actual disposal"));}
        slot.cleanup=Some(self.clocks.first_cleanup_ceiling(Instant::now())?);
        slot.close_sent=true;self.send_witness(role,&WP::ClosePurpose{coordinator:self.coordinator.clone(),session:self.session.clone()})
    }
    pub(super) fn cancel_witnesses(&mut self)->Result<()>{
        for role in [Target::Signer1,Target::Signer2]{let i=role.index();if self.witnesses[i].closed||self.witnesses[i].cancel_sent{continue;}
            if self.core.phase.witness_phase(i)==W_ADMITTED&&self.core.witness_outbound[i].load(Ordering::Acquire)==PENDING{return Err(rejected("admitted financial Witness Final precedes Cancel"));}
            self.witnesses[i].cancel_sent=true;
            self.send_witness(role,&WP::Cancel{coordinator:self.coordinator.clone(),session:self.session.clone()})?;
        }Ok(())
    }
}
// Receive only: an ordinary R race suppresses positive progress without
// destroying custody of a different already-admitted effect. Never mask an
// unexpected phase or failed immutable/actor/clock validation with R.
fn received_witness_progress(phase:&Phases,slot:usize,from:u8,to:u8)->Result<bool>{
    match phase.witness_step(slot,from,to){
        Ok(())=>Ok(!phase.revoked()),
        Err(_) if phase.revoked()&&phase.witness_phase(slot)==from=>Ok(false),
        Err(error)=>Err(error),
    }
}
pub(super) fn witness_pending(core:&Core)->bool{(0..2).any(|i|witness_pending_phase(core.phase.witness_phase(i),core.witness_outbound[i].load(Ordering::Acquire)))}
fn witness_pending_phase(phase:u8,status:u8)->bool{phase==W_ADMITTED&&status==PENDING}

impl CWSlot {
    pub(super) fn closed(&self)->bool { self.closed }
    pub(super) fn observe_active(&self,core:&Core,i:usize)->Result<()> {
        match core.phase.witness_phase(i) {
            W_SETUP_REVIEW|W_SETUP_ADMITTED=>self.setup.as_ref().ok_or_else(||rejected("active W Setup missing"))?.check(),
            W_REVIEW|W_ARMED=>self.review.as_ref().ok_or_else(||rejected("active W review missing"))?.check(false),
            W_READY=>self.ready.as_ref().ok_or_else(||rejected("active W Ready missing"))?.check(false),
            W_ADMITTED if !self.outcome=>self.ready.as_ref().ok_or_else(||rejected("admitted W binding missing"))?.check(true),
            _=>Ok(()),
        }
    }
}
#[cfg(test)] mod tests{
    use super::*;
    #[test]
    fn witness_receive_race_is_restrictive_without_masking_wrong_phase(){
        let p=Phases::new();p.witness_step(0,0,W_SETUP_ADMITTED).unwrap();p.revoke();
        assert!(!received_witness_progress(&p,0,W_SETUP_ADMITTED,W_REVIEW).unwrap());
        assert_eq!(p.witness_phase(0),W_SETUP_ADMITTED);assert!(p.revoked());
        assert!(received_witness_progress(&p,0,W_ARMED,W_READY).is_err());
        let p=Phases::new();p.witness_step(1,0,W_ARMED).unwrap();p.revoke();
        assert!(!received_witness_progress(&p,1,W_ARMED,W_READY).unwrap());
        assert!(p.witness_step(1,W_READY,W_ADMITTED).is_err());
        let p=Phases::new();p.witness_step(0,0,W_ARMED).unwrap();
        assert!(received_witness_progress(&p,0,W_ARMED,W_READY).unwrap());
        assert!(received_witness_progress(&p,0,W_ARMED,W_READY).is_err());
    }
    #[test]
    fn both_witness_final_slots_share_signer_global_admission_restriction_order(){
        let p=Phases::new();p.step(0,0,CONT_READY).unwrap();p.witness_step(0,0,W_READY).unwrap();p.witness_step(1,0,W_READY).unwrap();
        p.witness_step(0,W_READY,W_ADMITTED).unwrap();p.revoke();
        assert!(p.step(0,CONT_READY,CONT_ADMITTED).is_err());assert!(p.witness_step(1,W_READY,W_ADMITTED).is_err());
        assert_eq!(p.witness_phase(0),W_ADMITTED);assert!(p.witness_step(0,W_ADMITTED,0).is_err());
        assert!(witness_pending_phase(W_ADMITTED,PENDING));assert!(!witness_pending_phase(W_ADMITTED,SENT));
        assert!(!witness_pending_phase(W_ADMITTED,ABANDONED));assert!(!witness_pending_phase(W_READY,PENDING));
    }
}
