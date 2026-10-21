//! Actual fixed C->W financial-continuation custody. No imported role, packet,
//! key, descriptor, review DTO or public constructor can create these grants.
use crate::{bootstrap::{self,LeafCustody},channel::require_time,rejected,Result,
    financial_workflow_clock::{FullWorkflowClocksV1,PROFILE},financial_workflow_source::wall_ceiling,
    financial_witness_channel::{self as wire,Packet,Setup,FinancialWitnessInputsV1,FinancialWitnessContinuationV1,
        FinancialWitnessPresentationV1,FinancialWitnessReadyV1,FinancialWitnessOutcomeV1},
    host_restriction::WitnessSharedRestrictionV1,signer_continue_state::{self as state,CheckedPeer},DeliveryFailureV1};
use std::{sync::{Arc,atomic::{AtomicBool,AtomicU8,AtomicU64,Ordering}},time::Instant};
const SETUP:u8=1;const REVIEW:u8=2;const ARMED:u8=3;const READY:u8=4;const ADMITTED:u8=5;
struct WitnessCore {
    peer:CheckedPeer,restriction:WitnessSharedRestrictionV1,clocks:FullWorkflowClocksV1,
    pid:libc::pid_t,uid:libc::uid_t,alive:AtomicBool,revoked:AtomicBool,phase:AtomicU8,
}
impl WitnessCore {
    fn actors(&self)->Result<()>{
        if !self.alive.load(Ordering::Acquire)||unsafe{libc::getpid()}!=self.pid||unsafe{libc::geteuid()}!=self.uid{
            return Err(rejected("financial Witness original actor lost"));}self.peer.check()
    }
    fn action(&self)->Result<()>{self.actors()?;require_time(self.clocks.supervision())?;
        if self.revoked.load(Ordering::Acquire){return Err(rejected("financial Witness restricted"));}
        self.restriction.check_current()
    }
    fn revoke(&self){self.revoked.store(true,Ordering::Release);}
    fn close(&self){self.revoke();self.alive.store(false,Ordering::Release);self.peer.shutdown();}
    fn step(&self,from:u8,to:u8)->Result<()>{
        self.phase.compare_exchange(from,to,Ordering::AcqRel,Ordering::Acquire)
            .map(|_|()).map_err(|_|rejected("financial Witness phase consumed"))
    }
}
struct SetupBinding {core:Arc<WitnessCore>,wire:Setup,ceiling:Instant,source:Instant,last_wall:AtomicU64}
impl SetupBinding {
    fn current(&self)->Result<()>{self.core.action()?;require_time(self.ceiling)?;require_time(self.source)?;
        let wall=state::wall_ms()?;let old=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<old||wall>=self.wire.continuation.source_expires_at_ms{return Err(rejected("financial Witness setup source clock"));}Ok(())}
}
struct ReviewBinding {setup:Arc<SetupBinding>,presentation:FinancialWitnessPresentationV1,challenge:String,
    original_review:Instant,ceiling:Instant,last_wall:AtomicU64}
impl ReviewBinding {
    fn check(&self,admitted:bool)->Result<()>{
        self.setup.core.actors()?;require_time(self.setup.core.clocks.supervision())?;
        require_time(self.setup.source)?;require_time(self.original_review)?;require_time(self.ceiling)?;
        let wall=state::wall_ms()?;let old=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<old||wall<self.presentation.prepared_at_ms||wall>=self.presentation.expires_at_ms
            ||wall>=self.setup.wire.continuation.source_expires_at_ms{return Err(rejected("financial Witness review clock"));}
        if !admitted{self.setup.core.action()?;}Ok(())
    }
}
struct ReadyBinding {review:Arc<ReviewBinding>,data:FinancialWitnessReadyV1,challenge:String,
    original_accepted:Instant,ceiling:Instant}
impl ReadyBinding {
    fn check(&self,admitted:bool)->Result<()>{self.review.check(admitted)?;
        require_time(self.original_accepted)?;require_time(self.ceiling)?;
        let wall=state::wall_ms()?;
        if wall<self.data.accepted_at_ms||wall>=self.data.accepted_tls_expires_at_ms{return Err(rejected("financial Witness original accepted clock"));}Ok(())}
}
/// Genuine native Setup receive only, authorizing just the disclosed maintained
/// source/TLS/listener preparation. It is NOT Arm or append permission.
pub struct WitnessFinancialContinuationSetupV1 {binding:Arc<SetupBinding>}
impl WitnessFinancialContinuationSetupV1 {
    pub fn check_current(&self)->Result<()>{self.binding.current()?;
        if self.binding.core.phase.load(Ordering::Acquire)!=SETUP{return Err(rejected("financial Witness Setup no longer current"));}Ok(())}
    pub fn check_original_coordinator_alive(&self)->Result<()>{self.binding.core.actors()}
    pub fn inputs(&self)->&FinancialWitnessInputsV1{&self.binding.wire.inputs}
    pub fn continuation(&self)->&FinancialWitnessContinuationV1{&self.binding.wire.continuation}
    pub fn original_setup_deadline(&self)->Instant{self.binding.ceiling}
    pub fn setup_challenge(&self)->&str{&self.binding.wire.setup_challenge}
}
pub struct WitnessFinancialContinuationArmV1 {binding:Arc<ReviewBinding>}
impl WitnessFinancialContinuationArmV1 {
    pub fn presentation_digest(&self)->&str{&self.binding.presentation.presentation_digest}
    pub fn original_review_deadline(&self)->Instant{self.binding.original_review}
    /// Already-retained source/review/supervision minimum, never a new budget.
    pub fn effective_io_deadline(&self)->Instant{self.binding.ceiling}
    pub fn check_original_coordinator_alive(&self)->Result<()>{self.binding.setup.core.actors()}
    pub fn check_current(&self)->Result<()>{self.binding.check(false)?;
        if !matches!(self.binding.setup.core.phase.load(Ordering::Acquire),ARMED|READY){return Err(rejected("financial Witness Arm consumed"));}Ok(())}
}
/// Only the matching authenticated original C Final receive constructs this.
/// A later ordinary R does not recall this one local append. Actor/channel,
/// source, record, review and accepted TLS bounds never receive an exception.
pub struct WitnessFinancialContinuationFinalV1 {binding:Arc<ReadyBinding>}
impl WitnessFinancialContinuationFinalV1 {
    pub fn effect_commitment(&self)->&str{&self.binding.data.effect_commitment}
    pub fn presentation_digest(&self)->&str{&self.binding.review.presentation.presentation_digest}
    pub fn original_review_deadline(&self)->Instant{self.binding.review.original_review}
    pub fn original_accepted_deadline(&self)->Instant{self.binding.original_accepted}
    pub fn check_original_coordinator_alive(&self)->Result<()>{self.binding.review.setup.core.actors()}
    pub fn check_current(&self)->Result<()>{self.binding.check(true)?;
        if self.binding.review.setup.core.phase.load(Ordering::Acquire)!=ADMITTED{return Err(rejected("financial Witness Final not admitted"));}Ok(())}
}
pub enum FinancialWitnessRequestV1 {
    PrepareOnce(WitnessFinancialContinuationSetupV1),Arm(WitnessFinancialContinuationArmV1),
    FinalAdmit(WitnessFinancialContinuationFinalV1),Cancel,ClosePurpose,
}
pub struct WitnessFinancialContinuationOriginV1 {
    core:Arc<WitnessCore>,leaf:Option<LeafCustody>,instance:String,setup:Option<Arc<SetupBinding>>,
    review:Option<Arc<ReviewBinding>>,ready:Option<Arc<ReadyBinding>>,ready_consumed:bool,
    coordinator:Option<(String,String)>,armed_ack:bool,cancel_seen:bool,failed:bool,
    first_failure:bool,outcome:bool,disposed:bool,close_seen:bool,closed:bool,cleanup:Option<Instant>,
}
impl WitnessFinancialContinuationOriginV1 {
    pub(super) fn from_leaf(leaf:LeafCustody,restriction:WitnessSharedRestrictionV1)->Result<Self>{
        if !wire::is_financial_witness(leaf.origin.role()){return Err(rejected("not fixed financial Witness custody"));}
        let core=Arc::new(WitnessCore{peer:leaf.origin.continue_observer()?,restriction,clocks:leaf.clocks.workflow(),
            pid:unsafe{libc::getpid()},uid:unsafe{libc::geteuid()},alive:AtomicBool::new(true),revoked:AtomicBool::new(false),phase:AtomicU8::new(0)});
        core.action()?;let instance=state::nonce()?;
        Ok(Self{core,leaf:Some(leaf),instance,setup:None,review:None,ready:None,ready_consumed:false,coordinator:None,
            armed_ack:false,cancel_seen:false,failed:false,first_failure:false,outcome:false,disposed:false,close_seen:false,closed:false,cleanup:None})
    }
    pub fn session_deadline(&self)->Instant{self.core.clocks.supervision()}
    pub fn check_original_coordinator_alive(&self)->Result<()>{self.core.actors()}
    fn transport(&self)->Result<()>{self.core.actors()?;require_time(self.cleanup.unwrap_or(self.core.clocks.hard_cleanup()))}
    fn send(&self,p:&Packet)->Result<()>{self.transport()?;
        self.leaf.as_ref().ok_or_else(||rejected("financial Witness custody consumed"))?.origin.financial_witness_send(p)}
    fn identity(&self,c:&str,s:&str)->bool{self.coordinator.as_ref().is_some_and(|(a,b)|a==c&&b==s)}
    pub fn retain_cleanup_deadline(&mut self, original:Instant)->Result<Instant>{
        let retained=self.core.clocks.retain_cleanup(self.cleanup,original,Instant::now())?;
        self.cleanup=Some(retained);Ok(retained)
    }
    /// Reads only the already established cutoff, even after actor/channel loss.
    pub fn original_cleanup_deadline(&self)->Result<Instant>{
        self.cleanup.ok_or_else(||rejected("financial Witness cleanup not started"))
    }
    fn first_cleanup(&mut self)->Result<()>{
        self.retain_cleanup_deadline(self.core.clocks.hard_cleanup())?;Ok(())
    }
    pub fn try_receive(&mut self)->Result<Option<FinancialWitnessRequestV1>>{
        let result=self.receive_inner();if result.is_err(){self.core.close();}result
    }
    fn receive_inner(&mut self)->Result<Option<FinancialWitnessRequestV1>>{
        self.transport()?;
        let Some(p)=self.leaf.as_ref().ok_or_else(||rejected("financial Witness custody consumed"))?.origin.financial_witness_receive()? else{return Ok(None)};
        let request=match p {
            Packet::PrepareOnce{setup}=>{
                if self.setup.is_some()||self.cancel_seen||self.disposed{return Err(rejected("financial Witness Setup reused"));}
                // The actual receive consumes this phase BEFORE fallible validation.
                self.core.step(0,SETUP)?;setup.validate()?;self.core.action()?;
                if wire::role_for(setup.continuation.actor.signer_role)!=self.leaf.as_ref().unwrap().origin.role(){return Err(rejected("financial Witness wrong owner slot"));}
                let now=Instant::now();let wall=state::wall_ms()?;
                let source=self.core.clocks.restrict_received(PROFILE,setup.continuation.source_ceiling_ms,self.core.clocks.supervision(),now)?;
                let ceiling=self.core.clocks.restrict_received(PROFILE,setup.setup_ceiling_ms,source,now)?;
                if ceiling.duration_since(now)>std::time::Duration::from_secs(120){return Err(rejected("financial Witness Setup ceiling too wide"));}
                self.coordinator=Some((setup.continuation.actor.coordinator_process_instance.clone(),setup.continuation.actor.session_challenge.clone()));
                let b=Arc::new(SetupBinding{core:Arc::clone(&self.core),wire:setup,ceiling,source,last_wall:AtomicU64::new(wall)});
                b.current()?;self.setup=Some(Arc::clone(&b));FinancialWitnessRequestV1::PrepareOnce(WitnessFinancialContinuationSetupV1{binding:b})
            }
            Packet::Arm{setup_challenge,witness_instance,review_challenge,presentation_digest}=>{
                if self.cancel_seen||self.failed||self.outcome||self.disposed{return Err(rejected("financial Witness Arm after terminal"));}
                let b=self.review.as_ref().ok_or_else(||rejected("financial Witness Arm without review"))?;
                if setup_challenge!=b.setup.wire.setup_challenge||witness_instance!=self.instance||review_challenge!=b.challenge||presentation_digest!=b.presentation.presentation_digest{return Err(rejected("financial Witness Arm mismatch"));}
                b.check(false)?;self.core.step(REVIEW,ARMED)?;FinancialWitnessRequestV1::Arm(WitnessFinancialContinuationArmV1{binding:Arc::clone(b)})
            }
            Packet::FinalAdmit{setup_challenge,witness_instance,review_challenge,ready_challenge,effect_commitment}=>{
                if self.ready_consumed||self.cancel_seen||self.failed||self.outcome||self.disposed{return Err(rejected("financial Witness Final reused or terminal"));}
                self.ready_consumed=true;
                let b=self.ready.as_ref().ok_or_else(||rejected("financial Witness Final without Ready"))?;
                if setup_challenge!=b.review.setup.wire.setup_challenge||witness_instance!=self.instance||review_challenge!=b.review.challenge
                    ||ready_challenge!=b.challenge||effect_commitment!=b.data.effect_commitment{return Err(rejected("financial Witness Final mismatch"));}
                // ONLY this matching ordered receive observes C's previous A.
                // A shared R may already be visible, but ordered Cancel may not.
                b.check(true)?;self.core.step(READY,ADMITTED)?;
                FinancialWitnessRequestV1::FinalAdmit(WitnessFinancialContinuationFinalV1{binding:Arc::clone(b)})
            }
            Packet::Cancel{coordinator,session}=>{
                if self.cancel_seen||self.closed||!state::hash(&coordinator)||!state::hash(&session){return Err(rejected("financial Witness Cancel repeated"));}
                if self.coordinator.is_none(){self.coordinator=Some((coordinator.clone(),session.clone()));}
                if !self.identity(&coordinator,&session){return Err(rejected("financial Witness Cancel identity"));}
                self.core.revoke();self.cancel_seen=true;self.first_cleanup()?;FinancialWitnessRequestV1::Cancel
            }
            Packet::ClosePurpose{coordinator,session}=>{
                if !self.identity(&coordinator,&session)||!self.disposed||self.close_seen{return Err(rejected("financial Witness close before disposal"));}
                self.first_cleanup()?;self.close_seen=true;FinancialWitnessRequestV1::ClosePurpose
            }
            _=>return Err(rejected("unexpected financial Witness command")),
        };Ok(Some(request))
    }
    pub fn send_display(&mut self,data:FinancialWitnessPresentationV1,original_review:Instant)->Result<()>{
        if self.review.is_some()||self.failed||self.cancel_seen||self.disposed{return Err(rejected("financial Witness Display repeated"));}
        let setup=self.setup.as_ref().ok_or_else(||rejected("financial Witness Display without Setup"))?;setup.current()?;data.validate()?;
        if data.continuation!=setup.wire.continuation{return Err(rejected("financial Witness changed original continuation"));}
        let now=Instant::now();let wall=state::wall_ms()?;
        if original_review<=now||original_review.duration_since(now)>std::time::Duration::from_secs(120){return Err(rejected("financial Witness review original ceiling"));}
        let review_ceiling_ms=self.core.clocks.restrictive_offset(original_review,setup.source)?;
        let ceiling=self.core.clocks.restrict_received(PROFILE,review_ceiling_ms,original_review,now)?.min(wall_ceiling(now,wall,data.prepared_at_ms,data.expires_at_ms)?);
        let b=Arc::new(ReviewBinding{setup:Arc::clone(setup),presentation:data.clone(),challenge:state::nonce()?,original_review,ceiling,last_wall:AtomicU64::new(wall)});
        b.check(false)?;self.core.step(SETUP,REVIEW)?;self.review=Some(Arc::clone(&b));
        self.send(&Packet::Display{setup_challenge:setup.wire.setup_challenge.clone(),witness_instance:self.instance.clone(),review_challenge:b.challenge.clone(),review_ceiling_ms,data})
    }
    pub fn acknowledge_armed(&mut self)->Result<()>{
        if self.armed_ack||self.core.phase.load(Ordering::Acquire)!=ARMED{return Err(rejected("financial Witness Armed acknowledgement repeated"));}
        let b=self.review.as_ref().ok_or_else(||rejected("financial Witness review missing"))?;b.check(false)?;self.armed_ack=true;
        self.send(&Packet::Armed{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:self.instance.clone(),presentation_digest:b.presentation.presentation_digest.clone()})
    }
    pub fn send_ready(&mut self,data:FinancialWitnessReadyV1,original_accepted:Instant)->Result<()>{
        if !self.armed_ack||self.ready.is_some()||self.failed||self.outcome||self.disposed{return Err(rejected("financial Witness Ready repeated"));}
        let review=self.review.as_ref().ok_or_else(||rejected("financial Witness Ready before review"))?;review.check(false)?;
        if !data.matches(&review.presentation){return Err(rejected("financial Witness Ready facts mismatch"));}
        let now=Instant::now();let wall=state::wall_ms()?;
        if original_accepted<=now||original_accepted.duration_since(now)>std::time::Duration::from_secs(10){return Err(rejected("financial Witness accepted ceiling"));}
        let accepted_ceiling_ms=self.core.clocks.restrictive_offset(original_accepted,review.ceiling)?;
        let ceiling=self.core.clocks.restrict_received(PROFILE,accepted_ceiling_ms,original_accepted,now)?
            .min(wall_ceiling(now,wall,data.accepted_at_ms,data.accepted_tls_expires_at_ms)?);
        let b=Arc::new(ReadyBinding{review:Arc::clone(review),data:data.clone(),challenge:state::nonce()?,original_accepted,ceiling});
        b.check(false)?;self.core.step(ARMED,READY)?;self.ready=Some(Arc::clone(&b));
        self.send(&Packet::Ready{setup_challenge:review.setup.wire.setup_challenge.clone(),witness_instance:self.instance.clone(),review_challenge:review.challenge.clone(),ready_challenge:b.challenge.clone(),accepted_ceiling_ms,data})
    }
    pub fn send_first_failure(&mut self,data:DeliveryFailureV1)->Result<()>{
        if self.first_failure||self.outcome||self.disposed{return Err(rejected("financial Witness first failure repeated"));}
        self.first_failure=true;let setup=self.setup.as_ref().ok_or_else(||rejected("financial Witness failure before Setup"))?;
        self.send(&Packet::FirstFailure{setup_challenge:setup.wire.setup_challenge.clone(),data})
    }
    pub fn send_preparation_failed(&mut self)->Result<()>{
        if self.failed||self.review.is_some()||self.disposed{return Err(rejected("financial Witness preparation failure phase"));}
        self.failed=true;let setup=self.setup.as_ref().ok_or_else(||rejected("financial Witness failure before Setup"))?;
        self.send(&Packet::PreparationFailed{setup_challenge:setup.wire.setup_challenge.clone()})
    }
    pub fn send_outcome(&mut self,data:FinancialWitnessOutcomeV1)->Result<()>{
        if self.outcome||self.disposed{return Err(rejected("financial Witness outcome repeated"));}
        let review=self.review.as_ref().ok_or_else(||rejected("financial Witness outcome before Display"))?;
        if !data.matches(&review.presentation,self.ready.as_ref().map(|r|&r.data))
            ||matches!(data,FinancialWitnessOutcomeV1::Committed{..})&&self.core.phase.load(Ordering::Acquire)!=ADMITTED{return Err(rejected("financial Witness outcome mismatch"));}
        self.outcome=true;self.send(&Packet::Outcome{setup_challenge:review.setup.wire.setup_challenge.clone(),witness_instance:self.instance.clone(),data})
    }
    /// Caller must already have joined the actual worker and dropped proposal,
    /// namespace, TLS and listener custody. This observation itself proves none.
    pub fn send_disposed(&mut self)->Result<()>{
        if self.disposed||self.review.is_some()&&!self.outcome||self.review.is_none()&&!self.failed&&!self.cancel_seen{return Err(rejected("financial Witness disposal phase"));}
        self.first_cleanup()?;
        let cleanup_ceiling_ms=self.core.clocks.cleanup_offset(self.original_cleanup_deadline()?)?;
        let(c,s)=self.coordinator.as_ref().ok_or_else(||rejected("financial Witness disposal identity"))?;
        self.send(&Packet::Disposed{coordinator:c.clone(),session:s.clone(),cleanup_ceiling_ms})?;self.disposed=true;Ok(())
    }
    pub fn send_purpose_closed(&mut self)->Result<()>{
        if !self.close_seen||self.closed||!self.disposed{return Err(rejected("financial Witness grammar not closed"));}
        let(c,s)=self.coordinator.as_ref().ok_or_else(||rejected("financial Witness close identity"))?;
        self.send(&Packet::PurposeClosed{coordinator:c.clone(),session:s.clone()})?;self.closed=true;Ok(())
    }
    pub fn complete(mut self,work:Result<()>)->!{
        let result=(||{work?;if !self.closed||!self.disposed{return Err(rejected("financial Witness incomplete terminal handshake"));}
            let leaf=self.leaf.take().ok_or_else(||rejected("financial Witness custody consumed"))?;
            bootstrap::finish_leaf_capped(leaf,Ok(()),self.cleanup)})();
        // Endpoint closes all check-only duplicates only AFTER generic Exit.
        self.core.close();bootstrap::child_exit(result)
    }
}
impl Drop for WitnessFinancialContinuationOriginV1{fn drop(&mut self){self.core.close();}}
