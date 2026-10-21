//! Finite normal close of the actual completed originals. No Cancel-as-success.
use super::*;
use crate::{FinancialNormalCompletionNoticeV1,FinancialSavedSummaryV1,financial_normal_completion_data::FinancialNormalCloseContextV1};
use super::completed_pair::CompletedPairServiceLease;
use std::time::Duration;
#[derive(Default)]
pub(super) struct NormalCState {notice:Option<FinancialNormalCompletionNoticeV1>}
#[derive(Default)]
pub(super) struct NormalSState {pub(super) context:Option<FinancialNormalCloseContextV1>,disposed:bool}
#[derive(Default)]
pub(super) struct NormalHState {notice_sent:bool,disposed:[bool;2],ready_sent:bool}
struct FinishReview {core:Arc<Core>,clocks:FullWorkflowClocksV1,notice:FinancialNormalCompletionNoticeV1,pair:CompletedPairServiceLease,deadline:Instant}
impl FinishReview {fn check(&self)->Result<()>{self.core.check_action_restrictions()?;crate::channel::require_time(self.deadline)?;self.pair.check()?;if state::wall_ms()?>=self.notice.summary.original_valid_until_ms{return Err(rejected("saved normal completion review expired"));}Ok(())}}
pub struct FinancialNormalFinishTicketV1 {binding:Arc<FinishReview>,consumed:bool}
impl FinancialNormalFinishTicketV1 {
 pub fn presentation(&self)->&FinancialNormalCompletionNoticeV1{&self.binding.notice}
 pub fn native_deadline(&self)->Instant{self.binding.deadline}
 pub fn check_current(&self)->Result<()>{self.binding.check()?;if self.binding.core.phase.normal_phase()!=1{return Err(rejected("normal Finish review consumed"));}Ok(())}
}
impl Drop for FinancialNormalFinishTicketV1{fn drop(&mut self){if !self.consumed{self.binding.core.phase.revoke();}}}
pub struct FinancialNormalFinishOutboundV1 {binding:Arc<FinishReview>,context:FinancialNormalCloseContextV1,cutoff:Instant,consumed:bool}
impl FinancialNormalFinishOutboundV1 {pub fn original_cleanup_deadline(&self)->Instant{self.cutoff}}
impl Drop for FinancialNormalFinishOutboundV1{fn drop(&mut self){if !self.consumed{self.binding.core.phase.revoke();}}}
pub struct FinancialNormalCompletionV1 {core:Arc<Core>,summary:FinancialSavedSummaryV1}
impl FinancialNormalCompletionV1 {
 pub fn summary(&self)->&FinancialSavedSummaryV1{&self.summary}
 pub fn check_completed(&self)->Result<()>{if self.core.phase.normal_phase()!=5||self.core.phase.revoked()||unsafe{libc::getpid()}!=self.core.owner_pid||unsafe{libc::geteuid()}!=self.core.owner_uid{return Err(rejected("actual normal reap proof absent"));}Ok(())}
}
impl CoordinatorFinancialNativeV1 {
 pub fn admit_normal_finish(&self,mut ticket:FinancialNormalFinishTicketV1,pair:&FinancialCompletedPairServingV1)->Result<FinancialNormalFinishOutboundV1>{
  ticket.check_current()?;pair.check_current()?;
  if !Arc::ptr_eq(&self.core,&ticket.binding.core)||pair.presentation().presentation_digest!=ticket.binding.notice.pair_presentation_digest{return Err(rejected("normal Finish original Pair changed"));}
  let cutoff=ticket.binding.clocks.first_cleanup_ceiling(Instant::now())?;
  let context=FinancialNormalCloseContextV1{coordinator:pair.presentation().original.owners[0].actor.coordinator_process_instance.clone(),session:pair.presentation().original.owners[0].actor.session_challenge.clone(),challenge:state::nonce()?,notice:ticket.binding.notice.clone(),cleanup_ceiling_ms:ticket.binding.clocks.cleanup_offset(cutoff)?};context.validate()?;
  self.core.phase.normal_step(1,2)?;ticket.consumed=true;
  Ok(FinancialNormalFinishOutboundV1{binding:Arc::clone(&ticket.binding),context,cutoff,consumed:false})
 }
}
impl CoordinatorFinancialEndpointV1 {
 pub(super) fn receive_normal_notice(&mut self,notice:FinancialNormalCompletionNoticeV1)->Result<CoordinatorFinancialEventV1>{
  self.core.check_action_restrictions()?;notice.validate()?;
  if self.normal.notice.is_some()||self.cancel_sent||self.retirement_resume.is_some(){return Err(rejected("normal notice repeated or active retirement"));}
  let pair=self.normal_pair_lease()?;
  if pair.presentation().presentation_digest!=notice.pair_presentation_digest{return Err(rejected("normal notice Pair mismatch"));}
  for i in 0..2{let slot=self.slots[i].as_ref().ok_or_else(||rejected("normal completion source missing"))?;
   if slot.wire_phase!=73||slot.activate.wallet.sign.returning.actual_completed()?!=&notice.returned[i]{return Err(rejected("normal completion actual Return mismatch"));}
   let custody=self.signed_result_custody(if i==0{Target::Signer1}else{Target::Signer2})?;
   if custody.signed_result().result_digest!=notice.returned[i].result_digest||custody.signed_result().outbox_digest!=notice.returned[i].outbox_digest{return Err(rejected("normal completion signed result mismatch"));}
  }
  let now=Instant::now();let deadline=self.clocks.supervision().min(now+Duration::from_secs(120)).min(wall_ceiling(now,state::wall_ms()?,state::wall_ms()?,notice.summary.original_valid_until_ms)?);
  let binding=Arc::new(FinishReview{core:Arc::clone(&self.core),clocks:self.clocks,notice:notice.clone(),pair,deadline});binding.check()?;
  self.core.phase.normal_step(0,1)?;self.normal.notice=Some(notice);
  Ok(CoordinatorFinancialEventV1::NormalCompletionReview(FinancialNormalFinishTicketV1{binding,consumed:false}))
 }
 pub fn finish_normal(mut self,mut outbound:FinancialNormalFinishOutboundV1,mut terminal:crate::CoordinatorHostTerminalEndpointV1)->Result<FinancialNormalCompletionV1>{
  let result=(||{
   if !Arc::ptr_eq(&self.core,&outbound.binding.core)||self.normal.notice.as_ref()!=Some(&outbound.context.notice)||self.core.phase.normal_phase()!=2||self.cancel_sent{return Err(rejected("normal Finish owner changed"));}
   let cutoff=outbound.cutoff;crate::channel::require_time(cutoff)?;self.core.check()?;if self.core.phase.revoked(){return Err(rejected("normal Finish revoked"));}
   terminal.begin_normal_hold(&self.core)?;self.cleanup=Some(cutoff);self.core.phase.normal_step(2,3)?;
   self.send_positive(&Packet::NormalClose{context:outbound.context.clone()},cutoff)?.require_sent()?;
   self.finish_completed_pair_for_normal()?;
   let mut source_disposed=[false;2];let mut host_ready=false;let mut pair_closed=false;
   while !host_ready||!pair_closed {
    crate::channel::require_time(cutoff)?;self.core.check()?;if self.core.phase.revoked(){return Err(rejected("normal close interrupted"));}
    terminal.drain_normal_output(&self.core,cutoff,false)?;
    if let Some(packet)=self.tree.as_ref().ok_or_else(||rejected("normal tree missing"))?.continue_host()?.workflow_receive()?{match packet{
     Packet::NormalDisposed{role,challenge,notice_digest} if challenge==outbound.context.challenge&&notice_digest==outbound.context.notice.notice_digest&&!source_disposed[role.index()]=>source_disposed[role.index()]=true,
     Packet::NormalReady{challenge,notice_digest} if challenge==outbound.context.challenge&&notice_digest==outbound.context.notice.notice_digest&&source_disposed==[true;2]&&!host_ready=>host_ready=true,
     _=>return Err(rejected("normal close unexpected Host evidence")),
    }}
    if !pair_closed{if let Some(event)=self.try_receive_completed_pair()?{match event{
     CoordinatorCompletedPairEventV1::Disposed=>self.close_completed_pair_purpose()?,
     CoordinatorCompletedPairEventV1::PurposeClosed=>pair_closed=true,
     _=>return Err(rejected("normal Pair close failed")),
    }}}
    std::thread::sleep(Duration::from_millis(1));
   }
   self.core.phase.normal_step(3,4)?;
   // The exact sole tree consumes each owned child and verifies waitpid success.
   // No ordinary all-peer currentness check is valid during these expected exits.
   self.tree.take().ok_or_else(||rejected("normal tree already consumed"))?.stop_and_reap(cutoff)?;
   terminal.drain_normal_output(&self.core,cutoff,true)?;
   crate::channel::require_time(cutoff)?;self.core.phase.normal_step(4,5)?;
   terminal.release_after_normal_reaps(&self.core)?;
   self.core.alive.store(false,Ordering::Release);outbound.consumed=true;
   let proof=FinancialNormalCompletionV1{core:Arc::clone(&self.core),summary:outbound.context.notice.summary.clone()};proof.check_completed()?;Ok(proof)
  })();if result.is_err(){self.core.close();}result
 }
}
/// Exact S receive token. It grants only dropping already-completed local owners.
pub struct SignerNormalCloseV1 {core:Arc<Core>,context:FinancialNormalCloseContextV1,cutoff:Instant,role:Target,consumed:bool}
impl SignerNormalCloseV1 {pub fn check_current(&self)->Result<()>{self.core.check()?;if let Some(reader)=&self.core.signer_restriction{reader.check_current()?;}crate::channel::require_time(self.cutoff)?;if self.core.phase.revoked()||self.core.phase.phase(self.role.index())!=73{return Err(rejected("normal Source close not current"));}Ok(())}}
impl Drop for SignerNormalCloseV1{fn drop(&mut self){if !self.consumed{self.core.phase.revoke();}}}
impl SignerFinancialWorkflowOriginV1 {
 pub(super) fn receive_normal_close(&mut self,context:FinancialNormalCloseContextV1)->Result<SignerFinancialWorkflowRequestV1>{
  context.validate()?;self.core.check_action_restrictions()?;
  let start=self.start.as_ref().ok_or_else(||rejected("normal Source close without original"))?;
  if self.normal.context.is_some()||self.cancel_seen||self.failed||self.core.phase.phase(self.target.index())!=73||context.coordinator!=start.coordinator||context.session!=start.session||self.activate.wallet.sign.returning.actual_completed()?!=&context.notice.returned[self.target.index()]{return Err(rejected("normal Source close before exact Return"));}
  let cutoff=self.clocks.retain_cleanup(self.cleanup,self.clocks.received_cleanup(context.cleanup_ceiling_ms,Instant::now())?,Instant::now())?;self.cleanup=Some(cutoff);self.normal.context=Some(context.clone());
  Ok(SignerFinancialWorkflowRequestV1::NormalClose{action:SignerNormalCloseV1{core:Arc::clone(&self.core),context,cutoff,role:self.target,consumed:false}})
 }
 pub fn send_normal_disposed(&mut self,mut action:SignerNormalCloseV1)->Result<()>{
  action.check_current()?;
  if !Arc::ptr_eq(&self.core,&action.core)||self.normal.context.as_ref()!=Some(&action.context)||self.normal.disposed||self.cancel_seen{return Err(rejected("normal Source disposal context mismatch"));}
  self.normal.disposed=true;action.consumed=true;
  self.send(&Packet::NormalDisposed{role:self.target,challenge:action.context.challenge.clone(),notice_digest:action.context.notice.notice_digest.clone()})
 }
 pub fn complete_normal(mut self,work:Result<()>)->! {
  let work=work.and_then(|()|{if self.normal.context.is_none()||!self.normal.disposed||self.cancel_seen||self.failed||self.core.phase.revoked(){Err(rejected("actual normal Source disposal missing"))}else{Ok(())}});
  self.recipient.take();let result=match self.leaf.take(){Some(leaf)=>bootstrap::finish_leaf_capped(leaf,work,self.cleanup),None=>Err(rejected("normal Source custody consumed"))};
  self.core.close();bootstrap::child_exit(result)
 }
}
impl HostFinancialWorkflowRelayV1 {
 pub(super) fn normal_control(&mut self,packet:&Packet)->Result<bool>{
  let Packet::NormalClose{context}=packet else{return Ok(false)};context.validate()?;self.lifecycle.check_wait()?;
  if self.cancel_seen||self.restricted||self.retirement.is_some()||!self.normal.notice_sent||self.lifecycle.normal.notice.lock().map_err(|_|rejected("normal Host notice poisoned"))?.as_ref()!=Some(&context.notice)||self.coordinator.as_deref()!=Some(context.coordinator.as_str())||self.session.as_deref()!=Some(context.session.as_str()){return Err(rejected("normal Host close mismatch"));}
  for i in 0..2{if self.slots[i].as_ref().ok_or_else(||rejected("normal Host source missing"))?.activate.wallet.sign.returning.actual_completed()?!=&context.notice.returned[i]{return Err(rejected("normal Host Return mismatch"));}}
  let cutoff=self.clocks.retain_cleanup(self.cleanup,self.clocks.received_cleanup(context.cleanup_ceiling_ms,Instant::now())?,Instant::now())?;
  let mut stored=self.lifecycle.normal.context.lock().map_err(|_|rejected("normal Host context poisoned"))?;
  if stored.is_some(){return Err(rejected("normal Host close repeated"));}*stored=Some(context.clone());self.cleanup=Some(cutoff);
  self.lifecycle.normal.phase.compare_exchange(1,2,Ordering::AcqRel,Ordering::Acquire).map_err(|_|rejected("normal Host foreground missing"))?;drop(stored);
  let host=self.host.as_ref().ok_or_else(||rejected("normal Host consumed"))?;
  for role in [Target::Signer1,Target::Signer2]{host.continue_child(role)?.workflow_send(packet)?;}Ok(true)
 }
 pub(super) fn normal_observation(&mut self)->Result<bool>{
  if self.cancel_seen||self.restricted{return Ok(false);}
  self.lifecycle.check_wait()?;
  if !self.normal.notice_sent&&self.lifecycle.normal.phase.load(Ordering::Acquire)==1 {
   let summary=self.lifecycle.normal.summary.lock().map_err(|_|rejected("normal saved summary poisoned"))?.clone().ok_or_else(||rejected("actual saved summary absent"))?;
   let service=self.lifecycle.normal_pair_presentation()?;
   let mut returned=Vec::new();for i in 0..2{returned.push(self.slots[i].as_ref().ok_or_else(||rejected("normal Host source missing"))?.activate.wallet.sign.returning.actual_completed()?.clone());}
   let mut notice=FinancialNormalCompletionNoticeV1{summary,returned:returned.try_into().map_err(|_|rejected("normal returned cardinality"))?,pair_presentation_digest:service.presentation_digest,notice_digest:String::new()};notice.notice_digest=notice.digest()?;notice.validate()?;
   *self.lifecycle.normal.notice.lock().map_err(|_|rejected("normal Host notice poisoned"))?=Some(notice.clone());
   self.host.as_ref().ok_or_else(||rejected("normal Host consumed"))?.workflow_send_c(&Packet::NormalCompletionNotice{notice})?;self.normal.notice_sent=true;return Ok(true);
  }
  if !self.normal.ready_sent&&self.normal.disposed==[true;2]&&self.lifecycle.normal.phase.load(Ordering::Acquire)==3 {
   let context=self.lifecycle.normal.context.lock().map_err(|_|rejected("normal Host context poisoned"))?.clone().ok_or_else(||rejected("normal Host close absent"))?;
   crate::channel::require_time(self.cleanup.ok_or_else(||rejected("normal Host cleanup absent"))?)?;
   self.host.as_ref().ok_or_else(||rejected("normal Host consumed"))?.workflow_send_c(&Packet::NormalReady{challenge:context.challenge,notice_digest:context.notice.notice_digest})?;
   self.normal.ready_sent=true;self.lifecycle.normal.phase.store(4,Ordering::Release);return Ok(true);
  }Ok(false)
 }
 pub(super) fn up_normal_disposed(&mut self,role:Target,packet:&Packet)->Result<bool>{
  let Packet::NormalDisposed{role:actual,challenge,notice_digest}=packet else{return Err(rejected("normal Source disposal packet"))};
  self.lifecycle.check_wait()?;
  let context=self.lifecycle.normal.context.lock().map_err(|_|rejected("normal Host context poisoned"))?.clone().ok_or_else(||rejected("normal Source disposal before close"))?;
  if self.cancel_seen||self.restricted||*actual!=role||self.normal.disposed[role.index()]||challenge!=&context.challenge||notice_digest!=&context.notice.notice_digest{return Err(rejected("normal Source disposal mismatch"));}
  self.normal.disposed[role.index()]=true;Ok(true)
 }
 pub fn normal_close_ready(&self)->Result<bool>{
  self.lifecycle.check_wait()?;Ok(self.normal.ready_sent&&self.normal.disposed==[true;2]&&self.lifecycle.normal.phase.load(Ordering::Acquire)==4&&!self.cancel_seen&&!self.restricted)
 }
 pub fn finish_normal(mut self)->Result<()> {
  if !self.normal_close_ready()?{return Err(rejected("normal Host close evidence incomplete"));}
  let cutoff=self.cleanup.ok_or_else(||rejected("normal Host cleanup absent"))?;
  bootstrap::finish_host_capped(self.host.take().ok_or_else(||rejected("normal Host consumed"))?,Some(cutoff))?;
  self.lifecycle.normal_reap_check(cutoff)
 }
}
