//! Actual H foreground handoff. No ordinary summary can construct this owner.
use super::*;
use crate::{FinancialSavedSummaryV1,FinancialNormalCompletionNoticeV1,financial_normal_completion_data::FinancialNormalCloseContextV1};
#[derive(Default)]
pub(crate) struct HostNormalState {
 pub(crate) summary:Mutex<Option<FinancialSavedSummaryV1>>,
 pub(crate) notice:Mutex<Option<FinancialNormalCompletionNoticeV1>>,
 pub(crate) context:Mutex<Option<FinancialNormalCloseContextV1>>,
 pub(crate) phase:AtomicU8,
}
pub struct HostNormalFinishWaitV1 {state:Arc<HostLifecycle>,consumed:bool}
pub struct HostNormalCloseV1 {state:Arc<HostLifecycle>,context:FinancialNormalCloseContextV1,consumed:bool}
impl HostFinancialForegroundV1 {
 pub fn begin_normal_completion(mut self,service:&HostCompletedPairServiceV1,summary:FinancialSavedSummaryV1)->Result<HostNormalFinishWaitV1>{
  service.matches_lifecycle(&self.state)?;self.state.check_wait()?;self.state.check_foreground()?;summary.validate()?;
  if crate::signer_continue_state::wall_ms()?>=summary.original_valid_until_ms{return Err(rejected("saved summary original deadline elapsed"));}
  let mut slot=self.state.normal.summary.lock().map_err(|_|rejected("normal summary poisoned"))?;
  if slot.is_some()||self.state.normal.phase.load(Ordering::Acquire)!=0{return Err(rejected("normal foreground repeated"));}
  self.state.state.compare_exchange(RUNNING,PARKED,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("normal foreground not active"))?;
  *slot=Some(summary);self.state.normal.phase.store(1,Ordering::Release);self.consumed=true;
  Ok(HostNormalFinishWaitV1{state:Arc::clone(&self.state),consumed:false})
 }
}
impl HostNormalFinishWaitV1 {
 pub fn wait_for_close(mut self)->Result<HostNormalCloseV1>{loop{
  self.state.check_wait()?;
  if let Some(context)=self.state.normal.context.lock().map_err(|_|rejected("normal close context poisoned"))?.clone(){
   if self.state.normal.phase.load(Ordering::Acquire)!=2{return Err(rejected("normal close not admitted"));}
   require_time(self.state.clocks.received_cleanup(context.cleanup_ceiling_ms,Instant::now())?)?;
   self.consumed=true;return Ok(HostNormalCloseV1{state:Arc::clone(&self.state),context,consumed:false});
  }
  std::thread::sleep(std::time::Duration::from_millis(1));
 }}
}
impl HostNormalCloseV1 {
 /// Caller has dropped its actual Host/source/private owner, never a boolean shortcut.
 pub fn acknowledge_disposed(mut self)->Result<()> {
  self.state.check_wait()?;require_time(self.state.clocks.received_cleanup(self.context.cleanup_ceiling_ms,Instant::now())?)?;
  if self.state.normal.context.lock().map_err(|_|rejected("normal context poisoned"))?.as_ref()!=Some(&self.context){return Err(rejected("normal foreground disposal context changed"));}
  self.state.normal.phase.compare_exchange(2,3,Ordering::AcqRel,Ordering::Acquire).map_err(|_|rejected("normal foreground disposal repeated"))?;
  self.consumed=true;Ok(())
 }
}
impl Drop for HostNormalFinishWaitV1{fn drop(&mut self){if !self.consumed{self.state.poison();}}}
impl Drop for HostNormalCloseV1{fn drop(&mut self){if !self.consumed{self.state.poison();}}}
