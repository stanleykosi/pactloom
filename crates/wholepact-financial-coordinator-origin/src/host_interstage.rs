//! Same-H restriction-only interstage ownership. No W-completion claim or
//! permission is made by parking. Only actual C control traffic releases it.
use crate::{channel::require_time,financial_workflow_clock::{FullWorkflowClocksV1,PROFILE},
    host_restriction::HostRestrictionChecks,signer_continue_state::hash,rejected,Result,
    signer_continue_channel::SignerContinueRoleV1};
use serde::{Deserialize,Serialize};
use std::{marker::PhantomData,rc::Rc,sync::{Arc,Mutex,atomic::{AtomicU8,AtomicBool,Ordering}},time::Instant};
const RUNNING:u8=0;const PARKED:u8=1;const REQUESTED:u8=2;const GUARDED:u8=3;
const RESUME:u8=4;const RESUMED:u8=5;const POISON:u8=255;
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetirementRequest {
    pub profile:String,pub coordinator:String,pub session:String,pub target:SignerContinueRoleV1,
    pub witness_instance:String,pub challenge:String,pub cleanup_ceiling_ms:u64,
}
impl RetirementRequest {
    pub(super) fn validate(&self,clocks:FullWorkflowClocksV1)->Result<Instant>{
        if self.profile!=PROFILE||![&self.coordinator,&self.session,&self.witness_instance,&self.challenge].iter().all(|v|hash(v)){
            return Err(rejected("original retirement identity rejected"));}
        clocks.received_cleanup(self.cleanup_ceiling_ms,Instant::now())
    }
}
/// Created only in actual H after both S forks. Physical-effect paths sample
/// only this atomic; the tiny inert control-record mutex never covers I/O.
pub(super) struct HostLifecycle {
    state:AtomicU8,acknowledged:AtomicBool,request:Mutex<Option<(RetirementRequest,Instant)>>,
    checks:Arc<HostRestrictionChecks>,clocks:FullWorkflowClocksV1,
}
impl HostLifecycle {
    pub(super) fn create(checks:Arc<HostRestrictionChecks>,clocks:FullWorkflowClocksV1)
        ->(HostLifecycleOwner,Arc<Self>){
        let state=Arc::new(Self{state:AtomicU8::new(RUNNING),acknowledged:AtomicBool::new(false),request:Mutex::new(None),checks,clocks});
        (HostLifecycleOwner(Arc::clone(&state)),state)
    }
    pub(super) fn poison(&self){self.state.store(POISON,Ordering::SeqCst);}
    pub(super) fn check_foreground(&self)->Result<()>{
        if self.state.load(Ordering::SeqCst)!=RUNNING{return Err(rejected("original Host foreground parked or poisoned"));}Ok(())
    }
    fn check_wait(&self)->Result<()>{self.checks.check_current()?;
        if self.state.load(Ordering::SeqCst)==POISON{return Err(rejected("original Host interstage poisoned"));}
        require_time(self.clocks.supervision())?;
        if let Some((_,cutoff))=self.request.lock().map_err(|_|rejected("Host interstage record poisoned"))?.as_ref(){require_time(*cutoff)?;}Ok(())}
    pub(super) fn request(&self,request:RetirementRequest)->Result<()>{
        self.check_wait()?;let cutoff=request.validate(self.clocks)?;
        let mut slot=self.request.lock().map_err(|_|rejected("Host interstage record poisoned"))?;
        if slot.is_some(){return Err(rejected("Host retirement already pending"));}
        // A C request may await the actual no-effect foreground boundary, but
        // never makes that foreground quiescent by itself.
        self.acknowledged.store(false,Ordering::Release);*slot=Some((request,cutoff));Ok(())
    }
    pub(super) fn quiescent(&self)->Result<Option<RetirementRequest>>{
        self.check_wait()?;
        if self.state.load(Ordering::SeqCst)!=GUARDED{return Ok(None);}
        Ok(self.request.lock().map_err(|_|rejected("Host interstage record poisoned"))?.as_ref().map(|(r,_)|r.clone()))
    }
    pub(super) fn receive_resume(&self,request:&RetirementRequest)->Result<()>{
        self.check_wait()?;
        let slot=self.request.lock().map_err(|_|rejected("Host interstage record poisoned"))?;
        if slot.as_ref().is_none_or(|(r,_)|r!=request){return Err(rejected("Host retirement Resume mismatch"));}
        self.state.compare_exchange(GUARDED,RESUME,Ordering::SeqCst,Ordering::SeqCst)
            .map_err(|_|rejected("Host retirement Resume reordered"))?;Ok(())
    }
    pub(super) fn resumed(&self)->Result<Option<RetirementRequest>>{
        self.check_wait()?;
        if self.state.load(Ordering::SeqCst)!=RESUMED{return Ok(None);}
        Ok(self.request.lock().map_err(|_|rejected("Host interstage record poisoned"))?.as_ref().map(|(r,_)|r.clone()))
    }
    pub(super) fn acknowledge_resumed(&self,request:&RetirementRequest)->Result<()>{
        self.check_wait()?;
        if self.state.load(Ordering::SeqCst)!=RESUMED{return Err(rejected("Host guard has not consumed Resume"));}
        let mut slot=self.request.lock().map_err(|_|rejected("Host interstage record poisoned"))?;
        if slot.as_ref().is_none_or(|(r,_)|r!=request){return Err(rejected("Host resumed record mismatch"));}
        self.acknowledged.store(true,Ordering::Release);Ok(())
    }
}
/// First field in actual H custody. Denial precedes every child Drop/reap.
pub(super) struct HostLifecycleOwner(pub(super) Arc<HostLifecycle>);
impl Drop for HostLifecycleOwner{fn drop(&mut self){self.0.poison();}}
pub struct HostFinancialForegroundV1{state:Arc<HostLifecycle>,consumed:bool,_thread:PhantomData<Rc<()>>}
impl HostFinancialForegroundV1{
    pub(super) fn from_actual_host(state:Arc<HostLifecycle>)->Self{Self{state,consumed:false,_thread:PhantomData}}
    /// Called only by the pinned Host completed-boundary holder after all
    /// function-local source/network/TTY attempts and locks have ended.
    pub fn enter_owner_workflow_wait(mut self)->Result<HostFinancialInterstageWaitV1>{
        self.state.check_wait()?;
        self.state.state.compare_exchange(RUNNING,PARKED,Ordering::SeqCst,Ordering::SeqCst)
            .map_err(|_|rejected("Host foreground cannot park twice"))?;
        self.consumed=true;Ok(HostFinancialInterstageWaitV1{state:Arc::clone(&self.state),consumed:false,_thread:PhantomData})
    }
}
impl Drop for HostFinancialForegroundV1{fn drop(&mut self){if !self.consumed{self.state.poison();}}}
pub struct HostFinancialInterstageWaitV1{state:Arc<HostLifecycle>,consumed:bool,_thread:PhantomData<Rc<()>>}
impl HostFinancialInterstageWaitV1{
    pub fn try_next_retirement(&mut self)->Result<Option<HostWitnessRetirementGuardV1<'_>>>{
        let result=(||{self.state.check_wait()?;
            // A completed guard can remain parked for another finite request;
            // it never reopens the foreground implicitly.
            if self.state.state.load(Ordering::SeqCst)==RESUMED{
                if !self.state.acknowledged.load(Ordering::Acquire){return Ok(None);}
                self.state.request.lock().map_err(|_|rejected("Host record poisoned"))?.take();
                self.state.state.compare_exchange(RESUMED,PARKED,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("Host repark race"))?;
            }
            if self.state.state.load(Ordering::SeqCst)!=PARKED{return Err(rejected("Host wait not parked"));}
            let request=self.state.request.lock().map_err(|_|rejected("Host record poisoned"))?.as_ref().map(|(r,_)|r.clone());
            if let Some(request)=request{
                self.state.state.compare_exchange(PARKED,REQUESTED,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("Host request raced poison"))?;
                self.state.state.compare_exchange(REQUESTED,GUARDED,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("Host guard raced poison"))?;
                Ok(Some(request))
            }else{Ok(None)}
        })();
        match result{Ok(Some(request))=>Ok(Some(HostWitnessRetirementGuardV1{wait:self,request,consumed:false})),Ok(None)=>Ok(None),Err(e)=>{self.state.poison();Err(e)}}
    }
    pub fn leave_after_resume(mut self)->Result<HostFinancialForegroundV1>{
        self.state.check_wait()?;
        if !self.state.acknowledged.load(Ordering::Acquire){return Err(rejected("Host Resume not yet acknowledged"));}
        self.state.state.compare_exchange(RESUMED,RUNNING,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("Host leave without exact Resume"))?;
        self.state.request.lock().map_err(|_|rejected("Host record poisoned"))?.take();
        self.consumed=true;Ok(HostFinancialForegroundV1{state:Arc::clone(&self.state),consumed:false,_thread:PhantomData})
    }
}
impl Drop for HostFinancialInterstageWaitV1{fn drop(&mut self){if !self.consumed{self.state.poison();}}}
pub struct HostWitnessRetirementGuardV1<'a>{wait:&'a mut HostFinancialInterstageWaitV1,request:RetirementRequest,consumed:bool}
impl HostWitnessRetirementGuardV1<'_>{
    pub fn wait_resume(mut self)->Result<()>{
        loop{self.wait.state.check_wait()?;
            let phase=self.wait.state.state.load(Ordering::SeqCst);
            if phase==RESUME{
                let slot=self.wait.state.request.lock().map_err(|_|rejected("Host record poisoned"))?;
                if slot.as_ref().is_none_or(|(r,_)|r!=&self.request){return Err(rejected("Host guard changed"));}
                self.wait.state.state.compare_exchange(RESUME,RESUMED,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("Host Resume raced restriction"))?;
                drop(slot);
                while !self.wait.state.acknowledged.load(Ordering::Acquire){self.wait.state.check_wait()?;std::thread::sleep(std::time::Duration::from_millis(1));}
                self.consumed=true;return Ok(());
            }
            if phase!=GUARDED{return Err(rejected("Host guard no longer current"));}
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
impl Drop for HostWitnessRetirementGuardV1<'_>{fn drop(&mut self){if !self.consumed{self.wait.state.poison();}}}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn retirement_request_is_fixed_profile_identity_and_original_cleanup_data(){
        let clocks=FullWorkflowClocksV1::from_initial_epoch(Instant::now()).unwrap();let h="a".repeat(64);
        let r=RetirementRequest{profile:PROFILE.into(),coordinator:h.clone(),session:h.clone(),target:SignerContinueRoleV1::Signer1,
            witness_instance:h.clone(),challenge:h,cleanup_ceiling_ms:5_000};
        r.validate(clocks).unwrap();let mut bad=r.clone();bad.profile="another-profile".into();assert!(bad.validate(clocks).is_err());
        bad=r.clone();bad.challenge="".into();assert!(bad.validate(clocks).is_err());
        bad=r.clone();bad.cleanup_ceiling_ms=1_805_001;assert!(bad.validate(clocks).is_err());
        let text=serde_json::to_string(&r).unwrap();let bad=text.replacen('{',"{\"caller_permission\":true,",1);
        assert!(serde_json::from_str::<RetirementRequest>(&bad).is_err());
    }
}
