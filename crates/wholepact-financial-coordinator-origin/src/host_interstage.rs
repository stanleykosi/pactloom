//! Same-H restriction-only interstage ownership. No W-completion claim or
//! permission is made by parking. Only actual C control traffic releases it.
use crate::{channel::require_time,financial_workflow_clock::{FullWorkflowClocksV1,PROFILE},
    host_restriction::HostRestrictionChecks,signer_continue_state::hash,rejected,Result,
    signer_continue_channel::SignerContinueRoleV1};
use serde::{Deserialize,Serialize};
use std::{marker::PhantomData,rc::Rc,sync::{Arc,Mutex,atomic::{AtomicU8,AtomicBool,Ordering}},time::Instant};
#[path="host_completed_pair.rs"]
mod completed_pair;
pub use completed_pair::HostCompletedPairServiceV1;
pub(crate) use completed_pair::HostPairReceiveState;
const RUNNING:u8=0;const PARKED:u8=1;const REQUESTED:u8=2;const GUARDED:u8=3;
const RESUME:u8=4;const RESUMED:u8=5;const POISON:u8=255;
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(super) enum RetirementPurpose{InitialHistory,FinancialContinuation,FinancialSigning}
impl RetirementPurpose{
    pub(super) fn index(self)->usize{match self{Self::InitialHistory=>0,Self::FinancialContinuation=>1,Self::FinancialSigning=>2}}
    pub(super) fn role(self,target:SignerContinueRoleV1)->crate::process::Role{match self{
        Self::InitialHistory=>crate::financial_history_channel::role_for(target),Self::FinancialContinuation=>crate::financial_witness_channel::role_for(target),Self::FinancialSigning=>crate::financial_signing_channel::role_for(target)}}
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetirementRequest {
    pub profile:String,pub coordinator:String,pub session:String,pub target:SignerContinueRoleV1,pub purpose:RetirementPurpose,pub binding_digest:String,
    pub witness_instance:String,pub challenge:String,pub cleanup_ceiling_ms:u64,
    pub signing:Option<SigningRetirementBindingV1>,
}
impl RetirementRequest {
    pub(super) fn validate(&self,clocks:FullWorkflowClocksV1)->Result<Instant>{
        if self.profile!=PROFILE||![&self.coordinator,&self.session,&self.witness_instance,&self.challenge,&self.binding_digest].iter().all(|v|hash(v)){
            return Err(rejected("original retirement identity rejected"));}
        match (&self.purpose,&self.signing) {
            (RetirementPurpose::FinancialSigning,Some(binding))=>{binding.validate()?;if binding.commitment()?!=self.binding_digest{return Err(rejected("Signing retirement commitment changed"));}},
            (RetirementPurpose::FinancialSigning,None)=>return Err(rejected("Signing retirement missing actual result")),
            (_,Some(_))=>return Err(rejected("non Signing retirement contains signed result")),
            (_,None)=>{},
        }
        clocks.received_cleanup(self.cleanup_ceiling_ms,Instant::now())
    }
}
/// Ordinary correlation only. Only the actual C/H result slots may supply it.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SigningRetirementBindingV1 {
    pub original_commitment:String,
    pub signed:crate::SignerSignCommittedV1,
}
impl SigningRetirementBindingV1 {
    pub(super) fn validate(&self)->Result<()>{self.signed.validate()?;if !hash(&self.original_commitment){return Err(rejected("Signing retirement original"));}Ok(())}
    pub(super) fn commitment(&self)->Result<String>{use sha2::{Digest,Sha256};self.validate()?;let mut h=Sha256::new();h.update(b"wholepact:signing-retirement:v1\0");h.update(serde_json::to_vec(self).map_err(|_|rejected("Signing retirement encoding"))?);Ok(hex::encode(h.finalize()))}
}
/// Created only in actual H after both S forks. Physical-effect paths sample
/// only this atomic; the tiny inert control-record mutex never covers I/O.
enum V3DisclosureSlot { Unseen, Ready(crate::SignerV3CurrentDisclosureV1), Taken }
enum V3EndpointSlot { Unseen, Ready(crate::SignerV3PairEndpointV1), Taken(crate::SignerV3PairEndpointV1) }
pub(super) struct HostLifecycle {
    state:AtomicU8,acknowledged:AtomicBool,request:Mutex<Option<(RetirementRequest,Instant)>>,
    v3_pair_endpoints:Mutex<[V3EndpointSlot;2]>,
    v3_current_disclosures:Mutex<[V3DisclosureSlot;2]>,
    checks:Arc<HostRestrictionChecks>,clocks:FullWorkflowClocksV1,
    pair_service:std::sync::OnceLock<Arc<completed_pair::PairServiceRecord>>,pair_handoff:AtomicBool,
}
impl HostLifecycle {
    pub(super) fn create(checks:Arc<HostRestrictionChecks>,clocks:FullWorkflowClocksV1)
        ->(HostLifecycleOwner,Arc<Self>){
        let state=Arc::new(Self{state:AtomicU8::new(RUNNING),acknowledged:AtomicBool::new(false),request:Mutex::new(None),v3_pair_endpoints:Mutex::new([V3EndpointSlot::Unseen,V3EndpointSlot::Unseen]),v3_current_disclosures:Mutex::new([V3DisclosureSlot::Unseen,V3DisclosureSlot::Unseen]),checks,clocks,pair_service:std::sync::OnceLock::new(),pair_handoff:AtomicBool::new(false)});
        (HostLifecycleOwner(Arc::clone(&state)),state)
    }
    /// Inert location metadata from the authenticated original S relay. This
    /// neither grants pairing nor changes foreground/parked state.
    pub(super) fn publish_v3_pair_endpoint(&self,target:SignerContinueRoleV1,endpoint:crate::SignerV3PairEndpointV1)->Result<()> {
        self.check_wait()?;endpoint.validate()?;
        let mut slots=self.v3_pair_endpoints.lock().map_err(|_|rejected("Host V3 endpoint mailbox poisoned"))?;
        if !matches!(slots[target.index()],V3EndpointSlot::Unseen){return Err(rejected("Host V3 endpoint repeated"));}
        slots[target.index()]=V3EndpointSlot::Ready(endpoint);Ok(())
    }
    fn take_v3_pair_endpoint(&self,target:SignerContinueRoleV1)->Result<Option<crate::SignerV3PairEndpointV1>> {
        self.check_wait()?;self.check_foreground()?;
        let mut slots=self.v3_pair_endpoints.lock().map_err(|_|rejected("Host V3 endpoint mailbox poisoned"))?;
        match &slots[target.index()] {
            V3EndpointSlot::Unseen=>return Ok(None),
            V3EndpointSlot::Taken(_)=>return Err(rejected("Host V3 endpoint already consumed")),
            V3EndpointSlot::Ready(_)=>{},
        }
        let V3EndpointSlot::Ready(endpoint)=&slots[target.index()] else{return Err(rejected("Host V3 endpoint invalid state"));};
        let endpoint=endpoint.clone();slots[target.index()]=V3EndpointSlot::Taken(endpoint.clone());
        Ok(Some(endpoint))
    }
    /// Authenticated committed observations only. A racing R drops positive H
    /// metadata, not the receipt result being forwarded to C.
    pub(super) fn publish_v3_current_disclosure(&self,target:SignerContinueRoleV1,data:crate::SignerV3CurrentDisclosureV1)->Result<()> {
        data.validate()?;self.check_not_poisoned()?;
        let mut slots=self.v3_current_disclosures.lock().map_err(|_|rejected("Host V3 disclosure mailbox poisoned"))?;
        if !matches!(slots[target.index()],V3DisclosureSlot::Unseen){return Err(rejected("Host V3 disclosure repeated"));}
        let endpoints=self.v3_pair_endpoints.lock().map_err(|_|rejected("Host V3 endpoint mailbox poisoned"))?;
        if matches!(endpoints[target.index()],V3EndpointSlot::Unseen){return Err(rejected("Host V3 disclosure before endpoint"));}
        if let V3EndpointSlot::Ready(endpoint)|V3EndpointSlot::Taken(endpoint)=&endpoints[target.index()] {
            if endpoint.source_identity_digest!=data.source_identity_digest || endpoint.entry_presentation_digest!=data.entry_presentation_digest {return Err(rejected("Host V3 disclosure endpoint mismatch"));}
        }
        drop(endpoints);
        require_time(self.clocks.supervision())?;
        if !self.checks.check_current_or_restricted()? {slots[target.index()]=V3DisclosureSlot::Taken;return Ok(());}
        slots[target.index()]=V3DisclosureSlot::Ready(data);Ok(())
    }
    fn take_v3_current_disclosure(&self,target:SignerContinueRoleV1)->Result<Option<crate::SignerV3CurrentDisclosureV1>> {
        self.check_wait()?;self.check_foreground()?;
        let mut slots=self.v3_current_disclosures.lock().map_err(|_|rejected("Host V3 disclosure mailbox poisoned"))?;
        match &slots[target.index()] { V3DisclosureSlot::Unseen=>return Ok(None),V3DisclosureSlot::Taken=>return Err(rejected("Host V3 disclosure already consumed")),V3DisclosureSlot::Ready(_)=>{} }
        let V3DisclosureSlot::Ready(data)=std::mem::replace(&mut slots[target.index()],V3DisclosureSlot::Taken) else{return Err(rejected("Host V3 disclosure invalid state"));};
        Ok(Some(data))
    }
    pub(super) fn poison(&self){self.state.store(POISON,Ordering::SeqCst);}
    pub(super) fn check_not_poisoned(&self)->Result<()>{if self.state.load(Ordering::SeqCst)==POISON{return Err(rejected("original Host foreground permanently poisoned"));}Ok(())}
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
    pub fn take_v3_pair_endpoint_signer1(&self)->Result<Option<crate::SignerV3PairEndpointV1>> {
        self.state.take_v3_pair_endpoint(SignerContinueRoleV1::Signer1)
    }
    pub fn take_v3_pair_endpoint_signer2(&self)->Result<Option<crate::SignerV3PairEndpointV1>> {
        self.state.take_v3_pair_endpoint(SignerContinueRoleV1::Signer2)
    }
    pub fn take_v3_current_disclosure_signer1(&self)->Result<Option<crate::SignerV3CurrentDisclosureV1>> {self.state.take_v3_current_disclosure(SignerContinueRoleV1::Signer1)}
    pub fn take_v3_current_disclosure_signer2(&self)->Result<Option<crate::SignerV3CurrentDisclosureV1>> {self.state.take_v3_current_disclosure(SignerContinueRoleV1::Signer2)}
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
    /// Consume only this owner's genuine initial-History retirement Resume.
    pub fn wait_initial_history_resume(self, target: SignerContinueRoleV1)->Result<()> {
        if self.request.target != target || self.request.purpose != RetirementPurpose::InitialHistory {
            self.wait.state.poison(); return Err(rejected("Host initial History retirement changed"));
        }
        self.wait_resume()
    }
    /// Consume only this owner's genuine continuation-admission retirement.
    pub fn wait_financial_continuation_resume(self, target: SignerContinueRoleV1)->Result<()> {
        if self.request.target != target || self.request.purpose != RetirementPurpose::FinancialContinuation {
            self.wait.state.poison(); return Err(rejected("Host continuation retirement changed"));
        }
        self.wait_resume()
    }

    pub fn wait_financial_signing_resume(self,target:SignerContinueRoleV1,authorization_id:&str,original_consent_ref:&str)->Result<()> {
        let matches=self.request.target==target && self.request.purpose==RetirementPurpose::FinancialSigning
            && self.request.signing.as_ref().is_some_and(|b|b.signed.authorization_id==authorization_id && b.signed.original_consent_ref==original_consent_ref);
        if !matches{self.wait.state.poison();return Err(rejected("Host Signing retirement differs from selected actual result"));}
        self.wait_resume()
    }
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
    fn retirement_purposes_map_only_fixed_distinct_original_slots(){
        use crate::process::Role;
        assert_eq!(RetirementPurpose::InitialHistory.role(SignerContinueRoleV1::Signer1),Role::Owner1FinancialReadHistory);
        assert_eq!(RetirementPurpose::FinancialContinuation.role(SignerContinueRoleV1::Signer1),Role::Owner1FinancialContinuationAdmission);
        assert_ne!(RetirementPurpose::InitialHistory.index(),RetirementPurpose::FinancialContinuation.index());
        assert_eq!(RetirementPurpose::FinancialSigning.role(SignerContinueRoleV1::Signer1),Role::Owner1FinancialSigning);
    }
    #[test]
    fn retirement_request_is_fixed_profile_identity_and_original_cleanup_data(){
        let clocks=FullWorkflowClocksV1::from_initial_epoch(Instant::now()).unwrap();let h="a".repeat(64);
        let r=RetirementRequest{profile:PROFILE.into(),coordinator:h.clone(),session:h.clone(),target:SignerContinueRoleV1::Signer1,purpose:RetirementPurpose::FinancialContinuation,binding_digest:h.clone(),
            witness_instance:h.clone(),challenge:h,cleanup_ceiling_ms:5_000,signing:None};
        r.validate(clocks).unwrap();let mut bad=r.clone();bad.profile="another-profile".into();assert!(bad.validate(clocks).is_err());
        bad=r.clone();bad.challenge="".into();assert!(bad.validate(clocks).is_err());
        bad=r.clone();bad.cleanup_ceiling_ms=1_805_001;assert!(bad.validate(clocks).is_err());
        let text=serde_json::to_string(&r).unwrap();let bad=text.replacen('{',"{\"caller_permission\":true,",1);
        assert!(serde_json::from_str::<RetirementRequest>(&bad).is_err());
    }
}
