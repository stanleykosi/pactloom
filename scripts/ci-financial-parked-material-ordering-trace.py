#!/usr/bin/env python3
"""Private exact-method ordering reproduction; inert time/control carriers only.

No native authority, authentic Resume, process liveness or initiating-cause
claim. Default operation extracts source only. --run is an explicit focused
cloud test invocation, never a product build or runtime attempt.
"""
import argparse,hashlib,json,os,re,selectors,shutil,subprocess,sys,time
from pathlib import Path
DEFAULT_SOURCE=Path(__file__).resolve().parents[1]
ORIGIN='crates/wholepact-financial-coordinator-origin/src/'
HOST='crates/wholepact-native-host/src/'
WAIT=HOST+'host/financial/durable_delivery_admission_v2/closed_review_v3/coordinated_owner_workflow_wait_v1.rs'
MATERIAL=HOST+'host/financial/durable_delivery_admission_v2/closed_review_v3/retained_result_v1.rs'
DIAG=ORIGIN+'financial_ci_host_diagnostics.rs'
BOUNDS=HOST+'terminal/original_prompt_bounds_v1.rs'
NATIVE=HOST+'financial_ci_host_failure.rs'
INTERSTAGE=ORIGIN+'host_interstage.rs'
RELAY=ORIGIN+'financial_workflow_origin.rs'
LATER=HOST+'host/financial/retained_foreground_v1.rs'
ERROR=HOST+'lib.rs'
PINS={MATERIAL:'5746b0be4b3da8f3146ebcd27d3d362c09ce5318ff40da550f35317c5cc392d1',WAIT:'af1f16cef7d3b28ab5e866576a975c0387f330e2d44767f23641ea219cb63b25',DIAG:'edfe0a6ec185645c9c6d64edd5e4d1a1f01e3de17312d1c370bed02050a9de04',BOUNDS:'85ccb0583f6674cf6525c7e2d2ad688d826df907e79df12b33ece9c538042f91',NATIVE:'baf9e6566ecc693bdd59249caff25997afcb458d895a96535778d6952f4efc25',INTERSTAGE:'a95b64b3d4e4c2edcd6e0bbb082b7e3b48c02f8e6c2b71d29d89be119b8a758d',RELAY:'2f878955c8a2ebe5bc5081710cf3b64ec953c924aaefc31ae83ee418fb59d96f',LATER:'95b43c94b6a6bc305795f2cfa3d99b6157d7c7ae5828e6d57284b330c8b8799d',ERROR:'58e04cca7f423e321291966b603dff34d6a31b3f147567780818cd8e604d1f01'}
CANDIDATE_PINS={**PINS,MATERIAL:'951fb5bc1113f00147c9e27e5fba0446dee7e5be77d9b00466591700628d24a0',DIAG:'236a6294388e01f5d5ab5002a6c12042eacac0aebf52ae756cc1671402c9962c'}
RUSTC_VERSION='rustc 1.99.0 (b940084d7 2026-09-28)'
RUSTC_HOST='x86_64-unknown-linux-gnu'
GENERATED_RUST_SHA256='fe22fe83ca9309bad499590e2a90076f2206c0f0f146afd4c6d5d90e7c1a2cad'
MAX_LOG_BYTES=2*1024*1024
BEFORE='    pub(super) fn check_parked_wait_bounds(&self) -> Result<()> {\n        self.bounds.check()\n    }'
AFTER='    pub(super) fn check_parked_wait_bounds(&self) -> Result<()> {\n        let result = self.bounds.check();\n        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        if let Err(error) = &result {\n            crate::financial_ci_host_failure::native(\n                crate::financial_ci_host_failure::Stage::ParkedMaterialBounds, error,\n            );\n        }\n        result\n    }'

def sha(raw):return hashlib.sha256(raw if isinstance(raw,bytes) else raw.encode()).hexdigest()
def block(text,needle):
 assert text.count(needle)==1,('nonunique',needle)
 start=text.index(needle);brace=text.index('{',start);depth=0
 for i in range(brace,len(text)):
  depth+=(text[i]=='{')-(text[i]=='}')
  if depth==0:return text[start:i+1]
 raise AssertionError(('unclosed',needle))
def extract(source):
 source=Path(source)
 new={p:(source/p).read_bytes().decode('utf-8') for p in PINS}
 assert {p:sha(v) for p,v in new.items()}==CANDIDATE_PINS, 'candidate full-source byte drift'
 assert new[MATERIAL].count(AFTER)==1 and BEFORE not in new[MATERIAL], 'unique parked replacement absent'
 suffix=', RelayPump, RelayFinish, ParkedMaterialBounds});'
 assert new[DIAG].count(suffix)==1, 'unique appended Stage absent'
 old=dict(new)
 old[MATERIAL]=new[MATERIAL].replace(AFTER,BEFORE,1)
 old[DIAG]=new[DIAG].replace(suffix,', RelayPump, RelayFinish});',1)
 assert {p:sha(v) for p,v in old.items()}==PINS, 'whole-file P90 inverse drift'
 needle='    pub(super) fn check_parked_wait_bounds(&self) -> Result<()>'
 prior,current=block(old[MATERIAL],needle),block(new[MATERIAL],needle)
 assert (prior,current)==(BEFORE,AFTER)
 assert current.count('self.bounds.check()')==1 and current.count('::native(')==1
 return old,new,prior,current

PREFIX=r'''#![allow(dead_code)]
use std::{cell::{Cell,RefCell},collections::VecDeque,marker::PhantomData,rc::Rc,sync::{Arc,Barrier,atomic::{AtomicU8,AtomicUsize,Ordering}}};
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
impl Instant{fn now()->Self{trace("monotonic");Self(MONO.with(Cell::get))}}
struct SystemTime(Option<u128>);struct WallDuration(u128);const UNIX_EPOCH:SystemTime=SystemTime(Some(0));
impl SystemTime{fn now()->Self{trace("wall");Self(WALL.with(|v|v.borrow_mut().pop_front()).unwrap_or(Some(150)))}fn duration_since(self,_:SystemTime)->std::result::Result<WallDuration,()>{self.0.map(WallDuration).ok_or(())}}
impl WallDuration{fn as_millis(&self)->u128{self.0}}
thread_local!{static MONO:Cell<u64>=const{Cell::new(1)};static WALL:RefCell<VecDeque<Option<u128>>>=RefCell::new(VecDeque::new());static CALLS:RefCell<Vec<&'static str>>=RefCell::new(Vec::new());}
fn trace(v:&'static str){CALLS.with(|c|c.borrow_mut().push(v));}
fn reset(mono:u64,walls:&[Option<u128>]){MONO.with(|v|v.set(mono));WALL.with(|v|*v.borrow_mut()=walls.iter().copied().collect());CALLS.with(|v|v.borrow_mut().clear());financial_ci_host_diagnostics::reset_test_slots();}
mod fake_thread{pub fn sleep(duration:std::time::Duration){crate::trace("sleep");crate::MONO.with(|v|v.set(v.get()+duration.as_millis()as u64));}}
mod libc{pub unsafe fn getpid()->i32{101}}
mod process{pub enum Role{Coordinator,Host,Other}}
__ERROR__
type Result<T>=std::result::Result<T,Error>;
__FROM_IO__
mod terminal{use crate::{Error,Result,Instant,SystemTime,UNIX_EPOCH};
#[derive(Clone,Copy)] __BOUNDS_STRUCT__
__BOUNDS_IMPL__
}
#[derive(Clone,Copy)]struct Plan{idle:usize,next_error:bool,resume_error:bool}
impl Default for Plan{fn default()->Self{Self{idle:0,next_error:false,resume_error:false}}}
mod wholepact_financial_coordinator_origin{
 use super::*;type Result<T>=std::io::Result<T>;
 fn rejected(s:&'static str)->std::io::Error{std::io::Error::new(std::io::ErrorKind::PermissionDenied,s)}
 const RUNNING:u8=0;const PARKED:u8=1;const RESUMED:u8=5;const POISON:u8=255;
 #[derive(Clone,Copy,PartialEq)]pub enum SignerContinueRoleV1{Signer1,Signer2}
 #[derive(Clone,Copy,PartialEq)]enum RetirementPurpose{InitialHistory}
 struct RetirementRequest{target:SignerContinueRoleV1,purpose:RetirementPurpose}
 pub(super) struct HostLifecycle{state:AtomicU8,plan:Plan,polls:AtomicUsize,host_drops:Arc<AtomicUsize>}
 impl HostLifecycle{
  pub(super) fn inert(plan:Plan)->Arc<Self>{Arc::new(Self{state:AtomicU8::new(PARKED),plan,polls:AtomicUsize::new(0),host_drops:Arc::new(AtomicUsize::new(0))})}
__POISON__
__CHECK_NOT_POISONED__
  pub(super) fn phase(&self)->u8{self.state.load(Ordering::SeqCst)}
  pub(super) fn host_drops(&self)->usize{self.host_drops.load(Ordering::Relaxed)}
 }
__FOREGROUND_STRUCT__
__FOREGROUND_DROP__
__INTERSTAGE_STRUCT__
__INTERSTAGE_DROP__
__GUARD_STRUCT__
__GUARD_DROP__
 impl HostFinancialInterstageWaitV1{
  pub(super) fn inert(state:Arc<HostLifecycle>)->Self{Self{state,consumed:false,_thread:PhantomData}}
  // Inert request/Resume delegates. They prove no authenticated control traffic.
  pub fn try_next_retirement(&mut self)->Result<Option<HostWitnessRetirementGuardV1<'_>>>{trace("next");if self.state.plan.next_error{return Err(rejected("inert next denial"));}let poll=self.state.polls.fetch_add(1,Ordering::Relaxed);if poll<self.state.plan.idle{return Ok(None);}Ok(Some(HostWitnessRetirementGuardV1{wait:self,request:RetirementRequest{target:SignerContinueRoleV1::Signer1,purpose:RetirementPurpose::InitialHistory},consumed:false}))}
  pub fn leave_after_resume(mut self)->Result<HostFinancialForegroundV1>{trace("leave");assert_eq!(self.state.phase(),RESUMED);self.state.state.store(RUNNING,Ordering::SeqCst);self.consumed=true;Ok(HostFinancialForegroundV1{state:Arc::clone(&self.state),consumed:false,_thread:PhantomData})}
 }
 impl HostWitnessRetirementGuardV1<'_>{
__INITIAL_RESUME__
  fn wait_resume(mut self)->Result<()>{trace("resume");if self.wait.state.plan.resume_error{return Err(rejected("inert Resume denial"));}self.wait.state.state.store(RESUMED,Ordering::SeqCst);self.consumed=true;Ok(())}
 }
 pub mod financial_ci_host_diagnostics{
  use std::sync::atomic::{AtomicI32,AtomicU32,AtomicU8,Ordering};use crate::libc;
__CODES_MACRO__
__STAGE__
__CLASS__
__RELAY_STAGE__
__REAP_CONTEXT__
__CLASSIFY_IO__
#[derive(Clone,Copy,Debug,PartialEq,Eq)] __FAILURE_FACTS__
#[derive(Clone,Copy,Debug,PartialEq,Eq)] __RELAY_FACTS__
__SLOTS_STRUCT__
impl Slots{
__SLOTS_METHODS__
}
static SLOTS:Slots=Slots::new();
__LATCH_FAILURE__
__LATCH_RELAY__
__SAMPLE_FAILURE__
pub(crate) fn reset_test_slots(){SLOTS.pid.store(0,Ordering::Relaxed);SLOTS.enter(101,2);}
 }
 pub(super) struct InertHost(Arc<AtomicUsize>);
 impl Drop for InertHost{fn drop(&mut self){self.0.fetch_add(1,Ordering::Relaxed);}}
 pub(super) struct Relay{lifecycle:Arc<HostLifecycle>,host:Option<InertHost>}
__RELAY_MACRO__
 impl Relay{
  pub(super) fn inert(lifecycle:Arc<HostLifecycle>)->Self{Self{host:Some(InertHost(lifecycle.host_drops.clone())),lifecycle}}
__RELAY_PUMP__
  fn pump_inner(&mut self)->Result<bool>{
__RELAY_FIRST_CHECK__
   Ok(false)
  }
 }
}
use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics;
mod financial_ci_host_failure{
use crate::Error;use crate::wholepact_financial_coordinator_origin;
pub(crate) use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::Stage;
use wholepact_financial_coordinator_origin::financial_ci_host_diagnostics::{Class,latch_failure,classify_io};
__NATIVE__
__NATIVE_CLASS__
}
mod host{pub mod financial{use crate::*;
__LEGACY_MODULE__
__CANDIDATE_MODULE__
pub(crate) fn owned(legacy:bool,state:Arc<wholepact_financial_coordinator_origin::HostLifecycle>)->Result<()>{if legacy{legacy::owned(state)}else{candidate::owned(state)}}
}}
fn outer(error:Error)->Error{
__OUTER_LATCH__
error
}
#[derive(Debug,PartialEq,Eq)]struct Snapshot{error:Option<&'static str>,calls:Vec<&'static str>,phase:u8,host_drops:usize,before_relay:Option<financial_ci_host_diagnostics::FailureFacts>,after_relay:Option<financial_ci_host_diagnostics::FailureFacts>}
fn run(legacy:bool,mono:u64,walls:&[Option<u128>],plan:Plan,compete:bool,earlier:bool)->Snapshot{
 reset(mono,walls);
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]if earlier{financial_ci_host_diagnostics::latch_failure(financial_ci_host_diagnostics::Stage::HostOpen,financial_ci_host_diagnostics::Class::Terminal);}
 let _=earlier;let state=wholepact_financial_coordinator_origin::HostLifecycle::inert(plan);
 let result=host::financial::owned(legacy,state.clone());
 let before_relay=financial_ci_host_diagnostics::sample_failure();
 let error=match result{Err(error)=>{
  // The actual owning method returned Err only after actual self Drop poisoned.
  assert_eq!(state.phase(),255);
  if compete{let start=Arc::new(Barrier::new(2));let finished=Arc::new(Barrier::new(2));let a=start.clone();let b=finished.clone();let lifecycle=state.clone();let relay=std::thread::spawn(move||{a.wait();let mut relay=wholepact_financial_coordinator_origin::Relay::inert(lifecycle);assert_eq!(relay.pump().unwrap_err().kind(),std::io::ErrorKind::PermissionDenied);b.wait();});start.wait();finished.wait();relay.join().unwrap();}
  let error=outer(error);Some(match error{Error::Permission=>"Permission",Error::Storage=>"Storage",_=>panic!("unexpected original error")})
 },Ok(())=>None};
 Snapshot{error,calls:CALLS.with(|v|v.borrow().clone()),phase:state.phase(),host_drops:state.host_drops(),before_relay,after_relay:financial_ci_host_diagnostics::sample_failure()}
}
'''

OWNER_MODULE=r'''
mod __NAME__{use super::*;use crate::fake_thread as thread;use std::time::Duration;
use wholepact_financial_coordinator_origin::{HostFinancialForegroundV1,HostFinancialInterstageWaitV1};
__MATERIAL_STRUCT__
impl HostMaterialDeliveryRestrictionV1{
__MATERIAL_CHECK__
}
struct RetainedOriginalCoordinatedAdmissionV1<'host>{material_delivery_restriction:HostMaterialDeliveryRestrictionV1,_host:PhantomData<&'host ()>}
impl Drop for RetainedOriginalCoordinatedAdmissionV1<'_>{fn drop(&mut self){trace("admission_drop");}}
__OWNER_STRUCT__
impl<'host> RetainedCoordinatedOwnerWorkflowWaitV1<'host>{
__OWNER_METHODS__
}
pub(super) fn owned(state:Arc<wholepact_financial_coordinator_origin::HostLifecycle>)->Result<()>{
 let restriction=HostMaterialDeliveryRestrictionV1{original_deadline:Instant(100),bounds:terminal::OriginalPromptBoundsV1::new(Instant(100),(100,200))?};
 let owner=RetainedCoordinatedOwnerWorkflowWaitV1{wait:HostFinancialInterstageWaitV1::inert(state.clone()),admission:RetainedOriginalCoordinatedAdmissionV1{material_delivery_restriction:restriction,_host:PhantomData}};
 let owner=owner.wait_for_initial_history_retirement(wholepact_financial_coordinator_origin::SignerContinueRoleV1::Signer1)?;
 let (admission,foreground)=owner.leave_after_resume()?;assert_eq!(state.phase(),0);trace("continued");
 drop(admission);drop(foreground);Ok(())
}
}
'''

TESTS=r'''
#[test]fn legacy_outer_diagnostic_is_masked_by_actual_relay_after_owned_drop(){let s=run(true,100,&[Some(150)],Plan::default(),true,false);assert_eq!(s.error,Some("Permission"));assert_eq!(s.phase,255);assert_eq!(s.host_drops,1);assert!(s.before_relay.is_none());#[cfg(wholepact_financial_rendered_host_semantic_ci)]{let f=s.after_relay.unwrap();assert_eq!((f.stage,f.class),("RelayPump","IoPermissionDenied"));assert_eq!(f.relay.unwrap().stage,"LifecycleCheck");}#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]assert!(s.after_relay.is_none());}
#[test]fn candidate_preserves_parked_operation_before_competing_relay_and_outer(){let s=run(false,100,&[Some(150)],Plan::default(),true,false);assert_eq!(s.error,Some("Permission"));assert_eq!(s.phase,255);assert_eq!(s.host_drops,1);#[cfg(wholepact_financial_rendered_host_semantic_ci)]{let before=s.before_relay.unwrap();assert_eq!((before.stage,before.class),("ParkedMaterialBounds","Permission"));assert!(before.relay.is_none());let after=s.after_relay.unwrap();assert_eq!((after.stage,after.class),("ParkedMaterialBounds","Permission"));assert_eq!((after.relay.unwrap().stage,after.relay.unwrap().class),("LifecycleCheck","IoPermissionDenied"));}#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]{assert!(s.before_relay.is_none());assert!(s.after_relay.is_none());}}
#[test]fn all_original_clock_and_wall_read_denials_keep_same_error_calls_and_poison(){for (mono,wall) in [(100,Some(150)),(1,Some(99)),(1,Some(200)),(1,None),(1,Some(u64::MAX as u128+1))]{let old=run(true,mono,&[wall],Plan::default(),true,false);let new=run(false,mono,&[wall],Plan::default(),true,false);assert_eq!((&old.error,&old.calls,old.phase,old.host_drops),(&new.error,&new.calls,new.phase,new.host_drops));assert_eq!(new.error,Some("Permission"));assert_eq!(new.calls,if wall.is_none()||wall.unwrap()>u64::MAX as u128{vec!["wall","admission_drop"]}else{vec!["wall","monotonic","admission_drop"]});}}
#[test]fn healthy_idle_poll_resume_and_leave_remain_silent_and_identical(){for idle in [0,1]{let plan=Plan{idle,..Plan::default()};let old=run(true,1,&[],plan,true,false);let new=run(false,1,&[],plan,true,false);assert_eq!(old,new);assert!(new.error.is_none());assert!(new.before_relay.is_none());assert!(new.after_relay.is_none());assert_eq!(new.calls.iter().filter(|&&v|v=="wall").count(),3+idle);assert_eq!(new.calls.iter().filter(|&&v|v=="monotonic").count(),3+idle);assert_eq!(new.calls.iter().filter(|&&v|v=="sleep").count(),idle);assert!(new.calls.contains(&"continued"));assert_eq!(new.phase,255);}}
#[test]fn later_poll_and_post_resume_clock_denials_keep_original_drop_semantics(){for (walls,idle) in [(vec![Some(150),Some(200)],1),(vec![Some(150),Some(200)],0),(vec![Some(150),Some(150),Some(200)],0)]{let plan=Plan{idle,..Plan::default()};let old=run(true,1,&walls,plan,true,false);let new=run(false,1,&walls,plan,true,false);assert_eq!((&old.error,&old.calls,old.phase,old.host_drops),(&new.error,&new.calls,new.phase,new.host_drops));assert_eq!(new.error,Some("Permission"));assert!(!new.calls.contains(&"continued"));#[cfg(wholepact_financial_rendered_host_semantic_ci)]assert_eq!(new.before_relay.unwrap().stage,"ParkedMaterialBounds");}}
#[test]fn existing_first_failure_survives_new_bounds_relay_and_outer_observers(){let s=run(false,100,&[Some(150)],Plan::default(),true,true);#[cfg(wholepact_financial_rendered_host_semantic_ci)]{assert_eq!((s.before_relay.unwrap().stage,s.before_relay.unwrap().class),("HostOpen","Terminal"));assert_eq!((s.after_relay.unwrap().stage,s.after_relay.unwrap().class),("HostOpen","Terminal"));assert_eq!(s.after_relay.unwrap().relay.unwrap().stage,"LifecycleCheck");}#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]assert!(s.after_relay.is_none());}
#[test]fn original_control_delegate_errors_do_not_become_material_bounds_failures(){for plan in [Plan{next_error:true,..Plan::default()},Plan{resume_error:true,..Plan::default()}]{let old=run(true,1,&[],plan,true,false);let new=run(false,1,&[],plan,true,false);assert_eq!(old,new);assert_eq!(new.error,Some("Storage"));assert!(new.before_relay.is_none());assert_eq!(new.phase,255);#[cfg(wholepact_financial_rendered_host_semantic_ci)]assert_eq!(new.after_relay.unwrap().stage,"RelayPump");}}
#[test]fn without_competing_relay_legacy_later_workflow_and_candidate_local_stage_differ_only_in_diagnostic(){let old=run(true,100,&[Some(150)],Plan::default(),false,false);let new=run(false,100,&[Some(150)],Plan::default(),false,false);assert_eq!((&old.error,&old.calls,old.phase,old.host_drops),(&new.error,&new.calls,new.phase,new.host_drops));#[cfg(wholepact_financial_rendered_host_semantic_ci)]{assert_eq!(old.after_relay.unwrap().stage,"LaterWorkflow");assert_eq!(new.after_relay.unwrap().stage,"ParkedMaterialBounds");assert!(new.after_relay.unwrap().relay.is_none());}}
'''

TEST_NAMES={'without_competing_relay_legacy_later_workflow_and_candidate_local_stage_differ_only_in_diagnostic', 'later_poll_and_post_resume_clock_denials_keep_original_drop_semantics', 'healthy_idle_poll_resume_and_leave_remain_silent_and_identical', 'existing_first_failure_survives_new_bounds_relay_and_outer_observers', 'legacy_outer_diagnostic_is_masked_by_actual_relay_after_owned_drop', 'candidate_preserves_parked_operation_before_competing_relay_and_outer', 'original_control_delegate_errors_do_not_become_material_bounds_failures', 'all_original_clock_and_wall_read_denials_keep_same_error_calls_and_poison'}

def generate(source,out):
 source,out=Path(source),Path(out)
 old,new,prior,current=extract(source);pieces={}
 def keep(name,text):pieces[name]=text;return text
 e=keep('native_error_enum',block(old[ERROR],'pub enum Error {'))
 e='#[derive(Debug,PartialEq,Eq)]\n'+re.sub(r'\s*#\[error\([\s\S]*?\)\]','',e)
 pieces['native_error_enum_test_adaptation']=e
 values={'ERROR':e,'FROM_IO':keep('native_io_conversion',block(old[ERROR],'impl From<std::io::Error> for Error {')),
 'BOUNDS_STRUCT':keep('bounds_struct',block(old[BOUNDS],'pub(crate) struct OriginalPromptBoundsV1 {')),
 'BOUNDS_IMPL':keep('bounds_impl',block(old[BOUNDS],'impl OriginalPromptBoundsV1 {'))}
 for key,needle in [('POISON','    pub(super) fn poison(&self)'),('CHECK_NOT_POISONED','    pub(super) fn check_not_poisoned(&self)'),('FOREGROUND_STRUCT','pub struct HostFinancialForegroundV1{'),('FOREGROUND_DROP','impl Drop for HostFinancialForegroundV1{'),('INTERSTAGE_STRUCT','pub struct HostFinancialInterstageWaitV1{'),('INTERSTAGE_DROP','impl Drop for HostFinancialInterstageWaitV1{'),('GUARD_STRUCT',"pub struct HostWitnessRetirementGuardV1<'a>{"),('GUARD_DROP',"impl Drop for HostWitnessRetirementGuardV1<'_>{"),('INITIAL_RESUME','    pub fn wait_initial_history_resume(')]:values[key]=keep(key.lower(),block(old[INTERSTAGE],needle))
 values['CODES_MACRO']=keep('codes_macro',block(new[DIAG],'macro_rules! codes '))
 for key,enum in [('STAGE','Stage'),('CLASS','Class'),('RELAY_STAGE','RelayStage'),('REAP_CONTEXT','ReapContext')]:values[key]=keep(key.lower(),block(new[DIAG],'codes!('+enum+' {')+');')
 for key,needle in [('CLASSIFY_IO','pub fn classify_io('),('FAILURE_FACTS','pub(crate) struct FailureFacts '),('RELAY_FACTS','pub(crate) struct RelayFacts '),('SLOTS_STRUCT','struct Slots '),('LATCH_FAILURE','pub fn latch_failure('),('LATCH_RELAY','pub(crate) fn latch_relay('),('SAMPLE_FAILURE','pub(crate) fn sample_failure()')]:values[key]=keep(key.lower(),block(new[DIAG],needle))
 slots=block(new[DIAG],'impl Slots {')
 values['SLOTS_METHODS']='\n'.join(keep('slot_'+name,block(slots,needle)) for name,needle in [('new',' const fn new()'),('enter',' fn enter('),('active',' fn active('),('failure',' fn failure('),('relay',' fn relay('),('sample_relay',' fn sample_relay('),('sample_failure',' fn sample_failure(')])
 values['NATIVE']=keep('native_latch',block(old[NATIVE],'pub(crate) fn native('))
 values['NATIVE_CLASS']=keep('native_class',block(old[NATIVE],'fn class('))
 values['RELAY_MACRO']=keep('relay_macro',block(old[RELAY],'macro_rules! relay_boundary '))
 values['RELAY_PUMP']=keep('relay_pump',block(old[RELAY],'    pub fn pump(&mut self)->Result<bool>'))
 first='        relay_boundary!(LifecycleCheck,self.lifecycle.check_not_poisoned())?;'
 assert old[RELAY].count(first)==1;values['RELAY_FIRST_CHECK']=keep('relay_first_check',first)
 outer='''            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            crate::financial_ci_host_failure::native(crate::financial_ci_host_failure::Stage::LaterWorkflow,&error);'''
 assert old[LATER].count(outer)==1;values['OUTER_LATCH']=keep('outer_latch',outer)
 owner_struct=keep('owner_struct',block(old[WAIT],"pub(in crate::host::financial) struct RetainedCoordinatedOwnerWorkflowWaitV1<'host> {"))
 owner_impl=block(old[WAIT],"impl<'host> RetainedCoordinatedOwnerWorkflowWaitV1<'host> {")
 methods='\n'.join(keep('owner_'+name,block(owner_impl,needle)) for name,needle in [('wait_for_initial_history_retirement','    pub(in crate::host::financial) fn wait_for_initial_history_retirement('),('wait_for_original_resume','    fn wait_for_original_resume('),('leave_after_resume','    pub(in crate::host::financial) fn leave_after_resume(')])
 material_struct=keep('material_struct',block(old[MATERIAL],'pub(super) struct HostMaterialDeliveryRestrictionV1 {'))
 for name,method in [('legacy',prior),('candidate',current)]:
  text=OWNER_MODULE
  for key,value in {'NAME':name,'MATERIAL_STRUCT':material_struct,'MATERIAL_CHECK':keep(name+'_material_check',method),'OWNER_STRUCT':owner_struct,'OWNER_METHODS':methods}.items():text=text.replace('__'+key+'__',value)
  values[name.upper()+'_MODULE']=text
 rust=PREFIX
 for key,value in values.items():rust=rust.replace('__'+key+'__',value)
 assert not re.search(r'__[A-Z_]+__',rust)
 rust+='\n'+TESTS
 assert set(re.findall(r'#\[test\]fn ([a-z0-9_]+)',TESTS))==TEST_NAMES and len(TEST_NAMES)==8, 'test selection drift'
 assert sha(rust)==GENERATED_RUST_SHA256, 'reviewed Rust bytes drift'
 out.mkdir(parents=True,exist_ok=False)
 (out/'parked-material-ordering.rs').write_text(rust)
 binding={'source':str(source),'baseline':'P90 reconstructed by exact whole-file inverse','baseline_sha256':PINS,'candidate_sha256':CANDIDATE_PINS,'pieces':{name:sha(text) for name,text in pieces.items()},'rust_sha256':sha(rust),'test_names':sorted(TEST_NAMES),'test_count':8,'whole_file_inverses':True,'executed':False,'limits':'Exact affected methods/first-wins/poison/relay wrapper; modeled clocks, process identity, request/Resume delegates and Host payload. No authority, actual cleanup/reap, initiating cause, signer fix or full-flow proof.','adaptations':['Original Error enum: remove thiserror formatting attributes, add test equality derives; variants unchanged.','Failure/RelayFacts: omit serde derive only.','Test-only time/control carriers; actual transplanted method bodies unchanged.']}
 (out/'binding.json').write_text(json.dumps(binding,indent=2,sort_keys=True)+'\n')
 return binding

class CommandFailure(RuntimeError):
 def __init__(self,reason,returncode=None):
  self.reason=reason;self.returncode=returncode
  super().__init__(reason if returncode is None else reason+': '+str(returncode))

def checked(command,path,timeout):
 # Existing admit-read bounded-drain design; never retain more than 2 MiB.
 chunks=[];size=0;failure=None;status=None;deadline=time.monotonic()+timeout
 try:proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 except OSError as error:path.write_text(str(error)+'\n');raise
 selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
 try:
  while selector.get_map():
   remaining=deadline-time.monotonic()
   if remaining<=0:failure='timed_out';break
   for key,_ in selector.select(min(remaining,1)):
    data=os.read(key.fd,65536)
    if not data:selector.unregister(key.fileobj);continue
    if size+len(data)>MAX_LOG_BYTES:
     chunks.append(data[:MAX_LOG_BYTES-size]);failure='output_limit';break
    chunks.append(data);size+=len(data)
   if failure:break
  if failure:proc.kill()
  try:status=proc.wait(timeout=max(0.001,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:proc.kill();proc.wait();failure='timed_out'
 finally:
  if proc.poll() is None:proc.kill();proc.wait()
  selector.close();proc.stdout.close();path.write_bytes(b''.join(chunks))
 if failure or status:
  print(path.read_bytes()[-16384:].decode(errors='replace'),file=sys.stderr)
  raise CommandFailure(failure or 'nonzero',status)
 return path.read_bytes().decode('utf-8')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--source',type=Path,default=DEFAULT_SOURCE)
 p.add_argument('--out',type=Path,required=True)
 p.add_argument('--run',action='store_true',help='Explicit focused test invocation in an authorized environment')
 p.add_argument('--rustc',default='rustc',help='Existing compiler executable or PATH command; never installed here')
 a=p.parse_args();a.source=a.source.resolve();a.out=a.out.resolve()
 binding=generate(a.source,a.out);print(json.dumps({'generated':True,'executed':False,'tests':8}))
 if not a.run:return
 execution=a.out/'execution';execution.mkdir(exist_ok=False)
 receipt={'status':'running','native_execution_attempted':False,'native_listings_completed':[],
          'compiled_profiles':[],'tests_started':[],'profiles_passed':[],
          'rust_sha256':binding['rust_sha256'],'generator_sha256':sha(Path(__file__).read_bytes()),
          'binding_sha256':sha((a.out/'binding.json').read_bytes()),'commands':[],
          'expected_compiler':RUSTC_VERSION,'expected_host':RUSTC_HOST,'tests':sorted(TEST_NAMES),
          'toolchain_provenance':'Invoked executable/proxy hash and reported compiler identity only; official installation custody is the caller responsibility.'}
 def retain():
  receipt['logs']={f.name:sha(f.read_bytes()) for f in sorted(execution.glob('*.log'))}
  (execution/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
 def invoke(command,log,timeout,kind,profile=None):
  entry={'argv':command,'log':log,'timeout_seconds':timeout,'kind':kind,'profile':profile,'status':'attempted'}
  receipt['commands'].append(entry)
  if kind in ('list','tests'):receipt['native_execution_attempted']=True
  if kind=='tests':receipt['tests_started'].append(profile)
  retain();start=time.monotonic()
  try:text=checked(command,execution/log,timeout)
  except BaseException as error:
   entry.update(status=getattr(error,'reason','failed'),error_type=type(error).__name__,returncode=getattr(error,'returncode',None));raise
  else:entry.update(status='completed',returncode=0);return text
  finally:entry['elapsed_seconds']=time.monotonic()-start;retain()
 retain()
 try:
  resolved=shutil.which(a.rustc)
  if resolved is None:raise FileNotFoundError('existing rustc executable not found: '+a.rustc)
  rustc=str(Path(resolved).absolute())
  receipt['invoked_executable']={'path':rustc,'sha256':sha(Path(rustc).read_bytes()),'may_be_rustup_proxy':True};retain()
  version=invoke([rustc,'--version'],'compiler-version.log',15,'version').strip();receipt['compiler']=version
  if version!=RUSTC_VERSION:raise RuntimeError('wrong rustc identity: '+version)
  verbose=invoke([rustc,'-Vv'],'compiler-verbose.log',15,'verbose')
  if verbose.splitlines().count('host: '+RUSTC_HOST)!=1:raise RuntimeError('wrong rustc host')
  for profile,flags in [('production',[]),('semantic',['--cfg','wholepact_financial_rendered_host_semantic_ci'])]:
   binary=execution/('tests-'+profile)
   invoke([rustc,'--edition=2021','--test',*flags,str(a.out/'parked-material-ordering.rs'),'-o',str(binary)],profile+'-compile.log',60,'compile',profile)
   receipt['compiled_profiles'].append(profile);retain()
   listing=invoke([str(binary),'--list'],profile+'-list.log',10,'list',profile)
   receipt['native_listings_completed'].append(profile);retain()
   names=[s[:-6] for s in listing.splitlines() if s.endswith(': test')]
   assert len(names)==8 and set(names)==TEST_NAMES, 'compiled test inventory mismatch'
   output=invoke([str(binary),'--test-threads=1'],profile+'-tests.log',30,'tests',profile)
   assert '8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' in output, 'test completion mismatch'
   receipt['profiles_passed'].append(profile);retain()
  extract(a.source)
  assert sha((a.out/'parked-material-ordering.rs').read_bytes())==GENERATED_RUST_SHA256
  receipt['source_pins_after']=True
  receipt['binary_sha256']={profile:sha((execution/('tests-'+profile)).read_bytes()) for profile in receipt['profiles_passed']}
  receipt['status']='success';retain();print(json.dumps({'executed':True,'profiles':2,'tests_per_profile':8}))
 except BaseException as error:
  receipt.update(status=getattr(error,'reason','failed'),error_type=type(error).__name__);retain();raise
if __name__=='__main__':main()
