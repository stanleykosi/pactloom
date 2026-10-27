//! Semantic qualification only. Independent actor-local observations, not causes.
//! Reap/error paths only latch bounded atomics; no allocation, lock, IO or retry.
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU8, Ordering};
macro_rules! codes { ($name:ident {$($code:ident),+ $(,)?}) => {
 #[derive(Clone, Copy, Debug, PartialEq, Eq)] #[repr(u8)]
 pub enum $name {$($code),+}
 impl $name {const NAMES:&'static [&'static str]=&[$(stringify!($code)),+];}
}; }
codes!(Stage {TerminalSetup, OriginalCustody, RelaySetup, StartupSelection, HostOpen, CommandsPath, CommandsFileRead, CommandsDecode, CommandsCheck, Reviewer1Message, Reviewer1EndpointWait, LaterWorkflow, NormalClose, RunnerReturn, PairEndpointValidate, PairScopeValidate, PairOriginalCustody, PairConnect, PairEnableCredentials, PairVerifySigner, PairObservePeer, PairCloneObserver, PairRequestWrite, PairResponseRead, PairResponseDecode, PairResponseValidate, PairResponseDigest, PairChannelDigest, PairInitialCurrent, PairStatusOpen, PairStatusRead, PairStatusDecode, PairStatusValidate, PairFinalCurrent, DeliverySourceOpen, DeliverySourceInspection, DeliverySourcePlan, DeliveryRecipientPrepare, DeliveryExportPreview, DeliveryNativeCheck, DeliverySourceCheck, DeliverySourceScopePredicate, DeliveryProofRolePredicate, DeliveryMaterialActionPredicate, DeliveryMaterialScopePredicate, PreparationSourceBefore, PreparationApproval, PreparationSourceAfter, HistoricalApprovalDeadline, HistoricalApprovalForeground, OriginalDisclosureSelector, MaterialRestrictionCapture, PairConfirmation, ExportRecipientBinding, ExportMetadataSource, ExportMetadataMaterials, ExportMetadataApproval, ExportRecipientBind, ExportFinalApproval, ExportConsent, ExportCommit, ExportVerifiedWait, AdmissionAwaitingAudit, AdmissionUnknown, AdmissionAuditRejected, AdmissionRequestDeadline, AdmissionRequestChannel, AdmissionRequestIntent, AdmissionRequestNonce, AdmissionHistoryIntent, AdmissionHistoryOwner, AdmissionHistoryDeadline, AdmissionHistoryNonce, AdmissionHistoryOpen, AdmissionHistoryCurrent, AdmissionHistoryStatus, AdmissionHistoryPrevious, AdmissionHistoryResponseMatch, AdmissionResponseCheckBefore, AdmissionResponsePeerBefore, AdmissionResponseDeadlineBefore, AdmissionResponseFrame, AdmissionResponseCheckAfter, AdmissionResponsePeerAfter, AdmissionResponseDeadlineAfter, AdmissionResponseDecode, PreparationReadinessCheckBefore, PreparationReadinessPeerBefore, PreparationReadinessDeadlineBefore, PreparationReadinessFrame, PreparationReadinessCheckAfter, PreparationReadinessPeerAfter, PreparationReadinessDeadlineAfter, PreparationReadinessDecode, RelayPump, RelayFinish, ParkedMaterialBounds});
codes!(Class {Platform, Terminal, Permission, Locked, Invalid, Authentication, Storage, Quarantined, Unsupported, Receipt, RecoverySemantic, RecoveryBackupUnsupported, RecoveryFinancialUnsupported, CompleteOriginRecoveryUnavailable, HistoricalExportIncomplete, GenerationArchiveIncomplete, IoNotFound, IoPermissionDenied, IoInterrupted, IoWouldBlock, IoInvalidInput, IoInvalidData, IoUnexpectedEof, IoTimedOut, IoOther, BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit, BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable, BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority, BridgeWallet, BridgeIpc, FrameUnclassified, FrameDeadline, FrameEof, FrameCredentialsMissing, FrameCredentialsMismatch, FrameAncillaryRejected, FrameTruncated, FramePeerNotLive, FrameCurrentCheck, FrameIo, FrameLimit, FrameInvalidFrame, FrameInvalidBudget, EngineDisclosureUnknown, EngineDisclosureDenied, EngineRecoveryRequired, EngineIdempotencyConflict, EngineRevisionConflict, EngineDurableProposalConflict, EngineDurableConstructionUnavailable, EngineDurableProfileUnavailable, EngineResourceExhausted, EngineUnclassified, PredicateDenied});
codes!(RelayStage {LifecycleCheck, DeadlineCheck, HostAbsent, CoordinatorLifetime, Signer1Lifetime, Signer2Lifetime, CoordinatorReceive, NormalControl, CompletedPairControl, RetirementControl, DownstreamValidation, TargetSelection, Signer1Send, Signer2Send, RetirementObservation, NormalObservation, Signer1Receive, Signer2Receive, Signer1UpstreamValidation, Signer2UpstreamValidation, CoordinatorSend, FinalLifecycleCheck});
codes!(ReapContext {FinishPath, DropKillAttempted, RetirementTryReap});
/// Closed IO category only, before any native conversion discards it.
pub fn classify_io(kind:std::io::ErrorKind)->Class {
 use std::io::ErrorKind as K;match kind {
 K::NotFound=>Class::IoNotFound,K::PermissionDenied=>Class::IoPermissionDenied,
 K::Interrupted=>Class::IoInterrupted,K::WouldBlock=>Class::IoWouldBlock,
 K::InvalidInput=>Class::IoInvalidInput,K::InvalidData=>Class::IoInvalidData,
 K::UnexpectedEof=>Class::IoUnexpectedEof,K::TimedOut=>Class::IoTimedOut,_=>Class::IoOther}
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ReapFacts {pub version:u8,pub context:&'static str,pub exit_code:Option<u8>,pub signal:Option<u8>}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct FailureFacts {pub version:u8,pub stage:&'static str,pub class:&'static str,pub relay:Option<RelayFacts>}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RelayFacts {pub stage:&'static str,pub class:&'static str}
struct Slots {pid:AtomicI32,role:AtomicU8,reap:AtomicU32,failure:AtomicU32,relay:AtomicU32}
impl Slots {
 const fn new()->Self {Self {pid:AtomicI32::new(0),role:AtomicU8::new(0),reap:AtomicU32::new(0),failure:AtomicU32::new(0),relay:AtomicU32::new(0)}}
 fn enter(&self,pid:i32,role:u8) {
  if self.pid.load(Ordering::Relaxed)==pid {return;}
  self.pid.store(0,Ordering::Relaxed);self.role.store(role,Ordering::Relaxed);
  self.reap.store(0,Ordering::Relaxed);self.failure.store(0,Ordering::Relaxed);self.relay.store(0,Ordering::Relaxed);
  self.pid.store(pid,Ordering::Release);
 }
 fn active(&self,pid:i32,role:u8)->bool {self.pid.load(Ordering::Acquire)==pid&&self.role.load(Ordering::Relaxed)==role}
 fn reap(&self,pid:i32,context:ReapContext,status:i32) {
  if !self.active(pid,1) {return;}
  if let Some(value)=encode_reap(context,status) {let _=self.reap.compare_exchange(0,value,Ordering::Relaxed,Ordering::Relaxed);}
 }
 fn failure(&self,pid:i32,stage:Stage,class:Class) {
  if self.active(pid,2) {let value=1+(stage as u32)+((class as u32)<<8);let _=self.failure.compare_exchange(0,value,Ordering::Relaxed,Ordering::Relaxed);}
 }
 fn relay(&self,pid:i32,stage:RelayStage,kind:std::io::ErrorKind) {
  if self.active(pid,2) {let value=1+(stage as u32)+((classify_io(kind) as u32)<<8);let _=self.relay.compare_exchange(0,value,Ordering::Relaxed,Ordering::Relaxed);}
 }
 fn sample_relay(&self,pid:i32)->Option<RelayFacts> {
  if !self.active(pid,2){return None;}let value=self.relay.load(Ordering::Relaxed).checked_sub(1)?;
  Some(RelayFacts{stage:*RelayStage::NAMES.get((value&255)as usize)?,class:*Class::NAMES.get((value>>8)as usize)?})
 }
 fn sample_reap(&self,pid:i32)->Option<ReapFacts> {if !self.active(pid,1){return None;}decode_reap(self.reap.load(Ordering::Relaxed))}
 fn sample_failure(&self,pid:i32)->Option<FailureFacts> {
  if !self.active(pid,2){return None;}let value=self.failure.load(Ordering::Relaxed).checked_sub(1)?;
  Some(FailureFacts{version:1,stage:*Stage::NAMES.get((value&255)as usize)?,class:*Class::NAMES.get((value>>8)as usize)?,relay:self.sample_relay(pid)})
 }
}
fn encode_reap(context:ReapContext,status:i32)->Option<u32> {
 let (kind,value)=if libc::WIFEXITED(status){(1,libc::WEXITSTATUS(status))}
 else if libc::WIFSIGNALED(status){let signal=libc::WTERMSIG(status);if !(1..=64).contains(&signal){return None;}(2,signal)}else{return None;};
 Some(((context as u32+1)<<16)|(kind<<8)|value as u32)
}
fn decode_reap(value:u32)->Option<ReapFacts> {
 let context=*ReapContext::NAMES.get(((value>>16).checked_sub(1)?)as usize)?;
 let code=(value&255)as u8;
 let (exit_code,signal)=match (value>>8)&255 {1=>(Some(code),None),2 if (1..=64).contains(&code)=>(None,Some(code)),_=>return None};
 Some(ReapFacts{version:1,context,exit_code,signal})
}
static SLOTS:Slots=Slots::new();
pub(crate) fn enter(role:crate::process::Role) {let role=match role {crate::process::Role::Coordinator=>1,crate::process::Role::Host=>2,_=>0};SLOTS.enter(unsafe{libc::getpid()},role);}
pub(crate) fn reap(child:crate::process::Role,context:ReapContext,status:i32) {if child==crate::process::Role::Host{SLOTS.reap(unsafe{libc::getpid()},context,status);}}
/// Actual propagated error only; payloads must never enter this API.
pub fn latch_failure(stage:Stage,class:Class) {SLOTS.failure(unsafe{libc::getpid()},stage,class);}
/// Independent actual pump failure only; called before original poison/cleanup.
pub(crate) fn latch_relay(stage:RelayStage,error:&std::io::Error) {SLOTS.relay(unsafe{libc::getpid()},stage,error.kind());}
pub(crate) fn sample_reap()->Option<ReapFacts>{SLOTS.sample_reap(unsafe{libc::getpid()})}
pub(crate) fn sample_failure()->Option<FailureFacts>{SLOTS.sample_failure(unsafe{libc::getpid()})}
#[derive(Clone,Copy,Default)]
pub(crate) struct Reporter {attempted:bool}
impl Reporter {
 pub(crate) fn flush<T>(&mut self,facts:Option<T>,mut append:impl FnMut(T)->Result<(),()>) {
  if self.attempted{return;}if let Some(facts)=facts {self.attempted=true;let _=append(facts);}
 }
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn preparation_specific_failure_survives_outer_error_propagation() {
  for stage in [Stage::HistoricalApprovalDeadline, Stage::HistoricalApprovalForeground, Stage::PreparationSourceBefore, Stage::PreparationApproval, Stage::PreparationSourceAfter, Stage::OriginalDisclosureSelector, Stage::MaterialRestrictionCapture, Stage::PairConfirmation] {
   let s=Slots::new(); s.enter(101,2); s.failure(101,stage,Class::Permission);
   s.failure(101,Stage::DeliveryNativeCheck,Class::Permission);
   s.failure(101,Stage::DeliveryExportPreview,Class::EngineDisclosureDenied);
   s.failure(101,Stage::LaterWorkflow,Class::Permission);
   let facts=s.sample_failure(101).unwrap(); assert_eq!(facts.stage,Stage::NAMES[stage as usize]); assert_eq!(facts.class,"Permission");
  }
 }
 #[test] fn relay_top_level_failure_preserves_inner_observation_and_first_failure() {
  for stage in [Stage::RelayPump,Stage::RelayFinish] {
   let s=Slots::new();s.enter(101,2);
   s.relay(101,RelayStage::Signer1Lifetime,std::io::ErrorKind::PermissionDenied);
   s.failure(101,stage,classify_io(std::io::ErrorKind::PermissionDenied));
   s.failure(101,Stage::RunnerReturn,Class::IoOther);
   let facts=s.sample_failure(101).unwrap();
   assert_eq!(facts.stage,Stage::NAMES[stage as usize]);assert_eq!(facts.class,"IoPermissionDenied");
   assert_eq!(facts.relay,Some(RelayFacts{stage:"Signer1Lifetime",class:"IoPermissionDenied"}));
  }
 }
 #[test] fn copied_reporter_records_panicking_or_failed_append_before_second_flush() {
  for panics in [false,true] {
   let s=Slots::new();s.enter(101,2);s.failure(101,Stage::RelayPump,Class::IoPermissionDenied);
   let mut stored=Reporter::default();let mut calls=0;
   let mut reporter=stored;
   reporter.flush(s.sample_failure(101),|_|crate::financial_observer::best_effort_diagnostic_append(|| {
    calls+=1;if panics{panic!("synthetic Host append panic");}Err(())
   }));
   stored=reporter;
   let mut reporter=stored;
   reporter.flush(s.sample_failure(101),|_|{calls+=1;Ok(())});
   stored=reporter;
   assert!(stored.attempted);assert_eq!(calls,1);
  }
 }
 #[test] fn actual_wait_status_classifier() {
  for context in [ReapContext::FinishPath,ReapContext::DropKillAttempted,ReapContext::RetirementTryReap] {
   for code in [0,1,101,255] {let f=decode_reap(encode_reap(context,code<<8).unwrap()).unwrap();assert_eq!(f.exit_code,Some(code as u8));assert_eq!(f.signal,None);assert_eq!(f.context,ReapContext::NAMES[context as usize]);}
   for signal in [6,9,64] {let f=decode_reap(encode_reap(context,signal).unwrap()).unwrap();assert_eq!(f.signal,Some(signal as u8));assert_eq!(f.exit_code,None);}
  }
  for status in [0x137f,0xffff,65] {assert!(encode_reap(ReapContext::FinishPath,status).is_none());}
 }
 #[test] fn roles_pid_inheritance_and_first_value_are_exact() {
  let s=Slots::new();s.enter(101,1);s.reap(102,ReapContext::FinishPath,0);assert!(s.sample_reap(101).is_none());
  s.failure(101,Stage::CommandsDecode,Class::Invalid);assert!(s.sample_failure(101).is_none());
  s.reap(101,ReapContext::FinishPath,256);s.reap(101,ReapContext::DropKillAttempted,9);s.enter(101,1);assert_eq!(s.sample_reap(101).unwrap().exit_code,Some(1));
  s.enter(102,2);assert!(s.sample_reap(102).is_none());s.failure(102,Stage::CommandsDecode,Class::Invalid);s.failure(102,Stage::RunnerReturn,Class::IoOther);assert_eq!(s.sample_failure(102).unwrap().stage,"CommandsDecode");
  s.enter(103,0);s.failure(103,Stage::RunnerReturn,Class::IoOther);assert!(s.sample_failure(103).is_none());
 }
 #[test] fn failed_or_partial_append_never_retried_and_absence_does_not_attempt() {
  let mut r=Reporter::default();let mut calls=0;r.flush(None::<u8>,|_|{calls+=1;Ok(())});assert_eq!(calls,0);
  r.flush(Some(1),|_|{calls+=1;Err(())});r.flush(Some(2),|_|{calls+=1;Ok(())});assert_eq!(calls,1);
 }
 #[test] fn relay_is_independent_first_local_and_cannot_emit_alone() {
  let s=Slots::new();s.enter(7,2);s.relay(7,RelayStage::Signer2Lifetime,std::io::ErrorKind::BrokenPipe);
  assert!(s.sample_failure(7).is_none());s.relay(7,RelayStage::FinalLifecycleCheck,std::io::ErrorKind::PermissionDenied);
  s.failure(7,Stage::Reviewer1EndpointWait,Class::IoPermissionDenied);let f=s.sample_failure(7).unwrap();assert_eq!(f.stage,"Reviewer1EndpointWait");assert_eq!(f.relay.unwrap().stage,"Signer2Lifetime");assert_eq!(f.relay.unwrap().class,"IoOther");
  assert!(s.sample_relay(8).is_none());s.enter(8,1);s.relay(8,RelayStage::CoordinatorReceive,std::io::ErrorKind::TimedOut);assert!(s.sample_relay(8).is_none());
 }
 #[test] fn io_kind_closed_mapping() {
  use std::io::ErrorKind as K;for (kind,class) in [(K::NotFound,Class::IoNotFound),(K::PermissionDenied,Class::IoPermissionDenied),(K::Interrupted,Class::IoInterrupted),(K::WouldBlock,Class::IoWouldBlock),(K::InvalidInput,Class::IoInvalidInput),(K::InvalidData,Class::IoInvalidData),(K::UnexpectedEof,Class::IoUnexpectedEof),(K::TimedOut,Class::IoTimedOut),(K::BrokenPipe,Class::IoOther)] {assert_eq!(classify_io(kind),class);}
 }
 #[test] fn successful_append_never_repeats() {let mut r=Reporter::default();let mut calls=0;for _ in 0..4{r.flush(Some(0),|_|{calls+=1;Ok(())});}assert_eq!(calls,1);}
 #[test] fn wire_shape_has_no_process_or_raw_status() {
  let r=decode_reap(encode_reap(ReapContext::DropKillAttempted,9).unwrap()).unwrap();assert_eq!(serde_json::to_value(r).unwrap(),serde_json::json!({"version":1,"context":"DropKillAttempted","exit_code":null,"signal":9}));
  let s=Slots::new();s.enter(100,2);s.failure(100,Stage::CommandsFileRead,Class::IoNotFound);assert_eq!(serde_json::to_value(s.sample_failure(100)).unwrap(),serde_json::json!({"version":1,"stage":"CommandsFileRead","class":"IoNotFound","relay":null}));
 }
}
