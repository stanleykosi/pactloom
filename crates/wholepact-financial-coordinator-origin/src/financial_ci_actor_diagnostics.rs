//! Semantic qualification only: independent first locally observed errors.
//! Slots contain finite discriminants only, never authority, payloads or global causes.
//! Latches are allocation/lock/IO-free; original getpid binds the actor after fork.
use std::sync::atomic::{AtomicBool,AtomicI32,AtomicU8,AtomicU32,Ordering};
macro_rules! codes { ($name:ident {$($code:ident),+ $(,)?}) => {
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] #[repr(u8)]
 pub enum $name {$($code),+}
 impl $name {const NAMES:&'static [&'static str]=&[$(stringify!($code)),+];}
}; }
codes!(DriverStage {Initialization,OriginalActors,Receive,Handle,Opening,PairBegin,PairPoll,EnrollmentBegin,ReceiptPoll,RedisclosurePoll,StatusPoll,DeliveryPoll,FinancialPoll,FinancialTransport,SourceRetention,WorkUnclassified,Cleanup,DisposalSend,EnrollmentPairingCheck,EnrollmentSessionCheck,EnrollmentPeerCheck,ManifestPairingCheck,ManifestSessionCheck,ManifestPeerCheck,PreconstructionCheck,WitnessWork,LeafProtocol,NormalDispose});
codes!(ListenerStage {BoundsSource,BoundsHost,BoundsStopped,BoundsDeadline,PeerPairLifetime,PeerProcess,PeerRevoked,PeerDeadline,Accept,ReadTimeout,WriteTimeout,EnableCredentials,ObservePeer,OriginalHost,RequestRead,RequestDecode,Mode,GrantId,TokenDigest,GrantLock,GrantMissing,GrantCurrent,GrantPeer,TokenMismatch,RequestValidate,StatusRepeated,StatusNotProved,StatusEnqueue,StatusWrite,PairRepeated,PairScope,PairLabel,PairEnqueue,RequestEnqueue,RequestKind,StreamClone,WorkUnclassified});
codes!(OriginStage {PeerProcessExit,PeerProcessPollError,PeerEdgeClosed,PeerEdgePollError,RootProcessExit,RootProcessPollError,ActorCustody,ActorClosed,SessionDeadline,ActionRevoked,ActionQuiescent,ActionClosing,SharedRestriction,SharedRestrictionCustody,SharedRestrictionDeadline,SharedWallDeadline,SharedWallRead,SharedWallRollback,SourceWallSample,SourceLifetime,SourceAction,PairWallSample,PairChannel,PairAction,PairPhase,WitnessReceive,WitnessWork,LeafStop,LeafExit,ChildBootstrap,WitnessCheck,NormalHandshake,SourceDeadline,ReviewDeadline,AcceptedDeadline,ReadDeadline,ServiceDeadline,BoundDeadline});
codes!(Class {IoNotFound,IoPermissionDenied,IoInterrupted,IoWouldBlock,IoInvalidInput,IoInvalidData,IoUnexpectedEof,IoTimedOut,IoOther,SignerUnavailable,SignerPeerLifetimeUnavailable,SignerAuthentication,SignerInvalidData,SignerCrypto,SignerLocked,SignerBackupRequired,SignerRecoveryRequired,SignerAlreadyOpen,SignerReviewMismatch,SignerVerification,SignerUncertain,SignerConsentJournal,SignerStore,BridgeBinding,BridgeConflict,BridgeMissing,BridgeUncertain,BridgeLimit,BridgePermission,BridgeRecoveryRequired,BridgeCompleteOriginRecoveryUnavailable,BridgeVerification,BridgeSignerOriginUnavailable,BridgeJournal,BridgeAuthority,BridgeWallet,BridgeIpc,FrameUnclassified,FrameDeadline,FrameEof,FrameCredentialsMissing,FrameCredentialsMismatch,FrameAncillaryRejected,FrameTruncated,FramePeerNotLive,FrameCurrentCheck,FrameIo,FrameLimit,FrameInvalidFrame,FrameInvalidBudget,PredicateDenied,ClockExpired,WallRollback,Restricted,Quiescent,Closing,ProcessExited,ProcessPollError,EdgeClosed,EdgePollError,CustodyMismatch,AlreadyClosed,JournalStorage,JournalDatabase,JournalPermission,JournalExpired,JournalRecoveryRequired,JournalUnsupportedSchema,JournalOfflineHistoryUnsupported,JournalNamedRecipientHistoryUnsupported,JournalConstructionHistoryUnsupported,JournalInvalidBinding,JournalConflict,JournalNotFound,JournalLiveAuthorization,JournalInputReserved,JournalBudgetExceeded,JournalLimit});
codes!(PeerRole {Coordinator,Host,Signer1,Signer2,Owner1BootstrapHistory,Owner1V3DeliveryAdmission,Owner1DeliveryAuditHistory,Owner1FinancialReadHistory,Owner1FinancialContinuationAdmission,Owner1FinancialSigning,Owner2BootstrapHistory,Owner2V3DeliveryAdmission,Owner2DeliveryAuditHistory,Owner2FinancialReadHistory,Owner2FinancialContinuationAdmission,Owner2FinancialSigning,CompletedPair});
codes!(ReapContext {FinishPath,DropKillAttempted,RetirementTryReap});

pub fn classify_io(kind:std::io::ErrorKind)->Class {use std::io::ErrorKind as K;match kind {
 K::NotFound=>Class::IoNotFound,K::PermissionDenied=>Class::IoPermissionDenied,K::Interrupted=>Class::IoInterrupted,
 K::WouldBlock=>Class::IoWouldBlock,K::InvalidInput=>Class::IoInvalidInput,K::InvalidData=>Class::IoInvalidData,
 K::UnexpectedEof=>Class::IoUnexpectedEof,K::TimedOut=>Class::IoTimedOut,_=>Class::IoOther}}
impl PeerRole {
 pub(crate) fn from_role(role:crate::process::Role)->Self {match role {
crate::process::Role::Coordinator=>Self::Coordinator,
crate::process::Role::Host=>Self::Host,
crate::process::Role::Signer1=>Self::Signer1,
crate::process::Role::Signer2=>Self::Signer2,
crate::process::Role::Owner1BootstrapHistory=>Self::Owner1BootstrapHistory,
crate::process::Role::Owner1V3DeliveryAdmission=>Self::Owner1V3DeliveryAdmission,
crate::process::Role::Owner1DeliveryAuditHistory=>Self::Owner1DeliveryAuditHistory,
crate::process::Role::Owner1FinancialReadHistory=>Self::Owner1FinancialReadHistory,
crate::process::Role::Owner1FinancialContinuationAdmission=>Self::Owner1FinancialContinuationAdmission,
crate::process::Role::Owner1FinancialSigning=>Self::Owner1FinancialSigning,
crate::process::Role::Owner2BootstrapHistory=>Self::Owner2BootstrapHistory,
crate::process::Role::Owner2V3DeliveryAdmission=>Self::Owner2V3DeliveryAdmission,
crate::process::Role::Owner2DeliveryAuditHistory=>Self::Owner2DeliveryAuditHistory,
crate::process::Role::Owner2FinancialReadHistory=>Self::Owner2FinancialReadHistory,
crate::process::Role::Owner2FinancialContinuationAdmission=>Self::Owner2FinancialContinuationAdmission,
crate::process::Role::Owner2FinancialSigning=>Self::Owner2FinancialSigning,
crate::process::Role::CompletedPair=>Self::CompletedPair,
 }}
}
fn owned(parent:PeerRole,child:PeerRole)->bool {match parent {
 PeerRole::Coordinator=>!matches!(child,PeerRole::Coordinator|PeerRole::Signer1|PeerRole::Signer2),
 PeerRole::Host=>matches!(child,PeerRole::Signer1|PeerRole::Signer2),_=>false}}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) struct Detail {pub stage:&'static str,pub class:&'static str}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) struct OriginDetail {pub stage:&'static str,pub class:&'static str,pub peer:Option<&'static str>}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) struct FailureFacts {pub version:u8,pub driver:Option<Detail>,pub listener:Option<Detail>,pub origin:Option<OriginDetail>}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) struct ReapFacts {pub version:u8,pub child:&'static str,pub context:&'static str,pub exit_code:Option<u8>,pub signal:Option<u8>}
struct Slots {pid:AtomicI32,role:AtomicU8,failed:AtomicBool,driver:AtomicU32,listener:AtomicU32,origin:AtomicU32,reaps:[AtomicU32;17]}
impl Slots {
 const fn new()->Self {Self{pid:AtomicI32::new(0),role:AtomicU8::new(0),failed:AtomicBool::new(false),driver:AtomicU32::new(0),listener:AtomicU32::new(0),origin:AtomicU32::new(0),reaps:[const{AtomicU32::new(0)};17]}}
 fn enter(&self,pid:i32,role:PeerRole) {if self.pid.load(Ordering::Acquire)==pid{return;}self.pid.store(0,Ordering::Release);self.role.store(role as u8,Ordering::Relaxed);self.failed.store(false,Ordering::Relaxed);for s in [&self.driver,&self.listener,&self.origin].into_iter().chain(self.reaps.iter()){s.store(0,Ordering::Relaxed);}self.pid.store(pid,Ordering::Release);}
 fn active(&self,pid:i32)->bool {pid>0&&self.pid.load(Ordering::Acquire)==pid}
 fn latch(&self,pid:i32,slot:&AtomicU32,stage:u8,class:Class,peer:Option<PeerRole>) {if self.active(pid){let value=1+stage as u32+((class as u32)<<8)+(peer.map_or(0,|r|r as u32+1)<<16);let _=slot.compare_exchange(0,value,Ordering::Relaxed,Ordering::Relaxed);}}
 fn mark_failed(&self,pid:i32){if self.active(pid){self.failed.store(true,Ordering::Relaxed);}}
 fn failure(&self,pid:i32)->Option<FailureFacts> {if !self.active(pid)||!self.failed.load(Ordering::Relaxed){return None;}
  let driver=detail(self.driver.load(Ordering::Relaxed),DriverStage::NAMES);
  let listener=detail(self.listener.load(Ordering::Relaxed),ListenerStage::NAMES);
  let raw=self.origin.load(Ordering::Relaxed);let origin=detail(raw,OriginStage::NAMES).map(|d|OriginDetail{stage:d.stage,class:d.class,peer:raw.checked_sub(1).and_then(|v|(v>>16).checked_sub(1)).and_then(|v|PeerRole::NAMES.get(v as usize).copied())});
  if driver.is_none(){return None;}Some(FailureFacts{version:1,driver,listener,origin})}
 fn reap(&self,pid:i32,child:PeerRole,context:ReapContext,status:i32){if !self.active(pid){return;}let parent=self.role.load(Ordering::Relaxed);if parent>=17||!owned(role_from_index(parent).unwrap(),child){return;}if let Some(v)=encode_reap(context,status){let _=self.reaps[child as usize].compare_exchange(0,v,Ordering::Relaxed,Ordering::Relaxed);}}
 fn reaps(&self,pid:i32)->[Option<ReapFacts>;17]{if !self.active(pid){return [None;17];}std::array::from_fn(|i|decode_reap(i,self.reaps[i].load(Ordering::Relaxed)))}
}
fn role_from_index(index:u8)->Option<PeerRole>{match index {0=>Some(PeerRole::Coordinator),1=>Some(PeerRole::Host),2=>Some(PeerRole::Signer1),3=>Some(PeerRole::Signer2),4=>Some(PeerRole::Owner1BootstrapHistory),5=>Some(PeerRole::Owner1V3DeliveryAdmission),6=>Some(PeerRole::Owner1DeliveryAuditHistory),7=>Some(PeerRole::Owner1FinancialReadHistory),8=>Some(PeerRole::Owner1FinancialContinuationAdmission),9=>Some(PeerRole::Owner1FinancialSigning),10=>Some(PeerRole::Owner2BootstrapHistory),11=>Some(PeerRole::Owner2V3DeliveryAdmission),12=>Some(PeerRole::Owner2DeliveryAuditHistory),13=>Some(PeerRole::Owner2FinancialReadHistory),14=>Some(PeerRole::Owner2FinancialContinuationAdmission),15=>Some(PeerRole::Owner2FinancialSigning),16=>Some(PeerRole::CompletedPair), _=>None}}
fn detail(raw:u32,names:&[&'static str])->Option<Detail>{let v=raw.checked_sub(1)?;Some(Detail{stage:*names.get((v&255)as usize)?,class:*Class::NAMES.get(((v>>8)&255)as usize)?})}
fn encode_reap(context:ReapContext,status:i32)->Option<u32>{let(kind,value)=if libc::WIFEXITED(status){(1,libc::WEXITSTATUS(status))}else if libc::WIFSIGNALED(status){let signal=libc::WTERMSIG(status);if !(1..=64).contains(&signal){return None;}(2,signal)}else{return None;};Some(((context as u32+1)<<16)|(kind<<8)|value as u32)}
fn decode_reap(child:usize,v:u32)->Option<ReapFacts>{let context=*ReapContext::NAMES.get(((v>>16).checked_sub(1)?)as usize)?;let code=(v&255)as u8;let(exit_code,signal)=match(v>>8)&255 {1=>(Some(code),None),2 if(1..=64).contains(&code)=>(None,Some(code)),_=>return None};Some(ReapFacts{version:1,child:*PeerRole::NAMES.get(child)?,context,exit_code,signal})}
static SLOTS:Slots=Slots::new();
fn pid()->i32 {unsafe{libc::getpid()}}
pub(crate) fn enter(role:crate::process::Role){SLOTS.enter(pid(),PeerRole::from_role(role));}
/// Actual propagated driver/work error. This is the failure gate, never a Drop hook.
pub fn driver_detail(stage:DriverStage,class:Class){SLOTS.latch(pid(),&SLOTS.driver,stage as u8,class,None);}
pub fn driver(stage:DriverStage,class:Class){driver_detail(stage,class);mark_failed();}
/// Detail only. An ordinary listener stopping during cleanup must not enable failure.
pub fn listener(stage:ListenerStage,class:Class){let p=pid();if SLOTS.active(p)&&matches!(role_from_index(SLOTS.role.load(Ordering::Relaxed)),Some(PeerRole::Signer1|PeerRole::Signer2)){SLOTS.latch(p,&SLOTS.listener,stage as u8,class,None);}}
/// Detail only, captured before existing error conversion/restriction.
pub fn origin(stage:OriginStage,class:Class,peer:Option<PeerRole>){SLOTS.latch(pid(),&SLOTS.origin,stage as u8,class,peer);}
pub fn mark_failed(){SLOTS.mark_failed(pid());}
pub fn work_fallback(stage:DriverStage,error:&std::io::Error){driver(stage,classify_io(error.kind()));}
pub(crate) fn origin_io(stage:OriginStage,error:&std::io::Error,peer:Option<PeerRole>){origin(stage,classify_io(error.kind()),peer);}
pub(crate) fn reap(child:crate::process::Role,context:ReapContext,status:i32){SLOTS.reap(pid(),PeerRole::from_role(child),context,status);}
pub(crate) fn sample_failure()->Option<FailureFacts>{SLOTS.failure(pid())}
pub(crate) fn sample_reaps()->[Option<ReapFacts>;17]{SLOTS.reaps(pid())}
#[derive(Clone,Copy,Default)]pub(crate) struct Reporter{failure_attempted:bool,reap_attempted:u32,failed:bool}
impl Reporter {
 pub(crate) fn flush_failure(&mut self,facts:Option<FailureFacts>,mut append:impl FnMut(FailureFacts)->Result<(),()>){if self.failed||self.failure_attempted{return;}if let Some(facts)=facts{self.failure_attempted=true;if append(facts).is_err(){self.failed=true;}}}
 pub(crate) fn flush_reaps(&mut self,facts:[Option<ReapFacts>;17],mut append:impl FnMut(ReapFacts)->Result<(),()>){if self.failed{return;}for(i,fact)in facts.into_iter().enumerate(){if self.reap_attempted&(1<<i)!=0{continue;}if let Some(fact)=fact{self.reap_attempted|=1<<i;if append(fact).is_err(){self.failed=true;break;}}}}
}

/// Root index comes only from the original C-owned [Host, fixed W] vector.
pub(crate) fn root_peer(index:usize)->Option<PeerRole>{if SLOTS.role.load(Ordering::Relaxed)!=PeerRole::Coordinator as u8{return None;}if index==0{Some(PeerRole::Host)}else{crate::process::WITNESS_ROLES.get(index-1).copied().map(PeerRole::from_role)}}

#[cfg(test)]
mod tests {
 use super::*;
 fn actor(role:PeerRole)->Slots{let s=Slots::new();s.enter(11,role);s}
 fn fail(s:&Slots){s.latch(11,&s.driver,DriverStage::ReceiptPoll as u8,Class::SignerLocked,None);s.mark_failed(11);}
 #[test] fn detail_and_normal_cleanup_never_enable_failure(){let s=actor(PeerRole::Signer1);s.latch(11,&s.listener,ListenerStage::BoundsStopped as u8,Class::PredicateDenied,None);s.latch(11,&s.origin,OriginStage::ActorClosed as u8,Class::AlreadyClosed,None);assert!(s.failure(11).is_none());s.mark_failed(11);assert!(s.failure(11).is_none());}
 #[test] fn actual_work_failure_retains_independent_first_details(){let s=actor(PeerRole::Signer1);s.latch(11,&s.listener,ListenerStage::StatusWrite as u8,Class::BridgeIpc,None);s.latch(11,&s.listener,ListenerStage::BoundsStopped as u8,Class::PredicateDenied,None);s.latch(11,&s.origin,OriginStage::PeerProcessExit as u8,Class::ProcessExited,Some(PeerRole::Host));fail(&s);let f=s.failure(11).unwrap();assert_eq!(f.driver.unwrap().stage,"ReceiptPoll");assert_eq!(f.listener.unwrap().stage,"StatusWrite");assert_eq!(f.origin.unwrap().peer,Some("Host"));}
 #[test] fn nested_driver_detail_requires_propagated_error(){let s=actor(PeerRole::Signer1);s.latch(11,&s.driver,DriverStage::EnrollmentSessionCheck as u8,Class::SignerLocked,None);assert!(s.failure(11).is_none());fail(&s);assert_eq!(s.failure(11).unwrap().driver.unwrap().stage,"EnrollmentSessionCheck");}
 #[test] fn foreign_pid_and_inherited_slots_unavailable(){let s=actor(PeerRole::Signer1);fail(&s);assert!(s.failure(12).is_none());s.latch(12,&s.listener,ListenerStage::StatusWrite as u8,Class::BridgeIpc,None);assert!(s.failure(11).unwrap().listener.is_none());s.enter(12,PeerRole::Signer2);assert!(s.failure(12).is_none());assert!(s.failure(11).is_none());}
 #[test] fn repeated_same_actor_entry_never_resets_or_changes_role(){let s=actor(PeerRole::Coordinator);fail(&s);s.enter(11,PeerRole::Host);assert!(s.failure(11).is_some());s.reap(11,PeerRole::Signer1,ReapContext::FinishPath,0);assert!(s.reaps(11).iter().all(Option::is_none));}
 #[test] fn genuine_owner_only_reaps_exact_children(){for(i,role)in (0..17).filter_map(role_from_index).enumerate(){let s=actor(role);for child in (0..17).filter_map(role_from_index){s.reap(11,child,ReapContext::FinishPath,0);}let count=s.reaps(11).iter().flatten().count();assert_eq!(count,if i==0{14}else if i==1{2}else{0});}}
 #[test] fn zero_exit_is_observed_and_first_actual_status_wins(){let s=actor(PeerRole::Host);s.reap(11,PeerRole::Signer1,ReapContext::FinishPath,0);s.reap(11,PeerRole::Signer1,ReapContext::DropKillAttempted,9);let f=s.reaps(11)[PeerRole::Signer1 as usize].unwrap();assert_eq!(f.exit_code,Some(0));assert_eq!(f.signal,None);assert_eq!(f.context,"FinishPath");}
 #[test] fn status_classifier_accepts_only_exit_or_signal(){for context in [ReapContext::FinishPath,ReapContext::DropKillAttempted,ReapContext::RetirementTryReap]{for code in [0,1,101,255]{assert_eq!(decode_reap(2,encode_reap(context,code<<8).unwrap()).unwrap().exit_code,Some(code as u8));}for signal in [1,6,9,64]{assert_eq!(decode_reap(2,encode_reap(context,signal).unwrap()).unwrap().signal,Some(signal as u8));}}for status in [0x137f,0xffff,65]{assert!(encode_reap(ReapContext::FinishPath,status).is_none());}}
 #[test] fn failed_append_prevents_all_later_retry_or_enrichment(){let s=actor(PeerRole::Host);fail(&s);s.reap(11,PeerRole::Signer1,ReapContext::FinishPath,256);let mut r=Reporter::default();let mut n=0;r.flush_failure(s.failure(11),|_|{n+=1;Err(())});r.flush_failure(s.failure(11),|_|panic!("retry"));r.flush_reaps(s.reaps(11),|_|panic!("append after uncertain failure"));assert_eq!(n,1);}
 #[test] fn successful_final_summary_and_each_reap_emit_once(){let s=actor(PeerRole::Host);fail(&s);s.reap(11,PeerRole::Signer1,ReapContext::FinishPath,0);s.reap(11,PeerRole::Signer2,ReapContext::RetirementTryReap,256);let mut r=Reporter::default();let(mut failures,mut reaps)=(0,0);for _ in 0..3{r.flush_failure(s.failure(11),|_|{failures+=1;Ok(())});r.flush_reaps(s.reaps(11),|_|{reaps+=1;Ok(())});}assert_eq!((failures,reaps),(1,2));}
 #[test] fn unavailable_does_not_attempt_or_claim_success(){let mut r=Reporter::default();r.flush_failure(None,|_|panic!());r.flush_reaps([None;17],|_|panic!());assert!(!r.failure_attempted);assert_eq!(r.reap_attempted,0);}
 #[test] fn error_payload_is_never_serialized(){let secret=std::io::Error::new(std::io::ErrorKind::PermissionDenied,"not-a-wire-field");let s=actor(PeerRole::Signer1);s.latch(11,&s.driver,DriverStage::Receive as u8,classify_io(secret.kind()),None);s.mark_failed(11);let value=serde_json::to_value(s.failure(11).unwrap()).unwrap();assert_eq!(value,serde_json::json!({"version":1,"driver":{"stage":"Receive","class":"IoPermissionDenied"},"listener":null,"origin":null}));assert!(!value.to_string().contains("not-a-wire-field"));}
 #[test] fn concurrent_first_values_are_immutable(){let s=std::sync::Arc::new(actor(PeerRole::Signer1));let mut workers=Vec::new();for stage in [ListenerStage::StatusWrite,ListenerStage::BoundsSource,ListenerStage::RequestRead]{let s=s.clone();workers.push(std::thread::spawn(move||{for _ in 0..100{s.latch(11,&s.listener,stage as u8,Class::BridgeIpc,None);}}));}for w in workers{w.join().unwrap();}fail(&s);let f=s.failure(11).unwrap();s.latch(11,&s.listener,ListenerStage::WorkUnclassified as u8,Class::IoOther,None);assert_eq!(s.failure(11).unwrap(),f);}
}
