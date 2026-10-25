#!/usr/bin/env python3
"""Exact source extraction, inert identities/transport only; no product authority."""
from pathlib import Path
import argparse,hashlib,json,re
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source',required=True,type=Path,help='exact candidate repository root')
parser.add_argument('--out',required=True,type=Path,help='directory for generated inert Rust tests and source bindings')
args=parser.parse_args()
root=args.source.resolve()
out=args.out.resolve()
out.mkdir(parents=True,exist_ok=True)
bindings=[]
def read(rel):
 p=root/rel;s=p.read_text();bindings.append({'path':rel,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()});return s
def block(s,marker):
 start=s.index(marker);at=s.index('{',start);depth=1;i=at+1
 while depth:
  if s[i]=='{':depth+=1
  elif s[i]=='}':depth-=1
  i+=1
 return s[start:i]
owner=read('crates/wholepact-authority/src/transport/coordinated_service_worker_v1.rs')
(out/'authority-owner-harness.rs').write_text('''#![allow(dead_code)]
#[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum AuthorityError {Permission,Storage,Conflict}
pub type Result<T> = std::result::Result<T,AuthorityError>;
mod actual_owner {
'''+owner+'\n}\n')
obs=read('crates/wholepact-financial-coordinator-origin/src/financial_observer.rs')
diag=read('crates/wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs')
reporter=diag[diag.index('#[derive(Clone,Copy,Default)]pub(crate) struct Reporter'):diag.index('/// Root index')]
parts=['''#![allow(dead_code)]
use std::sync::{Mutex,Arc,atomic::{AtomicBool,AtomicU8,Ordering}};
use std::cell::RefCell;
type Result<T> = std::io::Result<T>;
static EVENTS:Mutex<Vec<&'static str>>=Mutex::new(Vec::new());
static TEST:Mutex<()>=Mutex::new(());
static GATE:AtomicBool=AtomicBool::new(false);
static MODE:AtomicU8=AtomicU8::new(0);
thread_local! {static FLAGS:RefCell<Option<(Arc<AtomicBool>,Arc<AtomicBool>)>>=const{RefCell::new(None)};}
fn event(s:&'static str){EVENTS.lock().unwrap().push(s);}
fn denied(){FLAGS.with(|f|{let f=f.borrow();let(r,a)=f.as_ref().unwrap();assert!(r.load(Ordering::Acquire));assert!(!a.load(Ordering::Acquire));});}
fn events()->Vec<&'static str>{EVENTS.lock().unwrap().clone()}
fn reset(mode:u8){EVENTS.lock().unwrap().clear();GATE.store(false,Ordering::Release);MODE.store(mode,Ordering::Release);let mut w=WRITER.lock().unwrap_or_else(|p|p.into_inner());*w=Some(Writer{pid:42,actor_diagnostic:Reporter::default()});drop(w);WRITER.clear_poison();}
struct Peer;
impl Peer{fn shutdown(&self){denied();event("shutdown");}}
struct Leaf;
impl Drop for Leaf{fn drop(&mut self){event("leaf_drop");}}
#[derive(Clone,Copy)]struct FailureFacts;
#[derive(Clone,Copy)]struct ReapFacts;
mod libc {pub unsafe fn getpid()->i32{42}}
''','mod reporter {use super::{FailureFacts,ReapFacts};\n'+reporter+'\n}\nuse reporter::Reporter;\n', '''
struct Writer {pid:i32,actor_diagnostic:Reporter}
static WRITER:Mutex<Option<Writer>>=Mutex::new(None);
fn emit_locked(_: &mut Writer, kind:&str, _: &FailureFacts)->std::result::Result<(),()> {
 assert_eq!(kind,"ActorFailureBoundary");denied();event("append");
 match MODE.load(Ordering::Acquire){1=>Err(()),2=>panic!("synthetic append unwind"),_=>Ok(())}
}
mod financial_ci_actor_diagnostics {
 use super::*;
 #[derive(Clone,Copy,Debug)]pub enum DriverStage{Receive,WitnessWork}
 #[derive(Clone,Copy,Debug)]pub enum Class{IoOther,IoPermissionDenied}
 pub enum OriginStage{WitnessReceive}
 pub fn driver(_:DriverStage,_:Class){GATE.store(true,Ordering::Release);event("gate");}
 pub fn classify_io(k:std::io::ErrorKind)->Class{if k==std::io::ErrorKind::PermissionDenied{Class::IoPermissionDenied}else{Class::IoOther}}
 pub fn origin_io(_:OriginStage,_:&std::io::Error,_:Option<()>){event("origin_detail");}
 pub fn sample_failure()->Option<FailureFacts>{GATE.load(Ordering::Acquire).then_some(FailureFacts)}
}
mod financial_observer {use super::*;
''',block(obs,'pub(crate) fn financial_ci_flush_actor_failure_before_edge_close'), '\n',block(obs,'pub(crate) fn best_effort_diagnostic_append'), '\n',block(obs,'fn best_effort_actor_observation'),'\n}\n']
for filename,core,origin,request in [
 ('financial_history_origin.rs','HistoryCore','WitnessFinancialHistoryOriginV1','FinancialHistoryRequestV1'),
 ('financial_signing_origin.rs','SigningCore','WitnessFinancialSigningOriginV1','FinancialSigningRequestV1'),
 ('completed_pair_origin.rs','PairCore','WitnessCompletedPairOriginV1','CompletedPairRequestV1')]:
 s=read('crates/wholepact-financial-coordinator-origin/src/'+filename)
 actual_core=re.search(r'impl (\w+Core) \{',s).group(1);core=actual_core
 module=filename[:-3]
 parts.append(f'\nmod {module} {{\nuse super::*;\nstruct {core} {{restricted:Arc<AtomicBool>,alive:Arc<AtomicBool>,peer:Peer}}\nimpl {core} {{\n')
 for marker in ['fn restrict(&self)','fn close(&self)','fn close_with_failure_observation(&self)','fn close_after_restriction(&self, observe: impl FnOnce())']:
  parts.append(block(s,marker)+'\n')
 parts.append(f'}}\nenum {request}{{}}\nstruct {origin}{{core:Arc<{core}>,leaf:Option<Leaf>,failed:bool,next:Option<std::io::Error>}}\nimpl {origin}{{\n')
 for marker in ['pub fn close_for_failed_worker_v1','pub fn close_for_failed_worker_error_v1','pub fn try_receive']:
  parts.append(block(s,marker)+'\n')
 parts.append(f'fn receive_inner(&mut self)->Result<Option<{request}>>{{match self.next.take(){{Some(e)=>Err(e),None=>Ok(None)}}}}\n}}\n')
 parts.append(block(s,'impl Drop for '+origin)+'\n')
 parts.append(f'''fn owner()->{origin}{{let r=Arc::new(AtomicBool::new(false));let a=Arc::new(AtomicBool::new(true));FLAGS.with(|f|*f.borrow_mut()=Some((r.clone(),a.clone())));{origin}{{core:Arc::new({core}{{restricted:r,alive:a,peer:Peer}}),leaf:Some(Leaf),failed:false,next:None}}}}
#[test]fn ordinary_drop_has_no_failure_gate_or_append(){{let _guard=TEST.lock().unwrap();reset(2);drop(owner());assert_eq!(events(),["shutdown","leaf_drop"]);assert!(!GATE.load(Ordering::Acquire));}}
#[test]fn successful_receive_preserves_open_custody_without_append(){{let _guard=TEST.lock().unwrap();reset(2);let mut o=owner();assert!(o.try_receive().unwrap().is_none());assert!(events().is_empty());assert!(o.core.alive.load(Ordering::Acquire));assert!(!o.core.restricted.load(Ordering::Acquire));}}
#[test]fn actual_receive_error_preserves_error_after_denied_observation_and_shutdown(){{let _guard=TEST.lock().unwrap();reset(0);let mut o=owner();o.next=Some(std::io::Error::from_raw_os_error(13));let err=o.try_receive().err().unwrap();assert_eq!(err.raw_os_error(),Some(13));assert_eq!(events(),["origin_detail","gate","append","shutdown"]);}}
#[test]fn actual_error_close_is_once_and_append_error_cannot_skip_shutdown(){{let _guard=TEST.lock().unwrap();reset(1);let mut o=owner();o.close_for_failed_worker_error_v1();assert_eq!(events(),["gate","append","shutdown","leaf_drop"]);o.close_for_failed_worker_error_v1();assert_eq!(events(),["gate","append","shutdown","leaf_drop","gate","shutdown"]);}}
#[test]fn append_unwind_is_caught_before_unconditional_shutdown(){{let _guard=TEST.lock().unwrap();reset(2);let mut o=owner();o.close_for_failed_worker_error_v1();assert_eq!(events(),["gate","append","shutdown","leaf_drop"]);o.close_for_failed_worker_error_v1();assert_eq!(events(),["gate","append","shutdown","leaf_drop","gate","shutdown"]);}}
#[test]fn normal_explicit_close_never_enables_failure(){{let _guard=TEST.lock().unwrap();reset(2);let mut o=owner();o.close_for_failed_worker_v1();assert_eq!(events(),["shutdown","leaf_drop"]);assert!(!GATE.load(Ordering::Acquire));}}
}}
''')
(out/'witness-close-harness.rs').write_text(''.join(parts))
(out/'harness-source-bindings.json').write_text(json.dumps({'candidate':str(root),'sources':bindings,'limitations':['Inert source carriers replace original process/peer/transport and writer sink; no authority or kernel/runtime behavior is asserted.','Authority owner source and its five maintained tests are included verbatim; real origin impls are disabled by original feature cfg.','W method bodies, Reporter and best_effort/early-flush function bodies are extracted verbatim; injected append/identity adapters are explicitly inert.','This generator does not compile or execute Rust; execution must be recorded separately against these source bindings.']},indent=2)+'\n')
print('generated authority-owner-harness.rs (5 tests), witness-close-harness.rs (18 tests)')
