#!/usr/bin/env python3
"""P75 exact-source cause-boundary control trace, not an authority fixture.

Unmodified relay pump/finish/Drop, custody/owner Drop and finite Slots methods
are executed with inert lifecycle, child and append adapters. No HostOrigin,
Final, process, socket, TLS or native actor is constructed. The Signer wrapper
is unmodified; its failure carrier/classifier are explicitly inert diagnostic
adapters, not actual transport. Actual Reporter/WRITER tests run separately.
Default requires exact pinned rustc; --source-only explicitly does NOT run Rust.
The script writes only to a temporary directory, never to repository sources.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PINNED_RUSTC = 'rustc 1.99.0 (b940084d7 2026-09-28)'
BASELINE = '33297608c4c7e89a8a4b662673eaa84d5d301d38'
PATHS = {'relay': 'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs', 'custody': 'crates/wholepact-financial-coordinator-origin/src/fork_signer.rs', 'lifecycle': 'crates/wholepact-financial-coordinator-origin/src/host_interstage.rs', 'bootstrap': 'crates/wholepact-financial-coordinator-origin/src/bootstrap.rs', 'diagnostic': 'crates/wholepact-financial-coordinator-origin/src/financial_ci_host_diagnostics.rs', 'signer': 'crates/wholepact-signer/src/financial_ci_actor.rs'}
ANCHORS = {'relay_pump': ('relay', 'pub fn pump(&mut self)->Result<bool>'), 'relay_finish': ('relay', 'pub fn finish(mut self,work:Result<()>)'), 'relay_drop': ('relay', 'impl Drop for HostFinancialWorkflowRelayV1'), 'custody_struct': ('custody', 'pub(super) struct HostVerifierCustody'), 'custody_impl': ('custody', 'impl HostVerifierCustody'), 'custody_drop': ('custody', 'impl Drop for HostVerifierCustody'), 'owner_drop': ('lifecycle', 'impl Drop for HostLifecycleOwner'), 'codes_macro': ('diagnostic', 'macro_rules! codes'), 'slots_struct': ('diagnostic', 'struct Slots'), 'slots_new': ('diagnostic', 'const fn new()->Self'), 'slots_enter': ('diagnostic', 'fn enter(&self,pid:i32,role:u8)'), 'slots_active': ('diagnostic', 'fn active(&self,pid:i32,role:u8)'), 'slots_failure': ('diagnostic', 'fn failure(&self,pid:i32,stage:Stage,class:Class)'), 'classify_io': ('diagnostic', 'pub fn classify_io('), 'signer_wrapper': ('signer', 'pub(crate) fn admit_transport_diagnosed_result<T>')}
RESTORATION = {'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs': {'baseline_sha256': '622279abb0938e482932d13841203645d7f40d79e8498c0294a9b0a96fdecfec', 'exact_inverse': [{'remove': '    pub fn pump(&mut self)->Result<bool>{let result=self.pump_inner();if result.is_err(){\n        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        if let Err(error)=&result {crate::financial_ci_host_diagnostics::latch_failure(crate::financial_ci_host_diagnostics::Stage::RelayPump,crate::financial_ci_host_diagnostics::classify_io(error.kind()));}\n        self.lifecycle.poison();drop(self.host.take());}result}', 'restore': '    pub fn pump(&mut self)->Result<bool>{let result=self.pump_inner();if result.is_err(){self.lifecycle.poison();drop(self.host.take());}result}'}, {'remove': '        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        if let Err(error)=&work {crate::financial_ci_host_diagnostics::latch_failure(crate::financial_ci_host_diagnostics::Stage::RelayFinish,crate::financial_ci_host_diagnostics::classify_io(error.kind()));}\n', 'restore': ''}]}, 'crates/wholepact-financial-coordinator-origin/src/fork_signer.rs': {'baseline_sha256': '6d6392d710ccc9fddb6935387dd2adc58e58e94cc157c5c10fb1895d5e313218', 'exact_inverse': [{'remove': '    fn drop(&mut self) { self.live.store(false, Ordering::Release);\n        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        crate::financial_observer::financial_ci_flush_host_failure_before_owned_drop();\n    }', 'restore': '    fn drop(&mut self) { self.live.store(false, Ordering::Release); }'}]}}
BASE_ITEM_SHA = {'relay_drop': '07bd9f2f159f880ffc61a7c5e191b99b7a6e9fa1ac3511c8226cc4a192cab632', 'owner_drop': 'f922c11b41ff5f27fb438a921bd0bf943679ef205a4bcdd6f6fb86cd0785dc65', 'host_origin_fields': '35c2e2876890e61c7d8ea8699beb6b5e58479a7fcc77a8861e6b198298eeec4c', 'owner_struct': 'fbe4495c214174953a0c8ebd20d47b17bf40c17d952bbc8ca87a33da068b08fa'}

def item(source, anchor):
    """Extract one selected Rust item without rewriting a byte of its body."""
    if source.count(anchor) != 1:
        raise AssertionError(('nonunique selected item', anchor))
    start = source.index(anchor)
    opening = source.index('{', start)
    depth, block, quoted, escaped = 0, 0, False, False
    i = opening
    while i < len(source):
        if quoted:
            if escaped:
                escaped = False
            elif source[i] == '\\':
                escaped = True
            elif source[i] == '"':
                quoted = False
            i += 1
            continue
        if block:
            if source.startswith('/*', i):
                block += 1
                i += 2
            elif source.startswith('*/', i):
                block -= 1
                i += 2
            else:
                i += 1
            continue
        if source.startswith('//', i):
            end = source.find('\n', i)
            if end < 0:
                break
            i = end + 1
            continue
        if source.startswith('/*', i):
            block = 1
            i += 2
            continue
        c = source[i]
        if c == '"':
            quoted = True
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise AssertionError(('unbalanced selected item', anchor))

TEST_NAMES = (
 'pump_error_preserves_identity_and_pre_drop_order',
 'pump_ok_false_has_no_failure_side_effects',
 'pump_ok_true_has_no_failure_side_effects',
 'finish_incoming_error_preserves_identity_and_pre_drop_order',
 'normal_custody_drop_has_no_failure_fact_or_append',
 'existing_failure_survives_relay_pump_and_finish',
 'signer_wrapper_keeps_returned_error_not_first_category',
 'signer_wrapper_ok_does_not_classify_or_mark',
)

def sha(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def inputs():
    return {name:(ROOT/path).read_text() for name,path in PATHS.items()}

def unique_line(source, prefix):
    lines=[line for line in source.splitlines() if line.startswith(prefix)]
    if len(lines)!=1:raise AssertionError(('nonunique selected line',prefix))
    return lines[0]

def extracted_items():
    s=inputs()
    out={name:item(s[key],anchor) for name,(key,anchor) in ANCHORS.items()}
    out['owner_struct']=unique_line(s['lifecycle'],'pub(super) struct HostLifecycleOwner')
    out['stage_codes']=unique_line(s['diagnostic'],'codes!(Stage {')
    out['class_codes']=unique_line(s['diagnostic'],'codes!(Class {')
    return out

class SourceContracts(unittest.TestCase):
    def test_host_observation_erases_to_exact_P74_files(self):
        for path,record in RESTORATION.items():
            restored=(ROOT/path).read_text()
            for change in record['exact_inverse']:
                self.assertEqual(restored.count(change['remove']),1,path)
                restored=restored.replace(change['remove'],change['restore'],1)
            self.assertEqual(sha(restored),record['baseline_sha256'],path)
    def test_actual_destructors_and_host_field_order_are_source_bound(self):
        s=inputs();e=extracted_items()
        for name in ('relay_drop','owner_drop','owner_struct'):
            self.assertEqual(sha(e[name]),BASE_ITEM_SHA[name])
        host=item(s['bootstrap'],'pub struct HostOriginV1')
        self.assertEqual(sha(host),BASE_ITEM_SHA['host_origin_fields'])
        self.assertLess(host.index('lifecycle_owner:'),host.index('verifier_custody:'))
        self.assertLess(host.index('verifier_custody:'),host.index('signers:'))
    def test_source_items_are_copied_unchanged(self):
        generated,items=build_harness()
        for name,value in items.items():self.assertEqual(generated.count(value),1,name)
        self.assertIn('self.live.store(false, Ordering::Release);',items['custody_drop'])
        self.assertIn('drop(self.host.take());result',items['relay_finish'])
    def test_signer_wrapper_returns_original_kernel_category(self):
        wrapper=extracted_items()['signer_wrapper']
        self.assertIn('failure.returned_error()',wrapper)
        self.assertNotIn('failure.into_error()',wrapper)
        self.assertIn('failure.error(),callback',wrapper)
        self.assertEqual(wrapper.count('diagnostic::driver(stage,class);'),1)
    def test_harness_inventory_and_explicit_inert_scope(self):
        generated,_=build_harness()
        self.assertEqual(len(TEST_NAMES),8)
        for name in TEST_NAMES:self.assertEqual(generated.count('fn '+name+'()'),1,name)
        self.assertNotIn('struct HostOriginV1',generated)
        self.assertNotIn('Command::new',generated)
        self.assertNotIn('UnixStream',generated)

RUST_SUPPORT=r"""
use std::{cell::RefCell, fmt, io, sync::{Arc,atomic::{AtomicBool,Ordering}}, time::Instant};
type Result<T> = std::io::Result<T>;
#[derive(Default)] struct State {
 trace:Vec<&'static str>, live:Option<Arc<AtomicBool>>, poisoned:bool,
 pump_calls:usize, flush_calls:usize, append_calls:usize, child_drops:usize,
 detail_calls:usize, signer_marks:Vec<(DriverStage,Class)>,
}
thread_local! { static STATE:RefCell<State>=RefCell::new(State::default()); }
fn trace(event:&'static str){STATE.with(|s|s.borrow_mut().trace.push(event));}
fn setup(){STATE.with(|s|*s.borrow_mut()=State::default());financial_ci_host_diagnostics::reset();}
struct HostLifecycle;
impl HostLifecycle {fn poison(&self){STATE.with(|s|{let mut s=s.borrow_mut();
 let event=if s.poisoned{"poison_again"}else{"poison"};s.trace.push(event);s.poisoned=true;});}}
pub(crate) mod financial_observer {
 pub fn financial_ci_flush_host_failure_before_owned_drop(){
  super::STATE.with(|s|{let mut s=s.borrow_mut();s.flush_calls+=1;
   assert!(!s.live.as_ref().unwrap().load(super::Ordering::Acquire));
   s.trace.push("custody_live_false_observed");
   if super::financial_ci_host_diagnostics::selected().is_some(){
    assert!(s.poisoned);s.append_calls+=1;s.trace.push("append_attempt");
   }
  });
 }
}
struct InertChild;
impl Drop for InertChild {fn drop(&mut self){STATE.with(|s|{let mut s=s.borrow_mut();
 assert!(!s.live.as_ref().unwrap().load(Ordering::Acquire));
 s.child_drops+=1;s.trace.push("owned_child_drop");});}}
// An inert ownership aggregate, deliberately NOT HostOriginV1 or a native Final.
// SourceContracts binds the real Host declaration's relevant relative order.
struct InertOwnedFields {lifecycle_owner:HostLifecycleOwner,
 verifier_custody:Option<HostVerifierCustody>,signers:InertChild}
struct HostFinancialWorkflowRelayV1 {lifecycle:Arc<HostLifecycle>,host:Option<InertOwnedFields>,
 next:Option<Result<bool>>,cancel_seen:bool,disposed:[bool;2],cleanup:Option<Instant>}
impl HostFinancialWorkflowRelayV1 {
 fn new(next:Result<bool>)->Self{let lifecycle=Arc::new(HostLifecycle);let custody=HostVerifierCustody::new();
 STATE.with(|s|s.borrow_mut().live=Some(Arc::clone(&custody.live)));
 Self{lifecycle:Arc::clone(&lifecycle),host:Some(InertOwnedFields{
 lifecycle_owner:HostLifecycleOwner(lifecycle),verifier_custody:Some(custody),signers:InertChild}),
 next:Some(next),cancel_seen:false,disposed:[false;2],cleanup:None}}
 fn pump_inner(&mut self)->Result<bool>{STATE.with(|s|s.borrow_mut().pump_calls+=1);self.next.take().unwrap()}
 fn is_disposed(&self)->bool{self.disposed==[true;2]}
}
fn rejected(message:&str)->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,message.to_owned())}
mod bootstrap {pub(super) fn finish_host_capped(_:super::InertOwnedFields,_:Option<super::Instant>)->super::Result<()>{panic!("not reached by incoming-Err trace")}}
#[derive(Debug)] struct IdentityError(Arc<()>);
impl fmt::Display for IdentityError {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"inert diagnostic sentinel")}}
impl std::error::Error for IdentityError {}
fn failure()->(io::Error,usize,Arc<()>){let token=Arc::new(());let error=io::Error::new(io::ErrorKind::PermissionDenied,IdentityError(Arc::clone(&token)));
 let address=error.get_ref().unwrap() as *const (dyn std::error::Error+Send+Sync) as *const () as usize;(error,address,token)}
fn assert_identity(error:&io::Error,address:usize,token:&Arc<()>){assert_eq!(error.kind(),io::ErrorKind::PermissionDenied);
 assert_eq!(error.get_ref().unwrap() as *const (dyn std::error::Error+Send+Sync) as *const () as usize,address);
 assert!(Arc::ptr_eq(&error.get_ref().unwrap().downcast_ref::<IdentityError>().unwrap().0,token));}
fn assert_order(){STATE.with(|s|{let s=s.borrow();let pos=|key|s.trace.iter().position(|x|*x==key).unwrap();
 assert!(pos("latch_attempt")<pos("poison"));assert!(pos("poison")<pos("custody_live_false_observed"));
 assert!(pos("custody_live_false_observed")<pos("append_attempt"));assert!(pos("append_attempt")<pos("owned_child_drop"));
 assert_eq!(s.append_calls,1);assert_eq!(s.child_drops,1);});}
// Explicit inert diagnostic carrier/classifier for the exact Signer wrapper.
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum DriverStage{AdmitTransport}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Class{FirstPermission,CallbackMarker}
mod wholepact_authority {
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum AuthorityError{Permission,Uncertain}
 pub type Result<T>=std::result::Result<T,AuthorityError>;
 pub mod transport {pub mod history_diagnostics_v1 {
  #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum InertStage{Response}
  #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum InertIo{Closed}
  pub struct CheckedHistoryFailureV1;
  impl CheckedHistoryFailureV1 {
   pub fn stage(&self)->InertStage{InertStage::Response}
   pub fn io_kind(&self)->Option<InertIo>{Some(InertIo::Closed)}
   pub fn error(&self)->super::super::AuthorityError{super::super::AuthorityError::Permission}
   pub fn returned_error(&self)->super::super::AuthorityError{super::super::AuthorityError::Uncertain}
   pub fn into_error(self)->super::super::AuthorityError{panic!("must not substitute first observed category")}
  }
 }}
}
fn admit_transport_detail(stage:wholepact_authority::transport::history_diagnostics_v1::InertStage,
 kind:Option<wholepact_authority::transport::history_diagnostics_v1::InertIo>,
 error:wholepact_authority::AuthorityError,callback:Option<Class>)->(DriverStage,Class){
 use wholepact_authority::transport::history_diagnostics_v1::{InertStage,InertIo};
 assert_eq!(stage,InertStage::Response);assert_eq!(kind,Some(InertIo::Closed));
 assert_eq!(error,wholepact_authority::AuthorityError::Permission);assert_eq!(callback,Some(Class::CallbackMarker));
 STATE.with(|s|s.borrow_mut().detail_calls+=1);(DriverStage::AdmitTransport,Class::FirstPermission)
}
mod diagnostic {pub(super) fn driver(stage:super::DriverStage,class:super::Class){super::STATE.with(|s|s.borrow_mut().signer_marks.push((stage,class)));}}
"""
RUST_DIAGNOSTIC_ADAPTER=r"""
thread_local! {static SLOTS:std::cell::RefCell<Slots>=std::cell::RefCell::new(Slots::new());}
pub(super) fn reset(){SLOTS.with(|s|{*s.borrow_mut()=Slots::new();s.borrow().enter(101,2);});}
pub fn latch_failure(stage:Stage,class:Class){super::trace("latch_attempt");SLOTS.with(|s|s.borrow().failure(101,stage,class));}
pub(super) fn selected()->Option<(&'static str,&'static str)>{SLOTS.with(|s|{
 let s=s.borrow();let value=s.failure.load(Ordering::Relaxed).checked_sub(1)?;
 Some((*Stage::NAMES.get((value&255)as usize)?,*Class::NAMES.get((value>>8)as usize)?))})}
"""
RUST_TESTS=r"""
#[test] fn pump_error_preserves_identity_and_pre_drop_order(){setup();let(error,address,token)=failure();let mut relay=HostFinancialWorkflowRelayV1::new(Err(error));
 let returned=relay.pump().unwrap_err();assert_identity(&returned,address,&token);assert_order();assert!(relay.host.is_none());
 assert_eq!(financial_ci_host_diagnostics::selected(),Some(("RelayPump","IoPermissionDenied")));STATE.with(|s|assert_eq!(s.borrow().pump_calls,1));
 drop(relay);STATE.with(|s|assert_eq!(s.borrow().trace.last(),Some(&"poison_again")));}
fn pump_ok_case(value:bool){setup();let mut relay=HostFinancialWorkflowRelayV1::new(Ok(value));assert_eq!(relay.pump().unwrap(),value);
 STATE.with(|s|{let s=s.borrow();assert_eq!(s.pump_calls,1);assert!(s.trace.is_empty());assert_eq!(s.flush_calls,0);assert_eq!(s.child_drops,0);assert!(s.live.as_ref().unwrap().load(Ordering::Acquire));});
 assert!(financial_ci_host_diagnostics::selected().is_none());assert!(relay.host.is_some());drop(relay);STATE.with(|s|assert_eq!(s.borrow().append_calls,0));}
#[test] fn pump_ok_false_has_no_failure_side_effects(){pump_ok_case(false);}
#[test] fn pump_ok_true_has_no_failure_side_effects(){pump_ok_case(true);}
#[test] fn finish_incoming_error_preserves_identity_and_pre_drop_order(){setup();let(error,address,token)=failure();let relay=HostFinancialWorkflowRelayV1::new(Ok(false));
 let returned=relay.finish(Err(error)).unwrap_err();assert_identity(&returned,address,&token);assert_order();
 assert_eq!(financial_ci_host_diagnostics::selected(),Some(("RelayFinish","IoPermissionDenied")));
 STATE.with(|s|{let s=s.borrow();assert_eq!(s.pump_calls,0);assert_eq!(s.trace.last(),Some(&"poison_again"));});}
#[test] fn normal_custody_drop_has_no_failure_fact_or_append(){setup();let custody=HostVerifierCustody::new();
 STATE.with(|s|s.borrow_mut().live=Some(Arc::clone(&custody.live)));drop(custody);
 assert!(financial_ci_host_diagnostics::selected().is_none());STATE.with(|s|{let s=s.borrow();assert!(!s.poisoned);assert_eq!(s.append_calls,0);assert_eq!(s.child_drops,0);assert_eq!(s.flush_calls,1);assert_eq!(s.trace,["custody_live_false_observed"]);});}
#[test] fn existing_failure_survives_relay_pump_and_finish(){for finish in [false,true]{setup();
 financial_ci_host_diagnostics::latch_failure(financial_ci_host_diagnostics::Stage::CommandsDecode,financial_ci_host_diagnostics::Class::Invalid);
 STATE.with(|s|s.borrow_mut().trace.clear());let(error,address,token)=failure();
 let returned=if finish {HostFinancialWorkflowRelayV1::new(Ok(false)).finish(Err(error)).unwrap_err()}else{
 let mut relay=HostFinancialWorkflowRelayV1::new(Err(error));let result=relay.pump().unwrap_err();drop(relay);result};
 assert_identity(&returned,address,&token);assert_order();assert_eq!(financial_ci_host_diagnostics::selected(),Some(("CommandsDecode","Invalid")));}}
#[test] fn signer_wrapper_keeps_returned_error_not_first_category(){setup();let result=admit_transport_diagnosed_result::<()>(Err(wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1),Some(Class::CallbackMarker));
 assert_eq!(result,Err(wholepact_authority::AuthorityError::Uncertain));STATE.with(|s|{let s=s.borrow();assert_eq!(s.detail_calls,1);assert_eq!(s.signer_marks,[(DriverStage::AdmitTransport,Class::FirstPermission)]);});}
#[test] fn signer_wrapper_ok_does_not_classify_or_mark(){setup();assert_eq!(admit_transport_diagnosed_result(Ok(47u8),Some(Class::CallbackMarker)),Ok(47));
 STATE.with(|s|{let s=s.borrow();assert_eq!(s.detail_calls,0);assert!(s.signer_marks.is_empty());});}
"""

def build_harness():
    e=extracted_items()
    diag='\n'.join(e[k] for k in ('codes_macro','stage_codes','class_codes','slots_struct','classify_io'))
    diag+='\nimpl Slots {\n'+'\n'.join(e[k] for k in ('slots_new','slots_enter','slots_active','slots_failure'))+'\n}\n'
    ownership='\n'.join(e[k] for k in ('owner_struct','owner_drop','custody_struct','custody_impl','custody_drop'))
    methods='impl HostFinancialWorkflowRelayV1 {\n'+e['relay_pump']+'\n'+e['relay_finish']+'\n}\n'+e['relay_drop']
    rust='#![allow(dead_code)]\nmod harness {\n'+RUST_SUPPORT+'\npub(crate) mod financial_ci_host_diagnostics {\nuse std::sync::atomic::{AtomicI32,AtomicU32,AtomicU8,Ordering};\n'+diag+RUST_DIAGNOSTIC_ADAPTER+'\n}\n'+ownership+'\n'+methods+'\n'+e['signer_wrapper']+'\n'+RUST_TESTS+'\n}\nuse harness::{financial_ci_host_diagnostics,financial_observer};\n'
    return rust,e

def checked(command,timeout):
    result=subprocess.run(command,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        print(result.stdout,end='');print(result.stderr,end='')
        raise RuntimeError('cause trace command failed: '+command[0])
    return result.stdout

def native_tests():
    rustc=shutil.which('rustc')
    if rustc is None:raise RuntimeError('pinned rustc unavailable: Rust NOT RUN; default invocation cannot skip')
    version=checked([rustc,'--version'],15).strip()
    if version!=PINNED_RUSTC:raise RuntimeError('wrong rustc identity: '+version)
    generated,extracted=build_harness()
    with tempfile.TemporaryDirectory(prefix='p75-cause-trace-') as directory:
        root=Path(directory);src=root/'cause_trace.rs';binary=root/'cause_trace'
        src.write_text(generated)
        checked([rustc,'--edition=2021','--test','--cfg','wholepact_financial_rendered_host_semantic_ci','--cfg','feature="synthetic-qualification"','-C','opt-level=0',str(src),'-o',str(binary)],120)
        listing=checked([str(binary),'--list','--format','terse'],15)
        actual=sorted(line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test'))
        if actual!=sorted('harness::'+name for name in TEST_NAMES):raise AssertionError(('unexpected exact Rust test inventory',actual))
        output=checked([str(binary),'--test-threads=1'],60);print(output,end='')
        if f'test result: ok. {len(TEST_NAMES)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in output:
            raise AssertionError('Rust test result missing/count mismatch')
    return dict(rust_harness_executed=True,rust_tests_passed=len(TEST_NAMES),rust_ignored=0,compiler=version)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only',action='store_true',help='Static source checks only; Rust explicitly NOT RUN.')
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(SourceContracts)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
    generated,extracted=build_harness()
    evidence=dict(source_contract_tests_passed=result.testsRun,baseline=BASELINE,
        execution_kind='actual-source Host boundary/Drop/Slots and Signer result wrapper; inert ownership/I/O/classifier adapters',
        native_actor_execution=False,native_authority_finals_created=False,actual_transport_executed=False,
        actual_reporter_or_writer_executed=False,full_native_qualification=False,
        generated_source_sha256=sha(generated),extracted_item_sha256={k:sha(v) for k,v in extracted.items()},
        expected_rust_tests=list(TEST_NAMES),source_tree_written=False)
    if args.source_only:evidence.update(rust_harness_executed=False,rust_test_status='NOT RUN (explicit --source-only)')
    else:evidence.update(native_tests())
    print('P75_CAUSE_BOUNDARY_TRACE '+json.dumps(evidence,sort_keys=True))

if __name__=='__main__':main()
