#!/usr/bin/env python3
"""Exact retained-custody checks and shared-wall helper, with inert test carriers.

The legacy body is obtained only by the pinned, unique inverse of the narrow
P90 kernel replacement. Production method bodies are adapted by name only.
The clocks, entry/Core delegates and diagnostic sinks are modeled test inputs:
these tests do not establish native process liveness, authority, or P89 causality.
Without --run this script only verifies/extracts source and writes Rust text.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

CUSTODY = 'crates/wholepact-financial-coordinator-origin/src/signed_result_custody.rs'
STATE = 'crates/wholepact-financial-coordinator-origin/src/signer_continue_state.rs'
BASELINE_SHA256 = 'c60162e32fd54f848afffbb2ff09707989349dc1ea22932a8d51c7e6ab06a45d'
CANDIDATE_SHA256 = 'c074ce402eb08ebd624fe89b0fb674b5c776c86465d272d673dc8f01fa39faf8'
STATE_SHA256 = '33c4b1f180f6f4093fd195a65a27921bceea06cde078b9917e22f3a3048b0079'
PINNED_RUSTC = 'rustc 1.99.0 (b940084d7 2026-09-28)'
BEFORE = '''        crate::channel::require_time(self.service.min(self.writer).min(self.writer_wall).min(self.entry.original_source))?;
        self.entry.retirement_clock_bounds()?;
        let wall=state::wall_ms()?;let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<prior||wall<self.service_valid_from_ms||wall>=self.service_valid_until_ms{return Err(rejected("retired Signing original wall bounds"));}'''
AFTER = '''        let original=self.service.min(self.writer).min(self.writer_wall).min(self.entry.original_source);
        crate::channel::require_time(original)?;
        self.entry.retirement_clock_bounds()?;
        let wall=state::observe_shared_wall(&self.last_wall,original,state::wall_ms)?
            .ok_or_else(||rejected("retired Signing original wall bounds"))?;
        if wall<self.service_valid_from_ms||wall>=self.service_valid_until_ms{return Err(rejected("retired Signing original wall bounds"));}'''

PREFIX = r'''#![allow(dead_code)]
use std::{cell::{Cell,RefCell},collections::VecDeque,io,sync::{Arc,Barrier,atomic::{AtomicBool,AtomicU32,AtomicU64,AtomicUsize,Ordering}}};
type Result<T> = io::Result<T>;
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)] struct Instant(u64);
impl Instant { fn now()->Self { Self(NOW.with(|v|v.borrow_mut().pop_front()).unwrap_or_else(||CLOCK.with(Cell::get))) } }
thread_local! {
    static CLOCK:Cell<u64> = const{Cell::new(1)};
    static NOW:RefCell<VecDeque<u64>> = RefCell::new(VecDeque::new());
    static WALL:RefCell<Option<Box<dyn FnMut()->Result<u64>>>> = RefCell::new(None);
    static SAMPLES:Cell<usize> = const{Cell::new(0)};
    static CALLS:RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
    static DIAGNOSTICS:RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
}
fn log(value:&'static str){CALLS.with(|v|v.borrow_mut().push(value));}
fn calls()->Vec<&'static str>{CALLS.with(|v|v.borrow().clone())}
fn samples()->usize{SAMPLES.with(Cell::get)}
fn clock(value:u64){CLOCK.with(|v|v.set(value));}
fn wall(f:impl FnMut()->Result<u64>+'static){WALL.with(|v|*v.borrow_mut()=Some(Box::new(f)));}
fn reset(){clock(1);NOW.with(|v|v.borrow_mut().clear());WALL.with(|v|*v.borrow_mut()=None);SAMPLES.with(|v|v.set(0));CALLS.with(|v|v.borrow_mut().clear());DIAGNOSTICS.with(|v|v.borrow_mut().clear());}
fn rejected(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,message)}
mod channel {
    use super::*;
    pub(super) fn require_time(deadline:Instant)->Result<()>{log("require_time");if Instant::now()>=deadline{Err(rejected("original deadline"))}else{Ok(())}}
}
// Literal helper/macro calls bind to finite inert sinks; not production latches.
mod financial_ci_actor_diagnostics {
    use super::*;
    pub(super) enum OriginStage{SharedWallDeadline,SharedWallRollback,SharedWallRead}
    pub(super) enum Class{ClockExpired,WallRollback}
    pub(super) fn origin(stage:OriginStage,_class:Class,_peer:Option<()>){note(stage);}
    pub(super) fn origin_io(stage:OriginStage,_error:&io::Error,_peer:Option<()>){note(stage);}
    fn note(stage:OriginStage){DIAGNOSTICS.with(|v|v.borrow_mut().push(match stage{OriginStage::SharedWallDeadline=>"SharedWallDeadline",OriginStage::SharedWallRollback=>"SharedWallRollback",OriginStage::SharedWallRead=>"SharedWallRead"}));}
}
struct EntryReviewed{original_source:Instant,denied:bool,advance_to:Option<u64>,slot:usize}
impl EntryReviewed{
    fn retirement_clock_bounds(&self)->Result<()>{log("entry");if let Some(value)=self.advance_to{clock(value);}if self.denied{Err(rejected("entry bounds"))}else{Ok(())}}
    fn slot(&self)->usize{self.slot}
}
struct Phase{revoked:AtomicBool,signing:AtomicUsize,quiescent:AtomicBool,reads:AtomicUsize,revoke_at:usize}
impl Phase{
    fn revoked(&self)->bool{log("revoked");let n=self.reads.fetch_add(1,Ordering::AcqRel)+1;self.revoked.load(Ordering::Acquire)||(self.revoke_at!=0&&n>=self.revoke_at)}
    fn signing_phase(&self,_slot:usize)->usize{log("signing_phase");self.signing.load(Ordering::Acquire)}
    fn quiescent(&self)->bool{log("quiescent");self.quiescent.load(Ordering::Acquire)}
}
#[derive(Clone,Copy)] enum CoreFault{None,Host,Root}
struct Core{phase:Phase,retired_roots:AtomicU32,fault:CoreFault,revoke_on_check:bool}
impl Core{
    // Delegated outcomes only. No pidfd, Host, root, or authority is fabricated.
    fn check(&self)->Result<()>{log("core");if self.revoke_on_check{self.phase.revoked.store(true,Ordering::Release);}match self.fault{CoreFault::None=>Ok(()),CoreFault::Host=>Err(rejected("inert Host delegate")),CoreFault::Root=>Err(rejected("inert root delegate"))}}
}
struct SignedResultRecord{
    core:Arc<Core>,entry:Arc<EntryReviewed>,service:Instant,writer:Instant,writer_wall:Instant,retired_index:usize,
    service_valid_from_ms:u64,service_valid_until_ms:u64,last_wall:AtomicU64,
}
fn record()->SignedResultRecord{SignedResultRecord{
    core:Arc::new(Core{phase:Phase{revoked:AtomicBool::new(false),signing:AtomicUsize::new(6),quiescent:AtomicBool::new(false),reads:AtomicUsize::new(0),revoke_at:0},retired_roots:AtomicU32::new(1),fault:CoreFault::None,revoke_on_check:false}),
    entry:Arc::new(EntryReviewed{original_source:Instant(80),denied:false,advance_to:None,slot:0}),
    service:Instant(50),writer:Instant(60),writer_wall:Instant(70),retired_index:0,
    service_valid_from_ms:90,service_valid_until_ms:120,last_wall:AtomicU64::new(99),
}}
fn check(record:&SignedResultRecord,legacy:bool)->Result<()>{if legacy{record.check_legacy()}else{record.check_candidate()}}
fn denied(result:Result<()>,message:&str){let error=result.unwrap_err();assert_eq!(error.kind(),io::ErrorKind::PermissionDenied);assert_eq!(error.to_string(),message);}
fn diag(expected:&[&str]){
    #[cfg(wholepact_financial_rendered_host_semantic_ci)] assert_eq!(DIAGNOSTICS.with(|v|v.borrow().clone()),expected);
    #[cfg(not(wholepact_financial_rendered_host_semantic_ci))] {let _=expected;assert!(DIAGNOSTICS.with(|v|v.borrow().is_empty()));}
}
'''

TESTS = r'''
// The A sampler reads 100, waits while B finishes publishing 101, then returns
// its stale sample. Both calls use the very same Arc<SignedResultRecord>.
fn reordered(legacy:bool)->(Result<()>,usize,u64){
    reset();let record=Arc::new(record());let sampled=Arc::new(Barrier::new(2));let published=Arc::new(Barrier::new(2));
    let a_record=Arc::clone(&record);assert!(Arc::ptr_eq(&record,&a_record));let a_sampled=Arc::clone(&sampled);let a_published=Arc::clone(&published);
    let a=std::thread::spawn(move||{reset();let mut count=0;wall(move||{count+=1;if count==1{let sampled_wall=100;a_sampled.wait();a_published.wait();Ok(sampled_wall)}else{Ok(101)}});let result=check(&a_record,legacy);(result,samples())});
    sampled.wait();wall(||Ok(101));check(&record,legacy).unwrap();assert_eq!(record.last_wall.load(Ordering::Acquire),101);published.wait();
    let (result,count)=a.join().unwrap();(result,count,record.last_wall.load(Ordering::Acquire))
}
#[test] fn actual_legacy_check_reproduces_delayed_sample_false_rollback(){let (result,count,high)=reordered(true);denied(result,"retired Signing original wall bounds");assert_eq!((count,high),(1,101));}
#[test] fn actual_candidate_check_resamples_delayed_sample_without_false_rollback(){let (result,count,high)=reordered(false);result.unwrap();assert_eq!((count,high),(2,101));}
#[test] fn true_rollback_remains_denied_without_retry_or_lower_publication(){for legacy in [true,false]{reset();let record=record();record.last_wall.store(101,Ordering::Release);wall(||Ok(100));denied(check(&record,legacy),"retired Signing original wall bounds");assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(1,101));assert_eq!(calls(),vec!["require_time","entry","wall"]);diag(if legacy{&[]}else{&["SharedWallRollback"]});}}
#[derive(Debug)] struct WallError(Arc<()>);
impl std::fmt::Display for WallError{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"inert wall error")}}
impl std::error::Error for WallError{}
#[test] fn wall_error_preserves_original_kind_payload_identity_and_single_attempt(){for legacy in [true,false]{reset();let record=record();let token=Arc::new(());let error=io::Error::new(io::ErrorKind::Other,WallError(token.clone()));let pointer=error.get_ref().unwrap().downcast_ref::<WallError>().unwrap() as *const WallError as usize;let mut error=Some(error);wall(move||Err(error.take().expect("wall error must not retry")));let error=check(&record,legacy).unwrap_err();assert_eq!(error.kind(),io::ErrorKind::Other);let payload=error.get_ref().unwrap().downcast_ref::<WallError>().unwrap();assert_eq!(payload as *const WallError as usize,pointer);assert!(Arc::ptr_eq(&token,&payload.0));assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(1,99));assert_eq!(calls(),vec!["require_time","entry","wall"]);diag(if legacy{&[]}else{&["SharedWallRead"]});}}
#[test] fn every_original_bound_is_the_same_immutable_minimum(){for legacy in [true,false]{for which in 0..4{reset();let mut record=record();record.service=Instant(100);record.writer=Instant(100);record.writer_wall=Instant(100);Arc::get_mut(&mut record.entry).unwrap().original_source=Instant(100);match which{0=>record.service=Instant(7),1=>record.writer=Instant(7),2=>record.writer_wall=Instant(7),3=>Arc::get_mut(&mut record.entry).unwrap().original_source=Instant(7),_=>unreachable!()};clock(7);denied(check(&record,legacy),"original deadline");assert_eq!(calls(),vec!["require_time"]);assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(0,99));}}}
#[test] fn entry_bounds_follow_original_time_and_precede_wall_or_phase(){for legacy in [true,false]{reset();let mut record=record();Arc::get_mut(&mut record.entry).unwrap().denied=true;denied(check(&record,legacy),"entry bounds");assert_eq!(calls(),vec!["require_time","entry"]);assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(0,99));}}
#[test] fn service_interval_keeps_inclusive_start_and_exclusive_end(){for legacy in [true,false]{for value in [89,90,119,120]{reset();let record=record();record.last_wall.store(80,Ordering::Release);wall(move||Ok(value));let result=check(&record,legacy);if (90..120).contains(&value){result.unwrap();assert!(calls().contains(&"core"));}else{denied(result,"retired Signing original wall bounds");assert_eq!(calls(),vec!["require_time","entry","wall"]);}assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(1,value));}}}
#[test] fn equal_and_advancing_wall_samples_remain_accepted(){for legacy in [true,false]{reset();let record=record();record.last_wall.store(100,Ordering::Release);for value in [100,100,101,102]{wall(move||Ok(value));check(&record,legacy).unwrap();assert_eq!(record.last_wall.load(Ordering::Acquire),value);}assert_eq!(samples(),4);diag(&[]);}}
#[test] fn phase_revocation_and_retired_tombstone_guards_are_unchanged(){for legacy in [true,false]{for case in 0..5{reset();let mut record=record();match case{0=>Arc::get_mut(&mut record.core).unwrap().phase.revoked.store(true,Ordering::Release),1=>Arc::get_mut(&mut record.core).unwrap().phase.signing.store(5,Ordering::Release),2=>record.retired_index=32,3=>record.core.retired_roots.store(0,Ordering::Release),4=>{record.retired_index=31;record.core.retired_roots.store(1<<31,Ordering::Release);},_=>unreachable!()};let result=check(&record,legacy);if case==4{result.unwrap();assert!(calls().contains(&"core"));}else{denied(result,"actual retired signed custody restricted");assert!(!calls().contains(&"quiescent"));assert!(!calls().contains(&"core"));}assert_eq!(samples(),1);}}}
#[test] fn quiescence_skips_only_core_delegate_and_keeps_final_revocation_guard(){for legacy in [true,false]{for revoke in [false,true]{reset();let mut record=record();let core=Arc::get_mut(&mut record.core).unwrap();core.phase.quiescent.store(true,Ordering::Release);core.fault=CoreFault::Host;if revoke{core.phase.revoke_at=2;}let result=check(&record,legacy);if revoke{denied(result,"retired signed custody revoked");}else{result.unwrap();}assert_eq!(calls(),vec!["require_time","entry","wall","revoked","signing_phase","quiescent","revoked"]);}}}
#[test] fn nonquiescent_host_and_root_delegate_failures_still_propagate(){for legacy in [true,false]{for (fault,message) in [(CoreFault::Host,"inert Host delegate"),(CoreFault::Root,"inert root delegate")]{reset();let mut record=record();Arc::get_mut(&mut record.core).unwrap().fault=fault;denied(check(&record,legacy),message);assert_eq!(calls(),vec!["require_time","entry","wall","revoked","signing_phase","quiescent","core"]);}}}
#[test] fn revocation_after_successful_core_delegate_still_refuses(){for legacy in [true,false]{reset();let mut record=record();Arc::get_mut(&mut record.core).unwrap().revoke_on_check=true;denied(check(&record,legacy),"retired signed custody revoked");assert_eq!(calls(),vec!["require_time","entry","wall","revoked","signing_phase","quiescent","core","revoked"]);}}
#[test] fn helper_refuses_original_expiry_after_entry_before_sampling(){reset();let mut record=record();Arc::get_mut(&mut record.entry).unwrap().advance_to=Some(50);denied(check(&record,false),"retired Signing original wall bounds");assert_eq!(calls(),vec!["require_time","entry"]);assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(0,99));diag(&["SharedWallDeadline"]);}
#[test] fn helper_refuses_expiry_during_sample_before_publication(){reset();let record=record();wall(||{clock(50);Ok(100)});denied(check(&record,false),"retired Signing original wall bounds");assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(1,99));assert_eq!(calls(),vec!["require_time","entry","wall"]);diag(&["SharedWallDeadline"]);}
#[test] fn helper_refuses_expiry_after_cas_without_renewing_original(){reset();let record=record();NOW.with(|v|*v.borrow_mut()=VecDeque::from([1,1,1,50]));denied(check(&record,false),"retired Signing original wall bounds");assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(1,100));assert_eq!(calls(),vec!["require_time","entry","wall"]);diag(&["SharedWallDeadline"]);}
#[test] fn contention_expiry_stops_without_retry_sampling_or_overwriting_peer(){reset();let record=Arc::new(record());let captured=Arc::clone(&record);wall(move||{captured.last_wall.store(101,Ordering::Release);Ok(100)});NOW.with(|v|*v.borrow_mut()=VecDeque::from([1,1,1,50]));denied(check(&record,false),"retired Signing original wall bounds");assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(1,101));assert_eq!(calls(),vec!["require_time","entry","wall"]);diag(&["SharedWallDeadline"]);}
#[test] fn repeated_contention_resamples_under_same_bound_and_high_water(){reset();let record=Arc::new(record());let captured=Arc::clone(&record);let mut count=0;wall(move||{count+=1;if count<4{captured.last_wall.store(100+count,Ordering::Release);}Ok(100+count)});check(&record,false).unwrap();assert_eq!((samples(),record.last_wall.load(Ordering::Acquire)),(4,104));diag(&[]);}
'''

EXPECTED_TESTS = {
    'actual_legacy_check_reproduces_delayed_sample_false_rollback',
    'actual_candidate_check_resamples_delayed_sample_without_false_rollback',
    'true_rollback_remains_denied_without_retry_or_lower_publication',
    'wall_error_preserves_original_kind_payload_identity_and_single_attempt',
    'every_original_bound_is_the_same_immutable_minimum',
    'entry_bounds_follow_original_time_and_precede_wall_or_phase',
    'service_interval_keeps_inclusive_start_and_exclusive_end',
    'equal_and_advancing_wall_samples_remain_accepted',
    'phase_revocation_and_retired_tombstone_guards_are_unchanged',
    'quiescence_skips_only_core_delegate_and_keeps_final_revocation_guard',
    'nonquiescent_host_and_root_delegate_failures_still_propagate',
    'revocation_after_successful_core_delegate_still_refuses',
    'helper_refuses_original_expiry_after_entry_before_sampling',
    'helper_refuses_expiry_during_sample_before_publication',
    'helper_refuses_expiry_after_cas_without_renewing_original',
    'contention_expiry_stops_without_retry_sampling_or_overwriting_peer',
    'repeated_contention_resamples_under_same_bound_and_high_water',
}

def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def block(text, needle):
    assert text.count(needle) == 1, ('non-unique extraction', needle)
    start = text.index(needle)
    first = text.index('{', start)
    depth = 0
    for pos in range(first, len(text)):
        depth += (text[pos] == '{') - (text[pos] == '}')
        if depth == 0:
            return text[start:pos + 1]
    raise AssertionError(('unclosed extraction', needle))


def extract(source):
    source = Path(source)
    candidate = (source / CUSTODY).read_bytes().decode('utf-8')
    state = (source / STATE).read_bytes().decode('utf-8')
    assert digest(candidate) == CANDIDATE_SHA256, 'candidate custody source drift'
    assert digest(state) == STATE_SHA256, 'unchanged shared-wall/state source drift'
    assert candidate.count(AFTER) == 1 and BEFORE not in candidate, 'unique P90 replacement absent'
    legacy = candidate.replace(AFTER, BEFORE)
    assert digest(legacy) == BASELINE_SHA256, 'whole-file P89 inverse drift'
    candidate_check = block(block(candidate, 'impl SignedResultRecord {'), '    pub(super) fn check(&self)->Result<()>')
    legacy_check = block(block(legacy, 'impl SignedResultRecord {'), '    pub(super) fn check(&self)->Result<()>')
    assert candidate_check.replace(AFTER, BEFORE) == legacy_check
    helper = block(state, 'pub(crate) fn observe_shared_wall(')
    actor_macro = block(state, 'macro_rules! actor_boundary ')
    return dict(candidate_source=candidate, legacy_source=legacy,
                candidate_check=candidate_check, legacy_check=legacy_check,
                helper=helper, actor_macro=actor_macro)


def generate(source, out):
    source, out = Path(source), Path(out)
    value = extract(source)
    names = set(re.findall(r'#\[test\]\s*fn\s+([A-Za-z0-9_]+)', TESTS))
    assert names == EXPECTED_TESTS and len(names) == 17, 'test selection drift'
    candidate = value['candidate_check'].replace('fn check(', 'fn check_candidate(', 1)
    legacy = value['legacy_check'].replace('fn check(', 'fn check_legacy(', 1)
    assert candidate.replace('fn check_candidate(', 'fn check(', 1) == value['candidate_check']
    assert legacy.replace('fn check_legacy(', 'fn check(', 1) == value['legacy_check']
    rust = (PREFIX + '\n' + value['actor_macro'] + '\nmod state {\nuse super::*;\n'
            + 'pub(super) fn wall_ms()->Result<u64>{log("wall");SAMPLES.with(|v|v.set(v.get()+1));WALL.with(|v|{let mut callback=v.borrow_mut();match callback.as_mut(){Some(f)=>f(),None=>Ok(100)}})}\n'
            + value['helper'] + '\n}\nmod custody {\nuse super::*;\nimpl SignedResultRecord {\n'
            + candidate + '\n' + legacy + '\n}\n}\n' + TESTS)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'retired-wall-trace.rs').write_text(rust)
    binding = {
        'source': str(source),
        'files': {CUSTODY: CANDIDATE_SHA256, STATE: STATE_SHA256},
        'legacy_full_source_sha256': BASELINE_SHA256,
        'candidate_check_sha256': digest(value['candidate_check']),
        'legacy_check_sha256': digest(value['legacy_check']),
        'unchanged_helper_sha256': digest(value['helper']),
        'unchanged_actor_macro_sha256': digest(value['actor_macro']),
        'rust_sha256': digest(rust), 'test_count': len(EXPECTED_TESTS),
        'tests': sorted(EXPECTED_TESTS), 'generated': True, 'executed': False,
        'limits': 'Actual method/helper text; modeled monotonic/wall clocks, entry/Core delegates and diagnostic sinks. No native liveness/authority or P89 causality proof.',
        'diagnostic_effect': 'Existing finite SharedWallDeadline/SharedWallRollback/SharedWallRead sites become reachable from this check; helper unchanged.',
    }
    (out / 'binding.json').write_text(json.dumps(binding, indent=2, sort_keys=True) + '\n')
    return binding


def run(command, path, timeout):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or ''
        path.write_text(partial.decode(errors='replace') if isinstance(partial, bytes) else partial)
        raise
    except OSError as error:
        path.write_text(str(error) + '\n')
        raise
    path.write_text(result.stdout)
    if result.returncode:
        print(result.stdout[-16384:], file=sys.stderr)
        raise SystemExit(f'{path.name} failed: {result.returncode}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run', action='store_true', help='Explicitly compile/run only in an authorized test environment')
    args = parser.parse_args()
    binding = generate(args.source, args.out)
    print(json.dumps({'generated': True, 'executed': False, 'tests': binding['test_count']}))
    if args.run:
        # Never merge stale successful execution evidence into a fresh attempt.
        execution = args.out / 'execution'
        execution.mkdir(exist_ok=False)
        receipt = {'status': 'running', 'native_execution_attempted': False,
                   'native_listings_completed': [], 'compiler': None,
                   'expected_compiler': PINNED_RUSTC, 'compiled_profiles': [],
                   'tests_started': [], 'profiles_passed': [],
                   'tests_per_profile': len(EXPECTED_TESTS),
                   'rust_sha256': binding['rust_sha256'],
                   'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'binding_sha256': hashlib.sha256((args.out / 'binding.json').read_bytes()).hexdigest()}

        def retain():
            receipt['log_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                     for path in sorted(execution.glob('*.log'))}
            (execution / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')

        retain()
        try:
            version = run(['rustc', '--version'], execution / 'compiler-version.log', 15).strip()
            receipt['compiler'] = version
            if version != PINNED_RUSTC:
                raise RuntimeError('wrong rustc identity: ' + version)
            for profile, flags in [('production', []), ('semantic', ['--cfg', 'wholepact_financial_rendered_host_semantic_ci'])]:
                binary = execution / ('retired-wall-tests-' + profile)
                run(['rustc', '--edition=2021', '--test', *flags, str(args.out / 'retired-wall-trace.rs'), '-o', str(binary)], execution / (profile + '-compile.log'), 60)
                receipt['compiled_profiles'].append(profile)
                retain()
                receipt['native_execution_attempted'] = True
                retain()
                listed = run([str(binary), '--list'], execution / (profile + '-list.log'), 10)
                receipt['native_listings_completed'].append(profile)
                names = {line[:-6] for line in listed.splitlines() if line.endswith(': test')}
                assert names == EXPECTED_TESTS, ('compiled test inventory mismatch', names)
                receipt['tests_started'].append(profile)
                retain()
                output = run([str(binary), '--test-threads=1'], execution / (profile + '-tests.log'), 30)
                assert f'{len(EXPECTED_TESTS)} passed; 0 failed; 0 ignored' in output
                receipt['profiles_passed'].append(profile)
                retain()
            receipt.update(status='success')
            retain()
        except BaseException as error:
            receipt.update(status='timed_out' if isinstance(error, subprocess.TimeoutExpired) else 'failed',
                           error_type=type(error).__name__)
            retain()
            raise
        print(json.dumps({'executed': True, 'profiles': receipt['profiles_passed'], 'tests_per_profile': len(EXPECTED_TESTS)}))


if __name__ == '__main__':
    main()
