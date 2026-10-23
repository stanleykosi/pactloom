#!/usr/bin/env python3
"""Actual Pair constructor/clock conversion with inert entry, DTO and time.

The exact original epoch-offset, wall-cap, shared-wall and constructor bodies are
extracted. This checks arithmetic/control flow, not genuine approval, process
custody, DTO authentication, scheduling, sockets, or clock-provider behavior.
"""
import argparse, hashlib, json, os, re, subprocess, sys
from pathlib import Path


def block(s, marker):
    start=s.index(marker); pos=s.index('{',start)+1; depth=1
    token=re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]',re.S)
    while depth:
        hit=token.search(s,pos)
        if hit is None: raise ValueError(marker)
        depth+=(hit.group()=='{')-(hit.group()=='}');pos=hit.end()
    return s[start:pos]


PREFIX=r'''#![allow(dead_code,unused_imports)]
use std::{cell::RefCell,collections::VecDeque,sync::{Arc,atomic::{AtomicU64,Ordering}},time::Duration,ops::{Add,Sub}};
#[derive(Debug,Clone,PartialEq,Eq)]struct Error(&'static str);
type Result<T>=std::result::Result<T,Error>;
fn rejected(s:&'static str)->Error{Error(s)}
// Deterministic nanosecond Instant adapter. Actual production conversion code
// is literal; this is not an assertion about the operating system clock.
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u128);
impl Instant{
 fn now()->Self{SCRIPT.with(|s|{let mut s=s.borrow_mut();s.trace.push("now");s.now})}
 fn checked_add(self,d:Duration)->Option<Self>{self.0.checked_add(d.as_nanos()).map(Self)}
 fn checked_duration_since(self,old:Self)->Option<Duration>{self.0.checked_sub(old.0).and_then(|n|u64::try_from(n).ok()).map(Duration::from_nanos)}
}
impl Add<Duration> for Instant{type Output=Self;fn add(self,d:Duration)->Self{self.checked_add(d).unwrap()}}
impl Sub<Duration> for Instant{type Output=Self;fn sub(self,d:Duration)->Self{Self(self.0.checked_sub(d.as_nanos()).unwrap())}}
struct Script{now:Instant,wall:u64,walls:VecDeque<Result<u64>>,trace:Vec<&'static str>,custody:bool}
thread_local!{static SCRIPT:RefCell<Script>=RefCell::new(Script{now:Instant(100_000_000_000),wall:1_000_000,walls:VecDeque::new(),trace:vec![],custody:true});}
fn reset(){SCRIPT.with(|s|*s.borrow_mut()=Script{now:Instant(100_000_000_000),wall:1_000_000,walls:VecDeque::new(),trace:vec![],custody:true});}
fn edit(f:impl FnOnce(&mut Script)){SCRIPT.with(|s|f(&mut s.borrow_mut()));}
fn trace()->Vec<&'static str>{SCRIPT.with(|s|s.borrow().trace.clone())}
macro_rules! actor_boundary{($($v:tt)*)=>{{}};}
#[derive(Clone)]struct Facts{reviewed_at_ms:u64,expires_at_ms:u64,channel_expires_at_ms:u64}
#[derive(Clone)]struct SignerV3PairPresentationV1{facts:Facts,source_ceiling_ms:u64,pair_ceiling_ms:u64,channel_ceiling_ms:u64,actor:u8,valid:bool}
impl SignerV3PairPresentationV1{fn validate(&self)->Result<()>{SCRIPT.with(|s|s.borrow_mut().trace.push("validate"));if self.valid{Ok(())}else{Err(rejected("inert malformed DTO"))}}}
struct EntryPresentation{source_ceiling_ms:u64,actor:u8}
struct EntryWire{presentation:EntryPresentation}
struct V3EntryReviewed{clocks:FullWorkflowClocksV1,original_source:Instant,wire:EntryWire}
impl V3EntryReviewed{fn check_custody(&self)->Result<()>{SCRIPT.with(|s|{let mut s=s.borrow_mut();s.trace.push("custody");if s.custody{Ok(())}else{Err(rejected("inert custody denied"))}})}}
'''
TESTS=r'''
fn instant_ms(ms:u64)->Instant{Instant(u128::from(ms)*1_000_000)}
fn spec()->(Arc<V3EntryReviewed>,SignerV3PairPresentationV1){let clocks=FullWorkflowClocksV1::from_initial_epoch(Instant(0)).unwrap();(Arc::new(V3EntryReviewed{clocks,original_source:instant_ms(1_800_000),wire:EntryWire{presentation:EntryPresentation{source_ceiling_ms:1_800_000,actor:1}}}),SignerV3PairPresentationV1{facts:Facts{reviewed_at_ms:1_000_000,expires_at_ms:1_120_000,channel_expires_at_ms:1_900_000},source_ceiling_ms:1_800_000,pair_ceiling_ms:220_000,channel_ceiling_ms:1_000_000,actor:1,valid:true})}
#[test]fn displayed_900_channel_is_not_silently_a_120_action_for_either_actor(){for actor in [1,2]{reset();let(mut e,mut p)=spec();Arc::get_mut(&mut e).unwrap().wire.presentation.actor=actor;p.actor=actor;let old=before::make(e.clone(),p.clone()).unwrap();let old_trace=trace();reset();let new=after::make(e,p).unwrap();assert_eq!(trace(),old_trace);assert_eq!(old,(instant_ms(220_000),instant_ms(220_000)));assert_eq!(new,(instant_ms(1_000_000),instant_ms(220_000)));}}
#[test]fn original_source_offset_and_supervision_all_still_cap_channel(){for (source,offset,expected) in [(150_000,1_000_000,150_000),(1_800_000,500_000,500_000),(700_000,900_000,700_000)]{reset();let(mut e,mut p)=spec();Arc::get_mut(&mut e).unwrap().original_source=instant_ms(source);p.channel_ceiling_ms=offset;let(channel,action)=after::make(e,p).unwrap();assert_eq!(channel,instant_ms(expected));assert_eq!(action,instant_ms(expected.min(220_000)));}reset();let(mut e,mut p)=spec();let e=Arc::get_mut(&mut e).unwrap();e.original_source=instant_ms(2_000_000);let clocks=e.clocks;assert_eq!(clocks.restrict_received(PROFILE,1_800_000,instant_ms(2_000_000),instant_ms(100_000)).unwrap(),instant_ms(1_800_000));p.channel_ceiling_ms=1_800_001;assert!(clocks.restrict_received(PROFILE,p.channel_ceiling_ms,instant_ms(2_000_000),instant_ms(100_000)).is_err());}
#[test]fn exact_wall_expiry_is_an_independent_restrictive_minimum(){for (remaining,expected) in [(75_000,175_000),(400_000,500_000),(900_000,1_000_000)]{reset();let(e,mut p)=spec();p.facts.channel_expires_at_ms=1_000_000+remaining;let(c,a)=after::make(e,p).unwrap();assert_eq!(c,instant_ms(expected));assert_eq!(a,instant_ms(expected.min(220_000)));}}
#[test]fn late_receiver_construction_never_renews_channel_or_action(){reset();let(e,p)=spec();let initial=after::make(e.clone(),p.clone()).unwrap();edit(|s|{s.now=instant_ms(130_000);s.wall=1_030_000;});let later=after::make(e,p).unwrap();assert_eq!(later,initial);assert_eq!(later,(instant_ms(1_000_000),instant_ms(220_000)));}
#[test]fn strict_original_expiry_and_wall_equality_fail_closed(){for now in [1_000_000,1_000_001]{reset();let(e,p)=spec();edit(|s|s.now=instant_ms(now));assert!(after::make(e,p).is_err());}for wall in [999_999,1_120_000,1_900_000]{reset();let(e,p)=spec();edit(|s|s.wall=wall);assert!(after::make(e,p).is_err());}}
#[test]fn wall_rollback_provider_error_and_custody_remain_denials(){reset();let(e,p)=spec();edit(|s|s.walls=vec![Ok(1_000_000),Ok(1_000_000),Ok(1_000_000),Ok(999_999)].into());assert_eq!(after::make(e,p),Err(rejected("Pair original channel expired")));reset();let(e,p)=spec();edit(|s|s.walls=vec![Err(rejected("inert wall error"))].into());assert_eq!(after::make(e,p),Err(rejected("inert wall error")));reset();let(e,p)=spec();edit(|s|s.custody=false);assert_eq!(after::make(e,p),Err(rejected("inert custody denied")));}
#[test]fn submillisecond_wire_floor_only_shortens_original_instant(){reset();let(e,mut p)=spec();let original=instant_ms(1_000_000)+Duration::from_nanos(999_999);p.channel_ceiling_ms=e.clocks.restrictive_offset(original,e.original_source).unwrap();assert_eq!(p.channel_ceiling_ms,1_000_000);edit(|s|s.now=instant_ms(100_000)+Duration::from_nanos(999));let(c,_)=after::make(e,p).unwrap();assert_eq!(c,instant_ms(1_000_000));assert!(c<original);}
#[test]fn malformed_dto_returns_before_any_clock_or_custody_work(){for after_fix in [false,true]{reset();let(e,mut p)=spec();p.valid=false;let r=if after_fix{after::make(e,p)}else{before::make(e,p)};assert_eq!(r,Err(rejected("inert malformed DTO")));assert_eq!(trace(),vec!["validate"]);}}
#[test]fn exact_original_actor_and_source_bindings_are_unchanged(){for mismatch in [0,1]{for after_fix in [false,true]{reset();let(e,mut p)=spec();if mismatch==0{p.actor=2}else{p.source_ceiling_ms-=1}let r=if after_fix{after::make(e,p)}else{before::make(e,p)};assert_eq!(r,Err(rejected("Pair original actor/source clock")));assert!(!trace().contains(&"custody"));}}}
#[test]fn longer_channel_does_not_keep_pair_action_alive(){reset();let(e,p)=spec();let(channel,action)=after::inspect(e,p,instant_ms(221_000),1_121_000).unwrap();assert_eq!(channel,Ok(()));assert_eq!(action,Err(rejected("Pair original action expired")));}
#[test]fn only_private_channel_wall_helper_has_900_second_cap(){let now=instant_ms(100_000);assert_eq!(wall_ceiling(now,1_000_000,1_000_000,2_000_000).unwrap(),instant_ms(220_000));assert_eq!(pair_channel_wall_ceiling(now,1_000_000,1_000_000,2_000_000).unwrap(),instant_ms(1_000_000));for helper in [wall_ceiling,pair_channel_wall_ceiling]{assert!(helper(now,10,11,100).is_err());assert!(helper(now,100,10,100).is_err());assert!(helper(Instant(u128::MAX),10,10,100).is_err());}}
#[test]fn actual_epoch_receiver_rejects_bad_profile_offset_and_expiry(){let c=FullWorkflowClocksV1::from_initial_epoch(Instant(0)).unwrap();for (profile,offset) in [("wrong",1000),(PROFILE,0),(PROFILE,1_800_001)]{assert!(c.restrict_received(profile,offset,instant_ms(1_800_000),Instant(0)).is_err());}assert!(c.restrict_received(PROFILE,1000,instant_ms(2000),instant_ms(1000)).is_err());assert_eq!(c.restrict_received(PROFILE,1000,instant_ms(900),Instant(0)).unwrap(),instant_ms(900));}
'''
EXPECTED=['displayed_900_channel_is_not_silently_a_120_action_for_either_actor','original_source_offset_and_supervision_all_still_cap_channel','exact_wall_expiry_is_an_independent_restrictive_minimum','late_receiver_construction_never_renews_channel_or_action','strict_original_expiry_and_wall_equality_fail_closed','wall_rollback_provider_error_and_custody_remain_denials','submillisecond_wire_floor_only_shortens_original_instant','malformed_dto_returns_before_any_clock_or_custody_work','exact_original_actor_and_source_bindings_are_unchanged','longer_channel_does_not_keep_pair_action_alive','only_private_channel_wall_helper_has_900_second_cap','actual_epoch_receiver_rejects_bad_profile_offset_and_expiry']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,type=Path);parser.add_argument('--out',required=True,type=Path);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    root,out=args.source.resolve(),args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    files=[];pieces=[]
    def read(path):
        raw=(root/path).read_bytes();files.append({'path':path,'sha256':hashlib.sha256(raw).hexdigest()});return raw.decode()
    def take(s,m):
        v=block(s,m);pieces.append({'marker':m,'sha256':hashlib.sha256(v.encode()).hexdigest()});return v
    pre='crates/wholepact-financial-coordinator-origin/src/'
    pair=read(pre+'signer_v3_pair_origin.rs');entry=read(pre+'signer_v3_source_entry_origin.rs');clock=read(pre+'financial_workflow_clock.rs');state=read(pre+'signer_continue_state.rs')
    constructor=take(pair,'fn new(entry: Arc<V3EntryReviewed>, p: SignerV3PairPresentationV1)')
    assert constructor.count('.min(pair_channel_wall_ceiling(')==1
    before=constructor.replace('.min(pair_channel_wall_ceiling(','.min(wall_ceiling(')
    assert hashlib.sha256(before.encode()).hexdigest()=='b36227f891219ee4e374cff7c8902e91814e6780751e2106977f59453cc8d17e'
    shape=take(pair,'pub(super) struct PairBinding {');channel=take(pair,'pub(super) fn channel_bounds(');bounds=take(pair,'fn bounds(')
    wall=take(entry,'pub(super) fn wall_ceiling(');new_wall=take(pair,'fn pair_channel_wall_ceiling(');sampler=take(state,'pub(crate) fn observe_shared_wall(')
    constants='\n'.join(re.findall(r'^(?:pub\(super\) )?const [^\n]+;',clock,re.M))
    assert all(x in constants for x in ['1_800_000','from_secs(30)','from_secs(5)'])
    clock_struct=take(clock,'pub(super) struct FullWorkflowClocksV1 {');clock_impl=take(clock,'impl FullWorkflowClocksV1 {');check_offset=take(clock,'fn check_offset(')
    text=PREFIX+'\nmod clock {use super::*;\n'+constants+'\n#[derive(Clone,Copy)]\n'+clock_struct+'\n'+clock_impl+'\n'+check_offset+'\n}\nuse clock::{FullWorkflowClocksV1,PROFILE};\n'
    text+='mod state {use super::*;pub(super) fn wall_ms()->Result<u64>{SCRIPT.with(|s|{let mut s=s.borrow_mut();s.trace.push("wall");s.walls.pop_front().unwrap_or(Ok(s.wall))})}\n'+sampler+'\n}\n'
    # pub(super) wall helper stays in a module; no visibility/body rewrite.
    text+='mod wall_helpers {use super::*;\n'+wall+'\n'+new_wall+'\npub(super) fn channel(now:Instant,wall:u64,start:u64,end:u64)->Result<Instant>{pair_channel_wall_ceiling(now,wall,start,end)}\n}\nuse wall_helpers::{wall_ceiling,channel as pair_channel_wall_ceiling};\n'
    for name,new in [('before',before),('after',constructor)]:
        text+='mod '+name+' {use super::*;\n'+shape+'\nimpl PairBinding {\n'+new+'\n'+channel+'\n'+bounds+'\n}\n'
        text+='pub(super) fn make(e:Arc<V3EntryReviewed>,p:SignerV3PairPresentationV1)->Result<(Instant,Instant)>{let x=PairBinding::new(e,p)?;Ok((x.channel_deadline,x.deadline))}\n'
        text+='pub(super) fn inspect(e:Arc<V3EntryReviewed>,p:SignerV3PairPresentationV1,now:Instant,wall:u64)->Result<(Result<()>,Result<()>)>{let x=PairBinding::new(e,p)?;edit(|s|{s.now=now;s.wall=wall;});Ok((x.channel_bounds(),x.bounds()))}\n}\n'
    text+=TESTS
    assert sorted(re.findall(r'#\[test\]fn (\w+)\(',text))==sorted(EXPECTED)
    generated=out/'pair-channel-trace.rs';generated.write_text(text)
    binding={'version':1,'sources':files,'fragments':pieces,'P48_constructor_normalized_sha256':hashlib.sha256(before.encode()).hexdigest(),'generated_sha256':hashlib.sha256(text.encode()).hexdigest(),'expected_count':12,'expected_tests':EXPECTED,'executed':False,'limitations':['Instant/wall providers and custody/DTO validation are inert deterministic adapters.','Exact constructor, clock epoch/offset/restriction algorithms, wall helpers and shared-wall sampler are literal source.','No actual approval, authority, complete DTO validator, socket, process, concurrency or operating-system clock execution is claimed.']}
    record=out/'pair-channel-source-bindings.json';record.write_text(json.dumps(binding,indent=2)+'\n')
    if args.run:
        exe=out/'pair-channel-trace'
        for command,timeout,log in [([os.environ.get('RUSTC','rustc'),'--edition=2021','--test',str(generated),'-o',str(exe)],60,'compile.log'),([str(exe),'--list'],10,'list.log'),([str(exe),'--test-threads=1'],30,'tests.log')]:
            result=subprocess.run(command,text=True,capture_output=True,timeout=timeout);(out/log).write_text(result.stdout+result.stderr)
            if result.returncode:
                # Source-extracted compiler/test output only, never private runtime.
                diagnostic=(result.stdout+result.stderr)[-16_384:]
                print(f'{log} diagnostic (last 16384 characters):',file=sys.stderr)
                print(diagnostic,file=sys.stderr)
                raise SystemExit(f'{log} failed: {result.returncode}')
            if log=='list.log':assert sorted(re.findall(r'^(\w+): test$',result.stdout,re.M))==sorted(EXPECTED)
            if log=='tests.log':assert 'test result: ok. 12 passed; 0 failed;' in result.stdout
        binding['executed']=True;record.write_text(json.dumps(binding,indent=2)+'\n')
    print(json.dumps({'generated':str(generated),'tests':12,'executed':args.run}))


if __name__=='__main__':main()
