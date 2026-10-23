#!/usr/bin/env python3
"""Exact request/history client bodies with inert transport/time/data outcomes.

The response-reader kernel has a separate witness. No socket, authority or real
clock/credential is created here; the original polling sleep is an inert adapter.
"""
import argparse, hashlib, json, os, re, subprocess
from pathlib import Path


def block(s,m):
    a=s.index(m);i=s.index('{',a);depth=1;pos=i+1
    token=re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]',re.S)
    while depth:
        hit=token.search(s,pos)
        if hit is None:raise ValueError(m)
        depth+=(hit.group()=='{')-(hit.group()=='}');pos=hit.end()
    return s[a:pos]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--run',action='store_true');a=p.parse_args()
    root,out=a.source.resolve(),a.out.resolve();out.mkdir(parents=True,exist_ok=True);sources=[];pieces=[]
    def read(path):
        data=(root/path).read_bytes();sources.append({'path':path,'sha256':hashlib.sha256(data).hexdigest()});return data.decode()
    def take(s,m):
        text=block(s,m);pieces.append({'marker':m,'sha256':hashlib.sha256(text.encode()).hexdigest()});return text
    s=read('crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/admission_v1.rs')
    frame=read('crates/wholepact-signer-origin/src/framing.rs')
    request=take(s,'fn request_admission_retained_inner_v1(');history=take(s,'fn read_original_status_retained_inner_v1(')
    req_wrap='\n'.join(take(s,m) for m in ['pub fn request_admission_retained_v1(','pub fn request_admission_retained_observed_v1('])
    his_wrap='\n'.join(take(s,m) for m in ['pub fn read_original_status_retained_v1(','pub fn read_original_status_retained_observed_v1('])
    old_request='pub fn request_admission_retained_v1(\n        self,\n    ) -> Result<PendingCoordinatedDurableDeliveryAdmissionV1> '+request[request.index('{'):]
    old_history='pub fn read_original_status_retained_v1(\n        &mut self,\n    ) -> Result<CoordinatedDurableDeliveryAdmissionStatusV1> '+history[history.index('{'):]
    # P51 narrows only the single exchange transport ceiling. Reconstruct the
    # already-tested P47 operation body before its fixed baseline comparison.
    transport = ("            // One attempted Admit keeps its owner and original material bound.\n"
                 "            // Only this request's transport wait is narrowed to 120 seconds.\n"
                 "            let request_deadline = pending.deadline.min(pending.client.deadline).min(Instant::now() + Duration::from_secs(120));\n")
    assert old_request.count(transport) == 1
    old_request = old_request.replace(transport, '').replace(
        '                request_deadline,\n', '                pending.deadline,\n').replace(
        '&stream,request_deadline,', '&stream,pending.deadline,')
    old_request=re.sub(r'^\s*\*stage = CoordinatedAdmissionFailureStageV1::\w+;\n','',old_request,flags=re.M)
    old_history=re.sub(r'^\s*\*stage = CoordinatedAdmissionFailureStageV1::\w+;\n','',old_history,flags=re.M)
    old_history=old_history.replace('self.client.closed_response_detailed_v1(&stream, wait, &|| Ok(()), stage, frame_cause)', 'self.client.closed_response(&stream, wait, &|| Ok(()))')
    old_history=old_history.replace('''                _ => {
                    return Err(BridgeError::Permission);
                }''','''                _ => return Err(BridgeError::Permission),''')
    for name,text,digest in [('P47 original request',old_request,'599d3f5033bed41f980a21fe6d21c576fa1d5065c220be35df01aefdffa29e97'),('P47 original history',old_history,'0944c714a50594dac6853e961d07a82eb857daf96d5cc56e1e491c60551ec12a')]:
        assert hashlib.sha256(text.encode()).hexdigest()==digest,name
        pieces.append({'marker':name,'sha256':digest})
    stage=take(s,'pub enum CoordinatedAdmissionFailureStageV1 {');failure=take(s,'pub struct CoordinatedAdmissionFailureV1 {');failure_impl=take(s,'impl CoordinatedAdmissionFailureV1 {')
    attempt=take(s,'pub enum CoordinatedAdmissionAttemptV1 {');frame_enum=take(frame,'pub enum FrameReadCause {')
    prefix=r'''#![allow(dead_code,unused_imports)]
use std::{cell::RefCell,collections::{VecDeque,HashMap},ops::Add};
#[derive(Clone,Debug,PartialEq,Eq)]enum BridgeError{Permission,Binding,Uncertain,Ipc}
type Result<T>=std::result::Result<T,BridgeError>;
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
impl Instant{fn now()->Self{Self(10)}}
#[derive(Clone,Copy)]struct Duration(u64);impl Duration{fn from_secs(n:u64)->Self{Self(n*1000)}fn from_millis(n:u64)->Self{Self(n)}}
impl Add<Duration> for Instant{type Output=Self;fn add(self,d:Duration)->Self{Self(self.0+d.0)}}
mod fake_std{pub use ::std::*;pub mod thread{pub fn sleep(_:crate::Duration){crate::log("sleep");}}}
#[derive(Clone,Debug,PartialEq,Eq)]struct CoordinatedDurableDeliveryAdmissionStatusV1{request:u8,original_local_intent_digest:String,valid:bool}
#[derive(Clone)]struct Owner{account_id:u8,participant_id:u8,original_authorization_id:String}
struct Delivery{owners:Vec<Owner>}
struct Intent{account_id:u8,participant_id:u8,delivery:Delivery}
impl Intent{fn digest(&self)->Result<String>{step("intent")?;Ok("intent".into())}}
enum CoordinatedClosedCommandV1{Admit{intent_digest:String,nonce:String},History{intent_digest:String,authorization_id:String,nonce:String}}
#[derive(Clone)]enum CoordinatedClosedResponseV1{Admitting{nonce:String},Preparing{nonce:String},Admission{nonce:String,admission:CoordinatedDurableDeliveryAdmissionStatusV1},Other}
struct Stream{nonce:String}
struct Client{deadline:Instant}
impl Client{
 fn check_current(&self)->Result<()>{step("channel")}
 fn open_closed(&self,c:CoordinatedClosedCommandV1,d:Instant)->Result<Stream>{step("open")?;let nonce=match c{CoordinatedClosedCommandV1::Admit{intent_digest,nonce}=>{assert_eq!(intent_digest,"intent");log("Admit");nonce},CoordinatedClosedCommandV1::History{intent_digest,authorization_id,nonce}=>{assert_eq!(intent_digest,"intent");assert_eq!(authorization_id,"original-authorization");log("History");nonce}};SCRIPT.with(|v|v.borrow_mut().deadlines.push(d));Ok(Stream{nonce})}
 fn closed_response(&self,s:&Stream,_:Instant,current:&dyn Fn()->Result<()>)->Result<CoordinatedClosedResponseV1>{current()?;step("response")?;response(s)}
 // Explicit response-kernel adapter, NOT the actual framing/credential kernel.
 fn closed_response_detailed_v1(&self,s:&Stream,d:Instant,current:&dyn Fn()->Result<()>,stage:&mut CoordinatedAdmissionFailureStageV1,frame:&mut Option<wholepact_signer_origin::framing::FrameReadCause>)->Result<CoordinatedClosedResponseV1>{*stage=CoordinatedAdmissionFailureStageV1::ResponseFrame;self.closed_response(s,d,current).map_err(|e|{*frame=Some(wholepact_signer_origin::framing::FrameReadCause::Eof);e})}
}
#[derive(Clone)]struct Spec{history:bool,fail:Option<(&'static str,usize)>,responses:Vec<CoordinatedClosedResponseV1>,missing_owner:bool,expired:bool,previous:Option<CoordinatedDurableDeliveryAdmissionStatusV1>,client_deadline:u64}
impl Default for Spec{fn default()->Self{Self{history:false,fail:None,responses:vec![CoordinatedClosedResponseV1::Admitting{nonce:"AUTO".into()}],missing_owner:false,expired:false,previous:None,client_deadline:5000}}}
struct Script{trace:Vec<&'static str>,counts:HashMap<&'static str,usize>,fail:Option<(&'static str,usize)>,responses:VecDeque<CoordinatedClosedResponseV1>,deadlines:Vec<Instant>}
thread_local!{static SCRIPT:RefCell<Script>=RefCell::new(Script{trace:vec![],counts:HashMap::new(),fail:None,responses:VecDeque::new(),deadlines:vec![]});}
fn reset(s:&Spec){SCRIPT.with(|v|*v.borrow_mut()=Script{trace:vec![],counts:HashMap::new(),fail:s.fail,responses:s.responses.clone().into(),deadlines:vec![]});}
fn log(v:&'static str){SCRIPT.with(|s|s.borrow_mut().trace.push(v));}
fn step(name:&'static str)->Result<()>{SCRIPT.with(|v|{let mut s=v.borrow_mut();s.trace.push(name);let count={let n=s.counts.entry(name).or_insert(0);*n+=1;*n};if s.fail==Some((name,count)){Err(BridgeError::Ipc)}else{Ok(())}})}
fn require_before(d:Instant)->Result<()>{step("deadline")?;if Instant::now()>=d{Err(BridgeError::Permission)}else{Ok(())}}
fn fresh_nonce()->Result<String>{step("nonce")?;Ok(SCRIPT.with(|v|format!("nonce-{}",v.borrow().counts["nonce"])))}
fn response(s:&Stream)->Result<CoordinatedClosedResponseV1>{let mut r=SCRIPT.with(|v|v.borrow_mut().responses.pop_front()).ok_or(BridgeError::Ipc)?;match &mut r{CoordinatedClosedResponseV1::Admitting{nonce}|CoordinatedClosedResponseV1::Preparing{nonce}|CoordinatedClosedResponseV1::Admission{nonce,..}=>{if nonce=="AUTO"{*nonce=s.nonce.clone()}},_=>()};Ok(r)}
fn good_status()->CoordinatedDurableDeliveryAdmissionStatusV1{CoordinatedDurableDeliveryAdmissionStatusV1{request:1,original_local_intent_digest:"original".into(),valid:true}}
fn history_spec()->Spec{Spec{history:true,responses:vec![CoordinatedClosedResponseV1::Admission{nonce:"AUTO".into(),admission:good_status()}],..Spec::default()}}
'''
    prefix+='mod wholepact_signer_origin{pub mod framing{#[derive(Clone,Copy,Debug,PartialEq,Eq)]'+frame_enum+'}}\n#[derive(Clone,Copy,Debug,PartialEq,Eq)]'+stage+'\n'+failure+'\n'+failure_impl+'\n#[derive(Clone,Copy,Debug,PartialEq,Eq)]'+attempt+'\n'
    prefix+=r'''
#[derive(Debug,PartialEq,Eq)]struct Summary{result:Result<()>,attempt:Option<CoordinatedAdmissionAttemptV1>,attempt_error:Option<BridgeError>,status:Option<CoordinatedDurableDeliveryAdmissionStatusV1>,trace:Vec<&'static str>,deadlines:Vec<Instant>}
struct Report{summary:Summary,detail:Option<(CoordinatedAdmissionFailureStageV1,Option<wholepact_signer_origin::framing::FrameReadCause>)>}
'''
    common=r'''
use crate::*;use crate::fake_std as std;
struct VerifiedImportedCoordinatedDurableReviewSessionV1{client:Client,intent:Intent,deadline:Instant}
struct PendingCoordinatedDurableDeliveryAdmissionV1{client:Client,intent:Intent,deadline:Instant,status:Option<CoordinatedDurableDeliveryAdmissionStatusV1>,attempt:CoordinatedAdmissionAttemptV1,attempt_error:Option<BridgeError>}
impl PendingCoordinatedDurableDeliveryAdmissionV1{fn check_status(&self,s:&CoordinatedDurableDeliveryAdmissionStatusV1)->Result<()>{step("status")?;if s.valid{Ok(())}else{Err(BridgeError::Binding)}}}
pub(crate)fn run(s:Spec)->Report{reset(&s);let intent=Intent{account_id:1,participant_id:2,delivery:Delivery{owners:if s.missing_owner{vec![]}else{vec![Owner{account_id:1,participant_id:2,original_authorization_id:"original-authorization".into()}]}}};let client=Client{deadline:Instant(if s.expired{10}else{s.client_deadline})};let deadline=Instant(if s.expired{10}else{5000});
'''
    for name,observed in [('before',False),('after',True)]:
        prefix+='mod '+name+'{'+common
        if observed:
            history_call='match pending.read_original_status_retained_observed_v1(){Ok(_)=>(Ok(()),None),Err(f)=>{let d=(f.stage(),f.frame_cause());(Err(f.into_error()),Some(d))}}'
            request_call='match owner.request_admission_retained_observed_v1(){Ok(p)=>(Ok(()),Some(p.attempt),p.attempt_error,p.status,None),Err(f)=>{let d=(f.stage(),f.frame_cause());(Err(f.into_error()),None,None,None,Some(d))}}'
        else:
            history_call='(pending.read_original_status_retained_v1().map(|_|()),None)'
            request_call='match owner.request_admission_retained_v1(){Ok(p)=>(Ok(()),Some(p.attempt),p.attempt_error,p.status,None),Err(e)=>(Err(e),None,None,None,None)}'
        prefix+='let(result,attempt,attempt_error,status,detail)=if s.history {let mut pending=PendingCoordinatedDurableDeliveryAdmissionV1{client,intent,deadline,status:s.previous,attempt:CoordinatedAdmissionAttemptV1::Acknowledged,attempt_error:None};let(r,d)='+history_call+';(r,Some(pending.attempt),pending.attempt_error,pending.status,d)}else{let owner=VerifiedImportedCoordinatedDurableReviewSessionV1{client,intent,deadline};'+request_call+'};let(trace,deadlines)=SCRIPT.with(|v|{let s=v.borrow();(s.trace.clone(),s.deadlines.clone())});Report{summary:Summary{result,attempt,attempt_error,status,trace,deadlines},detail}}\n'
        prefix+='impl VerifiedImportedCoordinatedDurableReviewSessionV1{'+(req_wrap+'\n'+request if observed else old_request)+'}\nimpl PendingCoordinatedDurableDeliveryAdmissionV1{'+(his_wrap+'\n'+history if observed else old_history)+'}\n}\n'
    tests=r'''
fn both(s:Spec)->Report{let old=before::run(s.clone());assert!(old.detail.is_none());let new=after::run(s);assert_eq!(old.summary,new.summary,"old/new original Result or operation trace diverged");new}
#[test]fn all_four_preexchange_failure_stages_preserve_original_error(){use CoordinatedAdmissionFailureStageV1 as S;for(point,stage)in [("deadline",S::RequestDeadline),("channel",S::RequestChannel),("intent",S::RequestIntent),("nonce",S::RequestNonce)]{let r=both(Spec{fail:Some((point,1)),..Spec::default()});assert_eq!(r.summary.result,Err(BridgeError::Ipc));assert_eq!(r.detail,Some((stage,None)));assert!(!r.summary.trace.contains(&"Admit"));}}
#[test]fn all_nine_outer_history_failure_stages_are_actual_source_boundaries(){use CoordinatedAdmissionFailureStageV1 as S;let mut cases=vec![];for(point,stage)in [("intent",S::HistoryIntent),("deadline",S::HistoryDeadline),("nonce",S::HistoryNonce),("open",S::HistoryOpen),("status",S::HistoryStatus)]{cases.push((Spec{fail:Some((point,1)),..history_spec()},stage,BridgeError::Ipc));}cases.push((Spec{missing_owner:true,..history_spec()},S::HistoryOwner,BridgeError::Binding));cases.push((Spec{fail:Some(("channel",1)),responses:vec![CoordinatedClosedResponseV1::Preparing{nonce:"AUTO".into()}],..history_spec()},S::HistoryCurrent,BridgeError::Ipc));let mut previous=good_status();previous.request=2;cases.push((Spec{previous:Some(previous),..history_spec()},S::HistoryPrevious,BridgeError::Binding));cases.push((Spec{responses:vec![CoordinatedClosedResponseV1::Other],..history_spec()},S::HistoryResponseMatch,BridgeError::Permission));assert_eq!(cases.len(),9);for(spec,stage,error)in cases{let r=both(spec);assert_eq!(r.summary.result,Err(error));assert_eq!(r.detail,Some((stage,None)));}}
#[test]fn exchange_failures_remain_successful_pending_custody_not_terminal_observation(){for point in ["open","response"]{let r=both(Spec{fail:Some((point,1)),..Spec::default()});assert_eq!(r.summary.result,Ok(()));assert_eq!(r.summary.attempt,Some(CoordinatedAdmissionAttemptV1::PossiblyStarted));assert_eq!(r.summary.attempt_error,Some(BridgeError::Ipc));assert_eq!(r.detail,None);}let r=both(Spec{responses:vec![CoordinatedClosedResponseV1::Admitting{nonce:"wrong".into()}],..Spec::default()});assert_eq!(r.summary.result,Ok(()));assert_eq!(r.summary.attempt_error,Some(BridgeError::Uncertain));assert_eq!(r.detail,None);}
#[test]fn request_and_history_success_have_no_diagnostic_and_no_extra_operations(){let request=both(Spec::default());assert_eq!(request.summary.result,Ok(()));assert_eq!(request.summary.attempt,Some(CoordinatedAdmissionAttemptV1::Acknowledged));assert_eq!(request.detail,None);assert_eq!(request.summary.trace,vec!["deadline","channel","intent","nonce","open","Admit","response"]);let history=both(history_spec());assert_eq!(history.summary.result,Ok(()));assert_eq!(history.summary.status,Some(good_status()));assert_eq!(history.detail,None);assert!(!history.summary.trace.contains(&"Admit"));}
#[test]fn previous_binding_status_and_nonce_mismatch_remain_fail_closed(){for field in 0..2{let mut p=good_status();if field==0{p.request=2}else{p.original_local_intent_digest="changed".into()};let r=both(Spec{previous:Some(p),..history_spec()});assert_eq!(r.summary.result,Err(BridgeError::Binding));assert_eq!(r.detail.unwrap().0,CoordinatedAdmissionFailureStageV1::HistoryPrevious);}let mut invalid=good_status();invalid.valid=false;let r=both(Spec{responses:vec![CoordinatedClosedResponseV1::Admission{nonce:"AUTO".into(),admission:invalid}],..history_spec()});assert_eq!(r.summary.result,Err(BridgeError::Binding));assert_eq!(r.detail.unwrap().0,CoordinatedAdmissionFailureStageV1::HistoryStatus);for response in [CoordinatedClosedResponseV1::Preparing{nonce:"wrong".into()},CoordinatedClosedResponseV1::Admission{nonce:"wrong".into(),admission:good_status()}]{let r=both(Spec{responses:vec![response],..history_spec()});assert_eq!(r.summary.result,Err(BridgeError::Permission));assert_eq!(r.detail.unwrap().0,CoordinatedAdmissionFailureStageV1::HistoryResponseMatch);}}
#[test]fn preparing_response_continues_original_read_only_poll_with_fresh_nonce(){let r=both(Spec{responses:vec![CoordinatedClosedResponseV1::Preparing{nonce:"AUTO".into()},CoordinatedClosedResponseV1::Admission{nonce:"AUTO".into(),admission:good_status()}],..history_spec()});assert_eq!(r.summary.result,Ok(()));assert_eq!(r.detail,None);assert_eq!(r.summary.trace.iter().filter(|x|**x=="nonce").count(),2);assert_eq!(r.summary.trace.iter().filter(|x|**x=="History").count(),2);assert_eq!(r.summary.trace.iter().filter(|x|**x=="sleep").count(),1);assert!(!r.summary.trace.contains(&"Admit"));}
#[test]fn original_request_and_history_deadlines_and_120_cap_unchanged(){for history in [false,true]{let base=if history{history_spec()}else{Spec::default()};let r=both(Spec{expired:true,..base});assert_eq!(r.summary.result,Err(BridgeError::Permission));assert!(!r.summary.trace.contains(&"open"));}let r=both(Spec{client_deadline:900_000,..history_spec()});assert_eq!(r.summary.result,Ok(()));assert_eq!(r.summary.deadlines,vec![Instant(120_010)]);let r=both(history_spec());assert_eq!(r.summary.deadlines,vec![Instant(5000)]);}
#[test]fn response_detail_is_propagated_without_classifying_frame_here(){let r=both(Spec{fail:Some(("response",1)),..history_spec()});assert_eq!(r.summary.result,Err(BridgeError::Ipc));assert_eq!(r.detail,Some((CoordinatedAdmissionFailureStageV1::ResponseFrame,Some(wholepact_signer_origin::framing::FrameReadCause::Eof))));assert!(!r.summary.trace.contains(&"status"));}
'''
    code=prefix+tests;assert len(re.findall(r'#\[test\]',code))==8
    path=out/'admission-client-trace.rs';path.write_text(code)
    binding={'version':1,'sources':sources,'pieces':pieces,'tests':8,'harness_sha256':hashlib.sha256(code.encode()).hexdigest(),'executed':False,'limits':['13 outer checkpoint branches run exact source against inert external operations.','Response kernel, credentials, status business validation, transport and sleep are explicit inert adapters; response kernel has a separate witness.','Actual old methods normalize to frozen P47 hashes; no real authority, socket, clock lease or full workflow claim.']};bp=out/'admission-client-source-bindings.json';bp.write_text(json.dumps(binding,indent=2)+'\n')
    if a.run:
        exe=out/'admission-client-trace-tests'
        def run(cmd,timeout,log):
            r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout);(out/log).write_text(r.stdout)
            if r.returncode:print(r.stdout,end='');raise SystemExit(r.returncode)
            return r.stdout
        run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test',str(path),'-o',str(exe)],60,'compile.log');listing=run([str(exe),'--list'],10,'list.log');names=[v[:-6] for v in listing.splitlines() if v.endswith(': test')];expected=re.findall(r'#\[test\]\s*fn (\w+)\(',tests)
        if len(names)!=8 or set(names)!=set(expected):raise SystemExit('exact 8-test listing mismatch')
        print(run([str(exe),'--test-threads=1'],30,'tests.log'),end='');binding['executed']=True;bp.write_text(json.dumps(binding,indent=2)+'\n')
    print(json.dumps({'tests':8,'outer_stages':13,'executed':a.run}))


if __name__=='__main__':main()
