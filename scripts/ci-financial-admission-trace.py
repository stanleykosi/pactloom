#!/usr/bin/env python3
"""Literal Host admission control flow against explicit inert outcomes.

No actor authorities, sockets, native processes, deadlines, or real audit data.
The pre-fix functions are source-normalized and checked against frozen P47 hashes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def block(text, marker):
    start = text.index(marker); opening = text.index('{', start)
    depth, position = 1, opening + 1
    token = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]', re.S)
    while depth:
        match = token.search(text, position)
        if match is None: raise ValueError('unclosed source block: ' + marker)
        if match.group() == '{': depth += 1
        elif match.group() == '}': depth -= 1
        position = match.end()
    return text[start:position]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True,type=Path);p.add_argument('--out',required=True,type=Path)
    p.add_argument('--run',action='store_true');args=p.parse_args()
    root,out=args.source.resolve(),args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    sources=[];chunks=[]
    def read(path):
        data=(root/path).read_bytes();sources.append({'path':path,'sha256':hashlib.sha256(data).hexdigest()});return data.decode()
    def bind(name,text):
        chunks.append({'label':name,'sha256':hashlib.sha256(text.encode()).hexdigest()});return text
    export=read('crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2/closed_review_v3/coordinated_export_v1.rs')
    closed=read('crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2/closed_review_v3.rs')
    classifier=read('crates/wholepact-native-host/src/financial_ci_host_failure.rs')
    diagnostics=read('crates/wholepact-financial-coordinator-origin/src/financial_ci_host_diagnostics.rs')
    admission=read('crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/admission_v1.rs')
    request=bind('actual request_admission',block(export,'pub(in crate::host::financial) fn request_admission(self)'))
    verify=bind('actual verify_admission',block(export,'pub(in crate::host::financial) fn verify_admission(&mut self)'))
    validate=bind('actual validate_coordinated_status',block(export,'fn validate_coordinated_status_v1('))
    old_request=request.replace('admission_observed!(self.verified.request_admission_retained_v1(),self.verified.request_admission_retained_observed_v1())','self.verified.request_admission_retained_v1()')
    old_verify=verify.replace('admission_observed!(self.pending.read_original_status_retained_v1(),self.pending.read_original_status_retained_observed_v1())','self.pending.read_original_status_retained_v1()')
    start=validate.index('    let audit =');end=validate.index('    validate_coordinated_original_audit_v1',start)
    old_audit='''    let audit = status.verified_audit().map_err(|_| Error::Receipt(
        "The original V3 operation remains pending or unknown: complete authenticated Witness history has not established admission. Preserve the original operation; do not resend it".into(),
    ))?;
'''
    old_validate=validate[:start]+old_audit+validate[end:]
    for name,value,digest in [
        ('P47 request_admission',old_request,'f4818e5aea508d8af2040a2b83ef06bcdeef247054d0d1aac6a6b34a21ba561b'),
        ('P47 verify_admission',old_verify,'24ef94e7996aca57bc56086c293798c1496516a29fdef7f888d6d6db21c82a90'),
        ('P47 validate_coordinated_status',old_validate,'873b9f0e61edc6a10b59f5356dd95ec17c423d456738a29d4a3e908e39f94dfb')]:
        assert hashlib.sha256(value.encode()).hexdigest()==digest,name
        bind(name,value)
    macro=bind('actual borrowed admission observation macro',block(export,'macro_rules! admission_observed {'))
    bridge=bind('actual bridge classifier',block(classifier,'pub(crate) fn bridge('))
    admission_classifier=bind('actual detailed admission classifier',block(classifier,'pub(crate) fn admission('))
    failure_stage=bind('actual detail-stage enum',block(admission,'pub enum CoordinatedAdmissionFailureStageV1 {'))
    failure_struct=bind('actual borrowed detail carrier',block(admission,'pub struct CoordinatedAdmissionFailureV1 {'))
    failure_impl=bind('actual original-error preserving accessors',block(admission,'impl CoordinatedAdmissionFailureV1 {'))
    framing=read('crates/wholepact-signer-origin/src/framing.rs')
    frame_enum=bind('actual finite FrameReadCause enum',block(framing,'pub enum FrameReadCause {'))
    request_wrappers='\n'.join(bind(m,block(admission,m)) for m in ['pub fn request_admission_retained_v1(', 'pub fn request_admission_retained_observed_v1('])
    history_wrappers='\n'.join(bind(m,block(admission,m)) for m in ['pub fn read_original_status_retained_v1(', 'pub fn read_original_status_retained_observed_v1('])
    unknown=bind('actual unknown error',block(closed,'fn unknown()'))
    verified=bind('actual status verified_audit',block(admission,'pub fn verified_audit('))
    enums={name:re.search(r'codes!\('+name+r' \{([^}]+)\}\);',diagnostics).group(1) for name in ['Stage','Class']}
    # Exact kernel, fixed test-only process identity; no real actor role is used.
    slots=bind('actual slot layout',block(diagnostics,'struct Slots {'))
    slot_methods='\n'.join(bind('actual slot '+m,block(diagnostics,m)) for m in ['const fn new()->Self','fn enter(&self,pid:i32,role:u8)','fn active(&self,pid:i32,role:u8)','fn failure(&self,pid:i32,stage:Stage,class:Class)'])
    latch=bind('actual public finite latch',block(diagnostics,'pub fn latch_failure('))
    # Do not diagnose the recoverable network/status attempt or hidden attempt
    # error stored inside the actual pending owner; these source guards bind it.
    retained=block(admission,'fn request_admission_retained_inner_v1(')
    assert 'Err(e) => pending.attempt_error = Some(e)' in retained and retained.rstrip().endswith('Ok(pending)\n    }')
    assert 'export_observed!' not in verify[verify.index('let status = match'):verify.index('_ => {')]
    bind('actual request returns pending after retained exchange error',retained)
    prefix=r'''#![allow(dead_code,unused_imports)]
use std::{cell::RefCell,rc::Rc,path::Path,sync::atomic::{AtomicI32,AtomicU32,AtomicU8,Ordering}};
#[derive(Clone,Debug,PartialEq,Eq)]enum Error{Permission,Authentication,Terminal,Storage,Receipt(String)}
type Result<T>=std::result::Result<T,Error>;
type Trace=Rc<RefCell<Vec<&'static str>>>;
fn event(t:&Trace,s:&'static str){t.borrow_mut().push(s)}
mod wholepact_signer{pub mod authority_bridge{
 #[derive(Clone,Debug,PartialEq,Eq)]pub enum BridgeError{Binding,Conflict,Missing,Uncertain,Limit,Permission,RecoveryRequired,CompleteOriginRecoveryUnavailable,Verification,SignerOriginUnavailable,Journal(&'static str),Authority(&'static str),Wallet(&'static str),Ipc}
 pub mod durable_review_ipc_v3{pub mod coordinated_v1{pub use crate::{CoordinatedAdmissionStateV1,CoordinatedAdmissionFailureStageV1,CoordinatedAdmissionFailureV1};}}
}}
use wholepact_signer::authority_bridge::BridgeError;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum CoordinatedAdmissionStateV1{AwaitingAudit,Unknown,Verified}
#[derive(Clone)]struct DurableDeliveryAdmissionStatusV2{join_valid:bool,trace:Trace}
#[derive(Clone)]struct CoordinatedDurableDeliveryAdmissionStatusV1{intent_digest:String,state:CoordinatedAdmissionStateV1,audit:Option<DurableDeliveryAdmissionStatusV2>,shape_valid:bool,trace:Trace}
mod status_adapter{use super::*;type Result<T>=std::result::Result<T,BridgeError>;
impl CoordinatedDurableDeliveryAdmissionStatusV1{
 // Inert deterministic checked-data adapter. A malformed Verified record fails
 // validate before the diagnostic branch; no fake second-validation race.
 pub fn validate(&self)->Result<()>{event(&self.trace,"status_validate");if !self.shape_valid||(self.state==CoordinatedAdmissionStateV1::Verified&&self.audit.is_none()){Err(BridgeError::Binding)}else{Ok(())}}
'''
    prefix+=verified+'\n}}\n'
    prefix+='mod wholepact_signer_origin{pub mod framing{#[derive(Clone,Copy,Debug,PartialEq,Eq)]'+frame_enum+'}}\n'
    prefix+='#[derive(Clone,Copy,Debug,PartialEq,Eq)]'+failure_stage+'\n'+failure_struct+'\n'+failure_impl+'\n'
    prefix+='mod financial_ci_host_failure {use super::*;\n'
    for name,codes in enums.items():prefix+='#[derive(Clone,Copy,Debug,PartialEq,Eq)]#[repr(u8)]pub enum '+name+'{'+codes+'}\nimpl '+name+'{const NAMES:&\'static[&\'static str]=&['+','.join('"'+x.strip()+'"' for x in codes.split(',') if x.strip())+'];}\n'
    prefix+=slots+'\nimpl Slots{'+slot_methods+'}\nstatic SLOTS:Slots=Slots::new();\nmod libc{pub unsafe fn getpid()->i32{101}}\n'+latch+'\n'+bridge+'\n'+admission_classifier+r'''
 pub fn reset(){SLOTS.pid.store(0,Ordering::Relaxed);SLOTS.enter(101,2)}
 pub fn sample()->Option<(&'static str,&'static str)>{let n=SLOTS.failure.load(Ordering::Relaxed).checked_sub(1)?;Some((Stage::NAMES[(n&255)as usize],Class::NAMES[(n>>8)as usize]))}
}
'''+macro+r'''
#[derive(Clone)]struct Recipient{request:u8,delivery:u8,digest_error:bool,trace:Trace}
impl Recipient{fn digest(&self)->std::result::Result<String,BridgeError>{event(&self.trace,"intent_digest");if self.digest_error{Err(BridgeError::Binding)}else{Ok("exact-intent".into())}}}
#[derive(Clone)]struct CoordinatedDurableReviewExportScopeV1{recipient:Recipient}
#[derive(Clone)]struct Request{import_request:u8,delivery:u8}
#[derive(Clone)]struct CoordinatedOriginalDeliveryExportV1{request:Request,export_scope:CoordinatedDurableReviewExportScopeV1}
struct Terminal{trace:Trace,error:Option<Error>}
impl Terminal{fn message(&self,_:&str)->Result<()>{event(&self.trace,"message");self.error.clone().map_or(Ok(()),Err)}}
struct Host{terminal:Terminal,display_error:Option<Error>}
impl Host{fn display_original_coordinated_admission_status_v1(&self,_:&Path,_:&CoordinatedDurableReviewExportScopeV1,_:&CoordinatedDurableDeliveryAdmissionStatusV1)->Result<()>{event(&self.terminal.trace,"display");self.display_error.clone().map_or(Ok(()),Err)}}
struct PendingCoordinatedDurableDeliveryAdmissionV1{awaited:std::result::Result<CoordinatedDurableDeliveryAdmissionStatusV1,BridgeError>,history:std::result::Result<CoordinatedDurableDeliveryAdmissionStatusV1,BridgeError>,trace:Trace,history_stage:CoordinatedAdmissionFailureStageV1,frame_cause:Option<wholepact_signer_origin::framing::FrameReadCause>}
impl PendingCoordinatedDurableDeliveryAdmissionV1{fn await_status_v1(&mut self)->std::result::Result<CoordinatedDurableDeliveryAdmissionStatusV1,BridgeError>{event(&self.trace,"await_status");self.awaited.clone()}fn read_original_status_retained_inner_v1(&mut self,stage:&mut CoordinatedAdmissionFailureStageV1,frame:&mut Option<wholepact_signer_origin::framing::FrameReadCause>)->std::result::Result<CoordinatedDurableDeliveryAdmissionStatusV1,BridgeError>{event(&self.trace,"read_history");*stage=self.history_stage;*frame=self.frame_cause;self.history.clone()}}
struct Verified{pending:PendingCoordinatedDurableDeliveryAdmissionV1,error:Option<BridgeError>,trace:Trace}
impl Verified{fn request_admission_retained_inner_v1(self,stage:&mut CoordinatedAdmissionFailureStageV1)->std::result::Result<PendingCoordinatedDurableDeliveryAdmissionV1,BridgeError>{event(&self.trace,"request_admission");*stage=CoordinatedAdmissionFailureStageV1::RequestChannel;self.error.map_or(Ok(self.pending),Err)}}
fn validate_coordinated_original_audit_v1(_:&CoordinatedDurableReviewExportScopeV1,audit:&DurableDeliveryAdmissionStatusV2)->Result<()>{event(&audit.trace,"original_audit_join");if audit.join_valid{Ok(())}else{Err(Error::Authentication)}}
#[derive(Clone)]struct Spec{request_error:Option<BridgeError>,await_error:Option<BridgeError>,await_state:CoordinatedAdmissionStateV1,history_error:Option<BridgeError>,history_state:CoordinatedAdmissionStateV1,history_stage:CoordinatedAdmissionFailureStageV1,frame_cause:Option<wholepact_signer_origin::framing::FrameReadCause>,malformed:bool,wrong_digest:bool,digest_error:bool,bad_join:bool,bad_export:bool,message_error:bool,display_error:bool,repeat:bool,prior:bool}
impl Default for Spec{fn default()->Self{Self{request_error:None,await_error:None,await_state:CoordinatedAdmissionStateV1::Verified,history_error:None,history_state:CoordinatedAdmissionStateV1::Verified,history_stage:CoordinatedAdmissionFailureStageV1::HistoryOpen,frame_cause:None,malformed:false,wrong_digest:false,digest_error:false,bad_join:false,bad_export:false,message_error:false,display_error:false,repeat:false,prior:false}}}
#[derive(Debug,PartialEq,Eq)]struct Summary{result:Result<()>,second:Option<Result<()>>,trace:Vec<&'static str>,admitted:bool,verification_started:bool}
fn status(s:&Spec,state:CoordinatedAdmissionStateV1,trace:&Trace)->CoordinatedDurableDeliveryAdmissionStatusV1{CoordinatedDurableDeliveryAdmissionStatusV1{intent_digest:if s.wrong_digest{"wrong"}else{"exact-intent"}.into(),state,audit:if state==CoordinatedAdmissionStateV1::Verified&&!s.malformed{Some(DurableDeliveryAdmissionStatusV2{join_valid:!s.bad_join,trace:trace.clone()})}else{None},shape_valid:!s.malformed,trace:trace.clone()}}
mod host{pub mod financial{
'''
    common=r'''
use crate::*;
struct RetainedCoordinatedVerifiedExportV1<'host>{host:&'host Host,workspace:&'host Path,verified:Verified,exported:CoordinatedOriginalDeliveryExportV1,material_delivery_restriction:()}
struct RetainedOriginalCoordinatedAdmissionV1<'host>{host:&'host Host,workspace:&'host Path,pending:PendingCoordinatedDurableDeliveryAdmissionV1,exported:CoordinatedOriginalDeliveryExportV1,admitted:Option<CoordinatedDurableDeliveryAdmissionStatusV1>,verification_started:bool,material_delivery_restriction:()}
pub(crate) fn run(s:Spec)->Summary{
 let trace=Rc::new(RefCell::new(Vec::new()));let host=Host{terminal:Terminal{trace:trace.clone(),error:s.message_error.then_some(Error::Terminal)},display_error:s.display_error.then_some(Error::Storage)};
 let pending=PendingCoordinatedDurableDeliveryAdmissionV1{awaited:s.await_error.clone().map_or_else(||Ok(status(&s,s.await_state,&trace)),Err),history:s.history_error.clone().map_or_else(||Ok(status(&s,s.history_state,&trace)),Err),trace:trace.clone(),history_stage:s.history_stage,frame_cause:s.frame_cause};
 let source=RetainedCoordinatedVerifiedExportV1{host:&host,workspace:Path::new("/inert-public-synthetic"),verified:Verified{pending,error:s.request_error.clone(),trace:trace.clone()},exported:CoordinatedOriginalDeliveryExportV1{request:Request{import_request:if s.bad_export{2}else{1},delivery:1},export_scope:CoordinatedDurableReviewExportScopeV1{recipient:Recipient{request:1,delivery:1,digest_error:s.digest_error,trace:trace.clone()}}},material_delivery_restriction:()};
 let(result,second,admitted,verification_started)=match source.request_admission(){Err(e)=>(Err(e),None,false,false),Ok(mut owner)=>{let r=owner.verify_admission();let second=s.repeat.then(||owner.verify_admission());(r,second,owner.admitted.is_some(),owner.verification_started)}};
 let trace=trace.borrow().clone();Summary{result,second,trace,admitted,verification_started}
}
'''
    prefix=prefix.replace('mod host{pub mod financial{', 'mod wrapper_kernels{use super::*;type Result<T>=std::result::Result<T,BridgeError>;impl Verified{'+request_wrappers+'}impl PendingCoordinatedDurableDeliveryAdmissionV1{'+history_wrappers+'}}\nmod host{pub mod financial{')
    for name,req,ver,val in [('before',old_request,old_verify,old_validate),('after',request,verify,validate)]:
        prefix+='pub(crate) mod '+name+'{\n'+common+unknown+'\n'+val+'\nimpl<\'host> RetainedCoordinatedVerifiedExportV1<\'host>{\n'+req+'\n}\nimpl RetainedOriginalCoordinatedAdmissionV1<\'_>{\n'+ver+'\n}\n}\n'
    prefix+='}}\n'
    tests=r'''
static TEST:std::sync::Mutex<()>=std::sync::Mutex::new(());
fn paired(s:Spec)->(Summary,Option<(&'static str,&'static str)>){let _guard=TEST.lock().unwrap();financial_ci_host_failure::reset();let before=host::financial::before::run(s.clone());assert_eq!(financial_ci_host_failure::sample(),None);financial_ci_host_failure::reset();if s.prior{financial_ci_host_failure::latch_failure(financial_ci_host_failure::Stage::ExportCommit,financial_ci_host_failure::Class::EngineDisclosureUnknown)}let after=host::financial::after::run(s);assert_eq!(before,after,"original operation trace and Result changed");let event=financial_ci_host_failure::sample();(after,event)}
#[test]fn verified_success_has_no_failure_observation(){let(s,e)=paired(Spec::default());assert_eq!(s.result,Ok(()));assert!(s.admitted);assert_eq!(e,None);assert_eq!(s.trace.iter().filter(|x|**x=="request_admission").count(),1);assert!(!s.trace.contains(&"read_history"));}
#[test]fn recoverable_await_error_then_verified_history_is_not_failure(){let(s,e)=paired(Spec{await_error:Some(BridgeError::Ipc),..Spec::default()});assert_eq!(s.result,Ok(()));assert!(s.admitted);assert_eq!(e,None);assert!(s.trace.contains(&"message"));assert!(s.trace.contains(&"read_history"));}
#[test]fn pending_status_then_verified_history_is_not_failure(){let(s,e)=paired(Spec{await_state:CoordinatedAdmissionStateV1::AwaitingAudit,..Spec::default()});assert_eq!(s.result,Ok(()));assert_eq!(e,None);assert!(s.trace.contains(&"read_history"));}
#[test]fn propagated_preexchange_request_error_is_observed_once(){let(s,e)=paired(Spec{request_error:Some(BridgeError::Permission),..Spec::default()});assert!(matches!(s.result,Err(Error::Receipt(_))));assert_eq!(s.trace,vec!["request_admission"]);assert!(!s.verification_started);assert_eq!(e,Some(("AdmissionRequestChannel","BridgePermission")));}
#[test]fn terminal_history_error_is_observed_not_recoverable_await_error(){for frame in [None,Some(wholepact_signer_origin::framing::FrameReadCause::Eof)]{let(s,e)=paired(Spec{await_error:Some(BridgeError::Permission),history_error:Some(BridgeError::Ipc),history_stage:if frame.is_some(){CoordinatedAdmissionFailureStageV1::ResponseFrame}else{CoordinatedAdmissionFailureStageV1::HistoryOpen},frame_cause:frame,..Spec::default()});assert!(matches!(s.result,Err(Error::Receipt(_))));assert_eq!(e,if frame.is_some(){Some(("AdmissionResponseFrame","FrameEof"))}else{Some(("AdmissionHistoryOpen","BridgeIpc"))});assert_eq!(s.trace,vec!["request_admission","await_status","message","read_history"]);}}
#[test]fn terminal_awaiting_audit_has_exact_state_label(){let(s,e)=paired(Spec{await_error:Some(BridgeError::Ipc),history_state:CoordinatedAdmissionStateV1::AwaitingAudit,..Spec::default()});assert!(matches!(s.result,Err(Error::Receipt(_))));assert_eq!(e,Some(("AdmissionAwaitingAudit","BridgeUncertain")));assert!(!s.admitted);}
#[test]fn terminal_unknown_has_exact_state_label(){let(s,e)=paired(Spec{await_error:Some(BridgeError::Ipc),history_state:CoordinatedAdmissionStateV1::Unknown,..Spec::default()});assert!(matches!(s.result,Err(Error::Receipt(_))));assert_eq!(e,Some(("AdmissionUnknown","BridgeUncertain")));}
#[test]fn malformed_verified_rejects_before_audit_hook_without_fabricated_label(){let(s,e)=paired(Spec{await_error:Some(BridgeError::Ipc),malformed:true,..Spec::default()});assert_eq!(s.result,Err(Error::Authentication));assert_eq!(e,None);assert!(!s.trace.contains(&"original_audit_join"));}
#[test]fn digest_and_export_binding_errors_keep_original_results_without_new_label(){for spec in [Spec{wrong_digest:true,..Spec::default()},Spec{digest_error:true,..Spec::default()},Spec{bad_export:true,..Spec::default()}]{let(s,e)=paired(spec);assert_eq!(s.result,Err(Error::Authentication));assert_eq!(e,None);assert!(!s.admitted);}}
#[test]fn original_audit_join_error_is_not_misattributed_to_verified_audit(){let(s,e)=paired(Spec{bad_join:true,..Spec::default()});assert_eq!(s.result,Err(Error::Authentication));assert_eq!(e,None);assert!(s.trace.contains(&"original_audit_join"));}
#[test]fn message_failure_prevents_history_and_keeps_error_identity(){let(s,e)=paired(Spec{await_error:Some(BridgeError::Ipc),message_error:true,..Spec::default()});assert_eq!(s.result,Err(Error::Terminal));assert_eq!(e,None);assert!(!s.trace.contains(&"read_history"));}
#[test]fn display_failure_keeps_error_and_never_marks_admitted(){let(s,e)=paired(Spec{display_error:true,..Spec::default()});assert_eq!(s.result,Err(Error::Storage));assert_eq!(e,None);assert!(!s.admitted);}
#[test]fn first_actual_error_slot_is_immutable(){let(s,e)=paired(Spec{request_error:Some(BridgeError::Ipc),prior:true,..Spec::default()});assert!(matches!(s.result,Err(Error::Receipt(_))));assert_eq!(e,Some(("ExportCommit","EngineDisclosureUnknown")));}
#[test]fn verification_is_one_use_after_success_or_terminal_failure_and_never_resends(){for failure in [false,true]{let(s,e)=paired(Spec{await_error:failure.then_some(BridgeError::Ipc),history_error:failure.then_some(BridgeError::Permission),repeat:true,..Spec::default()});assert_eq!(s.second,Some(Err(Error::Permission)));assert!(s.verification_started);assert_eq!(s.trace.iter().filter(|x|**x=="request_admission").count(),1);assert_eq!(s.trace.iter().filter(|x|**x=="await_status").count(),1);assert_eq!(s.trace.iter().filter(|x|**x=="read_history").count(),usize::from(failure));assert_eq!(e,if failure{Some(("AdmissionHistoryOpen","BridgePermission"))}else{None});}}
'''
    harness=prefix+tests;assert len(re.findall(r'#\[test\]',harness))==14
    path=out/'admission-trace.rs';path.write_text(harness)
    binding={'version':1,'sources':sources,'chunks':chunks,'tests':14,'harness_sha256':hashlib.sha256(harness.encode()).hexdigest(),'executed':False,'limits':['Host/terminal/client/status validation/audit join are inert outcomes, not actual authority or network operations.','Actual three Host functions, verified_audit kernel, ordinary/observed wrappers, detail/Bridge classifier and first-slot CAS are literal source; wrapper inner calls are inert outcomes, not stage-injection proof.','Malformed Verified rejects before the audit hook; exhaustive AdmissionAuditRejected arm is not fabricated as reachable.','No PID custody, observer file, socket, actor scheduling or full-flow evidence is claimed.']}
    binding_path=out/'admission-source-bindings.json';binding_path.write_text(json.dumps(binding,indent=2)+'\n')
    if args.run:
        executable=out/'admission-trace-tests'
        def run(cmd,timeout,log):
            result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout);(out/log).write_text(result.stdout)
            if result.returncode:print(result.stdout,end='');raise SystemExit(result.returncode)
            return result.stdout
        run([os.environ.get('RUSTC','rustc'),'--edition=2021','--cfg','wholepact_financial_rendered_host_semantic_ci','--test',str(path),'-o',str(executable)],60,'compile.log')
        listing=run([str(executable),'--list'],10,'list.log');names=[line[:-6] for line in listing.splitlines() if line.endswith(': test')]
        expected=re.findall(r'#\[test\]\s*fn (\w+)\(',tests)
        if len(names)!=14 or set(names)!=set(expected):raise SystemExit('exact 14-test listing mismatch')
        print(run([str(executable),'--test-threads=1'],30,'tests.log'),end='');binding['executed']=True;binding_path.write_text(json.dumps(binding,indent=2)+'\n')
    print(json.dumps({'tests':14,'executed':args.run}))


if __name__=='__main__':main()
