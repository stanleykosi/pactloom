#!/usr/bin/env python3
"""Three actual post-import clients plus the actual authenticated frame kernel.

Clock, transport syscalls, DTOs and strict JSON adapter are inert. Budget,
framing/parser, currentness sequence, original client bodies and response helper
are extracted literally. This is not real socket/authority or full-flow proof.
"""
import argparse, hashlib, json, os, re, runpy, subprocess, sys
from pathlib import Path

PREFIX = r'''
mod client_std {pub use crate::real_std::*;pub mod thread{pub fn sleep(d:crate::Duration){crate::edit(|s|s.now+=d.as_millis() as u64);}}}
mod clients {
use crate::{Instant,Duration,UnixStream,PeerProcess};
use crate::real_std::{cell::RefCell,collections::VecDeque};
use crate::client_std as std;
#[derive(Clone,Debug,PartialEq,Eq)]enum BridgeError{Permission,Binding,Uncertain,Ipc}
type Result<T>=std::result::Result<T,BridgeError>;
const MAX_METADATA_V3:usize=64;
#[derive(Clone)]struct Intent{payload_digest:String,payload_bytes:u64,fixed:u8}
impl Intent{fn digest(&self)->Result<String>{Ok("intent".into())}}
#[derive(Clone)]struct Receipt{version:u16,intent_digest:String,payload_digest:String,payload_bytes:u64,verified_fixed_identity_digest:String,state:String}
fn receipt()->Receipt{Receipt{version:1,intent_digest:"intent".into(),payload_digest:"payload".into(),payload_bytes:2,verified_fixed_identity_digest:"fixed".into(),state:"verified_import_for_review".into()}}
fn verified_fixed_identity_digest_v3(_: &u8)->Result<String>{Ok("fixed".into())}
#[derive(Clone,Debug,PartialEq,Eq)]struct CoordinatedDurableDeliveryAdmissionStatusV1{valid:bool}
enum CoordinatedClosedCommandV1{VerifyImport{intent_digest:String,nonce:String},Admit{intent_digest:String,nonce:String},AdmissionStatus{intent_digest:String,nonce:String}}
#[derive(Clone)]enum CoordinatedClosedResponseV1{Verified{nonce:String,receipt:Receipt},Verifying{nonce:String},Admitting{nonce:String},Admission{nonce:String,admission:CoordinatedDurableDeliveryAdmissionStatusV1},Other}
struct Script{responses:VecDeque<CoordinatedClosedResponseV1>,opens:Vec<(&'static str,Instant,Instant,String)>,nonce:u64,last_nonce:String,open_delay:u64,open_error:bool,channel_error:bool}
impl Default for Script{fn default()->Self{Self{responses:VecDeque::new(),opens:vec![],nonce:0,last_nonce:String::new(),open_delay:0,open_error:false,channel_error:false}}}
thread_local!{static SCRIPT:RefCell<Script>=RefCell::new(Script::default());}
fn require_before(d:Instant)->Result<()>{if Instant::now()>=d{Err(BridgeError::Permission)}else{Ok(())}}
fn fresh_nonce()->Result<String>{SCRIPT.with(|v|{let mut s=v.borrow_mut();s.nonce+=1;Ok(format!("nonce-{}",s.nonce))})}
struct CoordinatedOriginalClientV1{deadline:Instant,peer:PeerProcess}
impl CoordinatedOriginalClientV1{
 fn check_current(&self)->Result<()>{require_before(self.deadline)?;if SCRIPT.with(|v|v.borrow().channel_error){Err(BridgeError::Permission)}else{Ok(())}}
 fn check_stream(&self,_:&UnixStream)->Result<()>{self.check_current()}
 fn open_closed(&self,c:CoordinatedClosedCommandV1,d:Instant)->Result<UnixStream>{let (kind,digest,nonce)=match c{CoordinatedClosedCommandV1::VerifyImport{intent_digest,nonce}=>("Verify",intent_digest,nonce),CoordinatedClosedCommandV1::Admit{intent_digest,nonce}=>("Admit",intent_digest,nonce),CoordinatedClosedCommandV1::AdmissionStatus{intent_digest,nonce}=>("Status",intent_digest,nonce)};assert_eq!(digest,"intent");let(now,delay,fail)=(Instant::now(),SCRIPT.with(|s|s.borrow().open_delay),SCRIPT.with(|s|s.borrow().open_error));SCRIPT.with(|v|{let mut s=v.borrow_mut();s.last_nonce=nonce.clone();s.opens.push((kind,d,now,nonce));});crate::edit(|s|s.now+=delay);if fail{Err(BridgeError::Ipc)}else{require_before(d.min(self.deadline))?;Ok(UnixStream)}}
}
mod wholepact_signer_origin{pub(crate) use crate::Error;pub mod framing{pub(crate) use crate::{FrameReadCause,read_frame_capped_checked_observed_until};}}
mod wholepact_core{pub mod strict_json{pub(crate) fn parse_typed_json_with_byte_limit(bytes:&[u8],cap:usize)->Result<super::super::CoordinatedClosedResponseV1,()>{assert_eq!(cap,64);assert_eq!(bytes,b"ok");super::super::SCRIPT.with(|v|{let mut s=v.borrow_mut();let mut r=s.responses.pop_front().ok_or(())?;let actual=s.last_nonce.clone();match &mut r{super::super::CoordinatedClosedResponseV1::Verified{nonce,..}|super::super::CoordinatedClosedResponseV1::Verifying{nonce}|super::super::CoordinatedClosedResponseV1::Admitting{nonce}|super::super::CoordinatedClosedResponseV1::Admission{nonce,..}=>if nonce=="AUTO"{*nonce=actual},_=>()};Ok(r)})}}}
fn reset(responses:Vec<CoordinatedClosedResponseV1>){crate::reset();let n=responses.len().max(1);crate::edit(|s|s.reads=(0..n).map(|_|crate::Read::bytes(0,b"ok\n")).collect());SCRIPT.with(|v|*v.borrow_mut()=Script{responses:responses.into(),..Script::default()});}
fn client(channel:u64)->CoordinatedOriginalClientV1{CoordinatedOriginalClientV1{deadline:Instant(channel),peer:PeerProcess}}
fn intent()->Intent{Intent{payload_digest:"payload".into(),payload_bytes:2,fixed:1}}
fn opens()->Vec<(&'static str,Instant,Instant,String)>{SCRIPT.with(|s|s.borrow().opens.clone())}
fn verified()->CoordinatedClosedResponseV1{CoordinatedClosedResponseV1::Verified{nonce:"AUTO".into(),receipt:receipt()}}
fn admitted()->CoordinatedClosedResponseV1{CoordinatedClosedResponseV1::Admission{nonce:"AUTO".into(),admission:CoordinatedDurableDeliveryAdmissionStatusV1{valid:true}}}
fn admitting()->CoordinatedClosedResponseV1{CoordinatedClosedResponseV1::Admitting{nonce:"AUTO".into()}}
'''
COMMON = r'''
use super::*;
struct ImportedCoordinatedDurableReviewSessionV1{client:CoordinatedOriginalClientV1,intent:Intent,deadline:Instant}
struct VerifiedImportedCoordinatedDurableReviewSessionV1{client:CoordinatedOriginalClientV1,intent:Intent,receipt:Receipt,deadline:Instant}
struct PendingCoordinatedDurableDeliveryAdmissionV1{client:CoordinatedOriginalClientV1,intent:Intent,deadline:Instant,status:Option<CoordinatedDurableDeliveryAdmissionStatusV1>,attempt:CoordinatedAdmissionAttemptV1,attempt_error:Option<BridgeError>}
impl PendingCoordinatedDurableDeliveryAdmissionV1{fn check_status(&self,s:&CoordinatedDurableDeliveryAdmissionStatusV1)->Result<()>{if s.valid{Ok(())}else{Err(BridgeError::Binding)}}}
pub(super) fn verify(material:u64,channel:u64)->Result<u64>{ImportedCoordinatedDurableReviewSessionV1{client:client(channel),intent:intent(),deadline:Instant(material)}.await_verified_v3().map(|v|v.deadline.0)}
pub(super) fn request(material:u64,channel:u64)->Result<(CoordinatedAdmissionAttemptV1,Option<BridgeError>,u64)>{let owner=VerifiedImportedCoordinatedDurableReviewSessionV1{client:client(channel),intent:intent(),receipt:receipt(),deadline:Instant(material)};let mut stage=CoordinatedAdmissionFailureStageV1::RequestDeadline;owner.request_admission_retained_inner_v1(&mut stage).map(|p|(p.attempt,p.attempt_error,p.deadline.0))}
pub(super) fn status(material:u64,channel:u64)->Result<u64>{let mut pending=PendingCoordinatedDurableDeliveryAdmissionV1{client:client(channel),intent:intent(),deadline:Instant(material),status:None,attempt:CoordinatedAdmissionAttemptV1::Acknowledged,attempt_error:None};pending.await_status_v1().map(|_|pending.deadline.0)}
'''
TESTS = r'''
#[test]fn three_old_clients_reject_long_material_at_actual_frame_gate(){reset(vec![verified()]);assert_eq!(before::verify(500000,600000),Err(BridgeError::Ipc));assert_eq!(crate::snapshot().1,0);reset(vec![admitting()]);assert_eq!(before::request(500000,600000),Ok((CoordinatedAdmissionAttemptV1::PossiblyStarted,Some(BridgeError::Ipc),500000)));assert_eq!(crate::snapshot().1,0);reset(vec![admitted()]);assert_eq!(before::status(500000,600000),Err(BridgeError::Ipc));assert_eq!(crate::snapshot().1,0);}
#[test]fn three_new_clients_retain_material_and_use_one_short_exchange(){reset(vec![verified()]);assert_eq!(after::verify(500000,600000),Ok(500000));assert_eq!(opens()[0].1,Instant(120000));reset(vec![admitting()]);assert_eq!(after::request(500000,600000),Ok((CoordinatedAdmissionAttemptV1::Acknowledged,None,500000)));assert_eq!(opens()[0].1,Instant(120000));reset(vec![admitted()]);assert_eq!(after::status(500000,600000),Ok(500000));assert_eq!(opens()[0].1,Instant(120000));assert_eq!(crate::snapshot().1,3);}
#[test]fn short_material_and_channel_bounds_are_never_extended(){for (material,channel,expected) in [(5000,900000,5000),(900000,7000,7000),(120000,900000,120000),(120001,900000,120000)]{reset(vec![verified()]);assert_eq!(after::verify(material,channel),Ok(material));assert_eq!(opens()[0].1,Instant(expected));reset(vec![admitting()]);assert_eq!(after::request(material,channel).unwrap().2,material);assert_eq!(opens()[0].1,Instant(expected));reset(vec![admitted()]);assert_eq!(after::status(material,channel),Ok(material));assert_eq!(opens()[0].1,Instant(expected));}}
#[test]fn original_expiry_refuses_all_three_before_open(){for kind in 0..3{reset(vec![verified()]);crate::edit(|s|s.now=5000);let r=match kind{0=>after::verify(5000,900000),1=>after::request(5000,900000).map(|v|v.2),_=>after::status(5000,900000)};assert_eq!(r,Err(BridgeError::Permission));assert!(opens().is_empty());assert_eq!(crate::snapshot().1,0);}}
#[test]fn transit_consumes_same_captured_request_budget(){reset(vec![verified()]);SCRIPT.with(|v|v.borrow_mut().open_delay=110000);crate::edit(|s|s.reads.front_mut().unwrap().advance=9999);assert_eq!(after::verify(500000,900000),Ok(500000));assert_eq!(opens()[0].1,Instant(120000));reset(vec![verified()]);SCRIPT.with(|v|v.borrow_mut().open_delay=110000);crate::edit(|s|s.reads.front_mut().unwrap().advance=10000);let(r,c)=after::observed(500000,900000);assert_eq!(r,Err(BridgeError::Ipc));assert_eq!(c,Some(crate::FrameReadCause::Deadline));}
#[test]fn status_loops_do_not_renew_original_material_and_use_new_nonce_only(){for verify in [true,false]{let pending=if verify{CoordinatedClosedResponseV1::Verifying{nonce:"AUTO".into()}}else{admitting()};let final_response=if verify{verified()}else{admitted()};reset(vec![pending,final_response]);crate::edit(|s|{s.reads[0].advance=119000;s.reads[1].advance=1000;});let r=if verify{after::verify(120050,900000)}else{after::status(120050,900000)};assert_eq!(r,Err(BridgeError::Ipc));let o=opens();assert_eq!(o.len(),2);assert_eq!(o[0].1,Instant(120000));assert_eq!(o[1].1,Instant(120050));assert_ne!(o[0].3,o[1].3);}}
#[test]fn short_success_and_transport_error_parity_preserve_original_results(){for bad in [false,true]{for kind in 0..3{let response=if kind==0{verified()}else if kind==1{admitting()}else{admitted()};reset(vec![response.clone()]);SCRIPT.with(|v|v.borrow_mut().open_error=bad);let old=match kind{0=>before::verify(5000,900000).map(|d|(None,None,d)),1=>before::request(5000,900000).map(|(a,e,d)|(Some(a),e,d)),_=>before::status(5000,900000).map(|d|(None,None,d))};let old_trace=crate::snapshot();let old_opens=opens();reset(vec![response]);SCRIPT.with(|v|v.borrow_mut().open_error=bad);let new=match kind{0=>after::verify(5000,900000).map(|d|(None,None,d)),1=>after::request(5000,900000).map(|(a,e,d)|(Some(a),e,d)),_=>after::status(5000,900000).map(|d|(None,None,d))};assert_eq!(old,new);assert_eq!(old_trace,crate::snapshot());assert_eq!(old_opens,opens());}}}
#[test]fn uncertain_admit_retains_owner_and_does_not_retry(){for wrong in [false,true]{reset(vec![if wrong{CoordinatedClosedResponseV1::Admitting{nonce:"wrong".into()}}else{admitting()}]);if !wrong{crate::edit(|s|s.reads=vec![crate::Read::bytes(0,b"")].into());}let p=after::request(500000,900000).unwrap();assert_eq!(p.0,CoordinatedAdmissionAttemptV1::PossiblyStarted);assert_eq!(p.1,Some(if wrong{BridgeError::Uncertain}else{BridgeError::Ipc}));assert_eq!(p.2,500000);assert_eq!(opens().len(),1);assert_eq!(opens()[0].0,"Admit");}}
#[test]fn ordinary_and_observed_verify_have_identical_ops_and_errors(){for fault in 0..5{let setup=||{reset(vec![verified()]);match fault{1=>crate::edit(|s|s.reads=vec![crate::Read::bytes(0,b"")].into()),2=>crate::edit(|s|s.reads.front_mut().unwrap().ancillary=crate::Ancillary::Wrong),3=>crate::edit(|s|s.fail_peer=Some(1)),4=>SCRIPT.with(|s|s.borrow_mut().channel_error=true),_=>()}};setup();let ordinary=after::verify(500000,900000);let trace=crate::snapshot();let opened=opens();setup();let (observed,cause)=after::observed(500000,900000);assert_eq!(ordinary,observed);assert_eq!(trace,crate::snapshot());assert_eq!(opened,opens());if fault==0||fault==4{assert_eq!(cause,None)}else{assert_eq!(cause,Some(match fault{1=>crate::FrameReadCause::Eof,2=>crate::FrameReadCause::CredentialsMismatch,_=>crate::FrameReadCause::PeerNotLive}));}}}
#[test]fn successful_verifying_response_carries_no_failure_detail(){reset(vec![CoordinatedClosedResponseV1::Verifying{nonce:"AUTO".into()},verified()]);assert_eq!(after::observed(500000,900000),(Ok(500000),None));assert_eq!(opens().len(),2);assert!(opens().iter().all(|v|v.0=="Verify"));}
#[test]fn malformed_verified_binding_and_nonce_still_deny(){for bad in 0..8{let mut value=receipt();match bad{0=>value.version=2,1=>value.intent_digest="wrong".into(),2=>value.payload_digest="wrong".into(),3=>value.payload_bytes=3,4=>value.verified_fixed_identity_digest="wrong".into(),5=>value.state="wrong".into(),_=>()};reset(vec![if bad==7{CoordinatedClosedResponseV1::Other}else{CoordinatedClosedResponseV1::Verified{nonce:if bad==6{"wrong".into()}else{"AUTO".into()},receipt:value}}]);let(r,c)=after::observed(500000,900000);assert_eq!(r,Err(if bad<6{BridgeError::Binding}else{BridgeError::Permission}));assert_eq!(c,None);}}
}
'''

MAPPER_TESTS = r'''
 #[test]fn actual_verified_mapper_uses_only_existing_stage_and_finite_error(){
  use crate::FrameReadCause as F;
  for (cause,class) in [(F::Unclassified,Class::FrameUnclassified),(F::Deadline,Class::FrameDeadline),(F::Eof,Class::FrameEof),(F::CredentialsMissing,Class::FrameCredentialsMissing),(F::CredentialsMismatch,Class::FrameCredentialsMismatch),(F::AncillaryRejected,Class::FrameAncillaryRejected),(F::Truncated,Class::FrameTruncated),(F::PeerNotLive,Class::FramePeerNotLive),(F::CurrentCheck,Class::FrameCurrentCheck),(F::Io,Class::FrameIo),(F::FrameLimit,Class::FrameLimit),(F::InvalidFrame,Class::FrameInvalidFrame),(F::InvalidBudget,Class::FrameInvalidBudget)]{
   assert_eq!(take(),None);let error=CoordinatedVerifiedFailureV1{frame_cause:Some(cause),error:BridgeError::Ipc};verified_wait(&error);assert_eq!(take(),Some((Stage::ExportVerifiedWait,class)));assert_eq!(error.into_error(),BridgeError::Ipc);
  }
  for (error,class) in [(BridgeError::Ipc,Class::BridgeIpc),(BridgeError::Permission,Class::BridgePermission)]{let failure=CoordinatedVerifiedFailureV1{frame_cause:None,error};verified_wait(&failure);assert_eq!(take(),Some((Stage::ExportVerifiedWait,class)));}
  let payload=String::from("public-inert-error-payload");let address=payload.as_ptr();let failure=CoordinatedVerifiedFailureV1{frame_cause:None,error:BridgeError::Journal(payload)};verified_wait(&failure);assert_eq!(take(),Some((Stage::ExportVerifiedWait,Class::BridgeJournal)));match failure.into_error(){BridgeError::Journal(value)=>assert_eq!(value.as_ptr(),address),_=>panic!("original owned error changed")};
  latch_failure(Stage::LaterWorkflow,Class::Permission);let failure=CoordinatedVerifiedFailureV1{frame_cause:Some(F::Eof),error:BridgeError::Ipc};verified_wait(&failure);assert_eq!(take(),Some((Stage::LaterWorkflow,Class::Permission)));
 }
}
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--run',action='store_true');a=p.parse_args();root=a.source.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
 framework=root/'scripts/ci-financial-readiness-frame-trace.py';fw=runpy.run_path(str(framework));block=fw['block'];sources={};pieces=[]
 def read(path):
  raw=(root/path).read_bytes();sources[path]=hashlib.sha256(raw).hexdigest();return raw.decode()
 def take(s,m):
  t=block(s,m);pieces.append({'marker':m,'sha256':hashlib.sha256(t.encode()).hexdigest()});return t
 lifecycle=read('crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/lifecycle_v1.rs');admission=read('crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/admission_v1.rs');frame=read('crates/wholepact-signer-origin/src/framing.rs')
 verify=take(lifecycle,'fn await_verified_inner_v3(');request=take(admission,'fn request_admission_retained_inner_v1(');status=take(admission,'pub fn await_status_v1(')
 verify_old=verify.replace('fn await_verified_inner_v3(self, frame_cause: &mut Option<wholepact_signer_origin::framing::FrameReadCause>)','pub fn await_verified_v3(self)').replace('            let mut stage = CoordinatedAdmissionFailureStageV1::ResponseCheckBefore;\n','').replace('.closed_response_detailed_v1(&stream, request_deadline, &|| Ok(()), &mut stage, frame_cause)?','.closed_response(&stream, self.deadline, &|| Ok(()))?')
 def original(body,who,comments):
  for c in comments:assert body.count(c)==1;body=body.replace(c,'')
  line=f'            let request_deadline = {who}.deadline.min({who}.client.deadline).min(Instant::now() + Duration::from_secs(120));\n'
  assert body.count(line)==1;body=body.replace(line,'').replace('                request_deadline,\n','                '+who+'.deadline,\n').replace('&stream, request_deadline,','&stream, '+who+'.deadline,').replace('&stream,request_deadline,','&stream,'+who+'.deadline,')
  return body
 verify_old=original(verify_old,'self',['            // Material custody is the overall bound, not a single frame budget.\n','            // Freeze one transport ceiling before opening this exchange.\n'])
 request_old=original(request,'pending',['            // One attempted Admit keeps its owner and original material bound.\n',"            // Only this request's transport wait is narrowed to 120 seconds.\n"])
 status_old=original(status,'self',['            // Polling does not renew original material custody. Each exchange\n','            // separately uses the ordinary authenticated frame budget.\n'])
 for value,expected in [(verify_old,'dbae32579cadf141730579cebaa491bc7aca748a3c5824cb052a74e50a210647'),(request_old,'a5d53bdcddc4f933d1fdee0558c7ee9024c2e64c85de79955eeb056c3e53555d'),(status_old,'aad551ec0b98c0bc0f4caca5d5dd71aa97161cc9f395040f38db4cd9a5a11b59')]:assert hashlib.sha256(value.encode()).hexdigest()==expected,expected
 # Reconstruct complete P50b files, not only selected method bodies: no
 # unreviewed initial Prepare/history or unrelated operation may change.
 restored=lifecycle
 start=restored.index('/// Local terminal verification-read detail;')
 end=restored.index('impl ImportedCoordinatedDurableReviewSessionV1 {',start)
 restored=restored[:start]+restored[end:]
 start=restored.index('    pub fn await_verified_v3(')
 inner_start=restored.index('fn await_verified_inner_v3(',start)
 end=inner_start+len(verify)
 restored=restored[:start]+'    '+verify_old+restored[end:]
 assert hashlib.sha256(restored.encode()).hexdigest()=='636be8651b8b760bd3b4c75798873558dac9c2ba761038b6c8d2d72b00844fe1'
 assert hashlib.sha256(admission.replace(request,request_old).replace(status,status_old).encode()).hexdigest()=='ba876b439dd99962d74a045c5c23d2531b086e517bb019e225d331c6159f1f34'
 assert hashlib.sha256(frame.encode()).hexdigest()=='c26c9633513b85ac8034f05b17f2ac6c3cecb1fef1b74269cb617ce33bf66bf6'
 delivery=take(lifecycle,'pub fn deliver_prepared_restricted_v3(');assert 'deadline: self.material_deadline,' in delivery
 code=fw['PREFIX']+'\n'
 for m in ['pub enum FrameReadCause {','pub struct ObservedFrameError {','fn observe<T>(', 'pub fn read_frame_capped_checked_observed_until(','fn read_frame_capped_observed_kernel(','fn admit_restricted_receive(','fn remaining_at(','fn append_capped_chunk(','fn read_frame_inner_observed(']:
  if m=='pub enum FrameReadCause {':code+='#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'
  if m=='pub struct ObservedFrameError {':code+='#[derive(Debug)]\n'
  code+=take(frame,m)+'\n'
 code+=PREFIX+'#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+take(admission,'pub enum CoordinatedAdmissionFailureStageV1 {')+'\n#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+take(admission,'pub enum CoordinatedAdmissionAttemptV1 {')+'\n'
 code+='impl CoordinatedOriginalClientV1{'+take(lifecycle,'pub(super) fn closed_response(')+take(lifecycle,'pub(super) fn closed_response_detailed_v1(')+'}\n'
 code+=take(lifecycle,'pub struct CoordinatedVerifiedFailureV1 {')+take(lifecycle,'impl CoordinatedVerifiedFailureV1 {')+'\n'
 wrappers=take(lifecycle,'pub fn await_verified_v3(')+take(lifecycle,'pub fn await_verified_observed_v3(')
 for name in ['before','after']:
  code+='mod '+name+'{'+COMMON
  code+='impl ImportedCoordinatedDurableReviewSessionV1{'+(verify_old if name=='before' else wrappers+verify)+'}\n'
  code+='impl VerifiedImportedCoordinatedDurableReviewSessionV1{'+(request_old if name=='before' else request)+'}\n'
  code+='impl PendingCoordinatedDurableDeliveryAdmissionV1{'+(status_old if name=='before' else status)+'}\n'
  if name=='after':code+='pub(super)fn observed(material:u64,channel:u64)->(Result<u64>,Option<crate::FrameReadCause>){match (ImportedCoordinatedDurableReviewSessionV1{client:client(channel),intent:intent(),deadline:Instant(material)}).await_verified_observed_v3(){Ok(v)=>(Ok(v.deadline.0),None),Err(e)=>{let c=e.frame_cause();(Err(e.into_error()),c)}}}\n'
  code+='}\n'
 code+=TESTS
 host=read('crates/wholepact-native-host/src/financial_ci_host_failure.rs');codes=read('crates/wholepact-financial-coordinator-origin/src/financial_ci_host_diagnostics.rs')
 mapper_prefix=fw['MAPPER_PREFIX'].replace(' pub(crate) use super::readiness_helper::CoordinatedAdmissionFailureStageV1;\n','').replace('CoordinatedPreparationFailureV1,CoordinatedAdmissionFailureStageV1','CoordinatedVerifiedFailureV1')
 code+=mapper_prefix+take(codes,'macro_rules! codes {')+'\n'+'\n'.join(take(codes,'codes!('+name+' {')+');' for name in ['Stage','Class'])
 code+=take(lifecycle,'pub struct CoordinatedVerifiedFailureV1 {')+take(lifecycle,'impl CoordinatedVerifiedFailureV1 {')+take(host,'pub(crate) fn verified_wait(')+take(host,'pub(crate) fn bridge(')+MAPPER_TESTS
 expected=['clients::'+name for name in re.findall(r'#\[test\]fn (\w+)\(',TESTS)]+['host_mapper::actual_verified_mapper_uses_only_existing_stage_and_finite_error'];assert len(expected)==12
 generated=out/'postimport-frame-trace.rs';generated.write_text(code);record=out/'source-bindings.json';evidence={'source':sources,'pieces':pieces,'adapter_sha256':hashlib.sha256(framework.read_bytes()).hexdigest(),'generated_sha256':hashlib.sha256(code.encode()).hexdigest(),'expected':expected,'count':12,'executed':False,'limits':['Actual three client methods and response/helper/frame kernels extracted; old methods fixed-hash-bound to tested P50b.','Clock, syscalls, credentials, peer, JSON/DTO adapter are inert; no real socket, authority or end-to-end proof.','Owner, nonce, original deadline, per-exchange bound, no-Admit-retry and actual framing failure paths are executed.']};record.write_text(json.dumps(evidence,indent=2)+'\n')
 if a.run:
  binary=out/'postimport-frame-trace';commands=[([os.environ.get('RUSTC','rustc'),'--edition=2021','--test',str(generated),'-o',str(binary)],60,'compile.log'),([str(binary),'--list'],10,'list.log'),([str(binary),'--test-threads=1'],30,'tests.log')]
  for cmd,timeout,log in commands:
   r=subprocess.run(cmd,text=True,capture_output=True,timeout=timeout);output=r.stdout+r.stderr;(out/log).write_text(output)
   if r.returncode:print(output[-16384:],file=sys.stderr);raise SystemExit(f'{log} failed: {r.returncode}')
   if log=='list.log':assert sorted(re.findall(r'^(\w+(?:::\w+)*): test$',output,re.M))==sorted(expected)
   if log=='tests.log':assert 'test result: ok. 12 passed; 0 failed;' in output
  evidence['executed']=True;record.write_text(json.dumps(evidence,indent=2)+'\n')
 print(json.dumps({'tests':12,'executed':a.run}))
if __name__=='__main__':main()
