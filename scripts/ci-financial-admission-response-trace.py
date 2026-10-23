"""Exact response-helper parity, with inert I/O/peer/parser carriers, not socket proof."""
from pathlib import Path
import argparse,hashlib,json,re,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--run',action='store_true');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
rel='crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/lifecycle_v1.rs';s=(a.source/rel).read_text()
def item(s,n):
 start=s.index(n);b=s.index('{',start);d=1;i=b+1
 while d:
  d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[start:i]
current=item(s,'pub(super) fn closed_response_detailed_v1(')
wrapper=item(s,'pub(super) fn closed_response(')
# Exact original P47 body, hash-checked below after stripping only diagnostics.
prior='''pub(super) fn closed_response_prior(
        &self,
        stream: &UnixStream,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<CoordinatedClosedResponseV1> {
        check()?;
        self.check_stream(stream)?;
        require_before(deadline)?;
        let bytes = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            stream,
            &self.peer,
            MAX_METADATA_V3,
            deadline.min(self.deadline),
            || {
                check().map_err(|_| wholepact_signer_origin::Error::Permission)?;
                self.check_stream(stream)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|_| BridgeError::Ipc)?;
        check()?;
        self.check_stream(stream)?;
        require_before(deadline)?;
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_METADATA_V3)
            .map_err(|_| BridgeError::Binding)
    }'''
def body(s):return s[s.index('{')+1:-1]
def tokens(s):return re.findall(r'"(?:\\.|[^"\\])*"|\S',s)
normalized=body(current)
normalized=re.sub(r'^\s*\*(?:stage|frame_cause) = [^\n]+;\n','\n',normalized,flags=re.M)
normalized=normalized.replace('read_frame_capped_checked_observed_until','read_frame_capped_checked_until')
normalized=re.sub(r'\.map_err\(\|failure\| \{\s*BridgeError::Ipc\s*\}\)\?;', '.map_err(|_| BridgeError::Ipc)?;', normalized)
assert tokens(normalized)==tokens(body(prior)),normalized
baseline_hash=hashlib.sha256('\n'.join(tokens(body(prior))).encode()).hexdigest()
assert baseline_hash=='33fbeb408577c27b61dd23f413b74aff8fcd51d9628faacea5fdbe5e5b2883f6'
framing_rel='crates/wholepact-signer-origin/src/framing.rs';framing=(a.source/framing_rel).read_text()
assert 'read_frame_capped_checked_observed_until(stream, peer, max_wire_bytes, deadline, check_current)\n        .map_err(|observed| observed.error)' in item(framing,'pub fn read_frame_capped_checked_until(')
stage_rel='crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/admission_v1.rs'
stage=item((a.source/stage_rel).read_text(),'pub enum CoordinatedAdmissionFailureStageV1')
code='''#![allow(dead_code,unused_imports)]
// Actual response helper and ordinary wrapper; inert peer/parser/I/O carriers.
// The fake kernel invokes one current callback. This tests same invocation and
// error transport, NOT recvmsg, clocks, credential parsing or native authority.
use std::cell::RefCell;use std::time::{Instant,Duration};
#[derive(Clone,Debug,PartialEq,Eq)]enum BridgeError{Permission,Binding,Ipc,Synthetic(usize)}
type Result<T>=std::result::Result<T,BridgeError>;
#[derive(Clone,Debug,PartialEq,Eq)]struct CoordinatedClosedResponseV1(u8);
struct UnixStream;struct Peer;const MAX_METADATA_V3:usize=123;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
'''+stage+'''
#[derive(Clone)]struct Setup{fail:usize,at:usize,frame:wholepact_signer_origin::framing::FrameReadCause,events:Vec<&'static str>}
thread_local!{static TRACE:RefCell<Setup>=RefCell::new(Setup{fail:0,at:0,frame:wholepact_signer_origin::framing::FrameReadCause::Io,events:vec![]});}
fn op(name:&'static str)->Result<()>{TRACE.with(|t|{let mut t=t.borrow_mut();t.at+=1;t.events.push(name);if t.at==t.fail{Err(BridgeError::Synthetic(t.at))}else{Ok(())}})}
fn require_before(_:Instant)->Result<()>{op("deadline")}
mod wholepact_core{pub mod strict_json{use super::super::*;pub fn parse_typed_json_with_byte_limit(_: &[u8],_:usize)->Result<CoordinatedClosedResponseV1>{op("parse")?;Ok(CoordinatedClosedResponseV1(7))}}}
mod wholepact_signer_origin{
 #[derive(Debug)]pub enum Error{Permission}
 pub mod framing{
  use super::super::*;
  #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum FrameReadCause{Unclassified,Deadline,Eof,CredentialsMissing,CredentialsMismatch,AncillaryRejected,Truncated,PeerNotLive,CurrentCheck,Io,FrameLimit,InvalidFrame,InvalidBudget}
  pub struct Failure{pub cause:FrameReadCause,pub error:super::Error}
  pub fn read_frame_capped_checked_observed_until(_: &UnixStream,_:&Peer,_:usize,_:Instant,mut check:impl FnMut()->std::result::Result<(),super::Error>)->std::result::Result<Vec<u8>,Failure>{
   op("frame").map_err(|_|Failure{cause:TRACE.with(|t|t.borrow().frame),error:super::Error::Permission})?;
   check().map_err(|e|Failure{cause:FrameReadCause::CurrentCheck,error:e})?;
   Ok(vec![1])
  }
  pub fn read_frame_capped_checked_until(s:&UnixStream,p:&Peer,m:usize,d:Instant,c:impl FnMut()->std::result::Result<(),super::Error>)->std::result::Result<Vec<u8>,super::Error>{read_frame_capped_checked_observed_until(s,p,m,d,c).map_err(|e|e.error)}
 }
}
use wholepact_signer_origin::framing::FrameReadCause as F;
struct Client{peer:Peer,deadline:Instant}
impl Client{
 fn check_stream(&self,_:&UnixStream)->Result<()>{op("peer")}
'''+prior+'\n'+wrapper+'\n'+current+'''
}
fn run(kind:u8,fail:usize,frame:F)->(Result<CoordinatedClosedResponseV1>,CoordinatedAdmissionFailureStageV1,Option<F>,Vec<&'static str>){
 TRACE.with(|t|*t.borrow_mut()=Setup{fail,at:0,frame,events:vec![]});
 let client=Client{peer:Peer,deadline:Instant::now()+Duration::from_secs(60)};let mut stage=CoordinatedAdmissionFailureStageV1::HistoryOpen;let mut cause=Some(F::InvalidBudget);
 let result=match kind{0=>client.closed_response_prior(&UnixStream,client.deadline,&||op("check")),1=>client.closed_response_detailed_v1(&UnixStream,client.deadline,&||op("check"),&mut stage,&mut cause),_=>client.closed_response(&UnixStream,client.deadline,&||op("check"))};
 (result,stage,cause,TRACE.with(|t|t.borrow().events.clone()))
}
#[test]fn exact_all_predicate_failures_preserve_operation_result_and_error_identity(){use CoordinatedAdmissionFailureStageV1 as S;for(fail,stage)in[(1,S::ResponseCheckBefore),(2,S::ResponsePeerBefore),(3,S::ResponseDeadlineBefore),(4,S::ResponseFrame),(5,S::ResponseFrame),(6,S::ResponseFrame),(7,S::ResponseCheckAfter),(8,S::ResponsePeerAfter),(9,S::ResponseDeadlineAfter),(10,S::ResponseDecode)]{let old=run(0,fail,F::Io);let new=run(1,fail,F::Io);let normal=run(2,fail,F::Io);assert_eq!(old.0,new.0);assert_eq!(old.3,new.3);assert_eq!(old.0,normal.0);assert_eq!(old.3,normal.3);assert_eq!(new.1,stage);assert_eq!(new.2,if fail==4{Some(F::Io)}else if fail==5||fail==6{Some(F::CurrentCheck)}else{None});}}
#[test]fn all_thirteen_actual_frame_categories_are_retained_without_a_second_read(){for cause in [F::Unclassified,F::Deadline,F::Eof,F::CredentialsMissing,F::CredentialsMismatch,F::AncillaryRejected,F::Truncated,F::PeerNotLive,F::CurrentCheck,F::Io,F::FrameLimit,F::InvalidFrame,F::InvalidBudget]{let old=run(0,4,cause);let new=run(1,4,cause);assert_eq!(old.0,new.0);assert_eq!(old.3,new.3);assert_eq!(new.2,Some(cause));assert_eq!(new.3.iter().filter(|e|**e=="frame").count(),1);}}
#[test]fn successful_response_has_identical_single_read_trace_and_clears_stale_detail(){let old=run(0,0,F::Io);let new=run(1,0,F::Io);let normal=run(2,0,F::Io);assert_eq!(new.0,Ok(CoordinatedClosedResponseV1(7)));assert_eq!(old.0,new.0);assert_eq!(old.3,new.3);assert_eq!(normal.0,new.0);assert_eq!(normal.3,new.3);assert_eq!(new.2,None);assert_eq!(new.3,vec!["check","peer","deadline","frame","check","peer","check","peer","deadline","parse"]);}
'''
code=code.replace('pub(super) fn ', 'pub fn ')  # lexical visibility only in root-level inert harness
(a.out/'admission-response-trace.rs').write_text(code)
binding={'baseline_commit':'e450539ebc32beccd6ac69c396e64e0a8b62dc5f','baseline_body_token_sha256':baseline_hash,'paths':{x:hashlib.sha256((a.source/x).read_bytes()).hexdigest() for x in [rel,framing_rel,stage_rel]}}
(a.out/'admission-response-binding.json').write_text(json.dumps(binding,indent=2)+'\n');print(json.dumps({'tests':3,'executed':False,'phase':'generated'}))
if a.run:
 rustc=os.environ.get('RUSTC','rustc');binary=(a.out/'admission-response-tests').resolve()
 subprocess.run([rustc,'--edition=2021','--test',str(a.out/'admission-response-trace.rs'),'-o',str(binary)],check=True,timeout=60)
 listed=subprocess.run([str(binary),'--list'],check=True,capture_output=True,text=True,timeout=10).stdout
 expected={'exact_all_predicate_failures_preserve_operation_result_and_error_identity','all_thirteen_actual_frame_categories_are_retained_without_a_second_read','successful_response_has_identical_single_read_trace_and_clears_stale_detail'}
 assert {x[:-6] for x in listed.splitlines() if x.endswith(': test')}==expected,listed
 subprocess.run([str(binary),'--test-threads=1'],check=True,timeout=30)
 print(json.dumps({'tests':3,'executed':True,'result':'passed'}))
