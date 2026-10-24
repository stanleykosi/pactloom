#!/usr/bin/env python3
"""Exact deadline/wait-loop extraction. Virtual time and inert adapters; no TLS or Final."""
import argparse,hashlib,json,subprocess,selectors,os,time,importlib.util
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--run',action='store_true');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
T='crates/wholepact-authority/src/transport.rs';A='crates/wholepact-authority/src/transport/durable_delivery_admission_v3.rs';D='crates/wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs';J='crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs';U='crates/wholepact-financial-coordinator/src/financial_source_ui.rs'
s={n:(a.source/n).read_text() for n in (T,A,D,J,U)}
BASELINE_SOURCE_SHA256 = {'crates/wholepact-authority/src/transport.rs': '2c58ec5ae515ce13786ec81661901c9ba1c72a5f9827d3c925e4fbc48e4f2716', 'crates/wholepact-authority/src/transport/durable_delivery_admission_v3.rs': 'dda6bd34a47e3144bfc1fb8f633374da35ee30efa2a6fa7518dfb6ecc5a0af13', 'crates/wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs': '59c9fc8331a83323fab2d85ae4f0de853888af1eadcf090561d01b574846ef46', 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs': 'e14cd1da0c7c263722217a721453f6bd47132578629fbaf4e8b5c0bb4a71f2a8', 'crates/wholepact-financial-coordinator/src/financial_source_ui.rs': 'e7eab264c493c758e8723576fb476b1373204502d35d125113ede6d537dbdc96'}
spec=importlib.util.spec_from_file_location('ready_worker_audit',a.source/'scripts/ci-financial-admit-read-source-audit.py')
prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
assert {n:hashlib.sha256((prior.restore_ready_worker(v) if n==D else v).encode()).hexdigest() for n,v in s.items()} == BASELINE_SOURCE_SHA256
def block(text,needle):
 start=text.index(needle);i=text.index('{',start);depth=1;j=i+1
 while depth:
  depth += (text[j]=='{')-(text[j]=='}');j+=1
 return text[start:j]
funcs='\n'.join(block(s[T],f'fn {n}(') for n in ['caller_remaining_at','require_before_caller_deadline','bounded_transport_deadline_at'])
check=block(s[A],'pub fn check_current(&self)')
loop=block(s[D],'let action = loop')+';'
assert 'const IO_TIMEOUT: Duration = Duration::from_secs(10);' in s[T]
assert s[A].index('let deadline = bounded_transport_deadline_at(Instant::now(),caller_deadline)?;') < s[A].index('WireRequest::PrepareDurableDeliveryAdmissionV3') < s[A].index('WireResponse::DurableDeliveryAdmissionReadyV3') < s[A].index('Ok(AuthenticatedDurableAdmissionChannelV3 {client:self,stream,request:request.clone(),deadline,')
assert s[D].index('let channel = self') < s[D].index('let ready = wholepact_financial_coordinator_origin::SignerV3AdmitReadyV1') < s[D].index('let action = loop')
assert s[J].index('channel.check_current().map_err(invalid)?;') < s[J].index('intent.admission = AdmissionProvenanceV1') < s[J].index('self.with_coordinated_admission_effect_v1')
transition=block(s[U],'fn transition(&mut self, phase: Phase, frame: u64)')
assert 'self.read_to_end = false;' in transition and 'self.acknowledged = false;' in transition
assert 'self.transition(Phase::V3AdmitReady, frame);' in s[U]
assert 'self.read_to_end&&self.acknowledged&&later_frame' in s[U]
assert 'self.serve_connection_before(socket, Instant::now() + IO_TIMEOUT)' in s[T]
server=block(s[A],'pub(super) fn serve_durable_delivery_admission_v3(')
assert server.index('DurableDeliveryAdmissionReadyV3') < server.index('let request: WireRequest = read_frame_checked_v3')
prefix=r'''#![allow(dead_code)]
use std::{cell::Cell,time::Duration,ops::Add};
thread_local!{static CLOCK:Cell<u64>=const{Cell::new(0)};static EFFECT:Cell<bool>=const{Cell::new(false)};}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
impl Instant {fn now()->Self{Self(CLOCK.with(Cell::get))}fn checked_duration_since(self,old:Self)->Option<Duration>{self.0.checked_sub(old.0).map(Duration::from_millis)}}
impl Add<Duration> for Instant{type Output=Self;fn add(self,d:Duration)->Self{Self(self.0+d.as_millis() as u64)}}
#[derive(Debug,PartialEq,Eq)]enum AuthorityError{Permission,Authentication}
#[derive(Debug,PartialEq,Eq)]enum Error{Source,Custody,Uncertain,Locked,Unavailable,JournalBinding}
type Result<T>=std::result::Result<T,Error>;
fn now(t:u64){CLOCK.with(|c|c.set(t));}
mod authority{
 use super::*;type Result<T>=std::result::Result<T,AuthorityError>;
 const IO_TIMEOUT:Duration=Duration::from_secs(10);const ALPN:&[u8]=b"inert-same-alpn";
 __FUNCTIONS__
 pub(super) fn capture(start:u64,caller:u64)->std::result::Result<Instant,AuthorityError>{bounded_transport_deadline_at(Instant(start),Instant(caller))}
 struct Tls{pinned_certificate:String}struct Client{tls:Tls}struct Conn{certs:Vec<String>,alpn:Vec<u8>}
 impl Conn{fn peer_certificates(&self)->Option<&[String]>{Some(&self.certs)}fn alpn_protocol(&self)->Option<&[u8]>{Some(&self.alpn)}}
 struct Stream{conn:Conn}fn certificate_digest(cert:&String)->String{cert.clone()}
 pub(super) struct Channel{deadline:Instant,client:Client,stream:Stream}
 impl Channel{
  pub(super) fn inert(deadline:Instant)->Self{Self{deadline,client:Client{tls:Tls{pinned_certificate:"same".into()}},stream:Stream{conn:Conn{certs:vec!["same".into()],alpn:ALPN.into()}}}}
  __CHECK__
 }
}
struct Source(bool);impl Source{fn check_current(&self)->Result<()>{if self.0{Ok(())}else{Err(Error::Source)}}}
struct Witness(bool);impl Witness{fn check_custody(&self)->Result<()>{if self.0{Ok(())}else{Err(Error::Custody)}}}
struct Receiver{final_at:Option<u64>,disconnected:bool}
impl Receiver{fn recv_timeout(&self,d:Duration)->std::result::Result<u8,std::sync::mpsc::RecvTimeoutError>{
 if self.disconnected{return Err(std::sync::mpsc::RecvTimeoutError::Disconnected)}
 let next=Instant::now().0+d.as_millis() as u64;
 if let Some(at)=self.final_at{if at<=next{now(at.max(Instant::now().0));return Ok(1)}}
 now(next);Err(std::sync::mpsc::RecvTimeoutError::Timeout)
}}
struct Worker{source:Source,witness:Witness}
impl Worker{
 fn wait(&self,channel:&authority::Channel,deadline:Instant,final_receiver:Receiver)->Result<u8>{
  __LOOP__
  Ok(action)
 }
}
fn invalid(_:AuthorityError)->Error{Error::JournalBinding}
fn prepublication_gate(channel:&authority::Channel)->Result<()>{
 // Exact original gate before the genuine journal's mutation; effect below is
 // ONLY an inert marker, not a transaction/permission/Final implementation.
 channel.check_current().map_err(invalid)?;
 EFFECT.with(|v|v.set(true));Ok(())
}
fn worker()->Worker{Worker{source:Source(true),witness:Witness(true)}}
'''
tests=r'''
#[test]fn caller_and_transport_capture_are_fixed_before_ready(){
 assert_eq!(authority::capture(0,120_000),Ok(Instant(10_000)));
 assert_eq!(authority::capture(0,5_000),Ok(Instant(5_000)));
 assert_eq!(authority::capture(0,0),Err(AuthorityError::Permission));
 let c=authority::Channel::inert(authority::capture(0,120_000).unwrap());
 now(8_000);assert_eq!(c.check_current(),Ok(())); // READY arrives late; no new deadline.
 now(9_999);assert_eq!(c.check_current(),Ok(()));
 now(10_000);assert_eq!(c.check_current(),Err(AuthorityError::Permission));
}
#[test]fn delayed_review_is_denied_while_source_and_action_remain_current(){
 let c=authority::Channel::inert(authority::capture(0,120_000).unwrap());
 now(2_000);EFFECT.with(|v|v.set(false));
 assert_eq!(worker().wait(&c,Instant(120_000),Receiver{final_at:Some(11_000),disconnected:false}),Err(Error::Uncertain));
 assert_eq!(Instant::now(),Instant(10_000));assert!(!EFFECT.with(Cell::get));
 now(2_000);assert_eq!(worker().wait(&c,Instant(120_000),Receiver{final_at:Some(9_000),disconnected:false}),Ok(1));
 assert_eq!(prepublication_gate(&c),Ok(()));assert!(EFFECT.with(Cell::get));
}
#[test]fn exact_deadline_final_arrival_still_cannot_publish(){
 let c=authority::Channel::inert(authority::capture(0,120_000).unwrap());
 now(9_980);EFFECT.with(|v|v.set(false));
 // recv_timeout may return a Final exactly at the cap without another loop.
 // The existing actual journal gate still rejects before its effect boundary.
 assert_eq!(worker().wait(&c,Instant(120_000),Receiver{final_at:Some(10_000),disconnected:false}),Ok(1));
 assert_eq!(prepublication_gate(&c),Err(Error::JournalBinding));assert!(!EFFECT.with(Cell::get));
}
#[test]fn earlier_caller_and_original_currentness_failures_keep_precedence(){
 let c=authority::Channel::inert(authority::capture(0,5_000).unwrap());now(0);
 assert_eq!(worker().wait(&c,Instant(5_000),Receiver{final_at:Some(6_000),disconnected:false}),Err(Error::Uncertain));
 let c=authority::Channel::inert(authority::capture(0,120_000).unwrap());now(0);
 assert_eq!(Worker{source:Source(false),witness:Witness(true)}.wait(&c,Instant(120_000),Receiver{final_at:Some(1),disconnected:false}),Err(Error::Source));
 assert_eq!(Worker{source:Source(true),witness:Witness(false)}.wait(&c,Instant(120_000),Receiver{final_at:Some(1),disconnected:false}),Err(Error::Custody));
 assert_eq!(worker().wait(&c,Instant(120_000),Receiver{final_at:None,disconnected:true}),Err(Error::Unavailable));
}
'''
generated=prefix.replace('__FUNCTIONS__',funcs).replace('__CHECK__',check).replace('__LOOP__',loop)+tests
(a.out/'ready-contract.rs').write_text(generated)
def digest(v):return hashlib.sha256(v.encode()).hexdigest()
e={'source_sha256':{k:digest(v) for k,v in s.items()},'fragment_sha256':{k:digest(v) for k,v in {'deadlines':funcs,'channel_current':check,'wait_loop':loop,'ui_transition':transition,'server_ready_mutation':server}.items()},'count':4,'executed':False,'scope':'C: actual deadline/current/wait snippets with virtual time and inert certificate/source/receiver/effect adapters; no TLS, genuine Final, journal effect or live UI timing qualification','intent_conclusion':'10s derives from shared transport IO_TIMEOUT, captured before PREPARE and not refreshed at READY. UI separately requires fresh read/ack after READY. This proves current effective contract, not intended human-review duration or live inability to meet it.'}
if a.run:
 def run(cmd,name,timeout):
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ)
  chunks=[];size=0;deadline=time.monotonic()+timeout;failure=None
  try:
   while sel.get_map():
    remaining=deadline-time.monotonic()
    if remaining<=0:failure='source test timeout';break
    for key,_ in sel.select(min(remaining,0.1)):
     data=os.read(key.fileobj.fileno(),65536)
     if not data:sel.unregister(key.fileobj);continue
     size+=len(data)
     if size>2*1024*1024:failure='source test output cap';break
     chunks.append(data)
    if failure:break
   if failure:proc.kill()
   code=proc.wait(timeout=max(1,deadline-time.monotonic()))
  finally:
   sel.close()
   if proc.poll() is None:proc.kill();proc.wait()
   proc.stdout.close()
  raw=b''.join(chunks);(a.out/name).write_bytes(raw)
  if failure or code:
   print(raw[-16384:].decode(errors='replace'));raise SystemExit(failure or code)
  return raw.decode()
 binary=a.out/'ready-contract';run(['rustc','--edition=2021','--test',str(a.out/'ready-contract.rs'),'-o',str(binary)],'compile.log',60)
 names={'caller_and_transport_capture_are_fixed_before_ready','delayed_review_is_denied_while_source_and_action_remain_current','exact_deadline_final_arrival_still_cannot_publish','earlier_caller_and_original_currentness_failures_keep_precedence'}
 listing=run([str(binary),'--list'],'list.log',10);assert {x.removesuffix(': test') for x in listing.splitlines() if x.endswith(': test')}==names
 r=run([str(binary),'--test-threads=1'],'tests.log',30);assert '4 passed; 0 failed; 0 ignored;' in r;e['executed']=True
(a.out/'source-binding.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e,sort_keys=True))
