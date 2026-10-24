#!/usr/bin/env python3
"""Actual source data-assembly regression for distinct Host identity domains.

Extracts the enrollment transport initializer, full coordinated redisclosure
validator, unchanged admission transport predicate and same_live_process body.
Peer/currentness and hash adapters are INERT: this neither constructs a genuine
Pair/Final nor qualifies kernel credentials, sockets, cryptography or authority.
The independent maintained encrypted-row test exercises full persisted joins.
"""
import argparse, hashlib, importlib.util, json, re, subprocess
from pathlib import Path
BASELINE='647638353f2d58fe7bac1d3c07226b6eca3c219d'
PINS = {'crates/wholepact-signer/src/consent_journal/authority/coordinated_preconstruction_v1.rs': '21a72bfe737eea8a6de2474bd0fc4659b988fcc5db157b941e14b4464e1ffc34', 'crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/redisclosure_v1.rs': 'f915f7e6538c67f9ac21def7b4a0eb3d1d02e5393aba8cf1b2a261d79c2e1c06', 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs': '5bc0e767583d9f8159a186efff5715cae412628c91c16af5f915cb754f8bbadc', 'crates/wholepact-signer-origin/src/native_peer.rs': 'e0c7f16d43dc27e8bb0ca8e04160c65831efb664a0d34f411ca77805c805e14b', 'crates/wholepact-signer/src/ipc/coordinated_pair_v1.rs': '6025d99c16c02c3925c6053f554b85560a070a1ad800d977f8d203639965af4d', 'crates/wholepact-signer/src/native_ui/runtime/coordinated_v3_delivery_v1.rs': '92ec93f1d431cd5e9e744c78ef230b95c7b937a60a399a0d1c85a8ac6d0801a5', 'crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1.rs': '4dc6ecdd5357bd9cf268982cb2deff30a4c567b918f3ed60f7089c9fdb5c49eb', 'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1/coordinated_pairing_v1.rs': '86ead9b303978bb8b6ca453f390b024ae119981f2afabe0a4a689290ad76941d'}
PRODUCER='crates/wholepact-signer/src/consent_journal/authority/coordinated_preconstruction_v1.rs'
CONSUMER='crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/redisclosure_v1.rs'
ROWS='crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs'
PEER='crates/wholepact-signer-origin/src/native_peer.rs'
PAIR='crates/wholepact-signer/src/ipc/coordinated_pair_v1.rs'
RECEIVE='crates/wholepact-signer/src/native_ui/runtime/coordinated_v3_delivery_v1.rs'
COMMENT='// The observed socket peer has its own fresh observation label.\n            // Persist the authenticated original Host identity, not that label.\n            '
NAMES={
 'old_observation_label_reproduces_unchanged_row_rejection',
 'canonical_original_label_satisfies_client_and_rows',
 'wrong_original_and_observation_labels_remain_rejected',
 'all_other_transport_binding_fields_remain_enforced',
 'same_live_process_is_not_observation_label_equality',
 'client_currentness_errors_and_single_evaluation_are_preserved',
}
PREFIX=r'''
#![allow(dead_code, unused_imports)]
use std::cell::Cell;
use std::ops::Deref;
#[derive(Debug,Clone,Copy,PartialEq,Eq)] enum BridgeError{Binding,Permission}
type Error=BridgeError;
type JournalError=BridgeError;
type Result<T> = std::result::Result<T,BridgeError>;
impl BridgeError { const Authentication:Self=Self::Binding; const InvalidBinding:Self=Self::Binding; }
macro_rules! actor_admit_read_detail_result {($stage:ident,$result:expr)=>{$result}}
mod libc { pub unsafe fn geteuid()->u32 {1000} }
mod hex {
 pub fn decode(s:&str)->std::result::Result<Vec<u8>,()> { if s.len()%2!=0{return Err(())} (0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).map_err(|_|())).collect() }
 pub fn encode(bytes:impl AsRef<[u8]>)->String {bytes.as_ref().iter().map(|b|format!("{b:02x}")).collect()}
}
struct Zeroizing<T>(T); impl<T> Zeroizing<T>{fn new(x:T)->Self{Self(x)}}
impl<T> Deref for Zeroizing<T>{type Target=T;fn deref(&self)->&T{&self.0}}
// Inert hash adapter, not a cryptographic implementation. The actual verifier
// still evaluates its original digest operation once and compares its output.
struct Sha256; impl Sha256 {fn digest(_: &[u8])->[u8;32]{[3;32]}}
#[derive(Clone,Debug,PartialEq,Eq)] struct Scope {account_id:String,agreement_id:String,participant_id:String,manifest_digest:String}
#[derive(Clone,Debug,PartialEq,Eq)] enum TransportIdentityBinding {
 None,
 LocalProcess {transport_identity_id:String,channel_key_digest:String,channel_binding_digest:String,uid:u32,pid:u32,process_instance:String,signer_generation:u64,account_id:String,agreement_id:String,participant_id:String,manifest_digest:String}
}
#[derive(Clone)] struct Observed {uid:u32,pid:u32,instance:String,live:bool}
impl Observed {fn uid(&self)->u32{self.uid} fn pid(&self)->u32{self.pid} fn instance(&self)->&str{&self.instance} fn check_alive(&self)->Result<()>{if self.live{Ok(())}else{Err(BridgeError::Binding)}}
__SAME_LIVE__
}
struct Peer {observed:Observed,original:String,scope:Scope}
impl Peer {fn actual_peer(&self)->&Observed{&self.observed} fn original_host_process_instance(&self)->&str{&self.original} fn scope(&self)->&Scope{&self.scope} fn grant_id(&self)->&str{"grant"} fn key_digest(&self)->&str{KEY} fn channel_digest(&self)->&str{"channel"} fn generation(&self)->u64{1}}
struct Session{peer:Peer}
struct Terms{transport:TransportIdentityBinding}
impl Session {
 fn old(&self)->TransportIdentityBinding {let mut terms=Terms{transport:TransportIdentityBinding::None}; __OLD_PRODUCER__ terms.transport}
 fn new(&self)->TransportIdentityBinding {let mut terms=Terms{transport:TransportIdentityBinding::None}; __NEW_PRODUCER__ terms.transport}
}
struct Client {token:String,grant_id:String,channel_digest:String,observed_host_process_instance:String,original_host_process_instance:String,scope:Scope,current:bool,calls:Cell<usize>}
impl Client {fn check_current(&self)->Result<()>{self.calls.set(self.calls.get()+1);if self.current{Ok(())}else{Err(BridgeError::Permission)}}
__OLD_CONSUMER__
__NEW_CONSUMER__
}
struct Current{transport:TransportIdentityBinding}
impl Current{fn recipient_transport(&self)->&TransportIdentityBinding{&self.transport}}
struct Recipient{authorized_host_process_instance:String,source_generation:u64,account_id:String,agreement_id:String,participant_id:String,manifest_digest:String}
fn rows(current:&Current,recipient:&Recipient)->Result<()> {__ROWS__ Ok(())}
const KEY:&str="0303030303030303030303030303030303030303030303030303030303030303";
fn fixture()->(Session,Client,Recipient) {
 let scope=Scope{account_id:"account".into(),agreement_id:"agreement".into(),participant_id:"participant".into(),manifest_digest:"manifest".into()};
 let original="e1".repeat(32);let observed="51".repeat(32);assert_ne!(original,observed);
 let peer=Peer{observed:Observed{uid:1000,pid:std::process::id(),instance:observed.clone(),live:true},original:original.clone(),scope:scope.clone()};
 let client=Client{token:"09".repeat(32),grant_id:"grant".into(),channel_digest:"channel".into(),observed_host_process_instance:observed,original_host_process_instance:original.clone(),scope:scope.clone(),current:true,calls:Cell::new(0)};
 let recipient=Recipient{authorized_host_process_instance:original,source_generation:1,account_id:scope.account_id,agreement_id:scope.agreement_id,participant_id:scope.participant_id,manifest_digest:scope.manifest_digest};
 (Session{peer},client,recipient)
}
'''
TESTS=r'''
#[test] fn old_observation_label_reproduces_unchanged_row_rejection(){
 let(s,c,r)=fixture();let old=s.old();assert!(c.old_verify(&old).is_ok());
 assert_eq!(rows(&Current{transport:old},&r),Err(BridgeError::Binding));
}
#[test] fn canonical_original_label_satisfies_client_and_rows(){
 let(s,c,r)=fixture();let mut old=s.old();let new=s.new();
 if let TransportIdentityBinding::LocalProcess{process_instance,..}=&mut old{*process_instance=r.authorized_host_process_instance.clone()}else{panic!()}
 assert_eq!(old,new,"only original process label changes");
 assert!(c.new_verify(&new).is_ok());assert!(rows(&Current{transport:new},&r).is_ok());assert_eq!(c.calls.get(),1);
}
#[test] fn wrong_original_and_observation_labels_remain_rejected(){
 let(s,c,r)=fixture();for label in ["51".repeat(32),"f2".repeat(32)]{
 let mut transport=s.new();if let TransportIdentityBinding::LocalProcess{process_instance,..}=&mut transport{*process_instance=label}else{panic!()}
 assert_eq!(c.new_verify(&transport),Err(BridgeError::Binding));assert_eq!(rows(&Current{transport},&r),Err(BridgeError::Binding));
 }
 assert_eq!(c.new_verify(&TransportIdentityBinding::None),Err(BridgeError::Binding));
 assert_eq!(rows(&Current{transport:TransportIdentityBinding::None},&r),Err(BridgeError::Binding));
}
#[test] fn all_other_transport_binding_fields_remain_enforced(){
 let(s,c,r)=fixture();for index in 0..10 {
 let mut transport=s.new();let TransportIdentityBinding::LocalProcess{transport_identity_id,channel_key_digest,channel_binding_digest,uid,pid,signer_generation,account_id,agreement_id,participant_id,manifest_digest,..}=&mut transport else{panic!()};
 match index {0=>transport_identity_id.push('x'),1=>channel_key_digest.push('x'),2=>channel_binding_digest.push('x'),3=>*uid+=1,4=>*pid+=1,5=>*signer_generation+=1,6=>account_id.push('x'),7=>agreement_id.push('x'),8=>participant_id.push('x'),9=>manifest_digest.push('x'),_=>unreachable!()}
 assert_eq!(c.new_verify(&transport),Err(BridgeError::Binding),"field {index}");
 if index>=5{assert_eq!(rows(&Current{transport},&r),Err(BridgeError::Binding),"row field {index}");}
 }
}
#[test] fn same_live_process_is_not_observation_label_equality(){
 let(s,_,_)=fixture();let mut original=s.peer.observed.clone();original.instance=s.peer.original.clone();
 assert_ne!(original.instance(),s.peer.observed.instance());assert!(original.same_live_process(&s.peer.observed).is_ok());
 let mut wrong=original.clone();wrong.pid+=1;assert!(original.same_live_process(&wrong).is_err());
 wrong=original.clone();wrong.uid+=1;assert!(original.same_live_process(&wrong).is_err());
 wrong=original.clone();wrong.live=false;assert!(original.same_live_process(&wrong).is_err());
}
#[test] fn client_currentness_errors_and_single_evaluation_are_preserved(){
 let(s,mut c,_)=fixture();c.current=false;
 assert_eq!(c.old_verify(&s.old()),Err(BridgeError::Permission));assert_eq!(c.calls.get(),1);
 assert_eq!(c.new_verify(&s.new()),Err(BridgeError::Permission));assert_eq!(c.calls.get(),2);
}
'''
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def checked(command,path,timeout):
 p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,text=True)
 path.write_text(p.stdout)
 if p.returncode:
  print(p.stdout[-16384:],flush=True)
  raise SystemExit(f'{path.name} failed: {p.returncode}')
 return p.stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--run',action='store_true');a=p.parse_args();root=a.source.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
 spec=importlib.util.spec_from_file_location('prior',root/'scripts/ci-financial-admit-read-source-audit.py');prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
 src={name:(root/name).read_text() for name in PINS}
 old=dict(src)
 assert src[PRODUCER].count(COMMENT)==1
 old[PRODUCER]=src[PRODUCER].replace(COMMENT,'').replace('process_instance: self.peer.original_host_process_instance().into(),','process_instance: self.peer.actual_peer().instance().into(),')
 assert src[CONSUMER].count('process_instance != &self.original_host_process_instance')==1
 old[CONSUMER]=src[CONSUMER].replace('process_instance != &self.original_host_process_instance','process_instance != &self.observed_host_process_instance')
 for path,expected in PINS.items():assert digest(old[path])==expected,path
 def fn(raw,start):
  begin=raw.index(start);brace=raw.index('{',begin);return raw[begin:prior.balanced_end(raw,brace,"{","}")]
 def producer(raw):
  start=raw.index('terms.transport = TransportIdentityBinding::LocalProcess {');end=prior.balanced_end(raw,raw.index('{',start),'{','}');assert raw[end]==';';return raw[start:end+1]
 consumer=fn(src[CONSUMER],'    fn verify_coordinated_recipient(')
 oldconsumer=fn(old[CONSUMER],'    fn verify_coordinated_recipient(')
 start=src[ROWS].index('    let TransportIdentityBinding::LocalProcess {',src[ROWS].index('fn validate_original_rows'))
 end=src[ROWS].index('    let scope = &original.request().scope;',start)
 rows=src[ROWS][start:end]
 same=fn(src[PEER],'    pub fn same_live_process(')
 assert 'instance: hex::encode(crate::random::<32>()?),' in src[PEER]
 assert 'self.uid() != other.uid() || self.pid() != other.pid()' in same and 'instance' not in same
 # Existing live checks join original provenance to this newly observed socket.
 assert src[PAIR].index('PeerProcess::observe(stream)')<src[PAIR].index('bounds.host.same_live_process(&observed)')
 assert 'observed: pending.peer,' in src[PAIR] and 'self.bounds.host.instance()' in src[PAIR]
 assert 'channel.update(reply.observed_host_process_instance.as_bytes());' in src['crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1.rs']
 joined=src['crates/wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1/coordinated_pairing_v1.rs']
 assert 'peer.actual_peer().same_live_process(&self.source.host)?;' in joined
 assert 'peer.original_host_process_instance() != self.source.host.instance()' in joined
 assert 'authorized_host_process_instance: peer.original_host_process_instance().into(),' in src[RECEIVE]
 generated=PREFIX.replace('__SAME_LIVE__',same).replace('__OLD_PRODUCER__',producer(old[PRODUCER])).replace('__NEW_PRODUCER__',producer(src[PRODUCER])).replace('__OLD_CONSUMER__',oldconsumer.replace('fn verify_coordinated_recipient','fn old_verify',1)).replace('__NEW_CONSUMER__',consumer.replace('fn verify_coordinated_recipient','fn new_verify',1)).replace('__ROWS__',rows)+TESTS
 path=out/'transport-identity-trace.rs';path.write_text(generated)
 evidence={'baseline':BASELINE,'source_pins':PINS,'candidate_hashes':{p:digest(s) for p,s in src.items()},'extracted_fragment_hashes':{'old_producer':digest(producer(old[PRODUCER])),'new_producer':digest(producer(src[PRODUCER])),'old_client':digest(oldconsumer),'new_client':digest(consumer),'unchanged_rows':digest(rows),'same_live_process':digest(same)},'test_count':len(NAMES),'executed':False,'genuine_peer_or_final':False,'kernel_or_crypto_qualification':False}
 if a.run:
  binary=out/'transport-identity-trace';checked(['rustc','--edition=2021','--test',str(path),'-o',str(binary)],out/'compile.log',60)
  listing=checked([str(binary),'--list'],out/'list.log',10);actual={line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test')};assert actual==NAMES,(actual,NAMES)
  result=checked([str(binary),'--test-threads=1'],out/'tests.log',30)
  assert f'{len(NAMES)} passed; 0 failed; 0 ignored;' in result
  evidence['executed']=True
 (out/'source-binding.json').write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps(evidence,sort_keys=True))
if __name__=='__main__':main()
