#!/usr/bin/env python3
"""Source-bound readiness regression; --run executes exact 2+14 std-only tests.

Clock, DTO validation and transport are explicitly inert adapters. No socket,
credentials, real authority, native product or hosted timing claim is made.
"""
from pathlib import Path
import hashlib,json
import argparse
p=argparse.ArgumentParser();p.add_argument('--source',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--run',action='store_true');args=p.parse_args();base=args.source;out=args.out;out.mkdir(parents=True,exist_ok=True)
paths=['crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/lifecycle_v1.rs','crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3.rs','crates/wholepact-signer/src/native_ui/runtime/coordinated_financial_driver_v1.rs']
def item(s,needle):
 p=s.index(needle);i=s.index('{',p)+1;d=1
 while d:
  if s[i]=='{':d+=1
  elif s[i]=='}':d-=1
  i+=1
 return s[p:i]
lifecycle=(base/paths[0]).read_text();common=(base/paths[1]).read_text();driver=(base/paths[2]).read_text()
method=item(lifecycle,'pub fn prepare_closed_recipient_v1(')
# Clock and transport are inert; no genuine socket/actor/authority is fabricated.
# The sole body substitution prevents a real100ms sleep in a fake-clock test.
method=method.replace('std::thread::sleep(Duration::from_millis(100));','sleep(Duration::from_millis(100));')
require=item(common,'pub(crate) fn require_before(')
narrow=item(common,'fn narrowed_deadline(')
assert 'State::DeliveryReceiveReview' not in driver[driver.index('let event = match &self.state {',driver.index('// Waiting status sockets')):driver.index('if let Some(event) = event {',driver.index('// Waiting status sockets'))]
helper=item(lifecycle,'fn preparation_status_deadline(')
text='''#![allow(dead_code,unused_imports)]
// Exact client preparation control flow. Inert DTO validators, clock and
// transport replace product authority/kernel execution; source binding explicit.
use std::{cell::RefCell,collections::VecDeque,time::Duration};
#[derive(Debug,PartialEq,Eq)]enum BridgeError{Permission,Binding,Ipc}
type Result<T>=std::result::Result<T,BridgeError>;
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
impl Instant{fn now()->Self{CLOCK.with(|c|*c.borrow())}}
impl std::ops::Add<Duration> for Instant{type Output=Self;fn add(self,d:Duration)->Self{Self(self.0+d.as_millis() as u64)}}
thread_local!{static CLOCK:RefCell<Instant>=const{RefCell::new(Instant(0))};static STEPS:RefCell<VecDeque<(u64,CoordinatedClosedResponseV1)>>=const{RefCell::new(VecDeque::new())};static TRACE:RefCell<Vec<(&'static str,u64)>>=const{RefCell::new(Vec::new())};static NONCE:RefCell<u64>=const{RefCell::new(0)};static REPEAT:RefCell<bool>=const{RefCell::new(false)};}
fn sleep(d:Duration){CLOCK.with(|c|{let prior=*c.borrow();*c.borrow_mut()=prior+d;});}
fn observe_bridge_v3<T>(r:Result<T>,_:&str)->Result<T>{r}
'''+require+'\n'+narrow+'\n'+helper+'''
fn fresh_nonce()->Result<String>{NONCE.with(|n|{if !REPEAT.with(|r|*r.borrow()){*n.borrow_mut()+=1;}Ok(format!("nonce{}",*n.borrow()))})}
type DurableReviewDeliveryRequestV1=u8;type FixedProposalIdentityV1=u8;type DurableDeliveryPlanV2=u8;type DurableDeliveryMaterialScopeRefV2=u8;
#[derive(Clone,Debug,PartialEq,Eq)]struct Preparation(u8);impl Preparation{fn digest(&self)->Result<String>{Ok("request".into())}}
#[derive(Clone,Debug,PartialEq,Eq)]struct Intent{marker:u8,account_id:String,participant_id:String,agreement_id:String,manifest_digest:String,source_identity_digest:String,authorized_host_process_instance:String,signer_process_instance:String,coordinated_provider_reference:String,receive_decision:String}
type CoordinatedRecipientIntentV1=Intent;
impl Intent{fn validate(&self)->Result<()>{if self.marker==0{Err(BridgeError::Binding)}else{Ok(())}}fn preparation(&self)->Preparation{Preparation(self.marker)}}
struct Scope{account_id:String,participant_id:String,agreement_id:String,manifest_digest:String}
struct Endpoint{source_identity_digest:String,signer_process_instance:String,coordinated_provider_reference:String}
struct CoordinatedOriginalClientV1{deadline:Instant,scope:Scope,endpoint:Endpoint,original_host_process_instance:String}
struct PreparedCoordinatedDurableReviewRecipientV1{client:CoordinatedOriginalClientV1,intent:Intent,deadline:Instant,material_deadline:Instant}
struct UnixStream;
enum CoordinatedAppRequestV1{Prepare{request:Box<Preparation>}}
enum CoordinatedClosedCommandV1{PreparationStatus{request_digest:String,nonce:String}}
enum CoordinatedClosedResponseV1{Staged{request_digest:String},Preparing{nonce:String},Prepared{nonce:String,intent:Intent,remaining_read_ms:u64,remaining_material_ms:u64},Invalid}
impl CoordinatedOriginalClientV1{
 fn check_current(&self)->Result<()>{require_before(self.deadline)}
 fn build_preparation(&self,_:u8,_:u8,_:String,_:u64,_:u8,_:Vec<u8>)->Result<Preparation>{self.check_current()?;Ok(Preparation(1))}
 fn open_request(&self,_:&CoordinatedAppRequestV1,deadline:Instant)->Result<UnixStream>{TRACE.with(|t|t.borrow_mut().push(("Prepare",deadline.0)));require_before(deadline)?;self.check_current()?;Ok(UnixStream)}
 fn open_closed(&self,_:CoordinatedClosedCommandV1,deadline:Instant)->Result<UnixStream>{TRACE.with(|t|t.borrow_mut().push(("PreparationStatus",deadline.0)));require_before(deadline)?;self.check_current()?;Ok(UnixStream)}
 fn closed_response(&self,_:&UnixStream,deadline:Instant,_:&dyn Fn()->Result<()>)->Result<CoordinatedClosedResponseV1>{let(delay,response)=STEPS.with(|s|s.borrow_mut().pop_front()).ok_or(BridgeError::Ipc)?;sleep(Duration::from_millis(delay));require_before(deadline)?;self.check_current()?;Ok(response)}
'''+method+'''
}
fn intent()->Intent{Intent{marker:1,account_id:"a".into(),participant_id:"p".into(),agreement_id:"g".into(),manifest_digest:"m".into(),source_identity_digest:"s".into(),authorized_host_process_instance:"h".into(),signer_process_instance:"i".into(),coordinated_provider_reference:"r".into(),receive_decision:"originaldecision".into()}}
fn client(cap:u64)->CoordinatedOriginalClientV1{CoordinatedOriginalClientV1{deadline:Instant(cap),scope:Scope{account_id:"a".into(),participant_id:"p".into(),agreement_id:"g".into(),manifest_digest:"m".into()},endpoint:Endpoint{source_identity_digest:"s".into(),signer_process_instance:"i".into(),coordinated_provider_reference:"r".into()},original_host_process_instance:"h".into()}}
fn prepared(nonce:u64,delay:u64,read:u64,material:u64)->(u64,CoordinatedClosedResponseV1){(delay,CoordinatedClosedResponseV1::Prepared{nonce:format!("nonce{nonce}"),intent:intent(),remaining_read_ms:read,remaining_material_ms:material})}
fn run(cap:u64,steps:Vec<(u64,CoordinatedClosedResponseV1)>)->Result<PreparedCoordinatedDurableReviewRecipientV1>{run_nonce_mode(cap,steps,false)}
fn run_nonce_mode(cap:u64,steps:Vec<(u64,CoordinatedClosedResponseV1)>,repeat:bool)->Result<PreparedCoordinatedDurableReviewRecipientV1>{CLOCK.with(|c|*c.borrow_mut()=Instant(0));NONCE.with(|n|*n.borrow_mut()=0);REPEAT.with(|r|*r.borrow_mut()=repeat);TRACE.with(|t|t.borrow_mut().clear());STEPS.with(|s|*s.borrow_mut()=steps.into());client(cap).prepare_closed_recipient_v1(0,0,"payload".into(),10,0,vec![])}
fn staged()->(u64,CoordinatedClosedResponseV1){(1,CoordinatedClosedResponseV1::Staged{request_digest:"request".into()})}
#[test]fn serial_valid_reviews_over120_succeed_only_after_second_query(){let p=run(900000,vec![staged(),prepared(1,240000,120000,600000),prepared(2,10,119990,599990)]).unwrap();assert_eq!(TRACE.with(|t|t.borrow().clone()),[("Prepare",120000),("PreparationStatus",900000),("PreparationStatus",360001)]);assert_eq!(p.deadline,Instant(359991));assert_eq!(p.material_deadline,Instant(839991));assert!(p.deadline>Instant::now());}
#[test]fn readiness_alone_never_constructs_a_client_lease(){assert!(matches!(run(900000,vec![staged(),prepared(1,240000,120000,600000)]),Err(BridgeError::Ipc)));assert_eq!(TRACE.with(|t|t.borrow().len()),3);}
#[test]fn initial_prepare_staged_120_is_unchanged(){assert!(matches!(run(900000,vec![(120001,CoordinatedClosedResponseV1::Staged{request_digest:"request".into()})]),Err(BridgeError::Permission)));assert_eq!(TRACE.with(|t|t.borrow().len()),1);}
#[test]fn original_channel_expiry_never_renews(){assert!(matches!(run(200000,vec![staged(),prepared(1,240000,120000,600000)]),Err(BridgeError::Permission)));assert_eq!(TRACE.with(|t|t.borrow().last().unwrap().1),200000);}
#[test]fn second_query_still_has120_cap_and_no_retry(){assert!(matches!(run(900000,vec![staged(),prepared(1,240000,120000,600000),prepared(2,120001,120000,600000)]),Err(BridgeError::Permission)));assert_eq!(TRACE.with(|t|t.borrow().len()),3);}
#[test]fn second_preparing_regression_is_not_retried(){assert!(matches!(run(900000,vec![staged(),prepared(1,1000,120000,600000),(1,CoordinatedClosedResponseV1::Preparing{nonce:"nonce2".into()})]),Err(BridgeError::Permission)));assert_eq!(TRACE.with(|t|t.borrow().len()),3);}
#[test]fn first_preparing_does_not_renew_parent_channel(){let p=run(900000,vec![staged(),(180000,CoordinatedClosedResponseV1::Preparing{nonce:"nonce1".into()}),prepared(2,60000,120000,600000),prepared(3,10,119990,599990)]).unwrap();assert!(p.deadline>Instant::now());assert_eq!(TRACE.with(|t|t.borrow()[1..3].iter().map(|x|x.1).collect::<Vec<_>>()),[900000,900000]);}
#[test]fn wrong_nonce_rejected_at_each_response(){for second in [false,true]{let mut steps=vec![staged()];if second{steps.push(prepared(1,1000,120000,600000));}steps.push((1,CoordinatedClosedResponseV1::Prepared{nonce:"wrong".into(),intent:intent(),remaining_read_ms:120000,remaining_material_ms:600000}));assert!(matches!(run(900000,steps),Err(BridgeError::Permission)));}}
#[test]fn first_and_second_ranges_remain_closed(){for second in [false,true]{for(read,material)in[(0,600000),(120001,600000),(120000,0),(120000,900001)]{let mut steps=vec![staged()];if second{steps.push(prepared(1,1000,120000,600000));}steps.push(prepared(if second{2}else{1},1,read,material));assert!(matches!(run(900000,steps),Err(BridgeError::Permission)));}}}
#[test]fn transit_cannot_extend_actual_remaining_permissions(){for(read,material)in[(1,600000),(120000,1)]{assert!(matches!(run(900000,vec![staged(),prepared(1,1000,120000,600000),prepared(2,2,read,material)]),Err(BridgeError::Permission)));}}
#[test]fn every_bound_identity_and_extra_intent_field_is_exact(){for index in 0..10{let mut changed=intent();match index{0=>changed.marker=2,1=>changed.account_id="bad".into(),2=>changed.participant_id="bad".into(),3=>changed.agreement_id="bad".into(),4=>changed.manifest_digest="bad".into(),5=>changed.source_identity_digest="bad".into(),6=>changed.authorized_host_process_instance="bad".into(),7=>changed.signer_process_instance="bad".into(),8=>changed.coordinated_provider_reference="bad".into(),_=>changed.receive_decision="bad".into()};assert!(matches!(run(900000,vec![staged(),prepared(1,1000,120000,600000),(1,CoordinatedClosedResponseV1::Prepared{nonce:"nonce2".into(),intent:changed,remaining_read_ms:119999,remaining_material_ms:599999})]),Err(BridgeError::Binding)));}}
#[test]fn reused_readiness_nonce_is_rejected_before_second_io(){assert!(matches!(run_nonce_mode(900000,vec![staged(),prepared(0,1000,120000,600000)],true),Err(BridgeError::Binding)));assert_eq!(TRACE.with(|t|t.borrow().len()),2);}
#[test]fn first_response_validation_is_not_only_a_readiness_boolean(){for index in 0..10{let mut bad=intent();match index{0=>bad.marker=0,1=>bad.marker=2,2=>bad.account_id="bad".into(),3=>bad.participant_id="bad".into(),4=>bad.agreement_id="bad".into(),5=>bad.manifest_digest="bad".into(),6=>bad.source_identity_digest="bad".into(),7=>bad.authorized_host_process_instance="bad".into(),8=>bad.signer_process_instance="bad".into(),_=>bad.coordinated_provider_reference="bad".into()};assert!(matches!(run(900000,vec![staged(),(1,CoordinatedClosedResponseV1::Prepared{nonce:"nonce1".into(),intent:bad,remaining_read_ms:120000,remaining_material_ms:600000})]),Err(BridgeError::Binding)));assert_eq!(TRACE.with(|t|t.borrow().len()),2);}}
#[test]fn uncertain_initial_stage_is_never_retried(){assert!(matches!(run(900000,vec![]),Err(BridgeError::Ipc)));assert_eq!(TRACE.with(|t|t.borrow().len()),1);}
'''
(out/'preparation-client-trace.rs').write_text(text)
(out/'preparation-client-source-binding.json').write_text(json.dumps({'candidate':str(base),'sources':{p:hashlib.sha256((base/p).read_bytes()).hexdigest()for p in paths},'limits':['Exact client method except real sleep replaced with fake-clock advancement.','Inert DTO/currentness/transport adapters do not establish authority/kernel/scheduling behavior.','Server no-status-before-Receive-Final verified structurally; no server operation executed.','No timing attribution to P45; actual Prepare timestamp unavailable.']},indent=2)+'\n')
print('generated14 source-bound client tests; execution separate')

# Exact before-body from P45a6916b8519647989071004c1358c9cfcd2f6190f.
old_method='pub fn prepare_closed_recipient_v1(\n        self,\n        request: DurableReviewDeliveryRequestV1,\n        fixed: FixedProposalIdentityV1,\n        payload_digest: String,\n        payload_bytes: u64,\n        delivery: DurableDeliveryPlanV2,\n        material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,\n    ) -> Result<PreparedCoordinatedDurableReviewRecipientV1> {\n        let preparation = self.build_preparation(\n            request,\n            fixed,\n            payload_digest,\n            payload_bytes,\n            delivery,\n            material_scopes,\n        )?;\n        let request_digest = preparation.digest()?;\n        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(120));\n        let stream = self.open_request(\n            &CoordinatedAppRequestV1::Prepare {\n                request: Box::new(preparation.clone()),\n            },\n            deadline,\n        )?;\n        match self.closed_response(&stream, deadline, &|| Ok(()))? {\n            CoordinatedClosedResponseV1::Staged {\n                request_digest: actual,\n            } if actual == request_digest => {}\n            _ => return Err(BridgeError::Permission),\n        }\n        drop(stream);\n        loop {\n            let nonce = fresh_nonce()?;\n            let started = Instant::now();\n            let stream = self.open_closed(\n                CoordinatedClosedCommandV1::PreparationStatus {\n                    request_digest: request_digest.clone(),\n                    nonce: nonce.clone(),\n                },\n                deadline,\n            )?;\n            match self.closed_response(&stream, deadline, &|| Ok(()))? {\n                CoordinatedClosedResponseV1::Prepared {\n                    nonce: actual,\n                    intent,\n                    remaining_read_ms,\n                    remaining_material_ms,\n                } if actual == nonce => {\n                    intent.validate()?;\n                    if intent.preparation() != preparation\n                        || intent.account_id != self.scope.account_id\n                        || intent.participant_id != self.scope.participant_id\n                        || intent.agreement_id != self.scope.agreement_id\n                        || intent.manifest_digest != self.scope.manifest_digest\n                        || intent.source_identity_digest != self.endpoint.source_identity_digest\n                        || intent.authorized_host_process_instance\n                            != self.original_host_process_instance\n                        || intent.signer_process_instance != self.endpoint.signer_process_instance\n                        || intent.coordinated_provider_reference\n                            != self.endpoint.coordinated_provider_reference\n                    {\n                        return Err(BridgeError::Binding);\n                    }\n                    // Original S communicates only its already captured material\n                    // ceiling. Anchor before request I/O so transit never renews it.\n                    if remaining_material_ms == 0 || remaining_material_ms > 900_000 {\n                        return Err(BridgeError::Permission);\n                    }\n                    let material_deadline =\n                        (started + Duration::from_millis(remaining_material_ms)).min(self.deadline);\n                    require_before(material_deadline)?;\n                    let deadline =\n                        narrowed_deadline(started, remaining_read_ms, material_deadline)?;\n                    return Ok(PreparedCoordinatedDurableReviewRecipientV1 {\n                        client: self,\n                        intent,\n                        deadline,\n                        material_deadline,\n                    });\n                }\n                CoordinatedClosedResponseV1::Preparing { nonce: actual } if actual == nonce => {\n                    drop(stream);\n                    require_before(deadline)?;\n                    self.check_current()?;\n                    sleep(Duration::from_millis(100));\n                }\n                _ => return Err(BridgeError::Permission),\n            }\n        }\n    }'
# Preserve the initial Prepare/Staged operation order and every original binding
# predicate exactly; only readiness status and its second-query fence change.
assert method[:method.index('        drop(stream);')] == old_method[:old_method.index('        drop(stream);')]
binding_start='                    intent.validate()?;'
binding_end='                    // Original S communicates'
original_binding=old_method[old_method.index(binding_start):old_method.index(binding_end)]
assert original_binding in method
original_construction=old_method[old_method.index('                    let material_deadline ='):old_method.index('                CoordinatedClosedResponseV1::Preparing')]
assert original_construction in method
binding_path=out/'preparation-client-source-binding.json'
binding=json.loads(binding_path.read_text())
binding['baseline_commit']='a6916b8519647989071004c1358c9cfcd2f6190f'
binding['baseline_method_with_sleep_adapter_sha256']=hashlib.sha256(old_method.encode()).hexdigest()
binding['current_method_with_sleep_adapter_sha256']=hashlib.sha256(method.encode()).hexdigest()
binding['unchanged_checks']=['Exact initial Prepare/Staged prefix','Exact original intent validation and all binding predicates','Exact original material/read deadline formula and prepared-client construction']
binding_path.write_text(json.dumps(binding,indent=2)+'\n')
old_text=text[:text.index('#[test]fn serial_valid_reviews_over120_succeed_only_after_second_query()')].replace(method,old_method)
old_text+='#[test]fn old_total120_rejects_valid_late_receive(){assert!(matches!(run(900000,vec![staged(),prepared(1,240000,120000,600000)]),Err(BridgeError::Permission)));}\n#[test]fn old_anchor_charges_wait_against_fresh_permission(){let p=run(900000,vec![staged(),prepared(1,119000,120000,600000)]).unwrap();assert_eq!(p.deadline,Instant(120001));assert_eq!(Instant::now(),Instant(119001));}\n'
(out/'preparation-client-before.rs').write_text(old_text)
if args.run:
 import subprocess,os
 rustc=os.environ.get('RUSTC','rustc')
 for name,count in [('preparation-client-before',2),('preparation-client-trace',14)]:
  binary=out/(name+'-tests')
  subprocess.run([rustc,'--edition=2021','--test',str(out/(name+'.rs')),'-o',str(binary)],check=True,timeout=60)
  listing=subprocess.run([str(binary.resolve()),'--list'],check=True,capture_output=True,text=True,timeout=10).stdout
  assert sum(x.endswith(': test')for x in listing.splitlines())==count,(name,listing)
  subprocess.run([str(binary.resolve()),'--test-threads=1'],check=True,timeout=30)
