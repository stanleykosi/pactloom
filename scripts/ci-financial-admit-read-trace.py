#!/usr/bin/env python3
"""Exact-source AdmitRead control-flow fault trace with inert std-only carriers.

Generation performs no native execution, sockets or product imports. --run is
for the approved hosted runner only. This is not genuine Final/Pair, journal,
TLS/history, source-IPC or whole-flow qualification. Dependencies below are
fault-injecting inert carriers; selected runtime bodies are extracted verbatim
apart from visibility and old/new finish method names.
"""
import argparse,hashlib,json,os,re,selectors,subprocess,sys,time
from pathlib import Path
PATHS = {'runtime': 'crates/wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs', 'witness': 'crates/wholepact-signer/src/native_ui/witness_workspace/durable_delivery_v3/coordinated_admit_read_v1.rs', 'final': 'crates/wholepact-financial-coordinator-origin/src/signer_v3_admit_read_origin.rs', 'macros': 'crates/wholepact-signer/src/lib.rs', 'actor': 'crates/wholepact-signer/src/financial_ci_actor.rs', 'core': 'crates/wholepact-financial-coordinator-origin/src/signer_continue_state.rs', 'observer': 'crates/wholepact-financial-coordinator-origin/src/financial_observer.rs', 'diagnostic': 'crates/wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs'}
BASELINE_COMMIT = '27e668bfcf84fe809b6bca4a1c15a5e8e6dd1caf'
BASELINE_FILES = {'runtime': '1a7102c966c67f396bf4615d38e91d4e4d0f92d149b5e8c82ff703cde29149bd', 'witness': 'fcc6488dd9c32f3b62ccef30a5e059721cdf640b9d40759307421c1086e6a265', 'final': 'eeb646b34732286186b5717f6d3060b485c3d2bd35f77e81fc62524405f01b79'}
BASELINE_BLOCKS = {'runtime_read': 'pub(in crate::native_ui::runtime) fn read_for_admission(\n        self,\n        action: SignerV3AdmitReadFinalV1,\n    ) -> Result<CoordinatedReadAdmissionV1> {\n        self.check_current()?;\n        action.check_current()?;\n        // A DTO-equivalent report alone cannot enter: this method consumes the\n        // sole actual proof-verified source/client/material owner as well.\n        if action.facts().received != self.report\n            || self.intent.digest().map_err(|_| Error::ReviewMismatch)?\n                != self.report.recipient_intent_digest\n        {\n            return Err(Error::ReviewMismatch);\n        }\n        self.source.check_admit_read_source(&action)?;\n        let Self {\n            source,\n            witness,\n            intent,\n            fixed,\n            receipt,\n            report,\n        } = self;\n        // The callback below is restriction-only; all actual journal reads are\n        // separately guarded by the retained nominal Final before and after.\n        let witness = witness.read_for_admission(action, || source.check_current())?;\n        source.check_admit_read_source(witness.action())?;\n        Ok(CoordinatedReadAdmissionV1 {\n            source,\n            witness,\n            intent,\n            fixed,\n            receipt,\n            received: report,\n        })\n    }', 'prepare': 'pub(in crate::native_ui::runtime) fn prepare(self) -> Result<PreparedCoordinatedAdmissionV1> {\n        let prepared = self.source.prepare_admission_intent(\n            self.witness.action(),\n            &self.fixed,\n            &self.intent,\n            self.witness.history(),\n        )?;\n        let request = prepared.request();\n        let retained_report = wholepact_financial_coordinator_origin::SignerV3AdmitReadRetainedV1 {\n            admit_read_presentation_digest: self\n                .witness\n                .action()\n                .presentation()\n                .presentation_digest\n                .clone(),\n            source_identity_digest: self.received.source_identity_digest.clone(),\n            owner_service_digest: self.received.owner_service_digest.clone(),\n            recipient_intent_digest: self.received.recipient_intent_digest.clone(),\n            authenticated_history_digest: self\n                .witness\n                .history()\n                .history_digest()\n                .map_err(|_| Error::ReviewMismatch)?,\n            admission_request_digest: prepared.request_digest()?,\n            admission_review_digest: prepared.review_digest().into(),\n            operation_id: request.operation_id.clone(),\n            expected_head_sequence: request.expected_head.sequence,\n            expected_head_digest: request.expected_head.digest.clone(),\n            display: prepared.display()?,\n        };\n        retained_report.validate()?;\n        self.source.check_admit_read_source(self.witness.action())?;\n        let read_deadline = self.witness.action().original_read_deadline();\n        let read_expires_at_ms = self.witness.action().facts().expires_at_ms;\n        let (witness, history) = self.witness.finish()?;\n        Ok(PreparedCoordinatedAdmissionV1 {\n            source: self.source,\n            witness,\n            intent: self.intent,\n            fixed: self.fixed,\n            receipt: self.receipt,\n            received: self.received,\n            history,\n            prepared,\n            retained_report,\n            read_deadline,\n            read_expires_at_ms,\n        })\n    }', 'witness_read': 'pub(in crate::native_ui) fn read_for_admission(\n        self,\n        action: SignerV3AdmitReadFinalV1,\n        mut check_source: impl FnMut() -> Result<()>,\n    ) -> Result<ReadCoordinatedDeliveryWitnessV1> {\n        let check = || -> Result<()> {\n            self.check_custody()?;\n            action.check_current()?;\n            action.presentation().validate()?;\n            let facts = action.facts();\n            let opened = &self.opened;\n            if facts.received.source_identity_digest != opened.source_identity\n                || facts.received.owner_service_digest != opened.owner_service_digest\n                || facts.received.prepare_read_presentation_digest\n                    != opened.prepare_read_presentation_digest\n                || facts.owner_selection_digest != opened.selection_digest\n                || facts.owner_certificate_digest != opened.certificate_digest\n                || facts.disclosure_digest\n                    != wholepact_core::proposal::canonical_digest(\n                        "wholepact:coordinated-v3-owner-disclosure:v1",\n                        &opened.disclosure,\n                    )\n                    .map_err(|_| Error::InvalidData)?\n                || action.original_source_deadline() != opened.original_source_deadline\n                || action.original_channel_deadline() != opened.original_channel_deadline\n                || action.original_service_deadline() != opened.original_service_deadline\n                || action.original_material_deadline() != opened.original_material_deadline\n            {\n                return Err(Error::ReviewMismatch);\n            }\n            Ok(())\n        };\n        check()?;\n        check_source()?;\n        let mut callback_error = None;\n        let result = self.opened.client.reconcile_history_checked_until(\n            action.original_read_deadline(),\n            || {\n                check().and_then(|_| check_source()).map_err(|error| {\n                    if callback_error.is_none() {\n                        callback_error = Some(error);\n                    }\n                    wholepact_authority::AuthorityError::Permission\n                })\n            },\n        );\n        if let Some(error) = callback_error {\n            return Err(error);\n        }\n        let history = result.map_err(|_| Error::Uncertain)?;\n        check()?;\n        check_source()?;\n        if history.disclosure() != &self.opened.disclosure {\n            return Err(Error::Authentication);\n        }\n        Ok(ReadCoordinatedDeliveryWitnessV1 {\n            witness: self,\n            history,\n            action,\n        })\n    }', 'witness_finish': 'pub(in crate::native_ui) fn finish(\n        self,\n    ) -> Result<(CoordinatedDeliveryWitnessV1, ReconciledAuthorityHistory)> {\n        self.witness.check_custody()?;\n        self.action.finish_read()?;\n        Ok((self.witness, self.history))\n    }', 'final_finish': 'pub fn finish_read(mut self) -> Result<()> {\n        self.check_current()?;\n        self.binding.owner.pair.entry.core.phase.step(\n            self.binding.owner.pair.entry.slot(),\n            151,\n            152,\n        )?;\n        self.consumed = true;\n        Ok(())\n    }'}
BASELINE_BLOCK_SHA256 = {'runtime_read': 'a3d9f315c394b57039a120708b514632a5c97642a631b9a5fe2f1711c44fb211', 'prepare': 'ed74af7ac975792f03549e5d06cb7531112b6eed9b3dcec9ee5f85c273a5c927', 'witness_read': 'ba9b267e5ac4cb8009ad37f148350fd94ff8394d11c99b5555053fb037369db6', 'witness_finish': 'd5105356e59513a3b77b086f05b6501157858bdf8e5588406c1ceabc48d4fa92', 'final_finish': '182c1703e8197613d17ed808908e855898a26cc88cd5ff820a1988395e88d59d'}

PREFIX = r'''#![allow(dead_code,unused_imports,unused_variables,non_snake_case)]
// INERT carriers only: no cryptographic/native authority, IPC or filesystem.
use std::{cell::{Cell,RefCell},collections::BTreeMap,rc::Rc,sync::{Mutex,atomic::Ordering}};
type Instant=u64;
#[derive(Debug,PartialEq,Eq)]enum Error{Injected(&'static str,usize),ReviewMismatch,InvalidData,Authentication,Uncertain,Permission,Opaque(Box<u64>)}
impl Error{fn kind(&self)->std::io::ErrorKind{std::io::ErrorKind::Other}}
type Result<T,E=Error>=std::result::Result<T,E>;
thread_local!{
 static EVENTS:RefCell<Vec<String>>=RefCell::new(Vec::new());
 static COUNTS:RefCell<BTreeMap<&'static str,usize>>=RefCell::new(BTreeMap::new());
 static FAULT:Cell<Option<(&'static str,usize)>>=const{Cell::new(None)};
 static OLD:Cell<bool>=const{Cell::new(false)};
 static MODE:Cell<u8>=const{Cell::new(0)};
 static MUTATION:Cell<u8>=const{Cell::new(0)};
 static FAILURE:Cell<Option<(DriverStage,Class)>>=const{Cell::new(None)};
}
fn event(s:impl Into<String>){EVENTS.with(|v|v.borrow_mut().push(s.into()));}
fn hit(name:&'static str)->Result<()> {
 let n=COUNTS.with(|v|{let mut v=v.borrow_mut();let n=v.entry(name).or_default();*n+=1;*n});
 event(format!("hit:{name}:{n}"));
 if FAULT.with(|f|f.get()==Some((name,n))){Err(Error::Injected(name,n))}else{Ok(())}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum Class{IoOther,SignerReviewMismatch,SignerInvalidData,SignerAuthentication,SignerUncertain}
mod financial_ci_actor_diagnostics{
 use super::*;
 pub(super) use super::{Class,DriverStage};
 pub(super) fn driver(stage:DriverStage,class:Class){event(format!("diagnostic:{stage:?}"));FAILURE.with(|v|if v.get().is_none(){v.set(Some((stage,class)))});}
 pub(super) fn classify_io(_:std::io::ErrorKind)->Class{Class::IoOther}
 pub(super) fn sample_failure()->Option<FailureFacts>{FAILURE.with(|v|v.get().map(|(stage,class)|FailureFacts{stage,class}))}
}
#[derive(Clone,Copy)]struct FailureFacts{stage:DriverStage,class:Class}
#[derive(Clone,Copy)]struct ReapFacts;
#[derive(Clone,Copy,Default)]struct Reporter{failure_attempted:bool,reap_attempted:u32,failed:bool}
mod libc{pub(super) unsafe fn getpid()->i32{1}}
'''

ACTOR_PREFIX = r'''
mod financial_ci_actor{
 use super::*;
 use crate::financial_ci_actor_diagnostics as diagnostic;
 pub(crate) trait ErrorClass{fn finite_class(&self)->Class;}
 impl ErrorClass for Error{fn finite_class(&self)->Class{match self{Error::ReviewMismatch=>Class::SignerReviewMismatch,Error::InvalidData=>Class::SignerInvalidData,Error::Authentication=>Class::SignerAuthentication,Error::Uncertain=>Class::SignerUncertain,_=>Class::IoOther}}}
 pub(crate) fn admit_read_history_detail(_: &DiagnosedError)->(DriverStage,Class){(DriverStage::AdmitReadHistorySnapshotResponseRead,Class::IoOther)}
'''

OBSERVER_PREFIX = r'''
mod financial_observer{
 use super::*;
 struct Writer{pid:i32,actor_diagnostic:Reporter}
 static WRITER:Mutex<Option<Writer>>=Mutex::new(None);
 fn emit_locked(_: &mut Writer,_: &str,_:&FailureFacts)->Result<(),()> {
  event("append"); match MODE.with(Cell::get){2=>Err(()),3=>panic!("synthetic observer append panic"),_=>Ok(())}
 }
 pub(super) fn reset(){WRITER.clear_poison();*WRITER.lock().unwrap()=Some(Writer{pid:1,actor_diagnostic:Reporter::default()});}
 pub(super) fn with_busy(f:impl FnOnce()) {let _held=WRITER.lock().unwrap();f();}
'''

COMMON = r'''
struct Phase;
impl Phase{fn revoke(&self){event("revoke")}fn step(&self,_:u8,_:u8,_:u8)->Result<()>{hit("phase_step")}}
struct Alive;impl Alive{fn store(&self,_:bool,_:Ordering){event("alive_false")}}
struct Peer;impl Peer{fn shutdown(&self){event("shutdown")}}
struct Core{phase:Phase,alive:Alive,peer:Peer}
struct Entry{core:Rc<Core>}impl Entry{fn slot(&self)->u8{0}}
struct Pair{entry:Entry}struct Owner{pair:Pair}struct Binding{owner:Owner}
#[derive(Clone,Debug,PartialEq,Eq)]struct SignerV3ReceivedV1{source_identity_digest:String,owner_service_digest:String,prepare_read_presentation_digest:String,recipient_intent_digest:String}
impl SignerV3ReceivedV1{fn new()->Self{Self{source_identity_digest:"source".into(),owner_service_digest:"owner".into(),prepare_read_presentation_digest:"prepare".into(),recipient_intent_digest:"intent".into()}}}
struct Facts{received:SignerV3ReceivedV1,owner_selection_digest:String,owner_certificate_digest:String,disclosure_digest:String,expires_at_ms:u64}
struct Presentation{facts:Facts,presentation_digest:String}
impl Presentation{fn validate(&self)->Result<()>{hit("presentation_validate")}}
struct SignerV3AdmitReadFinalV1{binding:Binding,p:Presentation,consumed:bool}
impl SignerV3AdmitReadFinalV1{
 fn new()->Self{let mut value=Self{binding:Binding{owner:Owner{pair:Pair{entry:Entry{core:Rc::new(Core{phase:Phase,alive:Alive,peer:Peer})}}}},p:Presentation{facts:Facts{received:SignerV3ReceivedV1::new(),owner_selection_digest:"selection".into(),owner_certificate_digest:"certificate".into(),disclosure_digest:"disclosure".into(),expires_at_ms:50},presentation_digest:"presentation".into()},consumed:false};if MUTATION.with(Cell::get)==12{value.p.facts.disclosure_digest.push('x')};value}
 fn presentation(&self)->&Presentation{&self.p}
 fn facts(&self)->&Facts{&self.p.facts}
 fn check_current(&self)->Result<()>{hit("action_current")}
 fn original_source_deadline(&self)->Instant{100}
 fn original_channel_deadline(&self)->Instant{90}
 fn original_service_deadline(&self)->Instant{80}
 fn original_material_deadline(&self)->Instant{70}
 fn original_read_deadline(&self)->Instant{50}
 fn finish_read(self)->Result<()>{if OLD.with(Cell::get){self.finish_read_old()}else{self.finish_read_new()}}
}
struct Head{sequence:u64,digest:String}struct Request{operation_id:String,expected_head:Head}
struct PreparedIntent{request:Request}
impl PreparedIntent{
 fn request(&self)->&Request{&self.request}
 fn request_digest(&self)->Result<String>{hit("request_digest")?;Ok("request".into())}
 fn review_digest(&self)->&str{"review"}
 fn display(&self)->Result<String>{hit("display")?;Ok("display".into())}
}
impl Drop for PreparedIntent{fn drop(&mut self){event("prepared_drop")}}
struct SignerV3AdmitReadRetainedV1{admit_read_presentation_digest:String,source_identity_digest:String,owner_service_digest:String,recipient_intent_digest:String,authenticated_history_digest:String,admission_request_digest:String,admission_review_digest:String,operation_id:String,expected_head_sequence:u64,expected_head_digest:String,display:String}
impl SignerV3AdmitReadRetainedV1{fn validate(&self)->Result<()>{hit("report_validate")}}
mod wholepact_financial_coordinator_origin{pub(super) use super::{SignerV3AdmitReadFinalV1,SignerV3AdmitReadRetainedV1,financial_ci_actor_diagnostics};}
mod consent_journal{pub(crate) mod durable_delivery_admission_intent_v3{pub(crate) mod coordinated_v1{pub(crate) type PreparedCoordinatedAdmissionIntentV1=crate::PreparedIntent;}}}
struct ReconciledAuthorityHistory{disclosure:String}
impl ReconciledAuthorityHistory{fn disclosure(&self)->&String{&self.disclosure}fn history_digest(&self)->Result<String>{hit("history_digest")?;Ok("history".into())}}
mod wholepact_authority{pub(super) use super::ReconciledAuthorityHistory;pub(super) type AuthorityError=super::Error;}
mod wholepact_core{pub(super) mod proposal{pub(crate) fn canonical_digest(_: &str,_:&String)->crate::Result<String>{crate::hit("disclosure_digest")?;Ok("disclosure".into())}}}
struct DiagnosedError{error:Error}impl DiagnosedError{fn returned_error(self)->Error{self.error}}
struct Client;
impl Client{
 fn reconcile_history_checked_until(&self,_:Instant,mut current:impl FnMut()->Result<()>)->Result<ReconciledAuthorityHistory>{
  event("history_call");
  if let Err(e)=current(){if MUTATION.with(Cell::get)==20{return Err(Error::Uncertain)}if MUTATION.with(Cell::get)==21{return Ok(ReconciledAuthorityHistory{disclosure:"disclosure".into()})}return Err(e)}
  hit("history_result")?;current()?;
  Ok(ReconciledAuthorityHistory{disclosure:if MUTATION.with(Cell::get)==14{"wrong"}else{"disclosure"}.into()})
 }
 fn reconcile_history_diagnosed_checked_until(&self,d:Instant,current:impl FnMut()->Result<()>)->Result<ReconciledAuthorityHistory,DiagnosedError>{self.reconcile_history_checked_until(d,current).map_err(|error|DiagnosedError{error})}
}
impl Drop for Client{fn drop(&mut self){event("client_drop")}}
'''

CARRIERS = r'''
struct CoordinatedPreparedDeliverySourceV1;
impl CoordinatedPreparedDeliverySourceV1{
 fn check_admit_read_source(&self,_:&SignerV3AdmitReadFinalV1)->Result<()>{hit("source_admit")}
 fn check_current(&self)->Result<()>{hit("source_current")}
 fn prepare_admission_intent(&self,_:&SignerV3AdmitReadFinalV1,_:&VerifiedDurableEconomicsV1,_:&CoordinatedRecipientIntentV1,_:&ReconciledAuthorityHistory)->Result<PreparedIntent>{hit("prepare_intent")?;Ok(PreparedIntent{request:Request{operation_id:"operation".into(),expected_head:Head{sequence:4,digest:"head".into()}}})}
}
impl Drop for CoordinatedPreparedDeliverySourceV1{fn drop(&mut self){event("source_ipc_drop")}}
struct CoordinatedRecipientIntentV1;impl CoordinatedRecipientIntentV1{fn digest(&self)->Result<String>{hit("intent_digest")?;Ok(if MUTATION.with(Cell::get)==2{"wrong"}else{"intent"}.into())}}
impl Drop for CoordinatedRecipientIntentV1{fn drop(&mut self){event("intent_drop")}}
struct VerifiedDurableEconomicsV1;impl Drop for VerifiedDurableEconomicsV1{fn drop(&mut self){event("fixed_drop")}}
struct CoordinatedVerifiedReceiptV1;impl Drop for CoordinatedVerifiedReceiptV1{fn drop(&mut self){event("receipt_drop")}}
struct Opened{source_identity:String,owner_service_digest:String,prepare_read_presentation_digest:String,selection_digest:String,certificate_digest:String,disclosure:String,original_source_deadline:Instant,original_channel_deadline:Instant,original_service_deadline:Instant,original_material_deadline:Instant,client:Client}
struct CoordinatedDeliveryWitnessV1{opened:Opened}
impl CoordinatedDeliveryWitnessV1{
 fn check_custody(&self)->Result<()>{hit("custody")}
 fn new()->Self{
 let mut opened=Opened{source_identity:"source".into(),owner_service_digest:"owner".into(),prepare_read_presentation_digest:"prepare".into(),selection_digest:"selection".into(),certificate_digest:"certificate".into(),disclosure:"disclosure".into(),original_source_deadline:100,original_channel_deadline:90,original_service_deadline:80,original_material_deadline:70,client:Client};
 match MUTATION.with(Cell::get){3=>opened.source_identity.push('x'),4=>opened.owner_service_digest.push('x'),5=>opened.prepare_read_presentation_digest.push('x'),6=>opened.selection_digest.push('x'),7=>opened.certificate_digest.push('x'),8=>opened.original_source_deadline+=1,9=>opened.original_channel_deadline+=1,10=>opened.original_service_deadline+=1,11=>opened.original_material_deadline+=1,_=>()}
 Self{opened}
 }
}
struct CoordinatedVerifiedImportV1{source:CoordinatedPreparedDeliverySourceV1,witness:CoordinatedDeliveryWitnessV1,intent:CoordinatedRecipientIntentV1,fixed:VerifiedDurableEconomicsV1,receipt:CoordinatedVerifiedReceiptV1,report:SignerV3ReceivedV1}
impl CoordinatedVerifiedImportV1{
 fn check_current(&self)->Result<()>{hit("import_current")}
 fn new()->Self{let mut report=SignerV3ReceivedV1::new();if MUTATION.with(Cell::get)==1{report.source_identity_digest.push('x')};Self{source:CoordinatedPreparedDeliverySourceV1,witness:CoordinatedDeliveryWitnessV1::new(),intent:CoordinatedRecipientIntentV1,fixed:VerifiedDurableEconomicsV1,receipt:CoordinatedVerifiedReceiptV1,report}}
}
pub(super) fn run()->Result<()> {let action=SignerV3AdmitReadFinalV1::new();let result=CoordinatedVerifiedImportV1::new().read_for_admission(action)?.prepare()?;event("prepared_success");drop(result);Ok(())}
'''

TESTS = r'''
const EXPECTED_HITS:&[(&str,usize)]=&[
 ("import_current",1),("action_current",1),("intent_digest",1),("source_admit",1),
 ("custody",1),("action_current",2),("presentation_validate",1),("disclosure_digest",1),("source_current",1),
 ("custody",2),("action_current",3),("presentation_validate",2),("disclosure_digest",2),("source_current",2),
 ("history_result",1),
 ("custody",3),("action_current",4),("presentation_validate",3),("disclosure_digest",3),("source_current",3),
 ("custody",4),("action_current",5),("presentation_validate",4),("disclosure_digest",4),("source_current",4),
 ("source_admit",2),("prepare_intent",1),("history_digest",1),("request_digest",1),("display",1),("report_validate",1),
 ("source_admit",3),("custody",5),("action_current",6),("phase_step",1),
];
fn reset(old:bool,fault:Option<(&'static str,usize)>,mode:u8,mutation:u8){
 EVENTS.with(|v|v.borrow_mut().clear());COUNTS.with(|v|v.borrow_mut().clear());FAULT.with(|v|v.set(fault));OLD.with(|v|v.set(old));MODE.with(|v|v.set(mode));MUTATION.with(|v|v.set(mutation));FAILURE.with(|v|v.set(None));financial_observer::reset();
}
fn trace()->Vec<String>{EVENTS.with(|v|v.borrow().clone())}
fn exercise(old:bool,fault:Option<(&'static str,usize)>,mode:u8,mutation:u8)->(Result<()>,Vec<String>){
 reset(old,fault,mode,mutation);
 let run=||if old{prior::run()}else{candidate::run()};
 let result=if mode==1{let mut result=None;financial_observer::with_busy(||result=Some(run()));result.unwrap()}else{run()};
 (result,trace())
}
// Remove ONLY diagnostic latch events and the exact deliberately advanced
// restrictive close sequence. Original revoke/drop/check events are retained.
fn without_diagnostics(v:&[String])->Vec<String>{
 let mut out=Vec::new();let mut i=0;
 while i<v.len(){
  if v[i].starts_with("diagnostic:"){i+=1;continue}
  if v[i]=="revoke"&&v.get(i+1).is_some_and(|s|s=="alive_false"){
   i+=2;if v.get(i).is_some_and(|s|s=="append"){i+=1;}
   assert_eq!(v.get(i).map(String::as_str),Some("shutdown"));i+=1;continue
  }
  out.push(v[i].clone());i+=1;
 }out
}
fn assert_failure_close(v:&[String],mode:u8){
 if !cfg!(wholepact_financial_rendered_host_semantic_ci){assert!(!v.iter().any(|s|s.starts_with("diagnostic:")));assert!(!v.iter().any(|s|s=="shutdown"));return}
 let diag=v.iter().position(|s|s.starts_with("diagnostic:")).expect("terminal latch");
 let close=v.iter().position(|s|s=="alive_false").expect("restrictive close");
 let shutdown=v.iter().position(|s|s=="shutdown").unwrap();
 let source_drop=v.iter().position(|s|s=="source_ipc_drop").unwrap();
 assert!(diag<close&&close<shutdown&&shutdown<source_drop);
 assert_eq!(v[close-1],"revoke");
 assert_eq!(v.iter().filter(|s|s.as_str()=="shutdown").count(),1);
 if mode==1{assert!(!v.iter().any(|s|s=="append"));}else{assert_eq!(v[close+1],"append");assert_eq!(v[close+2],"shutdown");}
}
fn expected_stage(name:&str,n:usize)->DriverStage{
 use DriverStage::*;
 match (name,n){
  ("import_current",_)=>AdmitReadCurrent,("action_current",1)=>AdmitReadAction,("action_current",6)=>AdmitReadFinishCurrent,("action_current",_)=>AdmitReadWitnessAction,
  ("intent_digest",_)=>AdmitReadIntentDigest,("source_admit",1)=>AdmitReadSourceBefore,("source_admit",2)=>AdmitReadSourceAfter,("source_admit",3)=>AdmitReadPreparedSource,
  ("custody",5)=>AdmitReadFinishCustody,("custody",_)=>AdmitReadWitnessCustody,("presentation_validate",_)=>AdmitReadWitnessPresentation,("disclosure_digest",_)=>AdmitReadWitnessDigest,
  ("source_current",_)=>AdmitReadSourceCallback,("history_result",_)=>if cfg!(feature="synthetic-qualification"){AdmitReadHistorySnapshotResponseRead}else{AdmitReadHistory},
  ("prepare_intent",_)=>AdmitReadPrepareIntent,("history_digest",_)=>AdmitReadHistoryDigest,("request_digest",_)=>AdmitReadRequestDigest,("display",_)=>AdmitReadDisplay,("report_validate",_)=>AdmitReadReport,("phase_step",_)=>AdmitReadFinishPhase,
  _=>panic!("uncovered fixed boundary"),
 }
}
#[test]fn success_preserves_exact_result_trace_and_is_silent(){
 let(old,ot)=exercise(true,None,0,0);let(new,nt)=exercise(false,None,0,0);assert!(old.is_ok()&&new.is_ok());assert_eq!(nt,ot);
 let expected=EXPECTED_HITS.iter().map(|(s,n)|format!("hit:{s}:{n}")).collect::<Vec<_>>();assert_eq!(nt.iter().filter(|s|s.starts_with("hit:")).cloned().collect::<Vec<_>>(),expected);
 assert!(!nt.iter().any(|s|s=="append"||s=="shutdown"||s.starts_with("diagnostic:")));
 assert!(FAILURE.with(Cell::get).is_none());
}
#[test]fn every_fallible_boundary_preserves_result_and_drop_trace(){
 assert_eq!(EXPECTED_HITS.len(),35);
 for &(name,n) in EXPECTED_HITS{
  let(old,ot)=exercise(true,Some((name,n)),0,0);let(new,nt)=exercise(false,Some((name,n)),0,0);
  assert!(old.is_err(),"unreached baseline boundary {name}:{n}");assert_eq!(new,old,"result {name}:{n}");
  assert_eq!(without_diagnostics(&nt),ot,"trace {name}:{n}");assert_failure_close(&nt,0);
  if cfg!(wholepact_financial_rendered_host_semantic_ci){assert_eq!(FAILURE.with(Cell::get).map(|v|v.0),Some(expected_stage(name,n)),"stage {name}:{n}");}
 }
}
#[test]fn received_witness_and_history_mismatches_preserve_original_error(){
 for mutation in [1,2,3,4,5,6,7,8,9,10,11,12,14]{
  let(old,ot)=exercise(true,None,0,mutation);let(new,nt)=exercise(false,None,0,mutation);
  assert!(old.is_err(),"mutation {mutation}");assert_eq!(new,old);assert_eq!(without_diagnostics(&nt),ot);assert_failure_close(&nt,0);
 }
}
#[test]fn callback_original_error_precedes_transport_error(){
 for mutation in [20,21]{for fault in [("source_current",2),("custody",2),("action_current",3)]{
  let(old,ot)=exercise(true,Some(fault),0,mutation);let(new,nt)=exercise(false,Some(fault),0,mutation);
  assert_eq!(old,Err(Error::Injected(fault.0,fault.1)));assert_eq!(new,old);assert_eq!(without_diagnostics(&nt),ot);assert_failure_close(&nt,0);
 }}
}
#[test]fn terminal_failure_is_observed_before_source_ipc_drop(){
 for fault in [("import_current",1),("source_current",2),("prepare_intent",1),("phase_step",1)]{
  let(old,ot)=exercise(true,Some(fault),0,0);let(new,nt)=exercise(false,Some(fault),0,0);
  assert_eq!(new,old);assert_failure_close(&nt,0);
  let before_drop=|v:Vec<String>|v.into_iter().take_while(|s|s!="source_ipc_drop").collect::<Vec<_>>();
  assert!(!before_drop(ot).iter().any(|s|s=="append"));
  assert_eq!(before_drop(nt).iter().any(|s|s=="append"),cfg!(wholepact_financial_rendered_host_semantic_ci));
 }
}
#[test]fn observer_busy_error_and_unwind_cannot_skip_original_cleanup(){
 for mode in [1,2,3]{for fault in [("import_current",1),("history_result",1),("phase_step",1)]{
  let(old,ot)=exercise(true,Some(fault),mode,0);let(new,nt)=exercise(false,Some(fault),mode,0);
  assert_eq!(new,old);assert_eq!(without_diagnostics(&nt),ot);assert_failure_close(&nt,mode);
  for dropped in ["source_ipc_drop","client_drop","intent_drop","fixed_drop","receipt_drop"]{assert_eq!(nt.iter().filter(|s|s.as_str()==dropped).count(),1,"{mode} {dropped}");}
 }}
}
#[test]fn macro_evaluates_once_preserves_payload_and_ignores_success_action(){
 reset(false,None,0,0);let mut count=0;let mut action_count=0;let action=SignerV3AdmitReadFinalV1::new();
 let payload=Box::new(7);let pointer=&*payload as *const u64;
 let result:Result<()>=actor_admit_read_result!(AdmitReadCurrent,{action_count+=1;&action},{count+=1;Err(Error::Opaque(payload))});
 assert_eq!(count,1);assert_eq!(action_count,usize::from(cfg!(wholepact_financial_rendered_host_semantic_ci)));if let Err(Error::Opaque(payload))=result{assert_eq!(pointer,&*payload as *const u64)}else{panic!("original opaque error lost")}
 reset(false,None,0,0);let mut result_evaluations=0;let mut action_evaluations=0;
 let result:Result<u8>=actor_admit_read_result!(AdmitReadCurrent,{action_evaluations+=1;&action},{result_evaluations+=1;Ok(7)});
 assert_eq!(result,Ok(7));assert_eq!((result_evaluations,action_evaluations),(1,0));assert!(trace().is_empty());
}
#[test]fn lexical_detail_requires_terminal_and_restores_nested_scope(){
 reset(false,None,0,0);
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]{
  use financial_ci_actor::*;
  admit_read_detail(DriverStage::AdmitReadSourceBefore,&Error::Authentication);assert!(FAILURE.with(Cell::get).is_none());
  let outer=AdmitReadObservation::enter();admit_read_detail(DriverStage::AdmitReadSourceCurrent,&Error::ReviewMismatch);
  {let _inner=AdmitReadObservation::enter();admit_read_detail(DriverStage::AdmitReadWitnessCustody,&Error::Authentication);assert!(FAILURE.with(Cell::get).is_none());}
  admit_read_terminal(DriverStage::AdmitReadHistory,&Error::Uncertain);
  assert_eq!(FAILURE.with(Cell::get),Some((DriverStage::AdmitReadSourceCurrent,Class::SignerReviewMismatch)));drop(outer);
  FAILURE.with(|v|v.set(None));admit_read_terminal(DriverStage::AdmitReadHistory,&Error::Uncertain);
  assert_eq!(FAILURE.with(Cell::get),Some((DriverStage::AdmitReadHistory,Class::SignerUncertain)));
 }
 #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]{
  let result:Result<()>=actor_admit_read_detail_result!(AdmitReadSourceCurrent,Err(Error::ReviewMismatch));assert_eq!(result,Err(Error::ReviewMismatch));assert!(trace().is_empty());
 }
}
#[test]fn finish_errors_close_before_original_unconsumed_final_drop(){
 for fault in [("action_current",6),("phase_step",1)]{
  let(old,ot)=exercise(true,Some(fault),0,0);let(new,nt)=exercise(false,Some(fault),0,0);
  assert_eq!(new,old);assert_eq!(without_diagnostics(&nt),ot);assert_failure_close(&nt,0);
  if cfg!(wholepact_financial_rendered_host_semantic_ci){let shutdown=nt.iter().position(|s|s=="shutdown").unwrap();assert!(nt[shutdown+1..].iter().any(|s|s=="revoke"));}
 }
}
'''

EXPECTED_TESTS = {
 'success_preserves_exact_result_trace_and_is_silent',
 'every_fallible_boundary_preserves_result_and_drop_trace',
 'received_witness_and_history_mismatches_preserve_original_error',
 'callback_original_error_precedes_transport_error',
 'terminal_failure_is_observed_before_source_ipc_drop',
 'observer_busy_error_and_unwind_cannot_skip_original_cleanup',
 'macro_evaluates_once_preserves_payload_and_ignores_success_action',
 'lexical_detail_requires_terminal_and_restores_nested_scope',
 'finish_errors_close_before_original_unconsumed_final_drop',
}

def digest(data): return hashlib.sha256(data).hexdigest()
def item(text,needle):
    """Balanced fixed-source block; braces in this selected source are balanced."""
    p=text.index(needle); b=text.index('{',p); depth=1; i=b+1
    while depth:
        if text[i]=='{': depth+=1
        elif text[i]=='}': depth-=1
        i+=1
    return text[p:i]
def visibility(text): return re.sub(r'pub\(in crate::native_ui(?:::[a-z_]+)*\)', 'pub(super)', text)
def extract(source):
    texts={key:(source/path).read_text() for key,path in PATHS.items()}
    blocks={
      'runtime_read':item(texts['runtime'],'pub(in crate::native_ui::runtime) fn read_for_admission('),
      'prepare':item(texts['runtime'],'pub(in crate::native_ui::runtime) fn prepare(self)'),
      'witness_read':item(texts['witness'],'pub(in crate::native_ui) fn read_for_admission('),
      'witness_finish':item(texts['witness'],'pub(in crate::native_ui) fn finish('),
      'final_finish':item(texts['final'],'pub fn finish_read(mut self)'),
    }
    assert len(re.findall(r'actor_admit_read_result!',blocks['runtime_read']))==6
    assert len(re.findall(r'actor_admit_read_result!',blocks['prepare']))==6
    for name,block in BASELINE_BLOCKS.items(): assert digest(block.encode())==BASELINE_BLOCK_SHA256[name]
    return texts,blocks

def generate(source,out):
    texts,blocks=extract(source)
    stage=item(texts['diagnostic'],'codes!(DriverStage {').split('{',1)[1].rsplit('}',1)[0]
    stage='#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum DriverStage {'+stage+'}\n'
    macros='\n'.join(item(texts['macros'],'macro_rules! '+name) for name in ['actor_admit_read_result','actor_admit_read_detail_result'])
    scope_start=texts['actor'].index('type AdmitReadDetail =')
    terminal=item(texts['actor'],'pub(crate) fn admit_read_terminal(')
    scope=texts['actor'][scope_start:texts['actor'].index(terminal)+len(terminal)]
    reporter='impl Reporter {\n'+item(texts['diagnostic'],'pub(crate) fn flush_failure(')+'\n}'
    close='\n'.join(item(texts['core'],key) for key in ['pub(super) fn close(&self)','pub(super) fn close_with_failure_observation','fn close_after_restriction'])
    observer='\n'.join(item(texts['observer'],key) for key in ['pub(crate) fn financial_ci_flush_actor_failure_before_edge_close()', 'fn best_effort_actor_observation('])
    hook=item(texts['final'],'pub fn financial_ci_close_for_failed_admit_read_v1(')
    final_drop=item(texts['final'],'impl Drop for SignerV3AdmitReadFinalV1 {')
    declarations='\n'.join(visibility(item(texts[key],needle)) for key,needle in [
      ('runtime','pub(in crate::native_ui::runtime) struct CoordinatedReadAdmissionV1'),
      ('runtime','pub(in crate::native_ui::runtime) struct PreparedCoordinatedAdmissionV1'),
      ('witness','pub(in crate::native_ui) struct ReadCoordinatedDeliveryWitnessV1'),
    ])
    accessor='\n'.join(visibility(item(texts['witness'],needle)) for needle in ['pub(in crate::native_ui) fn history(', 'pub(in crate::native_ui) fn action('])
    code=PREFIX+stage+macros+'\n'+reporter+ACTOR_PREFIX+scope+'\n}\n'+OBSERVER_PREFIX+observer+'\n}\n'+COMMON
    code+='impl Core {\n'+close.replace('pub(super)', 'pub(crate)')+'\n}\n'
    code+='impl SignerV3AdmitReadFinalV1 {\n'+hook+'\n'+blocks['final_finish'].replace('fn finish_read(', 'fn finish_read_new(')+'\n'+BASELINE_BLOCKS['final_finish'].replace('fn finish_read(', 'fn finish_read_old(')+'\n}\n'+final_drop+'\n'
    for name,selected in [('prior',BASELINE_BLOCKS),('candidate',blocks)]:
        code+='mod '+name+' {\nuse super::*;\n'+CARRIERS+'\n'+declarations+'\n'
        code+='impl CoordinatedVerifiedImportV1 {\n'+visibility(selected['runtime_read'])+'\n}\n'
        code+='impl CoordinatedReadAdmissionV1 {\n'+visibility(selected['prepare'])+'\n}\n'
        code+='impl CoordinatedDeliveryWitnessV1 {\n'+visibility(selected['witness_read'])+'\n}\n'
        code+='impl ReadCoordinatedDeliveryWitnessV1 {\n'+accessor+'\n'+visibility(selected['witness_finish'])+'\n}\n}\n'
    code+=TESTS
    out.mkdir(parents=True,exist_ok=True)
    target=out/'admit-read-faulttrace.rs';target.write_text(code)
    binding={'schema_version':1,'source_directory':str(source),'baseline_commit':BASELINE_COMMIT,'source_files':{p:digest((source/p).read_bytes()) for p in PATHS.values()},'baseline_files':BASELINE_FILES,'baseline_blocks_sha256':BASELINE_BLOCK_SHA256,'extracted_blocks_sha256':{k:digest(v.encode()) for k,v in blocks.items()},'generated_sha256':digest(code.encode()),'generator_sha256':digest(Path(__file__).read_bytes()),'tests_per_profile':9,'profiles':['ordinary','semantic','semantic-synthetic'],'fixed_test_names':sorted(EXPECTED_TESTS),'fallible_boundary_occurrences':35,'binding_mismatch_cases':13,'generated':True,'executed':False,'scope':'Actual owned runtime read/prepare, witness read/finish, Final finish+Drop, terminal/detail macros, lexical scope, Core close, observer best-effort/flush and Reporter bodies; inert dependency/type carriers only.','limits':['No genuine Final/Pair/source authority constructed.','Client history/TLS/IPC and source checks are inert modeled dependencies, not their real implementation.','Source IPC destructor is an inert event; actual high-level Rust field/local drop order is exercised.','ErrorClass conversion and history-diagnostic adapter use inert finite-class carriers; maintained actual scope/classifier tests are separate.','Ordinary/semantic comparison strips only diagnostic latch and exact advanced revoke/alive-false/optional append/shutdown sequence.','A panic=abort, allocation abort, process kill or actual native cleanup completion is not modeled.']}
    (out/'admit-read-binding.json').write_text(json.dumps(binding,indent=2)+'\n')
    print(json.dumps({'generated':True,'executed':False,'tests_per_profile':9,'profiles':3,'boundaries':35}))
    return target

def checked(command,path,timeout):
    # Drain merged stdout/stderr incrementally, with a hard 2 MiB evidence cap.
    limit=2*1024*1024;chunks=[];size=0;failure=None;deadline=time.monotonic()+timeout
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0: failure='timed out';break
            for key,_ in selector.select(min(remaining,1)):
                data=os.read(key.fd,65536)
                if not data: selector.unregister(key.fileobj);continue
                if size+len(data)>limit:
                    chunks.append(data[:limit-size]);failure='exceeded bounded evidence size';break
                chunks.append(data);size+=len(data)
            if failure: break
        if failure: proc.kill()
        try: status=proc.wait(timeout=max(1,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait();failure='timed out';status=-1
    finally:
        selector.close();proc.stdout.close()
    payload=b''.join(chunks);path.write_bytes(payload);text=payload.decode(errors='replace')
    if failure or status:
        print(text[-16384:],file=sys.stderr)
        raise RuntimeError(path.name+' '+(failure or 'failed with '+str(status)))
    return text

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--run',action='store_true');a=p.parse_args()
    target=generate(a.source,a.out)
    if a.run:
        results=[]
        for profile,flags in [('ordinary',[]),('semantic',['--cfg','wholepact_financial_rendered_host_semantic_ci']),('semantic-synthetic',['--cfg','wholepact_financial_rendered_host_semantic_ci','--cfg','feature="synthetic-qualification"'])]:
            binary=(a.out/('admit-read-'+profile+'-tests')).resolve()
            checked([os.environ.get('RUSTC','rustc'),'--edition=2021','--test',str(target),'-o',str(binary),*flags],a.out/(profile+'-compile.log'),60)
            listing=checked([str(binary),'--list'],a.out/(profile+'-list.log'),10)
            names={line[:-6] for line in listing.splitlines() if line.endswith(': test')}
            assert names==EXPECTED_TESTS,(profile,names)
            output=checked([str(binary),'--test-threads=1'],a.out/(profile+'-tests.log'),30)
            assert '9 passed; 0 failed; 0 ignored' in output,profile
            results.append({'profile':profile,'passed':9,'ignored':0})
        (a.out/'admit-read-execution.json').write_text(json.dumps({'executed':True,'profiles':results,'fullflow':False,'genuine_authority':False},indent=2)+'\n')
        print(json.dumps({'executed':True,'profiles':results}))
if __name__=='__main__':main()
