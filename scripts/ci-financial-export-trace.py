"""Source-bound diagnostic-only macro/classifier tests; no actors/authorities."""
from pathlib import Path
import argparse,hashlib,json,re
p=argparse.ArgumentParser();p.add_argument('--source',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
paths=['crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2/closed_review_v3/coordinated_export_v1.rs','crates/wholepact-native-host/src/financial_ci_host_failure.rs','crates/wholepact-financial-coordinator-origin/src/financial_ci_host_diagnostics.rs']
call,mapper,codes=[(a.source/x).read_text() for x in paths]
def item(s,n):
 p=s.index(n);start=s.index('{',p);d=1;i=start+1
 while d:
  if s[i]=='{':d+=1
  elif s[i]=='}':d-=1
  i+=1
 return s[p:i]
def normalize_observers(text):
 start=text.find('// Observe only an already-returned error.')
 if start>=0:
  end=text.index('#[derive(Serialize)]',start);text=text[:start]+text[end:]
 for ordinary,observed in [('self.verified.request_admission_retained_v1()','self.verified.request_admission_retained_observed_v1()'),('self.pending.read_original_status_retained_v1()','self.pending.read_original_status_retained_observed_v1()')]:
  wrapper='admission_observed!('+ordinary+','+observed+')'
  assert text.count(wrapper)==1
  text=text.replace(wrapper,ordinary)
 while 'export_observed!(' in text:
  p=text.index('export_observed!(');start=p+len('export_observed!(');i=start;depth=0;quote=False;escape=False;commas=[]
  while i<len(text):
   c=text[i]
   if quote:
    if escape:escape=False
    elif c=='\\':escape=True
    elif c=='"':quote=False
   elif c=='"':quote=True
   elif c in '([{':depth+=1
   elif c in ')]}':
    if c==')' and depth==0:break
    depth-=1
   elif c==',' and depth==0:commas.append(i)
   i+=1
  assert len(commas)==2
  assert text[start:commas[0]].strip() in ['native','engine','bridge']
  assert (re.fullmatch(r'Export[A-Za-z]+',text[commas[0]+1:commas[1]].strip())
          or text[commas[0]+1:commas[1]].strip() in ['AdmissionRequest','AdmissionHistory'])
  text=text[:p]+text[commas[1]+1:i]+text[i+1:]
 # Strip only the exact reviewed terminal-audit observation block. This fixed
 # hash guards all finite status arms and preserves the original Receipt text.
 marker='    let audit = status.verified_audit().map_err(|error| {'
 if marker in text:
  start=text.index(marker);end=text.index('    validate_coordinated_original_audit_v1(scope, audit)',start)
  assert hashlib.sha256(text[start:end].encode()).hexdigest()=='42caf20d3713814ce88b57e487b832eaa5360d3782b246e44175395e5757d036'
  text=text[:start]+'''    let audit = status.verified_audit().map_err(|_| Error::Receipt(
        "The original V3 operation remains pending or unknown: complete authenticated Witness history has not established admission. Preserve the original operation; do not resend it".into(),
    ))?;
'''+text[end:]
 for expression in ['serde_json::to_string(&inspection)','serde_json::to_string(&export_scope)']:
  text=text.replace(expression+'.map_err(Error::from)',expression)
 return text
# Whitespace outside literals is semantically irrelevant; the literal content
# is retained exactly in this narrow token stream (including approval text).
def tokens(text):
 return re.findall(r'"(?:\\.|[^"\\])*"|\S',text)

# Baseline exact original tokens from c5b8bb38c51af58a14f0cb20845231ae9fbf4e3c.
assert hashlib.sha256('\n'.join(tokens(normalize_observers(call))).encode()).hexdigest()=='09b0bc081c9601b3066475c943ad8fe3a6cfa9f00460072b9f4365e9def21d9e'
print('exact original postRecipient tokens/approval literals preserved')
macro=item(call,'macro_rules! export_observed')
functions='\n'.join(item(mapper,k) for k in ['pub(crate) fn native(', 'fn class(', 'pub(crate) fn engine(', 'pub(crate) fn bridge('])
stages=['ExportRecipientBinding','ExportMetadataSource','ExportMetadataMaterials','ExportMetadataApproval','ExportRecipientBind','ExportFinalApproval','ExportConsent','ExportCommit','ExportVerifiedWait']
# Structural coverage validates every label is an actual callsite and the old
# preparation observer remains restored before any new wrapper.
start=call.index('drop(_observation_scope);');assert all(re.search(r'export_observed!\([^,]+,'+stage+r'\b',call[start:]) for stage in stages)
assert call.count('let result=$operation;')==1
assert not re.search(r'let\s+_observation_scope',call[start:])
class_names=re.search(r'codes!\(Class \{([^}]+)\}\)',codes).group(1)
stage_names=re.search(r'codes!\(Stage \{([^}]+)\}\)',codes).group(1)
s='''#![allow(dead_code,unused_imports)]
// Exact diagnostic macro and classifiers, inert error carriers. No product
// authority, approval/currentness check, engine operation or IPC is simulated.
use std::cell::{Cell,RefCell};
#[derive(Debug,PartialEq,Eq)]pub enum Error{Platform,Terminal,Permission,Locked,Invalid,Authentication,Storage,Quarantined,Unsupported,Receipt(String),RecoverySemantic(String),RecoveryBackupUnsupported,RecoveryFinancialUnsupported,CompleteOriginRecoveryUnavailable,HistoricalExportIncomplete,GenerationArchiveIncomplete}
mod wholepact_engine{pub struct ApiError{pub code:String}}
mod wholepact_signer{pub mod authority_bridge{pub enum BridgeError{Binding,Conflict,Missing,Uncertain,Limit,Permission,RecoveryRequired,CompleteOriginRecoveryUnavailable,Verification,SignerOriginUnavailable,Journal(String),Authority(String),Wallet(String),Ipc}}}
mod financial_ci_host_failure{
 use super::*;
 #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum Stage{'''+stage_names+'''}
 #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum Class{'''+class_names+'''}
 thread_local!{static FIRST:RefCell<Option<(Stage,Class)>>=const{RefCell::new(None)};}
 fn latch_failure(stage:Stage,class:Class){FIRST.with(|f|{let mut f=f.borrow_mut();if f.is_none(){*f=Some((stage,class));}})}
 pub fn reset(){FIRST.with(|f|*f.borrow_mut()=None)}
 pub fn sample()->Option<(Stage,Class)>{FIRST.with(|f|*f.borrow())}
'''+functions+'''
}
'''+macro+'''
use financial_ci_host_failure::{Stage,Class};
#[test]fn all_nine_native_error_sites_keep_value_identity_and_single_execution(){
'''
for stage in stages:
 s+=''' financial_ci_host_failure::reset();let n=Cell::new(0);let payload=String::from("synthetic payload never observed");let address=payload.as_ptr();let result:Result<(),Error>=export_observed!(native,'''+stage+''',{n.set(n.get()+1);Err(Error::Receipt(payload))});assert_eq!(n.get(),1);match result{Err(Error::Receipt(v))=>assert_eq!(v.as_ptr(),address),_=>panic!("original result changed")};assert_eq!(financial_ci_host_failure::sample(),Some((Stage::'''+stage+''',Class::Receipt)));
'''
s+='''}
#[test]fn success_has_no_observation_and_one_execution(){financial_ci_host_failure::reset();let n=Cell::new(0);let r:Result<u8,Error>=export_observed!(native,ExportMetadataApproval,{n.set(n.get()+1);Ok(7)});assert_eq!(r,Ok(7));assert_eq!(n.get(),1);assert_eq!(financial_ci_host_failure::sample(),None);}
#[test]fn specific_first_failure_survives_outer_wrapper(){financial_ci_host_failure::reset();let r:Result<(),Error>=export_observed!(native,ExportFinalApproval,export_observed!(native,ExportMetadataSource,Err(Error::Permission)));assert_eq!(r,Err(Error::Permission));assert_eq!(financial_ci_host_failure::sample(),Some((Stage::ExportMetadataSource,Class::Permission)));}
#[test]fn engine_codes_are_borrowed_and_unknown_payload_is_not_a_label(){for(code,class)in[("DISCLOSURE_UNKNOWN",Class::EngineDisclosureUnknown),("DISCLOSURE_DENIED",Class::EngineDisclosureDenied),("RECOVERY_REQUIRED",Class::EngineRecoveryRequired),("DURABLE_PROPOSAL_RECOVERY_REQUIRED",Class::EngineRecoveryRequired),("IDEMPOTENCY_CONFLICT",Class::EngineIdempotencyConflict),("REVISION_CONFLICT",Class::EngineRevisionConflict),("DURABLE_PROPOSAL_CONFLICT",Class::EngineDurableProposalConflict),("DURABLE_CONSTRUCTION_UNAVAILABLE",Class::EngineDurableConstructionUnavailable),("DURABLE_PROFILE_UNAVAILABLE",Class::EngineDurableProfileUnavailable),("RESOURCE_EXHAUSTED",Class::EngineResourceExhausted),("synthetic unknown private string",Class::EngineUnclassified)]{financial_ci_host_failure::reset();let error=wholepact_engine::ApiError{code:code.into()};let ptr=error.code.as_ptr();let result:Result<(),_>=export_observed!(engine,ExportRecipientBind,Err(error));assert_eq!(result.err().unwrap().code.as_ptr(),ptr);assert_eq!(financial_ci_host_failure::sample(),Some((Stage::ExportRecipientBind,class)));}}
#[test]fn bridge_wait_error_identity_and_category_precede_old_conversion(){financial_ci_host_failure::reset();let error=wholepact_signer::authority_bridge::BridgeError::Journal(String::from("synthetic opaque journal payload"));let result:Result<(),_>=export_observed!(bridge,ExportVerifiedWait,Err(error));assert!(matches!(result,Err(wholepact_signer::authority_bridge::BridgeError::Journal(_))));assert_eq!(financial_ci_host_failure::sample(),Some((Stage::ExportVerifiedWait,Class::BridgeJournal)));}
'''
(a.out/'host-export-trace.rs').write_text(s)
(a.out/'host-export-source-binding.json').write_text(json.dumps({x:hashlib.sha256((a.source/x).read_bytes()).hexdigest() for x in paths},indent=2)+'\n')
print('generated exact macro/classifier five-test harness; NOT executed')
