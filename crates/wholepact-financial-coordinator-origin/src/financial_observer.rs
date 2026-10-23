//! Observation-only, compiled exclusively into the pinned full-financial CI image.
//! No input, origin construction, approval or authority state mutation.
use crate::{process::Role,rejected,Result};
use serde_json::{json,Value};
use std::{fs::{File,OpenOptions},io::Write,os::{fd::{AsRawFd,FromRawFd},unix::fs::{OpenOptionsExt,MetadataExt}},sync::{Mutex,atomic::{AtomicU64,Ordering}}};
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
const OBSERVED_PROFILE:&str="coordinated-financial-rendered-host-semantic-v1";
#[cfg(all(wholepact_financial_external_ci, not(wholepact_financial_rendered_host_semantic_ci)))]
const OBSERVED_PROFILE:&str="coordinated-financial-external-pre-v3-witness-v1";
#[cfg(not(any(wholepact_financial_external_ci, wholepact_financial_rendered_host_semantic_ci)))]
const OBSERVED_PROFILE:&str="coordinated-financial-full-native-v1";
const DIRECTORY:&str="/ci-financial-evidence";
static EPOCH:AtomicU64=AtomicU64::new(0);
struct Writer{pid:i32,role:Role,sequence:u64,bytes:u64,inode:u64,device:u64,directory_inode:u64,directory_device:u64,last:u64,
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] semantic:SemanticState,
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] boundary:crate::financial_ci_failure_boundary::Reporter,
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] host_diagnostic:crate::financial_ci_host_diagnostics::Reporter,
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] actor_diagnostic:crate::financial_ci_actor_diagnostics::Reporter}
static WRITER:Mutex<Option<Writer>>=Mutex::new(None);
fn now()->Result<u64>{let mut t:libc::timespec=unsafe{std::mem::zeroed()};if unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut t)}!=0{return Err(std::io::Error::last_os_error());}u64::try_from(t.tv_sec).ok().and_then(|s|s.checked_mul(1_000_000_000)).and_then(|n|n.checked_add(t.tv_nsec as u64)).ok_or_else(||rejected("financial observer clock"))}
fn name(role:Role)->String{format!("{role:?}")}
fn directory()->Result<File>{let f=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(DIRECTORY)?;let m=f.metadata()?;if !m.is_dir()||m.uid()!=unsafe{libc::geteuid()}||m.mode()&0o777!=0o700{return Err(rejected("financial observer private directory"));}Ok(f)}
pub(crate) fn initialize()->Result<()>{if EPOCH.compare_exchange(0,now()?,Ordering::SeqCst,Ordering::SeqCst).is_err(){return Err(rejected("financial observer initialized twice"));}enter(Role::Coordinator)}
pub(crate) fn enter(role:Role)->Result<()>{
 let mut slot=WRITER.lock().map_err(|_|rejected("financial observer lock"))?;let pid=unsafe{libc::getpid()};
 if slot.as_ref().is_some_and(|w|w.pid==pid){return Err(rejected("financial observer repeated actor"));}
 let dir=directory()?;let path=std::ffi::CString::new(format!("{pid}.jsonl")).unwrap();let fd=unsafe{libc::openat(dir.as_raw_fd(),path.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_APPEND|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK,0o600)};if fd<0{return Err(std::io::Error::last_os_error());}let f=unsafe{File::from_raw_fd(fd)};let m=f.metadata()?;
 *slot=Some(Writer{pid,role,sequence:0,bytes:0,inode:m.ino(),device:m.dev(),directory_inode:dir.metadata()?.ino(),directory_device:dir.metadata()?.dev(),last:0,
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] semantic:SemanticState::default(),
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] boundary:crate::financial_ci_failure_boundary::Reporter::default(),
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] host_diagnostic:crate::financial_ci_host_diagnostics::Reporter::default(),
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] actor_diagnostic:crate::financial_ci_actor_diagnostics::Reporter::default()});drop(f);drop(slot);
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] crate::financial_ci_failure_boundary::enter(role==Role::Coordinator);
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] crate::financial_ci_host_diagnostics::enter(role);
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] crate::financial_ci_actor_diagnostics::enter(role);
 let parent=match role{Role::Coordinator=>None,Role::Signer1|Role::Signer2=>Some("Host"),_=>Some("Coordinator")};
 emit("Birth",json!({"pid":pid,"parent_pid":unsafe{libc::getppid()},"parent_role":parent}))
}
fn emit(kind:&str,facts:Value)->Result<()>{
 let mut slot=WRITER.lock().map_err(|_|rejected("financial observer lock"))?;let w=slot.as_mut().ok_or_else(||rejected("financial observer actor absent"))?;
 emit_locked(w,kind,&facts)
}
#[derive(serde::Serialize)]
struct Record<'a,T:serde::Serialize>{schema:u64,profile:&'static str,role:String,sequence:u64,elapsed_ns:u64,kind:&'a str,facts:&'a T}
fn emit_locked<T:serde::Serialize>(w:&mut Writer,kind:&str,facts:&T)->Result<()>{
 if w.pid!=unsafe{libc::getpid()}||w.sequence>=32768{return Err(rejected("financial observer actor or record limit"));}
 let elapsed=now()?.checked_sub(EPOCH.load(Ordering::SeqCst)).ok_or_else(||rejected("financial observer epoch"))?;
 if elapsed<w.last||elapsed>1_800_000_000_000{return Err(rejected("financial observer original deadline"));}
 let record=Record{schema:1,profile:OBSERVED_PROFILE,role:name(w.role),sequence:w.sequence+1,elapsed_ns:elapsed,kind,facts};
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 let mut bytes={
  let mut bytes=RecordBuffer(zeroize::Zeroizing::new(Vec::with_capacity(32768)));
  serde_json::to_writer(&mut bytes,&record).map_err(|_|rejected("financial observer encoding"))?;
  bytes.0
 };
 #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
 let mut bytes=serde_json::to_vec(&record).map_err(|_|rejected("financial observer encoding"))?;
 bytes.push(b'\n');
 if !record_fits(w.sequence,w.bytes,bytes.len()){return Err(rejected("financial observer size"));}
 let dir=directory()?;let dm=dir.metadata()?;if dm.ino()!=w.directory_inode||dm.dev()!=w.directory_device{return Err(rejected("financial observer directory changed"));}let path=std::ffi::CString::new(format!("{}.jsonl",w.pid)).unwrap();let fd=unsafe{libc::openat(dir.as_raw_fd(),path.as_ptr(),libc::O_WRONLY|libc::O_APPEND|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)};if fd<0{return Err(std::io::Error::last_os_error());}let mut f=unsafe{File::from_raw_fd(fd)};let m=f.metadata()?;
 if !m.is_file()||m.uid()!=unsafe{libc::geteuid()}||m.mode()&0o777!=0o600||m.nlink()!=1||m.ino()!=w.inode||m.dev()!=w.device||m.len()!=w.bytes{return Err(rejected("financial observer file changed"));}
 f.write_all(&bytes)?;w.sequence+=1;w.bytes+=bytes.len()as u64;w.last=elapsed;Ok(())
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
struct RecordBuffer(zeroize::Zeroizing<Vec<u8>>);
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
impl Write for RecordBuffer {
 fn write(&mut self,bytes:&[u8])->Result<usize>{
  // Reserve the final LF inside the unchanged 32768-byte record ceiling.
  // Refuse before growth, so no reallocation leaves an unwiped old text copy.
  if self.0.len().checked_add(bytes.len()).is_none_or(|n|n>32767){return Err(rejected("financial observer size"));}
  self.0.extend_from_slice(bytes);Ok(bytes.len())
 }
 fn flush(&mut self)->Result<()>{Ok(())}
}

fn record_fits(sequence:u64,written:u64,length:usize)->bool {
 sequence<32768 && length<=32768 && written.checked_add(length as u64).is_some_and(|n|n<=32*1024*1024)
}

fn role()->Result<Role>{WRITER.lock().map_err(|_|rejected("financial observer lock"))?.as_ref().filter(|w|w.pid==unsafe{libc::getpid()}).map(|w|w.role).ok_or_else(||rejected("financial observer actor absent"))}
pub(crate) fn root_event(kind:&'static str)->Result<()>{if role()?!=Role::Coordinator||!matches!(kind,"NormalFinishAdmitted"|"NormalFinished"|"PtyHeld"|"PtyReleased"){return Err(rejected("financial observer root event"));}emit(kind,json!({}))}
pub(crate) fn purpose(kind:&'static str)->Result<()>{if matches!(role()?,Role::Coordinator|Role::Host|Role::Signer1|Role::Signer2)||!matches!(kind,"PurposeServing"|"PurposeDisposed"|"PurposeClosed"){return Err(rejected("financial observer purpose event"));}emit(kind,json!({}))}
pub(crate) fn reaped(child:Role,pid:i32,status:i32)->Result<()>{let actual=role()?;let parent=if matches!(child,Role::Signer1|Role::Signer2){Role::Host}else{Role::Coordinator};if actual!=parent||child==Role::Coordinator||!libc::WIFEXITED(status){return Err(rejected("financial observer normal reap absent"));}emit("OwnedReap",json!({"child":name(child),"pid":pid,"exit_code":libc::WEXITSTATUS(status)}))}
#[derive(Clone,Copy,Debug)]
pub enum FinancialCiHostMilestoneV1 {Owner1AdmissionVerified,Owner1SigningRetired,Owner2AdmissionVerified,Owner2SigningRetired,CompletedPairRetained,BothReturnsIntaken,TransactionSavedVerified,NoDispatchSelected}
pub fn financial_ci_host_milestone(step:FinancialCiHostMilestoneV1)->Result<()>{if role()?!=Role::Host{return Err(rejected("financial observer Host role"));}emit("HostMilestone",json!({"step":format!("{step:?}")}))}
const PHASES:&[&str]=&["ActivateArmed", "ActivateReadReview", "ActivateReading", "ActivateReady", "ActivateReview", "Activated", "Activating", "AdmissionReview", "CompletedPairFlow", "Configuring", "ContinueArmed", "ContinueConfirm", "ContinuePreparing", "ContinueReview", "Continuing", "EntryConfirm", "EntryReview", "FinancialSetupConfiguring", "FinancialSetupSelected", "Finished", "HistoryPreparing", "HistoryReady", "HistoryRetiring", "HistoryReview", "HistorySetupNeeded", "HistorySetupPreparing", "HistorySetupReview", "HistoryStarting", "NormalClosing", "NormalFinishReview", "Opening", "Password", "Preparing", "ReadConfirm", "ReadReview", "Reading", "RetirementBlocked", "ReturnCompleted", "ReturnExactReview", "ReturnPrepared", "ReturnReadReview", "ReturnReading", "ReturningExact", "Revoked", "Selecting", "SetupNeeded", "SetupPreparing", "SetupReview", "SignCommitted", "SignExactReview", "SignPrepared", "SignReadReview", "SignReading", "SignedRetired", "SigningExact", "SigningRetiring", "V3AdmissionRetained", "V3AdmitArmed", "V3AdmitReadRetained", "V3AdmitReadReview", "V3AdmitReading", "V3AdmitReady", "V3AdmitReview", "V3Admitting", "V3AuditReview", "V3Audited", "V3Auditing", "V3Configuring", "V3Confirm", "V3Enrolled", "V3Enrolling", "V3EnrollmentReview", "V3Held", "V3ManifestAccepted", "V3ManifestReview", "V3Manifesting", "V3Opening", "V3OwnerConfiguring", "V3OwnerSelected", "V3PairReview", "V3Paired", "V3Pairing", "V3Password", "V3PrepareReadReview", "V3PrepareReading", "V3Prepared", "V3Preparing", "V3ReceiveReview", "V3Received", "V3Receiving", "V3RediscloseReview", "V3Redisclosed", "V3Redisclosing", "V3RedisclosurePrepared", "V3RedisclosureReadReview", "V3RedisclosureReading", "V3Review", "Waiting", "WalletObserveReview", "WalletObserved", "WalletObserving", "WalletPrepareReview", "WalletPrepared", "WalletPreparing", "WriterFlow"];
const SUBPHASES:&[&str]=&["AcquireArmed", "AcquireReview", "Acquired", "Acquiring", "Closed", "Configuring", "Disposed", "Failed", "Finished", "Idle", "None", "Preparing", "PreparingService", "ReadReview", "Reading", "Retiring", "Review", "ServeReview", "ServicePreparing", "ServiceReview", "ServiceStarting", "Serving", "SetupNeeded", "SetupPreparing", "SetupReview", "StartingService"];
const WIDGETS:&[&str]=&["ActivateArm", "ActivateFinal", "ActivateRead", "AdmitFinal", "ArmContinue", "ArmSigner", "ArmV3Admit", "ArmWitness", "Begin", "BeginContinue", "BeginHostLine", "BeginV3", "Close", "CompletedPairAction", "Configure", "ConfigureFinancialSetup", "ConfigureV3", "ConfigureV3Owner", "ConfirmV3", "ContinueConfirm", "ContinueSelectorPath", "EnterPassword", "EntryConfirm", "Field:AccountId", "Field:ContinueSelectorPath", "Field:Endpoint", "Field:FinancialSelection", "Field:HostCommands", "Field:HostProfile", "Field:HostWorkspace", "Field:InitialReadSelection", "Field:MaterialRoot", "Field:NetworkProfile", "Field:OwnerCertificate", "Field:OwnerCertificateDerHex", "Field:OwnerConfiguration", "Field:PinnedServerCertificate", "Field:ResultSelectorPath", "Field:SelectedJournal", "Field:ServerCertificate", "Field:ServerName", "Field:ServerPrivateKey", "Field:SourceIdentity", "Field:SourceRoot", "Field:StorageKey", "Field:TrustedClientRoot", "Field:TrustedServerRoot", "Field:V3Selection", "Field:WalletConfiguration", "Field:WitnessId", "Field:WriterCertificate", "Field:WriterConfiguration", "Field:WriterPrivateKey", "FinalV3Admit", "FinalV3AdmitRead", "FinalV3Audit", "FinalV3Enrollment", "FinalV3Manifest", "FinalV3Pair", "FinalV3PrepareRead", "FinalV3Receive", "FinalV3Redisclose", "FinalV3RedisclosureRead", "HostEditor", "HostOutput", "HostSubmit", "NormalFinish", "ParkFinancial", "PasswordSubmit", "PasswordV3", "PrepareCompletedPair", "PrepareHistory", "PrepareSetup", "Read", "ReadConfirm", "ResultSelectorPath", "ResumeFinancial", "RetireSigning", "ReturnExact", "ReturnRead", "ReviewAcknowledgement", "ReviewBody", "ReviewV3Admit", "ReviewV3AdmitRead", "ReviewV3Audit", "ReviewV3Enrollment", "ReviewV3Manifest", "ReviewV3Pair", "ReviewV3PrepareRead", "ReviewV3Receive", "ReviewV3Redisclose", "ReviewV3RedisclosureRead", "SaveContinuationSelector", "SaveResultSelector", "ScrollRegion", "SelectFinancialSetup", "SelectNextV3", "SelectV3Owner", "ServeHistory", "Setup", "SetupHistory", "ShowContinuationSelector", "SignExact", "SignRead", "SignerReviewAcknowledgement", "SignerReviewBody", "SourcePassword", "WalletObserve", "WalletPrepare", "WitnessReviewAcknowledgement", "WitnessReviewBody", "WriterAction"];
const SIGNER_STEPS:&[&str]=&["AdmissionAudited", "AdmissionCommitted", "ContinuationAdmitted", "ContinuationSaved", "DeliveryPrepared", "DeliveryReceived", "Enrolled", "EntryOpened", "FinancialEntryOpened", "HistoryRetained", "ManifestAccepted", "Paired", "Redisclosed", "ReturnFinished", "ReturnPrepared", "SignCommitted", "SigningRetired", "WalletObserved", "WalletPrepared", "WriterAcquired", "WriterActivated"];
pub(crate) fn signer(owner:crate::SignerContinueRoleV1,step:&'static str)->Result<()>{let actual=role()?;let label=match owner{crate::SignerContinueRoleV1::Signer1=>"Signer1",crate::SignerContinueRoleV1::Signer2=>"Signer2"};if !SIGNER_STEPS.contains(&step)||(actual!=Role::Coordinator&&name(actual)!=label){return Err(rejected("financial observer signer role"));}emit("SignerMilestone",json!({"owner":label,"step":step}))}
fn exact(v:&Value,keys:&[&str])->bool{v.as_object().is_some_and(|m|m.len()==keys.len()&&keys.iter().all(|k|m.contains_key(*k)))}
fn owner(v:&Value)->bool{v.is_null()||matches!(v.as_str(),Some("Signer1"|"Signer2"))}
fn host_observation(f: &Value) -> Result<()> {
 let h=&f["host_observation"];
 let bounded=|v:&Value,lo:u64,hi:u64|v.as_u64().is_some_and(|n|n>=lo&&n<=hi);
 if !exact(h,&["revision","nonws_end","context_valid","entry","editor","view"])
  || !bounded(&h["revision"],0,262144) || !bounded(&h["nonws_end"],0,1048576)
  || !h["context_valid"].is_boolean()
  || !matches!(h["entry"].as_str(),Some("Idle"|"Editing"|"Writing"|"Closed")) {return Err(rejected("financial Host context"));}
 let e=&h["editor"];
 if h["entry"]=="Editing" {
  if !exact(e,&["ordinal","revision"]) || !bounded(&e["ordinal"],1,128)
   || !bounded(&e["revision"],0,262144) || e["revision"]!=h["revision"] || f["host_input"]!=true {return Err(rejected("financial Host editor"));}
 } else if !e.is_null() {return Err(rejected("financial Host editor"));}
 if h["entry"]=="Writing" && f["host_input"]!=true {return Err(rejected("financial Host protection"));}
 let v=&h["view"];
 if !v.is_null() {
  if !exact(v,&["rect","nonws","rows"]) || h["context_valid"]!=true || h["entry"]!="Idle"
   || f["host_input"]!=false || f["secret_input"]!=false
   || !bounded(&v["nonws"],1,8192) || v["nonws"].as_u64()>h["nonws_end"].as_u64()
   || !bounded(&v["rows"],1,32) {return Err(rejected("financial Host view"));}
  let widgets=f["widgets"].as_array().ok_or_else(||rejected("financial Host widgets"))?;
  let output=widgets.iter().find(|w|w["tag"]=="HostOutput"&&w["owner"].is_null()).ok_or_else(||rejected("financial Host widget"))?;
  if output["enabled"]!=true {return Err(rejected("financial Host disabled"));}
  let r=v["rect"].as_array().filter(|r|r.len()==4).ok_or_else(||rejected("financial Host rectangle"))?;
  let a:Vec<f64>=r.iter().map(|n|n.as_f64().filter(|n|n.is_finite()).ok_or_else(||rejected("financial Host coordinate"))).collect::<Result<_>>()?;
  let b=output["rect"].as_array().ok_or_else(||rejected("financial Host clip"))?;
  let b:Vec<f64>=b.iter().map(|n|n.as_f64().ok_or_else(||rejected("financial Host clip"))).collect::<Result<_>>()?;
  if b.len()!=4 || !(b[0]<=a[0]&&a[0]<a[2]&&a[2]<=b[2]&&b[1]<=a[1]&&a[1]<a[3]&&a[3]<=b[3]) {return Err(rejected("financial Host clipped"));}
 }
 Ok(())
}
/// Closed geometry/state only. No review text, paths, passwords or Host output.
fn validate_core_snapshot(facts:&Value)->Result<()>{
 if !exact(&facts,&["phase","subphase","owner","view_generation","focused","secret_input","host_input","pixels_per_point","viewport","widgets","host_observation"]){return Err(rejected("financial snapshot shape"));}
 let f=&facts;let scale=f["pixels_per_point"].as_f64().filter(|s|s.is_finite()&&*s>=0.5&&*s<=4.0).ok_or_else(||rejected("financial snapshot scale"))?;
 if !f["phase"].as_str().is_some_and(|s|PHASES.contains(&s))||!f["subphase"].as_str().is_some_and(|s|SUBPHASES.contains(&s))||!owner(&f["owner"])||!f["view_generation"].as_u64().is_some_and(|g|g>0)||["focused","secret_input","host_input"].iter().any(|k|!f[*k].is_boolean())||f["viewport"]!=json!([1280,800]){return Err(rejected("financial snapshot state"));}
 let widgets=f["widgets"].as_array().filter(|w|w.len()<=128).ok_or_else(||rejected("financial snapshot widgets"))?;let mut seen=std::collections::HashSet::new();
 for w in widgets{if !exact(w,&["tag","owner","rect","enabled"])||!w["tag"].as_str().is_some_and(|s|WIDGETS.contains(&s))||!owner(&w["owner"])||!w["enabled"].is_boolean()||!seen.insert((w["tag"].to_string(),w["owner"].to_string())){return Err(rejected("financial snapshot widget"));}let r=w["rect"].as_array().filter(|r|r.len()==4).ok_or_else(||rejected("financial snapshot rect"))?;let a:Vec<f64>=r.iter().map(|v|v.as_f64().filter(|n|n.is_finite()).ok_or_else(||rejected("financial snapshot coordinate"))).collect::<Result<_>>()?;if !(0.0<=a[0]&&a[0]<a[2]&&a[2]<=1280.0/scale&&0.0<=a[1]&&a[1]<a[3]&&a[3]<=800.0/scale){return Err(rejected("financial snapshot bounds"));}}
 host_observation(f)?;
 Ok(())
}
#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
fn validate_snapshot(facts:&Value)->Result<()>{validate_core_snapshot(facts)}
#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
pub fn financial_ci_snapshot(facts:Value)->Result<()>{if role()?!=Role::Coordinator{return Err(rejected("financial snapshot actor"));}validate_snapshot(&facts)?;emit("UiSnapshot",facts)}

// This entire channel is absent from production and the old pixel-only profiles.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
#[derive(Default)]
struct SemanticState { last_id:u64, active:Option<ActiveHostView> }
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
struct ActiveHostView { id:u64, generation:u64, revision:u64, nonws_end:u64, view:Value, text:zeroize::Zeroizing<String> }
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
#[derive(serde::Serialize)]
struct RenderedFacts<'a> { id:u64, view_generation:u64, revision:u64, nonws_end:u64, view:&'a Value, text:&'a str }
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
impl ActiveHostView {
 fn facts(&self)->RenderedFacts<'_>{RenderedFacts{id:self.id,view_generation:self.generation,revision:self.revision,nonws_end:self.nonws_end,view:&self.view,text:&self.text}}
 fn matches(&self,f:&Value,text:&str)->bool {self.revision==f["host_observation"]["revision"].as_u64().unwrap_or(u64::MAX)
  && self.nonws_end==f["host_observation"]["nonws_end"].as_u64().unwrap_or(u64::MAX)
  && self.view==f["host_observation"]["view"] && self.text.as_str()==text}
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn validate_snapshot(f:&Value)->Result<()> {
 let mut core=f.clone();
 let reference=core.as_object_mut().and_then(|m|m.remove("host_view_id")).ok_or_else(||rejected("financial semantic snapshot shape"))?;
 validate_core_snapshot(&core)?;
 let h=&f["host_observation"];
 if h["view"].is_null() {if !reference.is_null(){return Err(rejected("financial semantic hidden reference"));}}
 else if !reference.as_u64().is_some_and(|id|(1..=512).contains(&id)) || f["focused"]!=true {return Err(rejected("financial semantic reference"));}
 Ok(())
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
impl SemanticState {
 /// No caller-supplied IDs. A protected/hidden interval destroys the active
 /// zeroizing text without resetting the lifetime monotone ID budget.
 fn clear(&mut self){self.active=None;}
 fn bind(&mut self,f:&mut Value,text:Option<zeroize::Zeroizing<String>>)->Result<bool>{
  if f.get("host_view_id")!=Some(&Value::Null){self.clear();return Err(rejected("financial semantic imported reference"));}
  let Some(text)=text else {
   self.clear();validate_snapshot(f)?;return Ok(false);
  };
  let h=f["host_observation"].clone();
  if text.is_empty() || text.len()>8192 || !text.bytes().all(|b|b==b'\n'||(b' '..=b'~').contains(&b))
   || Some(text.bytes().filter(|b|!b.is_ascii_whitespace()).count() as u64)!=h["view"]["nonws"].as_u64()
   || text.bytes().filter(|b|*b==b'\n').count() as u64>=h["view"]["rows"].as_u64().unwrap_or(0) {
   self.clear();return Err(rejected("financial semantic text shape"));
  }
  let changed=!self.active.as_ref().is_some_and(|a|a.matches(f,&text));
  let id=if changed {match self.last_id.checked_add(1).filter(|id|*id<=512){Some(id)=>id,None=>{self.clear();return Err(rejected("financial semantic view limit"));}}}
   else {self.active.as_ref().unwrap().id};
  f["host_view_id"]=json!(id);
  if let Err(error)=validate_snapshot(f){self.clear();return Err(error);}
  if changed {
   self.last_id=id;
   self.active=Some(ActiveHostView{id,generation:f["view_generation"].as_u64().unwrap(),revision:h["revision"].as_u64().unwrap(),
    nonws_end:h["nonws_end"].as_u64().unwrap(),view:h["view"].clone(),text});
  } else if self.active.as_ref().unwrap().generation>f["view_generation"].as_u64().unwrap(){self.clear();return Err(rejected("financial semantic generation"));}
  Ok(changed)
 }
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
pub fn financial_ci_clear_host_view()->Result<()> {
 let mut slot=WRITER.lock().map_err(|_|rejected("financial observer lock"))?;
 let w=slot.as_mut().filter(|w|w.pid==unsafe{libc::getpid()}&&w.role==Role::Coordinator).ok_or_else(||rejected("financial semantic actor"))?;
 w.semantic.clear();Ok(())
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
pub fn financial_ci_snapshot(mut facts:Value,text:Option<zeroize::Zeroizing<String>>)->Result<()> {
 let mut slot=WRITER.lock().map_err(|_|rejected("financial observer lock"))?;
 let w=slot.as_mut().filter(|w|w.pid==unsafe{libc::getpid()}&&w.role==Role::Coordinator).ok_or_else(||rejected("financial snapshot actor"))?;
 flush_failure_boundaries_locked(w);
 flush_host_diagnostics_locked(w);
 let changed=w.semantic.bind(&mut facts,text)?;
 // Move, not clone, the only retained text buffer while writing both adjacent
 // records under one lock. A partial filesystem read still needs consumer join.
 let active=w.semantic.active.take();
 w.semantic.active=emit_semantic_pair(active,&facts,changed,|record|match record {
  SemanticRecord::Rendered(facts)=>emit_locked(w,"HostRenderedView",&facts),
  SemanticRecord::Snapshot(facts)=>emit_locked(w,"UiSnapshot",facts),
 })?;
 Ok(())
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
enum SemanticRecord<'a>{Rendered(RenderedFacts<'a>),Snapshot(&'a Value)}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn emit_semantic_pair(active:Option<ActiveHostView>,facts:&Value,changed:bool,
 mut emit:impl FnMut(SemanticRecord<'_>)->Result<()>)->Result<Option<ActiveHostView>> {
 if changed {emit(SemanticRecord::Rendered(active.as_ref().ok_or_else(||rejected("financial semantic active view"))?.facts()))?;}
 emit(SemanticRecord::Snapshot(facts))?;
 Ok(active)
}

pub(crate) fn source_packet(packet:&crate::financial_workflow_channel::Packet)->Result<()>{
 use crate::financial_workflow_channel::Packet as P;
 let observation=match packet{
 P::V3SourceOpened{start,..}=>Some((start.role,"EntryOpened")),
 P::V3Paired{role,..}=>Some((*role,"Paired")),P::V3Enrolled{role,..}=>Some((*role,"Enrolled")),
 P::V3ManifestAccepted{role,..}=>Some((*role,"ManifestAccepted")),P::V3Redisclosed{role,..}=>Some((*role,"Redisclosed")),
 P::V3Prepared{role,..}=>Some((*role,"DeliveryPrepared")),P::V3Received{role,..}=>Some((*role,"DeliveryReceived")),
 P::V3Admitted{role,..}=>Some((*role,"AdmissionCommitted")),P::V3Audited{role,..}=>Some((*role,"AdmissionAudited")),
 P::SourceRetained{start,..}=>Some((start.role,"FinancialEntryOpened")),P::HistoryRetained{start,..}=>Some((start.role,"HistoryRetained")),
 P::ContinuationSaved{context,..}=>Some((context.start.role,"ContinuationSaved")),
 P::Admitted{actor,..}=>Some((actor.signer_role,"ContinuationAdmitted")),P::Acquired{actor,..}=>Some((actor.signer_role,"WriterAcquired")),P::Activated{actor,..}=>Some((actor.signer_role,"WriterActivated")),
 P::WalletPrepared{role,..}=>Some((*role,"WalletPrepared")),P::WalletObserved{role,..}=>Some((*role,"WalletObserved")),P::SignCommitted{role,..}=>Some((*role,"SignCommitted")),P::ReturnPrepared{role,..}=>Some((*role,"ReturnPrepared")),P::ReturnCompleted{role,..}=>Some((*role,"ReturnFinished")),_=>None};
 if let Some((owner,step))=observation{signer(owner,step)?;}Ok(())
}

#[cfg(test)]mod tests{
 use super::*;
 fn snapshot()->Value{let value=json!({"phase":"Selecting","subphase":"None","owner":null,"view_generation":1,"focused":true,"secret_input":false,"host_input":false,"pixels_per_point":1.0,"viewport":[1280,800],"host_observation":{"revision":0,"nonws_end":0,"context_valid":true,"entry":"Idle","editor":null,"view":null},"widgets":[{"tag":"Close","owner":null,"rect":[1.0,1.0,40.0,20.0],"enabled":true}]});
  #[cfg(wholepact_financial_rendered_host_semantic_ci)] let value={let mut value=value;value["host_view_id"]=Value::Null;value};
  value}
 #[test]fn closed_snapshot_never_accepts_text_or_unknown_fields(){let v=snapshot();validate_snapshot(&v).unwrap();let mut v=snapshot();v["password"]=json!("not permitted");assert!(validate_snapshot(&v).is_err());let mut v=snapshot();v["widgets"][0]["tag"]=json!("arbitrary private label");assert!(validate_snapshot(&v).is_err());}
 #[test]fn snapshot_rejects_duplicate_widgets_outside_geometry_and_new_phase(){let mut v=snapshot();let w=v["widgets"][0].clone();v["widgets"].as_array_mut().unwrap().push(w);assert!(validate_snapshot(&v).is_err());let mut v=snapshot();v["widgets"][0]["rect"]=json!([0,0,1400,800]);assert!(validate_snapshot(&v).is_err());let mut v=snapshot();v["phase"]=json!("ApproveEverything");assert!(validate_snapshot(&v).is_err());}
 #[test] fn host_view_roundtrip_and_fixed_bounds() {
  let mut v=snapshot();v["widgets"]=json!([{"tag":"HostOutput","owner":null,"rect":[0,0,640,240],"enabled":true}]);
  v["host_observation"]=json!({"revision":1,"nonws_end":100,"context_valid":true,"entry":"Idle","editor":null,"view":{"rect":[10,10,600,230],"nonws":100,"rows":4}});
  #[cfg(wholepact_financial_rendered_host_semantic_ci)] {v["host_view_id"]=json!(1);}
  let bytes=serde_json::to_vec(&v).unwrap();let roundtrip:Value=serde_json::from_slice(&bytes).unwrap();validate_snapshot(&roundtrip).unwrap();
  for (key,value) in [("revision",json!(262145)),("nonws_end",json!(1048577)),("raw_text",json!("forbidden"))] {
   let mut bad=v.clone();bad["host_observation"][key]=value;assert!(validate_snapshot(&bad).is_err());
  }
  let mut bad=v.clone();bad["host_input"]=json!(true);assert!(validate_snapshot(&bad).is_err());
  let mut bad=v.clone();bad["host_observation"]["view"]["rows"]=json!(33);assert!(validate_snapshot(&bad).is_err());
  let mut bad=v;bad["host_observation"]["view"]["rect"]=json!([-1,0,600,230]);assert!(validate_snapshot(&bad).is_err());
 }
 #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
 #[test] fn old_profile_rejects_semantic_snapshot_key() {
  let mut f=snapshot(); f["host_view_id"]=Value::Null; assert!(validate_snapshot(&f).is_err());
 }
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 fn rendered_snapshot()->Value {
  let mut f=snapshot();
  f["widgets"]=json!([{"tag":"HostOutput","owner":null,"rect":[0,0,640,240],"enabled":true}]);
  f["host_observation"]=json!({"revision":1,"nonws_end":7,"context_valid":true,"entry":"Idle","editor":null,"view":{"rect":[10,10,600,230],"nonws":7,"rows":2}});f
 }
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 fn text(s:&str)->Option<zeroize::Zeroizing<String>>{Some(zeroize::Zeroizing::new(s.to_owned()))}
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 #[test] fn semantic_changed_only_linkage_and_reentry_ids() {
  let mut state=SemanticState::default();let mut f=rendered_snapshot();
  assert!(state.bind(&mut f,text("prompt: \n")).unwrap());assert_eq!(f["host_view_id"],1);
  let bytes=serde_json::to_vec(&state.active.as_ref().unwrap().facts()).unwrap();
  let record:Value=serde_json::from_slice(&bytes).unwrap();
  assert!(exact(&record,&["id","view_generation","revision","nonws_end","view","text"]));
  assert_eq!(record["view"],f["host_observation"]["view"]);assert_eq!(record["text"],"prompt: \n");
  let mut f=rendered_snapshot();f["view_generation"]=json!(2);
  assert!(!state.bind(&mut f,text("prompt: \n")).unwrap());assert_eq!(f["host_view_id"],1);
  let mut f=rendered_snapshot();f["host_observation"]["revision"]=json!(2);
  assert!(state.bind(&mut f,text("prompt: \n")).unwrap());assert_eq!(f["host_view_id"],2);
  state.clear();assert!(state.active.is_none());
  let mut f=rendered_snapshot();assert!(state.bind(&mut f,text("prompt: \n")).unwrap());assert_eq!(f["host_view_id"],3);
  let mut f=rendered_snapshot();f["host_observation"]["view"]["rect"]=json!([11,10,600,230]);
  assert!(state.bind(&mut f,text("prompt: \n")).unwrap());assert_eq!(f["host_view_id"],4);
 }
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 #[test] fn semantic_protected_invalid_and_imported_references_fail_closed() {
  for (key,value) in [("host_input",json!(true)),("secret_input",json!(true)),("focused",json!(false)),("host_view_id",json!(1))] {
   let mut state=SemanticState::default();let mut f=rendered_snapshot();
   state.bind(&mut f,text("prompt: \n")).unwrap();
   let mut bad=rendered_snapshot();bad[key]=value;
   assert!(state.bind(&mut bad,text("prompt: \n")).is_err());assert!(state.active.is_none());
  }
  for entry in ["Editing","Writing","Closed"] {
   let mut state=SemanticState::default();let mut f=rendered_snapshot();f["host_observation"]["entry"]=json!(entry);
   assert!(state.bind(&mut f,text("prompt: \n")).is_err());assert!(state.active.is_none());
  }
  let mut state=SemanticState::default();let mut f=rendered_snapshot();f["host_observation"]["context_valid"]=json!(false);
  assert!(state.bind(&mut f,text("prompt: \n")).is_err());
  let mut f=rendered_snapshot();assert!(state.bind(&mut f,None).is_err());
  let mut f=snapshot();assert!(!state.bind(&mut f,None).unwrap());assert!(f["host_view_id"].is_null());
 }
 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 #[test] fn semantic_ascii_count_rows_generation_and_budget_refuse() {
  for bad in ["prompt:","prompt: \r", "prompt: \t", "prompt: é", "prompt: \n\n"] {
   let mut state=SemanticState::default();let mut f=rendered_snapshot();
   if bad=="prompt:" {f["host_observation"]["view"]["nonws"]=json!(8);}
   assert!(state.bind(&mut f,text(bad)).is_err());
  }
  let mut state=SemanticState::default();let mut f=rendered_snapshot();f["view_generation"]=json!(9);
  state.bind(&mut f,text("prompt: \n")).unwrap();let mut f=rendered_snapshot();
  assert!(state.bind(&mut f,text("prompt: \n")).is_err());assert!(state.active.is_none());
  state.last_id=512;let mut f=rendered_snapshot();assert!(state.bind(&mut f,text("prompt: \n")).is_err());assert!(state.active.is_none());
 }

 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 #[test] fn semantic_pair_order_or_second_budget_failure_wipes_active_cache() {
  let mut state=SemanticState::default();let mut f=rendered_snapshot();
  let changed=state.bind(&mut f,text("prompt: \n")).unwrap();
  let mut kinds=Vec::new();
  let active=emit_semantic_pair(state.active.take(),&f,changed,|record|{
   kinds.push(match record{SemanticRecord::Rendered(_)=>"HostRenderedView",SemanticRecord::Snapshot(_)=>"UiSnapshot"});Ok(())
  }).unwrap();
  assert_eq!(kinds,["HostRenderedView","UiSnapshot"]);state.active=active;
  let mut count=32767;let mut attempted=0;
  let result=emit_semantic_pair(state.active.take(),&f,true,|_|{
   attempted+=1;
   if !record_fits(count,0,512){return Err(rejected("synthetic record budget"));}
   count+=1;Ok(())
  });
  assert!(result.is_err());assert_eq!(attempted,2);assert!(state.active.is_none());assert_eq!(state.last_id,1);
  assert!(record_fits(32767,32*1024*1024-32768,32768));
  assert!(!record_fits(32768,0,1));assert!(!record_fits(0,0,32769));assert!(!record_fits(0,32*1024*1024,1));
 }

 #[cfg(wholepact_financial_rendered_host_semantic_ci)]
 #[test] fn semantic_serialization_refuses_growth_before_record_overflow() {
  let mut buffer=RecordBuffer(zeroize::Zeroizing::new(Vec::with_capacity(32768)));
  buffer.write_all(&vec![b'x';32767]).unwrap();assert_eq!(buffer.0.capacity(),32768);
  assert!(buffer.write_all(b"x").is_err());assert_eq!(buffer.0.len(),32767);assert_eq!(buffer.0.capacity(),32768);
  buffer.0.push(b'\n');assert_eq!(buffer.0.len(),32768);assert_eq!(buffer.0.capacity(),32768);
 }


}

pub(crate) fn inert_stopped()->Result<()>{if !matches!(role()?,Role::Owner1BootstrapHistory|Role::Owner1V3DeliveryAdmission|Role::Owner1DeliveryAuditHistory|Role::Owner2BootstrapHistory|Role::Owner2V3DeliveryAdmission|Role::Owner2DeliveryAuditHistory){return Err(rejected("financial observer inert role"));}emit("InertStopped",json!({}))}

// Safe observer boundaries only: never call from revoke/close/error/Drop paths.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn flush_failure_boundaries_locked(w:&mut Writer) {
 if w.pid!=unsafe{libc::getpid()} || w.role!=Role::Coordinator {return;}
 let mut reporter=w.boundary;
 reporter.flush(crate::financial_ci_failure_boundary::sample(),|f| {
  emit_locked(w,"NativeFailureBoundary",&json!({"version":f.version,"ui":f.ui,"driver":f.driver,"transport":f.transport,"core":f.core})).map_err(|_|())
 });
 w.boundary=reporter;
}
/// Best effort after the original Coordinator runner and owned join return.
/// Missing/failed evidence remains unavailable; original errors are unchanged.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
pub fn financial_ci_flush_failure_boundaries() {
 if let Ok(mut slot)=WRITER.lock() {if let Some(w)=slot.as_mut(){flush_failure_boundaries_locked(w);}}
}

// Independent original C/Host actor writer; never called from Drop/reap/abort.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn flush_host_diagnostics_locked(w:&mut Writer) {
 if w.pid!=unsafe{libc::getpid()} {return;}
 let mut reporter=w.host_diagnostic;
 match w.role {
  Role::Coordinator=>reporter.flush(crate::financial_ci_host_diagnostics::sample_reap(),|f|emit_locked(w,"HostReapObservation",&f).map_err(|_|())),
  Role::Host=>reporter.flush(crate::financial_ci_host_diagnostics::sample_failure(),|f|emit_locked(w,"HostFailureBoundary",&f).map_err(|_|())),
  _=>(),
 }
 w.host_diagnostic=reporter;
}
/// Best effort only after original owned cleanup/join; does not replace its result.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
pub fn financial_ci_flush_host_diagnostics() {
 if let Ok(mut slot)=WRITER.lock(){if let Some(w)=slot.as_mut(){flush_host_diagnostics_locked(w);}}
}

/// Failure-only snapshot after denial publication and before an explicit
/// failed-worker edge close. A busy/poisoned writer is unavailable, never waited
/// for here. The original writer bounds and attempted-once reporter apply;
/// append failure is swallowed and cannot replace or skip original teardown.
/// This snapshot does not assert joins/disposal or include later slot values.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
pub(crate) fn financial_ci_flush_actor_failure_before_edge_close() {
 best_effort_actor_observation(|| {
  if let Ok(mut slot)=WRITER.try_lock(){if let Some(w)=slot.as_mut(){
   if w.pid!=unsafe{libc::getpid()}{return;}
   let mut reporter=w.actor_diagnostic;
   reporter.flush_failure(crate::financial_ci_actor_diagnostics::sample_failure(),|f|emit_locked(w,"ActorFailureBoundary",&f).map_err(|_|()));
   w.actor_diagnostic=reporter;
  }}
 });
}
/// Only the new observation is isolated. This does not catch panic=abort,
/// allocation aborts or process death, and never changes an original failure.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn best_effort_actor_observation(observe: impl FnOnce()) {
 let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(observe));
}
#[cfg(all(test,wholepact_financial_rendered_host_semantic_ci))]
mod early_actor_observation_tests {
 use super::*;
 #[test] fn success_and_unwind_return_to_original_teardown() {
  for panics in [false,true] {
   let calls=std::cell::Cell::new(0);
   best_effort_actor_observation(||{calls.set(calls.get()+1);if panics{panic!("synthetic observer panic");}});
   calls.set(calls.get()+10);
   assert_eq!(calls.get(),11);
  }
 }
}

/// Final actor-local summary after the original work and owned joins return.
/// An earlier attempted failure snapshot is never retried or enriched.
/// No evidence operation changes or replaces an original result.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
pub fn financial_ci_flush_actor_diagnostics(){
 if let Ok(mut slot)=WRITER.lock(){if let Some(w)=slot.as_mut(){
  if w.pid!=unsafe{libc::getpid()}{return;}
  let mut reporter=w.actor_diagnostic;
  reporter.flush_failure(crate::financial_ci_actor_diagnostics::sample_failure(),|f|emit_locked(w,"ActorFailureBoundary",&f).map_err(|_|()));
  reporter.flush_reaps(crate::financial_ci_actor_diagnostics::sample_reaps(),|f|emit_locked(w,"ActorReapObservation",&f).map_err(|_|()));
  w.actor_diagnostic=reporter;
 }}
}
