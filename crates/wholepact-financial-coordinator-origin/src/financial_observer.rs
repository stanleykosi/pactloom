//! Observation-only, compiled exclusively into the pinned full-financial CI image.
//! No input, origin construction, approval or authority state mutation.
use crate::{process::Role,rejected,Result};
use serde_json::{json,Value};
use std::{fs::{File,OpenOptions},io::Write,os::{fd::{AsRawFd,FromRawFd},unix::fs::{OpenOptionsExt,MetadataExt}},sync::{Mutex,atomic::{AtomicU64,Ordering}}};
#[cfg(wholepact_financial_external_ci)]
const OBSERVED_PROFILE:&str="coordinated-financial-external-pre-v3-witness-v1";
#[cfg(not(wholepact_financial_external_ci))]
const OBSERVED_PROFILE:&str="coordinated-financial-full-native-v1";
const DIRECTORY:&str="/ci-financial-evidence";
static EPOCH:AtomicU64=AtomicU64::new(0);
struct Writer{pid:i32,role:Role,sequence:u64,bytes:u64,inode:u64,device:u64,directory_inode:u64,directory_device:u64,last:u64}
static WRITER:Mutex<Option<Writer>>=Mutex::new(None);
fn now()->Result<u64>{let mut t:libc::timespec=unsafe{std::mem::zeroed()};if unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut t)}!=0{return Err(std::io::Error::last_os_error());}u64::try_from(t.tv_sec).ok().and_then(|s|s.checked_mul(1_000_000_000)).and_then(|n|n.checked_add(t.tv_nsec as u64)).ok_or_else(||rejected("financial observer clock"))}
fn name(role:Role)->String{format!("{role:?}")}
fn directory()->Result<File>{let f=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(DIRECTORY)?;let m=f.metadata()?;if !m.is_dir()||m.uid()!=unsafe{libc::geteuid()}||m.mode()&0o777!=0o700{return Err(rejected("financial observer private directory"));}Ok(f)}
pub(crate) fn initialize()->Result<()>{if EPOCH.compare_exchange(0,now()?,Ordering::SeqCst,Ordering::SeqCst).is_err(){return Err(rejected("financial observer initialized twice"));}enter(Role::Coordinator)}
pub(crate) fn enter(role:Role)->Result<()>{
 let mut slot=WRITER.lock().map_err(|_|rejected("financial observer lock"))?;let pid=unsafe{libc::getpid()};
 if slot.as_ref().is_some_and(|w|w.pid==pid){return Err(rejected("financial observer repeated actor"));}
 let dir=directory()?;let path=std::ffi::CString::new(format!("{pid}.jsonl")).unwrap();let fd=unsafe{libc::openat(dir.as_raw_fd(),path.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_APPEND|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK,0o600)};if fd<0{return Err(std::io::Error::last_os_error());}let f=unsafe{File::from_raw_fd(fd)};let m=f.metadata()?;
 *slot=Some(Writer{pid,role,sequence:0,bytes:0,inode:m.ino(),device:m.dev(),directory_inode:dir.metadata()?.ino(),directory_device:dir.metadata()?.dev(),last:0});drop(f);drop(slot);
 let parent=match role{Role::Coordinator=>None,Role::Signer1|Role::Signer2=>Some("Host"),_=>Some("Coordinator")};
 emit("Birth",json!({"pid":pid,"parent_pid":unsafe{libc::getppid()},"parent_role":parent}))
}
fn emit(kind:&str,facts:Value)->Result<()>{
 let mut slot=WRITER.lock().map_err(|_|rejected("financial observer lock"))?;let w=slot.as_mut().ok_or_else(||rejected("financial observer actor absent"))?;
 if w.pid!=unsafe{libc::getpid()}||w.sequence>=32768{return Err(rejected("financial observer actor or record limit"));}
 let elapsed=now()?.checked_sub(EPOCH.load(Ordering::SeqCst)).ok_or_else(||rejected("financial observer epoch"))?;
 if elapsed<w.last||elapsed>1_800_000_000_000{return Err(rejected("financial observer original deadline"));}
 let mut bytes=serde_json::to_vec(&json!({"schema":1,"profile":OBSERVED_PROFILE,"role":name(w.role),"sequence":w.sequence+1,"elapsed_ns":elapsed,"kind":kind,"facts":facts})).map_err(|_|rejected("financial observer encoding"))?;bytes.push(b'\n');
 if bytes.len()>32768||w.bytes+bytes.len()as u64>32*1024*1024{return Err(rejected("financial observer size"));}
 let dir=directory()?;let dm=dir.metadata()?;if dm.ino()!=w.directory_inode||dm.dev()!=w.directory_device{return Err(rejected("financial observer directory changed"));}let path=std::ffi::CString::new(format!("{}.jsonl",w.pid)).unwrap();let fd=unsafe{libc::openat(dir.as_raw_fd(),path.as_ptr(),libc::O_WRONLY|libc::O_APPEND|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)};if fd<0{return Err(std::io::Error::last_os_error());}let mut f=unsafe{File::from_raw_fd(fd)};let m=f.metadata()?;
 if !m.is_file()||m.uid()!=unsafe{libc::geteuid()}||m.mode()&0o777!=0o600||m.nlink()!=1||m.ino()!=w.inode||m.dev()!=w.device||m.len()!=w.bytes{return Err(rejected("financial observer file changed"));}
 f.write_all(&bytes)?;w.sequence+=1;w.bytes+=bytes.len()as u64;w.last=elapsed;Ok(())
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
/// Closed geometry/state only. No review text, paths, passwords or Host output.
fn validate_snapshot(facts:&Value)->Result<()>{
 if !exact(&facts,&["phase","subphase","owner","view_generation","focused","secret_input","host_input","pixels_per_point","viewport","widgets"]){return Err(rejected("financial snapshot shape"));}
 let f=&facts;let scale=f["pixels_per_point"].as_f64().filter(|s|s.is_finite()&&*s>=0.5&&*s<=4.0).ok_or_else(||rejected("financial snapshot scale"))?;
 if !f["phase"].as_str().is_some_and(|s|PHASES.contains(&s))||!f["subphase"].as_str().is_some_and(|s|SUBPHASES.contains(&s))||!owner(&f["owner"])||!f["view_generation"].as_u64().is_some_and(|g|g>0)||["focused","secret_input","host_input"].iter().any(|k|!f[*k].is_boolean())||f["viewport"]!=json!([1280,800]){return Err(rejected("financial snapshot state"));}
 let widgets=f["widgets"].as_array().filter(|w|w.len()<=128).ok_or_else(||rejected("financial snapshot widgets"))?;let mut seen=std::collections::HashSet::new();
 for w in widgets{if !exact(w,&["tag","owner","rect","enabled"])||!w["tag"].as_str().is_some_and(|s|WIDGETS.contains(&s))||!owner(&w["owner"])||!w["enabled"].is_boolean()||!seen.insert((w["tag"].to_string(),w["owner"].to_string())){return Err(rejected("financial snapshot widget"));}let r=w["rect"].as_array().filter(|r|r.len()==4).ok_or_else(||rejected("financial snapshot rect"))?;let a:Vec<f64>=r.iter().map(|v|v.as_f64().filter(|n|n.is_finite()).ok_or_else(||rejected("financial snapshot coordinate"))).collect::<Result<_>>()?;if !(0.0<=a[0]&&a[0]<a[2]&&a[2]<=1280.0/scale&&0.0<=a[1]&&a[1]<a[3]&&a[3]<=800.0/scale){return Err(rejected("financial snapshot bounds"));}}
 Ok(())
}
pub fn financial_ci_snapshot(facts:Value)->Result<()>{if role()?!=Role::Coordinator{return Err(rejected("financial snapshot actor"));}validate_snapshot(&facts)?;emit("UiSnapshot",facts)}

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
 fn snapshot()->Value{json!({"phase":"Selecting","subphase":"None","owner":null,"view_generation":1,"focused":true,"secret_input":false,"host_input":false,"pixels_per_point":1.0,"viewport":[1280,800],"widgets":[{"tag":"Close","owner":null,"rect":[1.0,1.0,40.0,20.0],"enabled":true}]})}
 #[test]fn closed_snapshot_never_accepts_text_or_unknown_fields(){let v=snapshot();validate_snapshot(&v).unwrap();let mut v=snapshot();v["password"]=json!("not permitted");assert!(validate_snapshot(&v).is_err());let mut v=snapshot();v["widgets"][0]["tag"]=json!("arbitrary private label");assert!(validate_snapshot(&v).is_err());}
 #[test]fn snapshot_rejects_duplicate_widgets_outside_geometry_and_new_phase(){let mut v=snapshot();let w=v["widgets"][0].clone();v["widgets"].as_array_mut().unwrap().push(w);assert!(validate_snapshot(&v).is_err());let mut v=snapshot();v["widgets"][0]["rect"]=json!([0,0,1400,800]);assert!(validate_snapshot(&v).is_err());let mut v=snapshot();v["phase"]=json!("ApproveEverything");assert!(validate_snapshot(&v).is_err());}
}

pub(crate) fn inert_stopped()->Result<()>{if !matches!(role()?,Role::Owner1BootstrapHistory|Role::Owner1V3DeliveryAdmission|Role::Owner1DeliveryAuditHistory|Role::Owner2BootstrapHistory|Role::Owner2V3DeliveryAdmission|Role::Owner2DeliveryAuditHistory){return Err(rejected("financial observer inert role"));}emit("InertStopped",json!({}))}
