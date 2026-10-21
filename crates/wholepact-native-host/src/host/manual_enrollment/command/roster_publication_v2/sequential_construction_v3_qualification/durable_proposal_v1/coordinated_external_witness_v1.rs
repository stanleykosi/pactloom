//! Synthetic external native Witness operator, deliberately NOT a C-owned W
//! purpose. The ordinary request selector never supplies native permission.
//! Each phase uses the retained real fixture owner and maintained native UI.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}, time::{Duration, Instant}};
use wholepact_authority::{OwnerControlRequest, native_witness_owner::EphemeralNativeWitnessV1};

const CONTROL: &str = "/ci-financial-control";
const MAX_REQUEST: usize = 64 * 1024;
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all="snake_case")]
enum Event { BootstrapServing, BootstrapDrained, AdmissionCommitted, AdmissionDrained, AuditServing, AuditDrained, TransportParked }
#[derive(Serialize)]
struct Observation { version:u16, owner:&'static str, event:Event }

fn current(cutoff:Instant)->Result<()> { if Instant::now()>=cutoff {Err(Error::Permission)}else{Ok(())} }
fn authority<T>(value:wholepact_authority::Result<T>)->Result<T> {value.map_err(|_|Error::Authentication)}
struct Controls { root:PathBuf, directory:File, events:File, cutoff:Instant }
impl Controls {
    fn open(cutoff:Instant)->Result<Self> {
        current(cutoff)?;
        let root=PathBuf::from(CONTROL);
        let directory=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&root)?;
        let meta=directory.metadata()?;
        if !meta.is_dir()||meta.uid()!=unsafe{libc::geteuid()}||meta.mode()&0o777!=0o700 {return Err(Error::Permission)}
        let events=OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(root.join("external-witness-events.jsonl"))?;
        Ok(Self{root,directory,events,cutoff})
    }
    fn check(&self)->Result<()> {
        current(self.cutoff)?;
        let held=self.directory.metadata()?;let live=std::fs::symlink_metadata(&self.root)?;
        if !live.is_dir()||held.dev()!=live.dev()||held.ino()!=live.ino()||live.uid()!=unsafe{libc::geteuid()}||live.mode()&0o777!=0o700{return Err(Error::Permission)}
        Ok(())
    }
    fn observe(&mut self,index:usize,event:Event)->Result<()> {
        self.check()?;
        let owner=match index{0=>"signer1",1=>"signer2",_=>return Err(Error::Invalid)};
        let mut bytes=serde_json::to_vec(&Observation{version:1,owner,event})?;bytes.push(b'\n');
        self.events.write_all(&bytes)?;self.events.sync_data()?;self.check()
    }
    fn read(&self,name:&str)->Result<Option<Vec<u8>>> {
        self.check()?;
        let mut file=match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(self.root.join(name)) {
            Ok(file)=>file,Err(error)if error.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(error)=>return Err(error.into()),
        };
        let meta=file.metadata()?;
        if !meta.is_file()||meta.uid()!=unsafe{libc::geteuid()}||meta.mode()&0o777!=0o600||meta.nlink()!=1||meta.len()==0||meta.len()>MAX_REQUEST as u64{return Err(Error::Permission)}
        let mut bytes=Vec::new();Read::by_ref(&mut file).take((MAX_REQUEST+1)as u64).read_to_end(&mut bytes)?;
        let after=file.metadata()?;
        if bytes.len()>MAX_REQUEST||bytes.len()as u64!=meta.len()||after.len()!=meta.len()||after.dev()!=meta.dev()||after.ino()!=meta.ino()||after.uid()!=meta.uid()||after.mode()!=meta.mode()||after.nlink()!=1||after.mtime()!=meta.mtime()||after.mtime_nsec()!=meta.mtime_nsec()||after.ctime()!=meta.ctime()||after.ctime_nsec()!=meta.ctime_nsec(){return Err(Error::Permission)}
        self.check()?;Ok(Some(bytes))
    }
    fn wait_command(&self,name:&str,expected:&[u8])->Result<()> {
        loop {if let Some(bytes)=self.read(name)?{return if bytes==expected{Ok(())}else{Err(Error::Invalid)}}std::thread::sleep(Duration::from_millis(10));}
    }
}

// Exact selector schema supplied by the C-owned ordinary current-source
// display exporter. This is data input to real native preparation, not a grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestSelector {
    version:u16, profile:String, owner:String, source_identity_digest:String,
    owner_service_digest:String, admission_request_digest:String, request_json:String,
}
fn exact_hash(s:&str)->bool {s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn parse_request(bytes:&[u8],index:usize,account:&str)->Result<OwnerControlRequest> {
    let selected:RequestSelector=serde_json::from_slice(&bytes)?;
    if selected.version!=1||selected.profile!="external-pre-v3-witness-v1"||selected.owner!=format!("Signer{}",index+1)||selected.request_json.is_empty()||selected.request_json.len()>16384||![&selected.source_identity_digest,&selected.owner_service_digest,&selected.admission_request_digest].iter().all(|v|exact_hash(v)){return Err(Error::Authentication)}
    let request:OwnerControlRequest=serde_json::from_str(&selected.request_json)?;
    if request.account_id!=account || wholepact_core::proposal::canonical_digest(
        "wholepact:coordinated-durable-delivery-admission-request:v1", &request,
    ).map_err(|_|Error::Invalid)? != selected.admission_request_digest {return Err(Error::Authentication)}
    Ok(request)
}
fn request(controls:&Controls,index:usize,account:&str)->Result<OwnerControlRequest> {
    let name=format!("v3-admission-owner{}.json",index+1);
    loop {
        if let Some(bytes)=controls.read(&name)? {
            return parse_request(&bytes,index,account);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn run(terminal:&crate::terminal::Terminal,witness:&mut EphemeralNativeWitnessV1,account_ids:&[String;2],_root:&Path,original_cutoff:Instant)->Result<()> {
    if account_ids[0]==account_ids[1]{return Err(Error::Authentication)}
    let mut controls=Controls::open(original_cutoff)?;
    for index in 0..2 {
        if index==1 {controls.wait_command("v3-start-owner2",b"start\n")?;}
        controls.check()?;
        let history=authority(witness.serve_original_delivery_bootstrap_history_v2(&account_ids[index]))?;
        controls.observe(index,Event::BootstrapServing)?;
        if index==0 {terminal.message("SYNTHETIC_COORDINATED_PRE_V3_ORIGINALS_READY=1\n")?;}
        let actual_request=request(&controls,index,&account_ids[index])?;
        drop(history); // actual history thread join and journal/listener clone drop
        authority(witness.release_original_listener_when_idle_v1())?;
        controls.observe(index,Event::BootstrapDrained)?;
        authority(witness.start_exact_durable_delivery_admission_v2(&account_ids[index],&actual_request))?;
        authority(witness.finish_exact_durable_delivery_admission_v2())?;
        controls.observe(index,Event::AdmissionCommitted)?;
        authority(witness.release_original_listener_when_idle_v1())?;
        controls.observe(index,Event::AdmissionDrained)?;
        let history=authority(witness.serve_committed_durable_delivery_history_v2(&actual_request.operation_id))?;
        controls.observe(index,Event::AuditServing)?;
        // Scheduling restriction only. The harness waits for the ACTUAL S
        // audited receipt; this file can never create that receipt or a grant.
        controls.wait_command(&format!("v3-audit-stop-owner{}",index+1),b"stop\n")?;
        drop(history);
        authority(witness.release_original_listener_when_idle_v1())?;
        controls.observe(index,Event::AuditDrained)?;
        controls.observe(index,Event::TransportParked)?;
    }
    controls.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_selector_is_closed_and_is_not_a_permission() {
        let value=serde_json::json!({"version":1,"profile":"external-pre-v3-witness-v1","owner":"Signer1",
            "source_identity_digest":"a".repeat(64),"owner_service_digest":"b".repeat(64),
            "admission_request_digest":"c".repeat(64),"request_json":"{}","approved":true});
        assert!(serde_json::from_value::<RequestSelector>(value).is_err());
    }
    #[test]
    fn external_observation_has_no_request_or_grant_payload() {
        let value=serde_json::to_value(Observation{version:1,owner:"signer2",event:Event::TransportParked}).unwrap();
        assert_eq!(value,serde_json::json!({"version":1,"owner":"signer2","event":"transport_parked"}));
        assert!(exact_hash(&"a".repeat(64)));
        assert!(!exact_hash(&"A".repeat(64)));
    }
}

#[cfg(test)]
mod request_selector_tests {
    use super::*;
    // Ordinary typed data only. This helper does not authorize any operation;
    // the maintained native start separately rejects non-delivery purposes.
    fn selector(index:usize)->(OwnerControlRequest,serde_json::Value) {
        let request=OwnerControlRequest {operation_id:format!("synthetic-selector-{}",index+1),
            account_id:if index==0 {"11".repeat(32)}else{"22".repeat(32)},
            network_profile_id:"synthetic-selector-profile".into(),
            expected_head:wholepact_authority::AuthorityHead{sequence:4,digest:"ab".repeat(32)},
            writer_epoch:1,control:wholepact_authority::OwnerControl::Pause};
        let digest=wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-durable-delivery-admission-request:v1",&request).unwrap();
        let value=serde_json::json!({"version":1,"profile":"external-pre-v3-witness-v1",
            "owner":format!("Signer{}",index+1),"source_identity_digest":"aa".repeat(32),
            "owner_service_digest":"bb".repeat(32),"admission_request_digest":digest,
            "request_json":serde_json::to_string(&request).unwrap()});
        (request,value)
    }
    fn parse(value:&serde_json::Value,index:usize,account:&str)->Result<OwnerControlRequest> {
        parse_request(&serde_json::to_vec(value).unwrap(),index,account)
    }
    #[test]
    fn exact_second_owner_selector_parses_without_creating_permission() {
        let (request,value)=selector(1);
        assert!(parse(&value,1,&request.account_id).is_ok_and(|parsed|parsed==request));
    }
    #[test]
    fn owner_one_request_cannot_be_relabelled_for_owner_two() {
        let (_,mut value)=selector(0);let (second,_)=selector(1);
        assert!(parse(&value,1,&second.account_id).is_err());
        value["owner"]=serde_json::json!("Signer2");
        assert!(parse(&value,1,&second.account_id).is_err());
    }
    #[test]
    fn request_bytes_cannot_change_under_retained_commitment() {
        let (mut request,value)=selector(1);let mut changed=value.clone();
        request.operation_id.push('x');changed["request_json"]=serde_json::json!(serde_json::to_string(&request).unwrap());
        assert!(parse(&changed,1,&request.account_id).is_err());
        changed=value;changed["admission_request_digest"]=serde_json::json!("00".repeat(32));
        assert!(parse(&changed,1,&request.account_id).is_err());
    }
    #[test]
    fn selector_rejects_wrong_profile_unknown_fields_and_oversize_request() {
        let (request,value)=selector(1);
        let mut changed=value.clone();changed["profile"]=serde_json::json!("other");
        assert!(parse(&changed,1,&request.account_id).is_err());
        changed=value.clone();changed["native_permission"]=serde_json::json!(true);
        assert!(parse(&changed,1,&request.account_id).is_err());
        changed=value;changed["request_json"]=serde_json::json!(" ".repeat(16385));
        assert!(parse(&changed,1,&request.account_id).is_err());
    }
}
