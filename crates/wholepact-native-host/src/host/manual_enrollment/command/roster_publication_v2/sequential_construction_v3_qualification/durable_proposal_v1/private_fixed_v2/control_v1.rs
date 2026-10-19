//! Closed, inert restart expectations, not credentials or authority. Actual
//! original sources and current native consent are authenticated independently.
use serde::{Deserialize, Serialize};
use std::{fs::{File, OpenOptions}, io::{self, Read, Write},
    os::unix::{fs::{MetadataExt, OpenOptionsExt}, io::{AsRawFd, FromRawFd}},
    path::{Component, Path, PathBuf}};

const MAX_CONTROL: u64 = 16 * 1024;
const READY_FILE: &[u8] = b"private-workspace-fixed-control-v1.json\0";
const READER_FILE: &[u8] = b"private-workspace-reader-result-v1.json\0";
pub(super) const PUBLIC_PREFIX: &str = "CI_SYNTHETIC_PRIVATE_WORKSPACE ";
pub(super) const BOUNDARIES: [&str; 22] = [
    "PrivateWorkspaceBootstrap", "PrivateSourceSelect", "PrivateWorkspaceReserve",
    "PrivateWorkspaceAnchor", "PrivateWorkspacePublish", "PrivateWorkspaceInitialize",
    "PrivateWorkspaceCandidate", "PrivateWorkspaceCapture", "PrivateWorkspaceIntake",
    "PrivateWorkspaceObserve", "PrivateWorkspaceCheckpoint", "PrivateWorkspaceProof",
    "PrivateWorkspaceFreeze", "PrivateWorkspaceScanCleanup", "PrivateWorkspaceDurableMarker",
    "PrivateWorkspaceProducerKill", "PrivateWorkspaceProducerReap", "PrivateWorkspaceReaderOpen",
    "PrivateWorkspaceReadFixed", "PrivateWorkspaceIdentityCompare", "PrivateWorkspaceReaderReap",
    "PrivateWorkspaceRootCleanup",
];
fn invalid() -> io::Error { io::Error::other("private workspace comparison record refused") }
fn hash(value: &str) -> bool {
    value.len()==64 && value.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Digests originate inside the real private kernel / authenticated Host
/// identity wrapper. No digest here is derived from a reconstructed candidate.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FixedCommitmentsV1 {
    pub(super) original_host_digest: String,
    pub(super) original_financial_digest: String,
    pub(super) source_digest: String,
    pub(super) native_association_digest: String,
    pub(super) marker_digest: String,
    pub(super) metadata_origin: String,
    pub(super) proof_origin: String,
    pub(super) candidate_identity_digest: String,
    pub(super) manifest_digest: String,
    pub(super) original_checkpoint_key_digest: String,
    pub(super) coordination_request_digest: String,
    pub(super) checkpoint_receipt_digest: String,
    pub(super) action_mapping_digest: String,
    pub(super) job_identity_digest: String,
    pub(super) scope_digest: String,
    pub(super) input_digest: String,
    pub(super) result_digest: String,
    pub(super) fixed_identity_digest: String,
    pub(super) operation_history_digest: String,
    pub(super) proof_event_history_digest: String,
    pub(super) logical_state_digest: String,
}
impl FixedCommitmentsV1 {
    fn validate(&self) -> io::Result<()> {
        let values=[&self.original_host_digest,&self.original_financial_digest,&self.source_digest,
            &self.native_association_digest,&self.marker_digest,&self.metadata_origin,&self.proof_origin,
            &self.candidate_identity_digest,&self.manifest_digest,&self.original_checkpoint_key_digest,
            &self.coordination_request_digest,&self.checkpoint_receipt_digest,&self.action_mapping_digest,
            &self.job_identity_digest,&self.scope_digest,&self.input_digest,&self.result_digest,
            &self.fixed_identity_digest,&self.operation_history_digest,&self.proof_event_history_digest,&self.logical_state_digest];
        if values.iter().all(|value|hash(value)) { Ok(()) } else { Err(invalid()) }
    }
    pub(super) fn checkpoint_equal(&self, other: &Self) -> bool {
        self.coordination_request_digest==other.coordination_request_digest
            && self.checkpoint_receipt_digest==other.checkpoint_receipt_digest
            && self.action_mapping_digest==other.action_mapping_digest
            && self.scope_digest==other.scope_digest && self.input_digest==other.input_digest
            && self.result_digest==other.result_digest && self.job_identity_digest==other.job_identity_digest
    }
    pub(super) fn idempotency_equal(&self, other: &Self) -> bool {
        self.original_checkpoint_key_digest==other.original_checkpoint_key_digest
            && self.operation_history_digest==other.operation_history_digest
            && self.proof_event_history_digest==other.proof_event_history_digest
            && self.logical_state_digest==other.logical_state_digest
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadyControlV1 {
    pub(super) schema: u8,
    pub(super) profile: PathBuf,
    pub(super) workspace: PathBuf,
    pub(super) financial: PathBuf,
    pub(super) expected: FixedCommitmentsV1,
}
impl ReadyControlV1 {
    fn validate(&self,root:&Path)->io::Result<()> {
        if self.schema!=1 || !root.is_absolute() { return Err(invalid()); }
        for path in [&self.profile,&self.workspace,&self.financial] {
            let relative=path.strip_prefix(root).map_err(|_|invalid())?;
            if !path.is_absolute() || path.as_os_str().len()>4096 || relative.as_os_str().is_empty()
                || !relative.components().all(|part|matches!(part,Component::Normal(_))) {
                return Err(invalid());
            }
        }
        if self.profile==self.workspace || self.profile==self.financial || self.workspace==self.financial {
            return Err(invalid());
        }
        self.expected.validate()
    }
    pub(super) fn write_once(&self,root:&Path)->io::Result<()> {
        self.validate(root)?; write_record(root,READY_FILE,self)
    }
    pub(super) fn read_original(root:&Path)->io::Result<Self> {
        let result:Self=read_record(root,READY_FILE)?; result.validate(root)?; Ok(result)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReaderCompletionV1 {
    pub(super) schema:u8,
    pub(super) fixed_verified:bool,
    pub(super) exact_identity_preserved:bool,
    pub(super) exact_checkpoint_preserved:bool,
    pub(super) exact_idempotency_preserved:bool,
    pub(super) reader_no_effects_verified:bool,
}
impl ReaderCompletionV1 {
    pub(super) fn verified(&self)->bool {
        self.schema==1 && self.fixed_verified && self.exact_identity_preserved
            && self.exact_checkpoint_preserved && self.exact_idempotency_preserved
            && self.reader_no_effects_verified
    }
    pub(super) fn write_once(&self,root:&Path)->io::Result<()> {
        if !self.verified() { return Err(invalid()); } write_record(root,READER_FILE,self)
    }
    pub(super) fn read_after_reap(root:&Path)->io::Result<Self> {
        let result:Self=read_record(root,READER_FILE)?;
        if !result.verified() { return Err(invalid()); } Ok(result)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicOutcomeV1 {
    pub(super) schema:u8,
    pub(super) phase:String,
    pub(super) result:String,
    pub(super) first_failure:Option<String>,
    pub(super) producer_exit:String,
    pub(super) producer_reaped:bool,
    pub(super) producer_group_absent:bool,
    pub(super) reader_exit:String,
    pub(super) reader_reaped:bool,
    pub(super) reader_group_absent:bool,
    pub(super) root_cleanup:String,
    pub(super) fixed_verified:bool,
    pub(super) exact_identity_preserved:bool,
    pub(super) exact_checkpoint_preserved:bool,
    pub(super) exact_idempotency_preserved:bool,
    pub(super) reader_no_effects_verified:bool,
    pub(super) authorization_allowed:bool,
    pub(super) distribution_allowed:bool,
    pub(super) attended_native_acceptance_verified:bool,
    pub(super) public_chain_verified:bool,
}
impl PublicOutcomeV1 {
    pub(super) fn pending()->Self {
        Self { schema:1, phase:"fixed_reopen".into(), result:"failed".into(),first_failure:None,
            producer_exit:"unverified".into(),producer_reaped:false,producer_group_absent:false,
            reader_exit:"not_started".into(),reader_reaped:false,reader_group_absent:false,
            root_cleanup:"unverified".into(),fixed_verified:false,exact_identity_preserved:false,
            exact_checkpoint_preserved:false,exact_idempotency_preserved:false,reader_no_effects_verified:false,
            authorization_allowed:false,distribution_allowed:false,
            attended_native_acceptance_verified:false,public_chain_verified:false }
    }
    pub(super) fn fail(&mut self,boundary:&'static str) {
        if self.first_failure.is_none() && BOUNDARIES.contains(&boundary) {
            self.first_failure=Some(boundary.into());
        }
        self.result="failed".into();
    }
    pub(super) fn verified_success(&self)->bool {
        self.first_failure.is_none() && self.producer_exit=="sigkill" && self.producer_reaped
            && self.producer_group_absent && self.reader_exit=="success" && self.reader_reaped
            && self.reader_group_absent && self.root_cleanup=="closed_absent"
            && self.fixed_verified && self.exact_identity_preserved && self.exact_checkpoint_preserved
            && self.exact_idempotency_preserved && self.reader_no_effects_verified
    }
    pub(super) fn public_json(&self)->io::Result<String> {
        if self.schema!=1 || self.phase!="fixed_reopen" || !["passed","failed"].contains(&self.result.as_str())
            || self.first_failure.as_ref().is_some_and(|name|!BOUNDARIES.contains(&name.as_str()))
            || !["sigkill","other","unverified"].contains(&self.producer_exit.as_str())
            || !["success","other","not_started","unverified"].contains(&self.reader_exit.as_str())
            || !["closed_absent","retained","unverified"].contains(&self.root_cleanup.as_str())
            || self.authorization_allowed || self.distribution_allowed
            || self.attended_native_acceptance_verified || self.public_chain_verified
            || (self.reader_exit=="not_started" && (self.reader_reaped || self.reader_group_absent))
            || (self.result=="passed" && !self.verified_success())
            || (self.result=="failed" && self.first_failure.is_none()) { return Err(invalid()); }
        let text=serde_json::to_string(self).map_err(|_|invalid())?;
        if text.len()>2048 { return Err(invalid()); } Ok(text)
    }
}
fn directory(root:&Path)->io::Result<File> {
    let directory=OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(root)?;
    let metadata=directory.metadata()?;
    if !metadata.is_dir() || metadata.uid()!=unsafe { libc::geteuid() }
        || metadata.mode()&0o7777!=0o700 { return Err(invalid()); } Ok(directory)
}
fn file(directory:&File,name:&[u8],flags:libc::c_int)->io::Result<File> {
    let fd=unsafe { libc::openat(directory.as_raw_fd(),name.as_ptr().cast(),
        flags|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK,0o600) };
    if fd<0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn check_file(file:&File)->io::Result<()> {
    let metadata=file.metadata()?;
    if !metadata.is_file() || metadata.uid()!=unsafe { libc::geteuid() }
        || metadata.mode()&0o7777!=0o600 || metadata.nlink()!=1 || metadata.len()>MAX_CONTROL {
        return Err(invalid());
    }
    Ok(())
}
fn write_record(root:&Path,name:&[u8],value:&impl Serialize)->io::Result<()> {
    let bytes=zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_|invalid())?);
    if bytes.len() as u64>MAX_CONTROL { return Err(invalid()); }
    let directory=directory(root)?;
    let mut file=file(&directory,name,libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL)?;
    check_file(&file)?; file.write_all(&bytes)?; file.sync_all()?; directory.sync_all()
}
fn read_record<T:serde::de::DeserializeOwned>(root:&Path,name:&[u8])->io::Result<T> {
    let directory=directory(root)?; let file=file(&directory,name,libc::O_RDONLY)?; check_file(&file)?;
    let mut bytes=zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONTROL+1).read_to_end(&mut bytes)?;
    if bytes.len() as u64>MAX_CONTROL { return Err(invalid()); }
    serde_json::from_slice(&bytes).map_err(|_|invalid())
}
