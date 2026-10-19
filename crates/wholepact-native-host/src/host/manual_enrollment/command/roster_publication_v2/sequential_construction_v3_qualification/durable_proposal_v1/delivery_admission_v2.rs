//! A single actual fixed-source preparation, two native prospective admissions,
//! and controlled process death followed by a separate same-original reader.
//! Restart records are bounded inert selectors, never reconstructed authority.
use super::*;
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use wholepact_signer::authority_bridge::{
    ipc::OriginalHistoryClient,
    durable_delivery_admission_ipc_v2::{
        DurableDeliveryAdmissionStatusV2, DurableDeliveryHistoryRequestV2,
    },
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    durable_construction_v1::{
        DurableConstructionHistoryRequestV1, DurableConstructionRedisclosureRequestV1,
        DurableConstructionRedisclosureSourceV1, DurableConstructionScopeV1,
    },
};
use worker::{JoinedSignerCommandV1 as C, JoinedSignerReplyV1 as R};

const PASSWORD: &[u8] = b"synthetic-recovery-review-password";
const MAX_CONTROL: u64 = 1024 * 1024;
const READY_FILE: &[u8] = b"durable-delivery-control-v2.json\0";
const READER_FILE: &[u8] = b"durable-delivery-reader-result-v2.json\0";
const OWNER_FILES: [&[u8]; 2] = [
    b"durable-delivery-owner-one-v2.json\0",
    b"durable-delivery-owner-two-v2.json\0",
];
const PUBLIC_PREFIX: &str = "CI_SYNTHETIC_DURABLE_DELIVERY ";
const DEATH_MARKER: &str = "SYNTHETIC_DURABLE_DELIVERY_ADMITTED_V2=1";
const WORKFLOW_LIMIT: Duration = Duration::from_secs(900);
const BOUNDARIES: &[&str] = &[
    "PrivateWorkspaceBootstrap",
    "PrivateSourceSelect",
    "PrivateWorkspaceReserve",
    "PrivateWorkspaceAnchor",
    "PrivateWorkspacePublish",
    "PrivateWorkspaceInitialize",
    "PrivateWorkspaceCandidate",
    "PrivateWorkspaceCapture",
    "PrivateWorkspaceIntake",
    "PrivateWorkspaceObserve",
    "PrivateWorkspaceCheckpoint",
    "PrivateWorkspaceProof",
    "PrivateWorkspaceFreeze",
    "PrivateWorkspaceScanCleanup",
    "PrivateWorkspaceDurableMarker",
    "PrivateWorkspaceProducerKill",
    "PrivateWorkspaceProducerReap",
    "PrivateWorkspaceReaderOpen",
    "PrivateWorkspaceReadFixed",
    "PrivateWorkspaceIdentityCompare",
    "PrivateWorkspaceReaderReap",
    "PrivateWorkspaceRootCleanup",
    "DeliveryCredentialRegistration",
    "DeliverySourceExport",
    "DeliveryOriginalReopen",
    "DeliveryUnsupportedAudit",
    "DeliveryNativeAdmission",
    "DeliveryHistoricalRead",
    "DeliveryIdentityCompare",
    "DeliveryDurableMarker",
    "DeliveryProducerKill",
    "DeliveryProducerReap",
    "DeliveryReaderReap",
    "DeliveryRootCleanup",
];
fn invalid() -> io::Error {
    io::Error::other("closed original delivery qualification record refused")
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(value: &impl Serialize) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:synthetic-original-delivery-comparison:v2",
        value,
    )
    .map_err(|_| Error::Invalid)
}
fn scenario_root() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os("TMPDIR").ok_or(Error::Invalid)?);
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    Ok(path)
}
fn worker_error(_: &'static str) -> Error {
    Error::Receipt("exact original delivery worker refused".into())
}
fn bridge_error(error: wholepact_signer::authority_bridge::BridgeError) -> Error {
    bridge_error_at(B::DeliveryNativeAdmission, error)
}
fn bridge_error_at(boundary: B, error: wholepact_signer::authority_bridge::BridgeError) -> Error {
    use wholepact_signer::authority_bridge::BridgeError as E;
    let outcome = match error {
        E::Binding => Outcome::BridgeBinding,
        E::Conflict => Outcome::BridgeConflict,
        E::Missing => Outcome::BridgeMissing,
        E::Uncertain => Outcome::BridgeUncertain,
        E::Limit => Outcome::BridgeLimit,
        E::Permission => Outcome::BridgePermission,
        E::RecoveryRequired => Outcome::BridgeRecoveryRequired,
        E::CompleteOriginRecoveryUnavailable => Outcome::BridgeCompleteOriginRecoveryUnavailable,
        E::Verification => Outcome::BridgeVerification,
        E::SignerOriginUnavailable => Outcome::BridgeSignerOriginUnavailable,
        E::Journal(_) => Outcome::BridgeJournal,
        E::Authority(_) => Outcome::BridgeAuthority,
        E::Wallet(_) => Outcome::BridgeWallet,
        E::Ipc => Outcome::BridgeIpc,
    };
    diagnostic::emit(boundary, outcome);
    Error::Receipt("exact delivery bridge refused or uncertain".into())
}
fn witness_error(boundary: B, error: wholepact_authority::AuthorityError) -> Error {
    diagnostic::emit(boundary, diagnostic::authority_error(&error));
    Error::Receipt("exact original delivery witness refused or uncertain".into())
}
fn done(worker: &worker::JoinedSignerWorkerV1, index: usize) -> Result<()> {
    match worker.receive().map_err(worker_error)? {
        R::Done { index: actual } if actual == index => Ok(()),
        _ => Err(Error::Authentication),
    }
}
fn at<T>(boundary: B, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    diagnostic::host(boundary, operation)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderCompletionV2 {
    schema: u8,
    fixed_verified: bool,
    exact_fixed_prefix_preserved: bool,
    exact_export_history_preserved: bool,
    exact_original_scopes_preserved: bool,
    exact_original_intents_preserved: bool,
    authenticated_histories_verified: bool,
    unsupported_actions_denied: bool,
    reader_no_effects_verified: bool,
}
impl ReaderCompletionV2 {
    fn verified(&self) -> bool {
        self.schema == 2
            && self.fixed_verified
            && self.exact_fixed_prefix_preserved
            && self.exact_export_history_preserved
            && self.exact_original_scopes_preserved
            && self.exact_original_intents_preserved
            && self.authenticated_histories_verified
            && self.unsupported_actions_denied
            && self.reader_no_effects_verified
    }
    fn read_after_reap(root: &Path) -> io::Result<Self> {
        let row: Self = read_record(root, READER_FILE)?;
        if !row.verified() {
            return Err(invalid());
        }
        Ok(row)
    }
    fn write_once(&self, root: &Path) -> io::Result<()> {
        if !self.verified() {
            return Err(invalid());
        }
        write_record(root, READER_FILE, self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOutcomeV2 {
    schema: u8,
    phase: String,
    result: String,
    first_failure: Option<String>,
    producer_exit: String,
    producer_reaped: bool,
    producer_group_absent: bool,
    reader_exit: String,
    reader_reaped: bool,
    reader_group_absent: bool,
    root_cleanup: String,
    admission_count: String,
    fixed_verified: bool,
    exact_fixed_prefix_preserved: bool,
    exact_export_history_preserved: bool,
    exact_original_scopes_preserved: bool,
    exact_original_intents_preserved: bool,
    authenticated_histories_verified: bool,
    unsupported_actions_denied: bool,
    reader_no_effects_verified: bool,
    authorization_allowed: bool,
    distribution_allowed: bool,
    public_chain_verified: bool,
}
impl PublicOutcomeV2 {
    fn pending() -> Self {
        Self {
            schema: 2,
            phase: "durable_delivery_admission".into(),
            result: "failed".into(),
            first_failure: None,
            producer_exit: "unverified".into(),
            producer_reaped: false,
            producer_group_absent: false,
            reader_exit: "not_started".into(),
            reader_reaped: false,
            reader_group_absent: false,
            root_cleanup: "unverified".into(),
            admission_count: "unverified".into(),
            fixed_verified: false,
            exact_fixed_prefix_preserved: false,
            exact_export_history_preserved: false,
            exact_original_scopes_preserved: false,
            exact_original_intents_preserved: false,
            authenticated_histories_verified: false,
            unsupported_actions_denied: false,
            reader_no_effects_verified: false,
            authorization_allowed: false,
            distribution_allowed: false,
            public_chain_verified: false,
        }
    }
    fn fail(&mut self, boundary: &'static str) {
        if self.first_failure.is_none() && BOUNDARIES.contains(&boundary) {
            self.first_failure = Some(boundary.into());
        }
        self.result = "failed".into();
    }
    fn verified(&self) -> bool {
        self.first_failure.is_none()
            && self.producer_exit == "sigkill"
            && self.producer_reaped
            && self.producer_group_absent
            && self.reader_exit == "success"
            && self.reader_reaped
            && self.reader_group_absent
            && self.root_cleanup == "closed_absent"
            && self.admission_count == "2_of_2"
            && self.fixed_verified
            && self.exact_fixed_prefix_preserved
            && self.exact_export_history_preserved
            && self.exact_original_scopes_preserved
            && self.exact_original_intents_preserved
            && self.authenticated_histories_verified
            && self.unsupported_actions_denied
            && self.reader_no_effects_verified
            && !self.authorization_allowed
            && !self.distribution_allowed
            && !self.public_chain_verified
    }
    fn public_json(&self) -> io::Result<String> {
        if self.schema != 2
            || self.phase != "durable_delivery_admission"
            || !["passed", "failed"].contains(&self.result.as_str())
            || self
                .first_failure
                .as_ref()
                .is_some_and(|name| !BOUNDARIES.contains(&name.as_str()))
            || !["sigkill", "other", "unverified"].contains(&self.producer_exit.as_str())
            || !["success", "other", "not_started", "unverified"]
                .contains(&self.reader_exit.as_str())
            || !["closed_absent", "retained", "unverified"].contains(&self.root_cleanup.as_str())
            || !["unverified", "0_of_2", "1_of_2", "2_of_2"]
                .contains(&self.admission_count.as_str())
            || self.authorization_allowed
            || self.distribution_allowed
            || self.public_chain_verified
            || (self.reader_exit == "not_started"
                && (self.reader_reaped || self.reader_group_absent))
            || (self.result == "passed" && !self.verified())
            || (self.result == "failed" && self.first_failure.is_none())
        {
            return Err(invalid());
        }
        let json = serde_json::to_string(self).map_err(|_| invalid())?;
        if json.len() > 2048 {
            return Err(invalid());
        }
        Ok(json)
    }
}

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn death_marker_v2(
    tail: &str,
    producer: bool,
    inputs_complete: bool,
    terminal: bool,
) -> io::Result<bool> {
    if tail
        .split_inclusive('\n')
        .any(|line| line.trim_end_matches(['\r', '\n']) == "SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1")
    {
        return Err(invalid());
    }
    let count = tail
        .split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .filter(|line| {
            line.trim_end_matches('\n')
                .strip_suffix('\r')
                .unwrap_or(line.trim_end_matches('\n'))
                == DEATH_MARKER
        })
        .count();
    if count > 1 || (count == 1 && (!producer || !inputs_complete)) {
        return Err(invalid());
    }
    if terminal {
        let remainder = tail.rsplit_once('\n').map_or(tail, |(_, rest)| rest);
        if !remainder.is_empty()
            && (DEATH_MARKER.starts_with(remainder) || remainder.starts_with(DEATH_MARKER))
        {
            return Err(invalid());
        }
        if count != 1 {
            return Err(invalid());
        }
    }
    Ok(count == 1)
}
fn monotonic_now_ns() -> io::Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = unsafe { value.assume_init() };
    let seconds: u64 = value.tv_sec.try_into().map_err(|_| invalid())?;
    let nanos: u64 = value.tv_nsec.try_into().map_err(|_| invalid())?;
    if nanos >= 1_000_000_000 {
        return Err(invalid());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or_else(invalid)
}
fn first_failure(summary: &str, fallback: &'static str) -> &'static str {
    for entry in summary.split(',') {
        let mut parts = entry.split(':');
        if let (Some(boundary), Some(outcome)) = (parts.next(), parts.next()) {
            if outcome != "Begin" && outcome != "Complete" {
                if let Some(name) = BOUNDARIES.iter().find(|name| **name == boundary) {
                    return name;
                }
            }
        }
    }
    fallback
}
fn committed_count(root: &Path) -> io::Result<&'static str> {
    let mut committed = Vec::new();
    for name in OWNER_FILES {
        match read_record::<DurableDeliveryAdmissionStatusV2>(root, name) {
            Ok(status) if status.validate().is_ok() && status.witness_committed => {
                committed.push(status)
            }
            Ok(_) => return Err(invalid()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    if committed.len() == 2
        && (committed[0].scope.authorization.identity.account_id
            == committed[1].scope.authorization.identity.account_id
            || committed[0].scope.delivery != committed[1].scope.delivery)
    {
        return Err(invalid());
    }
    Ok(match committed.len() {
        0 => "unverified",
        1 => "1_of_2",
        2 => "2_of_2",
        _ => return Err(invalid()),
    })
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; actual native two-owner admission and process-death reopening"]
fn durable_delivery_native_admission_reopens_original_after_process_death() {
    run_two_processes_v2().expect("same original fixed/material source and exact two-owner prospective admission survive verified death and independent original reopening; all financial actions denied");
}
fn run_two_processes_v2() -> io::Result<()> {
    process_containment_v1::require_and_report_core_policy()?;
    let deadline = Instant::now() + WORKFLOW_LIMIT;
    let cutoff = monotonic_now_ns()?
        .checked_add(
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos()
                .try_into()
                .map_err(|_| invalid())?,
        )
        .ok_or_else(invalid)?;
    let mut public = PublicOutcomeV2::pending();
    let mut root = Some(
        tempfile::Builder::new()
            .prefix(CHILD_TEMPORARY_PREFIX)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?,
    );
    let workflow = (|| -> io::Result<()> {
        owned_test_process_group_v1::require_default_child_wait_policy().map_err(|error| {
            public.fail("PrivateWorkspaceBootstrap");
            if let Some(root) = root.take() {
                let _ = root.keep();
            }
            public.root_cleanup = "retained".into();
            error
        })?;
        let tls =
            synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(root.as_ref().unwrap().path())
                .map_err(|error| {
                public.fail("PrivateWorkspaceBootstrap");
                if let Some(root) = root.take() {
                    let _ = root.keep();
                }
                public.root_cleanup = "retained".into();
                error
            })?;
        let mut producer = private_workspace_stage_v1(
            root.take().unwrap(),
            Some(&tls),
            PrivateWorkspaceStageV1::DeliveryProducer,
            &producer_inputs(),
            deadline,
            cutoff,
        )
        .map_err(|error| {
            public.fail("PrivateWorkspaceBootstrap");
            public.root_cleanup = "retained".into();
            error
        })?;
        drop(tls);
        public.producer_reaped =
            producer.process.direct_child == owned_test_process_group_v1::DirectChildV1::Reaped;
        public.producer_group_absent = producer.process.group_absence
            == owned_test_process_group_v1::GroupAbsenceV1::OriginalGroupAbsentObserved;
        public.producer_exit = if producer
            .process
            .status
            .as_ref()
            .is_some_and(|status| status.signal() == Some(libc::SIGKILL))
        {
            "sigkill"
        } else if producer.process.status.is_some() {
            "other"
        } else {
            "unverified"
        }
        .into();
        root = producer.root.take();
        if producer.process.verified() {
            if let Some(root) = &root {
                public.admission_count = committed_count(root.path())?.into();
            }
        }
        if producer.outcome.is_err() {
            public.fail(first_failure(&producer.summary, "DeliveryDurableMarker"));
            return Err(invalid());
        }
        if !producer.process.verified()
            || producer.process.group_signal
                != owned_test_process_group_v1::GroupSignalV1::SentWhileLeaderOwned
            || public.producer_exit != "sigkill"
        {
            public.fail("DeliveryProducerReap");
            return Err(invalid());
        }
        diagnostic::emit(B::DeliveryProducerKill, Outcome::Complete);
        diagnostic::emit(B::DeliveryProducerReap, Outcome::Complete);
        if Instant::now() >= deadline {
            public.fail("DeliveryOriginalReopen");
            return Err(invalid());
        }
        let _ready = ReadyControlV2::read_original(root.as_ref().ok_or_else(invalid)?.path())
            .map_err(|error| {
                public.fail("DeliveryDurableMarker");
                error
            })?;
        let mut reader = private_workspace_stage_v1(
            root.take().unwrap(),
            None,
            PrivateWorkspaceStageV1::DeliveryReader,
            &reader_inputs(),
            deadline,
            cutoff,
        )
        .map_err(|error| {
            public.fail("DeliveryOriginalReopen");
            public.root_cleanup = "retained".into();
            error
        })?;
        public.reader_reaped =
            reader.process.direct_child == owned_test_process_group_v1::DirectChildV1::Reaped;
        public.reader_group_absent = reader.process.group_absence
            == owned_test_process_group_v1::GroupAbsenceV1::OriginalGroupAbsentObserved;
        public.reader_exit = if reader
            .process
            .status
            .as_ref()
            .is_some_and(|status| status.success())
        {
            "success"
        } else if reader.process.status.is_some() {
            "other"
        } else {
            "unverified"
        }
        .into();
        root = reader.root.take();
        if reader.outcome.is_err() {
            public.fail(first_failure(&reader.summary, "DeliveryHistoricalRead"));
            return Err(invalid());
        }
        if !reader.process.verified()
            || public.reader_exit != "success"
            || Instant::now() >= deadline
        {
            public.fail("DeliveryReaderReap");
            return Err(invalid());
        }
        let checked =
            ReaderCompletionV2::read_after_reap(root.as_ref().ok_or_else(invalid)?.path())
                .map_err(|error| {
                    public.fail("DeliveryIdentityCompare");
                    error
                })?;
        public.fixed_verified = checked.fixed_verified;
        public.exact_fixed_prefix_preserved = checked.exact_fixed_prefix_preserved;
        public.exact_export_history_preserved = checked.exact_export_history_preserved;
        public.exact_original_scopes_preserved = checked.exact_original_scopes_preserved;
        public.exact_original_intents_preserved = checked.exact_original_intents_preserved;
        public.authenticated_histories_verified = checked.authenticated_histories_verified;
        public.unsupported_actions_denied = checked.unsupported_actions_denied;
        public.reader_no_effects_verified = checked.reader_no_effects_verified;
        diagnostic::emit(B::DeliveryReaderReap, Outcome::Complete);
        Ok(())
    })();
    diagnostic::emit(B::DeliveryRootCleanup, Outcome::Begin);
    if let Some(root) = root.take() {
        public.root_cleanup = match close_owned_temporary_root(root) {
            TemporaryRootCleanupV1::ClosedAndAbsenceVerified => "closed_absent",
            TemporaryRootCleanupV1::RetainedForUnverifiedProcess => "retained",
            TemporaryRootCleanupV1::CloseOrAbsenceUnverified => "unverified",
        }
        .into();
    } else if public.root_cleanup == "unverified" {
        public.root_cleanup = "retained".into();
    }
    if public.root_cleanup != "closed_absent" {
        public.fail("DeliveryRootCleanup");
    } else {
        diagnostic::emit(B::DeliveryRootCleanup, Outcome::Complete);
    }
    if workflow.is_err() && public.first_failure.is_none() {
        public.fail("DeliveryNativeAdmission");
    }
    if workflow.is_ok() && public.verified() {
        public.result = "passed".into();
    } else if public.first_failure.is_none() {
        public.fail("DeliveryIdentityCompare");
    }
    eprintln!("{PUBLIC_PREFIX}{}", public.public_json()?);
    if public.result == "passed" {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn directory(root: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid());
    }
    Ok(directory)
}
fn file(directory: &File, name: &[u8], flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr().cast(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn check_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_CONTROL
    {
        return Err(invalid());
    }
    Ok(())
}
fn write_record(root: &Path, name: &[u8], value: &impl Serialize) -> io::Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| invalid())?);
    if bytes.len() as u64 > MAX_CONTROL {
        return Err(invalid());
    }
    let directory = directory(root)?;
    let mut file = file(
        &directory,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    check_file(&file)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    directory.sync_all()
}
fn read_record<T: serde::de::DeserializeOwned>(root: &Path, name: &[u8]) -> io::Result<T> {
    let directory = directory(root)?;
    let file = file(&directory, name, libc::O_RDONLY)?;
    check_file(&file)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONTROL + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL {
        return Err(invalid());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

fn review(detail: &'static str) -> Input<'static> {
    Input::ExactReview {
        detail,
        approve: true,
    }
}
fn source_status_inputs(inputs: &mut Vec<Input<'static>>) {
    inputs.push(review(
        "Inspect original fixed-prefix and bounded admission-export history metadata",
    ));
    inputs.push(review(
        "Read exact original delivery-admission fixed source and append-only export history.",
    ));
}
fn producer_inputs() -> Vec<Input<'static>> {
    let mut inputs = private_fixed_v2::producer_inputs();
    inputs.pop(); // Only the old final death review, never a preparation step.
    for detail in [
        "Read exact current selected original source and complete historical terms for NONSPENDING private coordination.",
        "Open ONLY the exact initialized original private workspace.",
        "Inspect exact original private V3 stage metadata.",
        "Approve V3 private fixed stage ReadFixed.",
        "Store this exact new dispatcher credential only",
        "Inspect all original source/workspace/proof/financial/submission identities",
        "Authenticate the same final-v4 original workspace",
    ] {
        inputs.push(review(detail));
    }
    private_fixed_v2::session_inputs(&mut inputs, false);
    inputs.push(review(
        "Inspect original fixed-prefix and bounded admission-export history metadata",
    ));
    for _ in 0..2 {
        inputs.push(review("Request one native-approved redisclosure of this exact original material to this current paired recipient. No capture, reconstruction or validity renewal."));
        inputs.push(review(
            "Inspect original fixed-prefix and bounded admission-export history metadata",
        ));
        inputs.push(review(
            "Approve exact original delivery export and prospective admission request.",
        ));
    }
    source_status_inputs(&mut inputs);
    inputs.push(review("SYNTHETIC ORIGINAL DELIVERY: retain this exact admitted Host for controlled process death."));
    inputs
}
fn reader_inputs() -> Vec<Input<'static>> {
    let mut inputs = vec![
        Input::Text {
            prompt: "Storage passphrase: ",
            response: "synthetic-recovery-review-password",
        },
        Input::Text {
            prompt: "Original primary financial passphrase: ",
            response: "synthetic-recovery-review-password",
        },
        review("Authenticate the same final-v4 original workspace"),
    ];
    private_fixed_v2::session_inputs(&mut inputs, true);
    source_status_inputs(&mut inputs);
    source_status_inputs(&mut inputs);
    inputs
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyControlV2 {
    schema: u8,
    profile: PathBuf,
    workspace: PathBuf,
    financial: PathBuf,
    fixed_prefix_digest: String,
    full_fixed_status_digest: String,
    export_history_digest: String,
    originals: [worker::DeliveryReopenV2; 2],
    witness_reopen: Vec<u8>,
    admissions: [DurableDeliveryAdmissionStatusV2; 2],
}
impl ReadyControlV2 {
    fn validate(&self, root: &Path) -> io::Result<()> {
        if self.schema != 2
            || self.witness_reopen.is_empty()
            || self.witness_reopen.len() > 256 * 1024
            || !hash(&self.fixed_prefix_digest)
            || !hash(&self.full_fixed_status_digest)
            || !hash(&self.export_history_digest)
            || self
                .originals
                .iter()
                .filter(|s| s.original_directory_preserved)
                .count()
                != 1
        {
            return Err(invalid());
        }
        for path in [
            &self.profile,
            &self.workspace,
            &self.financial,
            &self.originals[0].root,
            &self.originals[1].root,
        ] {
            let relative = path.strip_prefix(root).map_err(|_| invalid())?;
            if !path.is_absolute()
                || path.as_os_str().len() > 4096
                || relative.as_os_str().is_empty()
                || !relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err(invalid());
            }
        }
        if self.profile == self.workspace
            || self.profile == self.financial
            || self.workspace == self.financial
            || self.originals[0].root == self.originals[1].root
            || self.originals[0].root.parent() != self.originals[1].root.parent()
        {
            return Err(invalid());
        }
        for (original, admission) in self.originals.iter().zip(&self.admissions) {
            if original.version != 2
                || original.account_id != admission.scope.authorization.identity.account_id
                || original.owner_setup_json.is_empty()
                || original.owner_setup_json.len() > 64 * 1024
                || !admission.witness_committed
                || admission.version != 2
                || admission.validate().is_err()
                || admission.scope.accepted_manifest_ref != admission.original_accepted_manifest_ref
            {
                return Err(invalid());
            }
        }
        if self.admissions[0].scope.authorization.identity.account_id
            == self.admissions[1].scope.authorization.identity.account_id
            || self.admissions[0].scope.delivery != self.admissions[1].scope.delivery
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn write_once(&self, root: &Path) -> io::Result<()> {
        self.validate(root)?;
        write_record(root, READY_FILE, self)
    }
    fn read_original(root: &Path) -> io::Result<Self> {
        let record: Self = read_record(root, READY_FILE)?;
        record.validate(root)?;
        Ok(record)
    }
}
fn observe_delivery(
    site: crate::host::financial::durable_delivery_admission_v2::DeliveryObservationSiteV2,
    outcome: crate::host::financial::durable_delivery_admission_v2::DeliveryObservationOutcomeV2,
) {
    use crate::host::financial::durable_delivery_admission_v2::{
        DeliveryObservationSiteV2 as S, DeliveryObservationOutcomeV2 as O,
    };
    let boundary = match site {
        S::FixedRead => B::DeliveryHistoricalRead,
        S::SourceInspection | S::ExportPreview | S::ExportCommit | S::ExportPostcheck => {
            B::DeliverySourceExport
        }
    };
    let outcome = match outcome {
        O::ReturnedOk => Outcome::Complete,
        O::EngineDisclosureUnknown => Outcome::EngineDisclosureUnknown,
        O::EngineDisclosureDenied => Outcome::EngineDisclosureDenied,
        O::EngineRecoveryRequired => Outcome::EngineRecoveryRequired,
        O::EngineIdempotencyConflict => Outcome::EngineIdempotencyConflict,
        O::EngineRevisionConflict => Outcome::EngineRevisionConflict,
        O::EngineDurableProposalConflict => Outcome::EngineDurableProposalConflict,
        O::EngineDurableConstructionUnavailable => Outcome::EngineDurableConstructionUnavailable,
        O::EngineDurableProfileUnavailable => Outcome::EngineDurableProfileUnavailable,
        O::EngineResourceExhausted => Outcome::EngineResourceExhausted,
        O::EngineUnclassified => Outcome::EngineUnclassified,
        O::HostPermission => Outcome::HostPermission,
        O::HostTerminal => Outcome::HostTerminal,
        O::HostAuthentication => Outcome::HostAuthentication,
        O::HostUnclassified => Outcome::WorkerFailure,
    };
    diagnostic::emit(boundary, outcome);
}

fn pair_owner(
    signers: &worker::JoinedSignerWorkerV1,
    index: usize,
    delivery: bool,
) -> Result<OriginalHistoryClient> {
    let (peer, scope) = match signers.receive().map_err(worker_error)? {
        R::DurablePeer {
            index: actual,
            peer,
            scope,
            ..
        } if actual == index => (peer, scope),
        _ => return Err(Error::Authentication),
    };
    if Instant::now() >= peer.deadline {
        return Err(Error::Permission);
    }
    signers
        .send(if delivery {
            C::PollDeliveryPair(index)
        } else {
            C::PollDurablePair(index)
        })
        .map_err(worker_error)?;
    let client = OriginalHistoryClient::pair(
        peer.provider,
        &peer.endpoint,
        "Synthetic-original-delivery-admission",
        scope,
    )
    .map_err(bridge_error)?;
    done(signers, index)?;
    Ok(client)
}
fn audit_host_denials(host: &Host) -> Result<()> {
    if host.require_financial_generation_admission().is_ok() {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Inert correlation copied only from the successful actual original capture.
/// This cannot open a source or authorize a current recipient.
pub(super) struct OriginalDisclosureV2 {
    pub account_id: String,
    pub history: DurableConstructionHistoryRequestV1,
    pub scope: DurableConstructionScopeV1,
    pub material_digest: String,
    pub outbox_reference: String,
}

/// This continuation consumes only the actual completed predecessor's owners.
/// No successful fixture, receipt DTO or replacement proof can enter here.
pub(super) fn continue_completed_original(
    terminal: crate::terminal::Terminal,
    host: Host,
    mut original: initial::PrivateWorkspaceInitialV1,
    fixed: wholepact_engine::PrivateVerifiedFixedV2,
    proposal: wholepact_core::ProposalInput,
    runtime: tokio::runtime::Runtime,
    provider: synthetic_born_provider_v1::SyntheticBornProviderV1,
    profile: PathBuf,
    workspace: PathBuf,
    financial: PathBuf,
    disclosures: Vec<OriginalDisclosureV2>,
    provider_identity: wholepact_chain::BackendIdentity,
) -> Result<()> {
    crate::host::financial::durable_delivery_admission_v2::with_delivery_observer_v2(
        observe_delivery,
        || {
            let scenario = scenario_root()?;
            if fixed.state != "succeeded"
                || fixed.attempt != 1
                || !fixed.proof_verified
                || fixed.authorization_allowed
                || disclosures.len() != 2
            {
                return Err(Error::Authentication);
            }
            let fixed_prefix_digest = digest(&fixed)?;
            // All actual proof/cache work was completed before entry. Close the
            // original provider/runtime before any v4 vault publication.
            at(B::PrivateWorkspaceScanCleanup, || {
                runtime.block_on(provider.shutdown()).map_err(Error::from)
            })?;
            drop(runtime);
            drop(fixed);
            let origin = original
                .witness
                .origin()
                .map_err(|_| Error::Authentication)?;
            let roots = crate::files::read_private(&origin.trusted_server_root_file, 16 * 1024)?;
            let credentials =
                dedicated_dispatcher_credentials(&scenario, &original.born[1..], roots)?;
            drop(origin);
            let mut clients = Vec::with_capacity(2);
            for index in 1..=2 {
                original
                    .signers
                    .send(C::OpenDurable(index, proposal.clone()))
                    .map_err(worker_error)?;
                clients.push(pair_owner(&original.signers, index, false)?);
            }
            let stop = Arc::new(AtomicBool::new(false));
            original
                .signers
                .send(C::ServeOriginalEvidence(stop.clone()))
                .map_err(worker_error)?;
            let registered = at(B::DeliveryCredentialRegistration, || {
                host.register_workspace_dispatcher_v4(&workspace, credentials, clients, PASSWORD)
            });
            stop.store(true, Ordering::Release);
            let stopped = done(&original.signers, 0);
            registered?;
            stopped?;
            for index in 1..=2 {
                original
                    .signers
                    .send(C::CloseDurable(index))
                    .map_err(worker_error)?;
                done(&original.signers, index)?;
            }
            at(B::DeliveryCredentialRegistration, || {
                crate::host::durable_dispatcher_v2::finish_workspace_dispatcher_publication_v4(
                    &terminal, &profile, &workspace, PASSWORD, PASSWORD,
                )
            })?;
            terminal.message(&format!(
                "SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",
                scenario
                    .join("delivery-producer-v4-session.token")
                    .display()
            ))?;
            let host = at(B::DeliveryOriginalReopen, || {
                Host::open_workspace_dispatcher_with_passwords_v4(
                    terminal.clone(),
                    &profile,
                    &workspace,
                    PASSWORD,
                    PASSWORD,
                )
            })?;
            let identity = {
                let owner = host.original_delivery_admission_owner_v2(&workspace)?;
                let inspected = owner
                    .coordinator()
                    .inspect_original_for_admission_v2(host.access()?, &owner)?;
                inspected.fixed_identity().clone()
            };
            let choices=crate::host::financial::durable_delivery_admission_v2::DeliveryChoicesV2 {
            submission_operation_id:"synthetic-original-delivery-admission-v2".into(),
            provider:wholepact_core::manual_construction::PreconstructionProvider {source_id:provider_identity.source_id,endpoint:provider_identity.endpoint,trust_profile:provider_identity.trust_profile.into()},
            route:wholepact_authority::durable_delivery_scope_v2::DurableDeliveryRouteV2::Direct {},
            minimum_expiry_margin_blocks:1,maximum_fresh_admission_lifetime_ms:120_000,maximum_explicitly_approved_attempts:1,
        };
            let mut admissions = Vec::with_capacity(2);
            let mut preserved = Vec::with_capacity(2);
            original
                .signers
                .send(C::DropUnselectedAnchor(0))
                .map_err(worker_error)?;
            done(&original.signers, 0)?;
            for index in 1..=2 {
                let account = &original.born[index];
                original
                    .signers
                    .send(C::OpenDelivery(index, proposal.clone()))
                    .map_err(worker_error)?;
                let client = pair_owner(&original.signers, index, true)?;
                original
                    .signers
                    .send(C::AcceptDelivery(index))
                    .map_err(worker_error)?;
                let records = match original.signers.receive().map_err(worker_error)? {
                    R::Records {
                        index: actual,
                        records,
                    } if actual == index => records,
                    _ => return Err(Error::Authentication),
                };
                original
                    .signers
                    .send(C::ConfigureDeliveryWitness(index))
                    .map_err(worker_error)?;
                done(&original.signers, index)?;
                let original_disclosure = disclosures
                    .iter()
                    .find(|source| source.account_id == account.account_id)
                    .ok_or(Error::Authentication)?;
                let own_disclosure = original_disclosure.history.clone();
                let redisclosure_request = DurableConstructionRedisclosureRequestV1 {
                    operation_id: format!("synthetic-original-current-recipient-v2-{index}"),
                    original: DurableConstructionRedisclosureSourceV1 {
                        operation_id: own_disclosure.operation_id.clone(),
                        expected_request_digest: Some(
                            own_disclosure.expected_request_digest.clone(),
                        ),
                    },
                    enrollment_ref: records.enrollment_ref.clone(),
                    accepted_manifest_ref: records.accepted_manifest_ref.clone(),
                };
                let review = terminal.approve_historical(&format!("Request one native-approved redisclosure of this exact original material to this current paired recipient. No capture, reconstruction or validity renewal.\nOriginal immutable scope: {}\nOriginal material digest: {}\nExact current-recipient request: {}",serde_json::to_string_pretty(&original_disclosure.scope)?,original_disclosure.material_digest,serde_json::to_string_pretty(&redisclosure_request)?))?;
                review.check()?;
                let stop = Arc::new(AtomicBool::new(false));
                original
                    .signers
                    .send(C::PollDeliveryRedisclosure(
                        index,
                        redisclosure_request.clone(),
                        stop.clone(),
                    ))
                    .map_err(worker_error)?;
                let received = at(B::DeliverySourceExport, || {
                    client
                        .redisclose_durable_construction_v1(&redisclosure_request)
                        .map_err(|error| bridge_error_at(B::DeliverySourceExport, error))
                });
                stop.store(true, Ordering::Release);
                let stopped = done(&original.signers, index);
                let received = received?;
                stopped?;
                let outbox = received.outbox();
                let link = outbox.redisclosure().ok_or(Error::Authentication)?;
                // The returned value is the actual authenticated current-peer
                // response, not a reconstructed DTO. Normalize only the new
                // recipient grant; every original audience/material/clock field
                // must still match the completed capture byte-for-byte.
                let mut expected_scope = original_disclosure.scope.clone();
                expected_scope.constructor.authenticated_local_grant_digest =
                    outbox.recipient_grant_digest().into();
                expected_scope.prover.authenticated_local_grant_digest =
                    outbox.recipient_grant_digest().into();
                if outbox.request().operation_id != redisclosure_request.operation_id
                    || outbox.request().enrollment_ref != records.enrollment_ref
                    || outbox.request().accepted_manifest_ref != records.accepted_manifest_ref
                    || outbox.request().scope != expected_scope
                    || outbox.material_digest() != original_disclosure.material_digest
                    || link.original_operation_id != own_disclosure.operation_id
                    || link.original_request_digest != own_disclosure.expected_request_digest
                    || link.original_outbox_reference != original_disclosure.outbox_reference
                {
                    return Err(Error::Authentication);
                }
                let current_disclosure = DurableConstructionHistoryRequestV1 {
                    operation_id: outbox.request().operation_id.clone(),
                    expected_request_digest: outbox.request_digest().into(),
                };
                drop(received);
                let request = DurableReviewDeliveryRequestV1 {
                    operation_id: format!("synthetic-original-delivery-export-v2-{index}"),
                    enrollment_ref: records.enrollment_ref,
                    accepted_manifest_ref: records.accepted_manifest_ref,
                    own_disclosure,
                    current_disclosure: Some(current_disclosure),
                    proposal_binding: identity.proposal_binding.clone(),
                };
                original
                    .signers
                    .send(C::PollDeliveryImport(
                        index,
                        request.clone(),
                        identity.clone(),
                    ))
                    .map_err(worker_error)?;
                let exported = at(B::DeliverySourceExport, || {
                    host.private_original_delivery_export_v2(&workspace, &client, request, &choices)
                })?;
                done(&original.signers, index)?;
                // The original independent witness serves the pristine bootstrap
                // only while the signer derives its genuine pending native review.
                let history = original
                    .witness
                    .serve_original_delivery_bootstrap_history_v2(&account.account_id)
                    .map_err(|error| witness_error(B::DeliveryHistoricalRead, error))?;
                original
                    .signers
                    .send(C::PollDeliveryAdmission(index, exported.request.clone()))
                    .map_err(worker_error)?;
                let status =
                    std::thread::scope(|scope| -> Result<DurableDeliveryAdmissionStatusV2> {
                        let exchange = scope.spawn(|| {
                            client.request_durable_delivery_admission_v2(&exported.request)
                        });
                        let request = match original.signers.receive().map_err(worker_error)? {
                            R::DurableAdmissionRequest {
                                index: actual,
                                request,
                            } if actual == index => request,
                            _ => return Err(Error::Authentication),
                        };
                        drop(history);
                        at(B::DeliveryNativeAdmission, || {
                            original
                                .witness
                                .start_exact_durable_delivery_admission_v2(
                                    &account.account_id,
                                    &request,
                                )
                                .map_err(|error| witness_error(B::DeliveryNativeAdmission, error))
                        })?;
                        original
                            .signers
                            .send(C::ApproveDelivery(index))
                            .map_err(worker_error)?;
                        done(&original.signers, index)?;
                        original
                            .signers
                            .send(C::AwaitDeliveryResponse(index))
                            .map_err(worker_error)?;
                        at(B::DeliveryNativeAdmission, || {
                            original
                                .witness
                                .finish_exact_durable_delivery_admission_v2()
                                .map_err(|error| witness_error(B::DeliveryNativeAdmission, error))
                        })?;
                        done(&original.signers, index)?;
                        // The owner response is an inert unaudited intermediate,
                        // never a verified status. Establish the real original
                        // read-only listener BEFORE invoking the production
                        // one-time history continuation. The original admission
                        // IPC stream stays held throughout, with its old cutoff.
                        let committed_history = original
                            .witness
                            .serve_committed_durable_delivery_history_v2(&request.operation_id)
                            .map_err(|error| witness_error(B::DeliveryHistoricalRead, error))?;
                        original
                            .signers
                            .send(C::AwaitDeliveryAudit(index))
                            .map_err(worker_error)?;
                        let native = match original.signers.receive().map_err(worker_error)? {
                            R::DeliveryStatus {
                                index: actual,
                                status,
                            } if actual == index => status,
                            _ => return Err(Error::Authentication),
                        };
                        let returned = exchange
                            .join()
                            .map_err(|_| Error::Authentication)?
                            .map_err(bridge_error)?;
                        drop(committed_history);
                        if native != returned {
                            return Err(Error::Authentication);
                        }
                        Ok(returned)
                    })?;
                crate::host::financial::durable_delivery_admission_v2::validate_admission_result_v2(&exported,&status)?;
                write_record(&scenario, OWNER_FILES[index - 1], &status)?;
                at(B::DeliveryUnsupportedAudit, || {
                    original
                        .witness
                        .require_durable_delivery_financial_denials_v2(&status.request.operation_id)
                        .map_err(|error| witness_error(B::DeliveryUnsupportedAudit, error))
                })?;
                original
                    .signers
                    .send(C::AuditDeliveryDenials(index))
                    .map_err(worker_error)?;
                done(&original.signers, index)?;
                drop(client);
                original
                    .signers
                    .send(C::PreserveDelivery(index))
                    .map_err(worker_error)?;
                let selector = match original.signers.receive().map_err(worker_error)? {
                    R::DeliveryPreserved {
                        index: actual,
                        original,
                    } if actual == index => original,
                    _ => return Err(Error::Authentication),
                };
                admissions.push(status);
                preserved.push(selector);
            }
            let status = at(B::DeliveryHistoricalRead, || {
                host.private_original_delivery_status_v2(&workspace)
            })?;
            if digest(&status.fixed)? != fixed_prefix_digest
                || status.export_count != 2
                || !status.fixed.proof_verified
            {
                return Err(Error::Authentication);
            }
            at(B::DeliveryUnsupportedAudit, || audit_host_denials(&host))?;
            let full_fixed_status_digest = digest(&status)?;
            let export_history_digest = status.export_history_digest.clone();
            drop(status);
            original.signers.shutdown().map_err(worker_error)?;
            let witness_reopen = original
                .witness
                .preserve_durable_delivery_originals_v2()
                .map_err(|error| witness_error(B::DeliveryHistoricalRead, error))?;
            let ready = ReadyControlV2 {
                schema: 2,
                profile,
                workspace,
                financial,
                fixed_prefix_digest,
                full_fixed_status_digest,
                export_history_digest,
                originals: preserved.try_into().map_err(|_| Error::Authentication)?,
                witness_reopen,
                admissions: admissions.try_into().map_err(|_| Error::Authentication)?,
            };
            if Instant::now() >= private_fixed_v2::child_original_cutoff()? {
                return Err(Error::Permission);
            }
            let approval=terminal.approve_historical("SYNTHETIC ORIGINAL DELIVERY: retain this exact admitted Host for controlled process death. Both genuine native admissions and exact original export history are retained. All transient signer, witness, provider and proof workers are closed. No signature, financial execution or dispatch is authorized.")?;
            approval.effect(&mut || {
                ready.write_once(&scenario)?;
                Ok(())
            })?;
            diagnostic::emit(B::DeliveryDurableMarker, Outcome::Complete);
            terminal.message(&format!("{DEATH_MARKER}\n"))?;
            let _keep_actual_originals = (&host, &original.temporary);
            loop {
                std::thread::park();
            }
        },
    )
}

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn read_delivery_child(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    crate::host::financial::durable_delivery_admission_v2::with_delivery_observer_v2(
        observe_delivery,
        || {
            let scenario = scenario_root()?;
            let ready = ReadyControlV2::read_original(&scenario)?;
            let original_cutoff = private_fixed_v2::child_original_cutoff()?;
            terminal.message(&format!(
                "SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",
                scenario.join("delivery-reader-v4-session.token").display()
            ))?;
            let host = at(B::DeliveryOriginalReopen, || {
                Host::open_workspace_dispatcher_registered_v4(
                    terminal,
                    &ready.profile,
                    &ready.workspace,
                    false,
                )
            })?;
            if host
                .financial
                .as_ref()
                .ok_or(Error::Locked)?
                .current_directory()?
                != ready.financial
            {
                return Err(Error::Authentication);
            }
            // Positive current-source equality is established ONLY by the genuine
            // original fixed/material reader while the original ceilings still hold.
            let before = at(B::DeliveryHistoricalRead, || {
                host.private_original_delivery_status_v2(&ready.workspace)
            })?;
            if before.export_count != 2
                || !before.fixed.proof_verified
                || before.fixed.authorization_allowed
                || digest(&before.fixed)? != ready.fixed_prefix_digest
                || digest(&before)? != ready.full_fixed_status_digest
                || before.export_history_digest != ready.export_history_digest
            {
                return Err(Error::Authentication);
            }
            let mut witness = at(B::DeliveryOriginalReopen, || {
                wholepact_authority::native_witness_owner::EphemeralNativeWitnessV1::reopen_durable_delivery_originals_v2(&ready.witness_reopen).map_err(|error|witness_error(B::DeliveryOriginalReopen,error))
            })?;
            let signers = worker::JoinedSignerWorkerV1::reopen_delivery(ready.originals.clone())
                .map_err(worker_error)?;
            for index in 1..=2 {
                let expected = &ready.admissions[index - 1];
                expected.validate().map_err(bridge_error)?;
                signers.send(C::DeliveryPeer(index)).map_err(worker_error)?;
                let client = pair_owner(&signers, index, true)?;
                signers
                    .send(C::ConfigureDeliveryWitness(index))
                    .map_err(worker_error)?;
                done(&signers, index)?;
                let server = witness
                    .serve_committed_durable_delivery_history_v2(&expected.request.operation_id)
                    .map_err(|error| witness_error(B::DeliveryHistoricalRead, error))?;
                let stop = Arc::new(AtomicBool::new(false));
                signers
                    .send(C::ServeDeliveryData(index, stop.clone()))
                    .map_err(worker_error)?;
                let observed = client.durable_delivery_admission_history_v2(
                    &DurableDeliveryHistoryRequestV2 {
                        authorization_id: expected.scope.authorization.authorization_id.clone(),
                    },
                );
                stop.store(true, Ordering::Release);
                let stopped = done(&signers, index);
                drop(server);
                let observed =
                    observed.map_err(|error| bridge_error_at(B::DeliveryHistoricalRead, error))?;
                stopped?;
                observed
                    .validate()
                    .map_err(|error| bridge_error_at(B::DeliveryHistoricalRead, error))?;
                // Compare the ENTIRE original scope, request, local intent/FKs and
                // authenticated complete history. No freshly accepted manifest or
                // remote-only hash can substitute for these original source joins.
                if &observed != expected {
                    return Err(Error::Authentication);
                }
                at(B::DeliveryUnsupportedAudit, || {
                    witness
                        .require_durable_delivery_financial_denials_v2(
                            &expected.request.operation_id,
                        )
                        .map_err(|error| witness_error(B::DeliveryUnsupportedAudit, error))
                })?;
                signers
                    .send(C::AuditDeliveryDenials(index))
                    .map_err(worker_error)?;
                done(&signers, index)?;
                drop(client);
                signers
                    .send(C::CloseDeliveryReader(index))
                    .map_err(worker_error)?;
                done(&signers, index)?;
            }
            signers.shutdown().map_err(worker_error)?;
            drop(witness);
            at(B::DeliveryUnsupportedAudit, || audit_host_denials(&host))?;
            let after = at(B::DeliveryHistoricalRead, || {
                host.private_original_delivery_status_v2(&ready.workspace)
            })?;
            if Instant::now() >= original_cutoff || digest(&before)? != digest(&after)? {
                return Err(Error::Authentication);
            }
            let completed = ReaderCompletionV2 {
                schema: 2,
                fixed_verified: after.fixed.proof_verified,
                exact_fixed_prefix_preserved: digest(&after.fixed)? == ready.fixed_prefix_digest,
                exact_export_history_preserved: after.export_history_digest
                    == ready.export_history_digest
                    && after.export_count == 2,
                exact_original_scopes_preserved: true,
                exact_original_intents_preserved: true,
                authenticated_histories_verified: true,
                unsupported_actions_denied: true,
                reader_no_effects_verified: digest(&after)? == ready.full_fixed_status_digest,
            };
            if !completed.verified() {
                return Err(Error::Authentication);
            }
            completed.write_once(&scenario)?;
            diagnostic::emit(B::DeliveryIdentityCompare, Outcome::Complete);
            drop(after);
            drop(before);
            drop(host);
            Ok(())
        },
    )
}

// Source-byte-identical reuse of the existing exact-child containment helper.
// Its super::super names resolve through durable_proposal_v1's existing private
// imports of the qualification owner's process and core-policy modules.
#[path = "../owned_tls_child_v1.rs"]
mod dispatcher_tls_child_v2;

fn dedicated_dispatcher_credentials(
    scenario: &Path,
    owners: &[worker::PublicJoinedBornV1],
    server_root: Vec<u8>,
) -> Result<crate::host::durable_dispatcher_v2::DispatcherCredentialsV2> {
    use crate::host::durable_dispatcher_v2::{DispatcherCredentialsV2, DispatcherRootsV2};
    use std::os::unix::fs::DirBuilderExt;
    if owners.len() != 2
        || owners[0].account_id == owners[1].account_id
        || server_root.is_empty()
        || server_root.len() > 16 * 1024
    {
        return Err(Error::Invalid);
    }
    let parent = directory(scenario)?;
    // A separate fixture identity, never either owner's/writer's key or the
    // provider/server fixture certificate. This is not a live enrolled client.
    let root = scenario.join("synthetic-original-dispatcher-client-v2");
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let deadline =
        private_fixed_v2::child_original_cutoff()?.min(Instant::now() + Duration::from_secs(20));
    let run = |arguments: &[&str]| -> Result<()> {
        let mut command = Command::new("openssl");
        command
            .current_dir(&root)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        dispatcher_tls_child_v2::run(command, deadline)?;
        Ok(())
    };
    // On every error leave the subtree to the outer owned-group controller.
    // No destructor can delete a key while a failed/unverified child owns it.
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=wholepact-synthetic-original-dispatcher-client-v2",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature",
        "-addext",
        "extendedKeyUsage=clientAuth",
        "-keyout",
        "dispatcher.pem",
        "-outform",
        "DER",
        "-out",
        "dispatcher.der",
    ])?;
    run(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        "dispatcher.pem",
        "-outform",
        "DER",
        "-out",
        "dispatcher.pk8",
    ])?;
    for name in ["dispatcher.pem", "dispatcher.der", "dispatcher.pk8"] {
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o600))?;
    }
    let client_chain_der = vec![crate::files::read_private(
        &root.join("dispatcher.der"),
        16 * 1024,
    )?];
    let private_key_pkcs8 = zeroize::Zeroizing::new(crate::files::read_private(
        &root.join("dispatcher.pk8"),
        16 * 1024,
    )?);
    let server_roots = owners
        .iter()
        .map(|owner| DispatcherRootsV2 {
            account_id: owner.account_id.clone(),
            roots_der: vec![server_root.clone()],
        })
        .collect();
    // Both exact children have actually completed and been reaped. Only now
    // remove their dedicated synthetic transient plaintext key files.
    for name in ["dispatcher.pem", "dispatcher.der", "dispatcher.pk8"] {
        std::fs::remove_file(root.join(name))?;
    }
    std::fs::remove_dir(&root)?;
    parent.sync_all()?;
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        _ => return Err(Error::Storage),
    }
    Ok(DispatcherCredentialsV2 {
        client_chain_der,
        private_key_pkcs8,
        server_roots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn passed() -> PublicOutcomeV2 {
        let mut r = PublicOutcomeV2::pending();
        r.result = "passed".into();
        r.producer_exit = "sigkill".into();
        r.producer_reaped = true;
        r.producer_group_absent = true;
        r.reader_exit = "success".into();
        r.reader_reaped = true;
        r.reader_group_absent = true;
        r.root_cleanup = "closed_absent".into();
        r.admission_count = "2_of_2".into();
        r.fixed_verified = true;
        r.exact_fixed_prefix_preserved = true;
        r.exact_export_history_preserved = true;
        r.exact_original_scopes_preserved = true;
        r.exact_original_intents_preserved = true;
        r.authenticated_histories_verified = true;
        r.unsupported_actions_denied = true;
        r.reader_no_effects_verified = true;
        r
    }
    #[test]
    fn delivery_result_requires_exact_two_owners_and_cleanup() {
        let row = passed();
        assert!(row.verified());
        assert!(row.public_json().unwrap().len() < 2048);
        for mutate in [
            |r: &mut PublicOutcomeV2| r.producer_exit = "other".into(),
            |r: &mut PublicOutcomeV2| r.producer_reaped = false,
            |r: &mut PublicOutcomeV2| r.producer_group_absent = false,
            |r: &mut PublicOutcomeV2| r.reader_reaped = false,
            |r: &mut PublicOutcomeV2| r.reader_group_absent = false,
            |r: &mut PublicOutcomeV2| r.root_cleanup = "retained".into(),
            |r: &mut PublicOutcomeV2| r.admission_count = "1_of_2".into(),
            |r: &mut PublicOutcomeV2| r.fixed_verified = false,
            |r: &mut PublicOutcomeV2| r.exact_fixed_prefix_preserved = false,
            |r: &mut PublicOutcomeV2| r.exact_export_history_preserved = false,
            |r: &mut PublicOutcomeV2| r.exact_original_scopes_preserved = false,
            |r: &mut PublicOutcomeV2| r.exact_original_intents_preserved = false,
            |r: &mut PublicOutcomeV2| r.authenticated_histories_verified = false,
            |r: &mut PublicOutcomeV2| r.unsupported_actions_denied = false,
            |r: &mut PublicOutcomeV2| r.reader_no_effects_verified = false,
            |r: &mut PublicOutcomeV2| r.authorization_allowed = true,
            |r: &mut PublicOutcomeV2| r.distribution_allowed = true,
            |r: &mut PublicOutcomeV2| r.public_chain_verified = true,
        ] {
            let mut row = passed();
            mutate(&mut row);
            assert!(!row.verified());
            assert!(row.public_json().is_err());
        }
    }
    #[test]
    fn delivery_result_is_typed_finite_and_first_failure_preserving() {
        let mut row = PublicOutcomeV2::pending();
        row.fail("DeliverySourceExport");
        row.fail("DeliveryRootCleanup");
        assert_eq!(row.first_failure.as_deref(), Some("DeliverySourceExport"));
        let json = row.public_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 23);
        for forbidden in [
            "path",
            "hash",
            "pczt",
            "password",
            "timestamp",
            "pid",
            "account_id",
        ] {
            assert!(!value.as_object().unwrap().contains_key(forbidden));
        }
        assert!(
            serde_json::from_str::<PublicOutcomeV2>(
                &(json.trim_end_matches('}').to_owned() + ",\"schema\":2}")
            )
            .is_err()
        );
        row.first_failure = Some("unbounded-private-error".into());
        assert!(row.public_json().is_err());
    }
    #[test]
    fn delivery_marker_is_complete_single_role_exact_and_not_precursor() {
        let line = format!("{DEATH_MARKER}\r\n");
        assert!(death_marker_v2(&line, true, true, true).unwrap());
        assert!(death_marker_v2(&line, false, true, false).is_err());
        assert!(death_marker_v2(&line, true, false, false).is_err());
        assert!(death_marker_v2(&(line.clone() + &line), true, true, false).is_err());
        assert!(!death_marker_v2(DEATH_MARKER, true, true, false).unwrap());
        assert!(death_marker_v2(DEATH_MARKER, true, true, true).is_err());
        assert!(death_marker_v2(&(line + "SYNTHETIC_DURABLE_DELIVERY"), true, true, true).is_err());
        assert!(
            death_marker_v2("SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1\n", true, true, false).is_err()
        );
        for text in [
            format!("prefix {DEATH_MARKER}\n"),
            format!("{DEATH_MARKER} suffix\n"),
            format!("{DEATH_MARKER}\r\r\n"),
        ] {
            assert!(!death_marker_v2(&text, true, true, false).unwrap());
        }
    }
    #[test]
    fn delivery_native_branch_preserves_completed_precursor_and_original_deadlines() {
        let source = include_str!("private_fixed_v2.rs");
        let branch = source
            .find("if matches!(continuation, CompletedPreparationV2::DeliveryAdmission)")
            .unwrap();
        let finish = source
            .find("let fixed = runtime.block_on(session.finish_fixed_v2())?")
            .unwrap();
        // Capture correlation is inert; the sole session drop occurs only after
        // actual successful finish in the separately selected new branch.
        let tail = &source[finish..];
        assert!(tail.find("drop(session)").unwrap() < tail.find("let expected =").unwrap());
        assert!(
            source.contains("let _keep_original_owners = (&host, &session, &original.temporary)")
        );
        assert!(branch < source.len());
        assert_eq!(WORKFLOW_LIMIT, Duration::from_secs(900));
        let local = include_str!("delivery_admission_v2.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!local.contains("valid_until_unix_seconds:"));
        assert!(!local.contains("ArmCapture("));
        assert!(!local.contains("ArmRedisclosure("));
        assert!(local.contains("PollDeliveryRedisclosure("));
        assert!(local.contains("current_disclosure: Some(current_disclosure)"));
        let commit = local.find("send(C::AwaitDeliveryResponse(index))").unwrap();
        let listener = local[commit..]
            .find("serve_committed_durable_delivery_history_v2")
            .unwrap();
        let audit = local[commit..]
            .find("send(C::AwaitDeliveryAudit(index))")
            .unwrap();
        assert!(listener < audit);
        assert!(!local.contains("ReconcileDurableWriter("));
        let reader = local.split("fn read_delivery_child").nth(1).unwrap();
        assert!(!reader.contains("AcceptDelivery("));
        assert!(!reader.contains("PollDeliveryImport("));
        assert!(reader.contains("reopen_durable_delivery_originals_v2"));
    }
}
