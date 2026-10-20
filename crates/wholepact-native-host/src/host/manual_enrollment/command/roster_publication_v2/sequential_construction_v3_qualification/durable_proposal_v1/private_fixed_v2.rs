//! Original, anchored private workspace across real owned-process death. The
//! controller owns no Host, source/financial keys, signer, witness or TLS config.
//! Positive evidence comes only from actual production kernels and a new reader.
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use super::*;
use crate::host::financial::private_durable_fixed_v2 as private_diagnostic;
use private_diagnostic::{
    PrivateDiagnosticOperationV1 as DiagnosticOperation, PrivateDiagnosticSiteV1 as DiagnosticSite,
};
use std::io;
#[path = "private_fixed_v2/control_v1.rs"]
mod control_v1;
use control_v1::{PublicOutcomeV1, ReaderCompletionV1, ReadyControlV1};

const DEATH_MARKER: &str = "SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1";
const WORKFLOW_LIMIT: Duration = Duration::from_secs(900);

/// Complete physical lines only, with at most the PTY's one trailing CR.
/// Called immediately after append and before every ordinary input consume.
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn death_marker_v1(
    tail: &str,
    producer: bool,
    inputs_complete: bool,
    terminal: bool,
) -> io::Result<bool> {
    let mut count = 0usize;
    for line in tail.split_inclusive('\n') {
        if !line.ends_with('\n') {
            continue;
        }
        let line = &line[..line.len() - 1];
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line == DEATH_MARKER {
            count += 1;
        }
    }
    if count > 1 || (count == 1 && (!producer || !inputs_complete)) {
        return Err(io::Error::other(
            "unexpected duplicate or premature durable marker",
        ));
    }
    if terminal {
        // A final partial duplicate cannot be ignored as unrelated text.
        let remainder = tail.rsplit_once('\n').map_or(tail, |(_, rest)| rest);
        if !remainder.is_empty()
            && (DEATH_MARKER.starts_with(remainder) || remainder.starts_with(DEATH_MARKER))
        {
            return Err(io::Error::other("partial terminal durable marker"));
        }
        if count != 1 {
            return Err(io::Error::other("exact durable marker missing"));
        }
    }
    Ok(count == 1)
}
fn producer_cleanup_verified(process: &owned_test_process_group_v1::ProcessCleanupV1) -> bool {
    process.verified()
        && process.group_signal == owned_test_process_group_v1::GroupSignalV1::SentWhileLeaderOwned
        && process
            .status
            .as_ref()
            .is_some_and(|status| status.signal() == Some(libc::SIGKILL))
}

fn monotonic_now_ns() -> io::Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = unsafe { value.assume_init() };
    let seconds: u64 = value
        .tv_sec
        .try_into()
        .map_err(|_| io::Error::other("monotonic clock unavailable"))?;
    let nanos: u64 = value
        .tv_nsec
        .try_into()
        .map_err(|_| io::Error::other("monotonic clock unavailable"))?;
    if nanos >= 1_000_000_000 {
        return Err(io::Error::other("monotonic clock unavailable"));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or_else(|| io::Error::other("monotonic clock overflow"))
}
pub(super) fn child_original_cutoff() -> Result<Instant> {
    // Same monotonic clock namespace and exact original value across both
    // children. This is inert timing, never a credential or authority input.
    let raw = std::env::var("WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS")
        .map_err(|_| Error::Invalid)?;
    let cutoff: u64 = raw.parse().map_err(|_| Error::Invalid)?;
    if cutoff.to_string() != raw {
        return Err(Error::Invalid);
    }
    let sampled = Instant::now();
    let remaining = cutoff
        .checked_sub(monotonic_now_ns()?)
        .ok_or(Error::Permission)?;
    sampled
        .checked_add(Duration::from_nanos(remaining))
        .ok_or(Error::Invalid)
}

fn before_original_cutoff(deadline: Instant, now: Instant) -> bool {
    now < deadline
}
fn first_private_failure(summary: &str, fallback: &'static str) -> &'static str {
    for entry in summary.split(',') {
        let mut parts = entry.split(':');
        if let (Some(boundary), Some(outcome)) = (parts.next(), parts.next()) {
            if outcome != "Begin" && outcome != "Complete" {
                if let Some(name) = control_v1::BOUNDARIES
                    .iter()
                    .find(|name| **name == boundary)
                {
                    return name;
                }
            }
        }
    }
    fallback
}
fn private_fixed_detail_allowed(process_verified: bool, root_cleanup: &str) -> bool {
    process_verified && root_cleanup == "closed_absent"
}
fn private_failure_report(stage: &PrivateWorkspaceStageResultV1) -> String {
    format!(
        "[JOINED_FAILURE exit={:?} signal={:?} core_dumped={} inputs={}/{} reason={:?} static_boundaries={}]",
        stage
            .process
            .status
            .as_ref()
            .and_then(|status| status.code()),
        stage
            .process
            .status
            .as_ref()
            .and_then(|status| status.signal()),
        stage
            .process
            .status
            .as_ref()
            .is_some_and(|status| status.core_dumped()),
        stage.next,
        stage.expected,
        stage.failure_reason,
        stage.summary
    )
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; actual process death and original-file reopening"]
fn private_workspace_actual_process_death_reopens_same_fixed_proof() {
    run_two_processes_v1().expect("original fixed proof survives verified SIGKILL and independent original-file read-only reopening");
}
fn run_two_processes_v1() -> io::Result<()> {
    process_containment_v1::require_and_report_core_policy()?;
    // One shared cutoff begins before fixture preparation, not at reader spawn.
    let deadline = Instant::now() + WORKFLOW_LIMIT;
    let monotonic_cutoff_ns = monotonic_now_ns()?
        .checked_add(
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos()
                .try_into()
                .map_err(|_| io::Error::other("original cutoff overflow"))?,
        )
        .ok_or_else(|| io::Error::other("original cutoff overflow"))?;
    let mut public = PublicOutcomeV1::pending();
    let mut root = Some(
        tempfile::Builder::new()
            .prefix(CHILD_TEMPORARY_PREFIX)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?,
    );
    let mut first_report = None;
    let mut first_detail = None;
    let mut detail_withheld = false;
    let mut detail_process_verified = false;
    let workflow = (|| -> io::Result<()> {
        owned_test_process_group_v1::require_default_child_wait_policy().map_err(|error| {
            public.fail("PrivateWorkspaceBootstrap");
            if let Some(root) = root.take() {
                let _ = root.keep();
            }
            public.root_cleanup = "retained".into();
            error
        })?;
        // This helper holds a PathBuf, not a loaded TLS configuration or key.
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
            PrivateWorkspaceStageV1::Producer,
            &producer_inputs(),
            deadline,
            monotonic_cutoff_ns,
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
        if producer.outcome.is_err() {
            public.fail(first_private_failure(
                &producer.summary,
                if producer.failure_reason == HarnessFailureReason::CleanupUnverified {
                    "PrivateWorkspaceProducerReap"
                } else {
                    "PrivateWorkspaceDurableMarker"
                },
            ));
            first_report = Some(private_failure_report(&producer));
            first_detail = producer.private_fixed_diagnostic().cloned();
            detail_withheld = producer.diagnostic_withheld() || first_detail.is_none();
            detail_process_verified = producer.process.verified();
            return Err(io::Error::other("producer fixed workflow failed"));
        }
        if !producer_cleanup_verified(&producer.process) {
            public.fail(if public.producer_reaped && public.producer_group_absent {
                "PrivateWorkspaceProducerKill"
            } else {
                "PrivateWorkspaceProducerReap"
            });
            return Err(io::Error::other(
                "actual producer SIGKILL or exact cleanup unverified",
            ));
        }
        diagnostic::emit(B::PrivateWorkspaceProducerKill, Outcome::Complete);
        diagnostic::emit(B::PrivateWorkspaceProducerReap, Outcome::Complete);
        if !before_original_cutoff(deadline, Instant::now()) {
            public.fail("PrivateWorkspaceReaderOpen");
            return Err(io::Error::other("original shared cutoff expired"));
        }
        // The record is read only after actual reap/group absence. It contains
        // inert selectors/commitments, never source keys or inherited consent.
        let _control = ReadyControlV1::read_original(
            root.as_ref()
                .ok_or_else(|| io::Error::other("original root unavailable"))?
                .path(),
        )
        .map_err(|error| {
            public.fail("PrivateWorkspaceDurableMarker");
            error
        })?;
        let mut reader = private_workspace_stage_v1(
            root.take().unwrap(),
            None,
            PrivateWorkspaceStageV1::Reader,
            &reader_inputs(),
            deadline,
            monotonic_cutoff_ns,
        )
        .map_err(|error| {
            public.reader_exit = "unverified".into();
            public.root_cleanup = "retained".into();
            public.fail("PrivateWorkspaceReaderOpen");
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
            public.fail(first_private_failure(
                &reader.summary,
                if reader.failure_reason == HarnessFailureReason::CleanupUnverified {
                    "PrivateWorkspaceReaderReap"
                } else {
                    "PrivateWorkspaceReadFixed"
                },
            ));
            first_report = Some(private_failure_report(&reader));
            first_detail = reader.private_fixed_diagnostic().cloned();
            detail_withheld = reader.diagnostic_withheld() || first_detail.is_none();
            detail_process_verified = reader.process.verified();
            return Err(io::Error::other("independent reader workflow failed"));
        }
        if !reader.process.verified() || public.reader_exit != "success" {
            public.fail("PrivateWorkspaceReaderReap");
            return Err(io::Error::other("reader exit or cleanup unverified"));
        }
        if !before_original_cutoff(deadline, Instant::now()) {
            public.fail("PrivateWorkspaceReaderReap");
            return Err(io::Error::other("reader exceeded shared original cutoff"));
        }
        let checked = ReaderCompletionV1::read_after_reap(
            root.as_ref()
                .ok_or_else(|| io::Error::other("reader root unavailable"))?
                .path(),
        )
        .map_err(|error| {
            public.fail("PrivateWorkspaceIdentityCompare");
            error
        })?;
        public.fixed_verified = checked.fixed_verified;
        public.exact_identity_preserved = checked.exact_identity_preserved;
        public.exact_checkpoint_preserved = checked.exact_checkpoint_preserved;
        public.exact_idempotency_preserved = checked.exact_idempotency_preserved;
        public.reader_no_effects_verified = checked.reader_no_effects_verified;
        diagnostic::emit(B::PrivateWorkspaceReaderReap, Outcome::Complete);
        Ok(())
    })();
    diagnostic::emit(B::PrivateWorkspaceRootCleanup, Outcome::Begin);
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
        public.fail("PrivateWorkspaceRootCleanup");
    } else {
        diagnostic::emit(B::PrivateWorkspaceRootCleanup, Outcome::Complete);
    }
    if workflow.is_err() && public.first_failure.is_none() {
        public.fail("PrivateWorkspaceBootstrap");
    }
    if workflow.is_ok() && public.verified_success() {
        public.result = "passed".into();
    } else if public.first_failure.is_none() {
        public.fail("PrivateWorkspaceIdentityCompare");
    }
    if private_fixed_detail_allowed(detail_process_verified, &public.root_cleanup) {
        if detail_withheld {
            diagnostic::emit_private_fixed_diagnostic_unavailable();
        } else if let Some(detail) = &first_detail {
            diagnostic::emit_private_fixed_diagnostic(detail);
        }
    }
    if let Some(report) = first_report {
        eprintln!("{report}");
    }
    eprintln!("{}{}", control_v1::PUBLIC_PREFIX, public.public_json()?);
    if public.result == "passed" {
        Ok(())
    } else {
        Err(io::Error::other(
            "original private workspace qualification failed",
        ))
    }
}

const RETENTION: &str =
    "Private original workspace qualification only; irreversible viewing disclosure";
const PASSWORD: &str = "synthetic-recovery-review-password";
const SOURCE_KEY: &str = "private-original-source-selection-v1";
const FIX_KEY: &str = "private-original-fixed-v1";
fn fixture_error(_: &'static str) -> Error {
    Error::Receipt("synthetic original workspace worker failed".into())
}
fn amount(value: u64) -> wholepact_core::Amount {
    value
        .to_string()
        .parse()
        .expect("constant synthetic amount")
}
fn now_seconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::Invalid)
}
fn scenario_root() -> Result<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("TMPDIR").ok_or(Error::Invalid)?);
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    Ok(path)
}
fn done(signers: &worker::JoinedSignerWorkerV1, index: usize) -> Result<()> {
    match signers.receive().map_err(fixture_error)? {
        worker::JoinedSignerReplyV1::Done { index: actual } if index == actual => Ok(()),
        _ => Err(Error::Authentication),
    }
}
fn commitments(
    host: &Host,
    actual: &wholepact_engine::PrivateVerifiedFixedV2,
) -> Result<control_v1::FixedCommitmentsV1> {
    let original = host.private_workspace_comparison_v1()?;
    if actual.state != "succeeded"
        || actual.attempt != 1
        || !actual.proof_verified
        || actual.authorization_allowed
        || actual.source_digest != original.source_digest
        || actual.native_association_digest != original.native_association_digest
        || actual.metadata_origin != hex::encode(original.metadata_origin)
        || actual.proof_origin != hex::encode(original.proof_origin)
    {
        return Err(Error::Authentication);
    }
    Ok(control_v1::FixedCommitmentsV1 {
        original_host_digest: wholepact_core::proposal::canonical_digest(
            "wholepact:synthetic-original-workspace-identity:v1",
            &original,
        )
        .map_err(|_| Error::Invalid)?,
        original_financial_digest: original.financial_origin_digest,
        source_digest: actual.source_digest.clone(),
        native_association_digest: actual.native_association_digest.clone(),
        marker_digest: actual.marker_digest.clone(),
        metadata_origin: actual.metadata_origin.clone(),
        proof_origin: actual.proof_origin.clone(),
        candidate_identity_digest: actual.candidate_identity_digest.clone(),
        manifest_digest: actual.manifest_digest.clone(),
        original_checkpoint_key_digest: actual.original_checkpoint_key_digest.clone(),
        coordination_request_digest: actual.coordination_request_digest.clone(),
        checkpoint_receipt_digest: actual.checkpoint_receipt_digest.clone(),
        action_mapping_digest: actual.action_mapping_digest.clone(),
        job_identity_digest: actual.job_identity_digest.clone(),
        scope_digest: actual.scope_digest.clone(),
        input_digest: actual.input_digest.clone(),
        result_digest: actual.result_digest.clone(),
        fixed_identity_digest: actual.fixed_identity_digest.clone(),
        operation_history_digest: actual.operation_history_digest.clone(),
        proof_event_history_digest: actual.proof_event_history_digest.clone(),
        logical_state_digest: actual.logical_state_digest.clone(),
    })
}
pub(super) fn session_inputs(inputs: &mut Vec<Input<'static>>, read_only: bool) {
    use Input::Text;
    for (prompt, response) in [
        ("Local application principal ID: ", "synthetic-roster-host"),
        ("Scope choice: type SELECTED", "OWNED"),
        (
            "Additional shared agreement IDs, comma-separated; blank for none: ",
            "",
        ),
        (
            "Grant READ only, or PREPARE",
            if read_only { "READ" } else { "PREPARE" },
        ),
        ("Optional exact browser origin for this session", ""),
    ] {
        inputs.push(Text { prompt, response });
    }
    inputs.push(Input::CapturedPath {
        marker: "SYNTHETIC_PRIVATE_NEW_SESSION_PATH=",
        prompt: "New private bootstrap credential file (absolute path",
    });
    inputs.push(Input::ExactReview {
        detail: "Grant this session until lock/restart/revoke.",
        approve: true,
    });
}
fn open_inputs(inputs: &mut Vec<Input<'static>>, initialize: bool) {
    inputs.push(Input::Text {
        prompt: "Storage passphrase: ",
        response: PASSWORD,
    });
    inputs.push(Input::Text {
        prompt: "Original primary financial passphrase: ",
        response: PASSWORD,
    });
    if initialize {
        inputs.push(review(
            "Inspect exact anchored ORIGINAL files/source/financial/proof and saved seed plan",
        ));
    }
    inputs.push(review("Authenticate and read the exact final original workspace, complete original source and all four original primary journals"));
    session_inputs(inputs, !initialize);
    if initialize {
        inputs.push(review("Read exact current selected original source and complete historical terms for NONSPENDING private coordination."));
        inputs.push(review("Initialize ONCE the exact previously anchored private seed, original operation/idempotency/timestamps and marker."));
    }
}
fn review(detail: &'static str) -> Input<'static> {
    Input::ExactReview {
        detail,
        approve: true,
    }
}

pub(super) fn producer_inputs() -> Vec<Input<'static>> {
    let mut inputs = initial::inputs();
    inputs.push(review("Inspect the exact original Host roster, current agreement and complete original terms for nonbinding coordinator source selection."));
    inputs.push(review("Record exactly two NONBINDING coordinator-owned intent claims and select their unchanged amounts on this actual original Host."));
    inputs.push(Input::Text {
        prompt: "Storage passphrase for private workspace anchor: ",
        response: PASSWORD,
    });
    inputs.push(review("Read exact current selected original source and complete historical terms for NONSPENDING private coordination."));
    inputs.push(review("Register exact immutable private dependency."));
    open_inputs(&mut inputs, true);
    inputs.push(review("Read exact current selected original source and complete historical terms for NONSPENDING private coordination."));
    inputs.push(review(
        "Open ONLY the exact initialized original private workspace.",
    ));
    inputs.push(review("Operation: read sanitized progress."));
    inputs.push(review("Prepare exactly this one claims-only candidate in the fresh initialized original private workspace."));
    inputs.push(review("Operation: prepare exact candidate."));
    for index in 0..2 {
        inputs.push(review("Request genuine initial native viewing disclosure and durable capture for this exact original selected owner."));
        inputs.push(review("Operation: retain exact sealed material."));
        inputs.push(review("Allow this exact original private material for sealed initial durable retention in this current native command?"));
        if index == 1 {
            inputs.push(review("Allow this exact original private material for sealed initial durable retention in this current native command?"));
        }
    }
    for detail in [
        "Approve V3 private fixed stage Prepare.",
        "Approve V3 private fixed stage AdmitOriginal.",
        "Approve V3 private fixed stage ProveOriginal.",
        "Approve V3 private fixed stage FreezeFixed.",
        "Approve V3 private fixed stage ReadFixed.",
    ] {
        inputs.push(review("Inspect exact original private V3 stage metadata."));
        inputs.push(review(detail));
    }
    inputs.push(review("SYNTHETIC ORIGINAL WORKSPACE: keep these already verified original owners live for controlled process death."));
    inputs
}
fn reader_inputs() -> Vec<Input<'static>> {
    let mut inputs = Vec::new();
    open_inputs(&mut inputs, false);
    inputs.push(review("Read exact current selected original source and complete historical terms for NONSPENDING private coordination."));
    inputs.push(review(
        "Open ONLY the exact initialized original private workspace.",
    ));
    inputs.push(review("Inspect exact original private V3 stage metadata."));
    inputs.push(review("Approve V3 private fixed stage ReadFixed."));
    inputs
}

thread_local! {
    static CHILD_BOUNDARY: std::cell::Cell<B> = const { std::cell::Cell::new(B::PrivateWorkspaceBootstrap) };
    static CHILD_FIRST_FAILURE: std::cell::Cell<Option<(B,Outcome)>> = const { std::cell::Cell::new(None) };
}
fn observe_failure(boundary: B, outcome: Outcome) {
    let (boundary_label, outcome_label) = diagnostic::private_observation_labels(boundary, outcome);
    private_diagnostic::observe_private_fixed_boundary_v1(boundary_label, outcome_label);
    CHILD_FIRST_FAILURE.with(|first| {
        if first.get().is_none() {
            first.set(Some((boundary, outcome)));
        }
    });
    diagnostic::emit(boundary, outcome);
}
fn at<T>(boundary: B, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    CHILD_BOUNDARY.with(|current| current.set(boundary));
    let result = diagnostic::host(boundary, operation);
    if let Err(error) = &result {
        let (boundary_label, outcome_label) =
            diagnostic::private_observation_labels(boundary, diagnostic::host_error(error));
        private_diagnostic::observe_private_fixed_boundary_v1(boundary_label, outcome_label);
        if let Some((operation, site)) = diagnostic_boundary_site(boundary) {
            private_diagnostic::observe_private_fixed_host_v1(operation, site, error);
        }
        CHILD_FIRST_FAILURE.with(|first| {
            if first.get().is_none() {
                first.set(Some((boundary, diagnostic::host_error(error))));
            }
        });
    }
    result
}
fn diagnostic_boundary_site(boundary: B) -> Option<(DiagnosticOperation, DiagnosticSite)> {
    match boundary {
        B::PrivateWorkspaceCheckpoint => Some((
            DiagnosticOperation::Checkpoint,
            DiagnosticSite::HostCheckpointEntry,
        )),
        B::PrivateWorkspaceProof => Some((
            DiagnosticOperation::Proof,
            DiagnosticSite::HostProofPrecheck,
        )),
        B::PrivateWorkspaceFreeze => Some((
            DiagnosticOperation::Freeze,
            DiagnosticSite::HostFreezeReturn,
        )),
        B::PrivateWorkspaceReaderOpen => Some((
            DiagnosticOperation::OpenOriginal,
            DiagnosticSite::ReaderHostReturn,
        )),
        B::PrivateWorkspaceReadFixed => Some((
            DiagnosticOperation::ReadFixed,
            DiagnosticSite::HostReadReturn,
        )),
        B::PrivateWorkspaceIdentityCompare => Some((
            DiagnosticOperation::ReadFixed,
            DiagnosticSite::ReaderCommitments,
        )),
        _ => None,
    }
}
fn diagnostic_result_at<T>(
    operation: DiagnosticOperation,
    site: DiagnosticSite,
    result: Result<T>,
) -> Result<T> {
    if let Err(error) = &result {
        private_diagnostic::observe_private_fixed_host_v1(operation, site, error);
    }
    result
}
fn child_result(result: Result<()>) -> Result<()> {
    if let Err(error) = &result {
        let observed = private_diagnostic::first_private_fixed_boundary_v1();
        if !observed.is_some_and(|(boundary, outcome)| {
            diagnostic::emit_private_observation(boundary, outcome)
        }) {
            if let Some((boundary, outcome)) = CHILD_FIRST_FAILURE.with(|first| first.get()) {
                diagnostic::emit(boundary, outcome);
            } else {
                CHILD_BOUNDARY
                    .with(|current| diagnostic::emit(current.get(), diagnostic::host_error(error)));
            }
        }
        if let Some(detail) = private_diagnostic::private_fixed_diagnostic_snapshot_v1() {
            diagnostic::emit_private_fixed_diagnostic(&detail);
        } else {
            diagnostic::emit_private_fixed_diagnostic_unavailable();
        }
    }
    result
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn produce_fixed_child(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    let _diagnostic_scope = private_diagnostic::begin_private_fixed_diagnostic_scope_v1();
    child_result(produce_fixed_inner(
        terminal,
        CompletedPreparationV2::FixedReopen,
    ))
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn read_fixed_child(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    let _diagnostic_scope = private_diagnostic::begin_private_fixed_diagnostic_scope_v1();
    child_result(read_fixed_inner(terminal))
}

fn bridge_capture(error: wholepact_signer::authority_bridge::BridgeError) -> Error {
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
    observe_failure(B::PrivateWorkspaceCapture, outcome);
    Error::Receipt("private original capture refused".into())
}
fn source_engine_error(error: wholepact_engine::ApiError) -> Error {
    // Inspect only the actual maintained code before Host conversion erases it.
    let outcome = match error.code.as_str() {
        "MANUAL_CONSTRUCTION_DENIED" => Outcome::EngineManualConstructionDenied,
        "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => Outcome::EngineRetainedObservationUnavailable,
        "CANDIDATE_VERIFICATION_FAILED" => Outcome::EngineCandidateVerificationFailed,
        "IDEMPOTENCY_CONFLICT" => Outcome::EngineIdempotencyConflict,
        "REVISION_CONFLICT" => Outcome::EngineRevisionConflict,
        "NOT_FOUND" => Outcome::EngineNotFound,
        "INVALID_REQUEST" => Outcome::EngineInvalidRequest,
        "RECOVERY_REQUIRED" => Outcome::EngineRecoveryRequired,
        "LIVE_AUTHORIZATION_EXISTS" => Outcome::EngineLiveAuthorizationExists,
        "RESOURCE_EXHAUSTED" => Outcome::EngineResourceExhausted,
        "INVALID_TRANSITION" => Outcome::EngineInvalidTransition,
        "STORAGE_PROTECTION_REQUIRED" => Outcome::EngineStorageProtectionRequired,
        "STORAGE_UNAVAILABLE" => Outcome::EngineStorageUnavailable,
        "ACCESS_DENIED" => Outcome::EngineAccessDenied,
        _ => Outcome::EngineUnclassified,
    };
    observe_failure(B::PrivateSourceSelect, outcome);
    error.into()
}

/// Real original Host producer. No generic Engine, copied agreement, separate
/// proof database or fixture LocalPrivacy/LocalProofConsent is constructed here.
enum CompletedPreparationV2 {
    FixedReopen,
    DeliveryAdmission,
    FinancialContinuation,
}

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn produce_delivery_child(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    let _diagnostic_scope = private_diagnostic::begin_private_fixed_diagnostic_scope_v1();
    child_result(produce_fixed_inner(
        terminal,
        CompletedPreparationV2::DeliveryAdmission,
    ))
}

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn produce_financial_child(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    let _diagnostic_scope = private_diagnostic::begin_private_fixed_diagnostic_scope_v1();
    super::delivery_admission_v2::durable_financial_dispatch_v1::record_financial_preparation_v1()?;
    child_result(produce_fixed_inner(
        terminal,
        CompletedPreparationV2::FinancialContinuation,
    ))
}

fn produce_fixed_inner(
    terminal: crate::terminal::Terminal,
    continuation: CompletedPreparationV2,
) -> Result<()> {
    use crate::host::financial::private_durable_fixed_v2::{
        PrivateCaptureStageV2, PrivateSourceSelectionClaimV1, PrivateSourceSelectionV1,
    };
    use wholepact_core::{
        ClaimedInput, ClaimedOutput, IntentStatus, OutputAllocation, ParticipantAllocation,
        ParticipationIntent, ProposalManifest,
    };
    use wholepact_signer::authority_bridge::{
        durable_construction_v1::{
            DurableConstructionCaptureRequestV1, DurableConstructionScopeV1,
        },
        ipc::OriginalHistoryClient,
        preconstruction_ipc::{
            PreconstructionBirthday, PreconstructionProvider, PreconstructionRequest,
            PreconstructionScope,
        },
    };
    use wholepact_wallet::wallet::{
        protected_sync::durable_construction_v1::ConstructionReviewerV1,
        synthetic_born_receiver_blocks_v1::{
            SyntheticBornChainSpecV1, SyntheticBornReceiverBlocksV1,
        },
    };
    use worker::{JoinedSignerCommandV1 as C, JoinedSignerReplyV1 as R};
    let scenario = scenario_root()?;
    let mut original = at(B::PrivateWorkspaceBootstrap, || {
        initial::prepare_private_workspace_v1(terminal.clone())
    })?;
    let old_host = original.host.take().ok_or(Error::Invalid)?;
    let profile = old_host
        .directory
        .path("profile.vault")?
        .parent()
        .ok_or(Error::Invalid)?
        .to_path_buf();
    let financial = old_host
        .financial
        .as_ref()
        .ok_or(Error::Locked)?
        .current_directory()?;
    let workspace = original.temporary.path().join("original-private-workspace");
    let cache = scenario.join("private-process-only-scan-cache");
    let participants = original.born[1..]
        .iter()
        .map(|owner| ParticipantAllocation {
            participant_id: owner.participant_id.clone(),
            account_id: owner.account_id.clone(),
            contribution: amount(150_000),
            fee_share: amount(5_000),
            fee_cap: amount(5_000),
            maximum_net_debit: amount(155_000),
            charges: vec![],
        })
        .collect::<Vec<_>>();
    let selected = PrivateSourceSelectionV1 {
        claims: participants
            .iter()
            .enumerate()
            .map(|(index, participant)| PrivateSourceSelectionClaimV1 {
                account_id: participant.account_id.clone(),
                intent: ParticipationIntent {
                    intent_id: format!("private-original-intent-{index}"),
                    agreement_id: worker::AGREEMENT_ID.into(),
                    participant_id: participant.participant_id.clone(),
                    desired_contribution: participant.contribution,
                    maximum_net_debit: participant.maximum_net_debit,
                    fee_cap: participant.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            })
            .collect(),
    };
    let original_revision = old_host
        .engine
        .get(old_host.access()?, worker::AGREEMENT_ID)
        .map_err(source_engine_error)?
        .revision;
    at(B::PrivateSourceSelect, || {
        old_host.private_durable_source_select_v1(
            worker::AGREEMENT_ID,
            original_revision,
            SOURCE_KEY,
            selected,
        )
    })?;
    let agreement = old_host
        .engine
        .get(old_host.access()?, worker::AGREEMENT_ID)
        .map_err(source_engine_error)?
        .agreement;
    // The original Host is consumed, not duplicated or replaced by a dummy.
    // Password travels through the same private native terminal as the command.
    let password = terminal.secret("Storage passphrase for private workspace anchor: ")?;
    at(B::PrivateWorkspaceReserve, || {
        old_host.create_private_durable_workspace_v1(
            worker::AGREEMENT_ID,
            &workspace,
            RETENTION,
            password.as_bytes(),
        )
    })?;
    drop(password);
    terminal.message(&format!(
        "SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",
        scenario.join("private-producer-session.token").display()
    ))?;
    let host = at(B::PrivateWorkspaceInitialize, || {
        Host::open_private_workspace_registered_v1(terminal.clone(), &profile, &workspace, true)
    })?;
    let runtime = if matches!(continuation, CompletedPreparationV2::FinancialContinuation) {
        // The same finite provider must remain runnable while independent native
        // signing workers perform their fresh wallet reads outside block_on.
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
    };
    let blocks = SyntheticBornReceiverBlocksV1::build(
        [
            &original.born[1].public_receive_address,
            &original.born[2].public_receive_address,
        ],
        [155_000, 155_000],
        SyntheticBornChainSpecV1 {
            prior_height: 4_465_050,
            prior_hash_protocol: [73; 32],
            block_count: 1,
            timestamp: now_seconds()?.try_into().map_err(|_| Error::Invalid)?,
        },
    )
    .map_err(|_| Error::Invalid)?;
    let outpoints = blocks.public_funding_input_ids().clone();
    let birthday = blocks.trees()[0].clone();
    let anchor_height = blocks.fabricated_context().anchor_height;
    let expiry_height = anchor_height.checked_add(40).ok_or(Error::Invalid)?;
    let provider = runtime.block_on(synthetic_born_provider_v1::SyntheticBornProviderV1::start(
        blocks,
        synthetic_provider_tls_v1::child_server_config()?,
        child_original_cutoff()?,
    ))?;
    let source = wholepact_chain::ChainAdapter::testnet(
        "synthetic-private-original-blocks",
        provider.endpoint(),
        wholepact_chain::NetworkPolicy::default(),
    )?;
    let source_identity = source.identity().clone();
    drop(source);
    let request = wholepact_engine::CandidateRequest {
        manifest: ProposalManifest {
            agreement,
            participants: participants.clone(),
            inputs: participants
                .iter()
                .zip(outpoints)
                .map(|(participant, input_id)| ClaimedInput {
                    input_id,
                    participant_id: participant.participant_id.clone(),
                    account_id: participant.account_id.clone(),
                    amount: amount(155_000),
                    ownership_evidence_ref: None,
                })
                .collect(),
            outputs: vec![ClaimedOutput {
                output_id: "private-original-recipient".into(),
                address: original.payment_receiver.clone(),
                amount: amount(300_000),
                allocation: OutputAllocation::Recipient {
                    recipient_id: worker::RECIPIENT_ID.into(),
                },
            }],
            transaction_fee: amount(10_000),
            expiry_height,
        },
        previous_candidate_id: None,
    };
    let mut session = at(B::PrivateWorkspaceCandidate, || {
        host.private_fixed_session_v2(&workspace, FIX_KEY, request, &cache)
    })?;
    let accounts = session.reviewer_account_ids();
    if accounts.len() != 2 {
        return Err(Error::Authentication);
    }
    let mut delivery_original_disclosures = Vec::new();
    for (slot, account_id) in accounts.iter().enumerate() {
        let account = original.born[1..]
            .iter()
            .find(|born| &born.account_id == account_id)
            .ok_or(Error::Authentication)?;
        let index = account.index;
        CHILD_BOUNDARY.with(|current| current.set(B::PrivateWorkspaceCapture));
        diagnostic::emit(B::PrivateWorkspaceCapture, Outcome::Begin);
        original
            .signers
            .send(C::OpenDurable(index, session.proposal().clone()))
            .map_err(fixture_error)?;
        let (peer, scope) = match original.signers.receive().map_err(fixture_error)? {
            R::DurablePeer {
                index: actual,
                peer,
                scope,
                ..
            } if actual == index => (peer, scope),
            _ => return Err(Error::Authentication),
        };
        original
            .signers
            .send(C::PollDurablePair(index))
            .map_err(fixture_error)?;
        let client = OriginalHistoryClient::pair(
            peer.provider,
            &peer.endpoint,
            "Synthetic-original-private-constructor",
            scope,
        )
        .map_err(bridge_capture)?;
        done(&original.signers, index)?;
        original
            .signers
            .send(C::AcceptDurable(index))
            .map_err(fixture_error)?;
        let records = match original.signers.receive().map_err(fixture_error)? {
            R::Records {
                index: actual,
                records,
            } if actual == index => records,
            _ => return Err(Error::Authentication),
        };
        let principal = session.principal_id()?.to_owned();
        let destination = session
            .metadata_destination()
            .to_str()
            .ok_or(Error::Invalid)?
            .to_owned();
        let initial = PreconstructionRequest {
            enrollment_ref: records.enrollment_ref.clone(),
            accepted_manifest_ref: records.accepted_manifest_ref.clone(),
            sponsor_policy: None,
            scope: PreconstructionScope {
                schema_version: 1,
                proposal: session.proposal().clone(),
                account_id: account.account_id.clone(),
                participant_id: account.participant_id.clone(),
                profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
                principal_id: principal.clone(),
                operator_name: principal.clone(),
                operator_destination: destination.clone(),
                wallet_destination: session
                    .wallet_destination(slot)?
                    .to_str()
                    .ok_or(Error::Invalid)?
                    .into(),
                reviewer_account_ids: accounts.clone(),
                privacy_domain: account.privacy_domain.clone(),
                purpose: "construct_exact_accepted_candidate".into(),
                retention_policy: RETENTION.into(),
                provider: PreconstructionProvider {
                    source_id: source_identity.source_id.clone(),
                    endpoint: source_identity.endpoint.clone(),
                    trust_profile: source_identity.trust_profile.into(),
                },
                minimum_confirmations: 1,
                maximum_blocks: 16,
                anchor_height,
                maximum_net_debit_zatoshis: 155_000,
                birthday: PreconstructionBirthday {
                    prior_height: birthday.height.try_into().map_err(|_| Error::Invalid)?,
                    prior_block_hash: birthday.hash.clone(),
                    sapling_tree: birthday.sapling_tree.clone(),
                    orchard_tree: birthday.orchard_tree.clone(),
                    ironwood_tree: birthday.ironwood_tree.clone(),
                },
            },
        };
        let recipient = client
            .durable_construction_recipient_v1(&principal)
            .map_err(bridge_capture)?;
        let from = now_seconds()?;
        let capture = DurableConstructionCaptureRequestV1 {
            operation_id: format!("private-original-native-capture-{slot}"),
            enrollment_ref: records.enrollment_ref,
            accepted_manifest_ref: records.accepted_manifest_ref,
            scope: DurableConstructionScopeV1 {
                version: 2,
                purpose: wholepact_wallet::wallet::protected_sync::durable_construction_v1::PURPOSE
                    .into(),
                proposal: session.proposal().clone(),
                account_id: account.account_id.clone(),
                participant_id: account.participant_id.clone(),
                privacy_domain: account.privacy_domain.clone(),
                constructor: recipient.clone(),
                prover: recipient,
                reviewers: accounts
                    .iter()
                    .cloned()
                    .map(ConstructionReviewerV1::local_installed_signer)
                    .collect(),
                protected_destination: destination,
                retention_policy: RETENTION.into(),
                valid_from_unix_seconds: from,
                valid_until_unix_seconds: from.checked_add(1800).ok_or(Error::Invalid)?,
                minimum_confirmations: 1,
                maximum_scan_blocks: 16,
            },
        };
        let initial_command = initial.clone();
        let capture_command = capture.clone();
        let reference = runtime.block_on(session.capture_owner_v2(
            slot,
            &client,
            initial,
            capture,
            |stage| {
                match stage {
                    PrivateCaptureStageV2::BeforeInitial => {
                        original
                            .signers
                            .send(C::ArmInitial(index, initial_command.clone()))
                            .map_err(fixture_error)?;
                        done(&original.signers, index)?;
                        original
                            .signers
                            .send(C::PollDisclosure(index))
                            .map_err(fixture_error)?;
                    }
                    PrivateCaptureStageV2::BeforeCapture => {
                        original
                            .signers
                            .send(C::ArmCapture(index, capture_command.clone()))
                            .map_err(fixture_error)?;
                        done(&original.signers, index)?;
                        original
                            .signers
                            .send(C::PollDisclosure(index))
                            .map_err(fixture_error)?;
                    }
                    PrivateCaptureStageV2::AfterInitial | PrivateCaptureStageV2::AfterCapture => {
                        done(&original.signers, index)?
                    }
                }
                Ok(())
            },
        ))?;
        if matches!(continuation, CompletedPreparationV2::DeliveryAdmission)
            || matches!(continuation, CompletedPreparationV2::FinancialContinuation)
        {
            delivery_original_disclosures.push(super::delivery_admission_v2::OriginalDisclosureV2 {
                account_id: account.account_id.clone(),
                history: wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1 {
                    operation_id: capture_command.operation_id.clone(),
                    expected_request_digest: reference.request_digest.clone(),
                },
                scope: capture_command.scope.clone(),
                enrollment_ref: capture_command.enrollment_ref.clone(),
                accepted_manifest_ref: capture_command.accepted_manifest_ref.clone(),
                material_digest: reference.material_digest.clone(),
                outbox_reference: reference.outbox_reference.clone(),
            });
        }
        original
            .signers
            .send(C::CaptureCommitted(index))
            .map_err(fixture_error)?;
        match original.signers.receive().map_err(fixture_error)? {
            R::CaptureCommitted {
                index: actual,
                reference: actual_reference,
            } if actual == index && actual_reference == reference.outbox_reference => (),
            _ => return Err(Error::Authentication),
        }
        drop(client);
        original
            .signers
            .send(C::CloseDurable(index))
            .map_err(fixture_error)?;
        done(&original.signers, index)?;
        diagnostic::emit(B::PrivateWorkspaceCapture, Outcome::Complete);
    }
    let fixed = runtime.block_on(session.finish_fixed_v2())?;
    if matches!(continuation, CompletedPreparationV2::DeliveryAdmission)
        || matches!(continuation, CompletedPreparationV2::FinancialContinuation)
    {
        // ONLY the new branch releases this successfully completed session.
        // Its proof/cache workers have finished; the old branch below retains
        // the identical session and Host through its original SIGKILL boundary.
        let proposal = session.proposal().clone();
        drop(session);
        let financial_wallet_setup = if matches!(
            continuation,
            CompletedPreparationV2::FinancialContinuation
        ) {
            Some(serde_json::to_string(&serde_json::json!({
                "schema_version": 1, "purpose": "fresh_born_ephemeral_viewing_wallet_v1",
                "retention": "current_native_owner_only", "maximum_blocks": 16,
                "policy": { "confidence": "trusted_single_provider_snapshot", "source_id": source_identity.source_id,
                    "endpoint": source_identity.endpoint, "maximum_observation_age_seconds": 300,
                    "minimum_confirmations": 1, "minimum_expiry_margin_blocks": 1 },
                "birthday": { "prior_height": u32::try_from(birthday.height).map_err(|_| Error::Invalid)?,
                    "prior_block_hash": birthday.hash, "sapling_tree": birthday.sapling_tree,
                    "orchard_tree": birthday.orchard_tree, "ironwood_tree": birthday.ironwood_tree }
            }))?)
        } else {
            None
        };
        return super::delivery_admission_v2::continue_completed_original(
            terminal,
            host,
            original,
            fixed,
            proposal,
            runtime,
            provider,
            profile,
            workspace,
            financial,
            delivery_original_disclosures,
            source_identity,
            financial_wallet_setup,
        );
    }
    let expected = at(B::PrivateWorkspaceIdentityCompare, || {
        commitments(&host, &fixed)
    })?;
    drop(fixed);
    CHILD_BOUNDARY.with(|current| current.set(B::PrivateWorkspaceScanCleanup));
    diagnostic::emit(B::PrivateWorkspaceScanCleanup, Outcome::Begin);
    original.signers.shutdown().map_err(fixture_error)?;
    drop(original.witness);
    runtime.block_on(provider.shutdown())?;
    // Every actual async/proof task has finished. Dropping the runtime drains
    // its remaining infrastructure before marker; the original session stays live.
    drop(runtime);
    diagnostic::emit(B::PrivateWorkspaceScanCleanup, Outcome::Complete);
    let ready = ReadyControlV1 {
        schema: 1,
        profile,
        workspace,
        financial,
        expected,
    };
    CHILD_BOUNDARY.with(|current| current.set(B::PrivateWorkspaceDurableMarker));
    let final_review=terminal.approve_historical("SYNTHETIC ORIGINAL WORKSPACE: keep these already verified original owners live for controlled process death. All native disclosure associations, scan caches, provider work and proof workers are closed. This test-controller approval grants no new private, proof or financial effect.")?;
    final_review.effect(&mut || {
        ready.write_once(&scenario)?;
        Ok(())
    })?;
    diagnostic::emit(B::PrivateWorkspaceDurableMarker, Outcome::Complete);
    terminal.message(&format!("{DEATH_MARKER}\n"))?;
    // No orderly owner drop/reopen substitutes for this boundary. Parent sends
    // actual owned-group SIGKILL while these real original owners remain live.
    let _keep_original_owners = (&host, &session, &original.temporary);
    loop {
        std::thread::park();
    }
}

fn read_fixed_inner(terminal: crate::terminal::Terminal) -> Result<()> {
    let scenario = scenario_root()?;
    let ready = diagnostic_result_at(
        DiagnosticOperation::OpenOriginal,
        DiagnosticSite::ReaderControlRead,
        ReadyControlV1::read_original(&scenario).map_err(Error::from),
    )?;
    terminal.message(&format!(
        "SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",
        scenario.join("private-reader-session.token").display()
    ))?;
    let host = at(B::PrivateWorkspaceReaderOpen, || {
        Host::open_private_workspace_registered_v1(
            terminal,
            &ready.profile,
            &ready.workspace,
            false,
        )
    })?;
    diagnostic_result_at(
        DiagnosticOperation::ReadFixed,
        DiagnosticSite::ReaderFinancialCompare,
        (|| {
            if host
                .financial
                .as_ref()
                .ok_or(Error::Locked)?
                .current_directory()?
                != ready.financial
            {
                return Err(Error::Authentication);
            }
            Ok(())
        })(),
    )?;
    // The production reader discovers only the original saved fixed lineage.
    // It performs no initialize, capture, scan, constructor, enqueue or proof.
    let fixed = at(B::PrivateWorkspaceReadFixed, || {
        host.private_durable_read_fixed_v2(&ready.workspace)
    })?;
    let actual = at(B::PrivateWorkspaceIdentityCompare, || {
        commitments(&host, &fixed)
    })?;
    let result = ReaderCompletionV1 {
        schema: 1,
        fixed_verified: fixed.proof_verified,
        exact_identity_preserved: actual == ready.expected,
        exact_checkpoint_preserved: actual.checkpoint_equal(&ready.expected),
        exact_idempotency_preserved: actual.idempotency_equal(&ready.expected),
        reader_no_effects_verified: actual.logical_state_digest
            == ready.expected.logical_state_digest
            && actual.operation_history_digest == ready.expected.operation_history_digest
            && actual.proof_event_history_digest == ready.expected.proof_event_history_digest,
    };
    diagnostic_result_at(
        DiagnosticOperation::ReadFixed,
        DiagnosticSite::ReaderComparisonVerify,
        if !result.verified() {
            Err(Error::Authentication)
        } else {
            Ok(())
        },
    )?;
    diagnostic_result_at(
        DiagnosticOperation::ReadFixed,
        DiagnosticSite::ReaderCompletionWrite,
        result.write_once(&scenario).map_err(Error::from),
    )?;
    // Normal reader exit releases its independently authenticated original locks.
    drop(fixed);
    drop(host);
    Ok(())
}

#[cfg(test)]
mod pure_tests {
    use super::*;
    use owned_test_process_group_v1::{
        DirectChildV1, GroupAbsenceV1, GroupSignalV1, ProcessCleanupV1,
    };
    fn process(signal: i32) -> ProcessCleanupV1 {
        ProcessCleanupV1 {
            group_signal: GroupSignalV1::SentWhileLeaderOwned,
            group_absence: GroupAbsenceV1::OriginalGroupAbsentObserved,
            direct_child: DirectChildV1::Reaped,
            status: Some(std::process::ExitStatus::from_raw(signal)),
        }
    }
    fn success() -> PublicOutcomeV1 {
        let mut record = PublicOutcomeV1::pending();
        record.result = "passed".into();
        record.producer_exit = "sigkill".into();
        record.producer_reaped = true;
        record.producer_group_absent = true;
        record.reader_exit = "success".into();
        record.reader_reaped = true;
        record.reader_group_absent = true;
        record.root_cleanup = "closed_absent".into();
        record.fixed_verified = true;
        record.exact_identity_preserved = true;
        record.exact_checkpoint_preserved = true;
        record.exact_idempotency_preserved = true;
        record.reader_no_effects_verified = true;
        record
    }
    #[test]
    fn death_marker_cannot_replace_verified_sigkill_reap_and_group_absence() {
        assert!(death_marker_v1(&format!("{DEATH_MARKER}\n"), true, true, false).unwrap());
        assert!(producer_cleanup_verified(&process(libc::SIGKILL)));
        assert!(!producer_cleanup_verified(&process(0)));
        assert!(!producer_cleanup_verified(&process(libc::SIGTERM)));
        let mut absent = process(libc::SIGKILL);
        absent.group_signal = GroupSignalV1::AlreadyAbsentWhileLeaderOwned;
        assert!(!producer_cleanup_verified(&absent));
        absent.group_signal = GroupSignalV1::Unverified;
        assert!(!producer_cleanup_verified(&absent));
    }
    #[test]
    fn reader_never_starts_after_unverified_producer_cleanup() {
        let mut checked = process(libc::SIGKILL);
        checked.direct_child = DirectChildV1::Unverified;
        assert!(!producer_cleanup_verified(&checked));
        checked = process(libc::SIGKILL);
        checked.group_absence = GroupAbsenceV1::Unverified;
        assert!(!producer_cleanup_verified(&checked));
        checked = process(libc::SIGKILL);
        checked.status = None;
        assert!(!producer_cleanup_verified(&checked));
    }
    #[test]
    fn two_process_stages_share_one_original_deadline() {
        // Script parity uses the actual producer/reader arrays, not a duplicate
        // production authority or a replacement native approval fixture.
        let stage_reviews = |inputs: Vec<Input<'static>>| {
            inputs
                .into_iter()
                .filter_map(|input| match input {
                    Input::ExactReview { detail, .. }
                        if detail.starts_with("Inspect exact original private V3")
                            || detail.starts_with("Approve V3 private fixed stage") =>
                    {
                        Some(detail)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let inspection = "Inspect exact original private V3 stage metadata.";
        assert_eq!(
            stage_reviews(producer_inputs()),
            vec![
                inspection,
                "Approve V3 private fixed stage Prepare.",
                inspection,
                "Approve V3 private fixed stage AdmitOriginal.",
                inspection,
                "Approve V3 private fixed stage ProveOriginal.",
                inspection,
                "Approve V3 private fixed stage FreezeFixed.",
                inspection,
                "Approve V3 private fixed stage ReadFixed.",
            ]
        );
        assert_eq!(
            stage_reviews(reader_inputs()),
            vec![inspection, "Approve V3 private fixed stage ReadFixed."]
        );
        for inputs in [producer_inputs(), reader_inputs()] {
            assert!(!inputs.into_iter().any(|input| matches!(input, Input::ExactReview { detail, .. }
                if detail.starts_with("Allow InspectStatus") || detail.starts_with("Allow ProveLocally")
                    || detail.starts_with("Allow RetainPrivateWitnesses") || detail.starts_with("Observe this exact retained")
                    || detail.starts_with("Allow this exact original private material for bounded"))));
        }
        let start = Instant::now();
        let deadline = start + WORKFLOW_LIMIT;
        assert!(before_original_cutoff(
            deadline,
            start + Duration::from_secs(899)
        ));
        assert!(!before_original_cutoff(
            deadline,
            start + Duration::from_secs(900)
        ));
        assert!(!before_original_cutoff(
            deadline,
            start + Duration::from_secs(901)
        ));
        let reader_start = start + Duration::from_secs(899);
        assert_eq!(
            deadline.duration_since(reader_start),
            Duration::from_secs(1)
        );
    }
    #[test]
    fn fixed_outcome_is_closed_and_has_no_private_values() {
        let text = success().public_json().unwrap();
        assert!(text.len() <= 2048);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 20);
        for name in [
            "path",
            "hash",
            "candidate_id",
            "job_id",
            "password",
            "pczt",
            "timestamp",
            "pid",
        ] {
            assert!(!value.as_object().unwrap().contains_key(name));
        }
        for mutate in [
            |r: &mut PublicOutcomeV1| r.producer_reaped = false,
            |r: &mut PublicOutcomeV1| r.producer_group_absent = false,
            |r: &mut PublicOutcomeV1| r.reader_reaped = false,
            |r: &mut PublicOutcomeV1| r.reader_group_absent = false,
            |r: &mut PublicOutcomeV1| r.reader_no_effects_verified = false,
            |r: &mut PublicOutcomeV1| r.fixed_verified = false,
            |r: &mut PublicOutcomeV1| r.exact_identity_preserved = false,
            |r: &mut PublicOutcomeV1| r.exact_checkpoint_preserved = false,
            |r: &mut PublicOutcomeV1| r.exact_idempotency_preserved = false,
            |r: &mut PublicOutcomeV1| r.authorization_allowed = true,
        ] {
            let mut row = success();
            mutate(&mut row);
            assert!(row.public_json().is_err());
        }
        let mut row = success();
        row.fail("PrivateWorkspaceProof");
        row.fail("PrivateWorkspaceRootCleanup");
        assert_eq!(row.first_failure.as_deref(), Some("PrivateWorkspaceProof"));
        assert!(row.public_json().is_ok());
        let duplicate = text.trim_end_matches('}').to_owned() + ",\"schema\":1}";
        assert!(serde_json::from_str::<PublicOutcomeV1>(&duplicate).is_err());
    }
    #[test]
    fn fragmented_utf8_and_marker_use_the_existing_bounded_transcript() {
        let root = std::path::Path::new("/inert-owned-test-root");
        let line = format!("native \u{2013}\n{DEATH_MARKER}\r\n");
        for split in 0..=line.len() {
            let mut transcript = rolling_transcript_v1::Transcript::new([]).unwrap();
            transcript.append(&line.as_bytes()[..split], root).unwrap();
            if let Some(tail) = transcript.tail().unwrap() {
                let _ = death_marker_v1(tail, true, true, false).unwrap();
            }
            transcript.append(&line.as_bytes()[split..], root).unwrap();
            transcript.finish_text().unwrap();
            assert!(
                death_marker_v1(transcript.tail().unwrap().unwrap(), true, true, true).unwrap()
            );
        }
    }
    #[test]
    fn early_duplicate_and_partial_death_markers_refuse() {
        let line = format!("{DEATH_MARKER}\n");
        assert!(death_marker_v1(&line, true, false, false).is_err());
        assert!(death_marker_v1(&line, false, true, false).is_err());
        assert!(death_marker_v1(&(line.clone() + &line), true, true, false).is_err());
        assert!(!death_marker_v1(DEATH_MARKER, true, true, false).unwrap());
        assert!(death_marker_v1(DEATH_MARKER, true, true, true).is_err());
        assert!(death_marker_v1(&(line + "SYNTHETIC_PRIVATE_FIXED"), true, true, true).is_err());
        for line in [
            format!("prefix {DEATH_MARKER}\n"),
            format!("{DEATH_MARKER} suffix\n"),
            format!("{DEATH_MARKER}\r\r\n"),
        ] {
            assert!(!death_marker_v1(&line, true, true, false).unwrap());
        }
    }
    #[test]
    fn final_response_consumption_precedes_terminal_marker_retention() {
        let root = std::path::Path::new("/inert-owned-test-root");
        let mut transcript = rolling_transcript_v1::Transcript::new([]).unwrap();
        transcript
            .append(b"last exact native prompt: ", root)
            .unwrap();
        assert!(!death_marker_v1(transcript.tail().unwrap().unwrap(), true, false, false).unwrap());
        // Real driver consumes only after final response delivery; no consume
        // is permitted after inputs_complete. Terminal duplicate remains visible.
        transcript.consume(None).unwrap();
        transcript
            .append(format!("{DEATH_MARKER}\n").as_bytes(), root)
            .unwrap();
        assert!(death_marker_v1(transcript.tail().unwrap().unwrap(), true, true, false).unwrap());
        transcript
            .append(format!("{DEATH_MARKER}\n").as_bytes(), root)
            .unwrap();
        assert!(death_marker_v1(transcript.tail().unwrap().unwrap(), true, true, true).is_err());
    }
    #[test]
    fn private_fixed_diagnostic_reader_final_sites_forward_actual_errors() {
        let _scope = private_diagnostic::begin_private_fixed_diagnostic_scope_v1();
        let result: Result<()> = diagnostic_result_at(
            DiagnosticOperation::ReadFixed,
            DiagnosticSite::ReaderCompletionWrite,
            Err(io::Error::other("PRIVATE completion path").into()),
        );
        assert!(matches!(result, Err(Error::Storage)));
        let value = private_diagnostic::private_fixed_diagnostic_snapshot_v1().unwrap();
        assert_eq!(value.primary.site, DiagnosticSite::ReaderCompletionWrite);
        assert!(!value.canonical_json().unwrap().contains("PRIVATE"));
    }
    #[test]
    fn private_fixed_diagnostic_cleanup_never_replaces_first_observed_failure() {
        let _scope = private_diagnostic::begin_private_fixed_diagnostic_scope_v1();
        let first: Result<()> = diagnostic_result_at(
            DiagnosticOperation::ReadFixed,
            DiagnosticSite::ReaderComparisonVerify,
            Err(Error::Authentication),
        );
        let cleanup: Result<()> = diagnostic_result_at(
            DiagnosticOperation::ReadFixed,
            DiagnosticSite::ReaderFinalReturn,
            Err(Error::Storage),
        );
        assert!(matches!(first, Err(Error::Authentication)));
        assert!(matches!(cleanup, Err(Error::Storage)));
        assert_eq!(
            private_diagnostic::private_fixed_diagnostic_snapshot_v1()
                .unwrap()
                .primary
                .site,
            DiagnosticSite::ReaderComparisonVerify
        );
    }
    #[test]
    fn private_fixed_diagnostic_transport_waits_for_existing_cleanup_gate() {
        for process in [false, true] {
            for root in ["retained", "unverified", "closed_absent"] {
                assert_eq!(
                    private_fixed_detail_allowed(process, root),
                    process && root == "closed_absent"
                );
            }
        }
    }
}
