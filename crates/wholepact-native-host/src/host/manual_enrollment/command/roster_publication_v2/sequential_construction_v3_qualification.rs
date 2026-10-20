//! Ephemeral same-process-image qualification harness. All positive native input
//! below is SYNTHETIC controller delivery, not evidence of a human or compositor.
//! The child owns a real controlling PTY and calls the maintained terminal
//! challenge/foreground path. No native approval fields, completed construction
//! rows, installed provider configuration or production gate are fabricated.
//!
//! This first executable stage establishes the real Host/TTY test boundary and
//! the production refusal. It is NOT the two-owner construction acceptance test;
//! that stage must feed maintained retained owners to the shared inner method.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/synthetic_born_provider_v1.rs"]
mod synthetic_born_provider_v1;
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        io::{AsRawFd, FromRawFd},
        process::{CommandExt, ExitStatusExt},
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[path = "sequential_construction_v3_qualification/synthetic_provider_tls_v1.rs"]
mod synthetic_provider_tls_v1;

// Shares only the process/PTY test harness, not the old V3 construction owner.
#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
#[path = "sequential_construction_v3_qualification/durable_proposal_v1.rs"]
mod durable_proposal_v1;

#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/constructed_joined_v3.rs"]
mod constructed_joined_v3;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/continued_joined_v3.rs"]
mod continued_joined_v3;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/initial_joined_v3.rs"]
mod initial_joined_v3;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/joined_signer_worker_v1.rs"]
mod joined_signer_worker_v1;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/observed_joined_v3.rs"]
mod observed_joined_v3;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/retained_joined_v3.rs"]
mod retained_joined_v3;

#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/full_joined_v3.rs"]
mod full_joined_v3;

#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/full_payment_inputs_v1.rs"]
mod full_payment_inputs_v1;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/full_payment_joined_v1.rs"]
mod full_payment_joined_v1;
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/named_request_projection_v1.rs"]
mod named_request_projection_v1;

#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/public_outcome_v1.rs"]
mod public_outcome_v1;

#[path = "sequential_construction_v3_qualification/safe_diagnostics_v1.rs"]
mod safe_diagnostics_v1;

#[path = "sequential_construction_v3_qualification/rolling_transcript_v1.rs"]
mod rolling_transcript_v1;

#[path = "sequential_construction_v3_qualification/owned_test_process_group_v1.rs"]
mod owned_test_process_group_v1;
#[path = "sequential_construction_v3_qualification/process_containment_v1.rs"]
mod process_containment_v1;

const CHILD: &str = "host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::synthetic_foreground_child";
const CHILD_ENV: &str = "WHOLEPACT_TEST_ONLY_ROSTER_FOREGROUND_STAGE";
const SCOPE: &str = "SYNTHETIC TEMPORARY V3 HARNESS: exact saved-metadata review only";

/// Input is accepted only after the exact expected local prompt. The harness
/// never prints a transcript or echoes private artifacts into test output.
enum Input<'a> {
    Text { prompt: &'a str, response: &'a str },
    CapturedPath { marker: &'a str, prompt: &'a str },
    ExactReview { detail: &'a str, approve: bool },
}

impl Input<'_> {
    fn rendered_expectation(&self) -> zeroize::Zeroizing<String> {
        let expected = match self {
            Self::Text { prompt, .. } | Self::CapturedPath { prompt, .. } => prompt,
            Self::ExactReview { detail, .. } => detail,
        };
        crate::terminal::render_synthetic_expected_prompt(expected)
    }
}

#[test]
fn finite_prompt_rendering_preserves_exact_terminal_purpose() {
    let source = "Exact purpose 12–1024: \t\r\0\u{1b}\nASCII";
    let expected = "Exact purpose 12\\u{2013}1024: \\t\\r\\u{0}\\u{1b}\nASCII";
    for input in [
        Input::Text {
            prompt: source,
            response: "unchanged-response",
        },
        Input::CapturedPath {
            marker: "FIXED_PUBLIC_MARKER=",
            prompt: source,
        },
        Input::ExactReview {
            detail: source,
            approve: true,
        },
    ] {
        let rendered = input.rendered_expectation();
        assert_eq!(rendered.as_str(), expected);
        assert!(!source.contains(rendered.as_str()));
        assert!(format!("prefix {expected} suffix").contains(rendered.as_str()));
        assert!(
            !expected
                .replace("Exact purpose", "Other purpose")
                .contains(rendered.as_str())
        );
    }
    let ascii = "ASCII purpose: ~!09, keep spaces and newline\n";
    assert_eq!(
        Input::Text {
            prompt: ascii,
            response: "unchanged-response"
        }
        .rendered_expectation()
        .as_str(),
        ascii
    );
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[test]
fn full_finite_prompt_census_uses_only_exact_rendered_expectations() {
    let full = full_payment_inputs_v1::inputs();
    assert_eq!(full.len(), 204);
    let mut escaped = 0;
    for input in &full {
        let source = match input {
            Input::Text { prompt, response } => {
                assert!(!response.contains(['\r', '\n']));
                *prompt
            }
            Input::CapturedPath { marker, prompt } => {
                // Path markers are exact ASCII, including when emitted through
                // Terminal::message. Keep their separate byte contract unchanged.
                assert!(!marker.is_empty() && marker.bytes().all(|b| b.is_ascii_graphic()));
                *prompt
            }
            Input::ExactReview { detail, .. } => *detail,
        };
        let rendered = input.rendered_expectation();
        assert!(!rendered.is_empty());
        assert!(rendered.is_ascii());
        assert_eq!(
            rendered.as_str(),
            crate::terminal::render_synthetic_expected_prompt(source).as_str()
        );
        if source.is_ascii() {
            assert_eq!(rendered.as_str(), source);
        } else {
            escaped += 1;
            assert_ne!(rendered.as_str(), source);
            assert!(rendered.contains("\\u{2013}"));
        }
    }
    // Two preliminary-wallet prompts plus the original checkpoint disclosure.
    assert_eq!(escaped, 3);
    assert_eq!(
        full[65].rendered_expectation().as_str(),
        "New preliminary wallet passphrase (12\\u{2013}1024 bytes): "
    );
}

const CHILD_TEMPORARY_PREFIX: &str = "wp-pty-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemporaryRootCleanupV1 {
    ClosedAndAbsenceVerified,
    RetainedForUnverifiedProcess,
    CloseOrAbsenceUnverified,
}
fn close_owned_temporary_root(root: tempfile::TempDir) -> TemporaryRootCleanupV1 {
    // Exact owned path only; never enumerate/read artifacts or print the path.
    // Filesystem deletion is checked, but is not a preemptible wall-clock bound.
    let exact_path = root.path().to_path_buf();
    let closed = root.close().is_ok();
    let absent = matches!(
        std::fs::symlink_metadata(&exact_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    if closed && absent {
        TemporaryRootCleanupV1::ClosedAndAbsenceVerified
    } else {
        TemporaryRootCleanupV1::CloseOrAbsenceUnverified
    }
}

/// Closed parent-driver cause only. Never carries a private error or transcript.
/// This does not classify the child's product failure or imply cancelled effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessFailureReason {
    Unclassified,
    Deadline,
    ChildObservation,
    ChildExit,
    PollIo,
    ReadIo,
    OutputLimit,
    IncompleteUtf8,
    InvalidUtf8,
    MultilineInput,
    WriteIo,
    FlushIo,
    MissingPathMarker,
    InvalidPath,
    InvalidChallenge,
    OutcomeRead,
    CleanupUnverified,
}

fn harness_io<T>(
    failure: &mut HarnessFailureReason,
    reason: HarnessFailureReason,
    result: std::io::Result<T>,
) -> std::io::Result<T> {
    result.map_err(|error| {
        *failure = reason;
        error
    })
}

fn harness_transcript<T>(
    failure: &mut HarnessFailureReason,
    result: std::result::Result<T, rolling_transcript_v1::Failure>,
) -> std::io::Result<T> {
    result.map_err(|error| {
        use rolling_transcript_v1::Failure;
        *failure = match error {
            Failure::OutputLimit => HarnessFailureReason::OutputLimit,
            Failure::IncompleteUtf8 => HarnessFailureReason::IncompleteUtf8,
            Failure::InvalidUtf8 => HarnessFailureReason::InvalidUtf8,
            Failure::InvalidPath => HarnessFailureReason::InvalidPath,
            Failure::MissingPath => HarnessFailureReason::MissingPathMarker,
        };
        std::io::Error::other("bounded synthetic transcript refused; private contents withheld")
    })
}

fn foreground_child(stage: &str, inputs: &[Input<'_>]) -> std::io::Result<()> {
    let mut failure_reason = HarnessFailureReason::Unclassified;
    let mut transcript = harness_transcript(
        &mut failure_reason,
        rolling_transcript_v1::Transcript::new(inputs.iter().filter_map(|input| match input {
            Input::CapturedPath { marker, .. } => Some(*marker),
            _ => None,
        })),
    )?;
    process_containment_v1::require_and_report_core_policy()?;
    // This creates a temporary terminal, not an OS trust root or permission
    // override. The child still passes the actual foreground() implementation.
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    if unsafe { libc::grantpt(master_fd) } != 0 || unsafe { libc::unlockpt(master_fd) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut slave_name = [0i8; 256];
    if unsafe { libc::ptsname_r(master_fd, slave_name.as_mut_ptr(), slave_name.len()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let slave_name = unsafe { std::ffi::CStr::from_ptr(slave_name.as_ptr()) };
    use std::os::unix::ffi::OsStrExt;
    let slave = OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::ffi::OsStr::from_bytes(slave_name.to_bytes()))?;
    // Parent owns the exact synthetic root through process cleanup. It closes
    // and checks absence only after direct-child reap plus owned-group absence;
    // an uncertain process outcome retains the root without publishing its path.
    // TMPDIR changes allocation only in this isolated test process.
    let child_temporary_root = owned_test_process_group_v1::PreSpawnTemporaryRootV1::new(
        tempfile::Builder::new()
            .prefix(CHILD_TEMPORARY_PREFIX)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?,
    );
    // TLS preparation also spawns OpenSSL. Require a preserving default
    // SIGCHLD disposition before any fixture child creation, without changing it.
    // This exact test invocation must have no competing waiter or policy writer.
    if let Err(error) = owned_test_process_group_v1::require_default_child_wait_policy() {
        let _ = child_temporary_root.keep();
        return Err(std::io::Error::new(
            error.kind(),
            "synthetic child wait policy unverified; no fixture child started; owned root retained",
        ));
    }
    let tls_material =
        match synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(child_temporary_root.path()) {
            Ok(material) => material,
            Err(error) => {
                // Preparation uses exact bounded direct-child cleanup. Every error
                // still retains this root, without promoting uncertain cleanup.
                let _ = child_temporary_root.keep();
                return Err(std::io::Error::new(
                    error.kind(),
                    "synthetic TLS preparation failed; cleanup unverified; owned root retained",
                ));
            }
        };
    let prepared_command = (|| -> std::io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        tls_material.configure_child(&mut command);
        command
            .args([
                "--exact",
                CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, stage)
            .env("TMPDIR", child_temporary_root.path())
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        unsafe {
            command.pre_exec(|| {
                // Only the new child changes session membership. No parent's TTY,
                // foreground group or persistent system setting is changed.
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::tcsetpgrp(0, libc::getpgrp()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(command)
    })();
    let mut command = match prepared_command {
        Ok(command) => command,
        Err(error) => {
            // TLS preparation completed and no main child spawn was attempted.
            let cleanup = close_owned_temporary_root(child_temporary_root.into_tempdir());
            return Err(std::io::Error::new(
                error.kind(),
                format!("synthetic child command preparation failed; root_cleanup={cleanup:?}"),
            ));
        }
    };
    let spawned = match owned_test_process_group_v1::spawn_with_checked_wait_policy(&mut command) {
        Ok(child) => child,
        Err(error) => {
            // No Child handle is available to demonstrate ownership/reap. Do
            // not turn an ambiguous launch failure into root-removal evidence.
            let _ = child_temporary_root.keep();
            return Err(std::io::Error::new(
                error.kind(),
                "synthetic child spawn failed; cleanup unverified; owned root retained",
            ));
        }
    };
    let mut child = owned_test_process_group_v1::OwnedTestProcessGroupV1::from_spawned_session(
        spawned,
        child_temporary_root.into_tempdir(),
    );
    let safety_seconds = if matches!(
        stage,
        "three-born-retained-inputs-v3"
            | "three-born-all-observations-v3"
            | "three-born-constructed-checkpoint-v3"
            | "three-born-full-payment-v1"
            | "durable-proposal-native-owner-reopen-v1"
            | "durable-proposal-native-fixed-signing-v1"
            | "durable-proposal-native-acquire-reply-loss-v1"
    ) {
        900
    } else {
        180
    };
    let deadline = Instant::now() + Duration::from_secs(safety_seconds);
    let mut next = 0;
    #[allow(unused_mut)] // Mutation only for the synthetic public-sidecar check.
    let mut outcome = (|| {
        loop {
            if Instant::now() >= deadline {
                failure_reason = HarnessFailureReason::Deadline;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "synthetic foreground stage exceeded its original deadline",
                ));
            }
            if let Some(success) = harness_io(
                &mut failure_reason,
                HarnessFailureReason::ChildObservation,
                child.observe_exit(),
            )? {
                if success && next == inputs.len() {
                    // Observation/cleanup grace cannot renew the original stage.
                    if Instant::now() >= deadline {
                        failure_reason = HarnessFailureReason::Deadline;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "synthetic foreground success observed after original deadline",
                        ));
                    }
                    harness_transcript(&mut failure_reason, transcript.finish_text())?;
                    return Ok(());
                }
                // Child exit can precede our final PTY read. Drain only already
                // available bounded bytes; never wait or expose the transcript.
                for _ in 0..64 {
                    let mut descriptor = libc::pollfd {
                        fd: master.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut descriptor, 1, 0) } <= 0
                        || descriptor.revents & libc::POLLIN == 0
                    {
                        break;
                    }
                    let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
                    let Ok(length) = master.read(&mut chunk[..]) else {
                        break;
                    };
                    if length == 0
                        || transcript
                            .append(&chunk[..length], child.temporary_root())
                            .is_err()
                    {
                        break;
                    }
                }
                failure_reason = HarnessFailureReason::ChildExit;
                return Err(std::io::Error::other("synthetic foreground child failed"));
            }
            let mut descriptor = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut descriptor, 1, 50) } < 0 {
                failure_reason = HarnessFailureReason::PollIo;
                return Err(std::io::Error::last_os_error());
            }
            if descriptor.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
            let length = harness_io(
                &mut failure_reason,
                HarnessFailureReason::ReadIo,
                master.read(&mut chunk[..]),
            )?;
            if length == 0 {
                continue;
            }
            harness_transcript(
                &mut failure_reason,
                transcript.append(&chunk[..length], child.temporary_root()),
            )?;
            let Some(input) = inputs.get(next) else {
                continue;
            };
            let Some(tail) = harness_transcript(&mut failure_reason, transcript.tail())? else {
                // An incomplete final UTF-8 scalar waits for more bytes under
                // the unchanged original stage deadline. Invalid bytes refuse.
                continue;
            };
            let expected = input.rendered_expectation();
            let approve = match input {
                Input::Text { response, .. } => {
                    if !tail.contains(expected.as_str()) {
                        continue;
                    }
                    if response.contains(['\n', '\r']) {
                        failure_reason = HarnessFailureReason::MultilineInput;
                        return Err(std::io::Error::other("multiline synthetic input denied"));
                    }
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(response.as_bytes()),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(b"\n"),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::FlushIo,
                        master.flush(),
                    )?;
                    harness_transcript(&mut failure_reason, transcript.consume(None))?;
                    next += 1;
                    continue;
                }
                Input::CapturedPath { marker, .. } => {
                    let Some(prompt) = tail.find(expected.as_str()) else {
                        continue;
                    };
                    let path =
                        harness_transcript(&mut failure_reason, transcript.path(marker, prompt))?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(path.as_bytes()),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(b"\n"),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::FlushIo,
                        master.flush(),
                    )?;
                    harness_transcript(&mut failure_reason, transcript.consume(Some(marker)))?;
                    next += 1;
                    continue;
                }
                Input::ExactReview { approve, .. } => approve,
            };
            let Some(detail_start) = tail.find(expected.as_str()) else {
                continue;
            };
            let remaining = &tail[detail_start + expected.len()..];
            let prefix = "Type APPROVE ";
            let suffix = " to approve this exact operation, or anything else to reject: ";
            let Some(start) = remaining.find(prefix) else {
                continue;
            };
            let start = start + prefix.len();
            let Some(end) = remaining[start..].find(suffix) else {
                continue;
            };
            let challenge = &remaining[start..start + end];
            if challenge.len() != 16
                || !challenge
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                failure_reason = HarnessFailureReason::InvalidChallenge;
                return Err(std::io::Error::other(
                    "unexpected native exact-review challenge",
                ));
            }
            if *approve {
                harness_io(
                    &mut failure_reason,
                    HarnessFailureReason::WriteIo,
                    master.write_all(format!("APPROVE {challenge}\n").as_bytes()),
                )?;
            } else {
                harness_io(
                    &mut failure_reason,
                    HarnessFailureReason::WriteIo,
                    master.write_all(b"REJECT\n"),
                )?;
            }
            harness_io(
                &mut failure_reason,
                HarnessFailureReason::FlushIo,
                master.flush(),
            )?;
            harness_transcript(&mut failure_reason, transcript.consume(None))?;
            next += 1;
        }
    })();
    // Cleanup never converts an uncertain operation into cancelled/absent work.
    // Exactly one anchored group signal precedes the exact direct-child reap.
    let finished = child.finish();
    let process = finished.process;
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-full-payment-v1" {
        // Timing only: successful exit can precede the final PTY read. After
        // exact reap, drain at most64 already-available chunks into the fixed
        // timing framer, never the private transcript or outcome predicate.
        let mut drained = false;
        let flags = if process.verified() {
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) }
        } else {
            -1
        };
        // This descriptor belongs only to the already-reaped child fixture.
        // Failure to make the final reads nonblocking only loses telemetry.
        if flags >= 0
            && unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                >= 0
        {
            for _ in 0..64 {
                let mut descriptor = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
                if ready < 0 || descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    break;
                }
                if ready == 0 || descriptor.revents & libc::POLLIN == 0 {
                    drained = true;
                    break;
                }
                let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
                match master.read(&mut chunk[..]) {
                    Ok(0) => {
                        drained = true;
                        break;
                    }
                    Ok(length) => transcript.capture_timing(&chunk[..length]),
                    Err(_) => break,
                }
            }
        }
        transcript.finish_timing(drained);
    }
    // Read only the fixed PUBLIC sidecar, after exact direct-child reap and
    // original group absence. A failed/timed-out child never promotes its file.
    // Save validation failure, then still explicitly close the actual root.
    #[cfg(feature = "synthetic-born-joined-qualification")]
    let public_json =
        if stage == "three-born-full-payment-v1" && outcome.is_ok() && process.verified() {
            let parsed = finished
                .root_for_explicit_close
                .as_ref()
                .ok_or_else(|| std::io::Error::other("synthetic public outcome root unavailable"))
                .and_then(|root| public_outcome_v1::read_after_reap(root.path()))
                .and_then(|record| record.public_json());
            match parsed {
                Ok(json) => Some(json),
                Err(_) => {
                    failure_reason = HarnessFailureReason::OutcomeRead;
                    outcome = Err(std::io::Error::other(
                        "synthetic public outcome missing or invalid; private details withheld",
                    ));
                    None
                }
            }
        } else {
            None
        };
    let root_cleanup = match finished.root_for_explicit_close {
        Some(root) => close_owned_temporary_root(root),
        None => TemporaryRootCleanupV1::RetainedForUnverifiedProcess,
    };
    // Closed enum labels and numeric status only, after process cleanup and
    // explicit close/absence observation when allowed. Unverified stays explicit.
    eprintln!(
        "[JOINED_CLEANUP group_signal={:?} group_absence={:?} direct_child={:?} root_cleanup={:?} exit={:?} signal={:?} core_dumped={}]",
        process.group_signal,
        process.group_absence,
        process.direct_child,
        root_cleanup,
        process.status.as_ref().and_then(|status| status.code()),
        process.status.as_ref().and_then(|status| status.signal()),
        process
            .status
            .as_ref()
            .is_some_and(|status| status.core_dumped()),
    );
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-full-payment-v1"
        && process.verified()
        && root_cleanup == TemporaryRootCleanupV1::ClosedAndAbsenceVerified
    {
        if let Some(json) = transcript.timing_json() {
            // Optional telemetry only, even on failure. Write errors cannot
            // replace the original result or verified cleanup evidence.
            let _ = writeln!(std::io::stderr().lock(), "[JOINED_TIMING {json}]");
        }
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if (stage == "durable-proposal-native-fixed-signing-v1"
        || stage == "durable-proposal-native-acquire-reply-loss-v1")
        && process.verified()
        && root_cleanup == TemporaryRootCleanupV1::ClosedAndAbsenceVerified
    {
        // Only reparsed, bounded canonical records survive the private PTY.
        // Optional observations survive a failed scenario but cannot replace
        // its result or make an unverified cleanup look verified.
        for line in transcript
            .history_measurement_lines()
            .into_iter()
            .chain(transcript.admission_diagnostic_lines())
            .chain(transcript.durable_flow_lines())
            .chain(transcript.durable_lifecycle_lines())
        {
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
    }
    if outcome.is_err()
        || !process.verified()
        || root_cleanup != TemporaryRootCleanupV1::ClosedAndAbsenceVerified
    {
        if outcome.is_ok() {
            failure_reason = HarnessFailureReason::CleanupUnverified;
        }
        // Portable evidence extraction must never print a panic or raw PTY log.
        // The projection reparses only closed labels and canonical numeric errno.
        eprintln!(
            "[JOINED_FAILURE exit={:?} signal={:?} core_dumped={} inputs={}/{} reason={:?} static_boundaries={}]",
            process.status.as_ref().and_then(|status| status.code()),
            process.status.as_ref().and_then(|status| status.signal()),
            process
                .status
                .as_ref()
                .is_some_and(|status| status.core_dumped()),
            next,
            inputs.len(),
            failure_reason,
            transcript.summary(),
        );
    }
    if !process.verified() || root_cleanup != TemporaryRootCleanupV1::ClosedAndAbsenceVerified {
        let kind = outcome
            .as_ref()
            .err()
            .map_or(std::io::ErrorKind::Other, |error| error.kind());
        return Err(std::io::Error::new(
            kind,
            format!(
                "synthetic foreground cleanup unverified; private transcript withheld; group_signal={:?}; group_absence={:?}; direct_child={:?}; root_cleanup={:?}; exit={:?}; signal={:?}; core_dumped={}",
                process.group_signal,
                process.group_absence,
                process.direct_child,
                root_cleanup,
                process.status.as_ref().and_then(|status| status.code()),
                process.status.as_ref().and_then(|status| status.signal()),
                process
                    .status
                    .as_ref()
                    .is_some_and(|status| status.core_dumped()),
            ),
        ));
    }
    let status = process.status;
    outcome.map_err(|error| std::io::Error::new(error.kind(), format!(
        "synthetic foreground child failed; private transcript withheld; exit={:?}; signal={:?}; core_dumped={}; inputs={}/{}; static_boundaries={}",
        status.as_ref().and_then(|status| status.code()),
        status.as_ref().and_then(|status| status.signal()),
        status.as_ref().is_some_and(|status| status.core_dumped()),
        next, inputs.len(), transcript.summary(),
    )))?;
    // This is the only public outcome emission. The actual computation, exact
    // owned-process cleanup and explicit root close/absence have all succeeded.
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Some(json) = public_json {
        eprintln!("{}{}", public_outcome_v1::PUBLIC_MARKER, json);
    }
    Ok(())
}

#[test]
fn actual_host_public_refusal_and_foreground_review_controller() {
    foreground_child(
        "host-boundary-v1",
        &[
            Input::ExactReview {
                detail: SCOPE,
                approve: false,
            },
            Input::ExactReview {
                detail: SCOPE,
                approve: true,
            },
        ],
    )
    .expect("ephemeral actual controlling-PTY stage; not construction qualification");
}

#[test]
#[ignore = "invoked only by the bounded controlling-PTY parent above"]
fn synthetic_foreground_child() {
    process_containment_v1::require_and_report_core_policy()
        .expect("inherited zero core limit and read-only collector classification");
    let stage = std::env::var(CHILD_ENV).expect("bounded synthetic parent stage");
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "private-workspace-read-fixed-v1" {
        let terminal = crate::terminal::Terminal::open().expect("actual independent reader TTY");
        durable_proposal_v1::private_fixed_v2::read_fixed_child(terminal).unwrap();
        return;
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "durable-delivery-native-history-v2" {
        let terminal =
            crate::terminal::Terminal::open().expect("actual independent delivery reader TTY");
        durable_proposal_v1::delivery_admission_v2::read_delivery_child(terminal).unwrap();
        return;
    }
    let _synthetic_tls = synthetic_provider_tls_v1::child_server_config()
        .expect("owned test-process TLS identity, not chain qualification");
    let terminal = crate::terminal::Terminal::open().expect("actual foreground child TTY");
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "private-workspace-produce-fixed-v1" {
        durable_proposal_v1::private_fixed_v2::produce_fixed_child(terminal).unwrap();
        return;
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "durable-delivery-native-admission-v2" {
        durable_proposal_v1::private_fixed_v2::produce_delivery_child(terminal).unwrap();
        return;
    }
    #[cfg(all(feature = "durable-proposal",feature = "synthetic-born-joined-qualification"))]
    if stage == "durable-financial-produce-v1" {
        durable_proposal_v1::private_fixed_v2::produce_financial_child(terminal).unwrap();
        return;
    }
    #[cfg(all(feature = "durable-proposal",feature = "synthetic-born-joined-qualification"))]
    if stage == "durable-financial-dispatch-v1" {
        durable_proposal_v1::delivery_admission_v2::durable_financial_dispatch_v1::read_financial_child(terminal).unwrap();
        return;
    }
    if stage == "bounded-dispatch-review-v1" {
        let digest = "a".repeat(64);
        let detail = "SYNTHETIC TEMPORARY DISPATCH REVIEW: controller-only; no transaction or financial effect";
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(matches!(
            terminal.approve_born_dispatch_until_v1(&digest, detail, deadline, || Ok(())),
            Err(Error::Permission)
        ));
        let approved = terminal
            .approve_born_dispatch_until_v1(&digest, detail, deadline, || Ok(()))
            .unwrap();
        assert_eq!(approved.deadline(), deadline);
        let mut effect = 0;
        approved
            .commit(
                &digest,
                || Ok(()),
                |()| {
                    effect += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(effect, 1);
        return;
    }
    if stage == "bounded-dispatch-no-input-v1" {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(250);
        let result = terminal.approve_born_dispatch_until_v1(
            &"b".repeat(64),
            "SYNTHETIC TEMPORARY DISPATCH REVIEW: no-input deadline denial, no financial effect",
            deadline,
            || Ok(()),
        );
        assert!(matches!(result, Err(Error::Permission)));
        assert!(deadline.saturating_duration_since(Instant::now()) <= Duration::from_millis(1));
        assert!(start.elapsed() < Duration::from_secs(3));
        return;
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "durable-proposal-native-owner-reopen-v1" {
        durable_proposal_v1::exercise_stage(terminal).unwrap();
        return;
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "durable-proposal-native-fixed-signing-v1" {
        durable_proposal_v1::exercise_fixed_signing_stage(terminal).unwrap();
        return;
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    if stage == "durable-proposal-native-acquire-reply-loss-v1" {
        durable_proposal_v1::exercise_acquire_reply_loss_stage(terminal).unwrap();
        return;
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-initial-roster-v3" {
        initial_joined_v3::exercise_initial_audit_stage(terminal).unwrap();
        return;
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-retained-inputs-v3" {
        retained_joined_v3::exercise_retained_input_stage(terminal).unwrap();
        return;
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-all-observations-v3" {
        observed_joined_v3::exercise_all_observations_stage(terminal).unwrap();
        return;
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-constructed-checkpoint-v3" {
        constructed_joined_v3::exercise_constructed_checkpoint_stage(terminal).unwrap();
        return;
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if stage == "three-born-full-payment-v1" {
        full_payment_inputs_v1::exercise_full_payment_stage(terminal).unwrap();
        return;
    }
    if stage == "empty-layered-host-v1" {
        let (temporary, host) = crate::host::born_test_host_v1::create(terminal).unwrap();
        host.require_manual_session().unwrap();
        assert!(matches!(
            host.manual_roster_sequential_construct_v3_command(),
            Err(Error::Receipt(_))
        ));
        assert!(matches!(
            host.construct_retained_sequential_roster_v3(
                Vec::new(),
                "synthetic-key-v3-001".into(),
                4
            ),
            Err(Error::Invalid)
        ));
        // Actual source/session exist, but no constructed owner is fabricated.
        assert!(host.require_financial_generation_admission().is_err());
        host.authority.fence.revoke().unwrap();
        drop(host);
        drop(temporary);
        return;
    }
    assert_eq!(stage, "host-boundary-v1");
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("synthetic-host");
    let password = b"PUBLIC-NEVER-FUNDED-EPHEMERAL-HOST-TEST";
    crate::host::initialize(&profile, password).unwrap();
    let directory = crate::files::Directory::open(&profile).unwrap();
    let secrets =
        crate::vault::Secrets::open(&directory.read("profile.vault", 1024).unwrap(), password)
            .unwrap();
    let host = Host::open(directory, secrets, terminal.clone()).unwrap();
    assert!(host.access.is_none());
    // Real public command on a real encrypted Host, before session/prompt/source.
    assert!(matches!(
        host.manual_roster_sequential_construct_v3_command(),
        Err(Error::Receipt(_))
    ));
    // The shared inner boundary does not synthesize a session or owner from an
    // empty vector. A successful full test must supply actual produced owners.
    assert!(matches!(
        host.construct_retained_sequential_roster_v3(Vec::new(), "synthetic-key-v3-001".into(), 4),
        Err(Error::Permission)
    ));
    assert!(terminal.approve_historical(SCOPE).is_err());
    let approval = terminal.approve_historical(SCOPE).unwrap();
    let mut effects = 0;
    approval
        .effect(&mut || {
            effects += 1;
            Ok(())
        })
        .unwrap();
    assert!(
        approval
            .effect(&mut || {
                effects += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(effects, 1);
    host.authority.fence.revoke().unwrap();
    drop(host);
    drop(temporary);
}

fn bootstrap_inputs() -> Vec<Input<'static>> {
    let password = "synthetic-recovery-review-password";
    use Input::{ExactReview as Review, Text};
    vec![
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: create genuinely EMPTY",
            approve: true,
        },
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: copy this genuinely empty original",
            approve: true,
        },
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: publish this actual empty first-generation",
            approve: true,
        },
        Review {
            detail: "Authenticate every inherited and current private host-owned journal",
            approve: true,
        },
        Text {
            prompt: "Restricted successor storage passphrase: ",
            response: password,
        },
        Text {
            prompt: "New generation capsule recovery passphrase: ",
            response: password,
        },
        Text {
            prompt: "Repeat capsule recovery passphrase: ",
            response: password,
        },
        Review {
            detail: "Create this exact NEW encrypted capsule.",
            approve: true,
        },
        Review {
            detail: "Authenticate and read every private record and NON-signing recovery key",
            approve: true,
        },
        Text {
            prompt: "Generation capsule recovery passphrase: ",
            response: password,
        },
        Text {
            prompt: "New quarantined-capsule passphrase: ",
            response: password,
        },
        Text {
            prompt: "Repeat quarantined-capsule passphrase: ",
            response: password,
        },
        Review {
            detail: "Copy this exact complete encrypted capsule into a NEW permanently quarantined root.",
            approve: true,
        },
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: authenticate the exact just-restored",
            approve: true,
        },
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: create a NEW exact layered",
            approve: true,
        },
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: copy the exact complete authenticated",
            approve: true,
        },
        Review {
            detail: "SYNTHETIC TEMPORARY JOINED TEST: publish the actual empty layered",
            approve: true,
        },
        Text {
            prompt: "Local application principal ID: ",
            response: "synthetic-roster-host",
        },
        Text {
            prompt: "Scope choice: type SELECTED",
            response: "OWNED",
        },
        Text {
            prompt: "Additional shared agreement IDs, comma-separated; blank for none: ",
            response: "",
        },
        Text {
            prompt: "Grant READ only, or PREPARE",
            response: "PREPARE",
        },
        Text {
            prompt: "Optional exact browser origin for this session",
            response: "",
        },
        Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_BOOTSTRAP_PATH=",
            prompt: "New private bootstrap credential file (absolute path",
        },
        Review {
            detail: "Grant this session until lock/restart/revoke.",
            approve: true,
        },
        Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_FINANCIAL_PATH=",
            prompt: "NEW private financial profile directory (absolute): ",
        },
        Review {
            detail: "Create separately encrypted financial journals for this exact primary profile.",
            approve: true,
        },
        Text {
            prompt: "New financial profile passphrase: ",
            response: password,
        },
        Text {
            prompt: "Repeat financial profile passphrase: ",
            response: password,
        },
    ]
}

#[test]
fn actual_empty_layered_host_bootstrap_preserves_public_refusal() {
    let inputs = bootstrap_inputs();
    foreground_child("empty-layered-host-v1", &inputs).expect(
        "actual temporary layered Host bootstrap; no born account or construction qualification",
    );
    // The child owns and removes the session file after revocation. This parent
    // never reads/prints the generated token, only its exact temporary path.
}

#[test]
fn actual_foreground_dispatch_review_preserves_original_deadline() {
    let detail =
        "SYNTHETIC TEMPORARY DISPATCH REVIEW: controller-only; no transaction or financial effect";
    foreground_child(
        "bounded-dispatch-review-v1",
        &[
            Input::ExactReview {
                detail,
                approve: false,
            },
            Input::ExactReview {
                detail,
                approve: true,
            },
        ],
    )
    .expect("actual controlling-PTY accept/reject, not attended or financial evidence");
    foreground_child("bounded-dispatch-no-input-v1", &[])
        .expect("actual controlling-PTY no-input expiry must deny promptly");
}

#[test]
fn joined_temporary_socket_names_fit_linux_pathname_budget() {
    // Pure format check only: no socket, account, credential or network action.
    // tempfile's default random suffix is six bytes; LocalIpc uses 12 random
    // bytes encoded as 24 hex characters in requests-<hex>.sock.
    let basename = format!("requests-{}.sock", hex::encode([0u8; 12]));
    let candidate = |outer: &str, inner: &str| {
        std::path::Path::new("/tmp")
            .join(format!("{outer}aaaaaa"))
            .join(format!("{inner}bbbbbb"))
            .join(&basename)
    };
    use std::os::unix::ffi::OsStrExt;
    let old = candidate(
        "wholepact-synthetic-pty-owner-",
        "wholepact-born-manual-ipc-",
    );
    assert_eq!(old.as_os_str().as_bytes().len(), 113);
    for inner in ["wholepact-born-manual-ipc-", "wholepact-born-stop-", ".tmp"] {
        let current = candidate(CHILD_TEMPORARY_PREFIX, inner);
        assert!(current.as_os_str().as_bytes().len() < 108);
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "sequential_construction_v3_qualification/synthetic_born_submission_sink_v1.rs"]
mod synthetic_born_submission_sink_v1;

#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PrivateWorkspaceStageV1 {
    Producer,
    Reader,
    DeliveryProducer,
    DeliveryReader,
    FinancialProducer,
    FinancialReader,
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
impl PrivateWorkspaceStageV1 {
    fn label(self) -> &'static str {
        match self {
            Self::Producer => "private-workspace-produce-fixed-v1",
            Self::Reader => "private-workspace-read-fixed-v1",
            Self::DeliveryProducer => "durable-delivery-native-admission-v2",
            Self::DeliveryReader => "durable-delivery-native-history-v2",
            Self::FinancialProducer => "durable-financial-produce-v1",
            Self::FinancialReader => "durable-financial-dispatch-v1",
        }
    }
    fn producer(self) -> bool {
        matches!(self, Self::Producer | Self::DeliveryProducer | Self::FinancialProducer)
    }
    fn marker(self, tail: &str, complete: bool, terminal: bool) -> std::io::Result<bool> {
        match self {
            Self::Producer | Self::Reader => {
                durable_proposal_v1::private_fixed_v2::death_marker_v1(
                    tail,
                    self.producer(),
                    complete,
                    terminal,
                )
            }
            Self::FinancialProducer | Self::FinancialReader => {
                durable_proposal_v1::delivery_admission_v2::durable_financial_dispatch_v1::death_marker_financial_v1(tail,self.producer(),complete,terminal)
            }
            Self::DeliveryProducer | Self::DeliveryReader => {
                durable_proposal_v1::delivery_admission_v2::death_marker_v2(
                    tail,
                    self.producer(),
                    complete,
                    terminal,
                )
            }
        }
    }
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
struct PrivateWorkspaceStageResultV1 {
    delivery_first_failure: Option<safe_diagnostics_v1::DeliveryFailure>,
    private_fixed_diagnostic:
        Option<crate::host::durable_private_workspace_v1::PrivateFixedDiagnosticV1>,
    diagnostic_withheld: bool,
    outcome: std::io::Result<()>,
    process: owned_test_process_group_v1::ProcessCleanupV1,
    root: Option<tempfile::TempDir>,
    summary: String,
    failure_reason: HarnessFailureReason,
    next: usize,
    expected: usize,
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
impl PrivateWorkspaceStageResultV1 {
    fn private_fixed_diagnostic(
        &self,
    ) -> Option<&crate::host::durable_private_workspace_v1::PrivateFixedDiagnosticV1> {
        self.private_fixed_diagnostic.as_ref()
    }
    fn diagnostic_withheld(&self) -> bool {
        self.diagnostic_withheld
    }
}

/// Exactly one stage, sharing the caller's original cutoff and returning the
/// SAME TempDir only after existing exact process cleanup. No authority owner
/// exists in this controller. Existing single-child adapter is unchanged.
#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
fn private_workspace_stage_v1(
    root: tempfile::TempDir,
    tls_material: Option<&synthetic_provider_tls_v1::ChildTlsMaterialV1>,
    stage: PrivateWorkspaceStageV1,
    inputs: &[Input<'_>],
    deadline: Instant,
    monotonic_cutoff_ns: u64,
) -> std::io::Result<PrivateWorkspaceStageResultV1> {
    let needs_original_tls = stage.producer() || matches!(stage, PrivateWorkspaceStageV1::FinancialReader);
    if needs_original_tls != tls_material.is_some() {
        let _ = root.keep();
        return Err(std::io::Error::other(
            "exact private workspace child role refused",
        ));
    }
    let child_temporary_root = owned_test_process_group_v1::PreSpawnTemporaryRootV1::new(root);
    let mut failure_reason = HarnessFailureReason::Unclassified;
    let mut transcript = harness_transcript(
        &mut failure_reason,
        rolling_transcript_v1::Transcript::new(inputs.iter().filter_map(|input| match input {
            Input::CapturedPath { marker, .. } => Some(*marker),
            _ => None,
        })),
    )?;
    if matches!(stage, PrivateWorkspaceStageV1::DeliveryProducer | PrivateWorkspaceStageV1::DeliveryReader) {
        transcript.enable_delivery_first_failure();
    }
    // This creates a temporary terminal, not an OS trust root or permission
    // override. The child still passes the actual foreground() implementation.
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    if unsafe { libc::grantpt(master_fd) } != 0 || unsafe { libc::unlockpt(master_fd) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut slave_name = [0i8; 256];
    if unsafe { libc::ptsname_r(master_fd, slave_name.as_mut_ptr(), slave_name.len()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let slave_name = unsafe { std::ffi::CStr::from_ptr(slave_name.as_ptr()) };
    use std::os::unix::ffi::OsStrExt;
    let slave = OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::ffi::OsStr::from_bytes(slave_name.to_bytes()))?;
    let prepared_command = (|| -> std::io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        if let Some(material) = tls_material {
            material.configure_child(&mut command);
        } else {
            // The reader has no TLS authority, server config or signer/witness.
            command
                .env_remove("SSL_CERT_FILE")
                .env_remove("SSL_CERT_DIR");
        }
        command
            .args([
                "--exact",
                CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, stage.label())
            .env(
                "WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS",
                monotonic_cutoff_ns.to_string(),
            )
            .env("TMPDIR", child_temporary_root.path())
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        unsafe {
            command.pre_exec(|| {
                // Only the new child changes session membership. No parent's TTY,
                // foreground group or persistent system setting is changed.
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::tcsetpgrp(0, libc::getpgrp()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(command)
    })();
    let mut command = match prepared_command {
        Ok(command) => command,
        Err(error) => {
            // TLS preparation completed and no main child spawn was attempted.
            let cleanup = close_owned_temporary_root(child_temporary_root.into_tempdir());
            return Err(std::io::Error::new(
                error.kind(),
                format!("synthetic child command preparation failed; root_cleanup={cleanup:?}"),
            ));
        }
    };
    if Instant::now() >= deadline {
        let _ = close_owned_temporary_root(child_temporary_root.into_tempdir());
        return Err(std::io::Error::other(
            "original two-process cutoff expired before child spawn",
        ));
    }
    let spawned = match owned_test_process_group_v1::spawn_with_checked_wait_policy(&mut command) {
        Ok(child) => child,
        Err(error) => {
            // No Child handle is available to demonstrate ownership/reap. Do
            // not turn an ambiguous launch failure into root-removal evidence.
            let _ = child_temporary_root.keep();
            return Err(std::io::Error::new(
                error.kind(),
                "synthetic child spawn failed; cleanup unverified; owned root retained",
            ));
        }
    };
    // Close the parent's Command-owned slave handles before requiring PTY EOF.
    drop(command);
    let mut child = owned_test_process_group_v1::OwnedTestProcessGroupV1::from_spawned_session(
        spawned,
        child_temporary_root.into_tempdir(),
    );

    let mut next = 0;
    let mut marker_seen = false;
    let mut outcome = (|| -> std::io::Result<()> {
        loop {
            if Instant::now() >= deadline {
                failure_reason = HarnessFailureReason::Deadline;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "original two-process deadline expired",
                ));
            }
            if let Some(success) = harness_io(
                &mut failure_reason,
                HarnessFailureReason::ChildObservation,
                child.observe_exit(),
            )? {
                if !stage.producer() && success && next == inputs.len() {
                    // Remaining PTY bytes may complete a split UTF-8 scalar.
                    // Only the bounded post-reap terminal drain finishes text.
                    return Ok(());
                }
                failure_reason = HarnessFailureReason::ChildExit;
                return Err(std::io::Error::other(
                    "private workspace child exited before verified stage completion",
                ));
            }
            let mut descriptor = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut descriptor, 1, 50) } < 0 {
                failure_reason = HarnessFailureReason::PollIo;
                return Err(std::io::Error::last_os_error());
            }
            if descriptor.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
            let length = harness_io(
                &mut failure_reason,
                HarnessFailureReason::ReadIo,
                master.read(&mut chunk[..]),
            )?;
            if length == 0 {
                continue;
            }
            harness_transcript(
                &mut failure_reason,
                transcript.append(&chunk[..length], child.temporary_root()),
            )?;
            // Inspect BEFORE consuming any ordinary input. An early marker
            // cannot be erased by rolling transcript compaction.
            if let Some(tail) = harness_transcript(&mut failure_reason, transcript.tail())? {
                let recognized = stage.marker(tail, next == inputs.len(), false)?;
                if recognized {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("original deadline expired"));
                    }
                    marker_seen = true;
                    break;
                }
            }
            let Some(input) = inputs.get(next) else {
                continue;
            };
            let Some(tail) = harness_transcript(&mut failure_reason, transcript.tail())? else {
                // An incomplete final UTF-8 scalar waits for more bytes under
                // the unchanged original stage deadline. Invalid bytes refuse.
                continue;
            };
            let expected = input.rendered_expectation();
            let approve = match input {
                Input::Text { response, .. } => {
                    if !tail.contains(expected.as_str()) {
                        continue;
                    }
                    if response.contains(['\n', '\r']) {
                        failure_reason = HarnessFailureReason::MultilineInput;
                        return Err(std::io::Error::other("multiline synthetic input denied"));
                    }
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(response.as_bytes()),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(b"\n"),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::FlushIo,
                        master.flush(),
                    )?;
                    harness_transcript(&mut failure_reason, transcript.consume(None))?;
                    next += 1;
                    continue;
                }
                Input::CapturedPath { marker, .. } => {
                    let Some(prompt) = tail.find(expected.as_str()) else {
                        continue;
                    };
                    let path =
                        harness_transcript(&mut failure_reason, transcript.path(marker, prompt))?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(path.as_bytes()),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::WriteIo,
                        master.write_all(b"\n"),
                    )?;
                    harness_io(
                        &mut failure_reason,
                        HarnessFailureReason::FlushIo,
                        master.flush(),
                    )?;
                    harness_transcript(&mut failure_reason, transcript.consume(Some(marker)))?;
                    next += 1;
                    continue;
                }
                Input::ExactReview { approve, .. } => approve,
            };
            let Some(detail_start) = tail.find(expected.as_str()) else {
                continue;
            };
            let remaining = &tail[detail_start + expected.len()..];
            let prefix = "Type APPROVE ";
            let suffix = " to approve this exact operation, or anything else to reject: ";
            let Some(start) = remaining.find(prefix) else {
                continue;
            };
            let start = start + prefix.len();
            let Some(end) = remaining[start..].find(suffix) else {
                continue;
            };
            let challenge = &remaining[start..start + end];
            if challenge.len() != 16
                || !challenge
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                failure_reason = HarnessFailureReason::InvalidChallenge;
                return Err(std::io::Error::other(
                    "unexpected native exact-review challenge",
                ));
            }
            if *approve {
                harness_io(
                    &mut failure_reason,
                    HarnessFailureReason::WriteIo,
                    master.write_all(format!("APPROVE {challenge}\n").as_bytes()),
                )?;
            } else {
                harness_io(
                    &mut failure_reason,
                    HarnessFailureReason::WriteIo,
                    master.write_all(b"REJECT\n"),
                )?;
            }
            harness_io(
                &mut failure_reason,
                HarnessFailureReason::FlushIo,
                master.flush(),
            )?;
            harness_transcript(&mut failure_reason, transcript.consume(None))?;
            next += 1;
        }
        Ok(())
    })();
    // Producer marker recognition immediately takes the one owned SIGKILL path.
    // Cleanup grace does not replace or extend the workflow cutoff.
    let finished = child.finish();
    let process = finished.process;
    if process.verified() {
        // No consume/eviction occurs after the final input. Drain only already
        // available data, and require terminal EOF/EIO/hangup, not quietness.
        let drained = private_workspace_terminal_drain_v1(
            &mut master,
            &mut transcript,
            finished
                .root_for_explicit_close
                .as_ref()
                .map(|root| root.path()),
        );
        if outcome.is_ok() {
            if let Err(error) = drained {
                failure_reason = HarnessFailureReason::ReadIo;
                outcome = Err(error);
            }
        }
        if stage.producer() && outcome.is_ok() {
            let valid = transcript.finish_text().is_ok()
                && transcript.tail().ok().flatten().is_some_and(|tail| {
                    stage
                        .marker(tail, next == inputs.len(), true)
                        .unwrap_or(false)
                });
            if !marker_seen || !valid {
                failure_reason = HarnessFailureReason::OutcomeRead;
                outcome = Err(std::io::Error::other(
                    "terminal durable marker validation failed",
                ));
            }
        }
    }
    if !stage.producer()
        && outcome.is_ok()
        && transcript
            .tail()
            .ok()
            .flatten()
            .is_none_or(|tail| stage.marker(tail, next == inputs.len(), false).is_err())
    {
        failure_reason = HarnessFailureReason::OutcomeRead;
        outcome = Err(std::io::Error::other("unexpected reader terminal marker"));
    }
    if !process.verified() && outcome.is_ok() {
        failure_reason = HarnessFailureReason::CleanupUnverified;
        outcome = Err(std::io::Error::other(
            "private workspace process cleanup unverified",
        ));
    }
    transcript.finish_private_fixed_diagnostic();
    let private_fixed_diagnostic = if process.verified() {
        transcript.private_fixed_diagnostic().cloned()
    } else {
        None
    };
    let diagnostic_withheld = transcript.diagnostic_withheld();
    // The observation and input progress remain in this same child result.
    // Never forward a captured pair without exact process cleanup evidence.
    let delivery_first_failure = if process.verified() {
        transcript.delivery_first_failure()
    } else {
        None
    };
    Ok(PrivateWorkspaceStageResultV1 {
        delivery_first_failure,
        private_fixed_diagnostic,
        diagnostic_withheld,
        outcome,
        process,
        root: finished.root_for_explicit_close,
        summary: transcript.summary(),
        failure_reason,
        next,
        expected: inputs.len(),
    })
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
fn private_workspace_terminal_drain_v1(
    master: &mut File,
    transcript: &mut rolling_transcript_v1::Transcript<'_>,
    root: Option<&std::path::Path>,
) -> std::io::Result<()> {
    let root = root.ok_or_else(|| std::io::Error::other("verified root unavailable"))?;
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    for _ in 0..64 {
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 || descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(std::io::Error::other("terminal drain observation failed"));
        }
        let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
        match master.read(&mut chunk[..]) {
            Ok(0) => {
                return transcript
                    .finish_text()
                    .map_err(|_| std::io::Error::other("terminal utf8 incomplete"));
            }
            Ok(length) => transcript
                .append(&chunk[..length], root)
                .map_err(|_| std::io::Error::other("terminal bounded append failed"))?,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                return transcript
                    .finish_text()
                    .map_err(|_| std::io::Error::other("terminal utf8 incomplete"));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && descriptor.revents & libc::POLLHUP != 0 =>
            {
                return transcript
                    .finish_text()
                    .map_err(|_| std::io::Error::other("terminal utf8 incomplete"));
            }
            Err(_) => {
                return Err(std::io::Error::other(
                    "terminal EOF or hangup not established",
                ));
            }
        }
    }
    Err(std::io::Error::other("terminal bounded drain incomplete"))
}
