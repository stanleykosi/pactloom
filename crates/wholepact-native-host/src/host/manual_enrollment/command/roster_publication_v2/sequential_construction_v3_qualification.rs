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

#[path = "sequential_construction_v3_qualification/safe_diagnostics_v1.rs"]
mod safe_diagnostics_v1;

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

const CHILD_TEMPORARY_PREFIX: &str = "wp-pty-";

fn foreground_child(stage: &str, inputs: &[Input<'_>]) -> std::io::Result<()> {
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
    // Parent retains this root through kill+reap. Child-owned TempDirs cannot
    // run Drop after SIGKILL; this outer owner removes all synthetic secrets and
    // journals on timeout as well as success. TMPDIR affects only allocation in
    // the isolated test process, never a production namespace trust root.
    let child_temporary_root = tempfile::Builder::new()
        .prefix(CHILD_TEMPORARY_PREFIX)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let tls_material =
        synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(child_temporary_root.path())?;
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
    let mut child = command.spawn()?;
    let safety_seconds = if matches!(
        stage,
        "three-born-retained-inputs-v3"
            | "three-born-all-observations-v3"
            | "three-born-constructed-checkpoint-v3"
            | "three-born-full-payment-v1"
    ) {
        900
    } else {
        180
    };
    let deadline = Instant::now() + Duration::from_secs(safety_seconds);
    let mut transcript = zeroize::Zeroizing::new(Vec::new());
    let mut next = 0;
    let mut consumed = 0;
    let outcome = (|| {
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() && next == inputs.len() {
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
                    let mut chunk = [0u8; 4096];
                    let Ok(length) = master.read(&mut chunk) else {
                        break;
                    };
                    if length == 0 || transcript.len() + length > 262_144 {
                        break;
                    }
                    transcript.extend_from_slice(&chunk[..length]);
                }
                return Err(std::io::Error::other("synthetic foreground child failed"));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "synthetic foreground stage exceeded its original deadline",
                ));
            }
            let mut descriptor = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut descriptor, 1, 50) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if descriptor.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut chunk = [0; 4096];
            let length = master.read(&mut chunk)?;
            if length == 0 {
                continue;
            }
            if transcript.len() + length > 262_144 {
                return Err(std::io::Error::other(
                    "synthetic foreground output exceeded fixed bound",
                ));
            }
            transcript.extend_from_slice(&chunk[..length]);
            let Some(input) = inputs.get(next) else {
                continue;
            };
            let tail =
                std::str::from_utf8(&transcript[consumed..]).map_err(std::io::Error::other)?;
            let (detail, approve) = match input {
                Input::Text { prompt, response } => {
                    if !tail.contains(prompt) {
                        continue;
                    }
                    if response.contains(['\n', '\r']) {
                        return Err(std::io::Error::other("multiline synthetic input denied"));
                    }
                    master.write_all(response.as_bytes())?;
                    master.write_all(b"\n")?;
                    master.flush()?;
                    consumed = transcript.len();
                    next += 1;
                    continue;
                }
                Input::CapturedPath { marker, prompt } => {
                    if !tail.contains(prompt) {
                        continue;
                    }
                    let all = std::str::from_utf8(&transcript).map_err(std::io::Error::other)?;
                    let Some(marked) = all.rsplit_once(marker).map(|(_, rest)| rest) else {
                        return Err(std::io::Error::other(
                            "actual temporary path marker missing",
                        ));
                    };
                    let Some(path) = marked.lines().next() else {
                        continue;
                    };
                    let path = path.trim_end_matches('\r');
                    if !std::path::Path::new(path).is_absolute()
                        || !std::path::Path::new(path).starts_with(child_temporary_root.path())
                        || path.contains(['\r', '\n'])
                    {
                        return Err(std::io::Error::other("invalid temporary path marker"));
                    }
                    master.write_all(path.as_bytes())?;
                    master.write_all(b"\n")?;
                    master.flush()?;
                    consumed = transcript.len();
                    next += 1;
                    continue;
                }
                Input::ExactReview { detail, approve } => (detail, approve),
            };
            let Some(detail_start) = tail.find(detail) else {
                continue;
            };
            let remaining = &tail[detail_start + detail.len()..];
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
                return Err(std::io::Error::other(
                    "unexpected native exact-review challenge",
                ));
            }
            if *approve {
                master.write_all(format!("APPROVE {challenge}\n").as_bytes())?;
            } else {
                master.write_all(b"REJECT\n")?;
            }
            master.flush()?;
            consumed = transcript.len();
            next += 1;
        }
    })();
    // Always reap. Timeout/error is not evidence of cancellation of an admitted
    // financial operation; this harness stage performs none.
    if outcome.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().ok();
    outcome.map_err(|error| std::io::Error::new(error.kind(), format!(
        "synthetic foreground child failed; private transcript withheld; exit={:?}; signal={:?}; core_dumped={}; inputs={}/{}; static_boundaries={}",
        status.as_ref().and_then(|status| status.code()),
        status.as_ref().and_then(|status| status.signal()),
        status.as_ref().is_some_and(|status| status.core_dumped()),
        next, inputs.len(), safe_diagnostics_v1::summary(&transcript),
    )))
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
    let stage = std::env::var(CHILD_ENV).expect("bounded synthetic parent stage");
    let _synthetic_tls = synthetic_provider_tls_v1::child_server_config()
        .expect("owned test-process TLS identity, not chain qualification");
    let terminal = crate::terminal::Terminal::open().expect("actual foreground child TTY");
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
