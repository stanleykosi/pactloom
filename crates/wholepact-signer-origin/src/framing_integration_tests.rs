//! CI-only integration of the real bounded writer, recvmsg reader and kernel
//! peer lifetime adapter. No native/UI decision, wallet, key or grant is created.
use super::*;
use crate::framing::{read_frame_capped_checked_observed_until, FrameReadCause};
use std::{
    io::Read,
    net::Shutdown,
    os::unix::net::UnixListener,
    process::{Child, Command, Stdio},
    thread,
};

const HELPER: &str = "client::framing_integration_tests::origin_frame_peer_helper";
const BUDGET: Duration = Duration::from_secs(2);

fn require_ci() {
    assert!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"),
        "isolated CI only"
    );
    assert!(
        std::env::var("GITHUB_REPOSITORY").as_deref() == Ok("stanleykosi/pactloom"),
        "isolated CI only"
    );
    assert!(
        std::env::var("GITHUB_REF").ok().as_deref()
            == Some("refs/heads/qualification/durable-proposal-v1"),
        "isolated CI only"
    );
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } == 0
            && action.sa_sigaction == libc::SIG_DFL
            && action.sa_flags & libc::SA_NOCLDWAIT == 0,
        "owned-child wait policy required"
    );
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    assert!(
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0 && limit.rlim_cur == 0,
        "zero core limit required"
    );
}

#[test]
#[ignore = "helper only for the exact isolated CI origin integration gate"]
fn origin_frame_peer_helper() {
    require_ci();
    // All input is a fresh synthetic test endpoint plus a closed mode. Never
    // use this helper as a provider, issuer or installed signer launcher.
    let result = helper();
    assert!(result.is_ok(), "origin helper failed; details withheld");
}
fn helper() -> std::result::Result<(), ()> {
    let path = std::env::var_os("WHOLEPACT_ORIGIN_GATE_SOCKET").ok_or(())?;
    let mode = std::env::var("WHOLEPACT_ORIGIN_GATE_MODE").map_err(|_| ())?;
    if !matches!(
        mode.as_str(),
        "send" | "large" | "eof" | "idle" | "exit" | "broken"
    ) {
        return Err(());
    }
    let mut socket = UnixStream::connect(path).map_err(|_| ())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .map_err(|_| ())?;
    socket.set_write_timeout(Some(BUDGET)).map_err(|_| ())?;
    let mut start = [0u8; 1];
    socket.read_exact(&mut start).map_err(|_| ())?;
    if start != [b'g'] {
        return Err(());
    }
    if mode == "idle" {
        println!("ORIGIN_WRITER Idle");
    } else if mode == "eof" {
        socket.shutdown(Shutdown::Write).map_err(|_| ())?;
        println!("ORIGIN_WRITER Closed");
    } else {
        let value = if mode == "large" {
            "x".repeat(20_000)
        } else {
            "synthetic".into()
        };
        let mut cause = FrameWriteCause::Unclassified;
        // Actual production writer, not a fixture reimplementation.
        let result = write_frame_until_bounded_observed(
            &mut socket,
            &value,
            Instant::now() + BUDGET,
            None,
            32_768,
            &mut cause,
        );
        let outcome = if result.is_ok() {
            "Sent"
        } else {
            match cause {
                FrameWriteCause::BrokenPipe => "BrokenPipe",
                FrameWriteCause::Reset => "Reset",
                FrameWriteCause::Timeout => "Timeout",
                FrameWriteCause::Budget => "Budget",
                _ => "OtherFailure",
            }
        };
        println!("ORIGIN_WRITER {outcome}");
    }
    std::io::stdout().flush().map_err(|_| ())?;
    if mode == "exit" {
        return Ok(());
    }
    let mut done = [0u8; 1];
    socket.read_exact(&mut done).map_err(|_| ())?;
    if done != [b'q'] {
        return Err(());
    }
    Ok(())
}

struct Fixture {
    root: Option<tempfile::TempDir>,
    children: Vec<Child>,
}
impl Fixture {
    fn new() -> std::result::Result<Self, &'static str> {
        Ok(Self {
            root: Some(
                tempfile::Builder::new()
                    .prefix("wpo.")
                    .tempdir_in("/tmp")
                    .map_err(|_| "Root")?,
            ),
            children: Vec::new(),
        })
    }
    fn connect(
        &mut self,
        mode: &str,
        credentials: bool,
    ) -> std::result::Result<(UnixStream, PeerProcess), &'static str> {
        let path = self
            .root
            .as_ref()
            .ok_or("Root")?
            .path()
            .join(format!("{}.sock", self.children.len()));
        let listener = UnixListener::bind(&path).map_err(|_| "Bind")?;
        if credentials {
            framing::enable_credentials(listener.as_raw_fd()).map_err(|_| "Passcred")?;
        }
        listener.set_nonblocking(true).map_err(|_| "Nonblocking")?;
        let child = Command::new(std::env::current_exe().map_err(|_| "Image")?)
            .args([
                "--ignored",
                "--exact",
                HELPER,
                "--test-threads=1",
                "--nocapture",
            ])
            .env("WHOLEPACT_ORIGIN_GATE_SOCKET", &path)
            .env("WHOLEPACT_ORIGIN_GATE_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Spawn")?;
        self.children.push(child);
        let until = Instant::now() + BUDGET;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err("Accept"),
            }
        };
        stream
            .set_read_timeout(Some(BUDGET))
            .map_err(|_| "Timeout")?;
        stream
            .set_write_timeout(Some(BUDGET))
            .map_err(|_| "Timeout")?;
        let peer = PeerProcess::observe(&stream).map_err(|_| "KernelPeerUnavailable")?;
        Ok((stream, peer))
    }
    fn finish(&mut self) -> (bool, bool, &'static str) {
        let mut clean = true;
        let mut normal = true;
        let mut first_writer = "Unobserved";
        for (index, child) in self.children.iter_mut().enumerate() {
            let grace = Instant::now() + Duration::from_millis(250);
            let mut status = None;
            let mut ownership = true;
            while Instant::now() < grace {
                match child.try_wait() {
                    Ok(Some(value)) => {
                        status = Some(value);
                        break;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(5)),
                    Err(_) => {
                        clean = false;
                        ownership = false;
                        break;
                    }
                }
            }
            if status.is_none() && ownership {
                normal = false;
                // Only the still-owned direct Child is signalled. No numeric
                // process group, arbitrary PID, descendant or retry is used.
                if child.kill().is_err() {
                    clean = false;
                }
                let until = Instant::now() + BUDGET;
                while Instant::now() < until {
                    match child.try_wait() {
                        Ok(Some(value)) => {
                            status = Some(value);
                            break;
                        }
                        Ok(None) => thread::sleep(Duration::from_millis(5)),
                        Err(_) => {
                            clean = false;
                            break;
                        }
                    }
                }
            }
            if let Some(status) = status {
                normal &= status.success();
                if index == 0 {
                    let mut bytes = Vec::new();
                    if let Some(stdout) = child.stdout.take() {
                        if stdout.take(16_385).read_to_end(&mut bytes).is_ok()
                            && bytes.len() <= 16_384
                        {
                            if let Ok(text) = std::str::from_utf8(&bytes) {
                                let found: Vec<_> = text
                                    .lines()
                                    .filter_map(|line| {
                                        line.split_once("ORIGIN_WRITER ").map(|(_, value)| value)
                                    })
                                    .collect();
                                if found.len() == 1 {
                                    first_writer = match found[0] {
                                        "Sent" => "Sent",
                                        "Idle" => "Idle",
                                        "Closed" => "Closed",
                                        "BrokenPipe" => "BrokenPipe",
                                        "Reset" => "Reset",
                                        "Timeout" => "Timeout",
                                        "Budget" => "Budget",
                                        "OtherFailure" => "OtherFailure",
                                        _ => "Unobserved",
                                    };
                                }
                            }
                        }
                    }
                }
            } else {
                clean = false;
            }
        }
        self.children.clear();
        if let Some(root) = self.root.take() {
            if clean {
                clean &= root.close().is_ok();
            } else {
                let _ = root.keep();
            } // Never delete beneath an unverified child.
        }
        (clean, normal, first_writer)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.is_some() {
            let _ = self.finish();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Success,
    Large,
    Eof,
    Deadline,
    MissingCredentials,
    WrongPeer,
    PeerExit,
    Cancel,
    BrokenPipe,
}
fn exercise(
    fixture: &mut Fixture,
    case: Case,
) -> std::result::Result<(&'static str, bool), &'static str> {
    let mode = match case {
        Case::Large => "large",
        Case::Eof => "eof",
        Case::Deadline | Case::Cancel => "idle",
        Case::PeerExit => "exit",
        Case::BrokenPipe => "broken",
        _ => "send",
    };
    let (mut socket, peer) = fixture.connect(mode, !matches!(case, Case::MissingCredentials))?;
    let mut other = None;
    let check_peer = if matches!(case, Case::WrongPeer) {
        let (mut stream, other_peer) = fixture.connect("idle", true)?;
        stream.write_all(b"g").map_err(|_| "Start")?;
        other = Some(stream);
        other_peer
    } else {
        peer
    };
    if matches!(case, Case::BrokenPipe) {
        socket.shutdown(Shutdown::Read).map_err(|_| "Shutdown")?;
    }
    socket.write_all(b"g").map_err(|_| "Start")?;
    let received = if matches!(case, Case::BrokenPipe) {
        // The writer reports its actual bounded-write result after cleanup.
        Ok(("ReadClosed", true))
    } else {
        if matches!(case, Case::PeerExit) {
            let until = Instant::now() + BUDGET;
            loop {
                if fixture.children[0]
                    .try_wait()
                    .map_err(|_| "Wait")?
                    .is_some()
                {
                    break;
                }
                if Instant::now() >= until {
                    return Err("WaitDeadline");
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        let mut checks = 0;
        let budget = if matches!(case, Case::Deadline) {
            Duration::from_millis(150)
        } else {
            BUDGET
        };
        let result = read_frame_capped_checked_observed_until(
            &socket,
            &check_peer,
            32_768,
            Instant::now() + budget,
            || {
                checks += 1;
                if matches!(case, Case::Cancel) && checks >= 3 {
                    Err(Error::Permission)
                } else {
                    Ok(())
                }
            },
        );
        let (observed, valid) = match result {
            Ok(bytes) => {
                let valid = match case {
                    Case::Success => &**bytes == b"\"synthetic\"",
                    Case::Large => {
                        bytes.len() == 20_002
                            && bytes[0] == b'"'
                            && bytes[20_001] == b'"'
                            && bytes[1..20_001].iter().all(|byte| *byte == b'x')
                    }
                    _ => false,
                };
                ("Frame", valid)
            }
            Err(error) => {
                let label = match error.cause {
                    FrameReadCause::Unclassified => "Unclassified",
                    FrameReadCause::Deadline => "Deadline",
                    FrameReadCause::Eof => "Eof",
                    FrameReadCause::CredentialsMissing => "CredentialsMissing",
                    FrameReadCause::CredentialsMismatch => "CredentialsMismatch",
                    FrameReadCause::AncillaryRejected => "AncillaryRejected",
                    FrameReadCause::Truncated => "Truncated",
                    FrameReadCause::PeerNotLive => "PeerNotLive",
                    FrameReadCause::CurrentCheck => "CurrentCheck",
                    FrameReadCause::Io => "Io",
                    FrameReadCause::FrameLimit => "FrameLimit",
                    FrameReadCause::InvalidFrame => "InvalidFrame",
                    FrameReadCause::InvalidBudget => "InvalidBudget",
                };
                let valid = matches!(
                    (case, error.cause),
                    (Case::Eof, FrameReadCause::Eof)
                        | (Case::Deadline, FrameReadCause::Deadline)
                        | (Case::MissingCredentials, FrameReadCause::CredentialsMissing)
                        | (Case::WrongPeer, FrameReadCause::CredentialsMismatch)
                        | (Case::PeerExit, FrameReadCause::PeerNotLive)
                        | (Case::Cancel, FrameReadCause::CurrentCheck)
                );
                (label, valid)
            }
        };
        Ok((observed, valid))
    };
    if !matches!(case, Case::PeerExit) {
        socket.write_all(b"q").map_err(|_| "Release")?;
    }
    if let Some(mut other) = other {
        other.write_all(b"q").map_err(|_| "Release")?;
    }
    received
}

#[test]
#[ignore = "real AF_UNIX/SO_PEERPIDFD production integration, isolated CI only"]
fn production_frames_real_peer_contract() {
    require_ci();
    for (attempt, case) in [
        Case::Success,
        Case::Large,
        Case::Eof,
        Case::Deadline,
        Case::MissingCredentials,
        Case::WrongPeer,
        Case::PeerExit,
        Case::Cancel,
        Case::BrokenPipe,
    ]
    .into_iter()
    .enumerate()
    {
        let started = Instant::now();
        let mut fixture = Fixture::new().expect("origin fixture unavailable; details withheld");
        let result = exercise(&mut fixture, case);
        let (cleanup, normal, writer) = fixture.finish();
        let writer_matches = match case {
            Case::Deadline | Case::Cancel => writer == "Idle",
            Case::Eof => writer == "Closed",
            Case::BrokenPipe => writer == "BrokenPipe",
            _ => writer == "Sent",
        };
        let (receiver, contract) = result.unwrap_or_else(|stage| (stage, false));
        let passed = contract && cleanup && normal && writer_matches;
        // One same-attempt pair, emitted only after owned-child cleanup. Closed
        // values only, no ordering claim across independent endpoint events.
        println!("ORIGIN_INTEGRATION attempt={} case={:?} receiver={} writer={} elapsed_ms={} cleanup={} passed={}",
            attempt, case, receiver, writer, started.elapsed().as_millis(), cleanup, passed);
        assert!(passed, "origin integration failed; bounded report above");
    }
}
