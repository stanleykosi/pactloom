//! Compiled only into separately pinned disposable-CI images. This is NOT a
//! product entry or authority constructor. Cases are fixed at compilation;
//! runtime arguments/environment/FDs cannot select a role, case or origin.
use crate::{channel::Message, process::{PeerLifetime, Role}, rejected, Result};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::{fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}, unix::fs::OpenOptionsExt},
    sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
    time::Instant,
};

const CASE: &str = env!("WHOLEPACT_BOOTSTRAP_CI_CASE");
const CASES: [&str; 14] = [
    "observed_success", "wrong_role", "wrong_version", "oversized_packet",
    "duplicate_prepared", "rights", "rights_truncated", "later_wrong_sender",
    "missing_credentials", "coordinator_death", "host_death",
    "child_exit_after_released", "timeout_before_prepared", "stall_after_stopped",
];
const MAX_FILE: u64 = 64 * 1024;
static START_MS: AtomicU64 = AtomicU64::new(0);
static LOCAL_ROLE: AtomicU8 = AtomicU8::new(Role::Coordinator as u8);
static FAULT_USED: AtomicBool = AtomicBool::new(false);
static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
static REJECTION_RECORDED: AtomicBool = AtomicBool::new(false);

pub(super) fn initialize() -> Result<()> {
    if !CASES.contains(&CASE) { return Err(rejected("unsupported compiled CI case")); }
    START_MS.store(monotonic_ms()?, Ordering::SeqCst);
    record("started", json!({"uid": unsafe { libc::getuid() }, "euid": unsafe { libc::geteuid() }}))
}

pub(super) fn enter_role(role: Role) {
    LOCAL_ROLE.store(role as u8, Ordering::SeqCst);
    SEQUENCE.store(0, Ordering::SeqCst);
    // Each role owns its own first rejecting boundary. Never turn copied parent
    // diagnostic state into a permission or a reconstructed fork origin.
    REJECTION_RECORDED.store(false, Ordering::SeqCst);
}

pub(super) fn deadline(deadline: Instant) -> Result<()> {
    record("deadline", json!({"budget_ms": 30000, "deadline_elapsed_ms": elapsed_ms()? + remaining(deadline)}))
}

pub(super) fn birth(child_role: Role, child_pid: libc::pid_t) -> Result<()> {
    record("birth", json!({"child_role": role_name(child_role), "child_pid": child_pid}))
}

pub(super) fn ready(role: Role, mut expected: Vec<RawFd>, parent_pid: libc::pid_t, deadline: Instant) -> Result<()> {
    expected.sort_unstable();
    let actual = fd_inventory()?;
    if actual != expected {
        reject_boundary("fd_inventory", "unexpected_descriptor", None, None, None, false, None);
        return Err(rejected("CI actual role descriptor inventory mismatch"));
    }
    let mut limit = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    let core_zero = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0
        && limit.rlim_cur == 0 && limit.rlim_max == 0;
    let dumpable_zero = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
    if !core_zero || !dumpable_zero { return Err(rejected("CI observed lost hardening")); }
    record("ready", json!({
        "fds": actual, "expected_fds": expected, "fd_inventory_ok": true,
        "parent_pid": parent_pid, "remaining_ms": remaining(deadline),
        "core_zero": core_zero, "dumpable_zero": dumpable_zero,
    }))?;
    if CASE == "timeout_before_prepared" && role == Role::CompletedPair {
        fault("before_prepared")?;
        pause_past_deadline();
    }
    if CASE == "host_death" && role == Role::Host {
        fault("after_signers_prepared")?;
        kill_self();
    }
    Ok(())
}

pub(super) fn release_decision() -> Result<()> {
    record("release_decision", json!({"prepared": 14}))?;
    if CASE == "coordinator_death" {
        fault("after_all_prepared")?;
        kill_self();
    }
    Ok(())
}


/// Negative-fixture scheduling only: wait until the original W has reaped its
/// attacker before letting C perform its unchanged real recvmsg. The evidence
/// never supplies a sender identity or origin and cannot synthesize rejection.
pub(super) fn before_receive(message: Message, peer: &PeerLifetime, deadline: Instant) -> Result<()> {
    if CASE != "later_wrong_sender" || message != Message::Released || peer.role() != target_role()
        || LOCAL_ROLE.load(Ordering::SeqCst) != Role::Coordinator as u8 { return Ok(()); }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Event {
        schema_version: u8, case: String, event: String, role: String,
        pid: libc::pid_t, ppid: libc::pid_t, sequence: usize, elapsed_ms: u64,
        detail: Value,
    }
    loop {
        crate::channel::require_time(deadline)?;
        peer.check_alive()?;
        let mut bytes = Vec::new();
        // The path comes only from this exact internally retained peer, not
        // argv/env/wire JSON. No file or mutex survives this iteration.
        let mut file = OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(format!("/ci-evidence/{}.jsonl", peer.pid()))?;
        Read::by_ref(&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        drop(file);
        if bytes.len() as u64 > MAX_FILE { return Err(rejected("CI synchronization evidence oversized")); }
        let mut expected_sequence = 1;
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            if !line.ends_with(b"\n") { break; } // A still-appending bounded tail is not evidence.
            let event: Event = serde_json::from_slice(line).map_err(|_| rejected("CI synchronization evidence malformed"))?;
            if event.schema_version != 1 || event.case != CASE || event.role != role_name(peer.role())
                || event.pid != peer.pid() || event.ppid <= 0 || event.elapsed_ms > 45_000
                || event.sequence != expected_sequence { return Err(rejected("CI synchronization evidence mismatched")); }
            expected_sequence += 1;
            if expected_sequence > 257 { return Err(rejected("CI synchronization record limit")); }
            if event.event == "attacker_reaped" {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Reaped { attacker_pid: libc::pid_t, exit_code: libc::c_int }
                let detail: Reaped = serde_json::from_value(event.detail).map_err(|_| rejected("CI attacker-reap evidence malformed"))?;
                if detail.attacker_pid <= 0 || detail.exit_code != 0 { return Err(rejected("CI attacker was not cleanly reaped")); }
                return Ok(());
            }
        }
        // Short, bounded scheduling pause, with the same deadline rechecked.
        unsafe { libc::poll(std::ptr::null_mut(), 0, 5); }
    }
}

pub(super) fn received(message: Message, peer: &PeerLifetime, cred: &libc::ucred, deadline: Instant) -> Result<()> {
    record("received", json!({
        "kind": message_name(message), "peer_role": role_name(peer.role()),
        "peer_pid": peer.pid(), "sender_pid": cred.pid, "sender_uid": cred.uid,
        "peer_alive": true, "remaining_ms": remaining(deadline),
    }))
}

/// Diagnostic only: called at the actual fail-closed boundary. Preserve the
/// first cause in each actual process even when subsequent teardown also fails.
pub(super) fn reject_boundary(
    boundary: &'static str, reason: &'static str, peer: Option<&PeerLifetime>,
    sender_pid: Option<libc::pid_t>, peer_alive: Option<bool>,
    control_truncated: bool, fd_inventory_restored: Option<bool>,
) {
    if REJECTION_RECORDED.swap(true, Ordering::SeqCst) { return; }
    let _ = record("reject", json!({
        "boundary": boundary, "reason": reason,
        "peer_role": peer.map(|p| role_name(p.role())), "peer_pid": peer.map(|p| p.pid()),
        "sender_pid": sender_pid, "peer_alive": peer_alive,
        "control_truncated": control_truncated, "fd_inventory_restored": fd_inventory_restored,
    }));
}

pub(super) fn reaped(role: Role, pid: libc::pid_t, status: libc::c_int) {
    let (kind, code) = if libc::WIFEXITED(status) {
        ("exit", libc::WEXITSTATUS(status))
    } else {
        ("signal", libc::WTERMSIG(status))
    };
    let _ = record("reaped", json!({"child_role": role_name(role), "child_pid": pid, "kind": kind, "code": code}));
}

pub(super) fn finished(exit_code: libc::c_int) {
    if START_MS.load(Ordering::SeqCst) != 0 {
        let _ = record("finished", json!({"exit_code": exit_code}));
    }
}

pub(super) fn configure_pair(parent: Role, child: Role, receiver: RawFd) -> Result<()> {
    if CASE == "missing_credentials" && parent == Role::Coordinator && child == target_role() {
        fault("pair_created")?;
        // Test fault only. Production construction always enables PASSCRED.
        let disabled: libc::c_int = 0;
        if unsafe { libc::setsockopt(receiver, libc::SOL_SOCKET, libc::SO_PASSCRED, (&disabled as *const libc::c_int).cast(), std::mem::size_of_val(&disabled) as libc::socklen_t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Replaces at most one actual packet in one compiled negative image. It does
/// not change the receiver, create a listener or construct any origin/permit.
pub(super) fn send_override(fd: RawFd, message: Message, role: Role, bytes: &[u8; 8], deadline: Instant) -> Result<bool> {
    if role != target_role() { return Ok(false); }
    if CASE == "later_wrong_sender" && message == Message::Released {
        fault("send_released")?;
        let attacker = unsafe { libc::fork() };
        if attacker < 0 { return Err(std::io::Error::last_os_error()); }
        if attacker == 0 {
            SEQUENCE.store(0, Ordering::SeqCst);
            // Explicit adversarial extra process, never a Role/ForkOrigin. It
            // only misuses an inherited sender FD and exits immediately.
            let result = send_raw(fd, bytes).and_then(|()| record_as("Attacker", "attacker_sent", json!({"kind": "Released"})));
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) }
        }
        let mut owned = AttackerChild::capture_unreaped_fork_return(attacker)?;
        record("attacker_spawned", json!({"attacker_pid": attacker}))?;
        let status = owned.wait_until(deadline)?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 { return Err(rejected("CI attacker failed")); }
        record("attacker_reaped", json!({"attacker_pid": attacker, "exit_code": 0}))?;
        return Ok(true);
    }
    if message != Message::Prepared { return Ok(false); }
    match CASE {
        "wrong_role" => {
            fault("send_prepared")?;
            let mut altered = *bytes;
            altered[6] = Role::Signer1 as u8;
            send_raw(fd, &altered)?;
        }
        "wrong_version" => {
            fault("send_prepared")?;
            let mut altered = *bytes;
            altered[4] = 2;
            send_raw(fd, &altered)?;
        }
        "oversized_packet" => {
            fault("send_prepared")?;
            let mut altered = [0u8; 32];
            altered[..8].copy_from_slice(bytes);
            send_raw(fd, &altered)?;
        }
        "duplicate_prepared" => {
            fault("send_prepared")?;
            send_raw(fd, bytes)?;
            send_raw(fd, bytes)?;
        }
        "rights" | "rights_truncated" => {
            fault("send_prepared")?;
            send_rights(fd, bytes, if CASE == "rights" { 1 } else { 160 })?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn after_send(message: Message, role: Role) -> Result<()> {
    if role == target_role() && CASE == "child_exit_after_released" && message == Message::Released {
        fault("after_released")?;
        kill_self();
    }
    if role == target_role() && CASE == "stall_after_stopped" && message == Message::Stopped {
        fault("after_stopped")?;
        pause_past_deadline();
    }
    Ok(())
}

pub(super) fn fd_inventory() -> Result<Vec<RawFd>> {
    // No other thread opens descriptors. First finish/drop the enumerator, then
    // discard its now-closed descriptor before comparing actual survivors.
    let listed = std::fs::read_dir("/proc/self/fd")?
        .map(|entry| {
            entry?.file_name().to_str().ok_or_else(|| rejected("CI nonnumeric fd"))?
                .parse::<RawFd>().map_err(|_| rejected("CI nonnumeric fd"))
        }).collect::<Result<Vec<_>>>()?;
    let mut result: Vec<_> = listed.into_iter().filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0).collect();
    result.sort_unstable();
    Ok(result)
}

/// CI adversary lifetime only. Never a legitimate role or fork origin. Sole
/// constructor call is immediately after the actual test-only fork return.
struct AttackerChild { pid: libc::pid_t, pidfd: OwnedFd, reaped: bool }
impl AttackerChild {
    fn capture_unreaped_fork_return(pid: libc::pid_t) -> Result<Self> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            // Actual direct child is still unreaped under checked SIGCHLD DFL.
            unsafe { libc::kill(pid, libc::SIGKILL); }
            let _ = reap_attacker(pid);
            return Err(error);
        }
        Ok(Self { pid, pidfd: unsafe { OwnedFd::from_raw_fd(raw as RawFd) }, reaped: false })
    }
    fn wait_until(&mut self, deadline: Instant) -> Result<libc::c_int> {
        loop {
            crate::channel::require_time(deadline)?;
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid { self.reaped = true; return Ok(status); }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted { continue; }
                return Err(error);
            }
            let mut poll = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let millis = deadline.saturating_duration_since(Instant::now()).as_millis().clamp(1, 50) as libc::c_int;
            let result = unsafe { libc::poll(&mut poll, 1, millis) };
            if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
}
impl Drop for AttackerChild {
    fn drop(&mut self) {
        if self.reaped { return; }
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0u32); }
        // Final forced kernel reap can still block, as in production cleanup;
        // it is not mislabeled as a bounded graceful wait.
        let _ = reap_attacker(self.pid);
    }
}
fn reap_attacker(pid: libc::pid_t) -> Result<()> {
    loop {
        if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } == pid { return Ok(()); }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted { return Err(error); }
    }
}

fn fault(phase: &'static str) -> Result<()> {
    if FAULT_USED.swap(true, Ordering::SeqCst) { return Err(rejected("CI fault repeated")); }
    record("fault", json!({"name": CASE, "phase": phase}))
}
fn target_role() -> Role { Role::Owner1BootstrapHistory }
fn send_raw(fd: RawFd, bytes: &[u8]) -> Result<()> {
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("CI injected packet failed")); }
    Ok(())
}
fn send_rights(fd: RawFd, bytes: &[u8; 8], count: usize) -> Result<()> {
    let data_len = count * std::mem::size_of::<libc::c_int>();
    let space = unsafe { libc::CMSG_SPACE(data_len as libc::c_uint) } as usize;
    let mut storage = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec { iov_base: bytes.as_ptr().cast_mut().cast(), iov_len: bytes.len() };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = storage.as_mut_ptr().cast();
    header.msg_controllen = space;
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
    if cmsg.is_null() { return Err(rejected("CI control buffer failed")); }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(data_len as libc::c_uint) as usize;
        // FD0 is the actual role's /dev/null, not any caller data or credential.
        for i in 0..count { std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).add(i * std::mem::size_of::<libc::c_int>()).cast::<libc::c_int>(), 0); }
    }
    let sent = unsafe { libc::sendmsg(fd, &header, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize { return Err(rejected("CI rights injection failed")); }
    Ok(())
}
fn pause_past_deadline() {
    // Closed fault fixture only; never a production deadline extension.
    unsafe { libc::poll(std::ptr::null_mut(), 0, 35_000); }
}
fn kill_self() -> ! {
    unsafe { libc::kill(libc::getpid(), libc::SIGKILL); libc::_exit(99) }
}
fn remaining(deadline: Instant) -> u64 {
    deadline.saturating_duration_since(Instant::now()).as_millis().min(u64::MAX as u128) as u64
}
fn monotonic_ms() -> Result<u64> {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 { return Err(std::io::Error::last_os_error()); }
    Ok((now.tv_sec as u64).saturating_mul(1000).saturating_add(now.tv_nsec as u64 / 1_000_000))
}
fn elapsed_ms() -> Result<u64> { Ok(monotonic_ms()?.saturating_sub(START_MS.load(Ordering::SeqCst))) }
fn record(event: &'static str, detail: Value) -> Result<()> {
    record_as(role_number_name(LOCAL_ROLE.load(Ordering::SeqCst)), event, detail)
}
fn record_as(role: &'static str, event: &'static str, detail: Value) -> Result<()> {
    let pid = unsafe { libc::getpid() };
    let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1;
    if sequence > 256 { return Err(rejected("CI per-process event limit")); }
    let value = json!({"schema_version": 1, "case": CASE, "event": event, "role": role,
        "pid": pid, "ppid": unsafe { libc::getppid() }, "sequence": sequence, "elapsed_ms": elapsed_ms()?, "detail": detail});
    let mut bytes = serde_json::to_vec(&value).map_err(|_| rejected("CI evidence encode failed"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(format!("/ci-evidence/{pid}.jsonl"))?;
    if file.metadata()?.len().saturating_add(bytes.len() as u64) > MAX_FILE { return Err(rejected("CI evidence limit")); }
    file.write_all(&bytes)
}
fn message_name(message: Message) -> &'static str {
    match message { Message::Prepared => "Prepared", Message::Release => "Release", Message::Released => "Released", Message::Stop => "Stop", Message::Stopped => "Stopped", Message::Exit => "Exit" }
}
fn role_name(role: Role) -> &'static str { role_number_name(role as u8) }
fn role_number_name(role: u8) -> &'static str {
    match role {
        1 => "Coordinator", 2 => "Host", 3 => "Signer1", 4 => "Signer2",
        5 => "Owner1BootstrapHistory", 6 => "Owner1V3DeliveryAdmission", 7 => "Owner1DeliveryAuditHistory",
        8 => "Owner1FinancialReadHistory", 9 => "Owner1FinancialContinuationAdmission", 10 => "Owner1FinancialSigning",
        11 => "Owner2BootstrapHistory", 12 => "Owner2V3DeliveryAdmission", 13 => "Owner2DeliveryAuditHistory",
        14 => "Owner2FinancialReadHistory", 15 => "Owner2FinancialContinuationAdmission", 16 => "Owner2FinancialSigning",
        17 => "CompletedPair", _ => "Invalid",
    }
}
