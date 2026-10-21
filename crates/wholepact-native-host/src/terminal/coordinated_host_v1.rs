//! Original-C restriction only. Genuine foreground TTY consent remains required.
//! Installation is process-wide and irreversible, including every duplicated
//! approval file. A failed coordinated installation can never become legacy.
use super::*;
use std::{sync::{OnceLock, atomic::{AtomicBool, AtomicU8, Ordering}}, time::Duration};
use wholepact_financial_coordinator_origin::{HostControllingTerminalV1, HostOriginalRestrictionV1, HostCompletedPairServiceV1};

const LEGACY: u8 = 0;
const REQUIRED: u8 = 1;
const FAILED: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(LEGACY);
static INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static PAIR_REQUIRED: AtomicBool = AtomicBool::new(false);
static PAIR: OnceLock<Arc<HostCompletedPairServiceV1>> = OnceLock::new();
static ORIGINAL: OnceLock<Original> = OnceLock::new();
struct Original {
    terminal: HostControllingTerminalV1,
    restriction: HostOriginalRestrictionV1,
}

pub(super) fn required() -> bool { STATE.load(Ordering::SeqCst) != LEGACY }
pub(super) fn fail_closed() { STATE.store(FAILED, Ordering::SeqCst); }
fn deny<T>() -> Result<T> {
    fail_closed();
    Err(Error::Permission)
}
/// The genuine H role calls this BEFORE even fallible custody extraction. It
/// marks an obligation only, never installs or grants authority.
pub(super) fn require() -> Result<()> {
    match STATE.compare_exchange(LEGACY, REQUIRED, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) | Err(REQUIRED) => Ok(()),
        Err(_) => Err(Error::Permission),
    }
}
/// Must be the first coordinated Host operation. There is no reset, fallback,
/// importer, or ability to install a second terminal/observer after failure.
pub(super) fn install(terminal: HostControllingTerminalV1, restriction: HostOriginalRestrictionV1) -> Result<()> {
    require()?;
    if INSTALL_ATTEMPTED.swap(true, Ordering::SeqCst) { return deny(); }
    if terminal.deadline() != restriction.deadline()
        || terminal.check_current().is_err() || restriction.check_current().is_err()
        || ORIGINAL.set(Original { terminal, restriction }).is_err()
    { return deny(); }
    check(None)
}
/// Consume only genuine Origin custody. Obligation is irreversible even on
/// duplicate/failed install; the exact same Arc is returned to the owner.
pub(super) fn install_pair(service: HostCompletedPairServiceV1) -> Result<Arc<HostCompletedPairServiceV1>> {
    if PAIR_REQUIRED.swap(true, Ordering::SeqCst) { return deny(); }
    if STATE.load(Ordering::SeqCst) != REQUIRED || ORIGINAL.get().is_none()
        || service.check_current().is_err() { return deny(); }
    let service = Arc::new(service);
    if PAIR.set(Arc::clone(&service)).is_err() { return deny(); }
    // Installation occurs while genuinely PARKED. The ordinary physical
    // effect check requires RUNNING and must not be used to release this park.
    // Origin compares this sealed observer against the installed SAME Host
    // lifecycle, then samples original shared R without minting permission.
    let Some(original) = ORIGINAL.get() else { return deny(); };
    if original.terminal.check_current().is_err()
        || original.restriction.check_completed_pair_service(&service).is_err()
        || STATE.load(Ordering::SeqCst) != REQUIRED { return deny(); }
    Ok(service)
}
/// Zero-wait restriction check. No source, DB, Terminal mutex or remote call.
/// The observer's SeqCst zero sample is last after the original TTY/lifetime/
/// session checks, and is never returned as a reusable positive permit.
pub(super) fn check(file: Option<&File>) -> Result<()> {
    match STATE.load(Ordering::SeqCst) {
        LEGACY => return Ok(()),
        REQUIRED => {},
        _ => return Err(Error::Permission),
    }
    let Some(original) = ORIGINAL.get() else { return deny(); };
    let tty = match file {
        Some(file) => original.terminal.check_controlling_file(file),
        None => original.terminal.check_current(),
    };
    if tty.is_err() { return deny(); }
    if PAIR_REQUIRED.load(Ordering::SeqCst) {
        let Some(pair) = PAIR.get() else { return deny(); };
        if pair.check_current().is_err() { return deny(); }
    }
    // Preserve original shared-R sample last, after Pair cached restriction.
    if original.restriction.check_current().is_err() { return deny(); }
    Ok(())
}
/// Original installed H session ceiling, exposed only as an additional cached
/// restriction. No caller duration/importer and no new authority is created.
pub(super) fn original_session_ceiling() -> Result<std::time::Instant> {
    if !required() { return Err(Error::Permission); }
    check(None)?;
    Ok(ORIGINAL.get().ok_or(Error::Permission)?.terminal.deadline())
}

fn file() -> Result<File> {
    check(None)?;
    let file = OpenOptions::new().read(true).write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/dev/tty").map_err(|_| Error::Terminal)?;
    check(Some(&file))?;
    Ok(file)
}
fn wait(file: &File, events: libc::c_short, bounds: Option<&OriginalPromptBoundsV1>, held: Option<&crate::authority::Held>) -> Result<()> {
    check_prompt(bounds, held)?;
    check(Some(file))?;
    let original = ORIGINAL.get().ok_or(Error::Permission)?;
    let ceiling = bounds.map_or(original.terminal.deadline(), |b| b.deadline().min(original.terminal.deadline()));
    let remaining = ceiling.checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero()).ok_or(Error::Permission)?;
    // At most 50ms. The original deadline is never replaced by a receive budget.
    let timeout = remaining.min(Duration::from_millis(50)).as_millis() as i32;
    let mut poll = libc::pollfd { fd: file.as_raw_fd(), events, revents: 0 };
    let result = unsafe { libc::poll(&mut poll, 1, timeout) };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(Error::Terminal);
    }
    if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 { return Err(Error::Terminal); }
    check_prompt(bounds, held)?;
    check(Some(file))
}
fn check_prompt(bounds: Option<&OriginalPromptBoundsV1>, held: Option<&crate::authority::Held>) -> Result<()> {
    if let Some(bounds) = bounds { bounds.check()?; }
    if let Some(held) = held { held.check_final_effect_restriction()?; }
    Ok(())
}
pub(super) fn read_line() -> Result<Zeroizing<String>> { read_prompt(None, None) }
pub(super) fn read_prompt(bounds: Option<&OriginalPromptBoundsV1>, held: Option<&crate::authority::Held>) -> Result<Zeroizing<String>> {
    check_prompt(bounds, held)?;
    let mut file = file()?;
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        check_prompt(bounds, held)?;
        check(Some(&file))?;
        let mut byte = Zeroizing::new([0u8; 1]);
        match file.read(&mut *byte) {
            Ok(0) => return Err(Error::Terminal),
            Ok(_) if byte[0] == b'\n' => {
                check_prompt(bounds, held)?;
                check(Some(&file))?;
                return Ok(Zeroizing::new(std::str::from_utf8(&bytes)
                    .map_err(|_| Error::Invalid)?.trim_end_matches('\r').to_owned()));
            },
            Ok(_) => {
                if bytes.len() >= 8192 { return Err(Error::Invalid); }
                bytes.push(byte[0]);
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(&file, libc::POLLIN, bounds, held)?,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(_) => return Err(Error::Terminal),
        }
    }
}
pub(super) fn write_all(bytes: &[u8], deadline: Option<std::time::Instant>, wall_bounds: Option<(u64, u64)>) -> Result<()> {
    write_kernel(bytes, deadline, wall_bounds, None, None)
}
pub(super) fn write_prompt(bytes: &[u8], bounds: Option<&OriginalPromptBoundsV1>, held: Option<&crate::authority::Held>) -> Result<()> {
    write_kernel(bytes, None, None, bounds, held)
}
fn write_kernel(bytes: &[u8], deadline: Option<std::time::Instant>, wall_bounds: Option<(u64, u64)>, bounds: Option<&OriginalPromptBoundsV1>, held: Option<&crate::authority::Held>) -> Result<()> {
    check_prompt(bounds, held)?;
    let mut file = file()?;
    let mut offset = 0;
    while offset < bytes.len() {
        // These are original immutable purpose/source ceilings, not a new
        // relative budget or semantic callback inside the output loop.
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) { return Err(Error::Permission); }
        if let Some((from, until)) = wall_bounds {
            let now = crate::now()?;
            if now < from || now >= until { return Err(Error::Permission); }
        }
        check_prompt(bounds, held)?;
        // All descriptor setup, waits and exact-terminal checks precede this
        // fresh final shared sample. Only this physical write is admitted.
        check(Some(&file))?;
        match file.write(&bytes[offset..]) {
            Ok(0) => return Err(Error::Terminal),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(&file, libc::POLLOUT, bounds, held)?,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(_) => return Err(Error::Terminal),
        }
    }
    Ok(())
}
