//! Private lock-free two-slot restriction state and check-only actual lifetimes.
use crate::{process::PeerLifetime, rejected, Result};
use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

pub(super) const NEW: u8 = 0;
pub(super) const PREPARING: u8 = 1;
pub(super) const REVIEW: u8 = 2;
pub(super) const ARMED: u8 = 3;
pub(super) const READY: u8 = 4;
pub(super) const ADMITTED: u8 = 5;
const REVOKED: u32 = 1 << 31;
pub(super) const PENDING: u8 = 0;
pub(super) const SENT: u8 = 1;
pub(super) const ABANDONED: u8 = 2;

/// Both target slots and global R share one atomic word. Native A is precisely
/// the successful READY->ADMITTED CAS, never a later driver/relay dequeue.
pub(super) struct Phases {
    word: AtomicU32,
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    host_restriction: Option<crate::host_restriction::CoordinatorHostRestrictionV1>,
}
impl Phases {
    pub(super) fn new() -> Self { Self {
        word: AtomicU32::new(0),
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        host_restriction: None,
    } }
    /// Only the actual C branch can supply this private revoke-on-drop writer.
    /// S and narrow-profile constructors have no shared-memory write owner.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) fn coordinator(writer: crate::host_restriction::CoordinatorHostRestrictionV1) -> Self {
        Self { word: AtomicU32::new(0), host_restriction: Some(writer) }
    }
    pub(super) fn phase(&self, slot: usize) -> u8 { ((self.word.load(Ordering::Acquire) >> (slot * 8)) & 0xff) as u8 }
    pub(super) fn revoked(&self) -> bool { self.word.load(Ordering::Acquire) & REVOKED != 0 }
    pub(super) fn revoke(&self) {
        // EVERY local C restriction path, including errors and Drop, reaches
        // this ordering. Host observes R before local admission can observe R.
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        if let Some(writer) = &self.host_restriction { writer.revoke(); }
        self.word.fetch_or(REVOKED, Ordering::AcqRel);
    }
    /// Fixed observation-only completion. Preserves R and cannot issue a purpose.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_workflow_continue_saved(&self,slot:usize)->Result<()>{
        use crate::financial_workflow_continue::{CONT_ADMITTED,AWAITING_ADMISSION};
        if slot>1{return Err(rejected("not a fixed workflow slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if ((old>>shift)&0xff)!=CONT_ADMITTED as u32{return Err(rejected("Continue completion was not admitted"));}
            let new=(old&!(0xff<<shift))|((AWAITING_ADMISSION as u32)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Only S's authenticated ordered Final receive may record this exact
    /// transition after C already admitted it. Preserve R, never issue C's A.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_received_workflow_continue_final(&self,slot:usize)->Result<()>{
        use crate::financial_workflow_continue::{CONT_READY,CONT_ADMITTED};
        if slot>1{return Err(rejected("not a fixed received Continue slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if ((old>>shift)&0xff)!=CONT_READY as u32{return Err(rejected("received Continue Final was not Ready"));}
            let new=(old&!(0xff<<shift))|((CONT_ADMITTED as u32)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    pub(super) fn step(&self, slot: usize, from: u8, to: u8) -> Result<()> {
        if slot > 1 { return Err(rejected("not a fixed Continue slot")); }
        let shift = slot * 8;
        let mut old = self.word.load(Ordering::Acquire);
        loop {
            if old & REVOKED != 0 || ((old >> shift) & 0xff) != from as u32 {
                return Err(rejected("Continue slot consumed or revoked"));
            }
            let new = (old & !(0xff << shift)) | ((to as u32) << shift);
            match self.word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(()), Err(actual) => old = actual,
            }
        }
    }
}

pub(super) struct CheckedPeer { pidfd: OwnedFd, socket: OwnedFd }
impl CheckedPeer {
    pub(super) fn retain(peer: &PeerLifetime, socket: RawFd) -> Result<Self> {
        peer.check_alive()?;
        let result = Self { pidfd: duplicate(peer.fd())?, socket: duplicate(socket)? };
        result.check()?;
        Ok(result)
    }
    pub(super) fn check(&self) -> Result<()> {
        check_pidfd(&self.pidfd)?;
        let mut poll = libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN | libc::POLLRDHUP, revents: 0 };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0
            || poll.revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR | libc::POLLNVAL) != 0
        { return Err(rejected("original Continue edge lost")); }
        Ok(())
    }
    pub(super) fn shutdown(&self) { unsafe { libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_RDWR); } }
}
fn duplicate(fd: RawFd) -> Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn check_pidfd(fd: &OwnedFd) -> Result<()> {
    let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 || poll.revents != 0 {
        return Err(rejected("original Continue process lost"));
    }
    Ok(())
}

pub(super) struct Core {
    pub(super) phase: Phases,
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) signer_restriction: Option<crate::host_restriction::SignerSharedRestrictionV1>,
    pub(super) peer: CheckedPeer,
    pub(super) roots: Vec<OwnedFd>,
    pub(super) coordinator: Option<PeerLifetime>,
    pub(super) owner_pid: libc::pid_t,
    pub(super) owner_uid: libc::uid_t,
    pub(super) epoch: Instant,
    pub(super) session: Instant,
    pub(super) alive: AtomicBool,
    pub(super) outbound: [AtomicU8; 2],
}
impl Core {
    pub(super) fn check(&self) -> Result<()> {
        let result = (|| {
            if !self.alive.load(Ordering::Acquire) || unsafe { libc::getpid() } != self.owner_pid
                || unsafe { libc::geteuid() } != self.owner_uid
            { return Err(rejected("original Continue actor custody lost")); }
            self.peer.check()?;
            for fd in &self.roots { check_pidfd(fd)?; }
            if let Some(c) = &self.coordinator { c.check_alive()?; }
            Ok(())
        })();
        if result.is_err() { self.close(); }
        result
    }
    /// Ordinary action restriction only. Never call this from the admitted
    /// local Continue Final exception or from custody-only checks.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) fn check_action_restrictions(&self) -> Result<()> {
        let result = (|| {
            self.check()?;
            crate::channel::require_time(self.session)?;
            if self.phase.revoked() { return Err(rejected("original workflow restricted")); }
            // Last sample uses the original shared cell, not a queued Cancel.
            if let Some(reader) = &self.signer_restriction { reader.check_current()?; }
            Ok(())
        })();
        if result.is_err() { self.phase.revoke(); }
        result
    }
    pub(super) fn close(&self) {
        self.phase.revoke();
        self.alive.store(false, Ordering::Release);
        self.peer.shutdown();
    }
    pub(super) fn pending(&self) -> bool {
        (0..2).any(|i| self.phase.phase(i) == ADMITTED && self.outbound[i].load(Ordering::Acquire) == PENDING)
    }
}

pub(super) fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) } != bytes.len() as isize {
        return Err(rejected("fresh Continue challenge unavailable"));
    }
    Ok(hex::encode(bytes))
}
pub(super) fn hash(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
pub(super) fn wall_ms() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| rejected("Continue wall clock before epoch"))?
        .as_millis().try_into().map_err(|_| rejected("Continue wall clock overflow"))
}
pub(super) fn deadline_offset(epoch: Instant, deadline: Instant) -> Result<u64> {
    let ms: u64 = deadline.checked_duration_since(epoch).ok_or_else(|| rejected("Continue deadline underflow"))?
        .as_millis().try_into().map_err(|_| rejected("Continue deadline overflow"))?;
    if ms == 0 || ms > 300_000 { return Err(rejected("Continue deadline outside original session")); }
    Ok(ms) // Rounded DOWN, never a new budget from receive time.
}
pub(super) fn original_deadline(epoch: Instant, ms: u64, ceiling: Instant, now: Instant) -> Result<Instant> {
    if ms == 0 || ms > 300_000 { return Err(rejected("Continue original deadline unsupported")); }
    let result = epoch.checked_add(Duration::from_millis(ms)).ok_or_else(|| rejected("Continue deadline overflow"))?.min(ceiling);
    if result <= now { return Err(rejected("Continue original deadline expired")); }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_revoke_and_either_final_admission_share_one_atomic_order() {
        let state = Phases::new();
        state.step(0, NEW, READY).unwrap(); state.step(1, NEW, READY).unwrap();
        state.step(0, READY, ADMITTED).unwrap(); state.revoke();
        assert_eq!(state.phase(0), ADMITTED);
        assert!(state.step(1, READY, ADMITTED).is_err());
        assert!(state.step(0, ADMITTED, NEW).is_err());
        let state = Phases::new(); state.step(1, NEW, READY).unwrap(); state.revoke();
        assert!(state.step(1, READY, ADMITTED).is_err());
    }
    #[test]
    fn original_offsets_only_shorten_and_never_restart_a_deadline() {
        let epoch = Instant::now(); let exact = epoch + Duration::from_micros(1_234_567);
        let offset = deadline_offset(epoch, exact).unwrap(); assert_eq!(offset, 1234);
        let restored = original_deadline(epoch, offset, exact, epoch).unwrap();
        assert!(restored <= exact);
        assert!(original_deadline(epoch, offset, exact, restored).is_err());
        assert!(deadline_offset(exact, epoch).is_err());
        assert!(original_deadline(epoch, 300_001, exact, epoch).is_err());
        assert!(original_deadline(epoch, u64::MAX, exact, epoch).is_err());
    }
}
