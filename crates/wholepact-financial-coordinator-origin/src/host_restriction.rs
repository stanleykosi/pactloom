//! One original C/H/S monotone restriction cell, not a native approval issuer.
//! The mapping is RW in trusted whole-image C/H/S. H/S sealed APIs expose only
//! checks; this is NOT OS isolation from hostile code in either trusted role.
//! Bootstrap alone creates/prunes it. No pointer, FD, path, reset or importer
//! escapes, and no successful observation may be cached as an effect permit.
use crate::{
    bootstrap::PhaseDeadlinesV1,
    channel::require_time,
    process::{DirectChild, ForkOriginV1, PeerLifetime, Role},
    rejected,
    signer_continue_state::CheckedPeer,
    Result,
};
use std::{
    ptr::NonNull,
    sync::{Arc, atomic::{AtomicU32, Ordering}},
    time::Instant,
};

const CURRENT: u32 = 0;
const REVOKED: u32 = 1;

/// Each process owns its inherited virtual mapping, not another process's
/// mapping or child reaper. Anonymous MAP_SHARED keeps the atomic cell common.
struct SharedCell {
    word: NonNull<AtomicU32>,
}
// SAFETY: after the single prefork initialization, every access to the aligned
// live cell is atomic. An owner is never unmapped while borrowed, and Send/Sync
// do not expose its pointer or a non-atomic reference. Each fork unmaps only its
// own address space. No process shares a Rust allocator/refcount allocation.
unsafe impl Send for SharedCell {}
unsafe impl Sync for SharedCell {}
impl SharedCell {
    fn create() -> Result<Self> {
        let length = std::mem::size_of::<AtomicU32>();
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(), length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let Some(word) = NonNull::new(raw.cast::<AtomicU32>()) else {
            unsafe { libc::munmap(raw, length); }
            return Err(rejected("shared Host restriction address unavailable"));
        };
        if word.as_ptr().align_offset(std::mem::align_of::<AtomicU32>()) != 0 {
            unsafe { libc::munmap(raw, length); }
            return Err(rejected("shared Host restriction alignment unavailable"));
        }
        // SAFETY: fresh writable, sufficiently sized/aligned mapping, before
        // any fork or other reference exists. Initialization is exactly once.
        unsafe { word.as_ptr().write(AtomicU32::new(CURRENT)); }
        Ok(Self { word })
    }
    fn sample(&self) -> u32 {
        // SAFETY: self owns this live RW mapping for the full shared borrow.
        unsafe { self.word.as_ref() }.load(Ordering::SeqCst)
    }
    fn revoke(&self) {
        // The sole value ever stored after birth is R. Never clear/reset it.
        unsafe { self.word.as_ref() }.store(REVOKED, Ordering::SeqCst);
    }
}
impl Drop for SharedCell {
    fn drop(&mut self) {
        // No owned FD, external named object or other actor's mapping is closed.
        unsafe {
            libc::munmap(self.word.as_ptr().cast(), std::mem::size_of::<AtomicU32>());
        }
    }
}

/// Created before the fixed forks. Every C failure/drop from this instant
/// publishes R, including failures before a writer enters the full C Core.
/// Inherited H/S/W copies only unmap on drop; they never gain a write API.
pub(super) struct CreatedHostRestrictionV1 {
    cell: Option<SharedCell>,
    creator_pid: libc::pid_t,
    creator_uid: libc::uid_t,
    clocks: PhaseDeadlinesV1,
}
impl CreatedHostRestrictionV1 {
    pub(super) fn create(clocks: PhaseDeadlinesV1) -> Result<Self> {
        crate::process::require_single_thread()?;
        require_time(clocks.workflow().startup())?;
        Ok(Self {
            cell: Some(SharedCell::create()?),
            creator_pid: unsafe { libc::getpid() },
            creator_uid: unsafe { libc::geteuid() },
            clocks,
        })
    }
    pub(super) fn into_coordinator(
        mut self,
        host: &DirectChild,
    ) -> Result<CoordinatorHostRestrictionV1> {
        if unsafe { libc::getpid() } != self.creator_pid
            || unsafe { libc::geteuid() } != self.creator_uid
            || host.role() != Role::Host
        {
            return Err(rejected("shared restriction requires original C/H birth"));
        }
        require_time(self.clocks.workflow().startup())?;
        host.check_alive()?;
        Ok(CoordinatorHostRestrictionV1 {
            cell: self.cell.take().ok_or_else(|| rejected("shared restriction consumed"))?,
        })
    }
    /// Only the real H->S child branch may retain this inherited mapping. No
    /// extra FD is created: the full Core separately owns original C/H checks.
    pub(super) fn into_signer(mut self, origin: &ForkOriginV1, coordinator: &PeerLifetime) -> Result<SignerSharedRestrictionV1> {
        if !matches!(origin.role(), Role::Signer1 | Role::Signer2)
            || coordinator.role() != Role::Coordinator
            || coordinator.pid() != self.creator_pid || coordinator.uid() != self.creator_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || unsafe { libc::getpid() } == self.creator_pid
        { return Err(rejected("shared restriction requires original Signer birth")); }
        require_time(self.clocks.workflow().startup())?;
        origin.check_parent_alive()?;
        coordinator.check_alive()?;
        let observer = SignerSharedRestrictionV1 {
            cell: self.cell.take().ok_or_else(|| rejected("shared restriction consumed"))?,
            owner_pid: unsafe { libc::getpid() }, owner_uid: self.creator_uid,
            role: origin.role(), deadline: self.clocks.session,
        };
        observer.check_current()?;
        Ok(observer)
    }
    /// Exactly the six fixed original History/Continuation/Signing W branches
    /// retain this same prefork cell. No other W gains a mapping or writer.
    pub(super) fn into_financial_witness(mut self, origin: &ForkOriginV1) -> Result<WitnessSharedRestrictionV1> {
        if !(crate::financial_witness_channel::is_financial_witness(origin.role())
            ||crate::financial_history_channel::is_history_witness(origin.role())||crate::financial_signing_channel::is_signing_witness(origin.role()))
            || !origin.has_original_coordinator(self.creator_pid, self.creator_uid)
            || unsafe { libc::geteuid() } != self.creator_uid
        { return Err(rejected("shared restriction requires original financial Witness birth")); }
        require_time(self.clocks.workflow().startup())?;
        origin.check_parent_alive()?;
        let result = WitnessSharedRestrictionV1 {
            cell: self.cell.take().ok_or_else(|| rejected("shared restriction consumed"))?,
            owner_pid: unsafe { libc::getpid() }, owner_uid: self.creator_uid,
            deadline: self.clocks.session,
        };
        result.check_current()?;
        Ok(result)
    }
    pub(super) fn into_host(mut self, origin: &ForkOriginV1) -> Result<(HostOriginalRestrictionV1, crate::host_interstage::HostLifecycleOwner)> {
        let coordinator = origin.retain_host_coordinator_lifetime()?;
        let owner_pid = unsafe { libc::getpid() };
        if coordinator.pid() != self.creator_pid
            || coordinator.uid() != self.creator_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || owner_pid == self.creator_pid
        {
            return Err(rejected("shared restriction not inherited by original Host"));
        }
        require_time(self.clocks.workflow().startup())?;
        let peer = origin.continue_observer()?;
        let checks = Arc::new(HostRestrictionChecks {
            cell: self.cell.take().ok_or_else(|| rejected("shared restriction consumed"))?,
            peer,
            owner_pid,
            owner_uid: self.creator_uid,
            deadline: self.clocks.session,
        });
        checks.check_current()?;
        let (owner,lifecycle)=crate::host_interstage::HostLifecycle::create(Arc::clone(&checks),self.clocks.workflow());
        Ok((HostOriginalRestrictionV1{checks,lifecycle},owner))
    }
}
impl Drop for CreatedHostRestrictionV1 {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.creator_pid {
            if let Some(cell) = &self.cell {
                cell.revoke();
            }
        }
    }
}

/// Only the genuine C branch obtains this private writer. Phases::revoke must
/// call this BEFORE publishing its local R; Drop covers construction/errors.
pub(super) struct CoordinatorHostRestrictionV1 {
    cell: SharedCell,
}
impl CoordinatorHostRestrictionV1 {
    pub(super) fn revoke(&self) { self.cell.revoke(); }
}
impl Drop for CoordinatorHostRestrictionV1 {
    fn drop(&mut self) { self.revoke(); }
}

/// Sealed check-only custody from the actual original Host/C edge. It cannot
/// approve a TTY challenge, read a source, construct a permit, or renew a clock.
pub struct HostOriginalRestrictionV1 {
    checks:Arc<HostRestrictionChecks>,
    lifecycle:Arc<crate::host_interstage::HostLifecycle>,
}
pub(super) struct HostRestrictionChecks {
    cell:SharedCell,peer:CheckedPeer,owner_pid:libc::pid_t,owner_uid:libc::uid_t,deadline:Instant,
}
impl HostRestrictionChecks {
    pub(super) fn check_current(&self)->Result<()>{
        if unsafe{libc::getpid()}!=self.owner_pid||unsafe{libc::geteuid()}!=self.owner_uid{
            return Err(rejected("shared Host restriction outside original actor"));}
        self.peer.check()?;require_time(self.deadline)?;
        if self.cell.sample()!=CURRENT{return Err(rejected("original C restricted Host"));}Ok(())
    }
}
impl HostOriginalRestrictionV1 {
    pub fn deadline(&self)->Instant{self.checks.deadline}
    /// Zero-wait restriction sample. Same-H park/poison is checked before the
    /// final shared C-R SeqCst load; neither observation creates consent.
    pub fn check_current(&self)->Result<()>{
        self.lifecycle.check_foreground()?;self.checks.check_current()
    }
}

/// Private inherited mapping. Core calls only AFTER its actual C/H checks.
/// No writer, clone, importer or reaper is available to S.
pub(super) struct SignerSharedRestrictionV1 {
    cell: SharedCell,
    owner_pid: libc::pid_t,
    owner_uid: libc::uid_t,
    role: Role,
    deadline: Instant,
}
impl SignerSharedRestrictionV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        if unsafe { libc::getpid() } != self.owner_pid || unsafe { libc::geteuid() } != self.owner_uid
            || !matches!(self.role, Role::Signer1 | Role::Signer2)
        { return Err(rejected("shared restriction used outside original Signer")); }
        require_time(self.deadline)?;
        if self.cell.sample() != CURRENT {
            return Err(rejected("original Coordinator restricted Signer operation"));
        }
        Ok(())
    }
}

/// Private actual C->fixed-W inherited check-only map. Trusted W still has a RW
/// virtual mapping; the API is not hostile-W OS isolation.
pub(super) struct WitnessSharedRestrictionV1 {
    cell: SharedCell, owner_pid: libc::pid_t, owner_uid: libc::uid_t, deadline: Instant,
}
impl WitnessSharedRestrictionV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        if unsafe { libc::getpid() } != self.owner_pid || unsafe { libc::geteuid() } != self.owner_uid {
            return Err(rejected("financial Witness restriction actor mismatch"));
        }
        require_time(self.deadline)?;
        if self.cell.sample() != CURRENT { return Err(rejected("original C restricted financial Witness")); }
        Ok(())
    }
}
