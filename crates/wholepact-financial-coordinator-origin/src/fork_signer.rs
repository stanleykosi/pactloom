//! Check-only provenance for the two original H-owned Signer children. No
//! constructor, process/descriptor import, endpoint discovery or role work is
//! public. This cannot unlock, enroll, approve, sign, or issue an effect permit.
use crate::{image::VerifiedCommonImageIdentity, process::{PeerLifetime, Role}, rejected, Result};
use std::{fs::File, os::{fd::{AsRawFd, FromRawFd, OwnedFd}, unix::net::UnixStream},
    sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};

/// Non-Clone and issued only once from actual Host custody after the fixed
/// barrier. Copies of pidfds are check-only; Host retains the sole child reapers.
/// The trusted whole image forbids later role exec/fork or external worker entry.
pub struct OriginalForkSignerVerifier {
    owner_pid: libc::pid_t,
    child: PeerLifetime,
    coordinator: PeerLifetime,
    image: VerifiedCommonImageIdentity,
    custody_live: Arc<AtomicBool>,
    deadline: Instant,
}

/// The first field of HostOrigin, so ordinary drop invalidates before any owned
/// channel/child drop or potentially kernel-blocked reap. No descriptor is held.
pub(super) struct HostVerifierCustody { live: Arc<AtomicBool> }
impl HostVerifierCustody {
    pub(super) fn new() -> Self { Self { live: Arc::new(AtomicBool::new(true)) } }
}
impl Drop for HostVerifierCustody {
    fn drop(&mut self) { self.live.store(false, Ordering::Release); }
}

// Pure one-shot restriction. Even a failed first issuance cannot be retried.
pub(super) fn claim_pair(issued: &mut bool) -> Result<()> {
    if std::mem::replace(issued, true) { return Err(rejected("original Signer verifier pair consumed")); }
    Ok(())
}

impl OriginalForkSignerVerifier {
    pub(super) fn retain(
        child: PeerLifetime, coordinator: PeerLifetime,
        image: VerifiedCommonImageIdentity, custody: &HostVerifierCustody, deadline: Instant,
    ) -> Result<Self> {
        if !matches!(child.role(), Role::Signer1 | Role::Signer2)
            || coordinator.role() != Role::Coordinator
        { return Err(rejected("wrong retained original Signer edge")); }
        let result = Self { owner_pid: unsafe { libc::getpid() }, child, coordinator, image,
            custody_live: Arc::clone(&custody.live), deadline };
        result.check_original_custody_alive()?;
        Ok(result)
    }

    /// Restriction-only, nonblocking lifetime observation. Never an action lease
    /// or a substitute for an existing client's source/currentness checks.
    pub fn check_original_custody_alive(&self) -> Result<()> {
        if !self.custody_live.load(Ordering::Acquire)
            || unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::geteuid() } != self.child.uid()
        { return Err(rejected("original Host custody unavailable")); }
        crate::channel::require_time(self.deadline)?;
        self.coordinator.check_alive()?;
        self.child.check_alive()?;
        if !self.custody_live.load(Ordering::Acquire) {
            return Err(rejected("original Host custody disposed"));
        }
        Ok(())
    }

    /// Compare the SAME executable opened and verified by the independent fixed
    /// installed Signer pin loader. This does not itself load or replace that pin.
    /// Hashing is bounded but belongs on a worker, never the native event tail.
    pub fn verify_installed_executable(&self, executable: &File) -> Result<()> {
        self.check_original_custody_alive()?;
        self.image.verify_opened_executable(executable)?;
        self.check_original_custody_alive()
    }

    /// Authenticate an actual fresh directly connected Unix stream, not the
    /// inherited bootstrap socketpair (whose creator may be the wrong peer).
    /// Mandatory SO_PEERPIDFD is never replaced with a caller PID lookup.
    pub fn verify_connected_signer(&self, stream: &UnixStream) -> Result<()> {
        self.check_original_custody_alive()?;
        if socket_integer(stream, libc::SO_TYPE)? != libc::SOCK_STREAM
            || socket_integer(stream, libc::SO_DOMAIN)? != libc::AF_UNIX
        { return Err(rejected("not a direct Signer Unix stream")); }
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&credentials) as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(), &mut len) };
        if rc != 0 || len as usize != std::mem::size_of_val(&credentials)
            || credentials.pid != self.child.pid() || credentials.uid != self.child.uid()
        { return Err(rejected("connected peer is not the original Signer child")); }
        #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
        const SO_PEERPIDFD: libc::c_int = 0x0056;
        #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
        const SO_PEERPIDFD: libc::c_int = 77;
        let mut raw = -1;
        len = std::mem::size_of_val(&raw) as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, SO_PEERPIDFD,
            (&mut raw as *mut libc::c_int).cast(), &mut len) };
        if rc != 0 || raw < 0 { return Err(rejected("connected Signer pidfd unavailable")); }
        // Own immediately, so malformed successful output also closes the FD.
        let observed = unsafe { OwnedFd::from_raw_fd(raw) };
        if len as usize != std::mem::size_of::<libc::c_int>()
            || unsafe { libc::fcntl(observed.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0
        { return Err(rejected("connected Signer pidfd invalid")); }
        check_observed_alive(&observed)?;
        self.check_original_custody_alive()?;
        // Both live lifetime handles plus the kernel-observed exact PID/UID
        // exclude reuse. The original unreaped child was acquired only at fork.
        check_observed_alive(&observed)?;
        self.check_original_custody_alive()
    }
}

fn socket_integer(stream: &UnixStream, option: libc::c_int) -> Result<libc::c_int> {
    let mut value = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, option,
        (&mut value as *mut libc::c_int).cast(), &mut len) };
    if rc != 0 || len as usize != std::mem::size_of::<libc::c_int>() {
        return Err(rejected("connected Signer socket observation failed"));
    }
    Ok(value)
}
fn check_observed_alive(pidfd: &OwnedFd) -> Result<()> {
    let mut poll = libc::pollfd { fd: pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 || poll.revents != 0 {
        return Err(rejected("connected Signer lifetime lost"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifier_pair_claim_is_consumed_before_any_fallible_work() {
        let mut issued = false;
        claim_pair(&mut issued).unwrap();
        assert!(issued);
        // A subsequent duplication/validation failure cannot clear this bit.
        assert!(claim_pair(&mut issued).is_err());
        assert!(claim_pair(&mut issued).is_err());
    }
    #[test]
    fn custody_drop_monotonically_invalidates_observers() {
        let custody = HostVerifierCustody::new();
        let observer = Arc::clone(&custody.live);
        assert!(observer.load(Ordering::Acquire));
        drop(custody);
        assert!(!observer.load(Ordering::Acquire));
        assert!(!observer.load(Ordering::Acquire));
        // No process, descriptor or OriginalForkSignerVerifier was constructed.
    }
}
