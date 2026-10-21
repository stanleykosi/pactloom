//! Fixed genuine-fork provenance. None of these types is a financial permit or
//! a legacy InstalledSignerProvider. No PID/FD/argv reconstruction entry exists.
use crate::{channel::{Channel, Message}, rejected, Result};
use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd}, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Role {
    Coordinator = 1,
    Host,
    Signer1,
    Signer2,
    Owner1BootstrapHistory,
    Owner1V3DeliveryAdmission,
    Owner1DeliveryAuditHistory,
    Owner1FinancialReadHistory,
    Owner1FinancialContinuationAdmission,
    Owner1FinancialSigning,
    Owner2BootstrapHistory,
    Owner2V3DeliveryAdmission,
    Owner2DeliveryAuditHistory,
    Owner2FinancialReadHistory,
    Owner2FinancialContinuationAdmission,
    Owner2FinancialSigning,
    CompletedPair,
}

// Conservative supplied-originals-through-completed-pair *birth* inventory,
// not a minimum count, account construction/recovery or service activation
// order. Future activation must preserve the reviewed per-owner workflow.
pub(super) const WITNESS_ROLES: [Role; 13] = [
    Role::Owner1BootstrapHistory,
    Role::Owner1V3DeliveryAdmission,
    Role::Owner1DeliveryAuditHistory,
    Role::Owner1FinancialReadHistory,
    Role::Owner1FinancialContinuationAdmission,
    Role::Owner1FinancialSigning,
    Role::Owner2BootstrapHistory,
    Role::Owner2V3DeliveryAdmission,
    Role::Owner2DeliveryAuditHistory,
    Role::Owner2FinancialReadHistory,
    Role::Owner2FinancialContinuationAdmission,
    Role::Owner2FinancialSigning,
    Role::CompletedPair,
];

pub(super) struct PeerLifetime {
    pid: libc::pid_t,
    uid: libc::uid_t,
    pidfd: OwnedFd,
    role: Role,
}
impl PeerLifetime {
    pub(super) fn pid(&self) -> libc::pid_t { self.pid }
    pub(super) fn uid(&self) -> libc::uid_t { self.uid }
    pub(super) fn role(&self) -> Role { self.role }
    pub(super) fn fd(&self) -> libc::c_int { self.pidfd.as_raw_fd() }
    pub(super) fn check_alive(&self) -> Result<()> {
        let mut poll = libc::pollfd { fd: self.fd(), events: libc::POLLIN, revents: 0 };
        let rc = unsafe { libc::poll(&mut poll, 1, 0) };
        if rc != 0 || poll.revents != 0 {
            #[cfg(wholepact_bootstrap_ci)]
            crate::ci::reject_boundary("peer_lifetime", "dead_or_poll_error", Some(self), None, Some(false), false, None);
            return Err(rejected("original process not live"));
        }
        Ok(())
    }
}

/// Born solely in fork_edge's child return, never from a descriptor supplied by
/// a caller. Non-Clone and private to this kernel. Construction lineage only.
pub(super) struct ForkOriginV1 {
    local_role: Role,
    parent: PeerLifetime,
    channel: Channel,
}
impl ForkOriginV1 {
    #[cfg(wholepact_delivery_ci)]
    pub(super) fn observed_original_parent(&self) -> i32 { self.parent.pid }

    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn delivery_observer(&self) -> Result<crate::delivery_origin::ObservedPeer> {
        if self.local_role != Role::Owner1V3DeliveryAdmission { return Err(rejected("wrong positive witness")); }
        crate::delivery_origin::ObservedPeer::retain(&self.parent, self.channel.review_fd())
    }
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn delivery_send(&self, packet: &crate::delivery_channel::Packet) -> Result<()> {
        crate::delivery_channel::send(self.channel.review_fd(), self.local_role, &self.parent, packet)
    }
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn delivery_receive(&self) -> Result<Option<crate::delivery_channel::Packet>> {
        crate::delivery_channel::try_receive(self.channel.review_fd(), self.local_role, &self.parent)
    }

    #[cfg(feature = "cancel-only-witness-review")]
    pub(super) fn review_send(&self, packet: &crate::cancel_review::Packet) -> Result<()> {
        if self.local_role != crate::cancel_review::WITNESS || self.parent.role != Role::Coordinator { return Err(rejected("not the original cancel-only witness")); }
        crate::cancel_review::send(self.channel.review_fd(), self.local_role, &self.parent, packet)
    }
    #[cfg(feature = "cancel-only-witness-review")]
    pub(super) fn review_try_receive(&self) -> Result<Option<crate::cancel_review::Packet>> {
        if self.local_role != crate::cancel_review::WITNESS || self.parent.role != Role::Coordinator { return Err(rejected("not the original cancel-only witness")); }
        crate::cancel_review::try_receive(self.channel.review_fd(), self.local_role, &self.parent)
    }
    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    pub(super) fn wait_host_stop(&self, signers: &[Option<DirectChild>; 2], deadline: Instant) -> Result<()> {
        if self.local_role != Role::Host { return Err(rejected("not original Host")); }
        loop {
            crate::channel::require_time(deadline)?;
            self.parent.check_alive()?;
            for child in signers.iter().flatten() { child.check_alive()?; }
            let mut polls = [
                libc::pollfd { fd: self.channel.review_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.parent.fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: signers[0].as_ref().ok_or_else(|| rejected("missing S1"))?.peer.fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: signers[1].as_ref().ok_or_else(|| rejected("missing S2"))?.peer.fd(), events: libc::POLLIN, revents: 0 },
            ];
            let rc = unsafe { libc::poll(polls.as_mut_ptr(), 4, 50) };
            if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted { return Err(std::io::Error::last_os_error()); }
            if polls[1..].iter().any(|p| p.revents != 0) { return Err(rejected("original Host tree peer lost")); }
            if polls[0].revents != 0 { return self.receive(Message::Stop, deadline); }
        }
    }
    #[cfg(wholepact_bootstrap_ci)]
    pub(super) fn ci_descriptors(&self) -> [libc::c_int; 2] { [self.channel.ci_fd(), self.parent.fd()] }
    #[cfg(wholepact_bootstrap_ci)]
    pub(super) fn ci_parent_pid(&self) -> libc::pid_t { self.parent.pid() }
    pub(super) fn role(&self) -> Role { self.local_role }
    pub(super) fn check_parent_alive(&self) -> Result<()> { self.parent.check_alive() }
    pub(super) fn send(&self, message: Message, deadline: Instant) -> Result<()> {
        self.channel.send(message, self.local_role, &self.parent, deadline)
    }
    pub(super) fn receive(&self, message: Message, deadline: Instant) -> Result<()> {
        self.channel.receive(message, &self.parent, deadline)
    }
}

/// The real parent owns exactly this still-unreaped direct child. Children may
/// inherit copies during early fork, but can only drop/close those copied FDs.
pub(super) struct DirectChild {
    owner_pid: libc::pid_t,
    local_role: Role,
    peer: PeerLifetime,
    channel: Channel,
    reaped: bool,
}
impl DirectChild {
    #[cfg(wholepact_delivery_ci)]
    pub(super) fn observed_binding(&self) -> crate::delivery_observer::ChildBinding {
        crate::delivery_observer::ChildBinding { role: format!("{:?}", self.peer.role), pid: self.peer.pid }
    }

    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn duplicate_lifetime_for_delivery(&self) -> Result<OwnedFd> {
        self.require_owner()?;
        self.peer.check_alive()?;
        self.peer.pidfd.try_clone()
    }
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn delivery_observer(&self) -> Result<crate::delivery_origin::ObservedPeer> {
        self.require_owner()?;
        if self.peer.role != Role::Owner1V3DeliveryAdmission { return Err(rejected("wrong positive witness")); }
        crate::delivery_origin::ObservedPeer::retain(&self.peer, self.channel.review_fd())
    }
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn delivery_send(&self, packet: &crate::delivery_channel::Packet) -> Result<()> {
        self.require_owner()?;
        crate::delivery_channel::send(self.channel.review_fd(), self.local_role, &self.peer, packet)
    }
    #[cfg(feature = "coordinated-witness-delivery-append")]
    pub(super) fn delivery_receive(&self) -> Result<Option<crate::delivery_channel::Packet>> {
        self.require_owner()?;
        crate::delivery_channel::try_receive(self.channel.review_fd(), self.local_role, &self.peer)
    }

    #[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
    pub(super) fn role(&self) -> Role { self.peer.role }
    #[cfg(feature = "cancel-only-witness-review")]
    pub(super) fn review_send(&self, packet: &crate::cancel_review::Packet) -> Result<()> {
        self.require_owner()?;
        crate::cancel_review::send(self.channel.review_fd(), self.local_role, &self.peer, packet)
    }
    #[cfg(feature = "cancel-only-witness-review")]
    pub(super) fn review_try_receive(&self) -> Result<Option<crate::cancel_review::Packet>> {
        self.require_owner()?;
        crate::cancel_review::try_receive(self.channel.review_fd(), self.local_role, &self.peer)
    }
    #[cfg(wholepact_bootstrap_ci)]
    pub(super) fn ci_descriptors(&self) -> [libc::c_int; 2] { [self.channel.ci_fd(), self.peer.fd()] }
    pub(super) fn send(&self, message: Message, deadline: Instant) -> Result<()> {
        self.require_owner()?;
        self.channel.send(message, self.local_role, &self.peer, deadline)
    }
    pub(super) fn receive(&self, message: Message, deadline: Instant) -> Result<()> {
        self.require_owner()?;
        self.channel.receive(message, &self.peer, deadline)
    }
    pub(super) fn check_alive(&self) -> Result<()> {
        self.require_owner()?;
        self.peer.check_alive()
    }
    pub(super) fn finish(mut self, deadline: Instant) -> Result<()> {
        self.require_owner()?;
        let status = loop {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(self.peer.pid, &mut status, libc::WNOHANG) };
            if rc == self.peer.pid {
                self.reaped = true;
                #[cfg(wholepact_bootstrap_ci)]
                crate::ci::reaped(self.peer.role, self.peer.pid, status);
                #[cfg(wholepact_delivery_ci)]
                crate::delivery_observer::record(crate::delivery_observer::Event::OwnedReap {
                    child_role: format!("{:?}", self.peer.role), child_pid: self.peer.pid,
                    exit_code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
                    signal: libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)), forced: false,
                });
                break status;
            }
            if rc < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    crate::channel::require_time(deadline)?;
                    continue;
                }
                return Err(error);
            }
            crate::channel::require_time(deadline)?;
            let millis = deadline.saturating_duration_since(Instant::now()).as_millis().clamp(1, 100) as libc::c_int;
            let mut poll = libc::pollfd { fd: self.peer.fd(), events: libc::POLLIN, revents: 0 };
            let rc = unsafe { libc::poll(&mut poll, 1, millis) };
            if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(std::io::Error::last_os_error());
            }
        };
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(rejected("fixed child did not complete cleanly"));
        }
        Ok(())
    }
    fn require_owner(&self) -> Result<()> {
        if unsafe { libc::getpid() } != self.owner_pid || self.reaped {
            return Err(rejected("not original direct-child owner"));
        }
        Ok(())
    }
    fn wait(&mut self) -> Result<libc::c_int> {
        let mut status = 0;
        loop {
            let rc = unsafe { libc::waitpid(self.peer.pid, &mut status, 0) };
            if rc == self.peer.pid {
                self.reaped = true;
                #[cfg(wholepact_bootstrap_ci)]
                crate::ci::reaped(self.peer.role, self.peer.pid, status);
                #[cfg(wholepact_delivery_ci)]
                crate::delivery_observer::record(crate::delivery_observer::Event::OwnedReap {
                    child_role: format!("{:?}", self.peer.role), child_pid: self.peer.pid,
                    exit_code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
                    signal: libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)), forced: true,
                });
                return Ok(status);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted { return Err(error); }
        }
    }
}
impl Drop for DirectChild {
    fn drop(&mut self) {
        // This check runs before any cleanup operation. A forked copy cannot
        // kill or reap its sibling. Its OwnedFd fields still close on return.
        if self.reaped || unsafe { libc::getpid() } != self.owner_pid { return; }
        self.channel.shut_down();
        // This owned edge is now shut down. Signal the retained child lifetime,
        // not a PID lookup. No new process settings or subreaper are introduced.
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.peer.fd(), libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0u32); }
        // A kernel-stuck child can delay this wait indefinitely even after KILL.
        // Bounded protocol waits are NOT a wall-time guarantee for kernel reap.
        let _ = self.wait();
    }
}

pub(super) enum Forked {
    Parent(DirectChild),
    Child(ForkOriginV1),
}

pub(super) fn fork_edge(parent: Role, child: Role) -> Result<Forked> {
    if !allowed_edge(parent, child) { return Err(rejected("not a fixed role edge")); }
    require_single_thread()?;
    require_safe_sigchld()?;
    let parent_pid = unsafe { libc::getpid() };
    let uid = unsafe { libc::geteuid() };
    // Opening one's own pidfd has no lookup/reuse race. This is the parent's
    // actual lifetime inherited by its child, not a peer-supplied PID.
    let parent_lifetime = PeerLifetime { pid: parent_pid, uid, pidfd: open_pidfd(parent_pid)?, role: parent };
    let (parent_channel, child_channel) = Channel::pair()?;
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::configure_pair(parent, child, parent_channel.ci_fd())?;
    // SAFETY: reachable only from private main's fixed, single-threaded startup
    // and its equally early H branch, before runtime/GUI/keys. The public
    // entry checks the whole pinned image and exposes no per-role fork API.
    let pid = unsafe { libc::fork() };
    if pid < 0 { return Err(std::io::Error::last_os_error()); }
    if pid == 0 {
        drop(parent_channel);
        return Ok(Forked::Child(ForkOriginV1 { local_role: child, parent: parent_lifetime, channel: child_channel }));
    }
    drop(child_channel);
    drop(parent_lifetime);
    // No auto-reap, signal reaper or other thread exists. Even an exited direct
    // child remains our zombie, so this PID cannot be reassigned before wait.
    let pidfd = match open_pidfd(pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            // Still-unreaped actual fork return PID is safe only on this error
            // path before a pidfd exists. Never used for externally given PIDs.
            unsafe { libc::kill(pid, libc::SIGKILL); }
            loop {
                if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } == pid { break; }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted { break; }
            }
            return Err(error);
        }
    };
    let owned = DirectChild {
        owner_pid: parent_pid, local_role: parent,
        peer: PeerLifetime { pid, uid, pidfd, role: child },
        channel: parent_channel, reaped: false,
    };
    owned.peer.check_alive()?;
    #[cfg(wholepact_bootstrap_ci)]
    crate::ci::birth(child, pid)?;
    Ok(Forked::Parent(owned))
}

fn allowed_edge(parent: Role, child: Role) -> bool {
    (parent == Role::Coordinator && (child == Role::Host || WITNESS_ROLES.contains(&child)))
        || (parent == Role::Host && matches!(child, Role::Signer1 | Role::Signer2))
}

fn open_pidfd(pid: libc::pid_t) -> Result<OwnedFd> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

pub(super) fn require_single_thread() -> Result<()> {
    let own = unsafe { libc::getpid() }.to_string();
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        if entry.file_name() != std::ffi::OsStr::new(&own) {
            return Err(rejected("common-image startup is not single threaded"));
        }
        count += 1;
    }
    if count != 1 { return Err(rejected("single-thread inventory unavailable")); }
    // A runtime check is supplemental, not historical no-injection attestation.
    // The private call graph permits no subsequent thread-capable initializer.
    Ok(())
}

fn require_safe_sigchld() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) } != 0
    { return Err(std::io::Error::last_os_error()); }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0
        || unsafe { libc::sigismember(&mask, libc::SIGCHLD) } != 0
    { return Err(rejected("SIGCHLD disposition could lose owned child")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_is_closed_and_has_thirteen_purpose_named_witnesses() {
        assert_eq!(WITNESS_ROLES.len(), 13);
        for (i, role) in WITNESS_ROLES.iter().enumerate() {
            assert!(!WITNESS_ROLES[..i].contains(role));
            assert!(allowed_edge(Role::Coordinator, *role));
            assert!(!allowed_edge(Role::Host, *role));
        }
        assert!(allowed_edge(Role::Coordinator, Role::Host));
        assert!(!allowed_edge(Role::Coordinator, Role::Signer1));
        assert!(allowed_edge(Role::Host, Role::Signer1));
        assert!(allowed_edge(Role::Host, Role::Signer2));
        assert!(!allowed_edge(Role::Signer1, Role::Signer2));
    }
}
