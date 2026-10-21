//! Private fixed-size bootstrap packets, not financial or general RPC. The
//! inherited pair's SO_PEERPIDFD names its creator, so it is NOT used here.
//! Authentication combines actual retained fork lifetimes with per-packet
//! kernel SCM_CREDENTIALS. No caller can import a channel as a fork origin.
use crate::{process::{PeerLifetime, Role}, rejected, Result};
use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd}, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Message { Prepared = 1, Release, Released, Stop, Stopped, Exit }
const PACKET_BYTES: usize = 8;

pub(super) struct Channel(OwnedFd);
impl Channel {
    pub(super) fn pair() -> Result<(Self, Self)> {
        let mut pair = [-1; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0, pair.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let a = Self(unsafe { OwnedFd::from_raw_fd(pair[0]) });
        let b = Self(unsafe { OwnedFd::from_raw_fd(pair[1]) });
        for fd in [&a.0, &b.0] {
            let enabled: libc::c_int = 1;
            if unsafe { libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PASSCRED, (&enabled as *const libc::c_int).cast(), std::mem::size_of_val(&enabled) as libc::socklen_t) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok((a, b))
    }
    pub(super) fn send(&self, message: Message, local_role: Role, peer: &PeerLifetime, deadline: Instant) -> Result<()> {
        self.wait_ready(libc::POLLOUT, peer, deadline)?;
        let bytes = packet(message, local_role);
        let written = unsafe { libc::send(self.0.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if written != bytes.len() as isize { return Err(rejected("bootstrap packet send failed")); }
        require_time(deadline)?;
        // Exit is the sole terminal instruction. Its recipient may immediately
        // exit; we subsequently wait/reap that exact child rather than reject a
        // successful terminal send merely because exit raced this check.
        if message != Message::Exit { peer.check_alive()?; }
        Ok(())
    }
    pub(super) fn receive(&self, expected: Message, peer: &PeerLifetime, deadline: Instant) -> Result<()> {
        self.wait_ready(libc::POLLIN, peer, deadline)?;
        let mut bytes = [0u8; PACKET_BYTES];
        let mut iov = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
        // usize alignment is sufficient for cmsghdr on supported Linux targets.
        let mut control = [0usize; 64];
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = std::mem::size_of_val(&control);
        let read = unsafe { libc::recvmsg(self.0.as_raw_fd(), &mut header, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
        if read < 0 { return Err(std::io::Error::last_os_error()); }
        // Always inspect and close received rights, even if flags/length/payload
        // will fail. Rights cannot leak on the rejection path.
        let credentials = inspect_ancillary(&header, &control)?;
        if read != PACKET_BYTES as isize || header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || bytes != packet(expected, peer.role())
        { return Err(rejected("invalid bootstrap packet")); }
        let credentials = credentials.ok_or_else(|| rejected("missing bootstrap sender credentials"))?;
        if credentials.pid != peer.pid() || credentials.uid != peer.uid() {
            return Err(rejected("bootstrap sender is not original fork peer"));
        }
        require_time(deadline)?;
        peer.check_alive()
    }
    pub(super) fn shut_down(&self) {
        // Restriction only; caller owns this original edge. No copied sibling
        // handle may call this during branch pruning.
        unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_RDWR); }
    }
    fn wait_ready(&self, events: libc::c_short, peer: &PeerLifetime, deadline: Instant) -> Result<()> {
        loop {
            peer.check_alive()?;
            require_time(deadline)?;
            let millis = deadline.saturating_duration_since(Instant::now()).as_millis().clamp(1, 100) as libc::c_int;
            let mut polls = [
                libc::pollfd { fd: self.0.as_raw_fd(), events, revents: 0 },
                libc::pollfd { fd: peer.fd(), events: libc::POLLIN, revents: 0 },
            ];
            let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, millis) };
            if rc < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted { continue; }
                return Err(error);
            }
            require_time(deadline)?;
            if polls[1].revents != 0 || polls[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(rejected("original bootstrap channel lost"));
            }
            if polls[0].revents & events != 0 { return peer.check_alive(); }
        }
    }
}

fn packet(message: Message, role: Role) -> [u8; PACKET_BYTES] {
    [b'W', b'P', b'F', b'C', 1, message as u8, role as u8, 0]
}

fn inspect_ancillary(header: &libc::msghdr, control: &[usize; 64]) -> Result<Option<libc::ucred>> {
    let start = control.as_ptr() as usize;
    let end = start.checked_add(header.msg_controllen).ok_or_else(|| rejected("ancillary overflow"))?;
    if header.msg_controllen > std::mem::size_of_val(control) { return Err(rejected("ancillary bounds")); }
    let mut credentials = None;
    let mut rejected_control = false;
    let mut current = unsafe { libc::CMSG_FIRSTHDR(header) };
    while !current.is_null() {
        let address = current as usize;
        if address < start || address.checked_add(std::mem::size_of::<libc::cmsghdr>()).is_none_or(|v| v > end) {
            return Err(rejected("ancillary header bounds"));
        }
        let cmsg = unsafe { &*current };
        let min = unsafe { libc::CMSG_LEN(0) } as usize;
        if cmsg.cmsg_len < min || address.checked_add(cmsg.cmsg_len).is_none_or(|v| v > end) {
            return Err(rejected("ancillary payload bounds"));
        }
        let data = unsafe { libc::CMSG_DATA(current) };
        let data_len = cmsg.cmsg_len - min;
        if cmsg.cmsg_level == libc::SOL_SOCKET && cmsg.cmsg_type == libc::SCM_RIGHTS {
            // Kernel-delivered complete descriptors only; close every one before
            // rejecting. Linux closes excess undelivered rights on MSG_CTRUNC.
            for index in 0..data_len / std::mem::size_of::<libc::c_int>() {
                let fd = unsafe { std::ptr::read_unaligned(data.add(index * std::mem::size_of::<libc::c_int>()).cast::<libc::c_int>()) };
                if fd >= 0 { unsafe { libc::close(fd); } }
            }
            rejected_control = true;
        } else if cmsg.cmsg_level == libc::SOL_SOCKET && cmsg.cmsg_type == libc::SCM_CREDENTIALS
            && data_len == std::mem::size_of::<libc::ucred>() && credentials.is_none()
        {
            credentials = Some(unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) });
        } else {
            rejected_control = true;
        }
        current = unsafe { libc::CMSG_NXTHDR(header, current) };
    }
    if rejected_control { return Err(rejected("unexpected or duplicate bootstrap ancillary data")); }
    Ok(credentials)
}

pub(super) fn require_time(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline { return Err(rejected("original bootstrap deadline expired")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_packets_separate_role_and_transition_without_payload() {
        assert_eq!(packet(Message::Prepared, Role::Host).len(), 8);
        assert_ne!(packet(Message::Prepared, Role::Host), packet(Message::Released, Role::Host));
        assert_ne!(packet(Message::Prepared, Role::Signer1), packet(Message::Prepared, Role::Signer2));
    }
}
