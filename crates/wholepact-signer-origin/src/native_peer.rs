//! Kernel-observed local process identity. This proves a Unix peer/process
//! lifetime, not a publisher, a human, a sandbox, or a remote participant key.
//! Linux SO_PEERPIDFD is required: a caller PID and pidfd_open lookup cannot
//! close the connect/exit/PID-reuse race and are deliberately not a fallback.
#![cfg(target_os = "linux")]
use crate::{Error, Result};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    sync::Arc,
};

#[derive(Clone)]
pub struct PeerProcess(Arc<PeerInner>);
struct PeerInner {
    uid: u32,
    pid: u32,
    lifetime: PeerLifetime,
    instance: String,
}
// The coordinated variant retains the sealed original H proof itself, not an
// imported descriptor or caller-supplied identity. Cloning PeerProcess shares
// this same one-use-received lifetime; it never mints a new role or permission.
enum PeerLifetime {
    DirectPidfd(OwnedFd),
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    OriginalFinancialHost(wholepact_financial_coordinator_origin::OriginalSignerHostPeerV1),
}
impl PeerProcess {
    /// Consume only the genuine SCM_CREDENTIALS-authenticated original H
    /// handshake. This cannot accept an arbitrary PID, FD, DTO or legacy grant.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub fn from_original_financial_host(
        original: wholepact_financial_coordinator_origin::OriginalSignerHostPeerV1,
    ) -> Result<Self> {
        original
            .check_current()
            .map_err(|_| Error::Authentication)?;
        let peer = Self(Arc::new(PeerInner {
            uid: original.uid(),
            pid: original.pid(),
            instance: original.instance().to_owned(),
            lifetime: PeerLifetime::OriginalFinancialHost(original),
        }));
        peer.check_alive()?;
        Ok(peer)
    }

    pub fn observe(stream: &UnixStream) -> Result<Self> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        // SAFETY: the initialized output buffer and its exact length are valid.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0
            || len as usize != std::mem::size_of_val(&cred)
            || cred.pid <= 0
            || cred.uid != unsafe { libc::geteuid() }
        {
            return Err(Error::Authentication);
        }
        let mut fd: libc::c_int = -1;
        len = std::mem::size_of_val(&fd) as libc::socklen_t;
        // Linux UAPI SO_PEERPIDFD. sparc uses a distinct SOL_SOCKET namespace.
        #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
        const SO_PEERPIDFD: libc::c_int = 0x0056;
        #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
        const SO_PEERPIDFD: libc::c_int = 77;
        // SAFETY: the kernel installs an owned descriptor in fd on success.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&mut fd as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 || fd < 0 {
            return Err(Error::PeerLifetimeUnavailable);
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
        if len as usize != std::mem::size_of_val(&fd) {
            return Err(Error::Authentication);
        }
        // Redundant CLOEXEC hardening: never leak this lifetime handle to an app.
        if unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let peer = Self(Arc::new(PeerInner {
            uid: cred.uid,
            pid: cred.pid as u32,
            lifetime: PeerLifetime::DirectPidfd(pidfd),
            instance: hex::encode(crate::random::<32>()?),
        }));
        peer.check_alive()?;
        Ok(peer)
    }
    /// Unlike an arbitrary peer PID, an unreaped direct Child cannot be reused
    /// before the parent waits. Only the pinned launcher supplies this handle.
    pub(crate) fn owned_child(child: &std::process::Child) -> Result<Self> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0u32) };
        if fd < 0 {
            return Err(Error::PeerLifetimeUnavailable);
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        let result = Self(Arc::new(PeerInner {
            uid: unsafe { libc::geteuid() },
            pid: child.id(),
            lifetime: PeerLifetime::DirectPidfd(pidfd),
            instance: hex::encode(crate::random::<32>()?),
        }));
        result.check_alive()?;
        Ok(result)
    }
    pub fn uid(&self) -> u32 {
        self.0.uid
    }
    pub fn pid(&self) -> u32 {
        self.0.pid
    }
    pub fn instance(&self) -> &str {
        &self.0.instance
    }
    pub fn check_alive(&self) -> Result<()> {
        let pidfd = match &self.0.lifetime {
            PeerLifetime::DirectPidfd(pidfd) => pidfd,
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            PeerLifetime::OriginalFinancialHost(original) => {
                return original.check_current().map_err(|_| Error::Authentication);
            }
        };
        let mut poll = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd; zero timeout never blocks UI/authorization.
        let rc = unsafe { libc::poll(&mut poll, 1, 0) };
        if rc != 0 || poll.revents != 0 {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub fn same_live_process(&self, other: &Self) -> Result<()> {
        self.check_alive()?;
        other.check_alive()?;
        if self.uid() != other.uid() || self.pid() != other.pid() {
            return Err(Error::Authentication);
        }
        // A PID cannot be reassigned while the original pidfd is live. The
        // second handle came from the new connection, not a supplied PID.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn retained_peer_stays_send_sync_without_minting_original_host() {
        fn require<T: Send + Sync>() {}
        require::<super::PeerProcess>();
    }

    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    #[test]
    #[ignore = "subprocess helper for explicit local kernel qualification"]
    fn kernel_peer_child_helper() {
        let path = std::env::var("WHOLEPACT_SYNTHETIC_PEER_SOCKET")
            .expect("only invoked by synthetic parent test");
        let mut socket = UnixStream::connect(path).unwrap();
        if std::env::var_os("WHOLEPACT_SYNTHETIC_INHERITED_SENDER").is_some() {
            let fd = socket.as_raw_fd();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--ignored",
                    "--exact",
                    "native_peer::tests::inherited_stream_sender_helper",
                ])
                .stdout(std::process::Stdio::null());
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            assert!(command.spawn().unwrap().wait().unwrap().success());
        } else {
            socket.write_all(b"ready").unwrap();
        }
        let mut done = [0];
        socket.read_exact(&mut done).unwrap();
    }
    #[test]
    #[ignore = "explicit actual-process qualification requires AF_UNIX and Linux SO_PEERPIDFD"]
    fn actual_child_peer_lifetime_revokes_when_process_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "native_peer::tests::kernel_peer_child_helper",
            ])
            .env("WHOLEPACT_SYNTHETIC_PEER_SOCKET", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let peer = PeerProcess::observe(&stream).unwrap();
        assert_eq!(peer.pid(), child.id());
        let mut ready = [0; 5];
        stream.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready");
        peer.check_alive().unwrap();
        stream.write_all(b"q").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(peer.check_alive().is_err());
    }
    #[test]
    #[ignore = "subprocess helper for explicit inherited-descriptor qualification"]
    fn inherited_stream_sender_helper() {
        // Test executable only. This fd cannot create native authority or grants.
        assert!(std::env::var_os("WHOLEPACT_SYNTHETIC_INHERITED_SENDER").is_some());
        let mut stream = unsafe { UnixStream::from_raw_fd(3) };
        stream.write_all(b"{}\n").unwrap();
    }
    #[test]
    #[ignore = "explicit actual-process qualification requires AF_UNIX and Linux SO_PEERPIDFD"]
    fn inherited_connection_cannot_impersonate_original_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic-inherited.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        crate::framing::enable_credentials(listener.as_raw_fd()).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "native_peer::tests::kernel_peer_child_helper",
            ])
            .env("WHOLEPACT_SYNTHETIC_PEER_SOCKET", &path)
            .env(
                "WHOLEPACT_SYNTHETIC_INHERITED_SENDER",
                "fixed-synthetic-test",
            )
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let peer = PeerProcess::observe(&stream).unwrap();
        assert_eq!(peer.pid(), child.id());
        assert!(matches!(
            crate::framing::read_frame(&stream, &peer),
            Err(Error::Authentication)
        ));
        // Original peer is still alive: rejection is sender credentials, not exit.
        peer.check_alive().unwrap();
        stream.write_all(b"q").unwrap();
        assert!(child.wait().unwrap().success());
    }
}
