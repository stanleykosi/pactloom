//! Pinned direct-child launch for the installed Linux signer profile. The opened
//! executable is verified by the fixed installed-provider loader before entry.
//! The unreaped direct child prevents PID reuse while its pidfd is acquired.
//! The inherited socket only reports a request endpoint after native unlock;
//! neither argv nor this channel can unlock, approve, or provision an account.
#![cfg(target_os = "linux")]
use crate::{Error, Result, native_peer::PeerProcess};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

#[cfg(feature = "native-ui")]
use std::{io::Write, sync::Arc};

pub(crate) struct LaunchedSigner {
    child: Option<Child>,
    peer: PeerProcess,
    channel: Mutex<UnixStream>,
}
impl LaunchedSigner {
    pub(crate) fn spawn(image: File) -> Result<Self> {
        let (parent, child_channel) = UnixStream::pair()?;
        crate::framing::enable_credentials(parent.as_raw_fd())?;
        // Reserve a high descriptor so the private child channel at fd 3 cannot
        // overwrite the exact executable selected by the installed trust root.
        let fd = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if fd < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let exact_image = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut command = Command::new(format!("/proc/self/fd/{}", exact_image.as_raw_fd()));
        command
            .arg("--private-parent-channel")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Carry only the trusted desktop's display coordinates, never injection,
        // dynamic linker, inspection, arbitrary config, secrets or app arguments.
        for key in ["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let channel_fd = child_channel.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(channel_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        let peer = match PeerProcess::owned_child(&child) {
            Ok(peer) => peer,
            Err(error) => {
                reap_child(child);
                return Err(error);
            }
        };
        drop(child_channel);
        drop(exact_image);
        Ok(Self {
            child: Some(child),
            peer,
            channel: Mutex::new(parent),
        })
    }
    pub(crate) fn verify_server(&self, stream: &UnixStream) -> Result<PeerProcess> {
        let observed = PeerProcess::observe(stream)?;
        self.peer.same_live_process(&observed)?;
        Ok(observed)
    }
    pub(crate) fn wait_endpoint(&self, timeout: Duration) -> Result<PathBuf> {
        let channel = self.channel.lock().map_err(|_| Error::Locked)?;
        let frame = crate::framing::read_frame_with_deadline(&channel, &self.peer, timeout)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Endpoint {
            schema_version: u32,
            request_endpoint: String,
        }
        let message: Endpoint = serde_json::from_slice(&frame).map_err(|_| Error::InvalidData)?;
        if message.schema_version != 1
            || message.request_endpoint.len() > 4096
            || !Path::new(&message.request_endpoint).is_absolute()
        {
            return Err(Error::InvalidData);
        }
        self.peer.check_alive()?;
        Ok(message.request_endpoint.into())
    }
}
impl Drop for LaunchedSigner {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            reap_child(child);
        }
    }
}
fn reap_child(mut child: Child) {
    // Do not terminate a user-owned signer window when its requesting
    // application drops this handle. Reap an exited child immediately;
    // otherwise a wait-only thread owns the child until it exits. No PID
    // lookup or new authority is created by this cleanup.
    match child.try_wait() {
        Ok(Some(_)) => {}
        _ => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

/// Request endpoint reporting channel, never authorization input.
#[cfg(feature = "native-ui")]
#[derive(Clone)]
pub struct ParentChannel {
    stream: Arc<Mutex<UnixStream>>,
    peer: PeerProcess,
}
#[cfg(feature = "native-ui")]
impl ParentChannel {
    #[cfg(feature = "native-ui")]
    pub fn take_inherited() -> Result<Self> {
        // Only the explicit launcher mode consumes fd 3. A caller can supply it,
        // but doing so confers no authority: it receives public endpoint data.
        let mut kind: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&kind) as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if ok != 0 || kind != libc::SOCK_STREAM || len as usize != std::mem::size_of_val(&kind) {
            return Err(Error::InvalidData);
        }
        let mut domain: libc::c_int = 0;
        len = std::mem::size_of_val(&domain) as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if ok != 0 || domain != libc::AF_UNIX || len as usize != std::mem::size_of_val(&domain) {
            return Err(Error::InvalidData);
        }
        let stream = unsafe { UnixStream::from_raw_fd(3) };
        // The inherited report channel is local and belongs to a currently live
        // same-UID creator. It still conveys no account or approval authority.
        let peer = PeerProcess::observe(&stream)?;
        if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            peer,
        })
    }
    /// Nonblocking liveness only. This inherited channel carries no approval
    /// input; an inbound byte, peer exit, hangup or error cancels pending birth.
    #[cfg(feature = "authority-signing")]
    pub fn check_connected(&self) -> Result<()> {
        self.peer.check_alive()?;
        let stream = self.stream.try_lock().map_err(|_| Error::Locked)?;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        };
        // SAFETY: one valid descriptor is borrowed for a nonblocking poll.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        require_quiet_report_channel(descriptor.revents)?;
        self.peer.check_alive()
    }
    #[cfg(feature = "native-ui")]
    pub fn publish_endpoint(&self, endpoint: &Path) -> Result<()> {
        self.peer.check_alive()?;
        let path = endpoint.to_str().ok_or(Error::InvalidData)?;
        let bytes =
            serde_json::to_vec(&serde_json::json!({"schema_version":1,"request_endpoint":path}))
                .map_err(|_| Error::InvalidData)?;
        let mut stream = self.stream.lock().map_err(|_| Error::Locked)?;
        stream.write_all(&bytes)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        Ok(())
    }
}

#[cfg(all(feature = "native-ui", feature = "authority-signing"))]
fn require_quiet_report_channel(events: libc::c_short) -> Result<()> {
    if events != 0 {
        return Err(Error::Locked);
    }
    Ok(())
}

#[cfg(all(test, feature = "native-ui", feature = "authority-signing"))]
mod pending_birth_channel_tests {
    use super::*;
    #[test]
    fn report_channel_event_predicate_rejects_data_hangup_and_errors() {
        // Plain event-bit predicate only; no socket, pidfd or native fixture.
        assert!(require_quiet_report_channel(0).is_ok());
        for events in [
            libc::POLLIN,
            libc::POLLRDHUP,
            libc::POLLHUP,
            libc::POLLERR,
            libc::POLLNVAL,
            libc::POLLIN | libc::POLLRDHUP,
            0x4000,
        ] {
            assert!(matches!(
                require_quiet_report_channel(events),
                Err(Error::Locked)
            ));
        }
    }
}
