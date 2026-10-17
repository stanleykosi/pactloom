//! Born-only checked local I/O. Idle polling consumes no bytes; the maintained
//! receiver authenticates every actual chunk. A failed partial frame poisons the
//! stream, so a suffix can never be reinterpreted as an explicit Finish.
use super::{BridgeError, Result};
use crate::native_peer::PeerProcess;
use serde::Serialize;
use std::{
    io::{self, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const REQUEST_FRAME_LIMIT: usize = 128 * 1024;
const RESPONSE_FRAME_LIMIT: usize = 2_100_000;
pub(crate) fn lock_until<'a, T>(
    mutex: &'a std::sync::Mutex<T>,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<std::sync::MutexGuard<'a, T>> {
    loop {
        require_current(deadline, check)?;
        match mutex.try_lock() {
            Ok(guard) => {
                require_current(deadline, check)?;
                return Ok(guard);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(BridgeError::Ipc),
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
            ),
        }
    }
}
pub(crate) fn require_current(deadline: Instant, check: &impl Fn() -> Result<()>) -> Result<()> {
    check()?;
    if Instant::now() >= deadline {
        return Err(BridgeError::Permission);
    }
    Ok(())
}
pub(crate) fn write_checked<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<()> {
    write_capped_checked(stream, value, REQUEST_FRAME_LIMIT, deadline, check)
}
pub(crate) fn write_response_checked<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<()> {
    write_capped_checked(stream, value, RESPONSE_FRAME_LIMIT, deadline, check)
}
pub(crate) fn ensure_response_fits<T: Serialize>(value: &T) -> Result<usize> {
    let mut sink = BoundedFrame {
        bytes: None,
        len: 0,
        limit: RESPONSE_FRAME_LIMIT,
    };
    serde_json::to_writer(&mut sink, value).map_err(|_| BridgeError::Limit)?;
    Ok(sink.len + 1)
}
struct BoundedFrame {
    bytes: Option<Zeroizing<Vec<u8>>>,
    len: usize,
    limit: usize,
}
impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self
            .len
            .checked_add(bytes.len())
            .filter(|n| *n < self.limit)
            .ok_or_else(|| io::Error::other("born frame limit"))?;
        if let Some(buffer) = &mut self.bytes {
            buffer.extend_from_slice(bytes);
        }
        self.len = len;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_capped<T: Serialize>(value: &T, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(limit)
        .map_err(|_| BridgeError::Limit)?;
    let mut sink = BoundedFrame {
        bytes: Some(bytes),
        len: 0,
        limit,
    };
    serde_json::to_writer(&mut sink, value).map_err(|_| BridgeError::Limit)?;
    let mut bytes = sink.bytes.ok_or(BridgeError::Ipc)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn write_capped_checked<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    limit: usize,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<()> {
    require_current(deadline, check)?;
    let bytes = encode_capped(value, limit)?;
    let mut offset = 0;
    while offset < bytes.len() {
        require_current(deadline, check)?;
        stream
            .set_write_timeout(Some(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            ))
            .map_err(|_| BridgeError::Ipc)?;
        require_current(deadline, check)?;
        let result = stream.write(&bytes[offset..]);
        require_current(deadline, check)?;
        match result {
            Ok(0) => return Err(BridgeError::Ipc),
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err(BridgeError::Ipc),
        }
    }
    require_current(deadline, check)
}
pub(crate) fn read_checked(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    read_capped_checked(stream, peer, RESPONSE_FRAME_LIMIT, deadline, check)
}
fn read_capped_checked(
    stream: &UnixStream,
    peer: &PeerProcess,
    limit: usize,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    require_current(deadline, check)?;
    wholepact_signer_origin::framing::read_frame_capped_checked_until(
        stream,
        peer,
        limit,
        deadline,
        || {
            require_current(deadline, check)
                .map_err(|_| wholepact_signer_origin::Error::Authentication)
        },
    )
    .map_err(|_| BridgeError::Ipc)
}
#[derive(Default)]
pub(crate) struct HeldReceiver {
    poisoned: bool,
}
impl HeldReceiver {
    pub(crate) fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub(crate) fn read(
        &mut self,
        stream: &UnixStream,
        peer: &PeerProcess,
        deadline: Instant,
        check: &impl Fn() -> Result<()>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.poisoned {
            return Err(BridgeError::Ipc);
        }
        loop {
            require_current(deadline, check)?;
            peer.check_alive().map_err(|_| BridgeError::Permission)?;
            let mut fd = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = remaining.as_millis().clamp(1, 100) as libc::c_int;
            // SAFETY: one initialized descriptor, live for this bounded call.
            let got = unsafe { libc::poll(&mut fd, 1, timeout) };
            require_current(deadline, check)?;
            if got < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(BridgeError::Ipc);
            }
            if got == 0 {
                continue;
            }
            let frame_deadline = deadline.min(Instant::now() + Duration::from_secs(2));
            let result =
                read_capped_checked(stream, peer, REQUEST_FRAME_LIMIT, frame_deadline, check);
            if result.is_err() {
                self.poisoned = true;
            }
            return result;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn born_current_check_never_waits_unbounded_on_contended_channel() {
        let mutex = std::sync::Mutex::new(());
        let _held = mutex.lock().unwrap();
        let start = Instant::now();
        assert!(lock_until(&mutex, start + Duration::from_millis(20), &|| Ok(())).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn born_full_evidence_frame_preflight_matches_maintained_wire_cap() {
        let larger_than_old_limit = "x".repeat(REQUEST_FRAME_LIMIT + 1);
        assert!(ensure_response_fits(&larger_than_old_limit).unwrap() > REQUEST_FRAME_LIMIT);
        assert!(encode_capped(&larger_than_old_limit, REQUEST_FRAME_LIMIT).is_err());
        let exact = "x".repeat(RESPONSE_FRAME_LIMIT - 3);
        assert_eq!(ensure_response_fits(&exact).unwrap(), RESPONSE_FRAME_LIMIT);
        assert_eq!(
            encode_capped(&exact, RESPONSE_FRAME_LIMIT).unwrap().len(),
            RESPONSE_FRAME_LIMIT
        );
        assert!(ensure_response_fits(&(exact + "x")).is_err());
    }
    #[test]
    fn born_checked_writer_refuses_revocation_before_any_request_byte() {
        use std::{cell::Cell, io::Read};
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let calls = Cell::new(0);
        let check = || {
            calls.set(calls.get() + 1);
            if calls.get() > 1 {
                Err(BridgeError::Permission)
            } else {
                Ok(())
            }
        };
        assert!(
            write_checked(
                &mut writer,
                &serde_json::json!({"operation":"inert-synthetic"}),
                Instant::now() + Duration::from_secs(1),
                &check
            )
            .is_err()
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn born_held_receiver_accepts_delayed_check_and_preserves_partial_frame() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        wholepact_signer_origin::framing::enable_credentials(reader.as_raw_fd()).unwrap();
        let peer = PeerProcess::observe(&reader).unwrap();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2100));
            writer.write_all(b"{\"operation\":").unwrap();
            std::thread::sleep(Duration::from_millis(150));
            writer.write_all(b"\"check_current\"}\n").unwrap();
        });
        let mut receiver = HeldReceiver::default();
        let bytes = receiver
            .read(
                &reader,
                &peer,
                Instant::now() + Duration::from_secs(5),
                &|| Ok(()),
            )
            .unwrap();
        assert_eq!(&**bytes, b"{\"operation\":\"check_current\"}");
        assert!(!receiver.poisoned());
        worker.join().unwrap();
    }
    #[test]
    fn born_failed_partial_frame_cannot_reparse_suffix_as_finish() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        wholepact_signer_origin::framing::enable_credentials(reader.as_raw_fd()).unwrap();
        let peer = PeerProcess::observe(&reader).unwrap();
        writer.write_all(b"partial").unwrap();
        let mut receiver = HeldReceiver::default();
        assert!(
            receiver
                .read(
                    &reader,
                    &peer,
                    Instant::now() + Duration::from_millis(150),
                    &|| Ok(())
                )
                .is_err()
        );
        assert!(receiver.poisoned());
        writer.write_all(b"{\"operation\":\"finish\"}\n").unwrap();
        assert!(
            receiver
                .read(
                    &reader,
                    &peer,
                    Instant::now() + Duration::from_secs(1),
                    &|| Ok(())
                )
                .is_err()
        );
    }
}
