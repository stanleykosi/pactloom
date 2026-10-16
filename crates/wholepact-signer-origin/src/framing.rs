//! Exact extracted Linux authenticated frame receiver. Each recvmsg chunk must
//! carry the same kernel sender identity; inherited descriptors cannot substitute
//! another process. No serialized credential is trusted.
use crate::{Error, Result, native_peer::PeerProcess};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_FRAME: usize = 2_100_000;
pub fn enable_credentials(fd: std::os::fd::RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: exact initialized integer input and valid socket descriptor.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } != 0
    {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
pub fn read_frame(stream: &UnixStream, peer: &PeerProcess) -> Result<Zeroizing<Vec<u8>>> {
    read_frame_with_deadline(stream, peer, Duration::from_secs(2))
}
pub fn read_frame_with_deadline(
    stream: &UnixStream,
    peer: &PeerProcess,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    if timeout > Duration::from_secs(120) {
        return Err(Error::InvalidData);
    }
    let deadline = Instant::now() + timeout;
    read_frame_inner(stream, peer, deadline, None, None)
}

/// Dedicated bounded-transfer receiver. The cap counts the newline delimiter,
/// not just the returned JSON bytes. This does not widen the generic receiver or
/// change its timeout semantics. Every recvmsg retains the exact same kernel
/// credential validation and passed-descriptor rejection below.
///
/// A caller supplies one original absolute deadline for every protocol turn.
/// This boundary refuses a completed frame if the deadline expired during the
/// final receive or validation. Synchronous work is not preemptible.
pub fn read_frame_capped_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>> {
    if max_wire_bytes == 0 || max_wire_bytes > MAX_FRAME {
        return Err(Error::Limit);
    }
    let remaining = remaining_at(deadline, Instant::now())?;
    if remaining > Duration::from_secs(120) {
        return Err(Error::InvalidData);
    }
    read_frame_inner(stream, peer, deadline, Some(max_wire_bytes), None)
}

/// Bounded cancellation-aware owner read. Idle slices preserve the same partial
/// frame and original absolute deadline; the callback grants no authority.
pub fn read_frame_capped_checked_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    deadline: Instant,
    mut check_current: impl FnMut() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    if max_wire_bytes == 0 || max_wire_bytes > MAX_FRAME {
        return Err(Error::Limit);
    }
    if remaining_at(deadline, Instant::now())? > Duration::from_secs(120) {
        return Err(Error::InvalidData);
    }
    check_current()?;
    read_frame_inner(
        stream,
        peer,
        deadline,
        Some(max_wire_bytes),
        Some(&mut check_current),
    )
}

fn remaining_at(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::Authentication)
}

/// Synthetic byte-only seam used by the actual capped recvmsg path. No allocation
/// is requested until the cumulative wire length and delimiter are valid. Exact
/// reserve avoids Vec's geometric growth beyond the bounded frame capacity.
fn append_capped_chunk(
    frame: &mut Zeroizing<Vec<u8>>,
    chunk: &[u8],
    max_wire_bytes: usize,
) -> Result<bool> {
    let wire_len = frame.len().checked_add(chunk.len()).ok_or(Error::Limit)?;
    if chunk.is_empty() || wire_len > max_wire_bytes {
        return Err(Error::Limit);
    }
    let (body, complete) = match chunk.iter().position(|byte| *byte == b'\n') {
        Some(end) if end.checked_add(1) == Some(chunk.len()) => (&chunk[..end], true),
        Some(_) => return Err(Error::InvalidData),
        None if wire_len == max_wire_bytes => return Err(Error::Limit),
        None => (chunk, false),
    };
    frame
        .try_reserve_exact(body.len())
        .map_err(|_| Error::Limit)?;
    frame.extend_from_slice(body);
    Ok(complete)
}

fn read_frame_inner(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    max_wire_bytes: Option<usize>,
    mut check_current: Option<&mut dyn FnMut() -> Result<()>>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut frame = Zeroizing::new(Vec::new());
    if let Some(limit) = max_wire_bytes {
        // One bounded fallible allocation. No accumulating frame reallocation
        // leaves earlier private bytes behind, and the delimiter is not stored.
        frame
            .try_reserve_exact(limit - 1)
            .map_err(|_| Error::Limit)?;
    }
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let remaining = if max_wire_bytes.is_some() {
            remaining_at(deadline, Instant::now())?
        } else {
            // Preserve the existing generic receiver's zero-duration/error
            // behavior; only the dedicated entry point adds strict expiry.
            deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Authentication)?
        };
        if let Some(check) = check_current.as_mut() {
            check()?;
        }
        let timeout = if check_current.is_some() {
            remaining.min(Duration::from_millis(100))
        } else {
            remaining
        };
        stream.set_read_timeout(Some(timeout))?;
        // Aligned ancillary storage for the mandatory kernel sender credentials.
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: chunk.as_mut_ptr().cast(),
            iov_len: chunk.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: buffers remain live, disjoint and correctly sized for recvmsg.
        let got = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if check_current.is_some()
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                )
            {
                continue;
            }
            return Err(Error::Io(error));
        }
        let n = got as usize;
        let mut authenticated = false;
        let mut credential_count = 0usize;
        let mut unexpected = false;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&msg);
            while !header.is_null() {
                let h = &*header;
                if h.cmsg_level == libc::SOL_SOCKET
                    && h.cmsg_type == libc::SCM_CREDENTIALS
                    && h.cmsg_len
                        == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as _) as usize
                {
                    let cred =
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>());
                    credential_count += 1;
                    authenticated = credential_count == 1
                        && cred.pid > 0
                        && cred.pid as u32 == peer.pid()
                        && cred.uid == peer.uid();
                } else {
                    unexpected = true;
                    // Reject all passed descriptors and close anything the kernel
                    // delivered, including truncated SCM_RIGHTS messages.
                    if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                        let bytes = h.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                        for i in 0..bytes / std::mem::size_of::<libc::c_int>() {
                            libc::close(std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<libc::c_int>().add(i),
                            ));
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&msg, header);
            }
        }
        if n == 0
            || (max_wire_bytes.is_none() && frame.len().saturating_add(n) > MAX_FRAME)
            || credential_count != 1
            || !authenticated
            || unexpected
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(Error::Authentication);
        }
        if max_wire_bytes.is_some() {
            // Ancillary descriptors were already closed on rejection paths.
            // Even the final successful receive cannot outlive this deadline.
            remaining_at(deadline, Instant::now())?;
        }
        peer.check_alive()?;
        if let Some(check) = check_current.as_mut() {
            check()?;
        }
        if let Some(limit) = max_wire_bytes {
            let complete = append_capped_chunk(&mut frame, &chunk[..n], limit)?;
            remaining_at(deadline, Instant::now())?;
            if complete {
                return Ok(frame);
            }
            continue;
        }
        if let Some(end) = chunk[..n].iter().position(|b| *b == b'\n') {
            if end + 1 != n {
                return Err(Error::InvalidData);
            }
            frame.extend_from_slice(&chunk[..end]);
            return Ok(frame);
        }
        frame.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;

    #[test]
    fn bounded_accumulation_counts_delimiter_and_rejects_before_growth() {
        let mut frame = Zeroizing::new(Vec::new());
        assert!(!append_capped_chunk(&mut frame, b"abc", 5).unwrap());
        let before = frame.capacity();
        assert!(matches!(
            append_capped_chunk(&mut frame, b"de\n", 5),
            Err(Error::Limit)
        ));
        assert_eq!(&**frame, b"abc");
        assert_eq!(frame.capacity(), before);
        assert!(append_capped_chunk(&mut frame, b"d\n", 5).unwrap());
        assert_eq!(&**frame, b"abcd");
    }

    #[test]
    fn bounded_accumulation_requires_room_for_newline_and_rejects_coalescing() {
        for bytes in [b"abcde".as_slice(), b"a\nb".as_slice(), b"a\n\n".as_slice()] {
            let mut frame = Zeroizing::new(Vec::new());
            assert!(append_capped_chunk(&mut frame, bytes, 5).is_err());
            assert!(frame.is_empty());
            assert_eq!(frame.capacity(), 0);
        }
        let mut frame = Zeroizing::new(Vec::new());
        assert!(append_capped_chunk(&mut frame, b"\n", 1).unwrap());
        assert!(frame.is_empty());
    }

    #[test]
    fn bounded_accumulation_refuses_empty_chunk() {
        let mut frame = Zeroizing::new(Vec::new());
        assert!(append_capped_chunk(&mut frame, b"", 5).is_err());
        assert_eq!(frame.capacity(), 0);
    }

    #[test]
    fn absolute_deadline_refuses_equality_and_later_completion() {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(30);
        assert_eq!(
            remaining_at(deadline, started).unwrap(),
            Duration::from_secs(30)
        );
        assert!(remaining_at(deadline, deadline).is_err());
        assert!(remaining_at(deadline, deadline + Duration::from_nanos(1)).is_err());
    }
}
