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

/// Closed observations only: no peer identifiers, paths, payload or authority.
/// These supplement, never change, the existing fail-closed Error result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameReadCause {
    Unclassified,
    Deadline,
    Eof,
    CredentialsMissing,
    CredentialsMismatch,
    AncillaryRejected,
    Truncated,
    PeerNotLive,
    CurrentCheck,
    Io,
    FrameLimit,
    InvalidFrame,
    InvalidBudget,
}
#[derive(Debug)]
pub struct ObservedFrameError {
    pub cause: FrameReadCause,
    pub error: Error,
}
fn observe<T>(
    result: Result<T>,
    cause: FrameReadCause,
    observed: &mut FrameReadCause,
) -> Result<T> {
    result.map_err(|error| {
        *observed = cause;
        error
    })
}

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
    check_current: impl FnMut() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    read_frame_capped_checked_observed_until(stream, peer, max_wire_bytes, deadline, check_current)
        .map_err(|observed| observed.error)
}

/// Wait only for inert setup metadata, without consuming any socket bytes.
/// Once readable, perform exactly one unchanged authenticated action-budget
/// frame read. A failed or partial transfer is never retried or renewed here.
pub fn read_setup_frame_capped_checked_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    setup_deadline: Instant,
    check_current: impl FnMut() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    read_setup_frame_capped_checked_observed_until(
        stream,
        peer,
        max_wire_bytes,
        setup_deadline,
        check_current,
    )
    .map_err(|failure| failure.error)
}

/// Same setup/transfer kernel, with a finite failure cause and unchanged error.
pub fn read_setup_frame_capped_checked_observed_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    setup_deadline: Instant,
    check_current: impl FnMut() -> Result<()>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ObservedFrameError> {
    read_setup_frame_capped_observed_kernel(
        stream, peer, max_wire_bytes, setup_deadline, check_current, None,
    )
}

/// The maintained setup/read kernel with an additional denial-only check after
/// receive setup and immediately before each recvmsg. The same check is moved
/// into the transfer, without renewing the original setup/transfer ceiling.
/// It supplies no peer, read permission, positive receipt or retry authority.
pub fn read_setup_frame_capped_restricted_observed_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    setup_deadline: Instant,
    check_current: impl FnMut() -> Result<()>,
    mut final_restriction: impl FnMut() -> Result<()>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ObservedFrameError> {
    read_setup_frame_capped_observed_kernel(
        stream, peer, max_wire_bytes, setup_deadline, check_current,
        Some(&mut final_restriction),
    )
}

fn read_setup_frame_capped_observed_kernel(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    setup_deadline: Instant,
    mut check_current: impl FnMut() -> Result<()>,
    final_restriction: Option<&mut dyn FnMut() -> Result<()>>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ObservedFrameError> {
    let mut cause = FrameReadCause::Unclassified;
    let result = (|| {
        if max_wire_bytes == 0 || max_wire_bytes > MAX_FRAME {
            cause = FrameReadCause::FrameLimit;
            return Err(Error::Limit);
        }
        if observe(
            remaining_at(setup_deadline, Instant::now()),
            FrameReadCause::Deadline,
            &mut cause,
        )? > Duration::from_secs(900)
        {
            cause = FrameReadCause::InvalidBudget;
            return Err(Error::InvalidData);
        }
        loop {
            observe(check_current(), FrameReadCause::CurrentCheck, &mut cause)?;
            observe(peer.check_alive(), FrameReadCause::PeerNotLive, &mut cause)?;
            let remaining = observe(
                remaining_at(setup_deadline, Instant::now()),
                FrameReadCause::Deadline,
                &mut cause,
            )?;
            let wait_ms = remaining.as_millis().clamp(1, 100) as libc::c_int;
            let mut descriptor = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized pollfd borrowed only for this bounded call.
            let ready = unsafe { libc::poll(&mut descriptor, 1, wait_ms) };
            let poll_error = (ready < 0).then(std::io::Error::last_os_error);
            observe(check_current(), FrameReadCause::CurrentCheck, &mut cause)?;
            observe(peer.check_alive(), FrameReadCause::PeerNotLive, &mut cause)?;
            observe(
                remaining_at(setup_deadline, Instant::now()),
                FrameReadCause::Deadline,
                &mut cause,
            )?;
            if let Some(error) = poll_error {
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                cause = FrameReadCause::Io;
                return Err(Error::Io(error));
            }
            if ready == 0 {
                continue;
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
                cause = if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    FrameReadCause::Io
                } else {
                    FrameReadCause::Eof
                };
                return Err(Error::Authentication);
            }
            if descriptor.revents & libc::POLLIN != 0 {
                let transfer_deadline = observe(
                    setup_transfer_deadline(setup_deadline, Instant::now()),
                    FrameReadCause::Deadline,
                    &mut cause,
                )?;
                return read_frame_capped_observed_kernel(
                    stream,
                    peer,
                    max_wire_bytes,
                    transfer_deadline,
                    check_current,
                    final_restriction,
                )
                .map_err(|failure| {
                    cause = failure.cause;
                    failure.error
                });
            }
            cause = FrameReadCause::InvalidFrame;
            return Err(Error::Authentication);
        }
    })();
    result.map_err(|error| ObservedFrameError { cause, error })
}
fn setup_transfer_deadline(setup_deadline: Instant, now: Instant) -> Result<Instant> {
    remaining_at(setup_deadline, now)?;
    Ok(setup_deadline.min(now + Duration::from_secs(120)))
}

/// Same production receive kernel and checks as the legacy entry point. The
/// extra result is a closed cause classification, never an authentication grant.
pub fn read_frame_capped_checked_observed_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    deadline: Instant,
    check_current: impl FnMut() -> Result<()>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ObservedFrameError> {
    read_frame_capped_observed_kernel(
        stream, peer, max_wire_bytes, deadline, check_current, None,
    )
}

/// The exact authenticated frame parser with an additional denial-only final
/// attempt check. After all timeout/ancillary setup, the original deadline is
/// rechecked and this restriction is sampled immediately before each recvmsg.
/// A later denial does not erase bytes consumed by an earlier admitted attempt.
pub fn read_frame_capped_restricted_observed_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    deadline: Instant,
    check_current: impl FnMut() -> Result<()>,
    mut final_restriction: impl FnMut() -> Result<()>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ObservedFrameError> {
    read_frame_capped_observed_kernel(
        stream, peer, max_wire_bytes, deadline, check_current,
        Some(&mut final_restriction),
    )
}

fn read_frame_capped_observed_kernel(
    stream: &UnixStream,
    peer: &PeerProcess,
    max_wire_bytes: usize,
    deadline: Instant,
    mut check_current: impl FnMut() -> Result<()>,
    final_restriction: Option<&mut dyn FnMut() -> Result<()>>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ObservedFrameError> {
    let mut cause = FrameReadCause::Unclassified;
    let result = (|| {
        if max_wire_bytes == 0 || max_wire_bytes > MAX_FRAME {
            cause = FrameReadCause::FrameLimit;
            return Err(Error::Limit);
        }
        if observe(
            remaining_at(deadline, Instant::now()),
            FrameReadCause::Deadline,
            &mut cause,
        )? > Duration::from_secs(120)
        {
            cause = FrameReadCause::InvalidBudget;
            return Err(Error::InvalidData);
        }
        observe(check_current(), FrameReadCause::CurrentCheck, &mut cause)?;
        read_frame_inner_observed(
            stream,
            peer,
            deadline,
            Some(max_wire_bytes),
            Some(&mut check_current),
            final_restriction,
            &mut cause,
        )
    })();
    result.map_err(|error| ObservedFrameError { cause, error })
}

// None is deliberately inert: legacy callers keep their exact original check
// and error sequence. This is an admitted-attempt ordering, not atomic syscall
// cancellation; the callback must be zero-wait and must not re-enter source/DB.
fn admit_restricted_receive(
    deadline: Instant,
    restriction: &mut Option<&mut dyn FnMut() -> Result<()>>,
    observed: &mut FrameReadCause,
) -> Result<()> {
    if let Some(check) = restriction.as_mut() {
        observe(
            remaining_at(deadline, Instant::now()),
            FrameReadCause::Deadline,
            observed,
        )?;
        observe(check(), FrameReadCause::CurrentCheck, observed)?;
    }
    Ok(())
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
    check_current: Option<&mut dyn FnMut() -> Result<()>>,
) -> Result<Zeroizing<Vec<u8>>> {
    read_frame_inner_observed(
        stream,
        peer,
        deadline,
        max_wire_bytes,
        check_current,
        None,
        &mut FrameReadCause::Unclassified,
    )
}
fn read_frame_inner_observed(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    max_wire_bytes: Option<usize>,
    mut check_current: Option<&mut dyn FnMut() -> Result<()>>,
    mut final_restriction: Option<&mut dyn FnMut() -> Result<()>>,
    observed: &mut FrameReadCause,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut frame = Zeroizing::new(Vec::new());
    if let Some(limit) = max_wire_bytes {
        // One bounded fallible allocation. No accumulating frame reallocation
        // leaves earlier private bytes behind, and the delimiter is not stored.
        frame.try_reserve_exact(limit - 1).map_err(|_| {
            *observed = FrameReadCause::FrameLimit;
            Error::Limit
        })?;
    }
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let remaining = if max_wire_bytes.is_some() {
            observe(
                remaining_at(deadline, Instant::now()),
                FrameReadCause::Deadline,
                observed,
            )?
        } else {
            // Preserve the existing generic receiver's zero-duration/error
            // behavior; only the dedicated entry point adds strict expiry.
            deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    *observed = FrameReadCause::Deadline;
                    Error::Authentication
                })?
        };
        if let Some(check) = check_current.as_mut() {
            observe(check(), FrameReadCause::CurrentCheck, observed)?;
        }
        let timeout = if check_current.is_some() {
            remaining.min(Duration::from_millis(100))
        } else {
            remaining
        };
        observe(
            stream.set_read_timeout(Some(timeout)).map_err(Error::Io),
            FrameReadCause::Io,
            observed,
        )?;
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
        admit_restricted_receive(deadline, &mut final_restriction, observed)?;
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
            *observed = FrameReadCause::Io;
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
            // Report the first concrete condition in this one receive, not a
            // causal order between independent endpoints.
            *observed = if n == 0 {
                FrameReadCause::Eof
            } else if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                FrameReadCause::Truncated
            } else if unexpected {
                FrameReadCause::AncillaryRejected
            } else if credential_count == 0 {
                FrameReadCause::CredentialsMissing
            } else if credential_count != 1 || !authenticated {
                FrameReadCause::CredentialsMismatch
            } else {
                FrameReadCause::FrameLimit
            };
            return Err(Error::Authentication);
        }
        if max_wire_bytes.is_some() {
            // Ancillary descriptors were already closed on rejection paths.
            // Even the final successful receive cannot outlive this deadline.
            observe(
                remaining_at(deadline, Instant::now()),
                FrameReadCause::Deadline,
                observed,
            )?;
        }
        observe(peer.check_alive(), FrameReadCause::PeerNotLive, observed)?;
        if let Some(check) = check_current.as_mut() {
            observe(check(), FrameReadCause::CurrentCheck, observed)?;
        }
        if let Some(limit) = max_wire_bytes {
            let complete =
                append_capped_chunk(&mut frame, &chunk[..n], limit).map_err(|error| {
                    *observed = if matches!(error, Error::Limit) {
                        FrameReadCause::FrameLimit
                    } else {
                        FrameReadCause::InvalidFrame
                    };
                    error
                })?;
            observe(
                remaining_at(deadline, Instant::now()),
                FrameReadCause::Deadline,
                observed,
            )?;
            if complete {
                return Ok(frame);
            }
            continue;
        }
        if let Some(end) = chunk[..n].iter().position(|b| *b == b'\n') {
            if end + 1 != n {
                *observed = FrameReadCause::InvalidFrame;
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
    fn final_receive_restriction_preserves_none_and_denies_before_attempt() {
        use std::cell::RefCell;
        let expired = Instant::now() - Duration::from_secs(1);
        let live = Instant::now() + Duration::from_secs(60);
        let mut cause = FrameReadCause::Unclassified;
        // Legacy None adds no deadline failure or changed classification.
        admit_restricted_receive(expired, &mut None, &mut cause).unwrap();
        assert_eq!(cause, FrameReadCause::Unclassified);

        let trace = RefCell::new(vec!["timeout", "ancillary"]);
        let mut deny = || {
            trace.borrow_mut().push("restriction");
            Err(Error::Authentication)
        };
        let mut restriction: Option<&mut dyn FnMut() -> Result<()>> = Some(&mut deny);
        assert!(admit_restricted_receive(expired, &mut restriction, &mut cause).is_err());
        assert_eq!(cause, FrameReadCause::Deadline);
        assert_eq!(&*trace.borrow(), &["timeout", "ancillary"]);
        let attempted = admit_restricted_receive(live, &mut restriction, &mut cause)
            .map(|()| trace.borrow_mut().push("recvmsg"));
        assert!(attempted.is_err());
        assert_eq!(cause, FrameReadCause::CurrentCheck);
        assert_eq!(&*trace.borrow(), &["timeout", "ancillary", "restriction"]);

        let mut allow = || {
            trace.borrow_mut().push("restriction");
            Ok(())
        };
        let mut restriction: Option<&mut dyn FnMut() -> Result<()>> = Some(&mut allow);
        for _ in 0..2 {
            trace.borrow_mut().extend(["timeout", "ancillary"]);
            admit_restricted_receive(live, &mut restriction, &mut cause).unwrap();
            trace.borrow_mut().push("recvmsg");
        }
        assert_eq!(&trace.borrow()[3..], &[
            "timeout", "ancillary", "restriction", "recvmsg",
            "timeout", "ancillary", "restriction", "recvmsg",
        ]);
    }

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
    #[test]
    fn setup_transfer_preserves_original_ceiling_and_action_budget() {
        let now = Instant::now();
        let original = now + Duration::from_secs(900);
        assert_eq!(
            setup_transfer_deadline(original, now).unwrap(),
            now + Duration::from_secs(120)
        );
        let late = now + Duration::from_secs(850);
        assert_eq!(setup_transfer_deadline(original, late).unwrap(), original);
        assert!(setup_transfer_deadline(original, original).is_err());
        assert!(setup_transfer_deadline(original, original + Duration::from_nanos(1)).is_err());
    }
}

#[cfg(test)]
#[path = "framing_setup_integration_tests.rs"]
mod setup_integration_tests;
