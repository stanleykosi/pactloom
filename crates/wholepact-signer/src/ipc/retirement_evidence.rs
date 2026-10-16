//! Evidence-only reply-channel ownership. Only the dedicated endpoint can call
//! its private receive seam; installed activation remains closed. A received JSON
//! value, caller-selected peer, or newly observed process cannot construct this
//! owner. Native approvals remain held through serialization and every write.
//!
//! A write already admitted to the kernel may escape concurrent cancellation.
//! Failure can mean partial or complete disclosure, never atomic recall. Local
//! completion is not an acknowledgement that the recipient received anything.
#![allow(dead_code)]

use super::{AuthenticatedPeer, Grant, PairScope, authenticate_grant};

mod endpoint;
use crate::{Error, Result, native_peer::PeerProcess};
pub(crate) use endpoint::{
    RetirementEndpointCancellation, RetirementEndpointEvent, RetirementEvidenceEndpoint,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    collections::BTreeMap,
    io::{self, Write},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_signer_origin::retirement_evidence::{
    FRAME_LIMIT, RetirementDestinationEvidenceRequestV1,
};
use zeroize::{Zeroize, Zeroizing};

const REQUEST_BUDGET: Duration = Duration::from_secs(120);
// Owner invalidation is checked between bounded syscalls. Explicit request
// cancellation additionally shuts down this exact channel to wake a blocked IO.
const WRITE_CALL_LIMIT: Duration = Duration::from_millis(100);

/// Inert admission model, deliberately separate from the installed IpcMode.
/// Its ordinary/quarantined exclusions do not widen the actual endpoint. The
/// installed activation gate remains closed pending attended qualification.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StagedEndpointClass {
    RetirementEvidenceOnly,
    Ordinary,
    QuarantinedV5,
}
fn validate_staged_admission(
    class: StagedEndpointClass,
    request: &RetirementDestinationEvidenceRequestV1,
    scope: &PairScope,
) -> Result<()> {
    if class != StagedEndpointClass::RetirementEvidenceOnly {
        return Err(Error::Authentication);
    }
    request.require_pair_scope(scope).map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementRequestEnvelopeV1 {
    schema_version: u16,
    grant_id: String,
    token_hex: String,
    request: RetirementDestinationEvidenceRequestV1,
}
impl Drop for RetirementRequestEnvelopeV1 {
    fn drop(&mut self) {
        self.token_hex.zeroize();
    }
}

struct RetainedRequestChannel {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl RetainedRequestChannel {
    fn close(&self) -> io::Result<()> {
        self.cancelled.store(true, Ordering::Release);
        self.stream.shutdown(Shutdown::Both)
    }
}
impl Drop for RetainedRequestChannel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Restriction-only handle. It cannot send, renew, authenticate, replace a
/// channel, clear cancellation, or manufacture a new reply owner.
pub(crate) struct RetirementEvidenceCancellation {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl RetirementEvidenceCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Original request-channel identity and restriction ceiling. This is not an
/// authenticated peer or a delivery capability: it cannot read or write the
/// channel, substitute a grant, renew time, or recreate the opaque reply owner.
#[derive(Clone)]
pub(crate) struct RetirementEvidenceReplyBinding {
    cancelled: Arc<AtomicBool>,
    request_digest: String,
    admitted_at: Instant,
    deadline: Instant,
}
impl RetirementEvidenceReplyBinding {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Restriction-only. Actual socket/grant/native liveness is always checked
    /// through the original authenticated reply as well, never inferred here.
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Error::Authentication);
        }
        remaining_at(self.deadline, Instant::now())?;
        Ok(())
    }

    pub(crate) fn require_request_digest(&self, digest: &str) -> Result<()> {
        self.check_current()?;
        if self.request_digest != digest {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    fn require_same_channel(&self, other: &Self) -> Result<()> {
        self.check_current()?;
        other.check_current()?;
        if !Arc::ptr_eq(&self.cancelled, &other.cancelled)
            || self.request_digest != other.request_digest
            || self.admitted_at != other.admitted_at
            || self.deadline != other.deadline
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    /// Correlation/restriction fixture only; cannot fabricate an authenticated
    /// reply, peer, request stream, grant or native approval in any build.
    #[cfg(test)]
    pub(crate) fn synthetic_for_test(deadline: Instant, request_digest: String) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            request_digest,
            admitted_at: Instant::now(),
            deadline,
        }
    }

    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    Pending,
    Admitted,
    InFlight,
    Completed,
    Failed,
}

/// Issued only below after token, kernel sender, original concrete grant, exact
/// purpose/scope and the retained request channel all pass authentication.
/// No raw-stream/peer constructor, deserialization or transferable grant exists.
pub(crate) struct AuthenticatedRetirementEvidenceRequestV1 {
    channel: RetainedRequestChannel,
    peer: AuthenticatedPeer,
    request: RetirementDestinationEvidenceRequestV1,
    request_digest: String,
    admitted_at: Instant,
    deadline: Instant,
    state: Cell<AttemptState>,
}

/// Private parse/authentication seam for one frame already read on the exact
/// credentialed channel by the dedicated endpoint. It never observes a new
/// substitute peer, rereads a stream, or resets the pre-read admission instant.
fn receive_authenticated_retirement_evidence_request(
    grants: &Mutex<BTreeMap<String, Grant>>,
    channel: RetainedRequestChannel,
    observed: PeerProcess,
    frame: &[u8],
    admitted_at: Instant,
    endpoint_deadline: Instant,
) -> Result<AuthenticatedRetirementEvidenceRequestV1> {
    let request_deadline = (admitted_at + REQUEST_BUDGET).min(endpoint_deadline);
    remaining_at(request_deadline, Instant::now())?;
    let envelope: RetirementRequestEnvelopeV1 =
        serde_json::from_slice(frame).map_err(|_| Error::InvalidData)?;
    if envelope.schema_version != 1 {
        return Err(Error::InvalidData);
    }
    let peer = authenticate_grant(grants, observed, &envelope.grant_id, &envelope.token_hex)?;
    validate_staged_admission(
        StagedEndpointClass::RetirementEvidenceOnly,
        &envelope.request,
        &peer.scope,
    )?;
    let request_digest = envelope.request.digest()?;
    let deadline = request_deadline.min(peer.deadline());
    remaining_at(deadline, Instant::now())?;
    let owner = AuthenticatedRetirementEvidenceRequestV1 {
        channel,
        peer,
        request: envelope.request.clone(),
        request_digest,
        admitted_at,
        deadline,
        state: Cell::new(AttemptState::Pending),
    };
    owner.check_current()?;
    Ok(owner)
}

impl AuthenticatedRetirementEvidenceRequestV1 {
    pub(crate) fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }

    pub(crate) fn request(&self) -> &RetirementDestinationEvidenceRequestV1 {
        &self.request
    }

    /// Read-only original ceiling; native preparation can only shorten it.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn binding(&self) -> Result<RetirementEvidenceReplyBinding> {
        self.check_current()?;
        Ok(RetirementEvidenceReplyBinding {
            cancelled: Arc::clone(&self.channel.cancelled),
            request_digest: self.request_digest.clone(),
            admitted_at: self.admitted_at,
            deadline: self.deadline,
        })
    }

    pub(crate) fn require_binding(&self, binding: &RetirementEvidenceReplyBinding) -> Result<()> {
        self.binding()?.require_same_channel(binding)
    }

    pub(crate) fn cancellation_handle(&self) -> Result<RetirementEvidenceCancellation> {
        self.check_current()?;
        Ok(RetirementEvidenceCancellation {
            stream: self.channel.stream.try_clone()?,
            cancelled: Arc::clone(&self.channel.cancelled),
        })
    }

    pub(crate) fn check_current(&self) -> Result<()> {
        if self.channel.cancelled.load(Ordering::Acquire)
            || matches!(
                self.state.get(),
                AttemptState::Completed | AttemptState::Failed
            )
        {
            return Err(Error::Authentication);
        }
        remaining_at(self.deadline, Instant::now())?;
        self.peer.check_current()?;
        self.request.require_pair_scope(&self.peer.scope)?;
        if self.request.digest()? != self.request_digest
            || self.deadline > self.admitted_at + REQUEST_BUDGET
            || self.deadline > self.peer.deadline()
        {
            return Err(Error::Authentication);
        }
        check_exact_request_channel(&self.channel.stream, &self.peer.peer)?;
        // Checking the stream/process does not renew the grant or request.
        self.peer.check_current()?;
        remaining_at(self.deadline, Instant::now())?;
        if self.channel.cancelled.load(Ordering::Acquire) {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    /// One consumed attempt, one bounded frame, then shutdown. The concrete
    /// native delivery owner, both actual vault borrows and both original
    /// approvals survive every encoding/write/post-write check and shutdown.
    pub(crate) fn deliver(
        self,
        delivery: crate::native_ui::retirement_delivery::RetirementEvidenceDelivery<'_>,
    ) -> Result<()> {
        let result = self.deliver_inner(&delivery);
        // Failure after an admitted syscall may already have disclosed bytes.
        // Do not send a second denial frame, retry, or hand out an intermediate
        // response DTO. Closing is terminal even when the post-write check fails.
        let close_result = self.channel.close();
        let result = result.and_then(|()| close_result.map_err(Error::from));
        self.state.set(if result.is_ok() {
            AttemptState::Completed
        } else {
            AttemptState::Failed
        });
        result
    }

    fn deliver_inner(
        &self,
        delivery: &crate::native_ui::retirement_delivery::RetirementEvidenceDelivery<'_>,
    ) -> Result<()> {
        let deadline = self.deadline.min(delivery.deadline());
        let mut io = ConcreteDeliveryIo {
            reply: self,
            delivery,
            deadline,
        };
        io.check()?;
        self.state.set(AttemptState::Admitted);
        let response = delivery.response(&self.peer, &self.request)?;
        response.require_request_binding(&self.request, &self.peer.grant_id)?;
        io.check()?;
        let bytes = encode_frame_until(&response, deadline, &mut io)?;
        self.state.set(AttemptState::InFlight);
        write_bytes_until(&bytes, deadline, &mut io)?;
        io.check()
    }
}

/// Private implementation seam for byte/clock policy tests only. Production has
/// exactly one implementation, retaining the concrete owners above. This is
/// not a public authority callback, authenticator, source or construction API.
trait DeliveryIo {
    fn now(&self) -> Instant;
    fn check(&mut self) -> Result<()>;
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize>;
}

struct ConcreteDeliveryIo<'a, 'vault> {
    reply: &'a AuthenticatedRetirementEvidenceRequestV1,
    delivery: &'a crate::native_ui::retirement_delivery::RetirementEvidenceDelivery<'vault>,
    deadline: Instant,
}
impl DeliveryIo for ConcreteDeliveryIo<'_, '_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn check(&mut self) -> Result<()> {
        remaining_at(self.deadline, self.now())?;
        self.reply.check_current()?;
        self.delivery.require_reply(self.reply)?;
        self.delivery.check(&self.reply.peer, &self.reply.request)?;
        self.delivery.require_reply(self.reply)?;
        remaining_at(self.deadline, self.now())?;
        Ok(())
    }
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        self.reply.channel.stream.set_write_timeout(Some(timeout))?;
        let mut stream = &self.reply.channel.stream;
        stream.write(bytes)
    }
}

fn remaining_at(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::Authentication)
}

fn write_bytes_until(bytes: &[u8], deadline: Instant, io: &mut impl DeliveryIo) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > FRAME_LIMIT
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(Error::InvalidData);
    }
    let mut offset = 0;
    while offset < bytes.len() {
        io.check()?;
        let timeout = remaining_at(deadline, io.now())?.min(WRITE_CALL_LIMIT);
        let result = io.write(&bytes[offset..], timeout);
        // Always check after the syscall, including Interrupted, errors, the
        // final JSON byte and final newline. Already sent bytes are not recalled.
        io.check()?;
        remaining_at(deadline, io.now())?;
        match result {
            Ok(0) => return Err(Error::Io(io::Error::from(io::ErrorKind::WriteZero))),
            Ok(written) if written <= bytes.len() - offset => offset += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
            Ok(_) => return Err(Error::InvalidData),
        }
    }
    io.check()?;
    remaining_at(deadline, io.now())?;
    Ok(())
}

struct BoundedFrame {
    bytes: Zeroizing<Vec<u8>>,
}
impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|len| len >= FRAME_LIMIT)
        {
            return Err(io::Error::other("retirement evidence frame limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_frame(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let mut frame = BoundedFrame {
        bytes: Zeroizing::new(Vec::new()),
    };
    // Reserve once before encoding; oversized serde output never grows a
    // temporary unchecked Vec or leaves previous reallocation copies behind.
    frame
        .bytes
        .try_reserve_exact(FRAME_LIMIT)
        .map_err(|_| Error::InvalidData)?;
    serde_json::to_writer(&mut frame, value).map_err(|_| Error::InvalidData)?;
    frame.bytes.push(b'\n');
    Ok(frame.bytes)
}

fn encode_frame_until(
    value: &impl Serialize,
    deadline: Instant,
    io: &mut impl DeliveryIo,
) -> Result<Zeroizing<Vec<u8>>> {
    io.check()?;
    remaining_at(deadline, io.now())?;
    let bytes = encode_frame(value)?;
    io.check()?;
    remaining_at(deadline, io.now())?;
    Ok(bytes)
}

fn require_open_poll_state(revents: libc::c_short) -> Result<()> {
    if revents & !libc::POLLIN != 0 {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn check_exact_request_channel(stream: &UnixStream, retained: &PeerProcess) -> Result<()> {
    // This newly observed handle only compares the exact retained connection
    // with the original live peer. It is never substituted for the grant owner.
    let observed = PeerProcess::observe(stream)?;
    retained.same_live_process(&observed)?;
    let mut poll = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: exactly one initialized pollfd; zero timeout is nonblocking.
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    // HUP, RDHUP, ERR and NVAL are terminal even if the process remains alive.
    require_open_poll_state(poll.revents)?;

    let mut byte = [0u8; 1];
    let mut control = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: initialized, aligned and disjoint buffers live through recvmsg.
    // Do not MSG_PEEK: passed descriptors must be consumed, closed and denied.
    let got = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if got < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::WouldBlock {
            retained.same_live_process(&observed).map_err(Into::into)
        } else {
            Err(Error::Io(error))
        };
    }
    let mut credential_count = 0;
    let mut authenticated = false;
    let mut unexpected = false;
    // SAFETY: kernel-produced ancillary headers lie within this initialized
    // recvmsg buffer. Every delivered SCM_RIGHTS descriptor is closed on denial.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            let h = &*header;
            if h.cmsg_level == libc::SOL_SOCKET
                && h.cmsg_type == libc::SCM_CREDENTIALS
                && h.cmsg_len == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as _) as usize
            {
                let credential =
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>());
                credential_count += 1;
                authenticated = credential_count == 1
                    && credential.pid > 0
                    && credential.pid as u32 == retained.pid()
                    && credential.uid == retained.uid();
            } else {
                unexpected = true;
                if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                    let bytes = h.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    for index in 0..bytes / std::mem::size_of::<libc::c_int>() {
                        libc::close(std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        ));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    if got == 0
        || credential_count != 1
        || !authenticated
        || unexpected
        || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    {
        return Err(Error::Authentication);
    }
    // Even a correctly authenticated sender cannot append another request,
    // cancellation frame, substitute payload or success-like Finish message.
    Err(Error::InvalidData)
}

#[cfg(test)]
#[path = "retirement_evidence_tests.rs"]
mod tests;
