//! Installed-origin retirement observation adapter for the dedicated endpoint.
//! Public activation remains unavailable through the shared native/client gate
//! until attended native and actual kernel transport qualification is complete.
#![allow(dead_code)] // Private staged entry remains intentionally unreachable.
use super::*;
use crate::retirement_evidence::{
    FRAME_LIMIT, RetirementDestinationEvidenceRequestV1, RetirementDestinationEvidenceResponseV1,
    decode_response, encode_bounded_frame,
};
use std::{net::Shutdown, sync::Arc};

const MAX_REQUEST: Duration = Duration::from_secs(120);

/// Purpose-restricted installed signer owner. There is no conversion from or to
/// a manual/history client, and no arbitrary operation or raw-stream entry.
pub struct InstalledRetirementEvidenceClientV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    scope: PairScope,
    grant: ClientGrant,
    request: RetirementDestinationEvidenceRequestV1,
    deadline: Instant,
    requested: AtomicBool,
}
impl InstalledRetirementEvidenceClientV1 {
    /// This staged source is unavailable even when its opt-in feature is built.
    /// No provider load, launch, endpoint wait or connection is attempted here.
    pub fn availability() -> Result<()> {
        require_activation()
    }
    pub fn launch_and_pair(
        provider: InstalledSignerProvider,
        application_label: &str,
        request: RetirementDestinationEvidenceRequestV1,
    ) -> Result<Self> {
        require_activation()?;
        let deadline = request_deadline(Instant::now(), None)?;
        provider.launch_native()?;
        let socket = provider.wait_native_endpoint(remaining_before(deadline)?)?;
        Self::begin_pair_before_staged(provider, &socket, application_label, request, deadline)?
            .finish()
    }
    /// Endpoint paths are availability locators, never trust anchors. This
    /// entry returns unavailable before even validating/connecting the path.
    pub fn begin_pair_before(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        request: RetirementDestinationEvidenceRequestV1,
        deadline: Instant,
    ) -> Result<PendingRetirementEvidencePairV1> {
        require_activation()?;
        Self::begin_pair_before_staged(provider, socket, application_label, request, deadline)
    }
    /// Private implementation for review, not an alternate callable API. This
    /// function has no unguarded caller or synthetic provider constructor.
    fn begin_pair_before_staged(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        request: RetirementDestinationEvidenceRequestV1,
        deadline: Instant,
    ) -> Result<PendingRetirementEvidencePairV1> {
        let started = Instant::now();
        let deadline = request_deadline(started, Some(deadline))?;
        label(application_label)?;
        request.validate()?;
        let scope = request.pair_scope()?;
        let stream = connect_local_before(socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        let pending = EvidenceStream::new(stream);
        framing::enable_credentials(pending.stream.as_raw_fd())?;
        let peer = provider.verify_server(&pending.stream)?;
        let bytes = encode_bounded_frame(&serde_json::json!({
            "command":"request_pairing", "schema_version":1,
            "application_label":application_label, "scope":scope,
        }))?;
        write_request(
            &pending,
            &peer,
            &bytes,
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
        )?;
        remaining_before(deadline)?;
        Ok(PendingRetirementEvidencePairV1 {
            provider,
            socket: socket.into(),
            peer,
            request,
            scope,
            pending,
            started,
            deadline,
        })
    }
    /// One request on the exact original pairing. The first request proves
    /// token possession; there is no generic Status probe or retry fallback.
    pub fn begin_observation_before(
        &self,
        deadline: Instant,
    ) -> Result<PendingRetirementDestinationEvidenceV1<'_>> {
        require_activation()?;
        self.begin_observation_before_staged(deadline)
    }
    fn begin_observation_before_staged(
        &self,
        deadline: Instant,
    ) -> Result<PendingRetirementDestinationEvidenceV1<'_>> {
        self.check_current()?;
        self.request.require_pair_scope(&self.scope)?;
        claim_once(&self.requested)?;
        let deadline = deadline.min(self.deadline).min(self.grant.expires);
        remaining_before(deadline)?;
        let stream =
            connect_local_before(&self.socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        let pending = EvidenceStream::new(stream);
        framing::enable_credentials(pending.stream.as_raw_fd())?;
        self.require_channel(&pending.stream)?;
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: u16,
            grant_id: &'a str,
            token_hex: &'a str,
            request: &'a RetirementDestinationEvidenceRequestV1,
        }
        let bytes = encode_bounded_frame(&Envelope {
            schema_version: 1,
            grant_id: &self.grant.grant_id,
            token_hex: &self.grant.token_hex,
            request: &self.request,
        })?;
        write_request(
            &pending,
            &self.peer,
            &bytes,
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
        )?;
        self.check_current()?;
        remaining_before(deadline)?;
        // Leave the exact stream write-half open. Half-close is abandonment at
        // the server; the protocol has no second command or Finish frame.
        Ok(PendingRetirementDestinationEvidenceV1 {
            client: self,
            pending,
            deadline,
        })
    }
    fn check_current(&self) -> Result<()> {
        remaining_before(self.deadline.min(self.grant.expires))?;
        self.peer.check_alive()
    }
    fn require_channel(&self, stream: &UnixStream) -> Result<()> {
        self.check_current()?;
        let actual = self.provider.verify_server(stream)?;
        self.peer.same_live_process(&actual)?;
        self.check_current()
    }
}
fn require_activation() -> Result<()> {
    crate::retirement_evidence::require_native_transport_activation_v1()
}

/// Native pairing is still pending request capability, not permission to
/// disclose the response. Drop/cancel shuts down this stream without a command.
pub struct PendingRetirementEvidencePairV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    request: RetirementDestinationEvidenceRequestV1,
    scope: PairScope,
    pending: EvidenceStream,
    started: Instant,
    deadline: Instant,
}
impl PendingRetirementEvidencePairV1 {
    pub fn cancellation_handle(&self) -> Result<RetirementEvidenceCancellationV1> {
        self.pending.cancellation_handle()
    }
    pub fn finish(self) -> Result<InstalledRetirementEvidenceClientV1> {
        self.pending.check()?;
        let actual = self.provider.verify_server(&self.pending.stream)?;
        self.peer.same_live_process(&actual)?;
        let bytes = framing::read_frame_capped_until(
            &self.pending.stream,
            &self.peer,
            FRAME_LIMIT,
            self.deadline,
        )?;
        let response: PairResponse =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)?;
        validate_pair_response(&response)?;
        let expires = self
            .started
            .checked_add(Duration::from_secs(response.expires_in_seconds))
            .ok_or(Error::Permission)?
            .min(self.deadline);
        remaining_before(expires)?;
        require_terminal_eof(&self.pending, &self.peer, expires)?;
        let actual = self.provider.verify_server(&self.pending.stream)?;
        self.peer.same_live_process(&actual)?;
        self.pending.check()?;
        remaining_before(expires)?;
        Ok(InstalledRetirementEvidenceClientV1 {
            provider: self.provider,
            socket: self.socket,
            peer: self.peer,
            scope: self.scope,
            request: self.request,
            deadline: self.deadline,
            grant: ClientGrant {
                grant_id: response.grant_id.clone(),
                token_hex: Zeroizing::new(response.token_hex.clone()),
                expires,
            },
            requested: AtomicBool::new(false),
        })
    }
}
fn validate_pair_response(response: &PairResponse) -> Result<()> {
    if response.schema_version != 1
        || !response.accepted
        || response.reason_code != "LOCAL_PROCESS_REQUEST_SCOPE"
        || response.expires_in_seconds == 0
        || response.expires_in_seconds > 900
    {
        return Err(Error::Permission);
    }
    hash(&response.grant_id)?;
    hash(&response.token_hex)
}

pub struct PendingRetirementDestinationEvidenceV1<'client> {
    client: &'client InstalledRetirementEvidenceClientV1,
    pending: EvidenceStream,
    deadline: Instant,
}
impl PendingRetirementDestinationEvidenceV1<'_> {
    pub fn cancellation_handle(&self) -> Result<RetirementEvidenceCancellationV1> {
        self.pending.cancellation_handle()
    }
    /// A complete exact frame followed by terminal EOF is historical disclosure
    /// only. It cannot prove that the sender's final post-write check succeeded.
    pub fn finish(self) -> Result<RetirementDestinationEvidenceObservationV1> {
        self.pending.check()?;
        self.client.require_channel(&self.pending.stream)?;
        let bytes = framing::read_frame_capped_until(
            &self.pending.stream,
            &self.client.peer,
            FRAME_LIMIT,
            self.deadline,
        )?;
        self.pending.check()?;
        self.client.check_current()?;
        let response = decode_response(&bytes)?;
        response.require_request_binding(&self.client.request, &self.client.grant.grant_id)?;
        require_terminal_eof(&self.pending, &self.client.peer, self.deadline)?;
        self.client.require_channel(&self.pending.stream)?;
        self.pending.check()?;
        remaining_before(self.deadline)?;
        Ok(RetirementDestinationEvidenceObservationV1 { response })
    }
}

/// Received historical information with no live-authority, financial, recovery,
/// lease, current-check or deserialization conversion. The caller may retain the
/// inert fields; retention never extends any source/destination native owner.
/// ```compile_fail
/// # use wholepact_signer_origin::RetirementDestinationEvidenceObservationV1;
/// let _: RetirementDestinationEvidenceObservationV1 = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// # use wholepact_signer_origin::RetirementDestinationEvidenceObservationV1;
/// # use wholepact_core::retirement::UserControlledShieldedDestination;
/// fn promote(observed: RetirementDestinationEvidenceObservationV1) -> UserControlledShieldedDestination {
///     observed.into()
/// }
/// ```
pub struct RetirementDestinationEvidenceObservationV1 {
    response: RetirementDestinationEvidenceResponseV1,
}
impl RetirementDestinationEvidenceObservationV1 {
    /// Read-only access to an explicitly informational, publicly constructible
    /// DTO. No reference to a live provider, socket, token or native owner exits.
    pub fn response(&self) -> &RetirementDestinationEvidenceResponseV1 {
        &self.response
    }
}

/// A clone of the exact pending descriptor, restricted to shutting it down.
/// This can interrupt a blocked bounded receive without sending a protocol byte.
pub struct RetirementEvidenceCancellationV1 {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl RetirementEvidenceCancellationV1 {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
struct EvidenceStream {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl EvidenceStream {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    fn check(&self) -> Result<()> {
        check_cancelled(&self.cancelled)
    }
    fn cancellation_handle(&self) -> Result<RetirementEvidenceCancellationV1> {
        self.check()?;
        Ok(RetirementEvidenceCancellationV1 {
            stream: self.stream.try_clone()?,
            cancelled: self.cancelled.clone(),
        })
    }
}
impl Drop for EvidenceStream {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
fn check_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Permission);
    }
    Ok(())
}
fn claim_once(requested: &AtomicBool) -> Result<()> {
    requested
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| Error::Permission)
}
fn request_deadline(started: Instant, restriction: Option<Instant>) -> Result<Instant> {
    let maximum = started.checked_add(MAX_REQUEST).ok_or(Error::Permission)?;
    let deadline = restriction.map_or(maximum, |value| value.min(maximum));
    if deadline <= started {
        return Err(Error::Permission);
    }
    Ok(deadline)
}
fn write_request(
    pending: &EvidenceStream,
    peer: &PeerProcess,
    bytes: &[u8],
    deadline: Instant,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT || bytes.last() != Some(&b'\n') {
        return Err(Error::Limit);
    }
    let mut sent = 0;
    let mut stream = &pending.stream;
    while sent < bytes.len() {
        pending.check()?;
        peer.check_alive()?;
        let remaining = remaining_before(deadline)?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err(Error::Ipc),
            Ok(count) => sent += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Ipc),
        }
        pending.check()?;
        peer.check_alive()?;
        remaining_before(deadline)?;
    }
    Ok(())
}

/// One response, then close, under the same absolute request budget. Any extra
/// byte fails even if it arrives in a later receive. EOF itself carries no
/// sender credentials, so it is accepted only after the authenticated frame.
/// Rights are explicitly closed even on a rejected ancillary receive.
fn require_terminal_eof(
    pending: &EvidenceStream,
    peer: &PeerProcess,
    deadline: Instant,
) -> Result<()> {
    loop {
        pending.check()?;
        peer.check_alive()?;
        pending
            .stream
            .set_read_timeout(Some(remaining_before(deadline)?))?;
        let mut byte = [0u8; 1];
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        // SAFETY: msghdr is a plain C record; its pointers below refer to live,
        // disjoint buffers with the exact initialized lengths for this syscall.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: all buffers remain live and writable through recvmsg.
        let count = unsafe {
            libc::recvmsg(
                pending.stream.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count < 0 {
            let interrupted =
                std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
            pending.check()?;
            remaining_before(deadline)?;
            if interrupted {
                continue;
            }
            return Err(Error::Ipc);
        }
        let mut unexpected = false;
        // SAFETY: recvmsg initialized the ancillary prefix and CMSG traversal
        // respects msg_controllen. Every received SCM_RIGHTS descriptor closes.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let h = &*header;
                if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                    unexpected = true;
                    let size = h.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    for index in 0..size / std::mem::size_of::<libc::c_int>() {
                        libc::close(std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        ));
                    }
                } else if h.cmsg_level != libc::SOL_SOCKET
                    || h.cmsg_type != libc::SCM_CREDENTIALS
                    || h.cmsg_len
                        != libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as _) as usize
                {
                    unexpected = true;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        pending.check()?;
        peer.check_alive()?;
        remaining_before(deadline)?;
        return terminal_result(count as usize, message.msg_flags, unexpected);
    }
}
fn terminal_result(received: usize, flags: libc::c_int, unexpected_ancillary: bool) -> Result<()> {
    if received != 0 || flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || unexpected_ancillary {
        return Err(Error::InvalidData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retirement_public_activation_is_closed_without_provider_or_socket() {
        assert!(matches!(
            InstalledRetirementEvidenceClientV1::availability(),
            Err(Error::RetirementEvidenceUnavailable)
        ));
        assert!(matches!(
            require_activation(),
            Err(Error::RetirementEvidenceUnavailable)
        ));
    }
    #[test]
    fn retirement_terminal_policy_requires_eof_without_later_byte_or_ancillary() {
        assert!(terminal_result(0, 0, false).is_ok());
        for (count, flags, ancillary) in [
            (1, 0, false),
            (0, libc::MSG_TRUNC, false),
            (0, libc::MSG_CTRUNC, false),
            (0, 0, true),
        ] {
            assert!(terminal_result(count, flags, ancillary).is_err());
        }
    }
    #[test]
    fn retirement_cancel_and_request_attempt_are_monotone() {
        let cancelled = AtomicBool::new(false);
        assert!(check_cancelled(&cancelled).is_ok());
        cancelled.store(true, Ordering::Release);
        assert!(check_cancelled(&cancelled).is_err());
        assert!(check_cancelled(&cancelled).is_err());
        let requested = AtomicBool::new(false);
        assert!(claim_once(&requested).is_ok());
        assert!(claim_once(&requested).is_err());
        assert!(requested.load(Ordering::Acquire));
    }
    #[test]
    fn retirement_deadline_never_renews_original_request_budget() {
        let started = Instant::now();
        let original = request_deadline(started, None).unwrap();
        assert_eq!(original, started + MAX_REQUEST);
        assert_eq!(
            request_deadline(started, Some(original + MAX_REQUEST)).unwrap(),
            original
        );
        assert_eq!(
            request_deadline(started, Some(started + Duration::from_secs(1))).unwrap(),
            started + Duration::from_secs(1)
        );
        assert!(request_deadline(started, Some(started)).is_err());
        assert!(remaining_before(started).is_err());
    }
}
