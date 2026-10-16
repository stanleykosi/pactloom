//! Exact authenticated restriction request. Construction is private to the
//! credentialed dispatcher; a copied DTO or process observation is insufficient.
use super::*;
use std::net::Shutdown;
use wholepact_signer_origin::permanent_stop_v1::{
    HostPermanentStopRequestV1, PermanentStopCommandV1, MAX_FRAME_BYTES,
};
const IO_SLICE: Duration = Duration::from_millis(100);
pub(crate) struct PermanentStopCancellation {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl PermanentStopCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
/// Restriction identity only; it cannot construct an authenticated request.
#[derive(Clone)]
pub(crate) struct PermanentStopReplyBinding {
    cancelled: Arc<AtomicBool>,
    request_digest: String,
    deadline: Instant,
}
impl PermanentStopReplyBinding {
    fn check_at(&self, now: Instant) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) || now >= self.deadline {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn require_same(&self, other: &Self) -> Result<()> {
        self.check_at(Instant::now())?;
        other.check_at(Instant::now())?;
        if !Arc::ptr_eq(&self.cancelled, &other.cancelled)
            || self.request_digest != other.request_digest
            || self.deadline != other.deadline
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
/// Pure byte-progress bound used by the concrete producer. This is never an
/// approval or channel owner, and partial progress cannot renew its deadline.
pub(crate) struct PermanentStopFrameProgress {
    total: usize,
    offset: usize,
    deadline: Instant,
}
impl PermanentStopFrameProgress {
    pub(crate) fn new(total: usize, deadline: Instant) -> Result<Self> {
        if total == 0 || total > MAX_FRAME_BYTES {
            return Err(Error::InvalidData);
        }
        Ok(Self {
            total,
            offset: 0,
            deadline,
        })
    }
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }
    pub(crate) fn complete(&self) -> bool {
        self.offset == self.total
    }
    pub(crate) fn advance(&mut self, written: usize, now: Instant) -> Result<()> {
        if now >= self.deadline || written == 0 || written > self.total - self.offset {
            return Err(Error::Uncertain);
        }
        self.offset += written;
        Ok(())
    }
}
pub(crate) struct AuthenticatedPermanentStopRequestV1 {
    stream: UnixStream,
    peer: AuthenticatedPeer,
    request: HostPermanentStopRequestV1,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    binding: PermanentStopReplyBinding,
}
impl AuthenticatedPermanentStopRequestV1 {
    pub(super) fn admitted(
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: HostPermanentStopRequestV1,
    ) -> Result<Self> {
        request
            .require_scope(&peer.scope)
            .map_err(|_| Error::Authentication)?;
        let deadline = peer
            .deadline()
            .min(peer.native_origin.bounded_deadline()?)
            .min(Instant::now() + Duration::from_secs(120));
        let cancelled = Arc::new(AtomicBool::new(false));
        let binding = PermanentStopReplyBinding {
            cancelled: cancelled.clone(),
            request_digest: request.digest().map_err(|_| Error::InvalidData)?,
            deadline,
        };
        let value = Self {
            stream,
            peer,
            request,
            deadline,
            cancelled,
            binding,
        };
        value.check_current()?;
        Ok(value)
    }
    pub(crate) fn reply_binding(&self) -> PermanentStopReplyBinding {
        self.binding.clone()
    }
    pub(crate) fn require_reply_binding(&self, binding: &PermanentStopReplyBinding) -> Result<()> {
        self.binding.require_same(binding)
    }
    pub(crate) fn cancellation(&self) -> Result<PermanentStopCancellation> {
        Ok(PermanentStopCancellation {
            stream: self.stream.try_clone()?,
            cancelled: self.cancelled.clone(),
        })
    }
    pub(crate) fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }
    pub(crate) fn request(&self) -> &HostPermanentStopRequestV1 {
        &self.request
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.binding.check_at(Instant::now())?;
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::Authentication);
        }
        self.peer.check_current()?;
        self.request
            .require_scope(&self.peer.scope)
            .map_err(|_| Error::Authentication)?;
        let mut p = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, 0) } < 0
            || p.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// One bounded syscall only. The concrete native producer rechecks its
    /// retained source before every call and after every partial-progress write.
    pub(crate) fn write_part(&mut self, bytes: &[u8], deadline: Instant) -> Result<usize> {
        self.check_current()?;
        let remaining = deadline
            .min(self.deadline)
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Error::Authentication)?;
        self.stream
            .set_write_timeout(Some(remaining.min(IO_SLICE)))?;
        let n = self.stream.write(bytes)?;
        if n == 0 {
            return Err(Error::Uncertain);
        }
        self.check_current()?;
        Ok(n)
    }
    pub(crate) fn read_command(&self, deadline: Instant) -> Result<PermanentStopCommandV1> {
        self.check_current()?;
        let remaining = deadline
            .min(self.deadline)
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Error::Authentication)?;
        let bytes = wholepact_signer_origin::framing::read_frame_capped_until(
            &self.stream,
            &self.peer.peer,
            MAX_FRAME_BYTES,
            deadline
                .min(self.deadline)
                .min(Instant::now() + remaining.min(Duration::from_secs(2))),
        )
        .map_err(Error::from)?;
        self.check_current()?;
        if bytes.len() >= MAX_FRAME_BYTES {
            return Err(Error::InvalidData);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)
    }
}
impl Drop for AuthenticatedPermanentStopRequestV1 {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_channel_identity_rejects_substitution_cancellation_and_expiry() {
        // Restriction-only synthetic identity; no peer, socket, authenticated
        // grant, NativeDecision or reply owner can be made from this value.
        let now = Instant::now();
        let binding = PermanentStopReplyBinding {
            cancelled: Arc::new(AtomicBool::new(false)),
            request_digest: "a".repeat(64),
            deadline: now + Duration::from_secs(5),
        };
        binding.require_same(&binding.clone()).unwrap();
        let mut substituted = binding.clone();
        substituted.cancelled = Arc::new(AtomicBool::new(false));
        assert!(binding.require_same(&substituted).is_err());
        let mut substituted = binding.clone();
        substituted.request_digest = "b".repeat(64);
        assert!(binding.require_same(&substituted).is_err());
        assert!(binding.check_at(binding.deadline).is_err());
        binding.cancelled.store(true, Ordering::Release);
        assert!(binding.check_at(now).is_err());
    }
    #[test]
    fn partial_writes_never_extend_deadline_or_hide_interrupted_reply() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let mut progress = PermanentStopFrameProgress::new(9, deadline).unwrap();
        progress.advance(3, now).unwrap();
        assert_eq!(progress.offset(), 3);
        assert!(!progress.complete());
        assert!(progress.advance(0, now).is_err());
        assert!(progress.advance(7, now).is_err());
        assert!(progress.advance(6, deadline).is_err());
        assert!(!progress.complete());
        progress.advance(6, now + Duration::from_secs(4)).unwrap();
        assert!(progress.complete());
        assert!(PermanentStopFrameProgress::new(MAX_FRAME_BYTES + 1, deadline).is_err());
    }
}
