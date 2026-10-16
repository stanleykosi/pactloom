//! Restriction-only installed-origin client. A durable Host acknowledgment is
//! sent only by a caller holding this exact opaque lease. Cancellation poisons
//! the original request slot before it is released; no implicit Finish exists.
use super::*;
use crate::permanent_stop_v1::*;
use std::net::Shutdown;

impl NativeManualClient {
    pub fn begin_permanent_stop_v1_before(
        &self,
        request: &HostPermanentStopRequestV1,
        deadline: Instant,
    ) -> Result<PendingPermanentStopV1<'_>> {
        require_activation_v1()?;
        self.begin_permanent_stop_v1_staged(request, deadline)
    }
    fn begin_permanent_stop_v1_staged(
        &self,
        request: &HostPermanentStopRequestV1,
        deadline: Instant,
    ) -> Result<PendingPermanentStopV1<'_>> {
        request.require_scope(&self.scope)?;
        if request.provider_enrollment_ref != self.provider.native_enrollment_reference() {
            return Err(Error::Binding);
        }
        self.check_channel()?;
        let deadline = deadline
            .min(self.grant.expires)
            .min(Instant::now() + Duration::from_secs(120));
        remaining_before(deadline)?;
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        let stream = self.open_request_before(
            serde_json::json!({"operation":"request_born_permanent_stop_v1","request":request}),
            deadline,
        )?;
        Ok(PendingPermanentStopV1 {
            client: self,
            request: request.clone(),
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
        })
    }
}
pub struct PendingPermanentStopV1<'a> {
    client: &'a NativeManualClient,
    request: HostPermanentStopRequestV1,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'a>,
    deadline: Instant,
}
impl<'a> PendingPermanentStopV1<'a> {
    pub fn finish(mut self) -> Result<PermanentStopLeaseV1<'a>> {
        let response = read(self.pending.stream()?, &self.client.peer, self.deadline)?;
        let PermanentStopResponseV1::Held { lease_id, evidence } = response else {
            return Err(Error::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if evidence.request != self.request {
            return Err(Error::Binding);
        }
        self.client.check_channel()?;
        remaining_before(self.deadline)?;
        let lease = PermanentStopLeaseV1 {
            client: self.client,
            stream: Mutex::new(self.pending.take()?),
            lease_id,
            digest: evidence.digest()?,
            evidence: *evidence,
            deadline: self.deadline.min(Instant::now() + Duration::from_secs(30)),
            failed: AtomicBool::new(false),
            acknowledged: false,
            _slot: self.attempt.transfer_to_held()?,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
pub struct PermanentStopLeaseV1<'a> {
    client: &'a NativeManualClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    digest: String,
    evidence: PermanentStopEvidenceV1,
    deadline: Instant,
    failed: AtomicBool,
    acknowledged: bool,
    _slot: LeaseSlot<'a>,
}
impl PermanentStopLeaseV1<'_> {
    pub fn evidence(&self) -> &PermanentStopEvidenceV1 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        let result = (|| {
            if self.failed.load(Ordering::Acquire) {
                return Err(Error::Permission);
            }
            self.client.check_channel()?;
            remaining_before(self.deadline)?;
            let nonce = hex::encode(crate::random::<32>()?);
            let mut stream = self.stream.lock().map_err(|_| Error::Ipc)?;
            let phase = self.deadline.min(Instant::now() + MAX_CURRENT_WAIT);
            write_frame_until_bounded(
                &mut stream,
                &PermanentStopCommandV1::CheckCurrent {
                    lease_id: self.lease_id.clone(),
                    evidence_digest: self.digest.clone(),
                    challenge_nonce: nonce.clone(),
                },
                phase,
                None,
                MAX_FRAME_BYTES,
            )?;
            match read(&stream, &self.client.peer, phase)? {
                PermanentStopResponseV1::Current {
                    lease_id,
                    evidence_digest,
                    challenge_nonce,
                } if lease_id == self.lease_id
                    && evidence_digest == self.digest
                    && challenge_nonce == nonce => {}
                _ => return Err(Error::Binding),
            }
            remaining_before(self.deadline)?;
            self.client.check_channel()
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
            self.client.handoff.poison();
        }
        result
    }
    pub fn acknowledge(mut self, acknowledgment: HostPermanentStopAcknowledgmentV1) -> Result<()> {
        acknowledgment.require_evidence(&self.evidence)?;
        self.check_current()?;
        let phase = self.deadline.min(Instant::now() + MAX_CURRENT_WAIT);
        {
            let mut stream = self.stream.lock().map_err(|_| Error::Ipc)?;
            write_frame_until_bounded(
                &mut stream,
                &PermanentStopCommandV1::Acknowledge {
                    lease_id: self.lease_id.clone(),
                    evidence_digest: self.digest.clone(),
                    acknowledgment: Box::new(acknowledgment),
                },
                phase,
                None,
                MAX_FRAME_BYTES,
            )?;
            if !matches!(
                read(&stream, &self.client.peer, phase)?,
                PermanentStopResponseV1::Acknowledged {}
            ) {
                return Err(Error::Binding);
            }
        }
        remaining_before(phase)?;
        self.client.check_channel()?;
        self.acknowledged = true;
        Ok(())
    }
}
impl Drop for PermanentStopLeaseV1<'_> {
    fn drop(&mut self) {
        if !self.acknowledged {
            self.failed.store(true, Ordering::Release);
            self.client.handoff.poison();
        }
        if let Ok(stream) = self.stream.get_mut() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}
fn read(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
) -> Result<PermanentStopResponseV1> {
    let bytes = framing::read_frame_capped_until(stream, peer, MAX_FRAME_BYTES, deadline)?;
    if bytes.len() >= MAX_FRAME_BYTES {
        return Err(Error::Limit);
    }
    let response = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidData)?;
    remaining_before(deadline)?;
    Ok(response)
}
