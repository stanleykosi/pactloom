//! Monotone narrowing of the same original registry after actual V3 completion.
//! No Q/Resume bypass: original S actor, H/C, R and clocks stay checked.
use super::*;
use wholepact_financial_coordinator_origin::SignerV3CompletedLifetimeV1;

pub(crate) struct CoordinatedFinancialResultEventV1 {
    pub(crate) peer: CoordinatedPairPeerV1,
    pub(crate) stream: UnixStream,
    pub(crate) request:
        crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1,
    pub(crate) original_request_deadline: Instant,
}
/// No source/database/read owner and no way back to Pair or initial V3 APIs.
pub(crate) struct CoordinatedReturnTransportV1 {
    ipc: CoordinatedLocalIpcV1,
    peer: CoordinatedPairPeerV1,
}
fn discard(event: CoordinatedLocalEventV1) {
    match event {
        CoordinatedLocalEventV1::Request { stream, .. } => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        CoordinatedLocalEventV1::Pairing(pending) => {
            let _ = pending.stream.shutdown(std::net::Shutdown::Both);
        }
        CoordinatedLocalEventV1::StatusProof(_) => {}
    }
}
impl CoordinatedLocalIpcV1 {
    /// Called only by the consuming completed source owner after its final H
    /// status stream has finished and no source/worker action remains in flight.
    /// The genuine completion token cannot be reconstructed from status JSON.
    pub(crate) fn enter_financial_return_only(
        self,
        completed: &SignerV3CompletedLifetimeV1,
    ) -> Result<CoordinatedReturnTransportV1> {
        completed.check_current()?;
        self.bounds.check()?;
        if completed.source_identity_digest() != self.bounds.source_identity
            || completed.original_source_deadline() != self.bounds.deadline
        {
            return Err(Error::Authentication);
        }
        let peer = {
            let grants = self.grants.lock().map_err(|_| Error::Locked)?;
            if grants.len() != 1 {
                return Err(Error::Authentication);
            }
            let grant = grants.values().next().ok_or(Error::Authentication)?;
            grant.peer.check_current()?;
            if !grant.possession_proved
                || grant.peer.grant_id() != completed.pair_grant_id()
                || grant.peer.channel_digest() != completed.pair_channel_digest()
                || grant.peer.pair_presentation_digest() != completed.pair_presentation_digest()
                || grant.peer.deadline() != completed.original_channel_deadline()
            {
                return Err(Error::Authentication);
            }
            grant.peer.clone()
        };
        self.bounds
            .mode
            .compare_exchange(
                V3_RUNNING,
                RETURN_REQUESTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::Authentication)?;
        // Bounded parser-drain wait only, never a renewed source/action lease.
        let wait = (Instant::now() + Duration::from_secs(3))
            .min(peer.deadline())
            .min(self.bounds.deadline);
        loop {
            self.bounds.check()?;
            completed.check_current()?;
            peer.check_current()?;
            if self.bounds.mode.load(Ordering::Acquire) == RETURN_DRAINED {
                break;
            }
            if Instant::now() >= wait {
                return Err(Error::Locked);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // Worker is now ACKed and cannot emit any further parsed command.
        while let Ok(event) = self.events.try_recv() {
            discard(event);
        }
        completed.check_current()?;
        self.bounds.check()?;
        peer.check_current()?;
        self.bounds
            .mode
            .compare_exchange(
                RETURN_DRAINED,
                RETURN_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(CoordinatedReturnTransportV1 { ipc: self, peer })
    }
}
impl CoordinatedReturnTransportV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.ipc.bounds.check()?;
        self.peer.check_current()?;
        if self.ipc.bounds.mode.load(Ordering::Acquire) != RETURN_RUNNING {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn original_peer(&self) -> &CoordinatedPairPeerV1 {
        &self.peer
    }
    pub(crate) fn next_result(&self) -> Result<Option<CoordinatedFinancialResultEventV1>> {
        self.check_current()?;
        loop {
            let event = match self.ipc.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => return Ok(None),
                Err(mpsc::TryRecvError::Disconnected) => return Err(Error::Unavailable),
            };
            match event {
                CoordinatedLocalEventV1::Request {
                    peer,
                    stream,
                    request: CoordinatedRequestV1::FinancialResult(request),
                    original_request_deadline,
                } => {
                    self.peer.require_same_grant(&peer)?;
                    self.check_current()?;
                    return Ok(Some(CoordinatedFinancialResultEventV1 {
                        peer,
                        stream,
                        request,
                        original_request_deadline,
                    }));
                }
                other => discard(other),
            }
        }
    }
}
