//! A bounded, exact, key-free peer-request admission. It can survive peer focus,
//! but cannot produce a NativeDecision or renew any original request deadline.
use super::{
    request::RequestFile, worker::AssertionInput, NativeAuthority, NativeDecision, VerifierOwner,
};
use crate::{Error, Result};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
pub(super) struct Lifetime {
    alive: Arc<AtomicBool>,
    deadline: Instant,
    admitted_wall: u64,
    expires_wall: u64,
    phase: Arc<AtomicU8>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Pairing = 0,
    AwaitPossession = 1,
    Possession = 2,
    Collecting = 3,
    AwaitAssertion = 4,
    Assertion = 5,
    Finished = 6,
}
fn wall() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}
impl Lifetime {
    pub(super) fn check(&self) -> Result<()> {
        self.check_at(Instant::now(), wall()?)
    }
    fn check_at(&self, now: Instant, wall: u64) -> Result<()> {
        if !self.alive.load(Ordering::Acquire)
            || now >= self.deadline
            || wall < self.admitted_wall
            || wall >= self.expires_wall
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(super) fn cancel(&self) {
        self.alive.store(false, Ordering::Release);
    }
    pub(super) fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            0 => Phase::Pairing,
            1 => Phase::AwaitPossession,
            2 => Phase::Possession,
            3 => Phase::Collecting,
            4 => Phase::AwaitAssertion,
            5 => Phase::Assertion,
            _ => Phase::Finished,
        }
    }
    pub(super) fn set_phase(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Release);
    }
    pub(super) fn permits_peer_focus(&self) -> bool {
        matches!(
            self.phase(),
            Phase::Pairing | Phase::Collecting | Phase::AwaitPossession | Phase::AwaitAssertion
        ) && self.check().is_ok()
    }
}
pub(super) struct ApprovedRequest {
    pub endpoints: Vec<String>,
    pub input: AssertionInput,
    pub lifetime: Lifetime,
    pub key: [u8; 32],
    pub profile_commitment: String,
}
impl ApprovedRequest {
    pub(super) fn admit(
        request: RequestFile,
        decision: NativeDecision,
        native: &NativeAuthority,
        owner: &VerifierOwner,
    ) -> Result<Self> {
        native.check_current()?;
        owner.check_current()?;
        if decision.binding() != &native.binding()
            || native.binding() != owner.source
            || decision.reviewed_digest() != request.digest()?
            || decision.consumed_at().elapsed() >= Duration::from_secs(120)
        {
            return Err(Error::ReviewMismatch);
        }
        let now = wall()?;
        let expires = request
            .scopes
            .iter()
            .map(|s| {
                s.disclosure_expires_at_ms
                    .min(s.original_validity_expires_ms)
            })
            .min()
            .ok_or(Error::InvalidData)?;
        if request
            .scopes
            .iter()
            .any(|s| now < s.requested_at_ms || now < s.original_validity_not_before_ms)
            || now >= expires
        {
            return Err(Error::Locked);
        }
        let duration = Duration::from_millis(expires - now).min(Duration::from_secs(120));
        let deadline = Instant::now().checked_add(duration).ok_or(Error::Locked)?;
        let key = owner.public_key();
        let profile_commitment = owner.state_commitment()?;
        let (endpoints, input) = request.into_input()?;
        let lifetime = Lifetime {
            alive: Arc::new(AtomicBool::new(true)),
            deadline,
            admitted_wall: now,
            expires_wall: expires,
            phase: Arc::new(AtomicU8::new(Phase::Pairing as u8)),
        };
        Ok(Self {
            endpoints,
            input,
            lifetime,
            key,
            profile_commitment,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_handoff_never_renews_deadline_or_survives_explicit_cancel() {
        let start = Instant::now();
        let l = Lifetime {
            alive: Arc::new(AtomicBool::new(true)),
            deadline: start + Duration::from_secs(10),
            admitted_wall: 100,
            expires_wall: 200,
            phase: Arc::new(AtomicU8::new(0)),
        };
        assert!(l.check_at(start, 100).is_ok());
        assert!(l.check_at(start + Duration::from_secs(10), 101).is_err());
        assert!(l.check_at(start, 99).is_err());
        assert!(l.check_at(start, 200).is_err());
        let clone = l.clone();
        l.cancel();
        assert!(clone.check_at(start, 101).is_err());
    }
    #[test]
    fn peer_handoff_phase_does_not_create_key_authority() {
        let l = Lifetime {
            alive: Arc::new(AtomicBool::new(true)),
            deadline: Instant::now() + Duration::from_secs(10),
            admitted_wall: 0,
            expires_wall: u64::MAX,
            phase: Arc::new(AtomicU8::new(0)),
        };
        assert!(l.permits_peer_focus());
        for phase in [Phase::Possession, Phase::Assertion, Phase::Finished] {
            l.set_phase(phase);
            assert!(!l.permits_peer_focus());
        }
        l.set_phase(Phase::Collecting);
        assert!(l.permits_peer_focus());
        l.cancel();
        assert!(!l.permits_peer_focus());
    }
}
