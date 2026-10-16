//! Bounded admission before TLS or journal work; availability limits are explicit.
use crate::{AuthorityError, Result};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const MAX_PEERS: usize = 1024;
const PEER_BURST: u32 = 32;
const MAX_ACTIVE_PER_PEER: u32 = 2;
struct Peer {
    active: u32,
    tokens: u32,
    refill: Instant,
}
pub(crate) struct Admission {
    peers: Mutex<BTreeMap<IpAddr, Peer>>,
}
pub(crate) struct AdmissionGuard {
    state: Arc<Admission>,
    peer: IpAddr,
}
impl Admission {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            peers: Mutex::new(BTreeMap::new()),
        })
    }
    pub fn admit(self: &Arc<Self>, peer: IpAddr) -> Result<AdmissionGuard> {
        let now = Instant::now();
        let mut peers = self.peers.lock().map_err(|_| AuthorityError::Limit)?;
        peers.retain(|_, entry| {
            entry.active != 0 || now.duration_since(entry.refill) < Duration::from_secs(120)
        });
        if !peers.contains_key(&peer) && peers.len() >= MAX_PEERS {
            return Err(AuthorityError::Limit);
        }
        let entry = peers.entry(peer).or_insert(Peer {
            active: 0,
            tokens: PEER_BURST,
            refill: now,
        });
        let elapsed = now.duration_since(entry.refill).as_secs();
        if elapsed > 0 {
            entry.tokens = entry
                .tokens
                .saturating_add(elapsed.min(u64::from(PEER_BURST)) as u32)
                .min(PEER_BURST);
            entry.refill = now;
        }
        if entry.active >= MAX_ACTIVE_PER_PEER || entry.tokens == 0 {
            return Err(AuthorityError::Limit);
        }
        entry.tokens -= 1;
        entry.active += 1;
        Ok(AdmissionGuard {
            state: self.clone(),
            peer,
        })
    }
}
impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.state.peers.lock() {
            if let Some(entry) = peers.get_mut(&self.peer) {
                entry.active = entry.active.saturating_sub(1);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_concurrency_and_peer_rate_do_not_share_allowance() {
        let admission = Admission::new();
        let a = "127.0.0.1".parse().unwrap();
        let b = "127.0.0.2".parse().unwrap();
        let first = admission.admit(a).unwrap();
        let second = admission.admit(a).unwrap();
        assert!(admission.admit(a).is_err());
        assert!(admission.admit(b).is_ok());
        drop(first);
        drop(second);
        for _ in 0..30 {
            drop(admission.admit(a).unwrap());
        }
        assert!(admission.admit(a).is_err());
        assert!(admission.admit(b).is_ok());
    }
}
