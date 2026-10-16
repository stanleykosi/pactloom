//! Keyless pairing rehearsal. It never creates an IPC capability or OS process.
//! The real launcher must supply a qualified sandbox instance; a label or PID
//! supplied by an app never supplies that identity.
use crate::{Error, Result};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    Reviewing,
}
struct Pending {
    generation: u64,
    instance: [u8; 32],
    name: String,
}
pub(super) struct PairingState {
    stage: Stage,
    generation: u64,
    pending: Option<Pending>,
    grants: BTreeMap<String, DemoGrant>,
}
pub(super) struct DemoGrant {
    pub name: String,
    pub instance: String,
    expires: Instant,
}
impl PairingState {
    pub(super) fn new() -> Self {
        Self {
            stage: Stage::Idle,
            generation: 0,
            pending: None,
            grants: BTreeMap::new(),
        }
    }
    pub(super) fn begin_local_rehearsal(&mut self) -> Result<()> {
        self.cancel();
        self.pending = Some(Pending {
            generation: self.generation,
            instance: crate::vault::random()?,
            name: "Synthetic Workspace".into(),
        });
        self.stage = Stage::Reviewing;
        Ok(())
    }
    pub(super) fn is_reviewing(&self) -> bool {
        self.stage == Stage::Reviewing
    }
    pub(super) fn confirm_local_rehearsal(&mut self) -> Result<()> {
        let pending = self.pending.take().ok_or(Error::ReviewMismatch)?;
        if self.stage != Stage::Reviewing || pending.generation != self.generation {
            return Err(Error::ReviewMismatch);
        }
        let instance = hex::encode(pending.instance);
        self.grants.insert(
            instance.clone(),
            DemoGrant {
                name: pending.name,
                instance,
                expires: Instant::now() + Duration::from_secs(900),
            },
        );
        self.stage = Stage::Idle;
        Ok(())
    }
    pub(super) fn grants(&self) -> impl Iterator<Item = &DemoGrant> {
        self.grants.values().filter(|g| Instant::now() < g.expires)
    }
    pub(super) fn revoke(&mut self, instance: &str) {
        self.grants.remove(instance);
    }
    pub(super) fn cancel(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.pending = None;
        self.stage = Stage::Idle;
    }
    pub(super) fn lock(&mut self) {
        self.cancel();
        self.grants.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_needs_distinct_local_actions_and_revokes_on_lock() {
        let mut p = PairingState::new();
        assert!(p.confirm_local_rehearsal().is_err());
        p.begin_local_rehearsal().unwrap();
        p.confirm_local_rehearsal().unwrap();
        assert_eq!(p.grants().count(), 1);
        assert!(p.confirm_local_rehearsal().is_err());
        let instance = p.grants().next().unwrap().instance.clone();
        p.revoke(&instance);
        assert_eq!(p.grants().count(), 0);
        p.begin_local_rehearsal().unwrap();
        p.lock();
        assert!(p.confirm_local_rehearsal().is_err());
        assert_eq!(p.grants().count(), 0);
    }
    #[test]
    fn expiration_and_replacement_fail_closed() {
        let mut p = PairingState::new();
        p.begin_local_rehearsal().unwrap();
        let old = p.pending.as_ref().unwrap().instance;
        p.begin_local_rehearsal().unwrap();
        assert_ne!(old, p.pending.as_ref().unwrap().instance);
        p.confirm_local_rehearsal().unwrap();
        for grant in p.grants.values_mut() {
            grant.expires = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(p.grants().count(), 0);
    }
}
