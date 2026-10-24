//! Synthetic passive history service restriction only. Not an action, lease,
//! approval, journal constructor, transferable capability or fresh source clock.
use super::*;

/// Captured once before live-full fixture READY. No Clone, serde or raw fields.
/// Each account's already authenticated ledger independently narrows this cap.
pub struct EphemeralCoordinatedHistoryLifetimeV1 {
    deadline: Instant,
    captured_at: Instant,
    wall_floor_ms: u64,
    source_expires_at_ms: u64,
    owner_revoked: Arc<AtomicBool>,
}
impl EphemeralCoordinatedHistoryLifetimeV1 {
    pub(super) fn capture_at(owner_revoked: Arc<AtomicBool>, original_cutoff: Instant,
        source_expires_at_ms: u64, now: Instant, wall_ms: u64) -> Result<Self> {
        let remaining = original_cutoff.checked_duration_since(now).ok_or(AuthorityError::Expired)?;
        if remaining.is_zero() || remaining > Duration::from_secs(900)
            || owner_revoked.load(Ordering::Acquire) || wall_ms >= source_expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        let wall_end = now.checked_add(Duration::from_millis(source_expires_at_ms-wall_ms))
            .ok_or(AuthorityError::Expired)?;
        Ok(Self {deadline: original_cutoff.min(wall_end), captured_at: now, wall_floor_ms: wall_ms,
            source_expires_at_ms, owner_revoked})
    }
    pub(super) fn for_policy_at(&self, owner_revoked: &Arc<AtomicBool>,
        policy_expires_at_ms: u64, now: Instant, wall_ms: u64) -> Result<ScopedHistoryClockV1> {
        let expires_at_ms = self.source_expires_at_ms.min(policy_expires_at_ms);
        if !Arc::ptr_eq(&self.owner_revoked, owner_revoked)
            || owner_revoked.load(Ordering::Acquire) || now >= self.deadline
            || wall_ms < self.wall_floor_ms || wall_ms >= expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        let policy_end = self.captured_at.checked_add(Duration::from_millis(expires_at_ms-self.wall_floor_ms))
            .ok_or(AuthorityError::Expired)?;
        if now >= policy_end { return Err(AuthorityError::Expired); }
        Ok(ScopedHistoryClockV1 {deadline:self.deadline.min(policy_end),
            last_wall_ms:wall_ms, expires_at_ms, owner_revoked:owner_revoked.clone()})
    }
}
// Per-thread, monotone wall check: no shared load/sample publication race.
pub(super) struct ScopedHistoryClockV1 {
    deadline: Instant,
    last_wall_ms: u64,
    expires_at_ms: u64,
    owner_revoked: Arc<AtomicBool>,
}
impl ScopedHistoryClockV1 {
    pub(super) fn deadline(&self) -> Instant { self.deadline }
    pub(super) fn check_current(&mut self) -> Result<()> {
        self.check_at(Instant::now(), crate::now_ms()?)
    }
    fn check_at(&mut self, now: Instant, wall_ms: u64) -> Result<()> {
        if self.owner_revoked.load(Ordering::Acquire) || now >= self.deadline
            || wall_ms < self.last_wall_ms || wall_ms >= self.expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        self.last_wall_ms = wall_ms;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner()->Arc<AtomicBool>{Arc::new(AtomicBool::new(false))}
    #[test]
    fn fixed_service_survives_121_without_renewing_original_cutoff() {
        let now=Instant::now(); let owner=owner();
        let lifetime=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),now+Duration::from_secs(500),900_000,now,1000).unwrap();
        let mut first=lifetime.for_policy_at(&owner,900_000,now,1000).unwrap();
        assert!(first.check_at(now+Duration::from_secs(121),122_000).is_ok());
        let mut audit=lifetime.for_policy_at(&owner,900_000,now+Duration::from_secs(400),401_000).unwrap();
        assert_eq!(first.deadline(),audit.deadline());
        assert!(audit.check_at(now+Duration::from_secs(500),501_000).is_err());
    }
    #[test]
    fn original_source_and_actual_policy_caps_only_narrow() {
        let now=Instant::now(); let owner=owner();
        let lifetime=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),now+Duration::from_secs(800),301_000,now,1000).unwrap();
        assert_eq!(lifetime.deadline,now+Duration::from_secs(300));
        let mut policy=lifetime.for_policy_at(&owner,201_000,now,1000).unwrap();
        assert_eq!(policy.deadline(),now+Duration::from_secs(200));
        assert!(policy.check_at(now+Duration::from_secs(199),200_000).is_ok());
        assert!(policy.check_at(now+Duration::from_secs(200),201_000).is_err());
    }
    #[test]
    fn expired_zero_or_oversized_original_cutoff_is_refused() {
        let now=Instant::now();
        for cutoff in [now-Duration::from_nanos(1),now,now+Duration::from_secs(901)] {
            assert!(EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner(),cutoff,900_000,now,1000).is_err());
        }
        assert!(EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner(),now+Duration::from_secs(900),1000,now,1000).is_err());
        assert!(EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner(),now+Duration::from_secs(900),900_001,now,1).is_ok());
    }
    #[test]
    fn wrong_owner_and_owner_drop_revoke_existing_scope() {
        let now=Instant::now();let owner=owner();
        let lifetime=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),now+Duration::from_secs(500),900_000,now,1000).unwrap();
        assert!(lifetime.for_policy_at(&Arc::new(AtomicBool::new(false)),900_000,now,1000).is_err());
        let mut scope=lifetime.for_policy_at(&owner,900_000,now,1000).unwrap();
        owner.store(true,Ordering::Release);
        assert!(scope.check_at(now,1000).is_err());
        assert!(lifetime.for_policy_at(&owner,900_000,now,1000).is_err());
    }
    #[test]
    fn wall_rollback_and_expiry_refuse_without_refresh() {
        let now=Instant::now();let owner=owner();
        let lifetime=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),now+Duration::from_secs(500),501_000,now,1000).unwrap();
        assert!(lifetime.for_policy_at(&owner,501_000,now,999).is_err());
        let mut scope=lifetime.for_policy_at(&owner,501_000,now,1000).unwrap();
        assert!(scope.check_at(now+Duration::from_secs(1),2000).is_ok());
        assert!(scope.check_at(now+Duration::from_secs(1),1999).is_err());
        assert!(scope.check_at(now+Duration::from_secs(2),501_000).is_err());
    }
    #[test]
    fn later_stage_wall_drift_cannot_refresh_narrower_policy_cap() {
        let now=Instant::now();let owner=owner();
        let lifetime=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),now+Duration::from_secs(800),901_000,now,1000).unwrap();
        let first=lifetime.for_policy_at(&owner,301_000,now,1000).unwrap();
        let later=lifetime.for_policy_at(&owner,301_000,now+Duration::from_secs(200),101_000).unwrap();
        assert_eq!(first.deadline(),later.deadline());
        assert_eq!(first.deadline(),now+Duration::from_secs(300));
        assert!(lifetime.for_policy_at(&owner,301_000,now+Duration::from_secs(300),201_000).is_err());
    }
    #[test]
    fn late_stage_cannot_restart_expired_fixture_or_source() {
        let now=Instant::now();let owner=owner();
        let lifetime=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),now+Duration::from_secs(400),501_000,now,1000).unwrap();
        assert!(lifetime.for_policy_at(&owner,900_000,now+Duration::from_secs(400),401_000).is_err());
        assert!(lifetime.for_policy_at(&owner,900_000,now+Duration::from_secs(399),501_000).is_err());
    }
}
