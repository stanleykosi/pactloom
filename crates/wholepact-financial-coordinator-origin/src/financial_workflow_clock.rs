//! Fixed from-outset full-workflow supervision, never an action/material lease.
//! No runtime duration/profile selector and no constructor from received data.
#![allow(dead_code)] // Role conversion/packet consumers are a later reviewed slice.
use crate::{rejected, Result};
use std::time::{Duration, Instant};

pub(super) const PROFILE: &str = "coordinated-financial-workflow-v1";
pub(super) const SUPERVISION_MS: u64 = 1_800_000;
const STARTUP: Duration = Duration::from_secs(30);
const SUPERVISION: Duration = Duration::from_millis(SUPERVISION_MS);
const CLEANUP: Duration = Duration::from_secs(5);

/// Created once from the sole bootstrap's pre-fork epoch and inherited unchanged.
/// Copying this immutable record cannot move the epoch or any deadline forward.
#[derive(Clone, Copy)]
pub(super) struct FullWorkflowClocksV1 {
    epoch: Instant,
    startup: Instant,
    supervision: Instant,
    hard_cleanup: Instant,
}
impl FullWorkflowClocksV1 {
    pub(super) fn from_initial_epoch(epoch: Instant) -> Result<Self> {
        let startup = epoch.checked_add(STARTUP).ok_or_else(|| rejected("workflow startup overflow"))?;
        let supervision = epoch.checked_add(SUPERVISION).ok_or_else(|| rejected("workflow supervision overflow"))?;
        let hard_cleanup = supervision.checked_add(CLEANUP).ok_or_else(|| rejected("workflow cleanup overflow"))?;
        Ok(Self { epoch, startup, supervision, hard_cleanup })
    }
    pub(super) fn epoch(self) -> Instant { self.epoch }
    pub(super) fn startup(self) -> Instant { self.startup }
    pub(super) fn supervision(self) -> Instant { self.supervision }
    pub(super) fn hard_cleanup(self) -> Instant { self.hard_cleanup }
    /// Encode only the restrictive minimum; original source/material/review
    /// Instants remain separately owned at S and are NEVER rebuilt from this.
    pub(super) fn restrictive_offset(self, original: Instant, additional_cap: Instant) -> Result<u64> {
        let ceiling = original.min(additional_cap).min(self.supervision);
        let elapsed = ceiling.checked_duration_since(self.epoch).ok_or_else(|| rejected("workflow offset underflow"))?;
        let millis = u64::try_from(elapsed.as_millis()).map_err(|_| rejected("workflow offset overflow"))?;
        check_offset(PROFILE, millis)?;
        Ok(millis)
    }
    /// The profile is a required literal, not a selector. Received offsets use
    /// THIS retained epoch; exact actor/session/challenge matching is also
    /// required by the later finite channel consumer. Receive time never renews.
    pub(super) fn restrict_received(self, profile: &str, millis: u64, original_cap: Instant, now: Instant) -> Result<Instant> {
        check_offset(profile, millis)?;
        let from_epoch = self.epoch.checked_add(Duration::from_millis(millis)).ok_or_else(|| rejected("workflow offset overflow"))?;
        let deadline = from_epoch.min(original_cap).min(self.supervision);
        if deadline <= now { return Err(rejected("workflow original ceiling elapsed")); }
        Ok(deadline)
    }
    /// A cleanup attempt may only shorten the original hard ceiling. The caller
    /// stores its FIRST returned cutoff; repeated traffic must not call again.
    pub(super) fn first_cleanup_ceiling(self, now: Instant) -> Result<Instant> {
        let local = now.checked_add(CLEANUP).ok_or_else(|| rejected("workflow cleanup overflow"))?;
        let ceiling = local.min(self.hard_cleanup);
        if now >= ceiling { return Err(rejected("workflow cleanup elapsed")); }
        Ok(ceiling)
    }
}
fn check_offset(profile: &str, millis: u64) -> Result<()> {
    if profile != PROFILE || millis == 0 || millis > SUPERVISION_MS {
        return Err(rejected("invalid full-workflow profile or offset"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_full_workflow_clocks_share_one_original_epoch() {
        let epoch = Instant::now(); let clocks = FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();
        assert_eq!(clocks.epoch(), epoch);
        assert_eq!(clocks.startup() - epoch, Duration::from_secs(30));
        assert_eq!(clocks.supervision() - epoch, Duration::from_secs(1800));
        assert_eq!(clocks.hard_cleanup() - epoch, Duration::from_secs(1805));
        let copy = clocks;
        assert_eq!(copy.supervision(), clocks.supervision());
    }
    #[test]
    fn full_offsets_shorten_and_never_restart_at_receive() {
        let epoch = Instant::now(); let clocks = FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();
        let original = epoch + Duration::from_micros(120_000_999);
        let offset = clocks.restrictive_offset(original, clocks.supervision()).unwrap();
        assert_eq!(offset, 120000);
        let received = clocks.restrict_received(PROFILE, offset, original, epoch + Duration::from_secs(90)).unwrap();
        assert!(received <= original);
        assert_eq!(received, epoch + Duration::from_secs(120));
        assert!(clocks.restrict_received(PROFILE, offset, original, received).is_err());
        assert_eq!(clocks.restrict_received(PROFILE, offset, epoch + Duration::from_secs(100), epoch).unwrap(), epoch + Duration::from_secs(100));
        assert!(clocks.restrictive_offset(epoch, clocks.supervision()).is_err());
        assert!(clocks.restrict_received("coordinated-signer-continue", offset, original, epoch).is_err());
        assert!(clocks.restrict_received(PROFILE, SUPERVISION_MS + 1, original, epoch).is_err());
    }
    #[test]
    fn full_cleanup_is_capped_without_action_extension() {
        let epoch = Instant::now(); let clocks = FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();
        let first = clocks.first_cleanup_ceiling(epoch + Duration::from_secs(20)).unwrap();
        assert_eq!(first, epoch + Duration::from_secs(25));
        assert_eq!(clocks.first_cleanup_ceiling(clocks.supervision() + Duration::from_secs(3)).unwrap(), clocks.hard_cleanup());
        assert!(clocks.first_cleanup_ceiling(clocks.hard_cleanup()).is_err());
        let action = epoch + Duration::from_secs(21);
        assert!(clocks.restrict_received(PROFILE, 21000, action, action).is_err());
        assert!(first > action); // Disposal time is not a surviving action lease.
    }
}
