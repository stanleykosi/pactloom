//! GUI-owned revocation and exact one-shot worker admission. All I/O executes on
//! one private worker while the GUI continues processing focus/cancel/close.
//!
//! OPEN -> REVOKED and OPEN -> PUBLISHING are the linearization race. If revoke
//! wins, no publication can start. If publication wins, that one exact bounded
//! final action may drain; later blur must be reported as in-flight, not canceled.
//! No OS fsync wall-time bound is claimed. There are no generic execution closures.
use crate::{AuthorityError, Result};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

const OPEN: u8 = 0;
const REVOKED: u8 = 1;
const PUBLISHING: u8 = 2;
const FINISHED: u8 = 3;
const MAX_REVIEW_LIFETIME: Duration = Duration::from_secs(120);

struct NativeState {
    phase: AtomicU8,
    revoke_requested: AtomicBool,
    publication_started: AtomicBool,
}

pub(super) struct NativeOwner {
    state: Arc<NativeState>,
    _gui_thread_only: PhantomData<Rc<()>>,
}
impl NativeOwner {
    pub(super) fn entered_window() -> Self {
        Self {
            state: Arc::new(NativeState {
                phase: AtomicU8::new(OPEN),
                revoke_requested: AtomicBool::new(false),
                publication_started: AtomicBool::new(false),
            }),
            _gui_thread_only: PhantomData,
        }
    }
    pub(super) fn is_open(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == OPEN
    }
    pub(super) fn publication_in_flight(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == PUBLISHING
    }
    pub(super) fn publication_started(&self) -> bool {
        self.state.publication_started.load(Ordering::Acquire)
    }
    pub(super) fn revoke_requested(&self) -> bool {
        self.state.revoke_requested.load(Ordering::Acquire)
    }
    pub(super) fn revoke(&self) {
        // Never wait for a lock held by a worker or any filesystem operation.
        let _ =
            self.state
                .phase
                .compare_exchange(OPEN, REVOKED, Ordering::AcqRel, Ordering::Acquire);
        self.state.revoke_requested.store(true, Ordering::Release);
    }
    // Only a real final-click token from window.rs can produce worker authority.
    pub(super) fn accept_final_click(
        &self,
        click: super::window::FinalPrimaryClick,
    ) -> Result<NativeWorkerLease> {
        let (review_digest, clock) = click.into_parts();
        if !self.is_open() {
            return Err(AuthorityError::Permission);
        }
        clock.check()?;
        Ok(NativeWorkerLease {
            state: self.state.clone(),
            review_digest,
            clock,
        })
    }
}
impl Drop for NativeOwner {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Data-only clock cannot grant native authority. A completed original audit
/// retry can omit the first-commit deadline only after backend authentication.
// Cloning this data-only clock retains the original deadline and monotonic start;
// it never renews the review or duplicates a native approval capability.
#[derive(Clone)]
pub(super) struct ReviewClock {
    prepared_at_ms: u64,
    first_commit_deadline_ms: Option<u64>,
    started: Instant,
    lifetime: Duration,
}
impl ReviewClock {
    pub(super) fn start(first_commit_deadline_ms: Option<u64>) -> Result<Self> {
        let now = crate::now_ms()?;
        Self::at(now, first_commit_deadline_ms)
    }
    fn at(now: u64, first_commit_deadline_ms: Option<u64>) -> Result<Self> {
        let lifetime = match first_commit_deadline_ms {
            Some(deadline) => Duration::from_millis(
                deadline
                    .checked_sub(now)
                    .filter(|n| *n > 0)
                    .ok_or(AuthorityError::Expired)?,
            )
            .min(MAX_REVIEW_LIFETIME),
            None => MAX_REVIEW_LIFETIME,
        };
        Ok(Self {
            prepared_at_ms: now,
            first_commit_deadline_ms,
            started: Instant::now(),
            lifetime,
        })
    }
    fn check_at(&self, now: u64, elapsed: Duration) -> Result<()> {
        if now < self.prepared_at_ms
            || elapsed >= self.lifetime
            || self
                .first_commit_deadline_ms
                .is_some_and(|deadline| now >= deadline)
        {
            Err(AuthorityError::Expired)
        } else {
            Ok(())
        }
    }
    pub(super) fn check(&self) -> Result<()> {
        self.check_at(crate::now_ms()?, self.started.elapsed())
    }
    /// Original monotonic bound only; never reconstructed from wire timestamps.
    #[cfg(any(feature = "coordinated-witness-delivery-append", feature = "coordinated-witness-financial-continuation"))]
    pub(super) fn original_deadline(&self) -> Instant { self.started + self.lifetime }
    /// Inert display bounds only. This does not renew the retained local clock.
    #[cfg(any(feature = "coordinated-witness-cancel-review", feature = "coordinated-witness-delivery-append", feature = "coordinated-witness-financial-continuation"))]
    pub(super) fn display_bounds(&self) -> Result<(u64, u64)> {
        let lifetime = u64::try_from(self.lifetime.as_millis())
            .map_err(|_| AuthorityError::Limit)?;
        let expires = self.prepared_at_ms.checked_add(lifetime)
            .ok_or(AuthorityError::Limit)?;
        Ok((self.prepared_at_ms, expires))
    }
}

/// Opaque exact one-shot admission from the actual focused primary-click branch.
/// No Clone/Serialize/Deserialize/Default, public constructor or bool adapter.
/// This can move to the private worker, but the NativeOwner stays in the GUI.
pub(crate) struct NativeWorkerLease {
    state: Arc<NativeState>,
    review_digest: String,
    clock: ReviewClock,
}
impl NativeWorkerLease {
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.state.phase.load(Ordering::Acquire) != OPEN {
            return Err(AuthorityError::Permission);
        }
        self.clock.check()
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.review_digest
    }
    /// Consume the only worker admission. The caller must first finish all
    /// preflight reads/locks and check the opaque proposal. The returned capability
    /// is only for its exact setup, birth or archive publication, never arbitrary
    /// work. Historical disclosure readers retain the revocable OPEN lease and
    /// must not promote it to a publication lease.
    pub(crate) fn publication_lease(self) -> Result<NativePublicationLease> {
        self.check_current()?;
        let admitted_at_ms = crate::now_ms()?;
        self.state
            .phase
            .compare_exchange(OPEN, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| AuthorityError::Permission)?;
        self.state
            .publication_started
            .store(true, Ordering::Release);
        let publication = NativePublicationLease {
            state: self.state,
            review_digest: self.review_digest,
            clock: self.clock,
            admitted_at_ms,
        };
        publication.check_current()?;
        Ok(publication)
    }
}

/// Owned, nonclone lease lets the reserved journal owner retain the exact native
/// source without a self-referential borrowed lock. The actual first-commit time
/// is captured by the journal under check_current, not copied from admission time.
pub(crate) struct NativePublicationLease {
    state: Arc<NativeState>,
    review_digest: String,
    clock: ReviewClock,
    admitted_at_ms: u64,
}
impl NativePublicationLease {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.review_digest
    }
    pub(crate) fn admitted_at_ms(&self) -> u64 {
        self.admitted_at_ms
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.state.phase.load(Ordering::Acquire) != PUBLISHING {
            return Err(AuthorityError::Permission);
        }
        // Focus revocation AFTER final admission cannot erase a potentially
        // committed journal. Its one exact operation may drain. Lifetime/deadline
        // remain checked at the first-commit boundary; uncertain writes stay
        // retained and require authenticated exact recovery, never a fresh init.
        self.clock.check()
    }
}
impl Drop for NativePublicationLease {
    fn drop(&mut self) {
        self.state.phase.store(FINISHED, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_view_clock_does_not_renew_the_original_review() {
        let original = ReviewClock::at(1_000, Some(2_000)).unwrap();
        let retained = original.clone();
        assert_eq!(retained.started, original.started);
        assert_eq!(retained.prepared_at_ms, original.prepared_at_ms);
        assert_eq!(
            retained.first_commit_deadline_ms,
            original.first_commit_deadline_ms
        );
        assert_eq!(retained.lifetime, original.lifetime);
        assert!(
            retained
                .check_at(2_000, Duration::from_millis(999))
                .is_err()
        );
        assert!(
            retained
                .check_at(1_999, Duration::from_millis(1_000))
                .is_err()
        );
    }
    #[test]
    fn modeled_clock_denies_deadline_rollback_and_monotonic_expiry() {
        let c = ReviewClock::at(1_000, Some(2_000)).unwrap();
        assert!(c.check_at(999, Duration::ZERO).is_err());
        assert!(c.check_at(2_000, Duration::from_millis(999)).is_err());
        assert!(c.check_at(1_500, Duration::from_millis(1_000)).is_err());
        assert!(ReviewClock::at(2_000, Some(2_000)).is_err());
        assert_eq!(
            ReviewClock::at(1_000, None).unwrap().lifetime,
            MAX_REVIEW_LIFETIME
        );
    }
    #[test]
    fn revoke_is_nonblocking_and_cannot_restore_open_state() {
        let owner = NativeOwner::entered_window();
        owner.revoke();
        owner.revoke();
        assert!(!owner.is_open());
        assert!(!owner.publication_in_flight());
        assert!(owner.revoke_requested());
        assert!(
            owner
                .state
                .phase
                .compare_exchange(OPEN, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        );
    }
    #[test]
    fn modeled_publication_race_has_one_winner_and_no_second_admission() {
        // State transitions only: no actual FinalPrimaryClick or worker lease.
        let owner = NativeOwner::entered_window();
        owner
            .state
            .phase
            .compare_exchange(OPEN, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .unwrap();
        owner.revoke();
        assert!(owner.publication_in_flight());
        assert!(owner.revoke_requested());
        assert!(
            owner
                .state
                .phase
                .compare_exchange(OPEN, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        );
        owner.state.phase.store(FINISHED, Ordering::Release);
        owner.revoke();
        assert!(!owner.is_open());
    }
}
