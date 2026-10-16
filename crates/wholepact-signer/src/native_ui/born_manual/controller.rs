//! Inert lifecycle controller used by the real UI. This is deliberately not a
//! native owner: every positive operation also needs its held opaque producer.
use crate::{Error, Result};
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Phase {
    #[default]
    Closed,
    InitialExport,
    AwaitExactRequest,
    Queued,
    ReentryReviewed,
    Acquiring,
    Published,
}
#[derive(Default)]
pub(super) struct BootstrapController {
    phase: Phase,
    original_ref: Option<String>,
}
impl BootstrapController {
    pub(super) fn opened(&mut self, retained: Option<String>) -> Result<()> {
        if self.phase != Phase::Closed {
            return Err(Error::ReviewMismatch);
        }
        self.phase = if retained.is_some() {
            Phase::AwaitExactRequest
        } else {
            Phase::InitialExport
        };
        self.original_ref = retained;
        Ok(())
    }
    pub(super) fn queue(&mut self) -> Result<()> {
        if self.phase != Phase::AwaitExactRequest {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Queued;
        Ok(())
    }
    pub(super) fn reviewed(&mut self) -> Result<()> {
        if self.phase != Phase::Queued {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::ReentryReviewed;
        Ok(())
    }
    pub(super) fn can_acquire(&self) -> bool {
        self.phase == Phase::ReentryReviewed && self.original_ref.is_some()
    }
    pub(super) fn begin_acquire(&mut self) -> Result<()> {
        if !self.can_acquire() {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Acquiring;
        Ok(())
    }
    pub(super) fn published(&mut self) -> Result<()> {
        if self.phase != Phase::Acquiring {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Published;
        Ok(())
    }
    pub(super) fn initial_export(&self) -> bool {
        self.phase == Phase::InitialExport
    }
    pub(super) fn clear(&mut self) {
        self.phase = Phase::Closed;
        self.original_ref = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_export_entry_can_never_acquire_or_upgrade_itself() {
        let mut c = BootstrapController::default();
        c.opened(None).unwrap();
        assert!(c.initial_export());
        assert!(!c.can_acquire());
        assert!(c.queue().is_err());
        assert!(c.reviewed().is_err());
        assert!(c.begin_acquire().is_err());
        assert!(c.opened(Some("original-ref".into())).is_err());
    }
    #[test]
    fn blur_invalidates_queue_and_review_then_fresh_retained_entry_is_required() {
        let mut c = BootstrapController::default();
        c.opened(Some("unchanged-ref".into())).unwrap();
        c.queue().unwrap();
        c.reviewed().unwrap();
        assert!(c.can_acquire());
        c.clear();
        assert!(!c.can_acquire());
        assert!(c.begin_acquire().is_err());
        assert!(c.queue().is_err());
        c.opened(Some("unchanged-ref".into())).unwrap();
        assert!(!c.can_acquire());
        c.queue().unwrap();
        c.reviewed().unwrap();
        assert!(c.can_acquire());
        assert_eq!(c.original_ref.as_deref(), Some("unchanged-ref"));
    }
    #[test]
    fn duplicate_queue_and_repeat_first_acquire_are_denied() {
        let mut c = BootstrapController::default();
        c.opened(Some("immutable-ref".into())).unwrap();
        assert!(c.begin_acquire().is_err());
        c.queue().unwrap();
        assert!(c.queue().is_err());
        assert!(c.begin_acquire().is_err());
        c.reviewed().unwrap();
        c.begin_acquire().unwrap();
        assert!(!c.can_acquire());
        assert!(c.begin_acquire().is_err());
        c.published().unwrap();
        assert!(c.queue().is_err());
    }
}
