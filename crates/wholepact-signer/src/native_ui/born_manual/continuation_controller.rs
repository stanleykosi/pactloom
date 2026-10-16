//! Used by the actual UI; inert phase state never creates native permission.
use crate::{Error, Result};
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Phase {
    #[default]
    Closed,
    Ready,
    ExportOnly,
    Queued,
    Reviewed,
    Acquiring,
    Published,
}
#[derive(Default)]
pub(super) struct ContinuationController {
    phase: Phase,
    original_ref: Option<String>,
    request_digest: Option<String>,
}
impl ContinuationController {
    pub(super) fn opened(&mut self, original_ref: String) -> Result<()> {
        if self.phase != Phase::Closed {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Ready;
        self.original_ref = Some(original_ref);
        Ok(())
    }
    pub(super) fn can_propose(&self) -> bool {
        self.phase == Phase::Ready
    }
    pub(super) fn retained_proposal(&mut self) -> Result<()> {
        if self.phase != Phase::Ready {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::ExportOnly;
        Ok(())
    }
    pub(super) fn queue(&mut self, digest: String) -> Result<()> {
        if self.phase != Phase::Ready {
            return Err(Error::ReviewMismatch);
        }
        self.request_digest = Some(digest);
        self.phase = Phase::Queued;
        Ok(())
    }
    pub(super) fn queued(&self) -> bool {
        self.phase == Phase::Queued
    }
    pub(super) fn reviewed(&mut self) -> Result<()> {
        if self.phase != Phase::Queued {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Reviewed;
        Ok(())
    }
    pub(super) fn can_acquire(&self) -> bool {
        self.phase == Phase::Reviewed
            && self.original_ref.is_some()
            && self.request_digest.is_some()
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
    pub(super) fn clear(&mut self) {
        self.phase = Phase::Closed;
        self.original_ref = None;
        self.request_digest = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_export_requires_fresh_entry_and_new_review() {
        let mut c = ContinuationController::default();
        c.opened("original".into()).unwrap();
        c.retained_proposal().unwrap();
        assert!(c.queue("exact-v2".into()).is_err());
        assert!(!c.can_acquire());
        c.clear();
        c.opened("original".into()).unwrap();
        c.queue("exact-v2".into()).unwrap();
        assert!(!c.can_acquire());
        c.reviewed().unwrap();
        assert!(c.can_acquire());
        c.begin_acquire().unwrap();
        assert!(c.begin_acquire().is_err());
    }
    #[test]
    fn continuation_blur_discards_review_and_queue() {
        let mut c = ContinuationController::default();
        c.opened("original".into()).unwrap();
        c.queue("exact-v2".into()).unwrap();
        c.reviewed().unwrap();
        c.clear();
        assert!(!c.can_acquire());
        assert!(c.reviewed().is_err());
        assert!(c.begin_acquire().is_err());
    }
}
