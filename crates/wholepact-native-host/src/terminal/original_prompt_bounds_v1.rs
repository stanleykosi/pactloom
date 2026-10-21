//! Cached original prompt restrictions only, never an approval or source owner.
use crate::{Error, Result};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
pub(crate) struct OriginalPromptBoundsV1 {
    deadline: Instant,
    from_ms: u64,
    until_ms: u64,
}
impl OriginalPromptBoundsV1 {
    pub(crate) fn new(deadline: Instant, (from_ms, until_ms): (u64, u64)) -> Result<Self> {
        if from_ms >= until_ms { return Err(Error::Permission); }
        Ok(Self { deadline, from_ms, until_ms })
    }
    pub(crate) fn narrow_deadline(self, deadline: Instant) -> Self { Self { deadline: self.deadline.min(deadline), ..self } }
    pub(crate) fn narrow_until(self, until_ms: u64) -> Result<Self> {
        self.narrow_wall((self.from_ms, until_ms))
    }
    pub(crate) fn narrow_wall(self, (from_ms, until_ms): (u64, u64)) -> Result<Self> {
        Self::new(self.deadline, (self.from_ms.max(from_ms), self.until_ms.min(until_ms)))
    }
    pub(super) fn deadline(&self) -> Instant { self.deadline }
    pub(crate) fn check(&self) -> Result<()> {
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Permission)?.as_millis()).map_err(|_| Error::Permission)?;
        self.check_at(Instant::now(), now)
    }
    fn check_at(&self, monotonic: Instant, wall_ms: u64) -> Result<()> {
        if monotonic >= self.deadline || wall_ms < self.from_ms || wall_ms >= self.until_ms {
            return Err(Error::Permission);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_prompt_bounds_only_narrow_and_preserve_both_clocks() {
        let start = Instant::now();
        let end = start + std::time::Duration::from_secs(10);
        let original = OriginalPromptBoundsV1::new(end, (100, 200)).unwrap();
        let narrowed = original.narrow_deadline(end + std::time::Duration::from_secs(10))
            .narrow_wall((50, 300)).unwrap();
        assert_eq!(narrowed.deadline, end);
        assert!(narrowed.check_at(start, 100).is_ok());
        assert!(narrowed.check_at(start, 199).is_ok());
        assert!(narrowed.check_at(start, 99).is_err());
        assert!(narrowed.check_at(start, 200).is_err());
        assert!(narrowed.check_at(end, 150).is_err());
        assert!(original.narrow_wall((200, 300)).is_err());
        assert!(original.narrow_until(150).unwrap().check_at(start, 150).is_err());
    }
}
