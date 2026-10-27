//! Qualification-only fail-stop AFTER durable intake and BEFORE Finish ACK.
//! This owns no permission, changes no deadline, and never manufactures success.
use crate::{Error, Result};
use std::{sync::Mutex, time::{Duration, Instant}};

pub(super) const MARKER: &str = "SYNTHETIC_DURABLE_RESULT_INTAKE_ACK_PENDING_V2=1";
struct Arm { account: String, key: String, cutoff: Instant }
struct Latch { used: bool, pending: Option<Arm> }
impl Latch {
    fn arm(&mut self, account: &str, key: &str, cutoff: Instant) -> Result<()> {
        crate::id(account)?; crate::id(key)?;
        if self.used || Instant::now() >= cutoff { return Err(Error::Permission); }
        self.used = true;
        self.pending = Some(Arm { account: account.into(), key: key.into(), cutoff });
        Ok(())
    }
    fn consume(&mut self, account: &str, key: &str) -> Result<Option<Arm>> {
        let Some(arm) = self.pending.take() else { return Ok(None); };
        if arm.account != account || arm.key != key || Instant::now() >= arm.cutoff {
            return Err(Error::Authentication);
        }
        Ok(Some(arm))
    }
}
static LATCH: Mutex<Latch> = Mutex::new(Latch { used: false, pending: None });
pub(super) fn arm_once(account: &str, key: &str, original_outer_cutoff: Instant) -> Result<()> {
    LATCH.lock().map_err(|_| Error::Locked)?.arm(account, key, original_outer_cutoff)
}
pub(super) fn after_committed_intake(account: &str, key: &str) -> Result<()> {
    let arm = LATCH.lock().map_err(|_| Error::Locked)?.consume(account, key)?;
    let Some(arm) = arm else { return Ok(()); };
    // The supervisor recognizes only this exact complete line, then kills the
    // owned group. No result, account, key, timestamp or capability is printed.
    eprintln!("{MARKER}");
    while let Some(remaining) = arm.cutoff.checked_duration_since(Instant::now()) {
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
    // If the supervisor does not kill us, fail. NEVER fall through to Finish.
    Err(Error::Receipt("qualification stopped after committed intake before acknowledgement".into()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intake_ack_fault_latch_is_one_shot_exact_and_rejects_elapsed_arm() {
        let mut latch = Latch { used: false, pending: None };
        assert!(latch.consume("owner", "key").unwrap().is_none());
        let deadline = Instant::now() + Duration::from_secs(30);
        latch.arm("owner", "key", deadline).unwrap();
        assert!(latch.arm("owner", "key", deadline).is_err());
        assert!(latch.consume("other", "key").is_err());
        assert!(latch.pending.is_none());
        assert!(latch.arm("owner", "key", deadline).is_err());
        let mut expired = Latch { used: false, pending: None };
        assert!(expired.arm("owner", "key", Instant::now()).is_err());
        let mut exact = Latch { used: false, pending: None };
        exact.arm("owner", "key", deadline).unwrap();
        assert_eq!(exact.consume("owner", "key").unwrap().unwrap().cutoff, deadline);
    }
}
