//! New purpose-specific exact saved-job privacy/CPU decision, not renewal of
//! construction, witness, transport, source-observation or financial authority.
use super::historical::HistoricalApproval;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) struct BornSavedProofApprovalV1 {
    terminal: Terminal,
    foreground_file: File,
    exact_digest: String,
    deadline: Instant,
    spent: AtomicBool,
}
impl BornSavedProofApprovalV1 {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check(&self, exact_digest: &str) -> Result<()> {
        if self.exact_digest != exact_digest || Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        foreground(&self.foreground_file)
    }
    pub(crate) fn progress(&self, exact_digest: &str) -> Result<()> {
        self.check(exact_digest)?;
        let mut file = self.foreground_file.try_clone()?;
        write_current_until(&mut file,
            b"Original local proof work is active; no signing or dispatch is occurring.\n",
            Some(self.deadline), None,
        )?;
        file.flush()?;
        self.check(exact_digest)
    }
    /// One foreground effect owns the exact TTY until bounded CPU work drains.
    /// Expiry/foreground loss is checked by the proof journal before committing
    /// success; it cannot interrupt an already executing Halo2 call.
    pub(crate) fn effect<T>(
        &self,
        exact_digest: &str,
        effect: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if self.spent.swap(true, Ordering::AcqRel) {
            return Err(Error::Permission);
        }
        let terminal = self.terminal.0.lock().map_err(|_| Error::Terminal)?;
        self.check(exact_digest)?;
        foreground(&terminal)?;
        let result = effect();
        drop(terminal);
        result
    }
}
impl Terminal {
    /// Prior approval permits revealing selected source metadata at this prompt
    /// only. A NEW explicit decision grants the described exact saved-job reads,
    /// source-integrity rechecks, private retention and one first proof attempt
    /// for a fresh fixed one-hour deadline. No previous capability is renewed.
    pub(crate) fn approve_born_saved_proof_v1(
        &self,
        prior: &HistoricalApproval,
        exact_digest: &str,
        detail: &str,
    ) -> Result<BornSavedProofApprovalV1> {
        if exact_digest.len() != 64
            || !exact_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Permission);
        }
        // Reuse the canonical same-terminal/prior-checking prompt rather than
        // reading HistoricalApproval's private fields or accepting a bool.
        let reviewed = self.approve_historical_reviewed(prior, detail)?;
        reviewed.check()?;
        let file = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(BornSavedProofApprovalV1 {
            terminal: self.clone(),
            foreground_file: file.try_clone()?,
            exact_digest: exact_digest.into(),
            deadline: Instant::now() + Duration::from_secs(3600),
            spent: AtomicBool::new(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disconnected_expired_or_wrong_scope_never_starts_saved_proof() {
        for expired in [false, true] {
            let terminal = Terminal::disconnected_for_test();
            let file = terminal.0.lock().unwrap().try_clone().unwrap();
            let approval = BornSavedProofApprovalV1 {
                terminal,
                foreground_file: file,
                exact_digest: "a".repeat(64),
                deadline: if expired {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_secs(3600)
                },
                spent: AtomicBool::new(false),
            };
            assert!(approval.check(&"b".repeat(64)).is_err());
            let mut called = false;
            assert!(
                approval
                    .effect(&"a".repeat(64), || {
                        called = true;
                        Ok(())
                    })
                    .is_err()
            );
            assert!(!called);
            assert!(approval.effect(&"a".repeat(64), || Ok(())).is_err());
        }
    }
}
