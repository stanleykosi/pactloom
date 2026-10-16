//! One-use native delivery approval. The original terminal mutex remains held
//! through disclosure; checks/output use private duplicates of that same TTY.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) struct HistoricalApproval {
    terminal: Terminal,
    foreground_file: File,
    deadline: Instant,
    spent: AtomicBool,
}
impl HistoricalApproval {
    /// Restriction-only monotonic bound, never an approval constructor.
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    pub(crate) fn check(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        foreground(&self.foreground_file)
    }
    #[cfg(test)]
    pub(crate) fn denied_for_test(expired: bool) -> Self {
        // Negative only: a regular file cannot satisfy foreground(), so this
        // helper can never admit private reads, output or a production owner.
        let terminal = Terminal::disconnected_for_test();
        let foreground_file = terminal.0.lock().unwrap().try_clone().unwrap();
        Self {
            terminal,
            foreground_file,
            deadline: if expired {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(120)
            },
            spent: AtomicBool::new(false),
        }
    }
    pub(crate) fn effect(&self, effect: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if self.spent.swap(true, Ordering::AcqRel) {
            return Err(Error::Permission);
        }
        let held = self.terminal.0.lock().map_err(|_| Error::Terminal)?;
        self.check()?;
        foreground(&held)?;
        let result = effect();
        drop(held);
        result
    }
}

/// Kept private to native composition. This cannot redirect output to another
/// recipient; a regular file, pipe or disconnected terminal is rejected.
pub(crate) struct HistoricalOutput(Mutex<File>);
impl HistoricalOutput {
    pub(crate) fn json<T: serde::Serialize>(&self, value: &T) -> Result<()> {
        self.json_checked(value, || Ok(()))
    }
    /// Render before acquiring the output lock, then check the exact owner's
    /// restrictions at each write admission. The check must not relock Terminal.
    /// Bytes already accepted by a blocking OS write cannot be recalled.
    pub(crate) fn json_checked<T: serde::Serialize>(
        &self,
        value: &T,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_string(value)?);
        if bytes.len() > wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES {
            return Err(Error::Invalid);
        }
        let rendered = sanitize(&bytes);
        if rendered.len().checked_add(1).is_none_or(|length| length > wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES) {
            return Err(Error::Invalid);
        }
        let mut file = self.0.lock().map_err(|_| Error::Terminal)?;
        check()?;
        foreground(&file)?;
        file.write_all(rendered.as_bytes())?;
        check()?;
        foreground(&file)?;
        file.write_all(b"\n")?;
        check()?;
        foreground(&file)?;
        file.flush()?;
        Ok(())
    }
}
impl Terminal {
    pub(crate) fn historical_output(&self) -> Result<HistoricalOutput> {
        let file = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(HistoricalOutput(Mutex::new(file.try_clone()?)))
    }
    /// Display an exact private scope only while its initial review remains
    /// valid on this same terminal, checked under the original terminal lock.
    pub(crate) fn approve_historical_reviewed(
        &self,
        prior: &HistoricalApproval,
        detail: &str,
    ) -> Result<HistoricalApproval> {
        if !Arc::ptr_eq(&self.0, &prior.terminal.0) {
            return Err(Error::Permission);
        }
        self.confirm_checked(detail, || prior.check())?;
        prior.check()?;
        let file = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(HistoricalApproval {
            terminal: self.clone(),
            foreground_file: file.try_clone()?,
            deadline: Instant::now() + Duration::from_secs(120),
            spent: AtomicBool::new(false),
        })
    }
    /// Reveal exact protected roster metadata only under its original same-TTY
    /// historical approval. Neither this prompt nor its wait renews that scope.
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub(crate) fn approve_publication_reviewed(
        &self,
        prior: &HistoricalApproval,
        manifest_digest: &str,
        detail: &str,
    ) -> Result<PublicationApproval> {
        if !Arc::ptr_eq(&self.0, &prior.terminal.0) {
            return Err(Error::Permission);
        }
        if manifest_digest.len() != 64
            || !manifest_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        self.confirm_checked(detail, || prior.check())?;
        prior.check()?;
        Ok(PublicationApproval {
            terminal: self.clone(),
            foreground_file: prior.foreground_file.try_clone()?,
            manifest_digest: manifest_digest.into(),
            deadline: prior
                .deadline
                .min(Instant::now() + Duration::from_secs(300)),
        })
    }
    pub(crate) fn approve_historical(&self, detail: &str) -> Result<HistoricalApproval> {
        self.confirm(detail)?;
        let file = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(HistoricalApproval {
            terminal: self.clone(),
            foreground_file: file.try_clone()?,
            deadline: Instant::now() + Duration::from_secs(120),
            spent: AtomicBool::new(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_deadline_and_disconnect_never_deliver() {
        for expired in [false, true] {
            let terminal = Terminal::disconnected_for_test();
            let foreground_file = terminal.0.lock().unwrap().try_clone().unwrap();
            // Negative fixture only: no terminal approval can be minted from
            // this regular file. Both deadline and disconnect deny the effect.
            let approval = HistoricalApproval {
                terminal,
                foreground_file,
                deadline: if expired {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_secs(120)
                },
                spent: AtomicBool::new(false),
            };
            let mut called = false;
            assert!(approval
                .effect(&mut || {
                    called = true;
                    Ok(())
                })
                .is_err());
            assert!(!called);
            assert!(approval
                .effect(&mut || {
                    called = true;
                    Ok(())
                })
                .is_err());
            assert!(!called);
        }
    }
    #[test]
    fn expired_or_disconnected_initial_review_never_discloses_scope_metadata() {
        for expired in [false, true] {
            let terminal = Terminal::disconnected_for_test();
            let foreground_file = terminal.0.lock().unwrap().try_clone().unwrap();
            let approval = HistoricalApproval {
                terminal,
                foreground_file,
                deadline: if expired {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_secs(120)
                },
                spent: AtomicBool::new(false),
            };
            let mut sink = tempfile::tempfile().unwrap();
            let mut disclosure_entered = false;
            assert!(approval
                .effect(&mut || {
                    disclosure_entered = true;
                    sink.write_all(b"synthetic private lineage metadata")?;
                    Ok(())
                })
                .is_err());
            assert!(!disclosure_entered);
            assert_eq!(sink.metadata().unwrap().len(), 0);
        }
    }
    #[test]
    fn exact_private_scope_rejects_expired_review_and_different_terminal() {
        let terminal = Terminal::disconnected_for_test();
        let foreground_file = terminal.0.lock().unwrap().try_clone().unwrap();
        let prior = HistoricalApproval {
            terminal: terminal.clone(),
            foreground_file,
            deadline: Instant::now(),
            spent: AtomicBool::new(true),
        };
        assert!(terminal
            .approve_historical_reviewed(&prior, "synthetic private scope")
            .is_err());
        assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
        let other = Terminal::disconnected_for_test();
        assert!(matches!(
            other.approve_historical_reviewed(&prior, "synthetic private scope"),
            Err(Error::Permission)
        ));
        assert_eq!(other.0.lock().unwrap().metadata().unwrap().len(), 0);
    }
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    #[test]
    fn roster_publication_review_never_discloses_after_expiry_or_terminal_rebind() {
        let terminal = Terminal::disconnected_for_test();
        let prior = HistoricalApproval {
            foreground_file: terminal.0.lock().unwrap().try_clone().unwrap(),
            terminal: terminal.clone(),
            deadline: Instant::now(),
            spent: AtomicBool::new(true),
        };
        assert!(terminal
            .approve_publication_reviewed(&prior, &"a".repeat(64), "synthetic private roster")
            .is_err());
        assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
        let other = Terminal::disconnected_for_test();
        assert!(matches!(
            other.approve_publication_reviewed(&prior, &"a".repeat(64), "synthetic private roster"),
            Err(Error::Permission)
        ));
        assert_eq!(other.0.lock().unwrap().metadata().unwrap().len(), 0);
        assert!(matches!(
            terminal.approve_publication_reviewed(&prior, "invalid", "synthetic private roster"),
            Err(Error::Invalid)
        ));
        assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
    }
    #[test]
    fn historical_rendered_output_bound_includes_escaped_unicode() {
        let output = HistoricalOutput(Mutex::new(tempfile::tempfile().unwrap()));
        let text = "é".repeat(24_000);
        assert!(serde_json::to_string(&text).unwrap().len() < 128 * 1024);
        assert!(matches!(output.json(&text), Err(Error::Invalid)));
        assert_eq!(output.0.lock().unwrap().metadata().unwrap().len(), 0);
    }
    #[test]
    fn serialization_invalidation_denies_after_output_lock_without_delivering_bytes() {
        use std::cell::Cell;
        struct Invalidates<'a>(&'a Cell<bool>);
        impl serde::Serialize for Invalidates<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                self.0.set(false);
                serializer.serialize_str("synthetic restricted metadata")
            }
        }
        let output = HistoricalOutput(Mutex::new(tempfile::tempfile().unwrap()));
        let current = Cell::new(true);
        let checks = Cell::new(0);
        assert!(matches!(
            output.json_checked(&Invalidates(&current), || {
                checks.set(checks.get() + 1);
                // The restriction runs only after rendering and taking the
                // output mutex. It denies before any foreground/write attempt.
                assert!(matches!(
                    output.0.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                if current.get() {
                    Ok(())
                } else {
                    Err(Error::Permission)
                }
            }),
            Err(Error::Permission)
        ));
        assert_eq!(checks.get(), 1);
        assert!(!current.get());
        assert_eq!(output.0.lock().unwrap().metadata().unwrap().len(), 0);
        // A successful restriction check still cannot turn this regular file
        // into native delivery authority: the real foreground guard denies it.
        assert!(matches!(
            output.json_checked(&"synthetic restricted metadata", || Ok(())),
            Err(Error::Terminal)
        ));
        assert_eq!(output.0.lock().unwrap().metadata().unwrap().len(), 0);
    }
    #[test]
    fn historical_delivery_requires_real_foreground_terminal() {
        let terminal = Terminal::disconnected_for_test();
        assert!(matches!(terminal.historical_output(), Err(Error::Terminal)));
        assert!(matches!(
            terminal.approve_historical("synthetic denied review"),
            Err(Error::Terminal)
        ));
    }
}
