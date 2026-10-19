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
// BEGIN private fixed stage V3 kernels.
/// This is the exact fixed-width framing written by confirm_checked: eight
/// random bytes become sixteen hexadecimal digits. Bound the full escaped
/// review and framing together before admitting any private disclosure.
const PRIVATE_FIXED_STAGE_PROMPT_V3: &str =
    "\nType APPROVE 0000000000000000 to approve this exact operation, or anything else to reject: ";

fn bound_private_fixed_stage_review_v3(detail: &str) -> Result<()> {
    let maximum = wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES;
    if detail.len() > maximum
        || sanitize(detail)
            .len()
            .checked_add(PRIVATE_FIXED_STAGE_PROMPT_V3.len())
            .is_none_or(|length| length > maximum)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Shared ordering only; neither callback nor this kernel can create authority.
fn private_fixed_stage_disclosure_v3(
    mut inspection: impl FnMut() -> Result<()>,
    source: impl FnOnce() -> Result<()>,
) -> Result<()> {
    inspection()?;
    source()?;
    // Source validation may be expensive. Inspection must still authorize the
    // disclosure immediately after it, before confirm_checked writes bytes.
    inspection()
}

/// A genuine response starts the new fixed budget before source postchecks.
/// The returned value is inert checked data, not a native approval factory.
fn private_fixed_stage_response_v3<T>(
    review: impl FnOnce() -> Result<()>,
    after_response: impl FnOnce() -> Result<T>,
) -> Result<(Instant, T)> {
    review()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let checked = after_response()?;
    check_private_fixed_stage_deadline_v3(deadline)?;
    Ok((deadline, checked))
}

/// Restriction-only final gate; a supplied instant cannot construct approval.
fn check_private_fixed_stage_deadline_v3(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    Ok(())
}
// END private fixed stage V3 kernels.

// A distinct purpose-specific composition. These kernels return only checked
// data and cannot construct an approval or change an existing recipient window.
fn bound_durable_delivery_review_v2(detail: &str) -> Result<()> {
    let maximum = wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES;
    const PROMPT: &str = "\nType APPROVE 0000000000000000 to approve this exact operation, or anything else to reject: ";
    if detail.len() > maximum
        || sanitize(detail)
            .len()
            .checked_add(PROMPT.len())
            .is_none_or(|length| length > maximum)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn durable_delivery_disclosure_v2(
    mut inspection: impl FnMut() -> Result<()>,
    source: impl FnOnce() -> Result<()>,
) -> Result<()> {
    inspection()?;
    source()?;
    inspection()
}

fn durable_delivery_response_v2<T>(
    response: impl FnOnce() -> Result<()>,
    source: impl FnOnce() -> Result<T>,
) -> Result<(Instant, T)> {
    response()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let result = source()?;
    if Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    Ok((deadline, result))
}

impl Terminal {
    /// Separate original-delivery purpose. The completed inspection admits only
    /// disclosure of its exact review; it is never renewed into delivery power.
    /// Callbacks must check the actual source without re-locking this terminal.
    pub(crate) fn approve_durable_delivery_v2(
        &self,
        prior: &HistoricalApproval,
        detail: &str,
        before_disclosure: impl FnOnce() -> Result<()>,
        after_response: impl FnOnce() -> Result<()>,
    ) -> Result<HistoricalApproval> {
        if !Arc::ptr_eq(&self.0, &prior.terminal.0) {
            return Err(Error::Permission);
        }
        bound_durable_delivery_review_v2(detail)?;
        let (deadline, foreground_file) = durable_delivery_response_v2(
            || {
                self.confirm_checked(detail, || {
                    durable_delivery_disclosure_v2(|| prior.check(), before_disclosure)
                })
            },
            || {
                let file = self.0.lock().map_err(|_| Error::Terminal)?;
                foreground(&file)?;
                after_response()?;
                foreground(&file)?;
                Ok(file.try_clone()?)
            },
        )?;
        let approval = HistoricalApproval {
            terminal: self.clone(),
            foreground_file,
            deadline,
            spent: AtomicBool::new(false),
        };
        approval.check()?;
        Ok(approval)
    }
    // BEGIN private fixed stage V3 terminal issuer.
    /// Issue a separately reviewed closed private-fixed stage, never renew the
    /// inspection that permitted its disclosure. Both source callbacks are
    /// private admission checks and must not re-lock this Terminal.
    pub(crate) fn approve_private_fixed_stage_v3(
        &self,
        prior: &HistoricalApproval,
        detail: &str,
        before_disclosure: impl FnOnce() -> Result<()>,
        after_response: impl FnOnce() -> Result<()>,
    ) -> Result<HistoricalApproval> {
        if !Arc::ptr_eq(&self.0, &prior.terminal.0) {
            return Err(Error::Permission);
        }
        bound_private_fixed_stage_review_v3(detail)?;
        let (deadline, foreground_file) = private_fixed_stage_response_v3(
            || {
                self.confirm_checked(detail, || {
                    private_fixed_stage_disclosure_v3(|| prior.check(), before_disclosure)
                })
            },
            || {
                let file = self.0.lock().map_err(|_| Error::Terminal)?;
                foreground(&file)?;
                // Inspection has completed. Only actual source, session,
                // revocation and original material ceilings are checked here.
                after_response()?;
                foreground(&file)?;
                Ok(file.try_clone()?)
            },
        )?;
        let approval = HistoricalApproval {
            terminal: self.clone(),
            foreground_file,
            deadline,
            spent: AtomicBool::new(false),
        };
        approval.check()?;
        Ok(approval)
    }
    // END private fixed stage V3 terminal issuer.
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
    // BEGIN private fixed stage V3 tests.
    #[test]
    fn private_fixed_stage_v3_complete_bound_includes_escaping_and_challenge() {
        let maximum = wholepact_storage_security::bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES;
        let exact = "x".repeat(maximum - PRIVATE_FIXED_STAGE_PROMPT_V3.len());
        assert!(bound_private_fixed_stage_review_v3(&exact).is_ok());
        assert!(matches!(
            bound_private_fixed_stage_review_v3(&(exact + "x")),
            Err(Error::Invalid)
        ));
        let escaped = "é".repeat(24_000);
        assert!(escaped.len() < maximum);
        assert!(matches!(
            bound_private_fixed_stage_review_v3(&escaped),
            Err(Error::Invalid)
        ));
    }

    #[test]
    fn private_fixed_stage_v3_disclosure_checks_original_inspection_then_source_once() {
        use std::cell::RefCell;
        let trace = RefCell::new(Vec::new());
        assert!(
            private_fixed_stage_disclosure_v3(
                || {
                    trace.borrow_mut().push("original inspection");
                    Ok(())
                },
                || {
                    trace
                        .borrow_mut()
                        .push("actual source and original material ceilings");
                    Ok(())
                },
            )
            .is_ok()
        );
        assert_eq!(
            *trace.borrow(),
            vec![
                "original inspection",
                "actual source and original material ceilings",
                "original inspection"
            ]
        );
        trace.borrow_mut().clear();
        assert!(matches!(
            private_fixed_stage_disclosure_v3(
                || {
                    trace.borrow_mut().push("expired original inspection");
                    Err(Error::Permission)
                },
                || {
                    trace.borrow_mut().push("must not run");
                    Ok(())
                },
            ),
            Err(Error::Permission)
        ));
        assert_eq!(*trace.borrow(), vec!["expired original inspection"]);
        trace.borrow_mut().clear();
        assert!(matches!(
            private_fixed_stage_disclosure_v3(
                || {
                    trace.borrow_mut().push("original inspection");
                    Ok(())
                },
                || {
                    trace.borrow_mut().push("refused source");
                    Err(Error::Invalid)
                },
            ),
            Err(Error::Invalid)
        ));
        assert_eq!(
            *trace.borrow(),
            vec!["original inspection", "refused source"]
        );
    }

    #[test]
    fn private_fixed_stage_v3_inspection_expiry_during_source_denies_disclosure() {
        use std::cell::{Cell, RefCell};
        let current = Cell::new(true);
        let trace = RefCell::new(Vec::new());
        assert!(matches!(
            private_fixed_stage_disclosure_v3(
                || {
                    trace.borrow_mut().push("inspection");
                    if current.get() {
                        Ok(())
                    } else {
                        Err(Error::Permission)
                    }
                },
                || {
                    trace.borrow_mut().push("source expires inspection");
                    current.set(false);
                    Ok(())
                },
            ),
            Err(Error::Permission)
        ));
        assert_eq!(
            *trace.borrow(),
            vec!["inspection", "source expires inspection", "inspection"]
        );
    }

    #[test]
    fn private_fixed_stage_v3_response_captures_budget_before_source_once() {
        use std::cell::{Cell, RefCell};
        let trace = RefCell::new(Vec::new());
        let inspection_current = Cell::new(true);
        let response_completed = Cell::new(None);
        let source_started = Cell::new(None);
        // Inert kernel control only: no terminal/native/source authority is
        // fabricated. Expiry during human deliberation is not rechecked after
        // that already-authorized disclosure and affirmative response.
        let (deadline, ()) = private_fixed_stage_response_v3(
            || {
                private_fixed_stage_disclosure_v3(
                    || {
                        assert!(inspection_current.get());
                        trace.borrow_mut().push("inspection");
                        Ok(())
                    },
                    || {
                        trace.borrow_mut().push("disclosure source");
                        Ok(())
                    },
                )?;
                inspection_current.set(false);
                trace.borrow_mut().push("affirmative response");
                response_completed.set(Some(Instant::now()));
                Ok(())
            },
            || {
                source_started.set(Some(Instant::now()));
                assert!(!inspection_current.get());
                trace.borrow_mut().push("post-response source only");
                Ok(())
            },
        )
        .unwrap();
        assert!(deadline >= response_completed.get().unwrap() + Duration::from_secs(120));
        assert!(deadline <= source_started.get().unwrap() + Duration::from_secs(120));
        assert_eq!(
            *trace.borrow(),
            vec![
                "inspection",
                "disclosure source",
                "inspection",
                "affirmative response",
                "post-response source only"
            ]
        );
    }

    #[test]
    fn private_fixed_stage_v3_response_preserves_first_error_without_reissue() {
        use std::cell::Cell;
        let reviews = Cell::new(0);
        let postchecks = Cell::new(0);
        assert!(matches!(
            private_fixed_stage_response_v3(
                || {
                    reviews.set(reviews.get() + 1);
                    Err(Error::Permission)
                },
                || {
                    postchecks.set(postchecks.get() + 1);
                    Ok(())
                },
            ),
            Err(Error::Permission)
        ));
        assert_eq!((reviews.get(), postchecks.get()), (1, 0));
        reviews.set(0);
        assert!(matches!(
            private_fixed_stage_response_v3(
                || {
                    reviews.set(reviews.get() + 1);
                    Ok(())
                },
                || {
                    postchecks.set(postchecks.get() + 1);
                    Err::<(), _>(Error::Invalid)
                },
            ),
            Err(Error::Invalid)
        ));
        assert_eq!((reviews.get(), postchecks.get()), (1, 1));
    }

    #[test]
    fn private_fixed_stage_v3_expired_new_stage_budget_denies_without_reissue() {
        // Exercise the response kernel's restriction-only final gate without
        // fabricating a native owner or waiting out the genuine fixed budget.
        let ended_stage_deadline = Instant::now();
        assert!(matches!(
            check_private_fixed_stage_deadline_v3(ended_stage_deadline),
            Err(Error::Permission)
        ));
        assert!(matches!(
            check_private_fixed_stage_deadline_v3(ended_stage_deadline),
            Err(Error::Permission)
        ));
    }

    #[test]
    fn private_fixed_stage_v3_expired_disconnected_or_rebound_inspection_never_discloses() {
        use std::cell::Cell;
        for expired in [false, true] {
            let prior = HistoricalApproval::denied_for_test(expired);
            let terminal = prior.terminal.clone();
            let before = Cell::new(0);
            let after = Cell::new(0);
            {
                // The real original check is safe under the original mutex:
                // its private duplicate neither re-locks nor admits this file.
                let held = terminal.0.lock().unwrap();
                let disclosure = private_fixed_stage_disclosure_v3(
                    || prior.check(),
                    || {
                        before.set(before.get() + 1);
                        Ok(())
                    },
                );
                if expired {
                    assert!(matches!(disclosure, Err(Error::Permission)));
                } else {
                    assert!(matches!(disclosure, Err(Error::Terminal)));
                }
                assert_eq!(held.metadata().unwrap().len(), 0);
            }
            assert_eq!(before.get(), 0);
            assert!(
                terminal
                    .approve_private_fixed_stage_v3(
                        &prior,
                        "synthetic private stage metadata",
                        || {
                            before.set(before.get() + 1);
                            Ok(())
                        },
                        || {
                            after.set(after.get() + 1);
                            Ok(())
                        },
                    )
                    .is_err()
            );
            assert_eq!((before.get(), after.get()), (0, 0));
            assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
            let other = Terminal::disconnected_for_test();
            assert!(matches!(
                other.approve_private_fixed_stage_v3(
                    &prior,
                    "synthetic private stage metadata",
                    || {
                        before.set(before.get() + 1);
                        Ok(())
                    },
                    || {
                        after.set(after.get() + 1);
                        Ok(())
                    },
                ),
                Err(Error::Permission)
            ));
            assert_eq!((before.get(), after.get()), (0, 0));
            assert_eq!(other.0.lock().unwrap().metadata().unwrap().len(), 0);
        }
    }

    #[test]
    fn private_fixed_stage_v3_oversize_review_never_checks_source_or_discloses() {
        use std::cell::Cell;
        let prior = HistoricalApproval::denied_for_test(false);
        let terminal = prior.terminal.clone();
        let before = Cell::new(false);
        let after = Cell::new(false);
        assert!(matches!(
            terminal.approve_private_fixed_stage_v3(
                &prior,
                &"é".repeat(24_000),
                || {
                    before.set(true);
                    Ok(())
                },
                || {
                    after.set(true);
                    Ok(())
                },
            ),
            Err(Error::Invalid)
        ));
        assert!(!before.get());
        assert!(!after.get());
        assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
    }
    // END private fixed stage V3 tests.
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
            assert!(
                approval
                    .effect(&mut || {
                        called = true;
                        Ok(())
                    })
                    .is_err()
            );
            assert!(!called);
            assert!(
                approval
                    .effect(&mut || {
                        called = true;
                        Ok(())
                    })
                    .is_err()
            );
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
            assert!(
                approval
                    .effect(&mut || {
                        disclosure_entered = true;
                        sink.write_all(b"synthetic private lineage metadata")?;
                        Ok(())
                    })
                    .is_err()
            );
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
        assert!(
            terminal
                .approve_historical_reviewed(&prior, "synthetic private scope")
                .is_err()
        );
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
        assert!(
            terminal
                .approve_publication_reviewed(&prior, &"a".repeat(64), "synthetic private roster")
                .is_err()
        );
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

#[cfg(test)]
mod durable_delivery_v2_tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn exact_disclosure_brackets_source_before_output_only() {
        let trace = RefCell::new(Vec::new());
        durable_delivery_disclosure_v2(
            || {
                trace.borrow_mut().push("inspection");
                Ok(())
            },
            || {
                trace.borrow_mut().push("source");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*trace.borrow(), ["inspection", "source", "inspection"]);
        let called = Cell::new(false);
        assert!(matches!(
            durable_delivery_disclosure_v2(
                || Err(Error::Permission),
                || {
                    called.set(true);
                    Ok(())
                },
            ),
            Err(Error::Permission)
        ));
        assert!(!called.get());
        let checks = Cell::new(0);
        assert!(matches!(
            durable_delivery_disclosure_v2(
                || {
                    checks.set(checks.get() + 1);
                    Ok(())
                },
                || Err(Error::Authentication),
            ),
            Err(Error::Authentication)
        ));
        assert_eq!(checks.get(), 1);
    }

    #[test]
    fn source_expiring_during_inspection_never_admits_disclosure() {
        let live = Cell::new(true);
        assert!(matches!(
            durable_delivery_disclosure_v2(
                || if live.get() {
                    Ok(())
                } else {
                    Err(Error::Permission)
                },
                || {
                    live.set(false);
                    Ok(())
                },
            ),
            Err(Error::Permission)
        ));
    }

    #[test]
    fn response_starts_fixed_budget_before_source_and_preserves_original_error() {
        let response = Cell::new(None);
        let source = Cell::new(None);
        let (deadline, value) = durable_delivery_response_v2(
            || {
                response.set(Some(Instant::now()));
                Ok(())
            },
            || {
                source.set(Some(Instant::now()));
                Ok(Box::new(7u8))
            },
        )
        .unwrap();
        assert_eq!(*value, 7);
        assert!(deadline >= response.get().unwrap() + Duration::from_secs(120));
        assert!(deadline <= source.get().unwrap() + Duration::from_secs(120));
        let post = Cell::new(0);
        assert!(matches!(
            durable_delivery_response_v2(
                || Err(Error::Permission),
                || {
                    post.set(post.get() + 1);
                    Ok(())
                },
            ),
            Err(Error::Permission)
        ));
        assert_eq!(post.get(), 0);
        assert!(matches!(
            durable_delivery_response_v2(
                || Ok(()),
                || {
                    post.set(post.get() + 1);
                    Err::<(), _>(Error::Authentication)
                },
            ),
            Err(Error::Authentication)
        ));
        assert_eq!(post.get(), 1);
    }

    #[test]
    fn disconnected_expired_and_other_tty_never_issue_delivery_approval() {
        for expired in [false, true] {
            let prior = HistoricalApproval::denied_for_test(expired);
            let terminal = prior.terminal.clone();
            let calls = Cell::new(0);
            assert!(
                terminal
                    .approve_durable_delivery_v2(
                        &prior,
                        "Exact synthetic original delivery review",
                        || {
                            calls.set(calls.get() + 1);
                            Ok(())
                        },
                        || {
                            calls.set(calls.get() + 1);
                            Ok(())
                        },
                    )
                    .is_err()
            );
            assert_eq!(calls.get(), 0);
            assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
            let other = Terminal::disconnected_for_test();
            assert!(matches!(
                other.approve_durable_delivery_v2(
                    &prior,
                    "Exact synthetic original delivery review",
                    || Ok(()),
                    || Ok(()),
                ),
                Err(Error::Permission)
            ));
            assert_eq!(other.0.lock().unwrap().metadata().unwrap().len(), 0);
        }
    }

    #[test]
    fn escaped_bounded_review_refuses_before_callbacks_or_output() {
        let prior = HistoricalApproval::denied_for_test(false);
        let terminal = prior.terminal.clone();
        let called = Cell::new(false);
        assert!(matches!(
            terminal.approve_durable_delivery_v2(
                &prior,
                &"é".repeat(24_000),
                || {
                    called.set(true);
                    Ok(())
                },
                || {
                    called.set(true);
                    Ok(())
                },
            ),
            Err(Error::Invalid)
        ));
        assert!(!called.get());
        assert_eq!(terminal.0.lock().unwrap().metadata().unwrap().len(), 0);
        assert!(
            bound_durable_delivery_review_v2(
                "Original exact export and disabled financial operations"
            )
            .is_ok()
        );
    }
}
