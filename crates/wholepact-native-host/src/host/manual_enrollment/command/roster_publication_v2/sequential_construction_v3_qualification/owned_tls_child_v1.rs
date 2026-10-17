//! Exact parent-TLS child lifetime only. No process-group or arbitrary PID API.
//! The fixture command is reviewed OpenSSL with null standard streams and no
//! descendants. The caller retains the exact outer root on every error/unwind.
use super::super::{owned_test_process_group_v1 as ownership, process_containment_v1};
use std::{
    io,
    process::{Child, Command, ExitStatus},
    time::{Duration, Instant},
};

const REAP_LIMIT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopPlan {
    ReapOnly,
    KillOnceThenReap,
    RetainUnverified,
}
fn stop_plan(observation: Result<Option<bool>, ()>, preserving_policy: bool) -> StopPlan {
    match observation {
        Ok(Some(_)) => StopPlan::ReapOnly,
        Ok(None) if preserving_policy => StopPlan::KillOnceThenReap,
        _ => StopPlan::RetainUnverified,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KillResult {
    NotNeeded,
    Sent,
    Unverified,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StopOutcome {
    kill: KillResult,
    direct_child_reaped: bool,
}

struct OwnedTlsChild {
    child: Option<Child>,
    anchor_available: bool,
}
impl OwnedTlsChild {
    fn observe(&mut self) -> io::Result<Option<bool>> {
        let result = ownership::observe_unreaped_child(
            self.child
                .as_ref()
                .ok_or_else(|| io::Error::other("synthetic TLS child already finished"))?,
        );
        if result.is_err() {
            self.anchor_available = false;
        }
        result
    }
    fn reap_completed(&mut self) -> io::Result<ExitStatus> {
        let child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("synthetic TLS child already finished"))?;
        bounded_reap(child)
            .ok_or_else(|| io::Error::other("synthetic TLS direct-child reap unverified"))
    }
    fn stop_and_reap(&mut self) -> StopOutcome {
        let unverified = StopOutcome {
            kill: KillResult::Unverified,
            direct_child_reaped: false,
        };
        let Some(mut child) = self.child.take() else {
            return unverified;
        };
        if !self.anchor_available {
            return unverified;
        }
        let observation = ownership::observe_unreaped_child(&child).map_err(|_| ());
        // Read-only check immediately before a potential nonzero exact-child
        // signal; inherited auto-reaping must not invalidate a live PID anchor.
        let preserving = ownership::require_default_child_wait_policy().is_ok();
        let kill = match stop_plan(observation, preserving) {
            StopPlan::RetainUnverified => return unverified,
            StopPlan::ReapOnly => KillResult::NotNeeded,
            StopPlan::KillOnceThenReap => {
                if child.kill().is_ok() {
                    KillResult::Sent
                } else {
                    KillResult::Unverified
                }
            }
        };
        StopOutcome {
            kill,
            direct_child_reaped: bounded_reap(child).is_some(),
        }
    }
}
impl Drop for OwnedTlsChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.stop_and_reap();
        }
    }
}
fn bounded_reap(mut child: Child) -> Option<ExitStatus> {
    let deadline = Instant::now() + REAP_LIMIT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn within_original_preparation(now: Instant, deadline: Instant) -> bool {
    now < deadline
}

pub(super) fn run(mut command: Command, deadline: Instant) -> io::Result<()> {
    process_containment_v1::require_inherited_core_policy()?;
    if !within_original_preparation(Instant::now(), deadline) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "synthetic TLS original preparation deadline expired; no command started",
        ));
    }
    let child = ownership::spawn_with_checked_wait_policy(&mut command)?;
    let mut owned = OwnedTlsChild {
        child: Some(child),
        anchor_available: true,
    };
    loop {
        if !within_original_preparation(Instant::now(), deadline) {
            let cleanup = owned.stop_and_reap();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "synthetic TLS preparation deadline; kill={:?}; direct_child_reaped={}",
                    cleanup.kill, cleanup.direct_child_reaped,
                ),
            ));
        }
        match owned.observe() {
            Ok(Some(_)) => {
                let status = owned.reap_completed()?;
                // Cleanup grace never admits a result after the ORIGINAL cutoff.
                if !within_original_preparation(Instant::now(), deadline) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "synthetic TLS original preparation expired during reap",
                    ));
                }
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(
                        "synthetic TLS material generation failed; direct child reaped",
                    ))
                };
            }
            Ok(None) => {}
            Err(_) => {
                return Err(io::Error::other(
                    "synthetic TLS child ownership unverified; retain owned root",
                ));
            }
        }

        std::thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

#[cfg(test)]
mod pure_tests {
    use super::*;
    #[test]
    fn pure_tls_original_preparation_cutoff_is_not_cleanup_grace() {
        let start = Instant::now();
        let original = start + Duration::from_secs(20);
        assert!(within_original_preparation(start, original));
        assert!(!within_original_preparation(original, original));
        assert!(!within_original_preparation(
            original + REAP_LIMIT,
            original
        ));
    }
    #[test]
    fn pure_tls_stop_plan_never_signals_missing_or_auto_reaped_anchor() {
        assert_eq!(stop_plan(Err(()), true), StopPlan::RetainUnverified);
        assert_eq!(stop_plan(Ok(None), false), StopPlan::RetainUnverified);
        assert_eq!(stop_plan(Ok(None), true), StopPlan::KillOnceThenReap);
    }
    #[test]
    fn pure_tls_exited_child_needs_only_exact_reap_never_a_signal() {
        for status in [true, false] {
            for policy in [true, false] {
                assert_eq!(stop_plan(Ok(Some(status)), policy), StopPlan::ReapOnly);
            }
        }
    }
}
