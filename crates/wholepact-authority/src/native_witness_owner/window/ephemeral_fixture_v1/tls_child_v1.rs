//! Synthetic fixture direct-child cleanup only, not a production process API.
//! This isolated invocation is the exclusive waiter for its OpenSSL children.
//! No concurrent handler/thread may reap them or change SIGCHLD policy. Read-only
//! policy checks reject unsafe inheritance but cannot enforce that contract
//! against arbitrary injected code. No process-wide signal policy is changed.
use super::{AuthorityError, EphemeralWitnessInstallation, Result};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use wholepact_storage_security::synthetic_child_observation_v1::{
    default_child_wait_policy as checked_wait_policy, exact_child_still_owned,
};
fn pause(now: Instant, deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
        .map(|left| left.min(Duration::from_millis(5)))
}

struct OwnedTlsGenerator {
    child: Option<Child>,
    anchor_available: bool,
    // Preserve the SAME original installation until direct-child cleanup is
    // verified. Uncertain cleanup leaves it for the outer owned root supervisor.
    installation: Option<Arc<EphemeralWitnessInstallation>>,
}
impl OwnedTlsGenerator {
    fn reap_or_kill_once(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        if !self.anchor_available
            || !checked_wait_policy()
            || !exact_child_still_owned(child)
            || !checked_wait_policy()
        {
            self.anchor_available = false;
            return false;
        }
        // One signal while the exact child anchor is retained. No signal after
        // any reap or ambiguous ownership result; no caller-selected PID exists.
        // A concurrent ordinary child exit is resolved only by exact wait.
        // Never retry a signal or infer that an error proves termination.
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child.take();
                    return true;
                }
                Ok(None) => {}
                Err(_) => {
                    self.anchor_available = false;
                    return false;
                }
            }
            let Some(delay) = pause(Instant::now(), deadline) else {
                return false;
            };
            std::thread::sleep(delay);
        }
    }
}
impl Drop for OwnedTlsGenerator {
    fn drop(&mut self) {
        if !self.reap_or_kill_once() {
            if let Some(installation) = self.installation.take() {
                // Do not delete files beneath an unverified child. This nominal
                // owner is deliberately retained until the isolated process ends;
                // the enclosing test owns group termination and exact TMPDIR close.
                std::mem::forget(installation);
            }
        }
    }
}

pub(super) fn run_openssl(
    root: &Path,
    installation: &Arc<EphemeralWitnessInstallation>,
    arguments: &[&str],
    deadline: Instant,
) -> Result<()> {
    if pause(Instant::now(), deadline).is_none() {
        return Err(AuthorityError::Expired);
    }
    if !checked_wait_policy() {
        return Err(AuthorityError::Storage);
    }
    let child = match Command::new("openssl")
        .current_dir(root)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            // No returned Child means this layer cannot prove cleanup. Preserve
            // the actual root for the enclosing group owner, without a PID guess.
            std::mem::forget(installation.clone());
            return Err(AuthorityError::Storage);
        }
    };
    let mut owned = OwnedTlsGenerator {
        child: Some(child),
        anchor_available: true,
        installation: Some(installation.clone()),
    };
    loop {
        let delay = pause(Instant::now(), deadline).ok_or(AuthorityError::Expired)?;
        let status = match owned
            .child
            .as_mut()
            .ok_or(AuthorityError::Storage)?
            .try_wait()
        {
            Ok(value) => value,
            Err(_) => {
                owned.anchor_available = false;
                return Err(AuthorityError::Storage);
            }
        };
        if let Some(status) = status {
            owned.child.take(); // Already reaped; Drop must not signal this PID.
            if pause(Instant::now(), deadline).is_none() {
                return Err(AuthorityError::Expired);
            }
            return if status.success() {
                Ok(())
            } else {
                Err(AuthorityError::Authentication)
            };
        }
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tls_generator_original_budget_never_renews() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(7);
        assert_eq!(pause(start, deadline), Some(Duration::from_millis(5)));
        assert_eq!(
            pause(start + Duration::from_millis(6), deadline),
            Some(Duration::from_millis(1))
        );
        assert_eq!(pause(deadline, deadline), None);
        assert_eq!(pause(deadline + Duration::from_millis(1), deadline), None);
    }
}
