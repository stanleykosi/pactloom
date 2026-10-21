//! Check-only original H provenance for S. The inherited socketpair's
//! SO_PEERCRED/SO_PEERPIDFD identifies its pre-fork creator, not the sender.
//! Issuance instead follows the mandatory first H packet authenticated by
//! SCM_CREDENTIALS against the actual fork-retained H lifetime. Core retains
//! that exact H pidfd and original socket; no PID lookup or FD import exists.
use crate::{rejected, signer_continue_state::Core, Result};
use std::sync::Arc;

/// One issued observation, not permission to unlock, read, receive, or mutate.
/// Non-Clone/non-serializable and has no public constructor or raw-parts export.
pub struct OriginalSignerHostPeerV1 {
    core: Arc<Core>,
    uid: u32,
    pid: u32,
    instance: String,
}
impl OriginalSignerHostPeerV1 {
    pub(in crate::financial_workflow_origin) fn from_authenticated_first_packet(
        core: Arc<Core>,
        uid: u32,
        pid: u32,
        instance: String,
    ) -> Result<Self> {
        if pid == 0 || !crate::signer_continue_state::hash(&instance) {
            return Err(rejected("original H handshake identity invalid"));
        }
        let token = Self {
            core,
            uid,
            pid,
            instance,
        };
        token.check_current()?;
        Ok(token)
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn instance(&self) -> &str {
        &self.instance
    }
    /// Nonblocking exact original pidfd/socket/owner/C/session/R/Q checks.
    pub fn check_current(&self) -> Result<()> {
        self.core.check_action_restrictions()
    }
}

pub(super) fn first_handshake_allowed(
    seen: bool,
    started: bool,
    expected: super::Target,
    received: super::Target,
) -> bool {
    !seen && !started && expected == received
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_handshake_rejects_duplicate_reorder_and_cross_role() {
        let a = super::super::Target::Signer1;
        let b = super::super::Target::Signer2;
        assert!(first_handshake_allowed(false, false, a, a));
        assert!(!first_handshake_allowed(true, false, a, a));
        assert!(!first_handshake_allowed(false, true, a, a));
        assert!(!first_handshake_allowed(false, false, a, b));
    }
    #[test]
    fn original_peer_is_send_sync_without_exporting_handles() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<OriginalSignerHostPeerV1>();
    }
}
