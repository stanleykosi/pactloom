//! Recovery-specific writer fencing against a surviving independent witness.
//! Neither an exported receipt nor restored witness history grants this capability.
use crate::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Audit evidence only. Deserializing it does not authenticate the witness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFenceReceipt {
    pub operation_id: String,
    pub inventory_digest: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub policy_digest: String,
    pub previous_writer_certificate_digest: String,
    pub previous_writer_epoch: u64,
    pub writer_certificate_digest: String,
    pub writer_epoch: u64,
    pub previous_head: AuthorityHead,
    pub committed_head: AuthorityHead,
}

/// A short-lived, sealed observation of the exact owner-authorized recovery
/// transition and the successor's live, independently owner-activated session.
/// It fences new writer operations; it does not revoke old signed transactions.
pub struct AuthenticatedRecoveryFence {
    receipt: RecoveryFenceReceipt,
    history: ReconciledAuthorityHistory,
    active: AuthenticatedWriterSession,
    deadline: Instant,
}
impl AuthenticatedRecoveryFence {
    pub fn receipt(&self) -> &RecoveryFenceReceipt {
        &self.receipt
    }
    pub fn history(&self) -> &ReconciledAuthorityHistory {
        &self.history
    }
    pub fn active_session(&self) -> &AuthenticatedWriterSession {
        &self.active
    }
    pub fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.deadline || now_ms()? >= self.active.receipt().expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}
impl AuthorityClient {
    /// Fetch and replay ALL witness history, then verify possession of this
    /// client's active ephemeral writer session at exactly that history head.
    /// No caller supplied snapshot, receipt or "verified" flag is accepted.
    pub fn authenticate_recovery_fence(
        &self,
        operation_id: &str,
        inventory_digest: &str,
    ) -> Result<AuthenticatedRecoveryFence> {
        id(operation_id)?;
        hash(inventory_digest)?;
        let started = Instant::now();
        let history = self.reconcile_history()?;
        let active = self.verify_active_session(&history)?;
        bind_fence(history, active, operation_id, inventory_digest, started)
    }
}

pub(crate) fn recovery_receipt(
    previous: &AccountSnapshot,
    mutation: &AuthorityMutation,
    committed: &AccountSnapshot,
) -> Option<RecoveryFenceReceipt> {
    let AuthorityMutation::OwnerControl(request) = mutation else {
        return None;
    };
    let OwnerControl::RecoverWriter {
        writer_certificate_digest,
        inventory_digest,
    } = &request.control
    else {
        return None;
    };
    Some(RecoveryFenceReceipt {
        operation_id: request.operation_id.clone(),
        inventory_digest: inventory_digest.clone(),
        account_id: previous.account_id.clone(),
        network_profile_id: previous.network_profile_id.clone(),
        policy_digest: previous.policy_digest.clone(),
        previous_writer_certificate_digest: previous.writer_certificate_digest.clone(),
        previous_writer_epoch: previous.writer_epoch,
        writer_certificate_digest: writer_certificate_digest.clone(),
        writer_epoch: committed.writer_epoch,
        previous_head: previous.head.clone(),
        committed_head: committed.head.clone(),
    })
}

pub(crate) fn bind_fence(
    history: ReconciledAuthorityHistory,
    active: AuthenticatedWriterSession,
    operation_id: &str,
    inventory_digest: &str,
    started: Instant,
) -> Result<AuthenticatedRecoveryFence> {
    let receipt = history
        .recovery_fences
        .iter()
        .find(|r| r.operation_id == operation_id)
        .ok_or(AuthorityError::RecoveryRequired)?
        .clone();
    let snapshot = history.snapshot();
    if receipt.inventory_digest != inventory_digest
        || receipt.account_id != snapshot.account_id
        || receipt.network_profile_id != snapshot.network_profile_id
        || receipt.policy_digest != snapshot.policy_digest
        || receipt.writer_epoch != snapshot.writer_epoch
        || receipt.writer_certificate_digest != snapshot.writer_certificate_digest
        || snapshot.writer_status != WriterStatus::Active
        || receipt.committed_head.sequence > snapshot.head.sequence
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let fence = AuthenticatedRecoveryFence {
        receipt,
        history,
        active,
        deadline: started + Duration::from_secs(30),
    };
    fence.check_current()?;
    Ok(fence)
}
