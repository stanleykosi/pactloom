//! Native-approved account-wide continuity disclosure for one exact restored
//! host inventory. This authenticates a surviving signer, never restores it or
//! proves completeness of a host inventory or of signatures outside this protocol.
use super::super::{BridgeError, Result};
mod history;
pub use history::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wholepact_authority::{AuthorityHead, WitnessDisclosureDescriptor};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityRequestV4 {
    pub schema_version: u16,
    pub inventory_digest: String,
    pub generation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub expected_writer_epoch: u64,
    pub expected_witness: WitnessDisclosureDescriptor,
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl HostRecoveryContinuityRequestV4 {
    pub fn validate(&self) -> Result<()> {
        hash(&self.inventory_digest)?;
        hash(&self.generation_id)?;
        self.expected_witness.validate()?;
        if self.schema_version != 4
            || self.expected_writer_epoch == 0
            || self.expected_writer_epoch > i64::MAX as u64
            || self.account_id != self.expected_witness.account_id
            || self.network_profile_id != self.expected_witness.network_profile_id
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-continuity-request:v4",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
/// Audit data only. A saved copy is never current authority. Every permit is
/// conservatively executable for host recovery, regardless of recorded resolution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityEvidenceV4 {
    pub request: HostRecoveryContinuityRequestV4,
    pub writer_certificate_digest: String,
    pub writer_session_id: String,
    pub writer_session_expires_at_ms: u64,
    pub head: AuthorityHead,
    pub history_digest: String,
    pub complete_history: HostRecoveryHistoryV4,
}
impl HostRecoveryContinuityEvidenceV4 {
    #[cfg(any(test, all(feature = "native-ui", feature = "authority-signing")))]
    pub(crate) fn require_unchanged(&self, current: &Self, elapsed: Duration) -> Result<()> {
        if self != current || elapsed >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-continuity-evidence:v4",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        for value in [
            &self.writer_certificate_digest,
            &self.writer_session_id,
            &self.head.digest,
            &self.history_digest,
        ] {
            hash(value)?;
        }
        if self.writer_session_expires_at_ms == 0
            || self.writer_session_expires_at_ms > i64::MAX as u64
            || self.head.sequence > i64::MAX as u64
        {
            return Err(BridgeError::Binding);
        }
        let snapshot = self.complete_history.construction.observed_snapshot();
        let active = snapshot
            .active_writer_session
            .as_ref()
            .ok_or(BridgeError::Binding)?;
        if self.complete_history.construction.complete_replay_digest() != self.history_digest
            || snapshot.writer_certificate_digest != self.writer_certificate_digest
            || active.session_id != self.writer_session_id
            || active.writer_certificate_digest != self.writer_certificate_digest
            || active.expires_at_ms != self.writer_session_expires_at_ms
            || active.writer_epoch != self.request.expected_writer_epoch
            || active.disclosure != self.request.expected_witness
            || snapshot.writer_status != wholepact_authority::WriterStatus::Active
        {
            return Err(BridgeError::Binding);
        }
        self.complete_history.validate(
            &self.request.account_id,
            &self.request.network_profile_id,
            &self.request.expected_witness,
            &self.head,
            self.request.expected_writer_epoch,
        )?;
        if serde_json::to_vec(self)
            .map_err(|_| BridgeError::Binding)?
            .len()
            > MAX_COMPLETE_HISTORY_V4_BYTES + 4096
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

/// No native V4 wire issuer exists yet. Archive validation is not admission.
pub const COMMON_CONTEXT_RECOVERY_ENDPOINT_UNAVAILABLE: &str = "Common-context recovery v4 is unavailable until its native producer, bounded framing and complete archived consumer graph are qualified";
pub fn require_common_context_recovery_endpoint() -> Result<()> {
    Err(BridgeError::CompleteOriginRecoveryUnavailable)
}
