//! Native-approved account-wide continuity disclosure for one exact restored
//! host inventory. This authenticates a surviving signer, never restores it or
//! proves completeness of a host inventory or of signatures outside this protocol.
use super::super::{BridgeError, Result, dispatch_ipc::write_frame, ipc::OriginalHistoryClient};
mod history;
pub use history::*;
use serde::{Deserialize, Serialize};
use std::{
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
use wholepact_authority::{AuthorityHead, WitnessDisclosureDescriptor};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityRequestV2 {
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
impl HostRecoveryContinuityRequestV2 {
    pub fn validate(&self) -> Result<()> {
        hash(&self.inventory_digest)?;
        hash(&self.generation_id)?;
        self.expected_witness.validate()?;
        if self.schema_version != 2
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
            "wholepact:host-recovery-continuity-request:v2",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
/// Audit data only. A saved copy is never current authority. Every permit is
/// conservatively executable for host recovery, regardless of recorded resolution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityEvidenceV2 {
    pub request: HostRecoveryContinuityRequestV2,
    pub writer_certificate_digest: String,
    pub writer_session_id: String,
    pub writer_session_expires_at_ms: u64,
    pub head: AuthorityHead,
    pub history_digest: String,
    pub complete_history: HostRecoveryHistoryV2,
}
impl HostRecoveryContinuityEvidenceV2 {
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
            "wholepact:host-recovery-continuity-evidence:v2",
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
            > 124 * 1024
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostContinuityResponseV2 {
    Held {
        lease_id: String,
        evidence: Box<HostRecoveryContinuityEvidenceV2>,
    },
    Current {
        lease_id: String,
        evidence_digest: String,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostContinuityCommandV2 {
    CheckCurrent,
    Finish,
}

/// Sealed, process-bound, short-lived read-only continuity proof. This does not
/// admit publication, activate the host, or authorize a durable external effect.
/// There is no constructor from audit evidence and no Clone.
pub struct HostRecoveryContinuityLeaseV2<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    evidence: HostRecoveryContinuityEvidenceV2,
    started: Instant,
}
struct PendingContinuityStreamV2(Option<UnixStream>);
impl Drop for PendingContinuityStreamV2 {
    fn drop(&mut self) {
        if let Some(stream) = self.0.as_mut() {
            let _ = write_frame(stream, &HostContinuityCommandV2::Finish);
        }
    }
}
impl OriginalHistoryClient {
    /// Requests a distinct native review disclosing complete account exposure.
    /// An existing agreement-history grant alone does not approve this disclosure.
    pub fn acquire_host_recovery_continuity_v2(
        &self,
        request: &HostRecoveryContinuityRequestV2,
    ) -> Result<HostRecoveryContinuityLeaseV2<'_>> {
        request.validate()?;
        require_complete_origin_endpoint()?;
        self.check_host_recovery_account_scope(&request.account_id)?;
        let stream = self.open_authenticated_request(serde_json::json!({
            "operation":"request_host_recovery_continuity_v2", "request":request
        }))?;
        // Every failed acquisition unwinds the server's held local authority.
        // A lost response never leaves an apparently live caller silently
        // holding a recovery freeze after it has abandoned inspection.
        let mut pending = PendingContinuityStreamV2(Some(stream));
        let stream = pending.0.as_ref().ok_or(BridgeError::Ipc)?;
        let frame =
            crate::ipc::read_frame_with_deadline(stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: HostContinuityResponseV2 =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        let HostContinuityResponseV2::Held { lease_id, evidence } = response else {
            return Err(BridgeError::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if &evidence.request != request {
            return Err(BridgeError::Binding);
        }
        let lease = HostRecoveryContinuityLeaseV2 {
            client: self,
            stream: Mutex::new(pending.0.take().ok_or(BridgeError::Ipc)?),
            lease_id,
            evidence: *evidence,
            started: Instant::now(),
        };
        lease.check_current()?;
        Ok(lease)
    }
}
impl HostRecoveryContinuityLeaseV2<'_> {
    pub fn binding(&self) -> &HostRecoveryContinuityRequestV2 {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV2 {
        &self.evidence
    }
    pub fn complete_history(&self) -> &HostRecoveryHistoryV2 {
        &self.evidence.complete_history
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.client.host_recovery_provider_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        self.client
            .check_host_recovery_account_scope(&self.binding().account_id)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &HostContinuityCommandV2::CheckCurrent)?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(30),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let response: HostContinuityResponseV2 =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        match response {
            HostContinuityResponseV2::Current {
                lease_id,
                evidence_digest,
            } if lease_id == self.lease_id && evidence_digest == self.evidence.digest()? => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for HostRecoveryContinuityLeaseV2<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &HostContinuityCommandV2::Finish);
        }
    }
}

/// This is deliberately unconditional. Source DTO/consumer qualification is not
/// enough to enable either operation. The runtime must add explicit v2 native
/// routing and qualify all committed/archive readers before changing this gate.
pub const COMPLETE_ORIGIN_ENDPOINT_UNAVAILABLE: &str = "Complete-origin host recovery v2 is unavailable until native review, complete journal continuity, publication and all archive consumers are coherently integrated and qualified";
pub fn require_complete_origin_endpoint() -> Result<()> {
    Err(BridgeError::CompleteOriginRecoveryUnavailable)
}

#[cfg(test)]
pub(crate) mod tests;
