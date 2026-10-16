//! Native-approved account-wide continuity disclosure for one exact restored
//! host inventory. This authenticates a surviving signer, never restores it or
//! proves completeness of a host inventory or of signatures outside this protocol.
use super::{BridgeError, Result, dispatch_ipc::write_frame, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
use wholepact_authority::{AuthorityHead, ReservationPermit, WitnessDisclosureDescriptor};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityRequest {
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
impl HostRecoveryContinuityRequest {
    pub fn validate(&self) -> Result<()> {
        hash(&self.inventory_digest)?;
        hash(&self.generation_id)?;
        self.expected_witness.validate()?;
        if self.schema_version != 1
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
            "wholepact:host-recovery-continuity-request:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
/// Audit data only. A saved copy is never current authority. Every permit is
/// conservatively executable for host recovery, regardless of recorded resolution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityEvidence {
    pub request: HostRecoveryContinuityRequest,
    pub writer_certificate_digest: String,
    pub writer_session_id: String,
    pub writer_session_expires_at_ms: u64,
    pub head: AuthorityHead,
    pub history_digest: String,
    pub conservative_permits: Vec<ReservationPermit>,
}
impl HostRecoveryContinuityEvidence {
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
            "wholepact:host-recovery-continuity-evidence:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.request.validate()?;
        for value in [
            &self.writer_certificate_digest,
            &self.writer_session_id,
            &self.head.digest,
            &self.history_digest,
        ] {
            hash(value)?;
        }
        if self.writer_session_expires_at_ms == 0 || self.conservative_permits.len() > 100_000 {
            return Err(BridgeError::Binding);
        }
        let mut ids = BTreeSet::new();
        for permit in &self.conservative_permits {
            permit.matches_request(&permit.request)?;
            let r = &permit.request;
            if r.account_id != self.request.account_id
                || r.network_profile_id != self.request.network_profile_id
                || permit.witness_id != self.request.expected_witness.witness_id
                || permit.policy_digest != self.request.expected_witness.policy_digest
                || r.writer_epoch > self.request.expected_writer_epoch
                || permit.committed_head.sequence > self.head.sequence
                || !ids.insert(&r.authorization_id)
            {
                return Err(BridgeError::Binding);
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostContinuityResponse {
    Held {
        lease_id: String,
        evidence: Box<HostRecoveryContinuityEvidence>,
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
pub(crate) enum HostContinuityCommand {
    CheckCurrent,
    Finish,
}

/// Sealed, process-bound, short-lived read-only continuity proof. This does not
/// admit publication, activate the host, or authorize a durable external effect.
/// There is no constructor from audit evidence and no Clone.
pub struct HostRecoveryContinuityLease<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    evidence: HostRecoveryContinuityEvidence,
    started: Instant,
}
struct PendingContinuityStream(Option<UnixStream>);
impl Drop for PendingContinuityStream {
    fn drop(&mut self) {
        if let Some(stream) = self.0.as_mut() {
            let _ = write_frame(stream, &HostContinuityCommand::Finish);
        }
    }
}
impl OriginalHistoryClient {
    /// Requests a distinct native review disclosing complete account exposure.
    /// An existing agreement-history grant alone does not approve this disclosure.
    pub fn acquire_host_recovery_continuity(
        &self,
        request: &HostRecoveryContinuityRequest,
    ) -> Result<HostRecoveryContinuityLease<'_>> {
        request.validate()?;
        self.check_host_recovery_scope(request)?;
        let stream = self.open_authenticated_request(serde_json::json!({
            "operation":"request_host_recovery_continuity", "request":request
        }))?;
        // Every failed acquisition unwinds the server's held local authority.
        // A lost response never leaves an apparently live caller silently
        // holding a recovery freeze after it has abandoned inspection.
        let mut pending = PendingContinuityStream(Some(stream));
        let stream = pending.0.as_ref().ok_or(BridgeError::Ipc)?;
        let frame =
            crate::ipc::read_frame_with_deadline(stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: HostContinuityResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        let HostContinuityResponse::Held { lease_id, evidence } = response else {
            return Err(BridgeError::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if &evidence.request != request {
            return Err(BridgeError::Binding);
        }
        let lease = HostRecoveryContinuityLease {
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
impl HostRecoveryContinuityLease<'_> {
    pub fn binding(&self) -> &HostRecoveryContinuityRequest {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidence {
        &self.evidence
    }
    pub fn conservative_permits(&self) -> &[ReservationPermit] {
        &self.evidence.conservative_permits
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.client.host_recovery_provider_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        self.client.check_host_recovery_scope(self.binding())?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &HostContinuityCommand::CheckCurrent)?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(30),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let response: HostContinuityResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        match response {
            HostContinuityResponse::Current {
                lease_id,
                evidence_digest,
            } if lease_id == self.lease_id && evidence_digest == self.evidence.digest()? => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for HostRecoveryContinuityLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &HostContinuityCommand::Finish);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> HostRecoveryContinuityRequest {
        HostRecoveryContinuityRequest {
            schema_version: 1,
            inventory_digest: "11".repeat(32),
            generation_id: "22".repeat(32),
            account_id: "synthetic-account".into(),
            network_profile_id: "synthetic-network".into(),
            expected_writer_epoch: 1,
            expected_witness: WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:4444".into(),
                server_name: "localhost".into(),
                witness_id: "synthetic-witness".into(),
                account_id: "synthetic-account".into(),
                network_profile_id: "synthetic-network".into(),
                policy_digest: "33".repeat(32),
                pinned_server_certificate_digest: "44".repeat(32),
            },
        }
    }
    #[test]
    fn continuity_request_binds_host_generation_account_and_witness() {
        let original = request();
        let digest = original.digest().unwrap();
        let mut changed = original.clone();
        changed.inventory_digest = "55".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original.clone();
        changed.generation_id = "66".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original.clone();
        changed.expected_writer_epoch = 2;
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original.clone();
        changed.expected_witness.pinned_server_certificate_digest = "77".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = original;
        changed.account_id = "other-account".into();
        assert!(changed.digest().is_err());
    }
    #[test]
    fn continuity_evidence_rejects_stale_changed_or_rebound_observations() {
        let evidence = HostRecoveryContinuityEvidence {
            request: request(),
            writer_certificate_digest: "55".repeat(32),
            writer_session_id: "66".repeat(32),
            writer_session_expires_at_ms: 1000,
            head: AuthorityHead {
                sequence: 2,
                digest: "77".repeat(32),
            },
            history_digest: "88".repeat(32),
            conservative_permits: vec![],
        };
        evidence.validate().unwrap();
        evidence
            .require_unchanged(&evidence, Duration::from_secs(29))
            .unwrap();
        assert!(
            evidence
                .require_unchanged(&evidence, Duration::from_secs(30))
                .is_err()
        );
        for changed in [
            HostRecoveryContinuityEvidence {
                head: AuthorityHead {
                    sequence: 3,
                    digest: "99".repeat(32),
                },
                ..evidence.clone()
            },
            HostRecoveryContinuityEvidence {
                writer_session_id: "aa".repeat(32),
                ..evidence.clone()
            },
            HostRecoveryContinuityEvidence {
                writer_session_expires_at_ms: 1001,
                ..evidence.clone()
            },
            HostRecoveryContinuityEvidence {
                request: HostRecoveryContinuityRequest {
                    generation_id: "bb".repeat(32),
                    ..request()
                },
                ..evidence.clone()
            },
        ] {
            assert!(
                evidence
                    .require_unchanged(&changed, Duration::ZERO)
                    .is_err()
            );
            assert_ne!(evidence.digest().unwrap(), changed.digest().unwrap());
        }
    }
    #[test]
    fn no_wire_authority_or_completeness_flags() {
        for key in [
            "approved",
            "verified",
            "host_inventory_complete",
            "all_signatures_known",
            "recover_writer",
            "clear_recovery",
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value[key] = true.into();
            assert!(serde_json::from_value::<HostRecoveryContinuityRequest>(value).is_err());
        }
        let mut malformed = request();
        malformed.generation_id = "AB".repeat(32);
        assert!(malformed.validate().is_err());
    }
}

/// Explicit complete-origin family. Legacy bytes and refusal remain unchanged.
pub mod v2;

/// Construction-complete historical family; no IPC endpoint enabled here.
pub mod v3;

/// Mixed V2/common-context V3 audit family. No transport or live issuer.
pub mod v4;

/// Explicit transport-handoff-complete immutable archive. No live issuer.
pub mod v5;
