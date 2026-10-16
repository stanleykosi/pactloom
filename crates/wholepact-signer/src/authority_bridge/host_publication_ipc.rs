//! Separate native admission for one exact restricted host recovery generation.
//! An admitted generation is informational. It grants no financial authority,
//! remote witness lease, global cutoff, or continuing signer freeze.
use super::{
    BridgeError, Result,
    dispatch_ipc::write_frame,
    host_recovery_ipc::{HostRecoveryContinuityEvidence, HostRecoveryContinuityRequest},
    ipc::OriginalHistoryClient,
};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::net::UnixStream,
    path::{Component, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryPublicationRequest {
    pub schema_version: u16,
    pub continuity: HostRecoveryContinuityRequest,
    pub target_profile: PathBuf,
    pub generation_manifest_digest: String,
    pub continuity_evidence_digest: String,
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
impl HostRecoveryPublicationRequest {
    pub fn validate(&self) -> Result<()> {
        self.continuity.validate()?;
        hash(&self.generation_manifest_digest)?;
        hash(&self.continuity_evidence_digest)?;
        let target = self.target_profile.to_str().ok_or(BridgeError::Binding)?;
        // The host separately authenticates its canonical directory handles.
        // This boundary rejects ambiguous textual targets and never opens them.
        if self.schema_version != 1
            || !self.target_profile.is_absolute()
            || self.target_profile.file_name().is_none()
            || target.len() > 4096
            || target.chars().any(|c| c.is_control() || matches!(c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            ))
            || target.contains("//")
            || target.ends_with('/')
            || target.split('/').any(|part| matches!(part, "." | ".."))
            || self
                .target_profile
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-publication-request:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub(crate) fn matches_evidence(&self, evidence: &HostRecoveryContinuityEvidence) -> Result<()> {
        self.validate()?;
        if evidence.request != self.continuity
            || evidence.digest()? != self.continuity_evidence_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

/// Saved audit data only. Deserializing this record cannot recreate admission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryPublicationRecord {
    pub request: HostRecoveryPublicationRequest,
    pub native_review_digest: String,
    pub admission_id: String,
}
impl HostRecoveryPublicationRecord {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.native_review_digest)?;
        hash(&self.admission_id)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-publication-record:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostPublicationResponse {
    Prepared {
        lease_id: String,
        request_digest: String,
        native_review_digest: String,
        evidence: Box<HostRecoveryContinuityEvidence>,
    },
    Admitted {
        record: Box<HostRecoveryPublicationRecord>,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostPublicationCommand {
    Admit {
        lease_id: String,
        request_digest: String,
    },
    Finish,
}

/// A separately reviewed, bounded preadmission lease. This is not publication
/// permission and is never convertible from the read-only disclosure lease.
pub struct HostRecoveryPublicationLease<'a> {
    client: &'a OriginalHistoryClient,
    stream: Option<UnixStream>,
    request: HostRecoveryPublicationRequest,
    evidence: HostRecoveryContinuityEvidence,
    lease_id: String,
    native_review_digest: String,
    started: Instant,
}
struct PendingPublicationStream(Option<UnixStream>);
impl Drop for PendingPublicationStream {
    fn drop(&mut self) {
        if let Some(stream) = self.0.as_mut() {
            let _ = write_frame(stream, &HostPublicationCommand::Finish);
        }
    }
}
impl OriginalHistoryClient {
    /// Requests a new exact native review, independent of historical disclosure
    /// approval. Release any read-only continuity lease before calling this.
    pub fn acquire_host_recovery_publication(
        &self,
        request: &HostRecoveryPublicationRequest,
    ) -> Result<HostRecoveryPublicationLease<'_>> {
        request.validate()?;
        self.check_host_recovery_scope(&request.continuity)?;
        let stream = self.open_authenticated_request(serde_json::json!({
            "operation":"request_host_recovery_publication", "request":request
        }))?;
        let mut pending = PendingPublicationStream(Some(stream));
        let frame = crate::ipc::read_frame_with_deadline(
            pending.0.as_ref().ok_or(BridgeError::Ipc)?,
            self.peer(),
            Duration::from_secs(120),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let HostPublicationResponse::Prepared {
            lease_id,
            request_digest,
            native_review_digest,
            evidence,
        } = serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?
        else {
            return Err(BridgeError::Permission);
        };
        hash(&lease_id)?;
        hash(&native_review_digest)?;
        request.matches_evidence(&evidence)?;
        if request_digest != request.digest()? {
            return Err(BridgeError::Binding);
        }
        Ok(HostRecoveryPublicationLease {
            client: self,
            stream: pending.0.take(),
            request: request.clone(),
            evidence: *evidence,
            lease_id,
            native_review_digest,
            started: Instant::now(),
        })
    }
}
impl HostRecoveryPublicationLease<'_> {
    pub fn binding(&self) -> &HostRecoveryPublicationRequest {
        &self.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidence {
        &self.evidence
    }
    /// Consumes the preadmission lease once. The signer releases its journal
    /// fence before replying. A lost/invalid response grants the host nothing.
    pub fn admit(mut self) -> Result<HostRecoveryPublicationAdmission> {
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        self.client
            .check_host_recovery_scope(&self.request.continuity)?;
        let stream = self.stream.as_mut().ok_or(BridgeError::Ipc)?;
        write_frame(
            stream,
            &HostPublicationCommand::Admit {
                lease_id: self.lease_id.clone(),
                request_digest: self.request.digest()?,
            },
        )?;
        let frame = crate::ipc::read_frame_with_deadline(
            stream,
            self.client.peer(),
            Duration::from_secs(30),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let HostPublicationResponse::Admitted { record } =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?
        else {
            return Err(BridgeError::Permission);
        };
        record.validate()?;
        if record.request != self.request
            || record.native_review_digest != self.native_review_digest
            || record.admission_id != self.lease_id
        {
            return Err(BridgeError::Binding);
        }
        // Admission occurred at the signer before its response. No postadmission
        // time/session/network check can retroactively revoke that exact snapshot.
        drop(self.stream.take());
        Ok(HostRecoveryPublicationAdmission {
            record: *record,
            evidence: self.evidence.clone(),
            provider_enrollment_reference: self.client.host_recovery_provider_reference().into(),
        })
    }
}
impl Drop for HostRecoveryPublicationLease<'_> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = write_frame(stream, &HostPublicationCommand::Finish);
        }
    }
}

/// Non-cloneable and non-deserializable one-shot permission to publish the exact
/// restricted informational generation. No signer guard or stream is retained.
/// A host-owned native publication lease must protect the final durable marker.
/// Every later financial operation requires fresh independent authorization.
pub struct HostRecoveryPublicationAdmission {
    record: HostRecoveryPublicationRecord,
    evidence: HostRecoveryContinuityEvidence,
    provider_enrollment_reference: String,
}
impl HostRecoveryPublicationAdmission {
    pub fn binding(&self) -> &HostRecoveryPublicationRequest {
        &self.record.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidence {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        &self.provider_enrollment_reference
    }
    pub fn audit_record(&self) -> &HostRecoveryPublicationRecord {
        &self.record
    }
    pub fn into_audit_record(self) -> HostRecoveryPublicationRecord {
        self.record
    }
}

/// Explicit one-way preadmission state, shared by the native protocol and its
/// no-socket interruption tests. Neither stalled peers nor negative remote
/// observations can promote this state or create a postadmission held fence.
#[cfg(any(test, all(feature = "native-ui", feature = "authority-signing")))]
#[derive(Default)]
pub(crate) struct PublicationWindow {
    closed: bool,
}
#[cfg(any(test, all(feature = "native-ui", feature = "authority-signing")))]
impl PublicationWindow {
    pub(crate) fn remaining(&mut self, elapsed: Duration) -> Result<Duration> {
        if self.closed || elapsed >= Duration::from_secs(30) {
            self.closed = true;
            return Err(BridgeError::Permission);
        }
        Ok(Duration::from_secs(30) - elapsed)
    }
    pub(crate) fn consume(&mut self, elapsed: Duration) -> Result<()> {
        self.remaining(elapsed)?;
        self.closed = true;
        Ok(())
    }
    /// The exact admission decision never carries its journal fence to a peer.
    pub(crate) fn consume_and_release<T>(&mut self, held: T, elapsed: Duration) -> Result<()> {
        let result = self.consume(elapsed);
        drop(held);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> HostRecoveryPublicationRequest {
        HostRecoveryPublicationRequest {
            schema_version: 1,
            continuity: HostRecoveryContinuityRequest {
                schema_version: 1,
                inventory_digest: "11".repeat(32),
                generation_id: "22".repeat(32),
                account_id: "synthetic-account".into(),
                network_profile_id: "synthetic-network".into(),
                expected_writer_epoch: 1,
                expected_witness: wholepact_authority::WitnessDisclosureDescriptor {
                    endpoint: "127.0.0.1:4444".into(),
                    server_name: "localhost".into(),
                    witness_id: "synthetic-witness".into(),
                    account_id: "synthetic-account".into(),
                    network_profile_id: "synthetic-network".into(),
                    policy_digest: "33".repeat(32),
                    pinned_server_certificate_digest: "44".repeat(32),
                },
            },
            target_profile: "/synthetic/host-successor".into(),
            generation_manifest_digest: "55".repeat(32),
            continuity_evidence_digest: "66".repeat(32),
        }
    }
    #[test]
    fn publication_binds_exact_target_manifest_and_prior_disclosure() {
        let original = request();
        let digest = original.digest().unwrap();
        let mut changed = original.clone();
        changed.target_profile = "/synthetic/other-successor".into();
        assert_ne!(digest, changed.digest().unwrap());
        changed = original.clone();
        changed.generation_manifest_digest = "77".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        changed = original.clone();
        changed.continuity_evidence_digest = "88".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        changed = original.clone();
        changed.continuity.generation_id = "99".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        for target in [
            "relative",
            "/",
            "/synthetic/../elsewhere",
            "/synthetic/./target",
            "/synthetic//target",
            "/synthetic/target/",
            "/synthetic/\ntarget",
        ] {
            changed = original.clone();
            changed.target_profile = target.into();
            assert!(changed.validate().is_err());
        }
        for flag in [
            "approved",
            "all_signatures_known",
            "atomic_global_cutoff",
            "financial_authority",
            "recover_writer",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            value[flag] = true.into();
            assert!(serde_json::from_value::<HostRecoveryPublicationRequest>(value).is_err());
        }
    }
    #[test]
    fn publication_requires_exact_live_evidence_and_distinct_wire_command() {
        let mut request = request();
        let evidence = HostRecoveryContinuityEvidence {
            request: request.continuity.clone(),
            writer_certificate_digest: "aa".repeat(32),
            writer_session_id: "bb".repeat(32),
            writer_session_expires_at_ms: 1000,
            head: wholepact_authority::AuthorityHead {
                sequence: 1,
                digest: "cc".repeat(32),
            },
            history_digest: "dd".repeat(32),
            conservative_permits: vec![],
        };
        request.continuity_evidence_digest = evidence.digest().unwrap();
        request.matches_evidence(&evidence).unwrap();
        let mut changed = evidence.clone();
        changed.writer_session_id = "ee".repeat(32);
        assert!(request.matches_evidence(&changed).is_err());
        changed = evidence.clone();
        changed.head.sequence = 2;
        assert!(request.matches_evidence(&changed).is_err());
        changed = evidence.clone();
        changed.request.generation_id = "ff".repeat(32);
        assert!(request.matches_evidence(&changed).is_err());
        let disclosure = serde_json::to_value(&request.continuity).unwrap();
        assert!(serde_json::from_value::<HostRecoveryPublicationRequest>(disclosure).is_err());
        assert!(
            serde_json::from_value::<HostPublicationCommand>(serde_json::json!({
                "operation":"check_current"
            }))
            .is_err()
        );
        let admit = serde_json::to_value(HostPublicationCommand::Admit {
            lease_id: "11".repeat(32),
            request_digest: request.digest().unwrap(),
        })
        .unwrap();
        assert!(
            serde_json::from_value::<super::super::host_recovery_ipc::HostContinuityCommand>(admit)
                .is_err()
        );
        // The audit wire type accepts its own exact fields, never an authority flag.
        let mut record = serde_json::to_value(HostRecoveryPublicationRecord {
            request,
            native_review_digest: "22".repeat(32),
            admission_id: "33".repeat(32),
        })
        .unwrap();
        record["approved"] = true.into();
        assert!(serde_json::from_value::<HostRecoveryPublicationRecord>(record).is_err());
    }
    #[test]
    fn stalled_or_expired_preadmission_cannot_be_promoted_or_renewed() {
        let mut window = PublicationWindow::default();
        assert_eq!(
            window.remaining(Duration::from_secs(29)).unwrap(),
            Duration::from_secs(1)
        );
        assert!(window.consume(Duration::from_secs(30)).is_err());
        assert!(window.consume(Duration::ZERO).is_err());
        let mut window = PublicationWindow::default();
        window
            .consume_and_release((), Duration::from_secs(29))
            .unwrap();
        assert!(window.consume(Duration::from_secs(29)).is_err());
        assert!(window.remaining(Duration::ZERO).is_err());
    }
}

/// Explicit complete-origin publication; no v1 downgrade is provided.
pub mod v2;

// Construction-complete historical family; endpoint remains unavailable.
pub mod v3;

pub mod v4;

// Transport-complete V5 owner; route remains denied pending qualification.
pub mod v5;
