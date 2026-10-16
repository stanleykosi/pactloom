//! Separate native admission for one exact restricted host recovery generation.
//! An admitted generation is informational. It grants no financial authority,
//! remote witness lease, global cutoff, or continuing signer freeze.
use super::super::{
    BridgeError, Result,
    dispatch_ipc::write_frame,
    host_recovery_ipc::v2::{
        HostRecoveryContinuityEvidenceV2, HostRecoveryContinuityRequestV2,
        require_complete_origin_endpoint,
    },
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
pub struct HostRecoveryPublicationRequestV2 {
    pub schema_version: u16,
    pub continuity: HostRecoveryContinuityRequestV2,
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
impl HostRecoveryPublicationRequestV2 {
    pub fn validate(&self) -> Result<()> {
        self.continuity.validate()?;
        hash(&self.generation_manifest_digest)?;
        hash(&self.continuity_evidence_digest)?;
        let target = self.target_profile.to_str().ok_or(BridgeError::Binding)?;
        // The host separately authenticates its canonical directory handles.
        // This boundary rejects ambiguous textual targets and never opens them.
        if self.schema_version != 2
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
            "wholepact:host-recovery-publication-request:v2",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub fn matches_evidence(&self, evidence: &HostRecoveryContinuityEvidenceV2) -> Result<()> {
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
pub struct HostRecoveryPublicationRecordV2 {
    pub request: HostRecoveryPublicationRequestV2,
    pub native_review_digest: String,
    pub admission_id: String,
}
impl HostRecoveryPublicationRecordV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.native_review_digest)?;
        hash(&self.admission_id)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-publication-record:v2",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostPublicationResponseV2 {
    Prepared {
        lease_id: String,
        request_digest: String,
        native_review_digest: String,
        evidence: Box<HostRecoveryContinuityEvidenceV2>,
    },
    Admitted {
        record: Box<HostRecoveryPublicationRecordV2>,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostPublicationCommandV2 {
    Admit {
        lease_id: String,
        request_digest: String,
    },
    Finish,
}

/// A separately reviewed, bounded preadmission lease. This is not publication
/// permission and is never convertible from the read-only disclosure lease.
pub struct HostRecoveryPublicationLeaseV2<'a> {
    client: &'a OriginalHistoryClient,
    stream: Option<UnixStream>,
    request: HostRecoveryPublicationRequestV2,
    evidence: HostRecoveryContinuityEvidenceV2,
    lease_id: String,
    native_review_digest: String,
    started: Instant,
}
struct PendingPublicationStreamV2(Option<UnixStream>);
impl Drop for PendingPublicationStreamV2 {
    fn drop(&mut self) {
        if let Some(stream) = self.0.as_mut() {
            let _ = write_frame(stream, &HostPublicationCommandV2::Finish);
        }
    }
}
impl OriginalHistoryClient {
    /// Requests a new exact native review, independent of historical disclosure
    /// approval. Release any read-only continuity lease before calling this.
    pub fn acquire_host_recovery_publication_v2(
        &self,
        request: &HostRecoveryPublicationRequestV2,
    ) -> Result<HostRecoveryPublicationLeaseV2<'_>> {
        request.validate()?;
        require_complete_origin_endpoint()?;
        self.check_host_recovery_account_scope(&request.continuity.account_id)?;
        let stream = self.open_authenticated_request(serde_json::json!({
            "operation":"request_host_recovery_publication_v2", "request":request
        }))?;
        let mut pending = PendingPublicationStreamV2(Some(stream));
        let frame = crate::ipc::read_frame_with_deadline(
            pending.0.as_ref().ok_or(BridgeError::Ipc)?,
            self.peer(),
            Duration::from_secs(120),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let HostPublicationResponseV2::Prepared {
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
        Ok(HostRecoveryPublicationLeaseV2 {
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
impl HostRecoveryPublicationLeaseV2<'_> {
    pub fn binding(&self) -> &HostRecoveryPublicationRequestV2 {
        &self.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV2 {
        &self.evidence
    }
    /// Consumes the preadmission lease once. The signer releases its journal
    /// fence before replying. A lost/invalid response grants the host nothing.
    pub fn admit(mut self) -> Result<HostRecoveryPublicationAdmissionV2> {
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err(BridgeError::Permission);
        }
        self.client
            .check_host_recovery_account_scope(&self.request.continuity.account_id)?;
        let stream = self.stream.as_mut().ok_or(BridgeError::Ipc)?;
        write_frame(
            stream,
            &HostPublicationCommandV2::Admit {
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
        let HostPublicationResponseV2::Admitted { record } =
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
        Ok(HostRecoveryPublicationAdmissionV2 {
            record: *record,
            evidence: self.evidence.clone(),
            provider_enrollment_reference: self.client.host_recovery_provider_reference().into(),
        })
    }
}
impl Drop for HostRecoveryPublicationLeaseV2<'_> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = write_frame(stream, &HostPublicationCommandV2::Finish);
        }
    }
}

/// Non-cloneable and non-deserializable one-shot permission to publish the exact
/// restricted informational generation. No signer guard or stream is retained.
/// A host-owned native publication lease must protect the final durable marker.
/// Every later financial operation requires fresh independent authorization.
pub struct HostRecoveryPublicationAdmissionV2 {
    record: HostRecoveryPublicationRecordV2,
    evidence: HostRecoveryContinuityEvidenceV2,
    provider_enrollment_reference: String,
}
impl HostRecoveryPublicationAdmissionV2 {
    pub fn binding(&self) -> &HostRecoveryPublicationRequestV2 {
        &self.record.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV2 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        &self.provider_enrollment_reference
    }
    pub fn audit_record(&self) -> &HostRecoveryPublicationRecordV2 {
        &self.record
    }
    pub fn into_audit_record(self) -> HostRecoveryPublicationRecordV2 {
        self.record
    }
}
