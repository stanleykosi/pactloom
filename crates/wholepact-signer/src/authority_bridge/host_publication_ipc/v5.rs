//! Separate native admission for one exact restricted host recovery generation.
//! An admitted generation is informational. It grants no financial authority,
//! remote witness lease, global cutoff, or continuing signer freeze.
use super::super::{
    BridgeError, Result,
    host_recovery_ipc::v5::{
        HostRecoveryContinuityEvidenceV5, HostRecoveryContinuityRequestV5,
        require_construction_transport_recovery_endpoint,
        transfer::{
            TransferCollector, TransferHeader, TransferPurpose, TransferResponseV1, decode_frame,
        },
        transfer_io::{read_frame_until, require_before_deadline, write_frame_until},
        v5_review_deadline, v5_transfer_deadline,
    },
    ipc::OriginalHistoryClient,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::Duration;
use std::{
    os::unix::net::UnixStream,
    path::{Component, Path, PathBuf},
    time::Instant,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryPublicationRequestV5 {
    pub schema_version: u16,
    pub continuity: HostRecoveryContinuityRequestV5,
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
impl HostRecoveryPublicationRequestV5 {
    /// Builds inert request data. Only a distinct current native review can
    /// admit publication; this constructor never grants permission.
    pub fn new(
        evidence: &HostRecoveryContinuityEvidenceV5,
        target_profile: PathBuf,
        generation_manifest_digest: String,
    ) -> Result<Self> {
        let request = Self {
            schema_version: 5,
            continuity: evidence.request.clone(),
            target_profile,
            generation_manifest_digest,
            continuity_evidence_digest: evidence.digest()?,
        };
        request.matches_evidence(evidence)?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.continuity.validate()?;
        hash(&self.generation_manifest_digest)?;
        hash(&self.continuity_evidence_digest)?;
        let target = self.target_profile.to_str().ok_or(BridgeError::Binding)?;
        // The host separately authenticates its canonical directory handles.
        // This boundary rejects ambiguous textual targets and never opens them.
        if self.schema_version != 5
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
            "wholepact:host-recovery-publication-request:v5",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub fn matches_evidence(&self, evidence: &HostRecoveryContinuityEvidenceV5) -> Result<()> {
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
pub struct HostRecoveryPublicationRecordV5 {
    pub request: HostRecoveryPublicationRequestV5,
    pub native_review_digest: String,
    pub admission_id: String,
}
impl HostRecoveryPublicationRecordV5 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.native_review_digest)?;
        hash(&self.admission_id)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-publication-record:v5",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostPublicationResponseV5 {
    Prepared {
        lease_id: String,
        request_digest: String,
        native_review_digest: String,
        evidence: Box<HostRecoveryContinuityEvidenceV5>,
    },
    Admitted {
        record: Box<HostRecoveryPublicationRecordV5>,
    },
    Finished {},
    Denied {},
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostPublicationCommandV5 {
    Admit {
        lease_id: String,
        request_digest: String,
    },
    Finish {},
}

// Pure binding validation shared by the authenticated response consumer and
// no-socket tests. It returns no owner and cannot turn an audit record into one.
fn require_exact_admission(
    record: &HostRecoveryPublicationRecordV5,
    request: &HostRecoveryPublicationRequestV5,
    native_review_digest: &str,
    lease_id: &str,
) -> Result<()> {
    record.validate()?;
    if &record.request != request
        || record.native_review_digest != native_review_digest
        || record.admission_id != lease_id
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

/// A separately reviewed, bounded preadmission lease. This is not publication
/// permission and is never convertible from the read-only disclosure lease.
pub struct HostRecoveryPublicationLeaseV5<'a> {
    client: &'a OriginalHistoryClient,
    stream: Option<UnixStream>,
    request: HostRecoveryPublicationRequestV5,
    evidence: HostRecoveryContinuityEvidenceV5,
    lease_id: String,
    native_review_digest: String,
    deadline: Instant,
    caller_restricted: bool,
}
// Pure evidence binding only. It cannot manufacture either native review or admission.
fn require_transferred_publication_evidence(
    request: &HostRecoveryPublicationRequestV5,
    header: &TransferHeader,
    evidence: &HostRecoveryContinuityEvidenceV5,
) -> Result<()> {
    header.validate()?;
    request.matches_evidence(evidence)?;
    if header.purpose != TransferPurpose::Publication
        || header.request_digest != request.digest()?
        || header.evidence_digest != evidence.digest()?
        || header.head_digest != evidence.head.digest
        || header.head_sequence != evidence.head.sequence
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
struct PendingPublicationStreamV5(Option<UnixStream>);
impl Drop for PendingPublicationStreamV5 {
    fn drop(&mut self) {
        // Closing a pending channel releases server state without starting a new
        // blocking cleanup timeout while native authority may still be held.
        if let Some(stream) = self.0.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}
impl OriginalHistoryClient {
    /// Requests a new exact native review, independent of historical disclosure
    /// approval. Release any read-only continuity lease before calling this.
    pub fn acquire_host_recovery_publication_v5(
        &self,
        request: &HostRecoveryPublicationRequestV5,
    ) -> Result<HostRecoveryPublicationLeaseV5<'_>> {
        request.validate()?;
        require_construction_transport_recovery_endpoint()?;
        self.acquire_host_recovery_publication_v5_bounded(request, None)
    }
    /// A separate exact informational publication review on the dedicated
    /// quarantined signer-only listener. Never writer/financial activation.
    pub fn acquire_quarantined_informational_publication_v5(
        &self,
        request: &HostRecoveryPublicationRequestV5,
    ) -> Result<HostRecoveryPublicationLeaseV5<'_>> {
        request.validate()?;
        crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(
        )?;
        self.acquire_host_recovery_publication_v5_bounded(request, None)
    }
    /// Carries the original caller deadline through native review, complete
    /// reconstruction and Admit. It can only shorten existing local/native caps.
    pub fn acquire_quarantined_informational_publication_v5_until(
        &self,
        request: &HostRecoveryPublicationRequestV5,
        original_deadline: Instant,
    ) -> Result<HostRecoveryPublicationLeaseV5<'_>> {
        require_before_deadline(original_deadline)?;
        request.validate()?;
        crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(
        )?;
        self.acquire_host_recovery_publication_v5_bounded(request, Some(original_deadline))
    }
    fn acquire_host_recovery_publication_v5_bounded(
        &self,
        request: &HostRecoveryPublicationRequestV5,
        original_deadline: Option<Instant>,
    ) -> Result<HostRecoveryPublicationLeaseV5<'_>> {
        self.check_host_recovery_v5_scope(
            &request.continuity.account_id,
            &request.continuity.inventory_digest,
        )?;
        let request_frame = serde_json::json!({
            "operation":"request_host_recovery_publication_v5", "request":request,
            "transfer_dialect":"v5_bounded_transfer_v1"
        });
        let (stream, original_deadline) = match original_deadline {
            Some(original) => {
                let review_deadline = v5_review_deadline(Some(original), Instant::now())?;
                let (stream, deadline) =
                    self.open_quarantined_v5_request_until(request_frame, review_deadline)?;
                (stream, Some(deadline))
            }
            None => (self.open_authenticated_request(request_frame)?, None),
        };
        let mut pending = PendingPublicationStreamV5(Some(stream));
        // This first bounded frame includes the original native-review wait.
        // Once Begin arrives the client never resets its local transfer budget;
        // the server independently enforces its earlier post-review start.
        let frame = read_frame_until(
            pending.0.as_ref().ok_or(BridgeError::Ipc)?,
            self.peer(),
            v5_review_deadline(original_deadline, Instant::now())?,
        )?;
        let deadline = v5_transfer_deadline(original_deadline, Instant::now())?;
        let check = || -> Result<()> {
            self.check_host_recovery_v5_scope(
                &request.continuity.account_id,
                &request.continuity.inventory_digest,
            )?;
            require_before_deadline(deadline)
        };
        check()?;
        let TransferResponseV1::Begin { header } = decode_frame(&frame)? else {
            return Err(BridgeError::Permission);
        };
        let mut collector =
            TransferCollector::new(TransferPurpose::Publication, request.digest()?)?;
        collector.begin(header)?;
        let header = collector.header()?.clone();
        hash(&header.lease_id)?;
        hash(&header.native_review_digest)?;
        for _ in 0..header.chunk_count {
            self.check_host_recovery_v5_scope(
                &request.continuity.account_id,
                &request.continuity.inventory_digest,
            )?;
            let command = collector.next_request()?;
            let stream = pending.0.as_mut().ok_or(BridgeError::Ipc)?;
            write_frame_until(stream, &command, deadline)?;
            let frame = read_frame_until(stream, self.peer(), deadline)?;
            check()?;
            let TransferResponseV1::Chunk { chunk } = decode_frame(&frame)? else {
                return Err(BridgeError::Permission);
            };
            collector.accept_chunk(chunk)?;
            check()?;
        }
        let mut complete = collector.finish()?;
        let evidence: HostRecoveryContinuityEvidenceV5 =
            serde_json::from_slice(complete.bytes()).map_err(|_| BridgeError::Ipc)?;
        require_transferred_publication_evidence(request, &header, &evidence)?;
        check()?;
        let command = complete.accept_complete(&evidence.digest()?)?;
        self.check_host_recovery_v5_scope(
            &request.continuity.account_id,
            &request.continuity.inventory_digest,
        )?;
        let stream = pending.0.as_mut().ok_or(BridgeError::Ipc)?;
        write_frame_until(stream, &command, deadline)?;
        let frame = read_frame_until(stream, self.peer(), deadline)?;
        check()?;
        let response: TransferResponseV1 = decode_frame(&frame)?;
        complete.require_confirmation(&response)?;
        self.check_host_recovery_v5_scope(
            &request.continuity.account_id,
            &request.continuity.inventory_digest,
        )?;
        require_before_deadline(deadline)?;
        let lease_id = header.lease_id;
        let native_review_digest = header.native_review_digest;
        Ok(HostRecoveryPublicationLeaseV5 {
            client: self,
            stream: pending.0.take(),
            request: request.clone(),
            evidence,
            lease_id,
            native_review_digest,
            deadline,
            caller_restricted: original_deadline.is_some(),
        })
    }
}
impl HostRecoveryPublicationLeaseV5<'_> {
    pub fn binding(&self) -> &HostRecoveryPublicationRequestV5 {
        &self.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV5 {
        &self.evidence
    }
    /// Consumes the preadmission lease once. The signer releases its journal
    /// fence before replying. A lost/invalid response grants the host nothing.
    pub fn admit(mut self) -> Result<HostRecoveryPublicationAdmissionV5> {
        require_before_deadline(self.deadline)?;
        self.client.check_host_recovery_v5_scope(
            &self.request.continuity.account_id,
            &self.request.continuity.inventory_digest,
        )?;
        let stream = self.stream.as_mut().ok_or(BridgeError::Ipc)?;
        let deadline = self.deadline;
        write_frame_until(
            stream,
            &HostPublicationCommandV5::Admit {
                lease_id: self.lease_id.clone(),
                request_digest: self.request.digest()?,
            },
            deadline,
        )?;
        let frame = read_frame_until(stream, self.client.peer(), deadline)?;
        let HostPublicationResponseV5::Admitted { record } = decode_frame(&frame)? else {
            return Err(BridgeError::Permission);
        };
        require_exact_admission(
            &record,
            &self.request,
            &self.native_review_digest,
            &self.lease_id,
        )?;
        // A dedicated caller restriction must still hold before issuing a local
        // admission owner. A late result remains uncertain: refusal cannot undo
        // the signer's earlier admission. Ordinary response semantics stay intact.
        if self.caller_restricted {
            require_before_deadline(deadline)?;
        }
        // Admission occurred at the signer before its response. No postadmission
        // check can retroactively revoke that exact snapshot.
        drop(self.stream.take());
        let admission = HostRecoveryPublicationAdmissionV5 {
            record: *record,
            evidence: self.evidence.clone(),
            provider_enrollment_reference: self.client.host_recovery_provider_reference().into(),
        };
        if self.caller_restricted {
            require_before_deadline(deadline)?;
        }
        Ok(admission)
    }
}
impl Drop for HostRecoveryPublicationLeaseV5<'_> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Non-cloneable and non-deserializable one-shot permission to publish the exact
/// restricted informational generation. No signer guard or stream is retained.
/// A host-owned native publication lease must protect the final durable marker.
/// Every later financial operation requires fresh independent authorization.
pub struct HostRecoveryPublicationAdmissionV5 {
    record: HostRecoveryPublicationRecordV5,
    evidence: HostRecoveryContinuityEvidenceV5,
    provider_enrollment_reference: String,
}
impl HostRecoveryPublicationAdmissionV5 {
    /// Consumes the one-shot owner only for the host's independently retained
    /// exact evidence and destination. A host native publication lease must
    /// still fence the final durable marker; this is no financial authority.
    pub fn consume(
        self,
        evidence: &HostRecoveryContinuityEvidenceV5,
        target_profile: &Path,
        generation_manifest_digest: &str,
    ) -> Result<HostRecoveryPublicationRecordV5> {
        self.record.validate()?;
        self.record.request.matches_evidence(evidence)?;
        if &self.evidence != evidence
            || self.record.request.target_profile.as_path() != target_profile
            || self.record.request.generation_manifest_digest != generation_manifest_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(self.record)
    }

    pub fn binding(&self) -> &HostRecoveryPublicationRequestV5 {
        &self.record.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV5 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        &self.provider_enrollment_reference
    }
    pub fn audit_record(&self) -> &HostRecoveryPublicationRecordV5 {
        &self.record
    }
    pub fn into_audit_record(self) -> HostRecoveryPublicationRecordV5 {
        self.record
    }
}

#[cfg(test)]
mod tests;
