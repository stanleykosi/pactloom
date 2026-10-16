//! Native-reviewed account-wide continuity evidence for one exact restored
//! host inventory. This authenticates a surviving signer, never restores it or
//! proves completeness of a host inventory or of signatures outside this protocol.
use super::super::{BridgeError, Result, ipc::OriginalHistoryClient};
mod history;
pub(crate) mod transfer;
pub use transfer::V5TransferDialect;
pub(crate) mod transfer_io;
pub use history::*;
use serde::{Deserialize, Serialize};
use std::{
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
use wholepact_authority::{AuthorityHead, WitnessDisclosureDescriptor};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityRequestV5 {
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
impl HostRecoveryContinuityRequestV5 {
    pub fn validate(&self) -> Result<()> {
        hash(&self.inventory_digest)?;
        hash(&self.generation_id)?;
        self.expected_witness.validate()?;
        if self.schema_version != 5
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
            "wholepact:host-recovery-continuity-request:v5",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
/// Audit data only. A saved copy is never current authority. Every permit is
/// conservatively executable for host recovery, regardless of recorded resolution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryContinuityEvidenceV5 {
    pub request: HostRecoveryContinuityRequestV5,
    pub writer_certificate_digest: String,
    /// Historical active-session slot at the observed head, never writer authority.
    /// Explicit paired null records that the snapshot has no active session.
    #[serde(deserialize_with = "required_historical_field")]
    pub writer_session_id: Option<String>,
    #[serde(deserialize_with = "required_historical_field")]
    pub writer_session_expires_at_ms: Option<u64>,
    pub head: AuthorityHead,
    pub history_digest: String,
    pub complete_history: HostRecoveryHistoryV5,
}
// Keep the fields mandatory even though their explicit JSON values may be null.
// This prevents omitted evidence from silently becoming a no-session assertion.
fn required_historical_field<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
impl HostRecoveryContinuityEvidenceV5 {
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
            "wholepact:host-recovery-continuity-evidence:v5",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub fn validate(&self) -> Result<()> {
        history::require_encoded_limit(self, MAX_COMPLETE_HISTORY_V5_BYTES + 4096)?;
        self.request.validate()?;
        for value in [
            &self.writer_certificate_digest,
            &self.head.digest,
            &self.history_digest,
        ] {
            hash(value)?;
        }
        if self.head.sequence > i64::MAX as u64 {
            return Err(BridgeError::Binding);
        }
        let snapshot = self.complete_history.construction.observed_snapshot();
        if self
            .complete_history
            .construction
            .original
            .complete_replay_digest()
            != self.history_digest
            || snapshot.writer_certificate_digest != self.writer_certificate_digest
            || snapshot.writer_epoch != self.request.expected_writer_epoch
        {
            return Err(BridgeError::Binding);
        }
        match (
            snapshot.active_writer_session.as_ref(),
            self.writer_session_id.as_deref(),
            self.writer_session_expires_at_ms,
        ) {
            (Some(historical), Some(id), Some(expires)) => {
                hash(id)?;
                if expires == 0
                    || expires > i64::MAX as u64
                    || historical.session_id != id
                    || historical.writer_certificate_digest != self.writer_certificate_digest
                    || historical.expires_at_ms != expires
                    || historical.writer_epoch != self.request.expected_writer_epoch
                    || historical.disclosure != self.request.expected_witness
                {
                    return Err(BridgeError::Binding);
                }
            }
            (None, None, None) => {}
            _ => return Err(BridgeError::Binding),
        }
        // Paused/revoked/quarantined/fenced state is truthful historical data.
        // Fresh observation ownership is separate, and no writer authority is
        // derived from this saved record or its former active-session slot.
        self.complete_history.validate(
            &self.request.account_id,
            &self.request.network_profile_id,
            &self.request.expected_witness,
            &self.head,
            self.request.expected_writer_epoch,
        )?;
        Ok(())
    }
}

/// Generic active-writer V5 routing remains unavailable. The separate narrow
/// quarantined informational route requires its own real readonly account/native
/// owners and never turns archive validation into writer or financial admission.
pub const CONSTRUCTION_TRANSPORT_RECOVERY_ENDPOINT_UNAVAILABLE: &str = "Construction transport recovery v5 is unavailable until its native continuity producer and complete downstream archived consumers are qualified";
pub fn require_construction_transport_recovery_endpoint() -> Result<()> {
    Err(BridgeError::CompleteOriginRecoveryUnavailable)
}

/// Separate source route for the dedicated signer-only informational owner.
/// This availability check grants no account, peer, native or witness authority.
/// Generic V5 and all financial startup routes retain their existing denial.
pub fn require_quarantined_informational_endpoint() -> Result<()> {
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostContinuityResponseV5 {
    Held {
        lease_id: String,
        evidence: Box<HostRecoveryContinuityEvidenceV5>,
    },
    Current {
        lease_id: String,
        evidence_digest: String,
    },
    Finished {},
    Denied {},
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostContinuityCommandV5 {
    CheckCurrent {},
    Finish {},
}

/// Sealed, process-bound, short-lived read-only continuity proof. This does not
/// admit publication, activate the host, or authorize a durable external effect.
/// There is no constructor from audit evidence and no Clone.
pub struct HostRecoveryContinuityLeaseV5<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    evidence: HostRecoveryContinuityEvidenceV5,
    evidence_digest: String,
    deadline: Instant,
}
struct PendingContinuityStreamV5(Option<UnixStream>);
impl Drop for PendingContinuityStreamV5 {
    fn drop(&mut self) {
        // Closing is cancellation. Never create a new write timeout while
        // unwinding failed or expired acquisition, or wait for an acknowledgement.
        if let Some(stream) = self.0.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}
impl OriginalHistoryClient {
    /// Requests a distinct native review disclosing complete account exposure.
    /// An existing agreement-history grant alone does not approve this disclosure.
    pub fn acquire_host_recovery_continuity_v5(
        &self,
        request: &HostRecoveryContinuityRequestV5,
    ) -> Result<HostRecoveryContinuityLeaseV5<'_>> {
        request.validate()?;
        require_construction_transport_recovery_endpoint()?;
        self.acquire_host_recovery_continuity_v5_bounded(request, None)
    }
    /// Requests only the separately entered quarantined signer-only native mode.
    /// A fresh exact pairing and native disclosure review are still mandatory.
    /// The returned lease is informational and has no writer/financial conversion.
    pub fn acquire_quarantined_informational_continuity_v5(
        &self,
        request: &HostRecoveryContinuityRequestV5,
    ) -> Result<HostRecoveryContinuityLeaseV5<'_>> {
        request.validate()?;
        require_quarantined_informational_endpoint()?;
        self.acquire_host_recovery_continuity_v5_bounded(request, None)
    }
    /// Adds only an immutable caller restriction. Neither native review nor
    /// Begin, Current or Finish may renew this original absolute deadline.
    pub fn acquire_quarantined_informational_continuity_v5_until(
        &self,
        request: &HostRecoveryContinuityRequestV5,
        original_deadline: Instant,
    ) -> Result<HostRecoveryContinuityLeaseV5<'_>> {
        transfer_io::require_before_deadline(original_deadline)?;
        request.validate()?;
        require_quarantined_informational_endpoint()?;
        self.acquire_host_recovery_continuity_v5_bounded(request, Some(original_deadline))
    }
    fn acquire_host_recovery_continuity_v5_bounded(
        &self,
        request: &HostRecoveryContinuityRequestV5,
        original_deadline: Option<Instant>,
    ) -> Result<HostRecoveryContinuityLeaseV5<'_>> {
        self.check_host_recovery_v5_scope(&request.account_id, &request.inventory_digest)?;
        let request_frame = serde_json::json!({
            "operation":"request_host_recovery_continuity_v5", "request":request,
            "transfer_dialect":transfer::TRANSFER_DIALECT_V1
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
        // Every failed acquisition closes this same authenticated channel. A
        // partial reconstruction never becomes evidence or a continuity lease.
        let mut pending = PendingContinuityStreamV5(Some(stream));
        let stream = pending.0.as_mut().ok_or(BridgeError::Ipc)?;
        let mut collector = transfer::TransferCollector::new(
            transfer::TransferPurpose::Continuity,
            request.digest()?,
        )?;
        // Native review retains its separate 120-second allowance. Receipt of
        // Begin starts the local transfer ceiling; the server's earlier clock
        // includes post-review replay and cannot be extended by this clock.
        let review_deadline = v5_review_deadline(original_deadline, Instant::now())?;
        let frame = transfer_io::read_frame_until(stream, self.peer(), review_deadline)?;
        let deadline = v5_transfer_deadline(original_deadline, Instant::now())?;
        let check = || -> Result<()> {
            transfer_io::require_before_deadline(deadline)?;
            self.check_host_recovery_v5_scope(&request.account_id, &request.inventory_digest)?;
            transfer_io::require_before_deadline(deadline)
        };
        check()?;
        let response: transfer::TransferResponseV1 = transfer::decode_frame(&frame)?;
        let transfer::TransferResponseV1::Begin { header } = response else {
            return Err(BridgeError::Permission);
        };
        collector.begin(header)?;
        check()?;
        for _ in 0..collector.header()?.chunk_count {
            let command = collector.next_request()?;
            check()?;
            transfer_io::write_frame_until(stream, &command, deadline)?;
            check()?;
            let frame = transfer_io::read_frame_until(stream, self.peer(), deadline)?;
            check()?;
            let response: transfer::TransferResponseV1 = transfer::decode_frame(&frame)?;
            let transfer::TransferResponseV1::Chunk { chunk } = response else {
                return Err(BridgeError::Binding);
            };
            collector.accept_chunk(chunk)?;
            check()?;
        }
        let mut complete = collector.finish()?;
        check()?;
        let evidence = validate_complete_continuity_transfer(&complete, request)?;
        let evidence_digest = evidence.digest()?;
        let lease_id = complete.header().lease_id.clone();
        check()?;
        let accept = complete.accept_complete(&evidence_digest)?;
        transfer_io::write_frame_until(stream, &accept, deadline)?;
        check()?;
        let frame = transfer_io::read_frame_until(stream, self.peer(), deadline)?;
        check()?;
        let response: transfer::TransferResponseV1 = transfer::decode_frame(&frame)?;
        complete.require_confirmation(&response)?;
        check()?;
        // Scratch bytes are zeroized before constructing the private lease.
        // Confirmation is necessary but is never sufficient without Current.
        drop(complete);
        let lease = HostRecoveryContinuityLeaseV5 {
            client: self,
            stream: Mutex::new(pending.0.take().ok_or(BridgeError::Ipc)?),
            lease_id,
            evidence,
            evidence_digest,
            deadline,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
/// Pure restriction-only clock selection shared by both dedicated V5 clients.
/// None preserves the generic path's existing local cap. Some can only shorten it.
pub(in crate::authority_bridge) fn v5_review_deadline(
    original: Option<Instant>,
    now: Instant,
) -> Result<Instant> {
    v5_capped_deadline(original, now, Duration::from_secs(120))
}
pub(in crate::authority_bridge) fn v5_transfer_deadline(
    original: Option<Instant>,
    now: Instant,
) -> Result<Instant> {
    v5_capped_deadline(original, now, Duration::from_secs(30))
}
fn v5_capped_deadline(original: Option<Instant>, now: Instant, cap: Duration) -> Result<Instant> {
    let deadline = original.map_or(now + cap, |original| original.min(now + cap));
    if now >= deadline {
        return Err(BridgeError::Permission);
    }
    Ok(deadline)
}

/// Full schema validation is deliberately separate from the byte collector.
/// This helper is private and returns only inert evidence, never a sealed lease.
fn validate_complete_continuity_transfer(
    complete: &transfer::CompleteTransferBytes,
    request: &HostRecoveryContinuityRequestV5,
) -> Result<HostRecoveryContinuityEvidenceV5> {
    let bytes = complete.bytes();
    if bytes.first() != Some(&b'{') || bytes.last() != Some(&b'}') {
        return Err(BridgeError::Binding);
    }
    let evidence: HostRecoveryContinuityEvidenceV5 =
        serde_json::from_slice(bytes).map_err(|_| BridgeError::Binding)?;
    require_transferred_continuity_evidence(request, complete.header(), &evidence)?;
    Ok(evidence)
}
fn require_transferred_continuity_evidence(
    request: &HostRecoveryContinuityRequestV5,
    header: &transfer::TransferHeader,
    evidence: &HostRecoveryContinuityEvidenceV5,
) -> Result<()> {
    evidence.validate()?;
    if header.purpose != transfer::TransferPurpose::Continuity
        || &evidence.request != request
        || header.request_digest != request.digest()?
        || header.head_digest != evidence.head.digest
        || header.head_sequence != evidence.head.sequence
        || header.evidence_digest != evidence.digest()?
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl HostRecoveryContinuityLeaseV5<'_> {
    /// Explicitly completes this exact read-only phase on the retained stream.
    /// Drop remains cancellation and cannot produce successful native completion.
    /// No retry, replacement channel or fresh deadline is created. Success grants
    /// no publication authority; the next phase still requires fresh native review.
    pub fn finish(mut self) -> Result<()> {
        let deadline = self.deadline;
        transfer_io::require_before_deadline(deadline)?;
        let request = &self.evidence.request;
        self.client
            .check_host_recovery_v5_scope(&request.account_id, &request.inventory_digest)?;
        // Consuming self gives exclusive access without waiting on the mutex.
        let stream = self.stream.get_mut().map_err(|_| BridgeError::Ipc)?;
        transfer_io::write_frame_until(stream, &HostContinuityCommandV5::Finish {}, deadline)?;
        self.client
            .check_host_recovery_v5_scope(&request.account_id, &request.inventory_digest)?;
        let frame = transfer_io::read_frame_until(stream, self.client.peer(), deadline)?;
        let response: HostContinuityResponseV5 = transfer::decode_frame(&frame)?;
        require_explicit_continuity_finished(&response)?;
        self.client
            .check_host_recovery_v5_scope(&request.account_id, &request.inventory_digest)?;
        transfer_io::require_before_deadline(deadline)
    }
    pub fn binding(&self) -> &HostRecoveryContinuityRequestV5 {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV5 {
        &self.evidence
    }
    pub fn complete_history(&self) -> &HostRecoveryHistoryV5 {
        &self.evidence.complete_history
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.client.host_recovery_provider_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        transfer_io::require_before_deadline(self.deadline)?;
        self.client.check_host_recovery_v5_scope(
            &self.binding().account_id,
            &self.binding().inventory_digest,
        )?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        let deadline = self.deadline;
        transfer_io::require_before_deadline(deadline)?;
        transfer_io::write_frame_until(
            &mut stream,
            &HostContinuityCommandV5::CheckCurrent {},
            deadline,
        )?;
        self.client.check_host_recovery_v5_scope(
            &self.binding().account_id,
            &self.binding().inventory_digest,
        )?;
        let frame = transfer_io::read_frame_until(&stream, self.client.peer(), deadline)?;
        let response: HostContinuityResponseV5 = transfer::decode_frame(&frame)?;
        transfer_io::require_before_deadline(self.deadline)?;
        self.client.check_host_recovery_v5_scope(
            &self.binding().account_id,
            &self.binding().inventory_digest,
        )?;
        match response {
            HostContinuityResponseV5::Current {
                lease_id,
                evidence_digest,
            } if lease_id == self.lease_id && evidence_digest == self.evidence_digest => {
                transfer_io::require_before_deadline(deadline)
            }
            _ => Err(BridgeError::Permission),
        }
    }
}
fn require_explicit_continuity_finished(response: &HostContinuityResponseV5) -> Result<()> {
    match response {
        HostContinuityResponseV5::Finished {} => Ok(()),
        _ => Err(BridgeError::Permission),
    }
}
impl Drop for HostRecoveryContinuityLeaseV5<'_> {
    fn drop(&mut self) {
        // We exclusively own the lease at Drop. No lock wait, acknowledgement
        // drain or fresh network timeout may extend its original deadline.
        if let Ok(stream) = self.stream.get_mut() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// V5 archives retain their larger immutable storage budget. Wire disclosure
/// never truncates complete evidence or widens the existing IPC frame ceiling.
pub(crate) fn require_wire_capacity<T: Serialize>(value: &T) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| BridgeError::Ipc)?);
    if bytes.len() > 128 * 1024 {
        return Err(BridgeError::Limit);
    }
    Ok(())
}

#[cfg(test)]
mod bounded_continuity_tests {
    use super::*;
    use crate::consent_journal::common_context_reentry_audit_fixture as fixture;
    use transfer::{
        TransferCollector, TransferMetadata, TransferPurpose, TransferResponseV1, TransferSender,
    };

    // Pure production encoder/collector/semantic-validation composition. This
    // does not manufacture a native owner, socket, continuity lease or admission.
    #[test]
    fn complete_continuity_transfer_preserves_canonical_history_and_semantic_digest() {
        let evidence = fixture::fixture();
        let original = serde_json::to_vec(&evidence).unwrap();
        let semantic_digest = evidence.digest().unwrap();
        assert_eq!(original.len(), 683_170);
        let mut sender = TransferSender::new(
            TransferMetadata {
                purpose: TransferPurpose::Continuity,
                transfer_id: "81".repeat(32),
                lease_id: "82".repeat(32),
                request_digest: evidence.request.digest().unwrap(),
                native_review_digest: "83".repeat(32),
                evidence_digest: semantic_digest.clone(),
                head_digest: evidence.head.digest.clone(),
                head_sequence: evidence.head.sequence,
            },
            &evidence,
        )
        .unwrap();
        let header = sender.begin().unwrap();
        assert_eq!(header.chunk_count, 21);
        let mut collector = TransferCollector::new(
            TransferPurpose::Continuity,
            evidence.request.digest().unwrap(),
        )
        .unwrap();
        let begin_bytes = transfer::encode_frame(&TransferResponseV1::Begin {
            header: header.clone(),
        })
        .unwrap();
        let TransferResponseV1::Begin { header: received } =
            transfer::decode_frame(&begin_bytes).unwrap()
        else {
            panic!("expected Begin")
        };
        collector.begin(received).unwrap();
        let mut maximum_frame = begin_bytes.len() + 1;
        for _ in 0..header.chunk_count {
            let next = collector.next_request().unwrap();
            let next_bytes = transfer::encode_frame(&next).unwrap();
            let next = transfer::decode_frame(&next_bytes).unwrap();
            let chunk = sender.next(&next).unwrap();
            let bytes = transfer::encode_frame(&TransferResponseV1::Chunk { chunk }).unwrap();
            maximum_frame = maximum_frame.max(bytes.len() + 1);
            let TransferResponseV1::Chunk { chunk } = transfer::decode_frame(&bytes).unwrap()
            else {
                panic!("expected Chunk")
            };
            collector.accept_chunk(chunk).unwrap();
        }
        assert!(maximum_frame <= transfer::MAX_TRANSFER_FRAME_BYTES);
        let mut complete = collector.finish().unwrap();
        assert_eq!(complete.bytes(), original);
        let restored = validate_complete_continuity_transfer(&complete, &evidence.request).unwrap();
        assert!(restored == evidence);
        assert_eq!(restored.digest().unwrap(), semantic_digest);
        let accept = complete.accept_complete(&semantic_digest).unwrap();
        sender.accept_complete(&accept).unwrap();
        complete
            .require_confirmation(&sender.confirmation().unwrap())
            .unwrap();
        assert_eq!(&*complete.into_bytes().unwrap(), &original);
        assert!(
            restored
                .complete_history
                .require_financial_activation_supported()
                .is_err()
        );
        assert!(require_construction_transport_recovery_endpoint().is_err());
        eprintln!(
            "bounded continuity evidence_bytes={} chunks={} max_wire_frame={}",
            original.len(),
            header.chunk_count,
            maximum_frame
        );
    }

    #[test]
    fn complete_continuity_validation_rejects_purpose_request_head_and_semantic_substitution() {
        let evidence = fixture::fixture();
        let sender = TransferSender::new(
            TransferMetadata {
                purpose: TransferPurpose::Continuity,
                transfer_id: "81".repeat(32),
                lease_id: "82".repeat(32),
                request_digest: evidence.request.digest().unwrap(),
                native_review_digest: "83".repeat(32),
                evidence_digest: evidence.digest().unwrap(),
                head_digest: evidence.head.digest.clone(),
                head_sequence: evidence.head.sequence,
            },
            &evidence,
        )
        .unwrap();
        for changed_field in 0..5 {
            let mut header = sender.header().clone();
            match changed_field {
                0 => header.purpose = TransferPurpose::Publication,
                1 => header.request_digest = "84".repeat(32),
                2 => header.evidence_digest = "84".repeat(32),
                3 => header.head_digest = "84".repeat(32),
                _ => header.head_sequence += 1,
            }
            assert!(
                require_transferred_continuity_evidence(&evidence.request, &header, &evidence,)
                    .is_err()
            );
        }
        let mut changed_request = evidence.request.clone();
        changed_request.inventory_digest = "84".repeat(32);
        assert!(
            require_transferred_continuity_evidence(&changed_request, sender.header(), &evidence,)
                .is_err()
        );
        // Old peers cannot silently turn a requested bounded transfer into Held.
        assert!(
            transfer::decode_frame::<TransferResponseV1>(
                br#"{"status":"held","lease_id":"00","evidence":null}"#,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod explicit_continuity_finish_tests {
    use super::*;
    #[test]
    fn explicit_finish_accepts_only_finished_on_the_existing_response_protocol() {
        require_explicit_continuity_finished(&HostContinuityResponseV5::Finished {}).unwrap();
        assert!(
            require_explicit_continuity_finished(&HostContinuityResponseV5::Denied {}).is_err()
        );
        assert!(
            require_explicit_continuity_finished(&HostContinuityResponseV5::Current {
                lease_id: "11".repeat(32),
                evidence_digest: "22".repeat(32),
            })
            .is_err()
        );
        assert_eq!(
            serde_json::to_string(&HostContinuityResponseV5::Finished {}).unwrap(),
            r#"{"status":"finished"}"#
        );
        assert_eq!(
            serde_json::to_string(&HostContinuityCommandV5::Finish {}).unwrap(),
            r#"{"operation":"finish"}"#
        );
        for wire in [
            br#"{"operation":"finish","approved":true}"#.as_slice(),
            br#"{"operation":"check_current","approved":true}"#.as_slice(),
        ] {
            assert!(transfer::decode_frame::<HostContinuityCommandV5>(wire).is_err());
        }
        for wire in [
            br#"{"status":"finished","approved":true}"#.as_slice(),
            br#"{"status":"denied","approved":true}"#.as_slice(),
            br#"{"status":"prepared_complete","binding":{}}"#.as_slice(),
            br#"{"status":"held_complete","binding":{}}"#.as_slice(),
        ] {
            assert!(transfer::decode_frame::<HostContinuityResponseV5>(wire).is_err());
        }
    }
}

#[cfg(test)]
mod caller_deadline_tests {
    use super::*;
    #[test]
    fn v5_original_review_and_transfer_deadlines_never_renew() {
        // Clocks only: no client, credential, provider, socket or native owner.
        let now = Instant::now();
        let original = now + Duration::from_secs(12);
        let review = v5_review_deadline(Some(original), now).unwrap();
        assert_eq!(review, original);
        let transfer = v5_transfer_deadline(Some(review), now + Duration::from_secs(9)).unwrap();
        assert_eq!(transfer, original);
        for offset in [12, 13, 120] {
            let late = now + Duration::from_secs(offset);
            assert!(v5_review_deadline(Some(original), late).is_err());
            assert!(v5_transfer_deadline(Some(transfer), late).is_err());
        }
    }
    #[test]
    fn v5_local_caps_only_shorten_longer_caller_budgets() {
        let now = Instant::now();
        let distant = now + Duration::from_secs(600);
        assert_eq!(
            v5_review_deadline(Some(distant), now).unwrap(),
            now + Duration::from_secs(120)
        );
        assert_eq!(
            v5_transfer_deadline(Some(distant), now).unwrap(),
            now + Duration::from_secs(30)
        );
        assert_eq!(
            v5_review_deadline(None, now).unwrap(),
            now + Duration::from_secs(120)
        );
        assert_eq!(
            v5_transfer_deadline(None, now).unwrap(),
            now + Duration::from_secs(30)
        );
    }
}
