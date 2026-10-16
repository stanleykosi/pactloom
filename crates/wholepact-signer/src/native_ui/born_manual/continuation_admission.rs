//! Finite exact enrollment-publication IPC. A genuine native decision sends
//! actual producer evidence; no imported record or DTO constructs its owner.
//! No lock is held across remote I/O and no action/spending permission is issued.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use crate::{
    Error, Result, account::birth::enrollment::BornManualEnrolledSigner, ipc::AuthenticatedPeer,
};
use std::{
    collections::BTreeSet,
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Arc,
    time::{Duration, Instant},
};
use wholepact_signer_origin::manual::{ManualAdmissionCommand, ManualAdmissionResponse};
use wholepact_signer_origin::manual_continuation_v2::{
    HostManualEnrollmentContinuationRequestV2, ManualEnrollmentContinuationEvidenceV2,
};
use zeroize::Zeroizing;

const MAX_SERVE: Duration = Duration::from_secs(30);
const MAX_COMMANDS: usize = 128;
pub(super) struct PreparedNativeManualContinuation {
    enrolled: Arc<BornManualEnrolledSigner>,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: HostManualEnrollmentContinuationRequestV2,
    evidence: ManualEnrollmentContinuationEvidenceV2,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedNativeManualContinuation {
    pub(super) fn prepare(
        enrolled: Arc<BornManualEnrolledSigner>,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: HostManualEnrollmentContinuationRequestV2,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        enrolled.require_host_owner(&peer, owner)?;
        connected(&stream, &peer)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        if request.enrollment.terms != enrolled.record().terms {
            return Err(Error::ReviewMismatch);
        }
        let pairing = super::super::AuthenticatedPairing::from_authenticated_request(peer.clone())?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-manual-host-publication:v2",
            &(
                &request,
                enrolled.record().reference()?,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let evidence = enrolled.host_continuation_evidence(&request, &peer, owner, &digest)?;
        let display = Zeroizing::new(format!(
            "DISCLOSE EXACT FINITE ENROLLMENT PUBLICATION TO THIS PAIRED PROCESS\n\n{}\n\n{}\n\nThis sends immutable account/birth/policy/host-generation linkage, original witness admission and current local native review evidence to the exact paired process above. The application must independently verify its actual locked host target. This is only the already durably admitted enrollment publication, never financial permission. The original witness admission timestamps and original native entry deadline cannot be extended. The channel closes on disconnect, blur, expiry or after at most 30 seconds. No witness, native or journal lock is held while waiting for the host; previously admitted durable evidence remains if the host result is uncertain.\nExact review: {}",
            serde_json::to_string_pretty(pairing.binding()).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(&evidence).map_err(|_| Error::InvalidData)?,
            digest
        ));
        enrolled.require_host_owner(&peer, owner)?;
        Ok(Self {
            enrolled,
            peer,
            stream,
            request,
            evidence,
            source: owner.native().binding(),
            digest,
            display,
        })
    }
    pub(super) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        connected(&self.stream, &self.peer)?;
        Ok(self.display.to_string())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        if owner.native().binding() != self.source {
            return Err(Error::ReviewMismatch);
        }
        self.enrolled.require_host_owner(&self.peer, owner)?;
        connected(&self.stream, &self.peer)?;
        let actual = self.enrolled.host_continuation_evidence(
            &self.request,
            &self.peer,
            owner,
            &self.digest,
        )?;
        if actual != self.evidence {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn approve_and_serve(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        // No reusable closure and no serialization of the one-shot decision.
        // Its linearization guard covers admission only, never remote waiting.
        {
            let _admitted = self.source.publication_lease()?;
            self.check(owner)?;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::ReviewMismatch)?
            .as_millis();
        let now: u64 = now.try_into().map_err(|_| Error::ReviewMismatch)?;
        let budget = original_budget(
            self.evidence.admission.admitted_at_ms,
            self.evidence.admission.admission_deadline_ms,
            now,
        )?;
        let deadline = self
            .source
            .bounded_deadline()?
            .min(Instant::now() + budget.min(MAX_SERVE));
        let lease_id = hex::encode(crate::vault::random::<32>()?);
        let evidence_digest = self.evidence.digest().map_err(|_| Error::InvalidData)?;
        self.check(owner)?;
        write(
            &mut self.stream,
            &ManualAdmissionResponse::EnrollmentContinuationHeldV2 {
                lease_id: lease_id.clone(),
                evidence: Box::new(self.evidence.clone()),
            },
            deadline,
        )?;
        let mut challenges = BTreeSet::new();
        for _ in 0..MAX_COMMANDS {
            self.check(owner)?;
            let remaining = remaining(deadline)?;
            let frame = crate::ipc::read_frame_with_deadline(
                &self.stream,
                &self.peer.peer,
                remaining.min(Duration::from_secs(2)),
            )?;
            if frame.len() > 4096 {
                return Err(Error::InvalidData);
            }
            let command: ManualAdmissionCommand =
                serde_json::from_slice(&frame).map_err(|_| Error::InvalidData)?;
            self.check(owner)?;
            match command {
                ManualAdmissionCommand::CheckCurrent {
                    lease_id: requested,
                    evidence_digest: expected,
                    challenge_nonce,
                } => {
                    exact_challenge(
                        &lease_id,
                        &evidence_digest,
                        &requested,
                        &expected,
                        &challenge_nonce,
                    )?;
                    if !challenges.insert(challenge_nonce.clone()) {
                        return Err(Error::ReviewMismatch);
                    }
                    write(
                        &mut self.stream,
                        &ManualAdmissionResponse::Current {
                            lease_id: lease_id.clone(),
                            evidence_digest: evidence_digest.clone(),
                            challenge_nonce,
                        },
                        deadline,
                    )?;
                }
                ManualAdmissionCommand::Finish {} => {
                    write(
                        &mut self.stream,
                        &ManualAdmissionResponse::Finished {},
                        deadline,
                    )?;
                    return Ok(());
                }
            }
        }
        Err(Error::Unavailable)
    }
}
fn original_budget(admitted: u64, deadline: u64, now: u64) -> Result<Duration> {
    if now < admitted || deadline <= admitted || deadline - admitted > 120_000 || now >= deadline {
        return Err(Error::ReviewMismatch);
    }
    Ok(Duration::from_millis(deadline - now))
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::ReviewMismatch)
}
fn write(
    stream: &mut UnixStream,
    value: &ManualAdmissionResponse,
    deadline: Instant,
) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
    if bytes.len() > 128 * 1024 {
        return Err(Error::InvalidData);
    }
    bytes.push(b'\n');
    let mut offset = 0usize;
    while offset < bytes.len() {
        // Absolute cutoff is rechecked after every partial-progress send.
        stream.set_write_timeout(Some(remaining(deadline)?.min(Duration::from_secs(2))))?;
        let wrote = stream.write(&bytes[offset..])?;
        if wrote == 0 {
            return Err(Error::Uncertain);
        }
        offset += wrote;
    }
    remaining(deadline)?;
    Ok(())
}
pub(super) fn connected(stream: &UnixStream, peer: &AuthenticatedPeer) -> Result<()> {
    peer.check_current()?;
    let actual = crate::native_peer::PeerProcess::observe(stream)?;
    peer.peer.same_live_process(&actual)?;
    let mut state = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Only connection liveness is sampled. Per-frame SCM_CREDENTIALS below
    // authenticates the actual sender even for an inherited descriptor.
    if unsafe { libc::poll(&mut state, 1, 0) } < 0
        || state.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn exact_challenge(
    lease: &str,
    evidence: &str,
    requested: &str,
    expected: &str,
    nonce: &str,
) -> Result<()> {
    if lease != requested
        || evidence != expected
        || nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_lease_evidence_and_nonce_are_denied_without_an_owner() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        assert!(exact_challenge(&a, &b, &a, &b, &c).is_ok());
        assert!(exact_challenge(&a, &b, &c, &b, &c).is_err());
        assert!(exact_challenge(&a, &b, &a, &c, &c).is_err());
        assert!(exact_challenge(&a, &b, &a, &b, "1").is_err());
    }
    #[test]
    fn elapsed_initial_cutoff_cannot_be_refreshed_by_a_command() {
        assert!(remaining(Instant::now() - Duration::from_secs(1)).is_err());
    }
    #[test]
    fn original_admission_deadline_is_never_restarted() {
        assert_eq!(
            original_budget(1000, 121000, 120999).unwrap(),
            Duration::from_millis(1)
        );
        assert!(original_budget(1000, 121000, 121000).is_err());
        assert!(original_budget(1000, 121000, 999).is_err());
        assert!(original_budget(1000, 121001, 1000).is_err());
    }
    #[test]
    fn finish_rejects_hidden_approval_fields() {
        assert!(
            serde_json::from_str::<ManualAdmissionCommand>(
                r#"{"operation":"finish","approved":true}"#
            )
            .is_err()
        );
    }
}
