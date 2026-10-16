//! Candidate-free viewing disclosure from an actual held continued enrollment.
//! No import/JSON factory issues this owner. Old publication grants are retired
//! before the separate privacy pairing; the original native deadline survives.
pub(crate) mod candidate;
use super::*;
use std::{
    collections::BTreeSet,
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_core::manual_inventory::{
    MAX_PRELIMINARY_DISCLOSURE_MS, ManualPreliminaryInventoryRequest,
};
use wholepact_signer_origin::manual::{
    ManualAdmissionCommand, ManualAdmissionResponse, ManualCurrentState,
};
use wholepact_signer_origin::manual_inventory::{
    ManualPreliminaryInventoryEvidence, ManualPreliminaryInventoryResponse,
};

/// Purpose-specific ownership transfer out of the actual V2 publication owner.
/// This preserves original witness/native provenance, while never treating its
/// now-retired grant as current authority for a new destination or disclosure.
pub(crate) struct BornInventorySource {
    enrolled: Arc<BornManualEnrolledSigner>,
}
impl BornInventorySource {
    pub(crate) fn prepare_repair(
        enrolled: Arc<BornManualEnrolledSigner>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        enrolled.require_host_owner(&enrolled.peer, owner)?;
        if !matches!(&enrolled.witness, BornManualWitness::Continued(_)) {
            return Err(Error::Unavailable);
        }
        original(&enrolled.retained.account)?
            .anchor()
            .recipient_policy_v2()?;
        Ok(Self { enrolled })
    }
    pub(crate) fn prepare_next_pair(
        self,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        self.check(peer, owner)?;
        Ok(self)
    }
    fn check(&self, peer: &AuthenticatedPeer, owner: &PendingAccountNativeAuthority) -> Result<()> {
        let e = &self.enrolled;
        owner.check_current()?;
        e.source.check_current()?;
        e.source.bounded_deadline()?;
        peer.check_current()?;
        if e.source != owner.native().binding()
            || peer.native_origin != e.source
            || peer.grant_id == e.peer.grant_id
        {
            return Err(Error::Authentication);
        }
        // A historical grant is NOT checked as current. Only its actual kernel
        // process identity is compared to the fresh independently approved peer.
        peer.peer.same_live_process(&e.peer.peer)?;
        e.retained.check()?;
        e.witness
            .require_retained(&e.retained, &read_commit(&e.retained)?)?;
        e.journal.check_initial_born_owner(
            &e.retained.record.genesis,
            e.retained.record.terms.signer.writer_epoch,
        )?;
        check_current_history(&e.retained, &e.history, &e.witness)?;
        e.witness
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        original(&e.retained.account)?
            .anchor()
            .recipient_policy_v2()?;
        Ok(())
    }
    fn require_request(
        &self,
        request: &ManualPreliminaryInventoryRequest,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        let e = &self.enrolled;
        let s = &request.scope;
        let t = &e.retained.record.terms;
        let BornManualWitness::Continued(w) = &e.witness else {
            return Err(Error::Unavailable);
        };
        let scope = &peer.scope;
        if s.enrollment != *t
            || s.enrollment_ref != e.retained.record.reference()?
            || s.witness_extension_digest
                != w.extension().digest().map_err(|_| Error::InvalidData)?
            || s.attempt.continuation_digest
                != w.continuation()
                    .digest_for(w.extension())
                    .map_err(|_| Error::InvalidData)?
            || s.attempt.attempt_sequence != w.continuation().sequence
            || &s.original_recipient_policy
                != original(&e.retained.account)?
                    .anchor()
                    .recipient_policy_v2()?
            || scope.account_id != t.identity.account_id
            || scope.agreement_id != t.scope.agreement_id
            || scope.participant_id != t.scope.participant_id
            || scope.manifest_digest != s.pairing_digest().map_err(|_| Error::InvalidData)?
            || scope.history_read
            || scope.authorization_export
            || scope.preconstruction_export
            || request.current_caller_binding_digest
                != wholepact_signer_origin::manual_current_caller_binding_digest(
                    &peer.grant_id,
                    scope,
                )
                .map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        request
            .remaining_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
        Ok(())
    }
}
pub(crate) struct PreparedPreliminaryInventory {
    source: BornInventorySource,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: ManualPreliminaryInventoryRequest,
    evidence: ManualPreliminaryInventoryEvidence,
    observed_session: wholepact_authority::AuthenticatedWriterSession,
    native: NativeAuthorityBinding,
    window: DisclosureWindow,
    digest: String,
    display: Zeroizing<String>,
}
struct DisclosureWindow {
    monotonic_deadline: Instant,
    requested_at_ms: u64,
    expires_at_ms: u64,
}
impl DisclosureWindow {
    fn new(
        requested: u64,
        expires: u64,
        wall: u64,
        monotonic: Instant,
        source_deadline: Instant,
    ) -> Result<Self> {
        if requested == 0
            || expires <= requested
            || expires - requested > MAX_PRELIMINARY_DISCLOSURE_MS
            || wall < requested
            || wall >= expires
        {
            return Err(Error::ReviewMismatch);
        }
        let deadline = monotonic
            .checked_add(Duration::from_millis(expires - wall))
            .ok_or(Error::ReviewMismatch)?
            .min(source_deadline);
        let result = Self {
            monotonic_deadline: deadline,
            requested_at_ms: requested,
            expires_at_ms: expires,
        };
        result.remaining(wall, monotonic)?;
        Ok(result)
    }
    fn remaining(&self, wall: u64, monotonic: Instant) -> Result<Duration> {
        if wall < self.requested_at_ms || wall >= self.expires_at_ms {
            return Err(Error::ReviewMismatch);
        }
        self.monotonic_deadline
            .checked_duration_since(monotonic)
            .filter(|d| !d.is_zero())
            .map(|d| d.min(Duration::from_millis(self.expires_at_ms - wall)))
            .ok_or(Error::ReviewMismatch)
    }
}
impl PreparedPreliminaryInventory {
    pub(crate) fn prepare(
        source: BornInventorySource,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: ManualPreliminaryInventoryRequest,
        history: ReconciledAuthorityHistory,
        observed_session: wholepact_authority::AuthenticatedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.require_request(&request, &peer, owner)?;
        check_current_history(
            &source.enrolled.retained,
            &history,
            &source.enrolled.witness,
        )?;
        require_observed_session_time(
            observed_session.observed_at_ms(),
            observed_session.observation_age(),
            now()?,
            observed_session.receipt().expires_at_ms,
        )?;
        if observed_session.snapshot() != history.snapshot()
            || observed_session.receipt() != source.enrolled.witness.session()
            || observed_session.disclosure() != &source.enrolled.retained.disclosure()?
            || observed_session.history_digest()
                != history.history_digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        connected(&stream, &peer)?;
        let native = owner.native().binding();
        let window = DisclosureWindow::new(
            request.requested_at_ms,
            request.disclosure_expires_at_ms,
            now()?,
            Instant::now(),
            native.bounded_deadline()?,
        )?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(peer.clone())?;
        let digest = canonical(
            "wholepact:native-preliminary-inventory-review:v1",
            &(
                &request,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let e = &source.enrolled;
        let snapshot = history.snapshot();
        let session = e.witness.session();
        let audit = original(&e.retained.account)?
            .anchor()
            .audit_historical_witness_link(&history)?;
        let evidence = ManualPreliminaryInventoryEvidence {
            version: 1,
            request: request.clone(),
            retained_signer_intent_digest: e.retained.intent_digest.clone(),
            original_descriptor_digest: request
                .scope
                .original_recipient_policy
                .digest()
                .map_err(|_| Error::InvalidData)?,
            current: ManualCurrentState {
                writer_certificate_digest: session.writer_certificate_digest.clone(),
                writer_epoch: snapshot.writer_epoch,
                writer_session_digest: canonical(
                    "wholepact:born-manual-writer-session:v1",
                    session,
                )?,
                writer_session_expires_at_ms: session.expires_at_ms,
                witness_head_sequence: snapshot.head.sequence,
                witness_head_digest: snapshot.head.digest.clone(),
                complete_history_digest: history
                    .history_digest()
                    .map_err(|_| Error::InvalidData)?,
                exclusion_checkpoint_digest: canonical(
                    "wholepact:born-manual-exclusion-checkpoint:v1",
                    audit.checkpoint(),
                )?,
                native_review_digest: digest.clone(),
            },
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "DISCLOSE PRIVATE VIEWING DATA FOR PRELIMINARY INVENTORY ONLY\n{}\n\nActual paired process/channel:\n{}\n\nThis releases this account's full viewing key to the exact paired process for the stated wallet destination, provider and bounded scan. That process can learn this account's private balance, transfers and history. Copied viewing data cannot be recalled. The provider's TLS reports are not independently verified chain consensus. The witness session shown is a fresh authenticated observation, not a continuous remote lease or financial permission. No candidate or selected inputs exist in this request. This does not permit construction, spending-key release, proof, signatures, dispatch or automatic future use. The live permission expires at the original requested cutoff or earlier on focus, peer/parent disconnect or native expiry. An already-admitted exact response send may finish within its fixed at-most-two-second bound; cancellation admits no new send. Copied or already-buffered bytes cannot be recalled. Reopening or reviewing again cannot refresh it. Exact candidate preparation and every later effect require their separate actual owner decisions.\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(pairing.binding()).map_err(|_| Error::InvalidData)?,
            digest
        ));
        let prepared = Self {
            source,
            peer,
            stream,
            request,
            evidence,
            observed_session,
            native,
            window,
            digest,
            display,
        };
        prepared.check(owner)?;
        Ok(prepared)
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        self.peer.check_current()?;
        self.remaining()?;
        require_observed_session_time(
            self.observed_session.observed_at_ms(),
            self.observed_session.observation_age(),
            now()?,
            self.observed_session.receipt().expires_at_ms,
        )?;
        Ok(self.display.to_string())
    }
    fn remaining(&self) -> Result<Duration> {
        self.window.remaining(now()?, Instant::now())
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        if owner.native().binding() != self.native {
            return Err(Error::ReviewMismatch);
        }
        self.remaining()?;
        require_observed_session_time(
            self.observed_session.observed_at_ms(),
            self.observed_session.observation_age(),
            now()?,
            self.observed_session.receipt().expires_at_ms,
        )?;
        self.source
            .require_request(&self.request, &self.peer, owner)?;
        connected(&self.stream, &self.peer)
    }
    pub(crate) fn approve_and_serve(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornInventorySource> {
        self.check(owner)?;
        if decision.binding() != &self.native || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let key = Zeroizing::new(
            self.source
                .enrolled
                .retained
                .account
                .account()
                .fvk()?
                .to_bytes(),
        );
        if hex::encode(Sha256::digest(key.as_slice()))
            != self
                .request
                .scope
                .enrollment
                .identity
                .full_viewing_key_digest
        {
            return Err(Error::Authentication);
        }
        let key_hex = Zeroizing::new(hex::encode(key.as_slice()));
        let lease_id = hex::encode(vault::random::<32>()?);
        let digest = canonical(
            "wholepact:preliminary-inventory-evidence:v1",
            &self.evidence,
        )?;
        let response = ManualPreliminaryInventoryResponse::PreliminaryInventoryDisclosedV1 {
            lease_id: lease_id.clone(),
            evidence: Box::new(self.evidence.clone()),
            account_fvk_hex: key_hex.to_string(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
        drop(response); // Central response Drop wipes its owned FVK string.
        self.send(&bytes, owner)?;
        drop(bytes);
        drop(key_hex);
        drop(key);
        let mut challenges = BTreeSet::new();
        for _ in 0..128 {
            self.check(owner)?;
            let frame = crate::ipc::read_frame_with_deadline(
                &self.stream,
                &self.peer.peer,
                self.remaining()?.min(Duration::from_secs(2)),
            )?;
            if frame.len() > 4096 {
                return Err(Error::InvalidData);
            }
            let command: ManualAdmissionCommand =
                serde_json::from_slice(&frame).map_err(|_| Error::InvalidData)?;
            self.check(owner)?;
            let response = match command {
                ManualAdmissionCommand::CheckCurrent {
                    lease_id: requested,
                    evidence_digest,
                    challenge_nonce,
                } => {
                    if requested != lease_id
                        || evidence_digest != digest
                        || !is_hash(&challenge_nonce)
                        || !challenges.insert(challenge_nonce.clone())
                    {
                        return Err(Error::Authentication);
                    }
                    ManualAdmissionResponse::Current {
                        lease_id: lease_id.clone(),
                        evidence_digest: digest.clone(),
                        challenge_nonce,
                    }
                }
                ManualAdmissionCommand::Finish {} => {
                    let bytes = Zeroizing::new(
                        serde_json::to_vec(&ManualAdmissionResponse::Finished {})
                            .map_err(|_| Error::InvalidData)?,
                    );
                    self.send(&bytes, owner)?;
                    return Ok(self.source);
                }
            };
            let bytes =
                Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
            self.send(&bytes, owner)?;
        }
        Err(Error::Unavailable)
    }
    fn send(&mut self, bytes: &[u8], owner: &PendingAccountNativeAuthority) -> Result<()> {
        // The actual lower framing bound includes the newline. No prefix of an
        // oversized disclosure may be transmitted before rejecting it.
        if bytes.len() >= 128 * 1024 {
            return Err(Error::InvalidData);
        }
        self.check(owner)?;
        let started = Instant::now();
        let send_deadline = started
            .checked_add(self.remaining()?.min(Duration::from_secs(2)))
            .ok_or(Error::ReviewMismatch)?;
        let binding = self.native.clone();
        let _admitted = binding.publication_lease()?;
        // Hold genuine admission through THIS fixed bounded send only. Do not
        // retain it while waiting for a command, user action or provider I/O.
        let mut framed = Zeroizing::new(bytes.to_vec());
        framed.push(b'\n');
        let mut offset = 0;
        while offset < framed.len() {
            owner.check_current()?;
            self.native.check_current()?;
            self.peer.check_current()?;
            connected(&self.stream, &self.peer)?;
            let remaining = send_deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::ReviewMismatch)?
                .min(self.remaining()?);
            self.stream.set_write_timeout(Some(remaining))?;
            let wrote = self.stream.write(&framed[offset..])?;
            if wrote == 0 {
                return Err(Error::Uncertain);
            }
            offset += wrote;
        }
        self.remaining()?;
        if Instant::now() >= send_deadline {
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}
fn require_observed_session_time(
    observed_at_ms: u64,
    observation_age: Duration,
    wall_now_ms: u64,
    expires_at_ms: u64,
) -> Result<()> {
    if observed_at_ms == 0
        || expires_at_ms <= observed_at_ms
        || wall_now_ms < observed_at_ms
        || wall_now_ms >= expires_at_ms
        || observation_age >= Duration::from_secs(30)
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::ReviewMismatch)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::ReviewMismatch)
}
fn connected(stream: &UnixStream, peer: &AuthenticatedPeer) -> Result<()> {
    peer.check_current()?;
    peer.peer
        .same_live_process(&crate::native_peer::PeerProcess::observe(stream)?)?;
    let mut state = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut state, 1, 0) } < 0
        || state.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn fresh_session_observation_rejects_wall_rollback_even_with_unexpired_request() {
        // Original request may start at1000, but the authentic session read was
        // observed at2000. A later wall value1500 cannot become fresh evidence.
        assert!(
            require_observed_session_time(2000, Duration::from_millis(1), 1500, 40_000).is_err()
        );
        assert!(require_observed_session_time(2000, Duration::from_secs(29), 2000, 40_000).is_ok());
        assert!(
            require_observed_session_time(2000, Duration::from_secs(30), 2000, 40_000).is_err()
        );
        assert!(require_observed_session_time(2000, Duration::ZERO, 40_000, 40_000).is_err());
    }
    #[test]
    fn immutable_disclosure_cutoff_is_not_renewed_by_late_worker_or_clock_rollback() {
        let start = Instant::now();
        let source = start + Duration::from_secs(12);
        let window = DisclosureWindow::new(1000, 31_000, 2000, start, source).unwrap();
        assert_eq!(
            window.remaining(2000, start).unwrap(),
            Duration::from_secs(12)
        );
        assert!(window.remaining(2000, source).is_err());
        assert!(window.remaining(999, start).is_err());
        assert!(window.remaining(31_000, start).is_err());
        assert!(DisclosureWindow::new(1000, 31_001, 2000, start, source).is_err());
    }
}
