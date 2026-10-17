//! Distinct non-signing selection producer from the actual continued source.
//! No public constructor or view-lease conversion can issue this permission.
use super::*;
use wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2;
use wholepact_signer_origin::manual_roster_candidate_selection_v2::{
    ManualRosterCandidateSelectionEvidenceV2, ManualRosterCandidateSelectionResponseV2,
};

impl BornRosterInventorySourceV2 {
    fn require_candidate_request(
        &self,
        request: &ManualRosterCandidateSelectionRequestV2,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        let e = &self.enrolled;
        let s = &request.scope.selection.inventory;
        let t = &e.retained.record.account_record.terms;
        let w = &e.witness;
        let continuation = w.continuation().ok_or(Error::Unavailable)?;
        self.require_provenance(&request.scope.provenance, s)?;
        let scope = &peer.scope;
        if s.enrollment != *t
            || s.enrollment_ref != e.retained.record.account_record.reference()?
            || s.witness_extension_digest
                != w.extension()
                    .account_extension
                    .digest()
                    .map_err(|_| Error::InvalidData)?
            || s.attempt.continuation_digest
                != continuation
                    .digest_for(w.extension())
                    .map_err(|_| Error::InvalidData)?
            || s.attempt.attempt_sequence != continuation.sequence()
            || request.scope.selection.original_policy_origin
                != original(&e.retained.account)?
                    .anchor()
                    .complete_policy_origin_v2()?
            || scope.account_id != t.identity.account_id
            || scope.agreement_id != t.scope.agreement_id
            || scope.participant_id != t.scope.participant_id
            || scope.manifest_digest
                != request
                    .scope
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?
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
        require_qualified_economic_destinations(&request.scope.selection.economic_intent)?;
        let remaining = request
            .remaining_ms(now()?)
            .map_err(|_| Error::ReviewMismatch);
        #[cfg(feature = "synthetic-born-joined-qualification")]
        super::synthetic_denial::result(
            super::synthetic_denial::Boundary::CandidateRequestRemaining,
            &remaining,
        );
        remaining?;
        Ok(())
    }
}
fn require_qualified_economic_destinations(
    intent: &wholepact_core::manual_candidate_selection::ManualCandidateEconomicIntent,
) -> Result<()> {
    use wholepact_protocol::{construction::PROFILE_ID, review::decode_testnet_receiver};
    if intent.agreement.network_profile_id != PROFILE_ID {
        return Err(Error::Unavailable);
    }
    for address in intent
        .agreement
        .recipients
        .iter()
        .map(|r| &r.address)
        .chain(
            intent
                .participants
                .iter()
                .flat_map(|p| p.charges.iter().map(|c| &c.address)),
        )
    {
        decode_testnet_receiver(address).map_err(|_| Error::ReviewMismatch)?;
    }
    Ok(())
}

pub(crate) enum CandidateSelectionOutcomeV2 {
    Finished(Box<BornRosterInventorySourceV2>),
    Retention(Box<super::retention::PreparedRosterContributionRetentionV2>),
}
pub(crate) struct PreparedRosterCandidateSelectionV2 {
    pub(super) source: BornRosterInventorySourceV2,
    pub(super) peer: AuthenticatedPeer,
    pub(super) stream: UnixStream,
    pub(super) request: ManualRosterCandidateSelectionRequestV2,
    pub(super) evidence: ManualRosterCandidateSelectionEvidenceV2,
    observed_session: wholepact_authority::AuthenticatedWriterSession,
    pub(super) native: NativeAuthorityBinding,
    window: DisclosureWindow,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedRosterCandidateSelectionV2 {
    pub(crate) fn prepare(
        source: BornRosterInventorySourceV2,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: ManualRosterCandidateSelectionRequestV2,
        history: ReconciledAuthorityHistory,
        observed_session: wholepact_authority::AuthenticatedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.require_candidate_request(&request, &peer, owner)?;
        publication::check_history(
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
            "wholepact:native-roster-candidate-selection-review:v2",
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
        let evidence = ManualRosterCandidateSelectionEvidenceV2 {
            version: 2,
            request: request.clone(),
            retained_signer_intent_digest: e.retained.intent_digest.clone(),
            original_descriptor_digest: request
                .scope
                .selection
                .inventory
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
        let retention_notice = if request.scope.selection.version == 2 {
            format!(
                "ORIGINAL NONSPENDING RETENTION V2: the immutable retention ceiling is {} Unix milliseconds, selected before this attempt. The longer ceiling preserves only exact selected contribution evidence for one later all-observations-first common-context plan. It does not extend this at-most-30-second viewing/selection disclosure, any separate at-most-30-second witness Reserve/Consume admission, or any native owner. Original signing and dispatch each require separate fresh exact approvals and their own original bounds.\n\n",
                request
                    .scope
                    .selection
                    .invocation
                    .construction_expires_at_ms
            )
        } else {
            String::new()
        };
        let display = Zeroizing::new(format!(
            "APPROVE ONE PRIVATE INPUT SELECTION FOR EXACT ECONOMIC INTENT\n{retention_notice}{}\n\nThe original Host V3 audit is a correlation claim from the Host. Only its authenticated Store can verify that record. The exact roster predecessor, original signer wrapper and V2 witness wrapper below remain unchanged; per-account witness continuation ancestry is separate.\n\nActual paired process/channel:\n{}\n\nThis distinct permission releases this account's full viewing key to this exact local process and permits one local maintained-wallet input-selection attempt for the displayed original V2 policy and exact economic intent. The reviewed amount is derived from contribution, deterministic fee share and approved charges, not a caller-selected cap. Inputs, input values, nullifiers, actual change and the full proposal do not yet exist and are not approved. Only authenticated same-account returned value is allowed; maintained selection must derive and verify the actual return address. Every exact contribution/full-proposal disclosure and construction requires a NEW review after actual selection. This grants no financial reservation, budget reset, signing, proof, dispatch, spending-key release or automatic future use. The process may learn private balance, transfers and history; copied viewing data cannot be recalled. Provider TLS reports are not independently verified consensus or proof of unspentness. The witness session is a fresh authenticated observation, not a continuous remote lease. The original request cutoff is at most 30 seconds and never renews on re-pair, retry or review. Focus loss, peer/parent disconnection or native expiry stops new admission. An already-admitted exact response send may finish within its fixed at-most-two-second bound; already-buffered bytes cannot be recalled. Failed selection or exclusion conflict consumes this attempt and needs a new decision.\nExact review: {}",
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
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(crate) fn synthetic_request(&self) -> &ManualRosterCandidateSelectionRequestV2 {
        &self.request
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
    pub(super) fn remaining(&self) -> Result<Duration> {
        self.window.remaining(now()?, Instant::now())
    }
    pub(super) fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
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
            .require_candidate_request(&self.request, &self.peer, owner)?;
        connected(&self.stream, &self.peer)
    }
    /// Receive-only liveness cannot authorize disclosure, a retained review or
    /// a source handoff. Full `send` validation remains before every response;
    /// the Retain branch still enters `retention::prepare`, whose unchanged
    /// first and final checks validate this exact original source before it can
    /// produce the review owner. No persistent state changes during this wait.
    /// File changes while idle are detected at that next full check, not by a
    /// duplicate read before waiting for the authenticated command.
    fn check_receive_liveness(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
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
        owner.check_current()?;
        self.native.check_current()?;
        self.peer.check_current()?;
        connected(&self.stream, &self.peer)
    }
    pub(crate) fn approve_and_serve(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<CandidateSelectionOutcomeV2> {
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
                .selection
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest
        {
            return Err(Error::Authentication);
        }
        let key_hex = Zeroizing::new(hex::encode(key.as_slice()));
        let lease_id = hex::encode(vault::random::<32>()?);
        let digest = canonical(
            "wholepact:roster-candidate-selection-evidence:v2",
            &self.evidence,
        )?;
        let response =
            ManualRosterCandidateSelectionResponseV2::RosterCandidateSelectionDisclosedV2 {
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
            self.check_receive_liveness(owner)?;
            let frame = crate::ipc::read_frame_with_deadline(
                &self.stream,
                &self.peer.peer,
                self.remaining()?.min(Duration::from_secs(2)),
            )?;
            if frame.len() > wholepact_signer_origin::manual_roster_construction_v2::MAX_ROSTER_CONSTRUCTION_FRAME {
                return Err(Error::InvalidData);
            }
            let command: wholepact_signer_origin::manual_roster_construction_v2::ManualRosterSelectionCommandV2 =
                serde_json::from_slice(&frame).map_err(|_| Error::InvalidData)?;
            self.check_receive_liveness(owner)?;
            let (response, completed_challenge) = match command {
                wholepact_signer_origin::manual_roster_construction_v2::ManualRosterSelectionCommandV2::RetainExactContributionV2 { lease_id: requested, evidence_digest, request } => {
                    if requested != lease_id || evidence_digest != digest { return Err(Error::Authentication); }
                    let review = super::retention::PreparedRosterContributionRetentionV2::prepare(self,*request,owner)?;
                    return Ok(CandidateSelectionOutcomeV2::Retention(Box::new(review)));
                }
                wholepact_signer_origin::manual_roster_construction_v2::ManualRosterSelectionCommandV2::CheckCurrent {
                    lease_id: requested,
                    evidence_digest,
                    challenge_nonce,
                } => {
                    if requested != lease_id
                        || evidence_digest != digest
                        || !is_hash(&challenge_nonce)
                        || challenges.contains(&challenge_nonce)
                    {
                        return Err(Error::Authentication);
                    }
                    (
                        ManualAdmissionResponse::Current {
                            lease_id: lease_id.clone(),
                            evidence_digest: digest.clone(),
                            challenge_nonce: challenge_nonce.clone(),
                        },
                        challenge_nonce,
                    )
                }
                wholepact_signer_origin::manual_roster_construction_v2::ManualRosterSelectionCommandV2::Finish {} => {
                    let bytes = Zeroizing::new(
                        serde_json::to_vec(&ManualAdmissionResponse::Finished {})
                            .map_err(|_| Error::InvalidData)?,
                    );
                    self.send(&bytes, owner)?;
                    return Ok(CandidateSelectionOutcomeV2::Finished(Box::new(self.source)));
                }
            };
            let bytes =
                Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
            retain_challenge_after_send(
                self.send(&bytes, owner),
                &mut challenges,
                completed_challenge,
            )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_nonce_is_retained_only_after_fully_checked_send_success() {
        // Protocol bookkeeping only. This cannot manufacture a native owner or
        // bypass the real candidate send/retention checks exercised by CI.
        let nonce = "17".repeat(32);
        let mut challenges = BTreeSet::new();
        for failure in [Error::ReviewMismatch, Error::Authentication, Error::Uncertain] {
            assert!(retain_challenge_after_send(
                Err(failure),
                &mut challenges,
                nonce.clone(),
            )
            .is_err());
            assert!(!challenges.contains(&nonce));
        }
        retain_challenge_after_send(Ok(()), &mut challenges, nonce.clone()).unwrap();
        assert!(challenges.contains(&nonce));
        assert_eq!(challenges.len(), 1);
    }
    #[test]
    fn qualified_same_account_return_uses_maintained_decoder_and_fvk_ownership() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use wholepact_protocol::review::{decode_testnet_receiver, encode_testnet_receiver};
        // Public never-funded synthetic fixture; no native consent is minted.
        let key = SpendingKey::from_zip32_seed(&[31; 64], 1, 0u32.try_into().unwrap()).unwrap();
        let fvk = FullViewingKey::from(&key);
        let receiver = fvk.address_at(0u32, Scope::Internal);
        let decoded = decode_testnet_receiver(&encode_testnet_receiver(&receiver)).unwrap();
        assert_eq!(fvk.scope_for_address(&decoded), Some(Scope::Internal));
        assert!(decode_testnet_receiver("caller-asserted-owned-address").is_err());
    }
    #[test]
    fn selection_uses_original_window_even_if_common_completion_is_longer() {
        let start = Instant::now();
        let window = DisclosureWindow::new(
            1000,
            31_000,
            30_999,
            start,
            start + Duration::from_secs(100),
        )
        .unwrap();
        assert_eq!(
            window.remaining(30_999, start).unwrap(),
            Duration::from_millis(1)
        );
        assert!(window.remaining(31_000, start).is_err());
        assert!(window.remaining(999, start).is_err());
    }
}
