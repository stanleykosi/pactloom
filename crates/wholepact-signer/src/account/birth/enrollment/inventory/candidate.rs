//! Distinct non-signing selection producer from the actual continued source.
//! No public constructor or view-lease conversion can issue this permission.
use super::*;
use wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest;
use wholepact_signer_origin::manual_candidate_selection::{
    ManualCandidateSelectionEvidence, ManualCandidateSelectionResponse,
};

impl BornInventorySource {
    fn require_candidate_request(
        &self,
        request: &ManualCandidateSelectionRequest,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        let e = &self.enrolled;
        let s = &request.scope.inventory;
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
            || request.scope.original_policy_origin
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
        require_qualified_economic_destinations(&request.scope.economic_intent)?;
        request
            .remaining_ms(now()?)
            .map_err(|_| Error::ReviewMismatch)?;
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

pub(crate) struct PreparedCandidateSelection {
    source: BornInventorySource,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: ManualCandidateSelectionRequest,
    evidence: ManualCandidateSelectionEvidence,
    observed_session: wholepact_authority::AuthenticatedWriterSession,
    native: NativeAuthorityBinding,
    window: DisclosureWindow,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedCandidateSelection {
    pub(crate) fn prepare(
        source: BornInventorySource,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: ManualCandidateSelectionRequest,
        history: ReconciledAuthorityHistory,
        observed_session: wholepact_authority::AuthenticatedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.require_candidate_request(&request, &peer, owner)?;
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
            "wholepact:native-candidate-selection-review:v1",
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
        let evidence = ManualCandidateSelectionEvidence {
            version: 1,
            request: request.clone(),
            retained_signer_intent_digest: e.retained.intent_digest.clone(),
            original_descriptor_digest: request
                .scope
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
        let display = Zeroizing::new(format!(
            "APPROVE ONE PRIVATE INPUT SELECTION FOR EXACT ECONOMIC INTENT\n{}\n\nActual paired process/channel:\n{}\n\nThis distinct permission releases this account's full viewing key to this exact local process and permits one local maintained-wallet input-selection attempt for the displayed original V2 policy and exact economic intent. The reviewed amount is derived from contribution, deterministic fee share and approved charges, not a caller-selected cap. Inputs, input values, nullifiers, actual change and the full proposal do not yet exist and are not approved. Only authenticated same-account returned value is allowed; maintained selection must derive and verify the actual return address. Every exact contribution/full-proposal disclosure and construction requires a NEW review after actual selection. This grants no financial reservation, budget reset, signing, proof, dispatch, spending-key release or automatic future use. The process may learn private balance, transfers and history; copied viewing data cannot be recalled. Provider TLS reports are not independently verified consensus or proof of unspentness. The witness session is a fresh authenticated observation, not a continuous remote lease. The original request cutoff is at most 30 seconds and never renews on re-pair, retry or review. Focus loss, peer/parent disconnection or native expiry stops new admission. An already-admitted exact response send may finish within its fixed at-most-two-second bound; already-buffered bytes cannot be recalled. Failed selection or exclusion conflict consumes this attempt and needs a new decision.\nExact review: {}",
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
            .require_candidate_request(&self.request, &self.peer, owner)?;
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
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest
        {
            return Err(Error::Authentication);
        }
        let key_hex = Zeroizing::new(hex::encode(key.as_slice()));
        let lease_id = hex::encode(vault::random::<32>()?);
        let digest = canonical("wholepact:candidate-selection-evidence:v1", &self.evidence)?;
        let response = ManualCandidateSelectionResponse::CandidateSelectionDisclosedV1 {
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

#[cfg(test)]
mod tests {
    use super::*;
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
