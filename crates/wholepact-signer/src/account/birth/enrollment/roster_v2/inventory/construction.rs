//! Fresh native full-proposal review after sequential retained-data collection.
//! Historical receipt authentication is not current authority: this producer
//! requires a genuinely NEW continued original roster source, same actual OS
//! process pairing, current writer/history and one-use witness Reserve/Consume.
use super::*;
use wholepact_authority::manual_roster_construction_v2::{
    ManualRosterConstructionConsumeRequestV2, ManualRosterConstructionReservationRequestV2,
    construction_consume_operation_id_v2,
};
use wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2;
use wholepact_signer_origin::manual_roster_construction_v2::{
    MAX_ROSTER_CONSTRUCTION_FRAME, ManualRosterConstructionContributionEvidenceV2,
    ManualRosterConstructionResponseV2,
};

pub(crate) struct PreparedRosterConstructionV2 {
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: ManualRosterConstructionRequestV2,
    history: ReconciledAuthorityHistory,
    observed: wholepact_authority::AuthenticatedWriterSession,
    native: NativeAuthorityBinding,
    window: DisclosureWindow,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedRosterConstructionV2 {
    pub(crate) fn prepare(
        source: BornRosterInventorySourceV2,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: ManualRosterConstructionRequestV2,
        history: ReconciledAuthorityHistory,
        observed: wholepact_authority::AuthenticatedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(&peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        let e = &source.enrolled;
        let old = &request.plan.retained.selection.scope;
        let i = &old.selection.inventory;
        source.require_provenance(&old.provenance, i)?;
        let continuation = e.witness.continuation().ok_or(Error::Unavailable)?;
        let extension = e.witness.extension();
        // This phase is deliberately newer than the retained selection. A stale
        // session/attempt cannot be relabelled as a fresh full-proposal decision.
        if i.enrollment != e.retained.record.account_record.terms
            || i.enrollment_ref != e.retained.record.account_record.reference()?
            || continuation.sequence() <= i.attempt.attempt_sequence
            || continuation
                .digest_for(extension)
                .map_err(|_| Error::InvalidData)?
                == i.attempt.continuation_digest
            || old.selection.original_policy_origin
                != original(&e.retained.account)?
                    .anchor()
                    .complete_policy_origin_v2()?
            || peer.scope.account_id != i.enrollment.identity.account_id
            || peer.scope.agreement_id != i.enrollment.scope.agreement_id
            || peer.scope.participant_id != i.enrollment.scope.participant_id
            || peer.scope.manifest_digest
                != request.plan.digest().map_err(|_| Error::InvalidData)?
            || peer.scope.history_read
            || peer.scope.authorization_export
            || peer.scope.preconstruction_export
            || request.current_caller_binding_digest
                != wholepact_signer_origin::manual_current_caller_binding_digest(
                    &peer.grant_id,
                    &peer.scope,
                )
                .map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        super::super::retention::read_exact(
            &e.retained,
            &request.plan.retained,
            &request.plan.retained_evidence_digest,
        )?;
        publication::check_history(&e.retained, &history, &e.witness)?;
        require_observed_session_time(
            observed.observed_at_ms(),
            observed.observation_age(),
            now()?,
            observed.receipt().expires_at_ms,
        )?;
        if observed.snapshot() != history.snapshot()
            || observed.receipt() != e.witness.session()
            || observed.disclosure() != &e.retained.disclosure()?
            || observed.history_digest()
                != history.history_digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        let approval = history
            .manual_roster_construction_approval_v2(
                &request
                    .plan
                    .invocation_digest()
                    .map_err(|_| Error::InvalidData)?,
            )
            .map_err(|_| Error::ReviewMismatch)?
            .ok_or(Error::ReviewMismatch)?;
        approval
            .matches_request(&request, extension)
            .map_err(|_| Error::ReviewMismatch)?;
        let fvk = e.retained.account.account().fvk()?;
        let change = wholepact_protocol::review::decode_testnet_receiver(
            &request.plan.retained.change_address,
        )
        .map_err(|_| Error::ReviewMismatch)?;
        if fvk.scope_for_address(&change) != Some(orchard::keys::Scope::Internal) {
            return Err(Error::ReviewMismatch);
        }
        connected(&stream, &peer)?;
        let native = owner.native().binding();
        let window = DisclosureWindow::new(
            request.requested_at_ms,
            request.admission_expires_at_ms,
            now()?,
            Instant::now(),
            native.bounded_deadline()?,
        )?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(peer.clone())?;
        let digest = canonical(
            "wholepact:native-roster-full-construction-review:v2",
            &(
                &request,
                continuation,
                history.history_digest().map_err(|_| Error::InvalidData)?,
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let display = Zeroizing::new(format!(
            "APPROVE THIS EXACT FULL PROPOSAL FOR ONE NON-SIGNING CONSTRUCTION\n{}\n\nActual newly continued attempt:\n{}\n\nActual paired process:\n{}\n\nReview every recipient, amount, fee, output allocation, participant/account, exact owned input and nullifier, same-account change, original disclosure destination and original common deadline {}. The original retained contribution receipt is authenticated unchanged; this NEW source/attempt/native decision does not renew it or reset any budget. The separate original witness owner has approved this exact full plan. This action first reserves conservative account exposure, then consumes that reservation exactly once for non-signing construction. Reservation failure or uncertain response never refunds exposure or permits a second attempt. No spending key, transaction signature, proving or dispatch authority is released. Current chain reports are provider observations and do not guarantee unspentness or settlement. Cancellation, focus loss and disconnection stop NEW admission; already-admitted work may finish after focus changes within its fixed original bounds. Disclosed data cannot be recalled. A saved contribution or receipt is history and never signing or dispatch authority.\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(continuation).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(pairing.binding()).map_err(|_| Error::InvalidData)?,
            request.plan.completion_expires_at_ms(),
            digest
        ));
        let prepared = Self {
            source,
            peer,
            stream,
            request,
            history,
            observed,
            native,
            window,
            digest,
            display,
        };
        prepared.check(owner)?;
        Ok(prepared)
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        self.source.check(&self.peer, owner)?;
        if owner.native().binding() != self.native {
            return Err(Error::ReviewMismatch);
        }
        self.remaining()?;
        require_observed_session_time(
            self.observed.observed_at_ms(),
            self.observed.observation_age(),
            now()?,
            self.observed.receipt().expires_at_ms,
        )?;
        connected(&self.stream, &self.peer)
    }
    fn remaining(&self) -> Result<Duration> {
        self.window.remaining(now()?, Instant::now())
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.native.check_current()?;
        self.peer.check_current()?;
        self.remaining()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_serve(
        mut self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
        client: &wholepact_authority::AuthorityClient,
    ) -> Result<BornRosterInventorySourceV2> {
        self.check(owner)?;
        if decision.binding() != &self.native || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let e = &self.source.enrolled;
        let extension = e.witness.extension().clone();
        let continuation = e.witness.continuation().ok_or(Error::Unavailable)?.clone();
        let reviewed_at_ms = now()?;
        let request = ManualRosterConstructionReservationRequestV2 {
            version: 2,
            construction: self.request.clone(),
            attempt_digest: continuation
                .digest_for(&extension)
                .map_err(|_| Error::InvalidData)?,
            attempt_sequence: continuation.sequence(),
            writer_epoch: self.history.snapshot().writer_epoch,
            expected_head: self.history.snapshot().head.clone(),
            session_id: e.witness.session().session_id.clone(),
            signer_intent_digest: e.retained.intent_digest.clone(),
            native_review_digest: self.digest.clone(),
            reviewed_at_ms,
        };
        request
            .validate_for(&extension, &continuation)
            .map_err(|_| Error::ReviewMismatch)?;
        self.check(owner)?;
        // The actual financial effect is inside the one-use read-order gate.
        // Missing/mismatched/expired/reused admission never reaches Reserve.
        // Any callback error or uncertain response leaves the receipt consumed.
        let reservation = self.source.with_exact_observation_before_reserve(
            &self.request, &self.peer, || {
                client.reserve_manual_roster_construction_v2(
                    &self.history, &extension, &continuation, &request,
                ).map_err(|_| Error::Uncertain)
            },
        )?;
        reservation
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        let r = reservation.record();
        let consume = ManualRosterConstructionConsumeRequestV2 {
            version: 2,
            operation_id: construction_consume_operation_id_v2(r, &extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            reservation_operation_id: r.request.construction.operation_id.clone(),
            reservation_digest: r
                .digest_for(&extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            account_id: extension
                .account_extension
                .terms
                .identity
                .account_id
                .clone(),
            network_profile_id: extension
                .account_extension
                .terms
                .identity
                .network_profile_id
                .clone(),
            writer_epoch: r.request.writer_epoch,
            expected_head: r.snapshot.head.clone(),
            session_id: r.session.session_id.clone(),
            common_invocation_digest: r
                .request
                .invocation_digest()
                .map_err(|_| Error::InvalidData)?,
            current_caller_binding_digest: self.request.current_caller_binding_digest.clone(),
        };
        // Cancellation between Reserve and Consume leaves conservative exposure.
        // It never fabricates another reservation or construction permission.
        self.check(owner)?;
        let binding = self.native.clone();
        let _admitted = binding.publication_lease()?;
        self.check(owner)?;
        let contribution = client
            .consume_manual_roster_construction_v2(reservation, &consume)
            .map_err(|_| Error::Uncertain)?;
        contribution
            .check_current()
            .map_err(|_| Error::ReviewMismatch)?;
        let r = contribution.reservation();
        let consumed = contribution.consumed();
        let evidence = ManualRosterConstructionContributionEvidenceV2 {
            version: 2,
            request: self.request.clone(),
            retained_signer_intent_digest: r.request.signer_intent_digest.clone(),
            current_attempt_digest: r.request.attempt_digest.clone(),
            current_attempt_sequence: r.request.attempt_sequence,
            native_review_digest: self.digest.clone(),
            witness_reservation_digest: r
                .digest_for(&extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            witness_consumed_digest: consumed
                .digest_for(r, &extension, &continuation)
                .map_err(|_| Error::InvalidData)?,
            reviewed_at_ms,
            reserved_at_ms: r.admitted_at_ms,
            consumed_at_ms: consumed.consumed_at_ms,
            reserved_debit_zatoshis: r.reserved_debit_zatoshis,
            reserved_input_value_zatoshis: r.reserved_input_value_zatoshis,
            writer_session_expires_at_ms: r.session.expires_at_ms,
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        let response = ManualRosterConstructionResponseV2::ExactConstructionConsumedV2 {
            evidence: Box::new(evidence),
        };
        let mut bytes =
            Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
        if bytes.len() >= MAX_ROSTER_CONSTRUCTION_FRAME {
            return Err(Error::Unavailable);
        }
        bytes.push(b'\n');
        let deadline = Instant::now()
            .checked_add(self.remaining()?.min(Duration::from_secs(2)))
            .ok_or(Error::ReviewMismatch)?;
        let mut offset = 0;
        while offset < bytes.len() {
            contribution
                .check_current()
                .map_err(|_| Error::ReviewMismatch)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Uncertain)?
                .min(self.remaining()?);
            self.stream.set_write_timeout(Some(remaining))?;
            let n = self.stream.write(&bytes[offset..])?;
            if n == 0 {
                return Err(Error::Uncertain);
            }
            offset += n;
        }
        if Instant::now() >= deadline {
            return Err(Error::Uncertain);
        }
        Ok(self.source)
    }
}
