//! A genuine purpose-distinct native decision on the existing fresh full-plan
//! source. No viewing bytes, financial Reserve/Consume or wallet key are sent.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1;
use wholepact_signer_origin::manual_roster_exact_input_observation_v1::{
    MAX_EXACT_INPUT_OBSERVATION_FRAME, ManualRosterExactInputObservationEvidenceV1,
    ManualRosterExactInputObservationResponseV1,
};

/// In-process receipt for ordering this additional-read admission before the
/// independent financial ceremony. Never deserialized or restored from disk.
pub(super) struct NativeExactObservationAdmission {
    request: ManualRosterExactInputObservationRequestV1,
    peer_grant_id: String,
    completion_deadline: Instant,
    maximum_wall_seen: AtomicU64,
}
/// Exact immutable claims and fixed clocks passed together to the private
/// admission transition. This inert borrowed input creates no capability.
struct ExactReadAdmissionInputs<'a> {
    request: &'a ManualRosterExactInputObservationRequestV1,
    review_digest: &'a str,
    peer_grant_id: &'a str,
    completion_deadline: Instant,
    window: &'a DisclosureWindow,
    wall: u64,
    monotonic: Instant,
}
impl NativeExactObservationAdmission {
    /// Private production transition, called only after the concrete producer's
    /// source/account/peer/history checks. A matching real NativeDecision and
    /// actual publication lease remain mandatory. No public/test-only factory.
    fn admit<'a>(
        native: &'a NativeAuthorityBinding,
        decision: NativeDecision,
        inputs: ExactReadAdmissionInputs<'_>,
    ) -> Result<(crate::native_ui::NativePublicationLease<'a>, Self)> {
        let ExactReadAdmissionInputs {
            request,
            review_digest,
            peer_grant_id,
            completion_deadline,
            window,
            wall,
            monotonic,
        } = inputs;
        request.validate().map_err(|_| Error::InvalidData)?;
        if decision.binding() != native || decision.reviewed_digest() != review_digest {
            return Err(Error::ReviewMismatch);
        }
        window.remaining(wall, monotonic)?;
        let publication = native.publication_lease()?;
        let admitted = Self {
            request: request.clone(),
            peer_grant_id: peer_grant_id.into(),
            completion_deadline,
            maximum_wall_seen: AtomicU64::new(wall),
        };
        admitted.check_completion_at(wall, monotonic)?;
        Ok((publication, admitted))
    }
    fn check_completion_at(&self, wall: u64, monotonic: Instant) -> Result<()> {
        observe_wall(&self.maximum_wall_seen, wall)?;
        if wall < self.request.requested_at_ms
            || wall >= self.request.completion_expires_at_ms
            || monotonic >= self.completion_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// The same private boundary gates the actual Reserve call and the focused
    /// state-machine tests. Taking occurs BEFORE validation/effect; every error
    /// or uncertain callback result leaves the receipt consumed.
    fn before_reserve<T>(
        slot: &mut Option<Self>,
        request: &wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2,
        peer_grant_id: &str,
        wall: u64,
        monotonic: Instant,
        reserve: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let admitted = slot.take().ok_or(Error::ReviewMismatch)?;
        admitted.check_completion_at(wall, monotonic)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        if admitted.request.plan != request.plan
            || admitted.request.operation_id == request.operation_id
            || admitted.request.current_caller_binding_digest
                != request.current_caller_binding_digest
            || admitted.peer_grant_id != peer_grant_id
        {
            return Err(Error::ReviewMismatch);
        }
        reserve()
    }
}
impl BornRosterInventorySourceV2 {
    /// Consumed immediately before Reserve; any later error preserves exposure
    /// and cannot obtain another additional-read admission from this source.
    pub(super) fn with_exact_observation_before_reserve<T>(
        &mut self,
        request: &wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2,
        peer: &AuthenticatedPeer,
        reserve: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        NativeExactObservationAdmission::before_reserve(
            &mut self.exact_observation,
            request,
            &peer.grant_id,
            now()?,
            Instant::now(),
            reserve,
        )
    }
}
pub(crate) struct PreparedRosterExactInputObservationV1 {
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    request: ManualRosterExactInputObservationRequestV1,
    observed: wholepact_authority::AuthenticatedWriterSession,
    native: NativeAuthorityBinding,
    window: DisclosureWindow,
    completion_deadline: Instant,
    maximum_wall_seen: AtomicU64,
    attempt_digest: String,
    attempt_sequence: u64,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedRosterExactInputObservationV1 {
    pub(crate) fn prepare(
        mut source: BornRosterInventorySourceV2,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: ManualRosterExactInputObservationRequestV1,
        history: ReconciledAuthorityHistory,
        observed: wholepact_authority::AuthenticatedWriterSession,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        source.check(&peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        // Advancing-tip semantics are pinned to this exact supported candidate
        // profile. A future network/branch/profile needs separate qualification.
        if request.plan.enrollment().identity.network_profile_id
            != wholepact_protocol::construction::PROFILE_ID
            || request
                .plan
                .retained
                .selection
                .scope
                .selection
                .economic_intent
                .agreement
                .network_profile_id
                != wholepact_protocol::construction::PROFILE_ID
        {
            return Err(Error::Unavailable);
        }
        // The same live source has one preparation attempt. Rejection, focus
        // loss or an uncertain response cannot reset this state.
        if source.exact_observation_attempted {
            return Err(Error::ReviewMismatch);
        }
        source.exact_observation_attempted = true;
        let e = &source.enrolled;
        let old = &request.plan.retained.selection.scope;
        let inventory = &old.selection.inventory;
        source.require_provenance(&old.provenance, inventory)?;
        let continuation = e.witness.continuation().ok_or(Error::Unavailable)?;
        let extension = e.witness.extension();
        let attempt_digest = continuation
            .digest_for(extension)
            .map_err(|_| Error::InvalidData)?;
        let attempt_sequence = continuation.sequence();
        if inventory.enrollment != e.retained.record.account_record.terms
            || inventory.enrollment_ref != e.retained.record.account_record.reference()?
            || attempt_sequence <= inventory.attempt.attempt_sequence
            || attempt_digest == inventory.attempt.continuation_digest
            || old.selection.original_policy_origin
                != original(&e.retained.account)?
                    .anchor()
                    .complete_policy_origin_v2()?
            || peer.scope.account_id != inventory.enrollment.identity.account_id
            || peer.scope.agreement_id != inventory.enrollment.scope.agreement_id
            || peer.scope.participant_id != inventory.enrollment.scope.participant_id
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
        super::super::retention::read_exact_with_ciphertext_digest(
            &e.retained,
            &request.plan.retained,
            &request.plan.retained_evidence_digest,
            &request.original_durable_receipt_digest,
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
        // Independent witness full-plan review is required but is NOT read
        // permission: only the new NativeDecision below admits this purpose.
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
            .validate_for(extension)
            .map_err(|_| Error::ReviewMismatch)?;
        if approval.plan != request.plan {
            return Err(Error::ReviewMismatch);
        }
        let fvk = e.retained.account.account().fvk()?;
        let change = wholepact_protocol::review::decode_testnet_receiver(
            &request.plan.retained.change_address,
        )
        .map_err(|_| Error::ReviewMismatch)?;
        if fvk.scope_for_address(&change) != Some(orchard::keys::Scope::Internal)
            || hex::encode(Sha256::digest(fvk.to_bytes()))
                != inventory.enrollment.identity.full_viewing_key_digest
        {
            return Err(Error::ReviewMismatch);
        }
        connected(&stream, &peer)?;
        let native = owner.native().binding();
        let wall = now()?;
        let monotonic = Instant::now();
        let window = DisclosureWindow::new(
            request.requested_at_ms,
            request.admission_expires_at_ms,
            wall,
            monotonic,
            native.bounded_deadline()?,
        )?;
        // This ceiling restricts the native ordering receipt only. The client
        // additionally captures the ACTUAL original retained/Host Instant.
        let completion_deadline = monotonic
            .checked_add(Duration::from_millis(
                request
                    .completion_expires_at_ms
                    .checked_sub(wall)
                    .filter(|v| *v > 0)
                    .ok_or(Error::ReviewMismatch)?,
            ))
            .ok_or(Error::ReviewMismatch)?;
        let pairing =
            crate::native_ui::AuthenticatedPairing::from_authenticated_request(peer.clone())?;
        let digest = canonical(
            "wholepact:native-roster-exact-input-observation-review:v1",
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
            "APPROVE ONE ADDITIONAL EXACT-INPUT PRIVACY READ\n{}\n\nActual continuing attempt: {} / {}\nActual paired process:\n{}\n\nContact ONLY the original public-block provider {} at {}. It can observe timing, IP address and requested public heights. Scan ONLY the already imported original dedicated account at {} and inspect ONLY the named retained inputs and ORIGINAL anchor. No new viewing material is exported and no inputs are selected again. Append-only continuing-branch observations are provider reports, not independent consensus or global unspentness proof. Bounded scan progress may be persisted even if later checks fail.\n\nMaximum added blocks: {} (derived current cap {}, no chasing a moving tip). Maximum total scan/network runtime: {} ms. Post-scan admission runway: {} ms. Maximum public scan concurrency: {}. Minimum confirmations: {}. Immutable original expiry: {}; require current tip + {} < expiry, so maximum current tip is {}. Original anchor, witnesses, target, inputs, return and full plan stay unchanged.\n\nOne attempt, no automatic retry. This may be queued while other owners review. Cancellation, focus loss and disconnect stop NEW admission; this explicitly admitted bounded read may finish afterward, only before {} ms Unix time AND the already-captured ORIGINAL monotonic completion ceiling. No deadline is renewed. The additional native admission itself expires at {}. Data already disclosed cannot be recalled. This action does not reserve/consume financial exposure, sign, prove, dispatch, recover an account or clear exposure. A separate exact full-construction decision and financial Reserve/Consume remain required.\nExact review: {}",
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            attempt_sequence,
            attempt_digest,
            serde_json::to_string_pretty(pairing.binding()).map_err(|_| Error::InvalidData)?,
            inventory.provider.source_id,
            inventory.provider.endpoint,
            inventory.wallet_destination,
            request.profile.maximum_additional_blocks,
            request
                .maximum_additional_blocks()
                .map_err(|_| Error::InvalidData)?,
            request.profile.maximum_scan_runtime_ms,
            request.profile.post_scan_runway_ms,
            request.profile.maximum_parallel_scans,
            request.profile.minimum_confirmations,
            old.selection.economic_intent.expiry_height,
            request.profile.minimum_expiry_margin_blocks,
            request
                .maximum_observed_tip()
                .map_err(|_| Error::InvalidData)?,
            request.completion_expires_at_ms,
            request.admission_expires_at_ms,
            digest,
        ));
        let prepared = Self {
            source,
            peer,
            stream,
            request,
            observed,
            native,
            window,
            completion_deadline,
            maximum_wall_seen: AtomicU64::new(wall),
            attempt_digest,
            attempt_sequence,
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
        let wall = now()?;
        observe_wall(&self.maximum_wall_seen, wall)?;
        self.window.remaining(wall, Instant::now())
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
    ) -> Result<BornRosterInventorySourceV2> {
        self.check(owner)?;
        let binding = self.native.clone();
        let admitted_at_ms = now()?;
        let (_publication, admitted) = NativeExactObservationAdmission::admit(
            &binding,
            decision,
            ExactReadAdmissionInputs {
                request: &self.request,
                review_digest: &self.digest,
                peer_grant_id: &self.peer.grant_id,
                completion_deadline: self.completion_deadline,
                window: &self.window,
                wall: admitted_at_ms,
                monotonic: Instant::now(),
            },
        )?;
        self.check(owner)?;
        let evidence = ManualRosterExactInputObservationEvidenceV1 {
            version: 1,
            request: self.request.clone(),
            retained_signer_intent_digest: self.source.enrolled.retained.intent_digest.clone(),
            current_attempt_digest: self.attempt_digest.clone(),
            current_attempt_sequence: self.attempt_sequence,
            native_review_digest: self.digest.clone(),
            admitted_at_ms,
            writer_session_expires_at_ms: self.observed.receipt().expires_at_ms,
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        let response =
            ManualRosterExactInputObservationResponseV1::ExactInputObservationAdmittedV1 {
                evidence: Box::new(evidence),
            };
        let mut bytes =
            Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::InvalidData)?);
        if bytes.len() >= MAX_EXACT_INPUT_OBSERVATION_FRAME {
            return Err(Error::Unavailable);
        }
        bytes.push(b'\n');
        self.source.exact_observation = Some(admitted);
        let deadline = Instant::now()
            .checked_add(self.remaining()?.min(Duration::from_secs(2)))
            .ok_or(Error::ReviewMismatch)?;
        let mut offset = 0;
        while offset < bytes.len() {
            // After admission the exact bounded terminal response may complete
            // after focus changes. This checks SAME actual OS peer and fixed
            // clocks, without re-admitting or polling a stale focus grant.
            self.peer
                .peer
                .same_live_process(&crate::native_peer::PeerProcess::observe(&self.stream)?)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|v| !v.is_zero())
                .ok_or(Error::Uncertain)?
                .min(self.remaining()?);
            self.stream.set_write_timeout(Some(remaining))?;
            let wrote = self.stream.write(&bytes[offset..])?;
            if wrote == 0 {
                return Err(Error::Uncertain);
            }
            offset += wrote;
        }
        self.remaining()?;
        if Instant::now() >= deadline {
            return Err(Error::Uncertain);
        }
        Ok(self.source)
    }
}
fn observe_wall(high: &AtomicU64, now: u64) -> Result<()> {
    let previous = high.fetch_max(now, Ordering::AcqRel);
    if now < previous {
        Err(Error::ReviewMismatch)
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn additional_read_clock_high_water_cannot_be_rolled_back() {
        let high = AtomicU64::new(100);
        observe_wall(&high, 101).unwrap();
        assert!(observe_wall(&high, 100).is_err());
        observe_wall(&high, 101).unwrap();
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod source_state_machine_tests {
    use super::*;
    use crate::native_ui::{recovery_test_authority, recovery_test_decision};
    use std::cell::Cell;
    use wholepact_core::{
        manual_roster_construction_v2::ManualRosterConstructionRequestV2,
        manual_roster_exact_input_observation_v1::{
            ExactInputObservationProfileV1, ExactInputObservationPurposeV1,
        },
    };

    // Existing synthetic historical DATA only. No account, key, socket, peer,
    // financial client or current wallet is constructed by this fixture.
    fn requests() -> (
        ManualRosterExactInputObservationRequestV1,
        ManualRosterConstructionRequestV2,
    ) {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../consent_journal/construction_history.synthetic.json"
        ))
        .unwrap();
        let mut construction: ManualRosterConstructionRequestV2 = serde_json::from_value(
            value["alice-reservation"]["record"]["request"]["construction"].clone(),
        )
        .unwrap();
        construction.validate().unwrap();
        let requested = construction.requested_at_ms;
        let read = ManualRosterExactInputObservationRequestV1 {
            version: 1,
            operation_id: "synthetic-native-additional-read".into(),
            profile: ExactInputObservationProfileV1::for_plan(&construction.plan).unwrap(),
            original_durable_receipt_digest: "ab".repeat(32),
            purpose: ExactInputObservationPurposeV1::ObserveRetainedInputsOnly,
            current_caller_binding_digest: construction.current_caller_binding_digest.clone(),
            requested_at_ms: requested,
            admission_expires_at_ms: requested + 30_000,
            completion_expires_at_ms: construction.plan.completion_expires_at_ms(),
            plan: construction.plan.clone(),
        };
        read.validate().unwrap();
        construction.requested_at_ms += 1;
        construction.validate().unwrap();
        (read, construction)
    }
    fn admission(
        request: &ManualRosterExactInputObservationRequestV1,
        authority: &crate::native_ui::NativeAuthority,
        start: Instant,
    ) -> NativeExactObservationAdmission {
        let binding = authority.binding();
        let digest = "cd".repeat(32);
        let window = DisclosureWindow::new(
            request.requested_at_ms,
            request.admission_expires_at_ms,
            request.requested_at_ms,
            start,
            start + Duration::from_secs(30),
        )
        .unwrap();
        let (lease, receipt) = NativeExactObservationAdmission::admit(
            &binding,
            recovery_test_decision(authority, &digest),
            ExactReadAdmissionInputs {
                request,
                review_digest: &digest,
                peer_grant_id: "synthetic-peer-grant",
                completion_deadline: start + Duration::from_secs(60),
                window: &window,
                wall: request.requested_at_ms,
                monotonic: start,
            },
        )
        .unwrap();
        drop(lease);
        receipt
    }
    #[test]
    fn actual_order_gate_denies_missing_mismatched_and_reused_before_effect() {
        let (read, construction) = requests();
        let authority = recovery_test_authority();
        let start = Instant::now();
        let effects = Cell::new(0);
        let effect = || {
            effects.set(effects.get() + 1);
            Ok(())
        };
        let mut missing = None;
        assert!(
            NativeExactObservationAdmission::before_reserve(
                &mut missing,
                &construction,
                "synthetic-peer-grant",
                read.requested_at_ms + 1,
                start,
                effect
            )
            .is_err()
        );
        assert_eq!(effects.get(), 0);
        for mismatch in 0..4 {
            let mut slot = Some(admission(&read, &authority, start));
            let mut changed = construction.clone();
            let mut peer = "synthetic-peer-grant";
            match mismatch {
                0 => changed.current_caller_binding_digest = "ef".repeat(32),
                1 => changed.operation_id = read.operation_id.clone(),
                2 => peer = "other-peer-grant",
                _ => changed.plan.retained_evidence_digest = "de".repeat(32),
            }
            assert!(
                NativeExactObservationAdmission::before_reserve(
                    &mut slot,
                    &changed,
                    peer,
                    read.requested_at_ms + 1,
                    start,
                    effect
                )
                .is_err()
            );
            assert!(slot.is_none());
            assert_eq!(effects.get(), 0);
        }
        let mut slot = Some(admission(&read, &authority, start));
        NativeExactObservationAdmission::before_reserve(
            &mut slot,
            &construction,
            "synthetic-peer-grant",
            read.requested_at_ms + 1,
            start,
            effect,
        )
        .unwrap();
        assert_eq!(effects.get(), 1);
        assert!(
            NativeExactObservationAdmission::before_reserve(
                &mut slot,
                &construction,
                "synthetic-peer-grant",
                read.requested_at_ms + 1,
                start,
                effect
            )
            .is_err()
        );
        assert_eq!(effects.get(), 1);
    }
    #[test]
    fn reserve_callback_error_or_uncertainty_never_restores_read_receipt() {
        let (read, construction) = requests();
        let authority = recovery_test_authority();
        let start = Instant::now();
        let effects = Cell::new(0);
        let mut slot = Some(admission(&read, &authority, start));
        let result: Result<()> = NativeExactObservationAdmission::before_reserve(
            &mut slot,
            &construction,
            "synthetic-peer-grant",
            read.requested_at_ms + 1,
            start,
            || {
                effects.set(effects.get() + 1);
                Err(Error::Uncertain)
            },
        );
        assert!(result.is_err());
        assert!(slot.is_none());
        assert_eq!(effects.get(), 1);
        assert!(
            NativeExactObservationAdmission::before_reserve(
                &mut slot,
                &construction,
                "synthetic-peer-grant",
                read.requested_at_ms + 1,
                start,
                || {
                    effects.set(effects.get() + 1);
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(effects.get(), 1);
    }
    #[test]
    fn actual_native_decision_requires_current_same_source_and_exact_digest() {
        let (read, _) = requests();
        let start = Instant::now();
        let digest = "cd".repeat(32);
        for mismatch in 0..3 {
            let authority = recovery_test_authority();
            let other = recovery_test_authority();
            let binding = authority.binding();
            let decision = if mismatch == 0 {
                recovery_test_decision(&other, &digest)
            } else if mismatch == 1 {
                recovery_test_decision(&authority, &"de".repeat(32))
            } else {
                recovery_test_decision(&authority, &digest)
            };
            // Dropping uses the ACTUAL NativeAuthority invalidation path used
            // for lifecycle teardown. It creates no synthetic approval boolean.
            if mismatch == 2 {
                drop(authority);
            }
            let window = DisclosureWindow::new(
                read.requested_at_ms,
                read.admission_expires_at_ms,
                read.requested_at_ms,
                start,
                start + Duration::from_secs(30),
            )
            .unwrap();
            assert!(
                NativeExactObservationAdmission::admit(
                    &binding,
                    decision,
                    ExactReadAdmissionInputs {
                        request: &read,
                        review_digest: &digest,
                        peer_grant_id: "synthetic-peer-grant",
                        completion_deadline: start + Duration::from_secs(60),
                        window: &window,
                        wall: read.requested_at_ms,
                        monotonic: start,
                    }
                )
                .is_err()
            );
        }
    }
    #[test]
    fn admitted_completion_survives_native_invalidation_but_never_renews_bounds() {
        let (read, _) = requests();
        let authority = recovery_test_authority();
        let binding = authority.binding();
        let start = Instant::now();
        let admitted = admission(&read, &authority, start);
        drop(authority); // Actual binding invalidation; no lease held here.
        assert!(binding.check_current().is_err());
        assert!(binding.publication_lease().is_err());
        // Explicitly admitted data completion is independent of NEW admission.
        admitted
            .check_completion_at(read.requested_at_ms + 1, start + Duration::from_secs(1))
            .unwrap();
        assert!(
            admitted
                .check_completion_at(read.requested_at_ms, start + Duration::from_secs(2))
                .is_err()
        );
        assert!(
            admitted
                .check_completion_at(read.requested_at_ms + 2, start + Duration::from_secs(60))
                .is_err()
        );
        assert!(
            admitted
                .check_completion_at(read.completion_expires_at_ms, start)
                .is_err()
        );
    }
    #[test]
    fn actual_admission_cutoff_and_original_completion_ceiling_are_independent() {
        let (read, _) = requests();
        let authority = recovery_test_authority();
        let binding = authority.binding();
        let digest = "cd".repeat(32);
        let start = Instant::now();
        for boundary in 0..3 {
            let window = DisclosureWindow::new(
                read.requested_at_ms,
                read.admission_expires_at_ms,
                read.requested_at_ms,
                start,
                start + Duration::from_secs(30),
            )
            .unwrap();
            let (wall, monotonic, completion) = match boundary {
                0 => (
                    read.admission_expires_at_ms,
                    start,
                    start + Duration::from_secs(60),
                ),
                1 => (
                    read.requested_at_ms,
                    start + Duration::from_secs(30),
                    start + Duration::from_secs(60),
                ),
                _ => (read.requested_at_ms, start, start),
            };
            assert!(
                NativeExactObservationAdmission::admit(
                    &binding,
                    recovery_test_decision(&authority, &digest),
                    ExactReadAdmissionInputs {
                        request: &read,
                        review_digest: &digest,
                        peer_grant_id: "synthetic-peer-grant",
                        completion_deadline: completion,
                        window: &window,
                        wall,
                        monotonic,
                    }
                )
                .is_err()
            );
        }
    }
}
