//! Concrete installed-peer candidate-selection consumer. There is no public
//! constructor, Clone or Deserialize for the current selection owner.
use super::*;
use crate::manual_roster_candidate_selection_v2::{
    MAX_CANDIDATE_SELECTION_FRAME, ManualRosterCandidateSelectionEvidenceV2,
    ManualRosterCandidateSelectionResponseV2,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicU64;
use wholepact_core::manual_roster_candidate_selection_v2::{
    ManualRosterCandidateSelectionRequestV2, ManualRosterCandidateSelectionScopeV2,
};

impl NativeManualClient {
    /// A distinct native pairing in the same actual live installed process.
    /// Reuses neither the old grant nor its publication purpose. The native
    /// producer independently requires its actual retained continued source.
    pub fn begin_roster_candidate_selection_pair_before(
        self,
        application_label: &str,
        inventory: &ManualRosterCandidateSelectionScopeV2,
        deadline: Instant,
    ) -> Result<PendingNativeManualPair> {
        inventory.validate().map_err(|_| Error::Binding)?;
        self.require_scope(&inventory.selection.inventory.enrollment)?;
        if self.active_leases.load(Ordering::Acquire) != 0 {
            return Err(Error::Locked);
        }
        label(application_label)?;
        let scope = PairScope {
            account_id: inventory
                .selection
                .inventory
                .enrollment
                .identity
                .account_id
                .clone(),
            agreement_id: inventory
                .selection
                .inventory
                .enrollment
                .scope
                .agreement_id
                .clone(),
            participant_id: inventory
                .selection
                .inventory
                .enrollment
                .scope
                .participant_id
                .clone(),
            manifest_digest: inventory.pairing_digest().map_err(|_| Error::Binding)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let deadline = deadline.min(self.grant.expires);
        let mut stream =
            connect_local_before(&self.socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let peer = self.provider.verify_server(&stream)?;
        self.peer.same_live_process(&peer)?;
        let started = Instant::now();
        write_frame_until(
            &mut stream,
            &serde_json::json!({"command":"request_pairing","schema_version":1,"application_label":application_label,"scope":scope}),
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            None,
        )?;
        remaining_before(deadline)?;
        Ok(PendingNativeManualPair {
            provider: self.provider,
            socket: self.socket,
            peer,
            scope,
            stream,
            started,
            deadline,
        })
    }
    fn require_roster_candidate_selection_scope(
        &self,
        request: &ManualRosterCandidateSelectionRequestV2,
    ) -> Result<()> {
        request.validate().map_err(|_| Error::Binding)?;
        self.require_scope(&request.scope.selection.inventory.enrollment)?;
        if self.scope.manifest_digest
            != request.scope.pairing_digest().map_err(|_| Error::Binding)?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
            || request.current_caller_binding_digest != self.current_caller_binding_digest()?
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn begin_roster_candidate_selection_before(
        &self,
        request: &ManualRosterCandidateSelectionRequestV2,
        expected_retained_signer_intent_digest: &str,
        deadline: Instant,
    ) -> Result<PendingManualRosterCandidateSelectionV2<'_>> {
        hash(expected_retained_signer_intent_digest)?;
        self.require_roster_candidate_selection_scope(request)?;
        let now = Instant::now();
        let original_observed_at_ms = now_ms()?;
        let completion_deadline = now
            .checked_add(Duration::from_millis(
                request
                    .scope
                    .selection
                    .invocation
                    .construction_expires_at_ms
                    .checked_sub(original_observed_at_ms)
                    .ok_or(Error::Permission)?,
            ))
            .ok_or(Error::Permission)?;
        let window = request
            .remaining_ms(original_observed_at_ms)
            .map_err(|_| Error::Permission)?;
        let deadline = deadline.min(self.grant.expires).min(
            now.checked_add(Duration::from_millis(window))
                .ok_or(Error::Permission)?,
        );
        remaining_before(deadline)?;
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        // Guard is already armed if connect/write fails after partial delivery.
        let stream = self.open_request_before(serde_json::json!({"operation":"request_born_roster_candidate_selection_v2","request":request}),deadline)?;
        Ok(PendingManualRosterCandidateSelectionV2 {
            client: self,
            request: request.clone(),
            expected_retained_signer_intent_digest: expected_retained_signer_intent_digest.into(),
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
            completion_deadline,
            original_observed_at_ms,
        })
    }
}
/// A queued request only. No privacy or current-owner capability exists until
/// the actual native producer discloses under the fixed original deadline.
pub struct PendingManualRosterCandidateSelectionV2<'client> {
    client: &'client NativeManualClient,
    request: ManualRosterCandidateSelectionRequestV2,
    expected_retained_signer_intent_digest: String,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
    completion_deadline: Instant,
    original_observed_at_ms: u64,
}
impl<'client> PendingManualRosterCandidateSelectionV2<'client> {
    pub fn finish(mut self) -> Result<ManualRosterCandidateSelectionLeaseV2<'client>> {
        let bytes = Zeroizing::new(framing::read_frame_with_deadline(
            self.pending.stream()?,
            &self.client.peer,
            remaining_before(self.deadline)?,
        )?);
        if bytes.len() > MAX_CANDIDATE_SELECTION_FRAME {
            return Err(Error::Limit);
        }
        let response: ManualRosterCandidateSelectionResponseV2 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let ManualRosterCandidateSelectionResponseV2::RosterCandidateSelectionDisclosedV2 {
            lease_id,
            evidence,
            account_fvk_hex,
        } = &response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        hash(lease_id)?;
        if evidence.request != self.request
            || evidence.retained_signer_intent_digest != self.expected_retained_signer_intent_digest
        {
            return Err(Error::Binding);
        }
        let fvk = checked_inventory_fvk(
            account_fvk_hex,
            &self
                .request
                .scope
                .selection
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest,
        )?;
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        if observed_at_ms < self.original_observed_at_ms {
            return Err(Error::Permission);
        }
        let lifetime = original_deadline_budget(
            self.request.requested_at_ms,
            self.request.disclosure_expires_at_ms,
            observed_at_ms,
        )?
        .min(remaining_before(self.deadline)?);
        self.client
            .require_roster_candidate_selection_scope(&self.request)?;
        let lease = ManualRosterCandidateSelectionLeaseV2 {
            held: HeldLease {
                client: self.client,
                stream: Mutex::new(self.pending.take()?),
                lease_id: lease_id.clone(),
                evidence_digest: evidence.digest()?,
                started: observed,
                lifetime,
                original_deadline: Some((observed_at_ms, self.request.disclosure_expires_at_ms)),
                failed: AtomicBool::new(false),
                completion: CompletionState::Pending,
                // Last field: no fallible initialization follows the transfer.
                _slot: self.attempt.transfer_to_held()?,
            },
            evidence: evidence.as_ref().clone(),
            fvk,
            completion_deadline: self.completion_deadline,
            maximum_wall_seen: AtomicU64::new(observed_at_ms),
        };
        lease.check_current()?;
        Ok(lease)
    }
}
/// One live input-free candidate-selection consent. It cannot be converted to construction,
/// signing, dispatch, a saved contribution, or an admitted completion owner.
pub struct ManualRosterCandidateSelectionLeaseV2<'client> {
    held: HeldLease<'client>,
    evidence: ManualRosterCandidateSelectionEvidenceV2,
    fvk: Zeroizing<[u8; 96]>,
    completion_deadline: Instant,
    maximum_wall_seen: AtomicU64,
}
impl ManualRosterCandidateSelectionLeaseV2<'_> {
    /// Finish this exact purpose and await the native producer's bounded ack.
    /// Failure poisons the current client for any later request or re-pairing.
    /// Durable external effects remain retained even if acknowledgment fails.
    pub fn finish(self) -> Result<()> {
        self.held.finish()
    }

    pub fn binding(&self) -> &ManualRosterCandidateSelectionRequestV2 {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &ManualRosterCandidateSelectionEvidenceV2 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.held.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        observe_completion_wall(&self.maximum_wall_seen, now_ms()?)?;
        self.held.check_current()
    }
    pub fn full_viewing_key_bytes(&self) -> Result<&[u8; 96]> {
        self.check_current()?;
        Ok(&self.fvk)
    }
}
fn checked_inventory_fvk(encoded: &str, expected: &str) -> Result<Zeroizing<[u8; 96]>> {
    hash(expected)?;
    if encoded.len() != 192 {
        return Err(Error::Binding);
    }
    let decoded = Zeroizing::new(hex::decode(encoded).map_err(|_| Error::Binding)?);
    let fvk = Zeroizing::new(<[u8; 96]>::try_from(decoded.as_slice()).map_err(|_| Error::Binding)?);
    if hex::encode(Sha256::digest(fvk.as_slice())) != expected {
        return Err(Error::Binding);
    }
    Ok(fvk)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_viewing_bytes_require_exact_actual_account_digest() {
        let bytes = [7u8; 96];
        let expected = hex::encode(Sha256::digest(bytes));
        assert_eq!(
            checked_inventory_fvk(&hex::encode(bytes), &expected)
                .unwrap()
                .as_slice(),
            &bytes
        );
        for bad in [
            String::new(),
            "0".repeat(190),
            "g".repeat(192),
            "0".repeat(192),
        ] {
            assert!(checked_inventory_fvk(&bad, &expected).is_err());
        }
        assert!(checked_inventory_fvk(&hex::encode(bytes), &"0".repeat(64)).is_err());
    }
    #[test]
    fn candidate_deadline_is_remaining_original_time_not_reacquisition() {
        assert_eq!(
            original_deadline_budget(100, 30100, 30000).unwrap(),
            Duration::from_millis(100)
        );
        assert!(original_deadline_budget(100, 30100, 30100).is_err());
        assert!(original_deadline_budget(100, 30100, 99).is_err());
    }
}

use crate::manual_roster_construction_v2::{
    ManualRosterContributionRetentionEvidenceV2, ManualRosterContributionRetentionResponseV2,
    ManualRosterSelectionCommandV2,
};
use wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2;

impl<'client> ManualRosterCandidateSelectionLeaseV2<'client> {
    /// Irreversibly end viewing/selection access and ask the SAME native stream
    /// to review the actual selected contribution. No fresh window is created.
    /// The returned pending object retains cancellation poisoning and slot use.
    pub fn begin_retention(
        mut self,
        request: ManualRosterContributionRetentionRequestV2,
        original_completion_deadline: Instant,
    ) -> Result<PendingManualRosterContributionRetentionV2<'client>> {
        self.check_current()?;
        self.completion_deadline = self.completion_deadline.min(original_completion_deadline);
        remaining_before(self.completion_deadline)?;
        request.validate().map_err(|_| Error::Binding)?;
        if request.selection != self.evidence.request
            || request.selection_evidence_digest != self.evidence.digest()?
        {
            return Err(Error::Binding);
        }
        let wall = now_ms()?;
        let remaining = request
            .remaining_admission_ms(wall)
            .map_err(|_| Error::Permission)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or(Error::Permission)?
            .min(
                self.held
                    .started
                    .checked_add(self.held.lifetime)
                    .ok_or(Error::Permission)?,
            )
            .min(self.held.client.grant.expires);
        self.held.completion.begin()?;
        let command = ManualRosterSelectionCommandV2::RetainExactContributionV2 {
            lease_id: self.held.lease_id.clone(),
            evidence_digest: self.held.evidence_digest.clone(),
            request: Box::new(request.clone()),
        };
        {
            let mut stream = self.held.stream.lock().map_err(|_| Error::Ipc)?;
            write_frame_until_bounded(
                &mut stream,
                &command,
                restricted_phase(deadline, MAX_CURRENT_WAIT)?,
                Some((wall, request.admission_expires_at_ms)),
                crate::manual_roster_construction_v2::MAX_ROSTER_CONSTRUCTION_FRAME,
            )?;
        }
        Ok(PendingManualRosterContributionRetentionV2 {
            selected: self,
            request,
            deadline,
        })
    }
}
/// An unfinished native review, not retained-data or financial authority.
pub struct PendingManualRosterContributionRetentionV2<'client> {
    selected: ManualRosterCandidateSelectionLeaseV2<'client>,
    request: ManualRosterContributionRetentionRequestV2,
    deadline: Instant,
}
impl PendingManualRosterContributionRetentionV2<'_> {
    pub fn finish(mut self) -> Result<RetainedManualRosterContributionV2> {
        let wall = now_ms()?;
        self.request
            .remaining_admission_ms(wall)
            .map_err(|_| Error::Permission)?;
        let bytes = {
            let stream = self.selected.held.stream.lock().map_err(|_| Error::Ipc)?;
            Zeroizing::new(framing::read_frame_with_deadline(
                &stream,
                &self.selected.held.client.peer,
                phase_budget(
                    self.deadline,
                    Instant::now(),
                    Some((wall, self.request.admission_expires_at_ms)),
                    wall,
                )?,
            )?)
        };
        if bytes.len() > crate::manual_roster_construction_v2::MAX_ROSTER_CONSTRUCTION_FRAME {
            return Err(Error::Limit);
        }
        let response: ManualRosterContributionRetentionResponseV2 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let ManualRosterContributionRetentionResponseV2::ExactContributionRetainedV2 {
            evidence,
            durable_receipt_digest,
        } = response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        hash(&durable_receipt_digest)?;
        if evidence.request != self.request
            || evidence.retained_signer_intent_digest
                != self.selected.evidence.retained_signer_intent_digest
            || evidence.selection_observation != self.selected.evidence.current
        {
            return Err(Error::Binding);
        }
        // Admission happened while current. An exact already-admitted response
        // may finish after blur, but never after this original admission cutoff.
        phase_budget(
            self.deadline,
            Instant::now(),
            Some((wall, self.request.admission_expires_at_ms)),
            now_ms()?,
        )?;
        let observed_at_ms = now_ms()?;
        observe_completion_wall(&self.selected.maximum_wall_seen, observed_at_ms)?;
        let completion_expires_at_ms = self.request.completion_expires_at_ms();
        let lifetime = completion_budget(observed_at_ms, completion_expires_at_ms, observed_at_ms)?;
        let result = RetainedManualRosterContributionV2 {
            exact_observation_requested: AtomicBool::new(false),
            evidence: *evidence,
            durable_receipt_digest,
            provider_enrollment_reference: self
                .selected
                .held
                .client
                .provider
                .native_enrollment_reference()
                .into(),
            maximum_wall_seen: std::sync::Arc::new(AtomicU64::new(observed_at_ms)),
            completion_expires_at_ms,
            deadline: Instant::now()
                .checked_add(lifetime)
                .ok_or(Error::Permission)?
                .min(self.selected.completion_deadline),
        };
        // THIS exact retention reply is the terminal protocol acknowledgment.
        // No Finish command is sent on destruction and the old slot is released.
        self.selected.held.completion = CompletionState::Acknowledged;
        Ok(result)
    }
}
/// One purpose-specific, non-cloneable retained contribution permission. It has
/// no socket, native/current lease, FVK, signing or dispatch conversion. Only the
/// actual installed-peer response above creates it. Evidence is inert on disk.
///
/// ```compile_fail
/// # use wholepact_signer_origin::RetainedManualRosterContributionV2;
/// let _: RetainedManualRosterContributionV2 = serde_json::from_str("{}").unwrap();
/// ```
pub struct RetainedManualRosterContributionV2 {
    exact_observation_requested: AtomicBool,
    evidence: ManualRosterContributionRetentionEvidenceV2,
    durable_receipt_digest: String,
    provider_enrollment_reference: String,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
    completion_expires_at_ms: u64,
    deadline: Instant,
}
impl RetainedManualRosterContributionV2 {
    /// Crate-private one-shot request gate. Captures the genuine original
    /// monotonic ceiling; neither response JSON nor another client can reset it.
    pub(super) fn claim_exact_observation_attempt(&self) -> Result<(Instant, std::sync::Arc<AtomicU64>)> {
        self.check_retained()?;
        claim_read_once(&self.exact_observation_requested)?;
        Ok((self.deadline, self.maximum_wall_seen.clone()))
    }

    pub fn check_retained(&self) -> Result<()> {
        require_completion_at(
            self.deadline,
            &self.maximum_wall_seen,
            self.completion_expires_at_ms,
            now_ms()?,
            Instant::now(),
        )
    }
    pub fn request(&self) -> Result<&ManualRosterContributionRetentionRequestV2> {
        self.check_retained()?;
        Ok(&self.evidence.request)
    }
    pub fn evidence(&self) -> &ManualRosterContributionRetentionEvidenceV2 {
        &self.evidence
    }
    pub fn durable_receipt_digest(&self) -> &str {
        &self.durable_receipt_digest
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        &self.provider_enrollment_reference
    }
    /// Single ownership transfer for exact full-proposal assembly. This does not
    /// grant construction: later fresh full-proposal Reserve/Consume is required.
    pub fn into_retained_evidence(self) -> Result<ManualRosterContributionRetentionEvidenceV2> {
        self.check_retained()?;
        Ok(self.evidence)
    }
}
// A successful flag change is bookkeeping only; it creates no owner.
fn claim_read_once(attempted: &AtomicBool) -> Result<()> {
    if attempted.swap(true, Ordering::AcqRel) { Err(Error::Permission) } else { Ok(()) }
}

#[cfg(test)]
mod exact_observation_attempt_tests {
    use super::*;
    #[test]
    fn once_claimed_read_cannot_retry_after_loss_error_or_new_client() {
        let attempted = AtomicBool::new(false);
        claim_read_once(&attempted).unwrap();
        // The same retained owner gate, not any particular network client,
        // remains consumed through failed response/timeout/cancellation paths.
        for _ in 0..4 { assert!(claim_read_once(&attempted).is_err()); }
    }
    #[test]
    fn new_read_shares_original_wall_high_water_without_resetting_it() {
        let original = std::sync::Arc::new(AtomicU64::new(100));
        let admitted = original.clone();
        observe_completion_wall(&admitted, 200).unwrap();
        assert!(observe_completion_wall(&original, 199).is_err());
        observe_completion_wall(&original, 201).unwrap();
        assert!(observe_completion_wall(&admitted, 200).is_err());
    }
}

/// Pure deadline check; no authority is created by a clock or successful check.
pub(super) fn require_completion_at(
    deadline: Instant,
    maximum: &AtomicU64,
    expires: u64,
    wall: u64,
    monotonic: Instant,
) -> Result<()> {
    observe_completion_wall(maximum, wall)?;
    completion_budget(wall, expires, wall)?;
    if monotonic >= deadline {
        return Err(Error::Permission);
    }
    Ok(())
}
pub(super) fn observe_completion_wall(maximum: &AtomicU64, wall: u64) -> Result<()> {
    if wall < maximum.fetch_max(wall, Ordering::AcqRel) {
        return Err(Error::Permission);
    }
    Ok(())
}
fn completion_budget(observed: u64, expires: u64, wall: u64) -> Result<Duration> {
    if wall < observed || wall >= expires {
        return Err(Error::Permission);
    }
    Ok(Duration::from_millis(expires - wall))
}
#[cfg(test)]
mod retention_tests {
    use super::*;
    #[test]
    fn retained_guard_rejects_either_clock_expiry_and_high_water_rollback() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(900);
        let maximum = AtomicU64::new(100);
        require_completion_at(
            deadline,
            &maximum,
            1000,
            500,
            start + Duration::from_millis(400),
        )
        .unwrap();
        assert!(
            require_completion_at(
                deadline,
                &maximum,
                1000,
                499,
                start + Duration::from_millis(500)
            )
            .is_err()
        );
        assert!(require_completion_at(deadline, &maximum, 1000, 600, deadline).is_err());
        assert!(require_completion_at(deadline, &maximum, 1000, 1000, start).is_err());
    }
    #[test]
    fn observed_rollback_is_rejected_even_above_initial_wall() {
        let maximum = AtomicU64::new(100);
        observe_completion_wall(&maximum, 400).unwrap();
        assert!(observe_completion_wall(&maximum, 300).is_err());
        assert!(observe_completion_wall(&maximum, 399).is_err());
        observe_completion_wall(&maximum, 400).unwrap();
    }
    #[test]
    fn repeated_phase_transitions_cannot_extend_original_monotonic_ceiling() {
        let start = Instant::now();
        let original = start + Duration::from_millis(900);
        let mut inherited = original;
        for (elapsed, wall) in [(100, 200), (300, 150), (600, 700), (800, 250)] {
            let apparent = start
                + Duration::from_millis(elapsed)
                + completion_budget(100, 1000, wall).unwrap();
            inherited = inherited.min(apparent).min(original);
            assert!(inherited <= original);
        }
        assert!(inherited <= start + Duration::from_millis(900));
    }
    #[test]
    fn retained_completion_does_not_renew_or_follow_gui_focus() {
        assert_eq!(
            completion_budget(100, 1000, 999).unwrap(),
            Duration::from_millis(1)
        );
        assert!(completion_budget(100, 1000, 1000).is_err());
        assert!(completion_budget(100, 1000, 99).is_err());
    }
}
