//! Concrete installed-peer full-proposal consumer. Saved JSON, old selection
//! bytes and caller-created callbacks cannot mint the one-use completion owner.
use super::roster_candidate_selection_v2::require_completion_at;
use super::*;
use crate::manual_roster_construction_v2::{
    ManualRosterConstructionContributionEvidenceV2, ManualRosterConstructionResponseV2,
};
use std::sync::atomic::AtomicU64;
use wholepact_core::manual_roster_construction_v2::{
    ManualRosterConstructionPlanV2, ManualRosterConstructionRequestV2,
};
impl NativeManualClient {
    /// Called only after a genuine fresh V4 continuation/publication has finished.
    /// Pairing consumes the prior request client and still checks same OS process.
    pub fn begin_roster_construction_pair_before(
        self,
        application_label: &str,
        plan: &ManualRosterConstructionPlanV2,
        deadline: Instant,
    ) -> Result<PendingNativeManualPair> {
        plan.validate().map_err(|_| Error::Binding)?;
        let terms = plan.enrollment();
        self.require_scope(terms)?;
        if self.active_leases.load(Ordering::Acquire) != 0 {
            return Err(Error::Locked);
        }
        self.handoff.check()?;
        label(application_label)?;
        let scope = PairScope {
            account_id: terms.identity.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: plan.digest().map_err(|_| Error::Binding)?,
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
    pub fn begin_roster_construction_before(
        &self,
        request: &ManualRosterConstructionRequestV2,
        expected_signer_intent: &str,
        expected_current_attempt_digest: &str,
        expected_current_attempt_sequence: u64,
        deadline: Instant,
        original_completion_deadline: Instant,
    ) -> Result<PendingManualRosterConstructionV2<'_>> {
        request.validate().map_err(|_| Error::Binding)?;
        for h in [expected_signer_intent, expected_current_attempt_digest] {
            hash(h)?;
        }
        self.require_scope(request.plan.enrollment())?;
        if self.scope.manifest_digest != request.plan.digest().map_err(|_| Error::Binding)?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
            || request.current_caller_binding_digest != self.current_caller_binding_digest()?
            || expected_current_attempt_sequence < 2
        {
            return Err(Error::Binding);
        }
        let wall = now_ms()?;
        let completion_deadline = Instant::now()
            .checked_add(Duration::from_millis(
                request
                    .plan
                    .completion_expires_at_ms()
                    .checked_sub(wall)
                    .ok_or(Error::Permission)?,
            ))
            .ok_or(Error::Permission)?;
        let completion_deadline = completion_deadline.min(original_completion_deadline);
        remaining_before(completion_deadline)?;
        let budget = request
            .remaining_admission_ms(wall)
            .map_err(|_| Error::Permission)?;
        let deadline = deadline.min(self.grant.expires).min(
            Instant::now()
                .checked_add(Duration::from_millis(budget))
                .ok_or(Error::Permission)?,
        );
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        let stream=self.open_request_before_bounded(serde_json::json!({"operation":"request_born_roster_construction_v2","request":request}),deadline,crate::manual_roster_construction_v2::MAX_ROSTER_CONSTRUCTION_FRAME)?;
        Ok(PendingManualRosterConstructionV2 {
            client: self,
            request: request.clone(),
            expected_signer_intent: expected_signer_intent.into(),
            expected_current_attempt_digest: expected_current_attempt_digest.into(),
            expected_current_attempt_sequence,
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
            observed_at_ms: wall,
            completion_deadline,
        })
    }
}
pub struct PendingManualRosterConstructionV2<'client> {
    client: &'client NativeManualClient,
    request: ManualRosterConstructionRequestV2,
    expected_signer_intent: String,
    expected_current_attempt_digest: String,
    expected_current_attempt_sequence: u64,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
    observed_at_ms: u64,
    completion_deadline: Instant,
}
impl PendingManualRosterConstructionV2<'_> {
    pub fn finish(mut self) -> Result<AdmittedManualRosterConstructionContributionV2> {
        let bytes = Zeroizing::new(framing::read_frame_with_deadline(
            self.pending.stream()?,
            &self.client.peer,
            phase_budget(
                self.deadline,
                Instant::now(),
                Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
                now_ms()?,
            )?,
        )?);
        if bytes.len() > crate::manual_roster_construction_v2::MAX_ROSTER_CONSTRUCTION_FRAME {
            return Err(Error::Limit);
        }
        let response: ManualRosterConstructionResponseV2 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let ManualRosterConstructionResponseV2::ExactConstructionConsumedV2 { evidence } = response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        if evidence.request != self.request
            || evidence.retained_signer_intent_digest != self.expected_signer_intent
            || evidence.current_attempt_digest != self.expected_current_attempt_digest
            || evidence.current_attempt_sequence != self.expected_current_attempt_sequence
        {
            return Err(Error::Binding);
        }
        phase_budget(
            self.deadline,
            Instant::now(),
            Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
            now_ms()?,
        )?;
        let observed_at_ms = now_ms()?;
        let expires = self.request.plan.completion_expires_at_ms();
        if observed_at_ms < evidence.consumed_at_ms || observed_at_ms >= expires {
            return Err(Error::Permission);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(expires - observed_at_ms))
            .ok_or(Error::Permission)?;
        let owner = AdmittedManualRosterConstructionContributionV2 {
            evidence: *evidence,
            maximum_wall_seen: AtomicU64::new(observed_at_ms),
            deadline: deadline.min(self.completion_deadline),
        };
        // Exact authenticated terminal response acknowledges this request. Slot
        // closes now; no live GUI/writer/process owner escapes into completion.
        drop(self.attempt.slot.take().ok_or(Error::Permission)?);
        Ok(owner)
    }
}
/// One non-signing construction contribution. No Clone/Deserialize/public
/// constructor and no conversion to signing, proof, dispatch or fresh admission.
///
/// ```compile_fail
/// # use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV2;
/// let _: AdmittedManualRosterConstructionContributionV2 = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// # use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV2;
/// fn duplicate(owner: &AdmittedManualRosterConstructionContributionV2)
///     -> AdmittedManualRosterConstructionContributionV2 { owner.clone() }
/// ```
pub struct AdmittedManualRosterConstructionContributionV2 {
    evidence: ManualRosterConstructionContributionEvidenceV2,
    maximum_wall_seen: AtomicU64,
    deadline: Instant,
}
impl AdmittedManualRosterConstructionContributionV2 {
    pub fn check_completion(&self) -> Result<()> {
        require_completion_at(
            self.deadline,
            &self.maximum_wall_seen,
            self.evidence.request.plan.completion_expires_at_ms(),
            now_ms()?,
            Instant::now(),
        )
    }
    pub fn evidence(&self) -> &ManualRosterConstructionContributionEvidenceV2 {
        &self.evidence
    }
    pub fn request(&self) -> Result<&ManualRosterConstructionRequestV2> {
        self.check_completion()?;
        Ok(&self.evidence.request)
    }
    /// Ownership transfer into the concrete one-use Host invocation conjunction.
    /// Inert returned audit data cannot recreate this consumed owner.
    pub fn into_evidence(self) -> Result<ManualRosterConstructionContributionEvidenceV2> {
        self.check_completion()?;
        Ok(self.evidence)
    }
}
