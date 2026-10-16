//! Concrete installed-peer full-proposal consumer. Saved JSON, old selection
//! bytes and caller-created callbacks cannot mint the one-use completion owner.
use super::roster_candidate_selection_v2::require_completion_at;
use super::*;
use crate::manual_roster_construction_v3::{
    ManualRosterConstructionContributionEvidenceV3, ManualRosterConstructionResponseV3,
};
use std::sync::atomic::AtomicU64;
use wholepact_core::manual_roster_construction_v3::{
    ManualRosterConstructionPlanV3, ManualRosterConstructionRequestV3,
};
impl NativeManualClient {
    /// Called only after a genuine fresh V4 continuation/publication has finished.
    /// Pairing consumes the prior request client and still checks same OS process.
    pub fn begin_roster_construction_v3_pair_before(
        self,
        application_label: &str,
        plan: &ManualRosterConstructionPlanV3,
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
    pub fn begin_roster_construction_v3_before(
        &self,
        request: &ManualRosterConstructionRequestV3,
        expected_signer_intent: &str,
        expected_current_attempt_digest: &str,
        expected_current_attempt_sequence: u64,
        deadline: Instant,
        original_read: &StartedRosterCommonContextReadV1,
    ) -> Result<PendingManualRosterConstructionV3<'_>> {
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
        let (original_completion_deadline, maximum_wall_seen) =
            original_read.claim_construction_attempt(request)?;
        if expected_signer_intent != original_read.evidence().retained_signer_intent_digest {
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
        let stream=self.open_request_before_bounded(serde_json::json!({"operation":"request_born_roster_construction_v3","request":request}),deadline,crate::manual_roster_construction_v3::MAX_ROSTER_CONSTRUCTION_FRAME_V3)?;
        Ok(PendingManualRosterConstructionV3 {
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
            maximum_wall_seen,
            common_context_read_admission_digest: original_read.evidence().digest()?,
            witness_plan_approval_digest: original_read
                .request()?
                .witness_plan_approval_digest
                .clone(),
        })
    }
}
pub struct PendingManualRosterConstructionV3<'client> {
    client: &'client NativeManualClient,
    request: ManualRosterConstructionRequestV3,
    expected_signer_intent: String,
    expected_current_attempt_digest: String,
    expected_current_attempt_sequence: u64,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
    observed_at_ms: u64,
    completion_deadline: Instant,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
    common_context_read_admission_digest: String,
    witness_plan_approval_digest: String,
}
impl PendingManualRosterConstructionV3<'_> {
    pub fn finish(mut self) -> Result<AdmittedManualRosterConstructionContributionV3> {
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
        if bytes.len() > crate::manual_roster_construction_v3::MAX_ROSTER_CONSTRUCTION_FRAME_V3 {
            return Err(Error::Limit);
        }
        let response: ManualRosterConstructionResponseV3 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let ManualRosterConstructionResponseV3::ExactConstructionConsumedV3 { evidence } = response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        if evidence.common_context_read_admission_digest
            != self.common_context_read_admission_digest
            || evidence.witness_plan_approval_digest != self.witness_plan_approval_digest
            || evidence.request != self.request
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
        let owner = AdmittedManualRosterConstructionContributionV3 {
            evidence: *evidence,
            reentry: None,
            maximum_wall_seen: self.maximum_wall_seen.clone(),
            deadline: deadline.min(self.completion_deadline),
        };
        owner.check_completion()?;
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
/// # use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3;
/// let _: AdmittedManualRosterConstructionContributionV3 = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// # use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3;
/// fn duplicate(owner: &AdmittedManualRosterConstructionContributionV3)
///     -> AdmittedManualRosterConstructionContributionV3 { owner.clone() }
/// ```
struct ReenteredConstructionBinding {
    lineage: wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1,
    original_read_identity: std::sync::Arc<AtomicBool>,
}
pub struct AdmittedManualRosterConstructionContributionV3 {
    reentry: Option<ReenteredConstructionBinding>,
    evidence: ManualRosterConstructionContributionEvidenceV3,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
    deadline: Instant,
}
impl AdmittedManualRosterConstructionContributionV3 {
    pub fn check_completion(&self) -> Result<()> {
        require_completion_at(
            self.deadline,
            &self.maximum_wall_seen,
            self.reentry
                .as_ref()
                .map_or(self.evidence.request.plan.completion_expires_at_ms(), |v| {
                    v.lineage.completion_expires_at_ms
                }),
            now_ms()?,
            Instant::now(),
        )
    }
    pub fn evidence(&self) -> &ManualRosterConstructionContributionEvidenceV3 {
        &self.evidence
    }
    pub fn request(&self) -> Result<&ManualRosterConstructionRequestV3> {
        self.check_completion()?;
        Ok(&self.evidence.request)
    }
    /// Ownership transfer into the concrete one-use Host invocation conjunction.
    /// Inert returned audit data cannot recreate this consumed owner.
    pub fn into_evidence(self) -> Result<ManualRosterConstructionContributionEvidenceV3> {
        self.check_completion()?;
        // New lineage is mandatory archival data. The old extraction route
        // cannot silently erase the fact that this used a new native caller.
        if self.reentry.is_some() {
            return Err(Error::Binding);
        }
        Ok(self.evidence)
    }
    pub fn reentry_lineage(
        &self,
    ) -> Option<&wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1>
    {
        self.reentry.as_ref().map(|v| &v.lineage)
    }
    pub fn into_reentered_evidence(
        self,
    ) -> Result<crate::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1> {
        self.check_completion()?;
        let reentry = self.reentry.ok_or(Error::Binding)?;
        let value = crate::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1 {
            version: 1,
            reentry_lineage: reentry.lineage,
            construction: self.evidence,
        };
        value.validate()?;
        Ok(value)
    }
    /// The actual original wallet read remains required through construction.
    /// Saved equality is insufficient on the new path: pointer identity must
    /// match the exact original one-attempt state retained by the observation.
    pub fn check_original_read(&self, original: &StartedRosterCommonContextReadV1) -> Result<()> {
        self.check_completion()?;
        original.check_completion()?;
        let read = original.evidence();
        if self.evidence.common_context_read_admission_digest != read.digest()?
            || self.evidence.witness_plan_approval_digest
                != read.request.witness_plan_approval_digest
            || self.evidence.request.plan != read.request.plan
            || self.evidence.retained_signer_intent_digest != read.retained_signer_intent_digest
        {
            return Err(Error::Binding);
        }
        if let Some(reentry) = &self.reentry {
            original.matches_reentry_identity(&reentry.original_read_identity)?;
            let lineage = &reentry.lineage;
            if lineage.request.original_read != read.request
                || lineage.request.original_attempt_digest != read.current_attempt_digest
                || lineage.request.original_attempt_sequence != read.current_attempt_sequence
                || lineage.request.original_read_admission_digest != read.digest()?
                || lineage.request.current_caller_binding_digest
                    != self.evidence.request.current_caller_binding_digest
                || lineage.request.current_attempt_digest != self.evidence.current_attempt_digest
                || lineage.request.current_attempt_sequence
                    != self.evidence.current_attempt_sequence
                || !reentry.original_read_identity.load(Ordering::Acquire)
            {
                return Err(Error::Binding);
            }
        } else if self.evidence.request.current_caller_binding_digest
            != read.request.current_caller_binding_digest
            || self.evidence.current_attempt_digest != read.current_attempt_digest
            || self.evidence.current_attempt_sequence != read.current_attempt_sequence
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub(super) fn from_reentry(
        evidence: ManualRosterConstructionContributionEvidenceV3,
        lineage: wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1,
        identity: std::sync::Arc<AtomicBool>,
        maximum_wall_seen: std::sync::Arc<AtomicU64>,
        deadline: Instant,
    ) -> Result<Self> {
        let envelope = crate::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1 {
            version: 1,
            reentry_lineage: lineage,
            construction: evidence,
        };
        envelope.validate()?;
        if !identity.load(Ordering::Acquire) {
            return Err(Error::Conflict);
        }
        let value = Self {
            evidence: envelope.construction,
            reentry: Some(ReenteredConstructionBinding {
                lineage: envelope.reentry_lineage,
                original_read_identity: identity,
            }),
            maximum_wall_seen,
            deadline,
        };
        value.check_completion()?;
        Ok(value)
    }
}
