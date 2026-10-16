//! Genuine same-installed-peer additional-read admission. No public constructor
//! from a request, callback, saved receipt, response JSON or audit evidence.
use super::roster_candidate_selection_v2::require_completion_at;
use super::*;
use crate::roster_common_context_read_v1::{
    MAX_COMMON_CONTEXT_READ_FRAME, RosterCommonContextReadEvidenceV1,
    RosterCommonContextReadResponseV1,
};
use std::sync::atomic::AtomicU64;
use wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1;

impl NativeManualClient {
    /// New privacy decision on the freshly paired exact-full-plan source, before
    /// financial Reserve/Consume. Captures the actual original retained owner.
    pub fn begin_roster_common_context_read_before<'a>(
        &'a self,
        request: &RosterCommonContextReadRequestV1,
        retained: RetainedManualRosterContributionV2,
        expected_current_attempt_digest: &str,
        expected_current_attempt_sequence: u64,
        deadline: Instant,
        original_host_deadline: Instant,
    ) -> Result<PendingRosterCommonContextReadV1<'a>> {
        retained.check_retained()?;
        request.validate().map_err(|_| Error::Binding)?;
        hash(expected_current_attempt_digest)?;
        self.require_scope(request.plan.enrollment())?;
        if retained.request()? != &request.plan.retained
            || retained.evidence().digest()? != request.plan.retained_evidence_digest
            || retained.durable_receipt_digest() != request.original_durable_receipt_digest
            || retained.provider_enrollment_reference()
                != self.provider.native_enrollment_reference()
            || self.scope.manifest_digest != request.plan.digest().map_err(|_| Error::Binding)?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
            || request.current_caller_binding_digest != self.current_caller_binding_digest()?
            || expected_current_attempt_sequence
                <= request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .attempt_sequence
            || expected_current_attempt_digest
                == request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .continuation_digest
        {
            return Err(Error::Binding);
        }
        let observed_at_ms = now_ms()?;
        let started = Instant::now();
        let fresh_deadline = started
            .checked_add(Duration::from_millis(
                request
                    .completion_expires_at_ms
                    .checked_sub(observed_at_ms)
                    .filter(|v| *v > 0)
                    .ok_or(Error::Permission)?,
            ))
            .ok_or(Error::Permission)?;
        let admission_deadline = deadline.min(self.grant.expires).min(
            started
                .checked_add(Duration::from_millis(
                    request
                        .remaining_admission_ms(observed_at_ms)
                        .map_err(|_| Error::Permission)?,
                ))
                .ok_or(Error::Permission)?,
        );
        remaining_before(admission_deadline)?;
        self.handoff.check()?;
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        // Permanent attempt claim precedes the first connect/write effect. A lost
        // response, cancelled pending request or failure never resets it.
        let (original_deadline, maximum_wall_seen) = retained.claim_exact_observation_attempt()?;
        let completion_deadline = original_deadline
            .min(original_host_deadline)
            .min(self.grant.expires)
            .min(fresh_deadline);
        remaining_before(completion_deadline)?;
        let stream = self.open_request_before_bounded(
            serde_json::json!({"operation":"request_born_roster_common_context_read_v1","request":request}),
            admission_deadline.min(completion_deadline), MAX_COMMON_CONTEXT_READ_FRAME,
        )?;
        Ok(PendingRosterCommonContextReadV1 {
            client: self,
            retained,
            request: request.clone(),
            expected_current_attempt_digest: expected_current_attempt_digest.into(),
            expected_current_attempt_sequence,
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline: admission_deadline.min(completion_deadline),
            observed_at_ms,
            completion_deadline,
            maximum_wall_seen,
        })
    }
}

pub struct PendingRosterCommonContextReadV1<'client> {
    client: &'client NativeManualClient,
    retained: RetainedManualRosterContributionV2,
    request: RosterCommonContextReadRequestV1,
    expected_current_attempt_digest: String,
    expected_current_attempt_sequence: u64,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
    observed_at_ms: u64,
    completion_deadline: Instant,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
}
impl PendingRosterCommonContextReadV1<'_> {
    pub fn finish(mut self) -> Result<AdmittedRosterCommonContextReadV1> {
        self.retained.check_retained()?;
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
        if bytes.len() > MAX_COMMON_CONTEXT_READ_FRAME {
            return Err(Error::Limit);
        }
        let response: RosterCommonContextReadResponseV1 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let RosterCommonContextReadResponseV1::CommonContextReadAdmittedV1 { evidence } = response
        else {
            return Err(Error::Permission);
        };
        evidence.validate()?;
        if evidence.request != self.request
            || evidence.retained_signer_intent_digest
                != self.retained.evidence().retained_signer_intent_digest
            || evidence.current_attempt_digest != self.expected_current_attempt_digest
            || evidence.current_attempt_sequence != self.expected_current_attempt_sequence
        {
            return Err(Error::Binding);
        }
        self.retained.check_retained()?;
        let wall = now_ms()?;
        phase_budget(
            self.deadline,
            Instant::now(),
            Some((self.observed_at_ms, self.request.admission_expires_at_ms)),
            wall,
        )?;
        if wall < evidence.admitted_at_ms {
            return Err(Error::Permission);
        }
        let session_deadline = Instant::now()
            .checked_add(Duration::from_millis(
                evidence
                    .writer_session_expires_at_ms
                    .checked_sub(wall)
                    .filter(|v| *v > 0)
                    .ok_or(Error::Permission)?,
            ))
            .ok_or(Error::Permission)?;
        let owner = AdmittedRosterCommonContextReadV1 {
            evidence: *evidence,
            retained: self.retained,
            construction_attempted: std::sync::Arc::new(AtomicBool::new(false)),
            handoff_authorization_attempted: AtomicBool::new(false),
            original_signer_peer: self.client.peer.clone(),
            maximum_wall_seen: self.maximum_wall_seen.clone(),
            // Never recalculate the original deadline after review or transport.
            deadline: self.completion_deadline.min(session_deadline),
        };
        owner.check_completion()?;
        drop(self.attempt.slot.take().ok_or(Error::Permission)?);
        Ok(owner)
    }
}

/// One admitted additional privacy read, never financial permission. There is no
/// Clone/Deserialize or restoring constructor. An opaque original owner plus
/// actual expected-peer response is required; evidence remains inert.
/// ```compile_fail
/// # use wholepact_signer_origin::AdmittedRosterCommonContextReadV1;
/// let _: AdmittedRosterCommonContextReadV1 = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// # use wholepact_signer_origin::AdmittedRosterCommonContextReadV1;
/// fn duplicate(v: &AdmittedRosterCommonContextReadV1) -> AdmittedRosterCommonContextReadV1 { v.clone() }
/// ```
pub struct AdmittedRosterCommonContextReadV1 {
    retained: RetainedManualRosterContributionV2,
    construction_attempted: std::sync::Arc<AtomicBool>,
    handoff_authorization_attempted: AtomicBool,
    original_signer_peer: PeerProcess,
    evidence: RosterCommonContextReadEvidenceV1,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
    deadline: Instant,
}
impl AdmittedRosterCommonContextReadV1 {
    pub fn check_completion(&self) -> Result<()> {
        self.retained.check_retained()?;
        require_completion_at(
            self.deadline,
            &self.maximum_wall_seen,
            self.evidence.request.completion_expires_at_ms,
            now_ms()?,
            Instant::now(),
        )
    }
    pub fn request(&self) -> Result<&RosterCommonContextReadRequestV1> {
        self.check_completion()?;
        Ok(&self.evidence.request)
    }
    pub fn evidence(&self) -> &RosterCommonContextReadEvidenceV1 {
        &self.evidence
    }
    pub fn completion_deadline(&self) -> Instant {
        self.deadline
    }
    /// Call before ANY provider/read effect. Ownership is irreversibly moved,
    /// even on error; neither timeout nor failed scan can obtain another start.
    pub fn into_started(self) -> Result<StartedRosterCommonContextReadV1> {
        self.check_completion()?;
        Ok(StartedRosterCommonContextReadV1 { admitted: self })
    }
}
/// Restricted completion conjunction retained by the concrete wallet observer.
/// No method converts this owner back to an unstarted grant.
/// ```compile_fail
/// # use wholepact_signer_origin::StartedRosterCommonContextReadV1;
/// let _: StartedRosterCommonContextReadV1 = serde_json::from_str("{}").unwrap();
/// ```
pub struct StartedRosterCommonContextReadV1 {
    admitted: AdmittedRosterCommonContextReadV1,
}
impl StartedRosterCommonContextReadV1 {
    pub fn check_completion(&self) -> Result<()> {
        self.admitted.check_completion()
    }
    pub fn request(&self) -> Result<&RosterCommonContextReadRequestV1> {
        self.admitted.request()
    }
    pub fn evidence(&self) -> &RosterCommonContextReadEvidenceV1 {
        self.admitted.evidence()
    }
    pub fn completion_deadline(&self) -> Instant {
        self.admitted.completion_deadline()
    }
}

impl StartedRosterCommonContextReadV1 {
    // A claim is not authority. Only the authenticated exact native terminal
    // response can issue the separate non-signing completion contribution.
    pub(super) fn claim_construction_attempt(
        &self,
        request: &wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3,
    ) -> Result<(Instant, std::sync::Arc<AtomicU64>)> {
        self.check_completion()?;
        if request.plan != self.admitted.evidence.request.plan
            || request.current_caller_binding_digest
                != self.admitted.evidence.request.current_caller_binding_digest
            || request.operation_id == self.admitted.evidence.request.operation_id
        {
            return Err(Error::Binding);
        }
        if self
            .admitted
            .construction_attempted
            .swap(true, Ordering::AcqRel)
        {
            return Err(Error::Conflict);
        }
        Ok((
            self.admitted.deadline,
            self.admitted.maximum_wall_seen.clone(),
        ))
    }
}

/// Private movable identity for the actual admitted read. Clones are internal
/// borrows of the original gate and clock, never another read or construction
/// grant. Pointer equality remains stable when the wallet moves its owner.
pub(super) struct CommonContextCompletionBinding {
    pub(super) identity: std::sync::Arc<AtomicBool>,
    pub(super) maximum_wall_seen: std::sync::Arc<AtomicU64>,
    pub(super) deadline: Instant,
    pub(super) original_signer_peer: PeerProcess,
}
impl StartedRosterCommonContextReadV1 {
    pub(super) fn reentry_completion_binding(&self) -> Result<CommonContextCompletionBinding> {
        self.check_completion()?;
        Ok(CommonContextCompletionBinding {
            identity: self.admitted.construction_attempted.clone(),
            maximum_wall_seen: self.admitted.maximum_wall_seen.clone(),
            deadline: self.admitted.deadline,
            original_signer_peer: self.admitted.original_signer_peer.clone(),
        })
    }
    pub(super) fn matches_reentry_identity(
        &self,
        identity: &std::sync::Arc<AtomicBool>,
    ) -> Result<()> {
        self.check_completion()?;
        if !std::sync::Arc::ptr_eq(identity, &self.admitted.construction_attempted) {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

impl AdmittedRosterCommonContextReadV1 {
    pub(super) fn claim_handoff_authorization(&self) -> Result<CommonContextCompletionBinding> {
        self.check_completion()?;
        if self.handoff_authorization_attempted.swap(true, Ordering::AcqRel) {
            return Err(Error::Conflict);
        }
        Ok(CommonContextCompletionBinding {
            identity: self.construction_attempted.clone(),
            maximum_wall_seen: self.maximum_wall_seen.clone(),
            deadline: self.deadline,
            original_signer_peer: self.original_signer_peer.clone(),
        })
    }
}
