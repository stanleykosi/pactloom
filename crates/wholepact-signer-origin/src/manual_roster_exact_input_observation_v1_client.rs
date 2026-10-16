//! Genuine same-installed-peer additional-read admission. No public constructor
//! from a request, callback, saved receipt, response JSON or audit evidence.
use super::roster_candidate_selection_v2::require_completion_at;
use super::*;
use crate::manual_roster_exact_input_observation_v1::{
    MAX_EXACT_INPUT_OBSERVATION_FRAME, ManualRosterExactInputObservationEvidenceV1,
    ManualRosterExactInputObservationResponseV1,
};
use std::sync::atomic::AtomicU64;
use wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1;

impl NativeManualClient {
    /// New privacy decision on the freshly paired exact-full-plan source, before
    /// financial Reserve/Consume. Captures the actual original retained owner.
    pub fn begin_roster_exact_input_observation_before<'a>(
        &'a self,
        request: &ManualRosterExactInputObservationRequestV1,
        retained: &'a RetainedManualRosterContributionV2,
        expected_current_attempt_digest: &str,
        expected_current_attempt_sequence: u64,
        deadline: Instant,
        original_host_deadline: Instant,
    ) -> Result<PendingRosterExactInputObservationV1<'a>> {
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
            .min(fresh_deadline);
        remaining_before(completion_deadline)?;
        let stream = self.open_request_before_bounded(
            serde_json::json!({"operation":"request_born_roster_exact_input_observation_v1","request":request}),
            admission_deadline.min(completion_deadline), MAX_EXACT_INPUT_OBSERVATION_FRAME,
        )?;
        Ok(PendingRosterExactInputObservationV1 {
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

pub struct PendingRosterExactInputObservationV1<'client> {
    client: &'client NativeManualClient,
    retained: &'client RetainedManualRosterContributionV2,
    request: ManualRosterExactInputObservationRequestV1,
    expected_current_attempt_digest: String,
    expected_current_attempt_sequence: u64,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
    observed_at_ms: u64,
    completion_deadline: Instant,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
}
impl PendingRosterExactInputObservationV1<'_> {
    pub fn finish(mut self) -> Result<AdmittedRosterExactInputObservationV1> {
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
        if bytes.len() > MAX_EXACT_INPUT_OBSERVATION_FRAME {
            return Err(Error::Limit);
        }
        let response: ManualRosterExactInputObservationResponseV1 =
            serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        let ManualRosterExactInputObservationResponseV1::ExactInputObservationAdmittedV1 {
            evidence,
        } = response
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
        let owner = AdmittedRosterExactInputObservationV1 {
            evidence: *evidence,
            maximum_wall_seen: self.maximum_wall_seen.clone(),
            // Never recalculate the original deadline after review or transport.
            deadline: self.completion_deadline,
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
/// # use wholepact_signer_origin::AdmittedRosterExactInputObservationV1;
/// let _: AdmittedRosterExactInputObservationV1 = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// # use wholepact_signer_origin::AdmittedRosterExactInputObservationV1;
/// fn duplicate(v: &AdmittedRosterExactInputObservationV1) -> AdmittedRosterExactInputObservationV1 { v.clone() }
/// ```
pub struct AdmittedRosterExactInputObservationV1 {
    evidence: ManualRosterExactInputObservationEvidenceV1,
    maximum_wall_seen: std::sync::Arc<AtomicU64>,
    deadline: Instant,
}
impl AdmittedRosterExactInputObservationV1 {
    pub fn check_completion(&self) -> Result<()> {
        require_completion_at(
            self.deadline,
            &self.maximum_wall_seen,
            self.evidence.request.completion_expires_at_ms,
            now_ms()?,
            Instant::now(),
        )
    }
    pub fn request(&self) -> Result<&ManualRosterExactInputObservationRequestV1> {
        self.check_completion()?;
        Ok(&self.evidence.request)
    }
    pub fn evidence(&self) -> &ManualRosterExactInputObservationEvidenceV1 {
        &self.evidence
    }
    pub fn completion_deadline(&self) -> Instant {
        self.deadline
    }
    /// Call before ANY provider/read effect. Ownership is irreversibly moved,
    /// even on error; neither timeout nor failed scan can obtain another start.
    pub fn into_started(self) -> Result<StartedRosterExactInputObservationV1> {
        self.check_completion()?;
        Ok(StartedRosterExactInputObservationV1 { admitted: self })
    }
}
/// Restricted completion conjunction retained by the concrete wallet observer.
/// No method converts this owner back to an unstarted grant.
/// ```compile_fail
/// # use wholepact_signer_origin::StartedRosterExactInputObservationV1;
/// let _: StartedRosterExactInputObservationV1 = serde_json::from_str("{}").unwrap();
/// ```
pub struct StartedRosterExactInputObservationV1 {
    admitted: AdmittedRosterExactInputObservationV1,
}
impl StartedRosterExactInputObservationV1 {
    pub fn check_completion(&self) -> Result<()> {
        self.admitted.check_completion()
    }
    pub fn request(&self) -> Result<&ManualRosterExactInputObservationRequestV1> {
        self.admitted.request()
    }
    pub fn evidence(&self) -> &ManualRosterExactInputObservationEvidenceV1 {
        self.admitted.evidence()
    }
    pub fn completion_deadline(&self) -> Instant {
        self.admitted.completion_deadline()
    }
}
