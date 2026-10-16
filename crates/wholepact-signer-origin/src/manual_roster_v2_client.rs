//! Exact installed-peer roster publication. Public records never create this
//! current owner; only the existing independently pinned channel can do so.
use super::*;
use crate::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, HostManualRosterPublicationRequestV2,
    ManualRosterEnrollmentEvidenceV2,
};

impl NativeManualClient {
    pub fn submit_roster_enrollment_intent_v2_before(
        &self,
        intent: &HostManualRosterEnrollmentIntentV2,
        deadline: Instant,
    ) -> Result<()> {
        intent.validate()?;
        self.scope.validate()?;
        let original = &intent.account_intent;
        if self.scope.agreement_id != original.scope.agreement_id
            || self.scope.participant_id != original.scope.participant_id
            || self.scope.manifest_digest != intent.digest()?
            || self.scope.history_read
            || self.scope.authorization_export
            || self.scope.preconstruction_export
        {
            return Err(Error::Binding);
        }
        let deadline = deadline.min(self.grant.expires);
        remaining_before(deadline)?;
        let stream = self.open_request_before(
            serde_json::json!({
                "operation":"request_born_manual_roster_enrollment_intent_v2", "request":intent
            }),
            deadline,
        )?;
        let bytes = framing::read_frame_with_deadline(
            &stream,
            &self.peer,
            remaining_before(deadline)?.min(MAX_CURRENT_WAIT),
        )?;
        if bytes.len() > MAX_MANUAL_FRAME {
            return Err(Error::Limit);
        }
        require_request_only_ack(&bytes)?;
        remaining_before(deadline)?;
        self.check_channel()
    }

    /// Queues one full V2 request under fresh exact native pairing. The pending
    /// stream is not publication authority and cannot be recovered from a file.
    pub fn begin_roster_enrollment_v2_before(
        &self,
        request: &HostManualRosterPublicationRequestV2,
        deadline: Instant,
    ) -> Result<PendingManualRosterEnrollmentV2<'_>> {
        request.validate()?;
        self.require_scope(&request.enrollment.terms)?;
        require_roster_pair_scope(&self.scope, request)?;
        let deadline = deadline.min(self.grant.expires);
        remaining_before(deadline)?;
        let attempt = PendingRosterV2Attempt::new(&self.handoff, self.acquire_slot()?);
        // Guard is already armed if connect/write fails after partial delivery.
        let stream = self.open_request_before(
            serde_json::json!({
                "operation":"request_born_manual_roster_enrollment_v2", "request":request,
            }),
            deadline,
        )?;
        Ok(PendingManualRosterEnrollmentV2 {
            client: self,
            request: request.clone(),
            pending: PendingRosterV2Stream(Some(stream)),
            attempt,
            deadline,
        })
    }
}
fn require_roster_pair_scope(
    scope: &PairScope,
    request: &HostManualRosterPublicationRequestV2,
) -> Result<()> {
    request.validate()?;
    scope.validate()?;
    let terms = &request.enrollment.terms;
    if scope.account_id != terms.identity.account_id
        || scope.agreement_id != terms.scope.agreement_id
        || scope.participant_id != terms.scope.participant_id
        || scope.manifest_digest != request.digest()?
        || scope.history_read
        || scope.authorization_export
        || scope.preconstruction_export
    {
        return Err(Error::Binding);
    }
    Ok(())
}

pub struct PendingManualRosterEnrollmentV2<'client> {
    client: &'client NativeManualClient,
    request: HostManualRosterPublicationRequestV2,
    pending: PendingRosterV2Stream,
    attempt: PendingRosterV2Attempt<'client>,
    deadline: Instant,
}
impl<'client> PendingManualRosterEnrollmentV2<'client> {
    pub fn finish(mut self) -> Result<ManualRosterEnrollmentLeaseV2<'client>> {
        let response = read_response(
            self.pending.stream()?,
            &self.client.peer,
            remaining_before(self.deadline)?.min(Duration::from_secs(120)),
        )?;
        let ManualAdmissionResponse::RosterEnrollmentHeldV2 { lease_id, evidence } = response
        else {
            return Err(Error::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if evidence.request != self.request {
            return Err(Error::Binding);
        }
        self.client.check_channel()?;
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let lifetime = original_deadline_budget(
            evidence.admission.admitted_at_ms,
            evidence.admission.admission_deadline_ms,
            observed_at_ms,
        )?
        .min(remaining_before(self.deadline)?);
        let original_deadline = Some((observed_at_ms, evidence.admission.admission_deadline_ms));
        let lease = ManualRosterEnrollmentLeaseV2 {
            held: HeldLease {
                client: self.client,
                stream: Mutex::new(self.pending.take()?),
                lease_id,
                evidence_digest: evidence.digest()?,
                started: observed,
                lifetime,
                original_deadline,
                failed: AtomicBool::new(false),
                completion: CompletionState::Pending,
                // Last field: no fallible initialization follows the transfer.
                _slot: self.attempt.transfer_to_held()?,
            },
            evidence: *evidence,
        };
        lease.check_current()?;
        remaining_before(self.deadline)?;
        Ok(lease)
    }
}

/// Audit publication only. No Clone, deserialize, public constructor, V1
/// conversion, scope widening, key use or financial action is exposed.
pub struct ManualRosterEnrollmentLeaseV2<'client> {
    held: HeldLease<'client>,
    evidence: ManualRosterEnrollmentEvidenceV2,
}
impl ManualRosterEnrollmentLeaseV2<'_> {
    /// Finish this exact purpose and await the native producer's bounded ack.
    /// Failure poisons the current client for any later request or re-pairing.
    /// Durable external effects remain retained even if acknowledgment fails.
    pub fn finish(self) -> Result<()> {
        self.held.finish()
    }

    pub fn binding(&self) -> &HostManualRosterPublicationRequestV2 {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &ManualRosterEnrollmentEvidenceV2 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.held.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        self.held.check_current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual_roster_v2::ManualRosterPublicationAttemptV2;
    use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};
    fn request() -> HostManualRosterPublicationRequestV2 {
        let original = crate::manual_continuation_v2::tests::request().enrollment;
        let roster = HostRosterAppendBindingV2 {
            version: 2,
            generation_id: original.terms.host.generation_id.clone(),
            store_destination_identity: original.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: "a".repeat(64),
            },
        };
        HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: original,
            roster,
            attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
        }
    }
    fn scope(request: &HostManualRosterPublicationRequestV2) -> PairScope {
        PairScope {
            account_id: request.enrollment.terms.identity.account_id.clone(),
            agreement_id: request.enrollment.terms.scope.agreement_id.clone(),
            participant_id: request.enrollment.terms.scope.participant_id.clone(),
            manifest_digest: request.digest().unwrap(),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        }
    }
    #[test]
    fn roster_pair_requires_full_request_and_no_other_disclosure_purpose() {
        // Pure correlation only. No native/client/held lease is manufactured.
        let request = request();
        let scope = scope(&request);
        require_roster_pair_scope(&scope, &request).unwrap();
        for field in 0..7 {
            let mut wrong = scope.clone();
            match field {
                0 => wrong.account_id = "other".into(),
                1 => wrong.agreement_id = "other".into(),
                2 => wrong.participant_id = "other".into(),
                3 => wrong.manifest_digest = request.enrollment.digest().unwrap(),
                4 => wrong.history_read = true,
                5 => wrong.authorization_export = true,
                _ => wrong.preconstruction_export = true,
            }
            assert!(require_roster_pair_scope(&wrong, &request).is_err());
        }
    }
    #[test]
    fn changed_predecessor_or_attempt_cannot_reuse_pairing_commitment() {
        let original = request();
        let scope = scope(&original);
        let mut changed = original.clone();
        changed.roster.predecessor = HostRosterPredecessorV2::InitialPublicationV2 {
            audit_digest: "b".repeat(64),
        };
        changed.validate().unwrap();
        assert!(require_roster_pair_scope(&scope, &changed).is_err());
        changed = original;
        changed.attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: "c".repeat(64),
            attempt_sequence: 2,
        };
        changed.validate().unwrap();
        assert!(require_roster_pair_scope(&scope, &changed).is_err());
    }
    #[test]
    fn roster_publication_uses_existing_nonrenewable_remaining_budget() {
        assert_eq!(
            original_deadline_budget(1000, 2000, 1999).unwrap(),
            Duration::from_millis(1)
        );
        assert!(original_deadline_budget(1000, 2000, 2000).is_err());
        assert!(original_deadline_budget(1000, 2000, 999).is_err());
    }
}
