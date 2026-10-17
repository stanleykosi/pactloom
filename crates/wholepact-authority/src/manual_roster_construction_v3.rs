//! Purpose-distinct roster construction evidence. Parsing any record is audit
//! only; neither a record nor a consumed contribution authorizes signing,
//! proving, dispatch, replacement, account recovery or clearing exposure.
use crate::{
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2, *,
};
use serde::{Deserialize, Serialize};
use wholepact_core::{
    manual_construction::ManualConstructionInput,
    manual_enrollment::BornManualEnrollmentTerms,
    manual_roster_construction_v3::{
        ManualRosterConstructionPlanV3, ManualRosterConstructionRequestV3,
    },
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionOwnerSignatureV3 {
    pub version: u16,
    pub extension: ManualRosterEnrollmentExtensionV2,
    pub approval: ManualRosterConstructionApprovalV3,
    /// Only maintained P-256 SHA-256 ASN.1 is supported by this initial adapter.
    /// Unknown schemes fail closed; this is independent of existing TLS choices.
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Stable, independently owner-reviewed final plan. New caller/session bindings
/// are deliberately absent; no initial enrollment or continuation is reinterpreted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionApprovalV3 {
    pub version: u16,
    pub extension_digest: String,
    pub plan: ManualRosterConstructionPlanV3,
    pub issued_at_ms: u64,
    pub initial_commit_deadline_ms: u64,
}
impl ManualRosterConstructionApprovalV3 {
    pub fn validate_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<()> {
        // Reject oversized untrusted input before recursive original-plan or
        // signature validation. The native envelope retains this approval twice.
        if serde_json::to_vec(self)
            .map_err(|_| AuthorityError::InvalidBinding)?
            .len()
            > MAX_FRAME_BYTES / 2 - 16 * 1024
        {
            return Err(AuthorityError::Limit);
        }
        validate_plan_original(&self.plan, e)?;
        let invocation = &self.plan.retained.selection.scope.selection.invocation;
        if self.version != 3
            || self.extension_digest != e.digest()?
            || self
                .plan
                .originals
                .iter()
                .any(|o| self.issued_at_ms < o.request.requested_at_ms)
            || self.issued_at_ms < self.plan.retained.requested_at_ms
            || self.issued_at_ms < invocation.requested_at_ms
            || self.initial_commit_deadline_ms <= self.issued_at_ms
            || self.initial_commit_deadline_ms - self.issued_at_ms > 120_000
            || self.initial_commit_deadline_ms > self.plan.completion_deadline_ms()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        self.validate_for(e)?;
        digest("wholepact:manual-roster-construction-approval:v3", self)
    }
    pub(crate) fn owner_operation_id(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<String> {
        Ok(format!(
            "roster-construct-approve-v3-{}",
            self.digest_for(e)?
        ))
    }
    pub fn matches_request(
        &self,
        r: &ManualRosterConstructionRequestV3,
        e: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<()> {
        self.validate_for(e)?;
        r.validate().map_err(|_| AuthorityError::InvalidBinding)?;
        if r.plan != self.plan {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionApprovalRecordV3 {
    pub approval: ManualRosterConstructionApprovalV3,
    pub owner_signature_evidence_digest: String,
    pub owner_signature: Box<ManualRosterConstructionOwnerSignatureV3>,
    pub native_review_digest: String,
}
impl ManualRosterConstructionApprovalRecordV3 {
    pub(crate) fn validate_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<()> {
        self.approval.validate_for(e)?;
        hash(&self.owner_signature_evidence_digest)?;
        let signature = &self.owner_signature;
        if signature.version != 3
            || signature.extension != *e
            || signature.approval != self.approval
            || signature.scheme != "ecdsa-p256-sha256-asn1-v1"
            || signature.owner_certificate_der.is_empty()
            || signature.owner_certificate_der.len() > 16 * 1024
            || signature.signature.is_empty()
            || signature.signature.len() > 80
            || digest(
                "wholepact:manual-roster-construction-owner-signature:v3",
                signature,
            )? != self.owner_signature_evidence_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if !cfg!(feature = "pending-birth-foundation") {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        // The native publisher checks the actual pinned signature. Replay with
        // this feature also independently verifies the retained cryptographic evidence.
        #[cfg(feature = "pending-birth-foundation")]
        crate::manual_roster_construction_signature_v3::verify_manual_roster_construction_owner_signature_v3(
            signature, &e.account_extension.terms.signer.owner_certificate_digest)?;
        hash(&self.native_review_digest)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionReservationRequestV3 {
    pub version: u16,
    pub construction: ManualRosterConstructionRequestV3,
    /// Current real V2 attempt, distinct from the retained original selection.
    pub attempt_digest: String,
    pub attempt_sequence: u64,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub session_id: String,
    pub signer_intent_digest: String,
    pub native_review_digest: String,
    pub reviewed_at_ms: u64,
}
impl ManualRosterConstructionReservationRequestV3 {
    pub fn enrollment(&self) -> &BornManualEnrollmentTerms {
        &self
            .construction
            .plan
            .retained
            .selection
            .scope
            .selection
            .inventory
            .enrollment
    }
    pub fn selected_inputs(&self) -> &[ManualConstructionInput] {
        &self.construction.plan.retained.selected_inputs
    }
    pub fn completion_deadline_ms(&self) -> u64 {
        self.construction.plan.completion_deadline_ms()
    }
    pub fn invocation_digest(&self) -> Result<String> {
        self.construction
            .plan
            .retained
            .selection
            .scope
            .selection
            .invocation
            .digest()
            .map_err(|_| AuthorityError::InvalidBinding)
    }
    pub fn maximum_net_debit_zatoshis(&self) -> Result<u64> {
        let p = self
            .construction
            .validate()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        self.maximum_net_debit_from_proposal(&p)
    }
    // Pure join used only with this request's freshly validated Proposal.
    fn maximum_net_debit_from_proposal(
        &self,
        p: &wholepact_core::proposal::Proposal,
    ) -> Result<u64> {
        let e = self.enrollment();
        p.manifest()
            .participants
            .iter()
            .find(|p| {
                p.account_id == e.identity.account_id && p.participant_id == e.scope.participant_id
            })
            .map(|p| p.maximum_net_debit.as_zatoshis())
            .ok_or(AuthorityError::InvalidBinding)
    }
    pub fn input_value_zatoshis(&self) -> Result<u64> {
        self.selected_inputs().iter().try_fold(0u64, |n, i| {
            n.checked_add(i.value_zatoshis)
                .filter(|v| *v <= MAX_MONEY)
                .ok_or(AuthorityError::Limit)
        })
    }
    pub fn validate_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<()> {
        self.validate_with_proposal(e, c).map(|_| ())
    }
    // The private result borrows this exact immutable request and owns only the
    // Proposal returned by its complete validation. It cannot outlive the call
    // as a permission, replace a current check, or refer to another request.
    fn validate_with_proposal(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<ValidatedReservationRequest<'_>> {
        let proposal = self
            .construction
            .validate()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        e.validate()?;
        // construction.validate above already validated this exact plan.
        validate_plan_original_bindings(&self.construction.plan, e)?;
        c.validate_for(e)?;
        for h in [
            &self.expected_head.digest,
            &self.session_id,
            &self.signer_intent_digest,
            &self.native_review_digest,
            &self.attempt_digest,
        ] {
            hash(h)?;
        }
        if self.version != 3
            || self.attempt_digest != c.digest_for(e)?
            || self.attempt_sequence != c.sequence()
            || self.attempt_sequence
                <= self
                    .construction
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .attempt_sequence
            || self.attempt_digest
                == self
                    .construction
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .continuation_digest
            || self.writer_epoch != e.account_extension.terms.signer.writer_epoch
            || self.reviewed_at_ms < self.construction.requested_at_ms
            || self.reviewed_at_ms < c.inner().issued_at_ms
            || self.reviewed_at_ms >= self.construction.admission_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        id(&self.construction.operation_id)?;
        Ok(ValidatedReservationRequest {
            request: self,
            proposal,
        })
    }
    pub fn digest_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<String> {
        self.validate_for(e, c)?;
        digest(
            "wholepact:manual-roster-construction-reservation-request:v3",
            self,
        )
    }
}
// Call-local pure validation evidence only. No public constructor, Clone,
// deserialization, native owner, clock, source-file or journal authority.
struct ValidatedReservationRequest<'a> {
    request: &'a ManualRosterConstructionReservationRequestV3,
    proposal: wholepact_core::proposal::Proposal,
}
impl ValidatedReservationRequest<'_> {
    fn maximum_net_debit_zatoshis(&self) -> Result<u64> {
        self.request.maximum_net_debit_from_proposal(&self.proposal)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionReservationRecordV3 {
    pub request: ManualRosterConstructionReservationRequestV3,
    pub snapshot: AccountSnapshot,
    pub session: WriterSessionReceipt,
    pub admitted_at_ms: u64,
    pub construction_expires_at_ms: u64,
    pub reserved_debit_zatoshis: u64,
    pub reserved_input_value_zatoshis: u64,
}
impl ManualRosterConstructionReservationRecordV3 {
    pub fn validate_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<()> {
        let validated = self.request.validate_with_proposal(e, c)?;
        let t = &e.account_extension.terms;
        validate_snapshot(
            &self.snapshot,
            &self.session,
            e,
            &self.request.expected_head,
            self.admitted_at_ms,
            &self.request.session_id,
        )?;
        if self.admitted_at_ms < self.request.reviewed_at_ms
            || self.admitted_at_ms >= self.request.construction.admission_expires_at_ms
            || self.admitted_at_ms >= self.session.expires_at_ms
            || self.construction_expires_at_ms != self.request.completion_deadline_ms()
            || self.reserved_debit_zatoshis != validated.maximum_net_debit_zatoshis()?
            || self.reserved_input_value_zatoshis != self.request.input_value_zatoshis()?
            || self.snapshot.outstanding_debit_zatoshis < self.reserved_debit_zatoshis
            || self.snapshot.reserved_input_value_zatoshis < self.reserved_input_value_zatoshis
            || self.snapshot.aggregate_budget_zatoshis < self.snapshot.outstanding_debit_zatoshis
            || self
                .snapshot
                .outstanding_debit_zatoshis
                .checked_add(self.snapshot.settled_debit_zatoshis)
                .is_none_or(|n| {
                    n > t.scope.aggregate_budget_zatoshis
                        || n > self.snapshot.aggregate_budget_zatoshis
                })
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<String> {
        self.validate_for(e, c)?;
        self.encoded_digest()
    }
    // Sole nonvalidating caller is ConsumeRequest::validate_for, immediately
    // after it fully validates this same borrowed reservation against e and c.
    fn encoded_digest(&self) -> Result<String> {
        digest("wholepact:manual-roster-construction-reservation:v3", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionConsumeRequestV3 {
    pub version: u16,
    pub operation_id: String,
    pub reservation_operation_id: String,
    pub reservation_digest: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub session_id: String,
    pub common_invocation_digest: String,
    pub current_caller_binding_digest: String,
}
impl ManualRosterConstructionConsumeRequestV3 {
    pub fn validate_for(
        &self,
        r: &ManualRosterConstructionReservationRecordV3,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<()> {
        r.validate_for(e, c)?;
        let t = &e.account_extension.terms;
        if self.version != 3 {
            return Err(AuthorityError::InvalidBinding);
        }
        // r is immutable and has just passed its complete public validator.
        // Reuse its exact canonical digest for both original relational joins.
        let reservation_digest = r.encoded_digest()?;
        if self.operation_id != consume_operation_id_from_digest(&reservation_digest)
            || self.reservation_operation_id != r.request.construction.operation_id
            || self.reservation_digest != reservation_digest
            || self.account_id != t.identity.account_id
            || self.network_profile_id != t.identity.network_profile_id
            || self.writer_epoch != r.request.writer_epoch
            || self.session_id != r.session.session_id
            || self.expected_head != r.snapshot.head
            || self.common_invocation_digest != r.request.invocation_digest()?
            || self.current_caller_binding_digest
                != r.request.construction.current_caller_binding_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
pub fn construction_consume_operation_id_v3(
    r: &ManualRosterConstructionReservationRecordV3,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<String> {
    Ok(consume_operation_id_from_digest(&r.digest_for(e, c)?))
}
fn consume_operation_id_from_digest(digest: &str) -> String {
    format!("roster-construct-consume-v3-{digest}")
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionConsumedRecordV3 {
    pub request: ManualRosterConstructionConsumeRequestV3,
    pub snapshot: AccountSnapshot,
    pub consumed_at_ms: u64,
    pub construction_expires_at_ms: u64,
}
impl ManualRosterConstructionConsumedRecordV3 {
    pub fn validate_for(
        &self,
        r: &ManualRosterConstructionReservationRecordV3,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<()> {
        self.request.validate_for(r, e, c)?;
        let mut expected = r.snapshot.clone();
        expected.head = self.snapshot.head.clone();
        expected.last_witness_time_ms = self.consumed_at_ms;
        if self.snapshot != expected
            || self.snapshot.head.sequence
                != r.snapshot
                    .head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::Limit)?
            || self.consumed_at_ms < r.admitted_at_ms
            || self.consumed_at_ms >= r.request.construction.admission_expires_at_ms
            || self.consumed_at_ms >= r.session.expires_at_ms
            || self.construction_expires_at_ms != r.construction_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.snapshot.head.digest)
    }
    pub fn digest_for(
        &self,
        r: &ManualRosterConstructionReservationRecordV3,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<String> {
        self.validate_for(r, e, c)?;
        digest("wholepact:manual-roster-construction-consumed:v3", self)
    }
}

pub(crate) fn validate_plan_original(
    p: &ManualRosterConstructionPlanV3,
    e: &ManualRosterEnrollmentExtensionV2,
) -> Result<()> {
    e.validate()?;
    p.validate().map_err(|_| AuthorityError::InvalidBinding)?;
    validate_plan_original_bindings(p, e)
}
// Both callers fully validate the exact borrowed plan and extension first.
// This helper performs all unchanged original-plan/extension relationships.
fn validate_plan_original_bindings(
    p: &ManualRosterConstructionPlanV3,
    e: &ManualRosterEnrollmentExtensionV2,
) -> Result<()> {
    let scope = &p.retained.selection.scope;
    let i = &scope.selection.inventory;
    if i.enrollment != e.account_extension.terms
        || i.enrollment_ref != e.account_extension.enrollment_ref
        || i.witness_extension_digest != e.account_extension.digest()?
        || scope.provenance.witness_roster_extension_digest != e.digest()?
        || scope.provenance.signer_roster_record_digest != e.signer_roster_record_digest
        || scope.provenance.roster != e.roster
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
fn validate_snapshot(
    s: &AccountSnapshot,
    session: &WriterSessionReceipt,
    e: &ManualRosterEnrollmentExtensionV2,
    previous: &AuthorityHead,
    now: u64,
    session_id: &str,
) -> Result<()> {
    let t = &e.account_extension.terms;
    if s.account_id != t.identity.account_id
        || s.network_profile_id != t.identity.network_profile_id
        || s.policy_digest != t.original_policy_digest
        || s.writer_epoch != t.signer.writer_epoch
        || s.writer_certificate_digest != t.signer.writer_certificate_digest
        || s.writer_status != WriterStatus::Active
        || s.active_writer_session.as_ref() != Some(session)
        || session.session_id != session_id
        || session.writer_epoch != s.writer_epoch
        || session.writer_certificate_digest != s.writer_certificate_digest
        || s.last_witness_time_ms != now
        || s.head.sequence
            != previous
                .sequence
                .checked_add(1)
                .ok_or(AuthorityError::Limit)?
    {
        return Err(AuthorityError::InvalidBinding);
    }
    hash(&s.head.digest)
}
fn current(
    observed: &std::time::Instant,
    observed_at_ms: u64,
    admitted: u64,
    deadline: u64,
) -> Result<()> {
    let now = now_ms()?;
    if now < observed_at_ms
        || now < admitted
        || now >= deadline
        || observed.elapsed().as_millis() >= u128::from(deadline.saturating_sub(observed_at_ms))
    {
        return Err(AuthorityError::Expired);
    }
    Ok(())
}
/// A reservation is not construction permission. Only an authenticated one-use
/// Consume moves it into a contribution; uncertain responses cannot recreate it.
pub struct AuthenticatedManualRosterConstructionReservationV3 {
    pub(crate) extension: ManualRosterEnrollmentExtensionV2,
    pub(crate) continuation: ManualRosterSessionContinuationV2,
    pub(crate) record: ManualRosterConstructionReservationRecordV3,
    pub(crate) observed: std::time::Instant,
    pub(crate) observed_at_ms: u64,
}
impl AuthenticatedManualRosterConstructionReservationV3 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
        &self.continuation
    }
    pub fn record(&self) -> &ManualRosterConstructionReservationRecordV3 {
        &self.record
    }
    pub fn check_current(&self) -> Result<()> {
        self.record
            .validate_for(&self.extension, &self.continuation)?;
        current(
            &self.observed,
            self.observed_at_ms,
            self.record.admitted_at_ms,
            self.record
                .request
                .construction
                .admission_expires_at_ms
                .min(self.record.session.expires_at_ms),
        )
    }
}
/// No Clone, Deserialize or public constructor. One consumed non-signing
/// contribution may complete after focus/session handoff, only until its original
/// common deadline. It still needs the concrete Host one-use invocation gate.
pub struct AuthenticatedManualRosterConstructionContributionV3 {
    pub(crate) reservation: AuthenticatedManualRosterConstructionReservationV3,
    pub(crate) consumed: ManualRosterConstructionConsumedRecordV3,
}
impl AuthenticatedManualRosterConstructionContributionV3 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.reservation.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
        &self.reservation.continuation
    }
    pub fn reservation(&self) -> &ManualRosterConstructionReservationRecordV3 {
        &self.reservation.record
    }
    pub fn consumed(&self) -> &ManualRosterConstructionConsumedRecordV3 {
        &self.consumed
    }
    pub fn check_current(&self) -> Result<()> {
        self.consumed.validate_for(
            &self.reservation.record,
            &self.reservation.extension,
            &self.reservation.continuation,
        )?;
        current(
            &self.reservation.observed,
            self.reservation.observed_at_ms,
            self.consumed.consumed_at_ms,
            self.consumed.construction_expires_at_ms,
        )
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterConstructionHistoryRecordV3 {
    Reservation {
        record: Box<ManualRosterConstructionReservationRecordV3>,
    },
    Consumed {
        record: Box<ManualRosterConstructionConsumedRecordV3>,
    },
}
impl ReconciledAuthorityHistory {
    /// Complete audit-only non-signing history, including consumed reservations.
    /// Records never create a live contribution or become financial permits.
    pub fn manual_roster_construction_records_v3(
        &self,
    ) -> impl Iterator<Item = (&str, &ManualRosterConstructionHistoryRecordV3)> {
        self.manual_roster_construction_records_v3
            .iter()
            .map(|(id, record)| (id.as_str(), record))
    }
    pub fn manual_roster_construction_record_v3(
        &self,
        operation_id: &str,
    ) -> Result<Option<&ManualRosterConstructionHistoryRecordV3>> {
        id(operation_id)?;
        Ok(self.manual_roster_construction_records_v3.get(operation_id))
    }
    pub fn manual_roster_construction_approval_v3(
        &self,
        invocation_digest: &str,
    ) -> Result<Option<&ManualRosterConstructionApprovalV3>> {
        hash(invocation_digest)?;
        let mut found = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::ApproveManualRosterConstructionV3 { record } = &r.control {
                if record
                    .approval
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .digest()
                    .map_err(|_| AuthorityError::CorruptHistory)?
                    == invocation_digest
                {
                    if found.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    found = Some(&record.approval);
                }
            }
        }
        Ok(found)
    }
}
impl crate::policy::Ledger {
    pub(crate) fn roster_construction_history_v3(
        &self,
    ) -> std::collections::BTreeMap<String, ManualRosterConstructionHistoryRecordV3> {
        self.operations
            .iter()
            .filter_map(|(id, (_, _, result))| {
                let r = match result {
                    MutationResult::ManualRosterConstructionReservedV3(r) => {
                        ManualRosterConstructionHistoryRecordV3::Reservation { record: r.clone() }
                    }
                    MutationResult::ManualRosterConstructionConsumedV3(r) => {
                        ManualRosterConstructionHistoryRecordV3::Consumed { record: r.clone() }
                    }
                    _ => return None,
                };
                Some((id.clone(), r))
            })
            .collect()
    }
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "manual_roster_construction_v3_tests.rs"]
pub(crate) mod tests;

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "manual_roster_construction_v3_validation_reuse_tests.rs"]
mod validation_reuse_tests;
