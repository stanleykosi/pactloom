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
    manual_roster_construction_v2::{
        ManualRosterConstructionPlanV2, ManualRosterConstructionRequestV2,
    },
};

/// Stable, independently owner-reviewed final plan. New caller/session bindings
/// are deliberately absent; no initial enrollment or continuation is reinterpreted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionApprovalV2 {
    pub version: u16,
    pub extension_digest: String,
    pub plan: ManualRosterConstructionPlanV2,
    pub issued_at_ms: u64,
    pub initial_commit_deadline_ms: u64,
}
impl ManualRosterConstructionApprovalV2 {
    pub fn validate_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<()> {
        validate_plan_original(&self.plan, e)?;
        let invocation = &self.plan.retained.selection.scope.selection.invocation;
        if self.version != 2
            || self.extension_digest != e.digest()?
            || self.issued_at_ms < self.plan.retained.requested_at_ms
            || self.issued_at_ms < invocation.requested_at_ms
            || self.initial_commit_deadline_ms <= self.issued_at_ms
            || self.initial_commit_deadline_ms - self.issued_at_ms > 120_000
            || self.initial_commit_deadline_ms > invocation.construction_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        self.validate_for(e)?;
        digest("wholepact:manual-roster-construction-approval:v2", self)
    }
    pub(crate) fn owner_operation_id(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<String> {
        Ok(format!(
            "roster-construct-approve-v2-{}",
            self.digest_for(e)?
        ))
    }
    pub fn matches_request(
        &self,
        r: &ManualRosterConstructionRequestV2,
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
pub struct ManualRosterConstructionApprovalRecordV2 {
    pub approval: ManualRosterConstructionApprovalV2,
    pub owner_signature_evidence_digest: String,
    pub native_review_digest: String,
}
impl ManualRosterConstructionApprovalRecordV2 {
    pub(crate) fn validate_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<()> {
        self.approval.validate_for(e)?;
        hash(&self.owner_signature_evidence_digest)?;
        hash(&self.native_review_digest)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionReservationRequestV2 {
    pub version: u16,
    pub construction: ManualRosterConstructionRequestV2,
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
impl ManualRosterConstructionReservationRequestV2 {
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
        self.construction
            .plan
            .retained
            .selection
            .scope
            .selection
            .invocation
            .construction_expires_at_ms
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
        self.construction
            .validate()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        validate_plan_original(&self.construction.plan, e)?;
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
        if self.version != 2
            || self.attempt_digest != c.digest_for(e)?
            || self.attempt_sequence != c.sequence()
            || self.writer_epoch != e.account_extension.terms.signer.writer_epoch
            || self.reviewed_at_ms < self.construction.requested_at_ms
            || self.reviewed_at_ms < c.inner().issued_at_ms
            || self.reviewed_at_ms >= self.construction.admission_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        id(&self.construction.operation_id)?;
        Ok(())
    }
    pub fn digest_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<String> {
        self.validate_for(e, c)?;
        digest(
            "wholepact:manual-roster-construction-reservation-request:v2",
            self,
        )
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionReservationRecordV2 {
    pub request: ManualRosterConstructionReservationRequestV2,
    pub snapshot: AccountSnapshot,
    pub session: WriterSessionReceipt,
    pub admitted_at_ms: u64,
    pub construction_expires_at_ms: u64,
    pub reserved_debit_zatoshis: u64,
    pub reserved_input_value_zatoshis: u64,
}
impl ManualRosterConstructionReservationRecordV2 {
    pub fn validate_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<()> {
        self.request.validate_for(e, c)?;
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
            || self.reserved_debit_zatoshis != self.request.maximum_net_debit_zatoshis()?
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
        digest("wholepact:manual-roster-construction-reservation:v2", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionConsumeRequestV2 {
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
impl ManualRosterConstructionConsumeRequestV2 {
    pub fn validate_for(
        &self,
        r: &ManualRosterConstructionReservationRecordV2,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<()> {
        r.validate_for(e, c)?;
        let t = &e.account_extension.terms;
        if self.version != 2
            || self.operation_id != construction_consume_operation_id_v2(r, e, c)?
            || self.reservation_operation_id != r.request.construction.operation_id
            || self.reservation_digest != r.digest_for(e, c)?
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
pub fn construction_consume_operation_id_v2(
    r: &ManualRosterConstructionReservationRecordV2,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<String> {
    Ok(format!(
        "roster-construct-consume-v2-{}",
        r.digest_for(e, c)?
    ))
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionConsumedRecordV2 {
    pub request: ManualRosterConstructionConsumeRequestV2,
    pub snapshot: AccountSnapshot,
    pub consumed_at_ms: u64,
    pub construction_expires_at_ms: u64,
}
impl ManualRosterConstructionConsumedRecordV2 {
    pub fn validate_for(
        &self,
        r: &ManualRosterConstructionReservationRecordV2,
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
        r: &ManualRosterConstructionReservationRecordV2,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
    ) -> Result<String> {
        self.validate_for(r, e, c)?;
        digest("wholepact:manual-roster-construction-consumed:v2", self)
    }
}

pub(crate) fn validate_plan_original(
    p: &ManualRosterConstructionPlanV2,
    e: &ManualRosterEnrollmentExtensionV2,
) -> Result<()> {
    e.validate()?;
    p.validate().map_err(|_| AuthorityError::InvalidBinding)?;
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
pub struct AuthenticatedManualRosterConstructionReservationV2 {
    pub(crate) extension: ManualRosterEnrollmentExtensionV2,
    pub(crate) continuation: ManualRosterSessionContinuationV2,
    pub(crate) record: ManualRosterConstructionReservationRecordV2,
    pub(crate) observed: std::time::Instant,
    pub(crate) observed_at_ms: u64,
}
impl AuthenticatedManualRosterConstructionReservationV2 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
        &self.continuation
    }
    pub fn record(&self) -> &ManualRosterConstructionReservationRecordV2 {
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
pub struct AuthenticatedManualRosterConstructionContributionV2 {
    pub(crate) reservation: AuthenticatedManualRosterConstructionReservationV2,
    pub(crate) consumed: ManualRosterConstructionConsumedRecordV2,
}
impl AuthenticatedManualRosterConstructionContributionV2 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.reservation.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
        &self.reservation.continuation
    }
    pub fn reservation(&self) -> &ManualRosterConstructionReservationRecordV2 {
        &self.reservation.record
    }
    pub fn consumed(&self) -> &ManualRosterConstructionConsumedRecordV2 {
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
pub enum ManualRosterConstructionHistoryRecordV2 {
    Reservation {
        record: Box<ManualRosterConstructionReservationRecordV2>,
    },
    Consumed {
        record: Box<ManualRosterConstructionConsumedRecordV2>,
    },
}
impl ReconciledAuthorityHistory {
    /// Complete audit-only non-signing history, including consumed reservations.
    /// Records never create a live contribution or become financial permits.
    pub fn manual_roster_construction_records_v2(
        &self,
    ) -> impl Iterator<Item = (&str, &ManualRosterConstructionHistoryRecordV2)> {
        self.manual_roster_construction_records
            .iter()
            .map(|(id, record)| (id.as_str(), record))
    }
    pub fn manual_roster_construction_record_v2(
        &self,
        operation_id: &str,
    ) -> Result<Option<&ManualRosterConstructionHistoryRecordV2>> {
        id(operation_id)?;
        Ok(self.manual_roster_construction_records.get(operation_id))
    }
    pub fn manual_roster_construction_approval_v2(
        &self,
        invocation_digest: &str,
    ) -> Result<Option<&ManualRosterConstructionApprovalV2>> {
        hash(invocation_digest)?;
        let mut found = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::ApproveManualRosterConstructionV2 { record } = &r.control {
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
    pub(crate) fn roster_construction_history_v2(
        &self,
    ) -> std::collections::BTreeMap<String, ManualRosterConstructionHistoryRecordV2> {
        self.operations
            .iter()
            .filter_map(|(id, (_, _, result))| {
                let r = match result {
                    MutationResult::ManualRosterConstructionReservedV2(r) => {
                        ManualRosterConstructionHistoryRecordV2::Reservation { record: r.clone() }
                    }
                    MutationResult::ManualRosterConstructionConsumedV2(r) => {
                        ManualRosterConstructionHistoryRecordV2::Consumed { record: r.clone() }
                    }
                    _ => return None,
                };
                Some((id.clone(), r))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "manual_roster_construction_v2_tests.rs"]
pub(crate) mod tests;
