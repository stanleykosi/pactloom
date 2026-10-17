//! Purpose-distinct born offline reservation evidence. These public values are
//! inert data. They never convert to a legacy OfflineV1 permit or spending token.
use crate::{born_offline_artifacts_v1::*, born_offline_enrollment_v1::*, offline::*, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineReservationRequestV1 {
    pub version: u16,
    pub enrollment_digest: String,
    pub artifact_binding_digest: String,
    pub construction_link: crate::born_offline_construction_v1::BornOfflineConstructionLinkV1,
    pub reservation: ReserveOfflineAuthorization,
}
impl BornOfflineReservationRequestV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        hash(&self.enrollment_digest)?;
        hash(&self.artifact_binding_digest)?;
        self.construction_link.validate()?;
        self.reservation.validate()?;
        encode(self)?;
        Ok(())
    }
    pub fn request_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-reservation-request:v1", self)
    }
    /// Complete immutable origin/ceiling validation, not authentication. The
    /// caller must obtain all parents from the same fully reconciled history.
    pub fn validate_policy_bounds(
        &self,
        account: &AccountPolicy,
        enrollment: &BornOfflineEnrollmentV1,
        artifacts: &BornOfflineArtifactRecordV1,
        manual: &ManualEnrollmentExtension,
        now: u64,
    ) -> Result<()> {
        self.validate()?;
        enrollment.validate_original_policy(account)?;
        enrollment.require_born_construction_scope_v1(&self.construction_link)?;
        artifacts.validate()?;
        artifacts.binding.validate_enrollment(enrollment)?;
        manual.validate_original_policy(account)?;
        let r = &self.reservation;
        let t = &r.intent.terms;
        let s = &manual.terms.scope;
        r.validate_common_policy_bounds(account, &enrollment.policy, now)?;
        if self.enrollment_digest != enrollment.digest()?
            || self.artifact_binding_digest != artifacts.binding.digest()?
            || t.enrollment_ref != manual.enrollment_ref
            || t.agreement_id != s.agreement_id
            || t.obligation_id != s.obligation_id
            || !s
                .recipient_scope_digests
                .contains(&t.recipient_scope_digest)
            || t.maximum_debit_zatoshis > s.per_operation_limit_zatoshis
            || t.maximum_debit_zatoshis > s.aggregate_budget_zatoshis
            || t.fee_share_zatoshis > s.maximum_fee_share_zatoshis
            || t.transaction_fee_zatoshis > s.maximum_transaction_fee_zatoshis
            || r.admission_expires_at_ms > s.expires_at_ms
            || r.admission_expires_at_ms > enrollment.original_writer_session.expires_at_ms
            || r.admission_expires_at_ms - r.requested_at_ms > s.maximum_permit_lifetime_ms
            || r.writer_epoch != enrollment.original_writer_session.writer_epoch
            || r.requested_at_ms < artifacts.binding.issued_at_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineReservationRecordV1 {
    pub request: BornOfflineReservationRequestV1,
    pub authentication: OfflineIntentAuthenticationRecord,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineAuthorizationAdmissionV1 {
    pub version: u16,
    pub request: BornOfflineReservationRequestV1,
    /// Kept structurally compatible for exact term projection only. Legacy
    /// policy validation rejects its born enrollment reference; no conversion
    /// to a legacy authenticated admission exists.
    pub reserved: OfflineAuthorizationAdmission,
}
impl BornOfflineAuthorizationAdmissionV1 {
    pub fn matches_request(&self, request: &BornOfflineReservationRequestV1) -> Result<()> {
        request.validate()?;
        if self.version != 1 || self.request != *request {
            return Err(AuthorityError::InvalidBinding);
        }
        self.reserved.matches_request(&request.reservation)
    }
    pub fn admission_digest(&self) -> Result<String> {
        self.matches_request(&self.request)?;
        digest("wholepact:born-offline-original-admission:v1", self)
    }
    pub fn validate_reserved_policy_bounds(
        &self,
        account: &AccountPolicy,
        enrollment: &BornOfflineEnrollmentV1,
        artifacts: &BornOfflineArtifactRecordV1,
        manual: &ManualEnrollmentExtension,
    ) -> Result<()> {
        self.matches_request(&self.request)?;
        self.request.validate_policy_bounds(
            account,
            enrollment,
            artifacts,
            manual,
            self.reserved.reserved_at_ms,
        )?;
        if self.reserved.witness_id != account.witness_id
            || self.reserved.witness_policy_digest != account.policy_digest()?
            || self.reserved.witness_transport_key_digest
                != enrollment.policy.witness_transport_key_digest
            || self.reserved.writer_session_id != enrollment.original_writer_session.session_id
            || self.reserved.account_outstanding_debit_zatoshis > account.aggregate_budget_zatoshis
            || self.reserved.account_outstanding_debit_zatoshis
                > manual.terms.scope.aggregate_budget_zatoshis
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
}

impl policy::Ledger {
    pub(crate) fn validate_born_offline_request_v1(
        &self,
        r: &BornOfflineReservationRequestV1,
        now: u64,
    ) -> Result<()> {
        let e = self.require_born_offline_original_session_v1(now)?;
        let a = self
            .born_offline_artifacts_v1()?
            .ok_or(AuthorityError::Permission)?;
        let manual = &self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        r.validate_policy_bounds(&self.policy, e, a, manual, now)?;
        self.check_account_outstanding_limit(0)?;
        if self
            .snapshot
            .outstanding_debit_zatoshis
            .checked_add(self.snapshot.settled_debit_zatoshis)
            .is_none_or(|total| {
                total > self.policy.aggregate_budget_zatoshis
                    || total > manual.terms.scope.aggregate_budget_zatoshis
            })
        {
            return Err(AuthorityError::BudgetExceeded);
        }
        let origin = self.born_offline_construction_origin_v1(&r.construction_link)?;
        r.construction_link.validate_for(&origin, &r.reservation)?;
        if origin.reservation.session != e.original_writer_session
            || now >= origin.reservation.construction_expires_at_ms
            || self.snapshot.outstanding_debit_zatoshis < origin.reservation.reserved_debit_zatoshis
            || self.snapshot.reserved_input_value_zatoshis
                < origin.reservation.reserved_input_value_zatoshis
            || !self
                .obligations
                .contains(&r.reservation.intent.terms.obligation_id)
            || r.reservation.intent.terms.inputs.iter().any(|i| {
                !self.input_ids.contains(&i.input_id) || !self.nullifiers.contains(&i.nullifier)
            })
        {
            return Err(AuthorityError::PolicyDenied);
        }
        // Immutable one-per-original claim; no cleanup, refund or retry renewal.
        if self.operations.values().any(|(_, _, result)| matches!(result,
            MutationResult::BornOfflineReservedV1(old) if old.request.construction_link.reservation_operation_id == r.construction_link.reservation_operation_id && old.request != *r
        )) { return Err(AuthorityError::Conflict); }
        Ok(())
    }
    pub(crate) fn reserve_born_offline_v1(
        &mut self,
        record: &BornOfflineReservationRecordV1,
        event: &policy::Event,
        head: &AuthorityHead,
    ) -> Result<MutationResult> {
        self.validate_born_offline_request_v1(&record.request, event.witness_time_ms)?;
        let e = self
            .require_born_offline_original_session_v1(event.witness_time_ms)?
            .clone();
        let a = self
            .born_offline_artifacts_v1()?
            .ok_or(AuthorityError::Permission)?
            .clone();
        let manual = self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension
            .clone();
        let r = &record.request.reservation;
        let t = &r.intent.terms;
        self.fence(&r.expected_head, r.writer_epoch)?;
        if event.authenticated_certificate_digest != e.born_transport_certificate_v1()
            || event.writer_session_id != e.born_event_writer_session_v1()
        {
            return Err(AuthorityError::SessionRequired);
        }
        record.authentication.matches(r, &e.policy)?;
        if self.authorizations.contains(&t.authorization_id)
            || self.offline_intents.contains(&r.intent.intent_id)
            || self
                .offline_intent_digests
                .contains(&r.intent.intent_digest()?)
        {
            return Err(AuthorityError::Conflict);
        }
        // Continue exactly the existing construction bucket, never add another.
        let debit = self.snapshot.outstanding_debit_zatoshis;
        let selected = self.snapshot.reserved_input_value_zatoshis;
        let admission = BornOfflineAuthorizationAdmissionV1 {
            version: 1,
            request: record.request.clone(),
            reserved: OfflineAuthorizationAdmission {
                schema_version: OFFLINE_PROTOCOL_VERSION,
                witness_id: self.policy.witness_id.clone(),
                witness_policy_digest: self.snapshot.policy_digest.clone(),
                witness_transport_key_digest: e.policy.witness_transport_key_digest.clone(),
                request_digest: r.request_digest()?,
                request: r.clone(),
                committed_head: head.clone(),
                reserved_at_ms: event.witness_time_ms,
                account_outstanding_debit_zatoshis: debit,
                account_reserved_input_value_zatoshis: selected,
                writer_session_id: e.original_writer_session.session_id.clone(),
            },
        };
        admission.validate_reserved_policy_bounds(&self.policy, &e, &a, &manual)?;
        self.snapshot.outstanding_debit_zatoshis = debit;
        self.snapshot.reserved_input_value_zatoshis = selected;
        self.authorizations.insert(t.authorization_id.clone());
        self.offline_intents.insert(r.intent.intent_id.clone());
        self.offline_intent_digests
            .insert(r.intent.intent_digest()?);
        self.obligations.insert(t.obligation_id.clone());
        for i in &t.inputs {
            self.input_ids.insert(i.input_id.clone());
            self.nullifiers.insert(i.nullifier.clone());
        }
        Ok(MutationResult::BornOfflineReservedV1(Box::new(admission)))
    }
}

impl ReconciledAuthorityHistory {
    /// Complete authenticated history only, never a native owner or current permit.
    /// Read-only unique historical lookup after complete ledger reconciliation.
    /// This never constructs a live admission or legacy permit.
    pub fn born_offline_admission_by_authorization_v1(
        &self,
        authorization_id: &str,
    ) -> Option<&BornOfflineAuthorizationAdmissionV1> {
        let mut matches = self
            .born_offline_permits
            .iter()
            .filter(|p| p.request.reservation.intent.terms.authorization_id == authorization_id);
        let first = matches.next()?;
        if matches.next().is_some() {
            None
        } else {
            Some(first)
        }
    }
    pub fn born_offline_admission_v1(
        &self,
        operation: &str,
    ) -> Option<&BornOfflineAuthorizationAdmissionV1> {
        self.born_offline_permits
            .iter()
            .find(|p| p.request.reservation.operation_id == operation)
    }
    pub fn born_offline_enrollment_v1(&self) -> Result<Option<&BornOfflineEnrollmentRecordV1>> {
        let mut found = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::EnrollBornOfflineV1 { record } = &r.control {
                record.enrollment.validate_original_birth(
                    self.pending_birth_commit
                        .as_ref()
                        .ok_or(AuthorityError::CorruptHistory)?,
                )?;
                if found.replace(record.as_ref()).is_some() {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
        }
        Ok(found)
    }
    pub fn born_offline_artifacts_v1(&self) -> Result<Option<&BornOfflineArtifactRecordV1>> {
        let mut found = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::InstallBornOfflineArtifactsV1 { record } = &r.control {
                record.binding.validate_enrollment(
                    &self
                        .born_offline_enrollment_v1()?
                        .ok_or(AuthorityError::CorruptHistory)?
                        .enrollment,
                )?;
                if found.replace(record.as_ref()).is_some() {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
        }
        Ok(found)
    }
    /// Exact manual parent retained inside the born offline origin. Unlike a
    /// manual-only accessor this does not pretend offline history is absent.
    pub fn born_offline_manual_extension_v1(&self) -> Result<&ManualEnrollmentExtension> {
        let enrollment = &self
            .born_offline_enrollment_v1()?
            .ok_or(AuthorityError::Permission)?
            .enrollment;
        let mut found = None;
        for r in self.owner_controls.values() {
            let candidate = match &r.control {
                OwnerControl::ExtendManualEnrollment { record } => Some(&record.extension),
                OwnerControl::ExtendManualRosterEnrollmentV2 { record } => {
                    Some(&record.account_record.extension)
                }
                _ => None,
            };
            if let Some(e) = candidate {
                e.validate_original_birth(
                    self.pending_birth_commit
                        .as_ref()
                        .ok_or(AuthorityError::CorruptHistory)?,
                )?;
                if e.enrollment_ref != enrollment.policy.enrollment_ref
                    || found.replace(e).is_some()
                {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
        }
        found.ok_or(AuthorityError::CorruptHistory)
    }
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "born_offline_admission_v1_tests.rs"]
pub(crate) mod tests;
