//! Deterministic replay of an independently native-approved bounded enrollment.
//! This never changes the immutable genesis policy or permits the legacy issuer
//! to adopt a born account. Financial execution needs a separate concrete owner.
use crate::{born_offline_enrollment_v1::*, policy::Ledger, *};

impl Ledger {
    pub(crate) fn born_offline_enrollment_v1(
        &self,
    ) -> Result<Option<&BornOfflineEnrollmentRecordV1>> {
        let mut found = None;
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::EnrollBornOfflineV1 { record },
                ..
            }) = mutation
            {
                record.validate()?;
                if found.replace(record.as_ref()).is_some() {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
        }
        Ok(found)
    }
    pub(crate) fn validate_born_offline_birth_v1(
        &self,
        birth: Option<&crate::pending_birth::PendingBirthCommitRecord>,
    ) -> Result<()> {
        if let Some(record) = self.born_offline_enrollment_v1()? {
            record
                .enrollment
                .validate_original_birth(birth.ok_or(AuthorityError::CorruptHistory)?)?;
        }
        Ok(())
    }
    pub(crate) fn validate_new_born_offline_enrollment_v1(
        &self,
        record: &BornOfflineEnrollmentRecordV1,
        now: u64,
    ) -> Result<()> {
        record.validate()?;
        let e = &record.enrollment;
        e.validate_original_policy(&self.policy)?;
        e.require_first_commit_time(now)?;
        // Complete preceding history, never an empty projection. An offline
        // extension is not allowed to hide an excluded, replaced or used scope.
        self.require_supported_manual_history()?;
        if self.born_offline_enrollment_v1()?.is_some()
            || !self.offline_policies.is_empty()
            || !self.offline_policy_states.is_empty()
            || self.snapshot.pending_writer_session.is_some()
            || self.snapshot.head != e.expected_head
            || self.snapshot.active_writer_session.as_ref() != Some(&e.original_writer_session)
            || self.sessions.get(&e.original_writer_session.session_id)
                != Some(&e.original_writer_session)
            || now >= e.original_writer_session.expires_at_ms
        {
            return Err(AuthorityError::Conflict);
        }
        self.require_unfenced_transport(&e.original_writer_session.session_id)?;
        let common = &self
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        common.validate_original_policy(&self.policy)?;
        if e.policy.enrollment_ref != common.enrollment_ref
            || e.policy.expires_at_ms > common.terms.scope.expires_at_ms
            || e.policy.maximum_admission_lifetime_ms
                > common.terms.scope.maximum_permit_lifetime_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        if let Some(roster) = self.manual_roster_extension()? {
            let attempt = self.latest_manual_roster_attempt_v2()?;
            let admission = attempt
                .admission
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            if e.manual_extension_digest != roster.extension.digest()?
                || e.manual_attempt_digest != attempt.attempt_digest
                || e.manual_admission_digest
                    != admission.digest_for(&roster.extension, attempt.continuation.as_ref())?
                || admission.session != e.original_writer_session
                || e.issued_at_ms < admission.admitted_at_ms
            {
                return Err(AuthorityError::InvalidBinding);
            }
        } else {
            let attempt = self.latest_manual_attempt()?;
            let admission = attempt
                .admission
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            let (session, admitted_at_ms) = match admission {
                crate::manual_session_continuation::ManualEnrollmentAdmissionEvidence::First { record } => (&record.session, record.admitted_at_ms),
                crate::manual_session_continuation::ManualEnrollmentAdmissionEvidence::Continued { record } => (&record.session, record.admitted_at_ms),
            };
            if e.manual_extension_digest != common.digest()?
                || e.manual_attempt_digest != attempt.attempt_digest
                || e.manual_admission_digest
                    != attempt
                        .last_admission_digest(common)?
                        .ok_or(AuthorityError::Permission)?
                || session != &e.original_writer_session
                || e.issued_at_ms < admitted_at_ms
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        Ok(())
    }
    pub(crate) fn apply_born_offline_enrollment_v1(
        &mut self,
        record: &BornOfflineEnrollmentRecordV1,
        now: u64,
    ) -> Result<()> {
        self.validate_new_born_offline_enrollment_v1(record, now)?;
        let policy = record.enrollment.policy.clone();
        let key = policy.policy_digest()?;
        self.offline_policy_states.insert(
            policy.enrollment_ref.clone(),
            (key.clone(), OfflineEnrollmentStatus::Active),
        );
        self.offline_policies.insert(key, policy);
        Ok(())
    }
}
