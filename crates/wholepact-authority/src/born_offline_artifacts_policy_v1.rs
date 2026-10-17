//! Pure append-only installation replay. No secret or native issuer is exposed.
use crate::{born_offline_artifacts_v1::*, policy::Ledger, *};
impl Ledger {
    pub(crate) fn born_offline_artifacts_v1(&self) -> Result<Option<&BornOfflineArtifactRecordV1>> {
        let mut found = None;
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control: OwnerControl::InstallBornOfflineArtifactsV1 { record },
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
    pub(crate) fn require_born_offline_original_session_v1(
        &self,
        now: u64,
    ) -> Result<&crate::born_offline_enrollment_v1::BornOfflineEnrollmentV1> {
        self.account_use_history
            .require_not_permanently_excluded()?;
        let e = &self
            .born_offline_enrollment_v1()?
            .ok_or(AuthorityError::Permission)?
            .enrollment;
        e.validate_original_policy(&self.policy)?;
        let original = &e.original_writer_session;
        self.require_born_transport_lineage_v1(e)?;
        if self.snapshot.writer_status != WriterStatus::Active
            || self.snapshot.writer_epoch != original.writer_epoch
            || self.snapshot.writer_certificate_digest != original.writer_certificate_digest
            || self.snapshot.pending_writer_session.is_some()
            || self.snapshot.active_writer_session.as_ref() != Some(original)
            || self.sessions.get(&original.session_id) != Some(original)
            || !self.activated_sessions.contains(&original.session_id)
            || self.offline_policy_states.get(&e.policy.enrollment_ref)
                != Some(&(e.policy.policy_digest()?, OfflineEnrollmentStatus::Active))
        {
            return Err(AuthorityError::Inactive);
        }
        if now < self.snapshot.last_witness_time_ms
            || now < e.policy.valid_from_ms
            || now >= e.policy.expires_at_ms
            || now >= original.expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        Ok(e)
    }
    pub(crate) fn validate_new_born_offline_artifacts_v1(
        &self,
        record: &BornOfflineArtifactRecordV1,
        now: u64,
    ) -> Result<()> {
        record.validate()?;
        let e = self.require_born_offline_original_session_v1(now)?;
        record.binding.validate_enrollment(e)?;
        record.binding.require_first_commit_time(now)?;
        if self.born_offline_artifacts_v1()?.is_some()
            || record.binding.expected_head != self.snapshot.head
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }
}
