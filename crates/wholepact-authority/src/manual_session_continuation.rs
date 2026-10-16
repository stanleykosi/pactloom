//! Immutable one-attempt continuation evidence. Serializable values are audit
//! data, never native approval, current namespace authority or financial permits.
use crate::{manual_enrollment::*, *};
use serde::{Deserialize, Serialize};

pub fn initial_manual_attempt_digest(extension: &ManualEnrollmentExtension) -> Result<String> {
    extension.validate()?;
    digest(
        "wholepact:manual-enrollment-initial-attempt:v1",
        &extension.digest()?,
    )
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentSessionContinuation {
    pub version: u16,
    pub extension_digest: String,
    pub sequence: u64,
    pub previous_attempt_digest: String,
    pub expected_snapshot: AccountSnapshot,
    pub expected_previous_admission_digest: Option<String>,
    pub attempt_nonce: String,
    pub fresh_process_binding_digest: String,
    pub fresh_signer_review_digest: String,
    pub issued_at_ms: u64,
    pub initial_commit_deadline_ms: u64,
}
impl ManualEnrollmentSessionContinuation {
    pub fn validate_for(&self, original: &ManualEnrollmentExtension) -> Result<()> {
        original.validate()?;
        for value in [
            &self.extension_digest,
            &self.previous_attempt_digest,
            &self.attempt_nonce,
            &self.fresh_process_binding_digest,
            &self.fresh_signer_review_digest,
            &self.expected_snapshot.head.digest,
        ] {
            hash(value)?;
        }
        if let Some(d) = &self.expected_previous_admission_digest {
            hash(d)?;
        }
        let s = &self.expected_snapshot;
        if self.version != 1
            || self.sequence < 2
            || self.sequence > MAX_EVENTS
            || self.extension_digest != original.digest()?
            || s.account_id != original.terms.identity.account_id
            || s.network_profile_id != original.terms.identity.network_profile_id
            || s.policy_digest != original.terms.original_policy_digest
            || s.writer_certificate_digest != original.terms.signer.writer_certificate_digest
            || s.writer_epoch != original.terms.signer.writer_epoch
            || s.writer_status != WriterStatus::Active
            || self.issued_at_ms < original.terms.issued_at_ms
            || self.issued_at_ms < s.last_witness_time_ms
            || self.initial_commit_deadline_ms <= self.issued_at_ms
            || self.initial_commit_deadline_ms - self.issued_at_ms
                > MANUAL_ENROLLMENT_PUBLICATION_MS
            || self.initial_commit_deadline_ms > original.terms.scope.expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest_for(&self, original: &ManualEnrollmentExtension) -> Result<String> {
        self.validate_for(original)?;
        digest("wholepact:manual-enrollment-session-continuation:v1", self)
    }
    pub fn acquire_operation_id(&self, original: &ManualEnrollmentExtension) -> Result<String> {
        Ok(format!("manual-acquire-{}", self.digest_for(original)?))
    }
    pub fn admission_operation_id(&self, original: &ManualEnrollmentExtension) -> Result<String> {
        Ok(format!("manual-admit-v2-{}", self.digest_for(original)?))
    }
    pub(crate) fn owner_operation_id(
        &self,
        original: &ManualEnrollmentExtension,
    ) -> Result<String> {
        Ok(format!("manual-continue-{}", self.digest_for(original)?))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentSessionContinuationRecord {
    pub continuation: ManualEnrollmentSessionContinuation,
    pub owner_signature_evidence_digest: String,
    pub native_review_digest: String,
}
impl ManualEnrollmentSessionContinuationRecord {
    pub(crate) fn validate_for(&self, e: &ManualEnrollmentExtension) -> Result<()> {
        self.continuation.validate_for(e)?;
        hash(&self.owner_signature_evidence_digest)?;
        hash(&self.native_review_digest)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualEnrollmentAdmissionRequestV2 {
    pub version: u16,
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub extension_digest: String,
    pub enrollment_ref: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub session_id: String,
    pub attempt_digest: String,
    pub attempt_sequence: u64,
}
impl BornManualEnrollmentAdmissionRequestV2 {
    pub fn validate_for(
        &self,
        e: &ManualEnrollmentExtension,
        c: &ManualEnrollmentSessionContinuation,
    ) -> Result<()> {
        c.validate_for(e)?;
        hash(&self.expected_head.digest)?;
        hash(&self.session_id)?;
        if self.version != 2
            || self.operation_id != c.admission_operation_id(e)?
            || self.account_id != e.terms.identity.account_id
            || self.network_profile_id != e.terms.identity.network_profile_id
            || self.extension_digest != e.digest()?
            || self.enrollment_ref != e.enrollment_ref
            || self.writer_epoch != e.terms.signer.writer_epoch
            || self.attempt_digest != c.digest_for(e)?
            || self.attempt_sequence != c.sequence
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualEnrollmentAdmissionRecordV2 {
    pub request: BornManualEnrollmentAdmissionRequestV2,
    pub snapshot: AccountSnapshot,
    pub session: WriterSessionReceipt,
    pub admitted_at_ms: u64,
    pub publication_expires_at_ms: u64,
}
impl BornManualEnrollmentAdmissionRecordV2 {
    pub fn validate_for(
        &self,
        e: &ManualEnrollmentExtension,
        c: &ManualEnrollmentSessionContinuation,
    ) -> Result<()> {
        self.request.validate_for(e, c)?;
        if self.admitted_at_ms < c.issued_at_ms
            || self.publication_expires_at_ms <= self.admitted_at_ms
            || self.publication_expires_at_ms
                != self
                    .admitted_at_ms
                    .checked_add(MANUAL_ENROLLMENT_PUBLICATION_MS)
                    .ok_or(AuthorityError::Limit)?
                    .min(e.terms.scope.expires_at_ms)
                    .min(self.session.expires_at_ms)
            || self.snapshot.active_writer_session.as_ref() != Some(&self.session)
            || self.snapshot.writer_status != WriterStatus::Active
            || self.snapshot.writer_epoch != self.request.writer_epoch
            || self.session.writer_epoch != self.request.writer_epoch
            || self.session.session_id != self.request.session_id
            || self.session.writer_certificate_digest != e.terms.signer.writer_certificate_digest
            || self.snapshot.writer_certificate_digest != self.session.writer_certificate_digest
            || self.snapshot.head.sequence
                != self
                    .request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::Limit)?
            || self.snapshot.last_witness_time_ms != self.admitted_at_ms
            || self.snapshot.policy_digest != e.terms.original_policy_digest
            || self.snapshot.account_id != e.terms.identity.account_id
            || self.snapshot.network_profile_id != e.terms.identity.network_profile_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.snapshot.head.digest)
    }
    pub fn digest_for(
        &self,
        e: &ManualEnrollmentExtension,
        c: &ManualEnrollmentSessionContinuation,
    ) -> Result<String> {
        self.validate_for(e, c)?;
        digest("wholepact:born-manual-enrollment-admission:v2", self)
    }
}
/// Original variants stay distinct, including their exact original deadlines.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualEnrollmentAdmissionEvidence {
    First {
        record: BornManualEnrollmentAdmissionRecord,
    },
    Continued {
        record: BornManualEnrollmentAdmissionRecordV2,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualAttemptObservation {
    pub extension_digest: String,
    pub sequence: u64,
    pub attempt_digest: String,
    pub continuation: Option<ManualEnrollmentSessionContinuation>,
    pub snapshot: AccountSnapshot,
    pub admission: Option<ManualEnrollmentAdmissionEvidence>,
}
impl ManualAttemptObservation {
    pub fn digest(&self) -> &str {
        &self.attempt_digest
    }
    pub fn acquire_operation_id(&self, e: &ManualEnrollmentExtension) -> Result<String> {
        match &self.continuation {
            Some(c) => c.acquire_operation_id(e),
            None => e.acquire_operation_id(),
        }
    }
    pub fn admission_operation_id(&self, e: &ManualEnrollmentExtension) -> Result<String> {
        match &self.continuation {
            Some(c) => c.admission_operation_id(e),
            None => e.admission_operation_id(),
        }
    }
    pub fn last_admission_digest(&self, e: &ManualEnrollmentExtension) -> Result<Option<String>> {
        match (&self.admission, &self.continuation) {
            (None, _) => Ok(None),
            (Some(ManualEnrollmentAdmissionEvidence::First { record }), None) => {
                record.digest_for(e).map(Some)
            }
            (Some(ManualEnrollmentAdmissionEvidence::Continued { record }), Some(c)) => {
                record.digest_for(e, c).map(Some)
            }
            _ => Err(AuthorityError::CorruptHistory),
        }
    }
    pub fn last_publication_deadline_ms(&self) -> Option<u64> {
        self.admission.as_ref().map(|a| match a {
            ManualEnrollmentAdmissionEvidence::First { record } => record.publication_expires_at_ms,
            ManualEnrollmentAdmissionEvidence::Continued { record } => {
                record.publication_expires_at_ms
            }
        })
    }
}
impl ReconciledAuthorityHistory {
    /// Exact presence/absence from complete authenticated replay, including old
    /// candidates. Useful for immutable local proposal recovery, never approval.
    pub fn manual_session_continuation(
        &self,
        continuation_digest: &str,
    ) -> Result<Option<&ManualEnrollmentSessionContinuation>> {
        self.require_manual_v1_history()?;
        hash(continuation_digest)?;
        let mut originals =
            self.owner_controls
                .values()
                .filter_map(|request| match &request.control {
                    OwnerControl::ExtendManualEnrollment { record } => Some(&record.extension),
                    _ => None,
                });
        let Some(original) = originals.next() else {
            return Ok(None);
        };
        if originals.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        let mut found = None;
        for request in self.owner_controls.values() {
            if let OwnerControl::ContinueManualEnrollmentSession { record } = &request.control {
                if record.continuation.digest_for(original)? == continuation_digest {
                    if found.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    found = Some(&record.continuation);
                }
            }
        }
        Ok(found)
    }
    /// Projection of complete authenticated replay. It is never current approval.
    pub fn latest_manual_attempt(&self, enrollment_ref: &str) -> Result<ManualAttemptObservation> {
        let e = self
            .manual_enrollment_extension(enrollment_ref)?
            .ok_or(AuthorityError::Permission)?;
        let mut observation = self
            .manual_attempt
            .clone()
            .ok_or(AuthorityError::PolicyDenied)?;
        if observation.extension_digest != e.digest()? {
            return Err(AuthorityError::CorruptHistory);
        }
        // Quarantine from the current authenticated snapshot must not be hidden
        // by a historical replay projection.
        observation.snapshot = self.snapshot.clone();
        Ok(observation)
    }
}
/// Created only after actual mTLS + original exporter session MAC verification.
/// Finite enrollment storage publication only; no financial/current-use methods.
pub struct AuthenticatedBornManualEnrollmentV2 {
    pub(crate) extension: ManualEnrollmentExtension,
    pub(crate) continuation: ManualEnrollmentSessionContinuation,
    pub(crate) record: BornManualEnrollmentAdmissionRecordV2,
    pub(crate) observed_at_ms: u64,
    pub(crate) observed: std::time::Instant,
}
impl AuthenticatedBornManualEnrollmentV2 {
    pub fn extension(&self) -> &ManualEnrollmentExtension {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualEnrollmentSessionContinuation {
        &self.continuation
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.record.snapshot
    }
    pub fn session(&self) -> &WriterSessionReceipt {
        &self.record.session
    }
    pub fn record(&self) -> &BornManualEnrollmentAdmissionRecordV2 {
        &self.record
    }
    pub fn check_current(&self) -> Result<()> {
        self.record
            .validate_for(&self.extension, &self.continuation)?;
        let now = crate::now_ms()?;
        if now < self.observed_at_ms
            || now < self.record.admitted_at_ms
            || now >= self.record.publication_expires_at_ms
            || self.observed.elapsed().as_millis()
                >= u128::from(
                    self.record
                        .publication_expires_at_ms
                        .saturating_sub(self.observed_at_ms),
                )
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) struct BornManualBootstrapScope {
    pub(crate) extension_digest: String,
    pub(crate) attempt_digest: String,
}
#[cfg(test)]
#[path = "manual_session_continuation_tests.rs"]
pub(crate) mod tests;
