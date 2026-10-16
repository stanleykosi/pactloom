//! Roster-bound first-enrollment and explicit continuation evidence. All DTOs
//! are inert. Only authenticated transport creates the finite opaque admission.
use crate::{
    manual_enrollment::*, manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_session_continuation::ManualEnrollmentSessionContinuation, *,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterEnrollmentExtensionRecordV2 {
    pub extension: ManualRosterEnrollmentExtensionV2,
    /// Exact immutable inner first extension. Its signature/review evidence is
    /// for the complete V2 wrapper, never interpreted as a V1 owner signature.
    pub account_record: ManualEnrollmentExtensionRecord,
}
impl ManualRosterEnrollmentExtensionRecordV2 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.extension.validate()?;
        self.account_record.validate()?;
        if self.extension.account_extension != self.account_record.extension {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
pub fn initial_manual_roster_attempt_digest_v2(
    e: &ManualRosterEnrollmentExtensionV2,
) -> Result<String> {
    digest(
        "wholepact:manual-roster-enrollment-initial-attempt:v2",
        &e.digest()?,
    )
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterSessionContinuationV2 {
    pub version: u16,
    pub roster_extension_digest: String,
    pub continuation: ManualEnrollmentSessionContinuation,
}
impl ManualRosterSessionContinuationV2 {
    pub fn validate_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<()> {
        e.validate()?;
        self.continuation.validate_for(&e.account_extension)?;
        if self.version != 2 || self.roster_extension_digest != e.digest()? {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        self.validate_for(e)?;
        digest("wholepact:manual-roster-session-continuation:v2", self)
    }
    pub fn inner(&self) -> &ManualEnrollmentSessionContinuation {
        &self.continuation
    }
    pub fn sequence(&self) -> u64 {
        self.continuation.sequence
    }
    pub fn acquire_operation_id(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        Ok(format!("manual-roster-acquire-v2-{}", self.digest_for(e)?))
    }
    pub fn admission_operation_id(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        Ok(format!("manual-roster-admit-v2-{}", self.digest_for(e)?))
    }
    pub(crate) fn owner_operation_id(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<String> {
        Ok(format!("manual-roster-continue-v2-{}", self.digest_for(e)?))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterSessionContinuationRecordV2 {
    pub continuation: ManualRosterSessionContinuationV2,
    pub owner_signature_evidence_digest: String,
    pub native_review_digest: String,
}
impl ManualRosterSessionContinuationRecordV2 {
    pub(crate) fn validate_for(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<()> {
        self.continuation.validate_for(e)?;
        hash(&self.owner_signature_evidence_digest)?;
        hash(&self.native_review_digest)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualRosterAdmissionRequestV2 {
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
impl BornManualRosterAdmissionRequestV2 {
    pub fn validate_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: Option<&ManualRosterSessionContinuationV2>,
    ) -> Result<()> {
        e.validate()?;
        hash(&self.expected_head.digest)?;
        hash(&self.session_id)?;
        let (operation, attempt, sequence) = match c {
            Some(c) => (c.admission_operation_id(e)?, c.digest_for(e)?, c.sequence()),
            None => (
                e.admission_operation_id()?,
                initial_manual_roster_attempt_digest_v2(e)?,
                1,
            ),
        };
        let inner = &e.account_extension;
        if self.version != 2
            || self.operation_id != operation
            || self.account_id != inner.terms.identity.account_id
            || self.network_profile_id != inner.terms.identity.network_profile_id
            || self.extension_digest != e.digest()?
            || self.enrollment_ref != inner.enrollment_ref
            || self.writer_epoch != inner.terms.signer.writer_epoch
            || self.attempt_digest != attempt
            || self.attempt_sequence != sequence
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualRosterAdmissionRecordV2 {
    pub request: BornManualRosterAdmissionRequestV2,
    pub snapshot: AccountSnapshot,
    pub session: WriterSessionReceipt,
    pub admitted_at_ms: u64,
    pub publication_expires_at_ms: u64,
}
impl BornManualRosterAdmissionRecordV2 {
    pub fn validate_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: Option<&ManualRosterSessionContinuationV2>,
    ) -> Result<()> {
        self.request.validate_for(e, c)?;
        let inner = &e.account_extension;
        let issued = c.map_or(inner.terms.issued_at_ms, |c| c.inner().issued_at_ms);
        if self.admitted_at_ms < issued
            || self.publication_expires_at_ms <= self.admitted_at_ms
            || self.publication_expires_at_ms
                != self
                    .admitted_at_ms
                    .checked_add(MANUAL_ENROLLMENT_PUBLICATION_MS)
                    .ok_or(AuthorityError::Limit)?
                    .min(inner.terms.scope.expires_at_ms)
                    .min(self.session.expires_at_ms)
            || self.snapshot.active_writer_session.as_ref() != Some(&self.session)
            || self.snapshot.writer_status != WriterStatus::Active
            || self.snapshot.writer_epoch != self.request.writer_epoch
            || self.session.writer_epoch != self.request.writer_epoch
            || self.session.session_id != self.request.session_id
            || self.session.writer_certificate_digest
                != inner.terms.signer.writer_certificate_digest
            || self.snapshot.writer_certificate_digest != self.session.writer_certificate_digest
            || self.snapshot.head.sequence
                != self
                    .request
                    .expected_head
                    .sequence
                    .checked_add(1)
                    .ok_or(AuthorityError::Limit)?
            || self.snapshot.last_witness_time_ms != self.admitted_at_ms
            || self.snapshot.policy_digest != inner.terms.original_policy_digest
            || self.snapshot.account_id != inner.terms.identity.account_id
            || self.snapshot.network_profile_id != inner.terms.identity.network_profile_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.snapshot.head.digest)
    }
    pub fn digest_for(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: Option<&ManualRosterSessionContinuationV2>,
    ) -> Result<String> {
        self.validate_for(e, c)?;
        digest("wholepact:born-manual-roster-admission:v2", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterAttemptObservationV2 {
    pub extension_digest: String,
    pub sequence: u64,
    pub attempt_digest: String,
    pub continuation: Option<ManualRosterSessionContinuationV2>,
    pub snapshot: AccountSnapshot,
    pub admission: Option<BornManualRosterAdmissionRecordV2>,
}
impl ManualRosterAttemptObservationV2 {
    pub fn digest(&self) -> &str {
        &self.attempt_digest
    }
    pub fn acquire_operation_id(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        match &self.continuation {
            Some(c) => c.acquire_operation_id(e),
            None => e.acquire_operation_id(),
        }
    }
    pub fn admission_operation_id(&self, e: &ManualRosterEnrollmentExtensionV2) -> Result<String> {
        match &self.continuation {
            Some(c) => c.admission_operation_id(e),
            None => e.admission_operation_id(),
        }
    }
    pub fn last_admission_digest(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<Option<String>> {
        self.admission
            .as_ref()
            .map(|a| a.digest_for(e, self.continuation.as_ref()))
            .transpose()
    }
    pub fn last_publication_deadline_ms(&self) -> Option<u64> {
        self.admission.as_ref().map(|a| a.publication_expires_at_ms)
    }
}
impl ReconciledAuthorityHistory {
    pub fn manual_roster_enrollment_extension(
        &self,
        enrollment_ref: &str,
    ) -> Result<Option<&ManualRosterEnrollmentExtensionV2>> {
        hash(enrollment_ref)?;
        let mut selected = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::ExtendManualRosterEnrollmentV2 { record } = &r.control {
                record.validate()?;
                if record.extension.account_extension.enrollment_ref == enrollment_ref {
                    if selected.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    record.extension.validate_original_birth(
                        self.pending_birth_commit
                            .as_ref()
                            .ok_or(AuthorityError::CorruptHistory)?,
                    )?;
                    selected = Some(&record.extension);
                }
            }
        }
        Ok(selected)
    }
    pub fn latest_manual_roster_attempt_v2(
        &self,
        enrollment_ref: &str,
    ) -> Result<ManualRosterAttemptObservationV2> {
        let e = self
            .manual_roster_enrollment_extension(enrollment_ref)?
            .ok_or(AuthorityError::Permission)?;
        let mut a = self
            .manual_roster_attempt
            .clone()
            .ok_or(AuthorityError::PolicyDenied)?;
        if a.extension_digest != e.digest()? {
            return Err(AuthorityError::CorruptHistory);
        }
        a.snapshot = self.snapshot.clone();
        Ok(a)
    }
    pub fn manual_roster_session_continuation_v2(
        &self,
        continuation_digest: &str,
    ) -> Result<Option<&ManualRosterSessionContinuationV2>> {
        hash(continuation_digest)?;
        let mut originals = self
            .owner_controls
            .values()
            .filter_map(|r| match &r.control {
                OwnerControl::ExtendManualRosterEnrollmentV2 { record } => Some(&record.extension),
                _ => None,
            });
        let Some(e) = originals.next() else {
            return Ok(None);
        };
        if originals.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        let mut found = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::ContinueManualRosterSessionV2 { record } = &r.control {
                if record.continuation.digest_for(e)? == continuation_digest {
                    if found.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    found = Some(&record.continuation);
                }
            }
        }
        Ok(found)
    }
}
/// No Clone/Deserialize/public constructor. A signed or retained record cannot
/// mint this live bounded publication capability or refresh its original time.
pub struct AuthenticatedBornManualRosterEnrollmentV2 {
    pub(crate) extension: ManualRosterEnrollmentExtensionV2,
    pub(crate) continuation: Option<ManualRosterSessionContinuationV2>,
    pub(crate) record: BornManualRosterAdmissionRecordV2,
    pub(crate) observed_at_ms: u64,
    pub(crate) observed: std::time::Instant,
}
impl AuthenticatedBornManualRosterEnrollmentV2 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn continuation(&self) -> Option<&ManualRosterSessionContinuationV2> {
        self.continuation.as_ref()
    }
    pub fn record(&self) -> &BornManualRosterAdmissionRecordV2 {
        &self.record
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.record.snapshot
    }
    pub fn session(&self) -> &WriterSessionReceipt {
        &self.record.session
    }
    pub fn check_current(&self) -> Result<()> {
        self.record
            .validate_for(&self.extension, self.continuation.as_ref())?;
        let now = now_ms()?;
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

#[cfg(test)]
#[path = "manual_roster_witness_v2_tests.rs"]
pub(crate) mod tests;
