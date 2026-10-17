//! Purpose-specific, immutable born offline enrollment evidence. DTO validation
//! authenticates neither the owner nor native consent and grants no execution.
use crate::{offline::OfflineEnrollmentPolicy, pending_birth::PendingBirthCommitRecord, *};
use serde::{Deserialize, Serialize};

pub const BORN_OFFLINE_FIRST_COMMIT_MS: u64 = 120_000;

/// Explicit assurance selection. A named setup pin does not establish assertion
/// truth; no independent assurance is inferred from a named-verifier statement.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case", deny_unknown_fields)]
pub enum BornOfflineAssuranceV1 {
    Independent,
    NamedVerifierOwnEffectsV1 { owner_setup_digest: String },
}
impl BornOfflineAssuranceV1 {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Independent => Ok(()),
            Self::NamedVerifierOwnEffectsV1 { owner_setup_digest } => hash(owner_setup_digest),
        }
    }
}

/// One first enrollment tied to one already-activated, original writer session.
/// The complete signed request is immutable; no continuation or renewal exists.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineEnrollmentV1 {
    pub version: u16,
    pub policy: OfflineEnrollmentPolicy,
    pub assurance: BornOfflineAssuranceV1,
    /// Explicit new native-approved owner purpose after the old general MAC was fenced.
    /// Absence preserves the original writer-origin encoding and all its gates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_continuation:
        Option<crate::born_offline_owner_continuation_v1::BornOfflineOwnerContinuationV1>,
    pub original_policy_digest: String,
    pub account_use_genesis_digest: String,
    pub birth_request_digest: String,
    pub birth_commit_digest: String,
    pub native_birth_digest: String,
    pub original_witness_origin_digest: String,
    pub owner_certificate_digest: String,
    /// Exact actual parent family: roster extension digest for a roster account,
    /// otherwise its original single-account manual extension digest.
    pub manual_extension_digest: String,
    pub manual_attempt_digest: String,
    pub manual_admission_digest: String,
    pub original_writer_session: WriterSessionReceipt,
    pub expected_head: AuthorityHead,
    pub issued_at_ms: u64,
    pub first_commit_deadline_ms: u64,
}
impl BornOfflineEnrollmentV1 {
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        self.assurance.validate()?;
        if let Some(origin) = &self.owner_continuation {
            origin.validate()?;
        }
        for h in [
            &self.original_policy_digest,
            &self.account_use_genesis_digest,
            &self.birth_request_digest,
            &self.birth_commit_digest,
            &self.native_birth_digest,
            &self.original_witness_origin_digest,
            &self.owner_certificate_digest,
            &self.manual_extension_digest,
            &self.manual_attempt_digest,
            &self.manual_admission_digest,
            &self.expected_head.digest,
            &self.original_writer_session.session_id,
            &self.original_writer_session.writer_certificate_digest,
            &self.original_writer_session.reconciled_head.digest,
            &self.original_writer_session.reconciled_history_digest,
            &self.original_writer_session.acquired_head.digest,
        ] {
            hash(h)?;
        }
        let session = &self.original_writer_session;
        session.disclosure.validate()?;
        if self.version != 1
            || self.expected_head.sequence >= MAX_EVENTS
            || self.issued_at_ms == 0
            || self.issued_at_ms > i64::MAX as u64
            || self.first_commit_deadline_ms <= self.issued_at_ms
            || self.first_commit_deadline_ms - self.issued_at_ms > BORN_OFFLINE_FIRST_COMMIT_MS
            || self.first_commit_deadline_ms > self.policy.expires_at_ms
            || self.issued_at_ms < self.policy.valid_from_ms
            || self.policy.expires_at_ms > session.expires_at_ms
            || session.writer_epoch == 0
            || session.writer_epoch > i64::MAX as u64
            || session.acquired_at_ms > self.issued_at_ms
            || session.acquired_at_ms >= session.expires_at_ms
            || session.expires_at_ms > i64::MAX as u64
            || session.acquired_head.sequence > self.expected_head.sequence
            || session.disclosure.account_id != self.policy.account_id
            || session.disclosure.network_profile_id != self.policy.network_profile_id
            || session.disclosure.witness_id != self.policy.witness_id
            || session.disclosure.policy_digest != self.original_policy_digest
            || session.disclosure.pinned_server_certificate_digest
                != self.policy.witness_certificate_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-enrollment:v1", self)
    }
    pub fn owner_operation_id(&self) -> Result<String> {
        Ok(format!("born-offline-enroll-v1-{}", self.digest()?))
    }
    pub(crate) fn validate_original_policy(&self, account: &AccountPolicy) -> Result<()> {
        self.validate()?;
        account.validate()?;
        let genesis = account
            .account_use_genesis
            .as_ref()
            .ok_or(AuthorityError::PolicyDenied)?;
        if self.original_policy_digest != account.policy_digest()?
            || self.account_use_genesis_digest != genesis.digest()?
            || self.native_birth_digest != genesis.native_birth_digest
            || self.original_witness_origin_digest != genesis.witness_origin_digest
            || self.owner_certificate_digest != account.owner_certificate_digest
            || self.policy.account_id != account.account_id
            || self.policy.network_profile_id != account.network_profile_id
            || self.policy.witness_id != account.witness_id
            || self.policy.expires_at_ms > account.policy_expires_at_ms
            || self.policy.maximum_admission_lifetime_ms > account.maximum_permit_lifetime_ms
            || self.original_writer_session.writer_epoch != account.initial_writer_epoch
            || self.original_writer_session.writer_certificate_digest
                != account.initial_writer_certificate_digest
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    pub fn validate_original_birth(&self, birth: &PendingBirthCommitRecord) -> Result<()> {
        birth.validate()?;
        self.validate_original_policy(&birth.request.policy)?;
        if self.birth_request_digest != birth.request_digest
            || self.birth_commit_digest
                != crate::manual_enrollment::original_birth_commit_digest(birth)?
            || self.issued_at_ms < birth.committed_at_ms
            || self.original_writer_session.disclosure != birth.request.disclosure
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn require_first_commit_time(&self, now: u64) -> Result<()> {
        self.validate()?;
        if now < self.issued_at_ms || now >= self.first_commit_deadline_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}

/// Separate evidence avoids a native-review digest self-reference. The original
/// verified signature and review digests are retained unchanged on exact retry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineEnrollmentRecordV1 {
    pub enrollment: BornOfflineEnrollmentV1,
    pub owner_signature_evidence_digest: String,
    pub native_review_digest: String,
}
impl BornOfflineEnrollmentRecordV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.enrollment.validate()?;
        hash(&self.owner_signature_evidence_digest)?;
        hash(&self.native_review_digest)
    }
}

#[cfg(test)]
#[path = "born_offline_enrollment_v1_tests.rs"]
pub(crate) mod tests;
