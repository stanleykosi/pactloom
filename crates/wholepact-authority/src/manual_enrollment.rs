//! Exact append-only born manual enrollment. All serializable values are audit
//! data. A local native owner publishes an extension; only the separately scoped
//! namespace server can issue a finite, authenticated enrollment publication.
//! No financial consumer is enabled by this module.
use crate::{pending_birth::PendingBirthCommitRecord, *};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_enrollment::BornManualEnrollmentTerms;

pub const MANUAL_ENROLLMENT_PUBLICATION_MS: u64 = 120_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentExtension {
    pub version: u16,
    pub terms: BornManualEnrollmentTerms,
    pub enrollment_ref: String,
    pub enrollment_record_digest: String,
    pub sequence: u64,
    pub predecessor_digest: Option<String>,
}
impl ManualEnrollmentExtension {
    pub fn validate(&self) -> Result<()> {
        self.terms
            .validate()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        hash(&self.enrollment_ref)?;
        hash(&self.enrollment_record_digest)?;
        if self.version != 1
            || self.sequence != 1
            || self.predecessor_digest.is_some()
            || self.enrollment_ref != self.enrollment_record_digest
            || self.terms.host.scope_predecessor_digest.is_some()
        {
            // This bounded slice admits one immutable first extension only.
            // Successors require an explicit monotone protocol, never replacement.
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:manual-enrollment-extension:v1", self)
    }
    pub fn acquire_operation_id(&self) -> Result<String> {
        Ok(format!("manual-acquire-{}", self.digest()?))
    }
    pub fn admission_operation_id(&self) -> Result<String> {
        Ok(format!("manual-admit-{}", self.digest()?))
    }
    pub(crate) fn owner_operation_id(&self) -> Result<String> {
        Ok(format!("manual-extend-{}", self.digest()?))
    }
    pub fn validate_original_birth(&self, birth: &PendingBirthCommitRecord) -> Result<()> {
        self.validate()?;
        birth.validate()?;
        self.validate_original_policy(&birth.request.policy)?;
        let t = &self.terms;
        if t.birth_request_digest != birth.request_digest
            || t.birth_commit_digest != original_birth_commit_digest(birth)?
            || t.native_birth_digest != birth.request.native_birth_digest
            || t.issued_at_ms < birth.committed_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_original_policy(&self, p: &AccountPolicy) -> Result<()> {
        self.validate()?;
        p.validate()?;
        let g = p
            .account_use_genesis
            .as_ref()
            .ok_or(AuthorityError::PolicyDenied)?;
        let t = &self.terms;
        let s = &t.scope;
        if t.original_policy_digest != p.policy_digest()?
            || t.account_use_genesis_digest != g.digest()?
            || t.original_witness_origin_digest != g.witness_origin_digest
            || t.native_birth_digest != g.native_birth_digest
            || t.identity.account_id != g.identity.account_id
            || t.identity.full_viewing_key_digest != g.identity.full_viewing_key_digest
            || t.identity.network_profile_id != g.identity.network_profile_id
            || t.identity.derivation_domain != g.identity.derivation_domain
            || t.signer.owner_certificate_digest != p.owner_certificate_digest
            || t.signer.writer_certificate_digest != p.initial_writer_certificate_digest
            || t.signer.writer_epoch != p.initial_writer_epoch
            || p.enrollment_refs.contains(&self.enrollment_ref)
            || !p.agreement_ids.contains(&s.agreement_id)
            || s.recipient_scope_digests
                .iter()
                .any(|r| !p.recipient_scope_digests.contains(r))
            || s.aggregate_budget_zatoshis > p.aggregate_budget_zatoshis
            || s.per_operation_limit_zatoshis > p.per_operation_limit_zatoshis
            || s.maximum_fee_share_zatoshis > p.maximum_fee_share_zatoshis
            || s.maximum_transaction_fee_zatoshis > p.maximum_transaction_fee_zatoshis
            || s.maximum_permit_lifetime_ms > p.maximum_permit_lifetime_ms
            || s.expires_at_ms > p.policy_expires_at_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
}
/// Kept separate from the extension to avoid a review-digest self-reference.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentExtensionRecord {
    pub extension: ManualEnrollmentExtension,
    pub owner_signature_evidence_digest: String,
    pub native_review_digest: String,
}
impl ManualEnrollmentExtensionRecord {
    pub(crate) fn validate(&self) -> Result<()> {
        self.extension.validate()?;
        hash(&self.owner_signature_evidence_digest)?;
        hash(&self.native_review_digest)
    }
}
pub fn original_birth_commit_digest(birth: &PendingBirthCommitRecord) -> Result<String> {
    birth.validate()?;
    digest("wholepact:pending-account-birth-commit:v1", birth)
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualEnrollmentAdmissionRequest {
    pub version: u16,
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub extension_digest: String,
    pub enrollment_ref: String,
    pub writer_epoch: u64,
    pub expected_head: AuthorityHead,
    pub session_id: String,
}
impl BornManualEnrollmentAdmissionRequest {
    pub fn validate_for(&self, e: &ManualEnrollmentExtension) -> Result<()> {
        e.validate()?;
        hash(&self.expected_head.digest)?;
        hash(&self.session_id)?;
        if self.version != 1
            || self.operation_id != e.admission_operation_id()?
            || self.account_id != e.terms.identity.account_id
            || self.network_profile_id != e.terms.identity.network_profile_id
            || self.extension_digest != e.digest()?
            || self.enrollment_ref != e.enrollment_ref
            || self.writer_epoch != e.terms.signer.writer_epoch
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
/// Audit record with a fixed publication deadline. Exact retries cannot extend it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornManualEnrollmentAdmissionRecord {
    pub request: BornManualEnrollmentAdmissionRequest,
    pub snapshot: AccountSnapshot,
    pub session: WriterSessionReceipt,
    pub admitted_at_ms: u64,
    pub publication_expires_at_ms: u64,
}
impl BornManualEnrollmentAdmissionRecord {
    /// Checks inert historical evidence only; it cannot mint a live admission.
    pub fn validate_for(&self, e: &ManualEnrollmentExtension) -> Result<()> {
        self.request.validate_for(e)?;
        if self.admitted_at_ms < e.terms.issued_at_ms
            || self.publication_expires_at_ms <= self.admitted_at_ms
            || self.publication_expires_at_ms - self.admitted_at_ms
                > MANUAL_ENROLLMENT_PUBLICATION_MS
            || self.publication_expires_at_ms > e.terms.scope.expires_at_ms
            || self.publication_expires_at_ms > self.session.expires_at_ms
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
            || self.session.session_id != self.request.session_id
            || self.session.writer_certificate_digest != e.terms.signer.writer_certificate_digest
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
        hash(&self.snapshot.head.digest)?;
        Ok(())
    }
    /// Canonical commitment to the original immutable publication admission.
    /// Parsing or hashing retained evidence does not renew its deadline.
    pub fn digest_for(&self, extension: &ManualEnrollmentExtension) -> Result<String> {
        self.validate_for(extension)?;
        digest("wholepact:born-manual-enrollment-admission:v1", self)
    }
}
/// Created only by the real mTLS/session-MAC client path after a scoped namespace
/// admission. Not cloneable or deserializable; not a financial/current-use token.
/// A bounded already-admitted local publication may drain after remote UI blur.
pub struct AuthenticatedBornManualEnrollment {
    pub(crate) extension: ManualEnrollmentExtension,
    pub(crate) record: BornManualEnrollmentAdmissionRecord,
    pub(crate) observed_at_ms: u64,
    pub(crate) observed: std::time::Instant,
}
impl AuthenticatedBornManualEnrollment {
    pub fn extension(&self) -> &ManualEnrollmentExtension {
        &self.extension
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.record.snapshot
    }
    pub fn session(&self) -> &WriterSessionReceipt {
        &self.record.session
    }
    pub fn record(&self) -> &BornManualEnrollmentAdmissionRecord {
        &self.record
    }
    pub fn check_current(&self) -> Result<()> {
        self.record.validate_for(&self.extension)?;
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
impl ReconciledAuthorityHistory {
    /// An immutable inner V1 identity does not authenticate the V2 Host-roster
    /// wrapper. Public legacy evidence readers must never erase that binding.
    pub(crate) fn require_manual_v1_history(&self) -> Result<()> {
        if self.owner_controls.values().any(|r| {
            matches!(
                r.control,
                OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                    | OwnerControl::ContinueManualRosterSessionV2 { .. }
            )
        }) {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }

    /// Exact immutable extension from complete history. Still historical data.
    pub fn manual_enrollment_extension(
        &self,
        enrollment_ref: &str,
    ) -> Result<Option<&ManualEnrollmentExtension>> {
        self.require_manual_v1_history()?;
        hash(enrollment_ref)?;
        let mut found = None;
        for r in self.owner_controls.values() {
            if let OwnerControl::ExtendManualEnrollment { record } = &r.control {
                if record.extension.enrollment_ref == enrollment_ref {
                    if found.is_some() {
                        return Err(AuthorityError::CorruptHistory);
                    }
                    record.extension.validate_original_birth(
                        self.pending_birth_commit
                            .as_ref()
                            .ok_or(AuthorityError::CorruptHistory)?,
                    )?;
                    found = Some(&record.extension);
                }
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
#[path = "manual_enrollment_tests.rs"]
pub(crate) mod tests;
