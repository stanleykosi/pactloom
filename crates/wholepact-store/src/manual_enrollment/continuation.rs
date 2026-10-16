//! Platform-independent historical V2 continuation audit. These strict data
//! mirrors deliberately have no origin/IPC dependency and cannot issue leases.
//! An existing exact original enrollment is mandatory. Restored evidence never
//! recreates its owner, renews a deadline, or changes financial/account state.
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualContinuationEnrollment {
    pub terms: BornManualEnrollmentTerms,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualContinuationRequestV2 {
    pub version: u16,
    pub enrollment: ManualContinuationEnrollment,
    pub continuation_digest: String,
}
impl ManualContinuationRequestV2 {
    pub fn digest(&self) -> Result<String> {
        self.enrollment
            .terms
            .validate()
            .map_err(|_| StoreError::RecoveryRequired)?;
        hash(&self.continuation_digest)?;
        if self.version != 2 {
            return Err(StoreError::RecoveryRequired);
        }
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-manual-enrollment-continuation-request:v2",
            self,
        )
        .map_err(|_| StoreError::RecoveryRequired)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualContinuationAdmissionV2 {
    pub version: u16,
    pub exact_request_digest: String,
    pub signer_intent_digest: String,
    pub witness_admission_digest: String,
    pub attempt_digest: String,
    pub attempt_sequence: u64,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl ManualContinuationAdmissionV2 {
    pub fn validate_for(&self, request: &ManualContinuationRequestV2) -> Result<()> {
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
            &self.attempt_digest,
        ] {
            hash(value)?;
        }
        let terms = &request.enrollment.terms;
        if self.version != 2
            || self.attempt_sequence < 2
            || self.attempt_sequence > i64::MAX as u64
            || self.exact_request_digest != request.digest()?
            || self.attempt_digest != request.continuation_digest
            || self.admitted_at_ms == 0
            || self.admitted_at_ms < terms.issued_at_ms
            || self.admission_deadline_ms <= self.admitted_at_ms
            || self.admission_deadline_ms > i64::MAX as u64
            || self.admission_deadline_ms > terms.scope.expires_at_ms
            || self.admission_deadline_ms - self.admitted_at_ms > 120_000
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
}
/// Immutable observation at the first Host audit publication. Historical only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualContinuationCurrentAudit {
    pub writer_certificate_digest: String,
    pub writer_epoch: u64,
    pub writer_session_digest: String,
    pub writer_session_expires_at_ms: u64,
    pub witness_head_sequence: u64,
    pub witness_head_digest: String,
    pub complete_history_digest: String,
    pub exclusion_checkpoint_digest: String,
    pub native_review_digest: String,
}
impl ManualContinuationCurrentAudit {
    pub(super) fn validate(&self) -> Result<()> {
        for value in [
            &self.writer_certificate_digest,
            &self.writer_session_digest,
            &self.witness_head_digest,
            &self.complete_history_digest,
            &self.exclusion_checkpoint_digest,
            &self.native_review_digest,
        ] {
            hash(value)?;
        }
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.writer_session_expires_at_ms == 0
            || self.writer_session_expires_at_ms > i64::MAX as u64
            || self.witness_head_sequence > i64::MAX as u64
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualContinuationEvidenceV2 {
    pub version: u16,
    pub request: ManualContinuationRequestV2,
    pub enrollment_ref: String,
    pub witness_extension_digest: String,
    pub witness_extension_sequence: u64,
    pub witness_extension_predecessor_digest: Option<String>,
    pub admission: ManualContinuationAdmissionV2,
    pub current: ManualContinuationCurrentAudit,
}
impl ManualContinuationEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        hash(&self.enrollment_ref)?;
        hash(&self.witness_extension_digest)?;
        self.admission.validate_for(&self.request)?;
        self.current.validate()?;
        let terms = &self.request.enrollment.terms;
        if self.version != 2
            || self.witness_extension_sequence != 1
            || self.witness_extension_predecessor_digest.is_some()
            || terms.host.scope_predecessor_digest.is_some()
            || self.current.writer_epoch != terms.signer.writer_epoch
            || self.current.writer_certificate_digest != terms.signer.writer_certificate_digest
            || self.admission.admission_deadline_ms > self.current.writer_session_expires_at_ms
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    /// Fresh current observations never replace the first immutable audit.
    pub fn require_exact_retry(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.request != original.request
            || self.enrollment_ref != original.enrollment_ref
            || self.witness_extension_digest != original.witness_extension_digest
            || self.witness_extension_sequence != original.witness_extension_sequence
            || self.witness_extension_predecessor_digest
                != original.witness_extension_predecessor_digest
            || self.admission != original.admission
            || self.current.writer_session_digest != original.current.writer_session_digest
            || self.current.writer_session_expires_at_ms
                != original.current.writer_session_expires_at_ms
        {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentContinuationAudit {
    pub version: u16,
    pub enrollment_audit_digest: String,
    pub operation_id: String,
    pub request_identity_digest: String,
    pub provider_enrollment_ref: String,
    /// Host publication sequence, distinct from witness attempts. Remote
    /// attempts not published here are not invented or silently counted.
    pub store_sequence: u64,
    pub predecessor_digest: Option<String>,
    pub aliases: BTreeSet<String>,
    pub evidence: ManualContinuationEvidenceV2,
}
impl ManualEnrollmentContinuationAudit {
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        identity(
            &self.evidence.request.enrollment.terms.identity,
            &self.aliases,
        )?;
        validate_id(&self.operation_id)?;
        for value in [
            &self.enrollment_audit_digest,
            &self.request_identity_digest,
            &self.provider_enrollment_ref,
        ] {
            hash(value)?;
        }
        if let Some(value) = &self.predecessor_digest {
            hash(value)?;
        }
        if self.version != 2
            || self.store_sequence == 0
            || self.store_sequence > MAX_AUDITS as u64
            || (self.store_sequence == 1) != self.predecessor_digest.is_none()
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn validate_for(&self, original: &ManualEnrollmentAudit) -> Result<()> {
        self.validate()?;
        original.validate()?;
        let e = &self.evidence;
        if self.enrollment_audit_digest != original.digest()?
            || e.request.enrollment.terms != original.terms
            || e.enrollment_ref != original.enrollment_ref
            || e.witness_extension_digest != original.witness_extension_digest
            || e.witness_extension_sequence != original.witness_extension_sequence
            || e.witness_extension_predecessor_digest
                != original.witness_extension_predecessor_digest
            || self.aliases != original.aliases
            || self.provider_enrollment_ref != original.original_provider_enrollment_ref
            || e.admission.signer_intent_digest != original.admission.signer_intent_digest
            || e.admission.admitted_at_ms < original.admission.admission_deadline_ms
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest(
            "wholepact:store-manual-enrollment-continuation-audit:v2",
            self,
        )
    }
}

/// Complete audit-chain validation used during snapshot/backup/recovery and
/// before any append. A standalone syntactically valid row is insufficient.
pub(super) fn validate_chains(
    enrollments: &[(String, ManualEnrollmentAudit)],
    continuations: &[(String, ManualEnrollmentContinuationAudit)],
) -> Result<()> {
    let mut groups: BTreeMap<&str, Vec<(&str, &ManualEnrollmentContinuationAudit)>> =
        BTreeMap::new();
    let mut attempts = BTreeSet::new();
    for (id, audit) in continuations {
        let (_, original) = enrollments
            .iter()
            .find(|(digest, _)| digest == &audit.enrollment_audit_digest)
            .ok_or(StoreError::RecoveryRequired)?;
        audit.validate_for(original)?;
        if !attempts.insert(audit.evidence.admission.attempt_digest.as_str()) {
            return Err(StoreError::RecoveryRequired);
        }
        groups
            .entry(&audit.enrollment_audit_digest)
            .or_default()
            .push((id, audit));
    }
    for rows in groups.values_mut() {
        rows.sort_by_key(|(_, a)| a.store_sequence);
        let mut sessions = BTreeSet::new();
        for (i, (_, a)) in rows.iter().enumerate() {
            if !sessions.insert(a.evidence.current.writer_session_digest.as_str())
                || a.store_sequence != i as u64 + 1
                || a.predecessor_digest.as_deref() != i.checked_sub(1).map(|n| rows[n].0)
            {
                return Err(StoreError::RecoveryRequired);
            }
            if let Some(n) = i.checked_sub(1) {
                let old = &rows[n].1.evidence;
                if a.evidence.admission.attempt_sequence <= old.admission.attempt_sequence
                    || a.evidence.admission.admitted_at_ms < old.admission.admission_deadline_ms
                    || a.evidence.current.witness_head_sequence <= old.current.witness_head_sequence
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
    }
    Ok(())
}
