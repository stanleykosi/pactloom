//! Staged, unqualified historical roster records. No DTO creates a live lease.
//! Per-account first enrollment and generation-local roster order are distinct.
use super::*;
use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};

// Platform-neutral exact mirrors of the new signer-origin V2 wire. These are
// not aliases or conversions from the established first-scope V2 evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterPublicationAttemptV2 {
    InitialV2 {},
    ContinuationV2 {
        continuation_digest: String,
        attempt_sequence: u64,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterPublicationRequestV2 {
    pub version: u16,
    pub enrollment: ManualContinuationEnrollment,
    pub roster: HostRosterAppendBindingV2,
    pub attempt: ManualRosterPublicationAttemptV2,
}
impl ManualRosterPublicationRequestV2 {
    pub fn validate(&self) -> Result<()> {
        self.enrollment
            .terms
            .validate()
            .map_err(|_| StoreError::RecoveryRequired)?;
        self.roster
            .validate_for_host(&self.enrollment.terms.host)
            .map_err(|_| StoreError::RecoveryRequired)?;
        if self.version != 2 {
            return Err(StoreError::RecoveryRequired);
        }
        if let ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest,
            attempt_sequence,
        } = &self.attempt
        {
            hash(continuation_digest)?;
            if *attempt_sequence < 2 || *attempt_sequence > i64::MAX as u64 {
                return Err(StoreError::RecoveryRequired);
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-manual-roster-publication-request:v2",
            self,
        )
        .map_err(|_| StoreError::RecoveryRequired)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterAdmissionV2 {
    pub version: u16,
    pub exact_request_digest: String,
    pub signer_intent_digest: String,
    pub witness_admission_digest: String,
    pub attempt_digest: String,
    pub attempt_sequence: u64,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl ManualRosterAdmissionV2 {
    pub fn validate_for(&self, request: &ManualRosterPublicationRequestV2) -> Result<()> {
        request.validate()?;
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
            || self.exact_request_digest != request.digest()?
            || self.attempt_sequence == 0
            || self.attempt_sequence > i64::MAX as u64
            || self.admitted_at_ms == 0
            || self.admitted_at_ms < terms.issued_at_ms
            || self.admission_deadline_ms <= self.admitted_at_ms
            || self.admission_deadline_ms > i64::MAX as u64
            || self.admission_deadline_ms > terms.scope.expires_at_ms
            || self.admission_deadline_ms - self.admitted_at_ms > 120_000
        {
            return Err(StoreError::RecoveryRequired);
        }
        match &request.attempt {
            ManualRosterPublicationAttemptV2::InitialV2 {} if self.attempt_sequence != 1 => {
                Err(StoreError::RecoveryRequired)
            }
            ManualRosterPublicationAttemptV2::ContinuationV2 {
                continuation_digest,
                attempt_sequence,
            } if self.attempt_digest != *continuation_digest
                || self.attempt_sequence != *attempt_sequence =>
            {
                Err(StoreError::RecoveryRequired)
            }
            _ => Ok(()),
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterEnrollmentEvidenceV2 {
    pub version: u16,
    pub request: ManualRosterPublicationRequestV2,
    pub enrollment_ref: String,
    pub signer_roster_record_digest: String,
    pub witness_roster_extension_digest: String,
    pub witness_extension_digest: String,
    pub witness_extension_sequence: u64,
    pub witness_extension_predecessor_digest: Option<String>,
    pub admission: ManualRosterAdmissionV2,
    pub current: ManualContinuationCurrentAudit,
}
impl ManualRosterEnrollmentEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.admission.validate_for(&self.request)?;
        self.current.validate()?;
        for value in [
            &self.enrollment_ref,
            &self.signer_roster_record_digest,
            &self.witness_roster_extension_digest,
            &self.witness_extension_digest,
        ] {
            hash(value)?;
        }
        if matches!(
            self.request.attempt,
            ManualRosterPublicationAttemptV2::InitialV2 {}
        ) && self.admission.attempt_digest
            != wholepact_core::proposal::canonical_digest(
                "wholepact:manual-roster-enrollment-initial-attempt:v2",
                &self.witness_roster_extension_digest,
            )
            .map_err(|_| StoreError::RecoveryRequired)?
        {
            return Err(StoreError::RecoveryRequired);
        }
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
    pub fn require_exact_retry(&self, old: &Self) -> Result<()> {
        self.validate()?;
        old.validate()?;
        if self.request != old.request
            || self.enrollment_ref != old.enrollment_ref
            || self.signer_roster_record_digest != old.signer_roster_record_digest
            || self.witness_roster_extension_digest != old.witness_roster_extension_digest
            || self.witness_extension_digest != old.witness_extension_digest
            || self.witness_extension_sequence != old.witness_extension_sequence
            || self.witness_extension_predecessor_digest != old.witness_extension_predecessor_digest
            || self.admission != old.admission
            || self.current.writer_session_digest != old.current.writer_session_digest
            || self.current.writer_session_expires_at_ms != old.current.writer_session_expires_at_ms
        {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentAdditionalPublicationV3 {
    pub version: u16,
    pub operation_id: String,
    pub request_identity_digest: String,
    pub provider_enrollment_ref: String,
    pub store_sequence: u64,
    pub aliases: BTreeSet<String>,
    pub evidence: ManualRosterEnrollmentEvidenceV2,
}
impl ManualEnrollmentAdditionalPublicationV3 {
    pub fn terms(&self) -> &BornManualEnrollmentTerms {
        &self.evidence.request.enrollment.terms
    }
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        identity(&self.terms().identity, &self.aliases)?;
        validate_id(&self.operation_id)?;
        hash(&self.request_identity_digest)?;
        hash(&self.provider_enrollment_ref)?;
        if self.version != 3
            || self.store_sequence != self.evidence.request.roster.roster_sequence
            || self.operation_id == self.terms().operation_id
            || self.aliases != BTreeSet::from([self.terms().identity.account_id.clone()])
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest(
            "wholepact:store-manual-enrollment-additional-publication:v3",
            self,
        )
    }
    pub fn require_exact_retry(&self, old: &Self) -> Result<()> {
        self.validate()?;
        old.validate()?;
        self.evidence.require_exact_retry(&old.evidence)?;
        if self.operation_id != old.operation_id
            || self.request_identity_digest != old.request_identity_digest
            || self.provider_enrollment_ref != old.provider_enrollment_ref
            || self.store_sequence != old.store_sequence
            || self.aliases != old.aliases
        {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentContinuationAuditV4 {
    pub version: u16,
    pub original_audit: OriginalManualEnrollmentAuditLink,
    pub operation_id: String,
    pub request_identity_digest: String,
    pub provider_enrollment_ref: String,
    pub store_sequence: u64,
    pub predecessor_digest: Option<String>,
    pub aliases: BTreeSet<String>,
    pub evidence: ManualRosterEnrollmentEvidenceV2,
}
impl ManualEnrollmentContinuationAuditV4 {
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        identity(
            &self.evidence.request.enrollment.terms.identity,
            &self.aliases,
        )?;
        validate_id(&self.operation_id)?;
        for value in [
            self.original_audit.audit_digest(),
            &self.request_identity_digest,
            &self.provider_enrollment_ref,
        ] {
            hash(value)?;
        }
        if let Some(value) = &self.predecessor_digest {
            hash(value)?;
        }
        if self.version != 4
            || !matches!(
                self.original_audit,
                OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 { .. }
            )
            || !matches!(
                self.evidence.request.attempt,
                ManualRosterPublicationAttemptV2::ContinuationV2 { .. }
            )
            || self.store_sequence == 0
            || self.store_sequence > MAX_AUDITS as u64
            || (self.store_sequence == 1) != self.predecessor_digest.is_none()
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn validate_for(&self, original: &ManualEnrollmentAdditionalPublicationV3) -> Result<()> {
        self.validate()?;
        original.validate()?;
        let e = &self.evidence;
        let old = &original.evidence;
        if self.original_audit
            != (OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
                audit_digest: original.digest()?,
            })
            || e.request.enrollment != old.request.enrollment
            || e.request.roster != old.request.roster
            || e.enrollment_ref != old.enrollment_ref
            || e.signer_roster_record_digest != old.signer_roster_record_digest
            || e.witness_roster_extension_digest != old.witness_roster_extension_digest
            || e.witness_extension_digest != old.witness_extension_digest
            || self.aliases != original.aliases
            || self.provider_enrollment_ref != original.provider_enrollment_ref
            || e.admission.signer_intent_digest != old.admission.signer_intent_digest
            || e.admission.attempt_sequence <= old.admission.attempt_sequence
            || e.admission.admitted_at_ms < old.admission.admission_deadline_ms
            || e.current.writer_session_digest == old.current.writer_session_digest
            || e.current.witness_head_sequence <= old.current.witness_head_sequence
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest(
            "wholepact:store-manual-enrollment-continuation-audit:v4",
            self,
        )
    }
}

pub(super) fn validate_chains(
    originals: &[(String, ManualEnrollmentAdditionalPublicationV3)],
    continuations: &[(String, ManualEnrollmentContinuationAuditV4)],
) -> Result<()> {
    let mut groups: BTreeMap<&str, Vec<(&str, &ManualEnrollmentContinuationAuditV4)>> =
        BTreeMap::new();
    for (id, audit) in continuations {
        let digest = audit.original_audit.audit_digest();
        let (_, original) = originals
            .iter()
            .find(|(id, _)| id == digest)
            .ok_or(StoreError::RecoveryRequired)?;
        audit.validate_for(original)?;
        groups.entry(digest).or_default().push((id, audit));
    }
    for rows in groups.values_mut() {
        rows.sort_by_key(|(_, a)| a.store_sequence);
        let mut sessions = BTreeSet::new();
        for (i, (_, audit)) in rows.iter().enumerate() {
            if !sessions.insert(audit.evidence.current.writer_session_digest.as_str())
                || audit.store_sequence != i as u64 + 1
                || audit.predecessor_digest.as_deref() != i.checked_sub(1).map(|n| rows[n].0)
            {
                return Err(StoreError::RecoveryRequired);
            }
            if let Some(n) = i.checked_sub(1) {
                let old = &rows[n].1.evidence;
                if audit.evidence.admission.attempt_sequence <= old.admission.attempt_sequence
                    || audit.evidence.admission.admitted_at_ms < old.admission.admission_deadline_ms
                    || audit.evidence.current.witness_head_sequence
                        <= old.current.witness_head_sequence
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
    }
    Ok(())
}

impl ManualEnrollmentProjection<'_> {
    pub(super) fn roster_predecessor(&self) -> Option<&str> {
        match self {
            Self::EnrollmentV1(a) => a.terms.host.scope_predecessor_digest.as_deref(),
            Self::InitialPublicationV2(_) => None,
            Self::AdditionalPublicationV3(a) => {
                Some(match &a.evidence.request.roster.predecessor {
                    HostRosterPredecessorV2::EnrollmentV1 { audit_digest }
                    | HostRosterPredecessorV2::InitialPublicationV2 { audit_digest }
                    | HostRosterPredecessorV2::AdditionalPublicationV3 { audit_digest } => {
                        audit_digest
                    }
                })
            }
        }
    }
    pub(super) fn roster_link(&self) -> Result<HostRosterPredecessorV2> {
        let audit_digest = self.digest()?;
        Ok(match self {
            Self::EnrollmentV1(_) => HostRosterPredecessorV2::EnrollmentV1 { audit_digest },
            Self::InitialPublicationV2(_) => {
                HostRosterPredecessorV2::InitialPublicationV2 { audit_digest }
            }
            Self::AdditionalPublicationV3(_) => {
                HostRosterPredecessorV2::AdditionalPublicationV3 { audit_digest }
            }
        })
    }
}

#[cfg(test)]
#[path = "additional_publication_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) use tests::append_modeled_roster_layer_audits;

impl ManualEnrollmentAdditionalPublicationV3 {
    /// Compare the immutable account/roster wrappers before private pairing.
    /// A later attempt may change, but cannot replace any original identity.
    /// This is only a historical comparison and never a source of authority.
    #[cfg(any(test, all(feature = "manual-admission", target_os = "linux")))]
    pub(super) fn require_immutable_publication_identity(
        &self,
        request: &ManualRosterPublicationRequestV2,
        enrollment_ref: &str,
        witness_extension_digest: &str,
        witness_roster_extension_digest: &str,
        signer_roster_record_digest: &str,
    ) -> Result<()> {
        self.validate()?;
        request.validate()?;
        for value in [
            enrollment_ref,
            witness_extension_digest,
            witness_roster_extension_digest,
            signer_roster_record_digest,
        ] {
            hash(value)?;
        }
        let old = &self.evidence;
        if request.enrollment != old.request.enrollment
            || request.roster != old.request.roster
            || enrollment_ref != old.enrollment_ref
            || witness_extension_digest != old.witness_extension_digest
            || witness_roster_extension_digest != old.witness_roster_extension_digest
            || signer_roster_record_digest != old.signer_roster_record_digest
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }

    /// Pure cross-crate strict wire comparison, useful before private pairing on
    /// an initial-publication retry. It issues no current authority or receipt.
    pub fn require_exact_publication_request(&self, request: &serde_json::Value) -> Result<()> {
        self.validate()?;
        let request: ManualRosterPublicationRequestV2 = strict(request)?;
        request.validate()?;
        if request != self.evidence.request {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(())
    }
}
