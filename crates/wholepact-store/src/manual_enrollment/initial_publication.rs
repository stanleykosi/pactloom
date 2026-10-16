//! A first Host publication through an independently admitted successor attempt.
//! Original born terms remain V1 terms; the admission is genuinely V2. No V1
//! publication or admission is synthesized, including in internal projections.
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentInitialPublicationV2 {
    pub version: u16,
    /// Current Host publication operation, distinct from the original intent.
    pub operation_id: String,
    pub request_identity_digest: String,
    pub provider_enrollment_ref: String,
    pub store_sequence: u64,
    pub aliases: BTreeSet<String>,
    pub evidence: ManualContinuationEvidenceV2,
}
impl ManualEnrollmentInitialPublicationV2 {
    pub fn terms(&self) -> &BornManualEnrollmentTerms {
        &self.evidence.request.enrollment.terms
    }
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        identity(&self.terms().identity, &self.aliases)?;
        validate_id(&self.operation_id)?;
        hash(&self.request_identity_digest)?;
        hash(&self.provider_enrollment_ref)?;
        if self.version != 2
            || self.store_sequence != 1
            || self.operation_id == self.terms().operation_id
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest(
            "wholepact:store-manual-enrollment-initial-publication:v2",
            self,
        )
    }
    pub fn require_exact_retry(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        self.evidence.require_exact_retry(&original.evidence)?;
        if self.operation_id != original.operation_id
            || self.request_identity_digest != original.request_identity_digest
            || self.provider_enrollment_ref != original.provider_enrollment_ref
            || self.store_sequence != original.store_sequence
            || self.aliases != original.aliases
        {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(())
    }
}

/// Explicit historical linkage. A V2 initial publication can never be passed
/// off as the V1 original accepted by the established continuation wire format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OriginalManualEnrollmentAuditLink {
    EnrollmentV1 { audit_digest: String },
    InitialPublicationV2 { audit_digest: String },
    AdditionalPublicationV3 { audit_digest: String },
}
impl OriginalManualEnrollmentAuditLink {
    pub fn audit_digest(&self) -> &str {
        match self {
            Self::EnrollmentV1 { audit_digest }
            | Self::InitialPublicationV2 { audit_digest }
            | Self::AdditionalPublicationV3 { audit_digest } => audit_digest,
        }
    }
}

/// Borrowed, explicitly tagged original rows. This is read-only comparison
/// evidence; neither variant constructs an admission or a native owner.
pub enum ManualEnrollmentProjection<'a> {
    EnrollmentV1(&'a ManualEnrollmentAudit),
    InitialPublicationV2(&'a ManualEnrollmentInitialPublicationV2),
    AdditionalPublicationV3(&'a ManualEnrollmentAdditionalPublicationV3),
}
pub enum ManualInitialAdmissionProvenance<'a> {
    EnrollmentV1(&'a ManualDurableEnrollmentAudit),
    ContinuationV2(&'a ManualContinuationEvidenceV2),
    RosterV2(&'a ManualRosterEnrollmentEvidenceV2),
}
impl ManualEnrollmentProjection<'_> {
    pub fn terms(&self) -> &BornManualEnrollmentTerms {
        match self {
            Self::EnrollmentV1(a) => &a.terms,
            Self::InitialPublicationV2(a) => a.terms(),
            Self::AdditionalPublicationV3(a) => a.terms(),
        }
    }
    pub fn aliases(&self) -> &BTreeSet<String> {
        match self {
            Self::EnrollmentV1(a) => &a.aliases,
            Self::InitialPublicationV2(a) => &a.aliases,
            Self::AdditionalPublicationV3(a) => &a.aliases,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::EnrollmentV1(a) => a.validate(),
            Self::InitialPublicationV2(a) => a.validate(),
            Self::AdditionalPublicationV3(a) => a.validate(),
        }
    }
    pub fn digest(&self) -> Result<String> {
        match self {
            Self::EnrollmentV1(a) => a.digest(),
            Self::InitialPublicationV2(a) => a.digest(),
            Self::AdditionalPublicationV3(a) => a.digest(),
        }
    }
    pub fn original_audit_link(&self) -> Result<OriginalManualEnrollmentAuditLink> {
        Ok(match self {
            Self::EnrollmentV1(a) => OriginalManualEnrollmentAuditLink::EnrollmentV1 {
                audit_digest: a.digest()?,
            },
            Self::InitialPublicationV2(a) => {
                OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                    audit_digest: a.digest()?,
                }
            }
            Self::AdditionalPublicationV3(a) => {
                OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
                    audit_digest: a.digest()?,
                }
            }
        })
    }
    pub fn initial_admission(&self) -> ManualInitialAdmissionProvenance<'_> {
        match self {
            Self::EnrollmentV1(a) => ManualInitialAdmissionProvenance::EnrollmentV1(&a.admission),
            Self::InitialPublicationV2(a) => {
                ManualInitialAdmissionProvenance::ContinuationV2(&a.evidence)
            }
            Self::AdditionalPublicationV3(a) => {
                ManualInitialAdmissionProvenance::RosterV2(&a.evidence)
            }
        }
    }
    pub(super) fn store_sequence(&self) -> u64 {
        match self {
            Self::EnrollmentV1(a) => a.store_sequence,
            Self::InitialPublicationV2(a) => a.store_sequence,
            Self::AdditionalPublicationV3(a) => a.store_sequence,
        }
    }
    pub(super) fn enrollment_ref(&self) -> &str {
        match self {
            Self::EnrollmentV1(a) => &a.enrollment_ref,
            Self::InitialPublicationV2(a) => &a.evidence.enrollment_ref,
            Self::AdditionalPublicationV3(a) => &a.evidence.enrollment_ref,
        }
    }
}

/// New strict format for later Host publications after a V2 initial publication.
/// This does not change the V2-to-V1 continuation representation or its digest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentContinuationAuditV3 {
    pub version: u16,
    pub original_audit: OriginalManualEnrollmentAuditLink,
    pub operation_id: String,
    pub request_identity_digest: String,
    pub provider_enrollment_ref: String,
    pub store_sequence: u64,
    pub predecessor_digest: Option<String>,
    pub aliases: BTreeSet<String>,
    pub evidence: ManualContinuationEvidenceV2,
}
impl ManualEnrollmentContinuationAuditV3 {
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
        if self.version != 3
            || !matches!(
                self.original_audit,
                OriginalManualEnrollmentAuditLink::InitialPublicationV2 { .. }
            )
            || self.store_sequence == 0
            || self.store_sequence > MAX_AUDITS as u64
            || (self.store_sequence == 1) != self.predecessor_digest.is_none()
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn validate_for(&self, original: &ManualEnrollmentInitialPublicationV2) -> Result<()> {
        self.validate()?;
        original.validate()?;
        let e = &self.evidence;
        let old = &original.evidence;
        if self.original_audit
            != (OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                audit_digest: original.digest()?,
            })
            || e.request.enrollment != old.request.enrollment
            || e.enrollment_ref != old.enrollment_ref
            || e.witness_extension_digest != old.witness_extension_digest
            || e.witness_extension_sequence != old.witness_extension_sequence
            || e.witness_extension_predecessor_digest != old.witness_extension_predecessor_digest
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
            "wholepact:store-manual-enrollment-continuation-audit:v3",
            self,
        )
    }
}

pub(super) fn validate_chains(
    initials: &[(String, ManualEnrollmentInitialPublicationV2)],
    continuations: &[(String, ManualEnrollmentContinuationAuditV3)],
) -> Result<()> {
    let mut groups: BTreeMap<&str, Vec<(&str, &ManualEnrollmentContinuationAuditV3)>> =
        BTreeMap::new();
    for (id, audit) in continuations {
        let original_digest = audit.original_audit.audit_digest();
        let (_, original) = initials
            .iter()
            .find(|(id, _)| id == original_digest)
            .ok_or(StoreError::RecoveryRequired)?;
        audit.validate_for(original)?;
        groups.entry(original_digest).or_default().push((id, audit));
    }
    for rows in groups.values_mut() {
        rows.sort_by_key(|(_, a)| a.store_sequence);
        let mut sessions = BTreeSet::new();
        for (index, (_, audit)) in rows.iter().enumerate() {
            if !sessions.insert(audit.evidence.current.writer_session_digest.as_str())
                || audit.store_sequence != index as u64 + 1
                || audit.predecessor_digest.as_deref() != index.checked_sub(1).map(|i| rows[i].0)
            {
                return Err(StoreError::RecoveryRequired);
            }
            if let Some(i) = index.checked_sub(1) {
                let old = &rows[i].1.evidence;
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
