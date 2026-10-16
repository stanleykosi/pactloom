//! Historical restriction publication; no live signer or financial authority.
//! Established exclusion bytes and empty-history projection digests stay unchanged.
use super::*;
pub(crate) const PERMANENT_STOP_V1: &str = "generation_manual_permanent_stop_v1";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualPermanentStopPublicationV1 {
    pub version: u16,
    pub original_host_audit_digest: String,
    pub provider_enrollment_ref: String,
    pub request_digest: String,
    pub exclusion: ManualExclusionAudit,
    pub original_witness_receipt_digest: String,
    pub original_witness_head_sequence: u64,
    pub original_witness_head_digest: String,
    pub original_native_review_digest: String,
}
impl ManualPermanentStopPublicationV1 {
    pub fn validate(&self) -> Result<()> {
        self.exclusion.validate()?;
        for value in [
            &self.original_host_audit_digest,
            &self.provider_enrollment_ref,
            &self.request_digest,
            &self.original_witness_receipt_digest,
            &self.original_witness_head_digest,
            &self.original_native_review_digest,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.original_witness_head_sequence == 0
            || self.original_witness_head_sequence > i64::MAX as u64
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        domain_digest("wholepact:store-permanent-stop-publication:v1", self)
    }
    pub(crate) fn require_original(
        &self,
        original: &ManualEnrollmentAdditionalPublicationV3,
    ) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.original_host_audit_digest != original.digest()?
            || self.provider_enrollment_ref != original.provider_enrollment_ref
            || self.exclusion.identity != original.terms().identity
            || self.exclusion.aliases != original.aliases
            || self.exclusion.account_use_genesis_digest
                != original.terms().account_use_genesis_digest
            || self.request_digest != request_digest_for_original(original)?
        {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }
    /// Fresh reads cannot replace first-saved history/review bytes. Immutable
    /// exclusion and original witness receipt must match before returning them.
    pub(crate) fn require_same_publication(&self, proposed: &Self) -> Result<()> {
        self.validate()?;
        proposed.validate()?;
        if self.original_host_audit_digest != proposed.original_host_audit_digest
            || self.provider_enrollment_ref != proposed.provider_enrollment_ref
            || self.request_digest != proposed.request_digest
            || self.exclusion.operation_id != proposed.exclusion.operation_id
            || self.exclusion.identity != proposed.exclusion.identity
            || self.exclusion.aliases != proposed.exclusion.aliases
            || self.exclusion.account_use_genesis_digest
                != proposed.exclusion.account_use_genesis_digest
            || self.exclusion.exclusion_digest != proposed.exclusion.exclusion_digest
            || self.original_witness_receipt_digest != proposed.original_witness_receipt_digest
            || self.original_witness_head_sequence != proposed.original_witness_head_sequence
            || self.original_witness_head_digest != proposed.original_witness_head_digest
        {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(())
    }
}
/// Inert canonical correlation; runtime separately reconstructs the typed request
/// from the same actual Store original and checks this digest independently.
pub(crate) fn request_digest_for_original(
    original: &ManualEnrollmentAdditionalPublicationV3,
) -> Result<String> {
    original.validate()?;
    wholepact_core::proposal::canonical_digest("wholepact:host-permanent-stop-request:v1", &serde_json::json!({
        "version": 1, "original": {"version": 2, "enrollment": original.evidence.request.enrollment, "roster": original.evidence.request.roster},
        "original_host_audit_digest": original.digest()?, "provider_enrollment_ref": original.provider_enrollment_ref,
    })).map_err(|_| StoreError::RecoveryRequired)
}
pub(crate) fn validate_permanent_stop_set(
    rows: &[(String, ManualPermanentStopPublicationV1)],
    originals: &[(String, ManualEnrollmentAdditionalPublicationV3)],
    exclusions: &[(String, ManualExclusionAudit)],
) -> Result<()> {
    if rows.len() > MAX_AUDITS {
        return Err(StoreError::ResourceExhausted);
    }
    let mut original_ids = BTreeSet::new();
    let mut operations = BTreeSet::new();
    for (id, row) in rows {
        if *id != row.digest()?
            || !original_ids.insert(&row.original_host_audit_digest)
            || !operations.insert(&row.exclusion.operation_id)
        {
            return Err(StoreError::RecoveryRequired);
        }
        let original = originals
            .iter()
            .find(|(id, _)| id == &row.original_host_audit_digest)
            .ok_or(StoreError::RecoveryRequired)?;
        if original.0 != original.1.digest()? {
            return Err(StoreError::RecoveryRequired);
        }
        row.require_original(&original.1)?;
        if !exclusions.iter().any(|(id, exclusion)| {
            exclusion == &row.exclusion && row.exclusion.digest().is_ok_and(|digest| digest == *id)
        }) {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(())
}
