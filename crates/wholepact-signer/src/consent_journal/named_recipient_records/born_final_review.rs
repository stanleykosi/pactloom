//! Historical born final consent. This type is inert, not a native decision,
//! authenticated clock, history owner, or permission to invoke a spending key.
use super::*;
use wholepact_authority::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornNamedRecipientFinalReviewV1 {
    pub(crate) schema_version: u16,
    pub(crate) admission: BornOfflineAuthorizationAdmissionV1,
    pub(crate) origin_digest: String,
    pub(crate) witness: wholepact_authority::WitnessDisclosureDescriptor,
    pub(crate) history_digest: String,
    pub(crate) assertion_envelope_digest: String,
    pub(crate) admission_receipt: BornNamedAdmissionReceiptV1,
    pub(crate) native_review_digest: String,
    pub(crate) consent_reference: String,
    pub(crate) reviewed_at_ms: u64,
    pub(crate) return_message_id: String,
    pub(crate) return_sequence: u64,
    pub(crate) return_issued_at: i64,
    pub(crate) return_expires_at: i64,
}
impl BornNamedRecipientFinalReviewV1 {
    pub(crate) fn reference_digest(&self) -> Result<String> {
        digest(
            "wholepact:born-named-recipient-final-consent:v1",
            &(
                &self.admission,
                &self.origin_digest,
                &self.witness,
                &self.history_digest,
                &self.assertion_envelope_digest,
                &self.admission_receipt,
                &self.native_review_digest,
                self.reviewed_at_ms,
                &self.return_message_id,
                self.return_sequence,
                self.return_issued_at,
                self.return_expires_at,
            ),
        )
    }
    pub(crate) fn validate(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        started: &NamedRecipientStartedRecordV1,
    ) -> Result<()> {
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        self.admission
            .matches_request(&origin.request)
            .map_err(invalid_named_record)?;
        self.admission
            .validate_reserved_policy_bounds(
                &origin.birth.request.policy,
                &origin.enrollment.enrollment,
                &origin.artifacts,
                origin.manual_extension(),
            )
            .map_err(invalid_named_record)?;
        self.witness.validate().map_err(invalid_named_record)?;
        for h in [
            &self.origin_digest,
            &self.history_digest,
            &self.assertion_envelope_digest,
            &self.native_review_digest,
            &self.consent_reference,
        ] {
            hash(h)?;
        }
        exact_hex(&self.return_message_id, 16)?;
        let start = u64::try_from(self.return_issued_at)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or(JournalError::InvalidBinding)?;
        let end = u64::try_from(self.return_expires_at)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or(JournalError::InvalidBinding)?;
        if self.schema_version != 1
            || self.return_sequence == 0
            || self.return_sequence > i64::MAX as u64
            || self.origin_digest != origin.digest()?
            || self.admission_receipt.original_ref != original.reference
            || self.admission_receipt.profile_ref != original.profile_ref
            || self.admission_receipt.original_admission_digest
                != self
                    .admission
                    .admission_digest()
                    .map_err(invalid_named_record)?
            || self.witness.account_id != original.terms.account_id
            || self.witness.network_profile_id != original.terms.network_profile_id
            || self.witness.witness_id != self.admission.reserved.witness_id
            || self.witness.policy_digest != self.admission.reserved.witness_policy_digest
            || self.witness.pinned_server_certificate_digest
                != origin
                    .enrollment
                    .enrollment
                    .policy
                    .witness_certificate_digest
            || self.native_review_digest != started.native_review_digest
            || self.consent_reference != self.reference_digest()?
            || self.consent_reference
                == original
                    .reservation_request
                    .intent
                    .intent_digest()
                    .map_err(invalid_named_record)?
            || self.reviewed_at_ms < self.admission.reserved.reserved_at_ms
            || self.reviewed_at_ms >= started.original_deadline_ms
            || start > self.reviewed_at_ms
            || end <= self.reviewed_at_ms
            || end > started.original_deadline_ms
            || end > original.validity_expires_ms
        {
            return Err(JournalError::InvalidBinding);
        }
        self.admission_receipt.digest()?;
        Ok(())
    }
    pub(crate) fn validate_profile(
        &self,
        profile: &NamedRecipientProfileRecordV1,
        original: &NamedRecipientOriginalRecordV1,
    ) -> Result<()> {
        self.admission_receipt
            .validate_for(profile, original, &self.admission)
    }
}
