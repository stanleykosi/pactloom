//! Explicit coordinated historical provenance. This is evidence only; decoding
//! it cannot reconstruct a Read, SignExact, key fence or journal grant.
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoordinatedFinancialSpendProvenanceV1 {
    pub(crate) version: u16,
    pub(crate) presentation_json: String,
}
impl CoordinatedFinancialSpendProvenanceV1 {
    pub(super) fn validate(&self, terms: &SpendConsentTerms, binding: &FinancialSpendBindingV1) -> Result<()> {
        if self.version != 1 || self.presentation_json.len() > 60 * 1024 {
            return Err(JournalError::InvalidBinding);
        }
        #[cfg(not(feature = "coordinated-financial-workflow-v1"))]
        { let _ = (terms, binding); Err(JournalError::RecoveryRequired) }
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        {
            let p: wholepact_financial_coordinator_origin::SignerSignExactPresentationV1 =
                wholepact_core::parse_typed_json(self.presentation_json.as_bytes())
                    .map_err(|_| JournalError::InvalidBinding)?;
            p.validate().map_err(|_| JournalError::InvalidBinding)?;
            let f = &p.facts;
            let original = &f.original.activation.facts.original;
            let mut inert = serde_json::to_value(terms).map_err(|_| JournalError::InvalidBinding)?;
            inert.as_object_mut().ok_or(JournalError::InvalidBinding)?.remove("receipt");
            if serde_json::to_string(&p).map_err(|_| JournalError::InvalidBinding)? != self.presentation_json
                || serde_json::to_string(&inert).map_err(|_| JournalError::InvalidBinding)? != f.spend_terms_json
                || f.signing_terms_digest != binding.signing_terms_digest
                || f.signer_principal_id != terms.principal_id
                || original.source_identity_digest != binding.source_identity_digest
                || original.terms_digest != binding.terms_digest
                || p.presentation_digest != binding.action_review_digest
                || p.actor.session_challenge != binding.native_session_digest
                || p.actor.common_image_measurement != binding.measurement
                || p.challenge != binding.nonce
                || binding.permission_generation != 1
                || f.reviewed_at_ms != terms.receipt.reviewed_at_ms
                || f.expires_at_ms != terms.receipt.expires_at_ms
            {
                return Err(JournalError::InvalidBinding);
            }
            let snapshot: wholepact_authority::AccountSnapshot =
                wholepact_core::parse_typed_json(f.authenticated_snapshot_json.as_bytes())
                    .map_err(|_| JournalError::InvalidBinding)?;
            let receipt: wholepact_authority::WriterSessionReceipt =
                wholepact_core::parse_typed_json(f.active_receipt_json.as_bytes())
                    .map_err(|_| JournalError::InvalidBinding)?;
            if snapshot.head != binding.reviewed_head
                || snapshot.active_writer_session.as_ref() != Some(&receipt)
                || snapshot.pending_writer_session.is_some()
                || receipt.session_id != f.original.activated.session_id
                || receipt.writer_epoch != terms.receipt.writer_epoch
                || receipt.expires_at_ms < terms.receipt.expires_at_ms
                || serde_json::to_string(&snapshot).map_err(|_| JournalError::InvalidBinding)? != f.authenticated_snapshot_json
                || serde_json::to_string(&receipt).map_err(|_| JournalError::InvalidBinding)? != f.active_receipt_json
            {
                return Err(JournalError::InvalidBinding);
            }
            Ok(())
        }
    }
}
