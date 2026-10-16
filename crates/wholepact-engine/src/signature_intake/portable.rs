//! Exact existing transaction disclosure, preserving authenticated associations.
use super::*;
use wholepact_protocol::authorization::retention::transaction::{
    LocalTransactionCheckpoint, portable::TransactionDisclosureConsent,
};
impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn disclose_candidate_transaction<R>(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transactions: LocalTransactionCheckpoint<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
        recipient_id: &str,
        purpose: &str,
        consent: &dyn TransactionDisclosureConsent,
        disclose: impl FnOnce(&[u8], &dyn Fn() -> std::result::Result<(), RetentionError>) -> R,
    ) -> Result<R> {
        if deliveries.iter().any(|d| d.association.is_none()) {
            return Err(association_missing());
        }
        let (_, candidate) = self.candidate(access, candidate_id)?;
        let read = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let (context, signatures) = retention_inputs(
            &checkpoint,
            &candidate.proposal.manifest.agreement.agreement_id,
            &candidate.proposal.proposal_id,
            candidate.proposal.manifest.agreement.revision.into(),
            deliveries,
            now,
            true,
        )?;
        retention.journal.disclose_retained_transaction(context, key, checkpoint.pczt_bytes(), checkpoint.policy(),
            &signatures, wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
            &Gate { original: checkpoint.scope(), read, retain: retention.consent }, transactions,
            recipient_id, purpose, consent, disclose)
            .map_err(|_| ApiError::new("TRANSACTION_DISCLOSURE_DENIED", "Exact original transaction or separately approved disclosure unavailable; no reconstruction or replacement is allowed"))
    }
}
