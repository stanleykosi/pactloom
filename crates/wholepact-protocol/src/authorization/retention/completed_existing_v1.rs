//! Completed-original verification. All database operations in this module are
//! SELECTs. Missing or interrupted results are never repaired by verification.
use super::*;

struct VerifiedCompletedSignedResultV1 {
    scope: SignedRetentionScope,
    summary: SignedResultSummary,
    bytes: Zeroizing<Vec<u8>>,
}

impl SignedResultJournal {
    /// Verify a completed original intent/result without retaining or repairing
    /// anything. Normal journal opening is a separate configuration boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_completed_existing(
        &self, context: SignedCandidateContext, idempotency_key: &str,
        base: &[u8], policy: &ReviewPolicy, signatures: &[ExternalSignature],
        limits: ProvingLimits, consent: &dyn SignedRetentionConsent,
    ) -> Result<SignedResultSummary> {
        Ok(self.completed_existing(context, idempotency_key, base, policy,
            signatures, limits, consent)?.summary)
    }

    #[allow(clippy::too_many_arguments)]
    fn completed_existing(
        &self, context: SignedCandidateContext, idempotency_key: &str,
        base: &[u8], policy: &ReviewPolicy, signatures: &[ExternalSignature],
        limits: ProvingLimits, consent: &dyn SignedRetentionConsent,
    ) -> Result<VerifiedCompletedSignedResultV1> {
        validate(&context)?;
        if !(16..=128).contains(&idempotency_key.len())
            || !idempotency_key.bytes().all(|b| (33..=126).contains(&b))
            || base.len() > MAX_BYTES || signatures.is_empty() || signatures.len() > 64
            || hash(base) != context.proved_artifact_digest
            || hex::encode(policy.manifest_digest) != context.manifest_digest
            || !(1..=crate::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
            || policy.participants.iter().map(|p| p.account_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                != context.account_ids.iter().map(String::as_str).collect()
        { return Err(RetentionError::InvalidRequest); }
        let signatures_encoded = encode_signatures(signatures)?;
        let scope = SignedRetentionScope {
            context, signature_set_digest: hash(&signatures_encoded),
        };
        gate(consent, &scope)?;
        let encoded = Zeroizing::new(serde_json::to_vec(&scope)
            .map_err(|_| RetentionError::InvalidRequest)?);
        if encoded.len() > 16384 { return Err(RetentionError::InvalidRequest); }
        let request_digest = framed(&[&encoded, &signatures_encoded,
            &(limits.maximum_actions as u64).to_le_bytes()]);
        let result_id = format!("signed-{}", framed(&[
            scope.context.principal_id.as_bytes(), idempotency_key.as_bytes()]));
        let (saved, saved_digest) = {
            let c = self.connection.lock().map_err(|_| RetentionError::Storage)?;
            // CASE bounds allocations without disguising malformed existing rows
            // as missing. Identity columns are checked, not just the derived ID.
            let row: Option<(String, String, String, Option<Vec<u8>>, Option<Vec<u8>>)> = c.query_row(
                "SELECT substr(principal_id,1,129),substr(idem_key,1,129),substr(request_digest,1,65),CASE WHEN length(scope)<=16384 THEN scope ELSE NULL END,CASE WHEN length(signatures)<=10240 THEN signatures ELSE NULL END FROM signed_intents WHERE result_id=?1",
                [&result_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))
                .optional().map_err(db)?;
            let (principal, idem, request, saved_scope, saved_signatures) = row.ok_or(RetentionError::IntentNotFound)?;
            let saved_scope = Zeroizing::new(saved_scope.ok_or(RetentionError::VerificationFailed)?);
            let saved_signatures = Zeroizing::new(saved_signatures.ok_or(RetentionError::VerificationFailed)?);
            if principal != scope.context.principal_id || idem != idempotency_key
                || request != request_digest || *saved_scope != *encoded
                || *saved_signatures != *signatures_encoded
            { return Err(RetentionError::IdempotencyConflict); }
            gate(consent, &scope)?;
            let row: Option<(Option<Vec<u8>>, String)> = c.query_row(
                "SELECT CASE WHEN length(bytes)<=1048576 THEN bytes ELSE NULL END,substr(digest,1,65) FROM signed_results WHERE result_id=?1",
                [&result_id], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
            let (saved, digest) = row.ok_or(RetentionError::RecoveryRequired)?;
            (Zeroizing::new(saved.ok_or(RetentionError::VerificationFailed)?), digest)
        };
        gate(consent, &scope)?;
        if hash(&saved) != saved_digest { return Err(RetentionError::VerificationFailed); }
        let (inspection, reassembled) = assemble_external_signatures(base, policy,
            &scope.context.review_binding, signatures, limits)
            .map_err(|_| RetentionError::VerificationFailed)?;
        let reassembled = Zeroizing::new(reassembled);
        if reassembled.len() > MAX_BYTES || *reassembled != *saved
            || hash(&reassembled) != saved_digest
        { return Err(RetentionError::VerificationFailed); }
        gate(consent, &scope)?;
        Ok(VerifiedCompletedSignedResultV1 {
            scope, bytes: saved,
            summary: SignedResultSummary { result_id, request_digest,
                signed_candidate_digest: saved_digest, exact_replay: true,
                historical_reconciliation: true, inspection,
                transaction_extracted: false, authorization_allowed: false,
                distribution_allowed: false },
        })
    }

    #[cfg(feature = "transaction-checkpoint")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verified_completed_transaction_predecessor(
        &self, context: SignedCandidateContext, idempotency_key: &str,
        base: &[u8], policy: &ReviewPolicy, signatures: &[ExternalSignature],
        limits: ProvingLimits, consent: &dyn SignedRetentionConsent,
    ) -> Result<(transaction::TransactionRetentionScope, Zeroizing<Vec<u8>>)> {
        let completed = self.completed_existing(context, idempotency_key, base,
            policy, signatures, limits, consent)?;
        if !completed.summary.inspection.signatures_complete {
            return Err(RetentionError::IncompleteSignatures);
        }
        let scope = transaction::TransactionRetentionScope {
            signed_scope: completed.scope, signed_result_id: completed.summary.result_id,
            signed_request_digest: completed.summary.request_digest,
            signed_candidate_digest: completed.summary.signed_candidate_digest,
        };
        gate(consent, &scope.signed_scope)?;
        Ok((scope, completed.bytes))
    }
}
