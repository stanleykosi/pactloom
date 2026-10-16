//! Actual private owner composition. No public summary/trust-bit insertion API.
use super::*;
use crate::{
    proof_jobs::LocalProofJob,
    signature_intake::{AuthenticatedSignatureDelivery, LocalSignedRetention},
};
use wholepact_protocol::authorization::retention::{
    SignedResultSummary,
    transaction::{
        LocalTransactionCheckpoint, LocalTransactionRecovery, RecoveryState,
        TransactionCheckpointSummary, TransactionRecoveryConsent,
    },
};
use wholepact_transport::Timestamp;

impl Engine {
    /// Reconcile an existing exact signed intent. Deterministic assembly of its
    /// same original signatures may finish; no missing intent or signature is created.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_native_signature_result(
        &self,
        access: &Access,
        inspection: NativeSettlementInspection,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<NativeSettlementRequestView> {
        let saved = inspection.saved;
        if saved.kind != SettlementRequestKind::SignatureReconcile {
            return Err(inconsistent());
        }
        let revision = self.prepare_settlement_owner(access, &saved, false)?;
        self.verify_settlement_proof(access, &saved, &local)?;
        let summary = self.reconcile_retained_candidate_signatures(
            access,
            &saved.source.signature_retention_key,
            &saved.source.candidate_id,
            local,
            retention,
            deliveries,
            now,
        )?;
        let result = SettlementObservation::Signed {
            evidence: signed_observation(&summary)?,
        };
        self.finish_settlement_observation(access, &saved, revision, result)
    }
    /// Sole initial checkpoint attempt. Consumes the private one-shot metadata
    /// value; actual native consent and real authenticated signatures still gate extraction.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint_native_settlement_transaction(
        &self,
        access: &Access,
        attempt: NativeSettlementAttempt,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transaction: LocalTransactionCheckpoint<'_>,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<NativeSettlementRequestView> {
        let saved = attempt.saved;
        if saved.kind != SettlementRequestKind::TransactionCheckpoint {
            return Err(inconsistent());
        }
        let revision = self.prepare_settlement_owner(access, &saved, true)?;
        self.verify_settlement_proof(access, &saved, &local)?;
        let prior = self.reconcile_retained_candidate_signatures(
            access,
            &saved.source.signature_retention_key,
            &saved.source.candidate_id,
            copy_local(&local),
            copy_signed(&retention),
            deliveries,
            now,
        )?;
        let signed = signed_observation(&prior)?;
        if saved.expected_signed.as_ref() != Some(&signed) || !signed.signatures_complete {
            return Err(inconsistent());
        }
        let summary = self.checkpoint_retained_candidate_transaction(
            access,
            &saved.source.signature_retention_key,
            &saved.source.candidate_id,
            local,
            retention,
            transaction,
            deliveries,
            now,
        )?;
        let result = transaction_observation(signed, &summary)?;
        self.finish_settlement_observation(access, &saved, revision, result)
    }
    /// Repeatable existing-result inspection. Source-copy restore and extraction
    /// are structurally unavailable here, even if the caller has broader consent.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect_native_settlement_transaction(
        &self,
        access: &Access,
        inspection: NativeSettlementInspection,
        local: LocalProofJob<'_>,
        retention: LocalSignedRetention<'_>,
        transaction: LocalTransactionCheckpoint<'_>,
        recovery_consent: &dyn TransactionRecoveryConsent,
        deliveries: &[AuthenticatedSignatureDelivery<'_>],
        now: &Timestamp,
    ) -> Result<NativeSettlementRequestView> {
        let saved = inspection.saved;
        if saved.kind != SettlementRequestKind::TransactionCheckpoint {
            return Err(inconsistent());
        }
        let revision = self.prepare_settlement_owner(access, &saved, false)?;
        self.verify_settlement_proof(access, &saved, &local)?;
        let prior = self.reconcile_retained_candidate_signatures(
            access,
            &saved.source.signature_retention_key,
            &saved.source.candidate_id,
            copy_local(&local),
            copy_signed(&retention),
            deliveries,
            now,
        )?;
        let signed = signed_observation(&prior)?;
        if saved.expected_signed.as_ref() != Some(&signed) || !signed.signatures_complete {
            return Err(inconsistent());
        }
        let recovered = self.recover_retained_candidate_transaction(
            access,
            &saved.source.signature_retention_key,
            &saved.source.candidate_id,
            local,
            retention,
            LocalTransactionRecovery {
                destination: transaction,
                retained_copy: None,
                consent: recovery_consent,
            },
            deliveries,
            now,
        )?;
        if recovered.state != RecoveryState::CompleteExactReplay
            || recovered.re_extraction_allowed
            || recovered.authorization_allowed
            || recovered.distribution_allowed
            || recovered.release_allowed
        {
            return Err(ApiError::new(
                "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED",
                "Original bytes remain unknown or fenced; no extraction retry is available",
            ));
        }
        let result = transaction_observation(
            signed,
            recovered.checkpoint.as_ref().ok_or_else(inconsistent)?,
        )?;
        self.finish_settlement_observation(access, &saved, revision, result)
    }
    fn prepare_settlement_owner(
        &self,
        access: &Access,
        saved: &StoredNativeSettlementRequest,
        initial: bool,
    ) -> Result<u64> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(&saved.agreement_id)?;
        let e = self.load(access, &saved.agreement_id)?;
        let current = owned(&e, access, &saved.request_id)?;
        if !same_original(saved, current) || current.state != NativeRequestState::AttemptStarted {
            return Err(inconsistent());
        }
        if initial
            && (current.observation.is_some() || Some(e.view.revision) != current.attempt_revision)
        {
            return Err(closed());
        }
        Ok(e.view.revision)
    }
    fn verify_settlement_proof(
        &self,
        access: &Access,
        saved: &StoredNativeSettlementRequest,
        local: &LocalProofJob<'_>,
    ) -> Result<()> {
        if local.job_id != saved.source.job_id {
            return Err(inconsistent());
        }
        let proof = self.load_candidate_proof_for_local_review(
            access,
            &saved.source.candidate_id,
            copy_local(local),
        )?;
        use sha2::Digest;
        if proof.summary().result_digest.as_deref()
            != Some(saved.source.proved_artifact_digest.as_str())
            || hex::encode(sha2::Sha256::digest(proof.pczt_bytes()))
                != saved.source.proved_artifact_digest
            || proof.summary().scope_digest != saved.source.scope_digest
            || proof.scope().manifest_digest != saved.source.manifest_digest
        {
            return Err(inconsistent());
        }
        Ok(())
    }
    fn finish_settlement_observation(
        &self,
        access: &Access,
        saved: &StoredNativeSettlementRequest,
        revision: u64,
        result: SettlementObservation,
    ) -> Result<NativeSettlementRequestView> {
        let mut e = self.load(access, &saved.agreement_id)?;
        let current = owned(&e, access, &saved.request_id)?;
        if !same_original(saved, current) {
            return Err(inconsistent());
        }
        if let Some(prior) = &current.observation {
            if prior != &result {
                return Err(inconsistent());
            }
            return Ok(view(current));
        }
        candidates::check_revision(&e, revision)?;
        let command = context(
            access,
            &format!("native-settlement-observe-{}", saved.request_id),
            "native_settlement_observed",
            &saved.agreement_id,
            Some(revision),
            &json!({"request_id":saved.request_id,"observation":result}),
        )?;
        e.native_settlement_requests
            .get_mut(&saved.request_id)
            .ok_or_else(not_found)?
            .observation = Some(result);
        // The private journal may already have committed. Any metadata failure
        // leaves the immutable attempt unknown; fresh inspection can record the
        // same existing result later without resetting either journal.
        self.commit(
            &command,
            &saved.agreement_id,
            revision,
            e,
            "native_settlement_result_observed",
        )?;
        self.native_settlement_request(access, &saved.agreement_id, &saved.request_id)
    }
}
fn copy_local<'a>(local: &LocalProofJob<'a>) -> LocalProofJob<'a> {
    LocalProofJob {
        job_id: local.job_id,
        jobs: local.jobs,
        consent: local.consent,
    }
}
fn copy_signed<'a>(local: &LocalSignedRetention<'a>) -> LocalSignedRetention<'a> {
    LocalSignedRetention {
        journal: local.journal,
        consent: local.consent,
    }
}
fn same_original(a: &StoredNativeSettlementRequest, b: &StoredNativeSettlementRequest) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.observation = None;
    b.observation = None;
    a == b
}
fn signed_observation(summary: &SignedResultSummary) -> Result<SignedObservation> {
    if !summary.historical_reconciliation
        || !summary.inspection.proof_verified
        || !summary.inspection.exact_candidate_preserved
        || summary.inspection.authorization_allowed
        || summary.inspection.distribution_allowed
        || summary.inspection.chain_validated
        || summary.transaction_extracted
        || summary.authorization_allowed
        || summary.distribution_allowed
    {
        return Err(inconsistent());
    }
    let result = SignedObservation {
        result_id: summary.result_id.clone(),
        request_digest: summary.request_digest.clone(),
        signed_candidate_digest: summary.signed_candidate_digest.clone(),
        signatures_complete: summary.inspection.signatures_complete,
    };
    if !valid_signed(&result) {
        return Err(inconsistent());
    }
    Ok(result)
}
fn transaction_observation(
    signed: SignedObservation,
    summary: &TransactionCheckpointSummary,
) -> Result<SettlementObservation> {
    if !valid_signed(&signed)
        || !signed.signatures_complete
        || !summary
            .checkpoint_id
            .strip_prefix("transaction-")
            .is_some_and(digest)
        || summary.signed_result_id != signed.result_id
        || !summary.cryptographic_transaction_verified
        || !summary.transaction_extracted
        || summary.chain_validated
        || summary.authorization_allowed
        || summary.distribution_allowed
        || summary.release_allowed
        || !digest(&summary.transaction_digest)
        || !digest(&summary.txid)
    {
        return Err(inconsistent());
    }
    Ok(SettlementObservation::Transaction {
        signed,
        checkpoint_id: summary.checkpoint_id.clone(),
        transaction_digest: summary.transaction_digest.clone(),
        txid: summary.txid.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Pure result-shape models only; no signed artifact or native authority exists.
    #[test]
    fn private_observation_mapper_rejects_unverified_or_authority_shaped_summaries() {
        let summary = SignedResultSummary {
            result_id: format!("signed-{}", "12".repeat(32)),
            request_digest: "13".repeat(32),
            signed_candidate_digest: "14".repeat(32),
            exact_replay: true,
            historical_reconciliation: true,
            inspection: wholepact_protocol::authorization::SignatureInspection {
                verified_real_inputs: 1,
                required_real_inputs: 1,
                signatures_complete: true,
                exact_candidate_preserved: true,
                proof_verified: true,
                authorization_allowed: false,
                distribution_allowed: false,
                chain_validated: false,
            },
            transaction_extracted: false,
            authorization_allowed: false,
            distribution_allowed: false,
        };
        assert!(signed_observation(&summary).is_ok());
        for change in 0..6 {
            let mut bad = summary.clone();
            match change {
                0 => bad.historical_reconciliation = false,
                1 => bad.inspection.proof_verified = false,
                2 => bad.inspection.exact_candidate_preserved = false,
                3 => bad.inspection.chain_validated = true,
                4 => bad.authorization_allowed = true,
                _ => bad.distribution_allowed = true,
            };
            assert!(signed_observation(&bad).is_err());
        }
        let signed = signed_observation(&summary).unwrap();
        let tx = TransactionCheckpointSummary {
            checkpoint_id: format!("transaction-{}", "15".repeat(32)),
            signed_result_id: signed.result_id.clone(),
            transaction_digest: "16".repeat(32),
            txid: "17".repeat(32),
            exact_replay: true,
            cryptographic_transaction_verified: true,
            transaction_extracted: true,
            chain_validated: false,
            authorization_allowed: false,
            distribution_allowed: false,
            release_allowed: false,
        };
        assert!(transaction_observation(signed.clone(), &tx).is_ok());
        for change in 0..5 {
            let mut bad = tx.clone();
            match change {
                0 => bad.signed_result_id = "wrong".into(),
                1 => bad.cryptographic_transaction_verified = false,
                2 => bad.release_allowed = true,
                3 => bad.chain_validated = true,
                _ => bad.transaction_digest = "wrong".into(),
            };
            assert!(transaction_observation(signed.clone(), &bad).is_err());
        }
    }
}
