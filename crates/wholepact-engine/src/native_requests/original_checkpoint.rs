//! Original constructor evidence only. Missing durable evidence never proves
//! that signer disclosure, wallet import, scan or randomized construction did not occur.
use super::*;

#[derive(Debug, Serialize)]
pub struct NativeConstructionCheckpointView {
    pub request: NativeRequestView,
    pub construction_key: String,
    pub expected_job_id: String,
    pub receipt_storage_key: String,
    pub receipt_digest: Option<String>,
    pub scope_digest: Option<String>,
    pub coordination_request_digest: Option<String>,
    pub checkpoint_evidence: &'static str,
    pub original_operation_id: Option<String>,
    pub private_work_before_receipt: &'static str,
    pub retry_construction_allowed: bool,
}
impl Engine {
    /// Retained engine evidence only, not a private-journal absence claim.
    /// Input digests are read from the original immutable receipt, never supplied
    /// by clients and never used to reconstruct or issue a constructor command.
    pub fn original_native_construction_checkpoint(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeConstructionCheckpointView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let envelope = self.load(access, agreement)?;
        let saved = owned(&envelope, access, request)?;
        if saved.state != NativeRequestState::AttemptStarted {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Inspect only an original started construction request",
            ));
        }
        let construction_key = format!("native-construction-{request}");
        let receipt_storage_key = hash_domain(
            b"wholepact:checkpoint-receipt:v1\0",
            &json!({"principal":access.principal_id,"key":construction_key}),
        )?;
        let expected_job_id =
            wholepact_proof_jobs::job_id_for_key(&access.principal_id, &construction_key)
                .map_err(|_| internal())?;
        let mut view = NativeConstructionCheckpointView {
            request: saved.view(),
            construction_key,
            expected_job_id,
            receipt_storage_key,
            receipt_digest: None,
            scope_digest: None,
            coordination_request_digest: None,
            checkpoint_evidence: "no_constructor_receipt_observed",
            original_operation_id: None,
            private_work_before_receipt: "unknown",
            retry_construction_allowed: false,
        };
        let Some(receipt) = envelope.checkpoint_receipts.get(&view.receipt_storage_key) else {
            return Ok(view);
        };
        if receipt.principal_id != access.principal_id
            || receipt.candidate_id != saved.candidate_id
            || receipt.manifest_digest != saved.manifest_digest
            || receipt.job_id != view.expected_job_id
            || saved
                .attempt_revision
                .and_then(|revision| revision.checked_add(1))
                != Some(receipt.prepared_revision)
        {
            return Err(inconsistent());
        }
        let receipt_value = serde_json::to_value(receipt).map_err(|_| internal())?;
        view.receipt_digest = Some(hash_domain(
            b"wholepact:native-construction-receipt:v1\0",
            &receipt_value,
        )?);
        view.scope_digest = Some(receipt.scope_digest.clone());
        view.coordination_request_digest = Some(receipt.coordination_request_digest.clone());
        view.checkpoint_evidence = "constructor_receipt_private_checkpoint_unconfirmed";
        let context = CommandContext {
            principal_id: access.principal_id.clone(),
            idempotency_key: view.construction_key.clone(),
            request_digest: receipt.coordination_request_digest.clone(),
        };
        let Some(result) = self.store.find_replay(&context).map_err(store_error)? else {
            return Ok(view);
        };
        let historical = decode(&result.record)?;
        if result.record.id != agreement
            || result.record.revision
                != receipt
                    .prepared_revision
                    .checked_add(1)
                    .ok_or_else(internal)?
            || historical.native_requests.get(request) != Some(saved)
            || historical
                .checkpoint_receipts
                .get(&view.receipt_storage_key)
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| internal())?
                != Some(receipt_value)
            || !historical.view.candidates.iter().any(|candidate| {
                candidate.candidate_id == saved.candidate_id
                    && candidate.manifest_digest == saved.manifest_digest
                    && candidate.proof_jobs.iter().any(|job| {
                        job.job_id == view.expected_job_id
                            && job.scope_digest == receipt.scope_digest
                            && job.coordination_request_digest
                                == receipt.coordination_request_digest
                            && job.input_digest == receipt.artifact_digest
                            && job.review_binding == receipt.review_binding
                            && job.effects_commitment == receipt.effects_commitment
                    })
            })
        {
            return Err(inconsistent());
        }
        let operation = self
            .store
            .get_operation(&result.operation_id)
            .map_err(store_error)?
            .ok_or_else(inconsistent)?;
        if operation.principal_id != access.principal_id
            || operation.resource_id != agreement
            || !matches!(
                operation.kind.as_str(),
                "candidate_private_checkpoint_created" | "candidate_checkpoint_link_recovered"
            )
            || operation.status != "succeeded"
        {
            return Err(inconsistent());
        }
        view.original_operation_id = Some(result.operation_id);
        view.checkpoint_evidence = "exact_original_checkpoint_operation_recorded";
        Ok(view)
    }
}
fn inconsistent() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Original construction evidence is inconsistent; preserve both journals",
    )
}
