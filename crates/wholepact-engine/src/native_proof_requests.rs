//! Inert, exact client-to-native requests to refresh an existing proof-job cache.
//! No request, attempt, or cached result grants native consent or spending authority.
//! Completion is derived only from the original reconciliation command's durable
//! idempotency result, never from a caller flag or current cached job status.
use super::*;
use crate::native_requests::NativeRequestState;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProofReconcileRequest {
    pub candidate_id: String,
    pub job_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeProofRequest {
    principal_id: String,
    request_id: String,
    agreement_id: String,
    candidate_id: String,
    manifest_digest: String,
    job_id: String,
    receipt_storage_key: String,
    receipt_digest: String,
    scope_digest: String,
    coordination_request_digest: String,
    original_revision: u64,
    queued_revision: u64,
    attempt_revision: Option<u64>,
    state: NativeRequestState,
}

#[derive(Clone, Debug, Serialize)]
pub struct NativeProofRequestView {
    pub schema_version: u32,
    pub operation: &'static str,
    pub request_id: String,
    pub agreement_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub job_id: String,
    pub receipt_storage_key: String,
    pub receipt_digest: String,
    pub scope_digest: String,
    pub coordination_request_digest: String,
    pub original_revision: u64,
    pub queued_revision: u64,
    pub attempt_revision: Option<u64>,
    pub state: NativeRequestState,
    pub authorization_allowed: bool,
    pub result_status: &'static str,
    pub reconciliation_status: &'static str,
    pub reconciliation_operation_id: Option<String>,
}
impl NativeProofRequestView {
    /// Inert display identity for fresh native review before the atomic fence.
    pub fn reconciliation_key(&self) -> String {
        reconciliation_key(&self.request_id)
    }
}

/// Exact retained inputs, not serializable, a consent token, or a proof-run route.
pub struct NativeProofReconciliationAttempt {
    candidate_id: String,
    job_id: String,
    revision: u64,
    reconciliation_key: String,
    receipt_storage_key: String,
    receipt_digest: String,
    scope_digest: String,
    coordination_request_digest: String,
}
impl NativeProofReconciliationAttempt {
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn reconciliation_key(&self) -> &str {
        &self.reconciliation_key
    }
    pub fn receipt_storage_key(&self) -> &str {
        &self.receipt_storage_key
    }
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
    pub fn coordination_request_digest(&self) -> &str {
        &self.coordination_request_digest
    }
}

impl Engine {
    pub fn queue_native_proof_reconciliation(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeProofReconcileRequest,
    ) -> Result<NativeProofRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_proof_reconciliation",
            agreement,
            Some(revision),
            &request,
        )?;
        let request_id = hash_domain(
            b"wholepact:native-proof-request:v1\0",
            &json!({"principal": access.principal_id, "key": key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_proof_request(access, agreement, &request_id);
        }
        candidates::check_revision(&envelope, revision)?;
        if native_requests::total_requests(&envelope) >= native_requests::MAX_NATIVE_REQUESTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Native request history limit reached; preserve original requests",
            ));
        }
        // A new observation may follow a real exact reconciliation. An uncertain
        // attempt cannot be replaced, even if cached metadata happens to look done.
        for saved in envelope.native_proof_requests.values().filter(|saved| {
            saved.job_id == request.job_id && saved.state != NativeRequestState::Withdrawn
        }) {
            if self.cached_reconciliation(access, saved)?.is_none() {
                return Err(ApiError::new(
                    "INVALID_TRANSITION",
                    "This job has a queued or uncertain native reconciliation; inspect its original request",
                ));
            }
        }
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == request.candidate_id)
            .ok_or_else(not_found)?;
        // Reconciliation observes retained facts even after cancellation or expiry.
        // Current financial terms are deliberately not a prerequisite here.
        let (receipt_storage_key, receipt) = original_receipt(&envelope, access, &request)?;
        let saved = StoredNativeProofRequest {
            principal_id: access.principal_id.clone(),
            request_id: request_id.clone(),
            agreement_id: agreement.into(),
            candidate_id: candidate.candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            job_id: receipt.job_id.clone(),
            receipt_storage_key: receipt_storage_key.clone(),
            receipt_digest: receipt_digest(receipt)?,
            scope_digest: receipt.scope_digest.clone(),
            coordination_request_digest: receipt.coordination_request_digest.clone(),
            original_revision: revision,
            queued_revision: revision.checked_add(1).ok_or_else(internal)?,
            attempt_revision: None,
            state: NativeRequestState::Queued,
        };
        validate_binding(&envelope, &saved)?;
        if envelope
            .native_proof_requests
            .insert(request_id.clone(), saved)
            .is_some()
        {
            return Err(ApiError::new(
                "IDEMPOTENCY_CONFLICT",
                "Native proof request identity already exists",
            ));
        }
        self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_proof_reconciliation_requested",
        )?;
        self.native_proof_request(access, agreement, &request_id)
    }

    pub fn native_proof_request(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeProofRequestView> {
        let envelope = self.load(access, agreement)?;
        self.proof_request_view(access, owned(&envelope, access, request)?)
    }

    pub fn native_proof_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeProofRequestView>> {
        let envelope = self.load(access, agreement)?;
        envelope
            .native_proof_requests
            .values()
            .filter(|saved| saved.principal_id == access.principal_id)
            .map(|saved| self.proof_request_view(access, saved))
            .collect()
    }

    pub fn withdraw_native_proof_request(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: &str,
    ) -> Result<NativeProofRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_proof_request",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_proof_request(access, agreement, request);
        }
        candidates::check_revision(&envelope, revision)?;
        if owned(&envelope, access, request)?.state != NativeRequestState::Queued {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Only a never-started queued proof request can be withdrawn; an existing attempt remains unknown",
            ));
        }
        envelope
            .native_proof_requests
            .get_mut(request)
            .ok_or_else(not_found)?
            .state = NativeRequestState::Withdrawn;
        self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_proof_request_withdrawn",
        )?;
        self.native_proof_request(access, agreement, request)
    }

    /// Durable metadata fence only. HTTP must never route to this method.
    /// The caller still needs current exact InspectStatus consent at the real
    /// reconcile_candidate_proof_job call, with its attached original ProofJobStore.
    pub fn mark_native_proof_reconciliation_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeProofReconciliationAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let saved = owned(&envelope, access, request)?;
        if saved.state != NativeRequestState::Queued {
            return Err(closed_attempt());
        }
        let revision = saved.queued_revision;
        candidates::check_revision(&envelope, revision)?;
        validate_binding(&envelope, saved)?;
        let attempt = NativeProofReconciliationAttempt {
            candidate_id: saved.candidate_id.clone(),
            job_id: saved.job_id.clone(),
            revision: revision.checked_add(1).ok_or_else(internal)?,
            reconciliation_key: reconciliation_key(request),
            receipt_storage_key: saved.receipt_storage_key.clone(),
            receipt_digest: saved.receipt_digest.clone(),
            scope_digest: saved.scope_digest.clone(),
            coordination_request_digest: saved.coordination_request_digest.clone(),
        };
        let command = context(
            access,
            &format!("native-proof-attempt-{request}"),
            "native_proof_reconciliation_attempt_started",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        let saved = envelope
            .native_proof_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(attempt.revision);
        let committed = self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_proof_reconciliation_attempt_started",
        )?;
        if committed.replayed {
            return Err(closed_attempt());
        }
        Ok(attempt)
    }

    /// Recover only the immutable inputs of an already-started metadata operation.
    /// No fence is reset or minted again. The existing reconciliation consumer
    /// still requires actual encrypted-job InspectStatus consent on every call.
    /// Absent exact completion permits only the original unchanged revision.
    pub fn original_native_proof_reconciliation_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeProofReconciliationAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let envelope = self.load(access, agreement)?;
        let saved = owned(&envelope, access, request)?;
        if saved.state != NativeRequestState::AttemptStarted {
            return Err(closed_attempt());
        }
        validate_binding(&envelope, saved)?;
        let revision = saved.attempt_revision.ok_or_else(inconsistent)?;
        if self.cached_reconciliation(access, saved)?.is_none() {
            candidates::check_revision(&envelope, revision)?;
        }
        Ok(NativeProofReconciliationAttempt {
            candidate_id: saved.candidate_id.clone(),
            job_id: saved.job_id.clone(),
            revision,
            reconciliation_key: reconciliation_key(request),
            receipt_storage_key: saved.receipt_storage_key.clone(),
            receipt_digest: saved.receipt_digest.clone(),
            scope_digest: saved.scope_digest.clone(),
            coordination_request_digest: saved.coordination_request_digest.clone(),
        })
    }

    fn proof_request_view(
        &self,
        access: &Access,
        saved: &StoredNativeProofRequest,
    ) -> Result<NativeProofRequestView> {
        let completion = self.cached_reconciliation(access, saved)?;
        Ok(NativeProofRequestView {
            schema_version: 1,
            operation: "proof_reconcile",
            request_id: saved.request_id.clone(),
            agreement_id: saved.agreement_id.clone(),
            candidate_id: saved.candidate_id.clone(),
            manifest_digest: saved.manifest_digest.clone(),
            job_id: saved.job_id.clone(),
            receipt_storage_key: saved.receipt_storage_key.clone(),
            receipt_digest: saved.receipt_digest.clone(),
            scope_digest: saved.scope_digest.clone(),
            coordination_request_digest: saved.coordination_request_digest.clone(),
            original_revision: saved.original_revision,
            queued_revision: saved.queued_revision,
            attempt_revision: saved.attempt_revision,
            state: saved.state,
            authorization_allowed: false,
            result_status: "unknown_not_financial_evidence",
            reconciliation_status: if completion.is_some() {
                "cached_reconciliation_recorded"
            } else if saved.state == NativeRequestState::AttemptStarted {
                "unknown"
            } else {
                "not_attempted"
            },
            reconciliation_operation_id: completion,
        })
    }

    fn cached_reconciliation(
        &self,
        access: &Access,
        saved: &StoredNativeProofRequest,
    ) -> Result<Option<String>> {
        let Some(revision) = saved.attempt_revision else {
            return Ok(None);
        };
        // Keep this byte-identical to proof_jobs::record_proof_job's existing
        // reconcile branch. Never derive completion from candidate.proof_jobs.
        let command = reconciliation_command(
            access,
            &reconciliation_key(&saved.request_id),
            &saved.candidate_id,
            revision,
            &saved.job_id,
        )?;
        let Some(result) = self.store.find_replay(&command).map_err(store_error)? else {
            return Ok(None);
        };
        let historical = decode(&result.record)?;
        if result.record.id != saved.agreement_id
            || result.record.revision != revision.checked_add(1).ok_or_else(internal)?
            || !access.sees(&result.record.id, &historical.owner_client_id)
            || historical.native_proof_requests.get(&saved.request_id) != Some(saved)
            || !historical.view.candidates.iter().any(|candidate| {
                candidate.candidate_id == saved.candidate_id
                    && candidate.manifest_digest == saved.manifest_digest
                    && candidate.proof_jobs.iter().any(|job| {
                        job.job_id == saved.job_id
                            && job.scope_digest == saved.scope_digest
                            && job.coordination_request_digest == saved.coordination_request_digest
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
        if operation.principal_id != saved.principal_id
            || operation.resource_id != saved.agreement_id
            || operation.kind != "candidate_proof_checkpoint_reconciled"
            || operation.status != "succeeded"
        {
            return Err(inconsistent());
        }
        Ok(Some(result.operation_id))
    }
}

fn reconciliation_command(
    access: &Access,
    key: &str,
    candidate: &str,
    revision: u64,
    job: &str,
) -> Result<CommandContext> {
    context(
        access,
        key,
        "reconcile_candidate_proof_job",
        candidate,
        Some(revision),
        &json!({"job_id":job}),
    )
}
fn reconciliation_key(request: &str) -> String {
    format!("native-proof-reconcile-{request}")
}
fn receipt_digest(receipt: &candidates::CheckpointReceipt) -> Result<String> {
    hash_domain(
        b"wholepact:native-proof-request-receipt:v1\0",
        &serde_json::to_value(receipt).map_err(|_| internal())?,
    )
}
fn original_receipt<'a>(
    envelope: &'a Envelope,
    access: &Access,
    request: &NativeProofReconcileRequest,
) -> Result<(&'a String, &'a candidates::CheckpointReceipt)> {
    let mut matches = envelope.checkpoint_receipts.iter().filter(|(_, receipt)| {
        receipt.principal_id == access.principal_id
            && receipt.candidate_id == request.candidate_id
            && receipt.job_id == request.job_id
    });
    let found = matches.next().ok_or_else(|| {
        ApiError::new(
            "MISSING_EVIDENCE",
            "No original owner/candidate constructor receipt exists for this proof job",
        )
    })?;
    if matches.next().is_some() {
        return Err(inconsistent());
    }
    Ok(found)
}
fn owned<'a>(
    envelope: &'a Envelope,
    access: &Access,
    request: &str,
) -> Result<&'a StoredNativeProofRequest> {
    envelope
        .native_proof_requests
        .get(request)
        .filter(|saved| saved.principal_id == access.principal_id)
        .ok_or_else(not_found)
}
fn validate_binding(envelope: &Envelope, saved: &StoredNativeProofRequest) -> Result<()> {
    let receipt = envelope
        .checkpoint_receipts
        .get(&saved.receipt_storage_key)
        .ok_or_else(inconsistent)?;
    if !candidates::valid_checkpoint_receipt_index(&saved.receipt_storage_key, &saved.job_id)
        || saved.receipt_digest != receipt_digest(receipt)?
        || receipt.principal_id != saved.principal_id
        || receipt.candidate_id != saved.candidate_id
        || receipt.manifest_digest != saved.manifest_digest
        || receipt.job_id != saved.job_id
        || receipt.scope_digest != saved.scope_digest
        || receipt.coordination_request_digest != saved.coordination_request_digest
        || receipt.prepared_revision > saved.original_revision
        || receipt.prepared_revision == 0
        || !envelope.view.candidates.iter().any(|candidate| {
            candidate.candidate_id == saved.candidate_id
                && candidate.manifest_digest == saved.manifest_digest
        })
    {
        return Err(inconsistent());
    }
    Ok(())
}
pub(crate) fn validate_stored(envelope: &Envelope) -> Result<()> {
    for (key, saved) in &envelope.native_proof_requests {
        if key != &saved.request_id
            || !canonical_digest(key)
            || saved.principal_id.is_empty()
            || saved.principal_id.len() > 128
            || saved.agreement_id != envelope.view.agreement.agreement_id
            || !canonical_digest(&saved.receipt_digest)
            || !canonical_digest(&saved.scope_digest)
            || !canonical_digest(&saved.coordination_request_digest)
            || saved.original_revision.checked_add(1) != Some(saved.queued_revision)
            || saved.queued_revision > envelope.view.revision
            || match saved.state {
                NativeRequestState::Queued | NativeRequestState::Withdrawn => {
                    saved.attempt_revision.is_some()
                }
                NativeRequestState::AttemptStarted => {
                    saved.queued_revision.checked_add(1) != saved.attempt_revision
                        || saved
                            .attempt_revision
                            .is_some_and(|revision| revision > envelope.view.revision)
                }
            }
        {
            return Err(inconsistent());
        }
        validate_binding(envelope, saved)?;
    }
    Ok(())
}
fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn inconsistent() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Native proof request or exact constructor receipt binding changed; preserve the original journals",
    )
}
fn closed_attempt() -> ApiError {
    ApiError::new(
        "NATIVE_ATTEMPT_ALREADY_CLOSED",
        "The native proof request was already attempted or withdrawn; inspect the original exact reconciliation",
    )
}

#[cfg(test)]
mod tests;
