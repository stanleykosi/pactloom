//! Inert proved-artifact review/signature-intake handoffs to genuine native owners.
//! No request, attempt, or cached result grants native consent or spending authority.
//! Attempt status never establishes review, signatures or financial completion.
use super::*;
use crate::native_requests::NativeRequestState;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactHandoffKind {
    SignerReview,
    SignatureIntake,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactHandoffRequest {
    pub kind: ArtifactHandoffKind,
    pub candidate_id: String,
    pub job_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeArtifactHandoffRequest {
    kind: ArtifactHandoffKind,
    proved_artifact_digest: String,
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
pub struct NativeArtifactHandoffRequestView {
    pub kind: ArtifactHandoffKind,
    pub proved_artifact_digest: String,
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
    pub handoff_status: &'static str,
}
impl NativeArtifactHandoffRequestView {
    /// Inert display identity for fresh native review before the atomic fence.
    pub fn handoff_key(&self) -> String {
        handoff_key(&self.request_id)
    }
}

/// Exact retained inputs only. The actual proof store and fresh native consent remain required.
pub struct NativeArtifactHandoffAttempt {
    manifest_digest: String,
    kind: ArtifactHandoffKind,
    proved_artifact_digest: String,
    candidate_id: String,
    job_id: String,
    revision: u64,
    handoff_key: String,
    receipt_storage_key: String,
    receipt_digest: String,
    scope_digest: String,
    coordination_request_digest: String,
}
impl NativeArtifactHandoffAttempt {
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn kind(&self) -> ArtifactHandoffKind {
        self.kind
    }
    pub fn proved_artifact_digest(&self) -> &str {
        &self.proved_artifact_digest
    }
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn handoff_key(&self) -> &str {
        &self.handoff_key
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
    pub fn queue_native_artifact_handoff(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeArtifactHandoffRequest,
    ) -> Result<NativeArtifactHandoffRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_artifact_handoff",
            agreement,
            Some(revision),
            &request,
        )?;
        let request_id = hash_domain(
            b"wholepact:native-artifact-handoff-request:v1\0",
            &json!({"principal": access.principal_id, "key": key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_artifact_handoff_request(access, agreement, &request_id);
        }
        candidates::check_revision(&envelope, revision)?;
        if native_requests::total_requests(&envelope) >= native_requests::MAX_NATIVE_REQUESTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Native request history limit reached; preserve original requests",
            ));
        }
        // Never replace a non-withdrawn artifact handoff request, even after completion.
        // Inspect/reconcile the original job instead of generating a new handoff identity.
        if envelope
            .native_artifact_handoff_requests
            .values()
            .any(|saved| {
                saved.job_id == request.job_id
                    && saved.kind == request.kind
                    && saved.state != NativeRequestState::Withdrawn
            })
        {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "This job already has a queued or attempted artifact handoff request; inspect the original job",
            ));
        }

        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == request.candidate_id)
            .ok_or_else(not_found)?;
        // These handoffs inspect/disclose already-proved bytes or retain existing
        // signatures. Historical cancellation is not evidence that artifacts vanished.
        // Actual owner permissions remain fresh; no new spending is authorized here.
        let cached = candidate
            .proof_jobs
            .iter()
            .find(|job| job.job_id == request.job_id)
            .ok_or_else(|| {
                ApiError::new(
                    "MISSING_EVIDENCE",
                    "Inspect and reconcile the original proved checkpoint first",
                )
            })?;
        let proved_artifact_digest = cached_proved_digest(cached)?.to_owned();
        let (receipt_storage_key, receipt) = original_receipt(&envelope, access, &request)?;
        let saved = StoredNativeArtifactHandoffRequest {
            kind: request.kind,
            proved_artifact_digest,
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
            .native_artifact_handoff_requests
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
            "native_artifact_handoff_requested",
        )?;
        self.native_artifact_handoff_request(access, agreement, &request_id)
    }

    pub fn native_artifact_handoff_request(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeArtifactHandoffRequestView> {
        let envelope = self.load(access, agreement)?;
        self.artifact_handoff_request_view(access, owned(&envelope, access, request)?)
    }

    pub fn native_artifact_handoff_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeArtifactHandoffRequestView>> {
        let envelope = self.load(access, agreement)?;
        envelope
            .native_artifact_handoff_requests
            .values()
            .filter(|saved| saved.principal_id == access.principal_id)
            .map(|saved| self.artifact_handoff_request_view(access, saved))
            .collect()
    }

    pub fn withdraw_native_artifact_handoff_request(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: &str,
    ) -> Result<NativeArtifactHandoffRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_artifact_handoff_request",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_artifact_handoff_request(access, agreement, request);
        }
        candidates::check_revision(&envelope, revision)?;
        if owned(&envelope, access, request)?.state != NativeRequestState::Queued {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Only a never-started queued proof request can be withdrawn; an existing attempt remains unknown",
            ));
        }
        envelope
            .native_artifact_handoff_requests
            .get_mut(request)
            .ok_or_else(not_found)?
            .state = NativeRequestState::Withdrawn;
        self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_artifact_handoff_request_withdrawn",
        )?;
        self.native_artifact_handoff_request(access, agreement, request)
    }

    /// Durable metadata fence only. HTTP must never route to this method.
    /// The caller still needs current exact read/disclosure and independent signer consent at the real
    /// native owner. This attempt is not approval, proof or a signature.
    pub fn mark_native_artifact_handoff_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeArtifactHandoffAttempt> {
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
        let attempt = NativeArtifactHandoffAttempt {
            manifest_digest: saved.manifest_digest.clone(),
            kind: saved.kind,
            proved_artifact_digest: saved.proved_artifact_digest.clone(),
            candidate_id: saved.candidate_id.clone(),
            job_id: saved.job_id.clone(),
            revision: revision.checked_add(1).ok_or_else(internal)?,
            handoff_key: handoff_key(request),
            receipt_storage_key: saved.receipt_storage_key.clone(),
            receipt_digest: saved.receipt_digest.clone(),
            scope_digest: saved.scope_digest.clone(),
            coordination_request_digest: saved.coordination_request_digest.clone(),
        };
        let command = context(
            access,
            &format!("native-artifact-handoff-attempt-{request}"),
            "native_artifact_handoff_attempt_started",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        let saved = envelope
            .native_artifact_handoff_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(attempt.revision);
        let committed = self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_artifact_handoff_attempt_started",
        )?;
        if committed.replayed {
            return Err(closed_attempt());
        }
        Ok(attempt)
    }

    fn artifact_handoff_request_view(
        &self,
        access: &Access,
        saved: &StoredNativeArtifactHandoffRequest,
    ) -> Result<NativeArtifactHandoffRequestView> {
        let _ = access;
        Ok(NativeArtifactHandoffRequestView {
            kind: saved.kind,
            proved_artifact_digest: saved.proved_artifact_digest.clone(),
            schema_version: 1,
            operation: "artifact_handoff",
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
            handoff_status: if saved.state == NativeRequestState::AttemptStarted {
                "attempted_outcome_unknown"
            } else {
                "not_attempted"
            },
        })
    }
}

fn handoff_key(request: &str) -> String {
    format!("native-artifact-handoff-{request}")
}
fn receipt_digest(receipt: &candidates::CheckpointReceipt) -> Result<String> {
    hash_domain(
        b"wholepact:native-artifact-handoff-request-receipt:v1\0",
        &serde_json::to_value(receipt).map_err(|_| internal())?,
    )
}
fn cached_proved_digest(job: &candidates::CandidateProofJob) -> Result<&str> {
    if job.state != "succeeded" || !job.proof_verified {
        return Err(ApiError::new(
            "INVALID_TRANSITION",
            "The original proved checkpoint must be reconciled before requesting this handoff",
        ));
    }
    job.result_digest
        .as_deref()
        .filter(|value| canonical_digest(value))
        .ok_or_else(inconsistent)
}

fn original_receipt<'a>(
    envelope: &'a Envelope,
    access: &Access,
    request: &NativeArtifactHandoffRequest,
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
) -> Result<&'a StoredNativeArtifactHandoffRequest> {
    envelope
        .native_artifact_handoff_requests
        .get(request)
        .filter(|saved| saved.principal_id == access.principal_id)
        .ok_or_else(not_found)
}
fn validate_binding(envelope: &Envelope, saved: &StoredNativeArtifactHandoffRequest) -> Result<()> {
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
    for (key, saved) in &envelope.native_artifact_handoff_requests {
        if key != &saved.request_id
            || !canonical_digest(key)
            || !canonical_digest(&saved.proved_artifact_digest)
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
        "The native artifact handoff was already attempted or withdrawn; inspect the original owners and retained artifacts",
    )
}

// Exact historical source only; it never grants native result access.
pub(super) fn settlement_source(
    envelope: &Envelope,
    principal: &str,
    request: &str,
) -> Result<crate::native_settlement_requests::SettlementSource> {
    let saved = envelope
        .native_artifact_handoff_requests
        .get(request)
        .filter(|saved| saved.principal_id == principal)
        .ok_or_else(not_found)?;
    validate_binding(envelope, saved)?;
    if saved.kind != ArtifactHandoffKind::SignatureIntake
        || saved.state != NativeRequestState::AttemptStarted
    {
        return Err(ApiError::new(
            "MISSING_EVIDENCE",
            "Select the original attempted signature-intake request",
        ));
    }
    Ok(crate::native_settlement_requests::SettlementSource {
        intake_request_id: saved.request_id.clone(),
        candidate_id: saved.candidate_id.clone(),
        manifest_digest: saved.manifest_digest.clone(),
        job_id: saved.job_id.clone(),
        signature_retention_key: handoff_key(&saved.request_id),
        proved_artifact_digest: saved.proved_artifact_digest.clone(),
        receipt_storage_key: saved.receipt_storage_key.clone(),
        receipt_digest: saved.receipt_digest.clone(),
        scope_digest: saved.scope_digest.clone(),
        coordination_request_digest: saved.coordination_request_digest.clone(),
    })
}

#[cfg(test)]
mod tests;
