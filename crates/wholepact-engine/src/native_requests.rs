//! Inert client-to-native handoff metadata. No method here grants permission to
//! disclose, construct, prove, sign or submit. A real native owner revalidates
//! current scope and obtains every existing private-operation lease separately.
use super::*;
#[cfg(feature = "local-proof-jobs")]
mod original_checkpoint;
#[cfg(feature = "local-proof-jobs")]
pub use original_checkpoint::NativeConstructionCheckpointView;

pub const MAX_NATIVE_REQUESTS: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConstructionRequest {
    pub candidate_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRequestState {
    Queued,
    Withdrawn,
    /// The native owner may have performed private work. No result is implied.
    AttemptStarted,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeRequest {
    principal_id: String,
    request_id: String,
    agreement_id: String,
    candidate_id: String,
    manifest_digest: String,
    original_revision: u64,
    queued_revision: u64,
    attempt_revision: Option<u64>,
    state: NativeRequestState,
}

#[derive(Clone, Debug, Serialize)]
pub struct NativeRequestView {
    pub schema_version: u32,
    pub request_id: String,
    pub agreement_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub original_revision: u64,
    pub queued_revision: u64,
    pub attempt_revision: Option<u64>,
    pub state: NativeRequestState,
    pub authorization_allowed: bool,
    pub result_status: &'static str,
}

/// Exact inputs for a native UI to review. This value is inert metadata, never a
/// constructor lease. It deliberately cannot carry a caller-supplied approval.
pub struct NativeConstructionAttempt {
    candidate_id: String,
    revision: u64,
    construction_key: String,
}
impl NativeConstructionAttempt {
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn construction_key(&self) -> &str {
        &self.construction_key
    }
}

impl StoredNativeRequest {
    fn view(&self) -> NativeRequestView {
        NativeRequestView {
            schema_version: 1,
            request_id: self.request_id.clone(),
            agreement_id: self.agreement_id.clone(),
            candidate_id: self.candidate_id.clone(),
            manifest_digest: self.manifest_digest.clone(),
            original_revision: self.original_revision,
            queued_revision: self.queued_revision,
            attempt_revision: self.attempt_revision,
            state: self.state,
            authorization_allowed: false,
            result_status: "unknown_not_financial_evidence",
        }
    }
}

impl Engine {
    pub fn queue_native_construction(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeConstructionRequest,
    ) -> Result<NativeRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        // Scope is checked before idempotency lookup, including exact retries.
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_construction",
            agreement,
            Some(revision),
            &request,
        )?;
        let request_id = hash_domain(
            b"wholepact:native-request:v1\0",
            &json!({"principal": access.principal_id, "key": key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            let current = self.load(access, agreement)?;
            return owned(&current, access, &request_id).map(StoredNativeRequest::view);
        }
        candidates::check_revision(&envelope, revision)?;
        if total_requests(&envelope) >= MAX_NATIVE_REQUESTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Native request history limit reached; preserve original requests",
            ));
        }
        if envelope.native_requests.values().any(|saved| {
            saved.candidate_id == request.candidate_id
                && saved.state != NativeRequestState::Withdrawn
        }) {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "This candidate already has a queued or possibly attempted native request; inspect its original request",
            ));
        }
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == request.candidate_id)
            .ok_or_else(not_found)?;
        candidates::check_current_terms(&envelope.view, &candidate.proposal.manifest)?;
        let saved = StoredNativeRequest {
            principal_id: access.principal_id.clone(),
            request_id: request_id.clone(),
            agreement_id: agreement.into(),
            candidate_id: candidate.candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            original_revision: revision,
            queued_revision: revision.checked_add(1).ok_or_else(internal)?,
            attempt_revision: None,
            state: NativeRequestState::Queued,
        };
        let view = saved.view();
        if envelope.native_requests.insert(request_id, saved).is_some() {
            return Err(ApiError::new(
                "IDEMPOTENCY_CONFLICT",
                "Native request identity already exists",
            ));
        }
        self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_construction_requested",
        )?;
        Ok(view)
    }

    pub fn native_request(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeRequestView> {
        let envelope = self.load(access, agreement)?;
        Ok(owned(&envelope, access, request)?.view())
    }

    pub fn native_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeRequestView>> {
        let envelope = self.load(access, agreement)?;
        Ok(envelope
            .native_requests
            .values()
            .filter(|request| request.principal_id == access.principal_id)
            .map(StoredNativeRequest::view)
            .collect())
    }

    pub fn withdraw_native_request(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: &str,
    ) -> Result<NativeRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_request",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        if self.replay(access, &command)?.is_some() {
            let current = self.load(access, agreement)?;
            return owned(&current, access, request).map(StoredNativeRequest::view);
        }
        candidates::check_revision(&envelope, revision)?;
        if owned(&envelope, access, request)?.state != NativeRequestState::Queued {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Only a never-started queued request can be withdrawn; existing artifacts remain possible",
            ));
        }
        let saved = envelope
            .native_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::Withdrawn;
        let view = saved.view();
        self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_request_withdrawn",
        )?;
        Ok(view)
    }

    /// Durable execution fence only. Public embedded callers cannot obtain any
    /// financial lease through it. HTTP must never route to this method.
    pub fn mark_native_construction_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeConstructionAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let saved = owned(&envelope, access, request)?;
        if saved.state != NativeRequestState::Queued {
            return Err(ApiError::new(
                "NATIVE_ATTEMPT_ALREADY_CLOSED",
                "Do not rerun an attempted request; inspect its original key under fresh native review",
            ));
        }
        let revision = saved.queued_revision;
        candidates::check_revision(&envelope, revision)?;
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == saved.candidate_id)
            .ok_or_else(not_found)?;
        candidates::check_current_terms(&envelope.view, &candidate.proposal.manifest)?;
        if candidate.manifest_digest != saved.manifest_digest {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Native request candidate binding changed",
            ));
        }
        let attempt = NativeConstructionAttempt {
            candidate_id: saved.candidate_id.clone(),
            revision: revision.checked_add(1).ok_or_else(internal)?,
            construction_key: format!("native-construction-{request}"),
        };
        let command = context(
            access,
            &format!("native-attempt-{request}"),
            "native_construction_attempt_started",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        let saved = envelope
            .native_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(attempt.revision);
        let committed = self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_construction_attempt_started",
        )?;
        // Two callers may have observed Queued before the first transaction.
        // Store replay is durable metadata, never a second execution permit.
        if committed.replayed {
            return Err(ApiError::new(
                "NATIVE_ATTEMPT_ALREADY_CLOSED",
                "The native attempt was already committed; do not execute a replay",
            ));
        }
        Ok(attempt)
    }
}

fn owned<'a>(
    envelope: &'a Envelope,
    access: &Access,
    request: &str,
) -> Result<&'a StoredNativeRequest> {
    let saved = envelope
        .native_requests
        .get(request)
        .ok_or_else(not_found)?;
    if saved.principal_id != access.principal_id {
        return Err(not_found());
    }
    Ok(saved)
}

pub(crate) fn total_requests(envelope: &Envelope) -> usize {
    envelope
        .native_requests
        .len()
        .saturating_add(envelope.native_proof_requests.len())
        .saturating_add(envelope.native_proof_execution_requests.len())
        .saturating_add(envelope.native_artifact_handoff_requests.len())
        .saturating_add(envelope.native_settlement_requests.len())
        .saturating_add(envelope.native_dispatch_requests.len())
        .saturating_add(envelope.native_reconciliation_requests.len())
        .saturating_add(envelope.native_account_inspection_requests.len())
}

pub(crate) fn validate_stored(envelope: &Envelope) -> Result<()> {
    if total_requests(envelope) > MAX_NATIVE_REQUESTS {
        return Err(internal());
    }
    for (key, saved) in &envelope.native_requests {
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == saved.candidate_id);
        if key != &saved.request_id
            || key.len() != 64
            || !key.bytes().all(|b| b.is_ascii_hexdigit())
            || saved.principal_id.is_empty()
            || saved.principal_id.len() > 128
            || saved.agreement_id != envelope.view.agreement.agreement_id
            || saved.original_revision.checked_add(1) != Some(saved.queued_revision)
            || saved.queued_revision > envelope.view.revision
            || !candidate.is_some_and(|c| c.manifest_digest == saved.manifest_digest)
            || match saved.state {
                NativeRequestState::Queued | NativeRequestState::Withdrawn => {
                    saved.attempt_revision.is_some()
                }
                NativeRequestState::AttemptStarted => {
                    saved.queued_revision.checked_add(1) != saved.attempt_revision
                        || saved
                            .attempt_revision
                            .is_some_and(|r| r > envelope.view.revision)
                }
            }
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Native request history is inconsistent; preserve the original journal",
            ));
        }
    }
    Ok(())
}
