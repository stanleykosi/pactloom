//! Inert owner-scoped requests. HTTP can queue/read/withdraw only. A real
//! native signer supplies the first immutable historical result. Started but
//! uncommitted requests stay unknown permanently; status never re-runs a read.
use super::*;
use crate::native_requests::{MAX_NATIVE_REQUESTS, NativeRequestState};
pub use wholepact_core::owner_inspection::{OwnerInspectionRequest, OwnerInspectionSnapshot};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAccountInspectionRequest {
    pub candidate_id: String,
    pub participant_id: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeAccountInspectionRequest {
    request: OwnerInspectionRequest,
    expected_account_id: String,
    original_revision: u64,
    queued_revision: u64,
    attempt_revision: Option<u64>,
    state: NativeRequestState,
    result: Option<OwnerInspectionSnapshot>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeAccountInspectionRequestView {
    pub schema_version: u32,
    pub operation: &'static str,
    pub request: OwnerInspectionRequest,
    pub original_revision: u64,
    pub queued_revision: u64,
    pub attempt_revision: Option<u64>,
    pub state: NativeRequestState,
    pub result_status: &'static str,
    pub authorization_allowed: bool,
    pub result: Option<OwnerInspectionSnapshot>,
}
impl StoredNativeAccountInspectionRequest {
    fn view(&self) -> NativeAccountInspectionRequestView {
        NativeAccountInspectionRequestView {
            schema_version: 1,
            operation: "owner_account_inspection",
            request: self.request.clone(),
            original_revision: self.original_revision,
            queued_revision: self.queued_revision,
            attempt_revision: self.attempt_revision,
            state: self.state,
            result_status: if self.result.is_some() {
                "historical_native_approved_metadata"
            } else {
                "unknown_no_committed_result"
            },
            authorization_allowed: false,
            result: self.result.clone(),
        }
    }
}
/// Inert first-attempt marker; does not contain or grant native authority.
pub struct NativeAccountInspectionAttempt {
    saved: StoredNativeAccountInspectionRequest,
}
impl NativeAccountInspectionAttempt {
    pub fn request(&self) -> &OwnerInspectionRequest {
        &self.saved.request
    }
    pub fn expected_account_id(&self) -> &str {
        &self.saved.expected_account_id
    }
}
impl Engine {
    pub fn queue_native_account_inspection(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeAccountInspectionRequest,
    ) -> Result<NativeAccountInspectionRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_account_inspection",
            agreement,
            Some(revision),
            &request,
        )?;
        let id = hash_domain(
            b"wholepact:native-account-inspection:v1\0",
            &json!({"principal":access.principal_id,"key":key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_account_inspection_request(access, agreement, &id);
        }
        candidates::check_revision(&e, revision)?;
        if native_requests::total_requests(&e) >= MAX_NATIVE_REQUESTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Native request history is full; preserve original requests",
            ));
        }
        if e.native_account_inspection_requests.values().any(|saved| {
            saved.request.principal_id == access.principal_id
                && saved.request.candidate_id == request.candidate_id
                && saved.request.participant_id == request.participant_id
                && saved.state == NativeRequestState::Queued
        }) {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "An identical scoped inspection is already queued; preserve or withdraw that original request",
            ));
        }
        let candidate = e
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == request.candidate_id)
            .ok_or_else(not_found)?;
        let participant = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .find(|p| p.participant_id == request.participant_id)
            .ok_or_else(not_found)?;
        let saved = StoredNativeAccountInspectionRequest {
            request: OwnerInspectionRequest {
                request_id: id.clone(),
                principal_id: access.principal_id.clone(),
                agreement_id: agreement.into(),
                candidate_id: request.candidate_id,
                participant_id: request.participant_id,
                manifest_digest: candidate.manifest_digest.clone(),
            },
            expected_account_id: participant.account_id.clone(),
            original_revision: revision,
            queued_revision: revision.checked_add(1).ok_or_else(internal)?,
            attempt_revision: None,
            state: NativeRequestState::Queued,
            result: None,
        };
        if !saved.request.validate() {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "Invalid native inspection scope",
            ));
        }
        let view = saved.view();
        if e.native_account_inspection_requests
            .insert(id, saved)
            .is_some()
        {
            return Err(inconsistent());
        }
        self.commit(
            &command,
            agreement,
            revision,
            e,
            "native_account_inspection_requested",
        )?;
        Ok(view)
    }
    pub fn native_account_inspection_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeAccountInspectionRequestView>> {
        let e = self.load(access, agreement)?;
        Ok(e.native_account_inspection_requests
            .values()
            .filter(|s| s.request.principal_id == access.principal_id)
            .map(StoredNativeAccountInspectionRequest::view)
            .collect())
    }
    pub fn native_account_inspection_request(
        &self,
        access: &Access,
        agreement: &str,
        id: &str,
    ) -> Result<NativeAccountInspectionRequestView> {
        let e = self.load(access, agreement)?;
        Ok(owned(&e, access, id)?.view())
    }
    pub fn withdraw_native_account_inspection(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        id: &str,
    ) -> Result<NativeAccountInspectionRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_account_inspection",
            agreement,
            Some(revision),
            &json!({"request_id":id}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_account_inspection_request(access, agreement, id);
        }
        candidates::check_revision(&e, revision)?;
        if owned(&e, access, id)?.state != NativeRequestState::Queued {
            return Err(closed());
        }
        let saved = e
            .native_account_inspection_requests
            .get_mut(id)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::Withdrawn;
        let view = saved.view();
        self.commit(
            &command,
            agreement,
            revision,
            e,
            "native_account_inspection_withdrawn",
        )?;
        Ok(view)
    }
    /// Not routed by HTTP. The native host must stop/drain the service first.
    pub fn mark_native_account_inspection_attempt(
        &self,
        access: &Access,
        agreement: &str,
        id: &str,
    ) -> Result<NativeAccountInspectionAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let saved = owned(&e, access, id)?;
        if saved.state != NativeRequestState::Queued {
            return Err(closed());
        }
        candidates::check_revision(&e, saved.queued_revision)?;
        let revision = e.view.revision;
        let command = context(
            access,
            &format!("native-account-inspect-start-{id}"),
            "native_account_inspection_started",
            agreement,
            Some(revision),
            &json!({"request_id":id}),
        )?;
        let saved = e
            .native_account_inspection_requests
            .get_mut(id)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(revision.checked_add(1).ok_or_else(internal)?);
        let attempt = NativeAccountInspectionAttempt {
            saved: saved.clone(),
        };
        if self
            .commit(
                &command,
                agreement,
                revision,
                e,
                "native_account_inspection_started",
            )?
            .replayed
        {
            return Err(closed());
        }
        Ok(attempt)
    }
    #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
    pub fn retain_native_account_inspection(
        &self,
        access: &Access,
        attempt: NativeAccountInspectionAttempt,
        original:&wholepact_signer::authority_bridge::account_inspection_ipc::NativeOwnerInspection<'_>,
    ) -> Result<NativeAccountInspectionRequestView> {
        original.check_current().map_err(|_| inconsistent())?;
        self.retain_owner_inspection(access, attempt, original.snapshot().clone())
    }
    // Private sink. Deserialized or application-supplied metadata cannot call it.
    #[cfg(any(test, all(feature = "signer-authority-bridge", target_os = "linux")))]
    fn retain_owner_inspection(
        &self,
        access: &Access,
        attempt: NativeAccountInspectionAttempt,
        snapshot: OwnerInspectionSnapshot,
    ) -> Result<NativeAccountInspectionRequestView> {
        self.protected_record_store_binding()?;
        let r = &attempt.saved.request;
        self.require_current_agreement(&r.agreement_id)?;
        let mut e = self.load(access, &r.agreement_id)?;
        if owned(&e, access, &r.request_id)? != &attempt.saved
            || attempt.saved.state != NativeRequestState::AttemptStarted
            || snapshot.request != *r
            || snapshot.account_id != attempt.saved.expected_account_id
            || !snapshot.validate()
        {
            return Err(inconsistent());
        }
        let revision = e.view.revision;
        let command = context(
            access,
            &format!("native-account-inspect-result-{}", r.request_id),
            "native_account_inspection_result",
            &r.agreement_id,
            Some(revision),
            &snapshot,
        )?;
        e.native_account_inspection_requests
            .get_mut(&r.request_id)
            .ok_or_else(not_found)?
            .result = Some(snapshot);
        self.commit(
            &command,
            &r.agreement_id,
            revision,
            e,
            "native_account_inspection_result_retained",
        )?;
        self.native_account_inspection_request(access, &r.agreement_id, &r.request_id)
    }
}
fn owned<'a>(
    e: &'a Envelope,
    access: &Access,
    id: &str,
) -> Result<&'a StoredNativeAccountInspectionRequest> {
    e.native_account_inspection_requests
        .get(id)
        .filter(|s| s.request.principal_id == access.principal_id)
        .ok_or_else(not_found)
}
fn closed() -> ApiError {
    ApiError::new(
        "NATIVE_ATTEMPT_ALREADY_CLOSED",
        "Inspect the exact original saved result. Started or withdrawn inspection requests cannot run again; missing result remains unknown",
    )
}
fn inconsistent() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Native owner inspection binding is inconsistent; preserve original history",
    )
}
pub(crate) fn validate_stored(e: &Envelope) -> Result<()> {
    for (id, s) in &e.native_account_inspection_requests {
        if !s.request.validate()
            || id != &s.request.request_id
            || s.request.agreement_id != e.view.agreement.agreement_id
            || s.original_revision.checked_add(1) != Some(s.queued_revision)
            || s.queued_revision > e.view.revision
            || !e.view.candidates.iter().any(|c| {
                c.candidate_id == s.request.candidate_id
                    && c.manifest_digest == s.request.manifest_digest
                    && c.proposal.manifest.participants.iter().any(|p| {
                        p.participant_id == s.request.participant_id
                            && p.account_id == s.expected_account_id
                    })
            })
            || match s.state {
                NativeRequestState::Queued | NativeRequestState::Withdrawn => {
                    s.attempt_revision.is_some() || s.result.is_some()
                }
                NativeRequestState::AttemptStarted => {
                    s.queued_revision.checked_add(1) != s.attempt_revision
                        || s.attempt_revision.is_some_and(|r| r > e.view.revision)
                }
            }
            || s.result.as_ref().is_some_and(|r| {
                !r.validate() || r.request != s.request || r.account_id != s.expected_account_id
            })
        {
            return Err(inconsistent());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;
