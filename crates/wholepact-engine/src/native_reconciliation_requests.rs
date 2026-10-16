//! Inert, exact-original requests for repeatable observation and independently
//! authorized record resolution. A durable attempt fence is never reset.
use super::*;
use crate::native_dispatch_requests::{self, DispatchSource};
use crate::native_requests::NativeRequestState;
mod observations;
pub use observations::*;
#[cfg(feature = "submission-handoff")]
mod owner;
#[cfg(all(
    feature = "submission-handoff",
    feature = "signer-authority-bridge",
    target_os = "linux"
))]
pub use owner::NativeRecordResolutionGuard;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationRequestKind {
    ProviderObservation,
    IndependentRecordResolution,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeReconciliationRequest {
    ProviderObservation {
        dispatch_request_id: String,
    },
    IndependentRecordResolution {
        dispatch_request_id: String,
        participant_id: String,
        record_id: String,
    },
}
impl NativeReconciliationRequest {
    pub fn kind(&self) -> ReconciliationRequestKind {
        match self {
            Self::ProviderObservation { .. } => ReconciliationRequestKind::ProviderObservation,
            Self::IndependentRecordResolution { .. } => {
                ReconciliationRequestKind::IndependentRecordResolution
            }
        }
    }
    pub fn dispatch_request_id(&self) -> &str {
        match self {
            Self::ProviderObservation {
                dispatch_request_id,
            }
            | Self::IndependentRecordResolution {
                dispatch_request_id,
                ..
            } => dispatch_request_id,
        }
    }
    pub fn participant_id(&self) -> Option<&str> {
        match self {
            Self::IndependentRecordResolution { participant_id, .. } => Some(participant_id),
            _ => None,
        }
    }
    pub fn record_id(&self) -> Option<&str> {
        match self {
            Self::IndependentRecordResolution { record_id, .. } => Some(record_id),
            _ => None,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeReconciliationRequest {
    principal_id: String,
    request_id: String,
    agreement_id: String,
    request: NativeReconciliationRequest,
    source: DispatchSource,
    operation_id: String,
    submission_journal_identity: String,
    original_revision: u64,
    queued_revision: u64,
    attempt_revision: Option<u64>,
    state: NativeRequestState,
    observations: Vec<ReconciliationJournalObservation>,
    resolution_commit: Option<StoredResolutionCommit>,
}
/// Created only by the genuine verifier wrapper after successful local commit.
/// A later reorganization can invalidate confidence without erasing this history.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResolutionCommit {
    evidence_id: String,
    signer_settlement_request_digest: String,
    participant_id: String,
    record_id: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct HistoricalResolutionCommit {
    pub status: &'static str,
    pub observation_stale: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeReconciliationRequestView {
    pub schema_version: u32,
    pub operation: &'static str,
    pub kind: ReconciliationRequestKind,
    pub request_id: String,
    pub agreement_id: String,
    pub dispatch_request_id: String,
    #[serde(flatten)]
    pub source: DispatchSource,
    pub operation_id: String,
    pub submission_journal_identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    pub original_revision: u64,
    pub queued_revision: u64,
    pub attempt_revision: Option<u64>,
    pub state: NativeRequestState,
    pub authorization_allowed: bool,
    pub result_status: &'static str,
    pub outcome_status: &'static str,
    pub observations: Vec<ReconciliationJournalObservation>,
    pub resolution_commit: Option<HistoricalResolutionCommit>,
}
/// Non-Clone inert first-attempt marker. It cannot stand in for native authority.
pub struct NativeReconciliationAttempt {
    saved: StoredNativeReconciliationRequest,
}
/// Repeatable actual-journal inspection, never another private execution attempt.
pub struct NativeReconciliationInspection {
    saved: StoredNativeReconciliationRequest,
}
macro_rules! exact_accessors {
    () => {
        pub fn kind(&self) -> ReconciliationRequestKind {
            self.saved.request.kind()
        }
        pub fn dispatch_request_id(&self) -> &str {
            self.saved.request.dispatch_request_id()
        }
        pub fn source(&self) -> &DispatchSource {
            &self.saved.source
        }
        pub fn operation_id(&self) -> &str {
            &self.saved.operation_id
        }
        pub fn submission_journal_identity(&self) -> &str {
            &self.saved.submission_journal_identity
        }
        pub fn participant_id(&self) -> Option<&str> {
            self.saved.request.participant_id()
        }
        pub fn record_id(&self) -> Option<&str> {
            self.saved.request.record_id()
        }
        pub fn revision(&self) -> u64 {
            self.saved
                .attempt_revision
                .expect("constructed after durable fence")
        }
    };
}
impl NativeReconciliationAttempt {
    exact_accessors!();
    pub fn into_inspection(self) -> NativeReconciliationInspection {
        NativeReconciliationInspection { saved: self.saved }
    }
}
impl NativeReconciliationInspection {
    exact_accessors!();
}

impl Engine {
    pub fn queue_native_reconciliation(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeReconciliationRequest,
    ) -> Result<NativeReconciliationRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_reconciliation",
            agreement,
            Some(revision),
            &request,
        )?;
        let request_id = hash_domain(
            b"wholepact:native-reconciliation-request:v1\0",
            &json!({"principal":access.principal_id,"key":key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_reconciliation_request(access, agreement, &request_id);
        }
        candidates::check_revision(&e, revision)?;
        if native_requests::total_requests(&e) >= native_requests::MAX_NATIVE_REQUESTS {
            return Err(exhausted());
        }
        let original = native_dispatch_requests::reconciliation_original(
            &e,
            &access.principal_id,
            request.dispatch_request_id(),
        )?;
        validate_selection(&e, &access.principal_id, &request, &original.source)?;
        // Reads and independently reviewed resolution may be requested again. Each
        // old attempt remains immutable; at most one equivalent request is queued.
        if e.native_reconciliation_requests.values().any(|r| {
            r.principal_id == access.principal_id
                && same_purpose(&r.request, &request)
                && r.state == NativeRequestState::Queued
        }) {
            return Err(closed());
        }
        let saved = StoredNativeReconciliationRequest {
            principal_id: access.principal_id.clone(),
            request_id: request_id.clone(),
            agreement_id: agreement.into(),
            request,
            source: original.source,
            operation_id: original.operation_id,
            submission_journal_identity: original.submission_journal_identity,
            original_revision: revision,
            queued_revision: revision.checked_add(1).ok_or_else(internal)?,
            attempt_revision: None,
            state: NativeRequestState::Queued,
            observations: vec![],
            resolution_commit: None,
        };
        if e.native_reconciliation_requests
            .insert(request_id.clone(), saved)
            .is_some()
        {
            return Err(inconsistent());
        }
        self.commit(
            &command,
            agreement,
            revision,
            e,
            "native_reconciliation_requested",
        )?;
        self.native_reconciliation_request(access, agreement, &request_id)
    }
    pub fn native_reconciliation_request(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeReconciliationRequestView> {
        let e = self.load(access, agreement)?;
        Ok(view(owned(&e, access, request)?))
    }
    pub fn native_reconciliation_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeReconciliationRequestView>> {
        let e = self.load(access, agreement)?;
        Ok(e.native_reconciliation_requests
            .values()
            .filter(|r| r.principal_id == access.principal_id)
            .map(view)
            .collect())
    }
    pub fn withdraw_native_reconciliation_request(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: &str,
    ) -> Result<NativeReconciliationRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_reconciliation_request",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_reconciliation_request(access, agreement, request);
        }
        candidates::check_revision(&e, revision)?;
        if owned(&e, access, request)?.state != NativeRequestState::Queued {
            return Err(closed());
        }
        e.native_reconciliation_requests
            .get_mut(request)
            .ok_or_else(not_found)?
            .state = NativeRequestState::Withdrawn;
        self.commit(
            &command,
            agreement,
            revision,
            e,
            "native_reconciliation_withdrawn",
        )?;
        self.native_reconciliation_request(access, agreement, request)
    }
    /// Private native boundary. HTTP must never expose this method. Persist the
    /// unknown fence before network disclosure, signer contact or private mutation.
    pub fn mark_native_reconciliation_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeReconciliationAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let saved = owned(&e, access, request)?;
        if saved.state != NativeRequestState::Queued {
            return Err(closed());
        }
        candidates::check_revision(&e, saved.queued_revision)?;
        validate_original(&e, saved)?;
        let revision = e.view.revision;
        let command = context(
            access,
            &format!("native-reconciliation-start-{request}"),
            "native_reconciliation_attempt",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        let saved = e
            .native_reconciliation_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(revision.checked_add(1).ok_or_else(internal)?);
        let attempt = NativeReconciliationAttempt {
            saved: saved.clone(),
        };
        if self
            .commit(
                &command,
                agreement,
                revision,
                e,
                "native_reconciliation_attempt_started",
            )?
            .replayed
        {
            return Err(closed());
        }
        Ok(attempt)
    }
    pub fn native_reconciliation_inspection(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeReconciliationInspection> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let e = self.load(access, agreement)?;
        let saved = owned(&e, access, request)?;
        if saved.state != NativeRequestState::AttemptStarted {
            return Err(closed());
        }
        Ok(NativeReconciliationInspection {
            saved: saved.clone(),
        })
    }
}
fn same_purpose(a: &NativeReconciliationRequest, b: &NativeReconciliationRequest) -> bool {
    a.dispatch_request_id() == b.dispatch_request_id()
        && a.kind() == b.kind()
        && a.record_id() == b.record_id()
}
fn validate_selection(
    e: &Envelope,
    principal: &str,
    request: &NativeReconciliationRequest,
    source: &DispatchSource,
) -> Result<()> {
    if let NativeReconciliationRequest::IndependentRecordResolution {
        participant_id,
        record_id,
        ..
    } = request
    {
        crate::participant_records::reconciliation_selection::validate_selection(
            e,
            principal,
            source,
            participant_id,
            record_id,
        )?;
    }
    Ok(())
}
fn validate_original(e: &Envelope, r: &StoredNativeReconciliationRequest) -> Result<()> {
    let original = native_dispatch_requests::reconciliation_original(
        e,
        &r.principal_id,
        r.request.dispatch_request_id(),
    )?;
    if original.source != r.source
        || original.operation_id != r.operation_id
        || original.submission_journal_identity != r.submission_journal_identity
        || original.attempt_revision > r.original_revision
    {
        return Err(inconsistent());
    }
    validate_selection(e, &r.principal_id, &r.request, &r.source)
}
fn owned<'a>(
    e: &'a Envelope,
    access: &Access,
    id: &str,
) -> Result<&'a StoredNativeReconciliationRequest> {
    e.native_reconciliation_requests
        .get(id)
        .filter(|r| r.principal_id == access.principal_id)
        .ok_or_else(not_found)
}
fn view(r: &StoredNativeReconciliationRequest) -> NativeReconciliationRequestView {
    NativeReconciliationRequestView {
        schema_version: 1,
        operation: "settlement_reconciliation",
        kind: r.request.kind(),
        request_id: r.request_id.clone(),
        agreement_id: r.agreement_id.clone(),
        dispatch_request_id: r.request.dispatch_request_id().into(),
        source: r.source.clone(),
        operation_id: r.operation_id.clone(),
        submission_journal_identity: r.submission_journal_identity.clone(),
        participant_id: r.request.participant_id().map(str::to_owned),
        record_id: r.request.record_id().map(str::to_owned),
        original_revision: r.original_revision,
        queued_revision: r.queued_revision,
        attempt_revision: r.attempt_revision,
        state: r.state,
        authorization_allowed: false,
        result_status: "historical_metadata_only",
        outcome_status: if r.resolution_commit.is_some() {
            "historical_resolution_commit_recorded"
        } else if r.request.kind() == ReconciliationRequestKind::ProviderObservation
            && r.observations.iter().any(|o| o.report.is_some())
        {
            "historical_observation_recorded"
        } else if r.state == NativeRequestState::AttemptStarted {
            "attempted_outcome_unknown"
        } else {
            "not_attempted"
        },
        observations: r.observations.clone(),
        resolution_commit: r
            .resolution_commit
            .as_ref()
            .map(|_| HistoricalResolutionCommit {
                status: "historically_applied_independent_resolution",
                observation_stale: true,
            }),
    }
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn inconsistent() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Exact original reconciliation source or history is inconsistent; preserve all journals",
    )
}
fn closed() -> ApiError {
    ApiError::new(
        "NATIVE_ATTEMPT_ALREADY_CLOSED",
        "Preserve the original attempt; a separate explicit request never resets, retries or replaces its original payment",
    )
}
fn exhausted() -> ApiError {
    ApiError::new(
        "RESOURCE_EXHAUSTED",
        "Preserve bounded original native request and reconciliation history",
    )
}
#[cfg(feature = "submission-handoff")]
fn same_original(
    a: &StoredNativeReconciliationRequest,
    b: &StoredNativeReconciliationRequest,
) -> bool {
    let (mut a, mut b) = (a.clone(), b.clone());
    a.observations.clear();
    b.observations.clear();
    a.resolution_commit = None;
    b.resolution_commit = None;
    a == b
}
pub(crate) fn validate_stored(e: &Envelope) -> Result<()> {
    let mut queued = BTreeSet::new();
    for (id, r) in &e.native_reconciliation_requests {
        if id != &r.request_id
            || !digest(id)
            || !valid_id(&r.principal_id)
            || r.agreement_id != e.view.agreement.agreement_id
            || r.original_revision.checked_add(1) != Some(r.queued_revision)
            || r.queued_revision > e.view.revision
            || (r.state == NativeRequestState::Queued
                && !queued.insert((
                    &r.principal_id,
                    r.request.dispatch_request_id(),
                    r.request.kind(),
                    r.request.record_id(),
                )))
        {
            return Err(inconsistent());
        }
        validate_original(e, r)?;
        match r.state {
            NativeRequestState::Queued | NativeRequestState::Withdrawn => {
                if r.attempt_revision.is_some()
                    || !r.observations.is_empty()
                    || r.resolution_commit.is_some()
                {
                    return Err(inconsistent());
                }
            }
            NativeRequestState::AttemptStarted => {
                if r.queued_revision.checked_add(1) != r.attempt_revision
                    || r.attempt_revision.is_some_and(|v| v > e.view.revision)
                {
                    return Err(inconsistent());
                }
            }
        }
        observations::validate_observations(e, r)?;
        if let Some(commit) = &r.resolution_commit {
            if r.request.kind() != ReconciliationRequestKind::IndependentRecordResolution
                || !digest(&commit.evidence_id)
                || !digest(&commit.signer_settlement_request_digest)
                || Some(commit.participant_id.as_str()) != r.request.participant_id()
                || Some(commit.record_id.as_str()) != r.request.record_id()
            {
                return Err(inconsistent());
            }
        }
    }
    Ok(())
}
