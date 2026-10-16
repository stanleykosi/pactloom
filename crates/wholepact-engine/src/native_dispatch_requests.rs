//! Inert exact-checkpoint requests and append-only historical submission metadata.
//! No request, attempt marker or observation constitutes spending authority.
use super::*;
use crate::native_requests::NativeRequestState;
use crate::native_settlement_requests::{SettlementSource, SignedObservation};
mod observations;
pub use observations::*;
#[cfg(feature = "submission-handoff")]
mod owner;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDispatchRequest {
    pub transaction_request_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DispatchSource {
    pub transaction_request_id: String,
    #[serde(flatten)]
    pub original: SettlementSource,
    pub signed: SignedObservation,
    pub checkpoint_id: String,
    pub transaction_digest: String,
    pub txid: String,
}
// Explicit flattened decoder keeps the wire shape strict without combining
// serde flatten and nested deny_unknown_fields during deserialization.
impl<'de> Deserialize<'de> for DispatchSource {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            transaction_request_id: String,
            intake_request_id: String,
            candidate_id: String,
            manifest_digest: String,
            job_id: String,
            signature_retention_key: String,
            proved_artifact_digest: String,
            receipt_storage_key: String,
            receipt_digest: String,
            scope_digest: String,
            coordination_request_digest: String,
            signed: SignedObservation,
            checkpoint_id: String,
            transaction_digest: String,
            txid: String,
        }
        let w = Wire::deserialize(deserializer)?;
        Ok(Self {
            transaction_request_id: w.transaction_request_id,
            original: SettlementSource {
                intake_request_id: w.intake_request_id,
                candidate_id: w.candidate_id,
                manifest_digest: w.manifest_digest,
                job_id: w.job_id,
                signature_retention_key: w.signature_retention_key,
                proved_artifact_digest: w.proved_artifact_digest,
                receipt_storage_key: w.receipt_storage_key,
                receipt_digest: w.receipt_digest,
                scope_digest: w.scope_digest,
                coordination_request_digest: w.coordination_request_digest,
            },
            signed: w.signed,
            checkpoint_id: w.checkpoint_id,
            transaction_digest: w.transaction_digest,
            txid: w.txid,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeDispatchRequest {
    principal_id: String,
    request_id: String,
    agreement_id: String,
    source: DispatchSource,
    operation_id: String,
    submission_journal_identity: Option<String>,
    original_revision: u64,
    queued_revision: u64,
    attempt_revision: Option<u64>,
    state: NativeRequestState,
    observations: Vec<DispatchObservation>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeDispatchRequestView {
    pub schema_version: u32,
    pub operation: &'static str,
    pub request_id: String,
    pub agreement_id: String,
    #[serde(flatten)]
    pub source: DispatchSource,
    pub operation_id: String,
    pub submission_journal_identity: Option<String>,
    pub original_revision: u64,
    pub queued_revision: u64,
    pub attempt_revision: Option<u64>,
    pub state: NativeRequestState,
    pub authorization_allowed: bool,
    pub result_status: &'static str,
    pub outcome_status: &'static str,
    pub observations: Vec<DispatchObservation>,
}
/// Non-clone metadata fence, issued only after the one initial durable mark.
/// Actual native authority, consent and exact predecessor verification remain mandatory.
pub struct NativeDispatchAttempt {
    saved: StoredNativeDispatchRequest,
}
/// Repeatable historical inspection. Cannot construct an initial dispatch attempt.
pub struct NativeDispatchInspection {
    saved: StoredNativeDispatchRequest,
}
macro_rules! exact_accessors {
    () => {
        pub fn source(&self) -> &DispatchSource {
            &self.saved.source
        }
        pub fn operation_id(&self) -> &str {
            &self.saved.operation_id
        }
        pub fn submission_journal_identity(&self) -> &str {
            self.saved
                .submission_journal_identity
                .as_deref()
                .expect("constructed after durable journal binding")
        }
        pub fn revision(&self) -> u64 {
            self.saved
                .attempt_revision
                .expect("constructed after durable fence")
        }
    };
}
impl NativeDispatchAttempt {
    exact_accessors!();
    pub fn into_inspection(self) -> NativeDispatchInspection {
        NativeDispatchInspection { saved: self.saved }
    }
}
impl NativeDispatchInspection {
    exact_accessors!();
}

impl Engine {
    pub fn queue_native_dispatch(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeDispatchRequest,
    ) -> Result<NativeDispatchRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_dispatch",
            agreement,
            Some(revision),
            &request,
        )?;
        let request_id = hash_domain(
            b"wholepact:native-dispatch-request:v1\0",
            &json!({"principal":access.principal_id,"key":key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_dispatch_request(access, agreement, &request_id);
        }
        candidates::check_revision(&e, revision)?;
        if native_requests::total_requests(&e) >= native_requests::MAX_NATIVE_REQUESTS {
            return Err(exhausted());
        }
        let source = native_settlement_requests::dispatch_source(
            &e,
            &access.principal_id,
            &request.transaction_request_id,
        )?;
        // Only never-started withdrawals permit a new request. A possibly attempted
        // original keeps its operation forever and can never be replaced.
        if e.native_dispatch_requests.values().any(|r| {
            r.source.transaction_request_id == source.transaction_request_id
                && r.state != NativeRequestState::Withdrawn
        }) {
            return Err(closed());
        }
        let candidate = candidate_for_source(&e, &source)?;
        candidates::check_current_terms(&e.view, &candidate.proposal.manifest)?;
        let saved = StoredNativeDispatchRequest {
            principal_id: access.principal_id.clone(),
            request_id: request_id.clone(),
            agreement_id: agreement.into(),
            source,
            operation_id: format!("native-dispatch-{request_id}"),
            submission_journal_identity: None,
            original_revision: revision,
            queued_revision: revision.checked_add(1).ok_or_else(internal)?,
            attempt_revision: None,
            state: NativeRequestState::Queued,
            observations: vec![],
        };
        if e.native_dispatch_requests
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
            "native_dispatch_requested",
        )?;
        self.native_dispatch_request(access, agreement, &request_id)
    }
    pub fn native_dispatch_request(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeDispatchRequestView> {
        let e = self.load(access, agreement)?;
        Ok(view(owned(&e, access, request)?))
    }
    pub fn native_dispatch_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeDispatchRequestView>> {
        let e = self.load(access, agreement)?;
        Ok(e.native_dispatch_requests
            .values()
            .filter(|r| r.principal_id == access.principal_id)
            .map(view)
            .collect())
    }
    pub fn withdraw_native_dispatch_request(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: &str,
    ) -> Result<NativeDispatchRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_dispatch_request",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_dispatch_request(access, agreement, request);
        }
        candidates::check_revision(&e, revision)?;
        if owned(&e, access, request)?.state != NativeRequestState::Queued {
            return Err(closed());
        }
        e.native_dispatch_requests
            .get_mut(request)
            .ok_or_else(not_found)?
            .state = NativeRequestState::Withdrawn;
        self.commit(
            &command,
            agreement,
            revision,
            e,
            "native_dispatch_withdrawn",
        )?;
        self.native_dispatch_request(access, agreement, request)
    }
    /// Atomically bind the actual native owner's journal before any private effect.
    /// HTTP must never expose this method. A replay never issues a second attempt.
    pub fn mark_native_dispatch_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
        submission_journal_identity: &str,
    ) -> Result<NativeDispatchAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        if !valid_journal_identity(submission_journal_identity) {
            return Err(inconsistent());
        }
        let mut e = self.load(access, agreement)?;
        let saved = owned(&e, access, request)?;
        if saved.state != NativeRequestState::Queued {
            return Err(closed());
        }
        candidates::check_revision(&e, saved.queued_revision)?;
        candidates::check_current_terms(
            &e.view,
            &candidate_for_source(&e, &saved.source)?.proposal.manifest,
        )?;
        let revision = e.view.revision;
        let command = context(
            access,
            &format!("native-dispatch-start-{request}"),
            "native_dispatch_attempt",
            agreement,
            Some(revision),
            &json!({"request_id":request,"submission_journal_identity":submission_journal_identity}),
        )?;
        let saved = e
            .native_dispatch_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(revision.checked_add(1).ok_or_else(internal)?);
        saved.submission_journal_identity = Some(submission_journal_identity.into());
        let attempt = NativeDispatchAttempt {
            saved: saved.clone(),
        };
        if self
            .commit(
                &command,
                agreement,
                revision,
                e,
                "native_dispatch_attempt_started",
            )?
            .replayed
        {
            return Err(closed());
        }
        Ok(attempt)
    }
    pub fn native_dispatch_inspection(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeDispatchInspection> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let e = self.load(access, agreement)?;
        let saved = owned(&e, access, request)?;
        if saved.state != NativeRequestState::AttemptStarted {
            return Err(closed());
        }
        Ok(NativeDispatchInspection {
            saved: saved.clone(),
        })
    }
}
fn candidate_for_source<'a>(e: &'a Envelope, source: &DispatchSource) -> Result<&'a CandidateView> {
    let candidate = e
        .view
        .candidates
        .iter()
        .find(|c| c.candidate_id == source.original.candidate_id)
        .ok_or_else(inconsistent)?;
    if candidate.manifest_digest != source.original.manifest_digest {
        return Err(inconsistent());
    }
    Ok(candidate)
}
fn owned<'a>(
    e: &'a Envelope,
    access: &Access,
    id: &str,
) -> Result<&'a StoredNativeDispatchRequest> {
    e.native_dispatch_requests
        .get(id)
        .filter(|r| r.principal_id == access.principal_id)
        .ok_or_else(not_found)
}
fn view(r: &StoredNativeDispatchRequest) -> NativeDispatchRequestView {
    NativeDispatchRequestView {
        schema_version: 1,
        operation: "submission_dispatch",
        request_id: r.request_id.clone(),
        agreement_id: r.agreement_id.clone(),
        source: r.source.clone(),
        operation_id: r.operation_id.clone(),
        submission_journal_identity: r.submission_journal_identity.clone(),
        original_revision: r.original_revision,
        queued_revision: r.queued_revision,
        attempt_revision: r.attempt_revision,
        state: r.state,
        authorization_allowed: false,
        result_status: "historical_metadata_only",
        outcome_status: if r.observations.iter().any(|o| o.intent.is_some()) {
            "historical_result_recorded"
        } else if r.state == NativeRequestState::AttemptStarted {
            "attempted_outcome_unknown"
        } else {
            "not_attempted"
        },
        observations: r.observations.clone(),
    }
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_journal_identity(s: &str) -> bool {
    digest(s) && s.bytes().any(|b| b != b'0')
}
fn inconsistent() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Exact original dispatch source or journal history is inconsistent; preserve all journals",
    )
}
fn closed() -> ApiError {
    ApiError::new(
        "NATIVE_ATTEMPT_ALREADY_CLOSED",
        "Preserve the original dispatch request and operation; fresh native inspection never resets or retries it",
    )
}
fn exhausted() -> ApiError {
    ApiError::new(
        "RESOURCE_EXHAUSTED",
        "Preserve bounded original native request and observation history",
    )
}
#[cfg(feature = "submission-handoff")]
fn same_original(a: &StoredNativeDispatchRequest, b: &StoredNativeDispatchRequest) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.observations.clear();
    b.observations.clear();
    a == b
}
pub(crate) fn validate_stored(e: &Envelope) -> Result<()> {
    let mut originals = BTreeSet::new();
    for (id, r) in &e.native_dispatch_requests {
        if id != &r.request_id
            || !digest(id)
            || r.principal_id.is_empty()
            || r.principal_id.len() > 128
            || r.agreement_id != e.view.agreement.agreement_id
            || r.original_revision.checked_add(1) != Some(r.queued_revision)
            || r.queued_revision > e.view.revision
            || r.operation_id != format!("native-dispatch-{id}")
            || (r.state != NativeRequestState::Withdrawn
                && !originals.insert(&r.source.transaction_request_id))
            || native_settlement_requests::dispatch_source(
                e,
                &r.principal_id,
                &r.source.transaction_request_id,
            )? != r.source
        {
            return Err(inconsistent());
        }
        candidate_for_source(e, &r.source)?;
        match r.state {
            NativeRequestState::Queued | NativeRequestState::Withdrawn => {
                if r.attempt_revision.is_some()
                    || r.submission_journal_identity.is_some()
                    || !r.observations.is_empty()
                {
                    return Err(inconsistent());
                }
            }
            NativeRequestState::AttemptStarted => {
                if r.queued_revision.checked_add(1) != r.attempt_revision
                    || r.attempt_revision.is_some_and(|v| v > e.view.revision)
                    || !r
                        .submission_journal_identity
                        .as_deref()
                        .is_some_and(valid_journal_identity)
                {
                    return Err(inconsistent());
                }
            }
        }
        observations::validate_observations(e, r)?;
    }
    Ok(())
}

/// Exact immutable predecessor metadata; never retained private bytes or authority.
pub(crate) struct ReconciliationOriginal {
    pub source: DispatchSource,
    pub operation_id: String,
    pub submission_journal_identity: String,
    pub attempt_revision: u64,
}
pub(crate) fn reconciliation_original(e: &Envelope, principal: &str, request: &str) -> Result<ReconciliationOriginal> {
    let r = e.native_dispatch_requests.get(request).filter(|r| r.principal_id == principal).ok_or_else(not_found)?;
    if r.state != NativeRequestState::AttemptStarted { return Err(closed()); }
    let journal = r.submission_journal_identity.as_deref().filter(|j|valid_journal_identity(j)).ok_or_else(inconsistent)?;
    Ok(ReconciliationOriginal { source: r.source.clone(), operation_id: r.operation_id.clone(), submission_journal_identity: journal.into(), attempt_revision: r.attempt_revision.ok_or_else(inconsistent)? })
}
pub(crate) fn validate_reconciliation_observation(e: &Envelope, principal: &str, request: &str, observation: &DispatchObservation) -> Result<()> {
    let r=e.native_dispatch_requests.get(request).filter(|r|r.principal_id==principal).ok_or_else(not_found)?;
    observations::validate_observation(e,r,observation)
}
pub(crate) fn reconciliation_observation_monotone(a:&DispatchObservation,b:&DispatchObservation)->bool { observations::monotone(a,b) }
#[cfg(feature="submission-handoff")]
pub(crate) fn validate_reconciliation_descriptor(e:&Envelope,principal:&str,request:&str,descriptor:&DispatchDescriptor)->Result<()> {
    let r=e.native_dispatch_requests.get(request).filter(|r|r.principal_id==principal).ok_or_else(not_found)?;
    observations::descriptor_matches(e,r,descriptor)
}
