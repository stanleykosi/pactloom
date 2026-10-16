//! Exact inert requests and historical observations. No browser spending authority.
use super::*;
use crate::native_requests::NativeRequestState;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRequestKind {
    SignatureReconcile,
    TransactionCheckpoint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSettlementRequest {
    pub intake_request_id: String,
    pub kind: SettlementRequestKind,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementSource {
    pub intake_request_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub job_id: String,
    pub signature_retention_key: String,
    pub proved_artifact_digest: String,
    pub receipt_storage_key: String,
    pub receipt_digest: String,
    pub scope_digest: String,
    pub coordination_request_digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedObservation {
    pub result_id: String,
    pub request_digest: String,
    pub signed_candidate_digest: String,
    pub signatures_complete: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SettlementObservation {
    Signed {
        evidence: SignedObservation,
    },
    Transaction {
        signed: SignedObservation,
        checkpoint_id: String,
        transaction_digest: String,
        txid: String,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNativeSettlementRequest {
    principal_id: String,
    request_id: String,
    agreement_id: String,
    source: SettlementSource,
    kind: SettlementRequestKind,
    expected_signed: Option<SignedObservation>,
    original_revision: u64,
    queued_revision: u64,
    attempt_revision: Option<u64>,
    state: NativeRequestState,
    observation: Option<SettlementObservation>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeSettlementRequestView {
    pub schema_version: u32,
    pub operation: &'static str,
    pub request_id: String,
    pub agreement_id: String,
    #[serde(flatten)]
    pub source: SettlementSource,
    pub kind: SettlementRequestKind,
    pub original_revision: u64,
    pub queued_revision: u64,
    pub attempt_revision: Option<u64>,
    pub state: NativeRequestState,
    pub authorization_allowed: bool,
    pub result_status: &'static str,
    pub outcome_status: &'static str,
    pub observation: Option<SettlementObservation>,
}
/// Consumed by the sole initial native operation; contains no native authority.
/// Inspection cannot construct this type or regain permission to extract.
pub struct NativeSettlementAttempt {
    saved: StoredNativeSettlementRequest,
}
/// Exact original inputs for repeatable native historical inspection only.
pub struct NativeSettlementInspection {
    saved: StoredNativeSettlementRequest,
}
impl NativeSettlementAttempt {
    pub fn source(&self) -> &SettlementSource {
        &self.saved.source
    }
    pub fn kind(&self) -> SettlementRequestKind {
        self.saved.kind
    }
    pub fn revision(&self) -> u64 {
        self.saved
            .attempt_revision
            .expect("constructed after fencing")
    }
    pub fn into_inspection(self) -> NativeSettlementInspection {
        NativeSettlementInspection { saved: self.saved }
    }
}
impl NativeSettlementInspection {
    pub fn source(&self) -> &SettlementSource {
        &self.saved.source
    }
    pub fn kind(&self) -> SettlementRequestKind {
        self.saved.kind
    }
}
impl Engine {
    pub fn queue_native_settlement(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: NativeSettlementRequest,
    ) -> Result<NativeSettlementRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut envelope = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "queue_native_settlement",
            agreement,
            Some(revision),
            &request,
        )?;
        let request_id = hash_domain(
            b"wholepact:native-settlement-request:v1\0",
            &json!({"principal":access.principal_id,"key":key}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_settlement_request(access, agreement, &request_id);
        }
        candidates::check_revision(&envelope, revision)?;
        if native_requests::total_requests(&envelope) >= native_requests::MAX_NATIVE_REQUESTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Preserve bounded original native request history",
            ));
        }
        if envelope.native_settlement_requests.values().any(|r| {
            r.source.intake_request_id == request.intake_request_id
                && r.kind == request.kind
                && r.state != NativeRequestState::Withdrawn
        }) {
            return Err(closed());
        }
        let source = crate::native_artifact_handoff_requests::settlement_source(
            &envelope,
            &access.principal_id,
            &request.intake_request_id,
        )?;
        let expected_signed = match request.kind {
            SettlementRequestKind::SignatureReconcile => None,
            SettlementRequestKind::TransactionCheckpoint => {
                Some(reconciled_signed(&envelope, &access.principal_id, &source)?)
            }
        };
        let saved = StoredNativeSettlementRequest {
            principal_id: access.principal_id.clone(),
            request_id: request_id.clone(),
            agreement_id: agreement.into(),
            source,
            kind: request.kind,
            expected_signed,
            original_revision: revision,
            queued_revision: revision.checked_add(1).ok_or_else(internal)?,
            attempt_revision: None,
            state: NativeRequestState::Queued,
            observation: None,
        };
        if envelope
            .native_settlement_requests
            .insert(request_id.clone(), saved)
            .is_some()
        {
            return Err(inconsistent());
        }
        self.commit(
            &command,
            agreement,
            revision,
            envelope,
            "native_settlement_requested",
        )?;
        self.native_settlement_request(access, agreement, &request_id)
    }
    pub fn native_settlement_request(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeSettlementRequestView> {
        let e = self.load(access, agreement)?;
        Ok(view(owned(&e, access, request)?))
    }
    pub fn native_settlement_requests(
        &self,
        access: &Access,
        agreement: &str,
    ) -> Result<Vec<NativeSettlementRequestView>> {
        let e = self.load(access, agreement)?;
        Ok(e.native_settlement_requests
            .values()
            .filter(|r| r.principal_id == access.principal_id)
            .map(view)
            .collect())
    }
    pub fn withdraw_native_settlement_request(
        &self,
        access: &Access,
        key: &str,
        agreement: &str,
        revision: u64,
        request: &str,
    ) -> Result<NativeSettlementRequestView> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let command = context(
            access,
            key,
            "withdraw_native_settlement_request",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        if self.replay(access, &command)?.is_some() {
            return self.native_settlement_request(access, agreement, request);
        }
        candidates::check_revision(&e, revision)?;
        if owned(&e, access, request)?.state != NativeRequestState::Queued {
            return Err(closed());
        }
        e.native_settlement_requests
            .get_mut(request)
            .ok_or_else(not_found)?
            .state = NativeRequestState::Withdrawn;
        self.commit(
            &command,
            agreement,
            revision,
            e,
            "native_settlement_withdrawn",
        )?;
        self.native_settlement_request(access, agreement, request)
    }
    pub fn mark_native_settlement_attempt(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeSettlementAttempt> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let mut e = self.load(access, agreement)?;
        let saved = owned(&e, access, request)?;
        if saved.state != NativeRequestState::Queued {
            return Err(closed());
        }
        candidates::check_revision(&e, saved.queued_revision)?;
        let revision = e.view.revision;
        let command = context(
            access,
            &format!("native-settlement-start-{request}"),
            "native_settlement_attempt",
            agreement,
            Some(revision),
            &json!({"request_id":request}),
        )?;
        let saved = e
            .native_settlement_requests
            .get_mut(request)
            .ok_or_else(not_found)?;
        saved.state = NativeRequestState::AttemptStarted;
        saved.attempt_revision = Some(revision.checked_add(1).ok_or_else(internal)?);
        let result = NativeSettlementAttempt {
            saved: saved.clone(),
        };
        if self
            .commit(
                &command,
                agreement,
                revision,
                e,
                "native_settlement_attempt_started",
            )?
            .replayed
        {
            return Err(closed());
        }
        Ok(result)
    }
    /// Fresh private owner consent is still mandatory. This can never extract.
    pub fn native_settlement_inspection(
        &self,
        access: &Access,
        agreement: &str,
        request: &str,
    ) -> Result<NativeSettlementInspection> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(agreement)?;
        let e = self.load(access, agreement)?;
        let saved = owned(&e, access, request)?;
        if saved.state != NativeRequestState::AttemptStarted {
            return Err(closed());
        }
        Ok(NativeSettlementInspection {
            saved: saved.clone(),
        })
    }
}
fn reconciled_signed(
    e: &Envelope,
    principal: &str,
    source: &SettlementSource,
) -> Result<SignedObservation> {
    let mut values = e
        .native_settlement_requests
        .values()
        .filter(|r| {
            r.principal_id == principal
                && r.source == *source
                && r.kind == SettlementRequestKind::SignatureReconcile
                && r.state == NativeRequestState::AttemptStarted
        })
        .filter_map(|r| match &r.observation {
            Some(SettlementObservation::Signed { evidence }) if evidence.signatures_complete => {
                Some(evidence)
            }
            _ => None,
        });
    let found=values.next().ok_or_else(||ApiError::new("MISSING_EVIDENCE","Reconcile the exact original complete signature result under fresh native consent first"))?;
    if values.any(|other| other != found) {
        return Err(inconsistent());
    }
    Ok(found.clone())
}
fn owned<'a>(
    e: &'a Envelope,
    access: &Access,
    id: &str,
) -> Result<&'a StoredNativeSettlementRequest> {
    e.native_settlement_requests
        .get(id)
        .filter(|r| r.principal_id == access.principal_id)
        .ok_or_else(not_found)
}
fn view(r: &StoredNativeSettlementRequest) -> NativeSettlementRequestView {
    NativeSettlementRequestView {
        schema_version: 1,
        operation: "settlement_handoff",
        request_id: r.request_id.clone(),
        agreement_id: r.agreement_id.clone(),
        source: r.source.clone(),
        kind: r.kind,
        original_revision: r.original_revision,
        queued_revision: r.queued_revision,
        attempt_revision: r.attempt_revision,
        state: r.state,
        authorization_allowed: false,
        result_status: "historical_metadata_only",
        outcome_status: if r.observation.is_some() {
            "historical_result_recorded"
        } else if r.state == NativeRequestState::AttemptStarted {
            "attempted_outcome_unknown"
        } else {
            "not_attempted"
        },
        observation: r.observation.clone(),
    }
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_signed(s: &SignedObservation) -> bool {
    s.result_id.strip_prefix("signed-").is_some_and(digest)
        && digest(&s.request_digest)
        && digest(&s.signed_candidate_digest)
}
fn inconsistent() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Exact original settlement request/result binding is inconsistent; preserve all journals",
    )
}
fn closed() -> ApiError {
    ApiError::new(
        "NATIVE_ATTEMPT_ALREADY_CLOSED",
        "Preserve the original request; use fresh native inspection without resetting or extracting",
    )
}
pub(crate) fn validate_stored(e: &Envelope) -> Result<()> {
    for (id, r) in &e.native_settlement_requests {
        if id != &r.request_id
            || !digest(id)
            || r.agreement_id != e.view.agreement.agreement_id
            || r.original_revision.checked_add(1) != Some(r.queued_revision)
            || r.queued_revision > e.view.revision
            || crate::native_artifact_handoff_requests::settlement_source(
                e,
                &r.principal_id,
                &r.source.intake_request_id,
            )? != r.source
        {
            return Err(inconsistent());
        }
        match r.state {
            NativeRequestState::Queued | NativeRequestState::Withdrawn => {
                if r.attempt_revision.is_some() || r.observation.is_some() {
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
        match r.kind {
            SettlementRequestKind::SignatureReconcile => {
                if r.expected_signed.is_some() {
                    return Err(inconsistent());
                }
            }
            SettlementRequestKind::TransactionCheckpoint => {
                if r.expected_signed.as_ref()
                    != Some(&reconciled_signed(e, &r.principal_id, &r.source)?)
                {
                    return Err(inconsistent());
                }
            }
        }
        if let Some(result) = &r.observation {
            match result {
                SettlementObservation::Signed { evidence } => {
                    if r.kind != SettlementRequestKind::SignatureReconcile
                        || !valid_signed(evidence)
                    {
                        return Err(inconsistent());
                    }
                }
                SettlementObservation::Transaction {
                    signed,
                    checkpoint_id,
                    transaction_digest,
                    txid,
                } => {
                    if r.kind != SettlementRequestKind::TransactionCheckpoint
                        || r.expected_signed.as_ref() != Some(signed)
                        || !valid_signed(signed)
                        || !signed.signatures_complete
                        || !checkpoint_id
                            .strip_prefix("transaction-")
                            .is_some_and(digest)
                        || !digest(transaction_digest)
                        || !digest(txid)
                    {
                        return Err(inconsistent());
                    }
                }
            }
        }
    }
    Ok(())
}
#[cfg(feature = "transaction-checkpoint")]
mod owner;
#[cfg(test)]
mod tests;

/// Reconstruct the complete original completed-checkpoint metadata. This is
/// historical source identity only, never proof/signing/submission authority.
pub(crate) fn dispatch_source(
    e: &Envelope,
    principal: &str,
    request: &str,
) -> Result<crate::native_dispatch_requests::DispatchSource> {
    let row = e
        .native_settlement_requests
        .get(request)
        .filter(|row| row.principal_id == principal)
        .ok_or_else(not_found)?;
    if row.kind != SettlementRequestKind::TransactionCheckpoint
        || row.state != NativeRequestState::AttemptStarted
    {
        return Err(inconsistent());
    }
    let Some(SettlementObservation::Transaction {
        signed,
        checkpoint_id,
        transaction_digest,
        txid,
    }) = &row.observation
    else {
        return Err(ApiError::new(
            "MISSING_EVIDENCE",
            "Inspect the exact original completed transaction checkpoint first",
        ));
    };
    if !valid_signed(signed)
        || !signed.signatures_complete
        || row.expected_signed.as_ref() != Some(signed)
        || !checkpoint_id
            .strip_prefix("transaction-")
            .is_some_and(digest)
        || !digest(transaction_digest)
        || !digest(txid)
    {
        return Err(inconsistent());
    }
    Ok(crate::native_dispatch_requests::DispatchSource {
        transaction_request_id: row.request_id.clone(),
        original: row.source.clone(),
        signed: signed.clone(),
        checkpoint_id: checkpoint_id.clone(),
        transaction_digest: transaction_digest.clone(),
        txid: txid.clone(),
    })
}
