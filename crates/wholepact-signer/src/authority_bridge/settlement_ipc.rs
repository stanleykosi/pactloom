//! Request-only canonical settlement observation. Identifiers select protected
//! originals; neither request JSON nor the returned acknowledgement is evidence
//! of current chain state or authority to spend. The native runtime chooses its
//! currently enrolled source and requires a separate exact native decision.
use super::{
    BridgeError, Result,
    dispatch_ipc::write_frame,
    ipc::{HistoryRequest, OriginalHistoryClient},
    protocol::OriginalAuthorizationView,
};
use crate::{
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::AuthenticatedPeer,
};
use serde::{Deserialize, Serialize};
use std::{os::unix::net::UnixStream, time::Duration};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementRequest {
    pub history: HistoryRequest,
    pub dispatch_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<wholepact_chain::local_node::CanonicalConflictCandidate>,
}
impl SettlementRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        self.history.validate()?;
        if let Some(candidate) = &self.conflict {
            candidate
                .validate_shape()
                .map_err(|_| BridgeError::Binding)?;
        }
        crate::review::validate_label(&self.dispatch_operation_id).map_err(|_| BridgeError::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:signer-settlement-request:v1", self)
            .map_err(|_| BridgeError::Binding)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SettlementResponse {
    Committed { request_digest: String },
    Denied,
}

/// Verify the authenticated request against signer-owned history before staging
/// native review and again before execution. This does not grant approval.
#[cfg(feature = "authority-signing")]
pub(crate) fn validate_native_request(
    request: &SettlementRequest,
    peer: &AuthenticatedPeer,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> Result<()> {
    request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.history_read || !peer.scope.authorization_export {
        return Err(BridgeError::Permission);
    }
    let lease =
        journal.acquire_original_authorization(&request.history.authorization_id, session)?;
    let original = OriginalAuthorizationView::from_original(lease.evidence());
    request.history.matches(&original)?;
    if original.enrollment.account_id() != peer.scope.account_id
        || original.enrollment.agreement_id() != peer.scope.agreement_id
        || original.enrollment.participant_id() != peer.scope.participant_id
        || original.accepted_manifest.manifest_digest() != peer.scope.manifest_digest
    {
        return Err(BridgeError::Permission);
    }
    lease.check_current()?;
    // Candidate validation obtains its own protected original-history lease.
    // Release this read fence first: a queued writer can make recursive reads wait.
    drop(lease);
    if let Some(candidate) = &request.conflict {
        journal.validate_settlement_candidate(
            &request.history.authorization_id,
            &request.dispatch_operation_id,
            candidate,
            session,
        )?;
    }
    peer.check_current().map_err(|_| BridgeError::Permission)
}

/// Builds without the concrete settlement owner cannot admit this operation.
#[cfg(not(feature = "authority-signing"))]
pub(crate) fn validate_native_request(
    _request: &SettlementRequest,
    _peer: &AuthenticatedPeer,
    _journal: &SignerConsentJournal,
    _session: &SignerConsentSession,
) -> Result<()> { Err(BridgeError::Permission) }

/// Call only after the destination journal's durable resolution commit. An
/// uncertain/lost reply never licenses a caller to infer that commit occurred.
pub(crate) fn acknowledge_commit(
    stream: &mut UnixStream,
    request: &SettlementRequest,
) -> Result<()> {
    write_frame(
        stream,
        &SettlementResponse::Committed {
            request_digest: request.digest()?,
        },
    )
}
/// Historical commit acknowledgement with authenticated connection provenance.
/// There is intentionally no Deserialize, Clone, public constructor, conversion
/// to a settlement permit, or claim that the chain remains canonical now.
pub struct SignerSettlementReceipt<'a> {
    _client: &'a OriginalHistoryClient,
    _stream: UnixStream,
    request_digest: String,
}
impl SignerSettlementReceipt<'_> {
    /// The historical commit and original history must come from the same
    /// authenticated, independently enrolled signer client.
    pub fn matches_history(&self, history: &super::ipc::OriginalHistoryLease<'_>) -> bool {
        history.belongs_to(self._client)
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
}
impl OriginalHistoryClient {
    pub fn request_settlement(
        &self,
        request: &SettlementRequest,
    ) -> Result<SignerSettlementReceipt<'_>> {
        let expected = request.digest()?;
        let stream = self.open_authenticated_request(
            serde_json::json!({"operation":"request_settlement", "request":request}),
        )?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: SettlementResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        match response {
            SettlementResponse::Committed { request_digest } if request_digest == expected => {
                self.peer()
                    .check_alive()
                    .map_err(|_| BridgeError::Permission)?;
                Ok(SignerSettlementReceipt {
                    _client: self,
                    _stream: stream,
                    request_digest,
                })
            }
            SettlementResponse::Committed { .. } => Err(BridgeError::Binding),
            SettlementResponse::Denied => Err(BridgeError::Permission),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> SettlementRequest {
        SettlementRequest {
            history: HistoryRequest {
                authorization_id: "synthetic-authorization".into(),
                expected_original_consent_ref: "12".repeat(32),
                expected_enrollment_ref: "34".repeat(32),
                expected_manifest_ref: "56".repeat(32),
            },
            dispatch_operation_id: "synthetic-dispatch".into(),
            conflict: None,
        }
    }
    #[test]
    fn settlement_request_binds_exact_original_and_dispatch() {
        let r = fixture();
        let digest = r.digest().unwrap();
        let mut changed = r.clone();
        changed.dispatch_operation_id.push('2');
        assert_ne!(digest, changed.digest().unwrap());
        let mut changed = r.clone();
        changed.history.expected_original_consent_ref = "78".repeat(32);
        assert_ne!(digest, changed.digest().unwrap());
        let value = serde_json::to_value(&r).unwrap();
        assert!(serde_json::from_value::<SettlementRequest>(value).is_ok());
    }
    #[test]
    fn settlement_request_cannot_supply_source_or_authority() {
        for key in [
            "approved",
            "verified",
            "source_reference",
            "source",
            "proof",
            "receipt",
            "reorg",
        ] {
            let mut value = serde_json::to_value(fixture()).unwrap();
            value[key] = true.into();
            assert!(serde_json::from_value::<SettlementRequest>(value).is_err());
        }
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["history"]["verified"] = true.into();
        assert!(serde_json::from_value::<SettlementRequest>(value).is_err());
    }
    #[test]
    fn malformed_request_and_expanded_acknowledgement_fail_closed() {
        let mut r = fixture();
        r.dispatch_operation_id = "synthetic\nAPPROVED".into();
        assert!(r.digest().is_err());
        let mut r = fixture();
        r.history.expected_enrollment_ref = "AB".repeat(32);
        assert!(r.digest().is_err());
        assert!(
            serde_json::from_value::<SettlementResponse>(serde_json::json!({
                "status":"committed", "request_digest":"12".repeat(32), "spending_authority":true
            }))
            .is_err()
        );
    }
    #[test]
    fn canonical_conflict_request_digest_binds_alternative_raw_original_and_nullifier() {
        let mut request = fixture();
        let old = request.digest().unwrap();
        request.conflict = Some(wholepact_chain::local_node::CanonicalConflictCandidate {
            included_transaction_id: "11".repeat(32),
            original_transaction_hex: "00".into(),
            nullifier: "22".repeat(32),
        });
        let exact = request.digest().unwrap();
        assert_ne!(old, exact);
        for mode in 0..3 {
            let mut changed = request.clone();
            let candidate = changed.conflict.as_mut().unwrap();
            match mode {
                0 => candidate.included_transaction_id = "33".repeat(32),
                1 => candidate.original_transaction_hex = "01".into(),
                _ => candidate.nullifier = "44".repeat(32),
            }
            assert_ne!(exact, changed.digest().unwrap());
        }
    }
    /// Frozen synthetic request from the pre-conflict wire format.
    #[test]
    fn legacy_settlement_request_json_preserves_bytes_and_digest() {
        const LEGACY: &str = r#"{"history":{"authorization_id":"synthetic-authorization","expected_original_consent_ref":"1212121212121212121212121212121212121212121212121212121212121212","expected_enrollment_ref":"3434343434343434343434343434343434343434343434343434343434343434","expected_manifest_ref":"5656565656565656565656565656565656565656565656565656565656565656"},"dispatch_operation_id":"synthetic-dispatch"}"#;
        let request: SettlementRequest = serde_json::from_str(LEGACY).unwrap();
        assert!(request.conflict.is_none());
        assert_eq!(serde_json::to_string(&request).unwrap(), LEGACY);
        assert_eq!(
            request.digest().unwrap(),
            "68de869dc275a0270815e30107689fa47918ad0421a5f254248184f08fef12ef"
        );
    }
}
