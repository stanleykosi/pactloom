//! Authenticated native disclosure intake for durable, NON-SPENDING material.
//! The response closes after one bounded export. Later construction never needs
//! this signer connection to remain alive. Public records are historical data;
//! only the actual authenticated client can produce an intake owner. Same-grant
//! redelivery cannot authorize a new pairing after restart; that needs a new native disclosure.
use super::{BridgeError, Result, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wholepact_core::Proposal;
pub use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
    DurableConstructionScopeV1, HistoricalConstructionMaterialV1,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionRequestV1 {
    pub operation_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub scope: DurableConstructionScopeV1,
    pub material: HistoricalConstructionMaterialV1,
}
pub(super) fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl DurableConstructionRequestV1 {
    pub fn validate(&self) -> Result<Proposal> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        hash(&self.enrollment_ref)?;
        hash(&self.accepted_manifest_ref)?;
        self.material
            .validate_for(&self.scope)
            .map_err(|_| BridgeError::Binding)?;
        let raw =
            zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?);
        if raw.len() > 120 * 1024 {
            return Err(BridgeError::Limit);
        }
        self.scope.validate().map_err(|_| BridgeError::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:durable-construction-disclosure-request:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionHistoryRequestV1 {
    pub operation_id: String,
    pub expected_request_digest: String,
}
impl DurableConstructionHistoryRequestV1 {
    pub fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        hash(&self.expected_request_digest)
    }
}
/// Historical signer-owned consent/outbox, not a portable authentication proof
/// or an executable permit. Native decision objects never appear on this wire.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableConstructionOutboxV1 {
    pub(crate) request: DurableConstructionRequestV1,
    pub(crate) request_digest: String,
    pub(crate) material_digest: String,
    pub(crate) native_review_digest: String,
    pub(crate) native_entry_digest: String,
    pub(crate) recipient_grant_digest: String,
    pub(crate) original_channel_digest: String,
    pub(crate) original_grant_id: String,
    pub(crate) reference: String,
}
impl DurableConstructionOutboxV1 {
    pub fn request(&self) -> &DurableConstructionRequestV1 {
        &self.request
    }
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    pub fn material_digest(&self) -> &str {
        &self.material_digest
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn recipient_grant_digest(&self) -> &str {
        &self.recipient_grant_digest
    }
    pub fn validate(&self) -> Result<()> {
        for h in [
            &self.request_digest,
            &self.material_digest,
            &self.native_review_digest,
            &self.native_entry_digest,
            &self.recipient_grant_digest,
            &self.original_channel_digest,
            &self.reference,
        ] {
            hash(h)?;
        }
        hash(&self.original_grant_id)?;
        let encoded =
            zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?);
        if encoded.len() > 128 * 1024 - 64 {
            return Err(BridgeError::Limit);
        }
        if self.request.digest()? != self.request_digest
            || self
                .request
                .material
                .digest()
                .map_err(|_| BridgeError::Binding)?
                != self.material_digest
            || self
                .request
                .scope
                .constructor
                .authenticated_local_grant_digest
                != self.recipient_grant_digest
            || self.request.scope.prover.authenticated_local_grant_digest
                != self.recipient_grant_digest
            || self.compute_reference()? != self.reference
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub(crate) fn compute_reference(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:durable-construction-consent-outbox:v1",
            &(
                &self.request_digest,
                &self.material_digest,
                &self.native_review_digest,
                &self.native_entry_digest,
                &self.recipient_grant_digest,
                &self.original_channel_digest,
                &self.original_grant_id,
            ),
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableConstructionResponseV1 {
    Retained {
        outbox: Box<DurableConstructionOutboxV1>,
    },
    Denied,
}
/// Sealed proof that THIS process received this exact immutable outbox from the
/// installed signer on its authenticated channel. No Clone/Deserialize/from-DTO.
/// It is consumed by encrypted engine intake, not by a spending API.
pub struct AuthenticatedDurableConstructionDisclosureV1 {
    outbox: DurableConstructionOutboxV1,
    signer_enrollment_reference: String,
    signer_process_instance: String,
}
impl AuthenticatedDurableConstructionDisclosureV1 {
    pub fn outbox(&self) -> &DurableConstructionOutboxV1 {
        &self.outbox
    }
    pub fn signer_enrollment_reference(&self) -> &str {
        &self.signer_enrollment_reference
    }
    pub fn signer_process_instance(&self) -> &str {
        &self.signer_process_instance
    }
}
impl OriginalHistoryClient {
    pub fn request_durable_construction_v1(
        &self,
        request: &DurableConstructionRequestV1,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        request.validate()?;
        let stream = self.open_preconstruction_request(
            serde_json::json!({"operation":"request_durable_construction_v1", "request":request}),
        )?;
        self.receive_durable_construction_v1(stream, &request.operation_id, &request.digest()?)
    }
    pub fn read_durable_construction_v1(
        &self,
        request: &DurableConstructionHistoryRequestV1,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        request.validate()?;
        let stream = self.open_preconstruction_request(serde_json::json!({"operation":"request_durable_construction_history_v1", "request":request}))?;
        self.receive_durable_construction_v1(
            stream,
            &request.operation_id,
            &request.expected_request_digest,
        )
    }
    fn receive_durable_construction_v1(
        &self,
        stream: std::os::unix::net::UnixStream,
        operation: &str,
        expected: &str,
    ) -> Result<AuthenticatedDurableConstructionDisclosureV1> {
        let observed = self.proved_disclosure_recipient()?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let response: DurableConstructionResponseV1 =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Binding)?;
        let DurableConstructionResponseV1::Retained { outbox } = response else {
            return Err(BridgeError::Permission);
        };
        outbox.validate()?;
        if outbox.request.operation_id != operation
            || outbox.request_digest != expected
            || outbox.request.scope.account_id != observed.account_id
        {
            return Err(BridgeError::Binding);
        }
        let current = self.proved_disclosure_recipient()?;
        if current != observed {
            return Err(BridgeError::Permission);
        }
        Ok(AuthenticatedDurableConstructionDisclosureV1 {
            outbox: *outbox,
            signer_enrollment_reference: observed.provider_enrollment_reference,
            signer_process_instance: observed.process_instance,
        })
    }
}
