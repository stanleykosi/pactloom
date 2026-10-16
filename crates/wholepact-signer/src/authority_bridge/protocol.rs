//! Exact immutable evidence carried by the signer bridge. None of these
//! serializable records is an approval, authenticated permit or key-use token.
use super::{BridgeError, Result};
use crate::consent_journal::{OriginalAuthorizationEvidence, TransportIdentityBinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_authority::{
    AuthorityHead, InputReservation, ReservationPermit, ReserveAuthorization,
};

pub const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_OUTBOX_BYTES: usize = 16 * 1024;

/// Exact coordinator correlation label. It cannot select an account, recipient,
/// amount or input: all such terms come from original signer-owned consent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDeliveryScope {
    pub candidate_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedAuthorizationRequest {
    pub(crate) reservation: ReserveAuthorization,
    pub(crate) delivery: AuthorizationDeliveryScope,
    pub(crate) artifact_hex: String,
    pub(crate) disclosure: Option<super::disclosure::RetainedWitnessDisclosure>,
}
impl RetainedAuthorizationRequest {
    pub fn reservation(&self) -> &ReserveAuthorization {
        &self.reservation
    }
    pub fn delivery(&self) -> &AuthorizationDeliveryScope {
        &self.delivery
    }
    pub(crate) fn from_original(
        original: &OriginalAuthorizationEvidence,
        bytes: &[u8],
        expected_head: AuthorityHead,
        delivery: AuthorizationDeliveryScope,
    ) -> Result<Self> {
        crate::review::validate_label(&delivery.candidate_id).map_err(|_| BridgeError::Binding)?;
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(BridgeError::Limit);
        }
        let c = original.original_consent();
        let t = c.terms();
        if delivery.candidate_id != t.proposal_id {
            return Err(BridgeError::Binding);
        }
        if hex::encode(Sha256::digest(bytes)) != t.artifact_digest {
            return Err(BridgeError::Binding);
        }
        // The native receipt fixes the time window. The caller cannot extend it.
        let recipient_scope_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:signer-exact-authorization-recipient:v1",
            &(original.enrollment().transport(), &delivery),
        )
        .map_err(|_| BridgeError::Binding)?;
        let reservation = ReserveAuthorization {
            automation: t.automation.as_ref().map(|a| a.grant.clone()),
            operation_id: t.authorization_id.clone(),
            account_id: t.account_id.clone(),
            network_profile_id: original
                .accepted_manifest()
                .proposal_input()
                .manifest
                .agreement
                .network_profile_id
                .clone(),
            writer_epoch: t.receipt.writer_epoch(),
            expected_head,
            authorization_id: t.authorization_id.clone(),
            original_consent_ref: c.reference().into(),
            enrollment_ref: original.enrollment().reference().into(),
            accepted_manifest_ref: original.accepted_manifest().reference().into(),
            agreement_id: t.agreement_id.clone(),
            obligation_id: t.obligation_id.clone(),
            proposal_id: t.proposal_id.clone(),
            proposal_digest: t.proposal_digest.clone(),
            manifest_digest: t.manifest_digest.clone(),
            effects_digest: t.effects_digest.clone(),
            artifact_digest: t.artifact_digest.clone(),
            review_binding: t.review_binding.clone(),
            recipient_scope_digest,
            inputs: t
                .input_bindings
                .iter()
                .map(|i| InputReservation {
                    input_id: i.input_id.clone(),
                    nullifier: i.nullifier.clone(),
                    action_index: i.action_index,
                    value_zatoshis: i.value_zatoshis,
                })
                .collect(),
            maximum_debit_zatoshis: t.maximum_debit_zatoshis,
            fee_share_zatoshis: t.fee_share_zatoshis,
            transaction_fee_zatoshis: t.transaction_fee_zatoshis,
            transaction_expiry_height: t.transaction_expiry_height,
            reviewed_at_ms: t.receipt.reviewed_at_ms(),
            permit_expires_at_ms: t
                .automation
                .as_ref()
                .map_or(t.receipt.expires_at_ms(), |a| a.authorization_expires_at_ms),
        };
        reservation.validate().map_err(BridgeError::Authority)?;
        Ok(Self {
            reservation,
            delivery,
            artifact_hex: hex::encode(bytes),
            disclosure: None,
        })
    }
    pub(crate) fn validate_original(&self, original: &OriginalAuthorizationEvidence) -> Result<()> {
        let bytes = self.artifact()?;
        let mut expected = Self::from_original(
            original,
            &bytes,
            self.reservation.expected_head.clone(),
            self.delivery.clone(),
        )?;
        expected.disclosure = self.disclosure.clone();
        if let Some(disclosure) = &self.disclosure {
            disclosure.validate_original(original.original_consent())?;
            if disclosure.expected_head != self.reservation.expected_head
                || disclosure.descriptor.network_profile_id != self.reservation.network_profile_id
            {
                return Err(BridgeError::Binding);
            }
        }
        if expected != *self {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub(crate) fn artifact(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.artifact_hex.len() > MAX_ARTIFACT_BYTES * 2 {
            return Err(BridgeError::Limit);
        }
        let bytes = zeroize::Zeroizing::new(
            hex::decode(&self.artifact_hex).map_err(|_| BridgeError::Binding)?,
        );
        if bytes.is_empty()
            || hex::encode(Sha256::digest(&bytes)) != self.reservation.artifact_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(bytes)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedWitnessPermit {
    pub(crate) descriptor: ReservationPermit,
    pub(crate) witness_certificate_digest: String,
}
impl RetainedWitnessPermit {
    pub fn descriptor(&self) -> &ReservationPermit {
        &self.descriptor
    }
    pub fn witness_certificate_digest(&self) -> &str {
        &self.witness_certificate_digest
    }
    pub(crate) fn from_authenticated(
        permit: &wholepact_authority::AuthenticatedPermit,
        request: &ReserveAuthorization,
    ) -> Result<Self> {
        permit
            .matches_request(request)
            .map_err(BridgeError::Authority)?;
        Ok(Self {
            descriptor: permit.descriptor().clone(),
            witness_certificate_digest: permit.authenticated_witness_certificate_digest().into(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedAuthorizationResult {
    pub(crate) authorization_id: String,
    pub(crate) original_consent_ref: String,
    pub(crate) request_digest: String,
    pub(crate) result_digest: String,
    pub(crate) signed_pczt_hex: String,
    /// Original exact external_spend_signatures_v1 UTF-8 bytes, retained before
    /// any usable signature can leave the signer. Retries never reserialize it.
    pub(crate) outbox_payload: String,
    pub(crate) outbox_digest: String,
}
impl RetainedAuthorizationResult {
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.original_consent_ref
    }
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
    pub fn outbox_digest(&self) -> &str {
        &self.outbox_digest
    }
    pub(crate) fn validate(&self, request: &RetainedAuthorizationRequest) -> Result<()> {
        if self.authorization_id != request.reservation.authorization_id
            || self.original_consent_ref != request.reservation.original_consent_ref
            || self.request_digest
                != request
                    .reservation
                    .request_digest()
                    .map_err(BridgeError::Authority)?
            || self.signed_pczt_hex.is_empty()
            || self.signed_pczt_hex.len() > MAX_ARTIFACT_BYTES * 2
            || self.outbox_payload.is_empty()
            || self.outbox_payload.len() > MAX_OUTBOX_BYTES
        {
            return Err(BridgeError::Binding);
        }
        let bytes = zeroize::Zeroizing::new(
            hex::decode(&self.signed_pczt_hex).map_err(|_| BridgeError::Binding)?,
        );
        if hex::encode(Sha256::digest(&bytes)) != self.result_digest
            || hex::encode(Sha256::digest(self.outbox_payload.as_bytes())) != self.outbox_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

/// Read-only evidence response. Deserialization deliberately does not mint the
/// engine's authenticated association or original-consent lease.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedResultIdentity {
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub result_digest: String,
    pub outbox_digest: String,
    pub exact_local_recipient: TransportIdentityBinding,
    pub redelivery: Option<crate::consent_journal::ResultRedeliveryReference>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAuthorizationView {
    pub enrollment: crate::consent_journal::AccountEnrollmentRecord,
    pub accepted_manifest: crate::consent_journal::AcceptedManifestRecord,
    pub consent: crate::consent_journal::OriginalSpendConsent,
    pub release_intent: crate::consent_journal::ConsentLinkedReleaseIntent,
    pub retained_result: Option<RetainedResultIdentity>,
}
impl OriginalAuthorizationView {
    pub(crate) fn from_original(e: &OriginalAuthorizationEvidence) -> Self {
        Self {
            enrollment: e.enrollment().clone(),
            accepted_manifest: e.accepted_manifest().clone(),
            consent: e.original_consent().clone(),
            release_intent: e.release_intent().clone(),
            retained_result: None,
        }
    }
    pub fn transport(&self) -> &TransportIdentityBinding {
        self.enrollment.transport()
    }
}

impl Drop for RetainedAuthorizationRequest {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.artifact_hex);
    }
}
impl Drop for RetainedAuthorizationResult {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.signed_pczt_hex);
        zeroize::Zeroize::zeroize(&mut self.outbox_payload);
    }
}
