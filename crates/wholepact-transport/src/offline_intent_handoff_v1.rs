//! Inert exact-request courier file. Parsing authenticates nothing and grants no
//! enrollment, witness reservation, transport receipt or signing authority.
use crate::{EncryptedEnvelope, Result, TransportError};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_authority::{
    MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1, OfflineAdmissionExportPlan,
    offline::ReserveOfflineAuthorization, validate_offline_intent_delivery_size_v1,
};

pub const MAX_OFFLINE_INTENT_HANDOFF_BYTES_V1: usize = 2 * 1024 * 1024;
const FORMAT: &str = "wholepact.offline-intent-handoff.v1";

/// Untrusted public data, deliberately not Debug. This file discloses the full
/// own request/inputs to its online controller; native export must say so.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineIntentHandoffV1 {
    format: String,
    schema_version: u16,
    request: ReserveOfflineAuthorization,
    admission_export_template: OfflineAdmissionExportPlan,
    encrypted_intent_base64: String,
}
impl OfflineIntentHandoffV1 {
    pub fn from_untrusted_parts(
        request: ReserveOfflineAuthorization,
        admission_export_template: OfflineAdmissionExportPlan,
        encrypted_intent: &[u8],
    ) -> Result<Self> {
        if encrypted_intent.is_empty()
            || encrypted_intent.len() > MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1
        {
            return Err(TransportError::ResourceLimit);
        }
        let value = Self {
            format: FORMAT.into(),
            schema_version: 1,
            request,
            admission_export_template,
            encrypted_intent_base64: STANDARD_NO_PAD.encode(encrypted_intent),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_OFFLINE_INTENT_HANDOFF_BYTES_V1 {
            return Err(TransportError::ResourceLimit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| TransportError::Malformed)?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(TransportError::Malformed);
        }
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.format != FORMAT || self.schema_version != 1 {
            return Err(TransportError::UnsupportedVersion);
        }
        self.request
            .validate()
            .map_err(|_| TransportError::WrongContext)?;
        if self.admission_export_template.sequence != 0 {
            return Err(TransportError::WrongContext);
        }
        let mut allocated_shape = self.admission_export_template.clone();
        allocated_shape.sequence = 1;
        allocated_shape
            .validate()
            .map_err(|_| TransportError::WrongContext)?;
        let t = &self.request.intent.terms;
        let plan = &self.admission_export_template;
        let start = u64::try_from(plan.issued_at_unix_seconds)
            .ok()
            .and_then(|v| v.checked_mul(1000))
            .ok_or(TransportError::WrongContext)?;
        let end = u64::try_from(plan.expires_at_unix_seconds)
            .ok()
            .and_then(|v| v.checked_mul(1000))
            .ok_or(TransportError::WrongContext)?;
        if start < self.request.requested_at_ms
            || end > self.request.admission_expires_at_ms
            || plan.sender_id != format!("offline-admission:{}", t.offline_policy_digest)
            || plan.recipient_id != format!("offline-admission:{}", t.offline_signer_key_digest)
            || plan.recipient_key_fingerprint != t.offline_signer_key_digest
        {
            return Err(TransportError::WrongContext);
        }
        let bytes = self.encrypted_intent()?;
        validate_offline_intent_delivery_size_v1(
            &self.request,
            &bytes,
            &self.admission_export_template,
        )
        .map_err(|_| TransportError::ResourceLimit)?;
        EncryptedEnvelope::from_bytes(bytes)?;
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| TransportError::Malformed)?;
        if bytes.len() > MAX_OFFLINE_INTENT_HANDOFF_BYTES_V1 {
            return Err(TransportError::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn commitment(&self) -> Result<String> {
        let mut h = Sha256::new();
        h.update(b"wholepact:offline-intent-handoff:v1\0");
        h.update(self.canonical_bytes()?);
        Ok(hex::encode(h.finalize()))
    }
    pub fn request(&self) -> &ReserveOfflineAuthorization {
        &self.request
    }
    pub fn admission_export_template(&self) -> &OfflineAdmissionExportPlan {
        &self.admission_export_template
    }
    pub fn encrypted_intent(&self) -> Result<Vec<u8>> {
        if self.encrypted_intent_base64.is_empty()
            || self.encrypted_intent_base64.len()
                > MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1.div_ceil(3) * 4
        {
            return Err(TransportError::ResourceLimit);
        }
        let bytes = STANDARD_NO_PAD
            .decode(&self.encrypted_intent_base64)
            .map_err(|_| TransportError::Malformed)?;
        if bytes.len() > MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1
            || STANDARD_NO_PAD.encode(&bytes) != self.encrypted_intent_base64
        {
            return Err(TransportError::Malformed);
        }
        Ok(bytes)
    }
    pub fn grants_signing_authority(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[path = "offline_intent_handoff_v1_tests.rs"]
mod tests;
