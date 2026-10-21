//! Actual-source preparation, display and disposal only. This API is NOT native
//! consent, caller/process-origin authentication or a financial capability.
//! The fixed coordinator W branch checks its own genuine origin before calling.
//! Preparation reads existing private credentials, may perform the maintained
//! encrypted opener's sidecar work, and binds an inert listener. It is not a
//! zero-I/O or globally read-only operation. No accept/arm/append route exists.
use super::{delivery_preparation_v2::{self, InputsV2, PreparedNativeV2}, lifecycle::ReviewClock};
use crate::{witness_locator::NamespaceOpenInput, AuthorityError, OwnerControl, OwnerControlRequest, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::Path};
use zeroize::{Zeroize, Zeroizing};

pub const PRESENTATION_VERSION: u16 = 1;
pub const PRESENTATION_PURPOSE: &str = "coordinated-witness-durable-delivery-review";
pub const PRESENTATION_MODE: &str = "cancel-only";
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_REVIEW_BYTES: usize = 512 * 1024;
const MAX_REVIEW_LIFETIME_MS: u64 = 120_000;
const CANCEL_NOTICE: &str = "Approval is unavailable in this review-only slice. No append can be admitted. Cancel, close, Escape, or focus loss requests disposal of this review.";
const TRUST_NOTICE: &str = "Pre-release source; attended runtime qualification is pending. This review relies on the trusted coordinator and Witness processes, OS and compositor. Existing certificate possession does not prove fresh keys, fresh account provenance or independent administration. No setup, reset or approval is available here.";

/// Ordinary untrusted form data. Paths select existing private files; their
/// contents are never transported. Empty Default is a form, not a usable source.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelOnlyDeliveryInputsV1 {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
    pub network_profile_id: String,
    pub expected_account_id: String,
    pub owner_certificate_der_hex: String,
    pub storage_key_file: String,
    pub server_certificate_der: String,
    pub server_private_key_pkcs8_der: String,
    pub trusted_client_root_der: String,
    pub request_json: String,
}
impl CancelOnlyDeliveryInputsV1 {
    /// Pure shape validation only: no file, namespace, socket, password or key
    /// access, and no authentication of the actual selected original source.
    pub fn validate(&self) -> Result<()> {
        self.validate_lengths()?;
        let address: SocketAddr = self.endpoint.parse().map_err(|_| AuthorityError::InvalidBinding)?;
        if address.to_string() != self.endpoint || address.port() == 0
            || address.ip().is_unspecified() || address.ip().is_multicast()
        { return Err(AuthorityError::InvalidBinding); }
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| AuthorityError::InvalidBinding)?;
        crate::id(&self.witness_id)?;
        crate::id(&self.network_profile_id)?;
        crate::hash(&self.pinned_server_certificate_digest)?;
        crate::hash(&self.expected_account_id)?;
        for path in [&self.storage_key_file, &self.server_certificate_der,
            &self.server_private_key_pkcs8_der, &self.trusted_client_root_der]
        { validate_path(path)?; }
        self.owner_pin()?;
        let request: OwnerControlRequest = wholepact_core::parse_typed_json(self.request_json.as_bytes())
            .map_err(|_| AuthorityError::InvalidBinding)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control
        else { return Err(AuthorityError::Permission); };
        if request.account_id != self.expected_account_id || request.network_profile_id != self.network_profile_id {
            return Err(AuthorityError::InvalidBinding);
        }
        record.validate_request_shape(&request)
    }
    fn validate_lengths(&self) -> Result<()> {
        for (value, max) in [
            (&self.endpoint, 256), (&self.server_name, 253), (&self.witness_id, 128),
            (&self.pinned_server_certificate_digest, 64), (&self.network_profile_id, 128),
            (&self.expected_account_id, 64), (&self.owner_certificate_der_hex, 2 * MAX_CERTIFICATE_BYTES),
            (&self.storage_key_file, 4096), (&self.server_certificate_der, 4096),
            (&self.server_private_key_pkcs8_der, 4096), (&self.trusted_client_root_der, 4096),
            (&self.request_json, crate::MAX_FRAME_BYTES),
        ] {
            if value.is_empty() || value.len() > max { return Err(AuthorityError::Limit); }
        }
        Ok(())
    }
    fn owner_pin(&self) -> Result<String> {
        if self.owner_certificate_der_hex.is_empty()
            || self.owner_certificate_der_hex.len() > 2 * MAX_CERTIFICATE_BYTES
        { return Err(AuthorityError::Limit); }
        let der = Zeroizing::new(hex::decode(&self.owner_certificate_der_hex)
            .map_err(|_| AuthorityError::InvalidBinding)?);
        if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES { return Err(AuthorityError::InvalidBinding); }
        let certificate = rustls::pki_types::CertificateDer::from(der.as_slice());
        // Same public DER shape check as the original independently chosen form;
        // actual namespace policy and TLS authentication are separate checks.
        webpki::EndEntityCert::try_from(&certificate).map_err(|_| AuthorityError::InvalidBinding)?;
        Ok(crate::transport::certificate_digest(&certificate))
    }
}
fn validate_path(value: &str) -> Result<()> {
    if !Path::new(value).is_absolute() || value.len() > 4096 || value.ends_with('/')
        || value.bytes().any(|c| c.is_ascii_control())
        || value[1..].split('/').any(|part| part.is_empty() || part == "." || part == "..")
    { return Err(AuthorityError::InvalidBinding); }
    Ok(())
}

/// Inert bounded display data. Even a valid digest is correlation, never source
/// ownership, caller-origin proof, freshness, consent or permission to act.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelOnlyDeliveryPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub mode: String,
    pub display: String,
    pub backend_review_digest: String,
    pub presentation_digest: String,
    pub prepared_at_ms: u64,
    pub expires_at_ms: u64,
}
impl CancelOnlyDeliveryPresentationV1 {
    /// Pure validation of complete presentation bytes. Authentication must come
    /// separately from the retained original credential-checked role channel.
    pub fn validate(&self) -> Result<()> {
        if self.version != PRESENTATION_VERSION || self.purpose != PRESENTATION_PURPOSE
            || self.mode != PRESENTATION_MODE || self.display.is_empty()
            || self.display.len() > MAX_REVIEW_BYTES
            || !self.display.contains(CANCEL_NOTICE) || !self.display.contains(TRUST_NOTICE)
            || self.display.chars().any(|c| c != '\n' && c != ' ' && !c.is_ascii_graphic())
            || self.expires_at_ms.checked_sub(self.prepared_at_ms)
                .is_none_or(|lifetime| lifetime == 0 || lifetime > MAX_REVIEW_LIFETIME_MS)
        { return Err(AuthorityError::InvalidBinding); }
        crate::hash(&self.backend_review_digest)?;
        crate::hash(&self.presentation_digest)?;
        if self.presentation_digest != self.calculate_digest() { return Err(AuthorityError::InvalidBinding); }
        Ok(())
    }
    fn calculate_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"wholepact:coordinated-witness-cancel-only-presentation:v1\0");
        digest.update(self.version.to_le_bytes());
        for text in [&self.purpose, &self.mode, &self.display, &self.backend_review_digest] {
            digest.update((text.len() as u64).to_le_bytes());
            digest.update(text.as_bytes());
        }
        digest.update(self.prepared_at_ms.to_le_bytes());
        digest.update(self.expires_at_ms.to_le_bytes());
        hex::encode(digest.finalize())
    }
    fn from_facts(display: String, backend_review_digest: String, clock: &ReviewClock) -> Result<Self> {
        let (prepared_at_ms, expires_at_ms) = clock.display_bounds()?;
        let display = inert_text(&format!("{display}\n\nOriginal backend review digest: {backend_review_digest}\n\n{TRUST_NOTICE}"));
        if display.len() > MAX_REVIEW_BYTES { return Err(AuthorityError::Limit); }
        let mut result = Self {
            version: PRESENTATION_VERSION, purpose: PRESENTATION_PURPOSE.into(), mode: PRESENTATION_MODE.into(),
            display, backend_review_digest, presentation_digest: String::new(), prepared_at_ms, expires_at_ms,
        };
        result.presentation_digest = result.calculate_digest();
        result.validate()?;
        Ok(result)
    }
}
fn inert_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\n' || c == ' ' || c.is_ascii_graphic() { safe.push(c); }
        else { safe.extend(c.escape_default()); }
    }
    safe
}

/// Opaque real preparation custody. Deliberately no Debug/Clone/serde/Default,
/// public fields, inner getters, decision conversion, arm/server/append API or
/// raw-descriptor interface. Must remain exclusively in the actual W worker.
pub struct CancelOnlyDeliveryReviewV1 {
    prepared: PreparedNativeV2,
    presentation: CancelOnlyDeliveryPresentationV1,
    clock: ReviewClock,
}
impl CancelOnlyDeliveryReviewV1 {
    /// Does real protected-source/TLS preparation and binds the exact listener.
    /// The caller must be the reviewed fixed W branch; this API itself makes no
    /// origin claim. Never call from C or its native event/control thread.
    pub fn prepare(input: CancelOnlyDeliveryInputsV1) -> Result<Self> {
        input.validate()?;
        let owner_certificate_digest = input.owner_pin()?;
        let namespace = NamespaceOpenInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: None,
            endpoint: input.endpoint, server_name: input.server_name, witness_id: input.witness_id,
            pinned_server_certificate_digest: input.pinned_server_certificate_digest,
            owner_certificate_digest, network_profile_id: input.network_profile_id,
            storage_key_file: input.storage_key_file, expected_account_id: input.expected_account_id,
        };
        let fields = InputsV2 {
            request_json: Zeroizing::new(input.request_json),
            server_certificate_der: input.server_certificate_der,
            server_private_key_pkcs8_der: input.server_private_key_pkcs8_der,
            trusted_client_root_der: input.trusted_client_root_der,
        };
        let prepared = delivery_preparation_v2::prepare(namespace, fields)?;
        let clock = ReviewClock::start(prepared.proposal.first_commit_deadline_ms())?;
        let backend_review_digest = prepared.proposal.review_digest()?;
        let display = prepared.proposal.cancel_only_display_v1()?;
        let presentation = CancelOnlyDeliveryPresentationV1::from_facts(display, backend_review_digest, &clock)?;
        let result = Self { prepared, presentation, clock };
        result.check_current()?;
        Ok(result)
    }
    pub fn presentation(&self) -> &CancelOnlyDeliveryPresentationV1 { &self.presentation }
    /// May block in original filesystem, namespace/registry and journal locks.
    /// Run ONLY on the private W preparation/disposal worker, never C or the
    /// responsive role-control thread. It never refreshes the original clock.
    pub fn check_current(&self) -> Result<()> {
        self.clock.check()?;
        self.prepared.proposal.check_current()?;
        self.clock.check()
    }
    /// Unconditional consuming disposal, even after expiry/currentness failure.
    /// Returns only after every owned field has dropped. The role driver must
    /// additionally observe successful worker join before acknowledging disposal.
    pub fn dispose(self) { drop(self); }
}
impl Drop for CancelOnlyDeliveryReviewV1 {
    fn drop(&mut self) { self.presentation.display.zeroize(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    // These tests exercise inert parsing/bounds/digests only. Never call prepare,
    // check_current, a key reader, namespace opener, socket or native surface.
    #[test]
    fn empty_input_is_not_a_source_and_unknown_authority_fields_are_rejected() {
        assert!(CancelOnlyDeliveryInputsV1::default().validate().is_err());
        let value = serde_json::to_value(CancelOnlyDeliveryInputsV1::default()).unwrap();
        for field in ["synthetic_installation", "namespace_root", "role", "fd", "approved", "password"] {
            let mut altered = value.clone();
            altered.as_object_mut().unwrap().insert(field.into(), serde_json::json!(true));
            assert!(serde_json::from_value::<CancelOnlyDeliveryInputsV1>(altered).is_err());
        }
    }
    #[test]
    fn every_form_field_is_nonempty_and_bounded_before_backend_preparation() {
        let values = serde_json::json!({
            "endpoint": "127.0.0.1:443", "server_name": "witness.example",
            "witness_id": "witness", "pinned_server_certificate_digest": "a".repeat(64),
            "network_profile_id": "test", "expected_account_id": "b".repeat(64),
            "owner_certificate_der_hex": "00", "storage_key_file": "/not-opened/storage-key",
            "server_certificate_der": "/not-opened/cert", "server_private_key_pkcs8_der": "/not-opened/tls-key",
            "trusted_client_root_der": "/not-opened/root", "request_json": "{}",
        });
        let input: CancelOnlyDeliveryInputsV1 = serde_json::from_value(values.clone()).unwrap();
        assert!(input.validate_lengths().is_ok());
        // Invalid public DER/request deliberately cannot become a real source.
        assert!(input.validate().is_err());
        for (field, max) in [
            ("endpoint", 256), ("server_name", 253), ("witness_id", 128),
            ("pinned_server_certificate_digest", 64), ("network_profile_id", 128),
            ("expected_account_id", 64), ("owner_certificate_der_hex", 2 * MAX_CERTIFICATE_BYTES),
            ("storage_key_file", 4096), ("server_certificate_der", 4096),
            ("server_private_key_pkcs8_der", 4096), ("trusted_client_root_der", 4096),
            ("request_json", crate::MAX_FRAME_BYTES),
        ] {
            for replacement in [String::new(), "x".repeat(max + 1)] {
                let mut altered = values.clone();
                altered[field] = serde_json::Value::String(replacement);
                let input: CancelOnlyDeliveryInputsV1 = serde_json::from_value(altered).unwrap();
                assert!(input.validate_lengths().is_err());
            }
        }
    }
    #[test]
    fn path_validation_is_inert_and_rejects_overrides_and_controls() {
        assert!(validate_path("/operator/existing/key").is_ok());
        for path in ["", "relative", "/", "/a/../key", "/a/./key", "/a//key", "/a/key/", "/a/ke\ny", "/a/ke\0y"] {
            assert!(validate_path(path).is_err());
        }
        assert!(validate_path(&format!("/{}", "a".repeat(4096))).is_err());
    }
    fn inert_presentation() -> CancelOnlyDeliveryPresentationV1 {
        let mut data = CancelOnlyDeliveryPresentationV1 {
            version: PRESENTATION_VERSION, purpose: PRESENTATION_PURPOSE.into(), mode: PRESENTATION_MODE.into(),
            display: format!("INERT DATA TEST ONLY\n{CANCEL_NOTICE}\n{TRUST_NOTICE}"),
            backend_review_digest: "a".repeat(64), presentation_digest: String::new(),
            prepared_at_ms: 1000, expires_at_ms: 121000,
        };
        data.presentation_digest = data.calculate_digest();
        data
    }
    #[test]
    fn presentation_binds_notice_mode_backend_digest_and_original_bounds() {
        let original = inert_presentation();
        assert!(original.validate().is_ok());
        let mut changed = original.clone(); changed.mode = "one-exact-append".into();
        assert!(changed.validate().is_err());
        let mut changed = original.clone(); changed.display.push_str("extra text");
        assert!(changed.validate().is_err());
        let mut changed = original.clone(); changed.backend_review_digest = "b".repeat(64);
        assert!(changed.validate().is_err());
        let mut changed = original.clone(); changed.expires_at_ms += 1;
        assert!(changed.validate().is_err());
        let mut changed = original.clone(); changed.version += 1;
        assert!(changed.validate().is_err());
        let mut changed = original; changed.display = "Legacy cancel-before-publication promise".into();
        changed.presentation_digest = changed.calculate_digest();
        assert!(changed.validate().is_err());
    }
    #[test]
    fn presentation_is_complete_bounded_inert_data_not_a_hidden_control_channel() {
        let original = inert_presentation();
        let bytes = serde_json::to_vec(&original).unwrap();
        let roundtrip: CancelOnlyDeliveryPresentationV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(roundtrip.validate().is_ok());
        let mut changed = original.clone(); changed.display.push('\u{202e}');
        changed.presentation_digest = changed.calculate_digest();
        assert!(changed.validate().is_err());
        let mut changed = original.clone(); changed.display.push_str(&"x".repeat(MAX_REVIEW_BYTES));
        changed.presentation_digest = changed.calculate_digest();
        assert!(changed.validate().is_err());
        let mut value = serde_json::to_value(original).unwrap();
        value.as_object_mut().unwrap().insert("approval".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<CancelOnlyDeliveryPresentationV1>(value).is_err());
        assert_eq!(inert_text("safe\n\t\u{202e}"), "safe\n\\t\\u{202e}");
    }
}
