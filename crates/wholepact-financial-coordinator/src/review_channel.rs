//! Explicit lossless ordinary-data mapping. Origin owns the finite wire grammar;
//! Authority still validates the full input and complete presentation commitment.
//! No serialization, display digest or mapping is financial authority.
use crate::{rejected, Result};
use wholepact_authority::native_witness_owner::cancel_delivery_review_v1::{CancelOnlyDeliveryInputsV1, CancelOnlyDeliveryPresentationV1};
use wholepact_financial_coordinator_origin::{CancelReviewInputsV1, CancelReviewPresentationV1};

pub(super) fn inputs_to_wire(value: CancelOnlyDeliveryInputsV1) -> CancelReviewInputsV1 {
    CancelReviewInputsV1 {
        endpoint: value.endpoint,
        server_name: value.server_name,
        witness_id: value.witness_id,
        pinned_server_certificate_digest: value.pinned_server_certificate_digest,
        network_profile_id: value.network_profile_id,
        expected_account_id: value.expected_account_id,
        owner_certificate_der_hex: value.owner_certificate_der_hex,
        storage_key_file: value.storage_key_file,
        server_certificate_der: value.server_certificate_der,
        server_private_key_pkcs8_der: value.server_private_key_pkcs8_der,
        trusted_client_root_der: value.trusted_client_root_der,
        request_json: value.request_json,
    }
}

pub(super) fn inputs_from_wire(value: CancelReviewInputsV1) -> CancelOnlyDeliveryInputsV1 {
    CancelOnlyDeliveryInputsV1 {
        endpoint: value.endpoint,
        server_name: value.server_name,
        witness_id: value.witness_id,
        pinned_server_certificate_digest: value.pinned_server_certificate_digest,
        network_profile_id: value.network_profile_id,
        expected_account_id: value.expected_account_id,
        owner_certificate_der_hex: value.owner_certificate_der_hex,
        storage_key_file: value.storage_key_file,
        server_certificate_der: value.server_certificate_der,
        server_private_key_pkcs8_der: value.server_private_key_pkcs8_der,
        trusted_client_root_der: value.trusted_client_root_der,
        request_json: value.request_json,
    }
}

pub(super) fn presentation_to_wire(value: CancelOnlyDeliveryPresentationV1) -> CancelReviewPresentationV1 {
    CancelReviewPresentationV1 {
        version: value.version,
        purpose: value.purpose,
        mode: value.mode,
        display: value.display,
        backend_review_digest: value.backend_review_digest,
        presentation_digest: value.presentation_digest,
        prepared_at_ms: value.prepared_at_ms,
        expires_at_ms: value.expires_at_ms,
    }
}

pub(super) fn presentation_from_wire(value: CancelReviewPresentationV1) -> CancelOnlyDeliveryPresentationV1 {
    CancelOnlyDeliveryPresentationV1 {
        version: value.version,
        purpose: value.purpose,
        mode: value.mode,
        display: value.display,
        backend_review_digest: value.backend_review_digest,
        presentation_digest: value.presentation_digest,
        prepared_at_ms: value.prepared_at_ms,
        expires_at_ms: value.expires_at_ms,
    }
}

pub(super) fn validate_presentation(p: &CancelOnlyDeliveryPresentationV1) -> Result<()> {
    p.validate().map_err(|_| rejected("invalid complete cancel-only presentation"))?;
    if p.display.len() > 65_536 - 1024 { return Err(rejected("cancel-only presentation too large")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancel_input_mapping_preserves_every_field_and_wire_schema() {
        let value = CancelOnlyDeliveryInputsV1 {
            endpoint: "field-0".into(),
            server_name: "field-1".into(),
            witness_id: "field-2".into(),
            pinned_server_certificate_digest: "field-3".into(),
            network_profile_id: "field-4".into(),
            expected_account_id: "field-5".into(),
            owner_certificate_der_hex: "field-6".into(),
            storage_key_file: "field-7".into(),
            server_certificate_der: "field-8".into(),
            server_private_key_pkcs8_der: "field-9".into(),
            trusted_client_root_der: "field-10".into(),
            request_json: "field-11".into(),
        };
        let original = serde_json::to_value(&value).unwrap();
        let wire = inputs_to_wire(value);
        assert_eq!(serde_json::to_value(&wire).unwrap(), original);
        let bytes = serde_json::to_vec(&wire).unwrap();
        let decoded = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(wire, decoded);
        assert_eq!(serde_json::to_value(inputs_from_wire(decoded)).unwrap(), original);
    }
    #[test]
    fn cancel_display_mapping_preserves_complete_bytes_and_original_bounds() {
        let value = CancelOnlyDeliveryPresentationV1 {
            version: 1, purpose: "purpose".into(), mode: "cancel-only".into(),
            display: "complete\nreview with \"quotes\" and \\ escapes".into(),
            backend_review_digest: "original-backend".into(), presentation_digest: "original-presentation".into(),
            prepared_at_ms: 123, expires_at_ms: 456,
        };
        let original = serde_json::to_value(&value).unwrap();
        let wire = presentation_to_wire(value);
        assert_eq!(serde_json::to_value(&wire).unwrap(), original);
        let bytes = serde_json::to_vec(&wire).unwrap();
        let decoded = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(wire, decoded);
        assert_eq!(serde_json::to_value(presentation_from_wire(decoded)).unwrap(), original);
    }
}
