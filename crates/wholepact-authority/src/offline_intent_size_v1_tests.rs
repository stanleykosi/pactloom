//! Pure structural preflight only; deliberately invalid ciphertext and no keys,
//! transport receipt, server, enrollment or live authorization.
use super::*;
fn fixture() -> (ReserveOfflineAuthorization, OfflineAdmissionExportPlan) {
    let (request, _, policy) = crate::offline::tests::fixture();
    let plan = OfflineAdmissionExportPlan {
        message_id: "11".repeat(16),
        sequence: 0,
        issued_at_unix_seconds: 3,
        expires_at_unix_seconds: 20,
        purpose: "Synthetic structural courier".into(),
        persistence_warning: "Retained exact bytes".into(),
        sender_id: format!(
            "offline-admission:{}",
            request.intent.terms.offline_policy_digest
        ),
        recipient_id: format!(
            "offline-admission:{}",
            request.intent.terms.offline_signer_key_digest
        ),
        sender_key_fingerprint: policy.witness_transport_key_digest,
        recipient_key_fingerprint: policy.offline_signer_key_digest,
    };
    (request, plan)
}
#[test]
fn dedicated_raw_limit_matches_hex_decoder_and_actual_wire_shape() {
    let (request, plan) = fixture();
    assert_eq!(MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1, 65_536);
    let bytes = vec![0x42; MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1];
    validate_offline_intent_delivery_size_v1(&request, &bytes, &plan).unwrap();
    let wire = OfflineWitnessRequestV1 {
        request,
        export_template: plan,
        original_envelope_hex: hex::encode(&bytes),
        proof: protocol::WriterSessionProof {
            session_id: "a".repeat(64),
            tag: "f".repeat(64),
        },
    };
    assert_eq!(wire.envelope().unwrap(), bytes);
    assert!(
        encode(&protocol::WireRequest::SubmitOfflineIntentV1(Box::new(
            wire
        )))
        .unwrap()
        .len()
            <= MAX_FRAME_BYTES
    );
}
#[test]
fn pure_preflight_refuses_empty_oversize_and_allocated_or_malformed_original() {
    let (mut request, mut plan) = fixture();
    assert!(validate_offline_intent_delivery_size_v1(&request, &[], &plan).is_err());
    assert!(
        validate_offline_intent_delivery_size_v1(
            &request,
            &vec![0x42; MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1 + 1],
            &plan
        )
        .is_err()
    );
    plan.sequence = 1;
    assert!(validate_offline_intent_delivery_size_v1(&request, b"inert", &plan).is_err());
    plan.sequence = 0;
    request.operation_id.clear();
    assert!(validate_offline_intent_delivery_size_v1(&request, b"inert", &plan).is_err());
}
