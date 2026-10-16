use super::*;
#[test]
fn settlement_body_accepts_only_exact_intake_and_purpose() {
    let value = json!({"intake_request_id":"ab".repeat(32),"kind":"signature_reconcile"});
    assert!(serde_json::from_value::<NativeSettlementRequest>(value.clone()).is_ok());
    for field in [
        "candidate_id",
        "job_id",
        "signature_retention_key",
        "signed_candidate_digest",
        "approved",
        "observation",
    ] {
        let mut bad = value.clone();
        bad[field] = json!(true);
        assert!(serde_json::from_value::<NativeSettlementRequest>(bad).is_err());
    }
    for kind in ["sign", "dispatch", "transaction_extract_retry"] {
        let mut bad = value.clone();
        bad["kind"] = json!(kind);
        assert!(serde_json::from_value::<NativeSettlementRequest>(bad).is_err());
    }
}
#[test]
fn observation_validation_does_not_accept_forged_digest_shapes() {
    let valid = SignedObservation {
        result_id: format!("signed-{}", "ab".repeat(32)),
        request_digest: "cd".repeat(32),
        signed_candidate_digest: "ef".repeat(32),
        signatures_complete: true,
    };
    assert!(valid_signed(&valid));
    let mut bad = valid.clone();
    bad.signed_candidate_digest = "EF".repeat(32);
    assert!(!valid_signed(&bad));
}
#[cfg(all(
    target_os = "linux",
    feature = "synthetic-qualification",
    feature = "transaction-checkpoint"
))]
#[path = "constructed.rs"]
mod constructed;
