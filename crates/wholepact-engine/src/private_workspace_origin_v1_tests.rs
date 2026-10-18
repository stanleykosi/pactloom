//! Pure marker shape/projection tests. These do not authenticate a native
//! association, issue privacy consent, open a Store, or qualify first-write IO.
use super::*;
use serde_json::json;

fn marker() -> Value {
    json!({
        "version": 1,
        "purpose": "durable-private-coordination-v1",
        "native_association_digest": "a".repeat(64),
        "source_digest": "b".repeat(64),
        "principal_id": "synthetic-constructor",
        "agreement_id": "synthetic-agreement",
        "obligation_id": "synthetic-obligation",
        "reviewer_account_ids": ["1".repeat(64), "2".repeat(64)],
        "protected_destination": "/tmp/synthetic-private-workspace/private-coordination.sqlite",
        "retention_policy": "Synthetic data-only test retention",
        "metadata_origin": "c".repeat(64)
    })
}

#[test]
fn absent_marker_preserves_legacy_data_decode() {
    let payload = json!({"view": {"candidates": []}});
    assert!(refuse_public_payload(&payload).is_ok());
    assert!(decode_marker(&payload).unwrap().is_none());
}

#[test]
fn marker_only_seed_refuses_generic_projection() {
    let payload = json!({PRIVATE_WORKSPACE_ORIGIN_KEY_V1: marker(), "view": {"candidates": []}});
    assert!(decode_marker(&payload).unwrap().is_some());
    assert!(refuse_public_payload(&payload).is_err());
}

#[test]
fn present_null_empty_or_unknown_marker_is_not_legacy() {
    for value in [Value::Null, json!({}), json!({"version": 2})] {
        let payload = json!({PRIVATE_WORKSPACE_ORIGIN_KEY_V1: value});
        assert!(refuse_public_payload(&payload).is_err());
        assert!(decode_marker(&payload).is_err());
    }
    let mut changed = marker();
    changed["native_approved"] = json!(true);
    assert!(decode_marker(&json!({PRIVATE_WORKSPACE_ORIGIN_KEY_V1: changed})).is_err());
}

#[test]
fn marker_syntax_does_not_substitute_for_original_source_join() {
    let original = decode_marker(&json!({PRIVATE_WORKSPACE_ORIGIN_KEY_V1: marker()}))
        .unwrap()
        .unwrap();
    let mut changed = original.clone();
    changed.native_association_digest = "d".repeat(64);
    assert!(changed.validate().is_ok());
    assert!(changed != original);
    assert!(changed.digest().unwrap() != original.digest().unwrap());
    assert!(refuse_public_payload(&json!({PRIVATE_WORKSPACE_ORIGIN_KEY_V1: changed})).is_err());
}
