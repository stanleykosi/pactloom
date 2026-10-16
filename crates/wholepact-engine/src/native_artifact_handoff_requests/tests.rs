use super::*;
#[test]
fn native_handoff_body_requires_explicit_kind_and_rejects_approval_fields() {
    let body = json!({"candidate_id":"candidate","job_id":format!("proof-{}","12".repeat(32)),"kind":"signer_review"});
    assert!(serde_json::from_value::<NativeArtifactHandoffRequest>(body.clone()).is_ok());
    for kind in ["sign", "submit", "proof_execute", ""] {
        let mut value = body.clone();
        value["kind"] = json!(kind);
        assert!(serde_json::from_value::<NativeArtifactHandoffRequest>(value).is_err());
    }
    for field in [
        "approved",
        "proved_artifact_digest",
        "signer_socket",
        "signatures",
        "authority",
    ] {
        let mut value = body.clone();
        value[field] = json!(true);
        assert!(serde_json::from_value::<NativeArtifactHandoffRequest>(value).is_err());
    }
    let mut omitted = body;
    omitted.as_object_mut().unwrap().remove("kind");
    assert!(serde_json::from_value::<NativeArtifactHandoffRequest>(omitted).is_err());
}
#[test]
fn handoff_domain_cannot_reuse_execution_or_reconciliation_key() {
    let id = "12".repeat(32);
    let key = handoff_key(&id);
    assert_ne!(key, format!("native-proof-execute-{id}"));
    assert_ne!(key, format!("native-proof-reconcile-{id}"));
    assert_eq!(key, handoff_key(&id));
}
#[cfg(all(
    target_os = "linux",
    feature = "synthetic-qualification",
    feature = "local-proof-jobs"
))]
mod constructed;
