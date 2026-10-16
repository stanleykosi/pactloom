use super::*;

#[test]
fn request_body_accepts_only_candidate_and_job() {
    let body = json!({"candidate_id":"candidate", "job_id":format!("proof-{}", "12".repeat(32))});
    assert!(serde_json::from_value::<NativeProofReconcileRequest>(body.clone()).is_ok());
    for (field, value) in [
        ("approved", json!(true)),
        ("operation", json!("proof_run")),
        ("receipt_digest", json!("attacker")),
        ("scope_digest", json!("attacker")),
        (
            "reconciliation_status",
            json!("cached_reconciliation_recorded"),
        ),
        ("revision", json!(1)),
    ] {
        let mut changed = body.clone();
        changed[field] = value;
        assert!(serde_json::from_value::<NativeProofReconcileRequest>(changed).is_err());
    }
}

#[test]
fn completion_lookup_keeps_original_reconcile_command_bytes() {
    let access = Access {
        principal_id: "synthetic-controller".into(),
        ..Access::default()
    };
    let key = "native-proof-reconcile-fixed-command";
    let job = format!("proof-{}", "12".repeat(32));
    let actual = reconciliation_command(&access, key, "candidate-123", 29, &job).unwrap();
    // Independently spell the existing production record_proof_job branch.
    let expected = context(
        &access,
        key,
        "reconcile_candidate_proof_job",
        "candidate-123",
        Some(29),
        &json!({"job_id":job}),
    )
    .unwrap();
    assert_eq!(actual.principal_id, expected.principal_id);
    assert_eq!(actual.idempotency_key, expected.idempotency_key);
    assert_eq!(actual.request_digest, expected.request_digest);
    let payload = json!({"command":"reconcile_candidate_proof_job", "resource":"candidate-123",
        "expected_revision":29, "request":{"job_id":job}});
    let mut hash = Sha256::new();
    hash.update(b"wholepact:command:v1\0");
    hash.update(serde_json::to_vec(&payload).unwrap());
    assert_eq!(actual.request_digest, hex::encode(hash.finalize()));
    for changed in [
        context(
            &access,
            key,
            "run_candidate_proof_locally",
            "candidate-123",
            Some(29),
            &json!({"job_id":job}),
        )
        .unwrap(),
        reconciliation_command(&access, key, "other-candidate", 29, &job).unwrap(),
        reconciliation_command(&access, key, "candidate-123", 30, &job).unwrap(),
        reconciliation_command(&access, key, "candidate-123", 29, "other-job").unwrap(),
    ] {
        assert_ne!(actual.request_digest, changed.request_digest);
    }
}

#[test]
fn complete_receipt_digest_binds_every_original_field() {
    let original = json!({"job_id":format!("proof-{}", "12".repeat(32)), "scope_digest":"21".repeat(32),
        "principal_id":"owner", "candidate_id":"candidate", "manifest_digest":"31".repeat(32),
        "coordination_request_digest":"41".repeat(32), "artifact_digest":"51".repeat(32),
        "review_binding":"61".repeat(32), "effects_commitment":"71".repeat(32), "prepared_revision":7});
    let receipt: candidates::CheckpointReceipt = serde_json::from_value(original.clone()).unwrap();
    let before = receipt_digest(&receipt).unwrap();
    for field in original.as_object().unwrap().keys() {
        let mut changed = original.clone();
        changed[field] = if field == "prepared_revision" {
            json!(8)
        } else {
            json!("changed")
        };
        let changed: candidates::CheckpointReceipt = serde_json::from_value(changed).unwrap();
        assert_ne!(before, receipt_digest(&changed).unwrap(), "{field}");
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "synthetic-qualification",
    feature = "local-proof-jobs"
))]
mod constructed;
