//! Pure metadata models. None constructs proof, signatures or genuine native authority.
use super::*;
fn source() -> DispatchSource {
    DispatchSource {
        transaction_request_id: "10".repeat(32),
        original: SettlementSource {
            intake_request_id: "11".repeat(32),
            candidate_id: "synthetic-candidate".into(),
            manifest_digest: "12".repeat(32),
            job_id: "synthetic-job-id".into(),
            signature_retention_key: "synthetic-original-retention-key".into(),
            proved_artifact_digest: "13".repeat(32),
            receipt_storage_key: "synthetic-receipt-key".into(),
            receipt_digest: "14".repeat(32),
            scope_digest: "15".repeat(32),
            coordination_request_digest: "16".repeat(32),
        },
        signed: SignedObservation {
            result_id: format!("signed-{}", "17".repeat(32)),
            request_digest: "18".repeat(32),
            signed_candidate_digest: "19".repeat(32),
            signatures_complete: true,
        },
        checkpoint_id: format!("transaction-{}", "20".repeat(32)),
        transaction_digest: "21".repeat(32),
        txid: "22".repeat(32),
    }
}
#[test]
fn body_accepts_only_original_transaction_request() {
    let body = json!({"transaction_request_id":"ab".repeat(32)});
    assert!(serde_json::from_value::<NativeDispatchRequest>(body.clone()).is_ok());
    for field in [
        "candidate_id",
        "operation_id",
        "submission_journal_identity",
        "signed",
        "checkpoint_id",
        "txid",
        "transaction_digest",
        "approved",
        "observations",
        "bytes",
    ] {
        let mut forged = body.clone();
        forged[field] = json!(true);
        assert!(
            serde_json::from_value::<NativeDispatchRequest>(forged).is_err(),
            "{field}"
        );
    }
}
#[test]
fn flattened_source_roundtrip_is_strict_and_preserves_every_original_field() {
    let original = source();
    let encoded = serde_json::to_value(&original).unwrap();
    assert_eq!(
        encoded["signature_retention_key"],
        original.original.signature_retention_key
    );
    assert!(encoded.get("original").is_none());
    let decoded: DispatchSource = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, original);
    let mut forged = encoded;
    forged["permission"] = json!(true);
    assert!(serde_json::from_value::<DispatchSource>(forged).is_err());
}
fn observation() -> DispatchObservation {
    DispatchObservation {
        submission_journal_identity: "31".repeat(32),
        descriptor: Some(DispatchDescriptor {
            operation_id: "synthetic-operation".into(),
            obligation_id: "synthetic-obligation".into(),
            proposal_id: "synthetic-proposal".into(),
            transaction_id: "22".repeat(32),
            bytes_sha256: "21".repeat(32),
            expiry_height: 100,
            network: "testnet".into(),
            consensus_branch_id: 0x77190ad9,
        }),
        intent: Some(DispatchIntentObservation {
            operation_id: "synthetic-operation".into(),
            bytes_sha256: "21".repeat(32),
            historical_provider_state: DispatchProviderState::SubmissionUnknown,
        }),
        attempts: vec![DispatchAttemptObservation {
            number: 1,
            source_id: "synthetic-source".into(),
            started_at_unix_seconds: 1,
            outcome: DispatchAttemptOutcome::Unknown {},
        }],
    }
}
#[test]
fn snapshot_progression_never_erases_or_rewrites_original_facts() {
    let before = observation();
    let mut next = before.clone();
    next.attempts[0].outcome = DispatchAttemptOutcome::Acknowledged {};
    next.intent.as_mut().unwrap().historical_provider_state =
        DispatchProviderState::BackendAcknowledged;
    assert!(observations::monotone(&before, &next));
    assert!(!observations::monotone(&next, &before));
    let acknowledged = next.clone();
    next.attempts.push(DispatchAttemptObservation {
        number: 2,
        source_id: "same-byte-retry".into(),
        started_at_unix_seconds: 2,
        outcome: DispatchAttemptOutcome::Unknown {},
    });
    assert!(observations::monotone(&acknowledged, &next));
    for mutation in 0..7 {
        let mut forged = next.clone();
        match mutation {
            0 => forged.attempts[0].outcome = DispatchAttemptOutcome::Rejected { code: 1 },
            1 => forged.attempts[0].source_id = "replacement".into(),
            2 => forged.attempts[0].started_at_unix_seconds += 1,
            3 => forged.attempts.clear(),
            4 => forged.descriptor = None,
            5 => forged.intent = None,
            _ => forged.submission_journal_identity = "32".repeat(32),
        }
        assert!(!observations::monotone(&acknowledged, &forged));
    }
}
#[test]
fn absent_journal_is_unknown_and_never_a_reset() {
    let populated = observation();
    let absent = DispatchObservation {
        submission_journal_identity: populated.submission_journal_identity.clone(),
        descriptor: None,
        intent: None,
        attempts: vec![],
    };
    assert!(observations::monotone(&absent, &populated));
    assert!(!observations::monotone(&populated, &absent));
    assert!(valid_journal_identity(&"ab".repeat(32)));
    for bad in [
        "00".repeat(32),
        "AB".repeat(32),
        "x".repeat(64),
        "ab".repeat(31),
    ] {
        assert!(!valid_journal_identity(&bad));
    }
}
#[test]
fn strict_actual_metadata_shapes_reject_extra_permission_fields() {
    let mut value = serde_json::to_value(observation()).unwrap();
    value["authorization_allowed"] = json!(true);
    assert!(serde_json::from_value::<DispatchObservation>(value).is_err());
    for bad in [
        json!({"kind":"acknowledged","confirmed":true}),
        json!({"kind":"submitted"}),
        json!({"kind":"indeterminate","reason":{"code":"other","retry_allowed":true}}),
    ] {
        assert!(serde_json::from_value::<DispatchAttemptOutcome>(bad).is_err());
    }
}
