//! Pure synthetic metadata only. No proof, signature, live source or native approval.
use super::*;
use crate::native_dispatch_requests::*;
#[test]
fn request_bodies_only_select_originals_and_exact_existing_record() {
    let observation = json!({"kind":"provider_observation","dispatch_request_id":"ab".repeat(32)});
    let resolution = json!({"kind":"independent_record_resolution","dispatch_request_id":"ab".repeat(32),"participant_id":"synthetic-participant","record_id":"synthetic-record"});
    for body in [&observation, &resolution] {
        assert!(serde_json::from_value::<NativeReconciliationRequest>(body.clone()).is_ok());
        for field in [
            "operation_id",
            "source",
            "submission_journal_identity",
            "approved",
            "provider",
            "report",
            "evidence",
            "permission",
            "permit",
            "signer_receipt",
            "resolution_commit",
            "bytes",
        ] {
            let mut forged = body.clone();
            forged[field] = json!(true);
            assert!(
                serde_json::from_value::<NativeReconciliationRequest>(forged).is_err(),
                "{field}"
            );
        }
    }
    for field in ["participant_id", "record_id"] {
        let mut forged = observation.clone();
        forged[field] = json!("unrequested-record");
        assert!(serde_json::from_value::<NativeReconciliationRequest>(forged).is_err());
        let mut missing = resolution.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<NativeReconciliationRequest>(missing).is_err());
    }
}
fn snapshot() -> ReconciliationJournalObservation {
    ReconciliationJournalObservation {
        submission: DispatchObservation {
            submission_journal_identity: "aa".repeat(32),
            descriptor: Some(DispatchDescriptor {
                operation_id: "synthetic-operation".into(),
                obligation_id: "synthetic-obligation".into(),
                proposal_id: "synthetic-proposal".into(),
                transaction_id: "bb".repeat(32),
                bytes_sha256: "cc".repeat(32),
                expiry_height: 100,
                network: "testnet".into(),
                consensus_branch_id: 0x77190ad9,
            }),
            intent: Some(DispatchIntentObservation {
                operation_id: "synthetic-operation".into(),
                bytes_sha256: "cc".repeat(32),
                historical_provider_state: DispatchProviderState::SubmissionUnknown,
            }),
            attempts: vec![],
        },
        report: Some(HistoricalReconciliationReport {
            transaction_id: "bb".repeat(32),
            expiry_height: 100,
            policy: HistoricalConfirmationPolicy {
                required_confirmations: 10,
                expiry_observation_depth: 10,
                sources: vec!["synthetic-provider".into()],
            },
            observed_at_unix_seconds: 1,
            valid_until_unix_seconds: 2,
            state: HistoricalReconciliationState::Stale {},
            last_inclusion: None,
            confidence_lost: false,
            reorganization_observed: false,
            source_ids: vec!["synthetic-provider".into()],
            source_tips: vec![HistoricalSourceTip {
                source_id: "synthetic-provider".into(),
                tip: HistoricalBlockIdentity {
                    height: 1,
                    hash: "dd".repeat(32),
                },
            }],
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
            permits_replacement: false,
        }),
    }
}
#[test]
fn report_decoder_accepts_only_explicitly_stale_history() {
    let original = serde_json::to_value(snapshot()).unwrap();
    assert!(serde_json::from_value::<ReconciliationJournalObservation>(original.clone()).is_ok());
    for state in [
        json!({"status":"confirmation_policy_met","block":{"height":1,"hash":"dd".repeat(32)},"confirmations":10}),
        json!({"status":"stale","clear_exposure":true}),
        json!({"status":"backend_unavailable"}),
    ] {
        let mut forged = original.clone();
        forged["report"]["state"] = state;
        assert!(serde_json::from_value::<ReconciliationJournalObservation>(forged).is_err());
    }
}
#[test]
fn repeated_observations_preserve_submission_and_report_lineage() {
    let before = snapshot();
    let mut next = before.clone();
    next.report.as_mut().unwrap().observed_at_unix_seconds = 2;
    assert!(observations::monotone(&before, &next));
    assert!(!observations::monotone(&next, &before));
    next.report = None;
    assert!(!observations::monotone(&before, &next));
    next = before.clone();
    next.report.as_mut().unwrap().policy.sources = vec!["substitute-provider".into()];
    assert!(!observations::monotone(&before, &next));
    next = before.clone();
    next.submission.descriptor.as_mut().unwrap().bytes_sha256 = "ef".repeat(32);
    assert!(!observations::monotone(&before, &next));
}
#[test]
fn purpose_identity_separates_records_but_does_not_reset_attempts() {
    let a = NativeReconciliationRequest::ProviderObservation {
        dispatch_request_id: "ab".repeat(32),
    };
    let b = NativeReconciliationRequest::IndependentRecordResolution {
        dispatch_request_id: "ab".repeat(32),
        participant_id: "synthetic-p".into(),
        record_id: "synthetic-r".into(),
    };
    assert!(same_purpose(&a, &a));
    assert!(!same_purpose(&a, &b));
    let mut c = b.clone();
    if let NativeReconciliationRequest::IndependentRecordResolution { record_id, .. } = &mut c {
        *record_id = "different-record".into();
    }
    assert!(!same_purpose(&b, &c));
}
