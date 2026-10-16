//! Synthetic metadata/SQLite fence tests. No keys or issuance.
use super::*;
fn h(n: u64) -> String {
    format!("{n:064x}")
}
fn control_fixture() -> (OfflineAdmissionControl, OfflineAdmissionExportPlan) {
    let (request, account, policy) = crate::offline::tests::fixture();
    let t = &request.intent.terms;
    let plan = OfflineAdmissionExportPlan {
        message_id: "22".repeat(16),
        sequence: 1,
        issued_at_unix_seconds: 31,
        expires_at_unix_seconds: 45,
        purpose: "No admission was issued".into(),
        persistence_warning: "Transport evidence only; no signing authority".into(),
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        sender_key_fingerprint: policy.witness_transport_key_digest.clone(),
        recipient_key_fingerprint: policy.offline_signer_key_digest.clone(),
    };
    let control = OfflineAdmissionControl {
        schema_version: 1,
        witness_id: account.witness_id.clone(),
        witness_policy_digest: account.policy_digest().unwrap(),
        witness_transport_key_digest: policy.witness_transport_key_digest,
        request_digest: request.request_digest().unwrap(),
        request,
        prepared_record_digest: h(1),
        authenticated_receipt_digest: h(2),
        original_export_plan_digest: h(3),
        original_sequence: 1,
        selected_head: AuthorityHead {
            sequence: 1,
            digest: h(4),
        },
        selected_at_ms: 30_001,
        outcome: OfflineAdmissionControlOutcome::NoAdmission,
    };
    (control, plan)
}
fn outcome_fixture() -> OutcomeRecord {
    let (control, plan) = control_fixture();
    OutcomeRecord {
        schema_version: 1,
        prepared_record_digest: control.prepared_record_digest.clone(),
        authenticated_receipt_digest: control.authenticated_receipt_digest.clone(),
        request_digest: control.request_digest.clone(),
        original_export_plan_digest: control.original_export_plan_digest.clone(),
        selected_head: control.selected_head.clone(),
        selected_at_ms: control.selected_at_ms,
        emission_may_have_started: true,
        plan,
        artifact: OutcomeArtifact::Control(control),
    }
}
fn schema_fixture() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(offline_retry::OFFLINE_RETRY_SCHEMA)
        .unwrap();
    c.execute_batch(OFFLINE_OUTCOME_SCHEMA).unwrap();
    c.execute(
        "INSERT INTO authority_offline_originals VALUES('op','intent',?1,'auth',?2,?3,?4,?5,?6)",
        params![
            h(10),
            h(1),
            h(11),
            h(12),
            b"{}".as_slice(),
            b"synthetic invalid ciphertext".as_slice()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO authority_offline_original_receipts VALUES(?1,?2,?3,1,?4,?5,1,?6,?7)",
        params![
            h(1),
            h(2),
            h(13),
            "11".repeat(16),
            h(14),
            "12".repeat(16),
            b"{}".as_slice()
        ],
    )
    .unwrap();
    c
}
#[test]
fn control_has_fresh_ceil_window_but_never_renews_original_admission() {
    let (control, plan) = control_fixture();
    assert!(control.selected_at_ms > control.request.admission_expires_at_ms);
    control.validate_export_plan(&plan).unwrap();
    let mut changed = plan.clone();
    changed.issued_at_unix_seconds = 30;
    assert!(control.validate_export_plan(&changed).is_err());
    changed = plan.clone();
    changed.sequence += 1;
    assert!(control.validate_export_plan(&changed).is_err());
    changed = plan.clone();
    changed.recipient_id.push('x');
    assert!(control.validate_export_plan(&changed).is_err());
    changed = plan;
    changed.recipient_key_fingerprint = h(99);
    assert!(control.validate_export_plan(&changed).is_err());
}
#[test]
fn exposure_retained_is_distinct_and_cannot_omit_admission_digest() {
    let (mut control, plan) = control_fixture();
    let original = control.control_digest().unwrap();
    control.outcome = OfflineAdmissionControlOutcome::ExposureRetained {
        admission_digest: h(99),
    };
    control.validate_export_plan(&plan).unwrap();
    assert_ne!(original, control.control_digest().unwrap());
    control.outcome = OfflineAdmissionControlOutcome::ExposureRetained {
        admission_digest: String::new(),
    };
    assert!(control.validate().is_err());
}
#[test]
fn fence_commit_permanently_blocks_admission_and_same_outcome_reissuance() {
    let c = schema_fixture();
    let record = outcome_fixture();
    {
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
        require_unselected(&tx, &h(1)).unwrap();
        persist_outcome(&tx, &record).unwrap();
        tx.commit().unwrap();
    }
    assert!(matches!(
        ensure_admission_allowed(&c, &h(1)),
        Err(AuthorityError::Conflict)
    ));
    assert!(matches!(
        require_unselected(&c, &h(1)),
        Err(AuthorityError::Uncertain)
    ));
    // Simulate the losing selector after the winner's durable transaction.
    let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
    assert!(persist_outcome(&tx, &record).is_err());
    assert!(tx
        .execute("DELETE FROM authority_offline_outcomes", [])
        .is_err());
    assert!(tx
        .execute(
            "UPDATE authority_offline_outcomes SET emission_may_have_started=0",
            []
        )
        .is_err());
}
#[test]
fn failed_fence_transaction_does_not_publish_a_terminal_choice() {
    let c = schema_fixture();
    let record = outcome_fixture();
    {
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
        persist_outcome(&tx, &record).unwrap();
        // Callback/selection error before commit: no capability could escape.
    }
    require_unselected(&c, &h(1)).unwrap();
    ensure_admission_allowed(&c, &h(1)).unwrap();
}
#[test]
fn emission_marker_cannot_be_omitted_or_changed() {
    let mut record = outcome_fixture();
    record.emission_may_have_started = false;
    assert!(record.decision_digest().is_err());
    let (control, plan) = control_fixture();
    let historical = HistoricalOfflineControlExport {
        descriptor: control,
        plan,
    };
    assert!(!historical.authorization_allowed());
}

#[test]
fn legacy_reservation_entry_cannot_bypass_terminal_no_admission() {
    let c = schema_fixture();
    let record = outcome_fixture();
    let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
    persist_outcome(&tx, &record).unwrap();
    tx.commit().unwrap();
    let (mut request, _, _) = crate::offline::tests::fixture();
    request.operation_id = "op".into();
    assert!(matches!(
        ensure_offline_request_not_terminated(&c, &request),
        Err(AuthorityError::Conflict)
    ));
    request.operation_id = "reminted-op".into();
    request.intent.intent_id = "intent".into();
    assert!(matches!(
        ensure_offline_request_not_terminated(&c, &request),
        Err(AuthorityError::Conflict)
    ));
}
