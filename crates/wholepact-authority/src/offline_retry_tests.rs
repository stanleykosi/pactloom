//! Pure metadata and synthetic SQLite schema tests only.
//! These do not authenticate HPKE, use keys, mint authority, or qualify a runtime.
use super::*;

fn h(n: u64) -> String {
    format!("{n:064x}")
}
fn original_fixture() -> (OriginalPreparation, OfflineEnrollmentPolicy, Vec<u8>) {
    let (request, _, policy) = crate::offline::tests::fixture();
    let envelope = b"SYNTHETIC INVALID HPKE CIPHERTEXT; NEVER AUTHENTICATED".to_vec();
    let t = &request.intent.terms;
    let template = OfflineAdmissionExportPlan {
        message_id: "11".repeat(16),
        sequence: 0,
        issued_at_unix_seconds: 3,
        expires_at_unix_seconds: 20,
        purpose: "Synthetic exact admission evidence".into(),
        persistence_warning: "Recipient can retain evidence".into(),
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        sender_key_fingerprint: policy.witness_transport_key_digest.clone(),
        recipient_key_fingerprint: policy.offline_signer_key_digest.clone(),
    };
    (
        OriginalPreparation {
            schema_version: 1,
            request,
            export_plan_template: template,
            original_envelope_digest: envelope_digest(&envelope),
            writer_certificate_digest: h(101),
            writer_session_id: h(102),
            prepared_at_ms: 3000,
        },
        policy,
        envelope,
    )
}
fn receipt_fixture(
    original: &OriginalPreparation,
    policy: &OfflineEnrollmentPolicy,
) -> OriginalTransportReceipt {
    let t = &original.request.intent.terms;
    let sender = format!("offline-intent:{}", t.offline_signer_key_digest);
    let recipient = format!("offline-intent:{}", t.offline_policy_digest);
    OriginalTransportReceipt {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        stream_digest: stream_digest(&t.network_profile_id, &t.agreement_id, &sender, &recipient)
            .unwrap(),
        sender_id: sender,
        recipient_id: recipient,
        artifact_kind: "offline_reservation_intent".into(),
        message_id: "22".repeat(16),
        sequence: 1,
        issued_at_unix_seconds: 2,
        expires_at_unix_seconds: 25,
        sender_key_fingerprint: policy.offline_signer_key_digest.clone(),
        recipient_key_fingerprint: policy.witness_transport_key_digest.clone(),
        preview_digest: h(103),
        content_digest: h(104),
        payload_digest: h(105),
        envelope_digest: original.original_envelope_digest.clone(),
    }
}

#[test]
fn unallocated_template_is_not_an_export_plan_or_authority() {
    let (original, policy, envelope) = original_fixture();
    original.validate().unwrap();
    assert!(original.export_plan_template.validate().is_err());
    let retained = RetainedOfflineOriginal {
        original,
        envelope: Zeroizing::new(envelope),
        receipt: None,
    };
    verify_retained(&retained, &policy).unwrap();
    assert!(retained.export_plan().is_none());
    assert!(retained.authenticated_receipt().is_none());
    assert!(!retained.authorization_allowed());
}

#[test]
fn original_digest_fixes_full_request_ciphertext_template_and_preparation() {
    let (original, _, _) = original_fixture();
    let expected = original.prepared_digest().unwrap();
    for field in 0..7 {
        let mut changed = original.clone();
        match field {
            0 => changed.request.operation_id.push('x'),
            1 => changed.request.expected_head.digest = h(999),
            2 => changed.request.admission_expires_at_ms += 1,
            3 => changed.original_envelope_digest = h(999),
            4 => changed.export_plan_template.message_id = "33".repeat(16),
            5 => changed.export_plan_template.expires_at_unix_seconds += 1,
            _ => changed.prepared_at_ms += 1,
        }
        assert_ne!(expected, changed.prepared_digest().unwrap());
    }
    let mut allocated = original;
    allocated.export_plan_template.sequence = 1;
    assert!(allocated.validate().is_err());
}

#[test]
fn receipt_rejects_substituted_kind_context_order_key_and_envelope() {
    let (original, policy, _) = original_fixture();
    let receipt = receipt_fixture(&original, &policy);
    receipt.matches(&original, &policy).unwrap();
    for field in 0..9 {
        let mut changed = receipt.clone();
        match field {
            0 => changed.artifact_kind = "authorization".into(),
            1 => changed.proposal_id.push('x'),
            2 => changed.proposal_revision += 1,
            3 => changed.sequence = 0,
            4 => changed.sender_key_fingerprint = h(999),
            5 => changed.envelope_digest = h(999),
            6 => changed.stream_digest = h(999),
            7 => changed.message_id = "AA".repeat(16),
            _ => changed.issued_at_unix_seconds = 4,
        }
        assert!(changed.matches(&original, &policy).is_err());
    }
}

#[test]
fn authenticated_record_binds_allocated_sequence_without_extending_template() {
    let (original, policy, _) = original_fixture();
    let mut plan = original.export_plan_template.clone();
    plan.sequence = 1;
    let record = OriginalReceiptRecord {
        schema_version: 1,
        prepared_record_digest: original.prepared_digest().unwrap(),
        authenticated_at_ms: 3001,
        export_plan: plan,
        receipt: receipt_fixture(&original, &policy),
    };
    record.matches(&original, &policy).unwrap();
    let mut changed = record.clone();
    changed.export_plan.expires_at_unix_seconds += 1;
    assert!(changed.matches(&original, &policy).is_err());
    changed = record.clone();
    changed.authenticated_at_ms = 20_000;
    assert!(changed.matches(&original, &policy).is_err());
    changed = record.clone();
    changed.prepared_record_digest = h(999);
    assert!(changed.matches(&original, &policy).is_err());
    changed = record.clone();
    changed.export_plan.sequence += 1;
    assert_ne!(
        changed.receipt_digest().unwrap(),
        record.receipt_digest().unwrap()
    );
}

#[test]
fn ciphertext_change_and_all_bounds_fail_closed() {
    let (original, policy, mut envelope) = original_fixture();
    envelope.push(0);
    let retained = RetainedOfflineOriginal {
        original,
        envelope: Zeroizing::new(envelope),
        receipt: None,
    };
    assert!(matches!(
        verify_retained(&retained, &policy),
        Err(AuthorityError::CorruptHistory)
    ));
    assert!(check_envelope_len(&[]).is_err());
    assert!(check_envelope_len(&vec![0; MAX_ORIGINAL_ENVELOPE_BYTES + 1]).is_err());
    assert!(check_capacity(MAX_ORIGINAL_ROWS, 0, 1, 1, true).is_err());
    assert!(check_capacity(0, MAX_ORIGINAL_BYTES, 1, 0, false).is_err());
    assert!(check_capacity(0, u64::MAX, 1, 1, false).is_err());
    assert!(check_capacity(MAX_ORIGINAL_ROWS - 1, MAX_ORIGINAL_BYTES - 2, 1, 1, true).is_ok());
    for (start, end) in [(-1, 2), (2, 2), (3, 2), (1, i64::MAX), (1, 604802)] {
        assert!(window(start, end).is_err());
    }
}

// Synthetic schema exercises only. Raw SQL cannot be supplied to production
// primitives, which receive their handle only from AuthorityJournal.
fn schema_fixture() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(OFFLINE_RETRY_SCHEMA).unwrap();
    c.execute_batch(crate::offline_outcome::OFFLINE_OUTCOME_SCHEMA)
        .unwrap();
    c
}
fn insert_raw_original(c: &Connection, n: u64) {
    c.execute(
        "INSERT INTO authority_offline_originals VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            format!("op-{n}"),
            format!("intent-{n}"),
            h(1000 + n),
            format!("authorization-{n}"),
            h(2000 + n),
            h(3000 + n),
            h(4000 + n),
            b"{}".as_slice(),
            b"invalid ciphertext".as_slice()
        ],
    )
    .unwrap();
}
fn insert_raw_receipt(
    c: &Connection,
    n: u64,
    stream: &str,
    sequence: u64,
) -> rusqlite::Result<usize> {
    c.execute(
        "INSERT INTO authority_offline_original_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            h(2000 + n),
            h(5000 + n),
            h(6000 + n),
            1,
            format!("{n:032x}"),
            stream,
            sequence,
            format!("{n:032x}"),
            b"{}".as_slice()
        ],
    )
}

#[test]
fn invalid_ciphertext_preparations_do_not_allocate_or_mutate_authority() {
    let c = schema_fixture();
    for n in 1..=64 {
        insert_raw_original(&c, n);
    }
    let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
    // Simulate HPKE rejection by never entering the authenticated callback.
    assert_eq!(allocate_sequence(&tx, &h(42)).unwrap(), 1);
    assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM authority_offline_original_receipts",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        tx.query_row("SELECT count(*) FROM authority_events", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert!(ensure_capacity(&tx, MAX_ORIGINAL_BYTES as usize, 1, true).is_err());
}

#[test]
fn pending_authenticated_allocations_are_contiguous_and_not_advisory() {
    let c = schema_fixture();
    insert_raw_original(&c, 1);
    insert_raw_original(&c, 2);
    let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
    let stream = h(42);
    assert_eq!(allocate_sequence(&tx, &stream).unwrap(), 1);
    insert_raw_receipt(&tx, 1, &stream, 1).unwrap();
    assert_eq!(allocate_sequence(&tx, &stream).unwrap(), 2);
    assert!(insert_raw_receipt(&tx, 2, &stream, 1).is_err());
    insert_raw_receipt(&tx, 2, &stream, 2).unwrap();
    assert_eq!(allocate_sequence(&tx, &stream).unwrap(), 3);
    assert!(tx
        .execute("DELETE FROM authority_offline_original_receipts", [])
        .is_err());
    assert!(tx
        .execute(
            "UPDATE authority_offline_original_receipts SET export_sequence=9",
            []
        )
        .is_err());
}

#[test]
fn callback_transaction_failure_does_not_burn_sequence() {
    let c = schema_fixture();
    insert_raw_original(&c, 1);
    {
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
        insert_raw_receipt(&tx, 1, &h(42), 1).unwrap();
        assert_eq!(allocate_sequence(&tx, &h(42)).unwrap(), 2);
        // Simulated storage/domain failure: drop rolls back; nothing was exported.
    }
    let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
    assert_eq!(allocate_sequence(&tx, &h(42)).unwrap(), 1);
}

#[test]
fn inputs_are_immutable_and_sequence_holes_are_detected() {
    let c = schema_fixture();
    insert_raw_original(&c, 1);
    assert!(c
        .execute("UPDATE authority_offline_originals SET envelope=x'00'", [])
        .is_err());
    assert!(c
        .execute("DELETE FROM authority_offline_originals", [])
        .is_err());
    let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
    // Deliberately malformed raw test state, unreachable through allocation.
    insert_raw_receipt(&tx, 1, &h(42), 2).unwrap();
    assert!(matches!(
        allocate_sequence(&tx, &h(42)),
        Err(AuthorityError::CorruptHistory)
    ));
}

#[test]
fn authenticated_callback_without_actual_inbox_acceptance_cannot_admit() {
    let c = schema_fixture();
    let (original, _, envelope) = original_fixture();
    let retained = RetainedOfflineOriginal {
        original,
        envelope: Zeroizing::new(envelope),
        receipt: None,
    };
    assert!(matches!(
        require_inbox_acceptance(&c, &retained),
        Err(AuthorityError::Authentication)
    ));
}
