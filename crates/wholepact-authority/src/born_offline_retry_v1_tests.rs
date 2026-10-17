//! In-memory data-only crash/replay fixtures. Synthetic bytes are deliberately
//! not HPKE ciphertext, and these records cannot mint an authenticated input.
use super::*;
fn h(n: u8) -> String {
    format!("{n:064x}")
}
fn raw_digest(domain: &[u8], bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    hex::encode(h.finalize())
}
fn fixture() -> (
    Connection,
    policy::Ledger,
    BornOfflineReservationRecordV1,
    BornOriginalPreparationV1,
    OriginalTransportReceipt,
) {
    let (ledger, _, mut record) = crate::born_offline_admission_v1::tests::fixture();
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(crate::born_offline_artifact_schema_v1::INBOX_SCHEMA)
        .unwrap();
    c.execute_batch(crate::born_offline_artifact_schema_v1::OUTBOX_SCHEMA)
        .unwrap();
    c.execute_batch(include_str!("born_offline_retry_schema_v1.sql"))
        .unwrap();
    let bytes = b"synthetic inert ciphertext placeholder";
    record.authentication.envelope_digest = envelope_digest(bytes);
    let r = &record.request.reservation;
    let t = &r.intent.terms;
    let policy = &ledger
        .born_offline_enrollment_v1()
        .unwrap()
        .unwrap()
        .enrollment
        .policy;
    let plan = OfflineAdmissionExportPlan {
        message_id: "11".repeat(16),
        sequence: 1,
        issued_at_unix_seconds: 254,
        expires_at_unix_seconds: 255,
        purpose: "Synthetic original born admission".into(),
        persistence_warning: "Synthetic retained disclosure only".into(),
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        sender_key_fingerprint: policy.witness_transport_key_digest.clone(),
        recipient_key_fingerprint: policy.offline_signer_key_digest.clone(),
    };
    let mut template = plan.clone();
    template.sequence = 0;
    let original = BornOriginalPreparationV1 {
        version: 1,
        owner_transport_certificate_digest: None,
        request: record.request.clone(),
        original: OriginalPreparation {
            schema_version: 1,
            request: r.clone(),
            export_plan_template: template,
            original_envelope_digest: envelope_digest(bytes),
            writer_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
            writer_session_id: ledger
                .snapshot
                .active_writer_session
                .as_ref()
                .unwrap()
                .session_id
                .clone(),
            prepared_at_ms: 254000,
        },
        export_plan: plan,
    };
    original.validate(&ledger).unwrap();
    c.execute(
        "INSERT INTO authority_born_offline_originals VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            r.operation_id,
            record.request.request_digest().unwrap(),
            envelope_digest(bytes),
            original.export_stream().unwrap(),
            1,
            &*encode(&original).unwrap(),
            bytes.as_slice(),
            record.request.construction_link.reservation_operation_id,
        ],
    )
    .unwrap();
    let sender = format!("born-offline-intent:{}", t.offline_signer_key_digest);
    let recipient = format!("born-offline-intent:{}", t.offline_policy_digest);
    let receipt = OriginalTransportReceipt {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: sender.clone(),
        recipient_id: recipient.clone(),
        artifact_kind: "born_offline_intent_v1".into(),
        message_id: "22".repeat(16),
        sequence: 1,
        issued_at_unix_seconds: 253,
        expires_at_unix_seconds: 255,
        sender_key_fingerprint: policy.offline_signer_key_digest.clone(),
        recipient_key_fingerprint: policy.witness_transport_key_digest.clone(),
        stream_digest: digest(
            "wholepact.transport-stream.v1",
            &(&t.network_profile_id, &t.agreement_id, &sender, &recipient),
        )
        .unwrap(),
        preview_digest: h(1),
        content_digest: h(2),
        payload_digest: h(3),
        envelope_digest: envelope_digest(bytes),
    };
    receipt.matches_born(&original.original, policy).unwrap();
    (c, ledger, record, original, receipt)
}
fn callback(c: &Connection, o: &BornOriginalPreparationV1, r: &OriginalTransportReceipt) {
    c.execute(
        "INSERT INTO authority_born_offline_receipts VALUES(?1,?2)",
        params![o.request.reservation.operation_id, &*encode(r).unwrap()],
    )
    .unwrap();
}
fn inbox(c: &Connection, o: &BornOriginalPreparationV1, r: &OriginalTransportReceipt) {
    let retained = read_original(c, &o.request.reservation.operation_id)
        .unwrap()
        .unwrap();
    c.execute(
        "INSERT INTO receipts VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            r.stream_digest,
            r.sequence,
            raw_digest(b"wholepact.transport-message.v1\0", r.message_id.as_bytes()),
            r.content_digest,
            digest(
                "wholepact.transport-slot.v1",
                &(
                    &r.stream_digest,
                    &r.proposal_id,
                    r.proposal_revision,
                    "born_offline_intent_v1"
                )
            )
            .unwrap(),
            r.payload_digest,
            retained.envelope
        ],
    )
    .unwrap();
}
#[test]
fn born_crash_prefixes_are_retained_but_only_actual_inbox_joins_committed_event() {
    let (c, mut ledger, record, original, receipt) = fixture();
    verify_retained_born_offline_v1(&c, &ledger).unwrap();
    callback(&c, &original, &receipt);
    verify_retained_born_offline_v1(&c, &ledger).unwrap();
    let event = crate::born_offline_admission_v1::tests::event(&ledger, &record);
    ledger.apply(&event).unwrap();
    assert!(verify_retained_born_offline_v1(&c, &ledger).is_err());
    inbox(&c, &original, &receipt);
    verify_retained_born_offline_v1(&c, &ledger).unwrap();
    let old = read_original(&c, &record.request.reservation.operation_id)
        .unwrap()
        .unwrap();
    assert!(old.original == original);
    assert!(old.receipt == Some(receipt));
    assert!(
        c.execute("DELETE FROM authority_born_offline_originals", [])
            .is_err()
    );
    assert!(
        c.execute(
            "UPDATE authority_born_offline_receipts SET payload=payload",
            []
        )
        .is_err()
    );
}
#[test]
fn born_unlinked_inbox_auxiliary_rows_and_receipt_substitution_fail_closed() {
    let (c, ledger, _, o, r) = fixture();
    inbox(&c, &o, &r);
    assert!(verify_retained_born_offline_v1(&c, &ledger).is_err());
    callback(&c, &o, &r);
    verify_retained_born_offline_v1(&c, &ledger).unwrap();
    c.execute("UPDATE receipts SET slot=?1", [h(99)]).unwrap();
    assert!(verify_retained_born_offline_v1(&c, &ledger).is_err());
    for table in ["domain_imports", "offline_control_outcomes"] {
        let (c, ledger, _, o, r) = fixture();
        callback(&c, &o, &r);
        inbox(&c, &o, &r);
        if table == "domain_imports" {
            c.execute(
                "INSERT INTO domain_imports VALUES(?1,1,'unowned',?2,1,?3)",
                params![r.stream_digest, r.content_digest, h(4)],
            )
            .unwrap();
        } else {
            c.execute(
                "INSERT INTO offline_control_outcomes VALUES(?1,1,?2,?3,1,NULL)",
                params![r.stream_digest, r.content_digest, h(5)],
            )
            .unwrap();
        }
        assert!(verify_retained_born_offline_v1(&c, &ledger).is_err());
    }
}
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
#[test]
fn born_outbox_requires_committed_origin_and_exact_maintained_projection() {
    let (c, mut ledger, record, o, r) = fixture();
    callback(&c, &o, &r);
    inbox(&c, &o, &r);
    let event = crate::born_offline_admission_v1::tests::event(&ledger, &record);
    let MutationResult::BornOfflineReservedV1(admission) = ledger.apply(&event).unwrap() else {
        panic!()
    };
    let artifacts = ledger.born_offline_artifacts_v1().unwrap().unwrap();
    let at = crate::offline_witness_transport_v1::Timestamp::from_unix_seconds(254).unwrap();
    let prepared = configured_born_witness::prepare_original_export(
        &admission,
        &o.export_plan,
        artifacts,
        &at,
    )
    .unwrap();
    let p = prepared.preview();
    let bytes = b"synthetic inert response placeholder";
    c.execute(
        "INSERT INTO outbox VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9,254,255,?10,0)",
        params![
            o.export_stream().unwrap(),
            raw_digest(
                b"wholepact.transport-message.v1\0",
                o.export_plan.message_id.as_bytes()
            ),
            p.digest().unwrap(),
            digest("wholepact.outbox-context.v1", &p.context).unwrap(),
            p.sender_key_fingerprint,
            p.recipient_key_fingerprint,
            p.payload_digest,
            digest(
                "wholepact.transport-slot.v1",
                &(
                    &o.export_stream().unwrap(),
                    &p.context.proposal_id,
                    p.context.proposal_revision,
                    "born_offline_minimal_admission_v1"
                )
            )
            .unwrap(),
            envelope_digest(bytes),
            bytes.as_slice()
        ],
    )
    .unwrap();
    verify_retained_born_offline_v1(&c, &ledger).unwrap();
    for column in [
        "preview_digest",
        "context_digest",
        "payload_digest",
        "message_digest",
    ] {
        let tx = rusqlite::Transaction::new_unchecked(&c, rusqlite::TransactionBehavior::Deferred)
            .unwrap();
        tx.execute(&format!("UPDATE outbox SET {column}=?1"), [h(98)])
            .unwrap();
        assert!(verify_retained_born_offline_v1(&tx, &ledger).is_err());
    }
    let (before, _, _) = crate::born_offline_admission_v1::tests::fixture();
    assert!(verify_retained_born_offline_v1(&c, &before).is_err());
    // Read-only historical validation preserves committed bytes across pause.
    ledger.snapshot.writer_status = WriterStatus::Paused;
    verify_retained_born_offline_v1(&c, &ledger).unwrap();
}

#[test]
fn uncertain_first_preparation_irreversibly_claims_original_construction() {
    let (c, _, record, _, _) = fixture();
    // No inbox or admission exists. A second continuation cannot occupy this
    // construction through INSERT OR REPLACE, update, delete or a fresh ID.
    assert!(c.execute("INSERT OR REPLACE INTO authority_born_offline_originals SELECT 'second',?1,?2,export_stream,export_sequence+1,payload,envelope,construction_reservation_id FROM authority_born_offline_originals",params![h(90),h(91)]).is_err());
    assert!(
        c.execute(
            "DELETE FROM authority_born_offline_originals WHERE construction_reservation_id=?1",
            [&record.request.construction_link.reservation_operation_id]
        )
        .is_err()
    );
    let count: u64 = c
        .query_row(
            "SELECT count(*) FROM authority_born_offline_originals",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}
