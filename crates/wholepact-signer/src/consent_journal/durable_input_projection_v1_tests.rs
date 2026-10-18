//! Inert data/SQLite tests only. These fixtures cannot create a genuine native
//! decision, a FreshEntry, scan permission, spending authority, or live wallet.
use super::*;
use wholepact_core::durable_input_projection_v1::{
    DurableInputProjectionIntentV1, DurableInputProjectionPurposeV1, DurableInputProjectionV1,
    DurableProjectedInputV1, DurableProjectionContextV1,
};
use wholepact_core::{manual_construction::PreconstructionProvider, Amount, PrivacyMode};
use wholepact_signer_origin::durable_input_projection_v1::{
    projection_pairing_review_digest_v1,
    redisclosure::{
        redisclosure_pairing_review_digest_v1, DurableInputProjectionRedisclosureRequestV1,
        ProjectionRedisclosureChannelBindingV1,
    },
    ProjectionChannelBindingV1,
};

fn h(byte: char) -> String {
    byte.to_string().repeat(64)
}
fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF;
        CREATE TABLE signer_account_use_genesis(genesis_digest TEXT UNIQUE NOT NULL);",
    )
    .unwrap();
    c.execute(
        "INSERT INTO signer_account_use_genesis VALUES(?1)",
        [h('a')],
    )
    .unwrap();
    c.execute_batch(SCHEMA_V1).unwrap();
    c
}
fn insert_original(
    c: &Connection,
    operation: &str,
    request: &str,
    reference: &str,
    payload: &str,
    source: &str,
) -> rusqlite::Result<usize> {
    c.execute(
        "INSERT INTO signer_durable_input_projection_outbox_v1 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            operation,
            request,
            reference,
            h('1'),
            h('a'),
            h('f'),
            payload,
            source
        ],
    )
}
fn insert_delivery(
    c: &Connection,
    operation: &str,
    original: &str,
    original_request: &str,
    original_reference: &str,
) -> rusqlite::Result<usize> {
    c.execute(
        "INSERT INTO signer_durable_input_projection_deliveries_v1 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            operation,
            h('d'),
            h('e'),
            original,
            original_request,
            original_reference,
            h('f'),
            "{}"
        ],
    )
}
fn counts(c: &Connection) -> (u64, u64) {
    c.query_row("SELECT (SELECT count(*) FROM signer_durable_input_projection_outbox_v1), (SELECT count(*) FROM signer_durable_input_projection_deliveries_v1)", [],
        |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
}

#[test]
fn both_rows_are_immutable_even_when_replace_delete_triggers_are_disabled() {
    let c = db();
    insert_original(
        &c,
        "original",
        &h('b'),
        &h('c'),
        "original bytes",
        "source bytes",
    )
    .unwrap();
    insert_delivery(&c, "delivery", "original", &h('b'), &h('c')).unwrap();
    for table in [
        "signer_durable_input_projection_outbox_v1",
        "signer_durable_input_projection_deliveries_v1",
    ] {
        assert!(c
            .execute(&format!("UPDATE {table} SET payload='changed'"), [])
            .is_err());
        assert!(c.execute(&format!("DELETE FROM {table}"), []).is_err());
        assert!(c
            .execute(
                &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                []
            )
            .is_err());
    }
    assert_eq!(counts(&c), (1, 1));
    let payload: String = c.query_row("SELECT payload FROM signer_durable_input_projection_outbox_v1 WHERE operation_id='original'", [], |r| r.get(0)).unwrap();
    assert_eq!(payload, "original bytes");
}

#[test]
fn delivery_requires_exact_original_and_never_another_delivery_even_without_foreign_keys() {
    let c = db();
    // The exact-link trigger is stronger than relying on the connection pragma.
    c.pragma_update(None, "foreign_keys", false).unwrap();
    insert_original(&c, "original", &h('b'), &h('c'), "{}", "{}").unwrap();
    for (parent, request, reference) in [
        ("missing", h('b'), h('c')),
        ("original", h('9'), h('c')),
        ("original", h('b'), h('9')),
    ] {
        assert!(insert_delivery(&c, "bad-delivery", parent, &request, &reference).is_err());
    }
    insert_delivery(&c, "delivery", "original", &h('b'), &h('c')).unwrap();
    // Unique digests differ, so refusal is specifically the missing ORIGINAL.
    assert!(c.execute("INSERT INTO signer_durable_input_projection_deliveries_v1 VALUES('chain',?1,?2,'delivery',?3,?4,?5,'{}')",
        params![h('1'), h('2'), h('d'), h('e'), h('f')]).is_err());
    assert_eq!(counts(&c), (1, 1));
}

#[test]
fn operation_names_are_disjoint_and_request_and_reference_are_unique() {
    let c = db();
    insert_original(&c, "original", &h('b'), &h('c'), "{}", "{}").unwrap();
    assert!(insert_delivery(&c, "original", "original", &h('b'), &h('c')).is_err());
    insert_delivery(&c, "delivery", "original", &h('b'), &h('c')).unwrap();
    assert!(insert_original(&c, "delivery", &h('1'), &h('2'), "{}", "{}").is_err());
    assert!(insert_original(&c, "other", &h('b'), &h('2'), "{}", "{}").is_err());
    assert!(insert_original(&c, "other", &h('1'), &h('c'), "{}", "{}").is_err());
    assert!(operation_exists(&c, "original").unwrap());
    assert!(operation_exists(&c, "delivery").unwrap());
    assert!(!operation_exists(&c, "missing").unwrap());
    assert_eq!(counts(&c), (1, 1));
}

#[test]
fn source_and_outbox_are_byte_bounded_and_digest_columns_are_strict() {
    for (payload, source) in [
        (" ".repeat(MAX_INPUT_PROJECTION_FRAME_BYTES_V1), "{}".into()),
        ("{}".into(), " ".repeat(MAX_RECORD_BYTES + 1)),
        ("{}".into(), "é".repeat(MAX_RECORD_BYTES / 2 + 1)),
        (String::new(), "{}".into()),
        ("{}".into(), String::new()),
    ] {
        let c = db();
        assert!(insert_original(&c, "original", &h('b'), &h('c'), &payload, &source).is_err());
        assert_eq!(counts(&c), (0, 0));
    }
    let c = db();
    assert!(insert_original(&c, "original", &h('B'), &h('c'), "{}", "{}").is_err());
    assert!(insert_original(&c, &"x".repeat(129), &h('b'), &h('c'), "{}", "{}").is_err());
    assert!(insert_original(
        &c,
        "original",
        &h('b'),
        &h('c'),
        "{}",
        &" ".repeat(MAX_RECORD_BYTES)
    )
    .is_ok());
}

#[test]
fn interrupted_before_commit_rolls_back_but_after_commit_never_erases_exposure() {
    let mut c = db();
    {
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        insert_original(
            &tx,
            "original",
            &h('b'),
            &h('c'),
            "retained bytes",
            "source bytes",
        )
        .unwrap();
        // Crash/denial before commit: ordinary SQLite transaction rollback.
    }
    assert_eq!(counts(&c), (0, 0));
    {
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        insert_original(
            &tx,
            "original",
            &h('b'),
            &h('c'),
            "retained bytes",
            "source bytes",
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let ambiguous_send: std::result::Result<(), ()> = Err(());
    assert!(ambiguous_send.is_err());
    assert_eq!(counts(&c), (1, 0));
    assert!(c
        .execute("DELETE FROM signer_durable_input_projection_outbox_v1", [])
        .is_err());
    insert_delivery(&c, "delivery", "original", &h('b'), &h('c')).unwrap();
    assert_eq!(counts(&c), (1, 1));
}

fn outbox() -> DurableInputProjectionOutboxV1 {
    let mut agreement: wholepact_core::AgreementDraft = wholepact_core::parse_typed_json(
        include_bytes!("../../../wholepact-core/tests/fixtures/agreement.json"),
    )
    .unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.privacy_profile.mode = PrivacyMode::DeclaredOperator;
    agreement.privacy_profile.proving_operator = Some("synthetic-prover".into());
    let amount = |value| Amount::from_zatoshis(value).unwrap();
    let intent = DurableInputProjectionIntentV1 {
        version: 1,
        purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
        agreement,
        proposal_id: "synthetic-proposal".into(),
        account_id: h('1'),
        participant_id: "alice".into(),
        original_recipient_policy_digest: h('a'),
        privacy_domain: "synthetic-domain".into(),
        contribution: amount(400_000_000),
        maximum_fee_share: amount(12_000),
        maximum_transaction_fee: amount(30_000),
        transaction_expiry_height: 3_000_000,
        provider: PreconstructionProvider {
            source_id: "synthetic-provider".into(),
            endpoint: "https://invalid.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        anchor_height: 2_900_000,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
        constructor_principal_id: "synthetic-host".into(),
        protected_destination: "/synthetic/host/coordination.sqlite".into(),
        retention_policy: "Only until the original deadline.".into(),
        local_reviewer_account_ids: vec![h('1'), h('2')],
        valid_from_unix_seconds: 100,
        valid_until_unix_seconds: 200,
    };
    let request = DurableInputProjectionRequestV1 {
        version: 1,
        operation_id: "synthetic-original".into(),
        intent: intent.clone(),
    };
    let projection = DurableInputProjectionV1 {
        version: 1,
        intent,
        inputs: vec![DurableProjectedInputV1 {
            input_id: format!("ironwood:{}:0", h('a')),
            value: amount(500_000_000),
            commitment: h('b'),
        }],
        selected_total: amount(500_000_000),
        own_return_receiver: "usyntheticreturnalice".into(),
        context: DurableProjectionContextV1 {
            tip_height: 2_900_001,
            tip_hash: h('c'),
            anchor_height: 2_900_000,
            anchor_hash: h('d'),
            anchor_root: h('e'),
        },
        captured_at_unix_seconds: 101,
    };
    let scope = request.pair_scope().unwrap();
    let recipient = ProjectionChannelBindingV1 {
        version: 1,
        channel_binding_digest: projection_pairing_review_digest_v1(&scope, &h('c'), 1).unwrap(),
        scope,
        grant_id: h('d'),
        authenticated_local_grant_digest: h('e'),
        uid: 1000,
        pid: 17,
        process_instance: h('c'),
        signer_generation: 1,
    };
    let mut outbox = DurableInputProjectionOutboxV1 {
        version: 1,
        request_digest: request.digest().unwrap(),
        request,
        projection_digest: projection.digest().unwrap(),
        projection,
        native_review_digest: h('f'),
        native_entry_digest: h('a'),
        recipient,
        reference: h('0'),
    };
    outbox.reference = outbox.compute_reference().unwrap();
    outbox.validate().unwrap();
    outbox
}
fn delivery(original: &DurableInputProjectionOutboxV1) -> DurableInputProjectionDeliveryV1 {
    let request = DurableInputProjectionRedisclosureRequestV1 {
        version: 1,
        operation_id: "synthetic-delivery".into(),
        original_request: original.request.clone(),
    };
    let scope = request.pair_scope().unwrap();
    let recipient = ProjectionRedisclosureChannelBindingV1 {
        version: 1,
        channel_binding_digest: redisclosure_pairing_review_digest_v1(&scope, &h('7'), 2).unwrap(),
        scope,
        grant_id: h('8'),
        authenticated_local_grant_digest: h('9'),
        uid: 1000,
        pid: 27,
        process_instance: h('7'),
        signer_generation: 2,
    };
    let mut delivery = DurableInputProjectionDeliveryV1 {
        version: 1,
        request_digest: request.digest().unwrap(),
        request,
        original_outbox_reference: original.reference.clone(),
        original_projection_digest: original.projection_digest.clone(),
        native_review_digest: h('b'),
        native_entry_digest: h('c'),
        recipient,
        reference: h('0'),
    };
    delivery.reference = delivery.compute_reference().unwrap();
    delivery.require_original(original).unwrap();
    delivery
}

#[test]
fn canonical_committed_bytes_reject_duplicates_unknown_fields_and_normalization() {
    let outbox = outbox();
    let raw = encode_frame(&outbox).unwrap();
    let decoded: DurableInputProjectionOutboxV1 =
        decode_exact(&raw, MAX_INPUT_PROJECTION_FRAME_BYTES_V1).unwrap();
    assert!(decoded == outbox);
    let spaced = format!(" {}", raw.as_str());
    assert!(decode_exact::<DurableInputProjectionOutboxV1>(
        &spaced,
        MAX_INPUT_PROJECTION_FRAME_BYTES_V1
    )
    .is_err());
    let duplicate = raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(decode_exact::<DurableInputProjectionOutboxV1>(
        &duplicate,
        MAX_INPUT_PROJECTION_FRAME_BYTES_V1
    )
    .is_err());
    let extra = raw.replacen('{', "{\"approved\":true,", 1);
    assert!(decode_exact::<DurableInputProjectionOutboxV1>(
        &extra,
        MAX_INPUT_PROJECTION_FRAME_BYTES_V1
    )
    .is_err());
    assert!(decode_exact::<DurableInputProjectionOutboxV1>(&raw, raw.len() - 1).is_err());
}

#[test]
fn redisclosure_keeps_original_deadline_projection_and_provenance_exact() {
    let original = outbox();
    let next = delivery(&original);
    let bytes = encode_redisclosure_response_v1(&original, &next).unwrap();
    assert!(bytes.len() < MAX_INPUT_PROJECTION_FRAME_BYTES_V1);
    assert!(next.request.require_valid_at(199).is_ok());
    assert!(next.request.require_valid_at(200).is_err());
    assert_ne!(original.native_entry_digest, next.native_entry_digest);
    assert_ne!(
        original.recipient.process_instance,
        next.recipient.process_instance
    );
    for change in 0..6 {
        let mut other = original.clone();
        match change {
            0 => other
                .request
                .intent
                .protected_destination
                .push_str("-other"),
            1 => other.request.intent.valid_until_unix_seconds += 1,
            2 => other.request.intent.local_reviewer_account_ids[1] = h('3'),
            3 => other.projection.inputs[0].commitment = h('4'),
            4 => other.native_review_digest = h('5'),
            _ => other.recipient.pid += 1,
        }
        assert!(next.require_original(&other).is_err());
    }
    // Original expiry is historical evidence, not permission renewal.
    assert!(original.validate().is_ok());
    assert!(original.request.require_valid_at(200).is_err());
    assert!(next.validate().is_ok());
}

#[test]
fn self_consistent_wire_history_is_not_accepted_without_original_source_evidence() {
    let c = db();
    let original = outbox();
    let payload = encode_frame(&original).unwrap();
    insert_original(
        &c,
        &original.request.operation_id,
        &original.request_digest,
        &original.reference,
        &payload,
        "{}",
    )
    .unwrap();
    assert!(read_original(&c, &original.request.operation_id).is_err());
    assert!(validate_rows(&c).is_err());
}
