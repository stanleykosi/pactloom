//! Synthetic keys and data only. No network, signer, wallet or settlement occurs.
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Barrier},
};
use wholepact_transport::*;

static COUNTER: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wholepact-transport-synthetic-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn ledger(&self) -> SqliteReplayLedger {
        SqliteReplayLedger::open(self.0.join("inbox.sqlite")).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn now() -> Timestamp {
    Timestamp::from_unix_seconds(1_790_000_000).unwrap()
}
fn at(delta: i64) -> Timestamp {
    Timestamp::from_unix_seconds(now().unix_seconds() + delta).unwrap()
}
fn secret(byte: u8) -> TransportSecret {
    TransportSecret::from_bytes([byte; 32]).unwrap()
}
fn context() -> MessageContext {
    MessageContext {
        network_profile_id: "testnet-synthetic-unqualified".into(),
        agreement_id: "private-agreement".into(),
        proposal_id: "proposal-one".into(),
        proposal_revision: 1,
        sender_id: "sender".into(),
        recipient_id: "recipient".into(),
        artifact_kind: ArtifactKind::Contribution,
    }
}
fn request(context: MessageContext, sequence: u64, message: u128) -> ExportRequest {
    ExportRequest {
        context,
        order: MessageOrder {
            message_id: format!("{message:032x}"),
            sequence,
            issued_at: now(),
            expires_at: at(600),
        },
        purpose: "Synthetic offline test".into(),
        persistence_warning: "Recipient can retain copies. Disclosure cannot be recalled.".into(),
    }
}
fn prepared(
    context: MessageContext,
    sequence: u64,
    message: u128,
    payload: &[u8],
) -> PreparedExport {
    prepare_export(
        request(context, sequence, message),
        vec![DisclosureField::new("selected_evidence", payload.to_vec()).unwrap()],
        &secret(11).public_key().unwrap(),
        &secret(22).public_key().unwrap(),
        &now(),
    )
    .unwrap()
}
fn envelope(
    context: MessageContext,
    sequence: u64,
    message: u128,
    payload: &[u8],
) -> EncryptedEnvelope {
    let export = prepared(context, sequence, message, payload);
    let digest = export.preview().digest().unwrap();
    export.seal(&secret(11), &digest, &now()).unwrap()
}
fn receive(
    file: &EncryptedEnvelope,
    expected: &MessageContext,
    ledger: &mut impl ReplayLedger,
) -> Result<ReceivedArtifact> {
    open_envelope(
        file,
        &secret(22),
        &secret(11).public_key().unwrap(),
        expected,
        &now(),
        ledger,
    )
}
#[test]
fn offline_roundtrip_hides_context_and_selected_plaintext() {
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let canary = b"SYNTHETIC-WITNESS-CANARY-DO-NOT-LOG";
    let file = envelope(context(), 1, 1, canary);
    let encoded = std::str::from_utf8(file.as_bytes()).unwrap();
    for private in [
        "SYNTHETIC-WITNESS-CANARY",
        "private-agreement",
        "selected_evidence",
        "Synthetic offline test",
        "payload_digest",
    ] {
        assert!(!encoded.contains(private));
    }
    let path = temp.0.join("artifact.wholepact");
    file.write_new_file(&path).unwrap();
    assert_eq!(
        file.write_new_file(&path).err(),
        Some(TransportError::Storage)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let imported = EncryptedEnvelope::read_file(path).unwrap();
    let received = receive(&imported, &context(), &mut ledger).unwrap();
    assert_eq!(received.fields()[0].bytes(), canary);
    assert_eq!(received.preview().context, context());
    assert_eq!(ledger.record_count().unwrap(), 1);
    // WAL and database may contain ciphertext/hashes, never the selected raw text.
    for name in ["inbox.sqlite", "inbox.sqlite-wal"] {
        if let Ok(bytes) = std::fs::read(temp.0.join(name)) {
            assert!(!bytes.windows(canary.len()).any(|w| w == canary));
        }
    }
}
#[test]
fn every_context_dimension_keys_and_time_fail_before_replay_mutation() {
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let file = envelope(context(), 1, 1, b"fixture");
    let mut variants = Vec::new();
    let mut c = context();
    c.recipient_id = "other".into();
    variants.push((c, TransportError::WrongRecipient));
    let mut c = context();
    c.network_profile_id = "mainnet-not-supported".into();
    variants.push((c, TransportError::WrongNetwork));
    let mut c = context();
    c.agreement_id = "different".into();
    variants.push((c, TransportError::WrongContext));
    let mut c = context();
    c.proposal_id = "different".into();
    variants.push((c, TransportError::WrongContext));
    let mut c = context();
    c.proposal_revision = 2;
    variants.push((c, TransportError::WrongContext));
    let mut c = context();
    c.sender_id = "other".into();
    variants.push((c, TransportError::WrongContext));
    let mut c = context();
    c.artifact_kind = ArtifactKind::Authorization;
    variants.push((c, TransportError::WrongContext));
    for (expected, error) in variants {
        assert_eq!(receive(&file, &expected, &mut ledger).err(), Some(error));
    }
    assert_eq!(
        open_envelope(
            &file,
            &secret(33),
            &secret(11).public_key().unwrap(),
            &context(),
            &now(),
            &mut ledger
        )
        .err(),
        Some(TransportError::Authentication)
    );
    assert_eq!(
        open_envelope(
            &file,
            &secret(22),
            &secret(33).public_key().unwrap(),
            &context(),
            &now(),
            &mut ledger
        )
        .err(),
        Some(TransportError::Authentication)
    );
    for time in [at(-1), at(600), at(601)] {
        assert_eq!(
            open_envelope(
                &file,
                &secret(22),
                &secret(11).public_key().unwrap(),
                &context(),
                &time,
                &mut ledger
            )
            .err(),
            Some(TransportError::InvalidTime)
        );
    }
    assert_eq!(ledger.record_count().unwrap(), 0);
    assert!(receive(&file, &context(), &mut ledger).is_ok());
}
#[test]
fn exact_disclosure_binding_blocks_substitution_and_stale_review() {
    let token = prepared(context(), 1, 1, b"selected")
        .preview()
        .digest()
        .unwrap();
    assert_eq!(
        prepared(context(), 1, 1, b"extra-private-material")
            .seal(&secret(11), &token, &now())
            .err()
            .map(|e| e.to_string()),
        Some(TransportError::DisclosureDenied.to_string())
    );
    let mut revised = context();
    revised.proposal_revision = 2;
    assert_eq!(
        prepared(revised, 1, 1, b"selected")
            .seal(&secret(11), &token, &now())
            .err(),
        Some(TransportError::DisclosureDenied)
    );
    assert_eq!(
        prepared(context(), 2, 2, b"selected")
            .seal(&secret(11), &token, &now())
            .err(),
        Some(TransportError::DisclosureDenied)
    );
    let export = prepare_export(
        request(context(), 1, 1),
        vec![DisclosureField::new("selected_evidence", b"selected".to_vec()).unwrap()],
        &secret(11).public_key().unwrap(),
        &secret(33).public_key().unwrap(),
        &now(),
    )
    .unwrap();
    assert_eq!(
        export.seal(&secret(11), &token, &now()).err(),
        Some(TransportError::DisclosureDenied)
    );
    assert_eq!(
        prepared(context(), 1, 1, b"selected")
            .seal(&secret(33), &token, &now())
            .err(),
        Some(TransportError::DisclosureDenied)
    );
    assert_eq!(
        prepared(context(), 1, 1, b"selected")
            .seal(&secret(11), &token, &at(600))
            .err(),
        Some(TransportError::InvalidTime)
    );
}
#[test]
fn replay_reencryption_equivocation_and_sequence_gaps_are_distinct() {
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let file = envelope(context(), 1, 1, b"fixture");
    receive(&file, &context(), &mut ledger).unwrap();
    let resealed = envelope(context(), 1, 1, b"fixture");
    assert_ne!(file.as_bytes(), resealed.as_bytes());
    assert_eq!(
        receive(&resealed, &context(), &mut ledger).err(),
        Some(TransportError::Replay)
    );
    for (sequence, id, data, expected) in [
        (1, 2, &b"fixture"[..], TransportError::Equivocation),
        (2, 1, &b"fixture"[..], TransportError::Equivocation),
        (2, 2, &b"changed"[..], TransportError::Equivocation),
        (2, 3, &b"fixture"[..], TransportError::Replay),
    ] {
        assert_eq!(
            receive(
                &envelope(context(), sequence, id, data),
                &context(),
                &mut ledger
            )
            .err(),
            Some(expected)
        );
    }
    let mut next = context();
    next.proposal_id = "proposal-two".into();
    next.proposal_revision = 2;
    assert_eq!(
        receive(&envelope(next.clone(), 3, 3, b"next"), &next, &mut ledger).err(),
        Some(TransportError::OutOfOrder)
    );
    assert!(receive(&envelope(next.clone(), 2, 2, b"next"), &next, &mut ledger).is_ok());
    assert_eq!(ledger.record_count().unwrap(), 2);
}
#[test]
fn accepted_inbox_recovers_after_crash_without_new_delivery_even_after_expiry() {
    let temp = Temp::new();
    let file = envelope(context(), 1, 1, b"retained-synthetic-artifact");
    let stream = {
        let mut ledger = temp.ledger();
        let received = receive(&file, &context(), &mut ledger).unwrap();
        received.stream_digest().to_owned()
        // Caller loses ReceivedArtifact here, before its own domain processing.
    };
    let mut reopened = temp.ledger();
    assert_eq!(reopened.retained_sequences(&context()).unwrap(), vec![1]);
    let retained = reopened
        .retained_for_context(&context(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(retained.stream_digest(), stream);
    let restored = recover_received(
        &retained,
        &secret(22),
        &secret(11).public_key().unwrap(),
        &context(),
    )
    .unwrap();
    assert_eq!(
        restored.artifact().fields()[0].bytes(),
        b"retained-synthetic-artifact"
    );
    assert!(!restored.is_new_delivery());
    assert!(!restored.authorization_allowed());
    assert!(restored.is_currently_valid(&now()));
    assert!(!restored.is_currently_valid(&at(601)));
    assert_eq!(
        receive(&file, &context(), &mut reopened).err(),
        Some(TransportError::Replay)
    );
    let mut wrong = context();
    wrong.proposal_revision = 2;
    assert_eq!(
        recover_received(
            &retained,
            &secret(22),
            &secret(11).public_key().unwrap(),
            &wrong
        )
        .err(),
        Some(TransportError::WrongContext)
    );
}
#[test]
fn separate_database_connections_race_one_durable_acceptance() {
    let temp = Temp::new();
    drop(temp.ledger());
    let bytes = envelope(context(), 1, 1, b"race").as_bytes().to_vec();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = temp.0.join("inbox.sqlite");
            let barrier = barrier.clone();
            let bytes = bytes.clone();
            std::thread::spawn(move || {
                let mut ledger = SqliteReplayLedger::open(path).unwrap();
                let file = EncryptedEnvelope::from_bytes(bytes).unwrap();
                barrier.wait();
                receive(&file, &context(), &mut ledger).map(|_| ())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(TransportError::Replay))
            .count(),
        1
    );
    assert_eq!(temp.ledger().record_count().unwrap(), 1);
}
#[test]
fn failed_durable_write_never_returns_plaintext_or_consumes_sequence() {
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let db = rusqlite::Connection::open(temp.0.join("inbox.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER inject_failure BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT, 'synthetic fault'); END;").unwrap();
    let file = envelope(context(), 1, 1, b"safe-retry");
    assert_eq!(
        receive(&file, &context(), &mut ledger).err(),
        Some(TransportError::Storage)
    );
    assert_eq!(ledger.record_count().unwrap(), 0);
    db.execute_batch("DROP TRIGGER inject_failure;").unwrap();
    assert!(receive(&file, &context(), &mut ledger).is_ok());
}
#[test]
fn bounded_parser_rejects_malformed_tampered_duplicate_and_unknown_data() {
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let file = envelope(context(), 1, 1, b"fixture");
    let original: serde_json::Value = serde_json::from_slice(file.as_bytes()).unwrap();
    for name in ["encapsulated_key", "ciphertext"] {
        let mut value = original.clone();
        let field = value[name].as_str().unwrap();
        let replacement = if field.starts_with('0') { "1" } else { "0" };
        value[name] = format!("{}{}", replacement, &field[1..]).into();
        let altered = EncryptedEnvelope::from_bytes(serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            receive(&altered, &context(), &mut ledger).err(),
            Some(TransportError::Authentication)
        );
    }
    let mut value = original.clone();
    value["schema_version"] = 2.into();
    assert_eq!(
        EncryptedEnvelope::from_bytes(serde_json::to_vec(&value).unwrap()).err(),
        Some(TransportError::UnsupportedVersion)
    );
    let mut value = original;
    value["unknown_mandatory"] = true.into();
    assert_eq!(
        EncryptedEnvelope::from_bytes(serde_json::to_vec(&value).unwrap()).err(),
        Some(TransportError::Malformed)
    );
    let duplicate = String::from_utf8(file.as_bytes().to_vec())
        .unwrap()
        .replacen("{", "{\"schema_version\":1,", 1);
    assert_eq!(
        EncryptedEnvelope::from_bytes(duplicate.into_bytes()).err(),
        Some(TransportError::Malformed)
    );
    assert_eq!(
        EncryptedEnvelope::from_bytes(file.as_bytes()[..file.as_bytes().len() - 2].to_vec()).err(),
        Some(TransportError::Malformed)
    );
    assert_eq!(
        EncryptedEnvelope::from_bytes(vec![b' '; MAX_FILE_BYTES + 1]).err(),
        Some(TransportError::ResourceLimit)
    );
    let deep = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    assert_eq!(
        EncryptedEnvelope::from_bytes(deep.into_bytes()).err(),
        Some(TransportError::ResourceLimit)
    );
    assert_eq!(ledger.record_count().unwrap(), 0);
}
#[test]
fn payload_count_time_and_size_boundaries_are_enforced() {
    let fields = (0..MAX_FIELDS + 1)
        .map(|i| DisclosureField::new(format!("field{i}"), vec![0]).unwrap())
        .collect();
    assert_eq!(
        prepare_export(
            request(context(), 1, 1),
            fields,
            &secret(11).public_key().unwrap(),
            &secret(22).public_key().unwrap(),
            &now()
        )
        .err(),
        Some(TransportError::ResourceLimit)
    );
    assert_eq!(
        DisclosureField::new("field", vec![0; MAX_PAYLOAD_BYTES + 1]).err(),
        Some(TransportError::ResourceLimit)
    );
    assert_eq!(
        DisclosureField::new("bad\nfield", vec![0]).err(),
        Some(TransportError::Malformed)
    );
    for date in [
        "2026-10-13T14:00:00+00:00",
        "2026-10-13T14:00:00.0Z",
        "2016-12-31T23:59:60Z",
    ] {
        assert!(Timestamp::try_from(date.to_string()).is_err());
    }
    let mut invalid = request(context(), 1, 1);
    invalid.order.expires_at = at(MAX_MESSAGE_LIFETIME_SECONDS + 1);
    assert_eq!(
        prepare_export(
            invalid,
            vec![DisclosureField::new("field", vec![0]).unwrap()],
            &secret(11).public_key().unwrap(),
            &secret(22).public_key().unwrap(),
            &now()
        )
        .err(),
        Some(TransportError::InvalidTime)
    );
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let bytes = vec![42; MAX_PAYLOAD_BYTES];
    let file = envelope(context(), 1, 1, &bytes);
    assert!(file.as_bytes().len() < MAX_FILE_BYTES);
    assert_eq!(
        receive(&file, &context(), &mut ledger).unwrap().fields()[0].bytes(),
        bytes
    );
}

#[test]
fn corrupted_retained_rows_are_bounded_and_cannot_become_recovered_content() {
    let temp = Temp::new();
    let mut ledger = temp.ledger();
    let file = envelope(context(), 1, 1, b"recover-original");
    let received = receive(&file, &context(), &mut ledger).unwrap();
    let stream = received.stream_digest();
    let db = rusqlite::Connection::open(temp.0.join("inbox.sqlite")).unwrap();
    db.execute("UPDATE receipts SET content_digest=?1", ["00".repeat(32)])
        .unwrap();
    let retained = ledger.retained_envelope(stream, 1).unwrap().unwrap();
    assert_eq!(
        recover_received(
            &retained,
            &secret(22),
            &secret(11).public_key().unwrap(),
            &context()
        )
        .err(),
        Some(TransportError::Authentication)
    );
    db.execute(
        "UPDATE receipts SET envelope=zeroblob(?1)",
        [MAX_FILE_BYTES as i64 + 1],
    )
    .unwrap();
    assert_eq!(
        ledger.retained_envelope(stream, 1).err(),
        Some(TransportError::ResourceLimit)
    );
}
