//! All keys, identities, invitations and payloads here are synthetic fixtures.
//! These tests do not qualify real identity enrollment, signer release or settlement.
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};
use wholepact_transport::*;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wholepact-mailbox-synthetic-{}",
            random_message_id().unwrap()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn inbox(&self) -> SqliteReplayLedger {
        SqliteReplayLedger::open(self.0.join("inbox.sqlite")).unwrap()
    }
    fn outbox(&self) -> SqliteOutbox {
        SqliteOutbox::open(self.0.join("outbox.sqlite")).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn now() -> Timestamp {
    at(0)
}
fn at(delta: i64) -> Timestamp {
    Timestamp::from_unix_seconds(1_790_000_000 + delta).unwrap()
}
fn secret(byte: u8) -> TransportSecret {
    TransportSecret::from_bytes([byte; 32]).unwrap()
}
fn sender() -> TransportPublicKey {
    secret(11).public_key().unwrap()
}
fn recipient() -> TransportPublicKey {
    secret(22).public_key().unwrap()
}
fn context(kind: ArtifactKind) -> MessageContext {
    MessageContext {
        network_profile_id: "testnet-synthetic-unqualified".into(),
        agreement_id: "private-synthetic-agreement".into(),
        proposal_id: "proposal-one".into(),
        proposal_revision: 1,
        sender_id: "organizer".into(),
        recipient_id: "participant".into(),
        artifact_kind: kind,
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
        purpose: "Synthetic recipient-scoped exchange".into(),
        persistence_warning: "The recipient can retain disclosed data.".into(),
    }
}
fn prepared(kind: ArtifactKind, sequence: u64, message: u128, value: &[u8]) -> PreparedExport {
    prepare_export(
        request(context(kind), sequence, message),
        vec![DisclosureField::new("selected_artifact", value.to_vec()).unwrap()],
        &sender(),
        &recipient(),
        &now(),
    )
    .unwrap()
}
fn enqueue(
    outbox: &mut SqliteOutbox,
    kind: ArtifactKind,
    sequence: u64,
    message: u128,
    value: &[u8],
) -> Result<OutboxArtifact> {
    let prepared = prepared(kind, sequence, message, value);
    let approved = prepared.preview().digest().unwrap();
    outbox.enqueue(prepared, &secret(11), &approved, &now())
}
fn receive(
    file: &EncryptedEnvelope,
    kind: ArtifactKind,
    ledger: &mut SqliteReplayLedger,
) -> ReceivedArtifact {
    open_envelope(file, &secret(22), &sender(), &context(kind), &now(), ledger).unwrap()
}
fn invitation() -> PrivateInvitation {
    PrivateInvitation {
        schema_version: 1,
        invitation_id: "09".repeat(16),
        organizer_key_fingerprint: sender().fingerprint(),
        invited_participant_id: "participant".into(),
        agreement_manifest_digest: "ab".repeat(32),
        offered_roles: vec![InvitationRole::Contributor, InvitationRole::Sponsor],
        purpose: "Synthetic cooperative purchase".into(),
        recipient_summary: "Synthetic beneficiary; ownership verification is separate.".into(),
        fee_summary: "Fees require exact later review.".into(),
        visibility_summary: "Only the explicitly selected preview is shared.".into(),
        coordination_deadline: at(1200),
    }
}

#[test]
fn private_invitation_roundtrip_is_read_only_and_scope_bound() {
    let temp = Temp::new();
    let mut outbox = temp.outbox();
    let prepared = prepare_invitation(
        request(context(ArtifactKind::Invitation), 1, 1),
        invitation(),
        &sender(),
        &recipient(),
        &now(),
    )
    .unwrap();
    let approved = prepared.preview().digest().unwrap();
    let queued = outbox
        .enqueue(prepared, &secret(11), &approved, &now())
        .unwrap();
    let mut inbox = temp.inbox();
    let received = receive(queued.envelope(), ArtifactKind::Invitation, &mut inbox);
    let review = review_invitation(&received).unwrap();
    assert!(review.is_read_only());
    assert!(review.is_currently_valid(&now()));
    assert!(!review.is_currently_valid(&at(600)));
    assert!(!review.authorization_allowed());
    assert!(!review.wallet_control_verified());
    assert!(!review.recipient_ownership_verified());
    assert_eq!(
        review.invitation().agreement_manifest_digest,
        "ab".repeat(32)
    );
    let mut wrong = invitation();
    wrong.invited_participant_id = "other".into();
    assert_eq!(
        prepare_invitation(
            request(context(ArtifactKind::Invitation), 2, 2),
            wrong,
            &sender(),
            &recipient(),
            &now()
        )
        .err(),
        Some(TransportError::WrongRecipient)
    );
    let mut wrong = invitation();
    wrong.organizer_key_fingerprint = recipient().fingerprint();
    assert_eq!(
        prepare_invitation(
            request(context(ArtifactKind::Invitation), 2, 2),
            wrong,
            &sender(),
            &recipient(),
            &now()
        )
        .err(),
        Some(TransportError::Authentication)
    );
    let mut wrong = invitation();
    wrong.coordination_deadline = at(599);
    assert_eq!(
        prepare_invitation(
            request(context(ArtifactKind::Invitation), 2, 2),
            wrong,
            &sender(),
            &recipient(),
            &now()
        )
        .err(),
        Some(TransportError::InvalidTime)
    );
    let mut wrong = invitation();
    wrong.offered_roles.push(InvitationRole::Sponsor);
    assert_eq!(
        prepare_invitation(
            request(context(ArtifactKind::Invitation), 2, 2),
            wrong,
            &sender(),
            &recipient(),
            &now()
        )
        .err(),
        Some(TransportError::Malformed)
    );
}

#[test]
fn inbox_rejects_authenticated_invitation_with_unknown_or_extra_payload() {
    let temp = Temp::new();
    let mut value = serde_json::to_value(invitation()).unwrap();
    value["viewing_key"] = serde_json::json!("SYNTHETIC-SECRET-NOT-ALLOWED");
    let prepared = prepare_export(
        request(context(ArtifactKind::Invitation), 1, 1),
        vec![
            DisclosureField::new("private_invitation_v1", serde_json::to_vec(&value).unwrap())
                .unwrap(),
        ],
        &sender(),
        &recipient(),
        &now(),
    )
    .unwrap();
    let approved = prepared.preview().digest().unwrap();
    let file = prepared.seal(&secret(11), &approved, &now()).unwrap();
    let received = receive(&file, ArtifactKind::Invitation, &mut temp.inbox());
    assert_eq!(
        review_invitation(&received).err(),
        Some(TransportError::Malformed)
    );
}

#[test]
fn outbox_retry_recovers_identical_ciphertext_and_exact_recipient_scope() {
    let temp = Temp::new();
    let mut outbox = temp.outbox();
    let kind = ArtifactKind::FinalTransaction;
    let canary = b"SYNTHETIC-PRIVATE-FINALIZED-ARTIFACT-NO-NETWORK";
    let queued = enqueue(&mut outbox, kind, 1, 1, canary).unwrap();
    let bytes = queued.envelope().as_bytes().to_vec();
    assert_eq!(outbox.next_sequence(&context(kind)).unwrap(), 2);
    let retry = enqueue(&mut outbox, kind, 1, 1, canary).unwrap();
    assert_eq!(retry.envelope().as_bytes(), bytes);
    assert_eq!(
        enqueue(&mut outbox, kind, 1, 1, b"changed").err(),
        Some(TransportError::Equivocation)
    );
    assert_eq!(
        enqueue(&mut outbox, kind, 2, 2, canary).err(),
        Some(TransportError::Replay)
    );
    assert_eq!(
        enqueue(&mut outbox, kind, 2, 2, b"changed").err(),
        Some(TransportError::Equivocation)
    );
    drop(outbox);
    let outbox = temp.outbox();
    let recovered = outbox
        .recover_for_recipient(&context(kind), &recipient(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.envelope().as_bytes(), bytes);
    assert!(!recovered.authorization_allowed());
    assert!(!recovered.is_currently_valid(&at(-1)));
    assert!(recovered.is_currently_valid(&now()));
    assert!(!recovered.is_currently_valid(&at(600)));
    assert!(
        outbox
            .recover_for_recipient(&context(kind), &sender(), 1)
            .unwrap()
            .is_none()
    );
    let mut changed = context(kind);
    changed.proposal_revision += 1;
    assert!(
        outbox
            .recover_for_recipient(&changed, &recipient(), 1)
            .unwrap()
            .is_none()
    );
    for name in ["outbox.sqlite", "outbox.sqlite-wal"] {
        if let Ok(bytes) = std::fs::read(temp.0.join(name)) {
            for private in [canary.as_slice(), b"private-synthetic-agreement".as_slice()] {
                assert!(!bytes.windows(private.len()).any(|v| v == private));
            }
        }
    }
}

#[test]
fn missing_consent_gaps_and_authorization_never_consume_outbox_sequence() {
    let temp = Temp::new();
    let mut outbox = temp.outbox();
    assert_eq!(
        enqueue(&mut outbox, ArtifactKind::Authorization, 1, 1, b"signature").err(),
        Some(TransportError::AuthorityUnavailable)
    );
    assert_eq!(
        enqueue(&mut outbox, ArtifactKind::Invitation, 2, 2, b"preview").err(),
        Some(TransportError::OutOfOrder)
    );
    assert_eq!(
        outbox
            .enqueue(
                prepared(ArtifactKind::Invitation, 1, 1, b"preview"),
                &secret(11),
                &"ff".repeat(32),
                &now()
            )
            .err(),
        Some(TransportError::DisclosureDenied)
    );
    assert_eq!(
        outbox
            .next_sequence(&context(ArtifactKind::Invitation))
            .unwrap(),
        1
    );
    let prepared = prepared(ArtifactKind::Invitation, 1, 1, b"preview");
    let approved = prepared.preview().digest().unwrap();
    assert_eq!(
        outbox
            .enqueue(prepared, &secret(33), &approved, &now())
            .err(),
        Some(TransportError::DisclosureDenied)
    );
    assert!(
        outbox
            .pending_sequences(&context(ArtifactKind::Invitation), &recipient())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn authenticated_recipient_receipt_changes_only_delivery_state() {
    let sender_temp = Temp::new();
    let recipient_temp = Temp::new();
    let mut outbox = sender_temp.outbox();
    let queued = enqueue(
        &mut outbox,
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"synthetic-final-artifact",
    )
    .unwrap();
    let received = receive(
        queued.envelope(),
        ArtifactKind::FinalTransaction,
        &mut recipient_temp.inbox(),
    );
    let mut reverse = context(ArtifactKind::DeliveryAcknowledgment);
    std::mem::swap(&mut reverse.sender_id, &mut reverse.recipient_id);
    let prepared = prepare_delivery_acknowledgment(
        &received,
        request(reverse.clone(), 1, 11),
        &recipient(),
        &sender(),
        &now(),
    )
    .unwrap();
    let approved = prepared.preview().digest().unwrap();
    let receipt_file = recipient_temp
        .outbox()
        .enqueue(prepared, &secret(22), &approved, &now())
        .unwrap();
    let ack = open_envelope(
        receipt_file.envelope(),
        &secret(11),
        &recipient(),
        &reverse,
        &now(),
        &mut sender_temp.inbox(),
    )
    .unwrap();
    assert_eq!(
        outbox.record_acknowledgment(&ack).unwrap(),
        DeliveryStatus::RecipientReceiptRecorded
    );
    assert_eq!(
        outbox.record_acknowledgment(&ack).unwrap(),
        DeliveryStatus::RecipientReceiptRecorded
    );
    assert!(
        outbox
            .pending_sequences(&context(ArtifactKind::FinalTransaction), &recipient())
            .unwrap()
            .is_empty()
    );
    let recovered = outbox
        .recover_for_recipient(&context(ArtifactKind::FinalTransaction), &recipient(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.delivery_status(),
        DeliveryStatus::RecipientReceiptRecorded
    );
    assert!(!recovered.authorization_allowed());
    assert_eq!(
        recovered.envelope().as_bytes(),
        queued.envelope().as_bytes()
    );
    assert_eq!(
        prepare_delivery_acknowledgment(
            &ack,
            request(context(ArtifactKind::DeliveryAcknowledgment), 2, 12),
            &sender(),
            &recipient(),
            &now()
        )
        .err(),
        Some(TransportError::WrongContext)
    );
    assert_eq!(
        prepare_delivery_acknowledgment(
            &received,
            request(reverse, 2, 12),
            &secret(33).public_key().unwrap(),
            &sender(),
            &now()
        )
        .err(),
        Some(TransportError::Authentication)
    );
}

#[test]
fn acknowledgment_from_a_different_key_cannot_mark_original_delivery() {
    let temp = Temp::new();
    let inbox_temp = Temp::new();
    let mut outbox = temp.outbox();
    let queued = enqueue(
        &mut outbox,
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"artifact",
    )
    .unwrap();
    let received = receive(
        queued.envelope(),
        ArtifactKind::FinalTransaction,
        &mut inbox_temp.inbox(),
    );
    let mut reverse = context(ArtifactKind::DeliveryAcknowledgment);
    std::mem::swap(&mut reverse.sender_id, &mut reverse.recipient_id);
    let legitimate = prepare_delivery_acknowledgment(
        &received,
        request(reverse.clone(), 1, 3),
        &recipient(),
        &sender(),
        &now(),
    )
    .unwrap();
    let forged = prepare_export(
        request(reverse.clone(), 1, 3),
        legitimate
            .fields()
            .iter()
            .map(|f| DisclosureField::new(f.name(), f.bytes().to_vec()).unwrap())
            .collect(),
        &secret(33).public_key().unwrap(),
        &sender(),
        &now(),
    )
    .unwrap();
    let approved = forged.preview().digest().unwrap();
    let file = forged.seal(&secret(33), &approved, &now()).unwrap();
    let forged_received = open_envelope(
        &file,
        &secret(11),
        &secret(33).public_key().unwrap(),
        &reverse,
        &now(),
        &mut temp.inbox(),
    )
    .unwrap();
    assert_eq!(
        outbox.record_acknowledgment(&forged_received).err(),
        Some(TransportError::Authentication)
    );
    assert_eq!(
        outbox
            .pending_sequences(&context(ArtifactKind::FinalTransaction), &recipient())
            .unwrap(),
        vec![1]
    );
}

#[test]
fn domain_journal_handles_crash_gap_stable_idempotency_and_terminal_conflicts() {
    let temp = Temp::new();
    let queued = enqueue(
        &mut temp.outbox(),
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"artifact",
    )
    .unwrap();
    let mut inbox = temp.inbox();
    let received = receive(
        queued.envelope(),
        ArtifactKind::FinalTransaction,
        &mut inbox,
    );
    let ticket = inbox
        .domain_import_ticket(&received, "finalized-import-v1")
        .unwrap();
    assert!(ticket.completed().is_none());
    let key = ticket.idempotency_key().to_owned();
    assert_eq!(
        inbox
            .pending_domain_sequences(
                &context(ArtifactKind::FinalTransaction),
                "finalized-import-v1"
            )
            .unwrap(),
        vec![1]
    );
    // Simulate domain commit, then crash before recording the result in this inbox.
    let mut synthetic_domain_store = std::collections::BTreeMap::new();
    synthetic_domain_store.insert(key.clone(), "ab".repeat(32));
    drop(inbox);
    let mut inbox = temp.inbox();
    let retained = inbox
        .retained_for_context(&context(ArtifactKind::FinalTransaction), 1)
        .unwrap()
        .unwrap();
    let recovered = recover_received(
        &retained,
        &secret(22),
        &sender(),
        &context(ArtifactKind::FinalTransaction),
    )
    .unwrap();
    assert!(!recovered.authorization_allowed());
    let ticket = inbox
        .domain_import_ticket(recovered.artifact(), "finalized-import-v1")
        .unwrap();
    assert_eq!(ticket.idempotency_key(), key);
    let result = DomainImportResult {
        outcome: DomainOutcome::Applied,
        result_digest: synthetic_domain_store.get(&key).unwrap().clone(),
    };
    inbox
        .complete_domain_import(&ticket, result.clone())
        .unwrap();
    inbox
        .complete_domain_import(&ticket, result.clone())
        .unwrap();
    assert!(
        inbox
            .pending_domain_sequences(
                &context(ArtifactKind::FinalTransaction),
                "finalized-import-v1"
            )
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inbox
            .domain_import_ticket(recovered.artifact(), "finalized-import-v1")
            .unwrap()
            .completed(),
        Some(&result)
    );
    assert_eq!(
        inbox
            .complete_domain_import(
                &ticket,
                DomainImportResult {
                    outcome: DomainOutcome::Rejected,
                    result_digest: result.result_digest
                }
            )
            .err(),
        Some(TransportError::DomainConflict)
    );
    assert!(
        inbox
            .domain_import_ticket(recovered.artifact(), "different-import-v1")
            .unwrap()
            .completed()
            .is_none()
    );
    assert_eq!(
        Temp::new()
            .inbox()
            .domain_import_ticket(&received, "finalized-import-v1")
            .err(),
        Some(TransportError::Authentication)
    );
}

#[test]
fn durable_outbox_race_insertion_failure_and_database_mixup_fail_closed() {
    let temp = Temp::new();
    drop(temp.outbox());
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|i| {
            let path = temp.0.join("outbox.sqlite");
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut outbox = SqliteOutbox::open(path).unwrap();
                barrier.wait();
                enqueue(&mut outbox, ArtifactKind::Invitation, 1, i + 1, b"fixture").map(|_| ())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(TransportError::Equivocation))
            .count(),
        1
    );
    let connection = rusqlite::Connection::open(temp.0.join("outbox.sqlite")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_enqueue BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;").unwrap();
    assert_eq!(
        enqueue(
            &mut temp.outbox(),
            ArtifactKind::Invitation,
            2,
            3,
            b"fixture"
        )
        .err(),
        Some(TransportError::Storage)
    );
    assert_eq!(
        temp.outbox()
            .next_sequence(&context(ArtifactKind::Invitation))
            .unwrap(),
        2
    );
    assert_eq!(
        SqliteReplayLedger::open(temp.0.join("outbox.sqlite")).err(),
        Some(TransportError::UnsupportedVersion)
    );
    drop(temp.inbox());
    assert_eq!(
        SqliteOutbox::open(temp.0.join("inbox.sqlite")).err(),
        Some(TransportError::UnsupportedVersion)
    );
}

#[test]
fn legacy_inbox_migrates_with_all_receipts_pending_and_unknown_versions_fail() {
    let temp = Temp::new();
    let queued = enqueue(
        &mut temp.outbox(),
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"artifact",
    )
    .unwrap();
    receive(
        queued.envelope(),
        ArtifactKind::FinalTransaction,
        &mut temp.inbox(),
    );
    let connection = rusqlite::Connection::open(temp.0.join("inbox.sqlite")).unwrap();
    connection
        .execute_batch("DROP TABLE domain_imports; DROP TABLE IF EXISTS offline_control_outcomes; PRAGMA application_id=0; PRAGMA user_version=1;")
        .unwrap();
    drop(connection);
    assert_eq!(
        temp.inbox()
            .pending_domain_sequences(&context(ArtifactKind::FinalTransaction), "import-v1")
            .unwrap(),
        vec![1]
    );
    let connection = rusqlite::Connection::open(temp.0.join("inbox.sqlite")).unwrap();
    connection.execute_batch("PRAGMA user_version=99;").unwrap();
    assert_eq!(
        SqliteReplayLedger::open(temp.0.join("inbox.sqlite")).err(),
        Some(TransportError::UnsupportedVersion)
    );
}

#[test]
fn corruption_and_resource_exhaustion_fail_without_new_export() {
    let temp = Temp::new();
    let mut outbox = temp.outbox();
    enqueue(
        &mut outbox,
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"artifact",
    )
    .unwrap();
    let connection = rusqlite::Connection::open(temp.0.join("outbox.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE outbox SET envelope=zeroblob(?1)",
            [(MAX_FILE_BYTES + 1) as i64],
        )
        .unwrap();
    assert_eq!(
        outbox
            .recover_for_recipient(&context(ArtifactKind::FinalTransaction), &recipient(), 1)
            .err(),
        Some(TransportError::ResourceLimit)
    );
    connection
        .execute("UPDATE outbox SET envelope=x'0001'", [])
        .unwrap();
    assert_eq!(
        outbox
            .recover_for_recipient(&context(ArtifactKind::FinalTransaction), &recipient(), 1)
            .err(),
        Some(TransportError::Authentication)
    );
    let temp = Temp::new();
    let queued = enqueue(
        &mut temp.outbox(),
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"artifact",
    )
    .unwrap();
    let mut inbox = temp.inbox();
    let received = receive(
        queued.envelope(),
        ArtifactKind::FinalTransaction,
        &mut inbox,
    );
    for i in 0..16 {
        let ticket = inbox
            .domain_import_ticket(&received, &format!("processor-{i}"))
            .unwrap();
        inbox
            .complete_domain_import(
                &ticket,
                DomainImportResult {
                    outcome: DomainOutcome::Rejected,
                    result_digest: "ab".repeat(32),
                },
            )
            .unwrap();
    }
    let ticket = inbox
        .domain_import_ticket(&received, "processor-overflow")
        .unwrap();
    assert_eq!(
        inbox
            .complete_domain_import(
                &ticket,
                DomainImportResult {
                    outcome: DomainOutcome::Applied,
                    result_digest: "ab".repeat(32)
                }
            )
            .err(),
        Some(TransportError::ResourceLimit)
    );
}

#[test]
fn encrypted_mailboxes_protect_routing_metadata_and_reopen_without_plaintext_fallback() {
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    let temp = Temp::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let inbox_key = DatabaseKey::from_bytes([81; 32]);
    let outbox_key = DatabaseKey::from_bytes([82; 32]);
    let inbox_path = temp.0.join("private-inbox.db");
    let outbox_path = temp.0.join("private-outbox.db");
    let mut inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(&inbox_path, &inbox_key).unwrap(),
    )
    .unwrap();
    let mut outbox = SqliteOutbox::from_encrypted_connection(
        create_encrypted(&outbox_path, &outbox_key).unwrap(),
    )
    .unwrap();
    assert_eq!(inbox.protection(), MailboxProtection::Encrypted);
    assert_eq!(outbox.protection(), MailboxProtection::Encrypted);
    let queued = enqueue(
        &mut outbox,
        ArtifactKind::FinalTransaction,
        1,
        1,
        b"synthetic-final-artifact",
    )
    .unwrap();
    let received = receive(
        queued.envelope(),
        ArtifactKind::FinalTransaction,
        &mut inbox,
    );
    let protected_metadata = received.stream_digest().as_bytes();
    for entry in std::fs::read_dir(&temp.0).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(protected_metadata.len())
                .any(|v| v == protected_metadata)
        );
        assert!(!bytes.starts_with(b"SQLite format 3"));
    }
    drop(inbox);
    drop(outbox);
    assert!(SqliteReplayLedger::open(&inbox_path).is_err());
    assert!(SqliteOutbox::open(&outbox_path).is_err());
    let inbox = SqliteReplayLedger::from_encrypted_connection(
        open_encrypted(&inbox_path, &inbox_key).unwrap(),
    )
    .unwrap();
    assert_eq!(
        inbox
            .retained_sequences(&context(ArtifactKind::FinalTransaction))
            .unwrap(),
        vec![1]
    );
    let outbox =
        SqliteOutbox::from_encrypted_connection(open_encrypted(&outbox_path, &outbox_key).unwrap())
            .unwrap();
    let recovered = outbox
        .recover_for_recipient(&context(ArtifactKind::FinalTransaction), &recipient(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.envelope().as_bytes(),
        queued.envelope().as_bytes()
    );
    assert_eq!(
        temp.inbox().protection(),
        MailboxProtection::CiphertextOnlyMetadataUnencrypted
    );
}

#[test]
fn typed_encrypted_mailbox_bundle_preserves_receipts_and_restores_only_quarantined() {
    use std::collections::BTreeMap;
    use wholepact_storage_security::{
        DatabaseKey, StorageSecurityError, bundle::*, create_encrypted, open_encrypted,
    };
    // This mailbox-only fixture uses explicit synthetic coordination coverage.
    // The actual eight-journal production adapters have a separate engine fixture.
    static COORDINATION: JournalTemplate = JournalTemplate {
        kind: JournalKind::CoordinationAuthority,
        application_id: 0x5359434f,
        schema_version: 1,
        create_sql: "CREATE TABLE synthetic_coordination(id INTEGER PRIMARY KEY, note TEXT NOT NULL);",
    };
    struct SyntheticCoordination(rusqlite::Connection);
    impl JournalAdapter for SyntheticCoordination {
        fn template(&self) -> &'static JournalTemplate {
            &COORDINATION
        }
        fn read_locked(
            &self,
            permit: &BackupReadPermit<'_>,
            visitor: &mut dyn FnMut(&rusqlite::Connection) -> std::result::Result<(), BundleError>,
        ) -> std::result::Result<(), BundleError> {
            permit.check(self)?;
            visitor(&self.0)
        }
    }
    struct SyntheticAuthority {
        sources: Vec<(String, JournalBinding)>,
        root: PathBuf,
    }
    struct SyntheticLease;
    impl BundleLease for SyntheticLease {
        fn check_current(&self) -> std::result::Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-quiescent-mailboxes"
        }
    }
    impl BundleAuthority for SyntheticAuthority {
        fn acquire<'a>(
            &'a self,
            scope: &BundleScope<'_>,
        ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
            if scope.principal_id != "synthetic-admin"
                || scope.profile_id != "synthetic-profile"
                || !scope.archive.starts_with(&self.root)
                || scope
                    .destinations
                    .iter()
                    .any(|p| !p.starts_with(&self.root))
                || scope.wallet_spending_secrets_included
                || (scope.action == BundleAction::Snapshot && scope.sources != self.sources)
            {
                return Err(BundleError::Permission);
            }
            // Fixture has exclusively borrowed journals and no other connections
            // or workers. This is not a production profile-quiescence issuer.
            Ok(Box::new(SyntheticLease))
        }
    }
    let temp = Temp::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            temp.0.join("encrypted-inbox.db"),
            &DatabaseKey::from_bytes([101; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let mut outbox = SqliteOutbox::from_encrypted_connection(
        create_encrypted(
            temp.0.join("encrypted-outbox.db"),
            &DatabaseKey::from_bytes([102; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let sent = enqueue(
        &mut outbox,
        ArtifactKind::Proposal,
        1,
        201,
        b"SYNTHETIC-BUNDLE-PRIVATE-CANARY",
    )
    .unwrap();
    let received = receive(sent.envelope(), ArtifactKind::Proposal, &mut inbox);
    let ticket = inbox
        .domain_import_ticket(&received, "synthetic-processor")
        .unwrap();
    inbox
        .complete_domain_import(
            &ticket,
            DomainImportResult {
                outcome: DomainOutcome::Applied,
                result_digest: "12".repeat(32),
            },
        )
        .unwrap();
    let coordination = create_encrypted(
        temp.0.join("synthetic-coordination.db"),
        &DatabaseKey::from_bytes([106; 32]),
    )
    .unwrap()
    .into_connection();
    coordination.execute_batch(COORDINATION.create_sql).unwrap();
    coordination
        .execute(
            "INSERT INTO synthetic_coordination VALUES(1, 'synthetic fixture only')",
            [],
        )
        .unwrap();
    coordination
        .pragma_update(None, "application_id", COORDINATION.application_id)
        .unwrap();
    coordination
        .pragma_update(None, "user_version", COORDINATION.schema_version)
        .unwrap();
    let coordination = SyntheticCoordination(coordination);
    let inbox_adapter = inbox.backup_adapter().unwrap();
    let outbox_adapter = outbox.backup_adapter().unwrap();
    let sources = [
        RegisteredJournal::new("coordination", &coordination).unwrap(),
        RegisteredJournal::new("inbox", &inbox_adapter).unwrap(),
        RegisteredJournal::new("outbox", &outbox_adapter).unwrap(),
    ];
    let authority = SyntheticAuthority {
        sources: sources
            .iter()
            .map(|s| (s.id().into(), s.binding()))
            .collect(),
        root: temp.0.clone(),
    };
    let coverage = Coverage {
        present: BTreeMap::from([
            (
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            ),
            (JournalKind::TransportInbox, vec!["inbox".into()]),
            (JournalKind::TransportOutbox, vec!["outbox".into()]),
        ]),
        absent: [
            JournalKind::SignerConsentAuthority,
            JournalKind::WalletScan,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::Submission,
        ]
        .into(),
    };
    let archive = temp.0.join("synthetic-profile.backup");
    let archive_key = DatabaseKey::from_bytes([103; 32]);
    let manifest = snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        coverage,
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &authority,
    })
    .unwrap();
    assert_eq!(manifest.components.len(), 3);
    assert_eq!(manifest.components.iter().map(|c| c.rows).sum::<usize>(), 4);
    let inbox_destination = temp.0.join("restored-inbox.db");
    let outbox_destination = temp.0.join("restored-outbox.db");
    let restored_inbox_key = DatabaseKey::from_bytes([104; 32]);
    let restored_outbox_key = DatabaseKey::from_bytes([105; 32]);
    let coordination_destination = temp.0.join("restored-synthetic-coordination.db");
    let restored_coordination_key = DatabaseKey::from_bytes([107; 32]);
    let targets = [
        RestoreTarget {
            component_id: "coordination",
            template: &COORDINATION,
            destination: &coordination_destination,
            key: &restored_coordination_key,
        },
        RestoreTarget {
            component_id: "inbox",
            template: &INBOX_BACKUP_TEMPLATE,
            destination: &inbox_destination,
            key: &restored_inbox_key,
        },
        RestoreTarget {
            component_id: "outbox",
            template: &OUTBOX_BACKUP_TEMPLATE,
            destination: &outbox_destination,
            key: &restored_outbox_key,
        },
    ];
    let restored = test_restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &archive_key,
        targets: &targets,
        authority: &authority,
    })
    .unwrap();
    assert!(restored.integrity_verified && restored.all_components_quarantined);
    assert!(!restored.authorization_allowed && !restored.signer_recovered);
    assert!(matches!(
        open_encrypted(&coordination_destination, &restored_coordination_key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert!(matches!(
        open_encrypted(&inbox_destination, &restored_inbox_key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert!(matches!(
        open_encrypted(&outbox_destination, &restored_outbox_key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert!(
        SqliteReplayLedger::open(temp.0.join("legacy-inbox.db"))
            .unwrap()
            .backup_adapter()
            .is_err()
    );
    assert!(
        SqliteOutbox::open(temp.0.join("legacy-outbox.db"))
            .unwrap()
            .backup_adapter()
            .is_err()
    );
    for path in [&archive, &inbox_destination, &outbox_destination] {
        assert!(
            !std::fs::read(path)
                .unwrap()
                .windows(b"SYNTHETIC-BUNDLE-PRIVATE-CANARY".len())
                .any(|b| b == b"SYNTHETIC-BUNDLE-PRIVATE-CANARY")
        );
    }
}

#[cfg(feature = "offline-admission-export")]
#[test]
fn downgraded_version_with_control_table_is_rejected_without_filtering() {
    let temp = Temp::new();
    drop(temp.inbox());
    let connection = rusqlite::Connection::open(temp.0.join("inbox.sqlite")).unwrap();
    connection.execute_batch("PRAGMA user_version=2;").unwrap();
    drop(connection);
    assert_eq!(
        SqliteReplayLedger::open(temp.0.join("inbox.sqlite")).err(),
        Some(TransportError::UnsupportedVersion)
    );
    let connection = rusqlite::Connection::open(temp.0.join("inbox.sqlite")).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='offline_control_outcomes'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
}

#[cfg(target_os = "linux")]
#[test]
fn encrypted_inbox_identity_pins_live_file_not_same_key_or_plaintext() {
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    let temp = Temp::new();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = DatabaseKey::from_bytes([171; 32]);
    let first = temp.0.join("identity-first.db");
    let second = temp.0.join("identity-second.db");
    let a = SqliteReplayLedger::from_encrypted_connection(create_encrypted(&first, &key).unwrap())
        .unwrap();
    let same = SqliteReplayLedger::from_encrypted_connection(open_encrypted(&first, &key).unwrap())
        .unwrap();
    let other =
        SqliteReplayLedger::from_encrypted_connection(create_encrypted(&second, &key).unwrap())
            .unwrap();
    assert!(a.database_identity().unwrap() == same.database_identity().unwrap());
    assert!(a.database_identity().unwrap() != other.database_identity().unwrap());
    assert!(temp.inbox().database_identity().is_err());
    assert!(open_encrypted(&first, &DatabaseKey::from_bytes([172; 32])).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn encrypted_inbox_identity_refuses_moved_file() {
    use wholepact_storage_security::{DatabaseKey, create_encrypted};
    let temp = Temp::new();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let original = temp.0.join("identity-original.db");
    let moved = temp.0.join("identity-moved.db");
    let inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(&original, &DatabaseKey::from_bytes([173; 32])).unwrap(),
    )
    .unwrap();
    assert!(inbox.database_identity().is_ok());
    std::fs::rename(&original, &moved).unwrap();
    assert!(inbox.database_identity().is_err());
}
