//! Ephemeral in-memory codec qualification only; no persistent keys or sockets.
use super::*;
fn key() -> TransportSecret {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).unwrap();
    TransportSecret::from_bytes(*bytes).unwrap()
}
fn prepared(
    kind: ArtifactKind,
    sender: &TransportSecret,
    recipient: &TransportSecret,
) -> PreparedExport {
    let now = Timestamp::from_unix_seconds(1000).unwrap();
    prepare_export(
        ExportRequest {
            context: MessageContext {
                network_profile_id: "synthetic-testnet".into(),
                agreement_id: "agreement".into(),
                proposal_id: "proposal".into(),
                proposal_revision: 1,
                sender_id: "sender".into(),
                recipient_id: "recipient".into(),
                artifact_kind: kind,
            },
            order: MessageOrder {
                message_id: random_message_id().unwrap(),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: Timestamp::from_unix_seconds(1100).unwrap(),
            },
            purpose: "synthetic exact metadata".into(),
            persistence_warning: "recipient retains exact bytes".into(),
        },
        vec![DisclosureField::new("field", b"synthetic public payload".to_vec()).unwrap()],
        &sender.public_key().unwrap(),
        &recipient.public_key().unwrap(),
        &now,
    )
    .unwrap()
}
#[test]
fn retained_metadata_matches_actual_authenticated_plaintext_without_receipt_factory() {
    let sender = key();
    let recipient = key();
    let p = prepared(ArtifactKind::Contribution, &sender, &recipient);
    let context = p.preview().context.clone();
    let approved = p.preview().digest().unwrap();
    let metadata = p.retained_metadata().unwrap();
    // Independently spell the previous serialization in this regression only.
    let previous = ProtectedMessage {
        preview: p.preview.clone(),
        approved_preview_digest: approved.clone(),
        fields: encode_fields(&p.fields),
    };
    let previous_bytes = Zeroizing::new(encode(&previous).unwrap());
    assert_eq!(
        metadata.content_digest,
        digest(b"wholepact.authenticated-message.v1\0", &previous_bytes)
    );
    let now = Timestamp::from_unix_seconds(1000).unwrap();
    let envelope = p.seal(&sender, &approved, &now).unwrap();
    let (_, receipt) = authenticate(
        &envelope,
        &recipient,
        &sender.public_key().unwrap(),
        &context,
        Some(&now),
    )
    .unwrap();
    assert_eq!(
        metadata.immutable_slot_digest.as_deref(),
        receipt.immutable_slot_digest()
    );
    assert_eq!(metadata.stream_digest, receipt.stream_digest());
    assert_eq!(metadata.message_id_digest, receipt.message_id_digest());
    assert_eq!(metadata.content_digest, receipt.content_digest());
    assert_eq!(metadata.payload_digest, receipt.payload_digest());
}
#[test]
fn retained_metadata_does_not_enable_any_generic_offline_sealer() {
    let sender = key();
    let recipient = key();
    let now = Timestamp::from_unix_seconds(1000).unwrap();
    for kind in [
        ArtifactKind::OfflineReservationIntent,
        ArtifactKind::OfflineAuthorityAdmission,
        ArtifactKind::OfflineAdmissionControl,
        ArtifactKind::OfflineMinimalAuthorityAdmission,
        ArtifactKind::OfflineAuthorizationReturn,
        ArtifactKind::BornOfflineMinimalAdmissionV1,
        ArtifactKind::BornOfflineIntentV1,
        ArtifactKind::BornOfflineCheckpointOriginV1,
        ArtifactKind::BornOfflineAuthorizationReturnV1,
    ] {
        let p = prepared(kind, &sender, &recipient);
        let approved = p.preview().digest().unwrap();
        let metadata = p.retained_metadata().unwrap();
        assert_eq!(metadata.content_digest.len(), 64);
        assert!(matches!(
            p.seal(&sender, &approved, &now),
            Err(TransportError::AuthorityUnavailable)
        ));
    }
}

#[test]
fn retained_metadata_tracks_field_order_and_never_substitutes_approval() {
    let sender = key();
    let recipient = key();
    let now = Timestamp::from_unix_seconds(1000).unwrap();
    let mut p = prepared(ArtifactKind::Contribution, &sender, &recipient);
    let first = p.retained_metadata().unwrap();
    p.preview.order.sequence = 2;
    let changed_order = p.retained_metadata().unwrap();
    assert_ne!(first.content_digest, changed_order.content_digest);
    assert_eq!(first.payload_digest, changed_order.payload_digest);
    assert!(matches!(
        p.seal(&sender, &"00".repeat(32), &now),
        Err(TransportError::DisclosureDenied)
    ));

    let mut p = prepared(ArtifactKind::Contribution, &sender, &recipient);
    let original = p.retained_metadata().unwrap();
    // Deliberate internal fixture mutation; no production mutation API exists.
    p.fields[0] = DisclosureField::new("field", b"changed unapproved payload".to_vec()).unwrap();
    assert_ne!(
        original.content_digest,
        p.retained_metadata().unwrap().content_digest
    );
    let context = p.preview().context.clone();
    let approved = p.preview().digest().unwrap();
    let envelope = p.seal(&sender, &approved, &now).unwrap();
    assert!(
        authenticate(
            &envelope,
            &recipient,
            &sender.public_key().unwrap(),
            &context,
            Some(&now)
        )
        .is_err()
    );
}
