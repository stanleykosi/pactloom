//! Synthetic private-source regressions. No signer, issuer, sockets or proofs.
//! Direct private writer access below exists only in this cfg(test) module.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wholepact-split-source-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn at(n: i64) -> Timestamp {
    Timestamp::from_unix_seconds(1_790_000_000 + n).unwrap()
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
fn prepared(kind: ArtifactKind, field: &str) -> PreparedExport {
    prepare_export(
        ExportRequest {
            context: context(kind),
            order: MessageOrder {
                message_id: format!("{:032x}", 1),
                sequence: 1,
                issued_at: at(0),
                expires_at: at(600),
            },
            purpose: "Synthetic source regression".into(),
            persistence_warning: "Synthetic recipient may retain bytes".into(),
        },
        vec![DisclosureField::new(field, b"public synthetic payload".to_vec()).unwrap()],
        &TransportSecret::from_bytes([11; 32])
            .unwrap()
            .public_key()
            .unwrap(),
        &TransportSecret::from_bytes([22; 32])
            .unwrap()
            .public_key()
            .unwrap(),
        &at(0),
    )
    .unwrap()
}

#[test]
fn canonical_writer_rejects_all_six_raw_minimal_control_conflict_directions() {
    let variants = [
        (
            ArtifactKind::OfflineAuthorityAdmission,
            "offline-authority-admission-v1",
        ),
        (
            ArtifactKind::OfflineMinimalAuthorityAdmission,
            "offline-minimal-admission-v1",
        ),
        (
            ArtifactKind::OfflineAdmissionControl,
            "offline-admission-control-v1",
        ),
    ];
    for (first_index, &(first_kind, first_field)) in variants.iter().enumerate() {
        for (second_index, &(second_kind, second_field)) in variants.iter().enumerate() {
            if first_index == second_index {
                continue;
            }
            let temp = Temp::new();
            let mut outbox = SqliteOutbox::open(temp.0.join("outbox.sqlite")).unwrap();
            let sender = TransportSecret::from_bytes([11; 32]).unwrap();
            let first = prepared(first_kind, first_field);
            let approved = first.preview().digest().unwrap();
            let committed = outbox
                .enqueue_validated(first, &sender, &approved, &at(0))
                .unwrap();
            let original_bytes = committed.envelope().as_bytes().to_vec();
            let second = prepared(second_kind, second_field);
            let second_digest = second.preview().digest().unwrap();
            // Exercises the ACTUAL canonical shared writer, never a copied SELECT.
            assert_eq!(
                outbox
                    .enqueue_validated(second, &sender, &second_digest, &at(0))
                    .err(),
                Some(TransportError::Equivocation)
            );
            let recipient = TransportSecret::from_bytes([22; 32])
                .unwrap()
                .public_key()
                .unwrap();
            let retained = outbox
                .recover_for_recipient(&context(first_kind), &recipient, 1)
                .unwrap()
                .unwrap();
            assert_eq!(retained.envelope().as_bytes(), original_bytes);
            assert_eq!(outbox.next_sequence(&context(first_kind)).unwrap(), 2);
        }
    }
}

#[test]
fn generic_writer_still_rejects_authorization_and_every_offline_kind() {
    for kind in [
        ArtifactKind::Authorization,
        ArtifactKind::OfflineReservationIntent,
        ArtifactKind::OfflineAuthorityAdmission,
        ArtifactKind::OfflineMinimalAuthorityAdmission,
        ArtifactKind::OfflineAdmissionControl,
        ArtifactKind::OfflineAuthorizationReturn,
        ArtifactKind::BornOfflineMinimalAdmissionV1,
        ArtifactKind::BornOfflineIntentV1,
        ArtifactKind::BornOfflineCheckpointOriginV1,
        ArtifactKind::BornOfflineAuthorizationReturnV1,
    ] {
        let temp = Temp::new();
        let mut outbox = SqliteOutbox::open(temp.0.join("outbox.sqlite")).unwrap();
        let value = prepared(kind, "synthetic");
        let approved = value.preview().digest().unwrap();
        assert_eq!(
            outbox
                .enqueue(
                    value,
                    &TransportSecret::from_bytes([11; 32]).unwrap(),
                    &approved,
                    &at(0)
                )
                .err(),
            Some(TransportError::AuthorityUnavailable)
        );
        assert_eq!(outbox.next_sequence(&context(kind)).unwrap(), 1);
    }
}

#[test]
fn journal_context_order_and_kind_rules_match_transport_validation() {
    for kind in [
        ArtifactKind::Invitation,
        ArtifactKind::Authorization,
        ArtifactKind::OfflineReservationIntent,
        ArtifactKind::OfflineAuthorityAdmission,
        ArtifactKind::OfflineMinimalAuthorityAdmission,
        ArtifactKind::OfflineAdmissionControl,
        ArtifactKind::OfflineAuthorizationReturn,
        ArtifactKind::BornOfflineMinimalAdmissionV1,
        ArtifactKind::BornOfflineIntentV1,
        ArtifactKind::BornOfflineCheckpointOriginV1,
        ArtifactKind::BornOfflineAuthorizationReturnV1,
    ] {
        let mut ctx = context(kind);
        assert_eq!(
            stream_digest(&ctx).unwrap(),
            crate::replay::stream_digest(&ctx).unwrap()
        );
        assert_eq!(
            requires_qualified_export(kind),
            kind.requires_qualified_export()
        );
        assert_eq!(immutable_kind(kind), kind.immutable_slot());
        for bad in ["", "space not allowed", &"x".repeat(129)] {
            ctx.agreement_id = bad.into();
            assert_eq!(validate_context(&ctx), ctx.validate());
        }
        let value = prepared(kind, "synthetic");
        let mut order = value.preview().order.clone();
        for n in [0, 1, 599, 600, 601] {
            assert_eq!(validate_order(&order, &at(n)), order.validate(&at(n)));
        }
        order.sequence = 0;
        assert_eq!(validate_order(&order, &at(0)), order.validate(&at(0)));
    }
}

#[test]
fn pre_split_legacy_schema_and_ledger_hash_goldens_are_unchanged() {
    let ctx = context(ArtifactKind::Authorization);
    let stream = stream_digest(&ctx).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(OUTBOX_SCHEMA.as_bytes())),
        "a9ae22db46874e3235d53d80f487cd287c78d15a5a219820fb7da922d97a7851"
    );
    assert_eq!(
        stream,
        "c781728da159091ba9a2dd405a7520aba912300d08a0c21be4859c57b949b9f7"
    );
    assert_eq!(
        context_digest(&ctx).unwrap(),
        "8fe9a62cf546d03ef7dc66109f02bf89b3e0f5b516d54205d8e7d1f7d3e3fbd0"
    );
    assert_eq!(
        message_digest(&format!("{:032x}", 1)),
        "b5845e14bc0e9cbb51d7aadbb0b2fdeaadd648aeb33865d3ff6507f9c294943d"
    );
    assert_eq!(
        immutable_slot(&ctx, &stream).unwrap().unwrap(),
        "33f880748d5db950863f703de9de913fe03d11daad395c2c7424008036e31a3f"
    );
}

// Fresh material retained only for the duration of each named-export test.
fn named_random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}
fn named_prepared(sender: &TransportSecret, recipient: &TransportPublicKey) -> PreparedExport {
    prepare_export(
        ExportRequest {
            context: context(ArtifactKind::NamedVerifierAssertion),
            order: MessageOrder {
                message_id: format!("{:032x}", 1),
                sequence: 1,
                issued_at: at(0),
                expires_at: at(600),
            },
            purpose: "Synthetic source regression".into(),
            persistence_warning: "Synthetic recipient may retain bytes".into(),
        },
        vec![
            DisclosureField::new(
                "named-verifier-assertion-v1",
                b"public synthetic payload".to_vec(),
            )
            .unwrap(),
        ],
        &sender.public_key().unwrap(),
        recipient,
        &at(0),
    )
    .unwrap()
}

#[test]
fn named_assertion_exact_message_recovery_survives_reopen_without_reseal() {
    // Ephemeral OS-random transport encryption only: no wallet,
    // signature, proof, network, account enrollment or native authority.
    let temp = Temp::new();
    let path = temp.0.join("assertion.sqlite");
    let sender = TransportSecret::from_bytes(named_random_bytes()).unwrap();
    let recipient = TransportSecret::from_bytes(named_random_bytes())
        .unwrap()
        .public_key()
        .unwrap();
    let sender_public = sender.public_key().unwrap();
    let context = context(ArtifactKind::NamedVerifierAssertion);
    let original = named_prepared(&sender, &recipient);
    let payload = original.preview().payload_digest.clone();
    let message = original.preview().order.message_id.clone();
    let preview = original.preview().digest().unwrap();
    let mut outbox = SqliteOutbox::open(&path).unwrap();
    assert!(
        outbox
            .recover_message_for_recipient(&context, &recipient, &message, &payload, &sender_public)
            .unwrap()
            .is_none()
    );
    assert_eq!(outbox.next_sequence(&context).unwrap(), 1);
    let committed = outbox.enqueue(original, &sender, &preview, &at(0)).unwrap();
    let exact = committed.envelope().as_bytes().to_vec();
    drop(outbox);
    let outbox = SqliteOutbox::open(&path).unwrap();
    let recovered = outbox
        .recover_message_for_recipient(&context, &recipient, &message, &payload, &sender_public)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.envelope().as_bytes(), exact);
    assert!(!recovered.authorization_allowed());
    assert!(!recovered.is_currently_valid(&at(601)));
    assert_eq!(outbox.next_sequence(&context).unwrap(), 2);
    let mut changed = context.clone();
    changed.proposal_revision += 1;
    assert!(
        outbox
            .recover_message_for_recipient(&changed, &recipient, &message, &payload, &sender_public)
            .is_err()
    );
    let other = TransportSecret::from_bytes(named_random_bytes())
        .unwrap()
        .public_key()
        .unwrap();
    assert!(
        outbox
            .recover_message_for_recipient(&context, &other, &message, &payload, &sender_public)
            .is_err()
    );
    assert!(
        outbox
            .recover_message_for_recipient(
                &context,
                &recipient,
                &message,
                &"00".repeat(32),
                &sender_public
            )
            .is_err()
    );
    assert!(
        outbox
            .recover_message_for_recipient(&context, &recipient, &message, &payload, &other)
            .is_err()
    );
    assert_eq!(outbox.next_sequence(&context).unwrap(), 2);
}

#[test]
fn named_assertion_kind_never_confers_financial_export_authority() {
    assert_eq!(
        serde_json::to_string(&ArtifactKind::NamedVerifierAssertion).unwrap(),
        "\"named_verifier_assertion\""
    );
    assert!(!ArtifactKind::NamedVerifierAssertion.requires_qualified_export());
    assert!(ArtifactKind::NamedVerifierAssertion.immutable_slot());
    for kind in [
        ArtifactKind::Authorization,
        ArtifactKind::OfflineReservationIntent,
        ArtifactKind::OfflineAuthorityAdmission,
        ArtifactKind::OfflineMinimalAuthorityAdmission,
        ArtifactKind::OfflineAuthorizationReturn,
        ArtifactKind::BornOfflineMinimalAdmissionV1,
        ArtifactKind::BornOfflineIntentV1,
        ArtifactKind::BornOfflineCheckpointOriginV1,
        ArtifactKind::BornOfflineAuthorizationReturnV1,
    ] {
        assert!(kind.requires_qualified_export());
    }
    let sender = TransportSecret::from_bytes(named_random_bytes()).unwrap();
    let recipient = TransportSecret::from_bytes(named_random_bytes())
        .unwrap()
        .public_key()
        .unwrap();
    let fields = vec![
        DisclosureField::new(
            "named-verifier-assertion-v1",
            b"public synthetic payload".to_vec(),
        )
        .unwrap(),
    ];
    assert_eq!(
        crate::disclosure_payload_digest(&fields).unwrap(),
        named_prepared(&sender, &recipient).preview().payload_digest
    );
    assert!(
        DisclosureField::new(
            "named-verifier-assertion-v1",
            vec![0; crate::MAX_PAYLOAD_BYTES + 1]
        )
        .is_err()
    );
}

#[test]
fn export_setup_accepts_only_empty_authenticated_original_mailbox() {
    // Each test retains fresh OS-random keys only within this temporary fixture.
    let temp = Temp::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = temp.0.join("outbox.sqlite");
    let key = wholepact_storage_security::DatabaseKey::from_bytes(named_random_bytes());
    let connection = wholepact_storage_security::create_encrypted(&path, &key).unwrap();
    let mut outbox = SqliteOutbox::from_encrypted_connection(connection).unwrap();
    outbox.require_empty_for_initial_setup().unwrap();
    let sender = TransportSecret::from_bytes(named_random_bytes()).unwrap();
    let recipient = TransportSecret::from_bytes(named_random_bytes())
        .unwrap()
        .public_key()
        .unwrap();
    let p = named_prepared(&sender, &recipient);
    let d = p.preview().digest().unwrap();
    outbox.enqueue(p, &sender, &d, &at(0)).unwrap();
    assert!(outbox.require_empty_for_initial_setup().is_err());
    drop(outbox);
    let connection = wholepact_storage_security::open_encrypted(&path, &key).unwrap();
    let outbox = SqliteOutbox::from_encrypted_connection(connection).unwrap();
    assert!(outbox.require_empty_for_initial_setup().is_err());
}
