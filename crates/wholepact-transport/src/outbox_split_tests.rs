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
