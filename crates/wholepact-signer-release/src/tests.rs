//! Synthetic source-only tests. A private journal seam seeds historical bytes;
//! it is NOT a fabricated signer lease and cannot qualify actual authorization.
use super::*;
use crate::AUTHORIZATION_FIELD;
use std::os::unix::fs::PermissionsExt;
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
use wholepact_transport::*;

struct Fixture {
    dir: tempfile::TempDir,
    key: DatabaseKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            dir,
            key: DatabaseKey::from_bytes([0x51; 32]),
        }
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }
    fn outbox(&self, name: &str) -> SqliteOutbox {
        SqliteOutbox::from_encrypted_connection(
            create_encrypted(self.path(name), &self.key).unwrap(),
        )
        .unwrap()
    }
    fn adapter(&self, outbox: &SqliteOutbox, name: &str) -> AuthorizationOutbox {
        AuthorizationOutbox::from_encrypted_connection(
            outbox,
            open_encrypted(self.path(name), &self.key).unwrap(),
        )
        .unwrap()
    }
}
fn at(n: i64) -> Timestamp {
    Timestamp::from_unix_seconds(1_790_000_000 + n).unwrap()
}
fn context() -> MessageContext {
    MessageContext {
        network_profile_id: "testnet-synthetic-unqualified".into(),
        agreement_id: "private-synthetic-agreement".into(),
        proposal_id: "proposal-one".into(),
        proposal_revision: 1,
        sender_id: "organizer".into(),
        recipient_id: "participant".into(),
        artifact_kind: ArtifactKind::Authorization,
    }
}
fn prepared(changed: bool) -> PreparedExport {
    prepare_export(
        ExportRequest {
            context: context(),
            order: MessageOrder {
                message_id: format!("{:032x}", 1),
                sequence: 1,
                issued_at: at(0),
                expires_at: at(600),
            },
            purpose: if changed {
                "changed purpose"
            } else {
                "original synthetic purpose"
            }
            .into(),
            persistence_warning: "Recipient may retain synthetic bytes".into(),
        },
        vec![
            DisclosureField::new(
                AUTHORIZATION_FIELD,
                b"public synthetic authorization fixture".to_vec(),
            )
            .unwrap(),
        ],
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
fn constructor_and_use_reject_a_different_authenticated_mailbox() {
    let f = Fixture::new();
    let original = f.outbox("original.sqlite");
    let other = f.outbox("other.sqlite");
    let second = open_encrypted(f.path("other.sqlite"), &f.key).unwrap();
    assert!(matches!(
        AuthorizationOutbox::from_encrypted_connection(&original, second),
        Err(TransportError::WrongContext)
    ));
    let adapter = f.adapter(&original, "original.sqlite");
    adapter.check_binding(&original).unwrap();
    assert_eq!(
        adapter.check_binding(&other),
        Err(TransportError::WrongContext)
    );
    assert_eq!(original.next_sequence(&context()).unwrap(), 1);
    assert_eq!(other.next_sequence(&context()).unwrap(), 1);
}
#[test]
fn wrong_database_key_never_creates_an_adapter_or_reseals_history() {
    let f = Fixture::new();
    let original = f.outbox("original.sqlite");
    assert!(
        open_encrypted(
            f.path("original.sqlite"),
            &DatabaseKey::from_bytes([0x52; 32])
        )
        .is_err()
    );
    assert_eq!(original.next_sequence(&context()).unwrap(), 1);
    f.adapter(&original, "original.sqlite")
        .check_binding(&original)
        .unwrap();
}
#[test]
fn adapter_cannot_bind_plaintext_or_replacement_database() {
    let f = Fixture::new();
    let plaintext = SqliteOutbox::open(f.path("plaintext.sqlite")).unwrap();
    let original = f.outbox("original.sqlite");
    let second = open_encrypted(f.path("original.sqlite"), &f.key).unwrap();
    assert!(matches!(
        AuthorizationOutbox::from_encrypted_connection(&plaintext, second),
        Err(TransportError::AuthorityUnavailable)
    ));
    let adapter = f.adapter(&original, "original.sqlite");
    std::fs::rename(f.path("original.sqlite"), f.path("moved.sqlite")).unwrap();
    std::fs::write(f.path("original.sqlite"), [0u8; 4096]).unwrap();
    std::fs::set_permissions(
        f.path("original.sqlite"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(adapter.check_binding(&original).is_err());
}
#[test]
fn shared_private_writer_and_original_reader_preserve_exact_old_ciphertext() {
    let f = Fixture::new();
    let original = f.outbox("original.sqlite");
    let mut adapter = f.adapter(&original, "original.sqlite");
    let sender = TransportSecret::from_bytes([11; 32]).unwrap();
    let recipient = TransportSecret::from_bytes([22; 32])
        .unwrap()
        .public_key()
        .unwrap();
    // Private test seam only: does not construct or claim OriginalHistoryLease.
    let p = prepared(false);
    let preview = p.preview().digest().unwrap();
    let stored = adapter
        .journal
        .enqueue_validated(p, &sender, &preview, &at(0))
        .unwrap();
    let bytes = stored.envelope().as_bytes().to_vec();
    let old = original
        .recover_for_recipient(&context(), &recipient, 1)
        .unwrap()
        .unwrap();
    assert_eq!(old.envelope().as_bytes(), bytes);
    assert_eq!(old.preview_digest(), preview);
    assert!(old.is_currently_valid(&at(0)));
    assert!(!old.is_currently_valid(&at(600)));
    let repeated = adapter
        .journal
        .enqueue_validated(prepared(false), &sender, &preview, &at(1))
        .unwrap();
    assert_eq!(repeated.envelope().as_bytes(), bytes);
    let different = prepared(true);
    let different_digest = different.preview().digest().unwrap();
    assert_eq!(
        adapter
            .journal
            .enqueue_validated(different, &sender, &different_digest, &at(1))
            .err(),
        Some(TransportError::Equivocation)
    );
    let retained = original
        .recover_for_recipient(&context(), &recipient, 1)
        .unwrap()
        .unwrap();
    assert_eq!(retained.envelope().as_bytes(), bytes);
    assert_eq!(original.next_sequence(&context()).unwrap(), 2);
    let wrong = TransportSecret::from_bytes([23; 32])
        .unwrap()
        .public_key()
        .unwrap();
    assert!(
        original
            .recover_for_recipient(&context(), &wrong, 1)
            .unwrap()
            .is_none()
    );
    // Ordinary recovery and the unchanged outbox backup template see the same
    // persisted row; no second component or fresh ciphertext is created.
    assert_eq!(
        wholepact_transport::OUTBOX_BACKUP_TEMPLATE.schema_version,
        1
    );
    drop(adapter);
    drop(original);
    let reopened = SqliteOutbox::from_encrypted_connection(
        open_encrypted(f.path("original.sqlite"), &f.key).unwrap(),
    )
    .unwrap();
    let retained = reopened
        .recover_for_recipient(&context(), &recipient, 1)
        .unwrap()
        .unwrap();
    assert_eq!(retained.envelope().as_bytes(), bytes);
    assert!(!retained.is_currently_valid(&at(600)));
    // Quiescent synthetic encrypted backup includes the adapter-written row under
    // the unchanged ordinary outbox schema, without resealing its HPKE bytes.
    let backup_key = DatabaseKey::from_bytes([0x53; 32]);
    let source = open_encrypted(f.path("original.sqlite"), &f.key).unwrap();
    wholepact_storage_security::backup_encrypted(&source, f.path("snapshot.sqlite"), &backup_key)
        .unwrap();
    drop(source);
    let snapshot = SqliteOutbox::from_encrypted_connection(
        open_encrypted(f.path("snapshot.sqlite"), &backup_key).unwrap(),
    )
    .unwrap();
    let old = snapshot
        .recover_for_recipient(&context(), &recipient, 1)
        .unwrap()
        .unwrap();
    assert_eq!(old.envelope().as_bytes(), bytes);
    assert!(!old.is_currently_valid(&at(600)));
    // Readable backup history is not an alternate live retry mailbox.
    let snapshot_connection = open_encrypted(f.path("snapshot.sqlite"), &backup_key).unwrap();
    assert!(matches!(
        AuthorizationOutbox::from_encrypted_connection(&reopened, snapshot_connection),
        Err(TransportError::WrongContext)
    ));
}
#[test]
fn private_adapter_sealer_has_no_offline_qualified_escape() {
    let f = Fixture::new();
    let original = f.outbox("original.sqlite");
    let mut adapter = f.adapter(&original, "original.sqlite");
    let sender = TransportSecret::from_bytes([11; 32]).unwrap();
    let recipient = TransportSecret::from_bytes([22; 32])
        .unwrap()
        .public_key()
        .unwrap();
    for kind in [
        ArtifactKind::OfflineReservationIntent,
        ArtifactKind::OfflineAuthorityAdmission,
        ArtifactKind::OfflineMinimalAuthorityAdmission,
        ArtifactKind::OfflineAdmissionControl,
        ArtifactKind::OfflineAuthorizationReturn,
    ] {
        let mut ctx = context();
        ctx.artifact_kind = kind;
        let p = prepare_export(
            ExportRequest {
                context: ctx,
                order: MessageOrder {
                    message_id: format!("{:032x}", 1),
                    sequence: 1,
                    issued_at: at(0),
                    expires_at: at(600),
                },
                purpose: "synthetic unsupported artifact".into(),
                persistence_warning: "Synthetic only".into(),
            },
            vec![DisclosureField::new("synthetic", vec![1]).unwrap()],
            &sender.public_key().unwrap(),
            &recipient,
            &at(0),
        )
        .unwrap();
        let digest = p.preview().digest().unwrap();
        assert_eq!(
            adapter
                .journal
                .enqueue_validated(p, &sender, &digest, &at(0))
                .err(),
            Some(TransportError::AuthorityUnavailable)
        );
        assert_eq!(original.next_sequence(&context()).unwrap(), 1);
    }
}

#[test]
fn minimal_transport_and_original_signer_history_have_identical_canonical_statements() {
    use wholepact_signer::consent_journal::OfflineMinimalAdmissionHistoryStatement;
    use wholepact_transport::OfflineMinimalAdmission;
    let value = serde_json::json!({
        "schema_version":1,"witness_id":"synthetic-witness",
        "witness_transport_key_digest":"11".repeat(32),"witness_policy_digest":"22".repeat(32),
        "operation_id":"synthetic-operation","authorization_id":"synthetic-authorization",
        "request_digest":"33".repeat(32),"intent_digest":"44".repeat(32),"terms_digest":"55".repeat(32),
        "review_package_digest":"66".repeat(32),"original_admission_digest":"77".repeat(32),
        "original_export_plan_digest":"88".repeat(32),"committed_head":{"sequence":7,"digest":"99".repeat(32)},
        "reserved_at_ms":1790000000000u64,"admission_expires_at_ms":1790000600000u64
    });
    let transport: OfflineMinimalAdmission = serde_json::from_value(value.clone()).unwrap();
    let signer: OfflineMinimalAdmissionHistoryStatement = serde_json::from_value(value).unwrap();
    assert_eq!(
        serde_json::to_vec(&transport).unwrap(),
        serde_json::to_vec(&signer).unwrap()
    );
    assert_eq!(
        transport.statement_digest().unwrap(),
        signer.statement_digest().unwrap()
    );
    assert_eq!(
        transport.statement_digest().unwrap(),
        MINIMAL_STATEMENT_GOLDEN
    );
    let mut altered = signer;
    altered.committed_head.sequence += 1;
    assert_ne!(
        transport.statement_digest().unwrap(),
        altered.statement_digest().unwrap()
    );
}

const MINIMAL_STATEMENT_GOLDEN: &str =
    "ce16c7ada838344b5e5a66f491b02879a720f7f529fcd8b2ae0e92d8c389530e";
