//! Bounded genuine SQLCipher/transport fixture. OS-random ephemeral test-only
//! storage/transport/password material is retained within each test and never
//! persisted as keys. No wallet, verifier signing identity, native decision,
//! network, witness, signature issuance or live profile is constructed.
//! This tests storage and paired-file helpers, not a genuine native ceremony.
use super::*;
use rusqlite::Connection;
use std::{collections::BTreeMap, sync::Mutex};
use wholepact_storage_security::{
    create_encrypted, open_encrypted, open_encrypted_quiescent, open_encrypted_read_snapshot,
    EncryptedConnection, StorageSecurityError,
};
use wholepact_transport::{
    open_envelope, prepare_delivery_acknowledgment, prepare_export, ArtifactKind, DeliveryStatus,
    DisclosureField, ExportRequest, MessageContext, MessageOrder, OutboxArtifact, SqliteOutbox,
    SqliteReplayLedger, Timestamp, TransportSecret,
};

const PRINCIPAL: &str = "synthetic-storage-qualification";
// Each test owns one ephemeral context. Reuse within that test preserves exact
// source identity, receipt/replay authentication and restore-key continuity.
// Secret material is OS-random, zeroized on drop, and never logged or exported.
struct EphemeralKeys {
    archive: Zeroizing<[u8; 32]>,
    outbox: DatabaseKey,
    restore: DatabaseKey,
    recipient_ledger: DatabaseKey,
    sender_ledger: DatabaseKey,
    coordination: DatabaseKey,
    wrong_archive: DatabaseKey,
    sender: TransportSecret,
    recipient: TransportSecret,
    password: Zeroizing<[u8; 32]>,
    wrong_password: Zeroizing<[u8; 32]>,
}
fn ephemeral_bytes() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0; 32]);
    loop {
        getrandom::fill(&mut *bytes).expect("OS randomness for isolated fixture");
        if *bytes != [0; 32] {
            return bytes;
        }
    }
}
fn distinct_ephemeral_bytes(original: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    loop {
        let bytes = ephemeral_bytes();
        if &*bytes != original {
            return bytes;
        }
    }
}
impl EphemeralKeys {
    fn new() -> Self {
        let archive = ephemeral_bytes();
        let wrong_archive = DatabaseKey::from_bytes(*distinct_ephemeral_bytes(&archive));
        let password = ephemeral_bytes();
        let wrong_password = distinct_ephemeral_bytes(&password);
        Self {
            archive,
            outbox: DatabaseKey::from_bytes(*ephemeral_bytes()),
            restore: DatabaseKey::from_bytes(*ephemeral_bytes()),
            recipient_ledger: DatabaseKey::from_bytes(*ephemeral_bytes()),
            sender_ledger: DatabaseKey::from_bytes(*ephemeral_bytes()),
            coordination: DatabaseKey::from_bytes(*ephemeral_bytes()),
            wrong_archive,
            sender: TransportSecret::from_bytes(*ephemeral_bytes()).unwrap(),
            recipient: TransportSecret::from_bytes(*ephemeral_bytes()).unwrap(),
            password,
            wrong_password,
        }
    }
    fn archive_key(&self) -> DatabaseKey {
        DatabaseKey::from_bytes(*self.archive)
    }
}

/// Test-only BundleAuthority, never a NativeAuthority/NativeDecision. Each scope
/// is exact and sources are real registered adapters. The test owns every
/// connection and the actual private directory lock; no independent writers run.
struct SyntheticAuthority {
    profile: String,
    archive: PathBuf,
    destinations: Vec<PathBuf>,
    sources: Vec<(String, JournalBinding)>,
    coverage: Coverage,
    action: BundleAction,
    checkpoint: String,
}
struct SyntheticLease<'a>(&'a str);
impl BundleLease for SyntheticLease<'_> {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        self.0
    }
}
impl BundleAuthority for SyntheticAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != PRINCIPAL
            || scope.profile_id != self.profile
            || scope.archive != self.archive
            || scope.destinations != self.destinations
            || scope.sources != self.sources
            || scope.coverage != &self.coverage
            || scope.action != self.action
            || scope.wallet_spending_secrets_included
            || !scope.private_viewing_witness_and_correlation_data_may_be_included
            || scope.retention != "local-only; retain until deliberately removed"
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(SyntheticLease(&self.checkpoint)))
    }
}
fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix_seconds(1_790_000_000 + seconds).unwrap()
}
fn context() -> MessageContext {
    MessageContext {
        network_profile_id: "testnet-public-synthetic-unqualified".into(),
        agreement_id: "public-synthetic-agreement".into(),
        proposal_id: "public-proposal".into(),
        proposal_revision: 1,
        sender_id: "public-synthetic-sender".into(),
        recipient_id: "public-synthetic-recipient".into(),
        artifact_kind: ArtifactKind::Invitation,
    }
}
fn request(context: &MessageContext, sequence: u64) -> ExportRequest {
    ExportRequest {
        context: context.clone(),
        order: MessageOrder {
            message_id: format!("{sequence:032x}"),
            sequence,
            issued_at: at(0),
            expires_at: at(600),
        },
        purpose: "Public synthetic storage-only qualification".into(),
        persistence_warning: "Public synthetic recipient copies persist".into(),
    }
}
fn fixture_directory() -> (tempfile::TempDir, PrivateDirectory) {
    let temp = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::create(&temp.path().join("synthetic-storage-only")).unwrap();
    (temp, directory)
}
fn populated_outbox(
    directory: &PrivateDirectory,
    keys: &EphemeralKeys,
) -> (SqliteOutbox, Vec<OutboxArtifact>) {
    let mut outbox = SqliteOutbox::from_encrypted_connection(
        create_encrypted(directory.root().join(OUTBOX), &keys.outbox).unwrap(),
    )
    .unwrap();
    let sender = &keys.sender;
    let recipient = &keys.recipient;
    let ctx = context();
    let mut committed = Vec::new();
    for sequence in 1..=2 {
        let prepared = prepare_export(
            request(&ctx, sequence),
            vec![DisclosureField::new(
                "public-synthetic-message",
                format!("public payload {sequence}").into_bytes(),
            )
            .unwrap()],
            &sender.public_key().unwrap(),
            &recipient.public_key().unwrap(),
            &at(0),
        )
        .unwrap();
        let preview = prepared.preview().digest().unwrap();
        committed.push(outbox.enqueue(prepared, sender, &preview, &at(0)).unwrap());
    }
    assert_eq!(outbox.next_sequence(&ctx).unwrap(), 3);
    // Record a real authenticated recipient receipt for the first exact
    // ciphertext. No direct SQL changes fabricate an acknowledgment.
    let mut inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            directory.root().join("synthetic-recipient.sqlite"),
            &keys.recipient_ledger,
        )
        .unwrap(),
    )
    .unwrap();
    let received = open_envelope(
        committed[0].envelope(),
        recipient,
        &sender.public_key().unwrap(),
        &ctx,
        &at(1),
        &mut inbox,
    )
    .unwrap();
    let mut reverse = ctx.clone();
    std::mem::swap(&mut reverse.sender_id, &mut reverse.recipient_id);
    reverse.artifact_kind = ArtifactKind::DeliveryAcknowledgment;
    let acknowledgment = prepare_delivery_acknowledgment(
        &received,
        request(&reverse, 1),
        &recipient.public_key().unwrap(),
        &sender.public_key().unwrap(),
        &at(1),
    )
    .unwrap();
    let preview = acknowledgment.preview().digest().unwrap();
    let sealed = acknowledgment.seal(recipient, &preview, &at(1)).unwrap();
    let mut sender_inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            directory.root().join("synthetic-sender.sqlite"),
            &keys.sender_ledger,
        )
        .unwrap(),
    )
    .unwrap();
    let received_ack = open_envelope(
        &sealed,
        sender,
        &recipient.public_key().unwrap(),
        &reverse,
        &at(2),
        &mut sender_inbox,
    )
    .unwrap();
    assert_eq!(
        outbox.record_acknowledgment(&received_ack).unwrap(),
        DeliveryStatus::RecipientReceiptRecorded
    );
    (outbox, committed)
}
fn source_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .filter_map(|suffix| {
            let name = format!("{}{suffix}", path.display());
            match std::fs::read(&name) {
                Ok(bytes) => Some((suffix.into(), bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("synthetic file-set inspection failed: {error}"),
            }
        })
        .collect()
}
fn durable_source_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    // The genuine adapter reads its already-open source connection. SQLite may
    // update transient SHM read marks; this is not a source-preserving history
    // reader claim. Durable main/WAL/rollback bytes and logical rows must remain.
    let mut files = source_files(path);
    files.remove("-shm");
    files
}
fn snapshot_outbox(
    outbox: &mut SqliteOutbox,
    archive: &Path,
    profile_id: &str,
    checkpoint: &str,
    keys: &EphemeralKeys,
) -> BundleManifest {
    let adapter = outbox.backup_adapter().unwrap();
    let sources = [RegisteredJournal::new(COMPONENT, &adapter).unwrap()];
    let authority = SyntheticAuthority {
        profile: profile_id.into(),
        archive: archive.into(),
        destinations: vec![],
        sources: sources
            .iter()
            .map(|s| (s.id().into(), s.binding()))
            .collect(),
        coverage: named_verifier_transport_coverage(),
        action: BundleAction::Snapshot,
        checkpoint: checkpoint.into(),
    };
    snapshot_named_verifier_transport(SnapshotRequest {
        principal_id: PRINCIPAL,
        profile_id,
        coverage: authority.coverage.clone(),
        sources: &sources,
        destination: archive,
        key: &keys.archive_key(),
        authority: &authority,
    })
    .unwrap()
}
fn restore_outbox(
    archive: &Path,
    destination: &Path,
    manifest: &BundleManifest,
    keys: &EphemeralKeys,
) -> BundleRestoreReport {
    let targets = [RestoreTarget {
        component_id: COMPONENT,
        template: &OUTBOX_BACKUP_TEMPLATE,
        destination,
        key: &keys.restore,
    }];
    let authority = SyntheticAuthority {
        profile: manifest.profile_id.clone(),
        archive: archive.into(),
        destinations: vec![destination.into()],
        sources: vec![],
        coverage: named_verifier_transport_coverage(),
        action: BundleAction::Restore,
        checkpoint: manifest.checkpoint_id.clone(),
    };
    restore_named_verifier_transport(RestoreRequest {
        principal_id: PRINCIPAL,
        profile_id: &manifest.profile_id,
        archive,
        key: &keys.archive_key(),
        targets: &targets,
        authority: &authority,
    })
    .unwrap()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedRow {
    rowid: Option<i64>,
    cells: Vec<CapturedCell>,
}
#[derive(Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum CapturedCell {
    Null,
    Integer(i64),
    Real(u64),
    Text(String),
    Blob(Vec<u8>),
}
impl CapturedCell {
    fn integer(&self) -> i64 {
        match self {
            Self::Integer(value) => *value,
            Self::Real(bits) => panic!("unexpected real archive cell bits {bits}"),
            _ => panic!("expected integer archive cell"),
        }
    }
    fn blob(&self) -> &[u8] {
        match self {
            Self::Blob(value) => value,
            _ => panic!("expected blob archive cell"),
        }
    }
    fn text(&self) -> &str {
        match self {
            Self::Text(value) => value,
            _ => panic!("expected text archive cell"),
        }
    }
}

#[test]
fn named_verifier_encrypted_archive_roundtrip_preserves_exact_ciphertext_sequences_receipt_and_quarantine(
) {
    let keys = EphemeralKeys::new();
    let (_temp, directory) = fixture_directory();
    let (mut outbox, original) = populated_outbox(&directory, &keys);
    let original_path = directory.root().join(OUTBOX);
    let source_before = durable_source_files(&original_path);
    let archive = directory.root().join("transport-only.sqlite");
    let manifest = snapshot_outbox(
        &mut outbox,
        &archive,
        "synthetic-public-profile",
        "synthetic-original-checkpoint",
        &keys,
    );
    assert_eq!(manifest.format_version, 2);
    assert_eq!(manifest.components.len(), 1);
    assert_eq!(manifest.components[0].rows, 2);
    assert_eq!(manifest.components[0].kind, JournalKind::TransportOutbox);
    assert!(!manifest.writer_freshness_established && !manifest.wallet_spending_secrets_included);
    assert_eq!(durable_source_files(&original_path), source_before);
    let key = keys.archive_key();
    assert_eq!(
        inspect_named_verifier_transport(&archive, &key).unwrap(),
        manifest
    );
    let archive_before = source_files(&archive);
    // Public source-preserving reader exposes only an immutable encrypted copy.
    // The real bundle inspector above authenticated complete rows and inventory.
    let snapshot = open_encrypted_read_snapshot(&archive, &key).unwrap();
    let mut statement = snapshot.connection().prepare("SELECT payload FROM bundle_rows WHERE component=?1 AND table_name='outbox' ORDER BY row_number").unwrap();
    let rows = statement
        .query_map([COMPONENT], |row| row.get::<_, Vec<u8>>(0))
        .unwrap();
    let mut captured = BTreeMap::new();
    for row in rows {
        let row: CapturedRow = serde_json::from_slice(&row.unwrap()).unwrap();
        assert!(row.rowid.is_some());
        assert_eq!(row.cells.len(), 14);
        let sequence = row.cells[1].integer();
        assert!(captured.insert(sequence, row).is_none());
    }
    assert_eq!(captured.len(), 2);
    for (index, original) in original.iter().enumerate() {
        let sequence = (index + 1) as i64;
        let row = &captured[&sequence];
        assert_eq!(row.cells[12].blob(), original.envelope().as_bytes());
        assert_eq!(row.cells[3].text(), original.preview_digest());
        assert_eq!(row.cells[10].integer(), at(0).unix_seconds());
        assert_eq!(row.cells[11].integer(), at(600).unix_seconds());
        assert_eq!(row.cells[13].integer(), if sequence == 1 { 1 } else { 0 });
    }
    drop(statement);
    drop(snapshot);
    assert_eq!(source_files(&archive), archive_before);
    let restored = directory.root().join("informational-outbox.sqlite");
    let report = restore_outbox(&archive, &restored, &manifest, &keys);
    // The genuine restore path checks every restored logical row against the
    // archive before returning this report, with quarantine persisted first.
    assert!(report.integrity_verified && report.all_components_quarantined);
    assert!(!report.authorization_allowed && !report.signer_recovered);
    assert_eq!(report.restored_components, 1);
    assert_eq!(report.manifest, manifest);
    assert!(matches!(
        open_encrypted_quiescent(&restored, &keys.restore),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert!(matches!(
        open_encrypted(&restored, &keys.restore),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert!(open_encrypted(&restored, &keys.restore)
        .ok()
        .and_then(|connection| SqliteOutbox::from_encrypted_connection(connection).ok())
        .is_none());
    assert_eq!(durable_source_files(&original_path), source_before);
    let recipient = keys.recipient.public_key().unwrap();
    for (index, original) in original.iter().enumerate() {
        let retained = outbox
            .recover_for_recipient(&context(), &recipient, (index + 1) as u64)
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.envelope().as_bytes(),
            original.envelope().as_bytes()
        );
    }
    assert_eq!(outbox.next_sequence(&context()).unwrap(), 3);
    assert_eq!(
        outbox
            .recover_for_recipient(&context(), &recipient, 1)
            .unwrap()
            .unwrap()
            .delivery_status(),
        DeliveryStatus::RecipientReceiptRecorded
    );
    assert_eq!(
        outbox
            .recover_for_recipient(&context(), &recipient, 2)
            .unwrap()
            .unwrap()
            .delivery_status(),
        DeliveryStatus::AwaitingRecipientReceipt
    );
    for path in [&archive, &restored] {
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3\0"));
        assert!(!bytes
            .windows(b"public payload".len())
            .any(|w| w == b"public payload"));
    }
}

static SYNTHETIC_COORD: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0x5359434f,
    schema_version: 1,
    create_sql: "CREATE TABLE synthetic_records(value TEXT NOT NULL);",
};
struct SyntheticCoord(Mutex<EncryptedConnection>);
impl JournalAdapter for SyntheticCoord {
    fn template(&self) -> &'static JournalTemplate {
        &SYNTHETIC_COORD
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> std::result::Result<(), BundleError>,
    ) -> std::result::Result<(), BundleError> {
        permit.check(self)?;
        visitor(
            self.0
                .lock()
                .map_err(|_| BundleError::Permission)?
                .connection(),
        )
    }
}
fn ordinary_coverage() -> Coverage {
    let mut coverage = named_verifier_transport_coverage();
    coverage.present.clear();
    coverage.absent.insert(JournalKind::TransportOutbox);
    coverage.absent.remove(&JournalKind::CoordinationAuthority);
    coverage.present.insert(
        JournalKind::CoordinationAuthority,
        vec!["synthetic-coordination".into()],
    );
    coverage
}
#[test]
fn named_verifier_encrypted_archives_reject_legacy_cross_profile_and_mixed_financial_roles() {
    let keys = EphemeralKeys::new();
    let (_temp, directory) = fixture_directory();
    let (mut outbox, _original) = populated_outbox(&directory, &keys);
    let key = keys.archive_key();
    let named_path = directory.root().join("named.sqlite");
    let named = snapshot_outbox(
        &mut outbox,
        &named_path,
        "synthetic-public-profile",
        "synthetic-checkpoint",
        &keys,
    );
    let ordinary_connection = create_encrypted(
        directory.root().join("synthetic-coord.sqlite"),
        &keys.coordination,
    )
    .unwrap();
    ordinary_connection
        .connection()
        .execute_batch(SYNTHETIC_COORD.create_sql)
        .unwrap();
    ordinary_connection
        .connection()
        .pragma_update(None, "application_id", SYNTHETIC_COORD.application_id)
        .unwrap();
    ordinary_connection
        .connection()
        .pragma_update(None, "user_version", SYNTHETIC_COORD.schema_version)
        .unwrap();
    ordinary_connection
        .connection()
        .execute(
            "INSERT INTO synthetic_records VALUES(?1)",
            ["public synthetic ordinary archive"],
        )
        .unwrap();
    let coord = SyntheticCoord(Mutex::new(ordinary_connection));
    let coord_source = [RegisteredJournal::new("synthetic-coordination", &coord).unwrap()];
    let ordinary_path = directory.root().join("ordinary.sqlite");
    let authority = SyntheticAuthority {
        profile: named.profile_id.clone(),
        archive: ordinary_path.clone(),
        destinations: vec![],
        sources: coord_source
            .iter()
            .map(|s| (s.id().into(), s.binding()))
            .collect(),
        coverage: ordinary_coverage(),
        action: BundleAction::Snapshot,
        checkpoint: "synthetic-ordinary-checkpoint".into(),
    };
    let ordinary = snapshot(SnapshotRequest {
        principal_id: PRINCIPAL,
        profile_id: &authority.profile,
        coverage: authority.coverage.clone(),
        sources: &coord_source,
        destination: &ordinary_path,
        key: &key,
        authority: &authority,
    })
    .unwrap();
    assert_eq!(ordinary.format_version, 1);
    assert!(inspect(&named_path, &key).is_err());
    assert!(inspect_named_verifier_transport(&ordinary_path, &key).is_err());
    assert!(inspect_named_verifier_transport(&named_path, &keys.wrong_archive).is_err());
    for (archive, named_api, template, component) in [
        (
            &ordinary_path,
            true,
            &SYNTHETIC_COORD,
            "synthetic-coordination",
        ),
        (&named_path, false, &OUTBOX_BACKUP_TEMPLATE, COMPONENT),
    ] {
        let destination = directory.root().join(if named_api {
            "refused-named.sqlite"
        } else {
            "refused-ordinary.sqlite"
        });
        let targets = [RestoreTarget {
            component_id: component,
            template,
            destination: &destination,
            key: &keys.restore,
        }];
        let gate = SyntheticAuthority {
            profile: named.profile_id.clone(),
            archive: archive.clone(),
            destinations: vec![destination.clone()],
            sources: vec![],
            coverage: if named_api {
                ordinary_coverage()
            } else {
                named_verifier_transport_coverage()
            },
            action: BundleAction::Restore,
            checkpoint: "synthetic-cross-profile".into(),
        };
        let request = RestoreRequest {
            principal_id: PRINCIPAL,
            profile_id: &gate.profile,
            archive,
            key: &key,
            targets: &targets,
            authority: &gate,
        };
        let result = if named_api {
            restore_named_verifier_transport(request)
        } else {
            restore(request)
        };
        assert!(result.is_err());
        assert!(!destination.exists());
    }
    let adapter = outbox.backup_adapter().unwrap();
    let mixed_sources = [
        RegisteredJournal::new(COMPONENT, &adapter).unwrap(),
        RegisteredJournal::new("synthetic-coordination", &coord).unwrap(),
    ];
    let mut mixed = named_verifier_transport_coverage();
    mixed.absent.remove(&JournalKind::CoordinationAuthority);
    mixed.present.insert(
        JournalKind::CoordinationAuthority,
        vec!["synthetic-coordination".into()],
    );
    let destination = directory.root().join("refused-mixed.sqlite");
    let gate = SyntheticAuthority {
        profile: named.profile_id.clone(),
        archive: destination.clone(),
        destinations: vec![],
        sources: mixed_sources
            .iter()
            .map(|s| (s.id().into(), s.binding()))
            .collect(),
        coverage: mixed.clone(),
        action: BundleAction::Snapshot,
        checkpoint: "synthetic-mixed".into(),
    };
    assert!(snapshot_named_verifier_transport(SnapshotRequest {
        principal_id: PRINCIPAL,
        profile_id: &gate.profile,
        coverage: mixed,
        sources: &mixed_sources,
        destination: &destination,
        key: &key,
        authority: &gate
    })
    .is_err());
    assert!(!destination.exists());
}

#[test]
fn named_verifier_encrypted_pair_rejects_swapped_recovery_manifest_marker_and_wrong_password() {
    let keys = EphemeralKeys::new();
    let (_temp, directory) = fixture_directory();
    let (mut outbox, _original) = populated_outbox(&directory, &keys);
    // These are password envelopes of public test strings, not signer recovery
    // authority. Pair verification is exercised without creating a verifier key.
    let recovery_a = vault::password_envelope(
        RECOVERY_MAGIC,
        keys.password.as_ref(),
        b"public synthetic recovery bytes A",
    )
    .unwrap();
    let recovery_b = vault::password_envelope(
        RECOVERY_MAGIC,
        keys.password.as_ref(),
        b"public synthetic recovery bytes B",
    )
    .unwrap();
    let payload = Payload {
        archive_key: Zeroizing::new(*keys.archive),
        // Inert pair-only scalar metadata: never decoded or passed into a
        // private-key constructor, signing path or live VerifierOwner opener.
        seed: Zeroizing::new([0; 32]),
        journal: Journal {
            version: 1,
            public_key: [0; 32],
            restored_informational: false,
            families: Default::default(),
            rows: Default::default(),
            export_identity: None,
        },
    };
    let profile_id = profile(&payload.journal);
    let archive_a = directory.root().join("pair-a.sqlite");
    let archive_b = directory.root().join("pair-b.sqlite");
    let manifest_a = snapshot_outbox(
        &mut outbox,
        &archive_a,
        &profile_id,
        &hash(&recovery_a),
        &keys,
    );
    let manifest_b = snapshot_outbox(
        &mut outbox,
        &archive_b,
        &profile_id,
        &hash(&recovery_b),
        &keys,
    );
    let marker_a = vault::encrypt(
        &keys.archive,
        COMPLETE_DOMAIN,
        &Completion::from_manifest(&recovery_a, &manifest_a)
            .bytes()
            .unwrap(),
    )
    .unwrap();
    let marker_b = vault::encrypt(
        &keys.archive,
        COMPLETE_DOMAIN,
        &Completion::from_manifest(&recovery_b, &manifest_b)
            .bytes()
            .unwrap(),
    )
    .unwrap();
    assert!(verify_pair(&payload, &recovery_a, &manifest_a, &marker_a).is_ok());
    assert!(verify_pair(&payload, &recovery_b, &manifest_b, &marker_b).is_ok());
    let before_a = source_files(&archive_a);
    let before_b = source_files(&archive_b);
    assert!(verify_pair(&payload, &recovery_b, &manifest_a, &marker_a).is_err());
    assert!(verify_pair(&payload, &recovery_a, &manifest_b, &marker_a).is_err());
    assert!(verify_pair(&payload, &recovery_a, &manifest_a, &marker_b).is_err());
    assert!(verify_pair(&payload, &recovery_a, &manifest_a, &[]).is_err());
    let mut corrupt = marker_a.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(verify_pair(&payload, &recovery_a, &manifest_a, &corrupt).is_err());
    let wrong_domain = vault::encrypt(
        &keys.archive,
        RESTORE_DOMAIN,
        &Completion::from_manifest(&recovery_a, &manifest_a)
            .bytes()
            .unwrap(),
    )
    .unwrap();
    assert!(verify_pair(&payload, &recovery_a, &manifest_a, &wrong_domain).is_err());
    assert!(vault::open_password_envelope(
        RECOVERY_MAGIC,
        keys.wrong_password.as_ref(),
        &recovery_a,
        MAX_RECOVERY
    )
    .is_err());
    let (opened, _, _) = vault::open_password_envelope(
        RECOVERY_MAGIC,
        keys.password.as_ref(),
        &recovery_a,
        MAX_RECOVERY,
    )
    .unwrap();
    assert_eq!(&*opened, b"public synthetic recovery bytes A");
    let mut changed = manifest_a.clone();
    changed.digest = manifest_b.digest.clone();
    assert!(verify_pair(&payload, &recovery_a, &changed, &marker_a).is_err());
    assert_eq!(source_files(&archive_a), before_a);
    assert_eq!(source_files(&archive_b), before_b);
}
