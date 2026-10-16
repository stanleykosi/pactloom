//! Composed synthetic regression: maintained recorded import -> authenticated
//! wallet bundle -> quarantined restore -> immutable and archived history.
//!
//! The request and evidence digest are INERT public test data. Fixture gates
//! establish no native approval, provider trust, scan, spend, or host activation.
//! No network, socket, proof generation, live credential, or funded account is used.
use super::*;
use crate::bundle::{self as wallet_bundle, recovery as wallet_recovery};
use rusqlite::Connection;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use wholepact_storage_security::{
    DatabaseKey, StorageSecurityError,
    bundle::{
        self as storage_bundle, BundleAction, BundleAuthority, BundleError, BundleLease,
        BundleScope, Coverage, JournalAdapter, JournalBinding, JournalKind, RegisteredJournal,
        RestoreRequest, RestoreTarget, SnapshotRequest,
        history::HistoryOpenRequest,
        recovery::{RecoveryCell, RecoveryTable, generation::GenerationBinding},
    },
    generation_archive as capsule,
};
use wholepact_store::{Store, bundle::CoordinationBundleAdapter};

type BundleResult<T> = std::result::Result<T, BundleError>;
type RecordRow = (i64, i64, i64, Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    kind: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    digest: Option<[u8; 32]>,
}

// Includes every entry, root/subdirectory metadata, main DB, WAL/SHM/journal,
// unrelated sentinels, permissions and inode identity. Access time is omitted:
// ordinary filesystem reads can legitimately advance it.
fn tree(root: &Path) -> BTreeMap<PathBuf, Fingerprint> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(!meta.file_type().is_symlink());
        assert!(meta.is_file() || meta.is_dir());
        let digest = if meta.is_dir() {
            pending.extend(
                fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
            None
        } else {
            Some(Sha256::digest(fs::read(&path).unwrap()).into())
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            Fingerprint {
                kind: meta.mode() & 0o170000,
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                device: meta.dev(),
                inode: meta.ino(),
                links: meta.nlink(),
                length: meta.len(),
                modified: (meta.mtime(), meta.mtime_nsec()),
                changed: (meta.ctime(), meta.ctime_nsec()),
                digest,
            },
        );
    }
    result
}
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn add_unrelated_evidence(root: &Path) {
    let nested = root.join("unrelated-evidence");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let path = nested.join("sentinel.bin");
    fs::write(
        &path,
        b"public synthetic sentinel: preserve every source entry",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn records(connection: &Connection) -> Vec<RecordRow> {
    connection
        .prepare("SELECT rowid,sequence,format_version,record FROM ext_wholepact_import_records ORDER BY sequence")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap()
}
fn typed_records(tables: &[RecoveryTable]) -> Vec<RecordRow> {
    let table = tables
        .iter()
        .find(|table| table.name() == "ext_wholepact_import_records")
        .unwrap();
    assert_eq!(table.columns(), ["sequence", "format_version", "record"]);
    assert!(table.has_rowid());
    let mut result = table
        .rows()
        .iter()
        .map(|row| match row.cells() {
            [
                RecoveryCell::Integer(sequence),
                RecoveryCell::Integer(version),
                RecoveryCell::Blob(bytes),
            ] => (row.rowid().unwrap(), *sequence, *version, bytes.clone()),
            _ => panic!("recorded import cell types changed"),
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|row| row.1);
    result
}
fn assert_actual_account(connection: &Connection, actual_uuid: &[u8; 16]) {
    let uuids: Vec<Vec<u8>> = connection
        .prepare("SELECT uuid FROM accounts")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert_eq!(uuids, vec![actual_uuid.to_vec()]);
}
fn assert_typed_history(tables: &[RecoveryTable], expected: &[RecordRow], actual_uuid: &[u8; 16]) {
    assert_eq!(typed_records(tables), expected);
    let accounts = tables
        .iter()
        .find(|table| table.name() == "accounts")
        .unwrap();
    let uuid_column = accounts
        .columns()
        .iter()
        .position(|column| column == "uuid")
        .unwrap();
    assert_eq!(accounts.rows().len(), 1);
    assert!(
        matches!(&accounts.rows()[0].cells()[uuid_column], RecoveryCell::Blob(bytes) if bytes.as_slice() == actual_uuid)
    );
}

// Exact adapter/target enrollment for this single-threaded synthetic fixture.
// Production quiescence and native permission are deliberately NOT simulated.
struct FixtureGate {
    sources: Vec<JournalBinding>,
    archive: PathBuf,
    destinations: Vec<PathBuf>,
}
struct FixtureLease;
impl BundleLease for FixtureLease {
    fn check_current(&self) -> BundleResult<()> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-recorded-roundtrip"
    }
}
impl BundleAuthority for FixtureGate {
    fn acquire<'a>(&'a self, scope: &BundleScope<'_>) -> BundleResult<Box<dyn BundleLease + 'a>> {
        if scope.principal_id != "synthetic-admin"
            || scope.profile_id != "synthetic-profile"
            || scope.archive != self.archive
            || scope.wallet_spending_secrets_included
            || (scope.action == BundleAction::Snapshot
                && scope
                    .sources
                    .iter()
                    .map(|source| source.1.clone())
                    .collect::<Vec<_>>()
                    != self.sources)
            || (scope.action != BundleAction::Snapshot && scope.destinations != self.destinations)
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(FixtureLease))
    }
}
struct CapsuleGate(capsule::ArchiveScope);
impl capsule::ArchiveAuthority for CapsuleGate {
    fn acquire<'a>(
        &'a self,
        scope: &capsule::ArchiveScope,
    ) -> capsule::Result<Box<dyn capsule::ArchiveLease + 'a>> {
        if scope != &self.0 {
            return Err(capsule::ArchiveError::Permission);
        }
        Ok(Box::new(FixtureLease))
    }
}
impl capsule::ArchiveLease for FixtureLease {
    fn check_current(&self) -> capsule::Result<()> {
        Ok(())
    }
}

fn composed_roundtrip(
    directory: &tempfile::TempDir,
    source_key: &DatabaseKey,
    wallet: &DedicatedTestnetWallet,
    expected: &[RecordRow],
    actual_uuid: &[u8; 16],
) {
    let path = directory.path().join("wallet.sqlite");
    add_unrelated_evidence(directory.path());
    let support = private_dir();
    let output = private_dir();
    let recovered = private_dir();
    let archived = private_dir();
    let authority_key = DatabaseKey::from_bytes([0x71; 32]);
    let archive_key = DatabaseKey::from_bytes([0x72; 32]);
    let restored_key = DatabaseKey::from_bytes([0x73; 32]);
    let successor_key = DatabaseKey::from_bytes([0x74; 32]);
    let evidence_key = DatabaseKey::from_bytes([0x75; 32]);
    let capsule_key = DatabaseKey::from_bytes([0x76; 32]);
    let wrong_key = DatabaseKey::from_bytes([0x77; 32]);
    let anchor =
        Store::create_encrypted(support.path().join("coordination.sqlite"), &authority_key)
            .unwrap();
    let anchor_adapter = CoordinationBundleAdapter::new(&anchor).unwrap();
    let adapter = wallet_bundle::WalletScanBackupAdapter::new(
        wallet,
        wholepact_storage_security::open_encrypted_quiescent(&path, source_key).unwrap(),
    )
    .unwrap();
    assert!(std::ptr::eq(
        adapter.template(),
        wallet_bundle::trusted_recorded_import_template().unwrap()
    ));
    assert!(!std::ptr::eq(
        adapter.template(),
        wallet_bundle::trusted_template().unwrap()
    ));
    let sources = [
        RegisteredJournal::new("coordination", &anchor_adapter).unwrap(),
        RegisteredJournal::new("wallet", &adapter).unwrap(),
    ];
    let archive = output.path().join("wallet-bundle.sqlite");
    let restored = output.path().join("quarantined-wallet.sqlite");
    let restored_anchor = output.path().join("quarantined-coordination.sqlite");
    let gate = FixtureGate {
        sources: sources.iter().map(|source| source.binding()).collect(),
        archive: archive.clone(),
        destinations: vec![restored_anchor.clone(), restored.clone()],
    };
    let coverage = Coverage {
        present: BTreeMap::from([
            (
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            ),
            (JournalKind::WalletScan, vec!["wallet".into()]),
        ]),
        absent: BTreeSet::from([
            JournalKind::SignerConsentAuthority,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::Submission,
            JournalKind::TransportInbox,
            JournalKind::TransportOutbox,
        ]),
    };
    let source_before = tree(directory.path());
    let manifest = storage_bundle::snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        coverage,
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &gate,
    })
    .unwrap();
    assert!(!manifest.writer_freshness_established);
    assert!(!manifest.wallet_spending_secrets_included);
    assert!(manifest.restore_requires_recovery);
    assert_eq!(
        source_before,
        tree(directory.path()),
        "quiescent fixture backup changed source tree"
    );

    let selected =
        wallet_bundle::trusted_template_for_bundle_component(&archive, &archive_key, "wallet")
            .unwrap();
    assert!(std::ptr::eq(selected, adapter.template()));
    let targets = [
        RestoreTarget {
            component_id: "coordination",
            template: anchor_adapter.template(),
            destination: &restored_anchor,
            key: &restored_key,
        },
        RestoreTarget {
            component_id: "wallet",
            template: selected,
            destination: &restored,
            key: &restored_key,
        },
    ];
    let report = storage_bundle::restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &archive_key,
        targets: &targets,
        authority: &gate,
    })
    .unwrap();
    assert!(report.integrity_verified && report.all_components_quarantined);
    assert!(!report.authorization_allowed && !report.signer_recovered);
    assert_eq!(report.manifest, manifest);
    let output_before = tree(output.path());
    assert!(matches!(
        wholepact_storage_security::open_encrypted_quiescent(&restored, &restored_key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    let historical = wallet_recovery::open_verified_wallet_scan_component(HistoryOpenRequest {
        archive: &archive,
        archive_key: &archive_key,
        component_id: "wallet",
        restored_component: &restored,
        restored_key: &restored_key,
    })
    .unwrap();
    assert_typed_history(historical.tables(), expected, actual_uuid);
    assert!(std::ptr::eq(
        wallet_recovery::trusted_template_for_recovery_component(&historical).unwrap(),
        selected
    ));

    // Source reads are private captures; even the source WAL and SHM stay exact.
    let ordinary = wallet_bundle::open_wallet_scan_read_snapshot(&path, source_key).unwrap();
    assert_eq!(records(ordinary.connection()), expected);
    assert_actual_account(ordinary.connection(), actual_uuid);
    assert!(!ordinary.connection().is_autocommit());
    assert!(
        ordinary
            .connection()
            .execute("DELETE FROM ext_wholepact_import_records", [])
            .is_err()
    );
    drop(ordinary);

    let successor = recovered.path().join("successor.sqlite");
    let evidence_path = recovered.path().join("evidence.sqlite");
    let binding = GenerationBinding::new(&"81".repeat(32), &"82".repeat(32)).unwrap();
    wallet_recovery::reconstruct_wallet_scan_successor(&historical, &successor, &successor_key)
        .unwrap();
    wallet_recovery::reconstruct_wallet_scan_successor_evidence(
        &historical,
        &evidence_path,
        &evidence_key,
        &binding,
    )
    .unwrap();
    let recovered_before = tree(recovered.path());
    let successor_read =
        wallet_bundle::open_wallet_scan_read_snapshot(&successor, &successor_key).unwrap();
    assert_eq!(records(successor_read.connection()), expected);
    assert_actual_account(successor_read.connection(), actual_uuid);
    assert!(
        successor_read
            .connection()
            .execute("DELETE FROM accounts", [])
            .is_err()
    );
    drop(successor_read);
    let evidence = wallet_recovery::open_wallet_scan_successor_evidence(
        &evidence_path,
        &evidence_key,
        &binding,
        historical.provenance(),
    )
    .unwrap();
    assert_typed_history(evidence.tables(), expected, actual_uuid);
    assert_eq!(evidence.provenance(), historical.provenance());
    assert!(
        wholepact_storage_security::open_encrypted_quiescent(&evidence_path, &evidence_key)
            .is_err()
    );

    // Archive the actual original and reconstructed evidence with their exact
    // original paths. Archived reads must use sealed relocation, not reopen paths.
    let capsule_path = archived.path().join("history-capsule.sqlite");
    let node = capsule::NodeSpec {
        generation_id: "83".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: directory.path().to_path_buf(),
    };
    let capsule_sources = [
        capsule::RegisteredSource::new(
            "original",
            "original-wallet",
            capsule::Source::Journal(&path),
        )
        .unwrap(),
        capsule::RegisteredSource::new(
            "evidence",
            "wallet-evidence",
            capsule::Source::Journal(&evidence_path),
        )
        .unwrap(),
    ];
    let capsule_id = "84".repeat(32);
    let capsule_gate = CapsuleGate(
        capsule::ArchiveScope::for_snapshot(
            &capsule_path,
            &capsule_key,
            &capsule_id,
            &node,
            &capsule_sources,
            &[],
        )
        .unwrap(),
    );
    let capsule_report = capsule::snapshot(capsule::SnapshotRequest {
        destination: &capsule_path,
        key: &capsule_key,
        capsule_id: &capsule_id,
        node: &node,
        sources: &capsule_sources,
        parents: &[],
        authority: &capsule_gate,
    })
    .unwrap();
    let archived_before = tree(archived.path());
    let sealed = capsule::inspect(&capsule_path, &capsule_key).unwrap();
    assert!(sealed.report() == capsule_report);
    let archived_original = sealed
        .journal(&capsule_report.manifest_digest, "original")
        .unwrap();
    assert_eq!(archived_original.origin(), path.to_str().unwrap());
    let read =
        wallet_recovery::inspect_archived_wallet_scan_history(&archived_original, source_key)
            .unwrap();
    assert_typed_history(read.tables(), expected, actual_uuid);
    let archived_evidence = sealed
        .journal(&capsule_report.manifest_digest, "evidence")
        .unwrap();
    assert_eq!(archived_evidence.origin(), evidence_path.to_str().unwrap());
    let read = wallet_recovery::open_archived_wallet_scan_successor_evidence(
        &archived_evidence,
        &evidence_key,
        &binding,
        historical.provenance(),
    )
    .unwrap();
    assert_typed_history(read.tables(), expected, actual_uuid);
    assert_eq!(read.provenance(), historical.provenance());
    assert!(read.archive_origin().is_some());

    // Wrong keys, wrong full layout and wrong generation never fall back to a
    // legacy reader or create a writable recovery/issuer capability.
    assert!(wallet_bundle::open_wallet_scan_read_snapshot(&path, &wrong_key).is_err());
    assert!(
        wallet_bundle::trusted_template_for_bundle_component(&archive, &wrong_key, "wallet")
            .is_err()
    );
    assert!(
        wallet_recovery::open_verified_wallet_scan_component(HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "wallet",
            restored_component: &restored,
            restored_key: &wrong_key,
        })
        .is_err()
    );
    assert!(
        storage_bundle::recovery::VerifiedRecoveryComponent::open(
            HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "wallet",
                restored_component: &restored,
                restored_key: &restored_key,
            },
            wallet_bundle::trusted_template().unwrap()
        )
        .is_err()
    );
    assert!(
        wallet_recovery::open_wallet_scan_successor_evidence(
            &evidence_path,
            &wrong_key,
            &binding,
            historical.provenance()
        )
        .is_err()
    );
    let wrong_binding = GenerationBinding::new(&"85".repeat(32), &"86".repeat(32)).unwrap();
    assert!(
        wallet_recovery::open_wallet_scan_successor_evidence(
            &evidence_path,
            &evidence_key,
            &wrong_binding,
            historical.provenance()
        )
        .is_err()
    );
    assert!(
        wallet_recovery::inspect_archived_wallet_scan_history(&archived_original, &wrong_key)
            .is_err()
    );
    assert!(
        wallet_recovery::open_archived_wallet_scan_successor_evidence(
            &archived_evidence,
            &wrong_key,
            &binding,
            historical.provenance()
        )
        .is_err()
    );
    assert!(capsule::inspect(&capsule_path, &wrong_key).is_err());
    assert_eq!(
        source_before,
        tree(directory.path()),
        "source tree changed across history readers"
    );
    assert_eq!(
        output_before,
        tree(output.path()),
        "bundle/quarantine tree changed across readers"
    );
    assert_eq!(
        recovered_before,
        tree(recovered.path()),
        "successor/evidence tree changed across readers"
    );
    assert_eq!(
        archived_before,
        tree(archived.path()),
        "capsule tree changed across readers"
    );

    // Exercise issuer denial only on a disposable separately reconstructed copy,
    // keeping all original/recovered/archive read fixtures immutable above.
    let denied = private_dir();
    let denied_path = denied.path().join("cannot-mint.sqlite");
    let denied_key = DatabaseKey::from_bytes([0x78; 32]);
    wallet_recovery::reconstruct_wallet_scan_successor(&historical, &denied_path, &denied_key)
        .unwrap();
    let connection =
        wholepact_storage_security::open_encrypted_quiescent(&denied_path, &denied_key).unwrap();
    assert!(
        DedicatedTestnetWallet::from_encrypted_connection_recordable_import(connection).is_err()
    );
    let connection =
        wholepact_storage_security::open_encrypted_quiescent(&denied_path, &denied_key).unwrap();
    let mut reopened = DedicatedTestnetWallet::from_encrypted_connection(connection).unwrap();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    assert!(matches!(
        reopened.import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32)),
        Err(RecordedImportError::FreshOwnerRequired)
    ));
    assert_eq!(reopened.db.get_account_ids().unwrap().len(), 1);
    let unchanged =
        wallet_bundle::open_wallet_scan_read_snapshot(&denied_path, &denied_key).unwrap();
    assert_eq!(records(unchanged.connection()), expected);
    assert_actual_account(unchanged.connection(), actual_uuid);
}

#[test]
fn recorded_import_roundtrip_preserves_actual_uuid_and_exact_intent_completion() {
    let (directory, key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    let receipt = wallet
        .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
        .unwrap();
    let actual_uuid = *receipt.account_uuid().expose_uuid().as_bytes();
    assert_eq!(
        wallet.db.get_account_ids().unwrap(),
        vec![receipt.account_uuid()]
    );
    let snapshot = wallet_bundle::open_wallet_scan_read_snapshot(
        &directory.path().join("wallet.sqlite"),
        &key,
    )
    .unwrap();
    let expected = records(snapshot.connection());
    assert_eq!(expected.len(), 2);
    let original_intent: Intent = decode(&expected[0].3).unwrap();
    let completion: Completion = decode(&expected[1].3).unwrap();
    completion.require_intent(&original_intent).unwrap();
    assert!(original_intent.request == request);
    assert_eq!(
        original_intent.native_disclosure_evidence_digest,
        "44".repeat(32)
    );
    assert_eq!(completion.returned_account_uuid, actual_uuid);
    assert_eq!(completion.intent_digest, receipt.intent_digest());
    assert_eq!(
        completion.first_scan_height,
        request.scope.birthday.prior_height + 1
    );
    drop(snapshot);
    // The process-local receipt is deliberately discarded before any backup or
    // read; all later output is history, never a recreated issuer receipt.
    drop(receipt);
    composed_roundtrip(&directory, &key, &wallet, &expected, &actual_uuid);
}

#[test]
fn malformed_or_orphan_import_rows_survive_as_evidence_without_minting_issuer() {
    for orphan_completion in [false, true] {
        let (directory, key, mut wallet) = fresh();
        let fvk = public_fvk();
        let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
        let receipt = wallet
            .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
            .unwrap();
        let actual_uuid = *receipt.account_uuid().expose_uuid().as_bytes();
        drop(receipt);
        // Explicit fixture corruption of rows, never schema or product repair.
        wallet
            .db
            .transactionally_with_extension(|_, ext| -> Result<()> {
                if orphan_completion {
                    ext.execute(
                        "DELETE FROM ext_wholepact_import_records WHERE sequence=0",
                        [],
                    )?;
                    assert_eq!(count(ext)?, 1);
                    assert!(load::<Intent>(ext, 0).is_err());
                    assert_eq!(
                        load::<Completion>(ext, 1)?.returned_account_uuid,
                        actual_uuid
                    );
                } else {
                    ext.execute(
                        "UPDATE ext_wholepact_import_records SET record=x'00ff7b' WHERE sequence=0",
                        [],
                    )?;
                    assert_eq!(count(ext)?, 2);
                    assert!(load::<Intent>(ext, 0).is_err());
                }
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            wallet.import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32)),
            Err(RecordedImportError::FreshOwnerRequired)
        ));
        let snapshot = wallet_bundle::open_wallet_scan_read_snapshot(
            &directory.path().join("wallet.sqlite"),
            &key,
        )
        .unwrap();
        let expected = records(snapshot.connection());
        assert_eq!(expected.len(), if orphan_completion { 1 } else { 2 });
        if orphan_completion {
            assert_eq!(expected[0].1, 1);
        } else {
            assert_eq!(expected[0].3, [0, 255, 123]);
        }
        drop(snapshot);
        composed_roundtrip(&directory, &key, &wallet, &expected, &actual_uuid);
    }
}

#[test]
fn actual_wallet_unknown_layout_denies_without_touching_entire_source_tree() {
    let (directory, key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    let receipt = wallet
        .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
        .unwrap();
    drop(receipt);
    let path = directory.path().join("wallet.sqlite");
    let adversarial = wholepact_storage_security::open_encrypted_quiescent(&path, &key).unwrap();
    adversarial
        .connection()
        .execute_batch(
            "ALTER TABLE ext_wholepact_import_records ADD COLUMN unsupported_extra BLOB;",
        )
        .unwrap();
    add_unrelated_evidence(directory.path());
    // The live backup selector reads the actual SQLite connection and may
    // update its WAL read mark. Freeze only after that separate rejection.
    assert!(wallet_bundle::trusted_template_for_backup_source(&adversarial).is_err());
    let before = tree(directory.path());
    assert!(wallet_bundle::open_wallet_scan_read_snapshot(&path, &key).is_err());
    assert_eq!(before, tree(directory.path()));
    assert!(
        wallet_bundle::open_wallet_scan_read_snapshot(&path, &DatabaseKey::from_bytes([0x79; 32]))
            .is_err()
    );
    assert_eq!(before, tree(directory.path()));
}
