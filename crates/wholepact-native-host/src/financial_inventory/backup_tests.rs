//! Complete encrypted synthetic journal-bundle roundtrip. The test-only lower
//! bundle gate is not a native attachment approval, signer lease or live grant.
use super::*;
type SourceTreeFingerprint =
    std::collections::BTreeMap<PathBuf, (Vec<u8>, u32, u64, u64, i64, i64)>;
use crate::{
    financial_backup::{Adapters, RestoreFinancial},
    financial_profile::FinancialProfile,
};
use std::sync::Mutex;
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{self, *},
    create_encrypted,
};
const PASSWORD: &[u8] = b"synthetic-only-v2-backup-password";
struct SyntheticBundleGate(String);
impl BundleAuthority for SyntheticBundleGate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-v2-backup" || scope.wallet_spending_secrets_included {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(self))
    }
}
impl BundleLease for &SyntheticBundleGate {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        &self.0
    }
}
#[test]
fn complete_bundle_roundtrip_keeps_pending_dependency_and_exact_v2_registry() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs_canonical(temp.path());
    let host = Directory::create(&root.join("host")).unwrap();
    let archive = Directory::create(&root.join("archive")).unwrap();
    let restore_path = root.join("restored");
    let restored = Directory::create(&restore_path).unwrap();
    let secrets = Secrets::fresh().unwrap();
    let primary_path = root.join("financial-0");
    let participant_path = root.join("financial-1");
    register(
        &host,
        &secrets,
        &primary_path,
        AttachmentRole::PrimaryFinancial,
        None,
    )
    .unwrap();
    let primary = FinancialProfile::create(&primary_path, &secrets.profile(), PASSWORD).unwrap();
    let original_primary = primary
        .manual_journal_origin_digest(&host, &secrets)
        .unwrap();
    let registry = match load(&host, &secrets).unwrap() {
        Registry::V1(value) => value,
        _ => unreachable!(),
    };
    let mut value = InventoryV2 {
        version: 2,
        owner: secrets.profile(),
        original_primary: OriginalPrimary {
            registry,
            journal_origin_digest: original_primary,
        },
        extensions: Vec::new(),
    };
    value
        .append(
            Extension::Pending {
                request: PendingAttachment {
                    operation_digest: "11".repeat(32),
                    account_id: "22".repeat(32),
                    directory: participant_path.clone(),
                    mode: AttachmentOpenMode::Create,
                },
            },
            &"33".repeat(32),
            &secrets,
        )
        .unwrap();
    write_v2(&host, &secrets, &value).unwrap();
    // Model a completed encrypted create followed by interrupted extension commit.
    // The complete backup still MUST carry all four pending dependency journals.
    let participant =
        FinancialProfile::create(&participant_path, &secrets.profile(), PASSWORD).unwrap();
    let financial = [primary, participant];
    let entries = read(&host, &secrets).unwrap();
    assert_eq!(entries.len(), financial.len());
    for (entry, actual) in entries.iter().zip(&financial) {
        check_backup_owner(&host, &secrets, entry, actual).unwrap();
    }
    let store = wholepact_store::Store::create_encrypted(
        host.path("coordination.sqlite").unwrap(),
        &secrets.key(0).unwrap(),
    )
    .unwrap();
    let coordination = wholepact_store::bundle::CoordinationBundleAdapter::new(&store).unwrap();
    let mut inbox = wholepact_transport::SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(host.path("inbox.sqlite").unwrap(), &secrets.key(1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut outbox = wholepact_transport::SqliteOutbox::from_encrypted_connection(
        create_encrypted(
            host.path("outbox.sqlite").unwrap(),
            &secrets.key(2).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let submission = Mutex::new(
        wholepact_chain::EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(
                host.path("submission.sqlite").unwrap(),
                &secrets.key(3).unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let inbox = inbox.backup_adapter().unwrap();
    let outbox = outbox.backup_adapter().unwrap();
    let submission = wholepact_chain::backup::SubmissionBackupAdapter::new(&submission);
    let adapters = financial
        .iter()
        .map(|profile| Adapters::new(profile).unwrap())
        .collect::<Vec<_>>();
    let mut sources = vec![
        RegisteredJournal::new("coordination", &coordination).unwrap(),
        RegisteredJournal::new("inbox", &inbox).unwrap(),
        RegisteredJournal::new("outbox", &outbox).unwrap(),
        RegisteredJournal::new("submission", &submission).unwrap(),
    ];
    for (index, adapter) in adapters.iter().enumerate() {
        sources.extend(adapter.registered(index).unwrap());
    }
    for (index, profile) in financial.iter().enumerate() {
        archive
            .write_new(
                &format!("financial-{index}.vault"),
                &profile.secrets.seal(PASSWORD).unwrap(),
            )
            .unwrap();
    }
    let exact_registry = host.read(FILE, MAX).unwrap();
    archive.write_new(FILE, &exact_registry).unwrap();
    let gate = SyntheticBundleGate(crate::financial_backup::metadata_digest(&archive, 2).unwrap());
    let key = DatabaseKey::from_bytes([0x73; 32]);
    let bundle_path = archive.path("bundle.sqlite").unwrap();
    let manifest = bundle::snapshot(SnapshotRequest {
        principal_id: "synthetic-v2-backup",
        profile_id: &secrets.profile(),
        coverage: crate::financial_backup::coverage(2),
        sources: &sources,
        destination: &bundle_path,
        key: &key,
        authority: &gate,
    })
    .unwrap();
    assert_eq!(manifest.checkpoint_id, gate.0);
    assert_eq!(manifest.coverage, crate::financial_backup::coverage(2));
    restored
        .write_new("restored.quarantine", b"synthetic inert historical restore")
        .unwrap();
    let dependencies = RestoreFinancial::prepare(
        &archive,
        &restored,
        &restore_path,
        &secrets,
        PASSWORD,
        entries.len(),
    )
    .unwrap();
    assert_eq!(dependencies.paths.len(), 8);
    let paths = crate::vault::JOURNALS.map(|name| restored.path(name).unwrap());
    let keys = (0..4).map(|i| secrets.key(i).unwrap()).collect::<Vec<_>>();
    let templates = [
        wholepact_store::bundle::coordination_template(),
        &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
        &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE,
        &wholepact_chain::backup::TEMPLATE,
    ];
    let ids = ["coordination", "inbox", "outbox", "submission"];
    let mut targets = (0..4)
        .map(|i| RestoreTarget {
            component_id: ids[i],
            template: templates[i],
            destination: &paths[i],
            key: &keys[i],
        })
        .collect::<Vec<_>>();
    targets.extend(dependencies.targets(&bundle_path, &key).unwrap());
    bundle::restore(RestoreRequest {
        principal_id: "synthetic-v2-backup",
        profile_id: &secrets.profile(),
        archive: &bundle_path,
        key: &key,
        targets: &targets,
        authority: &gate,
    })
    .unwrap();
    dependencies.finish(PASSWORD).unwrap();
    assert_eq!(archive.read(FILE, MAX).unwrap(), exact_registry);
    assert_eq!(read_bytes(&exact_registry, &secrets).unwrap(), entries);
    let restored_entries = read(&restored, &secrets).unwrap();
    assert_eq!(restored_entries.len(), entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let destination = restore_path.with_file_name(format!("restored-financial-{index}"));
        let found = restored_entries
            .iter()
            .find(|item| item.directory == destination)
            .unwrap();
        assert_eq!(found.account, entry.account);
        assert_eq!(found.role, entry.role);
        for journal in crate::financial_profile::JOURNALS {
            assert!(destination.join(journal).is_file());
        }
        assert!(destination.join("restored.quarantine").is_file());
    }
    drop(targets);
    drop(dependencies);
    for entry in restored_entries {
        assert!(matches!(
            FinancialProfile::open(&entry.directory, &secrets.profile(), PASSWORD),
            Err(Error::Quarantined)
        ));
    }
}
fn fs_canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn generation_read_owner_matches_original_sources_without_mutation_and_rejects_replacement() {
    use crate::financial_profile::FinancialReadProfile;
    let temp = tempfile::tempdir().unwrap();
    let root = fs_canonical(temp.path());
    let host = Directory::create(&root.join("host")).unwrap();
    let secrets = Secrets::fresh().unwrap();
    let primary_path = root.join("primary");
    let participant_path = root.join("participant");
    register(
        &host,
        &secrets,
        &primary_path,
        AttachmentRole::PrimaryFinancial,
        None,
    )
    .unwrap();
    let primary = FinancialProfile::create(&primary_path, &secrets.profile(), PASSWORD).unwrap();
    let original = primary
        .manual_journal_origin_digest(&host, &secrets)
        .unwrap();
    let registry = match load(&host, &secrets).unwrap() {
        Registry::V1(value) => value,
        _ => unreachable!(),
    };
    let mut value = InventoryV2 {
        version: 2,
        owner: secrets.profile(),
        original_primary: OriginalPrimary {
            registry,
            journal_origin_digest: original.clone(),
        },
        extensions: Vec::new(),
    };
    let participant =
        FinancialProfile::create(&participant_path, &secrets.profile(), PASSWORD).unwrap();
    let actual = participant
        .manual_attachment_descriptor(&secrets.profile(), &"22".repeat(32))
        .unwrap();
    value
        .append(
            Extension::Pending {
                request: PendingAttachment {
                    operation_digest: "11".repeat(32),
                    account_id: "22".repeat(32),
                    directory: participant_path.clone(),
                    mode: AttachmentOpenMode::Create,
                },
            },
            &"33".repeat(32),
            &secrets,
        )
        .unwrap();
    value
        .append(
            Extension::Committed {
                pending_extension_digest: value.latest_digest().unwrap(),
                actual: actual.clone(),
            },
            &"33".repeat(32),
            &secrets,
        )
        .unwrap();
    write_v2(&host, &secrets, &value).unwrap();
    drop(primary);
    drop(participant);
    let before = source_tree(&root);
    let primary = FinancialReadProfile::open(&primary_path, &secrets.profile(), PASSWORD).unwrap();
    let participant =
        FinancialReadProfile::open(&participant_path, &secrets.profile(), PASSWORD).unwrap();
    assert_eq!(
        primary
            .manual_original_primary_origin_digest(&host, &secrets)
            .unwrap(),
        original
    );
    assert!(
        participant
            .manual_attachment_descriptor(&secrets.profile(), &"22".repeat(32))
            .unwrap()
            == actual
    );
    let entry = Attachment {
        directory: participant_path.clone(),
        role: AttachmentRole::ParticipantWallet,
        account: Some("22".repeat(32)),
    };
    check_read_backup_owner(&host, &secrets, &entry, &participant).unwrap();
    assert_eq!(source_tree(&root), before);
    participant
        .directory
        .write_new("unexpected-private-history", b"synthetic unexpected source")
        .unwrap();
    let before = source_tree(&root);
    assert!(check_read_backup_owner(&host, &secrets, &entry, &participant).is_err());
    assert_eq!(source_tree(&root), before);
    std::fs::remove_file(participant_path.join("unexpected-private-history")).unwrap();
    drop(participant);
    let before = source_tree(&root);
    assert!(
        FinancialReadProfile::open(
            &participant_path,
            &secrets.profile(),
            b"synthetic-wrong-password"
        )
        .is_err()
    );
    assert_eq!(source_tree(&root), before);
    std::fs::rename(
        &participant_path,
        root.join("retained-original-participant"),
    )
    .unwrap();
    drop(FinancialProfile::create(&participant_path, &secrets.profile(), PASSWORD).unwrap());
    let before = source_tree(&root);
    let replaced =
        FinancialReadProfile::open(&participant_path, &secrets.profile(), PASSWORD).unwrap();
    assert!(check_read_backup_owner(&host, &secrets, &entry, &replaced).is_err());
    assert_eq!(source_tree(&root), before);
    std::fs::rename(
        participant_path.join("transactions.sqlite"),
        root.join("retained-transactions.sqlite"),
    )
    .unwrap();
    let before = source_tree(&root);
    assert!(replaced.check_retained_owner(&secrets.profile()).is_err());
    assert_eq!(source_tree(&root), before);
    drop(replaced);
    assert!(FinancialReadProfile::open(&participant_path, &secrets.profile(), PASSWORD).is_err());
    assert!(!participant_path.join("transactions.sqlite").exists());
    assert_eq!(source_tree(&root), before);
}
#[cfg(target_os = "linux")]
fn source_tree(root: &Path) -> SourceTreeFingerprint {
    use std::os::unix::fs::MetadataExt;
    let mut result = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for child in std::fs::read_dir(directory).unwrap() {
            let path = child.unwrap().path();
            let m = std::fs::symlink_metadata(&path).unwrap();
            assert!(!m.file_type().is_symlink());
            let bytes = if m.is_dir() {
                pending.push(path.clone());
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            result.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (bytes, m.mode(), m.dev(), m.ino(), m.mtime(), m.mtime_nsec()),
            );
        }
    }
    result
}
