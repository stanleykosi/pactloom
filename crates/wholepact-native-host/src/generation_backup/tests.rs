//! Synthetic storage/capsule composition only. Production Terminal approval,
//! signer continuity, wallet freshness, network and financial effects are not
//! replaced or exercised by these test-only authorities.
use super::*;
use crate::recovery_inventory::tests::{PASSWORD, published_empty_fixture};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt};
use wholepact_storage_security::generation_archive::{CopyAuthority, CopyRequest, CopyScope};

struct CaptureGate<'a> {
    expected: ArchiveScope,
    directories: &'a [&'a Directory],
}
struct CaptureLease<'a>(&'a [&'a Directory]);
impl ArchiveLease for CaptureLease<'_> {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        for directory in self.0 {
            directory.check().map_err(|_| ArchiveError::Permission)?;
        }
        Ok(())
    }
}
impl ArchiveAuthority for CaptureGate<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &ArchiveScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if scope != &self.expected {
            return Err(ArchiveError::Permission);
        }
        let lease = CaptureLease(self.directories);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}
struct CopyGate<'a> {
    expected: CopyScope,
    directories: &'a [&'a Directory],
}
impl CopyAuthority for CopyGate<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &CopyScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if scope != &self.expected {
            return Err(ArchiveError::Permission);
        }
        let lease = CaptureLease(self.directories);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}
type Fingerprint = BTreeMap<PathBuf, (Vec<u8>, u32, u64, u64, i64, i64)>;
fn fingerprint(root: &Path) -> Fingerprint {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let bytes = if metadata.is_dir() {
                pending.push(path.clone());
                Vec::new()
            } else {
                fs::read(&path).unwrap()
            };
            result.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (
                    bytes,
                    metadata.mode(),
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            );
        }
    }
    result
}
fn structural_capture(
    output: &Directory,
    key: &DatabaseKey,
    capsule_id: &str,
    node: &NodeSpec,
    entries: &[Entry],
    directories: &[&Directory],
) -> archive::VerifiedArchive {
    structural_capture_with_parents(output, key, capsule_id, node, entries, &[], directories)
}
fn structural_capture_with_parents(
    output: &Directory,
    key: &DatabaseKey,
    capsule_id: &str,
    node: &NodeSpec,
    entries: &[Entry],
    parents: &[&archive::VerifiedArchive],
    directories: &[&Directory],
) -> archive::VerifiedArchive {
    let sources = entries
        .iter()
        .map(Entry::register)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let target = output.path(CAPSULE).unwrap();
    let gate = CaptureGate {
        expected: ArchiveScope::for_snapshot(&target, key, capsule_id, node, &sources, parents)
            .unwrap(),
        directories,
    };
    let report = archive::snapshot(SnapshotRequest {
        destination: &target,
        key,
        capsule_id,
        node,
        sources: &sources,
        parents,
        authority: &gate,
    })
    .unwrap();
    let archive = archive::inspect(&target, key).unwrap();
    assert_eq!(archive.manifest_digest(), report.manifest_digest);
    archive
}
fn attach_financial(directory: &Directory, secrets: &Secrets, path: &Path) -> FinancialSource {
    let profile =
        crate::financial_profile::FinancialProfile::create(path, &secrets.profile(), PASSWORD)
            .unwrap();
    crate::financial_inventory::register(
        directory,
        secrets,
        path,
        crate::financial_inventory::AttachmentRole::PrimaryFinancial,
        None,
    )
    .unwrap();
    drop(profile);
    FinancialSource {
        attachment: Attachment {
            directory: path.into(),
            role: crate::financial_inventory::AttachmentRole::PrimaryFinancial,
            account: None,
        },
        profile: crate::financial_profile::FinancialReadProfile::open(
            path,
            &secrets.profile(),
            PASSWORD,
        )
        .unwrap(),
    }
}

#[test]
fn complete_g1_capsule_with_current_attachment_rekeys_into_inert_quarantine() {
    let (_temp, legacy_backup, legacy_restored, successor) = published_empty_fixture();
    let directory = Directory::open(&successor).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let financial_path = successor.with_file_name("current-financial");
    let financial = vec![attach_financial(&directory, &secrets, &financial_path)];
    // Keep a committed current-journal write in WAL while capture remains
    // quiescent. No source SQLite connection is opened by the archive reader.
    let submission = wholepact_storage_security::open_encrypted_quiescent(
        directory.path("submission.sqlite").unwrap(),
        &secrets.key(3).unwrap(),
    )
    .unwrap();
    submission
        .connection()
        .execute_batch("PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    submission
        .connection()
        .execute(
            "UPDATE submission_journal_identity SET identity=?1",
            ["c7".repeat(32)],
        )
        .unwrap();
    let source_before = fingerprint(&successor);
    let financial_before = fingerprint(&financial_path);
    let old_backup_before = fingerprint(&legacy_backup);
    let old_restore_before = fingerprint(&legacy_restored);
    let metadata = capture_metadata(&directory, &secrets).unwrap();
    let entries = entries(&directory, &secrets, &metadata, &financial).unwrap();
    assert_eq!(entries.len(), 23); // 15 root/history entries plus registry pair and six financial objects.
    let node = NodeSpec {
        generation_id: metadata.descriptor().generation_id.clone(),
        profile_id: secrets.profile(),
        original_root: successor.clone(),
    };
    let capsule_id = "a1".repeat(32);
    let key_bytes = Zeroizing::new([161u8; 32]);
    let key = DatabaseKey::from_bytes(*key_bytes);
    let output_path = successor.with_file_name("generation-capsule");
    let output = Directory::create(&output_path).unwrap();
    let pending =
        PendingArchiveRecovery::new(&capsule_id, &metadata.descriptor().plan_digest, &key_bytes)
            .unwrap();
    output
        .write_new(PENDING, &pending.seal(PASSWORD).unwrap())
        .unwrap();
    let archive = structural_capture(
        &output,
        &key,
        &capsule_id,
        &node,
        &entries,
        &[&directory, &financial[0].profile.directory],
    );
    let capsule = VerifiedGenerationCapsule::open(archive).unwrap();
    assert_eq!(capsule.root().components().len(), 4);
    assert_eq!(capsule.root().current_journals().len(), 7);
    assert_eq!(capsule.root().descriptor().attachments.len(), 1);
    assert!(capsule.root().descriptor() == metadata.descriptor());
    let recovery = pending.finish(capsule.manifest_digest()).unwrap();
    output
        .write_new(RECOVERY, &recovery.seal(PASSWORD).unwrap())
        .unwrap();
    assert!(crate::generation_restore::open_archive(&output, PASSWORD).is_err());
    output.write_new("COMPLETE", COMPLETE).unwrap();
    let reopened = crate::generation_restore::open_archive(&output, PASSWORD).unwrap();
    assert_eq!(reopened.manifest_digest(), capsule.manifest_digest());
    assert!(crate::generation_restore::open_archive(&output, b"synthetic-wrong-password").is_err());
    assert!(
        source_before == fingerprint(&successor),
        "capture/native verification changed successor tree"
    );
    assert!(
        financial_before == fingerprint(&financial_path),
        "capture/native verification changed attachment tree"
    );
    assert!(
        old_backup_before == fingerprint(&legacy_backup),
        "capture changed original backup"
    );
    assert!(
        old_restore_before == fingerprint(&legacy_restored),
        "capture changed original quarantine"
    );

    let restore_path = successor.with_file_name("generation-quarantine");
    let restored = Directory::create(&restore_path).unwrap();
    let restore_key_bytes = Zeroizing::new([162u8; 32]);
    let restore_key = DatabaseKey::from_bytes(*restore_key_bytes);
    let restored_recovery = ArchiveRecovery::new(
        capsule.capsule_id(),
        capsule.manifest_digest(),
        &restore_key_bytes,
    )
    .unwrap();
    let envelope = restored_recovery.quarantine_envelope(PASSWORD).unwrap();
    restored
        .write_new("quarantine.recovery", &envelope)
        .unwrap();
    let destination = restored.path(CAPSULE).unwrap();
    let copy_gate = CopyGate {
        expected: CopyScope::for_copy(capsule.archive(), &destination, &restore_key).unwrap(),
        directories: &[&output],
    };
    let backup_before = fingerprint(&output_path);
    let copied = archive::copy(CopyRequest {
        source: capsule.archive(),
        destination: &destination,
        key: &restore_key,
        authority: &copy_gate,
    })
    .unwrap();
    assert_eq!(copied.manifest_digest, capsule.manifest_digest());
    let checked =
        VerifiedGenerationCapsule::open(archive::inspect(&destination, &restore_key).unwrap())
            .unwrap();
    assert_eq!(
        checked.root().current_provenance(),
        capsule.root().current_provenance()
    );
    assert!(archive::inspect(&destination, &key).is_err());
    assert!(Secrets::open(&envelope, PASSWORD).is_err());
    assert!(Secrets::open_recovery(&envelope, PASSWORD).is_err());
    restored
        .inventory_of(&[CAPSULE], &["profile.lock", "quarantine.recovery"])
        .unwrap();
    drop(restored);
    assert!(
        crate::generation_restore::RestoredGenerationCapsule::open(&restore_path, PASSWORD)
            .is_err()
    );
    let restored = Directory::open(&restore_path).unwrap();
    restored.write_new("RESTORED",b"wholepact-restored-generation-capsule-v1\nPermanent historical quarantine. Saved admissions are audit only. A fresh separately reviewed successor is required; no old authority is restored.\n").unwrap();
    drop(restored);
    let restored =
        crate::generation_restore::RestoredGenerationCapsule::open(&restore_path, PASSWORD)
            .unwrap();
    assert_eq!(
        restored.capsule().manifest_digest(),
        capsule.manifest_digest()
    );
    assert!(
        restored
            .external_destination(&successor.join("forbidden"))
            .is_err()
    );
    assert!(
        restored
            .external_destination(&financial_path.join("forbidden"))
            .is_err()
    );
    assert!(
        backup_before == fingerprint(&output_path),
        "restore copy/verification changed backup capsule"
    );
    assert!(
        source_before == fingerprint(&successor),
        "restore verification changed original successor"
    );
    assert!(
        financial_before == fingerprint(&financial_path),
        "restore verification changed original attachment"
    );
    assert!(!restore_path.join("profile.vault").exists());
    assert!(!restore_path.join("coordination.sqlite").exists());
}

#[test]
fn native_capsule_rejects_structurally_complete_missing_roles_keys_and_metadata() {
    let (_temp, _backup, _restored, successor) = published_empty_fixture();
    let directory = Directory::open(&successor).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let metadata = capture_metadata(&directory, &secrets).unwrap();
    let node = NodeSpec {
        generation_id: metadata.descriptor().generation_id.clone(),
        profile_id: secrets.profile(),
        original_root: successor.clone(),
    };
    let key = DatabaseKey::from_bytes([163; 32]);
    let before = fingerprint(&successor);
    for case in [
        "missing-history",
        "wrong-role",
        "wrong-key",
        "wrong-metadata",
        "missing-commit",
    ] {
        let mut inputs = entries(&directory, &secrets, &metadata, &[]).unwrap();
        match case {
            "missing-history" => inputs.retain(|entry| entry.id != "history-inbox"),
            "missing-commit" => inputs.retain(|entry| entry.id != "host-commit"),
            "wrong-role" => {
                inputs
                    .iter_mut()
                    .find(|entry| entry.id == "root-inbox")
                    .unwrap()
                    .role = "current-outbox".into()
            }
            "wrong-key" => {
                let input = &mut inputs
                    .iter_mut()
                    .find(|entry| entry.id == "host-source-material")
                    .unwrap()
                    .input;
                let Input::Secret(bytes) = input else {
                    panic!("synthetic key input")
                };
                *bytes.last_mut().unwrap() ^= 1;
            }
            "wrong-metadata" => {
                let input = &mut inputs
                    .iter_mut()
                    .find(|entry| entry.id == "host-source-descriptor")
                    .unwrap()
                    .input;
                let Input::Secret(bytes) = input else {
                    panic!("synthetic descriptor input")
                };
                let mut descriptor: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                descriptor["generation_id"] = serde_json::Value::String("ef".repeat(32));
                *bytes = Zeroizing::new(serde_json::to_vec(&descriptor).unwrap());
            }
            _ => unreachable!(),
        }
        let output =
            Directory::create(&successor.with_file_name(format!("negative-{case}"))).unwrap();
        let archive = structural_capture(
            &output,
            &key,
            &"a3".repeat(32),
            &node,
            &inputs,
            &[&directory],
        );
        assert!(
            VerifiedGenerationCapsule::open(archive).is_err(),
            "native accepted {case}"
        );
        assert!(
            before == fingerprint(&successor),
            "negative {case} changed original tree"
        );
    }
}

/// Real capsule lifecycle fixture for zero-account layered publication tests.
/// This helper is compiled only in this synthetic test module. It never supplies
/// an ordinary profile or a forged sealed source/admission to production code.
pub(crate) fn synthetic_capsule_quarantine(
    profile: &Path,
    backup: &Path,
    quarantine: &Path,
    key_tag: u8,
) -> crate::generation_restore::RestoredGenerationCapsule {
    synthetic_capsule_quarantine_for_accounts(
        profile,
        backup,
        quarantine,
        key_tag,
        &std::collections::BTreeSet::new(),
    )
}
fn synthetic_capsule_quarantine_for_accounts(
    profile: &Path,
    backup: &Path,
    quarantine: &Path,
    key_tag: u8,
    expected_accounts: &std::collections::BTreeSet<String>,
) -> crate::generation_restore::RestoredGenerationCapsule {
    use crate::recovery_generation::archive_history::{
        capture_layered_metadata, open_layered_parent, source_plan_version,
    };
    let directory = Directory::open(profile).unwrap();
    directory.external_destination(backup).unwrap();
    directory.external_destination(quarantine).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let before = fingerprint(profile);
    let (metadata, parent) = match source_plan_version(&directory, &secrets).unwrap() {
        1 => (capture_metadata(&directory, &secrets).unwrap(), None),
        2 => {
            let (_, parent) = open_layered_parent(&directory, &secrets).unwrap();
            let metadata = capture_layered_metadata(&directory, &secrets, &parent).unwrap();
            (metadata, Some(parent))
        }
        _ => panic!("unsupported synthetic source"),
    };
    assert!(metadata.descriptor().attachments.is_empty());
    let parents = parent
        .iter()
        .map(VerifiedGenerationCapsule::archive)
        .collect::<Vec<_>>();
    let entries = entries(&directory, &secrets, &metadata, &[]).unwrap();
    let node = NodeSpec {
        generation_id: metadata.descriptor().generation_id.clone(),
        profile_id: secrets.profile(),
        original_root: profile.into(),
    };
    let key_bytes = Zeroizing::new([key_tag; 32]);
    let key = DatabaseKey::from_bytes(*key_bytes);
    let capsule_id = format!("{key_tag:02x}").repeat(32);
    let output = Directory::create(backup).unwrap();
    let pending =
        PendingArchiveRecovery::new(&capsule_id, &metadata.descriptor().plan_digest, &key_bytes)
            .unwrap();
    output
        .write_new(PENDING, &pending.seal(PASSWORD).unwrap())
        .unwrap();
    let archive = structural_capture_with_parents(
        &output,
        &key,
        &capsule_id,
        &node,
        &entries,
        &parents,
        &[&directory],
    );
    let capsule = VerifiedGenerationCapsule::open(archive).unwrap();
    assert_eq!(
        capsule.root().current_semantics().accounts(),
        expected_accounts
    );
    output
        .write_new(
            RECOVERY,
            &pending
                .finish(capsule.manifest_digest())
                .unwrap()
                .seal(PASSWORD)
                .unwrap(),
        )
        .unwrap();
    output.write_new("COMPLETE", COMPLETE).unwrap();
    let verified = crate::generation_restore::open_archive(&output, PASSWORD).unwrap();
    assert_eq!(verified.manifest_digest(), capsule.manifest_digest());
    let backup_before = fingerprint(backup);
    let restored = Directory::create(quarantine).unwrap();
    let restored_key_bytes = Zeroizing::new([key_tag.checked_add(1).unwrap(); 32]);
    let restored_key = DatabaseKey::from_bytes(*restored_key_bytes);
    let recovery = ArchiveRecovery::new(
        capsule.capsule_id(),
        capsule.manifest_digest(),
        &restored_key_bytes,
    )
    .unwrap();
    restored
        .write_new(
            "quarantine.recovery",
            &recovery.quarantine_envelope(PASSWORD).unwrap(),
        )
        .unwrap();
    let destination = restored.path(CAPSULE).unwrap();
    let gate = CopyGate {
        expected: CopyScope::for_copy(capsule.archive(), &destination, &restored_key).unwrap(),
        directories: &[&output],
    };
    archive::copy(CopyRequest {
        source: capsule.archive(),
        destination: &destination,
        key: &restored_key,
        authority: &gate,
    })
    .unwrap();
    let verified =
        VerifiedGenerationCapsule::open(archive::inspect(&destination, &restored_key).unwrap())
            .unwrap();
    assert_eq!(verified.manifest_digest(), capsule.manifest_digest());
    restored.write_new("RESTORED",b"wholepact-restored-generation-capsule-v1\nPermanent historical quarantine. Saved admissions are audit only. A fresh separately reviewed successor is required; no old authority is restored.\n").unwrap();
    drop(restored);
    let restored =
        crate::generation_restore::RestoredGenerationCapsule::open(quarantine, PASSWORD).unwrap();
    assert!(
        before == fingerprint(profile),
        "synthetic complete lifecycle changed source"
    );
    assert!(
        backup_before == fingerprint(backup),
        "synthetic restore changed backup"
    );
    restored
}

#[path = "construction_v3_capsule_tests.rs"]
mod construction_v3;

#[cfg(feature = "manual-admission")]
#[path = "common_context_v4_capsule_tests.rs"]
mod common_context_v4;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "transport_v5_capsule_tests.rs"]
mod transport_v5;
