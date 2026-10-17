//! SYNTHETIC encrypted storage fixtures only. No native decision/publication
//! lease, live namespace owner, fixed-user path, actual key or financial act.
use super::*;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

#[derive(Clone, Copy)]
enum Damage {
    None,
    WrongMaster,
    WrongMarker,
    MissingLocator,
    ExtraEntry,
    OmittedIntent,
    WrongPublication,
    EmptyTarget,
    CommittedIncompleteTarget,
}
struct SyntheticCapture {
    expected: capsule::ArchiveScope,
    _source_lock: fs::File,
}
struct SyntheticLease<'a>(&'a SyntheticCapture);
impl capsule::ArchiveAuthority for SyntheticCapture {
    fn acquire<'a>(
        &'a self,
        scope: &capsule::ArchiveScope,
    ) -> capsule::Result<Box<dyn capsule::ArchiveLease + 'a>> {
        if scope != &self.expected {
            return Err(capsule::ArchiveError::Permission);
        }
        Ok(Box::new(SyntheticLease(self)))
    }
}
impl capsule::ArchiveLease for SyntheticLease<'_> {
    fn check_current(&self) -> capsule::Result<()> {
        self.0
            ._source_lock
            .metadata()
            .map_err(|_| capsule::ArchiveError::Storage)?;
        Ok(())
    }
}
struct Fixture {
    source: tempfile::TempDir,
    output: tempfile::TempDir,
    package_path: PathBuf,
    key_path: PathBuf,
    archive_key: DatabaseKey,
    expected_history_digest: String,
    expected_namespace_digest: String,
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn write_private(path: &Path, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
type SyntheticFileFingerprint = (u32, u64, i64, i64, Vec<u8>);
type SyntheticTreeFingerprint = BTreeMap<String, SyntheticFileFingerprint>;
fn tree(path: &Path) -> SyntheticTreeFingerprint {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, (u32, u64, i64, i64, Vec<u8>)>) {
        let mut children: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        children.sort();
        for child in children {
            let m = fs::symlink_metadata(&child).unwrap();
            if m.is_dir() {
                walk(root, &child, out);
            } else {
                out.insert(
                    child.strip_prefix(root).unwrap().display().to_string(),
                    (
                        m.mode(),
                        m.ino(),
                        m.mtime(),
                        m.mtime_nsec(),
                        fs::read(&child).unwrap(),
                    ),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(path, path, &mut out);
    out
}
fn fixture(damage: Damage) -> Fixture {
    let source = directory();
    let output = directory();
    let source_lock = fs::File::open(source.path()).unwrap();
    source_lock.try_lock().unwrap();
    let journals = source.path().join("journals");
    fs::DirBuilder::new().mode(0o700).create(&journals).unwrap();
    let request = request();
    let mut namespace = namespace(&request);
    namespace.canonical_private_root = source.path().display().to_string();
    let root_metadata = fs::metadata(source.path()).unwrap();
    let journal_metadata = fs::metadata(&journals).unwrap();
    namespace.root_identity = DirectoryIdentity {
        platform: "linux-unix-v1".into(),
        device: root_metadata.dev(),
        inode: root_metadata.ino(),
        owner_uid: root_metadata.uid(),
    };
    namespace.journals_identity = DirectoryIdentity {
        platform: "linux-unix-v1".into(),
        device: journal_metadata.dev(),
        inode: journal_metadata.ino(),
        owner_uid: journal_metadata.uid(),
    };
    let intent = intent(&namespace, request);
    let exclusion = exclusion(&namespace, &intent);
    let master = Zeroizing::new([0xb1u8; 32]); // public synthetic test constant
    let locator_key = derive_key(
        &master,
        &namespace.namespace_instance_id,
        "wholepact:witness-locator-storage-key:v1",
    )
    .unwrap();
    let registry_path = source.path().join("registry.wp");
    let registry =
        wholepact_storage_security::create_encrypted(&registry_path, &locator_key).unwrap();
    let c = registry.connection();
    c.execute_batch(storage::SCHEMA).unwrap();
    c.pragma_update(None, "application_id", storage::LOCATOR_APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", storage::LOCATOR_SCHEMA_VERSION)
        .unwrap();
    c.execute("INSERT INTO witness_locator_quarantine VALUES(1,0)", [])
        .unwrap();
    c.execute(
        "INSERT INTO witness_locator_namespace VALUES(1,?1,?2)",
        params![namespace.digest().unwrap(), &*encode(&namespace).unwrap()],
    )
    .unwrap();
    let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate).unwrap();
    let history = storage::load_exact(&tx, &namespace).unwrap();
    storage::prepare_in_transaction(&tx, &history, &intent, 1100).unwrap();
    let history = storage::load_exact(&tx, &namespace).unwrap();
    storage::exclude_in_transaction(&tx, &history, &exclusion).unwrap();
    tx.commit().unwrap();
    let history = storage::load_exact(c, &namespace).unwrap();
    let expected_history_digest = history_digest(&history).unwrap();
    let expected_namespace_digest = namespace.digest().unwrap();
    let mut descriptor = descriptor(&history);
    let account_path = source.path().join(&intent.derived_child);
    if matches!(
        damage,
        Damage::EmptyTarget | Damage::CommittedIncompleteTarget
    ) {
        let account_key = key_for(&master, &namespace, &intent).unwrap();
        let account =
            wholepact_storage_security::create_encrypted(&account_path, &account_key).unwrap();
        let state = if matches!(damage, Damage::CommittedIncompleteTarget) {
            // Synthetic typed rows only. No AuthorityJournal/ReservedBirth/native
            // decision exists in this fixture, and no live path is opened.
            let c = account.connection();
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate).unwrap();
            tx.execute_batch(NAMESPACE_ACCOUNT_TEMPLATE.create_sql)
                .unwrap();
            tx.execute(
                "INSERT INTO authority_genesis VALUES(1,?1)",
                [&*encode(&intent.request.policy).unwrap()],
            )
            .unwrap();
            tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])
                .unwrap();
            for peer in [
                &intent.request.policy.owner_certificate_digest,
                &intent.request.policy.initial_writer_certificate_digest,
            ] {
                tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])
                    .unwrap();
            }
            let record = birth(&intent);
            tx.execute(
                "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
                params![
                    record.request.operation_id,
                    record.request_digest,
                    serde_json::to_string(&record).unwrap()
                ],
            )
            .unwrap();
            tx.pragma_update(
                None,
                "application_id",
                NAMESPACE_ACCOUNT_TEMPLATE.application_id,
            )
            .unwrap();
            tx.pragma_update(
                None,
                "user_version",
                NAMESPACE_ACCOUNT_TEMPLATE.schema_version,
            )
            .unwrap();
            tx.commit().unwrap();
            let (stamp, actual_record) =
                namespace_account_stamp(c, &intent.request.policy).unwrap();
            assert!(actual_record == record);
            AccountState::Committed {
                stamp: Box::new(stamp),
            }
        } else {
            AccountState::AuthenticatedEmpty
        };
        descriptor
            .accounts
            .insert(intent.digest(&namespace).unwrap(), state);
        drop(account);
    }
    if matches!(damage, Damage::OmittedIntent) {
        descriptor.accounts.clear();
    }
    let descriptor_bytes = descriptor.bytes().unwrap();
    drop(registry);
    let marker_path = source.path().join("installation.id");
    let marker = if matches!(damage, Damage::WrongMarker) {
        h('f')
    } else {
        namespace.namespace_instance_id.clone()
    };
    write_private(&marker_path, marker.as_bytes());
    let package_path = output.path().join("synthetic-package");
    let files = NewPackage::prepare(&package_path, source.path())
        .unwrap()
        .create()
        .unwrap();
    let archive_key = DatabaseKey::from_bytes([0xb2; 32]); // public synthetic test constant
    let key_path = output.path().join("synthetic-archive-key");
    write_private(&key_path, &[0xb2; 32]);
    let archived_master = Zeroizing::new(if matches!(damage, Damage::WrongMaster) {
        [0xb3; 32]
    } else {
        *master
    });
    let mut sources = vec![
        capsule::RegisteredSource::new(
            DESCRIPTOR,
            DESCRIPTOR_ROLE,
            capsule::Source::Secret(&descriptor_bytes),
        )
        .unwrap(),
        capsule::RegisteredSource::new(
            MASTER,
            MASTER_ROLE,
            capsule::Source::Secret(&*archived_master),
        )
        .unwrap(),
        capsule::RegisteredSource::new(MARKER, MARKER_ROLE, capsule::Source::File(&marker_path))
            .unwrap(),
    ];
    if !matches!(damage, Damage::MissingLocator) {
        sources.push(
            capsule::RegisteredSource::new(
                LOCATOR,
                LOCATOR_ROLE,
                capsule::Source::Journal(&registry_path),
            )
            .unwrap(),
        );
    }
    if matches!(
        damage,
        Damage::EmptyTarget | Damage::CommittedIncompleteTarget
    ) {
        sources.push(
            capsule::RegisteredSource::new(
                &account_id(&intent.digest(&namespace).unwrap()).unwrap(),
                ACCOUNT_ROLE,
                capsule::Source::Journal(&account_path),
            )
            .unwrap(),
        );
    }
    if matches!(damage, Damage::ExtraEntry) {
        sources.push(
            capsule::RegisteredSource::new(
                "unknown-legacy-source",
                "unknown-role",
                capsule::Source::Secret(b"SYNTHETIC-INERT-EXTRA"),
            )
            .unwrap(),
        );
    }
    let node = capsule::NodeSpec {
        generation_id: namespace.namespace_instance_id.clone(),
        profile_id: namespace.witness_id.clone(),
        original_root: source.path().into(),
    };
    let destination = files.capsule();
    let capsule_id = h('a');
    let authority = SyntheticCapture {
        expected: capsule::ArchiveScope::for_snapshot(
            &destination,
            &archive_key,
            &capsule_id,
            &node,
            &sources,
            &[],
        )
        .unwrap(),
        _source_lock: source_lock,
    };
    let report = capsule::snapshot(capsule::SnapshotRequest {
        destination: &destination,
        key: &archive_key,
        capsule_id: &capsule_id,
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &authority,
    })
    .unwrap();
    let publication = Publication {
        version: 1,
        capsule_id,
        manifest_digest: if matches!(damage, Damage::WrongPublication) {
            h('f')
        } else {
            report.manifest_digest
        },
        namespace_digest: namespace.digest().unwrap(),
        source_plan_digest: descriptor.commitment().unwrap(),
        native_review_digest: h('b'),
        published_at_ms: 2200,
        permanently_historical: true,
    };
    // Shared SQL staging + actual encrypted publication/readback, never a fake
    // native approval. Corrupt fixture variants are intentionally sealed too.
    package::write_synthetic_publication_fixture(&files, &archive_key, &publication).unwrap();
    drop(files);
    Fixture {
        source,
        output,
        package_path,
        key_path,
        archive_key,
        expected_history_digest,
        expected_namespace_digest,
    }
}
#[test]
fn encrypted_package_roundtrip_retains_pending_reservation_and_exclusion() {
    let fixture = fixture(Damage::None);
    let source_before = tree(fixture.source.path());
    let package_before = tree(fixture.output.path());
    let files = PackageFiles::open(&fixture.package_path).unwrap();
    let publication = package::read_publication(&files, &fixture.archive_key).unwrap();
    let verified =
        verify_namespace_archive(capsule::inspect(&files.capsule(), &fixture.archive_key).unwrap())
            .unwrap();
    require_publication(&verified, &publication).unwrap();
    assert_eq!(
        verified.descriptor.locator_history_digest,
        fixture.expected_history_digest
    );
    assert_eq!(verified.history.prepared.len(), 1);
    assert!(verified.history.completed.is_empty());
    assert_eq!(verified.history.exclusions.len(), 1);
    assert!(matches!(
        verified.descriptor.accounts.values().next(),
        Some(AccountState::Absent)
    ));
    let retained = verified.history.prepared.values().next().unwrap();
    assert_eq!(
        retained.intent.request.policy.aggregate_budget_zatoshis,
        100
    );
    assert_eq!(retained.intent.request.initial_commit_deadline_ms, 2000);
    assert_eq!(source_before, tree(fixture.source.path()));
    assert_eq!(package_before, tree(fixture.output.path()));
    drop(verified);
    drop(files);
    let proposal = prepare_namespace_recovery_disclosure(NamespaceRecoveryInput {
        package_directory: fixture.package_path.display().to_string(),
        archive_key_file: fixture.key_path.display().to_string(),
        expected_namespace_digest: Some(fixture.expected_namespace_digest.clone()),
    })
    .unwrap();
    let display = proposal.display().unwrap();
    assert!(!display.contains(&fixture.expected_namespace_digest));
    assert!(!display.contains("synthetic-witness"));
    assert!(!display.contains(fixture.source.path().to_str().unwrap()));
    assert_eq!(source_before, tree(fixture.source.path()));
    assert_eq!(package_before, tree(fixture.output.path()));
}
#[test]
fn encrypted_capsule_semantic_corruption_is_denied_without_source_changes() {
    for damage in [
        Damage::WrongMaster,
        Damage::WrongMarker,
        Damage::MissingLocator,
        Damage::ExtraEntry,
        Damage::OmittedIntent,
        Damage::WrongPublication,
    ] {
        let fixture = fixture(damage);
        let source_before = tree(fixture.source.path());
        let package_before = tree(fixture.output.path());
        let input = NamespaceRecoveryInput {
            package_directory: fixture.package_path.display().to_string(),
            archive_key_file: fixture.key_path.display().to_string(),
            expected_namespace_digest: Some(fixture.expected_namespace_digest),
        };
        assert!(prepare_namespace_recovery_disclosure(input).is_err());
        assert_eq!(source_before, tree(fixture.source.path()));
        assert_eq!(package_before, tree(fixture.output.path()));
    }
}
#[test]
fn wrong_archive_key_and_wrong_expected_namespace_preserve_package() {
    let fixture = fixture(Damage::None);
    let before = tree(fixture.output.path());
    let source_before = tree(fixture.source.path());
    assert!(
        capsule::inspect(
            &fixture.package_path.join("capsule.wp"),
            &DatabaseKey::from_bytes([0xe1; 32])
        )
        .is_err()
    );
    assert!(
        prepare_namespace_recovery_disclosure(NamespaceRecoveryInput {
            package_directory: fixture.package_path.display().to_string(),
            archive_key_file: fixture.key_path.display().to_string(),
            expected_namespace_digest: Some(h('f'))
        })
        .is_err()
    );
    assert_eq!(before, tree(fixture.output.path()));
    assert_eq!(source_before, tree(fixture.source.path()));
}

#[test]
fn missing_publication_is_not_adopted_as_a_complete_package() {
    let fixture = fixture(Damage::None);
    fs::remove_file(fixture.package_path.join("publication.wp")).unwrap();
    let before = tree(fixture.output.path());
    let source_before = tree(fixture.source.path());
    assert!(
        prepare_namespace_recovery_disclosure(NamespaceRecoveryInput {
            package_directory: fixture.package_path.display().to_string(),
            archive_key_file: fixture.key_path.display().to_string(),
            expected_namespace_digest: None
        })
        .is_err()
    );
    assert_eq!(before, tree(fixture.output.path()));
    assert_eq!(source_before, tree(fixture.source.path()));
    assert!(!fixture.package_path.join("publication.wp").exists());
}

#[test]
fn export_refuses_protected_profile_ancestors_before_any_write() {
    for marker in [
        "account.wp",
        "profile.vault",
        "financial.vault",
        "born-backup.wp",
        "capsule.wp",
    ] {
        let source = directory();
        let parent = directory();
        let nested = parent.path().join("nested-private-output-parent");
        fs::DirBuilder::new().mode(0o700).create(&nested).unwrap();
        write_private(&parent.path().join(marker), b"SYNTHETIC-PROTECTED-MARKER");
        let destination = nested.join("new-witness-export");
        let before = tree(parent.path());
        assert!(NewPackage::prepare(&destination, source.path()).is_err());
        assert!(!destination.exists());
        assert_eq!(before, tree(parent.path()));
    }
}
#[test]
fn export_rechecks_late_markers_and_dangling_symlinks_without_creating_output() {
    let source = directory();
    let parent = directory();
    let destination = parent.path().join("new-witness-export");
    let proposal = NewPackage::prepare(&destination, source.path()).unwrap();
    // symlink_metadata must reject even a dangling protected marker.
    std::os::unix::fs::symlink(
        parent.path().join("missing-target"),
        parent.path().join("account.wp"),
    )
    .unwrap();
    assert!(proposal.check_current().is_err());
    assert!(proposal.create().is_err());
    assert!(!destination.exists());
}
#[test]
fn standalone_private_export_target_remains_supported() {
    let source = directory();
    let parent = directory();
    let destination = parent.path().join("standalone-witness-export");
    let proposal = NewPackage::prepare(&destination, source.path()).unwrap();
    assert!(!destination.exists());
    let files = proposal.create().unwrap();
    assert!(files.root().is_dir());
    assert!(files.check(false).is_ok());
    assert!(!files.capsule().exists());
    assert!(!files.publication().exists());
}

#[test]
fn encrypted_empty_target_stays_empty_without_initialization_or_completion() {
    let fixture = fixture(Damage::EmptyTarget);
    let before = tree(fixture.source.path());
    let package_before = tree(fixture.output.path());
    let files = PackageFiles::open(&fixture.package_path).unwrap();
    let publication = package::read_publication(&files, &fixture.archive_key).unwrap();
    let verified =
        verify_namespace_archive(capsule::inspect(&files.capsule(), &fixture.archive_key).unwrap())
            .unwrap();
    require_publication(&verified, &publication).unwrap();
    assert!(matches!(
        verified.descriptor.accounts.values().next(),
        Some(AccountState::AuthenticatedEmpty)
    ));
    assert!(verified.history.completed.is_empty());
    assert_eq!(verified.history.exclusions.len(), 1);
    assert_eq!(before, tree(fixture.source.path()));
    assert_eq!(package_before, tree(fixture.output.path()));
}
#[test]
fn encrypted_committed_genesis_does_not_repair_incomplete_locator() {
    let fixture = fixture(Damage::CommittedIncompleteTarget);
    let before = tree(fixture.source.path());
    let package_before = tree(fixture.output.path());
    let files = PackageFiles::open(&fixture.package_path).unwrap();
    let publication = package::read_publication(&files, &fixture.archive_key).unwrap();
    let verified =
        verify_namespace_archive(capsule::inspect(&files.capsule(), &fixture.archive_key).unwrap())
            .unwrap();
    require_publication(&verified, &publication).unwrap();
    assert!(matches!(
        verified.descriptor.accounts.values().next(),
        Some(AccountState::Committed { .. })
    ));
    assert!(verified.history.completed.is_empty());
    let (id, prepared) = verified.history.prepared.iter().next().unwrap();
    let key = key_for(
        &verified.master,
        &verified.descriptor.namespace,
        &prepared.intent,
    )
    .unwrap();
    let snapshot = verified
        .archive
        .journal(verified.archive.manifest_digest(), &account_id(id).unwrap())
        .unwrap()
        .open_ordinary(&key, &NAMESPACE_ACCOUNT_TEMPLATE)
        .unwrap();
    let summary =
        namespace_account_summary(snapshot.connection(), &prepared.intent.request.policy).unwrap();
    assert!(summary.historical_only);
    assert_eq!(summary.birth.committed_at_ms, 1500);
    assert_eq!(summary.snapshot.aggregate_budget_zatoshis, 100);
    let page = namespace_account_history_page(
        snapshot.connection(),
        &prepared.intent.request.policy,
        1,
        8,
    )
    .unwrap();
    assert!(page.historical_only);
    assert!(page.events.is_empty());
    assert_eq!(page.next_sequence, None);
    assert_eq!(before, tree(fixture.source.path()));
    assert_eq!(package_before, tree(fixture.output.path()));
}
