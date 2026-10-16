//! Modeled audit rows over actual sealed encrypted synthetic generations.
//! Supported bundle/archive integrity APIs supply immutable snapshot owners.
//! Synthetic gates are storage test fixtures, never native or financial consent.
use super::*;
use crate::manual_enrollment::{
    ManualActionAudit, ManualEnrollmentAudit, ManualExclusionAudit, append_modeled_layer_audits,
};
use std::collections::BTreeMap;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
use wholepact_storage_security::generation_archive as archive;
use wholepact_storage_security::{DatabaseKey, bundle as storage_bundle};

struct SyntheticBundleGate;
impl storage_bundle::BundleLease for SyntheticBundleGate {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-layer-root"
    }
}
impl storage_bundle::BundleAuthority for SyntheticBundleGate {
    fn acquire<'a>(
        &'a self,
        scope: &storage_bundle::BundleScope<'_>,
    ) -> std::result::Result<Box<dyn storage_bundle::BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-layer-admin"
            || scope.profile_id != "synthetic-layer-profile"
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(SyntheticBundleGate))
    }
}
struct SyntheticSourceAdapter<'a> {
    store: &'a Store,
    template: &'static JournalTemplate,
}
impl storage_bundle::JournalAdapter for SyntheticSourceAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        self.template
    }
    fn read_locked(
        &self,
        permit: &storage_bundle::BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> std::result::Result<(), BundleError>,
    ) -> std::result::Result<(), BundleError> {
        permit.check(self)?;
        let c = self
            .store
            .connection
            .lock()
            .map_err(|_| BundleError::Storage)?;
        crate::backup::validate_live_schema_and_rows(&c, self.template.schema_version)
            .map_err(|_| BundleError::Integrity)?;
        visitor(&c)
    }
}
struct SyntheticArchiveGate(archive::ArchiveScope);
struct SyntheticArchiveLease;
impl archive::ArchiveAuthority for SyntheticArchiveGate {
    fn acquire<'a>(
        &'a self,
        scope: &archive::ArchiveScope,
    ) -> std::result::Result<Box<dyn archive::ArchiveLease + 'a>, archive::ArchiveError> {
        if scope != &self.0 {
            return Err(archive::ArchiveError::Permission);
        }
        Ok(Box::new(SyntheticArchiveLease))
    }
}
impl archive::ArchiveLease for SyntheticArchiveLease {
    fn check_current(&self) -> std::result::Result<(), archive::ArchiveError> {
        Ok(())
    }
}

#[path = "manual_initial_audit_layers.rs"]
mod initial_publication;
#[path = "manual_roster_audit_layers.rs"]
mod roster_publication;

struct EncryptedFixture {
    // Keep the owning lock until the connection has closed.
    store: Store,
    _lock: fs::File,
    directory: PathBuf,
    source: RecoveryProvenance,
}
// Successor copies intentionally use the same fixed synthetic key. These real
// sealed storage fixtures do not qualify native consent, independent-key native
// publication, or live signer/witness admission.
const SYNTHETIC_KEY: [u8; 32] = [0x71; 32];
fn private_destination(directory: &Path) -> fs::File {
    fs::create_dir(directory).unwrap();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = fs::File::open(directory).unwrap();
    lock.try_lock().unwrap();
    lock
}
fn root_encrypted(directory: &Path) -> EncryptedFixture {
    root_encrypted_for_schema(
        directory,
        crate::SCHEMA_VERSION,
        coordination_successor_template().schema_version,
    )
}
fn root_encrypted_for_schema(
    directory: &Path,
    source_version: i64,
    recovered_version: i64,
) -> EncryptedFixture {
    let lock = private_destination(directory);
    let input = tempfile::tempdir().unwrap();
    fs::set_permissions(input.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let key = DatabaseKey::from_bytes(SYNTHETIC_KEY);
    let source_key = DatabaseKey::from_bytes([0x72; 32]);
    let bundle_key = DatabaseKey::from_bytes([0x73; 32]);
    let restored_key = DatabaseKey::from_bytes([0x74; 32]);
    let source_store =
        Store::create_encrypted(input.path().join("source.sqlite"), &source_key).unwrap();
    agreement(&source_store, "original-agreement");
    source_store
        .record_effect_intent(
            "original-effect",
            "send",
            "original-agreement",
            &"d".repeat(64),
            "retained:original",
        )
        .unwrap();
    source_store
        .initialize_authority_account("synthetic-account", 7)
        .unwrap();
    {
        let c = source_store.connection.lock().unwrap();
        insert_exposure(&c, &release("charged", "111"), "consumed");
        insert_exposure(&c, &release("expired", "222"), "expired_observed");
        // Authentic legacy synthetic fixture before any archive or sealed marker
        // exists. Only the compiled pre-V3 schema/rows may enter this adapter.
        c.pragma_update(None, "user_version", source_version)
            .unwrap();
    }
    let template = crate::bundle::coordination_template_for_schema(source_version).unwrap();
    let bundle_path = input.path().join("bundle.sqlite");
    let restored_path = input.path().join("restored.sqlite");
    let adapter = SyntheticSourceAdapter {
        store: &source_store,
        template,
    };
    let sources = [storage_bundle::RegisteredJournal::new("coordination", &adapter).unwrap()];
    storage_bundle::snapshot(storage_bundle::SnapshotRequest {
        principal_id: "synthetic-layer-admin",
        profile_id: "synthetic-layer-profile",
        coverage: storage_bundle::Coverage {
            present: BTreeMap::from([(
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            )]),
            absent: [
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]
            .into_iter()
            .collect(),
        },
        sources: &sources,
        destination: &bundle_path,
        key: &bundle_key,
        authority: &SyntheticBundleGate,
    })
    .unwrap();
    storage_bundle::restore(storage_bundle::RestoreRequest {
        principal_id: "synthetic-layer-admin",
        profile_id: "synthetic-layer-profile",
        archive: &bundle_path,
        key: &bundle_key,
        targets: &[storage_bundle::RestoreTarget {
            component_id: "coordination",
            template,
            destination: &restored_path,
            key: &restored_key,
        }],
        authority: &SyntheticBundleGate,
    })
    .unwrap();
    let verified = VerifiedRecoveryComponent::open(
        storage_bundle::history::HistoryOpenRequest {
            archive: &bundle_path,
            archive_key: &bundle_key,
            restored_component: &restored_path,
            restored_key: &restored_key,
            component_id: "coordination",
        },
        template,
    )
    .unwrap();
    let inventory = StoreRecoveryInventory::inspect(&verified).unwrap();
    let generation = binding(1);
    let path = directory.join("coordination.sqlite");
    // Real storage-owned marker; no hand-built marker or protected-open bypass.
    storage_bundle::recovery::generation::initialize_coordination_generation(
        &verified,
        template,
        coordination_successor_template_for_schema(recovered_version).unwrap(),
        &generation,
        &path,
        &key,
        |c| initialize_successor(c, &verified, &inventory).map_err(|_| BundleError::Integrity),
    )
    .unwrap();
    let store =
        Store::open_recovered_generation(&path, &key, &generation, verified.provenance()).unwrap();
    store
        .add_recovery_obligation_fences(
            &generation,
            &BTreeSet::from(["witness-generation-one".into()]),
        )
        .unwrap();
    EncryptedFixture {
        store,
        _lock: lock,
        directory: directory.into(),
        source: verified.provenance().clone(),
    }
}
impl EncryptedFixture {
    fn snapshot(&self) -> RecoveredStoreSnapshot {
        RecoveredStoreSnapshot::open(
            &self.directory.join("coordination.sqlite"),
            &DatabaseKey::from_bytes(SYNTHETIC_KEY),
            self.store.recovered_binding.as_ref().unwrap(),
            &self.source,
        )
        .unwrap()
    }
}

fn advance_encrypted(parent: &EncryptedFixture, directory: &Path, index: u8) -> EncryptedFixture {
    advance_encrypted_for_schema(
        parent,
        directory,
        index,
        coordination_layered_successor_template().schema_version,
    )
}
fn advance_encrypted_for_schema(
    parent: &EncryptedFixture,
    directory: &Path,
    index: u8,
    version: i64,
) -> EncryptedFixture {
    // The test owns every supported writer and keeps this mutex plus the
    // original directory lock throughout source inspection and typed capture.
    // Do not checkpoint or open the source through another writable connection.
    let _source_quiescence = parent.store.connection.lock().unwrap();
    let before = tree(&parent.directory);
    let snapshot = parent.snapshot();
    let parent_binding = parent.store.recovered_binding.as_ref().unwrap();
    let template = generation_template(snapshot.snapshot.connection()).unwrap();
    let capsule = tempfile::tempdir().unwrap();
    fs::set_permissions(capsule.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let archive_path = capsule.path().join("parent.sqlite");
    let archive_key = DatabaseKey::from_bytes([0x75; 32]);
    let capsule_id = format!("{index:02x}").repeat(32);
    let source_path = parent.directory.join("coordination.sqlite");
    let sources = [archive::RegisteredSource::new(
        "coordination",
        "current-coordination",
        archive::Source::Journal(&source_path),
    )
    .unwrap()];
    let node = archive::NodeSpec {
        generation_id: parent_binding.generation_id().into(),
        profile_id: "synthetic-layer-profile".into(),
        original_root: parent.directory.clone(),
    };
    let authority = SyntheticArchiveGate(
        archive::ArchiveScope::for_snapshot(
            &archive_path,
            &archive_key,
            &capsule_id,
            &node,
            &sources,
            &[],
        )
        .unwrap(),
    );
    archive::snapshot(archive::SnapshotRequest {
        destination: &archive_path,
        key: &archive_key,
        capsule_id: &capsule_id,
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &authority,
    })
    .unwrap();
    let archived = archive::inspect(&archive_path, &archive_key).unwrap();
    let journal = archived
        .journal(archived.manifest_digest(), "coordination")
        .unwrap();
    let key = DatabaseKey::from_bytes(SYNTHETIC_KEY);
    let sealed = journal
        .open_generation(&key, parent_binding, &parent.source, template)
        .unwrap();
    let c = sealed.snapshot().connection();
    validate_archived_source(&sealed).unwrap();
    let source = sealed.source_provenance().clone();
    let inventory = inventory(c, &source).unwrap();
    let (rows, tables, bytes) = capture(c).unwrap();
    let ordinal = generation_depth(c).unwrap();
    let generation = binding(index);
    let header = Layer {
        version: 2,
        ordinal,
        parent_generation_id: parent_binding.generation_id().into(),
        parent_inventory_digest: parent_binding.inventory_digest().into(),
        parent_provenance: parent.source.clone(),
        parent_schema_version: template.schema_version,
        parent_destination_identity: current_identity(c, parent_binding).unwrap(),
        destination_identity: format!("{:02x}", index + 112).repeat(32),
        generation_id: generation.generation_id().into(),
        inventory_digest: generation.inventory_digest().into(),
        source_provenance: source.clone(),
        previous_layer_digest: if ordinal > 1 {
            Some(
                c.query_row(
                    "SELECT digest FROM store_generation_layers WHERE ordinal=?1",
                    [(ordinal - 1) as i64],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        } else {
            None
        },
        tables,
        rows: rows.len(),
        bytes,
    };
    let lock = private_destination(directory);
    let destination = directory.join("coordination.sqlite");
    initialize_coordination_generation_from_archive(
        &sealed,
        template,
        coordination_layered_successor_template_for_schema(version).unwrap(),
        &generation,
        &destination,
        &key,
        |c| initialize_layer(c, &header, &rows, &inventory).map_err(|_| BundleError::Integrity),
    )
    .unwrap();
    let store = Store::open_recovered_generation(&destination, &key, &generation, &source).unwrap();
    snapshot.check_source_unchanged().unwrap();
    assert_eq!(
        tree(&parent.directory),
        before,
        "the entire encrypted source stays unchanged"
    );
    EncryptedFixture {
        store,
        _lock: lock,
        directory: directory.into(),
        source,
    }
}

// Read atime is excluded. Every other relevant identity/ownership/time and every
// byte (including WAL/SHM and nested inventory) is compared before/after capture.
#[derive(PartialEq, Eq)]
struct FileState {
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Option<Vec<u8>>,
}
impl std::fmt::Debug for FileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::Digest;
        let bytes_len_sha256 = self
            .bytes
            .as_ref()
            .map(|b| (b.len(), hex::encode(sha2::Sha256::digest(b))));
        f.debug_struct("FileState")
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("links", &self.links)
            .field("device", &self.device)
            .field("inode", &self.inode)
            .field("len", &self.len)
            .field("modified", &self.modified)
            .field("changed", &self.changed)
            .field("bytes_len_sha256", &bytes_len_sha256)
            .finish()
    }
}
fn tree(root: &Path) -> BTreeMap<PathBuf, FileState> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, FileState>) {
        let m = fs::symlink_metadata(path).unwrap();
        assert!(m.is_file() || m.is_dir());
        out.insert(
            path.strip_prefix(root).unwrap().into(),
            FileState {
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                links: m.nlink(),
                device: m.dev(),
                inode: m.ino(),
                len: m.len(),
                modified: (m.mtime(), m.mtime_nsec()),
                changed: (m.ctime(), m.ctime_nsec()),
                bytes: m.is_file().then(|| fs::read(path).unwrap()),
            },
        );
        if m.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn assert_retained(
    store: &Store,
    expected: &[(
        ManualEnrollmentAudit,
        ManualActionAudit,
        ManualExclusionAudit,
    )],
) {
    let c = store.connection.lock().unwrap();
    let generation = store.recovered_binding.as_ref().unwrap();
    let projection = crate::recovery::project_manual_snapshot(&c, generation).unwrap();
    assert_eq!(projection.enrollments().len(), expected.len());
    assert_eq!(projection.scope_audits().len(), expected.len());
    assert_eq!(projection.exclusions().len(), expected.len());
    assert_eq!(projection.continuations().len(), expected.len());
    for (enrollment, action, exclusion) in expected {
        assert!(projection.v1_enrollments().contains(enrollment));
        assert!(projection.scope_audits().contains(action));
        assert!(projection.exclusions().contains(exclusion));
        let continuation = projection
            .continuations()
            .iter()
            .find(|a| a.enrollment_audit_digest == enrollment.digest().unwrap())
            .unwrap();
        continuation.validate_for(enrollment).unwrap();
        require_fence(
            &c,
            "record",
            &format!(
                "{}:{}",
                crate::manual_enrollment::CONTINUATION,
                continuation.digest().unwrap()
            ),
        )
        .unwrap();
        require_fence(&c, "operation", &continuation.operation_id).unwrap();
        require_fence(&c, "idempotency", &continuation.request_identity_digest).unwrap();
        for alias in &enrollment.aliases {
            require_fence(&c, "account", alias).unwrap();
        }
        require_fence(&c, "agreement", &enrollment.terms.scope.agreement_id).unwrap();
        require_fence(&c, "obligation", &enrollment.terms.scope.obligation_id).unwrap();
        for (kind, digest) in [
            (
                crate::manual_enrollment::ENROLLMENT,
                enrollment.digest().unwrap(),
            ),
            (crate::manual_enrollment::SCOPE, action.digest().unwrap()),
            (
                crate::manual_enrollment::EXCLUSION,
                exclusion.digest().unwrap(),
            ),
        ] {
            require_fence(&c, "record", &format!("{kind}:{digest}")).unwrap();
        }
    }
}

#[test]
fn encrypted_manual_audits_continuations_and_exclusions_survive_two_modeled_layers() {
    let temporary = tempfile::tempdir().unwrap();
    let one = root_encrypted(&temporary.path().join("g1"));
    let first = append_modeled_layer_audits(&one.store, 1);
    let two = advance_encrypted(&one, &temporary.path().join("g2"), 2);
    assert_retained(&two.store, std::slice::from_ref(&first));
    let second = append_modeled_layer_audits(&two.store, 2);
    let three = advance_encrypted(&two, &temporary.path().join("g3"), 3);
    assert_retained(&three.store, &[first.clone(), second.clone()]);
    assert_eq!(
        three.store.settled_debit("synthetic-account").unwrap(),
        "111"
    );
    assert_eq!(
        three.store.outstanding_debit("synthetic-account").unwrap(),
        "222"
    );
    assert!(three.store.recovery_state().unwrap().recovery_required);
    for (enrollment, action, _) in [first, second] {
        assert!(
            three
                .store
                .authority_account(&enrollment.terms.identity.account_id)
                .unwrap()
                .is_none()
        );
        assert!(
            three
                .store
                .recovery_record_is_historical("agreement", &enrollment.terms.scope.agreement_id)
                .unwrap()
        );
        assert!(
            three
                .store
                .settlement_obligation_requires_recovery(&enrollment.terms.scope.obligation_id)
                .unwrap()
        );
        assert!(matches!(
            three.store.require_ordinary_financial_lineage(
                &enrollment.terms.scope.agreement_id,
                &enrollment.terms.scope.obligation_id,
                &enrollment.terms.scope.principal_id,
                None,
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(
            three
                .store
                .record_effect_intent(
                    &action.intent.operation_id,
                    "send",
                    &enrollment.terms.scope.agreement_id,
                    &"a".repeat(64),
                    "synthetic:no-effect"
                )
                .is_err()
        );
    }
    let c = three.store.connection.lock().unwrap();
    assert_eq!(generation_depth(&c).unwrap(), 3);
    validate_generation(&c, &three.source, &binding(3)).unwrap();
}

#[test]
fn encrypted_continuation_inventory_rejects_omission_and_alteration_without_source_writes() {
    let temporary = tempfile::tempdir().unwrap();
    let original = root_encrypted(&temporary.path().join("original"));
    append_modeled_layer_audits(&original.store, 1);
    let _quiescence = original.store.connection.lock().unwrap();
    let before = tree(&original.directory);
    let snapshot = original.snapshot();
    let c = snapshot.snapshot.connection();
    let projection = crate::recovery::project_manual_snapshot(
        c,
        original.store.recovered_binding.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(projection.continuations().len(), 1);
    let retained = &projection.continuations()[0];
    assert_eq!(retained.evidence.admission.attempt_sequence, 2);
    assert_eq!(retained.evidence.admission.admitted_at_ms, 1001);
    assert_eq!(retained.evidence.admission.admission_deadline_ms, 2000);
    assert_eq!(retained.evidence.current.writer_session_expires_at_ms, 9000);
    inventory(c, &original.source).unwrap();
    let rows: Vec<(String, Vec<RecoveryCell>)> = BASE
        .iter()
        .flat_map(|table| {
            read_rows(c, table, "")
                .unwrap()
                .into_iter()
                .map(move |row| {
                    let cells = row
                        .cells
                        .into_iter()
                        .map(|cell| match cell {
                            Value::Null => RecoveryCell::Null,
                            Value::String(value) => RecoveryCell::Text(value),
                            Value::Number(value) => RecoveryCell::Integer(value.as_i64().unwrap()),
                            _ => panic!("unexpected synthetic SQL cell"),
                        })
                        .collect();
                    (table.name.into(), cells)
                })
        })
        .collect();
    // These are inert extracted cell vectors. No raw data path can produce a
    // native decision, archived owner or live Store admission.
    let omitted: Vec<_> = rows.iter().filter(|(table, cells)| !(table == "records"
        && matches!(&cells[0], RecoveryCell::Text(kind) if kind == crate::manual_enrollment::ENROLLMENT))).collect();
    assert!(
        StoreRecoveryInventory::inspect_rows(
            &original.source,
            omitted
                .iter()
                .map(|(table, cells)| (table.as_str(), cells.as_slice())),
            true
        )
        .is_err()
    );
    for path in [
        "/provider_enrollment_ref",
        "/evidence/current/writer_session_digest",
        "/evidence/admission/attempt_digest",
        "/evidence/admission/admission_deadline_ms",
    ] {
        let mut changed: Vec<(String, Vec<RecoveryCell>)> = rows
            .iter()
            .map(|(table, cells)| {
                (
                    table.clone(),
                    cells
                        .iter()
                        .map(|cell| match cell {
                            RecoveryCell::Null => RecoveryCell::Null,
                            RecoveryCell::Integer(value) => RecoveryCell::Integer(*value),
                            RecoveryCell::Text(value) => RecoveryCell::Text(value.clone()),
                            _ => panic!("unexpected synthetic SQL cell"),
                        })
                        .collect(),
                )
            })
            .collect();
        let (_, cells) = changed.iter_mut().find(|(table, cells)| table == "records"
            && matches!(&cells[0], RecoveryCell::Text(kind) if kind == crate::manual_enrollment::CONTINUATION)).unwrap();
        let RecoveryCell::Text(encoded) = &cells[3] else {
            panic!("synthetic payload");
        };
        let mut payload: Value = serde_json::from_str(encoded).unwrap();
        *payload.pointer_mut(path).unwrap() = if path.ends_with("_ms") {
            2001.into()
        } else {
            "6".repeat(64).into()
        };
        cells[3] = RecoveryCell::Text(serde_json::to_string(&payload).unwrap());
        assert!(
            StoreRecoveryInventory::inspect_rows(
                &original.source,
                changed
                    .iter()
                    .map(|(table, cells)| (table.as_str(), cells.as_slice())),
                true
            )
            .is_err()
        );
    }
    assert_eq!(tree(&original.directory), before);
    let charges: Vec<(String, String)> = c
        .prepare("SELECT maximum_debit,state FROM authority_exposures ORDER BY authorization_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        charges,
        vec![
            ("111".into(), "consumed".into()),
            ("222".into(), "outstanding_uncertain".into())
        ]
    );
}

#[path = "construction_claim_layers.rs"]
mod construction_claims;

#[path = "construction_claim_v3_layers.rs"]
mod construction_claims_v3;
