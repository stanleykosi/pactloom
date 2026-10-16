//! Actual encrypted immutable generation readers over inert historical rows.
//! No native owner, construction token, live witness or financial permission.
//! Live Store reads are deliberately not used inside preservation assertions:
//! SQLite WAL bookkeeping belongs only to private snapshot copies here.
use super::*;
use crate::recovery::RecoveredStoreSnapshot;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{self, *},
};

#[path = "construction_staging_preservation_tests.rs"]
mod layered_staging;

// Synthetic bundle integrity fixture, never native or financial consent.
struct FixtureArchiveGate;
impl BundleLease for FixtureArchiveGate {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-inspection-history"
    }
}
impl BundleAuthority for FixtureArchiveGate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-history-admin"
            || scope.profile_id != "synthetic-profile"
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(FixtureArchiveGate))
    }
}
fn key(byte: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([byte; 32])
}

struct Fixture {
    store: Store,
    claim: ManualRosterConstructionClaimV2,
    receipt: Option<ManualRosterConstructionCheckpointV2>,
    root: ManualEnrollmentInitialPublicationV2,
    binding: bundle::recovery::generation::GenerationBinding,
    provenance: bundle::recovery::RecoveryProvenance,
    _source_store: Store,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new(with_receipt: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source_store =
            Store::create_encrypted(directory.path().join("source.sqlite"), &key(0x60)).unwrap();
        let context = crate::CommandContext::for_request(
            "synthetic-principal",
            "synthetic-inherited-key",
            &serde_json::json!(["synthetic inherited history"]),
        )
        .unwrap();
        source_store.create_agreement(&context, "synthetic-inherited-agreement", serde_json::json!({"view":{"agreement":{"agreement_id":"synthetic-inherited-agreement","obligation_id":"synthetic-inherited-obligation"}}})).unwrap();
        let archive = directory.path().join("bundle.sqlite");
        let restored = directory.path().join("restored.sqlite");
        {
            let adapter = crate::bundle::CoordinationBundleAdapter::new(&source_store).unwrap();
            let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
            let coverage = Coverage {
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
            };
            bundle::snapshot(SnapshotRequest {
                principal_id: "synthetic-history-admin",
                profile_id: "synthetic-profile",
                coverage,
                sources: &sources,
                destination: &archive,
                key: &key(0x62),
                authority: &FixtureArchiveGate,
            })
            .unwrap();
        }
        bundle::restore(RestoreRequest {
            principal_id: "synthetic-history-admin",
            profile_id: "synthetic-profile",
            archive: &archive,
            key: &key(0x62),
            targets: &[RestoreTarget {
                component_id: "coordination",
                template: crate::bundle::coordination_template(),
                destination: &restored,
                key: &key(0x63),
            }],
            authority: &FixtureArchiveGate,
        })
        .unwrap();
        let source = bundle::recovery::VerifiedRecoveryComponent::open(
            bundle::history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &key(0x62),
                restored_component: &restored,
                restored_key: &key(0x63),
                component_id: "coordination",
            },
            crate::bundle::coordination_template(),
        )
        .unwrap();
        let binding =
            bundle::recovery::generation::GenerationBinding::new(&h('a'), &h('b')).unwrap();
        let path = directory.path().join("coordination.sqlite");
        Store::reconstruct_recovered_generation(&source, &path, &key(0x61), &binding).unwrap();
        let store =
            Store::open_recovered_generation(&path, &key(0x61), &binding, source.provenance())
                .unwrap();
        let mut root = crate::manual_enrollment::tests::initial_publication::initial_fixture();
        let target = store.manual_store_target().unwrap();
        let terms = &mut root.evidence.request.enrollment.terms;
        terms.identity.account_id = h('3');
        terms.identity.full_viewing_key_digest = h('4');
        terms.host.generation_id = target.generation_id().into();
        terms.host.inventory_digest = target.inventory_digest().into();
        terms.host.store_destination_identity = target.store_destination_identity().into();
        root.aliases = BTreeSet::from([h('3')]);
        root.evidence.admission.exact_request_digest = root.evidence.request.digest().unwrap();
        root.validate().unwrap();
        drop(target);
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
                rusqlite::params![
                    INITIAL_PUBLICATION_V2,
                    root.digest().unwrap(),
                    serde_json::to_string(&root).unwrap()
                ],
            )
            .unwrap();
        let (claim, receipt) = append_modeled_construction_rows(&store, &root, with_receipt);
        fs::create_dir(directory.path().join("nested-preserved")).unwrap();
        fs::write(
            directory.path().join("nested-preserved/untouched"),
            b"synthetic history sentinel",
        )
        .unwrap();
        Self {
            store,
            claim,
            receipt,
            root,
            binding,
            provenance: source.provenance().clone(),
            _source_store: source_store,
            directory,
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.path().join("coordination.sqlite")
    }
    fn snapshot(&self) -> crate::Result<RecoveredStoreSnapshot> {
        RecoveredStoreSnapshot::open(&self.path(), &key(0x61), &self.binding, &self.provenance)
    }
}

#[test]
fn encrypted_exact_claim_receipt_and_absence_reads_preserve_complete_tree() {
    for with_receipt in [false, true] {
        let f = Fixture::new(with_receipt);
        let snapshot = unchanged(f.directory.path(), || f.snapshot().unwrap());
        let (claim, receipt) = unchanged(f.directory.path(), || {
            snapshot
                .manual_roster_construction_evidence_v2(
                    &f.claim.principal_id,
                    &f.claim.construction_key,
                )
                .unwrap()
                .unwrap()
        });
        assert!(claim == f.claim);
        assert!(receipt == f.receipt);
        assert_eq!(receipt.is_some(), with_receipt);
        unchanged(f.directory.path(), || {
            assert!(
                snapshot
                    .manual_roster_construction_evidence_v2(
                        "wrong-principal",
                        &f.claim.construction_key
                    )
                    .unwrap()
                    .is_none()
            );
            assert!(
                snapshot
                    .manual_roster_construction_evidence_v2(
                        &f.claim.principal_id,
                        "wrong-construction-key"
                    )
                    .unwrap()
                    .is_none()
            );
            assert!(
                snapshot
                    .manual_roster_construction_evidence_v2(
                        &f.claim.principal_id,
                        &format!("{} ", f.claim.construction_key)
                    )
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                snapshot.current_store_destination_identity().unwrap(),
                f.root.terms().host.store_destination_identity
            );
            assert_eq!(
                snapshot
                    .current_agreement_record(&f.claim.proposal().manifest.agreement.agreement_id)
                    .unwrap()
                    .revision,
                f.claim.agreement_revision()
            );
            assert!(
                snapshot
                    .current_agreement_record("synthetic-inherited-agreement")
                    .is_err()
            );
            assert!(
                snapshot
                    .current_agreement_record("missing-agreement")
                    .is_err()
            );
            snapshot.check_source_unchanged().unwrap();
        });
        unchanged(f.directory.path(), || drop(snapshot));
    }
}

#[test]
fn encrypted_corrupt_global_history_denies_exact_and_absent_reads_without_repair() {
    for corruption in 0..7 {
        let f = Fixture::new(true);
        let original = unchanged(f.directory.path(), || f.snapshot().unwrap());
        {
            let c = f.store.connection.lock().unwrap();
            match corruption {
                0 => {
                    c.execute(
                        "UPDATE records SET payload='{}' WHERE aggregate_type=?1",
                        [CONSTRUCTION_CLAIM_V2],
                    )
                    .unwrap();
                }
                1 => {
                    c.execute(
                        "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
                        rusqlite::params![INITIAL_PUBLICATION_V2, f.root.digest().unwrap()],
                    )
                    .unwrap();
                }
                2 => {
                    c.execute("INSERT INTO records VALUES('generation_manual_unknown_v99','synthetic-unknown',0,'{}',1,1)", []).unwrap();
                }
                3 => {
                    c.execute(
                        "UPDATE records SET revision=1 WHERE aggregate_type=?1",
                        [CONSTRUCTION_CHECKPOINT_V2],
                    )
                    .unwrap();
                }
                4 => {
                    let mut receipt = f.receipt.clone().unwrap();
                    receipt.scope.candidate_id = "different-candidate".into();
                    c.execute(
                        "UPDATE records SET payload=?1 WHERE aggregate_type=?2",
                        rusqlite::params![
                            serde_json::to_string(&receipt).unwrap(),
                            CONSTRUCTION_CHECKPOINT_V2
                        ],
                    )
                    .unwrap();
                }
                5 => {
                    c.execute(
                        "DELETE FROM records WHERE aggregate_type=?1",
                        [CONSTRUCTION_CLAIM_V2],
                    )
                    .unwrap();
                }
                _ => {
                    c.execute(
                        "UPDATE records SET updated_at_ms=2 WHERE aggregate_type=?1",
                        [CONSTRUCTION_CLAIM_V2],
                    )
                    .unwrap();
                }
            }
        }
        unchanged(f.directory.path(), || {
            // Authentication fails before any exact or absent claim can be
            // selected. Retained earlier snapshots also reject changed source.
            assert!(f.snapshot().is_err(), "corruption {corruption}");
            assert!(original.check_source_unchanged().is_err());
            assert!(
                original
                    .manual_roster_construction_evidence_v2(
                        &f.claim.principal_id,
                        &f.claim.construction_key
                    )
                    .is_err()
            );
            assert!(
                original
                    .manual_roster_construction_evidence_v2(
                        "wrong-principal",
                        "missing-construction-key"
                    )
                    .is_err()
            );
            assert!(
                original
                    .current_agreement_record(&f.claim.proposal().manifest.agreement.agreement_id)
                    .is_err()
            );
            assert!(original.current_store_destination_identity().is_err());
        });
        unchanged(f.directory.path(), || drop(original));
    }
}

#[test]
fn wrong_encryption_key_generation_and_successful_snapshot_preserve_complete_tree() {
    let f = Fixture::new(true);
    unchanged(f.directory.path(), || {
        assert!(
            RecoveredStoreSnapshot::open(&f.path(), &key(0x62), &f.binding, &f.provenance).is_err()
        );
    });
    for changed in [
        bundle::recovery::generation::GenerationBinding::new(&h('9'), f.binding.inventory_digest())
            .unwrap(),
        bundle::recovery::generation::GenerationBinding::new(f.binding.generation_id(), &h('9'))
            .unwrap(),
    ] {
        unchanged(f.directory.path(), || {
            assert!(
                RecoveredStoreSnapshot::open(&f.path(), &key(0x61), &changed, &f.provenance)
                    .is_err()
            )
        });
    }
    unchanged(f.directory.path(), || {
        let snapshot = f.snapshot().unwrap();
        let (actual, receipt) = snapshot
            .manual_roster_construction_evidence_v2(
                &f.claim.principal_id,
                &f.claim.construction_key,
            )
            .unwrap()
            .unwrap();
        assert!(actual == f.claim);
        assert!(receipt == f.receipt);
        snapshot.check_source_unchanged().unwrap();
    });
}

fn unchanged<T>(root: &Path, read: impl FnOnce() -> T) -> T {
    let before = tree(root);
    let result = read();
    assert_eq!(
        tree(root),
        before,
        "immutable historical read changed a file, SQLite sidecar, directory or file identity"
    );
    result
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
        // Equality still compares every raw byte. Diagnostic formatting never
        // dumps encrypted fixture pages, private contents, or megabytes of SHM.
        let bytes_len_sha256 = self
            .bytes
            .as_ref()
            .map(|bytes| (bytes.len(), hex::encode(sha2::Sha256::digest(bytes))));
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
