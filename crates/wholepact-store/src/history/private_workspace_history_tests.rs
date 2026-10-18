//! Store product-history content joins over real authenticated archive pairs.
//! Synthetic fixtures are not native approval, financial authority or activation.
use super::*;
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{
        self, BackupReadPermit, BundleAuthority, BundleLease, BundleScope, Coverage,
        JournalAdapter, JournalKind, JournalTemplate, RegisteredJournal, RestoreRequest,
        RestoreTarget, SnapshotRequest,
    },
};

const PROFILE: &str = "synthetic-history-profile";
const COMPONENT: &str = "coordination";
const AGREEMENT: &str = "synthetic-agreement";
const PRINCIPAL: &str = "synthetic-history-reader";
const MARKER_KEY: &str = "private_workspace_origin_v1";
const COLUMNS: [(&str, &str); 4] = [
    ("records", "payload"),
    ("operations", "result"),
    ("idempotency", "result"),
    ("events", "payload"),
];

// Consumed once, on this test thread, only after the real Store scan succeeds.
// Replacing paths here exercises the actual second authenticated opener without
// timing races, filesystem mutation, or any production bypass/callback.
std::thread_local! {
    static SECOND_OPEN: RefCell<Option<(PathBuf, PathBuf)>> = const { RefCell::new(None) };
}

pub(super) fn take_second_open() -> Option<(PathBuf, PathBuf)> {
    SECOND_OPEN.with(|replacement| replacement.borrow_mut().take())
}

struct SecondOpen;
impl SecondOpen {
    fn substitute(fixture: &Fixture) -> Self {
        SECOND_OPEN.with(|replacement| {
            let previous = replacement
                .borrow_mut()
                .replace((fixture.archive.clone(), fixture.restored.clone()));
            assert!(previous.is_none());
        });
        Self
    }
}
impl Drop for SecondOpen {
    fn drop(&mut self) {
        take_second_open();
    }
}

// Deliberately below the Store adapter so the fixture can contain authentic but
// unsupported private metadata. This is not a product export or history opener.
struct FixtureAdapter(Connection);
impl JournalAdapter for FixtureAdapter {
    fn template(&self) -> &'static JournalTemplate {
        crate::bundle::coordination_template()
    }

    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        visitor(&self.0)
    }
}

struct FixtureArchiveAuthority;
struct FixtureArchiveLease;
impl BundleAuthority for FixtureArchiveAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-archive-admin" || scope.profile_id != PROFILE {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(FixtureArchiveLease))
    }
}
impl BundleLease for FixtureArchiveLease {
    fn check_current(&self) -> Result<(), BundleError> {
        Ok(())
    }

    fn checkpoint_id(&self) -> &str {
        "synthetic-history-checkpoint"
    }
}

fn coverage() -> Coverage {
    Coverage {
        present: BTreeMap::from([(JournalKind::CoordinationAuthority, vec![COMPONENT.into()])]),
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
    }
}

fn synthetic_marker() -> Value {
    json!({
        "version": 1,
        "purpose": "durable-private-coordination-v1",
        "native_association_digest": "1".repeat(64),
        "source_digest": "2".repeat(64),
        "principal_id": "synthetic-constructor",
        "agreement_id": AGREEMENT,
        "obligation_id": "synthetic-obligation",
        "reviewer_account_ids": ["3".repeat(64), "4".repeat(64)],
        "protected_destination": "/synthetic-private/history.sqlite",
        "retention_policy": "synthetic-private-retention",
        "metadata_origin": "5".repeat(64)
    })
}

struct Fixture {
    directory: tempfile::TempDir,
    archive: PathBuf,
    restored: PathBuf,
    archive_key: DatabaseKey,
    restored_key: DatabaseKey,
    digest: String,
}

impl Fixture {
    fn new(private_column: Option<(&str, &str)>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let connection = wholepact_storage_security::create_encrypted(
            directory.path().join("source.sqlite"),
            &DatabaseKey::from_bytes([0x80; 32]),
        )
        .unwrap()
        .into_connection();
        connection
            .execute_batch(crate::bundle::coordination_template().create_sql)
            .unwrap();
        connection
            .pragma_update(None, "user_version", crate::SCHEMA_VERSION)
            .unwrap();
        let payload = json!({
            "owner_client_id": "synthetic-constructor",
            "view": {
                "agreement": {
                    "agreement_id": AGREEMENT,
                    "obligation_id": "synthetic-obligation",
                    "purpose": "Synthetic historical purpose"
                },
                "progress": "draft",
                "cancellation_requested": false
            },
            "durable_construction_v1": {},
            "durable_input_projections_v1": {}
        });
        let result = json!({
            "operation_id": "synthetic-operation",
            "record": {
                "id": AGREEMENT,
                "revision": 1,
                "payload": payload,
                "created_at_ms": 10,
                "updated_at_ms": 10
            }
        });
        connection
            .execute(
                "INSERT INTO records VALUES('agreement',?1,1,?2,10,10)",
                rusqlite::params![AGREEMENT, payload.to_string()],
            )
            .unwrap();
        connection.execute(
            "INSERT INTO operations VALUES('synthetic-operation','synthetic-constructor','agreement.create',?1,'succeeded',?2,10,10)",
            rusqlite::params![AGREEMENT, result.to_string()],
        ).unwrap();
        connection
            .execute(
                "INSERT INTO idempotency VALUES('synthetic-constructor','synthetic-key',?1,?2)",
                rusqlite::params!["a".repeat(64), result.to_string()],
            )
            .unwrap();
        connection.execute(
            "INSERT INTO events VALUES(1,'agreement',?1,1,'agreement.created',?2,'synthetic-operation',10)",
            rusqlite::params![AGREEMENT, json!({"id": AGREEMENT, "revision": 1}).to_string()],
        ).unwrap();
        if let Some((table, column)) = private_column {
            let raw: String = connection
                .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            let mut value: Value = serde_json::from_str(&raw).unwrap();
            if matches!(table, "operations" | "idempotency") {
                value["record"]["payload"][MARKER_KEY] = synthetic_marker();
            } else {
                value[MARKER_KEY] = synthetic_marker();
            }
            connection
                .execute(
                    &format!("UPDATE {table} SET {column}=?1"),
                    [value.to_string()],
                )
                .unwrap();
        }
        let archive = directory.path().join("archive.sqlite");
        let restored = directory.path().join("restored.sqlite");
        let archive_key = DatabaseKey::from_bytes([0x81; 32]);
        let restored_key = DatabaseKey::from_bytes([0x82; 32]);
        let adapter = FixtureAdapter(connection);
        let sources = [RegisteredJournal::new(COMPONENT, &adapter).unwrap()];
        let manifest = bundle::snapshot(SnapshotRequest {
            principal_id: "synthetic-archive-admin",
            profile_id: PROFILE,
            coverage: coverage(),
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &FixtureArchiveAuthority,
        })
        .unwrap();
        bundle::restore(RestoreRequest {
            principal_id: "synthetic-archive-admin",
            profile_id: PROFILE,
            archive: &archive,
            key: &archive_key,
            targets: &[RestoreTarget {
                component_id: COMPONENT,
                template: crate::bundle::coordination_template(),
                destination: &restored,
                key: &restored_key,
            }],
            authority: &FixtureArchiveAuthority,
        })
        .unwrap();
        Self {
            directory,
            archive,
            restored,
            archive_key,
            restored_key,
            digest: manifest.digest,
        }
    }

    fn request(&self) -> HistoryOpenRequest<'_> {
        HistoryOpenRequest {
            archive: &self.archive,
            archive_key: &self.archive_key,
            component_id: COMPONENT,
            restored_component: &self.restored,
            restored_key: &self.restored_key,
        }
    }

    fn open(&self) -> Result<QuarantinedCoordinationHistory, BundleError> {
        open_quarantined_history(self.request())
    }
}

struct Gate {
    binding: HistoryBinding,
    digest: String,
    action: HistoryAction,
    agreement: String,
    allow: bool,
    fail_check: Option<usize>,
    acquisitions: Cell<usize>,
    checks: Cell<usize>,
    drops: Cell<usize>,
    held: Cell<bool>,
}

impl Gate {
    fn new(history: &QuarantinedCoordinationHistory, digest: &str, action: HistoryAction) -> Self {
        Self {
            binding: history.binding(),
            digest: digest.into(),
            action,
            agreement: AGREEMENT.into(),
            allow: true,
            fail_check: None,
            acquisitions: Cell::new(0),
            checks: Cell::new(0),
            drops: Cell::new(0),
            held: Cell::new(false),
        }
    }

    fn assert_unused(&self) {
        assert_eq!(self.acquisitions.get(), 0);
        assert_eq!(self.checks.get(), 0);
        assert_eq!(self.drops.get(), 0);
        assert!(!self.held.get());
    }
}

impl HistoryAuthority for Gate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoryScope<'_>,
    ) -> Result<Box<dyn HistoryLease + 'a>, BundleError> {
        self.acquisitions.set(self.acquisitions.get() + 1);
        if !self.allow
            || scope.source != &self.binding
            || scope.principal_id != PRINCIPAL
            || scope.profile_id != PROFILE
            || scope.component_id != COMPONENT
            || scope.bundle_digest != self.digest
            || scope.agreement_id != self.agreement
            || scope.action != self.action
        {
            return Err(BundleError::Permission);
        }
        assert!(!self.held.replace(true));
        Ok(Box::new(Lease(self)))
    }
}

struct Lease<'a>(&'a Gate);
impl HistoryLease for Lease<'_> {
    fn check_current(&self) -> Result<(), BundleError> {
        assert!(self.0.held.get());
        let checks = self.0.checks.get() + 1;
        self.0.checks.set(checks);
        if self.0.fail_check == Some(checks) {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        assert!(self.0.held.replace(false));
        self.0.drops.set(self.0.drops.get() + 1);
    }
}

fn deny_both_without_delegation(history: &QuarantinedCoordinationHistory, digest: &str) {
    for id in [AGREEMENT, "absent-agreement"] {
        let mut agreement = Gate::new(history, digest, HistoryAction::AgreementSummary);
        agreement.agreement = id.into();
        assert!(matches!(
            history.agreement(PRINCIPAL, id, &agreement),
            Err(BundleError::Integrity)
        ));
        agreement.assert_unused();
        let mut events = Gate::new(history, digest, HistoryAction::AgreementEvents);
        events.agreement = id.into();
        assert!(matches!(
            history.events(PRINCIPAL, id, 0, 10, &events),
            Err(BundleError::Integrity)
        ));
        events.assert_unused();
    }
}

// Retain only closed hashes, never encrypted bytes or private JSON in diagnostics.
// Reads may change atime; all other relevant identity/metadata and contents stay exact.
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
    digest: Option<[u8; 32]>,
}

fn tree(root: &Path) -> BTreeMap<PathBuf, FileState> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, FileState>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let digest = if metadata.is_file() {
            Some(Sha256::digest(fs::read(path).unwrap()).into())
        } else {
            assert!(metadata.is_dir());
            None
        };
        output.insert(
            path.strip_prefix(root).unwrap().into(),
            FileState {
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
                device: metadata.dev(),
                inode: metadata.ino(),
                len: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                digest,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), output);
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

fn unchanged<T>(root: &Path, read: impl FnOnce() -> T) -> T {
    let before = tree(root);
    let result = read();
    assert!(
        tree(root) == before,
        "historical read changed source files or sidecars"
    );
    result
}

#[test]
fn swapped_authenticated_second_open_refuses_each_marker_only_column_before_authority() {
    let harmless = Fixture::new(None);
    for column in COLUMNS {
        let private = Fixture::new(Some(column));
        assert!(harmless.digest != private.digest);
        unchanged(private.directory.path(), || {
            // Ordinary product opening refuses the first scanned private pair.
            assert!(matches!(private.open(), Err(BundleError::Integrity)));
        });
        unchanged(harmless.directory.path(), || {
            unchanged(private.directory.path(), || {
                let _substitution = SecondOpen::substitute(&private);
                // This succeeds only if the real lower opener authenticates B.
                // Its data outputs still must join to the completely scanned A.
                let history = harmless.open().unwrap();
                assert!(take_second_open().is_none());
                assert!(history.scanned_bundle_digest == harmless.digest);
                deny_both_without_delegation(&history, &private.digest);
            })
        });
    }
}

#[test]
fn exact_scanned_content_delegates_original_scope_and_drops_real_lease() {
    let fixture = Fixture::new(None);
    unchanged(fixture.directory.path(), || {
        let history = fixture.open().unwrap();
        let gate = Gate::new(&history, &fixture.digest, HistoryAction::AgreementSummary);
        let agreement = history
            .agreement(PRINCIPAL, AGREEMENT, &gate)
            .unwrap()
            .unwrap();
        assert_eq!(agreement.agreement_id, AGREEMENT);
        assert_eq!(agreement.purpose, "Synthetic historical purpose");
        assert_eq!(agreement.revision, 1);
        assert_eq!(gate.acquisitions.get(), 1);
        assert_eq!(gate.checks.get(), 2);
        assert_eq!(gate.drops.get(), 1);
        assert!(!gate.held.get());

        let gate = Gate::new(&history, &fixture.digest, HistoryAction::AgreementEvents);
        let page = history.events(PRINCIPAL, AGREEMENT, 0, 10, &gate).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].change, HistoricalChange::Created);
        assert_eq!(gate.acquisitions.get(), 1);
        assert_eq!(gate.checks.get(), 2);
        assert_eq!(gate.drops.get(), 1);
        assert!(!gate.held.get());
    });
}

#[test]
fn genuine_authority_and_pre_post_lease_denials_are_not_weakened() {
    let fixture = Fixture::new(None);
    unchanged(fixture.directory.path(), || {
        let history = fixture.open().unwrap();
        for action in [
            HistoryAction::AgreementSummary,
            HistoryAction::AgreementEvents,
        ] {
            for fail_check in [None, Some(1), Some(2)] {
                let mut gate = Gate::new(&history, &fixture.digest, action);
                gate.allow = fail_check.is_some();
                gate.fail_check = fail_check;
                let denied = match action {
                    HistoryAction::AgreementSummary => matches!(
                        history.agreement(PRINCIPAL, AGREEMENT, &gate),
                        Err(BundleError::Permission)
                    ),
                    HistoryAction::AgreementEvents => matches!(
                        history.events(PRINCIPAL, AGREEMENT, 0, 10, &gate),
                        Err(BundleError::Permission)
                    ),
                };
                assert!(denied);
                assert_eq!(gate.acquisitions.get(), 1);
                assert_eq!(gate.checks.get(), fail_check.unwrap_or(0));
                assert_eq!(gate.drops.get(), usize::from(fail_check.is_some()));
                assert!(!gate.held.get());
            }
        }
    });
}

#[test]
fn genuine_scope_denials_receive_original_principal_agreement_action_and_binding() {
    let fixture = Fixture::new(None);
    unchanged(fixture.directory.path(), || {
        let history = fixture.open().unwrap();
        let other = fixture.open().unwrap();
        for action in [
            HistoryAction::AgreementSummary,
            HistoryAction::AgreementEvents,
        ] {
            for field in ["principal", "agreement", "action", "binding", "digest"] {
                let mut gate = Gate::new(&history, &fixture.digest, action);
                let principal = if field == "principal" {
                    "another-reader"
                } else {
                    PRINCIPAL
                };
                let agreement = if field == "agreement" {
                    "another-agreement"
                } else {
                    AGREEMENT
                };
                match field {
                    "action" => {
                        gate.action = match action {
                            HistoryAction::AgreementSummary => HistoryAction::AgreementEvents,
                            HistoryAction::AgreementEvents => HistoryAction::AgreementSummary,
                        }
                    }
                    "binding" => gate.binding = other.binding(),
                    "digest" => gate.digest = "e".repeat(64),
                    _ => (),
                }
                let denied = match action {
                    HistoryAction::AgreementSummary => matches!(
                        history.agreement(principal, agreement, &gate),
                        Err(BundleError::Permission)
                    ),
                    HistoryAction::AgreementEvents => matches!(
                        history.events(principal, agreement, 0, 10, &gate),
                        Err(BundleError::Permission)
                    ),
                };
                assert!(denied);
                assert_eq!(gate.acquisitions.get(), 1);
                assert_eq!(gate.checks.get(), 0);
                assert_eq!(gate.drops.get(), 0);
                assert!(!gate.held.get());
            }
        }
    });
}

#[test]
fn changed_scanned_identity_or_other_handle_binding_never_delegates() {
    let fixture = Fixture::new(None);
    unchanged(fixture.directory.path(), || {
        let other = fixture.open().unwrap();
        for field in ["profile", "component", "digest", "binding"] {
            let mut history = fixture.open().unwrap();
            match field {
                "profile" => history.scanned_profile_id = "different-profile".into(),
                "component" => history.scanned_component_id = "different-component".into(),
                "digest" => history.scanned_bundle_digest = "f".repeat(64),
                "binding" => {
                    assert!(history.binding() != other.binding());
                    history.binding = other.binding();
                }
                _ => unreachable!(),
            }
            deny_both_without_delegation(&history, &fixture.digest);
        }
    });
}

#[test]
fn equal_verified_content_at_other_paths_is_not_mistaken_for_path_authority() {
    let first = Fixture::new(None);
    let second = Fixture::new(None);
    assert!(first.digest == second.digest);
    unchanged(first.directory.path(), || {
        unchanged(second.directory.path(), || {
            let _substitution = SecondOpen::substitute(&second);
            let history = first.open().unwrap();
            let gate = Gate::new(&history, &first.digest, HistoryAction::AgreementSummary);
            assert!(
                history
                    .agreement(PRINCIPAL, AGREEMENT, &gate)
                    .unwrap()
                    .is_some()
            );
            assert_eq!(gate.acquisitions.get(), 1);
            assert_eq!(gate.checks.get(), 2);
            assert_eq!(gate.drops.get(), 1);
            assert!(!gate.held.get());
        })
    });
}
