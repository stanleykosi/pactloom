use super::*;
use crate::{create_encrypted, open_encrypted, StorageSecurityError};
use std::{cell::Cell, os::unix::fs::PermissionsExt};
static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 2,
    create_sql: "CREATE TABLE records(aggregate_type TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,created_at_ms INTEGER NOT NULL,updated_at_ms INTEGER NOT NULL,PRIMARY KEY(aggregate_type,id)); CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,aggregate_type TEXT NOT NULL,aggregate_id TEXT NOT NULL,aggregate_revision INTEGER NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL,operation_id TEXT NOT NULL,occurred_at_ms INTEGER NOT NULL);",
};
struct Adapter(Connection);
impl JournalAdapter for Adapter {
    fn template(&self) -> &'static JournalTemplate {
        &TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<()>,
    ) -> Result<()> {
        permit.check(self)?;
        visitor(&self.0)
    }
}
struct BackupGate;
struct BackupLease;
impl BundleLease for BackupLease {
    fn check_current(&self) -> Result<()> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-frozen-history"
    }
}
impl BundleAuthority for BackupGate {
    fn acquire<'a>(&'a self, _: &BundleScope<'_>) -> Result<Box<dyn BundleLease + 'a>> {
        Ok(Box::new(BackupLease))
    }
}
struct Gate {
    binding: HistoryBinding,
    action: HistoryAction,
    allow: bool,
    held: Cell<bool>,
    checks: Cell<usize>,
    revoke_after_first: bool,
}
struct Lease<'a>(&'a Gate);
impl HistoryLease for Lease<'_> {
    fn check_current(&self) -> Result<()> {
        assert!(self.0.held.get());
        let n = self.0.checks.get() + 1;
        self.0.checks.set(n);
        if self.0.revoke_after_first && n > 1 {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.held.set(false);
    }
}
impl HistoryAuthority for Gate {
    fn acquire<'a>(&'a self, s: &HistoryScope<'_>) -> Result<Box<dyn HistoryLease + 'a>> {
        if !self.allow
            || *s.source != self.binding
            || s.principal_id != "reader"
            || s.profile_id != "profile"
            || s.component_id != "coord"
            || s.agreement_id != "agreement"
            || s.action != self.action
        {
            return Err(BundleError::Permission);
        }
        assert!(!self.held.replace(true));
        Ok(Box::new(Lease(self)))
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    key: DatabaseKey,
    archive: PathBuf,
    restored: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([99; 32]);
        let source = create_encrypted(dir.path().join("source"), &key)
            .unwrap()
            .into_connection();
        source.execute_batch(TEMPLATE.create_sql).unwrap();
        source.pragma_update(None, "user_version", 2).unwrap();
        let payload = serde_json::json!({"owner_client_id":"PRIVATE_OWNER_CANARY","participant_records":{"private":"PRIVATE_RECORD_CANARY"},"sponsor_policies":{"private":"PRIVATE_POLICY_CANARY"},"view":{"agreement":{"agreement_id":"agreement","purpose":"Archived agreement"},"progress":"completed_claim_in_archive","cancellation_requested":true,"authorization_exposure":"none","chain_observation":"settled","unknown_future_secret":"PRIVATE_FUTURE_CANARY"}});
        source
            .execute(
                "INSERT INTO records VALUES('agreement','agreement',3,?1,10,20)",
                [payload.to_string()],
            )
            .unwrap();
        source.execute_batch("INSERT INTO events VALUES(1,'agreement','agreement',1,'agreement.created','PRIVATE_EVENT_PAYLOAD','operation',10); INSERT INTO events VALUES(2,'participant_record','agreement',2,'PRIVATE_KIND','PRIVATE_COLLISION','operation',15); INSERT INTO events VALUES(3,'agreement','agreement',3,'PRIVATE_KIND','PRIVATE_EVENT_PAYLOAD','operation',20);").unwrap();
        let adapter = Adapter(source);
        let sources = [RegisteredJournal::new("coord", &adapter).unwrap()];
        let coverage = Coverage {
            present: BTreeMap::from([(JournalKind::CoordinationAuthority, vec!["coord".into()])]),
            absent: KINDS
                .into_iter()
                .filter(|k| *k != JournalKind::CoordinationAuthority)
                .collect(),
        };
        let archive = dir.path().join("archive");
        snapshot(SnapshotRequest {
            principal_id: "admin",
            profile_id: "profile",
            coverage,
            sources: &sources,
            destination: &archive,
            key: &key,
            authority: &BackupGate,
        })
        .unwrap();
        let restored = dir.path().join("restored");
        restore(RestoreRequest {
            principal_id: "admin",
            profile_id: "profile",
            archive: &archive,
            key: &key,
            targets: &[RestoreTarget {
                component_id: "coord",
                template: &TEMPLATE,
                destination: &restored,
                key: &key,
            }],
            authority: &BackupGate,
        })
        .unwrap();
        Self {
            dir,
            key,
            archive,
            restored,
        }
    }
    fn open(&self) -> Result<QuarantinedCoordinationHistory> {
        QuarantinedCoordinationHistory::open(
            HistoryOpenRequest {
                archive: &self.archive,
                archive_key: &self.key,
                component_id: "coord",
                restored_component: &self.restored,
                restored_key: &self.key,
            },
            &TEMPLATE,
        )
    }
}
fn gate(h: &QuarantinedCoordinationHistory, action: HistoryAction) -> Gate {
    Gate {
        binding: h.binding(),
        action,
        allow: true,
        held: Cell::new(false),
        checks: Cell::new(0),
        revoke_after_first: false,
    }
}
#[test]
fn readonly_exact_scope_projection_filters_private_data_and_keeps_unknown_state() {
    let f = Fixture::new();
    let before = crate::tests::tree_fingerprint(f.dir.path());
    let history = f.open().unwrap();
    assert!(history
        .connection
        .execute("DELETE FROM records", [])
        .is_err());
    let consent = gate(&history, HistoryAction::AgreementSummary);
    let value = history
        .agreement("reader", "agreement", &consent)
        .unwrap()
        .unwrap();
    assert_eq!(value.revision, 3);
    assert!(value.recovery_required);
    assert_eq!(value.authorization_exposure, HistoricalObservation::Unknown);
    assert_eq!(value.chain_observation, HistoricalObservation::Unknown);
    assert!(!serde_json::to_string(&value).unwrap().contains("PRIVATE_"));
    assert!(!consent.held.get());
    assert!(history.agreement("other", "agreement", &consent).is_err());
    assert!(history
        .agreement("reader", "other-agreement", &consent)
        .is_err());
    let other = f.open().unwrap();
    assert!(other.agreement("reader", "agreement", &consent).is_err());
    assert!(history
        .events("reader", "agreement", 0, 100, &consent)
        .is_err());
    let events = history
        .events(
            "reader",
            "agreement",
            0,
            100,
            &gate(&history, HistoryAction::AgreementEvents),
        )
        .unwrap();
    assert_eq!(
        events.events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert!(!serde_json::to_string(&events).unwrap().contains("PRIVATE_"));
    let mut denied = gate(&history, HistoryAction::AgreementSummary);
    denied.allow = false;
    assert!(history.agreement("reader", "agreement", &denied).is_err());
    let mut revoked = gate(&history, HistoryAction::AgreementSummary);
    revoked.revoke_after_first = true;
    assert!(history.agreement("reader", "agreement", &revoked).is_err());
    assert!(!revoked.held.get());
    assert!(history
        .events(
            "reader",
            "agreement",
            0,
            101,
            &gate(&history, HistoryAction::AgreementEvents)
        )
        .is_err());
    drop(other);
    drop(history);
    assert_eq!(crate::tests::tree_fingerprint(f.dir.path()), before);
    assert!(matches!(
        open_encrypted(&f.restored, &f.key),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert!(f.dir.path().exists());
}
#[test]
fn modified_restored_rows_and_wrong_keys_are_rejected_before_history_access() {
    let f = Fixture::new();
    assert!(QuarantinedCoordinationHistory::open(
        HistoryOpenRequest {
            archive: &f.archive,
            archive_key: &DatabaseKey::from_bytes([100; 32]),
            component_id: "coord",
            restored_component: &f.restored,
            restored_key: &f.key
        },
        &TEMPLATE
    )
    .is_err());
    // Internal-only maintenance fixture. No public quarantine connection exists.
    let handle = crate::open_quarantined(&f.restored, &f.key).unwrap();
    handle
        .connection()
        .execute("UPDATE records SET revision=4", [])
        .unwrap();
    drop(handle);
    assert!(matches!(f.open(), Err(BundleError::Integrity)));
}
