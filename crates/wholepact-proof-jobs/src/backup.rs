//! Typed encrypted ProofWitness journal backup boundary. The adapter locks the
//! existing open journal only; whole-profile privacy/admin/quiescence permission
//! is independently required by `bundle::snapshot`. Restores remain quarantined.
use super::ProofJobStore;
use wholepact_storage_security::bundle::{
    BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate,
};

mod historical;
mod recovery_references;
pub use historical::{HistoricalProofMetadata, archived_historical_proof, historical_proof};
pub use recovery_references::{
    ProofRecoveryReference, archived_recovery_references, recovery_references,
    successor_recovery_references,
};

// Mirrored from the journal's compiled schema. The encrypted adapter roundtrip
// test checks exact sqlite_schema equality, so source/schema drift fails closed.
pub static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::ProofWitness,
    application_id: 1464881226,
    schema_version: 1,
    create_sql: "CREATE TABLE proof_jobs (
              job_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, idem_key TEXT NOT NULL,
              request_digest TEXT NOT NULL, scope BLOB NOT NULL, input_digest TEXT NOT NULL,
              input BLOB NOT NULL, policy BLOB NOT NULL, maximum_actions INTEGER NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('queued','running','uncertain','succeeded','failed')),
              attempt INTEGER NOT NULL DEFAULT 0, result BLOB, result_digest TEXT,
              UNIQUE(principal_id,idem_key), CHECK(length(input)<=1048576),
              CHECK(length(policy)<=131072), CHECK(result IS NULL OR length(result)<=1048576),
              CHECK((state='succeeded')=(result IS NOT NULL AND result_digest IS NOT NULL))
            );
            CREATE TABLE proof_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              job_id TEXT NOT NULL REFERENCES proof_jobs(job_id), state TEXT NOT NULL, attempt INTEGER NOT NULL);",
};

pub struct ProofWitnessBackupAdapter<'a> {
    journal: &'a ProofJobStore,
}
impl<'a> ProofWitnessBackupAdapter<'a> {
    /// This borrowed identity handle grants no backup, spending or recovery
    /// permission and never enrolls or reopens a caller-selected database path.
    pub fn new(journal: &'a ProofJobStore) -> Self {
        Self { journal }
    }
}
impl JournalAdapter for ProofWitnessBackupAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        &TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&rusqlite::Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        let connection = self
            .journal
            .connection
            .lock()
            .map_err(|_| BundleError::Storage)?;
        visitor(&connection)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use wholepact_storage_security::bundle::*;
    use wholepact_storage_security::{
        DatabaseKey, StorageSecurityError, create_encrypted, open_encrypted,
    };

    // Explicit storage-only empty coordination component. It is not a real
    // account-history source, signer grant or production inventory issuer.
    static SYNTHETIC_COORDINATION: JournalTemplate = JournalTemplate {
        kind: JournalKind::CoordinationAuthority,
        application_id: 0,
        schema_version: 1,
        create_sql: "CREATE TABLE synthetic_coordination(id TEXT PRIMARY KEY);",
    };
    struct SyntheticCoordination(std::sync::Mutex<wholepact_storage_security::EncryptedConnection>);
    impl SyntheticCoordination {
        fn new(path: &std::path::Path, key: &DatabaseKey) -> Self {
            let encrypted = create_encrypted(path, key).unwrap();
            encrypted
                .connection()
                .execute_batch(SYNTHETIC_COORDINATION.create_sql)
                .unwrap();
            encrypted
                .connection()
                .pragma_update(None, "user_version", 1)
                .unwrap();
            Self(std::sync::Mutex::new(encrypted))
        }
    }
    impl JournalAdapter for SyntheticCoordination {
        fn template(&self) -> &'static JournalTemplate {
            &SYNTHETIC_COORDINATION
        }
        fn read_locked(
            &self,
            permit: &BackupReadPermit<'_>,
            visitor: &mut dyn FnMut(&rusqlite::Connection) -> Result<(), BundleError>,
        ) -> Result<(), BundleError> {
            permit.check(self)?;
            let connection = self.0.lock().map_err(|_| BundleError::Storage)?;
            visitor(connection.connection())
        }
    }

    struct SyntheticSnapshotAuthority {
        bindings: Vec<(String, JournalBinding)>,
        archive: PathBuf,
        destinations: Vec<PathBuf>,
    }
    struct SyntheticLease;
    impl BundleLease for SyntheticLease {
        fn check_current(&self) -> Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-quiescent-proof-backup"
        }
    }
    impl BundleAuthority for SyntheticSnapshotAuthority {
        fn acquire<'a>(
            &'a self,
            scope: &BundleScope<'_>,
        ) -> Result<Box<dyn BundleLease + 'a>, BundleError> {
            if scope.principal_id != "synthetic-admin"
                || scope.profile_id != "synthetic-profile"
                || scope.archive != self.archive
                || scope.wallet_spending_secrets_included
                || !scope.private_viewing_witness_and_correlation_data_may_be_included
                || if scope.action == BundleAction::Snapshot {
                    scope.sources != self.bindings || !scope.destinations.is_empty()
                } else {
                    scope.action != BundleAction::TestRestore
                        || scope.destinations != self.destinations
                }
            {
                return Err(BundleError::Permission);
            }
            // This unit fixture owns all handles and runs without any worker.
            Ok(Box::new(SyntheticLease))
        }
    }
    #[test]
    fn encrypted_proof_bundle_preserves_stalled_work_and_never_restores_authority() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source_key = DatabaseKey::from_bytes([0x81; 32]);
        let archive_key = DatabaseKey::from_bytes([0x82; 32]);
        let restored_key = DatabaseKey::from_bytes([0x83; 32]);
        let source = ProofJobStore::from_encrypted_connection(
            create_encrypted(dir.path().join("proof-source"), &source_key).unwrap(),
        )
        .unwrap();
        // Storage-only fixture, deliberately not a cryptographically valid PCZT.
        // A backup must preserve in-flight uncertainty without replaying a prover.
        source.connection.lock().unwrap().execute(
            "INSERT INTO proof_jobs(job_id,principal_id,idem_key,request_digest,scope,input_digest,input,policy,maximum_actions,state,attempt) VALUES('fixture-job','owner','fixture-key','digest',?1,'digest',?1,?1,8,'running',1)",
            [b"synthetic-private-proof-backup-canary".as_slice()],
        ).unwrap();
        source.connection.lock().unwrap().execute(
            "INSERT INTO proof_events(sequence,job_id,state,attempt) VALUES(7,'fixture-job','running',1)", [],
        ).unwrap();
        let adapter = ProofWitnessBackupAdapter::new(&source);
        let coordination =
            SyntheticCoordination::new(&dir.path().join("coordination"), &source_key);
        let sources = [
            RegisteredJournal::new("coordination", &coordination).unwrap(),
            RegisteredJournal::new("proof", &adapter).unwrap(),
        ];
        let archive = dir.path().join("proof-archive");
        let restored = dir.path().join("proof-restored");
        let restored_coordination = dir.path().join("coordination-restored");
        let authority = SyntheticSnapshotAuthority {
            bindings: sources
                .iter()
                .map(|s| (s.id().into(), s.binding()))
                .collect(),
            archive: archive.clone(),
            destinations: vec![restored_coordination.clone(), restored.clone()],
        };
        let manifest = snapshot(SnapshotRequest {
            principal_id: "synthetic-admin",
            profile_id: "synthetic-profile",
            coverage: Coverage {
                present: BTreeMap::from([
                    (
                        JournalKind::CoordinationAuthority,
                        vec!["coordination".into()],
                    ),
                    (JournalKind::ProofWitness, vec!["proof".into()]),
                ]),
                absent: BTreeSet::from([
                    JournalKind::SignerConsentAuthority,
                    JournalKind::WalletScan,
                    JournalKind::SignedResults,
                    JournalKind::ExactTransactions,
                    JournalKind::Submission,
                    JournalKind::TransportInbox,
                    JournalKind::TransportOutbox,
                ]),
            },
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &authority,
        })
        .unwrap();
        assert_eq!(manifest.components.len(), 2);
        assert!(
            manifest
                .components
                .iter()
                .find(|c| c.kind == JournalKind::ProofWitness)
                .unwrap()
                .rows
                >= 2
        );
        assert_eq!(inspect(&archive, &archive_key).unwrap(), manifest);
        let targets = [
            RestoreTarget {
                component_id: "coordination",
                template: coordination.template(),
                destination: &restored_coordination,
                key: &restored_key,
            },
            RestoreTarget {
                component_id: "proof",
                template: adapter.template(),
                destination: &restored,
                key: &restored_key,
            },
        ];
        let report = test_restore(RestoreRequest {
            principal_id: "synthetic-admin",
            profile_id: "synthetic-profile",
            archive: &archive,
            key: &archive_key,
            targets: &targets,
            authority: &authority,
        })
        .unwrap();
        assert!(report.integrity_verified && report.all_components_quarantined);
        assert!(!report.authorization_allowed && !report.signer_recovered);
        for path in [&restored_coordination, &restored] {
            assert!(matches!(
                open_encrypted(path, &restored_key),
                Err(StorageSecurityError::QuarantinedDatabase)
            ));
        }
        let state: String = source
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT state FROM proof_jobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "running");
        for path in [&archive, &restored_coordination, &restored] {
            let bytes = std::fs::read(path).unwrap();
            assert!(!bytes.starts_with(b"SQLite format 3"));
            assert!(
                !bytes
                    .windows(b"synthetic-private-proof-backup-canary".len())
                    .any(|w| w == b"synthetic-private-proof-backup-canary")
            );
        }
    }
}

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_proof_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_proof_evidence(
        source, &TEMPLATE, path, key, binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_proof_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    wholepact_storage_security::bundle::recovery::evidence::open_proof_evidence(
        path, key, binding, expected, &TEMPLATE,
    )
}
