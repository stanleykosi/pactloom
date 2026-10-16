//! Typed encrypted ExactTransactions journal backup boundary. The adapter locks the
//! existing open journal only; whole-profile privacy/admin/quiescence permission
//! is independently required by `bundle::snapshot`. Restores remain quarantined.
use super::TransactionCheckpointJournal;
use wholepact_storage_security::bundle::{
    BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate,
};

pub use super::super::backup::{
    HistoricalTransactionExport, HistoricalTransactionMetadata, TransactionRecoveryReference,
    archived_historical_transaction, archived_historical_transaction_export,
    archived_transaction_recovery_references as archived_recovery_references,
    historical_transaction, historical_transaction_export,
    successor_transaction_recovery_references as successor_recovery_references,
    transaction_recovery_references as recovery_references,
};

// Mirrored from the journal's compiled schema. The encrypted adapter roundtrip
// test checks exact sqlite_schema equality, so source/schema drift fails closed.
pub static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::ExactTransactions,
    application_id: 1464882264,
    schema_version: 1,
    create_sql: "CREATE TABLE transaction_intents (
                checkpoint_id TEXT PRIMARY KEY, signed_result_id TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL, scope BLOB NOT NULL CHECK(length(scope)<=16384));
                CREATE TABLE transaction_results (
                checkpoint_id TEXT PRIMARY KEY REFERENCES transaction_intents(checkpoint_id),
                bytes BLOB NOT NULL CHECK(length(bytes)<=1048576), digest TEXT NOT NULL, txid TEXT NOT NULL);
                CREATE TRIGGER immutable_transaction_intent_update BEFORE UPDATE ON transaction_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_transaction_intent_delete BEFORE DELETE ON transaction_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_transaction_result_update BEFORE UPDATE ON transaction_results BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_transaction_result_delete BEFORE DELETE ON transaction_results BEGIN SELECT RAISE(ABORT,'immutable'); END;",
};

pub struct ExactTransactionsBackupAdapter<'a> {
    journal: &'a TransactionCheckpointJournal,
}
impl<'a> ExactTransactionsBackupAdapter<'a> {
    /// This borrowed identity handle grants no backup, spending or recovery
    /// permission and never enrolls or reopens a caller-selected database path.
    pub fn new(journal: &'a TransactionCheckpointJournal) -> Self {
        Self { journal }
    }
}
impl JournalAdapter for ExactTransactionsBackupAdapter<'_> {
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

#[cfg(all(test, feature = "transaction-checkpoint", target_os = "linux"))]
mod tests {
    use super::*;
    use crate::authorization::retention::{
        SignedResultJournal, backup::SignedResultsBackupAdapter,
    };
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
            "synthetic-quiescent-authorization-backup"
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
            // This unit fixture owns all writer handles and has no effect worker.
            Ok(Box::new(SyntheticLease))
        }
    }
    #[test]
    fn encrypted_signed_and_exact_bytes_backup_preserves_fenced_intents() {
        let dir = std::env::temp_dir().join(format!(
            "wholepact-retention-backup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([0x84; 32]);
        let archive_key = DatabaseKey::from_bytes([0x85; 32]);
        let restored_key = DatabaseKey::from_bytes([0x86; 32]);
        let signed = SignedResultJournal::from_encrypted_connection(
            create_encrypted(dir.join("signed"), &key).unwrap(),
        )
        .unwrap();
        let exact = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(dir.join("exact"), &key).unwrap(),
        )
        .unwrap();
        // Storage-only synthetic bytes; this fixture makes no signature/tx claim.
        // Preserve one completed row and one intent missing exact randomized bytes.
        signed
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO signed_intents VALUES('signed','owner','key','digest',?1,?1)",
                [b"synthetic-private-signature-backup-canary".as_slice()],
            )
            .unwrap();
        signed
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO signed_results VALUES('signed',?1,'digest')",
                [b"synthetic-private-signed-backup-canary".as_slice()],
            )
            .unwrap();
        exact
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO transaction_intents VALUES('checkpoint','signed','digest',?1)",
                [b"synthetic-private-transaction-backup-canary".as_slice()],
            )
            .unwrap();
        let signed_adapter = SignedResultsBackupAdapter::new(&signed);
        let exact_adapter = ExactTransactionsBackupAdapter::new(&exact);
        let coordination = SyntheticCoordination::new(&dir.join("coordination"), &key);
        let sources = [
            RegisteredJournal::new("coordination", &coordination).unwrap(),
            RegisteredJournal::new("signed", &signed_adapter).unwrap(),
            RegisteredJournal::new("exact", &exact_adapter).unwrap(),
        ];
        let archive = dir.join("archive");
        let restored_coordination = dir.join("restored-coordination");
        let restored_signed = dir.join("restored-signed");
        let restored_exact = dir.join("restored-exact");
        let authority = SyntheticSnapshotAuthority {
            bindings: sources
                .iter()
                .map(|s| (s.id().to_owned(), s.binding()))
                .collect(),
            archive: archive.clone(),
            destinations: vec![
                restored_coordination.clone(),
                restored_signed.clone(),
                restored_exact.clone(),
            ],
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
                    (JournalKind::SignedResults, vec!["signed".into()]),
                    (JournalKind::ExactTransactions, vec!["exact".into()]),
                ]),
                absent: BTreeSet::from([
                    JournalKind::SignerConsentAuthority,
                    JournalKind::WalletScan,
                    JournalKind::ProofWitness,
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
        assert_eq!(manifest.components.len(), 3);
        assert_eq!(manifest.components.iter().map(|c| c.rows).sum::<usize>(), 3);
        assert_eq!(inspect(&archive, &archive_key).unwrap(), manifest);
        let targets = [
            RestoreTarget {
                component_id: "coordination",
                template: coordination.template(),
                destination: &restored_coordination,
                key: &restored_key,
            },
            RestoreTarget {
                component_id: "signed",
                template: signed_adapter.template(),
                destination: &restored_signed,
                key: &restored_key,
            },
            RestoreTarget {
                component_id: "exact",
                template: exact_adapter.template(),
                destination: &restored_exact,
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
        for path in [&restored_coordination, &restored_signed, &restored_exact] {
            assert!(matches!(
                open_encrypted(path, &restored_key),
                Err(StorageSecurityError::QuarantinedDatabase)
            ));
        }
        assert_eq!(
            exact
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM transaction_results", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        for path in [
            &archive,
            &restored_coordination,
            &restored_signed,
            &restored_exact,
        ] {
            let bytes = std::fs::read(path).unwrap();
            assert!(!bytes.starts_with(b"SQLite format 3"));
            assert!(
                !bytes
                    .windows(b"synthetic-private".len())
                    .any(|w| w == b"synthetic-private")
            );
        }
        drop(signed);
        drop(exact);
        drop(coordination);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_transactions_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_transactions_evidence(
        source, &TEMPLATE, path, key, binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_transactions_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    wholepact_storage_security::bundle::recovery::evidence::open_transactions_evidence(
        path, key, binding, expected, &TEMPLATE,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod historical_tests;
