//! Typed encrypted SignedResults journal backup boundary. The adapter locks the
//! existing open journal only; whole-profile privacy/admin/quiescence permission
//! is independently required by `bundle::snapshot`. Restores remain quarantined.
use super::SignedResultJournal;
use wholepact_storage_security::bundle::{
    BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate,
};

mod historical;
mod recovery_references;
pub use historical::{
    HistoricalSignedResultMetadata, archived_historical_signed_result, historical_signed_result,
};
#[cfg(feature = "transaction-checkpoint")]
pub use historical::{
    HistoricalTransactionExport, HistoricalTransactionMetadata, archived_historical_transaction,
    archived_historical_transaction_export, historical_transaction, historical_transaction_export,
};
pub use recovery_references::{
    SignedRecoveryReference, archived_recovery_references, recovery_references,
    successor_recovery_references,
};
#[cfg(feature = "transaction-checkpoint")]
pub use recovery_references::{
    TransactionRecoveryReference, archived_transaction_recovery_references,
    successor_transaction_recovery_references, transaction_recovery_references,
};

// Mirrored from the journal's compiled schema. The encrypted adapter roundtrip
// test checks exact sqlite_schema equality, so source/schema drift fails closed.
pub static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::SignedResults,
    application_id: 1464882002,
    schema_version: 1,
    create_sql: "CREATE TABLE signed_intents (
                result_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, idem_key TEXT NOT NULL,
                request_digest TEXT NOT NULL, scope BLOB NOT NULL CHECK(length(scope)<=16384),
                signatures BLOB NOT NULL CHECK(length(signatures)<=10240),
                UNIQUE(principal_id,idem_key));
                CREATE TABLE signed_results (
                result_id TEXT PRIMARY KEY REFERENCES signed_intents(result_id),
                bytes BLOB NOT NULL CHECK(length(bytes)<=1048576), digest TEXT NOT NULL);
                CREATE TRIGGER immutable_signed_intent_update BEFORE UPDATE ON signed_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_signed_intent_delete BEFORE DELETE ON signed_intents BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_signed_result_update BEFORE UPDATE ON signed_results BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER immutable_signed_result_delete BEFORE DELETE ON signed_results BEGIN SELECT RAISE(ABORT,'immutable'); END;",
};

pub struct SignedResultsBackupAdapter<'a> {
    journal: &'a SignedResultJournal,
}
impl<'a> SignedResultsBackupAdapter<'a> {
    /// This borrowed identity handle grants no backup, spending or recovery
    /// permission and never enrolls or reopens a caller-selected database path.
    pub fn new(journal: &'a SignedResultJournal) -> Self {
        Self { journal }
    }
}
impl JournalAdapter for SignedResultsBackupAdapter<'_> {
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

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_signed_results_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_signed_results_evidence(
        source, &TEMPLATE, path, key, binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_signed_results_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    wholepact_storage_security::bundle::recovery::evidence::open_signed_results_evidence(
        path, key, binding, expected, &TEMPLATE,
    )
}
