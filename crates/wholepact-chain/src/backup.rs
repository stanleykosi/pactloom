//! Typed encrypted submission-journal backup bridge. The global bundle lease
//! must quiesce all writers; this mutex protects the enrolled open connection.
use crate::EncryptedSubmissionJournal;
use std::sync::Mutex;
use wholepact_storage_security::bundle::{
    BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate,
};

pub static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::Submission,
    application_id: 0x5750534a,
    schema_version: 3,
    create_sql: concat!("CREATE TABLE submission_intents(operation TEXT PRIMARY KEY NOT NULL CHECK(length(operation) BETWEEN 16 AND 128), bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 2097152), digest TEXT NOT NULL CHECK(length(digest)=64), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2)) STRICT;
CREATE TABLE submission_journal_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL CHECK(length(identity)=64)) STRICT;
CREATE TABLE submission_bindings(operation TEXT PRIMARY KEY NOT NULL REFERENCES submission_intents(operation), obligation TEXT NOT NULL UNIQUE, descriptor TEXT NOT NULL CHECK(length(descriptor)<=4096)) STRICT;
CREATE TABLE submission_attempts(operation TEXT NOT NULL REFERENCES submission_intents(operation), number INTEGER NOT NULL CHECK(number BETWEEN 1 AND 128), source TEXT NOT NULL, started INTEGER NOT NULL CHECK(started>=0), outcome TEXT NOT NULL CHECK(length(outcome)<=1024), PRIMARY KEY(operation,number)) STRICT;
CREATE TABLE submission_observations(operation TEXT PRIMARY KEY NOT NULL REFERENCES submission_intents(operation), report TEXT NOT NULL CHECK(length(report)<=16384)) STRICT;", include_str!("settlement_evidence_schema.sql")),
};
pub struct SubmissionBackupAdapter<'a> {
    journal: &'a Mutex<EncryptedSubmissionJournal>,
}
impl<'a> SubmissionBackupAdapter<'a> {
    pub fn new(journal: &'a Mutex<EncryptedSubmissionJournal>) -> Self {
        Self { journal }
    }
}
impl JournalAdapter for SubmissionBackupAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        &TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&rusqlite::Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        let journal = self.journal.lock().map_err(|_| BundleError::Storage)?;
        visitor(&journal.connection)
    }
}

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_submission_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_submission_evidence(
        source, &TEMPLATE, path, key, binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_submission_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    wholepact_storage_security::bundle::recovery::evidence::open_submission_evidence(
        path, key, binding, expected, &TEMPLATE,
    )
}
