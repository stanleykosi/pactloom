//! Narrow original named-verifier setup bridge; not a recovered-writer opener.
use crate::{SqliteOutbox, TransportError};
impl SqliteOutbox {
    /// Read-only classification before an original Prepared setup opens any
    /// writable handle. The caller retains its original owner lock throughout.
    /// Schema mismatch or existing rows cannot be adopted as fresh setup.
    pub fn inspect_empty_named_verifier_setup(
        path: &std::path::Path,
        key: &wholepact_storage_security::DatabaseKey,
    ) -> Result<wholepact_storage_security::EncryptedReadSnapshot, TransportError> {
        let snapshot = wholepact_storage_security::bundle::open_journal_read_snapshot(
            path,
            key,
            &crate::OUTBOX_BACKUP_TEMPLATE,
        )
        .map_err(|_| TransportError::AuthorityUnavailable)?;
        let rows: i64 = snapshot
            .connection()
            .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))
            .map_err(|_| TransportError::AuthorityUnavailable)?;
        if rows != 0 {
            return Err(TransportError::AuthorityUnavailable);
        }
        Ok(snapshot)
    }

    pub fn from_named_verifier_initialization(
        initialization: wholepact_storage_security::NamedVerifierOutboxInitialization,
    ) -> Result<Self, TransportError> {
        let outbox =
            Self::from_encrypted_connection(initialization.into_initialization_connection())?;
        outbox.require_empty_for_initial_setup()?;
        Ok(outbox)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "named_verifier_initialization_tests.rs"]
mod encrypted_tests;
