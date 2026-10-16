//! Resume only the pristine encrypted first page of a separately authorized
//! original named-verifier outbox setup. No authority, recovery activation,
//! credential generation, file deletion, rekeying or mailbox replacement.
use crate::{
    DatabaseKey, EncryptedConnection, EncryptedReadSnapshot, Result, StorageSecurityError,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Construct only after authenticating the original encrypted Prepared setup
/// intent. The exact canonical destination, original setup NativeDecision digest,
/// verifier identity digest and database-key commitment must already be durable.
/// This nonserializable expectation carries correlation, never native authority.
/// Keep the original owning directory lock and genuine fresh native setup
/// approval throughout inspection, resume and the typed outbox constructor.
pub struct PlannedNamedVerifierOutboxInitialization {
    verifier_digest: String,
    setup_review_digest: String,
    destination: PathBuf,
    key_commitment: Zeroizing<[u8; 32]>,
}
pub enum PlannedNamedVerifierOutboxInspection {
    AuthenticatedPristineEmpty,
    /// Classify this immutable snapshot using OUTBOX_BACKUP_TEMPLATE before the
    /// ordinary quiescent opener. Unknown/nonempty mailboxes cannot be adopted.
    Initialized(Box<EncryptedReadSnapshot>),
}
/// The original setup may hand this only to its typed outbox initializer.
/// It does not assert an owner decision, signer permission or writer freshness.
pub struct NamedVerifierOutboxInitialization {
    connection: EncryptedConnection,
}
impl NamedVerifierOutboxInitialization {
    /// Bridge for the transport crate's dedicated typed constructor. This is an
    /// authenticated empty database, not an approval or an activated recovery.
    pub fn into_initialization_connection(self) -> EncryptedConnection {
        self.connection
    }
}
impl PlannedNamedVerifierOutboxInitialization {
    /// Returns a commitment to include in the original encrypted SetupIntent
    /// before creating a mailbox. It is not a transport identity or approval.
    pub fn database_key_commitment(key: &DatabaseKey) -> [u8; 32] {
        *key_commitment(key)
    }
    pub fn new(
        verifier_digest: &str,
        setup_review_digest: &str,
        destination: &Path,
        key: &DatabaseKey,
        retained_key_commitment: &[u8; 32],
    ) -> Result<Self> {
        require_hash(verifier_digest)?;
        require_hash(setup_review_digest)?;
        crate::validate_parent(destination)?;
        let commitment = key_commitment(key);
        if *commitment != *retained_key_commitment {
            return Err(StorageSecurityError::SourceChanged);
        }
        Ok(Self {
            verifier_digest: verifier_digest.into(),
            setup_review_digest: setup_review_digest.into(),
            destination: exact_path(destination)?,
            key_commitment: commitment,
        })
    }
    fn check(
        &self,
        destination: &Path,
        key: &DatabaseKey,
        verifier_digest: &str,
        setup_review_digest: &str,
        retained_key_commitment: &[u8; 32],
    ) -> Result<()> {
        if self.verifier_digest != verifier_digest
            || self.setup_review_digest != setup_review_digest
            || self.destination != exact_path(destination)?
            || *self.key_commitment != *key_commitment(key)
            || *self.key_commitment != *retained_key_commitment
        {
            return Err(StorageSecurityError::SourceChanged);
        }
        Ok(())
    }
    pub fn inspect(
        &self,
        destination: &Path,
        key: &DatabaseKey,
        verifier_digest: &str,
        setup_review_digest: &str,
        retained_key_commitment: &[u8; 32],
    ) -> Result<PlannedNamedVerifierOutboxInspection> {
        self.check(
            destination,
            key,
            verifier_digest,
            setup_review_digest,
            retained_key_commitment,
        )?;
        // All SQLite inspection is over a private encrypted snapshot. This
        // preserves original base/WAL/SHM/rollback sidecars on rejection.
        let snapshot = crate::open_encrypted_read_only(destination, key)?;
        snapshot
            .execute_batch("BEGIN DEFERRED;")
            .map_err(|_| StorageSecurityError::Database)?;
        let application: i64 = snapshot
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| StorageSecurityError::Database)?;
        let version: i64 = snapshot
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| StorageSecurityError::Database)?;
        let objects: i64 = snapshot
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(|_| StorageSecurityError::Database)?;
        if application == 0 && version == 0 && objects == 0 {
            require_pristine_empty(&snapshot)?;
            return Ok(PlannedNamedVerifierOutboxInspection::AuthenticatedPristineEmpty);
        }
        crate::reject_quarantined_or_uninitialized(&snapshot)?;
        Ok(PlannedNamedVerifierOutboxInspection::Initialized(Box::new(
            EncryptedReadSnapshot { snapshot },
        )))
    }
    /// Resume only the same durable plan's authenticated pristine first page.
    /// Do not call as a catch-all fallback after arbitrary normal-open failures.
    /// Zero-length files have no authenticated encrypted page and remain blocked.
    pub fn resume(
        &self,
        destination: &Path,
        key: &DatabaseKey,
        verifier_digest: &str,
        setup_review_digest: &str,
        retained_key_commitment: &[u8; 32],
    ) -> Result<NamedVerifierOutboxInitialization> {
        self.check(
            destination,
            key,
            verifier_digest,
            setup_review_digest,
            retained_key_commitment,
        )?;
        let read = crate::open_encrypted_read_only(destination, key)?;
        read.execute_batch("BEGIN DEFERRED;")
            .map_err(|_| StorageSecurityError::Database)?;
        require_pristine_empty(&read)?;
        // The actual owner lock must still exclude all writers/replacement.
        // Keep the authenticated source stamps through writable allocation.
        crate::validate_parent(destination)?;
        crate::validate_file(destination, true)?;
        crate::validate_sidecars(destination, false)?;
        let connection = crate::keyed_connection_checked(destination, key, false, Some(&read))?;
        require_pristine_empty(&connection)?;
        Ok(NamedVerifierOutboxInitialization {
            connection: EncryptedConnection { connection },
        })
    }
}
fn key_commitment(key: &DatabaseKey) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:planned-named-verifier-outbox-key:v1\0");
    hash.update(key.0);
    Zeroizing::new(hash.finalize().into())
}
fn require_pristine_empty(connection: &Connection) -> Result<()> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let objects: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let pages: i64 = connection
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let free: i64 = connection
        .pragma_query_value(None, "freelist_count", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    pristine_state(application, version, objects, pages, free)
}
fn pristine_state(
    application: i64,
    version: i64,
    objects: i64,
    pages: i64,
    free: i64,
) -> Result<()> {
    if (application, version, objects, pages, free) != (0, 0, 0, 1, 0) {
        return Err(StorageSecurityError::SourceChanged);
    }
    Ok(())
}
fn require_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StorageSecurityError::SourceChanged);
    }
    Ok(())
}
fn exact_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().ok_or(StorageSecurityError::UnsafePath)?;
    let filename = path.file_name().ok_or(StorageSecurityError::UnsafePath)?;
    let exact = std::fs::canonicalize(parent)
        .map_err(|_| StorageSecurityError::UnsafePath)?
        .join(filename);
    if !path.is_absolute() || exact != path {
        return Err(StorageSecurityError::UnsafePath);
    }
    Ok(exact)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_pristine_first_page_is_resumable() {
        assert!(pristine_state(0, 0, 0, 1, 0).is_ok());
        for state in [
            (0, 0, 0, 0, 0),
            (0, 0, 0, 2, 0),
            (0, 0, 0, 1, 1),
            (0, 1, 0, 1, 0),
            (1, 0, 0, 1, 0),
            (0, 0, 1, 1, 0),
            (crate::bundle::QUARANTINE_APPLICATION_ID, 0, 0, 1, 0),
            (
                crate::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID,
                0,
                0,
                1,
                0,
            ),
        ] {
            assert!(pristine_state(state.0, state.1, state.2, state.3, state.4).is_err());
        }
    }
    #[test]
    fn original_intent_digest_is_exact_lowercase_hash() {
        assert!(require_hash(&"ab".repeat(32)).is_ok());
        for value in ["".into(), "ab".repeat(31), "AB".repeat(32), "zz".repeat(32)] {
            assert!(require_hash(&value).is_err());
        }
        // No credentials, native approval or filesystem database are fabricated.
    }
}
