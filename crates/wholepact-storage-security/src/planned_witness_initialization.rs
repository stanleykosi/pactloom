//! Source foundation: retry only the empty first page of a native-planned witness birth. No recovery
//! marker or application state is cleared, imported, or adopted by this API.

use crate::{DatabaseKey, EncryptedConnection, EncryptedReadSnapshot};
use crate::{Result, StorageSecurityError};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Exact expected initialization metadata supplied by an authenticated durable
/// witness locator intent. This is correlation metadata, NOT proof of the plan's authenticity,
/// native consent, live signer admission, publication, or freshness. It has no
/// serialization or deserialization implementation and exposes no key material.
///
/// The owning namespace must authenticate its durable intent before construction, including
/// the namespace-derived independently held database key and exact target path,
/// and keep the owning directory/profile lock throughout construction, retry,
/// and typed journal initialization. An empty database has no generation marker:
/// its connection to the plan depends on that authenticated key/path assignment.
pub struct PlannedWitnessBirthInitialization {
    namespace_digest: String,
    intent_digest: String,
    destination: PathBuf,
    key_digest: Zeroizing<[u8; 32]>,
}

pub enum PlannedWitnessBirthInspection {
    AuthenticatedEmpty,
    Initialized(Box<EncryptedReadSnapshot>),
}

impl PlannedWitnessBirthInitialization {
    /// Bind the exact expected values already authenticated by the namespace owner. This
    /// performs no filesystem writes, creates no database, and grants no native
    /// authority. Reconstruct this expectation from the same durable plan after
    /// an interruption; never infer a plan from the mere existence of a file.
    pub fn new(
        namespace_digest: &str,
        intent_digest: &str,
        path: &Path,
        key: &DatabaseKey,
    ) -> Result<Self> {
        require_hash(namespace_digest)?;
        require_hash(intent_digest)?;
        crate::validate_parent(path)?;
        Ok(Self {
            namespace_digest: namespace_digest.into(),
            intent_digest: intent_digest.into(),
            destination: exact_path(path)?,
            key_digest: key_digest(key),
        })
    }

    /// Dedicated source-preserving classification. Empty state is never exposed
    /// as an ordinary database handle; all protected nonempty identities still
    /// pass the same rejection checks as the ordinary immutable reader.
    pub fn inspect(
        &self,
        path: &Path,
        key: &DatabaseKey,
        namespace_digest: &str,
        intent_digest: &str,
    ) -> Result<PlannedWitnessBirthInspection> {
        if self.namespace_digest != namespace_digest
            || self.intent_digest != intent_digest
            || self.destination != exact_path(path)?
            || *self.key_digest != *key_digest(key)
        {
            return Err(StorageSecurityError::SourceChanged);
        }
        let snapshot = crate::open_encrypted_read_only(path, key)?;
        snapshot
            .execute_batch("BEGIN DEFERRED;")
            .map_err(|_| StorageSecurityError::Database)?;
        let application: i64 = snapshot
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| StorageSecurityError::Database)?;
        let version: i64 = snapshot
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| StorageSecurityError::Database)?;
        let objects: u64 = snapshot
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(|_| StorageSecurityError::Database)?;
        if application == 0 && version == 0 && objects == 0 {
            require_empty(&snapshot)?;
            return Ok(PlannedWitnessBirthInspection::AuthenticatedEmpty);
        }
        crate::reject_quarantined_or_uninitialized(&snapshot)?;
        Ok(PlannedWitnessBirthInspection::Initialized(Box::new(
            EncryptedReadSnapshot { snapshot },
        )))
    }

    /// Authenticate the exact planned empty target without opening the source
    /// for writes. This is classification only, never initialization authority.
    pub fn verify_empty(
        &self,
        path: &Path,
        key: &DatabaseKey,
        namespace_digest: &str,
        intent_digest: &str,
    ) -> Result<()> {
        if self.namespace_digest != namespace_digest
            || self.intent_digest != intent_digest
            || self.destination != exact_path(path)?
            || *self.key_digest != *key_digest(key)
        {
            return Err(StorageSecurityError::SourceChanged);
        }
        let read = crate::open_encrypted_read_only(path, key)?;
        read.execute_batch("BEGIN DEFERRED;")
            .map_err(|_| StorageSecurityError::Database)?;
        require_empty(&read)
    }

    /// Resume only a fully authenticated, schema-empty first page left between
    /// exclusive encrypted creation and the owning typed journal constructor.
    /// The requested key/path/namespace/intent must match this plan's expectations.
    ///
    /// Wrong keys, corrupt ciphertext, every schema object, nonzero application
    /// identity/version, and previously allocated pages are rejected before a
    /// writable handle reaches the original file. Quarantine and recovered
    /// generations are never accepted. Nothing is erased or reinitialized here.
    /// A completed typed initialization must use its normal authenticated open;
    /// this is not a fallback for any arbitrary failure of that normal open.
    pub fn resume(
        &self,
        path: &Path,
        key: &DatabaseKey,
        namespace_digest: &str,
        intent_digest: &str,
    ) -> Result<EncryptedConnection> {
        if self.namespace_digest != namespace_digest
            || self.intent_digest != intent_digest
            || self.destination != exact_path(path)?
            || *self.key_digest != *key_digest(key)
        {
            return Err(StorageSecurityError::SourceChanged);
        }

        // Authenticate and inspect an encrypted copy first, preserving the
        // original base and sidecars on every failed preflight.
        let read = crate::open_encrypted_read_only(path, key)?;
        read.execute_batch("BEGIN DEFERRED;")
            .map_err(|_| StorageSecurityError::Database)?;
        require_empty(&read)?;
        drop(read);

        // The caller's owning lock excludes replacement and all writers between
        // preflight and return. Still repeat every file and logical-state check.
        crate::validate_parent(path)?;
        crate::validate_file(path, true)?;
        crate::validate_sidecars(path, false)?;
        let connection = crate::keyed_connection(path, key)?;
        require_empty(&connection)?;
        Ok(EncryptedConnection { connection })
    }
}

fn key_digest(key: &DatabaseKey) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"wholepact:planned-witness-birth-initialization-key:v1\0");
    digest.update(key.0);
    Zeroizing::new(digest.finalize().into())
}

fn require_empty(connection: &Connection) -> Result<()> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let objects: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let pages: i64 = connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let free_pages: i64 = connection
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    if application != 0 || version != 0 || objects != 0 || pages != 1 || free_pages != 0 {
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
    let file = path.file_name().ok_or(StorageSecurityError::UnsafePath)?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|_| StorageSecurityError::UnsafePath)?;
    let exact = canonical_parent.join(file);
    if !path.is_absolute() || exact != path {
        return Err(StorageSecurityError::UnsafePath);
    }
    Ok(exact)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "planned_witness_initialization_tests.rs"]
mod tests;
