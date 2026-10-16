//! Retry only the empty first page of a planned auxiliary database. No recovery
//! marker or application state is cleared, imported, or adopted by this API.

use super::{BundleError, GenerationBinding, Result, bound_path};
use crate::{DatabaseKey, EncryptedConnection};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Exact expected initialization metadata supplied by an authenticated durable
/// host plan. This is correlation metadata, NOT proof of the plan's authenticity,
/// native consent, live signer admission, publication, or freshness. It has no
/// serialization or deserialization implementation and exposes no key material.
///
/// The host must authenticate its durable plan before construction, including
/// the generation's independently generated database key and exact target path,
/// and keep the owning directory/profile lock throughout construction, retry,
/// and typed journal initialization. An empty database has no generation marker:
/// its connection to the plan depends on that authenticated key/path assignment.
pub struct PlannedEmptyInitialization {
    generation: GenerationBinding,
    destination: String,
    key_digest: Zeroizing<[u8; 32]>,
}

impl PlannedEmptyInitialization {
    /// Bind the exact expected values already authenticated by the host. This
    /// performs no filesystem writes, creates no database, and grants no native
    /// authority. Reconstruct this expectation from the same durable plan after
    /// an interruption; never infer a plan from the mere existence of a file.
    pub fn new(binding: &GenerationBinding, path: &Path, key: &DatabaseKey) -> Result<Self> {
        let destination = bound_path(path)?;
        crate::validate_parent(path)?;
        Ok(Self {
            generation: binding.clone(),
            destination,
            key_digest: key_digest(key),
        })
    }

    /// Resume only a fully authenticated, schema-empty first page left between
    /// exclusive encrypted creation and the owning typed journal constructor.
    /// The requested key/path/generation must match this plan's expectations.
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
        binding: &GenerationBinding,
    ) -> Result<EncryptedConnection> {
        if self.generation != *binding
            || self.destination != bound_path(path)?
            || *self.key_digest != *key_digest(key)
        {
            return Err(BundleError::Integrity);
        }

        // Authenticate and inspect an encrypted copy first, preserving the
        // original base and sidecars on every failed preflight.
        let read = crate::open_encrypted_read_only(path, key)?;
        read.execute_batch("BEGIN DEFERRED;")?;
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
    digest.update(b"wholepact:planned-empty-initialization-key:v1\0");
    digest.update(key.0);
    Zeroizing::new(digest.finalize().into())
}

fn require_empty(connection: &Connection) -> Result<()> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let objects: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let free_pages: i64 =
        connection.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
    if application != 0 || version != 0 || objects != 0 || pages != 1 || free_pages != 0 {
        return Err(BundleError::Integrity);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{
        StorageSecurityError, bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID,
    };
    use std::{fs, os::unix::fs::PermissionsExt};

    // Synthetic storage-only fixtures; no native publication or financial
    // activation is established by an initialization handle.
    fn directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn binding() -> GenerationBinding {
        GenerationBinding::new(&"a1".repeat(32), &"b2".repeat(32)).unwrap()
    }

    #[test]
    fn planned_empty_initialization_resumes_only_before_typed_schema_commit() {
        let directory = directory();
        let path = directory.path().join("auxiliary.sqlite");
        let key = DatabaseKey::from_bytes([231; 32]);
        let binding = binding();
        let plan = PlannedEmptyInitialization::new(&binding, &path, &key).unwrap();
        assert!(!path.exists());
        assert!(plan.resume(&path, &key, &binding).is_err());
        assert!(!path.exists());
        drop(crate::create_encrypted(&path, &key).unwrap());
        assert!(matches!(
            crate::open_encrypted(&path, &key),
            Err(StorageSecurityError::UninitializedDatabase)
        ));
        // A second interruption before typed initialization remains resumable.
        drop(plan.resume(&path, &key, &binding).unwrap());
        let resumed = plan.resume(&path, &key, &binding).unwrap();
        resumed.connection().execute_batch(
            "BEGIN IMMEDIATE; CREATE TABLE typed_journal(id INTEGER PRIMARY KEY); PRAGMA user_version=1; COMMIT;",
        ).unwrap();
        drop(resumed);
        let before = crate::tests::tree_fingerprint(directory.path());
        assert!(plan.resume(&path, &key, &binding).is_err());
        assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
        assert!(crate::open_encrypted(&path, &key).is_ok());
    }

    #[test]
    fn planned_empty_initialization_rejects_conflicting_binding_path_and_key() {
        let directory = directory();
        let path = directory.path().join("auxiliary.sqlite");
        let other_path = directory.path().join("other.sqlite");
        let key = DatabaseKey::from_bytes([232; 32]);
        let wrong_key = DatabaseKey::from_bytes([233; 32]);
        let binding = binding();
        let other_generation =
            GenerationBinding::new(&"c3".repeat(32), binding.inventory_digest()).unwrap();
        let other_inventory =
            GenerationBinding::new(binding.generation_id(), &"d4".repeat(32)).unwrap();
        drop(crate::create_encrypted(&path, &key).unwrap());
        drop(crate::create_encrypted(&other_path, &key).unwrap());
        let plan = PlannedEmptyInitialization::new(&binding, &path, &key).unwrap();
        let before = crate::tests::tree_fingerprint(directory.path());
        for conflicting in [&other_generation, &other_inventory] {
            assert!(plan.resume(&path, &key, conflicting).is_err());
        }
        assert!(plan.resume(&other_path, &key, &binding).is_err());
        assert!(plan.resume(&path, &wrong_key, &binding).is_err());
        // Even consistent caller metadata cannot authenticate the wrong key.
        let wrong_plan = PlannedEmptyInitialization::new(&binding, &path, &wrong_key).unwrap();
        assert!(wrong_plan.resume(&path, &wrong_key, &binding).is_err());
        assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
    }

    #[test]
    fn planned_empty_initialization_rejects_tampered_ciphertext_without_mutation() {
        let directory = directory();
        let path = directory.path().join("auxiliary.sqlite");
        let key = DatabaseKey::from_bytes([234; 32]);
        let binding = binding();
        drop(crate::create_encrypted(&path, &key).unwrap());
        let plan = PlannedEmptyInitialization::new(&binding, &path, &key).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[100] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        let before = crate::tests::tree_fingerprint(directory.path());
        assert!(plan.resume(&path, &key, &binding).is_err());
        assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
    }

    #[test]
    fn planned_empty_initialization_rejects_existing_objects_and_reserved_identities() {
        let directory = directory();
        let key = DatabaseKey::from_bytes([235; 32]);
        let binding = binding();
        let statements = [
            "CREATE TABLE existing_data(value);".to_owned(),
            "CREATE VIEW existing_view AS SELECT 1;".to_owned(),
            "CREATE TABLE wholepact_recovered_generation(value);".to_owned(),
            "CREATE TABLE wholepact_bundle_quarantine(value);".to_owned(),
            "PRAGMA user_version=1;".to_owned(),
            "PRAGMA application_id=123;".to_owned(),
            format!(
                "PRAGMA application_id={};",
                crate::bundle::QUARANTINE_APPLICATION_ID
            ),
            format!("PRAGMA application_id={RECOVERED_GENERATION_APPLICATION_ID};"),
            "CREATE TABLE discarded(value); DROP TABLE discarded;".to_owned(),
        ];
        for (index, sql) in statements.iter().enumerate() {
            let path = directory.path().join(format!("existing-{index}.sqlite"));
            let connection = crate::create_encrypted(&path, &key).unwrap();
            connection.connection().execute_batch(sql).unwrap();
            drop(connection);
            let plan = PlannedEmptyInitialization::new(&binding, &path, &key).unwrap();
            let before = crate::tests::tree_fingerprint(directory.path());
            assert!(
                plan.resume(&path, &key, &binding).is_err(),
                "accepted case {index}"
            );
            assert_eq!(before, crate::tests::tree_fingerprint(directory.path()));
        }
    }
}
