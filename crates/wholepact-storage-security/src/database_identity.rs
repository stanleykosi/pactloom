//! Read-only binding of independently authenticated handles to one disk file.
//! This is neither an authority token nor a writer API. The embedding owner must
//! hold its existing private profile/directory replacement lock for the lifetime
//! of both handles. Hostile same-user/OS replacement outside that lock remains
//! outside the qualified boundary; identity checks do not create an OS sandbox.
use super::{Result, StorageSecurityError, validate_file, validate_parent};
use rusqlite::{Connection, ffi};
use std::path::PathBuf;

/// Opaque identity captured only from an authenticated EncryptedConnection.
/// No caller constructor, path/key getter, serialization or key hash exists.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseFileIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
}
impl DatabaseFileIdentity {
    /// Compare with an actual live connection, including SQLite's own retained
    /// file handle. This is a read-only check and cannot turn an unkeyed handle
    /// into an EncryptedConnection or confer permission to write a journal.
    pub fn check_current(&self, connection: &Connection) -> Result<()> {
        if self != &capture(connection)? {
            return Err(StorageSecurityError::SourceChanged);
        }
        Ok(())
    }
    /// Domain-separated commitment to this factory-authenticated file origin.
    /// No key or raw path is disclosed. This is correlation, not freshness,
    /// native permission, rollback detection or an authorization factory.
    pub fn origin_commitment(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let path = self.canonical_path.as_os_str().as_encoded_bytes();
        let mut hash = Sha256::new();
        hash.update(b"wholepact:authenticated-database-file-origin:v1\0");
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path);
        hash.update(self.device.to_le_bytes());
        hash.update(self.inode.to_le_bytes());
        hash.finalize().into()
    }
    /// Recheck the retained authenticated identity under the embedding owner's
    /// original exclusive Directory lock after its connection moved into a
    /// maintained journal. This DOES NOT inspect that journal's live SQLite
    /// handle and is not interchangeable with check_current(connection).
    /// Hostile same-user replacement bypassing that lock stays outside scope.
    pub fn check_retained_owner_path(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            validate_parent(&self.canonical_path)?;
            validate_file(&self.canonical_path, true)?;
            if std::fs::canonicalize(&self.canonical_path)
                .map_err(|_| StorageSecurityError::SourceChanged)?
                != self.canonical_path
            {
                return Err(StorageSecurityError::SourceChanged);
            }
            let metadata = std::fs::symlink_metadata(&self.canonical_path)
                .map_err(|_| StorageSecurityError::SourceChanged)?;
            if !metadata.is_file() || metadata.dev() != self.device || metadata.ino() != self.inode
            {
                return Err(StorageSecurityError::SourceChanged);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StorageSecurityError::UnsupportedPlatform)
        }
    }
}

pub(super) fn capture(connection: &Connection) -> Result<DatabaseFileIdentity> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        main_not_moved(connection)?;
        let path = connection
            .path()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .ok_or(StorageSecurityError::UnsafePath)?;
        // Use the same file/sidecar ownership qualification as encrypted open.
        // Final symlinks, nonregular files and hardlinks are never identities.
        validate_parent(&path)?;
        validate_file(&path, true)?;
        let canonical_path =
            std::fs::canonicalize(&path).map_err(|_| StorageSecurityError::SourceChanged)?;
        let first =
            std::fs::symlink_metadata(&path).map_err(|_| StorageSecurityError::SourceChanged)?;
        let canonical = std::fs::symlink_metadata(&canonical_path)
            .map_err(|_| StorageSecurityError::SourceChanged)?;
        if !first.is_file()
            || !canonical.is_file()
            || first.dev() != canonical.dev()
            || first.ino() != canonical.ino()
        {
            return Err(StorageSecurityError::SourceChanged);
        }
        main_not_moved(connection)?;
        let last =
            std::fs::symlink_metadata(&path).map_err(|_| StorageSecurityError::SourceChanged)?;
        if !last.is_file() || first.dev() != last.dev() || first.ino() != last.ino() {
            return Err(StorageSecurityError::SourceChanged);
        }
        Ok(DatabaseFileIdentity {
            canonical_path,
            device: first.dev(),
            inode: first.ino(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = connection;
        Err(StorageSecurityError::UnsupportedPlatform)
    }
}

/// Crate-private capture from the retained ORIGINAL source descriptor of an
/// already authenticated encrypted read snapshot. Never pass a snapshot-copy
/// descriptor or construct this identity from caller metadata. The owning
/// SourceSet checks the complete original main/WAL/journal/SHM set around this.
#[cfg(target_os = "linux")]
pub(crate) fn capture_authenticated_read_source(
    path: &std::path::Path,
    file: &std::fs::File,
) -> Result<DatabaseFileIdentity> {
    use std::os::unix::fs::MetadataExt;
    validate_parent(path)?;
    validate_file(path, true)?;
    let canonical_path =
        std::fs::canonicalize(path).map_err(|_| StorageSecurityError::SourceChanged)?;
    if canonical_path != path {
        return Err(StorageSecurityError::SourceChanged);
    }
    let descriptor = file
        .metadata()
        .map_err(|_| StorageSecurityError::SourceChanged)?;
    let current =
        std::fs::symlink_metadata(path).map_err(|_| StorageSecurityError::SourceChanged)?;
    if !descriptor.is_file()
        || descriptor.dev() != current.dev()
        || descriptor.ino() != current.ino()
    {
        return Err(StorageSecurityError::SourceChanged);
    }
    Ok(DatabaseFileIdentity {
        canonical_path,
        device: descriptor.dev(),
        inode: descriptor.ino(),
    })
}

fn main_not_moved(connection: &Connection) -> Result<()> {
    let mut moved: std::ffi::c_int = -1;
    // SAFETY: the borrowed Connection owns its live SQLite handle; `main` is a
    // static nul-terminated database name, and HAS_MOVED synchronously writes one
    // c_int into the correctly aligned stack variable. No SQL/key data is read.
    let rc = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_HAS_MOVED,
            (&mut moved as *mut std::ffi::c_int).cast(),
        )
    };
    accept_not_moved(rc, moved)
}
fn accept_not_moved(rc: std::ffi::c_int, moved: std::ffi::c_int) -> Result<()> {
    // Unimplemented VFS controls, errors, unchanged sentinel or unexpected values
    // all fail closed. Path equality alone cannot substitute for a handle check.
    if rc != ffi::SQLITE_OK || moved != 0 {
        return Err(StorageSecurityError::SourceChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_commitment_does_not_alias_path_device_or_inode() {
        // Pure tuple commitment fixture; not an authenticated production identity.
        let original = DatabaseFileIdentity {
            canonical_path: "/synthetic/one.sqlite".into(),
            device: 1,
            inode: 2,
        };
        assert_eq!(
            original.origin_commitment(),
            original.clone().origin_commitment()
        );
        for changed in 0..3 {
            let mut other = original.clone();
            match changed {
                0 => other.canonical_path = "/synthetic/two.sqlite".into(),
                1 => other.device += 1,
                _ => other.inode += 1,
            }
            assert_ne!(original.origin_commitment(), other.origin_commitment());
        }
    }
    #[test]
    fn unsupported_or_failed_handle_check_never_accepts_path_only_identity() {
        for (rc, moved) in [
            (ffi::SQLITE_NOTFOUND, 0),
            (ffi::SQLITE_ERROR, 0),
            (ffi::SQLITE_OK, 1),
            (ffi::SQLITE_OK, -1),
            (ffi::SQLITE_OK, 2),
        ] {
            assert!(matches!(
                accept_not_moved(rc, moved),
                Err(StorageSecurityError::SourceChanged)
            ));
        }
        assert!(accept_not_moved(ffi::SQLITE_OK, 0).is_ok());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_live_handle_rejects_path_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("synthetic-identity.sqlite");
        let key = super::super::DatabaseKey::from_bytes([0x71; 32]);
        let connection = super::super::create_encrypted(&path, &key).unwrap();
        connection
            .connection()
            .execute_batch("CREATE TABLE synthetic(v INTEGER);")
            .unwrap();
        let identity = connection.database_identity().unwrap();
        identity.check_current(connection.connection()).unwrap();
        // This intentionally violates the owner lock contract, to confirm the
        // defensive handle check detects the stale connection rather than rebinds.
        std::fs::rename(&path, directory.path().join("retained-original.sqlite")).unwrap();
        std::fs::write(&path, [0u8; 4096]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(identity.check_current(connection.connection()).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_snapshot_identity_is_original_not_private_copy_and_preserves_tree() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("synthetic-source.sqlite");
        let key = crate::DatabaseKey::from_bytes([0x81; 32]);
        let connection = crate::create_encrypted(&path, &key).unwrap();
        connection
            .connection()
            .execute_batch("CREATE TABLE synthetic(v INTEGER); INSERT INTO synthetic VALUES(1);")
            .unwrap();
        let original = connection.database_identity().unwrap();
        drop(connection);
        let before = crate::tests::tree_fingerprint(directory.path());
        let snapshot = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
        assert!(snapshot.source_database_identity().unwrap() == original);
        assert!(capture(snapshot.connection()).unwrap() != original);
        snapshot.check_source_unchanged().unwrap();
        assert_eq!(crate::tests::tree_fingerprint(directory.path()), before);
        drop(snapshot);
        assert_eq!(crate::tests::tree_fingerprint(directory.path()), before);
        assert!(
            crate::open_encrypted_read_snapshot(&path, &crate::DatabaseKey::from_bytes([0x82; 32]))
                .is_err()
        );
        assert_eq!(crate::tests::tree_fingerprint(directory.path()), before);
        let snapshot = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
        std::fs::rename(&path, directory.path().join("retained-original.sqlite")).unwrap();
        std::fs::copy(directory.path().join("retained-original.sqlite"), &path).unwrap();
        let before = crate::tests::tree_fingerprint(directory.path());
        assert!(snapshot.check_source_unchanged().is_err());
        assert!(snapshot.source_database_identity().is_err());
        assert_eq!(crate::tests::tree_fingerprint(directory.path()), before);
        drop(snapshot);
        let replacement = crate::open_encrypted_read_snapshot(&path, &key).unwrap();
        assert!(replacement.source_database_identity().unwrap() != original);
    }
}
