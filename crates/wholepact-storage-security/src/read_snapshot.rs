//! Source-preserving encrypted SQLite reads. READ_ONLY alone is insufficient:
//! SQLite can create, rebuild, or update WAL shared-memory files on a read.
//!
//! Callers must exclude source writers/checkpointers and file replacement using
//! their owning profile/recovery locks for the complete capture. The identity,
//! length and modification checks below detect races; they are not a substitute
//! for that external quiescence or a claim of cross-database atomicity.
use crate::{DatabaseKey, Result, StorageSecurityError};
use rusqlite::Connection;
use std::{fs, ops::Deref, path::Path};

pub(crate) const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

/// The field order is deliberate: close SQLite before removing its directory.
/// TempDir attempts cleanup on normal/error drops. Crashes or cleanup failures
/// can leave private encrypted remnants; this is not a secure-deletion promise.
pub(crate) struct ReadOnlySnapshot {
    connection: Connection,
    _directory: tempfile::TempDir,
    #[cfg(unix)]
    sources: capture::SourceSet,
}
impl Deref for ReadOnlySnapshot {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.connection
    }
}
impl ReadOnlySnapshot {
    /// Compare the original descriptors and complete path inventory, never the
    /// temporary SQLite copy. This is a race detector under an owning lock, not
    /// protection against hostile same-user filesystem replacement after check.
    pub(crate) fn check_source_unchanged(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            self.sources.check_for(path)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(StorageSecurityError::UnsupportedPlatform)
        }
    }
    pub(crate) fn source_database_identity(&self) -> Result<crate::DatabaseFileIdentity> {
        #[cfg(target_os = "linux")]
        {
            self.sources.authenticated_main_identity()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StorageSecurityError::UnsupportedPlatform)
        }
    }
    pub(crate) fn check_retained_source_unchanged(&self) -> Result<()> {
        #[cfg(unix)]
        {
            self.sources.check_unchanged()
        }
        #[cfg(not(unix))]
        {
            Err(StorageSecurityError::UnsupportedPlatform)
        }
    }
    pub(crate) fn open(path: &Path, key: &DatabaseKey) -> Result<Self> {
        Self::open_bounded(path, key, MAX_SNAPSHOT_BYTES)
    }
    pub(crate) fn open_bounded(path: &Path, key: &DatabaseKey, max_bytes: u64) -> Result<Self> {
        crate::validate_parent(path)?;
        crate::validate_sidecars(path, false)?;
        #[cfg(unix)]
        {
            capture::open(path, key, max_bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = (key, max_bytes);
            Err(StorageSecurityError::UnsupportedPlatform)
        }
    }
}

#[cfg(unix)]
pub(crate) mod capture {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        path::PathBuf,
    };

    // SHM is validated and included in the bound/change checks, but never copied:
    // its cached WAL index and locks are process-local, not durable evidence.
    const SUFFIXES: [&str; 4] = ["", "-wal", "-journal", "-shm"];

    #[derive(PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        length: u64,
        modified: (i64, i64),
        changed: (i64, i64),
        mode: u32,
        owner: u32,
        group: u32,
        links: u64,
    }
    impl Stamp {
        fn read(metadata: &fs::Metadata) -> Result<Self> {
            // SAFETY: geteuid has no arguments or memory effects.
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(StorageSecurityError::UnsafePath);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                mode: metadata.mode(),
                owner: metadata.uid(),
                group: metadata.gid(),
                links: metadata.nlink(),
            })
        }
    }
    struct SourceFile {
        file: fs::File,
        stamp: Stamp,
    }
    pub(crate) struct SourceSet {
        path: PathBuf,
        files: Vec<Option<SourceFile>>,
    }
    fn suffixed(path: &Path, suffix: &str) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    }
    impl SourceSet {
        pub(super) fn check_for(&self, path: &Path) -> Result<()> {
            if self.path != path {
                return Err(StorageSecurityError::SourceChanged);
            }
            self.check_unchanged()
        }
        pub(crate) fn open(path: &Path) -> Result<Self> {
            Self::open_bounded(path, MAX_SNAPSHOT_BYTES)
        }
        fn open_bounded(path: &Path, max_bytes: u64) -> Result<Self> {
            crate::validate_parent(path)?;
            crate::validate_sidecars(path, false)?;
            let mut total = 0u64;
            let mut files = Vec::new();
            for suffix in SUFFIXES {
                let file = match fs::OpenOptions::new()
                    .read(true)
                    // NONBLOCK prevents a replaced FIFO from hanging before
                    // descriptor metadata can reject the non-regular file.
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(suffixed(path, suffix))
                {
                    Ok(file) => file,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() =>
                    {
                        files.push(None);
                        continue;
                    }
                    Err(_) => return Err(StorageSecurityError::Io),
                };
                let stamp = Stamp::read(&file.metadata().map_err(|_| StorageSecurityError::Io)?)?;
                total = total
                    .checked_add(stamp.length)
                    .filter(|total| *total <= max_bytes)
                    .ok_or(StorageSecurityError::SnapshotLimit)?;
                if suffix.is_empty() {
                    if stamp.length < 4096 {
                        return Err(StorageSecurityError::MissingDatabase);
                    }
                    let mut header = [0u8; 16];
                    file.read_exact_at(&mut header, 0)
                        .map_err(|_| StorageSecurityError::AuthenticationFailed)?;
                    if header == crate::HEADER {
                        return Err(StorageSecurityError::PlaintextRefused);
                    }
                }
                files.push(Some(SourceFile { file, stamp }));
            }
            let sources = Self {
                path: path.to_path_buf(),
                files,
            };
            sources.check_unchanged()?;
            Ok(sources)
        }
        pub(crate) fn check_unchanged(&self) -> Result<()> {
            for (suffix, source) in SUFFIXES.into_iter().zip(&self.files) {
                let actual = match fs::symlink_metadata(suffixed(&self.path, suffix)) {
                    Ok(metadata) => Some(Stamp::read(&metadata)?),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(_) => return Err(StorageSecurityError::Io),
                };
                if actual.as_ref() != source.as_ref().map(|source| &source.stamp) {
                    return Err(StorageSecurityError::SourceChanged);
                }
                if let Some(source) = source {
                    let descriptor = Stamp::read(
                        &source
                            .file
                            .metadata()
                            .map_err(|_| StorageSecurityError::Io)?,
                    )?;
                    if descriptor != source.stamp {
                        return Err(StorageSecurityError::SourceChanged);
                    }
                }
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        pub(super) fn authenticated_main_identity(&self) -> Result<crate::DatabaseFileIdentity> {
            self.check_unchanged()?;
            let original = self
                .files
                .first()
                .and_then(Option::as_ref)
                .ok_or(StorageSecurityError::MissingDatabase)?;
            let identity = crate::database_identity::capture_authenticated_read_source(
                &self.path,
                &original.file,
            )?;
            self.check_unchanged()?;
            Ok(identity)
        }
        pub(crate) fn files(&self) -> impl Iterator<Item = (&'static str, &fs::File, u64)> {
            SUFFIXES
                .into_iter()
                .zip(&self.files)
                .filter_map(|(suffix, source)| {
                    source
                        .as_ref()
                        .map(|source| (suffix, &source.file, source.stamp.length))
                })
        }
        fn copy_to(&mut self, path: &Path) -> Result<()> {
            self.check_unchanged()?;
            for (suffix, source) in SUFFIXES.into_iter().zip(&mut self.files) {
                if suffix == "-shm" {
                    continue;
                }
                let Some(source) = source else { continue };
                let mut destination = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(suffixed(path, suffix))
                    .map_err(|_| StorageSecurityError::Io)?;
                // Copy ciphertext only, with a hard bound even if a source
                // grows concurrently. A changed length is never accepted.
                let copied = std::io::copy(
                    &mut (&mut source.file).take(source.stamp.length + 1),
                    &mut destination,
                )
                .map_err(|_| StorageSecurityError::Io)?;
                if copied != source.stamp.length {
                    return Err(StorageSecurityError::SourceChanged);
                }
                destination.flush().map_err(|_| StorageSecurityError::Io)?;
            }
            self.check_unchanged()
        }
    }

    pub(super) fn open(path: &Path, key: &DatabaseKey, max_bytes: u64) -> Result<ReadOnlySnapshot> {
        let mut sources = SourceSet::open_bounded(path, max_bytes)?;
        // The qualified Linux boundary deliberately ignores TMPDIR: a caller-
        // controlled temporary root could be inside the original profile tree.
        let temporary_root = fs::canonicalize("/tmp").map_err(|_| StorageSecurityError::Io)?;
        let source_parent =
            fs::canonicalize(path.parent().ok_or(StorageSecurityError::UnsafePath)?)
                .map_err(|_| StorageSecurityError::UnsafePath)?;
        if temporary_root.starts_with(&source_parent) {
            return Err(StorageSecurityError::UnsafePath);
        }
        let directory = tempfile::Builder::new()
            .prefix("wholepact-encrypted-read-")
            .tempdir_in(&temporary_root)
            .map_err(|_| StorageSecurityError::Io)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| StorageSecurityError::Io)?;
        let copy = directory.path().join("snapshot.sqlite");
        crate::validate_parent(&copy)?;
        sources.copy_to(&copy)?;
        // Do not use immutable=1: it can ignore committed WAL frames. SQLite
        // authenticates the copied database and applies its WAL normally; a hot
        // rollback journal requiring writes is safely refused by READ_ONLY.
        let connection = crate::keyed_connection_mode(&copy, key, true)?;
        sources.check_unchanged()?;
        Ok(ReadOnlySnapshot {
            connection,
            _directory: directory,
            sources,
        })
    }

    /// Descriptor-retained capture for non-SQLite ciphertext and private files.
    /// The same owner/mode/link/path checks apply, without requiring a DB header.
    pub(crate) struct CapturedFile {
        path: PathBuf,
        source: SourceFile,
    }
    impl CapturedFile {
        pub(crate) fn open(path: &Path) -> Result<Self> {
            crate::validate_parent(path)?;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| StorageSecurityError::Io)?;
            let stamp = Stamp::read(&file.metadata().map_err(|_| StorageSecurityError::Io)?)?;
            if stamp.length > MAX_SNAPSHOT_BYTES {
                return Err(StorageSecurityError::SnapshotLimit);
            }
            let captured = Self {
                path: path.into(),
                source: SourceFile { file, stamp },
            };
            captured.check_unchanged()?;
            Ok(captured)
        }
        pub(crate) fn file(&self) -> &fs::File {
            &self.source.file
        }
        pub(crate) fn length(&self) -> u64 {
            self.source.stamp.length
        }
        pub(crate) fn check_unchanged(&self) -> Result<()> {
            let path = Stamp::read(
                &fs::symlink_metadata(&self.path)
                    .map_err(|_| StorageSecurityError::SourceChanged)?,
            )?;
            let descriptor = Stamp::read(
                &self
                    .source
                    .file
                    .metadata()
                    .map_err(|_| StorageSecurityError::Io)?,
            )?;
            if path != self.source.stamp || descriptor != self.source.stamp {
                return Err(StorageSecurityError::SourceChanged);
            }
            Ok(())
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tests;
}
