//! Small, private-directory file operations. No caller-selected output paths are
//! accepted by the signer IPC. Local file locking is not clone-resistant fencing.
use crate::{Error, Result};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Retains the exact already-acquired directory and signer.lock descriptors.
/// There is no path-based constructor, new lock acquisition, or write method.
/// This is process-local source exclusion, not rollback or financial authority.
pub(crate) struct RetainedDirectoryExclusion {
    root: PathBuf,
    directory: Arc<File>,
    lock: Arc<File>,
    directory_identity: Metadata,
    lock_identity: Metadata,
}
impl RetainedDirectoryExclusion {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let directory = self.directory.metadata()?;
            let current_directory = fs::symlink_metadata(&self.root)?;
            let lock = self.lock.metadata()?;
            let current_lock = fs::symlink_metadata(self.root.join("signer.lock"))?;
            validate_directory(&directory)?;
            validate_directory(&current_directory)?;
            validate_lock(&lock)?;
            validate_lock(&current_lock)?;
            if fs::canonicalize(&self.root)? != self.root
                || !same_identity(&self.directory_identity, &directory)
                || !same_identity(&directory, &current_directory)
                || directory.nlink() != current_directory.nlink()
                || !same_identity(&self.lock_identity, &lock)
                || !same_identity(&lock, &current_lock)
            {
                return Err(Error::InvalidData);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(Error::Unavailable)
        }
    }
}

#[cfg(unix)]
fn same_identity(original: &Metadata, current: &Metadata) -> bool {
    original.dev() == current.dev()
        && original.ino() == current.ino()
        && original.uid() == current.uid()
        && original.gid() == current.gid()
        && original.mode() == current.mode()
}
#[cfg(unix)]
fn validate_directory(metadata: &Metadata) -> Result<()> {
    // SAFETY: geteuid has no arguments and does not mutate process state.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != uid
        || metadata.nlink() == 0
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}
#[cfg(unix)]
fn validate_lock(metadata: &Metadata) -> Result<()> {
    // SAFETY: geteuid has no arguments and does not mutate process state.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != uid
        || metadata.nlink() != 1
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}

pub struct PrivateDirectory {
    root: PathBuf,
    directory: Arc<File>,
    _lock: Arc<File>,
    directory_identity: Metadata,
    lock_identity: Metadata,
    journal_sources: Mutex<BTreeMap<String, Arc<crate::consent_journal::SignerJournalSourceOwner>>>,
}
impl PrivateDirectory {
    pub fn create(root: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let mut b = fs::DirBuilder::new();
            b.mode(0o700);
            b.create(root)?;
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            return Err(Error::Unavailable);
        }
        Self::open(root)
    }
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_internal(root, true)
    }
    /// Existing immutable source inventory must already contain its private lock.
    /// This never creates a missing source lock or repairs unknown inventory.
    pub(crate) fn open_existing(root: &Path) -> Result<Self> {
        Self::open_internal(root, false)
    }
    fn open_internal(root: &Path, create_lock: bool) -> Result<Self> {
        #[cfg(unix)]
        {
            let original = fs::symlink_metadata(root)?;
            validate_directory(&original)?;
            let root = fs::canonicalize(root)?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&root)?;
            let directory_identity = directory.metadata()?;
            let current = fs::symlink_metadata(&root)?;
            validate_directory(&directory_identity)?;
            validate_directory(&current)?;
            if fs::canonicalize(&root)? != root
                || !same_identity(&original, &directory_identity)
                || !same_identity(&directory_identity, &current)
                || directory_identity.nlink() != current.nlink()
            {
                return Err(Error::InvalidData);
            }
            let lock_path = root.join("signer.lock");
            match fs::symlink_metadata(&lock_path) {
                Ok(metadata) => validate_lock(&metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_lock => {}
                Err(error) => return Err(error.into()),
            }
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(create_lock)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path)?;
            validate_lock(&lock.metadata()?)?;
            lock.try_lock().map_err(|_| Error::AlreadyOpen)?;
            let lock_identity = lock.metadata()?;
            let result = Self {
                root,
                directory: Arc::new(directory),
                _lock: Arc::new(lock),
                directory_identity,
                lock_identity,
                journal_sources: Mutex::new(BTreeMap::new()),
            };
            result.retain_exclusion()?.check_current()?;
            Ok(result)
        }
        #[cfg(not(unix))]
        {
            let _ = (root, create_lock);
            Err(Error::Unavailable)
        }
    }
    fn retain_exclusion(&self) -> Result<RetainedDirectoryExclusion> {
        let retained = RetainedDirectoryExclusion {
            root: self.root.clone(),
            directory: Arc::clone(&self.directory),
            lock: Arc::clone(&self._lock),
            directory_identity: self.directory_identity.clone(),
            lock_identity: self.lock_identity.clone(),
        };
        retained.check_current()?;
        Ok(retained)
    }
    /// Metadata-only identity check of the original retained directory and lock.
    /// This does not obtain a journal source owner, mutex, SQL transaction, or
    /// permission; it only reuses the descriptor-backed exclusion invariant.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(crate) fn check_retained_exclusion_current_v1(&self) -> Result<()> {
        self.retain_exclusion()?.check_current()
    }
    /// One concrete owner for this actual locked directory's original journal.
    /// The owner retains descriptors, not this directory, so no strong cycle exists.
    pub(crate) fn signer_journal_source_owner(
        &self,
    ) -> Result<Arc<crate::consent_journal::SignerJournalSourceOwner>> {
        self.signer_journal_source_owner_for_child("authority.sqlite")
    }
    fn signer_journal_source_owner_for_child(
        &self,
        child: &str,
    ) -> Result<Arc<crate::consent_journal::SignerJournalSourceOwner>> {
        // Reuse the existing private filename grammar. No path-selected parent
        // or database file is opened while retaining the concrete source owner.
        self.path(child)?;
        let retained = self.retain_exclusion()?;
        let mut sources = self.journal_sources.lock().map_err(|_| Error::Locked)?;
        if let Some(source) = sources.get(child) {
            return Ok(Arc::clone(source));
        }
        let source = Arc::new(crate::consent_journal::SignerJournalSourceOwner::new(
            retained, child,
        )?);
        sources.insert(child.to_owned(), Arc::clone(&source));
        Ok(source)
    }
    /// Synthetic fixtures still use real directory exclusion and the identical
    /// per-child concrete owner. Only the parent is canonicalized, never the DB.
    #[cfg(test)]
    pub(crate) fn signer_journal_source_owner_for_test(
        &self,
        path: &Path,
    ) -> Result<Arc<crate::consent_journal::SignerJournalSourceOwner>> {
        let child = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::InvalidData)?;
        let parent = path.parent().ok_or(Error::InvalidData)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if fs::canonicalize(parent)? != self.root {
            return Err(Error::InvalidData);
        }
        self.signer_journal_source_owner_for_child(child)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || name.len() > 160
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || name == "."
            || name == ".."
        {
            return Err(Error::InvalidData);
        }
        Ok(self.root.join(name))
    }
    pub fn read(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(self.path(name)?)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > max as u64 {
            return Err(Error::InvalidData);
        }
        #[cfg(unix)]
        {
            if metadata.mode() & 0o077 != 0 {
                return Err(Error::InvalidData);
            }
        }
        let mut out = Vec::new();
        file.take(max as u64 + 1).read_to_end(&mut out)?;
        if out.len() > max {
            return Err(Error::InvalidData);
        }
        Ok(out)
    }
    pub fn exists(&self, name: &str) -> Result<bool> {
        match fs::symlink_metadata(self.path(name)?) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(Error::InvalidData),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    /// Writes, fsyncs, atomically renames, then fsyncs the directory. A returned
    /// error blocks authorization export, including uncertain directory fsync.
    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Crypto)?;
        let temporary = self.path(&format!("tmp-{}", hex::encode(random)))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary)?;
        let outcome = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, self.path(name)?)?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(temporary);
        }
        outcome
    }
    /// Durable publication barrier for a newly staged profile. Symlinks,
    /// hard links and non-private/non-regular files fail closed.
    #[cfg(all(
        feature = "authority-signing",
        feature = "native-ui",
        target_os = "linux"
    ))]
    pub(crate) fn sync_all_files(&self) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let file = options.open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(Error::InvalidData);
            }
            #[cfg(unix)]
            if metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(Error::InvalidData);
            }
            file.sync_all()?;
        }
        File::open(&self.root)?.sync_all()?;
        if let Some(parent) = self.root.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    /// Pre-create SQLite files privately; the parent directory also denies access.
    pub fn database_path(&self) -> Result<PathBuf> {
        let path = self.path("authority.sqlite")?;
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::InvalidData);
        }
        Ok(path)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod existing_source_tests {
    use super::*;
    #[test]
    fn missing_existing_lock_is_rejected_without_creating_source_files() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(temp.path().join("immutable-evidence"), b"synthetic source").unwrap();
        let before = std::fs::read(temp.path().join("immutable-evidence")).unwrap();
        assert!(PrivateDirectory::open_existing(temp.path()).is_err());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(temp.path().join("immutable-evidence")).unwrap(),
            before
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod retained_source_owner_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn directory() -> (tempfile::TempDir, PrivateDirectory) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = PrivateDirectory::open(temp.path()).unwrap();
        (temp, directory)
    }

    #[test]
    fn retained_exclusion_keeps_actual_lock_after_directory_drop() {
        let (temp, directory) = directory();
        let retained = directory.retain_exclusion().unwrap();
        assert_eq!(retained.root(), fs::canonicalize(temp.path()).unwrap());
        drop(directory);
        retained.check_current().unwrap();
        assert!(matches!(
            PrivateDirectory::open_existing(temp.path()),
            Err(Error::AlreadyOpen)
        ));
        drop(retained);
        PrivateDirectory::open_existing(temp.path()).unwrap();
    }

    #[test]
    fn cached_owners_share_exact_child_custody_without_touching_database() {
        let (temp, directory) = directory();
        let original = directory.signer_journal_source_owner().unwrap();
        let same = directory.signer_journal_source_owner().unwrap();
        assert!(Arc::ptr_eq(&original, &same));
        let normalized = directory
            .signer_journal_source_owner_for_test(&temp.path().join(".").join("authority.sqlite"))
            .unwrap();
        assert!(Arc::ptr_eq(&original, &normalized));
        let synthetic = directory
            .signer_journal_source_owner_for_test(&temp.path().join("synthetic-source.sqlite"))
            .unwrap();
        assert!(!Arc::ptr_eq(&original, &synthetic));
        let synthetic_again = directory
            .signer_journal_source_owner_for_test(&temp.path().join("synthetic-source.sqlite"))
            .unwrap();
        assert!(Arc::ptr_eq(&synthetic, &synthetic_again));
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        assert!(!temp.path().join("authority.sqlite").exists());
        assert!(!temp.path().join("synthetic-source.sqlite").exists());
    }

    #[test]
    fn source_owner_retains_lock_without_a_directory_reference_cycle() {
        let (temp, directory) = directory();
        let source = directory.signer_journal_source_owner().unwrap();
        drop(directory);
        assert!(matches!(
            PrivateDirectory::open_existing(temp.path()),
            Err(Error::AlreadyOpen)
        ));
        drop(source);
        PrivateDirectory::open_existing(temp.path()).unwrap();
    }

    #[test]
    fn synthetic_child_helper_cannot_rebind_to_foreign_or_nested_directory() {
        let (temp, directory) = directory();
        let foreign = tempfile::tempdir().unwrap();
        assert!(directory
            .signer_journal_source_owner_for_test(&foreign.path().join("synthetic-source.sqlite"),)
            .is_err());
        fs::create_dir(temp.path().join("nested")).unwrap();
        assert!(directory
            .signer_journal_source_owner_for_test(
                &temp.path().join("nested").join("synthetic-source.sqlite"),
            )
            .is_err());
        assert!(directory
            .signer_journal_source_owner_for_test(
                &temp.path().join("not a private filename.sqlite"),
            )
            .is_err());
        // A real child-directory changes directory nlink, not root identity.
        directory
            .retain_exclusion()
            .unwrap()
            .check_current()
            .unwrap();
    }

    #[test]
    fn replaced_lock_is_rejected_without_repair_or_new_lock() {
        let (temp, directory) = directory();
        let retained = directory.retain_exclusion().unwrap();
        let lock = temp.path().join("signer.lock");
        fs::rename(&lock, temp.path().join("original.lock")).unwrap();
        fs::write(&lock, b"foreign replacement").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(&lock).unwrap();
        assert!(retained.check_current().is_err());
        assert!(directory.signer_journal_source_owner().is_err());
        assert!(
            fs::read(&lock).unwrap() == before,
            "retained lock bytes changed"
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[test]
    fn hardlinked_or_mode_changed_lock_is_not_current() {
        let (temp, directory) = directory();
        let retained = directory.retain_exclusion().unwrap();
        let lock = temp.path().join("signer.lock");
        let alias = temp.path().join("alias.lock");
        fs::hard_link(&lock, &alias).unwrap();
        assert!(retained.check_current().is_err());
        fs::remove_file(&alias).unwrap();
        retained.check_current().unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(retained.check_current().is_err());
    }

    #[test]
    fn replaced_root_and_symlinked_root_fail_without_creating_a_lock() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("original");
        let moved = parent.path().join("moved");
        let directory = PrivateDirectory::create(&root).unwrap();
        let retained = directory.retain_exclusion().unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(retained.check_current().is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink(&moved, &root).unwrap();
        assert!(retained.check_current().is_err());
        assert!(PrivateDirectory::open(&root).is_err());
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
    }
}
