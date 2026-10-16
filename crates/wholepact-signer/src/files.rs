//! Small, private-directory file operations. No caller-selected output paths are
//! accepted by the signer IPC. Local file locking is not clone-resistant fencing.
use crate::{Error, Result};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct PrivateDirectory {
    root: PathBuf,
    _lock: File,
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
        let metadata = fs::symlink_metadata(root)?;
        #[cfg(unix)]
        {
            // SAFETY: geteuid has no arguments and does not mutate process state.
            let uid = unsafe { libc::geteuid() };
            if !metadata.is_dir() || metadata.mode() & 0o077 != 0 || metadata.uid() != uid {
                return Err(Error::InvalidData);
            }
        }
        #[cfg(not(unix))]
        {
            return Err(Error::Unavailable);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(create_lock);
        #[cfg(unix)]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let lock = options.open(root.join("signer.lock"))?;
        lock.try_lock().map_err(|_| Error::AlreadyOpen)?;
        Ok(Self {
            root: root.to_path_buf(),
            _lock: lock,
        })
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
