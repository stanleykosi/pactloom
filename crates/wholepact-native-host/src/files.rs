//! Only Linux-qualified private local files. The process lock is not clone detection.
use crate::{Error, Result};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) struct Directory {
    root: PathBuf,
    _lock: File,
    dev: u64,
    ino: u64,
}
impl Directory {
    pub(crate) fn create(root: &Path) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            return Err(Error::Platform);
        }
        #[cfg(target_os = "linux")]
        {
            validate_absolute(root)?;
            let parent = root.parent().ok_or(Error::Invalid)?;
            if fs::canonicalize(parent)? != parent {
                return Err(Error::Invalid);
            }
            fs::DirBuilder::new().mode(0o700).create(root)?;
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root.join("profile.lock"))?;
            f.sync_all()?;
            File::open(root)?.sync_all()?;
            drop(f);
            Self::open(root)
        }
    }
    pub(crate) fn open(root: &Path) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            return Err(Error::Platform);
        }
        #[cfg(target_os = "linux")]
        {
            validate_absolute(root)?;
            if fs::canonicalize(root)? != root {
                return Err(Error::Invalid);
            }
            let m = fs::symlink_metadata(root)?;
            // SAFETY: geteuid only reads the process effective uid.
            if !m.is_dir() || m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() } {
                return Err(Error::Invalid);
            }
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root.join("profile.lock"))?;
            validate_file(&f, 1024)?;
            f.try_lock().map_err(|_| Error::Locked)?;
            Ok(Self {
                root: root.into(),
                _lock: f,
                dev: m.dev(),
                ino: m.ino(),
            })
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let m = fs::symlink_metadata(&self.root)?;
            if !m.is_dir() || m.dev() != self.dev || m.ino() != self.ino || m.mode() & 0o077 != 0 {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    /// Correlation from this actual held directory, never from a caller path.
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn manual_target_identity_digest(&self) -> Result<String> {
        self.check()?;
        let root = self.root.to_str().ok_or(Error::Invalid)?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:native-manual-target-directory:v1",
            &(root, self.dev, self.ino),
        )
        .map_err(|_| Error::Authentication)
    }
    pub(crate) fn path(&self, name: &str) -> Result<PathBuf> {
        self.check()?;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(Error::Invalid);
        }
        Ok(self.root.join(name))
    }
    /// Export/credential/backup destinations must never add files to the fixed
    /// protected profile inventory or overwrite an absent SQLite sidecar name.
    /// Canonical no-symlink parent validation plus component and ancestor inode
    /// checks also rejects aliases of this held profile directory.
    pub(crate) fn external_destination(&self, destination: &Path) -> Result<()> {
        self.check()?;
        validate_absolute(destination)?;
        let parent = destination.parent().ok_or(Error::Invalid)?;
        let canonical = fs::canonicalize(parent)?;
        if canonical != parent || destination.starts_with(&self.root) {
            return Err(Error::Invalid);
        }
        #[cfg(target_os = "linux")]
        for ancestor in canonical.ancestors() {
            let m = fs::symlink_metadata(ancestor)?;
            if m.dev() == self.dev && m.ino() == self.ino {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    pub(crate) fn read(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        read_private(&self.path(name)?, max)
    }
    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        write_new(&self.path(name)?, bytes)
    }
    /// Atomic replacement under the held exclusive directory lock. Interrupted
    /// staging files remain visible and make strict inventory checks fail closed.
    pub(crate) fn replace_private(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let target = self.path(name)?;
        let temporary = self.path(&format!("staging-{}", hex::encode(crate::random::<16>()?)))?;
        write_new(&temporary, bytes)?;
        self.check()?;
        fs::rename(&temporary, target)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    pub(crate) fn inventory(&self) -> Result<()> {
        self.inventory_of(
            &crate::vault::JOURNALS,
            &[
                "profile.lock",
                "profile.vault",
                "restored.quarantine",
                "financial.attached",
                "financial.inventory",
            ],
        )
    }
    pub(crate) fn inventory_of(&self, journals: &[&str], other: &[&str]) -> Result<()> {
        self.check()?;
        for e in fs::read_dir(&self.root)? {
            let e = e?;
            let name = e.file_name();
            let name = name.to_str().ok_or(Error::Invalid)?;
            let journal = journals.iter().any(|p| {
                name == *p
                    || name == format!("{p}-wal")
                    || name == format!("{p}-shm")
                    || name == format!("{p}-journal")
            });
            if !journal && !other.contains(&name) {
                return Err(Error::Invalid);
            }
            let f = open_read(&e.path())?;
            validate_file(&f, 512 * 1024 * 1024)?;
        }
        Ok(())
    }
}
pub(crate) fn validate_absolute(p: &Path) -> Result<()> {
    if !p.is_absolute()
        || p.file_name().is_none()
        || p.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn open_read(p: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(target_os = "linux")]
    o.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    Ok(o.open(p)?)
}
fn validate_file(f: &File, max: u64) -> Result<()> {
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max {
        return Err(Error::Invalid);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: geteuid only reads the process effective uid.
    if m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() } || m.nlink() != 1 {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(crate) fn read_private(p: &Path, max: usize) -> Result<Vec<u8>> {
    validate_absolute(p)?;
    let f = open_read(p)?;
    validate_file(&f, max as u64)?;
    let mut v = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut v)?;
    if v.len() > max {
        return Err(Error::Invalid);
    }
    Ok(v)
}
/// Public encrypted transport artifacts need not be private, but must be regular,
/// bounded, explicitly selected local files. No symlinks, URLs, FIFO or devices.
pub(crate) fn read_artifact(p: &Path, max: usize) -> Result<Vec<u8>> {
    validate_absolute(p)?;
    let f = open_read(p)?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max as u64 {
        return Err(Error::Invalid);
    }
    let mut v = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut v)?;
    if v.len() > max {
        return Err(Error::Invalid);
    }
    Ok(v)
}
pub(crate) fn write_new(p: &Path, b: &[u8]) -> Result<()> {
    validate_absolute(p)?;
    let parent = p.parent().ok_or(Error::Invalid)?;
    if fs::canonicalize(parent)? != parent {
        return Err(Error::Invalid);
    }
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    o.mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut f = o.open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn outward_files_never_enter_protected_inventory_or_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let directory = Directory::create(&root).unwrap();
        for name in [
            "selected.json",
            "coordination.sqlite-journal",
            "profile.vault",
        ] {
            assert!(directory.external_destination(&root.join(name)).is_err());
        }
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(
            directory
                .external_destination(&alias.join("selected.json"))
                .is_err()
        );
        assert!(
            directory
                .external_destination(&temp.path().join("profile-sibling.json"))
                .is_ok()
        );
        directory.inventory().unwrap();
    }
    #[test]
    fn refuses_fifo_symlink_and_oversized_input_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let pipe = dir.path().join("input.pipe");
        let c = CString::new(pipe.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString is NUL terminated and mkfifo creates only this temporary test path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(read_artifact(&pipe, 1024), Err(Error::Invalid)));
        let file = dir.path().join("regular");
        write_new(&file, b"bounded").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_artifact(&link, 1024).is_err());
        assert!(read_artifact(&file, 1).is_err());
    }
}
