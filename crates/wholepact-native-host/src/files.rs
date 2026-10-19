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
    /// Fail closed even for malformed/partial workspace names, in every build.
    pub(crate) fn refuse_private_workspace_files(&self) -> Result<()> {
        self.check()?;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::Invalid)?;
            if private_workspace_name(name) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    pub(crate) fn private_workspace_candidates(&self) -> Result<Vec<String>> {
        self.check()?;
        fs::read_dir(&self.root)?
            .map(|entry| {
                let entry = entry?;
                entry.file_name().into_string().map_err(|_| Error::Invalid)
            })
            .filter_map(|name| match name {
                Ok(name) if private_workspace_name(&name) => Some(Ok(name)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
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
pub(crate) const PRIVATE_PENDING: &str = "durable-private.pending-v1";
pub(crate) const PRIVATE_COMMIT: &str = "durable-private.commit-v1";
pub(crate) fn private_workspace_name(name: &str) -> bool {
    name == PRIVATE_PENDING
        || name == PRIVATE_COMMIT
        || name.starts_with("staging-durable-private-")
}

/// A bounded retained descriptor, never an origin reconstructed from a path.
/// Its final role remains fixed across the only permitted no-replace rename.
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) struct PrivateWorkspaceFileV1 {
    file: File,
    name: String,
    final_name: &'static str,
    directory_identity: String,
    dev: u64,
    ino: u64,
    len: u64,
    ciphertext_digest: String,
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
impl PrivateWorkspaceFileV1 {
    pub(crate) fn open(
        directory: &Directory,
        name: &str,
        final_name: &'static str,
        max: usize,
    ) -> Result<Self> {
        let prefix = match final_name {
            PRIVATE_PENDING => "staging-durable-private-pending-v1-",
            PRIVATE_COMMIT => "staging-durable-private-commit-v1-",
            _ => return Err(Error::Invalid),
        };
        if name != final_name {
            let suffix = name.strip_prefix(prefix).ok_or(Error::Invalid)?;
            if suffix.len() != 32
                || !suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::Invalid);
            }
        }
        let file = open_read(&directory.path(name)?)?;
        validate_file(&file, max as u64)?;
        let metadata = file.metadata()?;
        let bytes = read_private(&directory.path(name)?, max)?;
        use sha2::{Digest, Sha256};
        let result = Self {
            file,
            name: name.into(),
            final_name,
            directory_identity: directory.manual_target_identity_digest()?,
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            ciphertext_digest: hex::encode(Sha256::digest(&bytes)),
        };
        result.check(directory, max)?;
        Ok(result)
    }
    pub(crate) fn stage(
        directory: &Directory,
        final_name: &'static str,
        bytes: &[u8],
        max: usize,
    ) -> Result<Self> {
        if bytes.len() > max {
            return Err(Error::Invalid);
        }
        let role = match final_name {
            PRIVATE_PENDING => "pending",
            PRIVATE_COMMIT => "commit",
            _ => return Err(Error::Invalid),
        };
        let name = format!(
            "staging-durable-private-{role}-v1-{}",
            hex::encode(crate::random::<16>()?)
        );
        directory.write_new(&name, bytes)?;
        Self::open(directory, &name, final_name, max)
    }
    pub(crate) fn check(&self, directory: &Directory, max: usize) -> Result<()> {
        use sha2::{Digest, Sha256};
        directory.check()?;
        validate_file(&self.file, max as u64)?;
        let held = self.file.metadata()?;
        let path = fs::symlink_metadata(directory.path(&self.name)?)?;
        if directory.manual_target_identity_digest()? != self.directory_identity
            || held.dev() != self.dev
            || held.ino() != self.ino
            || held.len() != self.len
            || path.dev() != self.dev
            || path.ino() != self.ino
            || path.len() != self.len
            || !path.is_file()
            || path.nlink() != 1
            || path.mode() & 0o077 != 0
            || path.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::Authentication);
        }
        let mut bytes = Vec::new();
        use std::os::unix::fs::FileExt;
        bytes.resize(self.len as usize, 0);
        self.file.read_exact_at(&mut bytes, 0)?;
        if hex::encode(Sha256::digest(&bytes)) != self.ciphertext_digest {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn bytes(&self, directory: &Directory, max: usize) -> Result<Vec<u8>> {
        self.check(directory, max)?;
        use std::os::unix::fs::FileExt;
        let mut bytes = vec![0; self.len as usize];
        self.file.read_exact_at(&mut bytes, 0)?;
        self.check(directory, max)?;
        Ok(bytes)
    }
    pub(crate) fn origin(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:native-private-workspace-file-origin:v1",
            &(
                &self.directory_identity,
                self.final_name,
                self.dev,
                self.ino,
                self.len,
            ),
        )
        .map_err(|_| Error::Authentication)
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn is_final(&self) -> bool {
        self.name == self.final_name
    }
    pub(crate) fn ciphertext_digest(&self) -> &str {
        &self.ciphertext_digest
    }
    pub(crate) fn publish(&mut self, directory: &Directory, max: usize) -> Result<()> {
        self.check(directory, max)?;
        if self.is_final() {
            return Ok(());
        }
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(directory.path(&self.name)?.as_os_str().as_bytes())
            .map_err(|_| Error::Invalid)?;
        let destination =
            std::ffi::CString::new(directory.path(self.final_name)?.as_os_str().as_bytes())
                .map_err(|_| Error::Invalid)?;
        // SAFETY: both C strings are valid, absolute, validated owned paths.
        // RENAME_NOREPLACE preserves the retained inode and never overwrites.
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.name = self.final_name.into();
        File::open(&directory.root)?.sync_all()?;
        self.check(directory, max)
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
