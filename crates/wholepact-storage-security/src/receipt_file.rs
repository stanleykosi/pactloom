//! Deliberate local plaintext receipt export. The caller must hold separate exact
//! disclosure consent; private filesystem permissions do not authorize disclosure.
//! No network delivery, overwrite, secure-deletion or external recall is implied.
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, sync::Arc};
use thiserror::Error;

pub const MAX_RECEIPT_BYTES: usize = 32_768;

#[derive(Debug, Error)]
pub enum ReceiptFileError {
    #[error("local receipt export is unsupported on this platform")]
    UnsupportedPlatform,
    #[error(
        "receipt target must be an explicit absolute path in a private owned directory without symlinks"
    )]
    UnsafeTarget,
    #[error("receipt target directory identity or permissions changed")]
    TargetChanged,
    #[error("existing receipt file differs; it was preserved without overwriting")]
    ExistingDifferent,
    #[error("receipt payload exceeds the supported bounded size")]
    InvalidPayload,
    #[error("receipt file operation failed; an attempted write may have left a partial file")]
    OutcomeUnknown,
}
pub type Result<T> = std::result::Result<T, ReceiptFileError>;

/// Private journal/consent metadata. Never put paths or filesystem identifiers in
/// ordinary service summaries. These values do not themselves grant access.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFileIdentity {
    path: String,
    directory_device: u64,
    directory_inode: u64,
}
impl ReceiptFileIdentity {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn validate(&self) -> Result<()> {
        validate_path(&self.path)?;
        Ok(())
    }
}
impl fmt::Debug for ReceiptFileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiptFileIdentity { private_path_and_identity: [REDACTED] }")
    }
}

/// Opaque instance binding; a reopened target requires a newly scoped lease even
/// when its persisted device/inode/path identity still matches.
#[derive(Clone)]
pub struct ReceiptTargetBinding(Arc<Inner>);
impl PartialEq for ReceiptTargetBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ReceiptTargetBinding {}
impl fmt::Debug for ReceiptTargetBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiptTargetBinding { opaque_open_directory }")
    }
}

pub struct PrivateReceiptTarget(Arc<Inner>);
struct Inner {
    identity: ReceiptFileIdentity,
    #[cfg(target_os = "linux")]
    directory: std::fs::File,
    #[cfg(target_os = "linux")]
    filename: std::ffi::CString,
}
impl fmt::Debug for PrivateReceiptTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateReceiptTarget { private_target: [REDACTED] }")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptWriteOutcome {
    CreatedAndSynced,
    ExistingExactAndSynced,
}

impl PrivateReceiptTarget {
    /// Opens directory handles only. Does not create/read the target receipt.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or(ReceiptFileError::UnsafeTarget)?;
        validate_path(path)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let directory = linux::open_parent(path)?;
            let metadata = linux::private_directory(&directory)?;
            let filename = std::ffi::CString::new(
                Path::new(path)
                    .file_name()
                    .ok_or(ReceiptFileError::UnsafeTarget)?
                    .as_encoded_bytes(),
            )
            .map_err(|_| ReceiptFileError::UnsafeTarget)?;
            Ok(Self(Arc::new(Inner {
                identity: ReceiptFileIdentity {
                    path: path.into(),
                    directory_device: metadata.dev(),
                    directory_inode: metadata.ino(),
                },
                directory,
                filename,
            })))
        }
        #[cfg(not(target_os = "linux"))]
        Err(ReceiptFileError::UnsupportedPlatform)
    }
    pub fn identity(&self) -> &ReceiptFileIdentity {
        &self.0.identity
    }
    pub fn binding(&self) -> ReceiptTargetBinding {
        ReceiptTargetBinding(self.0.clone())
    }
    pub fn check_current(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let held = linux::private_directory(&self.0.directory)?;
            let current = linux::open_parent(self.identity().path())
                .map_err(|_| ReceiptFileError::TargetChanged)?;
            let current = linux::private_directory(&current)?;
            if held.dev() != self.identity().directory_device
                || held.ino() != self.identity().directory_inode
                || current.dev() != held.dev()
                || current.ino() != held.ino()
            {
                return Err(ReceiptFileError::TargetChanged);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        Err(ReceiptFileError::UnsupportedPlatform)
    }
    /// Requires a caller-owned durable attempt marker and current exact export
    /// consent. Exclusive create; retries only accept an existing private single-
    /// link regular file containing exactly these bytes. Never repairs/truncates.
    pub fn write_exact(&self, bytes: &[u8]) -> Result<ReceiptWriteOutcome> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ReceiptFileError::InvalidPayload);
        }
        self.check_current()?;
        #[cfg(target_os = "linux")]
        {
            let outcome = linux::write_exact(&self.0, bytes)?;
            self.check_current()?;
            Ok(outcome)
        }
        #[cfg(not(target_os = "linux"))]
        Err(ReceiptFileError::UnsupportedPlatform)
    }
}
fn validate_path(path: &str) -> Result<()> {
    if path.len() > 4096
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\0')
        || path
            .split('/')
            .skip(1)
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(ReceiptFileError::UnsafeTarget);
    }
    let filename = Path::new(path)
        .file_name()
        .ok_or(ReceiptFileError::UnsafeTarget)?;
    if filename.as_encoded_bytes().len() > 255 {
        return Err(ReceiptFileError::UnsafeTarget);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        fs::{File, Metadata, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };

    pub(super) fn open_parent(path: &str) -> Result<File> {
        let mut current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|_| ReceiptFileError::UnsafeTarget)?;
        let parts: Vec<_> = path.split('/').skip(1).collect();
        for part in &parts[..parts.len() - 1] {
            let name = CString::new(*part).map_err(|_| ReceiptFileError::UnsafeTarget)?;
            current = open_at(&current, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        }
        Ok(current)
    }
    fn open_at(directory: &File, name: &CString, flags: i32) -> Result<File> {
        // SAFETY: directory is a live owned descriptor; name is NUL terminated.
        // O_NOFOLLOW applies to every component. Successful fd ownership moves
        // exactly once into File, which closes it normally on all return paths.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(ReceiptFileError::UnsafeTarget);
        }
        // SAFETY: openat returned a new owned nonnegative descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub(super) fn private_directory(file: &File) -> Result<Metadata> {
        let m = file
            .metadata()
            .map_err(|_| ReceiptFileError::UnsafeTarget)?;
        // SAFETY: geteuid has no memory inputs or side effects.
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
            return Err(ReceiptFileError::UnsafeTarget);
        }
        Ok(m)
    }
    fn private_file(file: &File) -> Result<Metadata> {
        let m = file
            .metadata()
            .map_err(|_| ReceiptFileError::UnsafeTarget)?;
        // SAFETY: geteuid has no memory inputs or side effects.
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o600
        {
            return Err(ReceiptFileError::UnsafeTarget);
        }
        Ok(m)
    }
    pub(super) fn write_exact(inner: &Inner, bytes: &[u8]) -> Result<ReceiptWriteOutcome> {
        // Exclusive creation distinguishes our newly created file from any prior
        // output. No path-based postcheck substitutes for checking these FDs.
        // SAFETY: both pointers/descriptors remain valid for the synchronous call.
        let fd = unsafe {
            libc::openat(
                inner.directory.as_raw_fd(),
                inner.filename.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        let (file, outcome) = if fd >= 0 {
            // SAFETY: fd is uniquely owned following successful exclusive openat.
            let mut file = unsafe { File::from_raw_fd(fd) };
            private_file(&file)?;
            file.write_all(bytes)
                .map_err(|_| ReceiptFileError::OutcomeUnknown)?;
            file.sync_all()
                .map_err(|_| ReceiptFileError::OutcomeUnknown)?;
            (file, ReceiptWriteOutcome::CreatedAndSynced)
        } else {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(ReceiptFileError::OutcomeUnknown);
            }
            let mut file = open_at(&inner.directory, &inner.filename, libc::O_RDONLY)?;
            let metadata = private_file(&file)?;
            if metadata.len() != bytes.len() as u64 {
                return Err(ReceiptFileError::ExistingDifferent);
            }
            let mut existing = Vec::with_capacity(bytes.len());
            (&mut file)
                .take(MAX_RECEIPT_BYTES as u64 + 1)
                .read_to_end(&mut existing)
                .map_err(|_| ReceiptFileError::OutcomeUnknown)?;
            if existing != bytes {
                return Err(ReceiptFileError::ExistingDifferent);
            }
            file.sync_all()
                .map_err(|_| ReceiptFileError::OutcomeUnknown)?;
            (file, ReceiptWriteOutcome::ExistingExactAndSynced)
        };
        let held = private_file(&file)?;
        let current = open_at(&inner.directory, &inner.filename, libc::O_RDONLY)?;
        let current = private_file(&current)?;
        if held.dev() != current.dev()
            || held.ino() != current.ino()
            || held.len() != bytes.len() as u64
        {
            return Err(ReceiptFileError::TargetChanged);
        }
        inner
            .directory
            .sync_all()
            .map_err(|_| ReceiptFileError::OutcomeUnknown)?;
        Ok(outcome)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn exclusive_private_write_exact_replay_and_changed_bytes_preserve_original() {
        let dir = directory();
        let path = dir.path().join("receipt.json");
        let target = PrivateReceiptTarget::open(&path).unwrap();
        assert_eq!(
            target.write_exact(b"selected synthetic receipt").unwrap(),
            ReceiptWriteOutcome::CreatedAndSynced
        );
        assert_eq!(
            target.write_exact(b"selected synthetic receipt").unwrap(),
            ReceiptWriteOutcome::ExistingExactAndSynced
        );
        assert!(matches!(
            target.write_exact(b"changed"),
            Err(ReceiptFileError::ExistingDifferent)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"selected synthetic receipt");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let reopened = PrivateReceiptTarget::open(&path).unwrap();
        assert_eq!(target.identity(), reopened.identity());
        assert_ne!(target.binding(), reopened.binding());
    }
    #[test]
    fn symlinks_hardlinks_broad_permissions_and_replaced_directories_are_rejected() {
        let dir = directory();
        let path = dir.path().join("receipt.json");
        let target = PrivateReceiptTarget::open(&path).unwrap();
        let other = dir.path().join("other.json");
        std::fs::write(&other, b"protected").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&other, &path).unwrap();
        // Content and permissions would otherwise pass: isolate O_NOFOLLOW.
        assert!(target.write_exact(b"protected").is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&other, &path).unwrap();
        // Content and permissions still pass: isolate the single-link rule.
        assert!(target.write_exact(b"protected").is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"protected");
        std::fs::remove_file(&path).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(target.write_exact(b"selected").is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = directory();
        let original = parent.path().join("original");
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bound = PrivateReceiptTarget::open(original.join("receipt.json")).unwrap();
        std::fs::rename(&original, parent.path().join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            bound.write_exact(b"selected"),
            Err(ReceiptFileError::TargetChanged)
        ));
        assert!(!original.join("receipt.json").exists());
        let link = parent.path().join("linked");
        symlink(&original, &link).unwrap();
        assert!(PrivateReceiptTarget::open(link.join("receipt.json")).is_err());
    }
}
