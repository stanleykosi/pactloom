//! Held private directory identity for one reviewed new ciphertext export.
//! Anchored openat prevents redirection through a changed path; postchecks detect
//! rename/replacement. No hostile-same-user immunity or rollback is claimed.
use super::*;
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(in crate::consent_journal::named_recipient_setup::inbox) struct ExactFileDestination {
    directory: File,
    parent: PathBuf,
    filename: String,
    device: u64,
    inode: u64,
    uid: u32,
}
impl ExactFileDestination {
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn prepare(
        destination: &Path,
    ) -> ImportResult<Self> {
        if !destination.is_absolute() || destination.as_os_str().len() > 4096 {
            return Err(TransportError::WrongContext);
        }
        let filename = destination
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && !n.chars().any(char::is_control))
            .ok_or(TransportError::WrongContext)?
            .to_owned();
        CString::new(filename.as_bytes()).map_err(|_| TransportError::WrongContext)?;
        let parent =
            std::fs::canonicalize(destination.parent().ok_or(TransportError::WrongContext)?)
                .map_err(|_| TransportError::Storage)?;
        if parent
            .to_str()
            .is_none_or(|p| p.chars().any(char::is_control))
        {
            return Err(TransportError::WrongContext);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent)
            .map_err(|_| TransportError::Storage)?;
        let metadata = directory.metadata().map_err(|_| TransportError::Storage)?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(TransportError::WrongContext);
        }
        let result = Self {
            directory,
            parent,
            filename,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid,
        };
        result.check_directory()?;
        result.require_absent()?;
        Ok(result)
    }
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn review_binding(
        &self,
    ) -> (&Path, &str, u64, u64, u32) {
        (
            &self.parent,
            &self.filename,
            self.device,
            self.inode,
            self.uid,
        )
    }
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn display_path(&self) -> PathBuf {
        self.parent.join(&self.filename)
    }
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn check_directory(
        &self,
    ) -> ImportResult<()> {
        if unsafe { libc::geteuid() } != self.uid
            || std::fs::canonicalize(&self.parent).map_err(|_| TransportError::Storage)?
                != self.parent
        {
            return Err(TransportError::WrongContext);
        }
        for m in [
            self.directory
                .metadata()
                .map_err(|_| TransportError::Storage)?,
            std::fs::symlink_metadata(&self.parent).map_err(|_| TransportError::Storage)?,
        ] {
            if !m.is_dir()
                || m.dev() != self.device
                || m.ino() != self.inode
                || m.uid() != self.uid
                || m.mode() & 0o077 != 0
            {
                return Err(TransportError::WrongContext);
            }
        }
        Ok(())
    }
    fn require_absent(&self) -> ImportResult<()> {
        match std::fs::symlink_metadata(self.display_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(TransportError::Storage),
            Ok(_) => Err(TransportError::WrongContext),
        }
    }
    /// An error before openat succeeds creates nothing. After success the caller
    /// owns a potentially durable empty file and must report later loss as uncertain.
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn allocate(
        &self,
    ) -> ImportResult<File> {
        self.check_directory()?;
        self.require_absent()?;
        let name =
            CString::new(self.filename.as_bytes()).map_err(|_| TransportError::WrongContext)?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(TransportError::Storage);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        self.check_created(&file, 0)
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        Ok(file)
    }
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn check_created(
        &self,
        file: &File,
        expected_len: u64,
    ) -> ImportResult<()> {
        self.check_directory()?;
        let held = file.metadata().map_err(|_| TransportError::Storage)?;
        let current =
            std::fs::symlink_metadata(self.display_path()).map_err(|_| TransportError::Storage)?;
        for m in [&held, &current] {
            if !m.is_file()
                || m.uid() != self.uid
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.len() != expected_len
                || m.dev() != held.dev()
                || m.ino() != held.ino()
            {
                return Err(TransportError::WrongContext);
            }
        }
        Ok(())
    }
    pub(in crate::consent_journal::named_recipient_setup::inbox) fn sync_parent(
        &self,
    ) -> ImportResult<()> {
        self.directory
            .sync_all()
            .map_err(|_| TransportError::Storage)
    }
}

#[cfg(test)]
#[path = "file_destination_tests.rs"]
mod tests;
