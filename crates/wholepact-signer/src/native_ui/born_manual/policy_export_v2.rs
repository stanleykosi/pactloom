//! Exact private export of the full ORIGINAL V2 recipient policy preimage.
//! This private one-shot native disclosure creates no witness or financial authority.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use super::export::{require_absent, require_standalone_destination};
use crate::{Error, Result, account::birth::enrollment::RetainedBornManualEnrollment};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) struct PreparedOriginalPolicyExportV2 {
    retained: RetainedBornManualEnrollment,
    source: NativeAuthorityBinding,
    directory: File,
    path: PathBuf,
    filename: String,
    device: u64,
    inode: u64,
    bytes: Zeroizing<Vec<u8>>,
    digest: String,
    display: String,
    started: Instant,
}
impl PreparedOriginalPolicyExportV2 {
    pub(super) fn prepare(
        retained: RetainedBornManualEnrollment,
        destination: &Path,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        retained.check_current_source(owner)?;
        let envelope = retained.original_recipient_policy_export_v2(owner)?;
        envelope.validate()?;
        if !destination.is_absolute()
            || destination.as_os_str().len() > 4096
            || std::fs::canonicalize(destination)? != destination
        {
            return Err(Error::InvalidData);
        }
        require_standalone_destination(destination)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(destination)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(Error::InvalidData);
        }
        let bytes =
            Zeroizing::new(serde_json::to_vec_pretty(&envelope).map_err(|_| Error::InvalidData)?);
        if bytes.len() > 256 * 1024 {
            return Err(Error::InvalidData);
        }
        let content_digest = hex::encode(Sha256::digest(&*bytes));
        let filename = format!("original-born-policy-v2-{content_digest}.json");
        require_absent(destination, &filename)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-original-born-policy-export:v2",
            &(
                retained.record().reference()?,
                envelope.digest()?,
                &content_digest,
                destination,
                &filename,
                metadata.dev(),
                metadata.ino(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "EXPORT EXACT ORIGINAL VERSION 2 POLICY PREIMAGE\nPrivate destination: {}\nFile: {filename}\nDirectory device/inode: {} / {}\nExact content SHA-256: {content_digest}\n\n{}\n\nThis file discloses the complete immutable original birth preimage, recipient and charge destinations/caps, FVK digest, original target/origin and retained witness birth receipt. It is inert historical evidence. The witness must match its own retained original birth/genesis and separately approve the exact purpose; this export does not grant signing or establish new-key provenance. No private key, seed or raw FVK is exported. The destination must already be a private local directory; this action never overwrites a file. It sends nothing over a network. Moving or sharing it later is a separate disclosure. Preserve the exact file for original-policy validation: the original account policy, budget, exposure and birth are never reset. Independent witness-owner review is still required.",
            destination.display(),
            metadata.dev(),
            metadata.ino(),
            String::from_utf8_lossy(&bytes)
        );
        Ok(Self {
            retained,
            source: owner.native().binding(),
            directory,
            path: destination.to_path_buf(),
            filename,
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes,
            digest,
            display,
            started: Instant::now(),
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        self.retained.check_current_source(owner)?;
        if self.source != owner.native().binding()
            || self.started.elapsed() >= Duration::from_secs(120)
            || std::fs::canonicalize(&self.path)? != self.path
        {
            return Err(Error::ReviewMismatch);
        }
        for metadata in [
            self.directory.metadata()?,
            std::fs::symlink_metadata(&self.path)?,
        ] {
            if !metadata.is_dir()
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(Error::ReviewMismatch);
            }
        }
        require_standalone_destination(&self.path)?;
        require_absent(&self.path, &self.filename)
    }
    pub(super) fn publish(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let _lease = self.source.publication_lease()?;
        self.check(owner)?;
        let name = CString::new(self.filename.as_bytes()).map_err(|_| Error::InvalidData)?;
        // Anchored descriptor and O_EXCL bind the approved directory and prohibit
        // replacement, symlink following and overwrite, even after path races.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&self.bytes)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        // A failed or interrupted export is never removed/replaced automatically.
        Ok(())
    }
}
