//! Exact private export of separately native-reviewed born owner enrollment.
//! Exact local-file disclosure of one already-signed retained request. This is
//! deliberately separate from existing-key signing and witness acknowledgement.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use super::export::{require_absent, require_standalone_destination};
use crate::{
    Error, Result,
    account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1,
};
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
use wholepact_authority::born_offline_enrollment_signature_v1::{
    BornOfflineEnrollmentOwnerSignatureV1, verify_born_offline_enrollment_v1_owner_signature,
};
use zeroize::Zeroizing;

pub(super) struct PreparedBornEnrollmentExportV1 {
    original_digest: String,
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
impl PreparedBornEnrollmentExportV1 {
    pub(super) fn prepare(
        actual: &ConsumedBornNamedSourceV1,
        envelope: BornOfflineEnrollmentOwnerSignatureV1,
        destination: &Path,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        actual.check(owner)?;
        let original_digest = actual
            .construction()
            .digest()
            .map_err(|_| Error::InvalidData)?;
        envelope
            .enrollment
            .owner_continuation
            .as_ref()
            .ok_or(Error::ReviewMismatch)?
            .validate_origin(&envelope.enrollment, actual.construction())
            .map_err(|_| Error::ReviewMismatch)?;
        verify_born_offline_enrollment_v1_owner_signature(
            &envelope,
            &actual.genesis().owner_certificate_digest,
        )
        .map_err(|_| Error::Authentication)?;
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
        let filename = format!("born-offline-owner-enrollment-v1-{content_digest}.json");
        require_absent(destination, &filename)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-offline-owner-enrollment-export:v1",
            &(
                &original_digest,
                envelope
                    .enrollment
                    .digest()
                    .map_err(|_| Error::InvalidData)?,
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
            "EXPORT EXACT SIGNED ORIGINAL-OWNER BORN ENROLLMENT\nPrivate destination: {}\nFile: {filename}\nDirectory device/inode: {} / {}\nExact content SHA-256: {content_digest}\n\n{}\n\nThis discloses the full original born enrollment, immutable consumed construction scope, existing original owner public certificate/signature and reviewed transport/verifier commitments. It contains no private key, seed or raw viewing key. The independent original witness owner must review and install exactly this envelope. This file grants no transaction signature, new writer session or current-input authority. Preserve it for exact retries; no automatic replacement or overwrite.",
            destination.display(),
            metadata.dev(),
            metadata.ino(),
            String::from_utf8_lossy(&bytes)
        );
        Ok(Self {
            original_digest,
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
    fn check(
        &self,
        actual: &ConsumedBornNamedSourceV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        actual.check(owner)?;
        if actual
            .construction()
            .digest()
            .map_err(|_| Error::InvalidData)?
            != self.original_digest
        {
            return Err(Error::ReviewMismatch);
        }
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
        actual: &ConsumedBornNamedSourceV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(actual, owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let _lease = self.source.publication_lease()?;
        self.check(actual, owner)?;
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
