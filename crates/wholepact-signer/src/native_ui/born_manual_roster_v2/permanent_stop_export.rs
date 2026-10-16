//! Exact permanent-stop disclosure from the actual retained born source.
//! Exact local-file disclosure of one already-signed retained request. This is
//! deliberately separate from existing-key signing and witness acknowledgement.
use super::super::{NativeAuthorityBinding, NativeDecision, PendingAccountNativeAuthority};
use crate::{
    account::birth::enrollment::roster_v2::permanent_stop::BornPermanentStopSourceV1, Error, Result,
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
use wholepact_authority::permanent_exclusion_signature::verify_permanent_exclusion_owner_signature_v1;
use zeroize::Zeroizing;

pub(super) struct PreparedPermanentStopExportV1 {
    retained: BornPermanentStopSourceV1,
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
impl PreparedPermanentStopExportV1 {
    pub(super) fn prepare(
        retained: BornPermanentStopSourceV1,
        destination: &Path,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        retained.check(owner)?;
        let envelope = retained
            .retained_signature()?
            .ok_or(Error::RecoveryRequired)?;
        if envelope.exclusion != retained.exclusion()? {
            return Err(Error::ReviewMismatch);
        }
        verify_permanent_exclusion_owner_signature_v1(
            &envelope,
            &retained
                .record()
                .account_record
                .terms
                .signer
                .owner_certificate_digest,
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
        let filename = format!("permanent-stop-owner-exclusion-v1-{content_digest}.json");
        require_absent(destination, &filename)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-permanent-stop-export:v1",
            &(
                retained.record().reference()?,
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
            "EXPORT EXACT RETAINED PERMANENT ACCOUNT EXCLUSION\nPrivate destination: {}\nFile: {filename}\nDirectory device/inode: {} / {}\nExact content SHA-256: {content_digest}\n\n{}\n\nThis file discloses account identity/FVK digest, immutable policy and origin linkage, exact immutable original permanent exclusion and operation, owner certificate and an existing-owner signature. Anyone receiving the file can inspect these fields and present the signed request to the named witness owner. No private key, seed or raw FVK is exported. The destination must already be a private local directory; this action never overwrites a file. It sends nothing over a network. Moving or sharing it later is a separate disclosure. Preserve the exact file for witness retries: the original account policy, budget, exposure and birth are never reset. Host roster position and account witness-attempt ancestry remain separate. Independent witness-owner review is still required.",
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
        self.retained.check(owner)?;
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
    ) -> Result<BornPermanentStopSourceV1> {
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
        drop(_lease);
        Ok(self.retained)
    }
}
pub(super) fn require_absent(directory: &Path, filename: &str) -> Result<()> {
    match std::fs::symlink_metadata(directory.join(filename)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Error::ReviewMismatch),
    }
}

pub(super) fn require_standalone_destination(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor
            .file_name()
            .is_some_and(|n| n == ".wholepact-witness")
        {
            return Err(Error::InvalidData);
        }
        for marker in [
            "account.wp",
            "profile.vault",
            "financial.vault",
            "born-backup.wp",
            "born-enrolled-backup.wp",
            "capsule.wp",
        ] {
            match std::fs::symlink_metadata(ancestor.join(marker)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(Error::InvalidData),
            }
        }
    }
    Ok(())
}
