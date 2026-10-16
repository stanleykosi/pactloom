//! Capsule-only quarantine restoration. Original profile files and saved
//! admissions remain inert inside the capsule; this never opens a live Host.
use crate::{
    Error, Result,
    files::Directory,
    generation_backup::{CAPSULE, COMPLETE, PENDING, RECOVERY},
    recovery_generation::archive_history::VerifiedGenerationCapsule,
    terminal::{Terminal, historical::HistoricalApproval},
    vault::generation_archive::{
        ArchiveRecovery, PendingArchiveRecovery, QuarantinedGenerationRecovery,
    },
};
use std::path::Path;
use wholepact_storage_security::{
    DatabaseKey,
    generation_archive::{
        self as archive, ArchiveError, ArchiveLease, ArchiveReport, CopyAuthority, CopyRequest,
        CopyScope,
    },
};
use zeroize::Zeroizing;

const QUARANTINE: &str = "quarantine.recovery";
const RESTORED: &[u8] = b"wholepact-restored-generation-capsule-v1\nPermanent historical quarantine. Saved admissions are audit only. A fresh separately reviewed successor is required; no old authority is restored.\n";

pub(crate) struct RestoredGenerationCapsule {
    capsule: VerifiedGenerationCapsule,
    // The lock remains held until every archived snapshot above is dropped.
    directory: Directory,
}
impl RestoredGenerationCapsule {
    pub(crate) fn open(path: &Path, password: &[u8]) -> Result<Self> {
        let directory = Directory::open(path)?;
        directory.inventory_of(&[CAPSULE], &["profile.lock", QUARANTINE, "RESTORED"])?;
        if directory.read("RESTORED", 1024)? != RESTORED {
            return Err(Error::Authentication);
        }
        let recovery =
            QuarantinedGenerationRecovery::open(&directory.read(QUARANTINE, 1024)?, password)?;
        let capsule = VerifiedGenerationCapsule::open(archive::inspect(
            &directory.path(CAPSULE)?,
            &recovery.key(),
        )?)?;
        if capsule.capsule_id() != recovery.capsule_id()
            || capsule.manifest_digest() != recovery.manifest_digest()
        {
            return Err(Error::Authentication);
        }
        directory.check()?;
        Ok(Self { capsule, directory })
    }
    pub(crate) fn capsule(&self) -> &VerifiedGenerationCapsule {
        &self.capsule
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.directory.check()
    }
    pub(crate) fn external_destination(&self, path: &Path) -> Result<()> {
        self.directory.external_destination(path)?;
        exclude_original_sources(&self.capsule, path)
    }
}
pub(crate) fn open_archive(
    directory: &Directory,
    password: &[u8],
) -> Result<VerifiedGenerationCapsule> {
    directory.inventory_of(&[CAPSULE], &["profile.lock", PENDING, RECOVERY, "COMPLETE"])?;
    if directory.read("COMPLETE", 1024)? != COMPLETE {
        return Err(Error::Authentication);
    }
    let pending = PendingArchiveRecovery::open(&directory.read(PENDING, 1024)?, password)?;
    let recovery = ArchiveRecovery::open(&directory.read(RECOVERY, 1024)?, password)?;
    if !pending.matches_final(&recovery) {
        return Err(Error::Authentication);
    }
    let capsule = VerifiedGenerationCapsule::open(archive::inspect(
        &directory.path(CAPSULE)?,
        &recovery.key(),
    )?)?;
    if capsule.capsule_id() != recovery.capsule_id()
        || pending.capsule_id() != capsule.capsule_id()
        || capsule.manifest_digest() != recovery.manifest_digest()
        || pending.source_plan_digest() != capsule.root().descriptor().plan_digest
    {
        return Err(Error::Authentication);
    }
    directory.check()?;
    Ok(capsule)
}
pub(crate) fn exclude_original_sources(
    capsule: &VerifiedGenerationCapsule,
    destination: &Path,
) -> Result<()> {
    crate::files::validate_absolute(destination)?;
    let parent = destination.parent().ok_or(Error::Invalid)?;
    if std::fs::canonicalize(parent)? != parent {
        return Err(Error::Invalid);
    }
    for (manifest, history) in capsule.histories() {
        let node = capsule.archive().node(manifest)?;
        let roots = std::iter::once(Path::new(&node.original_root)).chain(
            history
                .descriptor()
                .attachments
                .iter()
                .map(|a| a.directory.as_path()),
        );
        for root in roots {
            if destination.starts_with(root) {
                return Err(Error::Invalid);
            }
            let canonical = match std::fs::canonicalize(root) {
                Ok(p) => p,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(Error::Storage),
            };
            if destination.starts_with(&canonical) {
                return Err(Error::Invalid);
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                let protected = std::fs::symlink_metadata(&canonical)?;
                for ancestor in parent.ancestors() {
                    let current = std::fs::symlink_metadata(ancestor)?;
                    if current.dev() == protected.dev() && current.ino() == protected.ino() {
                        return Err(Error::Invalid);
                    }
                }
            }
        }
    }
    Ok(())
}
struct Consent<'a> {
    scope: CopyScope,
    approval: &'a HistoricalApproval,
    source: &'a Directory,
}
struct Lease<'a>(&'a Consent<'a>);
impl ArchiveLease for Lease<'_> {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        self.0
            .approval
            .check()
            .map_err(|_| ArchiveError::Permission)?;
        self.0.source.check().map_err(|_| ArchiveError::Permission)
    }
}
impl CopyAuthority for Consent<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &CopyScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if scope != &self.scope {
            return Err(ArchiveError::Permission);
        }
        let lease = Lease(self);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}

pub(crate) fn restore(terminal: Terminal, backup: &Path, destination: &Path) -> Result<()> {
    let source = Directory::open(backup)?;
    source.external_destination(destination)?;
    let read=terminal.approve_historical(&format!("Authenticate and read every private record and NON-signing recovery key in generation capsule {} before restoring a NEW permanent quarantine at {}. All viewing/witness/signature/transaction/transport history and current registered financial dependencies are included. No saved signer admission, old transport credential, grant or financial authority is activated.",backup.display(),destination.display()))?;
    let password = terminal.secret("Generation capsule recovery passphrase: ")?;
    let mut capsule = None;
    read.effect(&mut || {
        capsule = Some(open_archive(&source, password.as_bytes())?);
        Ok(())
    })?;
    read.check()?;
    drop(password);
    let capsule = capsule.ok_or(Error::Permission)?;
    exclude_original_sources(&capsule, destination)?;
    let password = terminal.secret("New quarantined-capsule passphrase: ")?;
    if *password != *terminal.secret("Repeat quarantined-capsule passphrase: ")? {
        return Err(Error::Authentication);
    }
    let key_bytes = Zeroizing::new(crate::random::<32>()?);
    let key = DatabaseKey::from_bytes(*key_bytes);
    let recovery =
        ArchiveRecovery::new(capsule.capsule_id(), capsule.manifest_digest(), &key_bytes)?;
    let envelope = recovery.quarantine_envelope(password.as_bytes())?;
    let target = destination.join(CAPSULE);
    let scope = CopyScope::for_copy(capsule.archive(), &target, &key)?;
    let detail = Zeroizing::new(serde_json::to_string(&scope)?);
    if detail.len() > 128 * 1024 {
        return Err(Error::Invalid);
    }
    read.check()?;
    let approval=terminal.approve_historical(&format!("Copy this exact complete encrypted capsule into a NEW permanently quarantined root. Original paths and every ancestor remain historical identities; nothing is imported into ordinary profile filenames or live journals. Destination: {}. Scope: {}",destination.display(),detail.as_str()))?;
    let consent = Consent {
        scope,
        approval: &approval,
        source: &source,
    };
    let mut output_started = false;
    let result = approval.effect(&mut || {
        let output = Directory::create(destination)?;
        output_started = true;
        output.write_new(QUARANTINE, &envelope)?;
        let report: ArchiveReport = archive::copy(CopyRequest {
            source: capsule.archive(),
            destination: &target,
            key: &key,
            authority: &consent,
        })?;
        let check = VerifiedGenerationCapsule::open(archive::inspect(&target, &key)?)?;
        if check.manifest_digest() != capsule.manifest_digest()
            || report.manifest_digest != capsule.manifest_digest()
            || check.capsule_id() != capsule.capsule_id()
        {
            return Err(Error::Authentication);
        }
        let wrapped = QuarantinedGenerationRecovery::open(
            &output.read(QUARANTINE, 1024)?,
            password.as_bytes(),
        )?;
        if wrapped.capsule_id() != check.capsule_id()
            || wrapped.manifest_digest() != check.manifest_digest()
        {
            return Err(Error::Authentication);
        }
        let reopened = VerifiedGenerationCapsule::open(archive::inspect(&target, &wrapped.key())?)?;
        if reopened.manifest_digest() != capsule.manifest_digest()
            || reopened.capsule_id() != capsule.capsule_id()
        {
            return Err(Error::Authentication);
        }
        consent.approval.check()?;
        source.check()?;
        output.inventory_of(&[CAPSULE], &["profile.lock", QUARANTINE])?;
        approval.check()?;
        output.write_new("RESTORED", RESTORED)?;
        output.inventory_of(&[CAPSULE], &["profile.lock", QUARANTINE, "RESTORED"])?;
        Ok(())
    });
    if let Err(error) = result {
        return Err(if output_started {
            Error::GenerationArchiveIncomplete
        } else {
            error
        });
    }
    approval
        .check()
        .map_err(|_| Error::GenerationArchiveIncomplete)?;
    terminal.message("Complete capsule restored in permanent quarantine. No ordinary profile or authority was activated; preserve all files for separately reviewed successor publication.\n").map_err(|_| Error::GenerationArchiveIncomplete)
}
