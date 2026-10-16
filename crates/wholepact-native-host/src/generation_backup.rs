//! Complete generation capsule capture through explicit native commands.
//! Recursive composition is source-tested; attended execution is unqualified.
use crate::{
    Error, Result,
    files::Directory,
    financial_inventory::Attachment,
    recovery_generation::archive_history::{
        CaptureMetadata, VerifiedGenerationCapsule, capture_layered_metadata, capture_metadata,
        open_layered_parent, source_plan_version,
    },
    terminal::{Terminal, historical::HistoricalApproval},
    vault::{
        Secrets,
        generation_archive::{self as vault_archive, ArchiveRecovery, PendingArchiveRecovery},
    },
};
use std::path::{Path, PathBuf};
use wholepact_storage_security::{
    DatabaseKey,
    generation_archive::{
        self as archive, ArchiveAuthority, ArchiveError, ArchiveLease, ArchiveScope, NodeSpec,
        RegisteredSource, SnapshotRequest, Source,
    },
};
use zeroize::Zeroizing;

pub(crate) const COMPLETE: &[u8] = b"wholepact-generation-capsule-complete-v1\nAll files and the complete inherited capsule graph are required. No restored signing, enrollment, replay or financial authority.\n";
pub(crate) const CAPSULE: &str = "capsule.sqlite";
pub(crate) const PENDING: &str = "pending.recovery";
pub(crate) const RECOVERY: &str = "archive.recovery";

struct FinancialSource {
    attachment: Attachment,
    // Original-source authenticated read snapshots retain every main/sidecar
    // descriptor. Their Directory lock outlives all private snapshot owners.
    profile: crate::financial_profile::FinancialReadProfile,
}
enum Input {
    File(PathBuf),
    Journal(PathBuf),
    Secret(Zeroizing<Vec<u8>>),
}
struct Entry {
    id: String,
    role: String,
    input: Input,
}
impl Entry {
    fn file(id: &str, role: &str, path: PathBuf) -> Self {
        Self {
            id: id.into(),
            role: role.into(),
            input: Input::File(path),
        }
    }
    fn journal(id: &str, role: &str, path: PathBuf) -> Self {
        Self {
            id: id.into(),
            role: role.into(),
            input: Input::Journal(path),
        }
    }
    fn secret(id: &str, role: &str, bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            role: role.into(),
            input: Input::Secret(bytes),
        }
    }
    fn register(&self) -> std::result::Result<RegisteredSource<'_>, ArchiveError> {
        RegisteredSource::new(
            &self.id,
            &self.role,
            match &self.input {
                Input::File(p) => Source::File(p),
                Input::Journal(p) => Source::Journal(p),
                Input::Secret(b) => Source::Secret(b),
            },
        )
    }
}
fn role(kind: wholepact_storage_security::bundle::JournalKind) -> Result<&'static str> {
    use wholepact_storage_security::bundle::JournalKind::*;
    Ok(match kind {
        CoordinationAuthority => "inherited-coordination",
        TransportInbox => "inherited-inbox",
        TransportOutbox => "inherited-outbox",
        Submission => "inherited-submission",
        WalletScan => "inherited-wallet",
        ProofWitness => "inherited-proof",
        SignedResults => "inherited-signed",
        ExactTransactions => "inherited-transactions",
        _ => return Err(Error::Unsupported),
    })
}
fn entries(
    directory: &Directory,
    secrets: &Secrets,
    metadata: &CaptureMetadata,
    financial: &[FinancialSource],
) -> Result<Vec<Entry>> {
    if ![1, 2].contains(&metadata.descriptor().plan_version) {
        return Err(Error::Unsupported);
    }
    let mut entries = vec![
        Entry::secret(
            "host-source-descriptor",
            "host-source-descriptor",
            Zeroizing::new(serde_json::to_vec(metadata.descriptor())?),
        ),
        Entry::secret(
            "host-source-material",
            "host-source-material",
            vault_archive::source_material(secrets)?,
        ),
    ];
    for (id, name) in [
        ("host-vault", "profile.vault"),
        ("host-plan", "recovery.plan"),
        ("host-manifest", "generation.manifest"),
        ("host-commit", "generation.commit"),
        ("host-evidence-keys", "generation.keys"),
    ] {
        entries.push(Entry::file(id, id, directory.path(name)?));
    }
    for (id, role, name) in [
        (
            "root-coordination",
            "current-coordination",
            "coordination.sqlite",
        ),
        ("root-inbox", "current-inbox", "inbox.sqlite"),
        ("root-outbox", "current-outbox", "outbox.sqlite"),
        ("root-submission", "current-submission", "submission.sqlite"),
    ] {
        entries.push(Entry::journal(id, role, directory.path(name)?));
    }
    for component in metadata.components() {
        entries.push(Entry::journal(
            &format!("history-{}", component.component_id),
            role(component.kind)?,
            directory.path(&format!("history-{}.sqlite", component.component_id))?,
        ));
    }
    if !financial.is_empty() {
        entries.push(Entry::file(
            "host-financial-marker",
            "host-financial-marker",
            directory.path("financial.attached")?,
        ));
        entries.push(Entry::file(
            "host-financial-registry",
            "host-financial-registry",
            directory.path("financial.inventory")?,
        ));
    }
    if financial.len() != metadata.descriptor().attachments.len() {
        return Err(Error::Authentication);
    }
    for (index, source) in financial.iter().enumerate() {
        if source.attachment != metadata.descriptor().attachments[index] {
            return Err(Error::Authentication);
        }
        crate::financial_inventory::check_read_backup_owner(
            directory,
            secrets,
            &source.attachment,
            &source.profile,
        )?;
        source.profile.directory.inventory_of(
            &[
                "wallet.sqlite",
                "proof.sqlite",
                "signed.sqlite",
                "transactions.sqlite",
            ],
            &["profile.lock", "financial.vault"],
        )?;
        entries.push(Entry::file(
            &format!("financial-{index}-vault"),
            "financial-vault",
            source.profile.directory.path("financial.vault")?,
        ));
        entries.push(Entry::secret(
            &format!("financial-{index}-source-material"),
            "financial-source-material",
            vault_archive::financial_material(&source.profile.secrets),
        ));
        for name in ["wallet", "proof", "signed", "transactions"] {
            entries.push(Entry::journal(
                &format!("financial-{index}-{name}"),
                &format!("financial-{name}"),
                source.profile.directory.path(&format!("{name}.sqlite"))?,
            ));
        }
    }
    Ok(entries)
}
struct Consent<'a> {
    expected: ArchiveScope,
    approval: &'a HistoricalApproval,
    directory: &'a Directory,
    secrets: &'a Secrets,
    financial: &'a [FinancialSource],
}
struct Lease<'a>(&'a Consent<'a>);
impl ArchiveLease for Lease<'_> {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        self.0
            .approval
            .check()
            .map_err(|_| ArchiveError::Permission)?;
        self.0
            .directory
            .check()
            .map_err(|_| ArchiveError::Permission)?;
        for source in self.0.financial {
            crate::financial_inventory::check_read_backup_owner(
                self.0.directory,
                self.0.secrets,
                &source.attachment,
                &source.profile,
            )
            .map_err(|_| ArchiveError::Permission)?;
        }
        Ok(())
    }
}
impl ArchiveAuthority for Consent<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &ArchiveScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if scope != &self.expected {
            return Err(ArchiveError::Permission);
        }
        let lease = Lease(self);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}

pub(crate) fn backup(terminal: Terminal, profile: &Path, destination: &Path) -> Result<()> {
    let directory = Directory::open(profile)?;
    directory.external_destination(destination)?;
    let read=terminal.approve_historical(&format!("Authenticate every inherited and current private host-owned journal for complete encrypted generation backup at {}. Viewing/scan data, witnesses, signatures, transactions, transport/observation history and NON-signing storage/transport recovery keys are included. Registered current financial directories require separate private-data approval. Nothing is sent, signed or submitted; no financial or clone freshness is established.",destination.display()))?;
    let password = terminal.secret("Restricted successor storage passphrase: ")?;
    let mut captured = None;
    read.effect(&mut || {
        let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, password.as_bytes())?;
        let (metadata, parent) = match source_plan_version(&directory, &secrets)? {
            1 => (capture_metadata(&directory, &secrets)?, None),
            2 => {
                let (_, parent) = open_layered_parent(&directory, &secrets)?;
                let metadata = capture_layered_metadata(&directory, &secrets, &parent)?;
                (metadata, Some(parent))
            }
            _ => return Err(Error::Unsupported),
        };
        captured = Some((secrets, metadata, parent));
        Ok(())
    })?;
    read.check()?;
    drop(password);
    let (secrets, metadata, parent) = captured.ok_or(Error::Permission)?;
    if let Some(parent) = &parent {
        crate::generation_restore::exclude_original_sources(parent, destination)?;
    }
    let parents = parent
        .iter()
        .map(VerifiedGenerationCapsule::archive)
        .collect::<Vec<_>>();
    let mut financial = Vec::new();
    for attachment in &metadata.descriptor().attachments {
        read.check()?;
        directory.external_destination(&attachment.directory)?;
        let approval=terminal.approve_historical(&format!("Read and include all four private financial journals at {} ({:?}, account {:?}) and their non-signing recovery keys in this complete encrypted capsule? No signer spending key or permission is included.",attachment.directory.display(),attachment.role,attachment.account))?;
        let password = terminal.secret("Registered financial dependency passphrase: ")?;
        approval.effect(&mut || {
            let profile = crate::financial_profile::FinancialReadProfile::open(
                &attachment.directory,
                &secrets.profile(),
                password.as_bytes(),
            )?;
            profile.directory.external_destination(destination)?;
            crate::financial_inventory::check_read_backup_owner(
                &directory, &secrets, attachment, &profile,
            )?;
            financial.push(FinancialSource {
                attachment: attachment.clone(),
                profile,
            });
            Ok(())
        })?;
    }
    let recovery_password = terminal.secret("New generation capsule recovery passphrase: ")?;
    if *recovery_password != *terminal.secret("Repeat capsule recovery passphrase: ")? {
        return Err(Error::Authentication);
    }
    let entries = entries(&directory, &secrets, &metadata, &financial)?;
    let sources = entries
        .iter()
        .map(Entry::register)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let capsule_id = hex::encode(crate::random::<32>()?);
    let key_bytes = Zeroizing::new(crate::random::<32>()?);
    let key = DatabaseKey::from_bytes(*key_bytes);
    let target = destination.join(CAPSULE);
    let node = NodeSpec {
        generation_id: metadata.descriptor().generation_id.clone(),
        profile_id: secrets.profile(),
        original_root: profile.into(),
    };
    let scope = ArchiveScope::for_snapshot(&target, &key, &capsule_id, &node, &sources, &parents)?;
    let detail = Zeroizing::new(serde_json::to_string(&scope)?);
    if detail.len() > 128 * 1024 {
        return Err(Error::Invalid);
    }
    read.check()?;
    let approval=terminal.approve_historical(&format!("Create this exact NEW encrypted capsule. All inherited history and current registered dependencies are required. It remains historical evidence; restored roots are quarantined and fresh publication/enrollment is separate. No network, proof or financial effect is authorized. Source locks remain held throughout. Scope: {}",detail.as_str()))?;
    let consent = Consent {
        expected: scope,
        approval: &approval,
        directory: &directory,
        secrets: &secrets,
        financial: &financial,
    };
    let pending =
        PendingArchiveRecovery::new(&capsule_id, &metadata.descriptor().plan_digest, &key_bytes)?;
    let pending_envelope = pending.seal(recovery_password.as_bytes())?;
    let mut output_started = false;
    let result = approval.effect(&mut || {
        let output = Directory::create(destination)?;
        output_started = true;
        output.write_new(PENDING, &pending_envelope)?;
        let report = archive::snapshot(SnapshotRequest {
            destination: &target,
            key: &key,
            capsule_id: &capsule_id,
            node: &node,
            sources: &sources,
            parents: &parents,
            authority: &consent,
        })?;
        Lease(&consent).check_current()?;
        let verified = VerifiedGenerationCapsule::open(archive::inspect(&target, &key)?)?;
        if verified.manifest_digest() != report.manifest_digest
            || verified.capsule_id() != capsule_id
            || verified.root().descriptor() != metadata.descriptor()
        {
            return Err(Error::Authentication);
        }
        let recovery = pending.finish(verified.manifest_digest())?;
        let envelope = recovery.seal(recovery_password.as_bytes())?;
        let reopened = ArchiveRecovery::open(&envelope, recovery_password.as_bytes())?;
        if !pending.matches_final(&reopened) || reopened.manifest_digest() != report.manifest_digest
        {
            return Err(Error::Authentication);
        }
        consent.approval.check()?;
        directory.check()?;
        output.write_new(RECOVERY, &envelope)?;
        output.inventory_of(&[CAPSULE], &["profile.lock", PENDING, RECOVERY])?;
        Lease(&consent).check_current()?;
        output.write_new("COMPLETE", COMPLETE)?;
        output.inventory_of(&[CAPSULE], &["profile.lock", PENDING, RECOVERY, "COMPLETE"])?;
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
    terminal.message("Complete encrypted generation capsule written. Retain every output file. This did not create financial authority or clear historical uncertainty.\n").map_err(|_| Error::GenerationArchiveIncomplete)
}

#[cfg(all(test, target_os = "linux", feature = "financial-runtime"))]
pub(crate) mod tests;
