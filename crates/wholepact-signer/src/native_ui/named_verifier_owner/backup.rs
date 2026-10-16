//! Native-only paired backup of the original verifier journal and exact outbox.
//! No IPC entry, key-use recovery, activation or restored live-owner constructor.
//! The ordinary bundle profile remains unchanged; this uses its explicitly
//! domain-separated, exactly-one-outbox named-verifier transport profile.
use super::{
    FILE, MAGIC, MAX, NativeAuthority, NativeAuthorityBinding, NativeDecision, VerifierOwner,
    export_identity::SetupState, export_setup::OUTBOX, journal::Journal,
};
use crate::{
    Error, Result, files::PrivateDirectory, native_ui::authority::NativePublicationLease, vault,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use wholepact_storage_security::{DatabaseKey, bundle::*};
use wholepact_transport::OUTBOX_BACKUP_TEMPLATE;
use zeroize::Zeroizing;

const RECOVERY_MAGIC: &[u8; 8] = b"WPNVB001";
const INFORMATIONAL_MAGIC: &[u8; 8] = b"WPNVI001";
const RECOVERY: &str = "recovery.wp";
const ARCHIVE: &str = "bundle.sqlite";
const COMPLETE: &str = "COMPLETE";
const INFORMATIONAL: &str = "named-verifier-informational.wp";
const RESTORE_COMPLETE: &str = "RESTORE-COMPLETE";
const COMPLETE_DOMAIN: &[u8] = b"wholepact:named-verifier-paired-backup-complete:v1";
const RESTORE_DOMAIN: &[u8] = b"wholepact:named-verifier-informational-restore-complete:v1";
const COMPONENT: &str = "named-verifier-outbox";
const MAX_RECOVERY: usize = MAX + 4096;
const MAX_MARKER: usize = 2048;

fn storage<T>(value: std::result::Result<T, BundleError>) -> Result<T> {
    value.map_err(|_| Error::RecoveryRequired)
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn exact_new_destination(source: &Path, output: &Path) -> Result<()> {
    if !source.is_absolute()
        || std::fs::canonicalize(source)? != source
        || !output.is_absolute()
        || output.starts_with(source)
        || output.file_name().is_none()
        || std::fs::canonicalize(output.parent().ok_or(Error::InvalidData)?)?
            != output.parent().ok_or(Error::InvalidData)?
    {
        return Err(Error::InvalidData);
    }
    match std::fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::InvalidData),
    }
}
fn profile(journal: &Journal) -> String {
    hash(&journal.public_key)
}
fn ready_original(journal: &Journal) -> Result<()> {
    journal.validate()?;
    if journal.restored_informational {
        return Err(Error::RecoveryRequired);
    }
    let identity = journal.export_identity.as_ref().ok_or(Error::Unavailable)?;
    if identity.state != SetupState::Ready {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
// Informational import validates retained public evidence without constructing a
// transport or attestation private-key object. Journal::validate otherwise calls
// ExportIdentity::validate, which derives a transport public key from the secret.
fn validate_retained_without_key_use(journal: &mut Journal) -> Result<()> {
    let identity = journal.export_identity.take().ok_or(Error::InvalidData)?;
    let public_result = journal.validate();
    journal.export_identity = Some(identity);
    public_result?;
    let identity = journal.export_identity.as_ref().ok_or(Error::InvalidData)?;
    identity.validate_metadata()?;
    if identity.state != SetupState::Ready
        || identity.setup_intent.verifier_digest != profile(journal)
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}
fn journal_bytes(journal: &Journal) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_json::to_vec(journal).map_err(|_| Error::InvalidData)?);
    if bytes.len() > MAX - 128 {
        return Err(Error::InvalidData);
    }
    Ok(bytes)
}
/// The private on-disk profile must still equal this unlocked owner. Source
/// ciphertext stays untouched; failures never reset an uncertain journal.
fn source_checkpoint(owner: &VerifierOwner) -> Result<String> {
    owner.check_current()?;
    ready_original(&owner.journal)?;
    let bytes = owner.directory.read(FILE, MAX)?;
    if bytes.len() < 64 || &bytes[..8] != MAGIC || bytes[8..24] != owner.salt {
        return Err(Error::Authentication);
    }
    let plain = vault::decrypt(&owner.encryption_key, &bytes[..24], &bytes[24..])?;
    let mut expected = Zeroizing::new(owner.seed.to_vec());
    expected.extend_from_slice(&journal_bytes(&owner.journal)?);
    if !bool::from(plain.as_slice().ct_eq(expected.as_slice())) {
        return Err(Error::Authentication);
    }
    Ok(hash(&bytes))
}
fn encode_payload(
    archive_key: &[u8; 32],
    seed: &[u8; 32],
    journal: &Journal,
) -> Result<Zeroizing<Vec<u8>>> {
    let body = journal_bytes(journal)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(69 + body.len()));
    plain.push(1);
    plain.extend_from_slice(archive_key);
    plain.extend_from_slice(seed);
    plain.extend_from_slice(
        &(u32::try_from(body.len()).map_err(|_| Error::InvalidData)?).to_le_bytes(),
    );
    plain.extend_from_slice(&body);
    if plain.len() > MAX_RECOVERY - 128 {
        return Err(Error::InvalidData);
    }
    Ok(plain)
}
struct Payload {
    archive_key: Zeroizing<[u8; 32]>,
    seed: Zeroizing<[u8; 32]>,
    journal: Journal,
}
fn decode_payload(plain: &[u8]) -> Result<Payload> {
    if plain.len() < 70 || plain.len() > MAX_RECOVERY - 128 || plain[0] != 1 {
        return Err(Error::InvalidData);
    }
    let length =
        u32::from_le_bytes(plain[65..69].try_into().map_err(|_| Error::InvalidData)?) as usize;
    if length != plain.len() - 69 || length > MAX - 128 {
        return Err(Error::InvalidData);
    }
    let mut journal: Journal =
        serde_json::from_slice(&plain[69..]).map_err(|_| Error::InvalidData)?;
    validate_retained_without_key_use(&mut journal)?;
    if journal.restored_informational {
        return Err(Error::RecoveryRequired);
    }
    let archive_key = Zeroizing::new(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
    let seed = Zeroizing::new(plain[33..65].try_into().map_err(|_| Error::InvalidData)?);
    let identity = journal.export_identity.as_ref().ok_or(Error::InvalidData)?;
    if *archive_key == [0; 32]
        || *archive_key == *seed
        || *archive_key == identity.secrets.database
        || *archive_key == identity.secrets.transport
    {
        return Err(Error::InvalidData);
    }
    // No Ed25519 or transport private key is instantiated on the restore path.
    // Authenticated backup binds these retained bytes to the original journal.
    Ok(Payload {
        archive_key,
        seed,
        journal,
    })
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Completion {
    version: u16,
    profile_id: String,
    recovery_digest: String,
    bundle_digest: String,
}
impl Completion {
    fn from_manifest(recovery: &[u8], manifest: &BundleManifest) -> Self {
        Self {
            version: 1,
            profile_id: manifest.profile_id.clone(),
            recovery_digest: hash(recovery),
            bundle_digest: manifest.digest.clone(),
        }
    }
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| Error::InvalidData)?,
        ))
    }
}
fn require_pair_checkpoint(
    profile_id: &str,
    recovery: &[u8],
    manifest: &BundleManifest,
) -> Result<()> {
    if manifest.profile_id != profile_id || manifest.checkpoint_id != hash(recovery) {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn verify_pair(
    payload: &Payload,
    recovery: &[u8],
    manifest: &BundleManifest,
    marker: &[u8],
) -> Result<()> {
    require_pair_checkpoint(&profile(&payload.journal), recovery, manifest)?;
    if manifest.coverage != named_verifier_transport_coverage()
        || manifest.components.len() != 1
        || manifest.components[0].id != COMPONENT
        || manifest.components[0].kind != JournalKind::TransportOutbox
        || manifest.components[0].application_id != OUTBOX_BACKUP_TEMPLATE.application_id
        || manifest.components[0].schema_version != OUTBOX_BACKUP_TEMPLATE.schema_version
        || manifest.wallet_spending_secrets_included
        || manifest.writer_freshness_established
        || !manifest.restore_requires_recovery
    {
        return Err(Error::Authentication);
    }
    let plain = vault::decrypt(&payload.archive_key, COMPLETE_DOMAIN, marker)?;
    let completion: Completion =
        serde_json::from_slice(&plain).map_err(|_| Error::Authentication)?;
    if completion != Completion::from_manifest(recovery, manifest) {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn exact_backup_inventory(source: &PrivateDirectory) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for entry in std::fs::read_dir(source.root())? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::InvalidData)?;
        if ![
            "signer.lock",
            RECOVERY,
            ARCHIVE,
            "bundle.sqlite-wal",
            "bundle.sqlite-shm",
            COMPLETE,
        ]
        .contains(&name)
        {
            return Err(Error::InvalidData);
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidData);
        }
    }
    Ok(())
}

/// Only constructed by consuming an actual exact NativeDecision. The held
/// publication lease fences native invalidation. The caller also retains its
/// exclusive PrivateDirectory and sole owner/worker scope throughout the pair.
struct NativeBundleConsent<'a> {
    source: &'a NativeAuthorityBinding,
    _publication: &'a NativePublicationLease<'a>,
    principal: String,
    profile: String,
    archive: PathBuf,
    destinations: Vec<PathBuf>,
    sources: Vec<(String, JournalBinding)>,
    action: BundleAction,
    checkpoint: String,
    expires: Instant,
}
struct Lease<'a, 'owner>(&'a NativeBundleConsent<'owner>);
impl BundleLease for Lease<'_, '_> {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        self.0
            .source
            .check_current()
            .map_err(|_| BundleError::PermissionChanged)?;
        if Instant::now() >= self.0.expires {
            return Err(BundleError::PermissionChanged);
        }
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        &self.0.checkpoint
    }
}
impl BundleAuthority for NativeBundleConsent<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != self.principal
            || scope.profile_id != self.profile
            || scope.archive != self.archive
            || scope.destinations != self.destinations
            || scope.sources != self.sources
            || scope.action != self.action
            || scope.coverage != &named_verifier_transport_coverage()
            || scope.retention != "local-only; retain until deliberately removed"
            || scope.wallet_spending_secrets_included
            || !scope.private_viewing_witness_and_correlation_data_may_be_included
        {
            return Err(BundleError::Permission);
        }
        let lease = Lease(self);
        lease.check_current()?;
        Ok(Box::new(lease))
    }
}
fn require_current_until(source: &NativeAuthorityBinding, expires: Instant) -> Result<()> {
    source.check_current()?;
    if Instant::now() >= expires {
        return Err(Error::Locked);
    }
    Ok(())
}
fn decision_deadline(
    decision: &NativeDecision,
    source: &NativeAuthorityBinding,
    digest: &str,
) -> Result<Instant> {
    source.check_current()?;
    if decision.binding() != source || decision.reviewed_digest() != digest {
        return Err(Error::ReviewMismatch);
    }
    let expires = decision
        .consumed_at()
        .checked_add(Duration::from_secs(120))
        .ok_or(Error::Locked)?;
    if Instant::now() >= expires {
        return Err(Error::Locked);
    }
    Ok(expires)
}

pub(super) struct PreparedBackup {
    output: PathBuf,
    source: NativeAuthorityBinding,
    principal: String,
    commitment: String,
    source_file: String,
    digest: String,
    display: String,
}
impl VerifierOwner {
    pub(super) fn prepare_backup(
        &mut self,
        output: &Path,
        native: &NativeAuthority,
    ) -> Result<PreparedBackup> {
        self.check_current()?;
        if self.source != native.binding() {
            return Err(Error::ReviewMismatch);
        }
        exact_new_destination(self.directory.root(), output)?;
        let source_file = source_checkpoint(self)?;
        let commitment = self.state_commitment()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-named-verifier-backup:v1",
            &(
                self.directory.root(),
                output,
                &commitment,
                &source_file,
                self.source.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "BACK UP ORIGINAL NAMED VERIFIER AND EXACT ENCRYPTED OUTBOX\nOriginal profile: {}\nNew private backup directory: {}\nVerifier fingerprint: {}\nThis local encrypted pair retains the attestation seed, independent transport/database keys, every original request family and Prepared/Started/Signed fence, signatures, original terms, recipient pins, exact ciphertext and sequence/receipt metadata. Untrusted imported request files and duplicate exported .wpe files are excluded; their authoritative retained results are in the journal and outbox. All files in the backup directory must stay together. The backup passphrase cannot be recovered. No spending secrets, new assertion, delivery or settlement are produced. A restored copy is informational only; no key use or export issuance is enabled. Later activity and disconnected clones are not excluded.\nExact review: {}",
            self.directory.root().display(),
            output.display(),
            profile(&self.journal),
            digest
        );
        Ok(PreparedBackup {
            output: output.into(),
            source: self.source.clone(),
            principal: native.principal_id().into(),
            commitment,
            source_file,
            digest,
            display,
        })
    }
}
impl PreparedBackup {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(
        self,
        owner: &mut VerifierOwner,
        decision: NativeDecision,
        backup_password: &[u8],
    ) -> Result<()> {
        let expires = decision_deadline(&decision, &self.source, &self.digest)?;
        if owner.source != self.source
            || owner.state_commitment()? != self.commitment
            || source_checkpoint(owner)? != self.source_file
        {
            return Err(Error::ReviewMismatch);
        }
        exact_new_destination(owner.directory.root(), &self.output)?;
        // No assertion worker may coexist with this owner. The directory lock
        // excludes cooperating reopeners; this mutable borrow excludes mutation.
        let mut outbox = owner.open_export_outbox()?;
        let adapter = outbox
            .backup_adapter()
            .map_err(|_| Error::RecoveryRequired)?;
        let sources = [storage(RegisteredJournal::new(COMPONENT, &adapter))?];
        let archive_key = Zeroizing::new(vault::random::<32>()?);
        let identity = owner
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::InvalidData)?;
        if *archive_key == [0; 32]
            || *archive_key == *owner.seed
            || *archive_key == identity.secrets.transport
            || *archive_key == identity.secrets.database
        {
            return Err(Error::Crypto);
        }
        let plain = encode_payload(&archive_key, &owner.seed, &owner.journal)?;
        let recovery = vault::password_envelope(RECOVERY_MAGIC, backup_password, &plain)?;
        // Password KDF work is outside the native publication fence. It cannot
        // extend the original consumed decision or admit a late first write.
        require_current_until(&self.source, expires)?;
        let publication = self.source.publication_lease()?;
        require_current_until(&self.source, expires)?;
        let destination = PrivateDirectory::create(&self.output)?;
        require_current_until(&self.source, expires)?;
        destination.write(RECOVERY, &recovery)?;
        require_current_until(&self.source, expires)?;
        let archive = self.output.join(ARCHIVE);
        let key = DatabaseKey::from_bytes(*archive_key);
        let consent = NativeBundleConsent {
            source: &self.source,
            _publication: &publication,
            principal: self.principal,
            profile: profile(&owner.journal),
            archive: archive.clone(),
            destinations: vec![],
            sources: sources
                .iter()
                .map(|s| (s.id().to_owned(), s.binding()))
                .collect(),
            action: BundleAction::Snapshot,
            checkpoint: hash(&recovery),
            expires,
        };
        let manifest = storage(snapshot_named_verifier_transport(SnapshotRequest {
            principal_id: &consent.principal,
            profile_id: &consent.profile,
            coverage: named_verifier_transport_coverage(),
            sources: &sources,
            destination: &archive,
            key: &key,
            authority: &consent,
        }))?;
        let (verified, _, _) = vault::open_password_envelope(
            RECOVERY_MAGIC,
            backup_password,
            &destination.read(RECOVERY, MAX_RECOVERY)?,
            MAX_RECOVERY,
        )?;
        if !bool::from(verified.as_slice().ct_eq(plain.as_slice()))
            || storage(inspect_named_verifier_transport(&archive, &key))?.digest != manifest.digest
            || source_checkpoint(owner)? != self.source_file
            || owner.state_commitment()? != self.commitment
        {
            return Err(Error::Authentication);
        }
        let completion = Completion::from_manifest(&recovery, &manifest);
        let marker = vault::encrypt(&archive_key, COMPLETE_DOMAIN, &completion.bytes()?)?;
        // All encrypted pieces are durable before the authenticated commit marker.
        destination.sync_all_files()?;
        Lease(&consent).check_current().map_err(|_| Error::Locked)?;
        destination.write(COMPLETE, &marker)?;
        destination.sync_all_files()?;
        verify_pair(
            &decode_payload(&verified)?,
            &recovery,
            &manifest,
            &destination.read(COMPLETE, MAX_MARKER)?,
        )?;
        Lease(&consent).check_current().map_err(|_| Error::Locked)?;
        Ok(())
    }
}

pub(super) struct PreparedRestore {
    // Retains backup lock through native review, exact verification and restore.
    backup: PrivateDirectory,
    output: PathBuf,
    source: NativeAuthorityBinding,
    principal: String,
    recovery: Vec<u8>,
    payload: Payload,
    manifest: BundleManifest,
    marker: Vec<u8>,
    digest: String,
    display: String,
}
impl PreparedRestore {
    pub(super) fn prepare(
        backup: &Path,
        output: &Path,
        backup_password: &[u8],
        native: &NativeAuthority,
    ) -> Result<Self> {
        native.check_current()?;
        exact_new_destination(backup, output)?;
        let backup = PrivateDirectory::open_existing(backup)?;
        exact_backup_inventory(&backup)?;
        let recovery = backup.read(RECOVERY, MAX_RECOVERY)?;
        let (plain, _, _) = vault::open_password_envelope(
            RECOVERY_MAGIC,
            backup_password,
            &recovery,
            MAX_RECOVERY,
        )?;
        let payload = decode_payload(&plain)?;
        let archive_key = DatabaseKey::from_bytes(*payload.archive_key);
        let manifest = storage(inspect_named_verifier_transport(
            &backup.root().join(ARCHIVE),
            &archive_key,
        ))?;
        let marker = backup.read(COMPLETE, MAX_MARKER)?;
        verify_pair(&payload, &recovery, &manifest, &marker)?;
        let source = native.binding();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-named-verifier-informational-restore:v1",
            &(
                backup.root(),
                output,
                &manifest.digest,
                &manifest.checkpoint_id,
                hash(&marker),
                source.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "RESTORE INFORMATIONAL NAMED-VERIFIER RECORDS\nExact backup: {}\nNew private destination: {}\nVerifier fingerprint: {}\nOriginal checkpoint: {}\nArchive commitment: {}\nRetained encrypted private material and complete original request/recipient/result history remain historical evidence. The restored outbox is independently quarantined. This never creates a live verifier profile, private-key use, recipient pin admission, new ciphertext or exact export retry. Validity and request fences never reset. It cannot revoke disconnected copies, establish freshness or recover financial authority. No network transmission occurs.\nExact review: {}",
            backup.root().display(),
            output.display(),
            manifest.profile_id,
            manifest.checkpoint_id,
            manifest.digest,
            digest
        );
        native.check_current()?;
        Ok(Self {
            backup,
            output: output.into(),
            source,
            principal: native.principal_id().into(),
            recovery,
            payload,
            manifest,
            marker,
            digest,
            display,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(mut self, decision: NativeDecision, new_password: &[u8]) -> Result<()> {
        let expires = decision_deadline(&decision, &self.source, &self.digest)?;
        exact_new_destination(self.backup.root(), &self.output)?;
        exact_backup_inventory(&self.backup)?;
        if self.backup.read(RECOVERY, MAX_RECOVERY)? != self.recovery
            || self.backup.read(COMPLETE, MAX_MARKER)? != self.marker
        {
            return Err(Error::ReviewMismatch);
        }
        let archive = self.backup.root().join(ARCHIVE);
        let archive_key = DatabaseKey::from_bytes(*self.payload.archive_key);
        let manifest = storage(inspect_named_verifier_transport(&archive, &archive_key))?;
        if manifest.digest != self.manifest.digest {
            return Err(Error::ReviewMismatch);
        }
        verify_pair(&self.payload, &self.recovery, &manifest, &self.marker)?;
        self.payload.journal.restored_informational = true;
        validate_retained_without_key_use(&mut self.payload.journal)?;
        let plaintext = encode_payload(
            &self.payload.archive_key,
            &self.payload.seed,
            &self.payload.journal,
        )?;
        let informational =
            vault::password_envelope(INFORMATIONAL_MAGIC, new_password, &plaintext)?;
        // Password KDF work is outside the native publication fence. It cannot
        // extend the original consumed decision or admit a late first write.
        require_current_until(&self.source, expires)?;
        let publication = self.source.publication_lease()?;
        require_current_until(&self.source, expires)?;
        let destination = PrivateDirectory::create(&self.output)?;
        require_current_until(&self.source, expires)?;
        // This is the first imported-data write. Distinct magic and filename
        // prevent a crash, missing marker or UI mistake reaching VerifierOwner.
        destination.write(INFORMATIONAL, &informational)?;
        require_current_until(&self.source, expires)?;
        let outbox_path = self.output.join(OUTBOX);
        let identity = self
            .payload
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::InvalidData)?;
        let outbox_key = DatabaseKey::from_bytes(identity.secrets.database);
        let targets = [RestoreTarget {
            component_id: COMPONENT,
            template: &OUTBOX_BACKUP_TEMPLATE,
            destination: &outbox_path,
            key: &outbox_key,
        }];
        let consent = NativeBundleConsent {
            source: &self.source,
            _publication: &publication,
            principal: self.principal,
            profile: manifest.profile_id.clone(),
            archive: archive.clone(),
            destinations: vec![outbox_path.clone()],
            sources: vec![],
            action: BundleAction::Restore,
            checkpoint: manifest.checkpoint_id.clone(),
            expires,
        };
        let report = storage(restore_named_verifier_transport(RestoreRequest {
            principal_id: &consent.principal,
            profile_id: &consent.profile,
            archive: &archive,
            key: &archive_key,
            targets: &targets,
            authority: &consent,
        }))?;
        if !report.integrity_verified
            || !report.all_components_quarantined
            || report.authorization_allowed
            || report.signer_recovered
            || report.manifest.digest != manifest.digest
            || report.restored_components != 1
        {
            return Err(Error::Verification);
        }
        let (verified, _, _) = vault::open_password_envelope(
            INFORMATIONAL_MAGIC,
            new_password,
            &destination.read(INFORMATIONAL, MAX_RECOVERY)?,
            MAX_RECOVERY,
        )?;
        if !bool::from(verified.as_slice().ct_eq(plaintext.as_slice())) {
            return Err(Error::Authentication);
        }
        destination.sync_all_files()?;
        Lease(&consent).check_current().map_err(|_| Error::Locked)?;
        let completion = Completion::from_manifest(&self.recovery, &manifest);
        let marker = vault::encrypt(
            &self.payload.archive_key,
            RESTORE_DOMAIN,
            &completion.bytes()?,
        )?;
        Lease(&consent).check_current().map_err(|_| Error::Locked)?;
        destination.write(RESTORE_COMPLETE, &marker)?;
        destination.sync_all_files()?;
        Lease(&consent).check_current().map_err(|_| Error::Locked)?;
        // No VerifierOwner, signing object, live mailbox or retained ciphertext
        // is returned. An interrupted destination is never overwritten or reset.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_write_gate_rejects_elapsed_original_deadline_and_revocation() {
        // Test-only inert native lifetime; no decision, profile or private write.
        let native = crate::native_ui::authority::recovery_test_authority();
        let source = native.binding();
        let future = Instant::now().checked_add(Duration::from_secs(60)).unwrap();
        require_current_until(&source, future).unwrap();
        assert!(require_current_until(&source, Instant::now()).is_err());
        drop(native);
        assert!(require_current_until(&source, future).is_err());
    }
    #[test]
    fn recovery_and_informational_wire_domains_are_disjoint() {
        assert_ne!(RECOVERY_MAGIC, INFORMATIONAL_MAGIC);
        assert_ne!(MAGIC, INFORMATIONAL_MAGIC);
        assert_ne!(FILE, INFORMATIONAL);
        assert_ne!(COMPLETE_DOMAIN, RESTORE_DOMAIN);
    }
    #[test]
    fn malformed_recovery_lengths_are_rejected_before_key_or_native_use() {
        for bytes in [vec![], vec![0; 69], vec![1; 70], vec![1; MAX_RECOVERY]] {
            assert!(decode_payload(&bytes).is_err());
        }
    }
    #[test]
    fn original_recovery_and_manifest_cannot_be_cross_paired() {
        let recovery = b"synthetic authenticated ciphertext identity";
        let mut manifest = BundleManifest {
            format_version: 2,
            profile_id: "public-profile".into(),
            checkpoint_id: hash(recovery),
            coverage: named_verifier_transport_coverage(),
            components: vec![],
            digest: "ab".repeat(32),
            wallet_spending_secrets_included: false,
            private_viewing_witness_and_correlation_data_may_be_included: true,
            writer_freshness_established: false,
            restore_requires_recovery: true,
        };
        assert!(require_pair_checkpoint("public-profile", recovery, &manifest).is_ok());
        assert!(
            require_pair_checkpoint("public-profile", b"substituted ciphertext", &manifest)
                .is_err()
        );
        assert!(require_pair_checkpoint("another-profile", recovery, &manifest).is_err());
        manifest.checkpoint_id = "cd".repeat(32);
        assert!(require_pair_checkpoint("public-profile", recovery, &manifest).is_err());
    }
    #[test]
    fn informational_envelope_never_enters_live_profile_decryption() {
        // The real ordinary envelope opener rejects the distinct magic before
        // KDF or private-key construction. No native approval/key is fabricated.
        let mut inert = INFORMATIONAL_MAGIC.to_vec();
        inert.resize(64, 0);
        assert!(matches!(
            vault::open_password_envelope(MAGIC, b"not-used", &inert, MAX),
            Err(Error::InvalidData)
        ));
        assert_ne!(FILE, INFORMATIONAL);
        // A source-level filesystem gate fixture contains no seed or encrypted
        // profile. The live owner's exact filename is absent and cannot open.
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::create(&temp.path().join("inert-informational")).unwrap();
        directory.write(INFORMATIONAL, &inert).unwrap();
        assert!(directory.read(FILE, MAX).is_err());
    }
    #[test]
    fn completion_commits_both_files_and_version() {
        let marker = Completion {
            version: 1,
            profile_id: "public-profile".into(),
            recovery_digest: hash(b"synthetic encrypted recovery bytes"),
            bundle_digest: "ab".repeat(32),
        };
        let bytes = marker.bytes().unwrap();
        let reopened: Completion = serde_json::from_slice(&bytes).unwrap();
        assert!(reopened == marker);
        let mut changed = reopened;
        changed.bundle_digest = "cd".repeat(32);
        assert!(changed != marker);
        assert_ne!(
            marker.recovery_digest,
            hash(b"different synthetic ciphertext")
        );
        assert!(serde_json::from_slice::<Completion>(b"{\"version\":1,\"extra\":true}").is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "backup/encrypted_roundtrip_tests.rs"]
mod encrypted_roundtrip_tests;
