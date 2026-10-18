//! Atomic successor publication. Original quarantine is never modified. A
//! recovered account is usable only with an authenticated vault generation,
//! complete supported inventory, final durable commit marker, and keyed journal
//! generation verification. A receipt DTO alone is never an activation token.
use super::*;
use crate::consent_journal::{
    ApprovedRecoveryActivation, RecoveryActivationInventory, RecoveryActivationRecord,
};
use serde::{Deserialize, Serialize};
use wholepact_authority::AuthenticatedRecoveryFence;
use wholepact_storage_security::bundle::{BundleManifest, JournalKind};

const DOMAIN: &[u8] = b"wholepact:profile-activation:v1\0";
const MAX_MANIFEST: usize = 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VaultGeneration {
    record: RecoveryActivationRecord,
    manifest_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationManifest {
    version: u32,
    record: RecoveryActivationRecord,
    source: BundleManifest,
    recipient_history_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet_key_digest: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPlan {
    version: u32,
    inventory: RecoveryActivationInventory,
    source: BundleManifest,
    source_directory: std::path::PathBuf,
    recipient_history_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet_key_digest: Option<String>,
}
/// Proof of an authenticated, immutable pending generation. Never constructed
/// from caller JSON or a path without decrypting the selected target vault.
pub(crate) struct VerifiedRecoveryPlan {
    inventory: RecoveryActivationInventory,
}
impl VerifiedRecoveryPlan {
    pub(crate) fn inventory(&self) -> &RecoveryActivationInventory {
        &self.inventory
    }
}
/// Sealed capability. No public constructor, deserializer, Clone or raw-field
/// mutator exists. Only the encrypted vault + committed manifest gate mints it.
pub(crate) struct VerifiedProfileActivation {
    record: RecoveryActivationRecord,
}
impl VerifiedProfileActivation {
    pub(crate) fn record(&self) -> &RecoveryActivationRecord {
        &self.record
    }
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::InvalidData)
}
fn supported(manifest: &BundleManifest) -> Result<()> {
    let wallet = manifest.components.iter().any(|c| c.id == "signer-wallet");
    if manifest.coverage != super::backup::coverage(wallet)
        || manifest.components.len() != if wallet { 2 } else { 1 }
        || manifest.components[0].id != "signer-authority"
        || manifest.components[0].kind != JournalKind::SignerConsentAuthority
        || (wallet
            && (manifest.components[1].id != "signer-wallet"
                || manifest.components[1].kind != JournalKind::WalletScan))
        || manifest.writer_freshness_established
        || !manifest.restore_requires_recovery
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
impl AccountVault {
    fn verify_recovery_wallet_key(
        &self,
        source: &BundleManifest,
        expected: &Option<String>,
        committed: bool,
    ) -> Result<()> {
        let included = source
            .components
            .iter()
            .any(|c| c.kind == JournalKind::WalletScan);
        if included != expected.is_some()
            || self.directory.exists("viewing-wallet-key.wp")? != included
            || (!included && self.directory.exists("viewing-wallet.sqlite")?)
            || (committed && included && !self.directory.exists("viewing-wallet.sqlite")?)
        {
            return Err(Error::Authentication);
        }
        if let Some(expected) = expected {
            let wrapped = self.directory.read("viewing-wallet-key.wp", 1024)?;
            if digest(&wrapped) != *expected {
                return Err(Error::Authentication);
            }
            let _ = self.recovery_wallet_key()?;
        }
        Ok(())
    }
    fn recovery_wallet_key(&self) -> Result<wholepact_storage_security::DatabaseKey> {
        let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
        domain.extend(self.account_id()?.as_bytes());
        let bytes = vault::decrypt(
            &self.encryption_key,
            &domain,
            &self.directory.read("viewing-wallet-key.wp", 1024)?,
        )?;
        Ok(wholepact_storage_security::DatabaseKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Authentication)?,
        ))
    }
    fn activation_domain(&self, suffix: &[u8]) -> Result<Vec<u8>> {
        let mut domain = DOMAIN.to_vec();
        domain.extend(self.account_id()?.as_bytes());
        domain.extend(suffix);
        Ok(domain)
    }
    pub(crate) fn verify_profile_activation(&self) -> Result<VerifiedProfileActivation> {
        let binding = self.generation.as_ref().ok_or(Error::RecoveryRequired)?;
        if !self.authority_initialized
            || !self.account.restored
            || binding.record.account_id != self.account_id()?
            || binding.record.target_profile != self.directory.root()
            || std::fs::canonicalize(self.directory.root())? != self.directory.root()
        {
            return Err(Error::RecoveryRequired);
        }
        let manifest_bytes = self
            .directory
            .read("activation-manifest.wp", MAX_MANIFEST)?;
        if digest(&manifest_bytes) != binding.manifest_digest {
            return Err(Error::Authentication);
        }
        let plaintext = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"manifest")?,
            &manifest_bytes,
        )?;
        let manifest: ActivationManifest =
            serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidData)?;
        supported(&manifest.source)?;
        self.verify_recovery_wallet_key(&manifest.source, &manifest.wallet_key_digest, true)?;
        if manifest.version != 1
            || manifest.record != binding.record
            || manifest.source.profile_id != binding.record.account_id
            || manifest.source.digest != binding.record.source_bundle_digest
            || manifest.source.components[0].digest != binding.record.source_component_digest
        {
            return Err(Error::Authentication);
        }
        let history = self
            .directory
            .read("recovery-recipient-history.wp", 4 * 1024 * 1024 + 1024)?;
        if digest(&history) != manifest.recipient_history_digest {
            return Err(Error::Authentication);
        }
        // Authentication, not only a file hash, is required for historical data.
        let _history = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"recipient-history")?,
            &history,
        )?;
        let marker = self.directory.read("activation-commit.wp", 64 * 1024)?;
        let marker = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"commit")?,
            &marker,
        )?;
        if marker.as_slice() != encode(binding)?.as_slice() {
            return Err(Error::Authentication);
        }
        Ok(VerifiedProfileActivation {
            record: binding.record.clone(),
        })
    }
    pub(crate) fn verify_recovery_plan(&self) -> Result<VerifiedRecoveryPlan> {
        let plan = self.read_recovery_plan()?;
        Ok(VerifiedRecoveryPlan {
            inventory: plan.inventory,
        })
    }
    fn read_recovery_plan(&self) -> Result<RecoveryPlan> {
        if !self.account.restored || !self.authority_initialized {
            return Err(Error::RecoveryRequired);
        }
        let bytes = self.directory.read("recovery-plan.wp", MAX_MANIFEST)?;
        let plain = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"plan")?,
            &bytes,
        )?;
        let plan: RecoveryPlan = serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
        supported(&plan.source)?;
        self.verify_recovery_wallet_key(&plan.source, &plan.wallet_key_digest, false)?;
        if plan.version != 1
            || plan.source.profile_id != self.account_id()?
            || plan.inventory.target_profile() != self.directory.root()
            || std::fs::canonicalize(self.directory.root())? != self.directory.root()
        {
            return Err(Error::Authentication);
        }
        let history = self
            .directory
            .read("recovery-recipient-history.wp", 4 * 1024 * 1024 + 1024)?;
        if digest(&history) != plan.recipient_history_digest {
            return Err(Error::Authentication);
        }
        let recipient = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"recipient-history")?,
            &history,
        )?;
        if recipient.as_slice() != self.read_recipient_records()?.as_slice() {
            return Err(Error::Authentication);
        }
        Ok(plan)
    }
    pub(crate) fn resume_recovery_inventory(
        &self,
        source: &BundleManifest,
        original: &AccountVault,
    ) -> Result<RecoveryActivationInventory> {
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        let plan = self.read_recovery_plan()?;
        if &plan.source != source
            || plan.source_directory != original.directory.root()
            || self.account_id()? != original.account_id()?
        {
            return Err(Error::Authentication);
        }
        Ok(plan.inventory)
    }
    pub(crate) fn save_recovery_owner_request(
        &self,
        request: &wholepact_authority::OwnerControlRequest,
    ) -> Result<()> {
        let plan = self.read_recovery_plan()?;
        if request.operation_id != plan.inventory.operation_id()
            || request.account_id != self.account_id()?
            || request.control
                != (wholepact_authority::OwnerControl::RecoverWriter {
                    writer_certificate_digest: plan
                        .inventory
                        .successor_writer_certificate_digest()
                        .to_owned(),
                    inventory_digest: plan.inventory.digest()?,
                })
        {
            return Err(Error::Authentication);
        }
        if let Some(existing) = self.read_recovery_owner_request()? {
            if existing != *request {
                return Err(Error::Authentication);
            }
            return Ok(());
        }
        let encrypted = vault::encrypt(
            &self.encryption_key,
            &self.activation_domain(b"owner-request")?,
            &encode(request)?,
        )?;
        self.directory
            .write("recovery-owner-request.wp", &encrypted)
    }
    pub(crate) fn read_recovery_owner_request(
        &self,
    ) -> Result<Option<wholepact_authority::OwnerControlRequest>> {
        let plan = self.read_recovery_plan()?;
        if !self.directory.exists("recovery-owner-request.wp")? {
            return Ok(None);
        }
        let bytes = self
            .directory
            .read("recovery-owner-request.wp", 64 * 1024)?;
        let plain = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"owner-request")?,
            &bytes,
        )?;
        let request: wholepact_authority::OwnerControlRequest =
            serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
        if request.operation_id != plan.inventory.operation_id()
            || request.account_id != self.account_id()?
            || request.control
                != (wholepact_authority::OwnerControl::RecoverWriter {
                    writer_certificate_digest: plan
                        .inventory
                        .successor_writer_certificate_digest()
                        .to_owned(),
                    inventory_digest: plan.inventory.digest()?,
                })
        {
            return Err(Error::Authentication);
        }
        Ok(Some(request))
    }
    fn check_request_revision(
        &self,
        old: &wholepact_authority::OwnerControlRequest,
        new: &wholepact_authority::OwnerControlRequest,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<()> {
        let plan = self.read_recovery_plan()?;
        if history.disclosure() != plan.inventory.witness() {
            return Err(Error::Authentication);
        }
        if old.operation_id != new.operation_id
            || old.account_id != new.account_id
            || old.network_profile_id != new.network_profile_id
            || old.control != new.control
            || old.writer_epoch != new.writer_epoch
            || new.account_id != self.account_id()?
            || history.snapshot().account_id != new.account_id
            || history.snapshot().network_profile_id != new.network_profile_id
        {
            return Err(Error::Authentication);
        }
        if let Some(committed) = history.owner_control_request(&new.operation_id) {
            if committed != new {
                return Err(Error::Authentication);
            }
        } else if history.contains_operation(&new.operation_id)
            || new.expected_head != history.snapshot().head
            || new.writer_epoch != history.snapshot().writer_epoch
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn archive_request_revision(
        &self,
        prefix: &str,
        request: &wholepact_authority::OwnerControlRequest,
    ) -> Result<()> {
        let raw = encode(request)?;
        let name = format!("{prefix}-{}.wp", digest(&raw));
        if self.directory.exists(&name)? {
            let bytes = self.directory.read(&name, 64 * 1024)?;
            if vault::decrypt(
                &self.encryption_key,
                &self.activation_domain(b"request-revision")?,
                &bytes,
            )?
            .as_slice()
                != raw
            {
                return Err(Error::Authentication);
            }
            return Ok(());
        }
        let bytes = vault::encrypt(
            &self.encryption_key,
            &self.activation_domain(b"request-revision")?,
            &raw,
        )?;
        self.directory.write(&name, &bytes)
    }
    pub(crate) fn reconcile_recovery_owner_request(
        &self,
        request: &wholepact_authority::OwnerControlRequest,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<()> {
        if let Some(old) = self.read_recovery_owner_request()? {
            if old != *request {
                self.check_request_revision(&old, request, history)?;
                self.archive_request_revision("recovery-owner-revision", &old)?;
                let bytes = vault::encrypt(
                    &self.encryption_key,
                    &self.activation_domain(b"owner-request")?,
                    &encode(request)?,
                )?;
                return self.directory.write("recovery-owner-request.wp", &bytes);
            }
        }
        self.save_recovery_owner_request(request)
    }
    pub(crate) fn reconcile_recovery_pause(
        &self,
        request: &wholepact_authority::OwnerControlRequest,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<()> {
        if let Some(old) = self.saved_recovery_pause()? {
            if old != *request {
                self.check_request_revision(&old, request, history)?;
                self.archive_request_revision("recovery-pause-revision", &old)?;
                let bytes = vault::encrypt(
                    &self.encryption_key,
                    &self.activation_domain(b"pause-pending")?,
                    &encode(&Some(request))?,
                )?;
                return self.directory.write("recovery-pause-pending.wp", &bytes);
            }
        }
        self.retain_recovery_pause(request)
    }
    pub(crate) fn saved_recovery_pause(
        &self,
    ) -> Result<Option<wholepact_authority::OwnerControlRequest>> {
        self.read_recovery_plan()?;
        if !self.directory.exists("recovery-pause-pending.wp")? {
            return Ok(None);
        }
        let bytes = self
            .directory
            .read("recovery-pause-pending.wp", 64 * 1024)?;
        let plain = vault::decrypt(
            &self.encryption_key,
            &self.activation_domain(b"pause-pending")?,
            &bytes,
        )?;
        let request: Option<wholepact_authority::OwnerControlRequest> =
            serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
        if let Some(request) = &request {
            if request.account_id != self.account_id()?
                || request.control != wholepact_authority::OwnerControl::Pause
            {
                return Err(Error::Authentication);
            }
        }
        Ok(request)
    }
    pub(crate) fn retain_recovery_pause(
        &self,
        request: &wholepact_authority::OwnerControlRequest,
    ) -> Result<()> {
        self.read_recovery_plan()?;
        if request.account_id != self.account_id()?
            || request.control != wholepact_authority::OwnerControl::Pause
            || request.operation_id.len() != 64
            || !request.operation_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Authentication);
        }
        if let Some(saved) = self.saved_recovery_pause()? {
            if saved != *request {
                return Err(Error::Authentication);
            }
            return Ok(());
        }
        let archive = format!("recovery-pause-{}.wp", request.operation_id);
        if self.directory.exists(&archive)? {
            return Err(Error::RecoveryRequired);
        }
        let bytes = vault::encrypt(
            &self.encryption_key,
            &self.activation_domain(b"pause-audit")?,
            &encode(request)?,
        )?;
        self.directory.write(&archive, &bytes)?;
        let bytes = vault::encrypt(
            &self.encryption_key,
            &self.activation_domain(b"pause-pending")?,
            &encode(&Some(request))?,
        )?;
        self.directory.write("recovery-pause-pending.wp", &bytes)
    }
    pub(crate) fn acknowledge_recovery_pause(
        &self,
        request: &wholepact_authority::OwnerControlRequest,
    ) -> Result<()> {
        if self.saved_recovery_pause()?.as_ref() != Some(request) {
            return Err(Error::Authentication);
        }
        let bytes = vault::encrypt(
            &self.encryption_key,
            &self.activation_domain(b"pause-pending")?,
            b"null",
        )?;
        self.directory.write("recovery-pause-pending.wp", &bytes)
    }
    /// Persist exact operation and generation BEFORE any owner witness mutation.
    /// An interrupted staging directory without the last plan is never adopted.
    pub(crate) fn stage_recovery_plan(
        &self,
        inventory: &RecoveryActivationInventory,
        verified_source: &wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource,
        password: &[u8],
    ) -> Result<()> {
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        let source = verified_source.manifest();
        supported(source)?;
        if !self.account.restored
            || self.generation.is_some()
            || source.profile_id != self.account_id()?
            || self.directory.exists("viewing-wallet-key.wp")? != verified_source.wallet().is_some()
            || self.directory.exists("viewing-wallet.sqlite")? != verified_source.wallet().is_some()
        {
            return Err(Error::RecoveryRequired);
        }
        let target = inventory.target_profile();
        super::backup::paths(self.directory.root(), target)?;
        let recipient = self.read_recipient_records()?;
        let salt = vault::random::<16>()?;
        let encryption_key = vault::derive(password, &salt)?;
        let successor = Self {
            #[cfg(all(
                feature = "authority-signing",
                feature = "native-ui",
                target_os = "linux"
            ))]
            born_origin: None,
            directory: PrivateDirectory::create(target)?,
            account: DedicatedAccount::decode(&self.account.encode())?,
            encryption_key,
            salt,
            authority_key: Zeroizing::new(vault::random::<32>()?),
            authority_initialized: true,
            generation: None,
        };
        successor.persist()?;
        let history = vault::encrypt(
            &successor.encryption_key,
            &successor.activation_domain(b"recipient-history")?,
            &recipient,
        )?;
        successor
            .directory
            .write("recovery-recipient-history.wp", &history)?;
        successor.write_recipient_records(&recipient)?;
        let wallet_key_digest = if verified_source.wallet().is_some() {
            let key = Zeroizing::new(vault::random::<32>()?);
            let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
            domain.extend(successor.account_id()?.as_bytes());
            let wrapped = vault::encrypt(&successor.encryption_key, &domain, key.as_slice())?;
            successor
                .directory
                .write("viewing-wallet-key.wp", &wrapped)?;
            Some(digest(&wrapped))
        } else {
            None
        };
        let plan = RecoveryPlan {
            version: 1,
            inventory: inventory.clone(),
            source: source.clone(),
            source_directory: self.directory.root().to_path_buf(),
            recipient_history_digest: digest(&history),
            wallet_key_digest,
        };
        successor.directory.sync_all_files()?;
        let encrypted = vault::encrypt(
            &successor.encryption_key,
            &successor.activation_domain(b"plan")?,
            &encode(&plan)?,
        )?;
        successor.directory.write("recovery-plan.wp", &encrypted)?;
        successor.directory.sync_all_files()?;
        let _ = successor.verify_recovery_plan()?;
        Ok(())
    }
    /// Exact native approval plus a fresh independent fence can complete ONLY
    /// the previously authenticated target plan. No unrelated directory is used.
    pub(crate) fn publish_recovery_successor(
        &self,
        approved: ApprovedRecoveryActivation,
        fresh: AuthenticatedRecoveryFence,
        password: &[u8],
    ) -> Result<Self> {
        if self.born_origin.is_some() {
            return Err(Error::Unavailable);
        }
        if !self.account.restored || self.generation.is_some() {
            return Err(Error::RecoveryRequired);
        }
        if approved.account_id() != self.account_id()?
            || approved.source_provenance().profile_id != self.account_id()?
            || approved.source_provenance().bundle_digest != approved.source_manifest().digest
        {
            return Err(Error::Authentication);
        }
        let target = approved.target_profile().to_path_buf();
        let mut successor = Self::unlock_pending_recovery(&target, password)?;
        let plan = successor.read_recovery_plan()?;
        if &plan.inventory != approved.inventory()
            || plan.source != *approved.source_manifest()
            || plan.source_directory != self.directory.root()
            || successor.account_id()? != self.account_id()?
        {
            return Err(Error::Authentication);
        }
        if let Some(wallet) = approved.source_wallet() {
            wholepact_wallet::bundle::recovery::reconstruct_wallet_scan_successor(
                wallet,
                target.join("viewing-wallet.sqlite"),
                &successor.recovery_wallet_key()?,
            )
            .map_err(|_| Error::RecoveryRequired)?;
        }
        let key = wholepact_storage_security::DatabaseKey::from_bytes(*successor.authority_key);
        let receipt = approved.commit(
            fresh,
            &target.join("authority.sqlite"),
            &key,
            &successor.directory.signer_journal_source_owner()?,
        )?;
        receipt.check_current()?;
        let record = receipt.record().clone();
        if record.account_id != successor.account_id()?
            || record.target_profile != target
            || record.source_bundle_digest != plan.source.digest
            || record.source_component_digest != plan.source.components[0].digest
        {
            return Err(Error::Authentication);
        }
        if let Some(binding) = &successor.generation {
            if binding.record != record {
                return Err(Error::Authentication);
            }
            if successor.directory.exists("activation-commit.wp")? {
                let _ = successor.verify_profile_activation()?;
                return Ok(successor);
            }
        }
        let manifest = ActivationManifest {
            version: 1,
            record: record.clone(),
            source: plan.source,
            recipient_history_digest: plan.recipient_history_digest,
            wallet_key_digest: plan.wallet_key_digest,
        };
        let bytes = vault::encrypt(
            &successor.encryption_key,
            &successor.activation_domain(b"manifest")?,
            &encode(&manifest)?,
        )?;
        successor
            .directory
            .write("activation-manifest.wp", &bytes)?;
        successor.generation = Some(VaultGeneration {
            record,
            manifest_digest: digest(&bytes),
        });
        successor.persist()?;
        successor.directory.sync_all_files()?;
        let marker = vault::encrypt(
            &successor.encryption_key,
            &successor.activation_domain(b"commit")?,
            &encode(
                successor
                    .generation
                    .as_ref()
                    .ok_or(Error::RecoveryRequired)?,
            )?,
        )?;
        // Admission is the authorization linearization point: it verifies the
        // fresh fence/native approval while holding the publication lease.
        // This exact durable write then drains before Lock returns. Expiry
        // afterward cannot undo a committed marker; future operations require
        // their own fresh authority and no deadline is extended here.
        let _publication = receipt.admit_publication()?;
        successor.directory.write("activation-commit.wp", &marker)?;
        let _ = successor.verify_profile_activation()?;
        Ok(successor)
    }
}
#[cfg(all(test, feature = "synthetic-qualification"))]
pub(crate) fn recovery_profile_fixture_with(
    before_backup: impl FnOnce(&AccountVault, &crate::consent_journal::SignerConsentJournal),
) -> (
    tempfile::TempDir,
    AccountVault,
    wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource,
) {
    let (directory, vault, source, _) = tests::fixture_with(before_backup);
    (directory, vault, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (
        tempfile::TempDir,
        AccountVault,
        wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource,
        RecoveryActivationInventory,
    ) {
        fixture_with(|_, _| {})
    }
    pub(super) fn fixture_with(
        before_backup: impl FnOnce(&AccountVault, &crate::consent_journal::SignerConsentJournal),
    ) -> (
        tempfile::TempDir,
        AccountVault,
        wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource,
        RecoveryActivationInventory,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let original = root.join("original");
        let archive = root.join("archive");
        let restored = root.join("quarantine");
        let account = DedicatedAccount::from_entropy(
            Zeroizing::new([0x5a; 32]),
            0,
            "synthetic-recovery-plan".into(),
            false,
        )
        .unwrap();
        let words = account.recovery_words().unwrap();
        let verified = PendingAccount { account }.verify_backup(&words).unwrap();
        let mut source =
            AccountVault::create(&original, verified, b"synthetic-original-password").unwrap();
        let journal = source.create_authority_journal().unwrap();
        before_backup(&source, &journal);
        source
            .write_recipient_records(b"[{\"synthetic\":\"historical-recipient\"}]")
            .unwrap();
        drop(journal);
        drop(source);
        backup::snapshot(
            &original,
            &archive,
            b"synthetic-original-password",
            b"synthetic-archive-password",
        )
        .unwrap();
        backup::restore(
            &archive,
            &restored,
            b"synthetic-archive-password",
            b"synthetic-restored-password",
        )
        .unwrap();
        let vault = AccountVault::unlock(&restored, b"synthetic-restored-password").unwrap();
        let source =
            backup::verified_recovery_source(&vault, &archive, b"synthetic-archive-password")
                .unwrap();
        let descriptor = wholepact_authority::WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:19191".into(),
            server_name: "synthetic.invalid".into(),
            witness_id: "synthetic-witness".into(),
            account_id: vault.account_id().unwrap(),
            network_profile_id: "synthetic-testnet".into(),
            policy_digest: "12".repeat(32),
            pinned_server_certificate_digest: "34".repeat(32),
        };
        let inventory = RecoveryActivationInventory::prepare(
            &source,
            "synthetic-fixed-operation".into(),
            "56".repeat(32),
            root.join("successor"),
            descriptor,
            "78".repeat(32),
        )
        .unwrap();
        (temp, vault, source, inventory)
    }
    #[test]
    fn pending_plan_reopens_only_exact_inventory_without_authority_or_source_mutation() {
        let (_temp, original, source, inventory) = fixture();
        let original_bytes =
            std::fs::read(original.directory.root().join("authority.sqlite")).unwrap();
        original
            .stage_recovery_plan(&inventory, &source, b"synthetic-successor-password")
            .unwrap();
        assert!(
            original
                .stage_recovery_plan(&inventory, &source, b"synthetic-successor-password")
                .is_err()
        );
        let mut pending = AccountVault::unlock_pending_recovery(
            inventory.target_profile(),
            b"synthetic-successor-password",
        )
        .unwrap();
        assert!(pending.account().recovery_required());
        let proof = pending.verify_recovery_plan().unwrap();
        assert!(proof.inventory() == &inventory);
        assert!(RecoveryActivationInventory::resume(&source, &proof).is_ok());
        assert!(
            pending
                .resume_recovery_inventory(source.manifest(), &original)
                .unwrap()
                == inventory
        );
        let mut wrong = source.manifest().clone();
        wrong.digest = "ab".repeat(32);
        assert!(
            pending
                .resume_recovery_inventory(&wrong, &original)
                .is_err()
        );
        assert!(pending.open_authority_journal().is_err());
        assert!(pending.account().recovery_required());
        assert_eq!(
            original_bytes,
            std::fs::read(original.directory.root().join("authority.sqlite")).unwrap()
        );
        assert!(original.account().recovery_required());
    }
    #[test]
    fn immutable_history_and_missing_last_plan_fail_closed() {
        let (_temp, original, source, inventory) = fixture();
        original
            .stage_recovery_plan(&inventory, &source, b"synthetic-successor-password")
            .unwrap();
        let history_path = inventory
            .target_profile()
            .join("recovery-recipient-history.wp");
        let mut history = std::fs::read(&history_path).unwrap();
        history[0] ^= 1;
        std::fs::write(&history_path, &history).unwrap();
        assert!(
            AccountVault::unlock_pending_recovery(
                inventory.target_profile(),
                b"synthetic-successor-password"
            )
            .is_err()
        );
        std::fs::remove_file(inventory.target_profile().join("recovery-plan.wp")).unwrap();
        assert!(
            AccountVault::unlock_pending_recovery(
                inventory.target_profile(),
                b"synthetic-successor-password"
            )
            .is_err()
        );
    }
    #[test]
    fn persisted_generation_without_final_marker_never_unlocks_or_clears_restore() {
        let (_temp, original, source, inventory) = fixture();
        original
            .stage_recovery_plan(&inventory, &source, b"synthetic-successor-password")
            .unwrap();
        let mut pending = AccountVault::unlock_pending_recovery(
            inventory.target_profile(),
            b"synthetic-successor-password",
        )
        .unwrap();
        let record = RecoveryActivationRecord {
            account_use_retention_digest: None,
            operation_id: inventory.operation_id().into(),
            generation_id: inventory.generation_id().into(),
            inventory_digest: inventory.digest().unwrap(),
            fence_digest: "11".repeat(32),
            history_digest: "22".repeat(32),
            account_id: original.account_id().unwrap(),
            writer_epoch: 2,
            source_bundle_digest: source.manifest().digest.clone(),
            source_component_digest: source.provenance().component_digest.clone(),
            target_profile: inventory.target_profile().into(),
            review_digest: "33".repeat(32),
        };
        pending.generation = Some(VaultGeneration {
            record,
            manifest_digest: "44".repeat(32),
        });
        pending.persist().unwrap();
        drop(pending);
        assert!(
            AccountVault::unlock(inventory.target_profile(), b"synthetic-successor-password")
                .is_err()
        );
        let pending = AccountVault::unlock_pending_recovery(
            inventory.target_profile(),
            b"synthetic-successor-password",
        )
        .unwrap();
        assert!(pending.account.restored && pending.account().recovery_required());
        assert!(pending.verify_profile_activation().is_err());
    }
}
