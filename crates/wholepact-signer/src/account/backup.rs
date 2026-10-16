//! Signer-owned local recovery, never a coordinator/IPC export. Entry points are
//! native-UI-only and open a fresh exclusive vault after all runtime owners drain.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_storage_security::{DatabaseKey, bundle::*};
const RECOVERY_MAGIC: &[u8; 8] = b"WPASB001";
const MAX_RECOVERY: usize = 5 * 1024 * 1024;
fn storage<T>(value: std::result::Result<T, BundleError>) -> Result<T> {
    value.map_err(|_| Error::RecoveryRequired)
}
pub(crate) fn coverage(wallet: bool) -> Coverage {
    let mut present = BTreeMap::from([(
        JournalKind::SignerConsentAuthority,
        vec!["signer-authority".into()],
    )]);
    let mut absent = BTreeSet::from([
        JournalKind::CoordinationAuthority,
        JournalKind::WalletScan,
        JournalKind::ProofWitness,
        JournalKind::SignedResults,
        JournalKind::ExactTransactions,
        JournalKind::Submission,
        JournalKind::TransportInbox,
        JournalKind::TransportOutbox,
    ]);
    if wallet {
        absent.remove(&JournalKind::WalletScan);
        present.insert(JournalKind::WalletScan, vec!["signer-wallet".into()]);
    }
    Coverage { present, absent }
}
struct Consent {
    profile: String,
    archive: std::path::PathBuf,
    destinations: Vec<std::path::PathBuf>,
    sources: Vec<(String, JournalBinding)>,
    coverage: Coverage,
    action: BundleAction,
    checkpoint: String,
    expires: std::time::Instant,
}
struct Lease<'a>(&'a Consent);
impl BundleLease for Lease<'_> {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        if std::time::Instant::now() >= self.0.expires {
            Err(BundleError::PermissionChanged)
        } else {
            Ok(())
        }
    }
    fn checkpoint_id(&self) -> &str {
        &self.0.checkpoint
    }
}
impl BundleAuthority for Consent {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.profile_id != self.profile
            || scope.principal_id != "native-signer-backup"
            || scope.archive != self.archive
            || scope.destinations != self.destinations
            || scope.sources != self.sources
            || scope.coverage != &self.coverage
            || scope.action != self.action
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
pub(super) fn paths(root: &Path, output: &Path) -> Result<()> {
    if !root.is_absolute()
        || std::fs::canonicalize(root)? != root
        || !output.is_absolute()
        || output.starts_with(root)
        || output.file_name().is_none()
        || std::fs::canonicalize(output.parent().ok_or(Error::InvalidData)?)?
            != output.parent().ok_or(Error::InvalidData)?
        || output.exists()
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}
fn exact_inventory(directory: &PrivateDirectory, backup: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::InvalidData)?;
        if !backup && name == "local-apps" {
            // Runtime-only IPC is not backed up. Admit only a private drained
            // directory, never a live socket, retained grant, or unknown file.
            let ipc = PrivateDirectory::open(&entry.path())?;
            for child in std::fs::read_dir(ipc.root())? {
                let child = child?;
                let metadata = std::fs::symlink_metadata(child.path())?;
                if child.file_name() != "signer.lock"
                    || !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o077 != 0
                    || metadata.uid() != unsafe { libc::geteuid() }
                {
                    return Err(Error::InvalidData);
                }
            }
            continue;
        }
        let allowed = if backup {
            ["signer.lock", "recovery.wp", "COMPLETE"].contains(&name)
                || ["bundle.sqlite", "bundle.sqlite-wal", "bundle.sqlite-shm"].contains(&name)
        } else {
            [
                "signer.lock",
                "account.wp",
                "viewing-wallet-key.wp",
                "recipient-record-key.wp",
                "recipient-records.wp",
                "recovery-plan.wp",
                "recovery-pause-pending.wp",
                "recovery-owner-request.wp",
                "recovery-recipient-history.wp",
                "activation-manifest.wp",
                "activation-commit.wp",
            ]
            .contains(&name)
                || ["recovery-owner-revision-", "recovery-pause-revision-"]
                    .iter()
                    .any(|prefix| {
                        name.strip_prefix(prefix)
                            .and_then(|n| n.strip_suffix(".wp"))
                            .is_some_and(|n| {
                                n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                    })
                || name
                    .strip_prefix("recovery-pause-")
                    .and_then(|n| n.strip_suffix(".wp"))
                    .is_some_and(|n| n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()))
                || ["authority.sqlite", "viewing-wallet.sqlite"]
                    .iter()
                    .any(|base| {
                        name == *base
                            || name == format!("{base}-wal")
                            || name == format!("{base}-shm")
                            || name == format!("{base}-journal")
                    })
        };
        let metadata = std::fs::symlink_metadata(entry.path())?;
        // SAFETY: geteuid reads the current process UID only.
        if !allowed
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidData);
        }
    }
    Ok(())
}
fn push_blob(output: &mut Vec<u8>, blob: &[u8]) -> Result<()> {
    let length = u32::try_from(blob.len()).map_err(|_| Error::InvalidData)?;
    output.extend(length.to_le_bytes());
    output.extend(blob);
    Ok(())
}
fn blob<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    if input.len() < 4 {
        return Err(Error::InvalidData);
    }
    let length =
        u32::from_le_bytes(input[..4].try_into().map_err(|_| Error::InvalidData)?) as usize;
    *input = &input[4..];
    if input.len() < length {
        return Err(Error::InvalidData);
    }
    let value = &input[..length];
    *input = &input[length..];
    Ok(value)
}
/// Called only by an explicit locked-state native backup action. No source path,
/// password or recovery bytes can enter this function through signer IPC.
pub(crate) fn snapshot(
    root: &Path,
    output: &Path,
    password: &[u8],
    recovery_password: &[u8],
) -> Result<()> {
    paths(root, output)?;
    let mut account = AccountVault::unlock(root, password)?;
    exact_inventory(&account.directory, false)?;
    let journal = account.open_authority_journal()?;
    if account.account.recovery_required() {
        return Err(Error::RecoveryRequired);
    }
    let adapter = journal.backup_adapter();
    let wallet_present = account.directory.exists("viewing-wallet.sqlite")?;
    if wallet_present != account.directory.exists("viewing-wallet-key.wp")? {
        return Err(Error::RecoveryRequired);
    }
    let mut wallet_key = Zeroizing::new(Vec::new());
    let wallet = if wallet_present {
        let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
        domain.extend(account.account_id()?.as_bytes());
        wallet_key = vault::decrypt(
            &account.encryption_key,
            &domain,
            &account.directory.read("viewing-wallet-key.wp", 1024)?,
        )?;
        if wallet_key.len() != 32 {
            return Err(Error::RecoveryRequired);
        }
        Some(
            wholepact_wallet::wallet::DedicatedTestnetWallet::from_encrypted_connection(
                account.open_viewing_wallet_storage()?,
            )
            .map_err(|_| Error::RecoveryRequired)?,
        )
    } else {
        None
    };
    let wallet_adapter = wallet
        .as_ref()
        .map(|wallet| {
            wholepact_wallet::bundle::WalletScanBackupAdapter::new(
                wallet,
                account
                    .open_viewing_wallet_storage()
                    .map_err(|_| BundleError::Storage)?,
            )
        })
        .transpose()
        .map_err(|_| Error::RecoveryRequired)?;
    let mut sources = vec![storage(RegisteredJournal::new(
        "signer-authority",
        &adapter,
    ))?];
    if let Some(adapter) = &wallet_adapter {
        sources.push(storage(RegisteredJournal::new("signer-wallet", adapter))?);
    }
    let archive_key = Zeroizing::new(vault::random::<32>()?);
    let mut recovery_account = DedicatedAccount::decode(&account.account.encode())?;
    recovery_account.restored = true;
    let recipient_present = account.directory.exists("recipient-record-key.wp")?;
    if recipient_present != account.directory.exists("recipient-records.wp")? {
        return Err(Error::RecoveryRequired);
    }
    let recipient = account.read_recipient_records()?;
    let mut payload = Zeroizing::new(vec![1]);
    payload.extend(*archive_key);
    payload.extend(*account.authority_key);
    push_blob(&mut payload, &recovery_account.encode())?;
    push_blob(&mut payload, &wallet_key)?;
    push_blob(
        &mut payload,
        if recipient_present { &recipient } else { &[] },
    )?;
    let recovery = vault::password_envelope(RECOVERY_MAGIC, recovery_password, &payload)?;
    if recovery.len() > MAX_RECOVERY {
        return Err(Error::InvalidData);
    }
    let destination = PrivateDirectory::create(output)?;
    destination.write("recovery.wp", &recovery)?;
    let archive = output.join("bundle.sqlite");
    let key = DatabaseKey::from_bytes(*archive_key);
    let consent = Consent {
        profile: account.account_id()?,
        archive: archive.clone(),
        destinations: vec![],
        sources: sources
            .iter()
            .map(|source| (source.id().to_owned(), source.binding()))
            .collect(),
        coverage: coverage(wallet_present),
        action: BundleAction::Snapshot,
        checkpoint: hex::encode(Sha256::digest(&recovery)),
        expires: std::time::Instant::now() + std::time::Duration::from_secs(300),
    };
    let manifest = storage(wholepact_storage_security::bundle::snapshot(
        SnapshotRequest {
            principal_id: "native-signer-backup",
            profile_id: &consent.profile,
            coverage: consent.coverage.clone(),
            sources: &sources,
            destination: &archive,
            key: &key,
            authority: &consent,
        },
    ))?;
    let (plain, _, _) = vault::open_password_envelope(
        RECOVERY_MAGIC,
        recovery_password,
        &destination.read("recovery.wp", MAX_RECOVERY)?,
        MAX_RECOVERY,
    )?;
    if *plain != *payload || storage(inspect(&archive, &key))?.digest != manifest.digest {
        return Err(Error::Authentication);
    }
    destination.write("COMPLETE", b"Signer-owned recovery v1. Contains encrypted spending recovery, signer history, optional viewing wallet and recipient records. Independent witness and coordinator history are separate. All restores remain quarantined.\n")?;
    Ok(())
}
pub(crate) fn restore(
    backup: &Path,
    output: &Path,
    recovery_password: &[u8],
    password: &[u8],
) -> Result<()> {
    paths(backup, output)?;
    let source = PrivateDirectory::open(backup)?;
    exact_inventory(&source, true)?;
    if source.read("COMPLETE", 512)?.is_empty() {
        return Err(Error::InvalidData);
    }
    let encrypted = source.read("recovery.wp", MAX_RECOVERY)?;
    let (plain, _, _) =
        vault::open_password_envelope(RECOVERY_MAGIC, recovery_password, &encrypted, MAX_RECOVERY)?;
    if plain.len() < 65 || plain[0] != 1 {
        return Err(Error::InvalidData);
    }
    let archive_key =
        DatabaseKey::from_bytes(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
    let authority_key = Zeroizing::new(plain[33..65].try_into().map_err(|_| Error::InvalidData)?);
    let mut remaining = &plain[65..];
    let account = DedicatedAccount::decode(blob(&mut remaining)?)?;
    let wallet_key = blob(&mut remaining)?;
    let recipient = blob(&mut remaining)?;
    if !remaining.is_empty()
        || !account.restored
        || (!wallet_key.is_empty() && wallet_key.len() != 32)
        || recipient.len() > 4 * 1024 * 1024
    {
        return Err(Error::InvalidData);
    }
    let archive = backup.join("bundle.sqlite");
    let manifest = storage(inspect(&archive, &archive_key))?;
    let expected = coverage(!wallet_key.is_empty());
    if manifest.profile_id != account.account_id()?
        || manifest.coverage != expected
        || manifest.checkpoint_id != hex::encode(Sha256::digest(&encrypted))
    {
        return Err(Error::Authentication);
    }
    let salt = vault::random::<16>()?;
    let encryption_key = vault::derive(password, &salt)?;
    let directory = PrivateDirectory::create(output)?;
    let restored = AccountVault {
        born_origin: None,
        directory,
        account,
        encryption_key,
        salt,
        authority_key,
        authority_initialized: true,
        generation: None,
    };
    // Account recovery_required is authenticated inside account.wp, not merely a
    // removable sidecar marker. Journal quarantine independently blocks writers.
    restored.persist()?;
    let authority_path = output.join("authority.sqlite");
    let authority_db_key = DatabaseKey::from_bytes(*restored.authority_key);
    let wallet_path = output.join("viewing-wallet.sqlite");
    let wallet_db_key = if wallet_key.is_empty() {
        None
    } else {
        Some(DatabaseKey::from_bytes(
            wallet_key.try_into().map_err(|_| Error::InvalidData)?,
        ))
    };
    let mut targets = vec![RestoreTarget {
        component_id: "signer-authority",
        template: crate::consent_journal::recovery_template(
            manifest
                .components
                .iter()
                .find(|c| c.id == "signer-authority")
                .ok_or(Error::InvalidData)?
                .schema_version,
        )?,
        destination: &authority_path,
        key: &authority_db_key,
    }];
    if let Some(key) = &wallet_db_key {
        targets.push(RestoreTarget {
            component_id: "signer-wallet",
            template: storage(
                wholepact_wallet::bundle::trusted_template_for_bundle_component(
                    &archive,
                    &archive_key,
                    "signer-wallet",
                ),
            )?,
            destination: &wallet_path,
            key,
        });
    }
    let consent = Consent {
        profile: manifest.profile_id.clone(),
        archive: archive.clone(),
        destinations: targets.iter().map(|t| t.destination.to_owned()).collect(),
        sources: vec![],
        coverage: expected,
        action: BundleAction::Restore,
        checkpoint: manifest.checkpoint_id.clone(),
        expires: std::time::Instant::now() + std::time::Duration::from_secs(300),
    };
    storage(wholepact_storage_security::bundle::restore(
        RestoreRequest {
            principal_id: "native-signer-backup",
            profile_id: &consent.profile,
            archive: &archive,
            key: &archive_key,
            targets: &targets,
            authority: &consent,
        },
    ))?;
    if !wallet_key.is_empty() {
        let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
        domain.extend(restored.account_id()?.as_bytes());
        restored.directory.write(
            "viewing-wallet-key.wp",
            &vault::encrypt(&restored.encryption_key, &domain, wallet_key)?,
        )?;
    }
    if !recipient.is_empty() {
        restored.write_recipient_records(recipient)?;
    }
    Ok(())
}

/// Authenticate a restored original against its encrypted backup without opening
/// a mutable journal or clearing either independent quarantine marker.
pub(crate) fn verified_recovery_source(
    restored: &AccountVault,
    backup: &Path,
    recovery_password: &[u8],
) -> Result<wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource> {
    if !restored.account.restored || restored.generation.is_some() {
        return Err(Error::RecoveryRequired);
    }
    if !backup.is_absolute()
        || std::fs::canonicalize(backup)? != backup
        || backup == restored.directory.root()
    {
        return Err(Error::InvalidData);
    }
    exact_inventory(&restored.directory, false)?;
    let source = PrivateDirectory::open(backup)?;
    exact_inventory(&source, true)?;
    if source.read("COMPLETE", 512)?.is_empty() {
        return Err(Error::InvalidData);
    }
    let encrypted = source.read("recovery.wp", MAX_RECOVERY)?;
    let (plain, _, _) =
        vault::open_password_envelope(RECOVERY_MAGIC, recovery_password, &encrypted, MAX_RECOVERY)?;
    if plain.len() < 65 || plain[0] != 1 {
        return Err(Error::InvalidData);
    }
    let archive_key =
        DatabaseKey::from_bytes(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
    if !bool::from(plain[33..65].ct_eq(restored.authority_key.as_slice())) {
        return Err(Error::Authentication);
    }
    let mut remaining = &plain[65..];
    let account = DedicatedAccount::decode(blob(&mut remaining)?)?;
    let wallet_key = blob(&mut remaining)?;
    let recipient = blob(&mut remaining)?;
    if !remaining.is_empty()
        || account.account_id()? != restored.account_id()?
        || !account.restored
        || (!wallet_key.is_empty() && wallet_key.len() != 32)
    {
        return Err(Error::RecoveryRequired);
    }
    let restored_recipient = restored.read_recipient_records()?;
    let expected_recipient: &[u8] = if recipient.is_empty() {
        b"[]"
    } else {
        recipient
    };
    if !bool::from(expected_recipient.ct_eq(restored_recipient.as_slice())) {
        return Err(Error::Authentication);
    }
    let archive = backup.join("bundle.sqlite");
    let manifest = storage(inspect(&archive, &archive_key))?;
    if manifest.profile_id != restored.account_id()?
        || manifest.coverage != coverage(!wallet_key.is_empty())
        || manifest.checkpoint_id != hex::encode(Sha256::digest(&encrypted))
        || manifest.components.len() != if wallet_key.is_empty() { 1 } else { 2 }
        || manifest.components[0].id != "signer-authority"
    {
        return Err(Error::Authentication);
    }
    let template =
        crate::consent_journal::recovery_template(manifest.components[0].schema_version)?;
    let restored_key = DatabaseKey::from_bytes(*restored.authority_key);
    let verified = storage(
        wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource::open(
            wholepact_storage_security::bundle::history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-authority",
                restored_component: &restored.directory.root().join("authority.sqlite"),
                restored_key: &restored_key,
            },
            template,
        ),
    )?;
    let wallet_present = !wallet_key.is_empty();
    if restored.directory.exists("viewing-wallet-key.wp")? != wallet_present
        || restored.directory.exists("viewing-wallet.sqlite")? != wallet_present
    {
        return Err(Error::Authentication);
    }
    if !wallet_present {
        return Ok(verified);
    }
    let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
    domain.extend(restored.account_id()?.as_bytes());
    let restored_wallet_key = vault::decrypt(
        &restored.encryption_key,
        &domain,
        &restored.directory.read("viewing-wallet-key.wp", 1024)?,
    )?;
    if !bool::from(wallet_key.ct_eq(restored_wallet_key.as_slice())) {
        return Err(Error::Authentication);
    }
    let wallet_db_key =
        DatabaseKey::from_bytes(wallet_key.try_into().map_err(|_| Error::Authentication)?);
    let wallet = storage(
        wholepact_wallet::bundle::recovery::open_verified_wallet_scan_component(
            history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-wallet",
                restored_component: &restored.directory.root().join("viewing-wallet.sqlite"),
                restored_key: &wallet_db_key,
            },
        ),
    )?;
    storage(verified.with_wallet(wallet))
}

// Dedicated retained-lock reader; ordinary recovery entry remains unchanged.
pub(super) fn verified_recovery_source_locked(
    restored: &AccountVault,
    backup: &Path,
    recovery_password: &[u8],
    source: &PrivateDirectory,
) -> Result<wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource> {
    if !restored.account.restored || restored.generation.is_some() {
        return Err(Error::RecoveryRequired);
    }
    if !backup.is_absolute()
        || std::fs::canonicalize(backup)? != backup
        || backup == restored.directory.root()
    {
        return Err(Error::InvalidData);
    }
    exact_inventory(&restored.directory, false)?;
    if source.root() != backup { return Err(Error::InvalidData); }
    exact_inventory(source, true)?;
    if source.read("COMPLETE", 512)?.is_empty() {
        return Err(Error::InvalidData);
    }
    let encrypted = source.read("recovery.wp", MAX_RECOVERY)?;
    let (plain, _, _) =
        vault::open_password_envelope(RECOVERY_MAGIC, recovery_password, &encrypted, MAX_RECOVERY)?;
    if plain.len() < 65 || plain[0] != 1 {
        return Err(Error::InvalidData);
    }
    let archive_key =
        DatabaseKey::from_bytes(plain[1..33].try_into().map_err(|_| Error::InvalidData)?);
    if !bool::from(plain[33..65].ct_eq(restored.authority_key.as_slice())) {
        return Err(Error::Authentication);
    }
    let mut remaining = &plain[65..];
    let account = DedicatedAccount::decode(blob(&mut remaining)?)?;
    let wallet_key = blob(&mut remaining)?;
    let recipient = blob(&mut remaining)?;
    if !remaining.is_empty()
        || account.account_id()? != restored.account_id()?
        || !bool::from(account.encode().as_slice().ct_eq(restored.account.encode().as_slice()))
        || !account.restored
        || (!wallet_key.is_empty() && wallet_key.len() != 32)
    {
        return Err(Error::RecoveryRequired);
    }
    if restored.directory.exists("recipient-record-key.wp")? == recipient.is_empty()
        || restored.directory.exists("recipient-records.wp")? == recipient.is_empty()
    { return Err(Error::Authentication); }
    let restored_recipient = restored.read_recipient_records()?;
    let expected_recipient: &[u8] = if recipient.is_empty() {
        b"[]"
    } else {
        recipient
    };
    if !bool::from(expected_recipient.ct_eq(restored_recipient.as_slice())) {
        return Err(Error::Authentication);
    }
    let archive = backup.join("bundle.sqlite");
    let manifest = storage(inspect(&archive, &archive_key))?;
    if manifest.profile_id != restored.account_id()?
        || manifest.coverage != coverage(!wallet_key.is_empty())
        || manifest.checkpoint_id != hex::encode(Sha256::digest(&encrypted))
        || manifest.components.len() != if wallet_key.is_empty() { 1 } else { 2 }
        || manifest.components[0].id != "signer-authority"
    {
        return Err(Error::Authentication);
    }
    let template =
        crate::consent_journal::recovery_template(manifest.components[0].schema_version)?;
    let restored_key = DatabaseKey::from_bytes(*restored.authority_key);
    let verified = storage(
        wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource::open(
            wholepact_storage_security::bundle::history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-authority",
                restored_component: &restored.directory.root().join("authority.sqlite"),
                restored_key: &restored_key,
            },
            template,
        ),
    )?;
    let wallet_present = !wallet_key.is_empty();
    if restored.directory.exists("viewing-wallet-key.wp")? != wallet_present
        || restored.directory.exists("viewing-wallet.sqlite")? != wallet_present
    {
        return Err(Error::Authentication);
    }
    if !wallet_present {
        return Ok(verified);
    }
    let mut domain = b"wholepact:dedicated-viewing-wallet-key:v1\0".to_vec();
    domain.extend(restored.account_id()?.as_bytes());
    let restored_wallet_key = vault::decrypt(
        &restored.encryption_key,
        &domain,
        &restored.directory.read("viewing-wallet-key.wp", 1024)?,
    )?;
    if !bool::from(wallet_key.ct_eq(restored_wallet_key.as_slice())) {
        return Err(Error::Authentication);
    }
    let wallet_db_key =
        DatabaseKey::from_bytes(wallet_key.try_into().map_err(|_| Error::Authentication)?);
    let wallet = storage(
        wholepact_wallet::bundle::recovery::open_verified_wallet_scan_component(
            history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-wallet",
                restored_component: &restored.directory.root().join("viewing-wallet.sqlite"),
                restored_key: &wallet_db_key,
            },
        ),
    )?;
    storage(verified.with_wallet(wallet))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_signer_backup_restores_wallet_and_recipient_history_only_in_quarantine() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("synthetic-source");
        let backup = temporary.path().join("synthetic-backup");
        let restored_root = temporary.path().join("synthetic-restored");
        let password = b"synthetic-original-password-only";
        let recovery = b"synthetic-backup-password-only";
        let new_password = b"synthetic-restored-password-only";
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: "synthetic-backup-fixture".into(),
            account_index: 0,
        })
        .unwrap();
        let words = pending.recovery_words().unwrap();
        let verified = pending.verify_backup(&words).unwrap();
        let mut source = AccountVault::create(&root, verified, password).unwrap();
        let journal = source.create_authority_journal().unwrap();
        let wallet = wholepact_wallet::wallet::DedicatedTestnetWallet::from_encrypted_connection(
            source.create_viewing_wallet_storage().unwrap(),
        )
        .unwrap();
        let recipient = b"[{\"synthetic_private_record\":\"history-must-survive\"}]";
        source.write_recipient_records(recipient).unwrap();
        drop(wallet);
        drop(journal);
        drop(source);
        snapshot(&root, &backup, password, recovery).unwrap();
        assert!(
            !std::fs::read(backup.join("recovery.wp"))
                .unwrap()
                .windows(recipient.len())
                .any(|window| window == recipient)
        );
        assert!(
            restore(
                &backup,
                &temporary.path().join("wrong"),
                b"synthetic-wrong-password",
                new_password
            )
            .is_err()
        );
        restore(&backup, &restored_root, recovery, new_password).unwrap();
        let mut restored = AccountVault::unlock(&restored_root, new_password).unwrap();
        assert!(restored.account().recovery_required());
        let verified = verified_recovery_source(&restored, &backup, recovery).unwrap();
        assert!(verified.wallet().is_some());
        assert_eq!(verified.manifest().coverage, coverage(true));
        assert_eq!(&*restored.read_recipient_records().unwrap(), recipient);
        assert!(restored.open_authority_journal().is_err());
        assert!(restored.open_viewing_wallet_storage().is_err());
        assert!(restored_root.join("viewing-wallet.sqlite").exists());
        drop(restored);
        assert!(
            snapshot(
                &restored_root,
                &temporary.path().join("invalid-resnapshot"),
                new_password,
                recovery
            )
            .is_err()
        );
    }
    #[test]
    fn bounded_recovery_blob_parser_rejects_truncation() {
        let mut bytes = vec![];
        push_blob(&mut bytes, b"synthetic").unwrap();
        let mut input = bytes.as_slice();
        assert_eq!(blob(&mut input).unwrap(), b"synthetic");
        assert!(input.is_empty());
        let mut truncated = &bytes[..bytes.len() - 1];
        assert!(blob(&mut truncated).is_err());
        let mut oversize = &[255, 255, 255, 255][..];
        assert!(blob(&mut oversize).is_err());
    }
}
