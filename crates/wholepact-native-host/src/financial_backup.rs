//! Financial journal assembly only. Signer spending material, signer authority,
//! recipient-local records and the independent witness are not owned by this host.
use crate::{
    Result, files::Directory, financial_inventory, financial_profile::FinancialProfile,
    terminal::Terminal, vault::Secrets,
};
use wholepact_proof_jobs::backup::ProofWitnessBackupAdapter;
use wholepact_protocol::authorization::retention::{
    backup::SignedResultsBackupAdapter, transaction::backup::ExactTransactionsBackupAdapter,
};
use wholepact_storage_security::{bundle::*, open_encrypted_quiescent as open_encrypted};
use wholepact_wallet::bundle::WalletScanBackupAdapter;
pub(crate) struct Adapters<'a> {
    wallet: WalletScanBackupAdapter<'a>,
    proof: ProofWitnessBackupAdapter<'a>,
    signed: SignedResultsBackupAdapter<'a>,
    transactions: ExactTransactionsBackupAdapter<'a>,
}
impl<'a> Adapters<'a> {
    pub(crate) fn new(profile: &'a FinancialProfile) -> Result<Self> {
        profile.inventory()?;
        // Retained authenticated handles must still name the exact files.
        profile.check_current_journals()?;
        Ok(Self {
            wallet: WalletScanBackupAdapter::new(
                &profile.wallet,
                open_encrypted(
                    profile.directory.path("wallet.sqlite")?,
                    &profile.secrets.key(0)?,
                )?,
            )?,
            proof: ProofWitnessBackupAdapter::new(&profile.proof),
            signed: SignedResultsBackupAdapter::new(&profile.signed),
            transactions: ExactTransactionsBackupAdapter::new(&profile.transactions),
        })
    }
    pub(crate) fn registered(&'a self, index: usize) -> Result<Vec<RegisteredJournal<'a>>> {
        Ok(vec![
            RegisteredJournal::new(&format!("financial-{index}-wallet"), &self.wallet)?,
            RegisteredJournal::new(&format!("financial-{index}-proof"), &self.proof)?,
            RegisteredJournal::new(&format!("financial-{index}-signed"), &self.signed)?,
            RegisteredJournal::new(
                &format!("financial-{index}-transactions"),
                &self.transactions,
            )?,
        ])
    }
}
/// Every runtime and main financial owner must have been dropped first. Locks
/// are acquired in canonical path order and retained until the archive commits.
pub(crate) fn open_all(
    directory: &Directory,
    secrets: &Secrets,
    terminal: &Terminal,
) -> Result<Vec<FinancialProfile>> {
    if !directory.path("financial.attached")?.try_exists()?
        && !directory.path(financial_inventory::FILE)?.try_exists()?
    {
        return Ok(Vec::new());
    }
    let mut entries = financial_inventory::read_current(directory, secrets)?;
    entries.sort_by(|a, b| a.directory.cmp(&b.directory));
    let mut profiles = Vec::new();
    for entry in entries {
        terminal.confirm(&format!("Include registered private financial journal dependency {} ({:?}) in this encrypted backup? Its wallet viewing history, proof witnesses and exact artifacts are private. Signer authority and recipient records remain separate and are NOT backed up by this command.", entry.directory.display(), entry.role))?;
        let password = terminal.secret("Registered financial dependency passphrase: ")?;
        let profile =
            FinancialProfile::open(&entry.directory, &secrets.profile(), password.as_bytes())?;
        financial_inventory::check_backup_owner(directory, secrets, &entry, &profile)?;
        profiles.push(profile);
    }
    Ok(profiles)
}
pub(crate) fn coverage(count: usize) -> Coverage {
    let mut coverage = super::backup::coverage();
    for (kind, name) in [
        (JournalKind::WalletScan, "wallet"),
        (JournalKind::ProofWitness, "proof"),
        (JournalKind::SignedResults, "signed"),
        (JournalKind::ExactTransactions, "transactions"),
    ] {
        if count != 0 {
            coverage.absent.remove(&kind);
            let mut ids: Vec<_> = (0..count)
                .map(|i| format!("financial-{i}-{name}"))
                .collect();
            // Bundle coverage is canonical lexical order, including indexes 10/11.
            ids.sort();
            coverage.present.insert(kind, ids);
        }
    }
    coverage
}

pub(crate) struct RestoreFinancial {
    pub(crate) directories: Vec<Directory>,
    pub(crate) secrets: Vec<crate::vault::FinancialSecrets>,
    pub(crate) paths: Vec<std::path::PathBuf>,
    pub(crate) keys: Vec<wholepact_storage_security::DatabaseKey>,
    pub(crate) ids: Vec<String>,
}
impl RestoreFinancial {
    pub(crate) fn prepare(
        source: &Directory,
        output: &Directory,
        destination: &std::path::Path,
        owner: &Secrets,
        password: &[u8],
        count: usize,
    ) -> Result<Self> {
        let entries = if count == 0 {
            Vec::new()
        } else {
            financial_inventory::read(source, owner)?
        };
        if entries.len() != count {
            return Err(crate::Error::Invalid);
        }
        let mut result = Self {
            directories: Vec::new(),
            secrets: Vec::new(),
            paths: Vec::new(),
            keys: Vec::new(),
            ids: Vec::new(),
        };
        // Register the primary first even when canonical path sorting places a
        // participant before it. Archive component indexes retain sorted order.
        let mut registration: Vec<_> = entries.iter().enumerate().collect();
        registration.sort_by_key(|(_, entry)| {
            if entry.role == financial_inventory::AttachmentRole::PrimaryFinancial {
                0
            } else {
                1
            }
        });
        for (index, entry) in registration {
            let name = destination
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(crate::Error::Invalid)?;
            let path = destination.with_file_name(format!("{name}-financial-{index}"));
            financial_inventory::register(
                output,
                owner,
                &path,
                entry.role.clone(),
                entry.account.as_deref(),
            )?;
        }
        for (index, _entry) in entries.iter().enumerate() {
            let secrets = crate::vault::FinancialSecrets::open(
                &source.read(&format!("financial-{index}.vault"), 1024)?,
                &owner.profile(),
                password,
            )?;
            let name = destination
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(crate::Error::Invalid)?;
            let path = destination.with_file_name(format!("{name}-financial-{index}"));
            let dir = Directory::create(&path)?;
            dir.write_new("restored.quarantine", b"Historical financial journals only. Writer authority and exposure continuity are not established.\n")?;
            for (number, suffix) in ["wallet", "proof", "signed", "transactions"]
                .iter()
                .enumerate()
            {
                result
                    .paths
                    .push(dir.path(crate::financial_profile::JOURNALS[number])?);
                result.keys.push(secrets.key(number)?);
                result.ids.push(format!("financial-{index}-{suffix}"));
            }
            result.directories.push(dir);
            result.secrets.push(secrets);
        }
        Ok(result)
    }
    pub(crate) fn targets(
        &self,
        archive: &std::path::Path,
        archive_key: &wholepact_storage_security::DatabaseKey,
    ) -> Result<Vec<RestoreTarget<'_>>> {
        let templates = [
            &wholepact_proof_jobs::backup::TEMPLATE,
            &wholepact_protocol::authorization::retention::backup::TEMPLATE,
            &wholepact_protocol::authorization::retention::transaction::backup::TEMPLATE,
        ];
        self.paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let template = if i % 4 == 0 {
                    wholepact_wallet::bundle::trusted_template_for_bundle_component(
                        archive,
                        archive_key,
                        &self.ids[i],
                    )?
                } else {
                    templates[i % 4 - 1]
                };
                Ok(RestoreTarget {
                    component_id: &self.ids[i],
                    template,
                    destination: path,
                    key: &self.keys[i],
                })
            })
            .collect()
    }
    pub(crate) fn finish(&self, password: &[u8]) -> Result<()> {
        for (dir, secrets) in self.directories.iter().zip(&self.secrets) {
            dir.write_new("financial.vault", &secrets.seal(password)?)?;
        }
        Ok(())
    }
}

/// Bind auxiliary encrypted recovery material to the authenticated bundle
/// checkpoint. Substituting another valid owner's older inventory is rejected.
pub(crate) fn metadata_digest(directory: &Directory, count: usize) -> Result<String> {
    use sha2::{Digest, Sha256};
    if count == 0 || count > 12 {
        return Err(crate::Error::Invalid);
    }
    let mut digest = Sha256::new();
    digest.update(b"wholepact-financial-backup-metadata-v1");
    for name in std::iter::once(financial_inventory::FILE.to_owned())
        .chain((0..count).map(|i| format!("financial-{i}.vault")))
    {
        let bytes = directory.read(&name, 65536)?;
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn maximum_financial_coverage_is_canonically_sorted() {
        let coverage = super::coverage(12);
        assert_eq!(coverage.present.values().map(Vec::len).sum::<usize>(), 52);
        for ids in coverage.present.values() {
            assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        }
        let wallet =
            &coverage.present[&wholepact_storage_security::bundle::JournalKind::WalletScan];
        assert_eq!(wallet[2], "financial-10-wallet");
        assert_eq!(wallet[3], "financial-11-wallet");
    }
}
