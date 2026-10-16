//! Separately unlocked financial storage. Four independently keyed maintained
//! journals; no signer seed, account import, grant, network or financial effect.
//! The owner retains this value until all operations drain. No journal escapes
//! through the HTTP facade and ordinary open never creates a missing file.
use crate::{Error, Result, files::Directory, vault::FinancialSecrets};
use std::path::Path;
use wholepact_proof_jobs::ProofJobStore;
use wholepact_protocol::authorization::retention::{
    SignedResultJournal, transaction::TransactionCheckpointJournal,
};
use wholepact_storage_security::{create_encrypted, open_encrypted_quiescent as open_encrypted};
use wholepact_wallet::wallet::DedicatedTestnetWallet;

pub(crate) const JOURNALS: [&str; 4] = [
    "wallet.sqlite",
    "proof.sqlite",
    "signed.sqlite",
    "transactions.sqlite",
];

pub(crate) struct FinancialProfile {
    // Declaration order keeps the exclusive directory lock until every journal
    // has closed. The storage factories retain their zeroizing connection keys.
    pub(crate) wallet: DedicatedTestnetWallet,
    pub(crate) proof: ProofJobStore,
    pub(crate) signed: SignedResultJournal,
    pub(crate) transactions: TransactionCheckpointJournal,
    pub(crate) secrets: FinancialSecrets,
    // Captured from the exact authenticated handles BEFORE each is consumed by
    // its maintained journal. Never reconstructed from registry labels.
    original_owner: String,
    original_databases: [wholepact_storage_security::DatabaseFileIdentity; 4],
    pub(crate) directory: Directory,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordableImportKind {
    None,
    V1,
    RosterV2,
    RosterExactInputV1,
}

impl FinancialProfile {
    pub(crate) fn create(path: &Path, owner: &str, password: &[u8]) -> Result<Self> {
        Self::create_layout(path, owner, password, RecordableImportKind::None)
    }
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub(crate) fn create_recordable_import(
        path: &Path,
        owner: &str,
        password: &[u8],
    ) -> Result<Self> {
        Self::create_layout(path, owner, password, RecordableImportKind::V1)
    }
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub(crate) fn create_recordable_roster_import_v2(
        path: &Path,
        owner: &str,
        password: &[u8],
    ) -> Result<Self> {
        Self::create_layout(path, owner, password, RecordableImportKind::RosterV2)
    }
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub(crate) fn create_recordable_roster_exact_input_v1(
        path: &Path,
        owner: &str,
        password: &[u8],
    ) -> Result<Self> {
        Self::create_layout(
            path,
            owner,
            password,
            RecordableImportKind::RosterExactInputV1,
        )
    }
    fn create_layout(
        path: &Path,
        owner: &str,
        password: &[u8],
        recorded_import: RecordableImportKind,
    ) -> Result<Self> {
        // Validate password and owner and prepare the encrypted last-commit
        // marker before any filesystem effect. Partial files are never adopted.
        let secrets = FinancialSecrets::fresh(owner)?;
        let envelope = secrets.seal(password)?;
        let directory = Directory::create(path)?;
        let result = Self::load(directory, secrets, owner, true, recorded_import)?;
        result.directory.write_new("financial.vault", &envelope)?;
        result.inventory()?;
        Ok(result)
    }
    pub(crate) fn open(path: &Path, owner: &str, password: &[u8]) -> Result<Self> {
        let directory = Directory::open(path)?;
        if directory.path("restored.quarantine")?.try_exists()? {
            return Err(Error::Quarantined);
        }
        directory.inventory_of(&JOURNALS, &["profile.lock", "financial.vault"])?;
        let secrets =
            FinancialSecrets::open(&directory.read("financial.vault", 1024)?, owner, password)?;
        // Check the complete fixed inventory before constructors can migrate.
        for name in JOURNALS {
            if !directory.path(name)?.try_exists()? {
                return Err(Error::Invalid);
            }
        }
        Self::load(directory, secrets, owner, false, RecordableImportKind::None)
    }
    fn load(
        directory: Directory,
        secrets: FinancialSecrets,
        owner: &str,
        create: bool,
        recorded_import: RecordableImportKind,
    ) -> Result<Self> {
        // Directory is exclusively locked before any journal owner is created.
        // Each quiescent preflight is over a different, not-yet-opened journal.
        let connection = |index: usize| -> Result<_> {
            let path = directory.path(JOURNALS[index])?;
            let key = secrets.key(index)?;
            Ok(if create {
                create_encrypted(path, &key)?
            } else {
                open_encrypted(path, &key)?
            })
        };
        let wallet_connection = connection(0)?;
        let wallet_identity = wallet_connection.database_identity()?;
        let wallet = if recorded_import != RecordableImportKind::None {
            if !create {
                return Err(Error::Permission);
            }
            #[cfg(all(feature = "manual-admission", target_os = "linux"))]
            {
                match recorded_import {
                    RecordableImportKind::V1 => DedicatedTestnetWallet::from_encrypted_connection_recordable_import(wallet_connection),
                    RecordableImportKind::RosterV2 => DedicatedTestnetWallet::from_encrypted_connection_recordable_roster_import_v2(wallet_connection),
                    RecordableImportKind::RosterExactInputV1 => DedicatedTestnetWallet::from_encrypted_connection_recordable_roster_exact_input_v1(wallet_connection),
                    RecordableImportKind::None => return Err(Error::Permission),
                }
            }
            #[cfg(not(all(feature = "manual-admission", target_os = "linux")))]
            {
                return Err(Error::Unsupported);
            }
        } else {
            DedicatedTestnetWallet::from_encrypted_connection(wallet_connection)
        }
        .map_err(|_| Error::Storage)?;
        let proof_connection = connection(1)?;
        let proof_identity = proof_connection.database_identity()?;
        let proof = ProofJobStore::from_encrypted_connection(proof_connection)
            .map_err(|_| Error::Storage)?;
        let signed_connection = connection(2)?;
        let signed_identity = signed_connection.database_identity()?;
        let signed = SignedResultJournal::from_encrypted_connection(signed_connection)
            .map_err(|_| Error::Storage)?;
        let transaction_connection = connection(3)?;
        let transaction_identity = transaction_connection.database_identity()?;
        let transactions =
            TransactionCheckpointJournal::from_encrypted_connection(transaction_connection)
                .map_err(|_| Error::Storage)?;
        Ok(Self {
            wallet,
            proof,
            signed,
            transactions,
            secrets,
            original_owner: owner.into(),
            original_databases: [
                wallet_identity,
                proof_identity,
                signed_identity,
                transaction_identity,
            ],
            directory,
        })
    }
    /// Exact correlation of the actually open primary financial storage. This
    /// does not establish chain freshness, account ownership or financial use.
    /// The owner lock is a precondition, not a hostile-same-user OS sandbox.
    pub(crate) fn manual_journal_origin_digest(
        &self,
        host: &Directory,
        secrets: &crate::vault::Secrets,
    ) -> Result<String> {
        host.check()?;
        self.inventory()?;
        if self.original_owner != secrets.profile()
            || host.read("financial.attached", 1024)?
                != b"wholepact-financial-profile-attached-v1\n"
        {
            return Err(Error::Authentication);
        }
        let entries = crate::financial_inventory::read(host, secrets)?;
        let actual_path = self.directory.path("financial.vault")?;
        let actual_root = actual_path.parent().ok_or(Error::Invalid)?;
        // First bounded slice excludes additional current participant profiles;
        // their complete current identity coverage is not established here.
        if entries.len() != 1
            || entries[0].role != crate::financial_inventory::AttachmentRole::PrimaryFinancial
            || entries[0].account.is_some()
            || entries[0].directory != actual_root
        {
            return Err(Error::RecoveryFinancialUnsupported);
        }
        for identity in &self.original_databases {
            identity.check_retained_owner_path()?;
        }
        let identities: Vec<_> = JOURNALS
            .iter()
            .zip(&self.original_databases)
            .map(|(name, identity)| (*name, hex::encode(identity.origin_commitment())))
            .collect();
        wholepact_core::proposal::canonical_digest(
            "wholepact:native-manual-financial-journal-origin:v1",
            &(
                &self.original_owner,
                self.directory.manual_target_identity_digest()?,
                &entries,
                identities,
            ),
        )
        .map_err(|_| Error::Authentication)
    }
    /// This checks the actual retained directory and all four authenticated file
    /// origins. It is read-only correlation, never a financial capability.
    pub(crate) fn check_current_journals(&self) -> Result<()> {
        self.check_retained_owner(&self.original_owner)
    }
    pub(crate) fn check_retained_owner(&self, owner: &str) -> Result<()> {
        check_retained(
            &self.directory,
            &self.original_owner,
            &self.original_databases,
            owner,
        )
    }
    pub(crate) fn current_directory(&self) -> Result<std::path::PathBuf> {
        current_directory(&self.directory)
    }
    pub(crate) fn manual_attachment_descriptor(
        &self,
        owner: &str,
        account: &str,
    ) -> Result<wholepact_core::manual_construction::ManualParticipantAttachment> {
        actual_descriptor(
            &self.directory,
            &self.original_owner,
            &self.original_databases,
            owner,
            account,
        )
    }
    /// A distinct v2-aware check reproduces the original v1 digest against only
    /// the immutable original primary registry. The existing v1 method above is
    /// deliberately unchanged and continues to deny additional dependencies.
    pub(crate) fn manual_original_primary_origin_digest(
        &self,
        host: &Directory,
        secrets: &crate::vault::Secrets,
    ) -> Result<String> {
        original_primary_origin(
            host,
            secrets,
            &self.directory,
            &self.original_owner,
            &self.original_databases,
        )
    }
    /// Metadata-only source snapshot of this exact held primary proof journal.
    /// The caller retains this profile's Directory lock and obtains a fresh
    /// native review before capture. No live proof Store method is called.
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub(crate) fn original_proof_status_snapshot(
        &self,
    ) -> Result<wholepact_proof_jobs::ProofStatusSnapshot> {
        self.inventory()?;
        let snapshot = wholepact_proof_jobs::ProofStatusSnapshot::open(
            &self.directory.path("proof.sqlite")?,
            &self.secrets.key(1)?,
        )
        .map_err(|_| Error::Authentication)?;
        if snapshot
            .source_database_identity()
            .map_err(|_| Error::Authentication)?
            != self.original_databases[1]
        {
            return Err(Error::Authentication);
        }
        snapshot
            .check_source_unchanged()
            .map_err(|_| Error::Authentication)?;
        self.inventory()?;
        Ok(snapshot)
    }
    pub(crate) fn inventory(&self) -> Result<()> {
        self.directory
            .inventory_of(&JOURNALS, &["profile.lock", "financial.vault"])
    }
}

/// Fixed read-only owner used solely for source-preserving generation capture.
/// Every identity comes from a factory-authenticated original source descriptor,
/// never the private temporary copy, a registry DTO, or a writable journal open.
pub(crate) struct FinancialReadProfile {
    sources: [wholepact_storage_security::EncryptedReadSnapshot; 4],
    original_owner: String,
    original_databases: [wholepact_storage_security::DatabaseFileIdentity; 4],
    pub(crate) secrets: FinancialSecrets,
    pub(crate) directory: Directory,
}
impl FinancialReadProfile {
    pub(crate) fn open(path: &Path, owner: &str, password: &[u8]) -> Result<Self> {
        let directory = Directory::open(path)?;
        directory.inventory_of(&JOURNALS, &["profile.lock", "financial.vault"])?;
        let secrets =
            FinancialSecrets::open(&directory.read("financial.vault", 1024)?, owner, password)?;
        let sources = (0..4)
            .map(|index| {
                Ok(if index == 0 {
                    wholepact_wallet::bundle::open_wallet_scan_read_snapshot(
                        &directory.path(JOURNALS[index])?,
                        &secrets.key(index)?,
                    )?
                } else {
                    wholepact_storage_security::open_encrypted_read_snapshot(
                        directory.path(JOURNALS[index])?,
                        &secrets.key(index)?,
                    )?
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let sources: [wholepact_storage_security::EncryptedReadSnapshot; 4] = sources;
        let original_databases = sources
            .iter()
            .map(|source| Ok(source.source_database_identity()?))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let profile = Self {
            sources,
            original_owner: owner.into(),
            original_databases,
            secrets,
            directory,
        };
        profile.check_retained_owner(owner)?;
        Ok(profile)
    }
    pub(crate) fn check_retained_owner(&self, owner: &str) -> Result<()> {
        for source in &self.sources {
            source.check_source_unchanged()?;
        }
        check_retained(
            &self.directory,
            &self.original_owner,
            &self.original_databases,
            owner,
        )
    }
    pub(crate) fn current_directory(&self) -> Result<std::path::PathBuf> {
        current_directory(&self.directory)
    }
    pub(crate) fn manual_attachment_descriptor(
        &self,
        owner: &str,
        account: &str,
    ) -> Result<wholepact_core::manual_construction::ManualParticipantAttachment> {
        self.check_retained_owner(owner)?;
        actual_descriptor(
            &self.directory,
            &self.original_owner,
            &self.original_databases,
            owner,
            account,
        )
    }
    pub(crate) fn manual_original_primary_origin_digest(
        &self,
        host: &Directory,
        secrets: &crate::vault::Secrets,
    ) -> Result<String> {
        self.check_retained_owner(&secrets.profile())?;
        original_primary_origin(
            host,
            secrets,
            &self.directory,
            &self.original_owner,
            &self.original_databases,
        )
    }
}
fn original_primary_origin(
    host: &Directory,
    secrets: &crate::vault::Secrets,
    directory: &Directory,
    original_owner: &str,
    databases: &[wholepact_storage_security::DatabaseFileIdentity; 4],
) -> Result<String> {
    host.check()?;
    check_retained(directory, original_owner, databases, &secrets.profile())?;
    let (entries, expected) = crate::financial_inventory::original_primary_anchor(host, secrets)?;
    if entries[0].directory != current_directory(directory)? {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    let identities: Vec<_> = JOURNALS
        .iter()
        .zip(databases)
        .map(|(name, identity)| (*name, hex::encode(identity.origin_commitment())))
        .collect();
    let actual = wholepact_core::proposal::canonical_digest(
        "wholepact:native-manual-financial-journal-origin:v1",
        &(
            original_owner,
            directory.manual_target_identity_digest()?,
            &entries,
            identities,
        ),
    )
    .map_err(|_| Error::Authentication)?;
    if expected
        .as_ref()
        .is_some_and(|expected| expected != &actual)
    {
        return Err(Error::Authentication);
    }
    Ok(actual)
}

/// A scoped participant scanner retains the entire original encrypted profile
/// and its exclusive directory lock. Dropping it discards observation authority;
/// reopening the profile always requires a fresh signer disclosure and scan.
pub(crate) struct ConstructionWallet {
    pub(crate) sync: wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
    _proof: ProofJobStore,
    _signed: SignedResultJournal,
    _transactions: TransactionCheckpointJournal,
    _secrets: FinancialSecrets,
    original_owner: String,
    original_databases: [wholepact_storage_security::DatabaseFileIdentity; 4],
    directory: Directory,
}
impl FinancialProfile {
    pub(crate) fn into_construction_wallet(
        self,
        source: wholepact_chain::ChainAdapter,
        minimum_confirmations: std::num::NonZeroU32,
    ) -> Result<ConstructionWallet> {
        self.check_current_journals()?;
        let Self {
            wallet,
            proof,
            signed,
            transactions,
            secrets,
            original_owner,
            original_databases,
            directory,
        } = self;
        let sync =
            wholepact_wallet::wallet::protected_sync::ProtectedWalletSync::from_initialized_wallet(
                wallet,
                source,
                minimum_confirmations,
            )
            .map_err(|_| Error::Invalid)?;
        Ok(ConstructionWallet {
            sync,
            _proof: proof,
            _signed: signed,
            _transactions: transactions,
            _secrets: secrets,
            original_owner,
            original_databases,
            directory,
        })
    }
}

/// Private borrowed view over the ORIGINAL retained provenance fields. It
/// cannot reopen a wallet or manufacture a source or permission owner.
pub(crate) struct ConstructionWalletProvenance<'a> {
    original_owner: &'a str,
    original_databases: &'a [wholepact_storage_security::DatabaseFileIdentity; 4],
    directory: &'a Directory,
}
impl ConstructionWalletProvenance<'_> {
    pub(crate) fn manual_attachment_descriptor(
        &self,
        owner: &str,
        account: &str,
    ) -> Result<wholepact_core::manual_construction::ManualParticipantAttachment> {
        actual_descriptor(
            self.directory,
            self.original_owner,
            self.original_databases,
            owner,
            account,
        )
    }
}
impl ConstructionWallet {
    pub(crate) fn exact_input_parts(
        &mut self,
    ) -> (
        &mut wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        ConstructionWalletProvenance<'_>,
    ) {
        (
            &mut self.sync,
            ConstructionWalletProvenance {
                original_owner: &self.original_owner,
                original_databases: &self.original_databases,
                directory: &self.directory,
            },
        )
    }
}
impl FinancialProfile {
    pub(crate) fn exact_input_excluded_origins(&self) -> Result<Vec<[u8; 32]>> {
        self.check_current_journals()?;
        Ok(self
            .original_databases
            .iter()
            .map(|identity| identity.origin_commitment())
            .collect())
    }
}
impl ConstructionWallet {
    /// Consuming a FinancialProfile into a scanner does not discard any actual
    /// retained journal origin or its owner. No DTO can supply these identities.
    pub(crate) fn manual_attachment_descriptor(
        &self,
        owner: &str,
        account: &str,
    ) -> Result<wholepact_core::manual_construction::ManualParticipantAttachment> {
        actual_descriptor(
            &self.directory,
            &self.original_owner,
            &self.original_databases,
            owner,
            account,
        )
    }
    pub(crate) fn check_manual_attachment(
        &self,
        owner: &str,
        expected: &wholepact_core::manual_construction::ManualParticipantAttachment,
    ) -> Result<()> {
        if &self.manual_attachment_descriptor(owner, &expected.account_id)? != expected {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
fn current_directory(directory: &Directory) -> Result<std::path::PathBuf> {
    directory
        .path("financial.vault")?
        .parent()
        .map(Path::to_owned)
        .ok_or(Error::Invalid)
}
fn check_retained(
    directory: &Directory,
    original_owner: &str,
    databases: &[wholepact_storage_security::DatabaseFileIdentity; 4],
    owner: &str,
) -> Result<()> {
    directory.inventory_of(&JOURNALS, &["profile.lock", "financial.vault"])?;
    if original_owner != owner || directory.read("financial.vault", 1024)?.is_empty() {
        return Err(Error::Authentication);
    }
    for identity in databases {
        identity.check_retained_owner_path()?;
    }
    Ok(())
}
fn actual_descriptor(
    directory: &Directory,
    original_owner: &str,
    databases: &[wholepact_storage_security::DatabaseFileIdentity; 4],
    owner: &str,
    account: &str,
) -> Result<wholepact_core::manual_construction::ManualParticipantAttachment> {
    check_retained(directory, original_owner, databases, owner)?;
    if account.len() != 64
        || !account
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    let canonical_directory = current_directory(directory)?
        .to_str()
        .ok_or(Error::Invalid)?
        .to_owned();
    if canonical_directory.len() > 2048
        || canonical_directory.chars().any(char::is_control)
        || canonical_directory.ends_with('/')
        || canonical_directory
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Invalid);
    }
    let directory_identity_digest = directory.manual_target_identity_digest()?;
    let identities: Vec<_> = JOURNALS
        .iter()
        .zip(databases)
        .map(|(name, identity)| (*name, hex::encode(identity.origin_commitment())))
        .collect();
    let journal_origin_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:native-manual-participant-journal-origin:v1",
        &(
            original_owner,
            &canonical_directory,
            &directory_identity_digest,
            identities,
        ),
    )
    .map_err(|_| Error::Authentication)?;
    Ok(
        wholepact_core::manual_construction::ManualParticipantAttachment {
            account_id: account.to_owned(),
            canonical_directory,
            directory_identity_digest,
            journal_origin_digest,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separate_profile_reopen_owner_binding_and_missing_journal_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temporary.path())
            .unwrap()
            .join("financial");
        let password = b"synthetic-only-storage-password";
        let profile = FinancialProfile::create(&root, "native-synthetic-owner", password).unwrap();
        profile.inventory().unwrap();
        assert!(FinancialProfile::open(&root, "native-synthetic-owner", password).is_err());
        drop(profile);
        assert!(FinancialProfile::open(&root, "native-wrong-owner", password).is_err());
        let reopened = FinancialProfile::open(&root, "native-synthetic-owner", password).unwrap();
        reopened.inventory().unwrap();
        drop(reopened);
        std::fs::remove_file(root.join(JOURNALS[2])).unwrap();
        assert!(FinancialProfile::open(&root, "native-synthetic-owner", password).is_err());
        assert!(!root.join(JOURNALS[2]).exists());
    }
}
