//! Existing registered born wallet ownership, deliberately disjoint from every
//! original-create constructor and its consumed contribution/import capability.
use super::*;
use wholepact_wallet::wallet::protected_sync::born_post_return_inputs_v1::BornPostReturnWalletReaderV1;

pub(crate) struct BornPostReturnWalletV1 {
    pub(crate) reader: BornPostReturnWalletReaderV1,
    pub(crate) provenance: BornPostReturnWalletProvenanceV1,
}
pub(crate) struct BornPostReturnWalletProvenanceV1 {
    _proof: ProofJobStore,
    _signed: SignedResultJournal,
    _transactions: TransactionCheckpointJournal,
    _secrets: FinancialSecrets,
    original_owner: String,
    original_databases: [wholepact_storage_security::DatabaseFileIdentity; 4],
    directory: Directory,
}
impl BornPostReturnWalletV1 {
    /// Caller must already hold purpose-specific foreground native approval and
    /// verify this exact registered dependency BEFORE opening any file.
    pub(crate) fn open_existing(
        path: &Path,
        owner: &str,
        password: &[u8],
        source: wholepact_chain::ChainAdapter,
        minimum_confirmations: std::num::NonZeroU32,
    ) -> Result<Self> {
        let directory = Directory::open(path)?;
        if directory.path("restored.quarantine")?.try_exists()? {
            return Err(Error::Quarantined);
        }
        directory.inventory_of(&JOURNALS, &["profile.lock", "financial.vault"])?;
        let secrets =
            FinancialSecrets::open(&directory.read("financial.vault", 1024)?, owner, password)?;
        for name in JOURNALS {
            if !directory.path(name)?.try_exists()? {
                return Err(Error::Invalid);
            }
        }
        let connection = |index: usize| -> Result<_> {
            Ok(open_encrypted(
                directory.path(JOURNALS[index])?,
                &secrets.key(index)?,
            )?)
        };
        let wallet_connection = connection(0)?;
        let wallet_identity = wallet_connection.database_identity()?;
        let reader = BornPostReturnWalletReaderV1::from_existing_encrypted(
            wallet_connection,
            source,
            minimum_confirmations,
        )
        .map_err(|_| Error::Storage)?;
        let proof_connection = connection(1)?;
        let proof_identity = proof_connection.database_identity()?;
        let proof = ProofJobStore::from_encrypted_connection(proof_connection)
            .map_err(|_| Error::Storage)?;
        let signed_connection = connection(2)?;
        let signed_identity = signed_connection.database_identity()?;
        let signed = SignedResultJournal::from_encrypted_connection(signed_connection)
            .map_err(|_| Error::Storage)?;
        let transactions_connection = connection(3)?;
        let transactions_identity = transactions_connection.database_identity()?;
        let transactions =
            TransactionCheckpointJournal::from_encrypted_connection(transactions_connection)
                .map_err(|_| Error::Storage)?;
        let result = Self {
            reader,
            provenance: BornPostReturnWalletProvenanceV1 {
                _proof: proof,
                _signed: signed,
                _transactions: transactions,
                _secrets: secrets,
                original_owner: owner.into(),
                original_databases: [
                    wallet_identity,
                    proof_identity,
                    signed_identity,
                    transactions_identity,
                ],
                directory,
            },
        };
        result.provenance.check_current(owner)?;
        Ok(result)
    }
}
impl BornPostReturnWalletProvenanceV1 {
    pub(crate) fn check_current(&self, owner: &str) -> Result<()> {
        check_retained(
            &self.directory,
            &self.original_owner,
            &self.original_databases,
            owner,
        )
    }
    pub(crate) fn descriptor(
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
    pub(crate) fn wallet_origin_digest(&self, owner: &str) -> Result<String> {
        self.check_current(owner)?;
        Ok(hex::encode(self.original_databases[0].origin_commitment()))
    }
}
