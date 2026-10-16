//! Dedicated, viewing-material-only SQLite wallet and Ironwood contribution selection.
//!
//! These APIs are library plumbing, not a trusted-user approval or account-provisioning
//! interface. Callers must obtain explicit consent before importing viewing material,
//! synchronizing an account, or exporting the resulting witness-bearing contribution.
//! The public durable constructor requires a protected-storage connection. Synthetic
//! qualification fixtures use ephemeral in-memory databases with public never-funded keys.

use orchard::{
    Address, Note,
    keys::{FullViewingKey, Scope},
    note::NoteVersion,
    tree::MerklePath,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::{collections::BTreeSet, num::NonZeroU32};
use thiserror::Error;
use zcash_address::unified::{self, Encoding};
pub use zcash_client_backend::data_api::AccountBirthday;
use zcash_client_backend::{
    data_api::{
        Account, AccountPurpose, InputSource, TargetValue, WalletCommitmentTrees, WalletRead,
        WalletWrite,
        chain::{self, BlockSource, ChainState},
        locking::{LockFilter, LockedInputPolicy},
        wallet::ConfirmationsPolicy,
    },
    util::SystemClock,
};
pub use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::{ReceivedNoteId, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, BranchId, NetworkType, TEST_NETWORK, TestNetwork},
    value::Zatoshis,
};

pub const MAX_SELECTED_NOTES: usize = 32;
#[cfg(any(
    test,
    feature = "synthetic-qualification",
    feature = "encrypted-storage"
))]
const WALLET_APPLICATION_ID: i64 = 0x57505754;
const MAX_MONEY: u64 = 2_100_000_000_000_000;

type Database = WalletDb<rusqlite::Connection, TestNetwork, SystemClock, UnwrapErr<SysRng>>;

/// Fixed messages deliberately exclude keys, witnesses, database rows and server errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletError {
    #[error("wallet storage operation failed")]
    Storage,
    #[error("wallet is not a single dedicated account")]
    AccountScope,
    #[error("wallet viewing authority does not match the authenticated local account")]
    AccountMismatch,
    #[error("wallet is not fully scanned to the expected testnet tip")]
    IncompleteSync,
    #[error("only the qualified testnet NU7 profile is supported")]
    UnsupportedProfile,
    #[error("wallet chain or anchor evidence does not match the accepted context")]
    ChainMismatch,
    #[error("confirmed Ironwood funds are insufficient")]
    InsufficientFunds,
    #[error("invalid bounded wallet contribution request")]
    InvalidRequest,
    #[error("required Ironwood witness or anchor is unavailable")]
    MissingWitness,
    #[error("selected note ownership, version or membership is invalid")]
    InvalidNote,
    #[error("wallet scanning failed; no signing authority was granted")]
    Scan,
    #[error("wallet sync transport failed or exceeded its deadline")]
    Transport,
}

/// An expectation obtained separately from the caller's explicitly trusted chain source.
/// Constructing this record does NOT authenticate a server or establish consensus validity.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionContext {
    pub tip_height: u32,
    pub tip_hash_protocol: [u8; 32],
    pub anchor_height: u32,
    pub anchor_hash_protocol: [u8; 32],
    pub anchor_root: [u8; 32],
}

/// Private note and witness material. Never log, serialize or send without consent.
pub struct SelectedNote {
    pub input_id: String,
    pub note: Note,
    pub witness: MerklePath,
}

/// Derived from the locally scanned wallet and trusted local FVK, never an imported claim.
/// This remains privacy-sensitive and is NOT a signing authorization or a note reservation.
pub struct WalletContribution {
    account_id: String,
    fvk: FullViewingKey,
    notes: Vec<SelectedNote>,
    change_address: Address,
    selected_zatoshis: u64,
    requested_debit_zatoshis: u64,
    context: SelectionContext,
    local_note_refs: Vec<ReceivedNoteId>,
    #[cfg(feature = "protected-sync")]
    local_outpoints: Vec<(zcash_protocol::TxId, u16)>,
}
impl WalletContribution {
    pub fn evidence(&self) -> LocallySelectedInputs {
        LocallySelectedInputs {
            account_id: self.account_id.clone(),
            fvk: self.fvk.clone(),
            inputs: self
                .notes
                .iter()
                .map(|n| SelectedInputEvidence {
                    input_id: n.input_id.clone(),
                    nullifier: n.note.nullifier(&self.fvk).to_bytes(),
                    value_zatoshis: n.note.value().inner(),
                })
                .collect(),
            context: self.context.clone(),
        }
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }
    pub fn notes(&self) -> &[SelectedNote] {
        &self.notes
    }
    pub fn change_address(&self) -> Address {
        self.change_address
    }
    pub fn selected_zatoshis(&self) -> u64 {
        self.selected_zatoshis
    }
    pub fn requested_debit_zatoshis(&self) -> u64 {
        self.requested_debit_zatoshis
    }
    pub fn context(&self) -> &SelectionContext {
        &self.context
    }
    pub fn local_note_refs(&self) -> &[ReceivedNoteId] {
        &self.local_note_refs
    }
    /// Move sensitive local selection into the multi-owner constructor only after disclosure
    /// consent. The constructor still needs exact proposal terms and matched chain context.
    pub fn into_contribution(self) -> wholepact_protocol::construction::OwnedContribution {
        wholepact_protocol::construction::OwnedContribution {
            account_id: self.account_id,
            fvk: self.fvk,
            change_address: self.change_address,
            notes: self
                .notes
                .into_iter()
                .map(|n| wholepact_protocol::construction::SpendableNote {
                    input_id: n.input_id,
                    note: n.note,
                    witness: n.witness,
                })
                .collect(),
        }
    }
}

/// Immutable local selection evidence. Private construction is a Rust boundary, not IPC
/// authentication. A separate signer still needs an authenticated local transport/binding.
#[derive(Clone)]
pub struct LocallySelectedInputs {
    account_id: String,
    fvk: FullViewingKey,
    inputs: Vec<SelectedInputEvidence>,
    context: SelectionContext,
}
impl LocallySelectedInputs {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }
    pub fn inputs(&self) -> &[SelectedInputEvidence] {
        &self.inputs
    }
    pub fn context(&self) -> &SelectionContext {
        &self.context
    }
}
#[derive(Clone)]
pub struct SelectedInputEvidence {
    input_id: String,
    nullifier: [u8; 32],
    value_zatoshis: u64,
}
impl SelectedInputEvidence {
    pub fn input_id(&self) -> &str {
        &self.input_id
    }
    pub fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }
    pub fn value_zatoshis(&self) -> u64 {
        self.value_zatoshis
    }
}

/// This adapter stores only a dedicated account's viewing material, never a seed or spend key.
/// The database still contains sensitive wallet history, FVKs and note witnesses.
pub struct DedicatedTestnetWallet {
    db: Database,
    #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
    pub(crate) backup_identity: Option<crate::bundle::WalletFileIdentity>,
    // Present only on the original explicit recordable-create path. Ordinary
    // reopen never recreates this process-local issuer, even with complete rows.
    #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
    recorded_import_origin: Option<wholepact_storage_security::DatabaseFileIdentity>,
    // V2 owns a distinct original-create lineage. The destination comes from the
    // authenticated connection, never from a caller request or a reopened row.
    #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
    exact_input_fail_fast_v1: bool,
    // Read-only original file identity survives consumption of the separate
    // import issuer. It can never mint an import record or native permission.
    #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
    exact_input_origin_v1: Option<(wholepact_storage_security::DatabaseFileIdentity, String)>,
    #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
    recorded_roster_import_origin_v2:
        Option<(wholepact_storage_security::DatabaseFileIdentity, String)>,
}

impl DedicatedTestnetWallet {
    /// Consume only a connection keyed and authenticated by the protected-storage factory.
    /// No raw disk-connection constructor is public. Encryption does not establish account
    /// ownership, approval, writer freshness or consensus validity.
    #[cfg(feature = "encrypted-storage")]
    pub fn from_encrypted_connection(
        connection: wholepact_storage_security::EncryptedConnection,
    ) -> Result<Self, WalletError> {
        #[cfg(target_os = "linux")]
        let identity = crate::bundle::WalletFileIdentity::capture(connection.connection())
            .map_err(|_| WalletError::Storage)?;
        let mut wallet = Self::from_connection(connection.into_connection())?;
        #[cfg(target_os = "linux")]
        {
            wallet.backup_identity = Some(identity);
        }
        Ok(wallet)
    }

    /// Explicit original-create-only factory for durable imported-wallet records.
    /// The authenticated connection must still be truly empty. This does not
    /// import a key, create an account, establish native permission, or reopen
    /// an old wallet. All ordinary constructors retain their legacy behavior.
    #[cfg(all(feature = "protected-sync", target_os = "linux"))]
    pub fn from_encrypted_connection_recordable_import(
        connection: wholepact_storage_security::EncryptedConnection,
    ) -> Result<Self, WalletError> {
        let origin = connection
            .database_identity()
            .map_err(|_| WalletError::Storage)?;
        origin
            .check_current(connection.connection())
            .map_err(|_| WalletError::Storage)?;
        let c = connection.connection();
        let app: i64 = c
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| WalletError::Storage)?;
        let version: i64 = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| WalletError::Storage)?;
        let objects: i64 = c
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(|_| WalletError::Storage)?;
        if app != 0 || version != 0 || objects != 0 {
            return Err(WalletError::AccountScope);
        }
        let identity =
            crate::bundle::WalletFileIdentity::capture(c).map_err(|_| WalletError::Storage)?;
        let mut wallet = Self::from_connection_layout(
            connection.into_connection(),
            Some(recorded_import::SCHEMA),
        )?;
        origin
            .check_retained_owner_path()
            .map_err(|_| WalletError::Storage)?;
        wallet.backup_identity = Some(identity);
        wallet.recorded_import_origin = Some(origin);
        Ok(wallet)
    }

    /// Explicit original-create-only factory for durable V2 roster imported-wallet records.
    /// The authenticated connection must still be truly empty. This does not
    /// import a key, create an account, establish native permission, or reopen
    /// an old wallet. All ordinary constructors retain their legacy behavior.
    #[cfg(all(feature = "protected-sync", target_os = "linux"))]
    pub fn from_encrypted_connection_recordable_roster_import_v2(
        connection: wholepact_storage_security::EncryptedConnection,
    ) -> Result<Self, WalletError> {
        let origin = connection
            .database_identity()
            .map_err(|_| WalletError::Storage)?;
        origin
            .check_current(connection.connection())
            .map_err(|_| WalletError::Storage)?;
        let c = connection.connection();
        let app: i64 = c
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| WalletError::Storage)?;
        let version: i64 = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| WalletError::Storage)?;
        let objects: i64 = c
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(|_| WalletError::Storage)?;
        if app != 0 || version != 0 || objects != 0 {
            return Err(WalletError::AccountScope);
        }
        let destination = std::fs::canonicalize(c.path().ok_or(WalletError::Storage)?)
            .map_err(|_| WalletError::Storage)?
            .to_str()
            .ok_or(WalletError::Storage)?
            .to_owned();
        let identity =
            crate::bundle::WalletFileIdentity::capture(c).map_err(|_| WalletError::Storage)?;
        let mut wallet = Self::from_connection_layout(
            connection.into_connection(),
            Some(recorded_roster_import_v2::SCHEMA),
        )?;
        origin
            .check_retained_owner_path()
            .map_err(|_| WalletError::Storage)?;
        wallet.backup_identity = Some(identity);
        wallet.recorded_roster_import_origin_v2 = Some((origin, destination));
        Ok(wallet)
    }

    /// Original-create-only variant for the exact-input observation route.
    /// Refuses existing databases through the unchanged V2 factory, sets zero
    /// SQLite busy wait before ownership transfer, and retains original origin.
    /// Reopened and ordinary V2 wallets cannot acquire this process-local mode.
    #[cfg(all(feature = "protected-sync", target_os = "linux"))]
    pub fn from_encrypted_connection_recordable_roster_exact_input_v1(
        connection: wholepact_storage_security::EncryptedConnection,
    ) -> Result<Self, WalletError> {
        connection
            .connection()
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(|_| WalletError::Storage)?;
        let mut wallet = Self::from_encrypted_connection_recordable_roster_import_v2(connection)?;
        wallet.exact_input_origin_v1 = wallet.recorded_roster_import_origin_v2.clone();
        wallet.exact_input_fail_fast_v1 = true;
        Ok(wallet)
    }

    /// Wrap and migrate an explicitly authorized SQLite connection. This function performs no
    /// network activity and imports no account. Production disk protection is the caller's duty.
    #[cfg(any(
        test,
        feature = "synthetic-qualification",
        feature = "encrypted-storage"
    ))]
    fn from_connection(connection: rusqlite::Connection) -> Result<Self, WalletError> {
        Self::from_connection_layout(connection, None)
    }

    #[cfg(any(
        test,
        feature = "synthetic-qualification",
        feature = "encrypted-storage"
    ))]
    fn from_connection_layout(
        mut connection: rusqlite::Connection,
        recorded_schema: Option<&'static str>,
    ) -> Result<Self, WalletError> {
        // Refuse to attach an arbitrary everyday wallet database. This marker prevents
        // accidental reuse; it is not authentication against an attacker editing the file.
        let app_id: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(|_| WalletError::Storage)?;
        let tables: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'", [], |row| row.get(0))
            .map_err(|_| WalletError::Storage)?;
        if (tables > 0 && app_id != WALLET_APPLICATION_ID)
            || (app_id != 0 && app_id != WALLET_APPLICATION_ID)
        {
            return Err(WalletError::AccountScope);
        }
        connection
            .pragma_update(None, "application_id", WALLET_APPLICATION_ID)
            .map_err(|_| WalletError::Storage)?;
        rusqlite::vtab::array::load_module(&connection).map_err(|_| WalletError::Storage)?;
        // Maintained WalletDb::transactionally uses the connection's default. A
        // key-use callback must acquire a writer lock before reading its snapshot,
        // including in WAL mode, rather than merely pinning an old read snapshot.
        connection.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);
        // Migrate with a temporary borrow so only the explicit fresh factory can
        // append its compiled ext_ schema before the owned wallet is constructed.
        {
            let mut db = WalletDb::from_connection(
                &mut connection,
                TEST_NETWORK,
                SystemClock,
                UnwrapErr(SysRng),
            );
            zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None)
                .map_err(|_| WalletError::Storage)?;
        }
        if let Some(recorded_schema) = recorded_schema {
            #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
            connection
                .execute_batch(recorded_schema)
                .map_err(|_| WalletError::Storage)?;
            #[cfg(not(all(feature = "encrypted-storage", target_os = "linux")))]
            return Err(WalletError::Storage);
        }
        let db =
            WalletDb::from_connection(connection, TEST_NETWORK, SystemClock, UnwrapErr(SysRng));
        if db
            .get_account_ids()
            .map_err(|_| WalletError::Storage)?
            .len()
            > 1
        {
            return Err(WalletError::AccountScope);
        }
        Ok(Self {
            db,
            #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
            backup_identity: None,
            #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
            recorded_import_origin: None,
            #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
            exact_input_fail_fast_v1: false,
            #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
            exact_input_origin_v1: None,
            #[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
            recorded_roster_import_origin_v2: None,
        })
    }

    /// Import an already-authorized dedicated Orchard/Ironwood FVK, with a verified prior
    /// tree state. Spending metadata is retained for witness selection, but no spend key is
    /// imported. Broad unified everyday-wallet keys cannot be passed to this interface.
    pub fn import_dedicated_fvk(
        &mut self,
        fvk: &FullViewingKey,
        birthday: AccountBirthday,
    ) -> Result<AccountUuid, WalletError> {
        if !self
            .db
            .get_account_ids()
            .map_err(|_| WalletError::Storage)?
            .is_empty()
        {
            return Err(WalletError::AccountScope);
        }
        let ufvk = unified::Ufvk::try_from_items(
            zcash_protocol::address::Revision::R0,
            vec![unified::Uitem::Data(unified::Fvk::Orchard(fvk.to_bytes()))],
        )
        .map_err(|_| WalletError::InvalidRequest)?;
        let encoded = ufvk.encode(&NetworkType::Test);
        let ufvk = UnifiedFullViewingKey::decode(&TEST_NETWORK, &encoded)
            .map_err(|_| WalletError::InvalidRequest)?;
        let account = self
            .db
            .import_account_ufvk(
                "Wholepact dedicated participation",
                &ufvk,
                &birthday,
                AccountPurpose::Spending { derivation: None },
                Some("explicit local signer viewing export"),
            )
            .map_err(|_| WalletError::Storage)?;
        Ok(account.id())
    }

    /// Scan supplied compact blocks with the maintained scanner. This checks local chain
    /// continuity and decrypts notes; it does not validate proof of work or full consensus.
    pub fn scan_cached<B: BlockSource>(
        &mut self,
        source: &B,
        prior: &ChainState,
        count: usize,
        reported_tip: u32,
    ) -> Result<(), WalletError> {
        if count == 0
            || count > 1_000
            || u32::from(prior.block_height()) == u32::MAX
            || reported_tip < u32::from(prior.block_height()) + 1
        {
            return Err(WalletError::InvalidRequest);
        }
        self.db
            .update_chain_tip(BlockHeight::from(reported_tip))
            .map_err(|_| WalletError::Storage)?;
        chain::scan_cached_blocks(
            &TEST_NETWORK,
            source,
            &mut self.db,
            prior.block_height() + 1,
            prior,
            count,
        )
        .map_err(|_| WalletError::Scan)?;
        Ok(())
    }

    fn check_selection_context(
        &mut self,
        min_confirmations: NonZeroU32,
        context: &SelectionContext,
    ) -> Result<(), WalletError> {
        if context.anchor_height > context.tip_height
            || context.tip_height - context.anchor_height + 1 < min_confirmations.get()
        {
            return Err(WalletError::InvalidRequest);
        }
        let scanned = self
            .db
            .block_fully_scanned()
            .map_err(|_| WalletError::Storage)?
            .ok_or(WalletError::IncompleteSync)?;
        if u32::from(scanned.block_height()) != context.tip_height
            || self.db.chain_height().map_err(|_| WalletError::Storage)?
                != Some(context.tip_height.into())
        {
            return Err(WalletError::IncompleteSync);
        }
        for (height, hash) in [
            (context.tip_height, context.tip_hash_protocol),
            (context.anchor_height, context.anchor_hash_protocol),
        ] {
            if self
                .db
                .get_block_hash(height.into())
                .map_err(|_| WalletError::Storage)?
                .map(|h| h.0)
                != Some(hash)
            {
                return Err(WalletError::ChainMismatch);
            }
        }
        if !self
            .db
            .anchor_computable(ShieldedPool::Ironwood, context.anchor_height.into())
            .map_err(|_| WalletError::Storage)?
        {
            return Err(WalletError::MissingWitness);
        }
        self.db
            .with_ironwood_tree_mut::<_, _, WalletError>(|tree| {
                let root = tree
                    .root_at_checkpoint_id(&context.anchor_height.into())?
                    .ok_or(WalletError::MissingWitness)?;
                if orchard::Anchor::from(root).to_bytes() != context.anchor_root {
                    return Err(WalletError::ChainMismatch);
                }
                Ok(())
            })?
            .ok_or(WalletError::MissingWitness)?;
        Ok(())
    }

    /// Read an account's confirmed Ironwood notes and cached witnesses for one common anchor.
    /// `authenticated_fvk` must come from the local signer association, never the coordinator.
    /// External reservations must be supplied in `exclude`; this read creates no reservation.
    #[allow(clippy::too_many_arguments)]
    pub fn select_contribution(
        &mut self,
        account: AccountUuid,
        authenticated_fvk: &FullViewingKey,
        accepted_account_id: &str,
        requested_debit_zatoshis: u64,
        min_confirmations: NonZeroU32,
        context: &SelectionContext,
        exclude: &[ReceivedNoteId],
    ) -> Result<WalletContribution, WalletError> {
        if accepted_account_id.is_empty()
            || accepted_account_id.len() > 128
            || !accepted_account_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            || requested_debit_zatoshis == 0
            || requested_debit_zatoshis > MAX_MONEY
            || exclude.len() > 1024
        {
            return Err(WalletError::InvalidRequest);
        }
        let target = context
            .tip_height
            .checked_add(1)
            .ok_or(WalletError::InvalidRequest)?;
        if BranchId::for_height(&TEST_NETWORK, BlockHeight::from(target)) != BranchId::Nu7 {
            return Err(WalletError::UnsupportedProfile);
        }
        if context.anchor_height > context.tip_height
            || context.tip_height - context.anchor_height + 1 < min_confirmations.get()
        {
            return Err(WalletError::InvalidRequest);
        }
        let ids = self
            .db
            .get_account_ids()
            .map_err(|_| WalletError::Storage)?;
        if ids != vec![account] {
            return Err(WalletError::AccountScope);
        }
        let local = self
            .db
            .get_account(account)
            .map_err(|_| WalletError::Storage)?
            .ok_or(WalletError::AccountScope)?;
        let fvk = local
            .ufvk()
            .and_then(|k| k.orchard())
            .ok_or(WalletError::AccountMismatch)?;
        if fvk.to_bytes() != authenticated_fvk.to_bytes() {
            return Err(WalletError::AccountMismatch);
        }
        self.check_selection_context(min_confirmations, context)?;
        let selected = self
            .db
            .select_spendable_notes(
                account,
                TargetValue::AtLeast(
                    Zatoshis::from_u64(requested_debit_zatoshis)
                        .map_err(|_| WalletError::InvalidRequest)?,
                ),
                &[ShieldedPool::Ironwood],
                target.into(),
                ConfirmationsPolicy::new_symmetrical(min_confirmations),
                exclude,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(|_| WalletError::Storage)?;
        if !selected.sapling().is_empty()
            || !selected.orchard().is_empty()
            || selected.ironwood().len() > MAX_SELECTED_NOTES
        {
            return Err(WalletError::InvalidNote);
        }
        let selected = selected.take_ironwood();
        let mut total = 0u64;
        let mut nullifiers = BTreeSet::new();
        for n in &selected {
            let note = n.note();
            if note.version() != NoteVersion::V3
                || note.value().inner() == 0
                || fvk.scope_for_address(&note.recipient()) != Some(n.spending_key_scope())
                || n.mined_height()
                    .is_none_or(|h| u32::from(h) > context.anchor_height)
                || !nullifiers.insert(note.nullifier(fvk).to_bytes())
            {
                return Err(WalletError::InvalidNote);
            }
            total = total
                .checked_add(note.value().inner())
                .filter(|v| *v <= MAX_MONEY)
                .ok_or(WalletError::InvalidNote)?;
        }
        if total < requested_debit_zatoshis {
            return Err(WalletError::InsufficientFunds);
        }
        let anchor_height = BlockHeight::from(context.anchor_height);
        let notes = self
            .db
            .with_ironwood_tree_mut(|tree| {
                let root = tree
                    .root_at_checkpoint_id(&anchor_height)
                    .map_err(|_| WalletError::MissingWitness)?
                    .ok_or(WalletError::MissingWitness)?;
                if orchard::Anchor::from(root).to_bytes() != context.anchor_root {
                    return Err(WalletError::ChainMismatch);
                }
                selected
                    .iter()
                    .map(|n| {
                        let witness: MerklePath = tree
                            .witness_at_checkpoint_id_caching(
                                n.note_commitment_tree_position(),
                                &anchor_height,
                            )
                            .map_err(|_| WalletError::MissingWitness)?
                            .ok_or(WalletError::MissingWitness)?
                            .into();
                        if witness.root(n.note().commitment().into()).to_bytes()
                            != context.anchor_root
                        {
                            return Err(WalletError::InvalidNote);
                        }
                        Ok(SelectedNote {
                            input_id: format!("ironwood:{}:{}", n.txid(), n.output_index()),
                            note: *n.note(),
                            witness,
                        })
                    })
                    .collect::<Result<Vec<_>, WalletError>>()
            })?
            .ok_or(WalletError::MissingWitness)?;
        Ok(WalletContribution {
            account_id: accepted_account_id.into(),
            fvk: fvk.clone(),
            notes,
            change_address: fvk.address_at(0u32, Scope::Internal),
            selected_zatoshis: total,
            requested_debit_zatoshis,
            context: context.clone(),
            local_note_refs: selected.iter().map(|n| *n.internal_note_id()).collect(),
            #[cfg(feature = "protected-sync")]
            local_outpoints: selected
                .iter()
                .map(|n| (*n.txid(), n.output_index()))
                .collect(),
        })
    }
}

impl<E> From<shardtree::error::ShardTreeError<E>> for WalletError {
    fn from(_: shardtree::error::ShardTreeError<E>) -> Self {
        Self::MissingWitness
    }
}

/// Fresh, never-funded qualification accounts scanned through the actual
/// maintained SQLite backend. This function makes no network requests and never signs.
/// The fabricated chain is not live testnet evidence; never fund these ephemeral test accounts.
#[cfg(feature = "synthetic-qualification")]
pub fn synthetic_scanned_contributions()
-> Result<(Vec<WalletContribution>, SelectionContext), WalletError> {
    SyntheticContributionFixture::generate().scanned_contributions()
}

#[cfg(any(test, feature = "synthetic-qualification"))]
#[path = "synthetic_fixture.rs"]
mod synthetic_fixture;

#[cfg(feature = "synthetic-qualification")]
pub use synthetic_fixture::SyntheticContributionFixture;

#[cfg(any(test, feature = "synthetic-qualification"))]
#[path = "qualification.rs"]
mod qualification;

#[cfg(feature = "protected-sync")]
#[path = "protected_sync.rs"]
pub mod protected_sync;

#[cfg(all(test, feature = "protected-sync", feature = "synthetic-qualification"))]
#[path = "../tests/support/mod.rs"]
mod sync_test_support;

/// Public synthetic ciphertext from a fabricated NU7 block. Never funded and never
/// evidence of network inclusion; exposed only for cross-crate qualification fixtures.
#[cfg(feature = "synthetic-qualification")]
pub fn synthetic_public_compact_block() -> zcash_client_backend::proto::compact_formats::CompactBlock
{
    qualification::synthetic_wallet().4.0.remove(0)
}

// Synthetic protected-storage boundary tests only. No account, network,
// signing, proof execution, enrollment or live credential is created.
#[cfg(all(test, feature = "encrypted-storage", target_os = "linux"))]
mod internal_name_filter_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wholepact-schema-DedicatedTestnetWallet-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn sqlite_prefix_user_table_and_trigger_cannot_admit_initialization() {
        for trigger in [false, true] {
            let dir = Temp::new();
            let path = dir.0.join("synthetic.sqlite");
            let key = DatabaseKey::from_bytes([0x75; 32]);
            let encrypted = create_encrypted(&path, &key).unwrap();
            encrypted.connection().execute_batch("CREATE TABLE sqliteXextra(value TEXT); INSERT INTO sqliteXextra VALUES('synthetic-preserved');").unwrap();
            if trigger {
                encrypted.connection().execute_batch("CREATE TRIGGER sqliteXtrigger AFTER INSERT ON sqliteXextra BEGIN SELECT 1; END;").unwrap();
            }
            assert!(matches!(
                DedicatedTestnetWallet::from_encrypted_connection(encrypted),
                Err(WalletError::AccountScope)
            ));
            let reopened = open_encrypted(&path, &key).unwrap();
            let c = reopened.connection();
            let app: i64 = c
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .unwrap();
            let version: i64 = c
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!((app, version), (0, 0));
            let preserved: String = c
                .query_row("SELECT value FROM sqliteXextra", [], |r| r.get(0))
                .unwrap();
            assert_eq!(preserved, "synthetic-preserved");
            let initialized: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='accounts')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!initialized);
        }
    }
    #[test]
    fn legitimate_sqlite_internal_objects_allow_initialization_and_exact_reopen() {
        let dir = Temp::new();
        let path = dir.0.join("synthetic.sqlite");
        let key = DatabaseKey::from_bytes([0x76; 32]);
        let encrypted = create_encrypted(&path, &key).unwrap();
        encrypted.connection().execute_batch("ANALYZE;").unwrap();
        let stats: bool = encrypted
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_stat1')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stats);
        let journal = DedicatedTestnetWallet::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = DedicatedTestnetWallet::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
}

// Schema recognition remains available to encrypted backup readers even when
// the opt-in protected-sync importer is not compiled. No runtime is activated.
#[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
#[path = "recorded_import.rs"]
pub mod recorded_import;

// Distinct V2 historical layout, available to backup inspection without enabling
// the opt-in importer. No V1 conversion or wallet-reopen authority is provided.
#[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
#[path = "recorded_roster_import_v2.rs"]
pub mod recorded_roster_import_v2;
