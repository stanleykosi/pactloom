//! Never-funded synthetic recipient for the joined born fixture only.
//! Retains only zeroizing viewing bytes, never exports a private key/FVK, and
//! reports maintained local decryption on explicitly fabricated blocks. It does
//! not issue authority or prove public-network inclusion/consensus/finality.
use super::synthetic_born_receiver_blocks_v1::SyntheticBornReceiverBlocksV1;
use super::{AccountBirthday, DedicatedTestnetWallet, SelectionContext, WalletError};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    tree::MerkleHashOrchard,
};
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
use serde::Serialize;
use std::{convert::Infallible, io::Cursor, num::NonZeroU32};
use wholepact_storage_security::EncryptedConnection;
use zcash_client_backend::{
    data_api::chain::{self, BlockSource, ChainState},
    proto::compact_formats::{ChainMetadata, CompactBlock, CompactTx},
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxVersion},
};
use zcash_protocol::consensus::{BlockHeight, BranchId, TEST_NETWORK};
use zeroize::Zeroizing;

/// Created once before the actual born policies; its public receiver must remain
/// unchanged through the agreement, final transaction and receipt. No Clone,
/// serialization or private-material getter is provided.
pub struct SyntheticBornPaymentRecipientV1 {
    viewing_bytes: Zeroizing<[u8; 96]>,
    receiver: String,
}
impl SyntheticBornPaymentRecipientV1 {
    pub fn new() -> Result<Self, WalletError> {
        let mut seed = Zeroizing::new([0u8; 64]);
        UnwrapErr(SysRng).fill_bytes(&mut *seed);
        let key = SpendingKey::from_zip32_seed(
            &*seed,
            1,
            0u32.try_into().map_err(|_| WalletError::InvalidRequest)?,
        )
        .map_err(|_| WalletError::InvalidRequest)?;
        let fvk = FullViewingKey::from(&key);
        let receiver = wholepact_protocol::review::encode_testnet_receiver(
            &fvk.address_at(0u32, Scope::External),
        );
        // This observer retains no spending authority. The maintained key and
        // seed drop here; only opaque viewing bytes survive until receipt/drop.
        Ok(Self {
            viewing_bytes: Zeroizing::new(fvk.to_bytes()),
            receiver,
        })
    }
    pub fn public_receive_address(&self) -> &str {
        &self.receiver
    }

    /// Call only with bytes actually received by the armed synthetic sink. The
    /// caller separately establishes that sink's genuine retained predecessor.
    /// This method makes no network request and has no authority semantics.
    /// The connection must be a fresh encrypted DB owned by the caller's bounded
    /// test TempDir; the caller retains cleanup ownership through this call.
    pub fn scan_received(
        &self,
        connection: EncryptedConnection,
        original_public_blocks: &SyntheticBornReceiverBlocksV1,
        received_wire: &[u8],
        expected_zatoshis: u64,
        required_confirmations: NonZeroU32,
    ) -> Result<SyntheticBornRecipientReceiptV1, WalletError> {
        if received_wire.is_empty()
            || received_wire.len() > 2 * 1024 * 1024
            || expected_zatoshis == 0
            || expected_zatoshis > super::MAX_MONEY
            || required_confirmations.get() > 32
        {
            return Err(WalletError::InvalidRequest);
        }
        let mut cursor = Cursor::new(received_wire);
        let tx = Transaction::read(&mut cursor, BranchId::Nu7)
            .map_err(|_| WalletError::InvalidRequest)?;
        let mut canonical = Vec::new();
        tx.write(&mut canonical)
            .map_err(|_| WalletError::InvalidRequest)?;
        if cursor.position() != received_wire.len() as u64
            || canonical != received_wire
            || tx.version() != TxVersion::V6
            || tx.consensus_branch_id() != BranchId::Nu7
            || tx.transparent_bundle().is_some()
            || tx.sprout_bundle().is_some()
            || tx.sapling_bundle().is_some()
            || tx.orchard_bundle().is_some()
        {
            return Err(WalletError::UnsupportedProfile);
        }
        let bundle = tx.ironwood_bundle().ok_or(WalletError::InvalidRequest)?;
        let mut blocks = original_public_blocks.blocks().to_vec();
        let last = blocks.last().ok_or(WalletError::InvalidRequest)?;
        let first_height = u32::try_from(last.height)
            .ok()
            .and_then(|h| h.checked_add(1))
            .ok_or(WalletError::InvalidRequest)?;
        let tip_height = first_height
            .checked_add(required_confirmations.get() - 1)
            .ok_or(WalletError::InvalidRequest)?;
        if first_height >= u32::from(tx.expiry_height())
            || BranchId::for_height(&TEST_NETWORK, tip_height.into()) != BranchId::Nu7
        {
            return Err(WalletError::UnsupportedProfile);
        }
        let mut previous: [u8; 32] = last
            .hash
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::InvalidRequest)?;
        let last_tree = original_public_blocks
            .trees()
            .last()
            .ok_or(WalletError::InvalidRequest)?;
        let tree_bytes =
            hex::decode(&last_tree.ironwood_tree).map_err(|_| WalletError::InvalidRequest)?;
        let mut tree_reader = Cursor::new(tree_bytes.as_slice());
        let mut tree: CommitmentTree<MerkleHashOrchard, 32> =
            zcash_primitives::merkle_tree::read_commitment_tree(&mut tree_reader)
                .map_err(|_| WalletError::MissingWitness)?;
        if tree_reader.position() != tree_bytes.len() as u64 {
            return Err(WalletError::InvalidRequest);
        }
        for action in bundle.actions().iter() {
            tree.append(MerkleHashOrchard::from_cmx(action.cmx()))
                .map_err(|_| WalletError::MissingWitness)?;
        }
        let actions = bundle.actions().iter().map(Into::into).collect::<Vec<_>>();
        let tree_size = u32::try_from(tree.size()).map_err(|_| WalletError::InvalidRequest)?;
        let mut first_hash = [0u8; 32];
        for offset in 0..required_confirmations.get() {
            let hash = loop {
                let mut hash = [0u8; 32];
                UnwrapErr(SysRng).fill_bytes(&mut hash);
                if hash != [0; 32] && !blocks.iter().any(|block| block.hash.as_slice() == hash) {
                    break hash;
                }
            };
            if offset == 0 {
                first_hash = hash;
            }
            blocks.push(CompactBlock {
                height: u64::from(first_height + offset),
                hash: hash.to_vec(),
                prev_hash: previous.to_vec(),
                time: original_public_blocks.spec().timestamp,
                vtx: if offset == 0 {
                    vec![CompactTx {
                        txid: tx.txid().as_ref().to_vec(),
                        ironwood_actions: actions.clone(),
                        ..Default::default()
                    }]
                } else {
                    Vec::new()
                },
                chain_metadata: Some(ChainMetadata {
                    sapling_commitment_tree_size: 0,
                    orchard_commitment_tree_size: 0,
                    ironwood_commitment_tree_size: tree_size,
                }),
                ..Default::default()
            });
            previous = hash;
        }
        let context = SelectionContext {
            tip_height,
            tip_hash_protocol: previous,
            anchor_height: first_height,
            anchor_hash_protocol: first_hash,
            anchor_root: orchard::Anchor::from(tree.root()).to_bytes(),
        };
        let original = original_public_blocks.spec();
        let prior = ChainState::empty(
            original.prior_height.into(),
            BlockHash(original.prior_hash_protocol),
        );
        let fvk =
            FullViewingKey::from_bytes(&self.viewing_bytes).ok_or(WalletError::InvalidRequest)?;
        if wholepact_protocol::review::encode_testnet_receiver(
            &fvk.address_at(0u32, Scope::External),
        ) != self.receiver
        {
            return Err(WalletError::AccountScope);
        }
        let mut wallet = DedicatedTestnetWallet::from_encrypted_connection(connection)?;
        let account =
            wallet.import_dedicated_fvk(&fvk, AccountBirthday::from_parts(prior.clone(), None))?;
        let count = blocks.len();
        wallet.scan_cached(&ReceiptBlocks(blocks), &prior, count, tip_height)?;
        let selected = wallet.select_contribution(
            account,
            &fvk,
            "synthetic-born-payment-recipient",
            expected_zatoshis,
            required_confirmations,
            &context,
            &[],
        )?;
        let prefix = format!("ironwood:{}:", tx.txid());
        let own = selected
            .notes()
            .iter()
            .filter(|note| {
                note.input_id.starts_with(&prefix)
                    && note.note.recipient() == fvk.address_at(0u32, Scope::External)
            })
            .collect::<Vec<_>>();
        let value = own
            .iter()
            .try_fold(0u64, |sum, note| sum.checked_add(note.note.value().inner()))
            .ok_or(WalletError::InvalidRequest)?;
        if own.len() != 1
            || value != expected_zatoshis
            || selected.selected_zatoshis() != expected_zatoshis
        {
            return Err(WalletError::InvalidRequest);
        }
        Ok(SyntheticBornRecipientReceiptV1 {
            transaction_id: tx.txid().to_string(),
            recipient_address: self.receiver.clone(),
            decrypted_zatoshis: value,
            owned_note_count: own.len(),
            fabricated_inclusion_height: first_height,
            fabricated_tip_height: tip_height,
            required_confirmations: required_confirmations.get(),
            public_network_inclusion_verified: false,
            independent_consensus_verified: false,
            evidence_kind: "maintained_recipient_decryption_on_fabricated_joined_fixture_blocks",
        })
    }
}

#[derive(Serialize)]
pub struct SyntheticBornRecipientReceiptV1 {
    pub transaction_id: String,
    pub recipient_address: String,
    pub decrypted_zatoshis: u64,
    pub owned_note_count: usize,
    pub fabricated_inclusion_height: u32,
    pub fabricated_tip_height: u32,
    pub required_confirmations: u32,
    pub public_network_inclusion_verified: bool,
    pub independent_consensus_verified: bool,
    pub evidence_kind: &'static str,
}
struct ReceiptBlocks(Vec<CompactBlock>);
impl BlockSource for ReceiptBlocks {
    type Error = Infallible;
    fn with_blocks<F, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        mut callback: F,
    ) -> Result<(), chain::error::Error<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain::error::Error<E, Self::Error>>,
    {
        for block in self
            .0
            .iter()
            .filter(|b| from.is_none_or(|h| b.height >= u64::from(u32::from(h))))
            .take(limit.unwrap_or(usize::MAX))
        {
            callback(block.clone())?;
        }
        Ok(())
    }
}
