//! Fabricated, never-funded public blocks for the joined born-account fixture.
//! The callers supply only public receivers of their ACTUAL acknowledged born
//! accounts. No private key, FVK, account factory or native authority enters
//! this builder. Nothing here is consensus or network-inclusion evidence.

use super::{SelectionContext, WalletError};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
use std::collections::BTreeSet;
pub use zcash_client_backend::proto::{
    compact_formats::{ChainMetadata, CompactBlock, CompactTx},
    service::{BlockId, BlockRange, Empty, LightdInfo, RawTransaction, SendResponse, TreeState},
};
use zcash_protocol::consensus::{BranchId, TEST_NETWORK};

/// Public fixture parameters, not a provider observation or import capability.
/// The caller must select these same public prior height/hash facts in the
/// genuine Host inventory/import birthday flow; signer birth assigns neither.
#[derive(Clone, Copy)]
pub struct SyntheticBornChainSpecV1 {
    pub prior_height: u32,
    pub prior_hash_protocol: [u8; 32],
    pub block_count: u32,
    pub timestamp: u32,
}

/// Complete finite fabricated block/tree response material. The two encrypted
/// outputs are addressed to the supplied actual born PUBLIC receivers, not to
/// new unrelated fixture owners. There is no spending material in this type.
#[derive(Clone)]
pub struct SyntheticBornReceiverBlocksV1 {
    spec: SyntheticBornChainSpecV1,
    blocks: Vec<CompactBlock>,
    trees: Vec<TreeState>,
    context: SelectionContext,
    funding_input_ids: [String; 2],
}

impl SyntheticBornReceiverBlocksV1 {
    pub fn build(
        receivers: [&str; 2],
        values_zatoshis: [u64; 2],
        spec: SyntheticBornChainSpecV1,
    ) -> Result<Self, WalletError> {
        let first_height = spec
            .prior_height
            .checked_add(1)
            .ok_or(WalletError::InvalidRequest)?;
        let tip_height = spec
            .prior_height
            .checked_add(spec.block_count)
            .ok_or(WalletError::InvalidRequest)?;
        if !(1..=32).contains(&spec.block_count)
            || spec.timestamp == 0
            || spec.prior_hash_protocol == [0; 32]
            || BranchId::for_height(&TEST_NETWORK, first_height.into()) != BranchId::Nu7
            || BranchId::for_height(&TEST_NETWORK, tip_height.into()) != BranchId::Nu7
            || values_zatoshis
                .iter()
                .any(|v| *v == 0 || *v > super::MAX_MONEY)
            || values_zatoshis[0]
                .checked_add(values_zatoshis[1])
                .is_none_or(|sum| sum > super::MAX_MONEY)
        {
            return Err(WalletError::InvalidRequest);
        }
        let first = wholepact_protocol::review::decode_testnet_receiver(receivers[0])
            .map_err(|_| WalletError::InvalidRequest)?;
        let second = wholepact_protocol::review::decode_testnet_receiver(receivers[1])
            .map_err(|_| WalletError::InvalidRequest)?;
        if first == second {
            return Err(WalletError::InvalidRequest);
        }
        let version = orchard::bundle::BundleVersion::ironwood_v3();
        let mut builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            version,
            version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .map_err(|_| WalletError::InvalidRequest)?;
        for (receiver, value) in [first, second].into_iter().zip(values_zatoshis) {
            builder
                .add_output(
                    None,
                    receiver,
                    orchard::value::NoteValue::from_raw(value),
                    zcash_protocol::memo::MemoBytes::empty().into_bytes(),
                )
                .map_err(|_| WalletError::InvalidRequest)?;
        }
        // Maintained encryption/commitments only. This fabricated incoming
        // funding block is deliberately NOT proved or submitted to a network.
        let (bundle, metadata) = builder
            .build::<i64>(UnwrapErr(SysRng))
            .map_err(|_| WalletError::InvalidRequest)?
            .ok_or(WalletError::InvalidRequest)?;
        let mut funding_txid = [0; 32];
        UnwrapErr(SysRng).fill_bytes(&mut funding_txid);
        let displayed_txid = zcash_protocol::TxId::from_bytes(funding_txid);
        let mut funding_input_ids = [String::new(), String::new()];
        for (receiver_index, input_id) in funding_input_ids.iter_mut().enumerate() {
            let action = metadata
                .output_action_index(receiver_index)
                .ok_or(WalletError::InvalidRequest)?;
            if action >= bundle.actions().len() {
                return Err(WalletError::InvalidRequest);
            }
            *input_id = format!("ironwood:{displayed_txid}:{action}");
        }
        if funding_input_ids[0] == funding_input_ids[1] {
            return Err(WalletError::InvalidRequest);
        }
        let actions = bundle.actions().iter().map(Into::into).collect::<Vec<_>>();
        let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        for action in bundle.actions().iter() {
            tree.append(MerkleHashOrchard::from_cmx(action.cmx()))
                .map_err(|_| WalletError::MissingWitness)?;
        }
        let anchor_root = orchard::Anchor::from(tree.root()).to_bytes();
        let mut tree_bytes = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree(&tree, &mut tree_bytes)
            .map_err(|_| WalletError::MissingWitness)?;
        let encoded_tree = encode_hex(&tree_bytes);
        let action_count = u32::try_from(actions.len()).map_err(|_| WalletError::InvalidRequest)?;
        let mut hashes = BTreeSet::from([spec.prior_hash_protocol]);
        let mut previous = spec.prior_hash_protocol;
        let mut blocks = Vec::new();
        let mut trees = vec![TreeState {
            network: "test".into(),
            height: u64::from(spec.prior_height),
            hash: display_hash(&spec.prior_hash_protocol),
            time: spec.timestamp,
            sapling_tree: "000000".into(),
            orchard_tree: "000000".into(),
            ironwood_tree: "000000".into(),
        }];
        for offset in 0..spec.block_count {
            let hash = loop {
                let mut bytes = [0; 32];
                UnwrapErr(SysRng).fill_bytes(&mut bytes);
                if bytes != [0; 32] && hashes.insert(bytes) {
                    break bytes;
                }
            };
            let height = first_height + offset;
            let transactions = if offset == 0 {
                vec![CompactTx {
                    txid: funding_txid.to_vec(),
                    ironwood_actions: actions.clone(),
                    ..Default::default()
                }]
            } else {
                Vec::new()
            };
            blocks.push(CompactBlock {
                height: u64::from(height),
                hash: hash.to_vec(),
                prev_hash: previous.to_vec(),
                time: spec.timestamp,
                vtx: transactions,
                chain_metadata: Some(ChainMetadata {
                    sapling_commitment_tree_size: 0,
                    orchard_commitment_tree_size: 0,
                    ironwood_commitment_tree_size: action_count,
                }),
                ..Default::default()
            });
            trees.push(TreeState {
                network: "test".into(),
                height: u64::from(height),
                hash: display_hash(&hash),
                time: spec.timestamp,
                sapling_tree: "000000".into(),
                orchard_tree: "000000".into(),
                ironwood_tree: encoded_tree.clone(),
            });
            previous = hash;
        }
        Ok(Self {
            spec,
            funding_input_ids,
            context: SelectionContext {
                tip_height,
                tip_hash_protocol: previous,
                anchor_height: first_height,
                anchor_hash_protocol: blocks[0]
                    .hash
                    .clone()
                    .try_into()
                    .map_err(|_| WalletError::InvalidRequest)?,
                anchor_root,
            },
            blocks,
            trees,
        })
    }

    /// Public fabricated funding outpoints in the original receiver order,
    /// obtained from the maintained builder's actual shuffled output mapping.
    /// No FVK, note secret, ownership authority or real-chain claim is returned.
    pub fn public_funding_input_ids(&self) -> &[String; 2] {
        &self.funding_input_ids
    }
    pub fn spec(&self) -> SyntheticBornChainSpecV1 {
        self.spec
    }
    pub fn blocks(&self) -> &[CompactBlock] {
        &self.blocks
    }
    /// Includes the exact empty prior birthday tree followed by every block.
    pub fn trees(&self) -> &[TreeState] {
        &self.trees
    }
    /// Inert fabricated selection facts, never authenticated chain evidence.
    pub fn fabricated_context(&self) -> &SelectionContext {
        &self.context
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn display_hash(bytes: &[u8; 32]) -> String {
    encode_hex(&bytes.iter().rev().copied().collect::<Vec<_>>())
}

/// One never-funded public payment destination for the joined fixture's exact
/// policy. Generate ONCE before enrollment and reuse that public string through
/// the proposal. No wallet/account is created and no spending/FVK material is
/// returned or persisted. This cannot prove recipient control or receipt.
#[cfg(feature = "protected-sync")]
pub fn synthetic_payment_receiver_v1() -> String {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    let key = loop {
        let mut bytes = zeroize::Zeroizing::new([0; 32]);
        UnwrapErr(SysRng).fill_bytes(&mut *bytes);
        if let Some(key) = Option::<SpendingKey>::from(SpendingKey::from_bytes(*bytes)) {
            break key;
        }
    };
    let fvk = FullViewingKey::from(&key);
    wholepact_protocol::review::encode_testnet_receiver(&fvk.address_at(0u32, Scope::External))
}

/// Bounded serialization of the already-built PUBLIC fixture only. Reopening
/// never calls the randomized builder and cannot create wallet or chain authority.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedPublicBlocksV1 {
    version: u32,
    prior_height: u32,
    prior_hash: [u8; 32],
    block_count: u32,
    timestamp: u32,
    blocks: Vec<Vec<u8>>,
    trees: Vec<Vec<u8>>,
    tip_height: u32,
    tip_hash: [u8; 32],
    anchor_height: u32,
    anchor_hash: [u8; 32],
    anchor_root: [u8; 32],
    funding_input_ids: [String; 2],
}
impl SyntheticBornReceiverBlocksV1 {
    pub fn preserve_public_original_v1(&self) -> Result<Vec<u8>, WalletError> {
        use prost::Message;
        let saved = PreservedPublicBlocksV1 {
            version: 1,
            prior_height: self.spec.prior_height,
            prior_hash: self.spec.prior_hash_protocol,
            block_count: self.spec.block_count,
            timestamp: self.spec.timestamp,
            blocks: self.blocks.iter().map(Message::encode_to_vec).collect(),
            trees: self.trees.iter().map(Message::encode_to_vec).collect(),
            tip_height: self.context.tip_height,
            tip_hash: self.context.tip_hash_protocol,
            anchor_height: self.context.anchor_height,
            anchor_hash: self.context.anchor_hash_protocol,
            anchor_root: self.context.anchor_root,
            funding_input_ids: self.funding_input_ids.clone(),
        };
        let bytes = serde_json::to_vec(&saved).map_err(|_| WalletError::InvalidRequest)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(WalletError::InvalidRequest);
        }
        Ok(bytes)
    }
    pub fn reopen_public_original_v1(bytes: &[u8]) -> Result<Self, WalletError> {
        use prost::Message;
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err(WalletError::InvalidRequest);
        }
        let saved: PreservedPublicBlocksV1 =
            serde_json::from_slice(bytes).map_err(|_| WalletError::InvalidRequest)?;
        if saved.version != 1
            || !(1..=32).contains(&saved.block_count)
            || saved.blocks.len() != saved.block_count as usize
            || saved.trees.len() != saved.blocks.len() + 1
            || saved.prior_height.checked_add(saved.block_count) != Some(saved.tip_height)
            || saved.prior_height.checked_add(1) != Some(saved.anchor_height)
            || saved.timestamp == 0
            || saved.prior_hash == [0; 32]
            || saved
                .funding_input_ids
                .iter()
                .any(|v| v.is_empty() || v.len() > 128)
            || saved.funding_input_ids[0] == saved.funding_input_ids[1]
        {
            return Err(WalletError::InvalidRequest);
        }
        let mut blocks = Vec::new();
        for encoded in &saved.blocks {
            if encoded.len() > 1024 * 1024 {
                return Err(WalletError::InvalidRequest);
            }
            let block = CompactBlock::decode(encoded.as_slice())
                .map_err(|_| WalletError::InvalidRequest)?;
            if block.encode_to_vec() != *encoded {
                return Err(WalletError::InvalidRequest);
            }
            blocks.push(block);
        }
        let mut trees = Vec::new();
        for encoded in &saved.trees {
            if encoded.len() > 1024 * 1024 {
                return Err(WalletError::InvalidRequest);
            }
            let tree =
                TreeState::decode(encoded.as_slice()).map_err(|_| WalletError::InvalidRequest)?;
            if tree.encode_to_vec() != *encoded {
                return Err(WalletError::InvalidRequest);
            }
            trees.push(tree);
        }
        let mut previous = saved.prior_hash.to_vec();
        for (index, block) in blocks.iter().enumerate() {
            if block.height != u64::from(saved.anchor_height) + index as u64
                || block.prev_hash != previous
                || block.hash.len() != 32
                || trees[index + 1].height != block.height
                || trees[index + 1].hash
                    != display_hash(
                        &block
                            .hash
                            .clone()
                            .try_into()
                            .map_err(|_| WalletError::InvalidRequest)?,
                    )
            {
                return Err(WalletError::InvalidRequest);
            }
            previous = block.hash.clone();
        }
        if blocks.first().map(|b| b.hash.as_slice()) != Some(saved.anchor_hash.as_slice())
            || previous != saved.tip_hash
            || trees[0].height != u64::from(saved.prior_height)
            || trees[0].hash != display_hash(&saved.prior_hash)
        {
            return Err(WalletError::InvalidRequest);
        }
        let result = Self {
            spec: SyntheticBornChainSpecV1 {
                prior_height: saved.prior_height,
                prior_hash_protocol: saved.prior_hash,
                block_count: saved.block_count,
                timestamp: saved.timestamp,
            },
            blocks,
            trees,
            context: SelectionContext {
                tip_height: saved.tip_height,
                tip_hash_protocol: saved.tip_hash,
                anchor_height: saved.anchor_height,
                anchor_hash_protocol: saved.anchor_hash,
                anchor_root: saved.anchor_root,
            },
            funding_input_ids: saved.funding_input_ids,
        };
        if result.preserve_public_original_v1()? != bytes {
            return Err(WalletError::InvalidRequest);
        }
        Ok(result)
    }
}
