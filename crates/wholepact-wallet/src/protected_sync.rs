//! Encrypted, bounded snapshot scanning and local contribution selection.
//! A matching single-provider snapshot is never unspentness or signing authority.
#[cfg(target_os = "linux")]
#[path = "born_post_return_inputs_v1.rs"]
pub mod born_post_return_inputs_v1;
#[cfg(target_os = "linux")]
#[path = "durable_construction_v1.rs"]
pub mod durable_construction_v1;
#[cfg(target_os = "linux")]
#[path = "durable_exact_selection_v1.rs"]
pub mod durable_exact_selection_v1;
#[cfg(target_os = "linux")]
#[path = "exact_input_observation.rs"]
pub mod exact_input_observation;
#[path = "wallet_key_use.rs"]
pub mod key_use;
#[path = "recovery_scan.rs"]
pub mod recovery;
use super::*;
use serde::Serialize;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub use wholepact_chain::{BackendIdentity, ChainAdapter, ChainContext, NetworkPolicy};
use wholepact_chain::{ChainError, PublicSyncChannel};
pub use zcash_client_backend::proto::service::TreeState;
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange},
};

const BATCH_BLOCKS: u32 = 32;
const MAX_BATCH_ITEMS: usize = 8192;
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

type Client = CompactTxStreamerClient<PublicSyncChannel>;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("local wallet access is not permitted")]
    AccessDenied,
    #[error("invalid bounded wallet sync request")]
    InvalidRequest,
    #[error("wallet scan deadline reached; durable progress may remain")]
    Interrupted,
    #[error("wallet history disagrees with the provider; explicit recovery is required")]
    ReconciliationRequired,
    #[error("provider returned incomplete or malformed wallet scan data")]
    InvalidResponse,
    #[error("wallet scan exceeds the bounded resource policy")]
    ResourceLimit,
    #[error("a current complete local wallet observation is unavailable")]
    NoCurrentObservation,
    #[error(transparent)]
    Wallet(#[from] WalletError),
    #[error(transparent)]
    Chain(#[from] ChainError),
}

#[derive(Clone, Copy)]
pub enum WalletAccessPurpose {
    SynchronizePublicBlocks,
    SelectPrivateContribution,
}
/// Trusted local embedding policy, not an HTTP approval field or default consent UI.
/// The policy must authenticate the account and obtain specific provider/privacy consent.
pub trait LocalWalletAccess {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool;
}

#[derive(Clone, Copy)]
pub struct SyncLimits {
    pub maximum_blocks: u32,
    /// Exact common anchor requested by the local construction workflow. If absent,
    /// use the maintained wallet's latest retained eligible checkpoint, then verify
    /// Ironwood computability and the source root. No requested anchor is substituted.
    pub anchor_height: Option<u32>,
    /// Bounds async waits and is checked between bounded synchronous scan batches.
    /// It cannot preempt a SQLite commit or a currently executing scanner batch.
    pub deadline: Duration,
}
impl Default for SyncLimits {
    fn default() -> Self {
        Self {
            maximum_blocks: 1000,
            anchor_height: None,
            deadline: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    Unobserved,
    Interrupted,
    Partial,
    SnapshotMatched,
    Stale,
    ReconciliationRequired,
}

/// Safe local summary. No FVK, note, address, transaction identifier, balance or witness.
/// It is not accepted back as authority by any method.
#[derive(Serialize)]
pub struct WalletSyncStatus {
    pub phase: SyncPhase,
    pub source: BackendIdentity,
    pub fully_scanned_height: Option<u32>,
    pub provider_tip_height: Option<u32>,
    pub minimum_confirmations: u32,
    pub observation: Option<ChainContext>,
    pub local_selection_context_available: bool,
    pub independently_consensus_verified: bool,
    pub provider_refresh_time_verified: bool,
    pub proves_unspentness: bool,
    pub reserves_inputs: bool,
    pub authorization_allowed: bool,
}

struct AcceptedObservation {
    monotonic_started: Instant,
    chain: ChainContext,
    selection: SelectionContext,
}

/// Non-deserializable private selection plus bounded source provenance. The weak
/// generation token expires on the next sync attempt or controller drop/restart.
/// It is local provenance, not authenticated IPC or an input reservation.
pub struct ProtectedContribution {
    monotonic_started: Instant,
    contribution: WalletContribution,
    observation: ChainContext,
    generation: Weak<()>,
}
/// Local source-lifetime check only. It holds no wallet material and cannot keep a
/// controller generation alive. Useful around a synchronous constructor operation.
pub struct WalletObservationGuard {
    monotonic_started: Instant,
    observation: ChainContext,
    generation: Weak<()>,
}
impl WalletObservationGuard {
    pub fn check_current(&self) -> Result<(), SyncError> {
        if self.generation.upgrade().is_none() {
            return Err(SyncError::NoCurrentObservation);
        }
        self.observation.check_fresh_at(now()?)?;
        check_observation_elapsed(&self.observation, elapsed_since(self.monotonic_started)?)?;
        Ok(())
    }
}
impl ProtectedContribution {
    pub fn check_current(&self) -> Result<(), SyncError> {
        self.observation_guard().check_current()
    }
    pub fn observation_guard(&self) -> WalletObservationGuard {
        WalletObservationGuard {
            monotonic_started: self.monotonic_started,
            observation: self.observation.clone(),
            generation: self.generation.clone(),
        }
    }
    pub fn observation(&self) -> &ChainContext {
        &self.observation
    }
    pub fn selection(&self) -> &WalletContribution {
        &self.contribution
    }
    /// Local-only constructor material. The embedding must separately authenticate
    /// exact disclosure approval before retaining or sending it to another operator.
    pub fn into_current_contribution(
        self,
    ) -> Result<
        (
            wholepact_protocol::construction::OwnedContribution,
            wholepact_protocol::construction::ConstructionContext,
        ),
        SyncError,
    > {
        self.check_current()?;
        let selected = self.contribution.context();
        let context = wholepact_protocol::construction::ConstructionContext {
            anchor: selected.anchor_root,
            anchor_height: selected.anchor_height,
            anchor_block_hash: selected.anchor_hash_protocol,
            target_height: selected
                .tip_height
                .checked_add(1)
                .ok_or(SyncError::InvalidResponse)?,
        };
        Ok((self.contribution.into_contribution(), context))
    }
}

/// Owns an encrypted wallet and the only current selection observation. A caller cannot
/// restore one from a DTO, supply an older observation, or mutate the wallet behind it.
/// Reopening always starts unobserved. Encryption does not establish writer freshness.
pub struct ProtectedWalletSync {
    wallet: DedicatedTestnetWallet,
    account: AccountUuid,
    source: ChainAdapter,
    minimum_confirmations: NonZeroU32,
    phase: SyncPhase,
    accepted: Option<AcceptedObservation>,
    provider_tip_height: Option<u32>,
    generation: Arc<()>,
}
impl ProtectedWalletSync {
    /// Account import/provisioning must already have been separately authorized and
    /// completed through the dedicated wallet. This consumes verified encrypted storage.
    pub fn from_encrypted_connection(
        connection: wholepact_storage_security::EncryptedConnection,
        source: ChainAdapter,
        minimum_confirmations: NonZeroU32,
    ) -> Result<Self, SyncError> {
        let wallet = DedicatedTestnetWallet::from_encrypted_connection(connection)?;
        Self::from_initialized_wallet(wallet, source, minimum_confirmations)
    }
    /// Consume a dedicated wallet just imported through the authenticated encrypted
    /// factory. This preserves its file identity and avoids reopening with raw keys.
    /// It starts unobserved; neither import nor this move approves provider contact.
    pub fn from_initialized_wallet(
        wallet: DedicatedTestnetWallet,
        source: ChainAdapter,
        minimum_confirmations: NonZeroU32,
    ) -> Result<Self, SyncError> {
        #[cfg(target_os = "linux")]
        wallet
            .backup_identity
            .as_ref()
            .ok_or(WalletError::Storage)?
            .check()
            .map_err(|_| WalletError::Storage)?;
        #[cfg(not(target_os = "linux"))]
        return Err(WalletError::Storage.into());
        let ids = wallet
            .db
            .get_account_ids()
            .map_err(|_| WalletError::Storage)?;
        if ids.len() != 1 {
            return Err(WalletError::AccountScope.into());
        }
        Ok(Self {
            account: ids[0],
            wallet,
            source,
            minimum_confirmations,
            phase: SyncPhase::Unobserved,
            accepted: None,
            provider_tip_height: None,
            generation: Arc::new(()),
        })
    }
    pub fn account_uuid(&self) -> AccountUuid {
        self.account
    }
    pub fn status(&self) -> Result<WalletSyncStatus, SyncError> {
        let fresh = self.accepted.as_ref().is_some_and(|o| {
            now().is_ok_and(|t| o.chain.check_fresh_at(t).is_ok())
                && elapsed_since(o.monotonic_started)
                    .is_ok_and(|elapsed| check_observation_elapsed(&o.chain, elapsed).is_ok())
        });
        let phase = if self.accepted.is_some() && !fresh {
            SyncPhase::Stale
        } else {
            self.phase
        };
        Ok(WalletSyncStatus {
            phase,
            source: self.source.identity().clone(),
            fully_scanned_height: self.scanned_height()?,
            provider_tip_height: self.provider_tip_height,
            minimum_confirmations: self.minimum_confirmations.get(),
            observation: self.accepted.as_ref().map(|o| o.chain.clone()),
            local_selection_context_available: fresh && phase == SyncPhase::SnapshotMatched,
            independently_consensus_verified: false,
            provider_refresh_time_verified: false,
            proves_unspentness: false,
            reserves_inputs: false,
            authorization_allowed: false,
        })
    }
    /// Check the signer-owned viewing authority before authorizing any provider
    /// contact for this file. This grants neither scan consent nor key use.
    pub fn verify_account_fvk(&self, expected: &FullViewingKey) -> Result<(), SyncError> {
        let local = self
            .wallet
            .db
            .get_account(self.account)
            .map_err(|_| WalletError::Storage)?
            .ok_or(WalletError::AccountScope)?;
        if local
            .ufvk()
            .and_then(|v| v.orchard())
            .is_none_or(|v| v.to_bytes() != expected.to_bytes())
        {
            return Err(WalletError::AccountMismatch.into());
        }
        Ok(())
    }
    /// Read the actual maintained account birthday and compare its first scan
    /// height. `expected` is the imported checkpoint's prior height plus one.
    /// This makes no provider request and changes no wallet history/observation.
    ///
    /// Height equality alone does not authenticate the prior block hash, tree
    /// frontiers, key disclosure, scan consent or complete account history. A
    /// caller using this for preliminary inventory must separately hold the
    /// concrete current FVK owner and the fresh exact full-checkpoint import
    /// receipt; a reopened wallet cannot infer that provenance from this check.
    pub fn verify_account_birthday_height(&self, expected: u32) -> Result<(), SyncError> {
        let actual = self
            .wallet
            .db
            .get_account_birthday(self.account)
            .map_err(|_| WalletError::Storage)?;
        if u32::from(actual) != expected {
            return Err(WalletError::AccountMismatch.into());
        }
        Ok(())
    }

    /// A native lock, cancellation or permission change may revoke local tickets
    /// without making any network request or rewriting durable scan history.
    pub fn invalidate_observation(&mut self) {
        self.accepted = None;
        self.generation = Arc::new(());
        self.phase = SyncPhase::Unobserved;
        self.provider_tip_height = None;
    }
    /// Fetch only public compact blocks and tree state. Provider contact still discloses
    /// timing, IP and requested height ranges. Each validated batch is independently
    /// committed; errors/cancellation do not roll back prior scanned batches.
    pub async fn synchronize(
        &mut self,
        access: &impl LocalWalletAccess,
        limits: SyncLimits,
    ) -> Result<WalletSyncStatus, SyncError> {
        // This happens before the first await. Dropping the future can never revive an
        // earlier observation. The exclusive mutable borrow prevents concurrent selection.
        self.accepted = None;
        self.generation = Arc::new(());
        self.phase = SyncPhase::Interrupted;
        self.provider_tip_height = None;
        if limits.maximum_blocks == 0
            || limits.maximum_blocks > 1000
            || limits.deadline.is_zero()
            || limits.deadline > Duration::from_secs(600)
        {
            return Err(SyncError::InvalidRequest);
        }
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let result = tokio::time::timeout(limits.deadline, self.synchronize_inner(access, limits))
            .await
            .unwrap_or(Err(SyncError::Interrupted));
        match result {
            Ok(()) => self.status(),
            Err(error) => {
                self.accepted = None;
                if matches!(error, SyncError::ReconciliationRequired) {
                    self.phase = SyncPhase::ReconciliationRequired;
                }
                Err(error)
            }
        }
    }
    async fn synchronize_inner(
        &mut self,
        access: &impl LocalWalletAccess,
        limits: SyncLimits,
    ) -> Result<(), SyncError> {
        self.synchronize_inner_restricted(access, limits, None, |_| Ok(()))
            .await
    }
    // The dedicated retained-input route can only add restrictions to the
    // maintained scanner. Generic synchronization retains its exact behavior.
    async fn synchronize_inner_restricted(
        &mut self,
        access: &impl LocalWalletAccess,
        limits: SyncLimits,
        initial: Option<(Instant, ChainContext)>,
        check_context: impl Fn(&ChainContext) -> Result<(), SyncError>,
    ) -> Result<(), SyncError> {
        let (started, initial) = match initial {
            Some(observed) => observed,
            None => {
                let started = Instant::now();
                (started, self.source.context().await?)
            }
        };
        check_context(&initial)?;
        let tip = u32::try_from(initial.tip().height).map_err(|_| SyncError::InvalidResponse)?;
        if tip == u32::MAX {
            return Err(SyncError::InvalidResponse);
        }
        self.provider_tip_height = Some(tip);
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let channel = self.source.public_sync_channel().await?;
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let mut client = Client::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(1024);
        let scanned = self.scanned_height()?;
        if scanned.is_some_and(|h| h > tip) {
            return Err(SyncError::ReconciliationRequired);
        }
        let birthday = self
            .wallet
            .db
            .get_account_birthday(self.account)
            .map_err(|_| WalletError::Storage)?;
        let mut next = match scanned {
            Some(h) => h.checked_add(1).ok_or(SyncError::InvalidResponse)?,
            None => u32::from(birthday),
        };
        if next == 0 || next < wholepact_chain::NU7_ACTIVATION_HEIGHT as u32 {
            return Err(WalletError::UnsupportedProfile.into());
        }
        let mut provenance = Vec::new();
        // Recheck the last locally scanned block even when no new blocks are needed.
        if let Some(height) = scanned {
            check_context(&initial)?;
            self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
            let response = client
                .get_block(BlockId {
                    height: u64::from(height),
                    hash: vec![],
                })
                .await
                .map_err(|_| SyncError::InvalidResponse)?;
            provenance.push(PublicSyncChannel::cache_observation(
                "GetBlock",
                response.metadata(),
            ));
            let block = response.into_inner();
            if block.height != u64::from(height)
                || block.hash.len() != 32
                || !block.header.is_empty()
            {
                return Err(SyncError::InvalidResponse);
            }
            if self
                .wallet
                .db
                .get_block_hash(height.into())
                .map_err(|_| WalletError::Storage)?
                .map(|h| h.0.to_vec())
                != Some(block.hash)
            {
                return Err(SyncError::ReconciliationRequired);
            }
        }
        let mut remaining = limits.maximum_blocks;
        while next <= tip && remaining > 0 {
            check_context(&initial)?;
            self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
            if started.elapsed() >= limits.deadline {
                return Err(SyncError::Interrupted);
            }
            let count = BATCH_BLOCKS.min(remaining).min(tip - next + 1);
            let end = next + count - 1;
            let tree = client
                .get_tree_state(BlockId {
                    height: u64::from(next - 1),
                    hash: vec![],
                })
                .await
                .map_err(|_| SyncError::InvalidResponse)?;
            provenance.push(PublicSyncChannel::cache_observation(
                "GetTreeState",
                tree.metadata(),
            ));
            let prior = validate_tree(tree.into_inner(), next - 1)?;
            if self
                .wallet
                .db
                .get_block_hash((next - 1).into())
                .map_err(|_| WalletError::Storage)?
                .is_some_and(|hash| hash != prior.block_hash())
            {
                return Err(SyncError::ReconciliationRequired);
            }
            check_context(&initial)?;
            self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
            let response = client
                .get_block_range(BlockRange {
                    start: Some(BlockId {
                        height: u64::from(next),
                        hash: vec![],
                    }),
                    end: Some(BlockId {
                        height: u64::from(end),
                        hash: vec![],
                    }),
                    pool_types: vec![],
                })
                .await
                .map_err(|_| SyncError::InvalidResponse)?;
            provenance.push(PublicSyncChannel::cache_observation(
                "GetBlockRange",
                response.metadata(),
            ));
            let mut stream = response.into_inner();
            let mut blocks = Vec::with_capacity(count as usize);
            while let Some(block) = stream
                .message()
                .await
                .map_err(|_| SyncError::InvalidResponse)?
            {
                if blocks.len() >= count as usize {
                    return Err(SyncError::InvalidResponse);
                }
                blocks.push(block);
            }
            validate_batch(&blocks, &prior, next, count)?;
            if end == tip
                && blocks.last().map(|b| display_hash(&b.hash)).transpose()?
                    != Some(initial.tip().hash.clone())
            {
                return Err(SyncError::ReconciliationRequired);
            }
            self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
            self.wallet
                .scan_cached(&SnapshotBlocks(blocks), &prior, count as usize, tip)?;
            if self.scanned_height()? != Some(end) {
                return Err(WalletError::IncompleteSync.into());
            }
            next = end + 1;
            remaining -= count;
        }
        if started.elapsed() >= limits.deadline {
            return Err(SyncError::Interrupted);
        }
        if self.scanned_height()? != Some(tip) {
            self.phase = SyncPhase::Partial;
            return Ok(());
        }
        // A new bounded observation is obtained after scanning. Equal tips establish
        // provider consistency only, even if every HTTP response reports a cache miss.
        check_context(&initial)?;
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let final_context = self.source.context().await?;
        check_context(&final_context)?;
        if initial.source() != final_context.source() || initial.tip() != final_context.tip() {
            return Err(SyncError::ReconciliationRequired);
        }
        let maximum_anchor = tip
            .checked_add(1)
            .and_then(|h| h.checked_sub(self.minimum_confirmations.get()))
            .ok_or(SyncError::InvalidRequest)?;
        let anchor_height = match limits.anchor_height {
            Some(height) => height,
            None => self
                .wallet
                .db
                .get_target_and_anchor_heights(self.minimum_confirmations)
                .map_err(|_| WalletError::Storage)?
                .map(|(_, h)| u32::from(h))
                .ok_or(WalletError::MissingWitness)?,
        };
        if anchor_height > maximum_anchor {
            return Err(SyncError::InvalidRequest);
        }
        check_context(&final_context)?;
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let anchor = self
            .source
            .ironwood_anchor(&final_context, u64::from(anchor_height))
            .await?;
        // Preserve the earliest request-time clock. A later same-tip check never makes
        // an earlier cached block/tree response newer. Advertised ages only shorten it.
        provenance.extend_from_slice(anchor.context.rpc_cache_observations());
        let chain = initial.with_additional_cache_observations(provenance)?;
        chain.check_fresh_at(now()?)?;
        check_context(&chain)?;
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        if started.elapsed() >= limits.deadline {
            return Err(SyncError::Interrupted);
        }
        let selection = SelectionContext {
            tip_height: tip,
            tip_hash_protocol: protocol_hash(&chain.tip().hash)?,
            anchor_height,
            anchor_hash_protocol: protocol_hash(&anchor.block.hash)?,
            anchor_root: hex::decode(anchor.root_protocol_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or(SyncError::InvalidResponse)?,
        };
        self.wallet
            .check_selection_context(self.minimum_confirmations, &selection)?;
        self.accepted = Some(AcceptedObservation {
            monotonic_started: started,
            chain,
            selection,
        });
        self.phase = SyncPhase::SnapshotMatched;
        Ok(())
    }
    /// Returns sensitive local material only through the independently consented typed
    /// boundary. It reserves nothing and carries no human/signing approval.
    pub fn select_contribution(
        &mut self,
        access: &impl LocalWalletAccess,
        authenticated_fvk: &FullViewingKey,
        accepted_account_id: &str,
        requested_debit_zatoshis: u64,
        exclude: &[ReceivedNoteId],
    ) -> Result<ProtectedContribution, SyncError> {
        self.require_access(access, WalletAccessPurpose::SelectPrivateContribution)?;
        let observed = self
            .accepted
            .as_ref()
            .ok_or(SyncError::NoCurrentObservation)?;
        observed.chain.check_fresh_at(now()?)?;
        check_observation_elapsed(&observed.chain, elapsed_since(observed.monotonic_started)?)?;
        let result = self.wallet.select_contribution(
            self.account,
            authenticated_fvk,
            accepted_account_id,
            requested_debit_zatoshis,
            self.minimum_confirmations,
            &observed.selection,
            exclude,
        )?;
        observed.chain.check_fresh_at(now()?)?;
        check_observation_elapsed(&observed.chain, elapsed_since(observed.monotonic_started)?)?;
        self.require_access(access, WalletAccessPurpose::SelectPrivateContribution)?;
        Ok(ProtectedContribution {
            monotonic_started: observed.monotonic_started,
            contribution: result,
            observation: observed.chain.clone(),
            generation: Arc::downgrade(&self.generation),
        })
    }
    fn scanned_height(&self) -> Result<Option<u32>, SyncError> {
        Ok(self
            .wallet
            .db
            .block_fully_scanned()
            .map_err(|_| WalletError::Storage)?
            .map(|b| u32::from(b.block_height())))
    }
    fn require_access(
        &self,
        access: &impl LocalWalletAccess,
        purpose: WalletAccessPurpose,
    ) -> Result<(), SyncError> {
        if access.permits(self.account, self.source.identity(), purpose) {
            Ok(())
        } else {
            Err(SyncError::AccessDenied)
        }
    }
}

fn now() -> Result<u64, SyncError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ChainError::ClockUnavailable.into())
}
fn display_hash(bytes: &[u8]) -> Result<String, SyncError> {
    if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) {
        return Err(SyncError::InvalidResponse);
    }
    Ok(hex::encode(bytes.iter().rev().copied().collect::<Vec<_>>()))
}
fn protocol_hash(display: &str) -> Result<[u8; 32], SyncError> {
    let mut bytes: [u8; 32] = hex::decode(display)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(SyncError::InvalidResponse)?;
    bytes.reverse();
    Ok(bytes)
}
fn validate_tree(tree: TreeState, expected: u32) -> Result<ChainState, SyncError> {
    if tree.network != "test" || tree.height != u64::from(expected) {
        return Err(SyncError::InvalidResponse);
    }
    protocol_hash(&tree.hash)?;
    for value in [&tree.sapling_tree, &tree.orchard_tree, &tree.ironwood_tree] {
        validate_tree_encoding(value)?;
    }
    tree.to_chain_state()
        .map_err(|_| SyncError::InvalidResponse)
}
/// Parse a bounded explicitly approved birthday checkpoint with the maintained
/// tree parser. The checkpoint is a provider/user claim, not consensus proof.
pub fn account_birthday_from_tree(tree: TreeState) -> Result<AccountBirthday, SyncError> {
    let height = u32::try_from(tree.height).map_err(|_| SyncError::InvalidRequest)?;
    if height < wholepact_chain::NU7_ACTIVATION_HEIGHT as u32 - 1 || height == u32::MAX {
        return Err(SyncError::InvalidRequest);
    }
    let prior = validate_tree(tree, height)?;
    Ok(AccountBirthday::from_parts(prior, None))
}
fn validate_tree_encoding(value: &str) -> Result<(), SyncError> {
    if value.is_empty() || value.len() > 2240 {
        return Err(SyncError::InvalidResponse);
    }
    let bytes = hex::decode(value).map_err(|_| SyncError::InvalidResponse)?;
    fn node(bytes: &[u8], p: &mut usize) -> Result<bool, SyncError> {
        let present = match bytes.get(*p) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(SyncError::InvalidResponse),
        };
        *p += if present { 33 } else { 1 };
        if *p > bytes.len() {
            return Err(SyncError::InvalidResponse);
        }
        Ok(present)
    }
    let mut p = 0;
    let left = node(&bytes, &mut p)?;
    let right = node(&bytes, &mut p)?;
    let count = *bytes.get(p).ok_or(SyncError::InvalidResponse)?;
    if count > 31 {
        return Err(SyncError::InvalidResponse);
    }
    p += 1;
    let mut parent = false;
    for _ in 0..count {
        parent |= node(&bytes, &mut p)?;
    }
    if p != bytes.len() || (!left && (right || parent)) {
        return Err(SyncError::InvalidResponse);
    }
    Ok(())
}
fn validate_batch(
    blocks: &[CompactBlock],
    prior: &ChainState,
    start: u32,
    count: u32,
) -> Result<(), SyncError> {
    if blocks.len() != count as usize
        || count == 0
        || count > BATCH_BLOCKS
        || u32::from(prior.block_height()).checked_add(1) != Some(start)
    {
        return Err(SyncError::InvalidResponse);
    }
    let mut hash = prior.block_hash().0.to_vec();
    let mut sizes = [
        prior.final_sapling_tree().tree_size(),
        prior.final_orchard_tree().tree_size(),
        prior.final_ironwood_tree().tree_size(),
    ];
    let mut items = 0usize;
    for (i, block) in blocks.iter().enumerate() {
        if block.height != u64::from(start) + i as u64
            || block.height >= u64::from(u32::MAX)
            || block.prev_hash != hash
            || !block.header.is_empty()
        {
            return Err(SyncError::InvalidResponse);
        }
        display_hash(&block.hash)?;
        let mut last_index = None;
        let mut indices = BTreeSet::new();
        let mut txids = BTreeSet::new();
        let mut added = [0u64; 3];
        for tx in &block.vtx {
            if tx.txid.len() != 32
                || tx.index > u64::from(u16::MAX)
                || last_index.is_some_and(|index| tx.index <= index)
                || !indices.insert(tx.index)
                || !txids.insert(&tx.txid)
            {
                return Err(SyncError::InvalidResponse);
            }
            last_index = Some(tx.index);
            if tx.spends.iter().any(|s| s.nf.len() != 32)
                || tx.outputs.iter().any(|o| {
                    o.cmu.len() != 32 || o.ephemeral_key.len() != 32 || o.ciphertext.len() != 52
                })
                || tx.actions.iter().chain(&tx.ironwood_actions).any(|a| {
                    a.nullifier.len() != 32
                        || a.cmx.len() != 32
                        || a.ephemeral_key.len() != 32
                        || a.ciphertext.len() != 52
                })
            {
                return Err(SyncError::InvalidResponse);
            }
            added[0] += tx.outputs.len() as u64;
            added[1] += tx.actions.len() as u64;
            added[2] += tx.ironwood_actions.len() as u64;
            items = items
                .checked_add(
                    1 + tx.spends.len()
                        + tx.outputs.len()
                        + tx.actions.len()
                        + tx.ironwood_actions.len()
                        + tx.vin.len()
                        + tx.vout.len(),
                )
                .ok_or(SyncError::ResourceLimit)?;
            if items > MAX_BATCH_ITEMS {
                return Err(SyncError::ResourceLimit);
            }
        }
        let metadata = block
            .chain_metadata
            .as_ref()
            .ok_or(SyncError::InvalidResponse)?;
        let reported = [
            metadata.sapling_commitment_tree_size,
            metadata.orchard_commitment_tree_size,
            metadata.ironwood_commitment_tree_size,
        ];
        for p in 0..3 {
            sizes[p] = sizes[p]
                .checked_add(added[p])
                .filter(|s| *s <= u64::from(u32::MAX))
                .ok_or(SyncError::InvalidResponse)?;
            if sizes[p] != u64::from(reported[p]) {
                return Err(SyncError::InvalidResponse);
            }
        }
        hash.clone_from(&block.hash);
    }
    Ok(())
}
/// Immutable in-memory public batch; scanner's two reads see identical bytes.
struct SnapshotBlocks(Vec<CompactBlock>);
impl BlockSource for SnapshotBlocks {
    type Error = std::convert::Infallible;
    fn with_blocks<F, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        mut f: F,
    ) -> Result<(), chain::error::Error<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), chain::error::Error<E, Self::Error>>,
    {
        for b in self
            .0
            .iter()
            .filter(|b| from.is_none_or(|h| b.height >= u64::from(u32::from(h))))
            .take(limit.unwrap_or(usize::MAX))
        {
            f(b.clone())?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "protected_sync_tests.rs"]
mod tests;

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "protected_sync_contact_tests.rs"]
mod contact_tests;

// A process-local monotonic bound complements wallclock freshness. A backwards
// clock adjustment must never extend an accepted generation's useful lifetime.
fn elapsed_since(started: Instant) -> Result<Duration, SyncError> {
    Instant::now()
        .checked_duration_since(started)
        .ok_or(SyncError::NoCurrentObservation)
}

fn check_observation_elapsed(observed: &ChainContext, elapsed: Duration) -> Result<(), SyncError> {
    let lifetime = observed
        .valid_until_unix_seconds()
        .checked_sub(observed.request_started_at_unix_seconds())
        .ok_or(SyncError::NoCurrentObservation)?;
    if elapsed > Duration::from_secs(lifetime) {
        return Err(SyncError::NoCurrentObservation);
    }
    Ok(())
}
