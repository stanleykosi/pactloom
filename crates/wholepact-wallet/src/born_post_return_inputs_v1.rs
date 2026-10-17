//! Fresh post-return observation of an existing born wallet. No old construction
//! material/ticket is consumed or renewed, and no signing capability is issued.
//! Native embedding ownership is mandatory; serialized scopes are only data.
use super::*;
pub use orchard::keys::FullViewingKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2;
use zcash_client_backend::wallet::Note as WalletNote;
use zcash_protocol::TxId;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BornPostReturnInputV1 {
    pub input_id: String,
    pub nullifier: String,
    pub value_zatoshis: u64,
    pub action_index: usize,
}
/// Exact inert disclosure facts derived by the native Host from its opaque
/// retained checkpoint and final transaction, never from an incoming status DTO.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BornPostReturnWalletScopeV1 {
    pub checkpoint_binding_digest: String,
    pub final_transaction_digest: String,
    pub final_transaction_id: String,
    pub final_effects_digest: String,
    pub transaction_expiry_height: u32,
    pub all_inputs: Vec<BornPostReturnInputV1>,
    pub own_inputs: Vec<BornPostReturnInputV1>,
    pub import_scope: ManualRosterInventoryScopeV2,
    pub wallet_origin_digest: String,
    pub provider_read_profile: wholepact_chain::public_read_profile_v1::PublicReadProfileV1,
    pub anchor_height: u32,
    pub anchor_hash: [u8; 32],
    pub anchor_root: [u8; 32],
    pub original_ancestry: Vec<(u32, [u8; 32])>,
    pub maximum_tip_height: u32,
    pub minimum_confirmations: u32,
    pub minimum_expiry_margin_blocks: u32,
    pub maximum_scan_runtime_ms: u64,
    pub native_observation_expires_at_ms: u64,
}
impl BornPostReturnWalletScopeV1 {
    pub fn validate(&self) -> Result<(), BornPostReturnErrorV1> {
        self.import_scope
            .validate()
            .map_err(|_| BornPostReturnErrorV1::Binding)?;
        let s = self;
        let provider = &s.import_scope.inventory.provider;
        let profile = &s.provider_read_profile;
        if profile.backend.source_id != provider.source_id
            || profile.backend.endpoint != provider.endpoint
            || profile.backend.trust_profile != provider.trust_profile
            || !profile.destination_tls_native_roots
            || !(1..=30_000).contains(&profile.request_timeout_ms)
            || profile.retries > 2
            || !(1..=60_000).contains(&profile.observation_ttl_ms)
        {
            return Err(BornPostReturnErrorV1::Binding);
        }

        for hash in [
            &s.checkpoint_binding_digest,
            &s.final_transaction_digest,
            &s.final_transaction_id,
            &s.final_effects_digest,
            &s.wallet_origin_digest,
        ] {
            decode_hash(hash)?;
        }
        if s.all_inputs.is_empty()
            || s.all_inputs.len() > 8
            || s.own_inputs.is_empty()
            || s.own_inputs.len() > 8
            || s.original_ancestry.is_empty()
            || s.original_ancestry.len() > 8
            || s.anchor_height == 0
            || s.anchor_root == [0; 32]
            || s.anchor_hash == [0; 32]
            || s.minimum_confirmations == 0
            || s.minimum_confirmations > 100
            || !(1..=100).contains(&s.minimum_expiry_margin_blocks)
            || !(1..=30_000).contains(&s.maximum_scan_runtime_ms)
            || s.native_observation_expires_at_ms == 0
            || s.transaction_expiry_height >= 500_000_000
            || s.maximum_tip_height
                .checked_add(s.minimum_expiry_margin_blocks)
                .is_none_or(|h| h > s.transaction_expiry_height)
        {
            return Err(BornPostReturnErrorV1::Binding);
        }
        let mut total = 0u64;
        let mut ids = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut actions = BTreeSet::new();
        for input in &s.all_inputs {
            total = total
                .checked_add(input.value_zatoshis)
                .filter(|v| *v <= wholepact_core::MAX_MONEY)
                .ok_or(BornPostReturnErrorV1::Binding)?;
            parse_outpoint(&input.input_id)?;
            if input.value_zatoshis == 0
                || input.value_zatoshis > wholepact_core::MAX_MONEY
                || input.action_index >= 8
                || !ids.insert(&input.input_id)
                || !nullifiers.insert(decode_hash(&input.nullifier)?)
                || !actions.insert(input.action_index)
            {
                return Err(BornPostReturnErrorV1::Binding);
            }
        }
        let mut own = BTreeSet::new();
        for input in &s.own_inputs {
            if !s.all_inputs.contains(input) || !own.insert(&input.input_id) {
                return Err(BornPostReturnErrorV1::Binding);
            }
        }
        let mut heights = BTreeSet::new();
        for (height, hash) in &s.original_ancestry {
            if !heights.insert(*height)
                || *hash == [0; 32]
                || *height < s.anchor_height
                || *height > s.maximum_tip_height
            {
                return Err(BornPostReturnErrorV1::Binding);
            }
        }
        let original_tip = s.original_ancestry.iter().map(|(h, _)| *h).max().unwrap();
        if s.maximum_tip_height - original_tip > 1000
            || s.anchor_height > original_tip
            || BranchId::for_height(&TEST_NETWORK, s.transaction_expiry_height.into())
                != BranchId::Nu7
        {
            return Err(BornPostReturnErrorV1::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, BornPostReturnErrorV1> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:born-post-return-wallet-scope:v1",
            self,
        )
        .map_err(|_| BornPostReturnErrorV1::Binding)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BornPostReturnErrorV1 {
    #[error("fresh exact born post-return native permission is unavailable")]
    Permission,
    #[error("retained checkpoint, wallet import, exact inputs or final transaction disagree")]
    Binding,
    #[error("post-return wallet lock, authenticated identity or storage failed")]
    Storage,
    #[error("post-return wallet or source state changed; retain authorization exposure")]
    StateChanged,
    #[error("post-return observation expired or lacks the approved transaction runway")]
    Expired,
    #[error("restored wallet requires recovery before post-return validation")]
    RecoveryRequired,
    #[error(transparent)]
    Sync(#[from] SyncError),
}
impl From<WalletError> for BornPostReturnErrorV1 {
    fn from(e: WalletError) -> Self {
        Self::Sync(e.into())
    }
}
/// Trusted native embedding boundary, not an HTTP approval field. Production
/// implements this privately using the actual checkpoint, registered files,
/// current Host generation and fresh foreground disclosure/revocation owner.
pub trait BornPostReturnReadPermissionV1 {
    fn scope(&self) -> &BornPostReturnWalletScopeV1;
    fn authenticated_fvk(&self) -> &FullViewingKey;
    fn check_current(&self) -> Result<(), BornPostReturnErrorV1>;
    fn monotonic_deadline(&self) -> Instant;
}

/// Non-Clone, non-Deserialize scanner result. It cannot supply selection,
/// construction, signing, input reservation or dispatch authority. Current note
/// state is usable ONLY inside `with_born_post_return_inputs_v1` below.
pub struct FreshBornPostReturnInputsV1<'native> {
    permission: &'native dyn BornPostReturnReadPermissionV1,
    scope_digest: String,
    observation: ChainContext,
    current: SelectionContext,
    started: Instant,
    deadline: Instant,
    generation: Weak<()>,
    account: AccountUuid,
    digest: String,
    observed_at_ms: u64,
    expires_at_ms: u64,
    lock_attempted: std::cell::Cell<bool>,
}
impl FreshBornPostReturnInputsV1<'_> {
    pub fn check_current(&self) -> Result<(), BornPostReturnErrorV1> {
        self.permission.check_current()?;
        let now = now_ms()?;
        if self.generation.upgrade().is_none()
            || Instant::now() >= self.permission.monotonic_deadline()
            || Instant::now() >= self.deadline
            || now < self.observed_at_ms
            || now >= self.expires_at_ms
            || self.permission.scope().digest()? != self.scope_digest
        {
            return Err(BornPostReturnErrorV1::Expired);
        }
        self.observation
            .check_fresh_at(now / 1000)
            .map_err(SyncError::from)?;
        check_observation_elapsed(&self.observation, elapsed_since(self.started)?)?;
        check_tip(self.permission.scope(), &self.observation)?;
        Ok(())
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// Immutable restriction-only cutoff captured from the original native and
    /// provider observation bounds. Reading it never renews either lifetime.
    pub fn monotonic_deadline(&self) -> Instant {
        self.deadline
    }
    pub fn observation(&self) -> &ChainContext {
        &self.observation
    }
}
/// Exists only while the actual maintained wallet transaction is held.
pub struct HeldBornPostReturnInputsV1<'guard> {
    fresh: &'guard FreshBornPostReturnInputsV1<'guard>,
    check: &'guard dyn Fn() -> Result<(), BornPostReturnErrorV1>,
}
impl HeldBornPostReturnInputsV1<'_> {
    pub fn check_current(&self) -> Result<(), BornPostReturnErrorV1> {
        (self.check)()
    }
    pub fn digest(&self) -> &str {
        self.fresh.digest()
    }
    pub fn observed_at_ms(&self) -> u64 {
        self.fresh.observed_at_ms()
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.fresh.expires_at_ms()
    }
    pub fn scope(&self) -> &BornPostReturnWalletScopeV1 {
        self.fresh.permission.scope()
    }
    pub fn observation(&self) -> &ChainContext {
        &self.fresh.observation
    }
}
struct ScanAccess<'a> {
    permission: &'a dyn BornPostReturnReadPermissionV1,
}
impl LocalWalletAccess for ScanAccess<'_> {
    fn permits(
        &self,
        _: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        let expected = &self.permission.scope().import_scope.inventory.provider;
        matches!(purpose, WalletAccessPurpose::SynchronizePublicBlocks)
            && provider.source_id == expected.source_id
            && provider.endpoint == expected.endpoint
            && provider.trust_profile == expected.trust_profile
            && self.permission.check_current().is_ok()
            && Instant::now() < self.permission.monotonic_deadline()
    }
}
/// Existing-file-only, purpose-distinct scanner. It never owns original-create
/// import provenance, selection material, a spending key, or a constructor ticket.
/// The native embedding authenticates registry/history before this factory.
pub struct BornPostReturnWalletReaderV1 {
    sync: ProtectedWalletSync,
}
impl BornPostReturnWalletReaderV1 {
    pub fn provider_read_profile(
        &self,
    ) -> wholepact_chain::public_read_profile_v1::PublicReadProfileV1 {
        self.sync.source.public_read_profile_v1()
    }

    pub fn from_existing_encrypted(
        connection: wholepact_storage_security::EncryptedConnection,
        source: ChainAdapter,
        minimum_confirmations: NonZeroU32,
    ) -> Result<Self, BornPostReturnErrorV1> {
        let c = connection.connection();
        let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let count: i64 = c.query_row(
            "SELECT count(*) FROM ext_wholepact_roster_import_records_v2",
            [],
            |r| r.get(0),
        )?;
        if app != super::WALLET_APPLICATION_ID || count != 2 {
            return Err(BornPostReturnErrorV1::Binding);
        }
        connection
            .database_identity()
            .map_err(|_| BornPostReturnErrorV1::Storage)?
            .check_current(c)
            .map_err(|_| BornPostReturnErrorV1::Storage)?;
        c.busy_timeout(Duration::ZERO)?;
        let wallet = DedicatedTestnetWallet::from_encrypted_connection(connection)?;
        let sync =
            ProtectedWalletSync::from_initialized_wallet(wallet, source, minimum_confirmations)?;
        Ok(Self { sync })
    }
    pub async fn observe_born_post_return_inputs_v1<'native>(
        &mut self,
        permission: &'native impl BornPostReturnReadPermissionV1,
    ) -> Result<FreshBornPostReturnInputsV1<'native>, BornPostReturnErrorV1> {
        let result = self
            .sync
            .observe_born_post_return_inputs_v1(permission)
            .await;
        if result.is_err() {
            self.sync.invalidate_observation();
        }
        result
    }
    pub fn with_born_post_return_inputs_v1<R, E: From<BornPostReturnErrorV1>>(
        &mut self,
        fresh: &FreshBornPostReturnInputsV1<'_>,
        callback: impl FnOnce(&HeldBornPostReturnInputsV1<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        self.sync.with_born_post_return_inputs_v1(fresh, callback)
    }
}
impl ProtectedWalletSync {
    async fn observe_born_post_return_inputs_v1<'native>(
        &mut self,
        permission: &'native impl BornPostReturnReadPermissionV1,
    ) -> Result<FreshBornPostReturnInputsV1<'native>, BornPostReturnErrorV1> {
        // Fresh new generation before any DB/provider action. Failed/dropped
        // attempts never revive a prior construction or post-return observation.
        self.invalidate_observation();
        permission.check_current()?;
        self.wallet
            .backup_identity
            .as_ref()
            .ok_or(BornPostReturnErrorV1::Storage)?
            .check()
            .map_err(|_| BornPostReturnErrorV1::Storage)?;
        let scope = permission.scope();
        scope.validate()?;
        if self.source.public_read_profile_v1() != scope.provider_read_profile {
            return Err(BornPostReturnErrorV1::Binding);
        }
        if hex::encode(Sha256::digest(permission.authenticated_fvk().to_bytes()))
            != scope
                .import_scope
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest
            || self.minimum_confirmations.get() < scope.minimum_confirmations
        {
            return Err(BornPostReturnErrorV1::Binding);
        }
        let access = ScanAccess { permission };
        self.require_access(&access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        self.verify_account_fvk(permission.authenticated_fvk())?;
        self.verify_account_birthday_height(
            scope
                .import_scope
                .inventory
                .birthday
                .prior_height
                .checked_add(1)
                .ok_or(BornPostReturnErrorV1::Binding)?,
        )?;
        let scanned = self
            .scanned_height()?
            .ok_or(BornPostReturnErrorV1::StateChanged)?;
        let original_tip = scope
            .original_ancestry
            .iter()
            .map(|(h, _)| *h)
            .max()
            .unwrap();
        if scanned < original_tip || scanned > scope.maximum_tip_height {
            return Err(BornPostReturnErrorV1::StateChanged);
        }
        self.verify_born_post_return_history_v1(permission)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(scope.maximum_scan_runtime_ms))
            .ok_or(BornPostReturnErrorV1::Expired)?
            .min(permission.monotonic_deadline());
        let limits = SyncLimits {
            maximum_blocks: (scope.maximum_tip_height - scanned).max(1),
            anchor_height: Some(scope.anchor_height),
            deadline: deadline.saturating_duration_since(started),
        };
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.synchronize_inner_restricted(&access, limits, None, |context| {
                permission
                    .check_current()
                    .map_err(|_| SyncError::AccessDenied)?;
                check_tip(scope, context).map_err(|_| SyncError::ReconciliationRequired)
            }),
        )
        .await
        .map_err(|_| BornPostReturnErrorV1::Expired)?;
        if let Err(error) = result {
            self.invalidate_observation();
            return Err(error.into());
        }
        let observed = self
            .accepted
            .take()
            .ok_or(BornPostReturnErrorV1::StateChanged)?;
        self.phase = SyncPhase::Unobserved; // no generic selection/key-use publication
        let observed_at_ms = observed
            .chain
            .request_started_at_unix_seconds()
            .checked_mul(1000)
            .ok_or(BornPostReturnErrorV1::Expired)?;
        let expires_at_ms = observed
            .chain
            .valid_until_unix_seconds()
            .checked_mul(1000)
            .ok_or(BornPostReturnErrorV1::Expired)?
            .min(scope.native_observation_expires_at_ms);
        if expires_at_ms <= observed_at_ms || expires_at_ms - observed_at_ms > 60_000 {
            return Err(BornPostReturnErrorV1::Expired);
        }
        let scope_digest = scope.digest()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:born-post-return-wallet-observation:v1",
            &(
                &scope_digest,
                &observed.chain,
                observed_at_ms,
                expires_at_ms,
                "maintained_scanner_locally_unspent_at_named_provider_tip_not_consensus_or_mempool",
            ),
        )
        .map_err(|_| BornPostReturnErrorV1::Binding)?;
        let lifetime = observed
            .chain
            .valid_until_unix_seconds()
            .checked_sub(observed.chain.request_started_at_unix_seconds())
            .ok_or(BornPostReturnErrorV1::Expired)?;
        let observation_deadline = started
            .checked_add(Duration::from_secs(lifetime))
            .ok_or(BornPostReturnErrorV1::Expired)?;
        let deadline = observation_deadline.min(permission.monotonic_deadline());
        let fresh = FreshBornPostReturnInputsV1 {
            permission,
            scope_digest,
            observation: observed.chain,
            current: observed.selection,
            started,
            deadline,
            generation: Arc::downgrade(&self.generation),
            account: self.account,
            digest,
            observed_at_ms,
            expires_at_ms,
            lock_attempted: std::cell::Cell::new(false),
        };
        fresh.check_current()?;
        Ok(fresh)
    }

    fn verify_born_post_return_history_v1(
        &mut self,
        permission: &dyn BornPostReturnReadPermissionV1,
    ) -> Result<(), BornPostReturnErrorV1> {
        permission.check_current()?;
        let scope = permission.scope();
        let account = self.account;
        let fvk = permission.authenticated_fvk();
        self.wallet.db.transactionally_with_extension(|db, ext| {
            check_recovery(ext)?;
            super::super::recorded_roster_import_v2::verify_post_return_history_v1(
                db,
                ext,
                &scope.import_scope,
                &scope.wallet_origin_digest,
                account,
                fvk,
            )
            .map_err(|_| BornPostReturnErrorV1::Binding)?;
            permission.check_current()
        })
    }

    fn with_born_post_return_inputs_v1<R, E: From<BornPostReturnErrorV1>>(
        &mut self,
        fresh: &FreshBornPostReturnInputsV1<'_>,
        callback: impl FnOnce(&HeldBornPostReturnInputsV1<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        if fresh.lock_attempted.replace(true)
            || fresh.account != self.account
            || !Weak::ptr_eq(&fresh.generation, &Arc::downgrade(&self.generation))
        {
            return Err(BornPostReturnErrorV1::StateChanged.into());
        }
        let identity = self
            .wallet
            .backup_identity
            .as_ref()
            .ok_or_else(|| E::from(BornPostReturnErrorV1::Storage))?;
        let external = || {
            fresh.check_current()?;
            identity.check().map_err(|_| BornPostReturnErrorV1::Storage)
        };
        external().map_err(E::from)?;
        let result = self
            .wallet
            .db
            .transactionally_with_extension(|db, ext| {
                external().map_err(|e| GuardError(E::from(e)))?;
                check_recovery(ext).map_err(|e| GuardError(E::from(e)))?;
                let notes = verify_notes(db, fresh).map_err(|e| GuardError(E::from(e)))?;
                verify_note_witnesses(db, fresh.permission.scope(), &notes)
                    .map_err(|e| GuardError(E::from(e)))?;
                let check = || {
                    check_recovery(ext)?;
                    external()?;
                    super::super::recorded_roster_import_v2::verify_post_return_history_v1(
                        db,
                        ext,
                        &fresh.permission.scope().import_scope,
                        &fresh.permission.scope().wallet_origin_digest,
                        fresh.account,
                        fresh.permission.authenticated_fvk(),
                    )
                    .map_err(|_| BornPostReturnErrorV1::Binding)?;
                    verify_notes(db, fresh).map(|_| ())
                };
                check().map_err(|e| GuardError(E::from(e)))?;
                let held = HeldBornPostReturnInputsV1 {
                    fresh,
                    check: &check,
                };
                let result = callback(&held).map_err(GuardError)?;
                check().map_err(|e| GuardError(E::from(e)))?;
                Ok(result)
            })
            .map_err(|e: GuardError<E>| e.0)?;
        external().map_err(E::from)?;
        Ok(result)
    }
}
struct GuardError<E>(E);
impl<E: From<BornPostReturnErrorV1>> From<rusqlite::Error> for GuardError<E> {
    fn from(_: rusqlite::Error) -> Self {
        Self(BornPostReturnErrorV1::Storage.into())
    }
}
impl From<rusqlite::Error> for BornPostReturnErrorV1 {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
fn check_recovery(
    ext: &zcash_client_sqlite::ExtensionTransaction<'_>,
) -> Result<(), BornPostReturnErrorV1> {
    let quarantined: bool = ext.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='wholepact_bundle_quarantine')",
        [],
        |r| r.get(0),
    )?;
    if quarantined {
        Err(BornPostReturnErrorV1::RecoveryRequired)
    } else {
        Ok(())
    }
}
fn check_tip(
    scope: &BornPostReturnWalletScopeV1,
    context: &ChainContext,
) -> Result<(), BornPostReturnErrorV1> {
    let tip = u32::try_from(context.tip().height).map_err(|_| BornPostReturnErrorV1::Binding)?;
    if tip > scope.maximum_tip_height
        || tip < scope.anchor_height
        || tip
            .checked_add(scope.minimum_expiry_margin_blocks)
            .is_none_or(|h| h > scope.transaction_expiry_height)
        || context.network() != "test"
        || context.branch_id() != "77190ad9"
        || context.source().trust_profile != "single_tls_provider_report_not_consensus"
    {
        return Err(BornPostReturnErrorV1::Expired);
    }
    Ok(())
}
fn decode_hash(s: &str) -> Result<[u8; 32], BornPostReturnErrorV1> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BornPostReturnErrorV1::Binding);
    }
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(BornPostReturnErrorV1::Binding)
}
fn parse_outpoint(s: &str) -> Result<(TxId, u16), BornPostReturnErrorV1> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 3 || parts[0] != "ironwood" {
        return Err(BornPostReturnErrorV1::Binding);
    }
    let tx = TxId::from_hex(parts[1]).ok_or(BornPostReturnErrorV1::Binding)?;
    let index = parts[2]
        .parse::<u16>()
        .map_err(|_| BornPostReturnErrorV1::Binding)?;
    if format!("ironwood:{tx}:{index}") != s {
        return Err(BornPostReturnErrorV1::Binding);
    }
    Ok((tx, index))
}
fn now_ms() -> Result<u64, BornPostReturnErrorV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BornPostReturnErrorV1::Expired)?
        .as_millis()
        .try_into()
        .map_err(|_| BornPostReturnErrorV1::Expired)
}
fn verify_notes<D>(
    db: &D,
    fresh: &FreshBornPostReturnInputsV1<'_>,
) -> Result<Vec<(orchard::Note, u64)>, BornPostReturnErrorV1>
where
    D: WalletRead<AccountId = AccountUuid>
        + InputSource<AccountId = AccountUuid, NoteRef = ReceivedNoteId>,
{
    verify_note_facts(
        db,
        fresh.permission.scope(),
        fresh.permission.authenticated_fvk(),
        &fresh.current,
        fresh.account,
    )
}

fn verify_note_facts<D>(
    db: &D,
    s: &BornPostReturnWalletScopeV1,
    fvk: &FullViewingKey,
    c: &SelectionContext,
    account: AccountUuid,
) -> Result<Vec<(orchard::Note, u64)>, BornPostReturnErrorV1>
where
    D: WalletRead<AccountId = AccountUuid>
        + InputSource<AccountId = AccountUuid, NoteRef = ReceivedNoteId>,
{
    let changed = |_| BornPostReturnErrorV1::StateChanged;
    if c.anchor_height != s.anchor_height
        || c.anchor_hash_protocol != s.anchor_hash
        || c.anchor_root != s.anchor_root
        || c.tip_height
            .checked_sub(s.anchor_height)
            .and_then(|v| v.checked_add(1))
            .is_none_or(|v| v < s.minimum_confirmations)
        || db.get_account_ids().map_err(changed)? != vec![account]
        || db
            .block_fully_scanned()
            .map_err(changed)?
            .map(|b| u32::from(b.block_height()))
            != Some(c.tip_height)
        || db.chain_height().map_err(changed)? != Some(c.tip_height.into())
    {
        return Err(BornPostReturnErrorV1::StateChanged);
    }
    let account = db
        .get_account(account)
        .map_err(changed)?
        .ok_or(BornPostReturnErrorV1::StateChanged)?;
    if account
        .ufvk()
        .and_then(|v| v.orchard())
        .is_none_or(|v| v.to_bytes() != fvk.to_bytes())
    {
        return Err(BornPostReturnErrorV1::StateChanged);
    }
    for (height, hash) in s.original_ancestry.iter().copied().chain([
        (s.anchor_height, s.anchor_hash),
        (c.tip_height, c.tip_hash_protocol),
    ]) {
        if height > c.tip_height
            || db
                .get_block_hash(height.into())
                .map_err(changed)?
                .map(|h| h.0)
                != Some(hash)
        {
            return Err(BornPostReturnErrorV1::StateChanged);
        }
    }
    let target = c
        .tip_height
        .checked_add(1)
        .ok_or(BornPostReturnErrorV1::Expired)?;
    if BranchId::for_height(&TEST_NETWORK, target.into()) != BranchId::Nu7
        || !db
            .anchor_computable(ShieldedPool::Ironwood, s.anchor_height.into())
            .map_err(|_| BornPostReturnErrorV1::StateChanged)?
    {
        return Err(BornPostReturnErrorV1::StateChanged);
    }
    let mut notes = Vec::new();
    for expected in &s.own_inputs {
        let (txid, index) = parse_outpoint(&expected.input_id)?;
        let received = db
            .get_spendable_note(
                &txid,
                ShieldedPool::Ironwood,
                u32::from(index),
                target.into(),
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(|_| BornPostReturnErrorV1::StateChanged)?
            .ok_or(BornPostReturnErrorV1::StateChanged)?;
        let WalletNote::Orchard {
            note,
            pool: orchard::ValuePool::Ironwood,
        } = received.note()
        else {
            return Err(BornPostReturnErrorV1::StateChanged);
        };
        if note.version() != NoteVersion::V3
            || note.value().inner() != expected.value_zatoshis
            || note.nullifier(fvk).to_bytes() != decode_hash(&expected.nullifier)?
            || received.txid() != &txid
            || received.output_index() != index
            || received
                .mined_height()
                .is_none_or(|h| u32::from(h) > s.anchor_height)
            || fvk.scope_for_address(&note.recipient()) != Some(received.spending_key_scope())
        {
            return Err(BornPostReturnErrorV1::StateChanged);
        }
        notes.push((*note, u64::from(received.note_commitment_tree_position())));
    }
    Ok(notes)
}

fn verify_note_witnesses<D: WalletCommitmentTrees>(
    db: &mut D,
    scope: &BornPostReturnWalletScopeV1,
    notes: &[(orchard::Note, u64)],
) -> Result<(), BornPostReturnErrorV1> {
    db.with_ironwood_tree_mut::<_, _, WalletError>(|tree| {
        let anchor = scope.anchor_height.into();
        let root = tree
            .root_at_checkpoint_id(&anchor)?
            .ok_or(WalletError::MissingWitness)?;
        if orchard::Anchor::from(root).to_bytes() != scope.anchor_root {
            return Err(WalletError::ChainMismatch);
        }
        for (note, position) in notes {
            let witness: MerklePath = tree
                .witness_at_checkpoint_id_caching((*position).into(), &anchor)?
                .ok_or(WalletError::MissingWitness)?
                .into();
            if witness.root(note.commitment().into()).to_bytes() != scope.anchor_root {
                return Err(WalletError::InvalidNote);
            }
        }
        Ok(())
    })?
    .ok_or(BornPostReturnErrorV1::StateChanged)?;
    Ok(())
}

/// Test-only access to the SAME maintained note and witness checks, without
/// manufacturing any Fresh/Held/native/provider owner or bypassing their gates.
#[cfg(test)]
pub(crate) fn verify_maintained_post_return_notes_for_test(
    wallet: &mut DedicatedTestnetWallet,
    scope: &BornPostReturnWalletScopeV1,
    fvk: &FullViewingKey,
    current: &SelectionContext,
    account: AccountUuid,
) -> Result<usize, BornPostReturnErrorV1> {
    wallet.db.transactionally_with_extension(|db, _| {
        let notes = verify_note_facts(db, scope, fvk, current, account)?;
        verify_note_witnesses(db, scope, &notes)?;
        Ok(notes.len())
    })
}
