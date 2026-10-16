//! Dedicated one-attempt exact-input observation. Historical material and current
//! provider observations are deliberately different owners. Neither grants key use.
//! The pinned NU7 rule requires an earlier block's final Ironwood root, without
//! a numeric age cutoff. Provider continuity and maintained witness availability
//! remain mandatory; neither is independent consensus validation.
use super::*;
use sha2::{Digest, Sha256};
use wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1;
use wholepact_signer_origin::{
    AdmittedRosterExactInputObservationV1, StartedRosterExactInputObservationV1,
};
use zcash_client_backend::wallet::Note as WalletNote;
use zcash_protocol::TxId;

#[path = "common_context_observation_v1.rs"]
mod common_context_v1;
pub use common_context_v1::*;

#[derive(Debug, thiserror::Error)]
pub enum ExactObservationError {
    #[error("exact-input native or original Host completion permission is unavailable")]
    Permission,
    #[error(
        "retained inputs belong to a different, revoked, or already attempted controller epoch"
    )]
    Lineage,
    #[error("exact-input request does not match original immutable wallet material")]
    Binding,
    #[error("wallet file identity, fail-fast lock, or transaction commit failed")]
    Storage,
    #[error("wallet requires explicit recovery")]
    RecoveryRequired,
    #[error("exact retained input, wallet account, or original anchor changed")]
    StateChanged,
    #[error("provider-reported network, branch or software profile changed")]
    ProfileChanged,
    #[error("the exact-input scan or source freshness leaves insufficient reviewed runway")]
    Budget,
    #[error("wallet roster contains an alias, duplicate, or incompatible observation")]
    Roster,
    #[error(transparent)]
    Sync(#[from] SyncError),
}
impl From<WalletError> for ExactObservationError {
    fn from(error: WalletError) -> Self {
        Self::Sync(error.into())
    }
}
type Result<T> = std::result::Result<T, ExactObservationError>;

/// Historical, non-cloneable wallet material. There is no restore/DTO factory,
/// raw constructor escape, or conversion into any signing/key-use ticket.
pub struct RetainedExactWalletMaterial {
    contribution: WalletContribution,
    original_observation: ChainContext,
    generation: Weak<()>,
    identity: Arc<()>,
    attempted: bool,
}
impl RetainedExactWalletMaterial {
    pub fn from_current(selected: ProtectedContribution) -> Result<Self> {
        selected.check_current()?;
        if selected.contribution.notes.is_empty()
            || selected.contribution.notes.len() > MAX_SELECTED_NOTES
        {
            return Err(ExactObservationError::Binding);
        }
        Ok(Self {
            contribution: selected.contribution,
            original_observation: selected.observation,
            generation: selected.generation,
            identity: Arc::new(()),
            attempted: false,
        })
    }
    // V2 and V3 call this SAME monotone attempt gate before database or provider
    // work. A failed attempt revokes original lineage and cannot be reset.
    fn begin_read_attempt(&mut self, sync: &mut ProtectedWalletSync) -> Result<()> {
        if self.attempted {
            return Err(ExactObservationError::Lineage);
        }
        self.attempted = true;
        let prior_matches = self.generation.upgrade().is_some()
            && Weak::ptr_eq(&self.generation, &Arc::downgrade(&sync.generation));
        self.generation = Weak::new();
        if !prior_matches {
            return Err(ExactObservationError::Lineage);
        }
        sync.accepted = None;
        sync.generation = Arc::new(());
        sync.phase = SyncPhase::Interrupted;
        sync.provider_tip_height = None;
        Ok(())
    }
    /// Historical lineage only. Original provider TTL is not relabeled current.
    /// Native retention, Host and construction deadlines remain separate checks.
    pub fn check_retained_lineage(&self) -> Result<()> {
        if self.generation.upgrade().is_none() {
            return Err(ExactObservationError::Lineage);
        }
        Ok(())
    }
    pub fn selection(&self) -> &WalletContribution {
        &self.contribution
    }
    pub fn original_observation(&self) -> &ChainContext {
        &self.original_observation
    }
    pub fn into_construction(
        self,
        held: &HeldExactRosterObservation<'_>,
    ) -> Result<(
        wholepact_protocol::construction::OwnedContribution,
        wholepact_protocol::construction::ConstructionContext,
    )> {
        held.matches_material(&self)?;
        let c = self.contribution.context();
        let context = wholepact_protocol::construction::ConstructionContext {
            anchor: c.anchor_root,
            anchor_height: c.anchor_height,
            anchor_block_hash: c.anchor_hash_protocol,
            target_height: c
                .tip_height
                .checked_add(1)
                .ok_or(ExactObservationError::Binding)?,
        };
        Ok((self.contribution.into_contribution(), context))
    }
}

/// New provider facts plus the actual consumed native read admission. This owner
/// is distinct from all original construction/signing/retention approvals.
pub struct FreshExactInputObservation {
    native: StartedRosterExactInputObservationV1,
    observation: ChainContext,
    current: SelectionContext,
    monotonic_started: Instant,
    generation: Weak<()>,
    material: Arc<()>,
    account: AccountUuid,
    origin: [u8; 32],
    lock_attempted: std::cell::Cell<bool>,
}
impl FreshExactInputObservation {
    pub fn check_current(&self) -> Result<()> {
        self.native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        if self.generation.upgrade().is_none() {
            return Err(ExactObservationError::Lineage);
        }
        self.observation
            .check_fresh_at(now()?)
            .map_err(SyncError::from)?;
        check_observation_elapsed(&self.observation, elapsed_since(self.monotonic_started)?)?;
        let request = self
            .native
            .request()
            .map_err(|_| ExactObservationError::Permission)?;
        if self.current.tip_height
            > request
                .maximum_observed_tip()
                .map_err(|_| ExactObservationError::Binding)?
        {
            return Err(ExactObservationError::Budget);
        }
        Ok(())
    }
    pub fn observation(&self) -> &ChainContext {
        &self.observation
    }
    pub fn prepare_verifier(
        &self,
        material: &RetainedExactWalletMaterial,
    ) -> Result<ExactInputVerifierSnapshot> {
        self.check_current()?;
        material.check_retained_lineage()?;
        if !Arc::ptr_eq(&self.material, &material.identity)
            || !Weak::ptr_eq(&self.generation, &material.generation)
        {
            return Err(ExactObservationError::Lineage);
        }
        let request = self
            .native
            .request()
            .map_err(|_| ExactObservationError::Permission)?;
        verify_native_binding(material, request)?;
        let inventory = &request.plan.retained.selection.scope.selection.inventory;
        let c = &material.contribution;
        Ok(ExactInputVerifierSnapshot {
            material: self.material.clone(),
            generation: self.generation.clone(),
            account: self.account,
            origin: self.origin,
            evidence: c.evidence(),
            notes: c
                .notes
                .iter()
                .map(|n| (n.note, n.witness.position()))
                .collect(),
            local_note_refs: c.local_note_refs.clone(),
            local_outpoints: c.local_outpoints.clone(),
            current: self.current.clone(),
            birthday: inventory
                .birthday
                .prior_height
                .checked_add(1)
                .ok_or(ExactObservationError::Binding)?,
            participant_id: inventory.enrollment.scope.participant_id.clone(),
            minimum_confirmations: request.profile.minimum_confirmations,
            required_ancestry: Vec::new(),
        })
    }
    fn check_runway(&self) -> Result<()> {
        self.check_current()?;
        let p = Duration::from_millis(
            self.native
                .request()
                .map_err(|_| ExactObservationError::Permission)?
                .profile
                .post_scan_runway_ms,
        );
        check_remaining(
            &self.observation,
            self.monotonic_started,
            self.native.completion_deadline(),
            p,
        )
    }
}

/// Bounded private verification facts, not a construction or native capability.
/// No public constructor, Clone, Debug, serialization or source access exists.
/// ```compile_fail
/// use wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactInputVerifierSnapshot;
/// let forged: ExactInputVerifierSnapshot = serde_json::from_str("{}").unwrap();
/// ```
pub struct ExactInputVerifierSnapshot {
    material: Arc<()>,
    generation: Weak<()>,
    account: AccountUuid,
    origin: [u8; 32],
    evidence: LocallySelectedInputs,
    notes: Vec<(Note, u32)>,
    local_note_refs: Vec<ReceivedNoteId>,
    local_outpoints: Vec<(TxId, u16)>,
    current: SelectionContext,
    birthday: u32,
    participant_id: String,
    minimum_confirmations: u32,
    // Populated only by the V3 native read producer. All historical tips must
    // remain on this wallet's actual maintained continuing scanned ancestry.
    required_ancestry: Vec<(u32, [u8; 32])>,
}

impl ProtectedWalletSync {
    /// A single specifically admitted read. The original generation is revoked
    /// before any database read/provider await; failed/dropped attempts never
    /// restore it. The SAME original controller and exact notes are retained.
    pub async fn observe_retained_exact_inputs(
        &mut self,
        material: &mut RetainedExactWalletMaterial,
        admitted: AdmittedRosterExactInputObservationV1,
        access: &impl LocalWalletAccess,
    ) -> Result<FreshExactInputObservation> {
        let native = admitted
            .into_started()
            .map_err(|_| ExactObservationError::Permission)?;
        material.begin_read_attempt(self)?;
        let result = self.observe_exact_inner(material, native, access).await;
        match result {
            Ok(fresh) => {
                material.generation = fresh.generation.clone();
                Ok(fresh)
            }
            Err(error) => {
                self.accepted = None;
                self.generation = Arc::new(());
                self.phase = SyncPhase::Interrupted;
                Err(error)
            }
        }
    }
    async fn observe_exact_inner(
        &mut self,
        material: &RetainedExactWalletMaterial,
        native: StartedRosterExactInputObservationV1,
        access: &impl LocalWalletAccess,
    ) -> Result<FreshExactInputObservation> {
        native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        let request = native
            .request()
            .map_err(|_| ExactObservationError::Permission)?;
        verify_native_binding(material, request)?;
        verify_observation_profile(
            material.original_observation(),
            material.original_observation(),
        )?;
        if !self.wallet.exact_input_fail_fast_v1 {
            return Err(ExactObservationError::Storage);
        }
        let (origin, destination) = self
            .wallet
            .exact_input_origin_v1
            .as_ref()
            .ok_or(ExactObservationError::Lineage)?;
        origin
            .check_retained_owner_path()
            .map_err(|_| ExactObservationError::Storage)?;
        let origin = origin.origin_commitment();
        let inventory = &request.plan.retained.selection.scope.selection.inventory;
        if destination != &inventory.wallet_destination
            || self.source.identity() != material.original_observation.source()
            || self.minimum_confirmations.get() < request.profile.minimum_confirmations
        {
            return Err(ExactObservationError::Binding);
        }
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        self.verify_account_fvk(material.contribution.fvk())?;
        self.verify_account_birthday_height(
            inventory
                .birthday
                .prior_height
                .checked_add(1)
                .ok_or(ExactObservationError::Binding)?,
        )?;
        if self.scanned_height()? != Some(material.contribution.context.tip_height) {
            return Err(ExactObservationError::StateChanged);
        }
        self.wallet
            .check_selection_context(self.minimum_confirmations, &material.contribution.context)?;
        let original = material.contribution.context.clone();
        let started = Instant::now();
        let runway = Duration::from_millis(request.profile.post_scan_runway_ms);
        let runtime = derive_scan_budget(
            started,
            native.completion_deadline(),
            request.completion_expires_at_ms,
            request.profile.maximum_scan_runtime_ms,
            runway,
        )?;
        let mut deadline = started
            .checked_add(runtime)
            .ok_or(ExactObservationError::Budget)?;
        let maximum_blocks = request
            .maximum_additional_blocks()
            .map_err(|_| ExactObservationError::Binding)?;
        let maximum_tip = request
            .maximum_observed_tip()
            .map_err(|_| ExactObservationError::Binding)?;
        native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        self.require_access(access, WalletAccessPurpose::SynchronizePublicBlocks)?;
        let initial = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.source.context(),
        )
        .await
        .map_err(|_| ExactObservationError::Budget)?
        .map_err(SyncError::from)?;
        // Narrow against the actual EARLIEST context before channel/block/tree
        // work. No later request recreates or extends this deadline.
        let source_lifetime = initial
            .valid_until_unix_seconds()
            .checked_sub(initial.request_started_at_unix_seconds())
            .map(Duration::from_secs)
            .and_then(|d| d.checked_sub(runway))
            .ok_or(ExactObservationError::Budget)?;
        deadline = deadline.min(
            started
                .checked_add(source_lifetime)
                .ok_or(ExactObservationError::Budget)?,
        );
        let wall_remaining = Duration::from_secs(initial.valid_until_unix_seconds())
            .checked_sub(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ExactObservationError::Budget)?,
            )
            .and_then(|d| d.checked_sub(runway))
            .ok_or(ExactObservationError::Budget)?;
        deadline = deadline.min(
            Instant::now()
                .checked_add(wall_remaining)
                .ok_or(ExactObservationError::Budget)?,
        );
        let restricted = ExactScanAccess {
            native: &native,
            outer: access,
            deadline,
        };
        let limits = SyncLimits {
            // Generic SyncLimits rejects zero. The exact target check below
            // proves zero additional blocks when B=0 BEFORE any block range.
            maximum_blocks: maximum_blocks.max(1),
            anchor_height: Some(original.anchor_height),
            deadline: runtime,
        };
        let check_context = |chain: &ChainContext| -> std::result::Result<(), SyncError> {
            native
                .check_completion()
                .map_err(|_| SyncError::AccessDenied)?;
            let tip = u32::try_from(chain.tip().height).map_err(|_| SyncError::InvalidResponse)?;
            validate_target(&original, tip, maximum_tip, maximum_blocks)?;
            if verify_observation_profile(material.original_observation(), chain).is_err() {
                return Err(SyncError::ReconciliationRequired);
            }
            if tip == original.tip_height
                && protocol_hash(&chain.tip().hash)? != original.tip_hash_protocol
            {
                return Err(SyncError::ReconciliationRequired);
            }
            check_remaining(chain, started, native.completion_deadline(), runway)
                .map_err(|_| SyncError::Interrupted)?;
            Ok(())
        };
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.synchronize_inner_restricted(
                &restricted,
                limits,
                Some((started, initial)),
                check_context,
            ),
        )
        .await
        .map_err(|_| ExactObservationError::Budget)??;
        // Never publish the dedicated observation through generic selection APIs.
        let observed = self
            .accepted
            .take()
            .ok_or(ExactObservationError::StateChanged)?;
        if observed.selection.anchor_height != original.anchor_height
            || observed.selection.anchor_hash_protocol != original.anchor_hash_protocol
            || observed.selection.anchor_root != original.anchor_root
        {
            return Err(ExactObservationError::StateChanged);
        }
        let fresh = FreshExactInputObservation {
            native,
            observation: observed.chain,
            current: observed.selection,
            monotonic_started: started,
            generation: Arc::downgrade(&self.generation),
            material: material.identity.clone(),
            account: self.account,
            origin,
            lock_attempted: std::cell::Cell::new(false),
        };
        fresh.check_runway()?;
        Ok(fresh)
    }
}

struct ExactScanAccess<'a, A> {
    native: &'a StartedRosterExactInputObservationV1,
    outer: &'a A,
    deadline: Instant,
}
impl<A: LocalWalletAccess> LocalWalletAccess for ExactScanAccess<'_, A> {
    fn permits(
        &self,
        account: AccountUuid,
        source: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        self.native.check_completion().is_ok()
            && Instant::now() < self.deadline
            && self.outer.permits(account, source, purpose)
    }
}

// Private borrowed comparison input, never an observation or permission owner.
// Production values come only from the genuine ChainContext getters below.
#[derive(Clone, Copy)]
struct ObservationProfileFacts<'a> {
    source: &'a BackendIdentity,
    network: &'a str,
    branch_id: &'a str,
    lightwalletd_version: &'a str,
    backend_subversion: &'a str,
    protocol_version: &'a str,
    lifetime_seconds: Option<u64>,
}
impl<'a> ObservationProfileFacts<'a> {
    fn from_context(context: &'a ChainContext) -> Self {
        Self {
            source: context.source(),
            network: context.network(),
            branch_id: context.branch_id(),
            lightwalletd_version: context.lightwalletd_version(),
            backend_subversion: context.backend_subversion(),
            protocol_version: context.protocol_version(),
            lifetime_seconds: context
                .valid_until_unix_seconds()
                .checked_sub(context.request_started_at_unix_seconds()),
        }
    }
}
fn verify_observation_profile(original: &ChainContext, current: &ChainContext) -> Result<()> {
    verify_profile_facts(
        ObservationProfileFacts::from_context(original),
        ObservationProfileFacts::from_context(current),
    )
}
fn verify_profile_facts(
    original: ObservationProfileFacts<'_>,
    current: ObservationProfileFacts<'_>,
) -> Result<()> {
    if current.network != "test"
        || current.lifetime_seconds.is_none_or(|v| v > 60)
        || original.lifetime_seconds.is_none_or(|v| v > 60)
        || current.branch_id != "0x77190ad9"
        || original.network != current.network
        || original.branch_id != current.branch_id
        || original.source != current.source
        || original.lightwalletd_version != current.lightwalletd_version
        || original.backend_subversion != current.backend_subversion
        || original.protocol_version != current.protocol_version
    {
        return Err(ExactObservationError::ProfileChanged);
    }
    Ok(())
}

fn verify_native_binding(
    material: &RetainedExactWalletMaterial,
    request: &ManualRosterExactInputObservationRequestV1,
) -> Result<()> {
    request
        .validate()
        .map_err(|_| ExactObservationError::Binding)?;
    verify_retained_binding(material, &request.plan.retained)
}

fn verify_retained_binding(
    material: &RetainedExactWalletMaterial,
    retained: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
) -> Result<()> {
    let inventory = &retained.selection.scope.selection.inventory;
    let actual = &material.contribution;
    let context = &actual.context;
    let mut inputs: Vec<_> = actual
        .evidence()
        .inputs
        .iter()
        .map(
            |i| wholepact_core::manual_construction::ManualConstructionInput {
                input_id: i.input_id.clone(),
                nullifier: hex::encode(i.nullifier),
                value_zatoshis: i.value_zatoshis,
            },
        )
        .collect();
    inputs.sort_by(|a, b| a.input_id.cmp(&b.input_id));
    if inputs != retained.selected_inputs
        || actual.account_id != inventory.enrollment.identity.account_id
        || hex::encode(Sha256::digest(actual.fvk.to_bytes()))
            != inventory.enrollment.identity.full_viewing_key_digest
        || actual.requested_debit_zatoshis
            != retained
                .selection
                .scope
                .requested_debit_zatoshis()
                .map_err(|_| ExactObservationError::Binding)?
        || actual
            .selected_zatoshis
            .checked_sub(actual.requested_debit_zatoshis)
            != Some(retained.change_value_zatoshis)
        || wholepact_protocol::review::encode_testnet_receiver(&actual.change_address)
            != retained.change_address
        || actual.fvk.scope_for_address(&actual.change_address)
            != Some(orchard::keys::Scope::Internal)
        || context.tip_height != retained.selection_context.tip_height
        || hex::encode(context.tip_hash_protocol) != retained.selection_context.tip_hash_protocol
        || context.anchor_height != retained.selection_context.anchor_height
        || hex::encode(context.anchor_hash_protocol)
            != retained.selection_context.anchor_hash_protocol
        || hex::encode(context.anchor_root) != retained.selection_context.anchor_root
        || material.original_observation.source().source_id != inventory.provider.source_id
        || material.original_observation.source().endpoint != inventory.provider.endpoint
        || material.original_observation.source().trust_profile != inventory.provider.trust_profile
    {
        return Err(ExactObservationError::Binding);
    }
    Ok(())
}

fn derive_scan_budget(
    start: Instant,
    completion: Instant,
    wall_ceiling_ms: u64,
    runtime_ms: u64,
    runway: Duration,
) -> Result<Duration> {
    let remaining = completion
        .checked_duration_since(start)
        .ok_or(ExactObservationError::Budget)?;
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExactObservationError::Budget)?
        .as_millis();
    let wall_remaining = u128::from(wall_ceiling_ms)
        .checked_sub(wall_now)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(ExactObservationError::Budget)?;
    let remaining = remaining.min(Duration::from_millis(wall_remaining));
    if runway < Duration::from_secs(10)
        || runway >= Duration::from_secs(60)
        || runtime_ms == 0
        || runtime_ms > 30_000
        || remaining <= runway
    {
        return Err(ExactObservationError::Budget);
    }
    Ok(Duration::from_millis(runtime_ms)
        .min(remaining - runway)
        .min(Duration::from_secs(60) - runway))
}
fn check_remaining(
    chain: &ChainContext,
    started: Instant,
    completion: Instant,
    runway: Duration,
) -> Result<()> {
    let instant = Instant::now();
    let age = instant
        .checked_duration_since(started)
        .ok_or(ExactObservationError::Budget)?;
    let lifetime = chain
        .valid_until_unix_seconds()
        .checked_sub(chain.request_started_at_unix_seconds())
        .ok_or(ExactObservationError::Budget)?;
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExactObservationError::Budget)?;
    let wall_expiry = Duration::from_secs(chain.valid_until_unix_seconds());
    if completion
        .checked_duration_since(instant)
        .is_none_or(|v| v <= runway)
        || Duration::from_secs(lifetime)
            .checked_sub(age)
            .is_none_or(|v| v <= runway)
        || wall_expiry
            .checked_sub(wall_now)
            .is_none_or(|v| v <= runway)
    {
        return Err(ExactObservationError::Budget);
    }
    Ok(())
}
fn validate_target(
    original: &SelectionContext,
    tip: u32,
    maximum_tip: u32,
    blocks: u32,
) -> std::result::Result<(), SyncError> {
    if tip > maximum_tip
        || tip
            .checked_sub(original.tip_height)
            .is_none_or(|n| n > blocks)
        || BranchId::for_height(
            &TEST_NETWORK,
            tip.checked_add(1).ok_or(SyncError::InvalidResponse)?.into(),
        ) != BranchId::Nu7
    {
        return Err(SyncError::InvalidRequest);
    }
    // ZIP258 b93e824b3fecbfdbcbbb5b4205223780a1320a25 and Zebra
    // 6d1e414d6f55e4180d0e47baaa934bf97d5b4fec anchors.rs:124..164:
    // the earlier final root must belong to the continuing branch. No numeric
    // age horizon follows from wallet PRUNING_DEPTH or ZIP318 migration rules.
    if original.anchor_height < wholepact_chain::NU7_ACTIVATION_HEIGHT as u32
        || original.tip_height < wholepact_chain::NU7_ACTIVATION_HEIGHT as u32
        || original.anchor_height > original.tip_height
        || original.anchor_height >= tip.checked_add(1).ok_or(SyncError::InvalidResponse)?
        || BranchId::for_height(
            &TEST_NETWORK,
            original
                .tip_height
                .checked_add(1)
                .ok_or(SyncError::InvalidResponse)?
                .into(),
        ) != BranchId::Nu7
    {
        return Err(SyncError::InvalidRequest);
    }
    Ok(())
}

/// An additional Host restriction, never an issuer. The concrete opaque native
/// owner is always checked independently. Implementations must not reenter a
/// wallet, acquire a new Directory, or access the currently held proof mutex.
pub trait ExactInputRestriction {
    fn check_current(&self, account: AccountUuid) -> Result<()>;
}
// Private dispatch lets component tests exercise the actual maintained lock
// stack without constructing a mock native admission. The ONLY production
// implementation and ONLY public slot constructor use the concrete Fresh owner.
trait ObservationChecks {
    fn check_current(&self) -> Result<()>;
    fn check_runway(&self) -> Result<()>;
    fn mark_lock_attempted(&self) -> bool;
}
impl ObservationChecks for FreshExactInputObservation {
    fn check_current(&self) -> Result<()> {
        FreshExactInputObservation::check_current(self)
    }
    fn check_runway(&self) -> Result<()> {
        FreshExactInputObservation::check_runway(self)
    }
    fn mark_lock_attempted(&self) -> bool {
        self.lock_attempted.replace(true)
    }
}

pub struct ExactInputWalletSlot<'a> {
    sync: &'a mut ProtectedWalletSync,
    snapshot: &'a ExactInputVerifierSnapshot,
    fresh: &'a dyn ObservationChecks,
    restriction: &'a dyn ExactInputRestriction,
}
impl<'a> ExactInputWalletSlot<'a> {
    pub fn new(
        sync: &'a mut ProtectedWalletSync,
        snapshot: &'a ExactInputVerifierSnapshot,
        fresh: &'a FreshExactInputObservation,
        restriction: &'a dyn ExactInputRestriction,
    ) -> Result<Self> {
        fresh.check_current()?;
        if sync.account != snapshot.account
            || !Arc::ptr_eq(&snapshot.material, &fresh.material)
            || !Weak::ptr_eq(&snapshot.generation, &fresh.generation)
            || !Weak::ptr_eq(&snapshot.generation, &Arc::downgrade(&sync.generation))
            || snapshot.origin != fresh.origin
            || snapshot.current != fresh.current
            || !sync.wallet.exact_input_fail_fast_v1
        {
            return Err(ExactObservationError::Lineage);
        }
        Ok(Self {
            sync,
            snapshot,
            fresh,
            restriction,
        })
    }
    fn check_external(&self) -> Result<()> {
        self.fresh.check_current()?;
        let (origin, _) = self
            .sync
            .wallet
            .exact_input_origin_v1
            .as_ref()
            .ok_or(ExactObservationError::Lineage)?;
        origin
            .check_retained_owner_path()
            .map_err(|_| ExactObservationError::Storage)?;
        if origin.origin_commitment() != self.snapshot.origin {
            return Err(ExactObservationError::Lineage);
        }
        self.sync
            .wallet
            .backup_identity
            .as_ref()
            .ok_or(ExactObservationError::Storage)?
            .check()
            .map_err(|_| ExactObservationError::Storage)?;
        self.restriction.check_current(self.snapshot.account)
    }
}

trait GuardChain {
    fn check_all(&self) -> Result<()>;
    fn check_acquisition(&self) -> Result<()>;
    fn contains(&self, identity: &Arc<()>, generation: &Weak<()>) -> bool;
}
struct EmptyChain;
impl GuardChain for EmptyChain {
    fn check_all(&self) -> Result<()> {
        Ok(())
    }
    fn check_acquisition(&self) -> Result<()> {
        Ok(())
    }
    fn contains(&self, _: &Arc<()>, _: &Weak<()>) -> bool {
        false
    }
}
struct ChainNode<'a> {
    prior: &'a dyn GuardChain,
    snapshot: &'a ExactInputVerifierSnapshot,
    check: &'a dyn Fn() -> Result<()>,
    runway: &'a dyn Fn() -> Result<()>,
}
impl GuardChain for ChainNode<'_> {
    fn check_all(&self) -> Result<()> {
        self.prior.check_all()?;
        (self.check)()
    }
    fn check_acquisition(&self) -> Result<()> {
        self.prior.check_acquisition()?;
        (self.check)()?;
        (self.runway)()
    }
    fn contains(&self, identity: &Arc<()>, generation: &Weak<()>) -> bool {
        (Arc::ptr_eq(identity, &self.snapshot.material)
            && Weak::ptr_eq(generation, &self.snapshot.generation))
            || self.prior.contains(identity, generation)
    }
}
/// Borrows every currently held maintained transaction. It cannot be fabricated,
/// cloned, serialized or returned from the higher-ranked callback.
/// ```compile_fail
/// use wholepact_wallet::wallet::protected_sync::exact_input_observation::*;
/// fn escape<'a>(slots: Vec<ExactInputWalletSlot<'a>>, exclusions: &[[u8; 32]])
///     -> Result<HeldExactRosterObservation<'a>, ExactObservationError> {
///     with_exact_input_roster(slots, exclusions, |held| Ok(*held))
/// }
/// ```
pub struct HeldExactRosterObservation<'a> {
    chain: &'a dyn GuardChain,
    current: &'a SelectionContext,
    count: usize,
}
impl HeldExactRosterObservation<'_> {
    pub fn check_all_current(&self) -> Result<()> {
        self.chain.check_all()
    }
    pub fn matches_material(&self, material: &RetainedExactWalletMaterial) -> Result<()> {
        self.check_all_current()?;
        material.check_retained_lineage()?;
        if !self
            .chain
            .contains(&material.identity, &material.generation)
        {
            return Err(ExactObservationError::Lineage);
        }
        Ok(())
    }
    pub fn current_tip(&self) -> (u32, [u8; 32]) {
        (self.current.tip_height, self.current.tip_hash_protocol)
    }
    pub fn participant_count(&self) -> usize {
        self.count
    }
}

/// Acquire actual wallet origins in deterministic order; financial participant
/// ordering is unchanged. Store/proof origin exclusions must come from actual
/// retained factory identities. Outer transaction failures do not roll back
/// independent Engine claim/receipt/proof journals; caller retains their outcome.
pub fn with_exact_input_roster<R, E, F>(
    slots: Vec<ExactInputWalletSlot<'_>>,
    excluded_origins: &[[u8; 32]],
    callback: F,
) -> std::result::Result<R, E>
where
    E: From<ExactObservationError>,
    F: for<'guard> FnOnce(&HeldExactRosterObservation<'guard>) -> std::result::Result<R, E>,
{
    with_exact_input_roster_inner(
        slots,
        excluded_origins,
        |snapshot, original| snapshot.evidence.context == *original,
        callback,
    )
}
// Private shared maintained-lock implementation. Public V2 always supplies the
// unchanged exact-original-context predicate. V3 supplies its opaque native-
// issued common-context binding; callers cannot provide a target override.
fn with_exact_input_roster_inner<R, E, F>(
    mut slots: Vec<ExactInputWalletSlot<'_>>,
    excluded_origins: &[[u8; 32]],
    originals_match: impl Fn(&ExactInputVerifierSnapshot, &SelectionContext) -> bool,
    callback: F,
) -> std::result::Result<R, E>
where
    E: From<ExactObservationError>,
    F: for<'guard> FnOnce(&HeldExactRosterObservation<'guard>) -> std::result::Result<R, E>,
{
    if !(2..=8).contains(&slots.len()) || excluded_origins.len() < 2 {
        return Err(ExactObservationError::Roster.into());
    }
    // The final maintained-lock wave is one attempt too. Contention, malformed
    // roster or later failure cannot silently retry this native read operation.
    let mut reused = false;
    for slot in &slots {
        reused |= slot.fresh.mark_lock_attempted();
    }
    if reused {
        return Err(ExactObservationError::Lineage.into());
    }
    slots.sort_by_key(|s| s.snapshot.origin);
    let mut origins = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    let mut fvks = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut participants = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    let original = slots[0].snapshot.evidence.context.clone();
    let current = slots[0].snapshot.current.clone();
    let count = slots.len();
    // The maintained constructor supports at most 64 real inputs in total.
    if slots.iter().map(|s| s.snapshot.notes.len()).sum::<usize>() > 64 {
        return Err(ExactObservationError::Roster.into());
    }
    for slot in &slots {
        let s = slot.snapshot;
        if !origins.insert(s.origin)
            || excluded_origins.contains(&s.origin)
            || !accounts.insert(*s.account.expose_uuid().as_bytes())
            || !fvks.insert(s.evidence.fvk.to_bytes())
            || !ids.insert(s.evidence.account_id.clone())
            || !participants.insert(s.participant_id.clone())
            || !originals_match(s, &original)
            || s.current != current
            || s.evidence
                .inputs
                .iter()
                .any(|input| !nullifiers.insert(input.nullifier))
        {
            return Err(ExactObservationError::Roster.into());
        }
        slot.check_external().map_err(E::from)?;
        slot.fresh.check_runway().map_err(E::from)?;
    }
    let result = recurse(
        &mut slots,
        &EmptyChain,
        &current,
        count,
        &mut Some(callback),
    )?;
    // The last maintained transaction commits AFTER its closure's final check.
    // That synchronous commit may cross a source/original completion deadline.
    // Slots still retain the actual native/observation/file/Host restrictions;
    // recheck them after EVERY transaction has unwound, without resetting any
    // clock, reserving fresh runway, rereading unlocked notes, or retrying work.
    // An error here preserves the caller's independent claim/progress tracker:
    // it does not assert that the already returned leaf result was rolled back.
    for slot in &slots {
        slot.check_external().map_err(E::from)?;
    }
    Ok(result)
}
struct TransactionError<E>(E);
impl<E: From<ExactObservationError>> From<rusqlite::Error> for TransactionError<E> {
    fn from(_: rusqlite::Error) -> Self {
        Self(ExactObservationError::Storage.into())
    }
}
fn recurse<R, E, F>(
    slots: &mut [ExactInputWalletSlot<'_>],
    prior: &dyn GuardChain,
    current: &SelectionContext,
    count: usize,
    callback: &mut Option<F>,
) -> std::result::Result<R, E>
where
    E: From<ExactObservationError>,
    F: for<'guard> FnOnce(&HeldExactRosterObservation<'guard>) -> std::result::Result<R, E>,
{
    // Every acquisition rechecks the SAME originally captured clocks for the
    // whole already-held + pending roster. No per-wallet timer is restarted.
    prior.check_acquisition().map_err(E::from)?;
    for pending in slots.iter() {
        pending.check_external().map_err(E::from)?;
        pending.fresh.check_runway().map_err(E::from)?;
    }
    let Some((slot, rest)) = slots.split_first_mut() else {
        let held = HeldExactRosterObservation {
            chain: prior,
            current,
            count,
        };
        held.check_all_current().map_err(E::from)?;
        return callback
            .take()
            .ok_or_else(|| E::from(ExactObservationError::Roster))?(&held);
    };
    // Split disjoint fields before acquiring the mutable maintained transaction.
    let snapshot = slot.snapshot;
    let fresh = slot.fresh;
    let restriction = slot.restriction;
    let wallet = &mut slot.sync.wallet;
    let (origin, _) = wallet
        .exact_input_origin_v1
        .as_ref()
        .ok_or_else(|| E::from(ExactObservationError::Lineage))?;
    let identity = wallet
        .backup_identity
        .as_ref()
        .ok_or_else(|| E::from(ExactObservationError::Storage))?;
    let external = || -> Result<()> {
        fresh.check_current()?;
        origin
            .check_retained_owner_path()
            .map_err(|_| ExactObservationError::Storage)?;
        identity
            .check()
            .map_err(|_| ExactObservationError::Storage)?;
        restriction.check_current(snapshot.account)
    };
    external().map_err(E::from)?;
    // Preliminary pending checks may themselves take time. Recheck all earlier
    // and pending clocks immediately before this next fail-fast acquisition.
    prior.check_acquisition().map_err(E::from)?;
    fresh.check_runway().map_err(E::from)?;
    for pending in rest.iter() {
        pending.fresh.check_runway().map_err(E::from)?;
    }
    wallet.db.transactionally_with_extension(|db, extension| {
        let recovery = || -> Result<()> {
            let quarantined: bool = extension.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='wholepact_bundle_quarantine')", [], |r| r.get(0))
                .map_err(|_| ExactObservationError::Storage)?;
            if quarantined { Err(ExactObservationError::RecoveryRequired) } else { Ok(()) }
        };
        recovery().map_err(|e| TransactionError(E::from(e)))?;
        external().map_err(|e| TransactionError(E::from(e)))?;
        verify_exact_notes(db, snapshot).map_err(|e| TransactionError(E::from(e)))?;
        db.with_ironwood_tree_mut::<_, _, WalletError>(|tree| {
            let anchor = snapshot.evidence.context.anchor_height.into();
            let root = tree.root_at_checkpoint_id(&anchor)?.ok_or(WalletError::MissingWitness)?;
            if orchard::Anchor::from(root).to_bytes() != snapshot.evidence.context.anchor_root {
                return Err(WalletError::ChainMismatch);
            }
            for (note, position) in &snapshot.notes {
                let witness: MerklePath = tree.witness_at_checkpoint_id_caching(u64::from(*position).into(), &anchor)?
                    .ok_or(WalletError::MissingWitness)?.into();
                if witness.root(note.commitment().into()).to_bytes() != snapshot.evidence.context.anchor_root {
                    return Err(WalletError::InvalidNote);
                }
            }
            Ok(())
        }).map_err(|e| TransactionError(E::from(ExactObservationError::from(e))))?
            .ok_or_else(|| TransactionError(E::from(ExactObservationError::StateChanged)))?;
        let check = || { recovery()?; external()?; verify_exact_notes(db, snapshot) };
        let runway = || fresh.check_runway();
        let node = ChainNode { prior, snapshot, check: &check, runway: &runway };
        node.check_all().map_err(|e| TransactionError(E::from(e)))?;
        let result = recurse(rest, &node, current, count, callback).map_err(TransactionError)?;
        node.check_all().map_err(|e| TransactionError(E::from(e)))?;
        Ok(result)
    }).map_err(|e: TransactionError<E>| e.0)
}

fn verify_exact_notes<D>(db: &D, snapshot: &ExactInputVerifierSnapshot) -> Result<()>
where
    D: WalletRead<AccountId = AccountUuid>
        + InputSource<AccountId = AccountUuid, NoteRef = ReceivedNoteId>,
{
    let s = snapshot;
    let original = &s.evidence.context;
    let current = &s.current;
    let changed = |_| ExactObservationError::StateChanged;
    if s.evidence.inputs.is_empty()
        || s.evidence.inputs.len() > MAX_SELECTED_NOTES
        || s.evidence.inputs.len() != s.notes.len()
        || s.notes.len() != s.local_note_refs.len()
        || s.notes.len() != s.local_outpoints.len()
        || current.anchor_height != original.anchor_height
        || current.anchor_hash_protocol != original.anchor_hash_protocol
        || current.anchor_root != original.anchor_root
        || current.tip_height < original.tip_height
        || current
            .tip_height
            .checked_sub(original.anchor_height)
            .and_then(|v| v.checked_add(1))
            .is_none_or(|v| v < s.minimum_confirmations)
        || db.get_account_ids().map_err(changed)? != vec![s.account]
        || u32::from(db.get_account_birthday(s.account).map_err(changed)?) != s.birthday
    {
        return Err(ExactObservationError::StateChanged);
    }
    let account = db
        .get_account(s.account)
        .map_err(changed)?
        .ok_or(ExactObservationError::StateChanged)?;
    if account
        .ufvk()
        .and_then(|k| k.orchard())
        .is_none_or(|k| k.to_bytes() != s.evidence.fvk.to_bytes())
        || db
            .block_fully_scanned()
            .map_err(changed)?
            .map(|b| u32::from(b.block_height()))
            != Some(current.tip_height)
        || db.chain_height().map_err(changed)? != Some(current.tip_height.into())
    {
        return Err(ExactObservationError::StateChanged);
    }
    for (height, hash) in [
        (original.tip_height, original.tip_hash_protocol),
        (original.anchor_height, original.anchor_hash_protocol),
        (current.tip_height, current.tip_hash_protocol),
    ] {
        if db
            .get_block_hash(height.into())
            .map_err(changed)?
            .map(|h| h.0)
            != Some(hash)
        {
            return Err(ExactObservationError::StateChanged);
        }
    }
    verify_required_ancestry(db, &s.required_ancestry, current.tip_height)?;
    let target = current
        .tip_height
        .checked_add(1)
        .ok_or(ExactObservationError::StateChanged)?;
    if BranchId::for_height(&TEST_NETWORK, target.into()) != BranchId::Nu7
        || !db
            .anchor_computable(ShieldedPool::Ironwood, original.anchor_height.into())
            .map_err(|_| ExactObservationError::StateChanged)?
    {
        return Err(ExactObservationError::StateChanged);
    }
    let mut nullifiers = BTreeSet::new();
    let mut refs = BTreeSet::new();
    for (((expected, note_ref), (txid, index)), (original_note, position)) in s
        .evidence
        .inputs
        .iter()
        .zip(&s.local_note_refs)
        .zip(&s.local_outpoints)
        .zip(&s.notes)
    {
        let received = db
            .get_spendable_note(
                txid,
                ShieldedPool::Ironwood,
                u32::from(*index),
                target.into(),
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(|_| ExactObservationError::StateChanged)?
            .ok_or(ExactObservationError::StateChanged)?;
        let WalletNote::Orchard {
            note,
            pool: orchard::ValuePool::Ironwood,
        } = received.note()
        else {
            return Err(ExactObservationError::StateChanged);
        };
        let nullifier = note.nullifier(&s.evidence.fvk).to_bytes();
        if note != original_note
            || note.version() != NoteVersion::V3
            || note.value().inner() == 0
            || received.internal_note_id() != note_ref
            || received.txid() != txid
            || received.output_index() != *index
            || u64::from(received.note_commitment_tree_position()) != u64::from(*position)
            || expected.input_id != format!("ironwood:{txid}:{index}")
            || expected.value_zatoshis != note.value().inner()
            || expected.nullifier != nullifier
            || !nullifiers.insert(nullifier)
            || !refs.insert((txid.to_string(), *index))
            || s.evidence.fvk.scope_for_address(&note.recipient())
                != Some(received.spending_key_scope())
            || received
                .mined_height()
                .is_none_or(|h| u32::from(h) > original.anchor_height)
        {
            return Err(ExactObservationError::StateChanged);
        }
    }
    Ok(())
}

// Local hashes below are maintained scanner output. The producer first checks
// the provider's continuing original tip and every appended prev-hash link.
fn verify_required_ancestry<D>(db: &D, required: &[(u32, [u8; 32])], current_tip: u32) -> Result<()>
where
    D: WalletRead<AccountId = AccountUuid>,
{
    if required.len() > 8 {
        return Err(ExactObservationError::Binding);
    }
    for (height, hash) in required {
        if *height > current_tip
            || db
                .get_block_hash((*height).into())
                .map_err(|_| ExactObservationError::StateChanged)?
                .map(|block| block.0)
                != Some(*hash)
        {
            return Err(ExactObservationError::StateChanged);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "exact_input_observation_tests.rs"]
mod tests;

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "exact_input_roster_tests.rs"]
mod roster_tests;

#[cfg(test)]
#[path = "exact_input_profile_tests.rs"]
mod profile_tests;
