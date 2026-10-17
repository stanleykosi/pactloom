//! V3-only protected common construction context. A native V3 read owns the
//! same historical material attempt and original clocks used by V2. A frozen
//! maximum-ORIGINAL-tip target never substitutes for current spendability.
use super::*;
#[path = "common_context_historical_capture_v1.rs"]
mod historical_capture_v1;
use historical_capture_v1::SnapshotHistorical;
use wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1;
use wholepact_signer_origin::{
    AdmittedManualRosterConstructionContributionV3, AdmittedRosterCommonContextReadV1,
    StartedRosterCommonContextReadV1,
};

#[derive(Clone)]
struct FrozenCommonContext {
    context: FrozenContextFacts,
    digest: String,
    required_ancestry: Vec<(u32, [u8; 32])>,
}
#[derive(Clone)]
struct FrozenContextFacts {
    anchor_height: u32,
    anchor_hash_protocol: String,
    anchor_root: String,
    reference_tip_height: u32,
    reference_tip_hash_protocol: String,
    target_height: u32,
    expiry_height: u32,
    participants: Vec<wholepact_core::manual_roster_construction_v3::CommonContextParticipantV1>,
}
impl FrozenCommonContext {
    fn from_request(request: &RosterCommonContextReadRequestV1) -> Result<Self> {
        request
            .validate()
            .map_err(|_| ExactObservationError::Binding)?;
        let source = &request.plan.common_context;
        let context = FrozenContextFacts {
            anchor_height: source.anchor_height,
            anchor_hash_protocol: source.anchor_hash_protocol.clone(),
            anchor_root: source.anchor_root.clone(),
            reference_tip_height: source.reference_tip_height,
            reference_tip_hash_protocol: source.reference_tip_hash_protocol.clone(),
            target_height: source.target_height,
            expiry_height: source.expiry_height,
            participants: source.participants.clone(),
        };
        let digest = source
            .digest()
            .map_err(|_| ExactObservationError::Binding)?;
        if digest != request.plan.common_context_digest {
            return Err(ExactObservationError::Binding);
        }
        let mut required_ancestry = Vec::new();
        for owner in &context.participants {
            let hash = decode_hash(&owner.original_tip_hash_protocol)?;
            if let Some((_, existing)) = required_ancestry
                .iter()
                .find(|(height, _)| *height == owner.original_tip_height)
            {
                if *existing != hash {
                    return Err(ExactObservationError::Binding);
                }
            } else {
                required_ancestry.push((owner.original_tip_height, hash));
            }
        }
        required_ancestry.sort_by_key(|entry| entry.0);
        if required_ancestry.last().copied()
            != Some((
                context.reference_tip_height,
                decode_hash(&context.reference_tip_hash_protocol)?,
            ))
            || context.reference_tip_height.checked_add(1) != Some(context.target_height)
            || context.anchor_height >= context.target_height
            || context.target_height > context.expiry_height
            || context.expiry_height >= 500_000_000
            || BranchId::for_height(&TEST_NETWORK, context.target_height.into()) != BranchId::Nu7
            || BranchId::for_height(&TEST_NETWORK, context.expiry_height.into()) != BranchId::Nu7
        {
            return Err(ExactObservationError::Binding);
        }
        Ok(Self {
            context,
            digest,
            required_ancestry,
        })
    }
    fn matches_snapshot(&self, snapshot: &ExactInputVerifierSnapshot) -> bool {
        let original = &snapshot.evidence.context;
        let Some(owner) = self.context.participants.iter().find(|owner| {
            owner.commitment.participant_id == snapshot.participant_id
                && owner.commitment.account_id == snapshot.evidence.account_id
        }) else {
            return false;
        };
        original.anchor_height == self.context.anchor_height
            && hex::encode(original.anchor_hash_protocol) == self.context.anchor_hash_protocol
            && hex::encode(original.anchor_root) == self.context.anchor_root
            && original.tip_height == owner.original_tip_height
            && hex::encode(original.tip_hash_protocol) == owner.original_tip_hash_protocol
            && hex::encode(Sha256::digest(snapshot.evidence.fvk.to_bytes()))
                == owner.commitment.full_viewing_key_digest
            && snapshot.required_ancestry == self.required_ancestry
            && snapshot.current.tip_height >= self.context.reference_tip_height
    }
    fn construction_context(
        &self,
    ) -> Result<wholepact_protocol::construction::ConstructionContext> {
        Ok(wholepact_protocol::construction::ConstructionContext {
            anchor: decode_hash(&self.context.anchor_root)?,
            anchor_height: self.context.anchor_height,
            anchor_block_hash: decode_hash(&self.context.anchor_hash_protocol)?,
            target_height: self.context.target_height,
        })
    }
}
fn decode_hash(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(ExactObservationError::Binding)
}
fn verify_common_native_binding(
    material: &RetainedExactWalletMaterial,
    request: &RosterCommonContextReadRequestV1,
) -> Result<()> {
    request
        .validate()
        .map_err(|_| ExactObservationError::Binding)?;
    verify_retained_binding(material, &request.plan.retained)
}

/// Non-Clone, non-serializable, one-read owner issued only by the maintained
/// scanner after consuming a concrete admitted native V3 decision.
pub struct FreshCommonContextObservation {
    native: StartedRosterCommonContextReadV1,
    observation: ChainContext,
    current: SelectionContext,
    monotonic_started: Instant,
    generation: Weak<()>,
    material: Arc<()>,
    account: AccountUuid,
    origin: [u8; 32],
    lock_attempted: std::cell::Cell<bool>,
    common: FrozenCommonContext,
    plan_digest: String,
}
impl FreshCommonContextObservation {
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
    /// Borrow the same actual plan-bound read owner for the separately fresh
    /// full-proposal native ceremony. This neither clones nor renews it.
    pub fn native_read(&self) -> &StartedRosterCommonContextReadV1 {
        &self.native
    }
    pub fn observation(&self) -> &ChainContext {
        &self.observation
    }
    /// Read-only comparison of two actual completed observations. This creates
    /// no lock/verification owner and cannot refresh either original deadline.
    pub fn require_same_current_context(&self, other: &Self) -> Result<()> {
        self.check_current()?;
        other.check_current()?;
        if self.current != other.current || self.common.digest != other.common.digest {
            return Err(ExactObservationError::Binding);
        }
        Ok(())
    }
    pub fn prepare_verifier(
        &self,
        material: &RetainedExactWalletMaterial,
    ) -> Result<CommonContextVerifierSnapshot> {
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
        verify_common_native_binding(material, request)?;
        let inventory = &request.plan.retained.selection.scope.selection.inventory;
        let c = &material.contribution;
        Ok(CommonContextVerifierSnapshot {
            historical: Some(SnapshotHistorical::capture(material, self)?),
            common: self.common.clone(),
            plan_digest: self.plan_digest.clone(),
            exact: ExactInputVerifierSnapshot {
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
                required_ancestry: self.common.required_ancestry.clone(),
            },
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

impl ProtectedWalletSync {
    /// A single specifically admitted read. The original generation is revoked
    /// before any database read/provider await; failed/dropped attempts never
    /// restore it. The SAME original controller and exact notes are retained.
    pub async fn observe_retained_common_context(
        &mut self,
        material: &mut RetainedExactWalletMaterial,
        admitted: AdmittedRosterCommonContextReadV1,
        access: &impl LocalWalletAccess,
    ) -> Result<FreshCommonContextObservation> {
        let native = admitted
            .into_started()
            .map_err(|_| ExactObservationError::Permission)?;
        material.begin_read_attempt(self)?;
        let result = self
            .observe_common_context_inner(material, native, access)
            .await;
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
    async fn observe_common_context_inner(
        &mut self,
        material: &RetainedExactWalletMaterial,
        native: StartedRosterCommonContextReadV1,
        access: &impl LocalWalletAccess,
    ) -> Result<FreshCommonContextObservation> {
        native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        let request = native
            .request()
            .map_err(|_| ExactObservationError::Permission)?;
        verify_common_native_binding(material, request)?;
        let common = FrozenCommonContext::from_request(request)?;
        let plan_digest = request
            .plan
            .digest()
            .map_err(|_| ExactObservationError::Binding)?;
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
        let restricted = CommonContextScanAccess {
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
            if tip < common.context.reference_tip_height {
                return Err(SyncError::ReconciliationRequired);
            }
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
        let mut observed = self
            .accepted
            .take()
            .ok_or(ExactObservationError::StateChanged)?;
        if observed.selection.anchor_height != original.anchor_height
            || observed.selection.anchor_hash_protocol != original.anchor_hash_protocol
            || observed.selection.anchor_root != original.anchor_root
        {
            return Err(ExactObservationError::StateChanged);
        }
        // Every original and the selected maximum-original reference must be
        // present on the maintained scanner's continuing ancestry. No arbitrary
        // provider assertion or compare_contexts shortcut can stand in for it.
        verify_required_ancestry(
            &self.wallet.db,
            &common.required_ancestry,
            observed.selection.tip_height,
        )?;
        let required: Vec<_> = common
            .required_ancestry
            .iter()
            .map(|(height, hash)| {
                Ok(wholepact_chain::BlockIdentity {
                    height: u64::from(*height),
                    hash: display_hash(hash)?,
                })
            })
            .collect::<std::result::Result<_, SyncError>>()?;
        native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        self.require_access(&restricted, WalletAccessPurpose::SynchronizePublicBlocks)?;
        observed.chain = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.source
                .revalidate_scanned_block_identities(&observed.chain, &required),
        )
        .await
        .map_err(|_| ExactObservationError::Budget)?
        .map_err(SyncError::from)?;
        // This remains the same admitted finite read wave. Revalidation does not
        // move the constructor target or renew any native/source/Host clock.
        let fresh = FreshCommonContextObservation {
            native,
            observation: observed.chain,
            current: observed.selection,
            monotonic_started: started,
            generation: Arc::downgrade(&self.generation),
            material: material.identity.clone(),
            account: self.account,
            origin,
            lock_attempted: std::cell::Cell::new(false),
            common,
            plan_digest,
        };
        fresh.check_runway()?;
        Ok(fresh)
    }
}

struct CommonContextScanAccess<'a, A> {
    native: &'a StartedRosterCommonContextReadV1,
    outer: &'a A,
    deadline: Instant,
}
impl<A: LocalWalletAccess> LocalWalletAccess for CommonContextScanAccess<'_, A> {
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

/// Private exact facts with the immutable native-approved V3 context. This is
/// verification data only; it cannot issue native construction authority.
pub struct CommonContextVerifierSnapshot {
    historical: Option<SnapshotHistorical>,
    exact: ExactInputVerifierSnapshot,
    common: FrozenCommonContext,
    plan_digest: String,
}
impl ObservationChecks for FreshCommonContextObservation {
    fn check_current(&self) -> Result<()> {
        FreshCommonContextObservation::check_current(self)
    }
    fn check_runway(&self) -> Result<()> {
        FreshCommonContextObservation::check_runway(self)
    }
    fn mark_lock_attempted(&self) -> bool {
        self.lock_attempted.replace(true)
    }
}
pub struct CommonContextWalletSlot<'a> {
    historical: &'a Option<SnapshotHistorical>,
    native_read: &'a StartedRosterCommonContextReadV1,
    exact: ExactInputWalletSlot<'a>,
    common: &'a FrozenCommonContext,
    plan_digest: &'a str,
}
// Private lock-only carrier shared with component fixtures. It cannot be
// supplied to the public roster entry or manufacture an original native read.
struct CommonContextLockSlot<'a> {
    historical: &'a Option<SnapshotHistorical>,
    exact: ExactInputWalletSlot<'a>,
    common: &'a FrozenCommonContext,
    plan_digest: &'a str,
}
impl<'a> CommonContextWalletSlot<'a> {
    pub fn new(
        sync: &'a mut ProtectedWalletSync,
        snapshot: &'a CommonContextVerifierSnapshot,
        fresh: &'a FreshCommonContextObservation,
        restriction: &'a dyn ExactInputRestriction,
    ) -> Result<Self> {
        fresh.check_current()?;
        let s = &snapshot.exact;
        if sync.account != s.account
            || !Arc::ptr_eq(&s.material, &fresh.material)
            || !Weak::ptr_eq(&s.generation, &fresh.generation)
            || !Weak::ptr_eq(&s.generation, &Arc::downgrade(&sync.generation))
            || s.origin != fresh.origin
            || s.current != fresh.current
            || !sync.wallet.exact_input_fail_fast_v1
            || snapshot.common.digest != fresh.common.digest
            || snapshot.plan_digest != fresh.plan_digest
            || !snapshot.common.matches_snapshot(s)
        {
            return Err(ExactObservationError::Lineage);
        }
        Ok(Self {
            exact: ExactInputWalletSlot {
                sync,
                snapshot: s,
                fresh,
                restriction,
            },
            historical: &snapshot.historical,
            native_read: fresh.native_read(),
            common: &snapshot.common,
            plan_digest: &snapshot.plan_digest,
        })
    }
}

/// Borrows all actual maintained V3 wallet locks. No DTO, Clone, or callback-
/// escaping factory exists, and the V2 conversion does not accept this type.
pub struct HeldCommonContextRosterObservation<'a> {
    historical: &'a std::collections::BTreeMap<String, &'a SnapshotHistorical>,
    chain: &'a dyn GuardChain,
    current: &'a SelectionContext,
    count: usize,
    common: &'a FrozenCommonContext,
    plans: &'a std::collections::BTreeMap<String, String>,
    native_reads: &'a std::collections::BTreeMap<String, &'a StartedRosterCommonContextReadV1>,
}
impl HeldCommonContextRosterObservation<'_> {
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
    pub fn common_context_digest(&self) -> &str {
        &self.common.digest
    }
}
impl RetainedExactWalletMaterial {
    /// Only this V3-specific conversion can supply the approved common target.
    /// Both actual held wallet provenance and the separately consumed native
    /// full-proposal owner must match the same exact original read plan.
    pub fn into_common_context_construction(
        self,
        held: &HeldCommonContextRosterObservation<'_>,
        native: &AdmittedManualRosterConstructionContributionV3,
    ) -> Result<(
        wholepact_protocol::construction::OwnedContribution,
        wholepact_protocol::construction::ConstructionContext,
    )> {
        held.matches_material(&self)?;
        native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        let plan = &native
            .request()
            .map_err(|_| ExactObservationError::Permission)?
            .plan;
        let digest = plan.digest().map_err(|_| ExactObservationError::Binding)?;
        if held.plans.get(&self.contribution.account_id) != Some(&digest)
            || plan.common_context_digest != held.common.digest
        {
            return Err(ExactObservationError::Binding);
        }
        native
            .check_original_read(
                held.native_reads
                    .get(&self.contribution.account_id)
                    .ok_or(ExactObservationError::Binding)?,
            )
            .map_err(|_| ExactObservationError::Binding)?;
        verify_retained_binding(&self, &plan.retained)?;
        let context = held.common.construction_context()?;
        held.check_all_current()?;
        native
            .check_completion()
            .map_err(|_| ExactObservationError::Permission)?;
        Ok((self.contribution.into_contribution(), context))
    }
}

/// One deterministic actual-wallet lock wave. The frozen original tips may
/// differ; every current context must still be identical. Current tip+1 is used
/// for spendability in the shared maintained verifier, never the frozen target.
pub fn with_common_context_roster<R, E, F>(
    slots: Vec<CommonContextWalletSlot<'_>>,
    excluded_origins: &[[u8; 32]],
    callback: F,
) -> std::result::Result<R, E>
where
    E: From<ExactObservationError>,
    F: for<'guard> FnOnce(&HeldCommonContextRosterObservation<'guard>) -> std::result::Result<R, E>,
{
    let mut native_reads = std::collections::BTreeMap::new();
    let mut locks = Vec::with_capacity(slots.len());
    for slot in slots {
        // The shared lock kernel rejects duplicate account IDs before its leaf;
        // the same exact account IDs key both the plan and native-owner maps.
        native_reads.insert(
            slot.exact.snapshot.evidence.account_id.clone(),
            slot.native_read,
        );
        locks.push(CommonContextLockSlot {
            historical: slot.historical,
            exact: slot.exact,
            common: slot.common,
            plan_digest: slot.plan_digest,
        });
    }
    with_common_context_roster_locks(locks, native_reads, excluded_origins, callback)
}

// A private component seam, never an alternate native-owner issuer. An empty
// native map can exercise actual lock/spendability checks, but final construction
// still fails the mandatory original-read lookup above.
fn with_common_context_roster_locks<'a, R, E, F>(
    slots: Vec<CommonContextLockSlot<'a>>,
    native_reads: std::collections::BTreeMap<String, &'a StartedRosterCommonContextReadV1>,
    excluded_origins: &[[u8; 32]],
    callback: F,
) -> std::result::Result<R, E>
where
    E: From<ExactObservationError>,
    F: for<'guard> FnOnce(&HeldCommonContextRosterObservation<'guard>) -> std::result::Result<R, E>,
{
    let common = slots
        .first()
        .ok_or_else(|| E::from(ExactObservationError::Roster))?
        .common
        .clone();
    let mut plans = std::collections::BTreeMap::new();
    let mut historical = std::collections::BTreeMap::new();
    let mut valid = slots.len() == common.context.participants.len();
    for slot in &slots {
        if let Some(row) = slot.historical {
            historical.insert(slot.exact.snapshot.evidence.account_id.clone(), row);
        }
        valid &=
            slot.common.digest == common.digest && common.matches_snapshot(slot.exact.snapshot);
        valid &= plans
            .insert(
                slot.exact.snapshot.evidence.account_id.clone(),
                slot.plan_digest.to_owned(),
            )
            .is_none();
    }
    // The shared implementation marks every native lock attempt before it
    // evaluates even a malformed common roster. No failed attempt is reset.
    with_exact_input_roster_inner(
        slots.into_iter().map(|slot| slot.exact).collect(),
        excluded_origins,
        |snapshot, _| valid && common.matches_snapshot(snapshot),
        |held| {
            callback(&HeldCommonContextRosterObservation {
                historical: &historical,
                chain: held.chain,
                current: held.current,
                count: held.count,
                common: &common,
                plans: &plans,
                native_reads: &native_reads,
            })
        },
    )
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "common_context_roster_tests.rs"]
mod roster_tests;
