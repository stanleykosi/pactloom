//! Exact local-wallet revalidation held through a synchronous key-use callback.
//!
//! This observes the maintained scanner's unspent state at an explicitly trusted
//! provider's tip. It does not observe a global mempool, validate consensus, reserve
//! chain inputs, or prevent another wallet or a concurrent chain reorganization.
//! A separate signer must bind this context to exact consent and an independent
//! writer/exposure authority. Neither a ticket nor a successful check is consent.
use super::*;
pub use crate::{WalletKeyUseConfidence, WalletKeyUsePolicy};
use zcash_client_backend::wallet::Note as WalletNote;
use zcash_protocol::TxId;

impl WalletKeyUsePolicy {
    fn validate(&self, source: &BackendIdentity) -> Result<(), WalletKeyUseError> {
        if self.source_id != source.source_id
            || self.endpoint != source.endpoint
            || !(1..=300).contains(&self.maximum_observation_age_seconds)
            || self.minimum_confirmations == 0
            || self.minimum_expiry_margin_blocks == 0
        {
            return Err(WalletKeyUseError::Policy);
        }
        let supported = match self.confidence {
            WalletKeyUseConfidence::TrustedSingleProviderSnapshot => {
                source.trust_profile == "single_tls_provider_report_not_consensus"
            }
            WalletKeyUseConfidence::IndependentlyVerifiedConsensus => false,
            WalletKeyUseConfidence::SyntheticNeverChainEvidence => {
                cfg!(feature = "synthetic-qualification")
                    && source.trust_profile == "synthetic_never_chain_evidence"
            }
        };
        if !supported {
            return Err(WalletKeyUseError::Policy);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletKeyUseError {
    #[error("held wallet key-use permission is absent, expired, revoked, or mismatched")]
    Permission,
    #[error(
        "the approved wallet source confidence or freshness policy is unsupported or mismatched"
    )]
    Policy,
    #[error("wallet selection belongs to an earlier, reopened, or different scan generation")]
    SelectionExpired,
    #[error("wallet key-use storage lock or identity check failed")]
    Storage,
    #[error("restored wallet requires recovery before any key use")]
    RecoveryRequired,
    #[error("wallet state, exact selected input, or chain context changed before key use")]
    StateChanged,
    #[error("the transaction is inside the approved conservative expiry margin")]
    Expiry,
    #[error(transparent)]
    Sync(#[from] SyncError),
}
impl From<WalletError> for WalletKeyUseError {
    fn from(e: WalletError) -> Self {
        Self::Sync(e.into())
    }
}

/// Scope passed only to a trusted native permission adapter. That adapter must
/// own a revocation-serialized native authorization lease, check its exact
/// account/FVK/provider/policy/expiry bindings, and keep it held until return.
/// Implementing this trait in an untrusted application confers no authority.
pub struct WalletKeyUseScope<'a> {
    pub wallet_account: AccountUuid,
    pub account_id: &'a str,
    pub authenticated_fvk: &'a FullViewingKey,
    pub source: &'a BackendIdentity,
    pub policy: &'a WalletKeyUsePolicy,
    pub transaction_expiry_height: u32,
}
pub trait HeldWalletPermission {
    fn check_current(&self, scope: &WalletKeyUseScope<'_>) -> Result<(), WalletKeyUseError>;
}

/// Non-serializable, private construction provenance. Retain it locally alongside
/// exact review; never persist or reconstruct it from a request or consent DTO.
/// A sync attempt, restart, restore/reopen, or controller drop invalidates it.
pub struct WalletKeyUseTicket {
    monotonic_started: Instant,
    evidence: LocallySelectedInputs,
    local_note_refs: Vec<ReceivedNoteId>,
    local_outpoints: Vec<(TxId, u16)>,
    generation: Weak<()>,
    observation: ChainContext,
    notes: Vec<(Note, u32)>,
}
impl WalletKeyUseTicket {
    pub fn evidence(&self) -> &LocallySelectedInputs {
        &self.evidence
    }
    pub fn observation(&self) -> &ChainContext {
        &self.observation
    }
    pub fn validate_policy(&self, policy: &WalletKeyUsePolicy) -> Result<(), WalletKeyUseError> {
        if self.generation.upgrade().is_none() {
            return Err(WalletKeyUseError::SelectionExpired);
        }
        policy.validate(self.observation.source())?;
        check_observation_freshness(&self.observation, self.monotonic_started, policy)?;
        let context = &self.evidence.context;
        if context.anchor_height > context.tip_height
            || context.tip_height - context.anchor_height + 1 < policy.minimum_confirmations
        {
            return Err(WalletKeyUseError::Policy);
        }
        Ok(())
    }
}
impl ProtectedContribution {
    pub fn key_use_ticket(&self) -> WalletKeyUseTicket {
        WalletKeyUseTicket {
            monotonic_started: self.monotonic_started,
            evidence: self.contribution.evidence(),
            local_note_refs: self.contribution.local_note_refs.clone(),
            local_outpoints: self.contribution.local_outpoints.clone(),
            generation: self.generation.clone(),
            observation: self.observation.clone(),
            notes: self
                .contribution
                .notes
                .iter()
                .map(|n| (n.note, n.witness.position()))
                .collect(),
        }
    }
}

/// Available only inside the locked callback. It cannot be constructed by the
/// signer or deserialized. The callback must check immediately before key use,
/// and persist its exact result before returning and releasing the wallet lock.
pub struct HeldWalletKeyUse<'a> {
    evidence: &'a LocallySelectedInputs,
    observation: &'a ChainContext,
    policy: &'a WalletKeyUsePolicy,
    transaction_expiry_height: u32,
    check: &'a dyn Fn() -> Result<(), WalletKeyUseError>,
}
impl HeldWalletKeyUse<'_> {
    pub fn check_current(&self) -> Result<(), WalletKeyUseError> {
        (self.check)()
    }
    pub fn evidence(&self) -> &LocallySelectedInputs {
        self.evidence
    }
    pub fn observation(&self) -> &ChainContext {
        self.observation
    }
    pub fn policy(&self) -> &WalletKeyUsePolicy {
        self.policy
    }
    pub fn transaction_expiry_height(&self) -> u32 {
        self.transaction_expiry_height
    }
}

struct TransactionError<E>(E);
impl<E: From<WalletKeyUseError>> From<rusqlite::Error> for TransactionError<E> {
    fn from(_: rusqlite::Error) -> Self {
        Self(WalletKeyUseError::Storage.into())
    }
}

impl ProtectedWalletSync {
    /// Holds the actual maintained wallet's BEGIN IMMEDIATE transaction, its
    /// exclusive Rust borrow, and the supplied native permission through callback
    /// completion. No network requests or alternative input selection occur here.
    /// Ordinary other connections cannot write during key use, including in WAL.
    /// File replacement is checked before and after use; arbitrary OS compromise
    /// and same-file disk rollback still require the independent writer authority.
    #[allow(clippy::too_many_arguments)]
    pub fn with_key_use_guard<R, E: From<WalletKeyUseError>>(
        &mut self,
        permission: &impl HeldWalletPermission,
        ticket: &WalletKeyUseTicket,
        authenticated_fvk: &FullViewingKey,
        policy: &WalletKeyUsePolicy,
        transaction_expiry_height: u32,
        use_key: impl FnOnce(&HeldWalletKeyUse<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        let accepted = self
            .accepted
            .as_ref()
            .ok_or_else(|| E::from(WalletKeyUseError::SelectionExpired))?;
        let current_generation = ticket
            .generation
            .upgrade()
            .ok_or_else(|| E::from(WalletKeyUseError::SelectionExpired))?;
        if self.phase != SyncPhase::SnapshotMatched
            || !Arc::ptr_eq(&current_generation, &self.generation)
            || accepted.monotonic_started != ticket.monotonic_started
            || accepted.selection != ticket.evidence.context
            || accepted.chain.source() != ticket.observation.source()
            || accepted.chain.tip() != ticket.observation.tip()
            || accepted.chain.observed_at_unix_seconds()
                != ticket.observation.observed_at_unix_seconds()
            || accepted.chain.valid_until_unix_seconds()
                != ticket.observation.valid_until_unix_seconds()
        {
            return Err(WalletKeyUseError::SelectionExpired.into());
        }
        policy.validate(self.source.identity()).map_err(E::from)?;
        if self.minimum_confirmations.get() < policy.minimum_confirmations
            || authenticated_fvk.to_bytes() != ticket.evidence.fvk.to_bytes()
        {
            return Err(WalletKeyUseError::Policy.into());
        }
        let scope = WalletKeyUseScope {
            wallet_account: self.account,
            account_id: ticket.evidence.account_id(),
            authenticated_fvk,
            source: self.source.identity(),
            policy,
            transaction_expiry_height,
        };
        let check_external = || {
            #[cfg(target_os = "linux")]
            self.wallet
                .backup_identity
                .as_ref()
                .ok_or(WalletKeyUseError::Storage)?
                .check()
                .map_err(|_| WalletKeyUseError::Storage)?;
            #[cfg(not(target_os = "linux"))]
            return Err(WalletKeyUseError::Storage);
            check_freshness(
                &accepted.chain,
                accepted.monotonic_started,
                policy,
                transaction_expiry_height,
            )?;
            permission.check_current(&scope)
        };
        check_external().map_err(E::from)?;
        self.wallet
            .db
            .transactionally_with_extension(|db, extension| {
                // A supported restore always carries this quarantine marker. The
                // maintained extension API permits read-only schema inspection.
                let check_recovery = || {
                    let quarantined: bool = extension.query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='wholepact_bundle_quarantine')",
                        [], |row| row.get(0),
                    ).map_err(|_| WalletKeyUseError::Storage)?;
                    if quarantined { return Err(WalletKeyUseError::RecoveryRequired); }
                    Ok(())
                };
                check_recovery().map_err(|e| TransactionError(E::from(e)))?;
                // The initial lock is acquired before any reads. Build and verify the
                // actual retained tree root under that same transaction.
                verify_exact_notes(db, ticket, self.account, authenticated_fvk, policy)
                    .map_err(|e| TransactionError(E::from(e)))?;
                db.with_ironwood_tree_mut::<_, _, WalletError>(|tree| {
                    let root = tree
                        .root_at_checkpoint_id(&ticket.evidence.context.anchor_height.into())?
                        .ok_or(WalletError::MissingWitness)?;
                    if orchard::Anchor::from(root).to_bytes() != ticket.evidence.context.anchor_root
                    {
                        return Err(WalletError::ChainMismatch);
                    }
                    for (note, position) in &ticket.notes {
                        let witness: MerklePath = tree
                            .witness_at_checkpoint_id_caching(
                                u64::from(*position).into(),
                                &ticket.evidence.context.anchor_height.into(),
                            )?
                            .ok_or(WalletError::MissingWitness)?
                            .into();
                        if witness.root(note.commitment().into()).to_bytes()
                            != ticket.evidence.context.anchor_root
                        {
                            return Err(WalletError::InvalidNote);
                        }
                    }
                    Ok(())
                })
                .map_err(|e| TransactionError(E::from(WalletKeyUseError::from(e))))?
                .ok_or_else(|| TransactionError(E::from(WalletKeyUseError::StateChanged)))?;
                let check = || {
                    check_recovery()?;
                    check_external()?;
                    verify_exact_notes(db, ticket, self.account, authenticated_fvk, policy)
                };
                let held = HeldWalletKeyUse {
                    evidence: &ticket.evidence,
                    observation: &accepted.chain,
                    policy,
                    transaction_expiry_height,
                    check: &check,
                };
                held.check_current()
                    .map_err(|e| TransactionError(E::from(e)))?;
                let result = use_key(&held).map_err(TransactionError)?;
                // If a permission expires or a path is replaced after signing, the
                // caller retains its conservative durable result/exposure. This error
                // never grants permission to generate a replacement authorization.
                held.check_current()
                    .map_err(|e| TransactionError(E::from(e)))?;
                Ok(result)
            })
            .map_err(|e: TransactionError<E>| e.0)
    }
}

fn check_observation_freshness(
    observed: &ChainContext,
    monotonic_started: Instant,
    policy: &WalletKeyUsePolicy,
) -> Result<(), WalletKeyUseError> {
    check_observation_freshness_at(observed, policy, now()?)?;
    check_monotonic_freshness(observed, policy, elapsed_since(monotonic_started)?)
}

fn check_monotonic_freshness(
    observed: &ChainContext,
    policy: &WalletKeyUsePolicy,
    elapsed: Duration,
) -> Result<(), WalletKeyUseError> {
    check_observation_elapsed(observed, elapsed)?;
    let advertised_age = observed
        .rpc_cache_observations()
        .iter()
        .filter_map(|o| o.reported_age_seconds)
        .max()
        .unwrap_or(0);
    let maximum_age = Duration::from_secs(u64::from(policy.maximum_observation_age_seconds));
    if elapsed
        .checked_add(Duration::from_secs(advertised_age))
        .is_none_or(|age| age > maximum_age)
    {
        return Err(SyncError::NoCurrentObservation.into());
    }
    Ok(())
}

fn check_observation_freshness_at(
    observed: &ChainContext,
    policy: &WalletKeyUsePolicy,
    time: u64,
) -> Result<(), WalletKeyUseError> {
    observed.check_fresh_at(time).map_err(SyncError::from)?;
    let reported_age = observed
        .rpc_cache_observations()
        .iter()
        .filter_map(|o| o.reported_age_seconds)
        .max()
        .unwrap_or(0);
    let earliest = observed
        .request_started_at_unix_seconds()
        .checked_sub(reported_age)
        .ok_or(SyncError::NoCurrentObservation)?;
    if time
        .checked_sub(earliest)
        .is_none_or(|age| age > u64::from(policy.maximum_observation_age_seconds))
    {
        return Err(SyncError::NoCurrentObservation.into());
    }
    Ok(())
}

fn check_freshness(
    observed: &ChainContext,
    monotonic_started: Instant,
    policy: &WalletKeyUsePolicy,
    transaction_expiry_height: u32,
) -> Result<(), WalletKeyUseError> {
    check_observation_freshness(observed, monotonic_started, policy)?;
    if observed
        .tip()
        .height
        .checked_add(u64::from(policy.minimum_expiry_margin_blocks))
        .is_none_or(|height| height >= u64::from(transaction_expiry_height))
    {
        return Err(WalletKeyUseError::Expiry);
    }
    Ok(())
}

fn verify_exact_notes<D>(
    db: &D,
    ticket: &WalletKeyUseTicket,
    account: AccountUuid,
    authenticated_fvk: &FullViewingKey,
    policy: &WalletKeyUsePolicy,
) -> Result<(), WalletKeyUseError>
where
    D: WalletRead<AccountId = AccountUuid>
        + InputSource<AccountId = AccountUuid, NoteRef = ReceivedNoteId>,
{
    let changed = |_| WalletKeyUseError::StateChanged;
    let context = &ticket.evidence.context;
    let count = ticket.evidence.inputs.len();
    if count == 0
        || count > MAX_SELECTED_NOTES
        || count != ticket.local_note_refs.len()
        || count != ticket.local_outpoints.len()
        || count != ticket.notes.len()
        || context.anchor_height > context.tip_height
        || context.tip_height - context.anchor_height + 1 < policy.minimum_confirmations
        || db.get_account_ids().map_err(changed)? != vec![account]
    {
        return Err(WalletKeyUseError::StateChanged);
    }
    let local = db
        .get_account(account)
        .map_err(changed)?
        .ok_or(WalletKeyUseError::StateChanged)?;
    if local
        .ufvk()
        .and_then(|k| k.orchard())
        .is_none_or(|fvk| fvk.to_bytes() != authenticated_fvk.to_bytes())
        || db
            .block_fully_scanned()
            .map_err(changed)?
            .map(|b| u32::from(b.block_height()))
            != Some(context.tip_height)
        || db.chain_height().map_err(changed)? != Some(context.tip_height.into())
    {
        return Err(WalletKeyUseError::StateChanged);
    }
    for (height, hash) in [
        (context.tip_height, context.tip_hash_protocol),
        (context.anchor_height, context.anchor_hash_protocol),
    ] {
        if db
            .get_block_hash(height.into())
            .map_err(changed)?
            .map(|h| h.0)
            != Some(hash)
        {
            return Err(WalletKeyUseError::StateChanged);
        }
    }
    let target = context
        .tip_height
        .checked_add(1)
        .ok_or(WalletKeyUseError::StateChanged)?;
    if BranchId::for_height(&TEST_NETWORK, target.into()) != BranchId::Nu7
        || !db
            .anchor_computable(ShieldedPool::Ironwood, context.anchor_height.into())
            .map_err(|_| WalletKeyUseError::StateChanged)?
    {
        return Err(WalletKeyUseError::StateChanged);
    }
    let mut nullifiers = BTreeSet::new();
    for (((expected, note_ref), (txid, index)), (original_note, original_position)) in ticket
        .evidence
        .inputs
        .iter()
        .zip(&ticket.local_note_refs)
        .zip(&ticket.local_outpoints)
        .zip(&ticket.notes)
    {
        let received = db
            .get_spendable_note(
                txid,
                ShieldedPool::Ironwood,
                u32::from(*index),
                target.into(),
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(|_| WalletKeyUseError::StateChanged)?
            .ok_or(WalletKeyUseError::StateChanged)?;
        let WalletNote::Orchard {
            note,
            pool: orchard::ValuePool::Ironwood,
        } = received.note()
        else {
            return Err(WalletKeyUseError::StateChanged);
        };
        let nullifier = note.nullifier(authenticated_fvk).to_bytes();
        if note != original_note
            || u64::from(received.note_commitment_tree_position()) != u64::from(*original_position)
            || received.internal_note_id() != note_ref
            || received.txid() != txid
            || received.output_index() != *index
            || expected.input_id != format!("ironwood:{txid}:{index}")
            || note.version() != NoteVersion::V3
            || note.value().inner() == 0
            || expected.value_zatoshis != note.value().inner()
            || expected.nullifier != nullifier
            || !nullifiers.insert(nullifier)
            || authenticated_fvk.scope_for_address(&note.recipient())
                != Some(received.spending_key_scope())
            || received
                .mined_height()
                .is_none_or(|h| u32::from(h) > context.anchor_height)
        {
            return Err(WalletKeyUseError::StateChanged);
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "synthetic-qualification", target_os = "linux"))]
#[path = "wallet_key_use_tests.rs"]
mod tests;
