//! Exact pre-proof recapture from maintained wallet rows, never coin selection.
//! Public expectations constrain a read only. They provide no viewing key, note,
//! witness, native approval, current observation or construction admission.
//! The caller must authenticate the projection and the newly accepted manifest;
//! fresh all-input construction revalidation and later key-use policy still apply.
use super::durable_construction_v1::{
    DurableConstructionError, DurableConstructionScopeV1, canonical_durable_account_id,
};
use super::*;
use zcash_client_backend::wallet::Note as WalletNote;
use zcash_protocol::TxId;

type Result<T> = std::result::Result<T, DurableConstructionError>;

#[derive(Clone, PartialEq, Eq)]
pub struct DurableExactInputV1 {
    /// Exact canonical maintained outpoint, not a database row identifier.
    pub input_id: String,
    pub value_zatoshis: u64,
    /// Optional restriction only. Its absence never permits another input.
    pub commitment: Option<[u8; 32]>,
}
impl DurableExactInputV1 {
    pub fn outpoint(&self) -> Result<(TxId, u16)> {
        let (hash, index) = self
            .input_id
            .strip_prefix("ironwood:")
            .and_then(|s| s.split_once(':'))
            .ok_or(DurableConstructionError::Binding)?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DurableConstructionError::Binding);
        }
        let index: u16 = index
            .parse()
            .map_err(|_| DurableConstructionError::Binding)?;
        let mut raw = hex::decode(hash).map_err(|_| DurableConstructionError::Binding)?;
        raw.reverse();
        let txid = TxId::from_bytes(
            raw.try_into()
                .map_err(|_| DurableConstructionError::Binding)?,
        );
        if self.input_id != format!("ironwood:{txid}:{index}")
            || self.value_zatoshis == 0
            || self.value_zatoshis > MAX_MONEY
        {
            return Err(DurableConstructionError::Binding);
        }
        Ok((txid, index))
    }
}

/// Historical data restrictions, not an authenticated projection by themselves.
/// Inputs must be strictly ordered by canonical input ID. A caller choosing a
/// new pre-proof anchor must explicitly approve a new expectation; this API does
/// not change the supplied anchor or alter an already-frozen PCZT.
#[derive(Clone)]
pub struct DurableExactSelectionExpectationV1 {
    pub provider: BackendIdentity,
    pub original_context: SelectionContext,
    pub inputs: Vec<DurableExactInputV1>,
}

struct SnapshotError(DurableConstructionError);
impl From<rusqlite::Error> for SnapshotError {
    fn from(_: rusqlite::Error) -> Self {
        Self(DurableConstructionError::Storage)
    }
}

impl ProtectedWalletSync {
    /// Rebuild private contribution data for exactly the projected and newly
    /// accepted inputs. No generic selector, equal-value substitution, provider
    /// request, signing permit or serialized capability is used here.
    pub fn select_exact_durable_contribution_v1(
        &mut self,
        access: &impl LocalWalletAccess,
        authenticated_fvk: &FullViewingKey,
        scope: &DurableConstructionScopeV1,
        expected: &DurableExactSelectionExpectationV1,
    ) -> Result<ProtectedContribution> {
        self.require_access(access, WalletAccessPurpose::SelectPrivateContribution)?;
        let proposal = scope.validate()?;
        scope.check_valid_at(now()?)?;
        if canonical_durable_account_id(authenticated_fvk) != scope.account_id
            || expected.inputs.is_empty()
            || expected.inputs.len() > MAX_SELECTED_NOTES
            || expected
                .inputs
                .windows(2)
                .any(|w| w[0].input_id >= w[1].input_id)
            || self.source.identity() != &expected.provider
            || self.minimum_confirmations.get() < scope.minimum_confirmations
        {
            return Err(DurableConstructionError::Binding);
        }
        let own_inputs = proposal
            .manifest()
            .inputs
            .iter()
            .filter(|i| i.account_id == scope.account_id)
            .collect::<Vec<_>>();
        if own_inputs.len() != expected.inputs.len()
            || own_inputs.iter().any(|i| {
                i.participant_id != scope.participant_id
                    || !expected.inputs.iter().any(|n| {
                        n.input_id == i.input_id && n.value_zatoshis == i.amount.as_zatoshis()
                    })
            })
        {
            return Err(DurableConstructionError::Binding);
        }
        let outpoints = expected
            .inputs
            .iter()
            .map(DurableExactInputV1::outpoint)
            .collect::<Result<Vec<_>>>()?;
        let debit = proposal
            .accounting()
            .participant_net_debits
            .get(&scope.participant_id)
            .ok_or(DurableConstructionError::Binding)?
            .as_zatoshis();
        let accepted = self
            .accepted
            .as_ref()
            .ok_or(DurableConstructionError::Stale)?;
        let current = accepted.selection.clone();
        let chain = accepted.chain.clone();
        let started = accepted.monotonic_started;
        let original = &expected.original_context;
        let target = current
            .tip_height
            .checked_add(1)
            .ok_or(DurableConstructionError::Stale)?;
        if self.phase != SyncPhase::SnapshotMatched
            || chain.source() != &expected.provider
            || current.anchor_height != original.anchor_height
            || current.anchor_hash_protocol != original.anchor_hash_protocol
            || current.anchor_root != original.anchor_root
            || original.anchor_height > original.tip_height
            || current
                .tip_height
                .checked_sub(original.tip_height)
                .is_none_or(|n| n > scope.maximum_scan_blocks)
            || current
                .tip_height
                .checked_sub(current.anchor_height)
                .and_then(|n| n.checked_add(1))
                .is_none_or(|n| n < scope.minimum_confirmations)
            || target > scope.proposal.manifest.expiry_height
            || BranchId::for_height(&TEST_NETWORK, target.into()) != BranchId::Nu7
        {
            return Err(DurableConstructionError::Stale);
        }
        let account = self.account;
        let generation = Arc::downgrade(&self.generation);
        let identity = self
            .wallet
            .backup_identity
            .as_ref()
            .ok_or(DurableConstructionError::Storage)?;
        let check = || -> Result<()> {
            scope.check_valid_at(now()?)?;
            chain.check_fresh_at(now()?).map_err(SyncError::from)?;
            check_observation_elapsed(&chain, elapsed_since(started)?)?;
            if generation.upgrade().is_none() {
                return Err(DurableConstructionError::Stale);
            }
            if !access.permits(
                account,
                &expected.provider,
                WalletAccessPurpose::SelectPrivateContribution,
            ) {
                return Err(SyncError::AccessDenied.into());
            }
            identity
                .check()
                .map_err(|_| DurableConstructionError::Storage)
        };
        check()?;
        let contribution = self.wallet.db.transactionally_with_extension(|db, extension| {
            let mut read = || -> Result<WalletContribution> {
                check()?;
                let quarantined: bool = extension.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='wholepact_bundle_quarantine')", [], |r| r.get(0))
                    .map_err(|_| DurableConstructionError::Storage)?;
                if quarantined || db.get_account_ids().map_err(|_| DurableConstructionError::Storage)? != vec![account]
                    || db.block_fully_scanned().map_err(|_| DurableConstructionError::Storage)?
                        .map(|b| u32::from(b.block_height())) != Some(current.tip_height)
                    || db.chain_height().map_err(|_| DurableConstructionError::Storage)? != Some(current.tip_height.into())
                { return Err(DurableConstructionError::Stale); }
                let local = db.get_account(account).map_err(|_| DurableConstructionError::Storage)?
                    .ok_or(DurableConstructionError::Binding)?;
                if local.ufvk().and_then(|k| k.orchard()).is_none_or(|f| f.to_bytes() != authenticated_fvk.to_bytes()) {
                    return Err(DurableConstructionError::Binding);
                }
                for (height, hash) in [(original.tip_height, original.tip_hash_protocol),
                    (current.tip_height, current.tip_hash_protocol), (current.anchor_height, current.anchor_hash_protocol)] {
                    if db.get_block_hash(height.into()).map_err(|_| DurableConstructionError::Storage)?.map(|b| b.0) != Some(hash) {
                        return Err(DurableConstructionError::Stale);
                    }
                }
                if !db.anchor_computable(ShieldedPool::Ironwood, current.anchor_height.into())
                    .map_err(|_| DurableConstructionError::Storage)? { return Err(DurableConstructionError::Stale); }
                let mut selected = Vec::with_capacity(expected.inputs.len());
                let mut nullifiers = BTreeSet::new();
                let mut total = 0u64;
                for (input, (txid, index)) in expected.inputs.iter().zip(&outpoints) {
                    check()?;
                    let received = db.get_spendable_note(txid, ShieldedPool::Ironwood, u32::from(*index), target.into(),
                        LockFilter::Policy(&LockedInputPolicy::Exclude)).map_err(|_| DurableConstructionError::Storage)?
                        .ok_or(DurableConstructionError::Stale)?;
                    let WalletNote::Orchard { note, pool: orchard::ValuePool::Ironwood } = received.note()
                        else { return Err(DurableConstructionError::Binding); };
                    let commitment = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
                    if received.txid() != txid || received.output_index() != *index || note.version() != NoteVersion::V3
                        || note.value().inner() != input.value_zatoshis
                        || input.commitment.is_some_and(|expected| expected != commitment)
                        || authenticated_fvk.scope_for_address(&note.recipient()) != Some(received.spending_key_scope())
                        || received.mined_height().is_none_or(|h| u32::from(h) > current.anchor_height)
                        || !nullifiers.insert(note.nullifier(authenticated_fvk).to_bytes())
                    { return Err(DurableConstructionError::Binding); }
                    total = total.checked_add(note.value().inner()).filter(|v| *v <= MAX_MONEY)
                        .ok_or(DurableConstructionError::Binding)?;
                    selected.push((*note, received.note_commitment_tree_position(), *received.internal_note_id(), *txid, *index));
                }
                let change = total.checked_sub(debit).ok_or(DurableConstructionError::Binding)?;
                let change_address = authenticated_fvk.address_at(0u32, Scope::Internal);
                let returns = proposal.manifest().outputs.iter().filter(|o| matches!(&o.allocation,
                    wholepact_core::OutputAllocation::Return {account_id, ..} if account_id == &scope.account_id))
                    .collect::<Vec<_>>();
                if (change == 0 && !returns.is_empty()) || (change > 0 && (returns.len() != 1
                    || returns[0].amount.as_zatoshis() != change
                    || wholepact_protocol::review::decode_testnet_receiver(&returns[0].address).ok() != Some(change_address))) {
                    return Err(DurableConstructionError::Binding);
                }
                let notes = db.with_ironwood_tree_mut::<_, _, WalletError>(|tree| {
                    let anchor = current.anchor_height.into();
                    let root = tree.root_at_checkpoint_id(&anchor)?.ok_or(WalletError::MissingWitness)?;
                    if orchard::Anchor::from(root).to_bytes() != current.anchor_root { return Err(WalletError::ChainMismatch); }
                    selected.iter().zip(&expected.inputs).map(|((note, position, _, _, _), input)| {
                        let witness: MerklePath = tree.witness_at_checkpoint_id_caching(*position, &anchor)?
                            .ok_or(WalletError::MissingWitness)?.into();
                        if witness.root(note.commitment().into()).to_bytes() != current.anchor_root {
                            return Err(WalletError::InvalidNote);
                        }
                        Ok(SelectedNote { input_id: input.input_id.clone(), note: *note, witness })
                    }).collect::<std::result::Result<Vec<_>, WalletError>>()
                })?.ok_or(DurableConstructionError::Stale)?;
                check()?;
                Ok(WalletContribution {
                    account_id: scope.account_id.clone(), fvk: authenticated_fvk.clone(), notes, change_address,
                    selected_zatoshis: total, requested_debit_zatoshis: debit, context: current.clone(),
                    local_note_refs: selected.iter().map(|v| v.2).collect(),
                    local_outpoints: selected.iter().map(|v| (v.3, v.4)).collect(),
                })
            };
            read().map_err(SnapshotError)
        }).map_err(|e: SnapshotError| e.0)?;
        check()?;
        Ok(ProtectedContribution {
            monotonic_started: started,
            observation: chain,
            generation,
            contribution,
        })
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "durable_exact_selection_v1_tests.rs"]
mod tests;
