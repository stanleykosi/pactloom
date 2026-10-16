//! Maintained SQLite multi-wallet COMPONENT tests. Ephemeral never-funded owners,
//! fabricated chain, no provider/native ceremony/financial claim. The private
//! ObservationChecks scaffolding cannot be used by the public slot constructor.
use super::*;
use std::cell::{Cell, RefCell};
use wholepact_storage_security::{
    DatabaseKey, EncryptedConnection, create_encrypted, open_encrypted,
};
use zcash_primitives::block::BlockHash;

pub(super) struct ComponentObservation {
    pub(super) active: Cell<bool>,
    pub(super) remaining_ms: Cell<u64>,
    pub(super) attempted: Cell<bool>,
}
impl ComponentObservation {
    pub(super) fn new() -> Self {
        Self {
            active: Cell::new(true),
            remaining_ms: Cell::new(60_000),
            attempted: Cell::new(false),
        }
    }
}
impl ObservationChecks for ComponentObservation {
    fn check_current(&self) -> Result<()> {
        if self.active.get() && self.remaining_ms.get() > 0 {
            Ok(())
        } else {
            Err(ExactObservationError::Budget)
        }
    }
    fn check_runway(&self) -> Result<()> {
        self.check_current()?;
        if self.remaining_ms.get() > 10_000 {
            Ok(())
        } else {
            Err(ExactObservationError::Budget)
        }
    }
    fn mark_lock_attempted(&self) -> bool {
        self.attempted.replace(true)
    }
}
pub(super) struct AllowComponent;
impl ExactInputRestriction for AllowComponent {
    fn check_current(&self, _: AccountUuid) -> Result<()> {
        Ok(())
    }
}
pub(super) struct Fixture {
    pub(super) _directory: tempfile::TempDir,
    pub(super) wallets: Vec<ProtectedWalletSync>,
    pub(super) snapshots: Vec<ExactInputVerifierSnapshot>,
    pub(super) competitors: Vec<EncryptedConnection>,
}
pub(super) fn fixture() -> Fixture {
    fixture_with_original_offsets([0, 0], 0)
}
pub(super) fn fixture_with_original_offsets(offsets: [u32; 2], current_offset: u32) -> Fixture {
    use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = crate::wallet::synthetic_fixture::SyntheticContributionFixture::generate();
    let (_, _, _, context, blocks) =
        crate::wallet::qualification::synthetic_wallet_with_fixture(&fixture);
    let mut wallets = Vec::new();
    let mut snapshots = Vec::new();
    let mut competitors = Vec::new();
    for (index, offset) in offsets.into_iter().enumerate() {
        let fvk = FullViewingKey::from(fixture.owner_spending_key(index));
        let mut key_bytes = [0; 32];
        UnwrapErr(SysRng).fill_bytes(&mut key_bytes);
        let key = DatabaseKey::from_bytes(key_bytes);
        let path = directory.path().join(format!("component-{index}.sqlite"));
        let connection = create_encrypted(&path, &key).unwrap();
        connection
            .connection()
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        let mut wallet =
            DedicatedTestnetWallet::from_encrypted_connection_recordable_roster_exact_input_v1(
                connection,
            )
            .unwrap();
        let prior = ChainState::empty((context.tip_height - 1).into(), BlockHash([50; 32]));
        let account = wallet
            .import_dedicated_fvk(&fvk, AccountBirthday::from_parts(prior.clone(), None))
            .unwrap();
        wallet
            .scan_cached(&blocks, &prior, 1, context.tip_height)
            .unwrap();
        scan_empty_to(
            &mut wallet,
            &context,
            context.tip_height,
            context.tip_height + offset,
        );
        let mut original = context.clone();
        original.tip_height += offset;
        original.tip_hash_protocol = [51 + offset as u8; 32];
        let selected = wallet
            .select_contribution(
                account,
                &fvk,
                &format!("component-{index}"),
                100_000,
                NonZeroU32::MIN,
                &original,
                &[],
            )
            .unwrap();
        scan_empty_to(
            &mut wallet,
            &context,
            original.tip_height,
            context.tip_height + current_offset,
        );
        let mut current = context.clone();
        current.tip_height += current_offset;
        current.tip_hash_protocol = [51 + current_offset as u8; 32];
        // Simulate consumption of the DISTINCT import issuer. Its read-only
        // original file identity must remain available to this exact route.
        wallet.recorded_roster_import_origin_v2.take().unwrap();
        assert!(wallet.exact_input_origin_v1.is_some());
        let source = ChainAdapter::synthetic_loopback_for_qualification(
            "http://127.0.0.1:1",
            NetworkPolicy::default(),
        )
        .unwrap();
        let sync =
            ProtectedWalletSync::from_initialized_wallet(wallet, source, NonZeroU32::MIN).unwrap();
        let origin = sync
            .wallet
            .exact_input_origin_v1
            .as_ref()
            .unwrap()
            .0
            .origin_commitment();
        snapshots.push(ExactInputVerifierSnapshot {
            material: Arc::new(()),
            generation: Arc::downgrade(&sync.generation),
            account,
            origin,
            evidence: selected.evidence(),
            notes: selected
                .notes
                .iter()
                .map(|n| (n.note, n.witness.position()))
                .collect(),
            local_note_refs: selected.local_note_refs.clone(),
            local_outpoints: selected.local_outpoints.clone(),
            current,
            birthday: context.tip_height,
            participant_id: format!("component-participant-{index}"),
            minimum_confirmations: 1,
            required_ancestry: Vec::new(),
        });
        let competitor = open_encrypted(&path, &key).unwrap();
        competitor
            .connection()
            .busy_timeout(Duration::ZERO)
            .unwrap();
        competitors.push(competitor);
        wallets.push(sync);
    }
    Fixture {
        _directory: directory,
        wallets,
        snapshots,
        competitors,
    }
}
// Empty fabricated blocks advance maintained checkpoints while retaining the
// original real Ironwood witnesses. No provider or proof operation is involved.
fn scan_empty_to(
    wallet: &mut DedicatedTestnetWallet,
    anchor: &SelectionContext,
    from: u32,
    target: u32,
) {
    use incrementalmerkletree::frontier::Frontier;
    use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactBlock};
    for height in from + 1..=target {
        let tree = wallet
            .db
            .with_ironwood_tree_mut::<_, _, WalletError>(|tree| Ok(tree.frontier()?))
            .unwrap()
            .unwrap();
        let size = tree.tree_size() as u32;
        let prior = ChainState::new(
            (height - 1).into(),
            BlockHash([50 + (height - anchor.tip_height) as u8; 32]),
            Frontier::empty(),
            Frontier::empty(),
            tree,
        );
        let blocks = crate::wallet::qualification::Blocks(vec![CompactBlock {
            height: u64::from(height),
            hash: vec![51 + (height - anchor.tip_height) as u8; 32],
            prev_hash: vec![50 + (height - anchor.tip_height) as u8; 32],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: size,
            }),
            ..Default::default()
        }]);
        wallet.scan_cached(&blocks, &prior, 1, height).unwrap();
    }
}
pub(super) fn try_write(connection: &EncryptedConnection) -> bool {
    match connection.connection().execute_batch("BEGIN IMMEDIATE;") {
        Ok(()) => {
            connection.connection().execute_batch("ROLLBACK;").unwrap();
            true
        }
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy =>
        {
            false
        }
        Err(error) => panic!("unexpected synthetic lock error: {error}"),
    }
}
pub(super) fn component_slots<'a>(
    wallets: &'a mut [ProtectedWalletSync],
    snapshots: &'a [ExactInputVerifierSnapshot],
    observations: &'a [ComponentObservation],
    restriction: &'a dyn ExactInputRestriction,
) -> Vec<ExactInputWalletSlot<'a>> {
    let mut slots: Vec<_> = wallets
        .iter_mut()
        .zip(snapshots)
        .zip(observations)
        .map(|((sync, snapshot), fresh)| ExactInputWalletSlot {
            sync,
            snapshot,
            fresh,
            restriction,
        })
        .collect();
    // Deliberately reverse actual file-origin order; production must sort it.
    slots.sort_by_key(|s| std::cmp::Reverse(s.snapshot.origin));
    slots
}
pub(super) struct ObserveAcquisition<'a> {
    pub(super) accounts: [AccountUuid; 2],
    pub(super) competitors: &'a [EncryptedConnection],
    pub(super) observed: RefCell<Vec<AccountUuid>>,
}
impl ExactInputRestriction for ObserveAcquisition<'_> {
    fn check_current(&self, account: AccountUuid) -> Result<()> {
        let index = self.accounts.iter().position(|a| *a == account).unwrap();
        if !try_write(&self.competitors[index]) && !self.observed.borrow().contains(&account) {
            self.observed.borrow_mut().push(account);
        }
        Ok(())
    }
}
#[test]
fn actual_two_wallet_wal_locks_are_sorted_and_held_through_leaf() {
    let mut f = fixture();
    let observations = [ComponentObservation::new(), ComponentObservation::new()];
    let restriction = ObserveAcquisition {
        accounts: [f.snapshots[0].account, f.snapshots[1].account],
        competitors: &f.competitors,
        observed: RefCell::new(Vec::new()),
    };
    let mut sorted = [
        (f.snapshots[0].origin, f.snapshots[0].account),
        (f.snapshots[1].origin, f.snapshots[1].account),
    ];
    sorted.sort_by_key(|e| e.0);
    let mut calls = 0;
    with_exact_input_roster(
        component_slots(&mut f.wallets, &f.snapshots, &observations, &restriction),
        &[[0; 32], [1; 32]],
        |held| {
            held.check_all_current()?;
            assert_eq!(held.participant_count(), 2);
            assert_eq!(
                *restriction.observed.borrow(),
                sorted.iter().map(|e| e.1).collect::<Vec<_>>()
            );
            assert!(f.competitors.iter().all(|c| !try_write(c)));
            calls += 1;
            Ok::<_, ExactObservationError>(())
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert!(f.competitors.iter().all(try_write));
}
#[test]
fn contended_second_wallet_denies_without_leaf_and_releases_first() {
    let mut f = fixture();
    let high = usize::from(f.snapshots[1].origin > f.snapshots[0].origin);
    f.competitors[high]
        .connection()
        .execute_batch("BEGIN IMMEDIATE;")
        .unwrap();
    let observations = [ComponentObservation::new(), ComponentObservation::new()];
    let mut calls = 0;
    let result = with_exact_input_roster(
        component_slots(&mut f.wallets, &f.snapshots, &observations, &AllowComponent),
        &[[0; 32], [1; 32]],
        |_| {
            calls += 1;
            Ok::<_, ExactObservationError>(())
        },
    );
    assert!(matches!(result, Err(ExactObservationError::Storage)));
    assert_eq!(calls, 0);
    assert!(try_write(&f.competitors[1 - high]));
    f.competitors[high]
        .connection()
        .execute_batch("ROLLBACK;")
        .unwrap();
    assert!(try_write(&f.competitors[high]));
    assert!(observations.iter().all(|o| o.attempted.get()));
}
#[test]
fn aliases_deny_before_any_leaf() {
    let mut f = fixture();
    let observations = [ComponentObservation::new(), ComponentObservation::new()];
    let alias = f.snapshots[0].origin;
    let calls = Cell::new(0);
    let result = with_exact_input_roster(
        component_slots(&mut f.wallets, &f.snapshots, &observations, &AllowComponent),
        &[alias, [1; 32]],
        |_| {
            calls.set(calls.get() + 1);
            Ok::<_, ExactObservationError>(())
        },
    );
    assert!(matches!(result, Err(ExactObservationError::Roster)));
    assert_eq!(calls.get(), 0);
    assert!(f.competitors.iter().all(try_write));
}
pub(super) struct DelayMiddle<'a> {
    pub(super) first: usize,
    pub(super) f: &'a [ComponentObservation],
    pub(super) competitors: &'a [EncryptedConnection],
    pub(super) fired: Cell<bool>,
}
impl ExactInputRestriction for DelayMiddle<'_> {
    fn check_current(&self, _: AccountUuid) -> Result<()> {
        if !self.fired.get() && !try_write(&self.competitors[self.first]) {
            // Controlled remaining-time change represents delay after the first
            // real maintained lock, before admission of the second lock/leaf.
            self.fired.set(true);
            self.f[self.first].remaining_ms.set(9_999);
        }
        Ok(())
    }
}
#[test]
fn delayed_middle_acquisition_rechecks_already_held_original_runway() {
    let mut f = fixture();
    let first = usize::from(f.snapshots[1].origin < f.snapshots[0].origin);
    let observations = [ComponentObservation::new(), ComponentObservation::new()];
    let restriction = DelayMiddle {
        first,
        f: &observations,
        competitors: &f.competitors,
        fired: Cell::new(false),
    };
    let calls = Cell::new(0);
    let result = with_exact_input_roster(
        component_slots(&mut f.wallets, &f.snapshots, &observations, &restriction),
        &[[0; 32], [1; 32]],
        |_| {
            calls.set(calls.get() + 1);
            Ok::<_, ExactObservationError>(())
        },
    );
    assert!(matches!(result, Err(ExactObservationError::Budget)));
    assert!(restriction.fired.get());
    assert_eq!(calls.get(), 0);
    assert!(f.competitors.iter().all(try_write));
}
#[test]
fn post_leaf_outer_error_preserves_caller_progress_and_releases_all_locks() {
    let mut f = fixture();
    let observations = [ComponentObservation::new(), ComponentObservation::new()];
    let claim_attempted = Cell::new(false);
    let result = with_exact_input_roster(
        component_slots(&mut f.wallets, &f.snapshots, &observations, &AllowComponent),
        &[[0; 32], [1; 32]],
        |_| {
            // Safe operation-local marker only, NOT an actual Store claim. Host
            // fault tests additionally verify the persisted-claim diagnostic.
            claim_attempted.set(true);
            observations[0].active.set(false);
            Ok::<_, ExactObservationError>(())
        },
    );
    assert!(result.is_err());
    assert!(claim_attempted.get());
    assert!(f.competitors.iter().all(try_write));
}

// Controlled completion-clock boundary: no fake native owner is constructed.
// Expiry appears only once the real maintained transactions have ALL released
// their WAL writer locks, exactly where a slow outermost commit can overrun.
pub(super) struct ExpireOnFullUnwind<'a> {
    pub(super) state: &'a ComponentObservation,
    pub(super) leaf_returned: &'a Cell<bool>,
    pub(super) competitors: &'a [EncryptedConnection],
    pub(super) observed_full_unwind: &'a Cell<bool>,
}
impl ObservationChecks for ExpireOnFullUnwind<'_> {
    fn check_current(&self) -> Result<()> {
        if self.leaf_returned.get() && self.competitors.iter().all(try_write) {
            self.observed_full_unwind.set(true);
            self.state.remaining_ms.set(0);
        }
        self.state.check_current()
    }
    fn check_runway(&self) -> Result<()> {
        self.check_current()?;
        self.state.check_runway()
    }
    fn mark_lock_attempted(&self) -> bool {
        self.state.mark_lock_attempted()
    }
}

#[test]
fn expiry_after_final_actual_commit_cannot_return_success_or_erase_progress() {
    let mut f = fixture();
    let states = [ComponentObservation::new(), ComponentObservation::new()];
    let leaf_returned = Cell::new(false);
    let observed_full_unwind = Cell::new(false);
    let claim_attempted = Cell::new(false);
    let observations: Vec<_> = states
        .iter()
        .map(|state| ExpireOnFullUnwind {
            state,
            leaf_returned: &leaf_returned,
            competitors: &f.competitors,
            observed_full_unwind: &observed_full_unwind,
        })
        .collect();
    let mut slots: Vec<_> = f
        .wallets
        .iter_mut()
        .zip(&f.snapshots)
        .zip(&observations)
        .map(|((sync, snapshot), fresh)| ExactInputWalletSlot {
            sync,
            snapshot,
            fresh,
            restriction: &AllowComponent,
        })
        .collect();
    slots.sort_by_key(|slot| std::cmp::Reverse(slot.snapshot.origin));
    let result = with_exact_input_roster(slots, &[[0; 32], [1; 32]], |held| {
        held.check_all_current()?;
        assert!(
            f.competitors
                .iter()
                .all(|connection| !try_write(connection))
        );
        claim_attempted.set(true); // Safe diagnostic only; no actual financial claim.
        leaf_returned.set(true);
        Ok::<_, ExactObservationError>(())
    });
    assert!(matches!(result, Err(ExactObservationError::Budget)));
    assert!(observed_full_unwind.get());
    assert!(claim_attempted.get());
    assert!(states.iter().all(|state| state.attempted.get()));
    assert!(f.competitors.iter().all(try_write));
}
