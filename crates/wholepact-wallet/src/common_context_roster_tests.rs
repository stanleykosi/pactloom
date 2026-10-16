//! Direct maintained encrypted-wallet COMPONENT evidence only. Synthetic public
//! never-funded keys and fabricated cached blocks, no network, native ceremony,
//! proof execution or genuine construction capability is created by these tests.
use super::super::roster_tests::*;
use super::*;
use std::cell::{Cell, RefCell};
use wholepact_core::{
    manual_roster_construction_v2::ManualRosterRetentionCommitmentV2,
    manual_roster_construction_v3::CommonContextParticipantV1,
};

fn snapshots(fixture: &mut Fixture) -> Vec<CommonContextVerifierSnapshot> {
    let reference = fixture
        .snapshots
        .iter()
        .map(|s| &s.evidence.context)
        .max_by_key(|c| c.tip_height)
        .unwrap();
    let mut ancestry: Vec<_> = fixture
        .snapshots
        .iter()
        .map(|s| {
            (
                s.evidence.context.tip_height,
                s.evidence.context.tip_hash_protocol,
            )
        })
        .collect();
    ancestry.sort_by_key(|a| a.0);
    ancestry.dedup();
    let common = FrozenCommonContext {
        digest: hex::encode([81; 32]),
        required_ancestry: ancestry,
        context: FrozenContextFacts {
            anchor_height: reference.anchor_height,
            anchor_hash_protocol: hex::encode(reference.anchor_hash_protocol),
            anchor_root: hex::encode(reference.anchor_root),
            reference_tip_height: reference.tip_height,
            reference_tip_hash_protocol: hex::encode(reference.tip_hash_protocol),
            target_height: reference.tip_height + 1,
            expiry_height: reference.tip_height + 40,
            participants: fixture
                .snapshots
                .iter()
                .map(|s| CommonContextParticipantV1 {
                    commitment: ManualRosterRetentionCommitmentV2 {
                        participant_id: s.participant_id.clone(),
                        account_id: s.evidence.account_id.clone(),
                        full_viewing_key_digest: hex::encode(Sha256::digest(
                            s.evidence.fvk.to_bytes(),
                        )),
                        retention_request_digest: hex::encode([82; 32]),
                        retention_evidence_digest: hex::encode([83; 32]),
                    },
                    original_host_audit: wholepact_core::manual_roster_inventory_v2::OriginalHostRosterAuditV3::AdditionalPublicationV3 { audit_digest: hex::encode([86;32]) },
                    roster: wholepact_core::manual_roster_v2::HostRosterAppendBindingV2 {
                        version:2, generation_id:hex::encode([87;32]), store_destination_identity:"synthetic-component-store".into(), roster_sequence:2,
                        predecessor:wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 { audit_digest:hex::encode([88;32]) },
                    },
                    original_tip_height: s.evidence.context.tip_height,
                    original_tip_hash_protocol: hex::encode(s.evidence.context.tip_hash_protocol),
                    original_completion_expires_at_ms: 1,
                    provider_configuration_digest: hex::encode([84; 32]),
                    read_scope_digest: hex::encode([85; 32]),
                })
                .collect(),
        },
    };
    std::mem::take(&mut fixture.snapshots)
        .into_iter()
        .enumerate()
        .map(|(index, mut exact)| {
            exact.required_ancestry = common.required_ancestry.clone();
            CommonContextVerifierSnapshot {
                exact,
                common: common.clone(),
                plan_digest: hex::encode([90 + index as u8; 32]),
            }
        })
        .collect()
}
fn slots<'a, O: ObservationChecks>(
    wallets: &'a mut [ProtectedWalletSync],
    snapshots: &'a [CommonContextVerifierSnapshot],
    observations: &'a [O],
    restriction: &'a dyn ExactInputRestriction,
) -> Vec<CommonContextLockSlot<'a>> {
    let mut slots: Vec<_> = wallets
        .iter_mut()
        .zip(snapshots)
        .zip(observations)
        .map(|((sync, snapshot), fresh)| CommonContextLockSlot {
            exact: ExactInputWalletSlot {
                sync,
                snapshot: &snapshot.exact,
                fresh,
                restriction,
            },
            common: &snapshot.common,
            plan_digest: &snapshot.plan_digest,
        })
        .collect();
    slots.sort_by_key(|slot| std::cmp::Reverse(slot.exact.snapshot.origin));
    slots
}

// Exercise the maintained lock kernel without a fabricated native read. The
// callback's empty owner map cannot satisfy final construction conversion.
fn with_component_common_context_roster<R, E, F>(
    slots: Vec<CommonContextLockSlot<'_>>,
    excluded_origins: &[[u8; 32]],
    callback: F,
) -> std::result::Result<R, E>
where
    E: From<ExactObservationError>,
    F: for<'guard> FnOnce(&HeldCommonContextRosterObservation<'guard>) -> std::result::Result<R, E>,
{
    with_common_context_roster_locks(
        slots,
        std::collections::BTreeMap::new(),
        excluded_origins,
        callback,
    )
}

#[test]
fn differing_original_tips_keep_frozen_target_under_sorted_actual_locks() {
    let mut f = fixture_with_original_offsets([0, 1], 3);
    let snapshots = snapshots(&mut f);
    let states = [ComponentObservation::new(), ComponentObservation::new()];
    let restriction = ObserveAcquisition {
        accounts: [snapshots[0].exact.account, snapshots[1].exact.account],
        competitors: &f.competitors,
        observed: RefCell::new(Vec::new()),
    };
    let mut order: Vec<_> = snapshots
        .iter()
        .map(|s| (s.exact.origin, s.exact.account))
        .collect();
    order.sort_by_key(|s| s.0);
    with_component_common_context_roster(
        slots(&mut f.wallets, &snapshots, &states, &restriction),
        &[[0; 32], [1; 32]],
        |held| {
            held.check_all_current()?;
            assert!(held.native_reads.is_empty());
            assert_eq!(held.participant_count(), 2);
            assert_eq!(held.current_tip().0, 4_465_043);
            let context = held.common.construction_context()?;
            assert_eq!(context.target_height, 4_465_042); // fixed maximum ORIGINAL + 1
            assert_eq!(context.anchor_height, 4_465_040);
            assert_eq!(
                *restriction.observed.borrow(),
                order.iter().map(|s| s.1).collect::<Vec<_>>()
            );
            assert!(
                f.competitors
                    .iter()
                    .all(|connection| !try_write(connection))
            );
            Ok::<_, ExactObservationError>(())
        },
    )
    .unwrap();
    assert!(f.competitors.iter().all(try_write));
    assert!(states.iter().all(|state| state.attempted.get()));
}

#[test]
fn v2_original_context_equality_remains_unchanged() {
    let mut f = fixture_with_original_offsets([0, 1], 3);
    let states = [ComponentObservation::new(), ComponentObservation::new()];
    let result = with_exact_input_roster(
        component_slots(&mut f.wallets, &f.snapshots, &states, &AllowComponent),
        &[[0; 32], [1; 32]],
        |_| {
            panic!("V2 must reject differing original tips before the leaf");
            #[allow(unreachable_code)]
            Ok::<_, ExactObservationError>(())
        },
    );
    assert!(matches!(result, Err(ExactObservationError::Roster)));
}

#[test]
fn every_wallet_checks_the_other_owners_original_tip_hash() {
    let mut f = fixture_with_original_offsets([0, 1], 3);
    let snapshots = snapshots(&mut f);
    // For wallet zero this is neither its own original tip, its anchor nor its
    // current tip. Only the V3 ALL-original ancestry requirement catches it.
    f.competitors[0]
        .connection()
        .execute(
            "UPDATE blocks SET hash=?1 WHERE height=?2",
            rusqlite::params![vec![99u8; 32], 4_465_041],
        )
        .unwrap();
    let states = [ComponentObservation::new(), ComponentObservation::new()];
    let result = with_component_common_context_roster(
        slots(&mut f.wallets, &snapshots, &states, &AllowComponent),
        &[[0; 32], [1; 32]],
        |_| Ok::<_, ExactObservationError>(()),
    );
    assert!(matches!(result, Err(ExactObservationError::StateChanged)));
    assert!(f.competitors.iter().all(try_write));
}

#[test]
fn changed_anchor_current_context_and_material_identity_fail_closed() {
    for mutation in 0..5 {
        let mut f = fixture_with_original_offsets([0, 1], 3);
        let mut snapshots = snapshots(&mut f);
        match mutation {
            0 => snapshots[1].exact.evidence.context.anchor_root[0] ^= 1,
            1 => snapshots[1].exact.current.tip_hash_protocol[0] ^= 1,
            2 => snapshots[1].exact.evidence.inputs[0].value_zatoshis += 1,
            3 => snapshots[1].exact.local_outpoints[0].1 += 1,
            _ => snapshots[1].exact.origin = snapshots[0].exact.origin,
        }
        let states = [ComponentObservation::new(), ComponentObservation::new()];
        let reached = Cell::new(false);
        let result = with_component_common_context_roster(
            slots(&mut f.wallets, &snapshots, &states, &AllowComponent),
            &[[0; 32], [1; 32]],
            |_| {
                reached.set(true);
                Ok::<_, ExactObservationError>(())
            },
        );
        assert!(result.is_err());
        assert!(!reached.get());
        assert!(f.competitors.iter().all(try_write));
    }
}

#[test]
fn spent_pending_unknown_and_missing_original_witness_fail_closed() {
    let mutations = [
        "INSERT INTO ironwood_received_note_spends(ironwood_received_note_id, transaction_id) SELECT id, transaction_id FROM ironwood_received_notes",
        "INSERT INTO transactions(txid, expiry_height, min_observed_height) VALUES (zeroblob(32), 4465100, 4465043); INSERT INTO ironwood_received_note_spends(ironwood_received_note_id, transaction_id) SELECT id, (SELECT MAX(id_tx) FROM transactions) FROM ironwood_received_notes",
        "INSERT INTO transactions(txid, expiry_height, min_observed_height) VALUES (zeroblob(32), NULL, 4465043); INSERT INTO ironwood_received_note_spends(ironwood_received_note_id, transaction_id) SELECT id, (SELECT MAX(id_tx) FROM transactions) FROM ironwood_received_notes",
        "DELETE FROM ironwood_tree_checkpoints WHERE checkpoint_id=4465040",
    ];
    for sql in mutations {
        let mut f = fixture_with_original_offsets([0, 1], 3);
        let snapshots = snapshots(&mut f);
        f.competitors[0].connection().execute_batch(sql).unwrap();
        let states = [ComponentObservation::new(), ComponentObservation::new()];
        let reached = Cell::new(false);
        let result = with_component_common_context_roster(
            slots(&mut f.wallets, &snapshots, &states, &AllowComponent),
            &[[0; 32], [1; 32]],
            |_| {
                reached.set(true);
                Ok::<_, ExactObservationError>(())
            },
        );
        assert!(result.is_err());
        assert!(!reached.get());
        assert!(f.competitors.iter().all(try_write));
    }
}

#[test]
fn current_tip_plus_one_drives_actual_maintained_spendability() {
    let mut f = fixture_with_original_offsets([0, 1], 3);
    let snapshots = snapshots(&mut f);
    // This synthetic unmined spend is expired at CURRENT tip+1 but would still
    // block the exact note if the earlier frozen constructor target were used.
    f.competitors[0].connection().execute_batch("INSERT INTO transactions(txid, expiry_height, min_observed_height) VALUES (zeroblob(32), 4465042, 4465041); INSERT INTO ironwood_received_note_spends(ironwood_received_note_id, transaction_id) SELECT id, (SELECT MAX(id_tx) FROM transactions) FROM ironwood_received_notes").unwrap();
    let s = &snapshots[0].exact;
    let (txid, index) = s.local_outpoints[0];
    assert!(
        f.wallets[0]
            .wallet
            .db
            .get_spendable_note(
                &txid,
                ShieldedPool::Ironwood,
                u32::from(index),
                4_465_042u32.into(),
                LockFilter::Policy(&LockedInputPolicy::Exclude)
            )
            .unwrap()
            .is_none()
    );
    let states = [ComponentObservation::new(), ComponentObservation::new()];
    with_component_common_context_roster(
        slots(&mut f.wallets, &snapshots, &states, &AllowComponent),
        &[[0; 32], [1; 32]],
        |_| Ok::<_, ExactObservationError>(()),
    )
    .unwrap();
}

#[test]
fn contention_at_each_position_consumes_the_single_lock_wave() {
    for position in 0..2 {
        let mut f = fixture_with_original_offsets([0, 1], 3);
        let snapshots = snapshots(&mut f);
        let mut order = [0, 1];
        order.sort_by_key(|i| snapshots[*i].exact.origin);
        f.competitors[order[position]]
            .connection()
            .execute_batch("BEGIN IMMEDIATE;")
            .unwrap();
        let states = [ComponentObservation::new(), ComponentObservation::new()];
        let result = with_component_common_context_roster(
            slots(&mut f.wallets, &snapshots, &states, &AllowComponent),
            &[[0; 32], [1; 32]],
            |_| Ok::<_, ExactObservationError>(()),
        );
        assert!(matches!(result, Err(ExactObservationError::Storage)));
        f.competitors[order[position]]
            .connection()
            .execute_batch("ROLLBACK;")
            .unwrap();
        assert!(f.competitors.iter().all(try_write));
        let retry = with_component_common_context_roster(
            slots(&mut f.wallets, &snapshots, &states, &AllowComponent),
            &[[0; 32], [1; 32]],
            |_| Ok::<_, ExactObservationError>(()),
        );
        assert!(matches!(retry, Err(ExactObservationError::Lineage)));
    }
}

#[test]
fn original_runway_and_postcommit_expiry_survive_common_lock_unwind() {
    let mut f = fixture_with_original_offsets([0, 1], 3);
    let snapshots = snapshots(&mut f);
    let states = [ComponentObservation::new(), ComponentObservation::new()];
    let leaf_returned = Cell::new(false);
    let observed_full_unwind = Cell::new(false);
    let observations: Vec<_> = states
        .iter()
        .map(|state| ExpireOnFullUnwind {
            state,
            leaf_returned: &leaf_returned,
            competitors: &f.competitors,
            observed_full_unwind: &observed_full_unwind,
        })
        .collect();
    let result = with_component_common_context_roster(
        slots(&mut f.wallets, &snapshots, &observations, &AllowComponent),
        &[[0; 32], [1; 32]],
        |_| {
            leaf_returned.set(true);
            Ok::<_, ExactObservationError>(())
        },
    );
    assert!(matches!(result, Err(ExactObservationError::Budget)));
    assert!(observed_full_unwind.get());
    assert!(leaf_returned.get()); // progress remains uncertain; it is never reset
    assert!(states.iter().all(|state| state.attempted.get()));
    assert!(f.competitors.iter().all(try_write));
}
