//! Controlled fixtures from tests/support are shared with the genuine engine integration test.
use super::*;
use crate::wallet::sync_test_support::*;
use std::sync::atomic::Ordering;
use zcash_primitives::block::BlockHash;

#[tokio::test]
async fn encrypted_snapshot_partial_reopen_selection_and_invalidation() {
    let (fake, endpoint, server, fvk) = fake_server(34).await;
    let (_directory, path, key) = database(&fvk);
    let mut wallet = controller(&path, &key, &endpoint);
    assert_eq!(wallet.status().unwrap().phase, SyncPhase::Unobserved);
    assert!(matches!(
        wallet.select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[]),
        Err(SyncError::NoCurrentObservation)
    ));
    let partial = wallet
        .synchronize(
            &FixtureAccess(true),
            SyncLimits {
                maximum_blocks: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(partial.phase, SyncPhase::Partial);
    assert!(!partial.local_selection_context_available);
    assert_eq!(partial.fully_scanned_height, Some(4_465_040));
    drop(wallet);
    let mut wallet = controller(&path, &key, &endpoint);
    assert_eq!(wallet.status().unwrap().phase, SyncPhase::Unobserved);
    let status = wallet
        .synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    assert_eq!(status.phase, SyncPhase::SnapshotMatched);
    assert!(status.local_selection_context_available);
    assert!(
        !status.authorization_allowed
            && !status.proves_unspentness
            && !status.provider_refresh_time_verified
    );
    let summary = serde_json::to_string(&status).unwrap();
    assert!(
        summary.contains("synthetic_never_chain_evidence") && summary.contains("GetBlockRange")
    );
    assert!(!summary.contains(&hex::encode(fvk.to_bytes())));
    let selected = wallet
        .select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[])
        .unwrap();
    assert_eq!(selected.selection().selected_zatoshis(), 200_000);
    let excluded = selected.selection().local_note_refs().to_vec();
    assert!(matches!(
        wallet.select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &excluded),
        Err(SyncError::Wallet(WalletError::InsufficientFunds))
    ));
    assert!(matches!(
        wallet.select_contribution(&FixtureAccess(false), &fvk, "owner-a", 1, &[]),
        Err(SyncError::AccessDenied)
    ));
    // A denied new attempt invalidates the previous observation before any network work.
    assert!(matches!(
        wallet
            .synchronize(&FixtureAccess(false), SyncLimits::default())
            .await,
        Err(SyncError::AccessDenied)
    ));
    assert!(!wallet.status().unwrap().local_selection_context_available);
    assert!(matches!(
        selected.check_current(),
        Err(SyncError::NoCurrentObservation)
    ));
    assert!(matches!(
        wallet.select_contribution(&FixtureAccess(true), &fvk, "owner-a", 1, &[]),
        Err(SyncError::NoCurrentObservation)
    ));
    // A partial-wallet reorg refuses to rewrite history automatically.
    drop(wallet);
    let (_other_directory, other_path, other_key) = database(&fvk);
    let mut partial = controller(&other_path, &other_key, &endpoint);
    partial
        .synchronize(
            &FixtureAccess(true),
            SyncLimits {
                maximum_blocks: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    fake.mode.store(REORG, Ordering::SeqCst);
    assert!(matches!(
        partial
            .synchronize(&FixtureAccess(true), SyncLimits::default())
            .await,
        Err(SyncError::ReconciliationRequired)
    ));
    assert_eq!(
        partial.status().unwrap().phase,
        SyncPhase::ReconciliationRequired
    );
    assert_eq!(
        partial.status().unwrap().fully_scanned_height,
        Some(4_465_040)
    );
    server.abort();
}

#[tokio::test]
async fn malformed_short_stale_and_wrong_root_never_create_an_observation() {
    let (fake, endpoint, server, fvk) = fake_server(1).await;
    for mode in [SHORT, WRONG_TREE_HEIGHT, MALFORMED, OLD_CACHE, WRONG_ROOT] {
        let (_directory, path, key) = database(&fvk);
        let mut wallet = controller(&path, &key, &endpoint);
        fake.mode.store(mode, Ordering::SeqCst);
        let result = wallet
            .synchronize(&FixtureAccess(true), SyncLimits::default())
            .await;
        match mode {
            WRONG_ROOT => assert!(matches!(
                result,
                Err(SyncError::Wallet(WalletError::ChainMismatch))
            )),
            OLD_CACHE => assert!(matches!(
                result,
                Err(SyncError::Chain(ChainError::StaleChain))
            )),
            _ => assert!(matches!(result, Err(SyncError::InvalidResponse))),
        }
        assert!(!wallet.status().unwrap().local_selection_context_available);
        if matches!(mode, SHORT | WRONG_TREE_HEIGHT | MALFORMED) {
            assert_eq!(wallet.status().unwrap().fully_scanned_height, None);
        }
        assert!(matches!(
            wallet.select_contribution(&FixtureAccess(true), &fvk, "owner-a", 1, &[]),
            Err(SyncError::NoCurrentObservation)
        ));
    }
    server.abort();
}

#[tokio::test]
async fn dropped_scan_future_and_deadline_leave_no_current_observation() {
    let (fake, endpoint, server, fvk) = fake_server(1).await;
    let (_directory, path, key) = database(&fvk);
    let mut wallet = controller(&path, &key, &endpoint);
    fake.mode.store(DELAY, Ordering::SeqCst);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            wallet.synchronize(&FixtureAccess(true), SyncLimits::default())
        )
        .await
        .is_err()
    );
    assert_eq!(wallet.status().unwrap().phase, SyncPhase::Interrupted);
    assert_eq!(wallet.status().unwrap().fully_scanned_height, None);
    assert!(matches!(
        wallet
            .synchronize(
                &FixtureAccess(true),
                SyncLimits {
                    deadline: Duration::from_millis(100),
                    ..Default::default()
                }
            )
            .await,
        Err(SyncError::Interrupted)
    ));
    fake.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        wallet
            .synchronize(&FixtureAccess(true), SyncLimits::default())
            .await
            .unwrap()
            .phase,
        SyncPhase::SnapshotMatched
    );
    server.abort();
}

#[test]
fn panic_triggering_and_ambiguous_compact_shapes_are_rejected_before_scanner() {
    let (_, _, _, _, source) = super::super::qualification::synthetic_wallet();
    let block = source.0[0].clone();
    let prior = ChainState::empty(4_465_039u32.into(), BlockHash([50; 32]));
    validate_batch(std::slice::from_ref(&block), &prior, 4_465_040, 1).unwrap();
    for case in 0..8 {
        let mut bad = block.clone();
        match case {
            0 => bad.height = u64::MAX,
            1 => bad.hash.clear(),
            2 => bad.prev_hash.clear(),
            3 => bad.header = vec![1],
            4 => bad.vtx[0].txid.clear(),
            5 => bad.vtx[0].index = u64::MAX,
            6 => bad.vtx[0].ironwood_actions[0].cmx.clear(),
            _ => {
                bad.chain_metadata
                    .as_mut()
                    .unwrap()
                    .ironwood_commitment_tree_size = u32::MAX
            }
        }
        assert!(validate_batch(&[bad], &prior, 4_465_040, 1).is_err());
    }
    for malformed in ["", "00000000", "0000ff", "00000101", "00ff00"] {
        assert!(validate_tree_encoding(malformed).is_err());
    }
    assert!(validate_batch(&[], &prior, 4_465_040, 1).is_err());
}

#[test]
fn actual_imported_birthday_height_matches_without_authorizing_or_contacting_provider() {
    // Existing encrypted fixture, public never-funded key, no server/scan/native
    // owner. Only the concrete maintained database's imported height is tested.
    let fvk = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([71; 32]).unwrap());
    let (_directory, path, key) = database(&fvk);
    let wallet = controller(&path, &key, "http://127.0.0.1:1");
    let account = wallet.account_uuid();
    wallet.verify_account_fvk(&fvk).unwrap();
    wallet.verify_account_birthday_height(4_465_040).unwrap();
    for wrong in [0, 4_465_039, 4_465_041, u32::MAX] {
        assert!(matches!(
            wallet.verify_account_birthday_height(wrong),
            Err(SyncError::Wallet(WalletError::AccountMismatch))
        ));
    }
    // No mismatch changes the imported origin or manufactures an observation.
    wallet.verify_account_birthday_height(4_465_040).unwrap();
    assert_eq!(wallet.account_uuid(), account);
    let status = wallet.status().unwrap();
    assert_eq!(status.phase, SyncPhase::Unobserved);
    assert_eq!(status.fully_scanned_height, None);
    assert!(!status.local_selection_context_available);
    assert!(!status.authorization_allowed);
}
