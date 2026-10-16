//! Public never-funded local HTTP/2 and encrypted-wallet fixtures only.
use super::*;
use crate::wallet::sync_test_support::*;
use std::cell::Cell;
use wholepact_storage_security::open_encrypted;

struct FixtureHeldPermission {
    active: Cell<bool>,
    fvk: FullViewingKey,
    account: AccountUuid,
    policy: WalletKeyUsePolicy,
    expiry: u32,
}
impl HeldWalletPermission for FixtureHeldPermission {
    fn check_current(&self, s: &WalletKeyUseScope<'_>) -> Result<(), WalletKeyUseError> {
        if !self.active.get()
            || s.wallet_account != self.account
            || s.account_id != "owner-a"
            || s.authenticated_fvk.to_bytes() != self.fvk.to_bytes()
            || s.policy != &self.policy
            || s.transaction_expiry_height != self.expiry
            || s.source.source_id != self.policy.source_id
            || s.source.endpoint != self.policy.endpoint
        {
            return Err(WalletKeyUseError::Permission);
        }
        Ok(())
    }
}
fn fixture_permission(
    wallet: &ProtectedWalletSync,
    ticket: &WalletKeyUseTicket,
    fvk: &FullViewingKey,
) -> FixtureHeldPermission {
    FixtureHeldPermission {
        active: Cell::new(true),
        fvk: fvk.clone(),
        account: wallet.account,
        policy: WalletKeyUsePolicy {
            confidence: WalletKeyUseConfidence::SyntheticNeverChainEvidence,
            source_id: ticket.observation().source().source_id.clone(),
            endpoint: ticket.observation().source().endpoint.clone(),
            maximum_observation_age_seconds: 60,
            minimum_confirmations: 1,
            minimum_expiry_margin_blocks: 3,
        },
        expiry: ticket.evidence().context().tip_height + 20,
    }
}

#[tokio::test]
async fn actual_wallet_writer_lock_and_exact_held_permission_span_callback() {
    let (_, endpoint, server, fvk) = fake_server(1).await;
    let (_directory, path, key) = database(&fvk);
    let mut wallet = controller(&path, &key, &endpoint);
    wallet
        .synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    let contribution = wallet
        .select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[])
        .unwrap();
    let ticket = contribution.key_use_ticket();
    let permission = fixture_permission(&wallet, &ticket, &fvk);
    let other = open_encrypted(&path, &key).unwrap();
    other.connection().busy_timeout(Duration::ZERO).unwrap();
    let mut calls = 0;
    wallet.with_key_use_guard(&permission, &ticket, &fvk, &permission.policy, permission.expiry, |held| {
        held.check_current()?;
        assert_eq!(held.evidence().inputs()[0].nullifier(), ticket.evidence().inputs()[0].nullifier());
        assert!(!held.observation().independently_consensus_verified());
        assert!(!held.observation().authorizes_signing());
        let err = other.connection().execute_batch("BEGIN IMMEDIATE; ROLLBACK;").unwrap_err();
        assert!(matches!(err, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DatabaseBusy));
        calls += 1;
        Ok::<_, WalletKeyUseError>(())
    }).unwrap();
    assert_eq!(calls, 1);
    // The competing writer is admitted only after the callback returns.
    other
        .connection()
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .unwrap();
    let denied = wallet.with_key_use_guard(
        &permission,
        &ticket,
        &fvk,
        &permission.policy,
        permission.expiry,
        |held| {
            permission.active.set(false);
            held.check_current()
        },
    );
    assert!(matches!(denied, Err(WalletKeyUseError::Permission)));
    let mut short_policy = permission.policy.clone();
    short_policy.maximum_observation_age_seconds = 1;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(ticket.validate_policy(&short_policy).is_err());
    let mut stale_calls = 0;
    assert!(
        wallet
            .with_key_use_guard(
                &permission,
                &ticket,
                &fvk,
                &short_policy,
                permission.expiry,
                |_| {
                    stale_calls += 1;
                    Ok::<_, WalletKeyUseError>(())
                }
            )
            .is_err()
    );
    assert_eq!(stale_calls, 0);
    server.abort();
}

#[tokio::test]
async fn confidence_provider_expiry_fvk_and_revocation_fail_before_callback() {
    let (_, endpoint, server, fvk) = fake_server(1).await;
    let (_directory, path, key) = database(&fvk);
    let mut wallet = controller(&path, &key, &endpoint);
    wallet
        .synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    let ticket = wallet
        .select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[])
        .unwrap()
        .key_use_ticket();
    let permission = fixture_permission(&wallet, &ticket, &fvk);
    let calls = Cell::new(0);
    let callback = |_: &HeldWalletKeyUse<'_>| {
        calls.set(calls.get() + 1);
        Ok::<_, WalletKeyUseError>(())
    };
    let mut policy = permission.policy.clone();
    policy.confidence = WalletKeyUseConfidence::IndependentlyVerifiedConsensus;
    assert!(matches!(
        wallet.with_key_use_guard(
            &permission,
            &ticket,
            &fvk,
            &policy,
            permission.expiry,
            callback
        ),
        Err(WalletKeyUseError::Policy)
    ));
    policy.confidence = WalletKeyUseConfidence::TrustedSingleProviderSnapshot;
    assert!(matches!(
        wallet.with_key_use_guard(
            &permission,
            &ticket,
            &fvk,
            &policy,
            permission.expiry,
            callback
        ),
        Err(WalletKeyUseError::Policy)
    ));
    policy = permission.policy.clone();
    policy.endpoint.push_str("/different");
    assert!(matches!(
        wallet.with_key_use_guard(
            &permission,
            &ticket,
            &fvk,
            &policy,
            permission.expiry,
            callback
        ),
        Err(WalletKeyUseError::Policy)
    ));
    let other_fvk =
        FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([72; 32]).unwrap());
    assert!(
        wallet
            .with_key_use_guard(
                &permission,
                &ticket,
                &other_fvk,
                &permission.policy,
                permission.expiry,
                callback
            )
            .is_err()
    );
    assert!(matches!(
        wallet.with_key_use_guard(
            &permission,
            &ticket,
            &fvk,
            &permission.policy,
            ticket.evidence.context.tip_height + 3,
            callback
        ),
        Err(WalletKeyUseError::Expiry)
    ));
    permission.active.set(false);
    assert!(matches!(
        wallet.with_key_use_guard(
            &permission,
            &ticket,
            &fvk,
            &permission.policy,
            permission.expiry,
            callback
        ),
        Err(WalletKeyUseError::Permission)
    ));
    assert_eq!(calls.get(), 0);
    server.abort();
}

#[tokio::test]
async fn selected_note_spend_scan_and_chain_mutations_fail_closed() {
    let (_, endpoint, server, fvk) = fake_server(1).await;
    // These are adversarial local database fault injections, not alternate wallet
    // production SQL. Every lookup/decision under test uses maintained APIs.
    let mutations = [
        "INSERT INTO ironwood_received_note_spends(ironwood_received_note_id, transaction_id) SELECT id, transaction_id FROM ironwood_received_notes",
        "UPDATE ironwood_received_notes SET value = value + 1",
        "UPDATE ironwood_received_notes SET commitment_tree_position = commitment_tree_position + 1",
        "UPDATE blocks SET hash = zeroblob(32)",
        "UPDATE scan_queue SET priority = 50",
        "CREATE TABLE wholepact_bundle_quarantine(recovery_required INTEGER)",
    ];
    for sql in mutations {
        let (_directory, path, key) = database(&fvk);
        let mut wallet = controller(&path, &key, &endpoint);
        wallet
            .synchronize(&FixtureAccess(true), SyncLimits::default())
            .await
            .unwrap();
        let ticket = wallet
            .select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[])
            .unwrap()
            .key_use_ticket();
        let permission = fixture_permission(&wallet, &ticket, &fvk);
        let other = open_encrypted(&path, &key).unwrap();
        other.connection().execute_batch(sql).unwrap();
        let calls = Cell::new(0);
        let result = wallet.with_key_use_guard(
            &permission,
            &ticket,
            &fvk,
            &permission.policy,
            permission.expiry,
            |_| {
                calls.set(calls.get() + 1);
                Ok::<_, WalletKeyUseError>(())
            },
        );
        assert!(result.is_err(), "fault injection must fail closed");
        assert_eq!(calls.get(), 0);
    }
    server.abort();
}

#[tokio::test]
async fn stale_generation_reopen_reorg_and_private_file_identity_are_not_authority() {
    let (fake, endpoint, server, fvk) = fake_server(2).await;
    let (_directory, path, key) = database(&fvk);
    let mut wallet = controller(&path, &key, &endpoint);
    wallet
        .synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    let ticket = wallet
        .select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[])
        .unwrap()
        .key_use_ticket();
    let permission = fixture_permission(&wallet, &ticket, &fvk);
    assert!(
        wallet
            .synchronize(&FixtureAccess(false), SyncLimits::default())
            .await
            .is_err()
    );
    let calls = Cell::new(0);
    assert!(
        wallet
            .with_key_use_guard(
                &permission,
                &ticket,
                &fvk,
                &permission.policy,
                permission.expiry,
                |_| {
                    calls.set(calls.get() + 1);
                    Ok::<_, WalletKeyUseError>(())
                }
            )
            .is_err()
    );
    drop(wallet);
    let mut reopened = controller(&path, &key, &endpoint);
    assert!(
        reopened
            .with_key_use_guard(
                &permission,
                &ticket,
                &fvk,
                &permission.policy,
                permission.expiry,
                |_| {
                    calls.set(calls.get() + 1);
                    Ok::<_, WalletKeyUseError>(())
                }
            )
            .is_err()
    );
    reopened
        .synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    assert!(
        reopened
            .with_key_use_guard(
                &permission,
                &ticket,
                &fvk,
                &permission.policy,
                permission.expiry,
                |_| {
                    calls.set(calls.get() + 1);
                    Ok::<_, WalletKeyUseError>(())
                }
            )
            .is_err()
    );
    let fresh_ticket = reopened
        .select_contribution(&FixtureAccess(true), &fvk, "owner-a", 100_000, &[])
        .unwrap()
        .key_use_ticket();
    let fresh_permission = fixture_permission(&reopened, &fresh_ticket, &fvk);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        reopened.with_key_use_guard(
            &fresh_permission,
            &fresh_ticket,
            &fvk,
            &fresh_permission.policy,
            fresh_permission.expiry,
            |_| {
                calls.set(calls.get() + 1);
                Ok::<_, WalletKeyUseError>(())
            }
        ),
        Err(WalletKeyUseError::Storage)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The first scanned block is made contradictory by the controlled provider.
    // Force an existing checkpoint recheck at that height with a separate partial wallet.
    fake.mode.store(REORG, std::sync::atomic::Ordering::SeqCst);
    let (_d2, p2, k2) = database(&fvk);
    let mut partial = controller(&p2, &k2, &endpoint);
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
    assert!(
        partial
            .synchronize(&FixtureAccess(true), SyncLimits::default())
            .await
            .is_err()
    );
    assert_eq!(calls.get(), 0);
    server.abort();
}

#[test]
fn policy_freshness_bounds_request_start_cache_age_and_clock_regression() {
    use wholepact_chain::{
        CacheStatus, RpcCacheObservation, synthetic_wallet_chain_context_for_qualification,
    };
    let observed = synthetic_wallet_chain_context_for_qualification(1_000).unwrap();
    assert_eq!(observed.request_started_at_unix_seconds(), 1_000);
    let policy = WalletKeyUsePolicy {
        confidence: WalletKeyUseConfidence::SyntheticNeverChainEvidence,
        source_id: observed.source().source_id.clone(),
        endpoint: observed.source().endpoint.clone(),
        maximum_observation_age_seconds: 10,
        minimum_confirmations: 1,
        minimum_expiry_margin_blocks: 3,
    };
    assert!(check_observation_freshness_at(&observed, &policy, 1_010).is_ok());
    assert!(check_observation_freshness_at(&observed, &policy, 1_011).is_err());
    assert!(check_observation_freshness_at(&observed, &policy, 999).is_err());
    let aged = observed
        .with_additional_cache_observations(vec![RpcCacheObservation {
            method: "GetBlock",
            cache_status: CacheStatus::Hit,
            reported_age_seconds: Some(7),
            malformed_age: false,
        }])
        .unwrap();
    assert!(check_observation_freshness_at(&aged, &policy, 1_003).is_ok());
    assert!(check_observation_freshness_at(&aged, &policy, 1_004).is_err());
    // The chain context's existing TTL remains a separate upper bound.
    let mut longer = policy;
    longer.maximum_observation_age_seconds = 300;
    assert!(
        check_observation_freshness_at(&aged, &longer, aged.valid_until_unix_seconds() + 1)
            .is_err()
    );
}

#[test]
fn monotonic_age_prevents_wallclock_rollback_extending_policy_or_adapter_lifetime() {
    use wholepact_chain::{
        CacheStatus, RpcCacheObservation, synthetic_wallet_chain_context_for_qualification,
    };
    let observed = synthetic_wallet_chain_context_for_qualification(1_000).unwrap();
    let mut policy = WalletKeyUsePolicy {
        confidence: WalletKeyUseConfidence::SyntheticNeverChainEvidence,
        source_id: observed.source().source_id.clone(),
        endpoint: observed.source().endpoint.clone(),
        maximum_observation_age_seconds: 10,
        minimum_confirmations: 1,
        minimum_expiry_margin_blocks: 3,
    };
    // The wall clock has rolled back from 1010 to 1005. It is still individually
    // wall-valid, but cannot make eleven actual elapsed seconds fresh again.
    assert!(check_observation_freshness_at(&observed, &policy, 1_005).is_ok());
    assert!(check_monotonic_freshness(&observed, &policy, Duration::from_secs(10)).is_ok());
    assert!(check_monotonic_freshness(&observed, &policy, Duration::from_secs(11)).is_err());
    assert!(check_monotonic_freshness(&observed, &policy, Duration::from_millis(10_001)).is_err());
    let aged = observed
        .clone()
        .with_additional_cache_observations(vec![RpcCacheObservation {
            method: "GetBlock",
            cache_status: CacheStatus::Hit,
            reported_age_seconds: Some(7),
            malformed_age: false,
        }])
        .unwrap();
    assert!(check_monotonic_freshness(&aged, &policy, Duration::from_secs(3)).is_ok());
    assert!(check_monotonic_freshness(&aged, &policy, Duration::from_millis(3_001)).is_err());
    policy.maximum_observation_age_seconds = 300;
    let ttl = observed.valid_until_unix_seconds() - observed.request_started_at_unix_seconds();
    assert!(check_monotonic_freshness(&observed, &policy, Duration::from_secs(ttl)).is_ok());
    assert!(check_monotonic_freshness(&observed, &policy, Duration::from_secs(ttl + 1)).is_err());
}
