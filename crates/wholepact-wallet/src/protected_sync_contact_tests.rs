//! Network-component ordering only. Fresh never-funded encrypted fixtures and
//! actual loopback connections exercise the maintained scanner. This policy is
//! test-only, not native disclosure consent, construction admission or key use.
use super::*;
use crate::wallet::sync_test_support::{
    controller, database_with_prior_height, fake_server_with_connection_hook,
};
use std::sync::atomic::{AtomicBool, Ordering};

struct RevocableFixtureAccess {
    allowed: Arc<AtomicBool>,
    account: AccountUuid,
    provider: BackendIdentity,
}
impl LocalWalletAccess for RevocableFixtureAccess {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        _: WalletAccessPurpose,
    ) -> bool {
        account == self.account
            && provider.source_id == self.provider.source_id
            && provider.endpoint == self.provider.endpoint
            && provider.trust_profile == "synthetic_never_chain_evidence"
            && self.allowed.load(Ordering::SeqCst)
    }
}

async fn revoke_at_connection(connection: usize, prior_height: u32) {
    let allowed = Arc::new(AtomicBool::new(true));
    let revoke = allowed.clone();
    let (fake, endpoint, server, fvk) = fake_server_with_connection_hook(1, move |count| {
        if count == connection {
            revoke.store(false, Ordering::SeqCst);
        }
    })
    .await;
    let (_directory, path, key) = database_with_prior_height(&fvk, prior_height);
    let mut wallet = controller(&path, &key, &endpoint);
    let access = RevocableFixtureAccess {
        allowed,
        account: wallet.account_uuid(),
        provider: wallet.source.identity().clone(),
    };
    let result = wallet
        .synchronize(
            &access,
            SyncLimits {
                deadline: Duration::from_secs(5),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(result, Err(SyncError::AccessDenied)));
    // The maintained ChainAdapter currently uses one actual connection for
    // each of these four context RPCs; the public sync channel is connection5.
    // Assert both lists/counts so any topology change is visible, never inferred
    // from a sleep, elapsed time or a synthetic context substituted into sync.
    assert_eq!(fake.accepted_connections.load(Ordering::SeqCst), connection);
    assert_eq!(
        *fake.rpc_methods.lock().unwrap(),
        [
            "GetLightdInfo",
            "GetLatestBlock",
            "GetBlock",
            "GetLatestBlock"
        ]
    );
    assert_eq!(wallet.scanned_height().unwrap(), None);
    assert!(wallet.accepted.is_none());
    assert_eq!(wallet.phase, SyncPhase::Interrupted);
    server.abort();
}

#[tokio::test]
async fn revocation_during_context_prevents_public_channel_contact() {
    revoke_at_connection(4, 4_465_039).await;
}

#[tokio::test]
async fn revocation_during_channel_prevents_later_wallet_read_or_rpc() {
    // A genuinely imported, unsupported pre-NU7 birthday is an ordering
    // sentinel: without the post-await access guard, sync would read it and
    // return UnsupportedProfile before the next RPC's access check. AccessDenied
    // must win immediately after the actual channel await instead.
    let prior = u32::try_from(wholepact_chain::NU7_ACTIVATION_HEIGHT).unwrap() - 2;
    revoke_at_connection(5, prior).await;
}
