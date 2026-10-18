//! Network-component ordering only. Fresh never-funded encrypted fixtures and
//! actual loopback connections exercise the maintained scanner. This policy is
//! test-only, not native disclosure consent, construction admission or key use.
use super::*;
use crate::wallet::sync_test_support::{
    controller, database_with_prior_height, fake_server_with_connection_hook,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct RevocableFixtureAccess {
    allowed: Arc<AtomicBool>,
    permission_checks: AtomicUsize,
    deny_post_channel_check: bool,
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
        let check = self.permission_checks.fetch_add(1, Ordering::SeqCst) + 1;
        if self.deny_post_channel_check && check == 3 {
            self.allowed.store(false, Ordering::SeqCst);
        }
        account == self.account
            && provider.source_id == self.provider.source_id
            && provider.endpoint == self.provider.endpoint
            && provider.trust_profile == "synthetic_never_chain_evidence"
            && self.allowed.load(Ordering::SeqCst)
    }
}

async fn revoke_at_scan_boundary(post_channel: bool, prior_height: u32) {
    let allowed = Arc::new(AtomicBool::new(true));
    let revoke = allowed.clone();
    let (fake, endpoint, server, fvk) = fake_server_with_connection_hook(1, move |count| {
        if !post_channel && count == 4 {
            revoke.store(false, Ordering::SeqCst);
        }
    })
    .await;
    let (_directory, path, key) = database_with_prior_height(&fvk, prior_height);
    let mut wallet = controller(&path, &key, &endpoint);
    let access = RevocableFixtureAccess {
        allowed,
        permission_checks: AtomicUsize::new(0),
        deny_post_channel_check: post_channel,
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
    // Closed kinds and finite topology counts only: never format a source
    // error, wallet status, provider endpoint or private wallet material.
    let outcome = match &result {
        Ok(_) => "Ok",
        Err(SyncError::AccessDenied) => "AccessDenied",
        Err(SyncError::InvalidRequest) => "InvalidRequest",
        Err(SyncError::Interrupted) => "Interrupted",
        Err(SyncError::ReconciliationRequired) => "ReconciliationRequired",
        Err(SyncError::InvalidResponse) => "InvalidResponse",
        Err(SyncError::ResourceLimit) => "ResourceLimit",
        Err(SyncError::NoCurrentObservation) => "NoCurrentObservation",
        Err(SyncError::Wallet(WalletError::UnsupportedProfile)) => "WalletUnsupportedProfile",
        Err(SyncError::Wallet(_)) => "WalletOther",
        Err(SyncError::Chain(_)) => "Chain",
    };
    assert!(
        matches!(result, Err(SyncError::AccessDenied)),
        "outcome={outcome}; permission_checks={}; accepted_connections={}; context_rpcs={}",
        access.permission_checks.load(Ordering::SeqCst),
        fake.accepted_connections.load(Ordering::SeqCst),
        fake.rpc_methods.lock().unwrap().len(),
    );
    assert_eq!(
        access.permission_checks.load(Ordering::SeqCst),
        if post_channel { 3 } else { 2 }
    );
    // The maintained adapter completes these four actual context RPCs first.
    // Channel creation uses the maintained connect path, but a server accept
    // callback is not a client-completion boundary and may not yet have run.
    // Never wait for or infer a fifth accept. The post-channel test's exact
    // boundary is permission check3, not a claim of revocation during I/O.
    let connections = fake.accepted_connections.load(Ordering::SeqCst);
    if post_channel {
        assert!((4..=5).contains(&connections));
    } else {
        assert_eq!(connections, 4);
    }
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
    revoke_at_scan_boundary(false, 4_465_039).await;
}

#[tokio::test]
async fn post_channel_permission_denial_prevents_wallet_read_and_further_rpc() {
    // A genuinely imported, unsupported pre-NU7 birthday is an ordering
    // sentinel: without the post-await access guard, sync would read it and
    // return UnsupportedProfile before the next RPC's access check. AccessDenied
    // must win at permission check3 after the actual channel await instead.
    // This deliberately injects denial at that permission check, not at a
    // server-accept hook whose scheduling cannot prove a pending client await.
    let prior = u32::try_from(wholepact_chain::NU7_ACTIVATION_HEIGHT).unwrap() - 2;
    revoke_at_scan_boundary(true, prior).await;
}
