//! Controlled HTTP/2 fixtures with fresh never-funded owner keys and fabricated
//! notes and hashes. This server cannot receive or submit transactions.
use orchard::keys::FullViewingKey;
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wholepact_chain::{BackendIdentity, ChainAdapter};
use wholepact_wallet::wallet::{DedicatedTestnetWallet, protected_sync::*};
use zcash_client_backend::{
    data_api::{AccountBirthday, chain::ChainState},
    proto::{
        compact_formats::CompactBlock,
        service::{BlockId, BlockRange, TreeState},
    },
};
use zcash_client_sqlite::AccountUuid;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn display_hash(bytes: &[u8]) -> String {
    hex::encode(bytes.iter().rev().copied().collect::<Vec<_>>())
}

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::Response,
    routing::post,
};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use wholepact_chain::NetworkPolicy;
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
use zcash_client_backend::proto::service::{Empty, LightdInfo};
use zcash_primitives::block::BlockHash;

#[derive(Clone)]
pub struct Fake {
    pub owner_fvks: [FullViewingKey; 2],
    pub blocks: Arc<Vec<CompactBlock>>,
    pub trees: Arc<Vec<TreeState>>,
    pub mode: Arc<AtomicU8>,
    pub accepted_connections: Arc<AtomicUsize>,
    pub rpc_methods: Arc<Mutex<Vec<String>>>,
}
pub const SHORT: u8 = 1;
pub const WRONG_TREE_HEIGHT: u8 = 2;
pub const MALFORMED: u8 = 3;
pub const OLD_CACHE: u8 = 4;
pub const REORG: u8 = 5;
pub const WRONG_ROOT: u8 = 6;
pub const DELAY: u8 = 7;

pub struct FixtureAccess(pub bool);
impl LocalWalletAccess for FixtureAccess {
    fn permits(&self, _: AccountUuid, provider: &BackendIdentity, _: WalletAccessPurpose) -> bool {
        self.0 && provider.trust_profile == "synthetic_never_chain_evidence"
    }
}
fn framed<M: Message>(messages: &[M]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for message in messages {
        let b = message.encode_to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&(b.len() as u32).to_be_bytes());
        bytes.extend(b);
    }
    bytes
}
async fn handle(State(fake): State<Fake>, request: Request) -> Response<Body> {
    let method = request.uri().path().rsplit('/').next().unwrap().to_owned();
    fake.rpc_methods.lock().unwrap().push(method.clone());
    assert!(!request.headers().contains_key("authorization"));
    let bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap();
    for owner in &fake.owner_fvks {
        let canary = owner.to_bytes();
        assert!(!bytes.windows(canary.len()).any(|w| w == canary));
    }
    assert!(!bytes.windows(7).any(|w| w == b"owner-a"));
    let data = if bytes.len() >= 5 { &bytes[5..] } else { &[] };
    let mode = fake.mode.load(Ordering::SeqCst);
    let tip = fake.blocks.last().unwrap();
    let mut age = "0";
    let body = match method.as_str() {
        "GetLightdInfo" => {
            let _ = Empty::decode(data).unwrap();
            assert!(data.is_empty());
            framed(&[LightdInfo {
                chain_name: "test".into(),
                sapling_activation_height: 280_000,
                consensus_branch_id: "77190ad9".into(),
                block_height: tip.height,
                estimated_height: tip.height,
                ..Default::default()
            }])
        }
        "GetLatestBlock" => {
            assert!(data.is_empty());
            framed(&[BlockId {
                height: tip.height,
                hash: tip.hash.clone(),
            }])
        }
        "GetBlock" => {
            let id = BlockId::decode(data).unwrap();
            assert!(id.hash.is_empty());
            assert_eq!(id.encode_to_vec(), data);
            let mut block = fake
                .blocks
                .iter()
                .find(|b| b.height == id.height)
                .unwrap()
                .clone();
            if mode == REORG && block.height != tip.height {
                block.hash = vec![99; 32];
            }
            framed(&[block])
        }
        "GetTreeState" => {
            let id = BlockId::decode(data).unwrap();
            assert!(id.hash.is_empty());
            assert_eq!(id.encode_to_vec(), data);
            let mut tree = fake
                .trees
                .iter()
                .find(|b| b.height == id.height)
                .unwrap()
                .clone();
            if mode == WRONG_TREE_HEIGHT {
                tree.height += 1;
            }
            if mode == WRONG_ROOT && tree.height == tip.height {
                tree.ironwood_tree = "000000".into();
            }
            framed(&[tree])
        }
        "GetBlockRange" => {
            if mode == DELAY {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let range = BlockRange::decode(data).unwrap();
            assert_eq!(range.encode_to_vec(), data);
            assert!(range.pool_types.is_empty());
            let start = range.start.unwrap();
            let end = range.end.unwrap();
            assert!(start.hash.is_empty() && end.hash.is_empty());
            let first = start.height;
            let last = end.height;
            assert!(last >= first && last - first < 32);
            let mut blocks: Vec<_> = fake
                .blocks
                .iter()
                .filter(|b| b.height >= first && b.height <= last)
                .cloned()
                .collect();
            if mode == SHORT {
                blocks.pop();
            }
            if mode == MALFORMED {
                blocks[0].vtx[0].txid.clear();
            }
            if mode == OLD_CACHE {
                age = "1000";
            }
            framed(&blocks)
        }
        _ => panic!("unexpected fixture RPC"),
    };
    Response::builder()
        .header("content-type", "application/grpc")
        .header("grpc-status", "0")
        .header("x-cache", "hit")
        .header("age", age)
        .body(Body::from(Bytes::from(body)))
        .unwrap()
}
pub async fn fake_server(
    block_count: u32,
) -> (Fake, String, tokio::task::JoinHandle<()>, FullViewingKey) {
    fake_server_with_connection_hook(block_count, |_| {}).await
}

/// Test-only actual connection observation. The default fixture installs no
/// hook; this never supplies a production privacy policy or native authority.
pub(crate) async fn fake_server_with_connection_hook(
    block_count: u32,
    on_connection: impl FnMut(usize) + Send + 'static,
) -> (Fake, String, tokio::task::JoinHandle<()>, FullViewingKey) {
    fake_server_inner(block_count, on_connection, false).await
}

/// A real later synthetic commitment gives the maintained scanner a second
/// checkpoint. Its unrelated owners do not add notes to either original wallet.
/// No checkpoint rows or roots are injected into the wallet database.
pub(crate) async fn fake_server_with_second_commitment_block()
-> (Fake, String, tokio::task::JoinHandle<()>, FullViewingKey) {
    fake_server_inner(2, |_| {}, true).await
}

async fn fake_server_inner(
    block_count: u32,
    mut on_connection: impl FnMut(usize) + Send + 'static,
    second_commitment_block: bool,
) -> (Fake, String, tokio::task::JoinHandle<()>, FullViewingKey) {
    use axum::serve::ListenerExt;
    let fixture = wholepact_wallet::wallet::SyntheticContributionFixture::generate();
    let fvk = FullViewingKey::from(fixture.owner_spending_key(0));
    let mut first = fixture.compact_block();
    first.time = now() as u32;
    let mut trees = vec![TreeState {
        network: "test".into(),
        height: first.height - 1,
        hash: display_hash(&first.prev_hash),
        time: first.time,
        sapling_tree: "000000".into(),
        orchard_tree: "000000".into(),
        ironwood_tree: "000000".into(),
    }];
    let mut blocks = vec![first.clone()];
    let mut cumulative_metadata = first.chain_metadata.unwrap();
    for i in 1..block_count {
        let previous = blocks.last().unwrap();
        let mut hash = [61; 32];
        hash[..4].copy_from_slice(&i.to_le_bytes());
        let vtx = if second_commitment_block && i == 1 {
            let unrelated = wholepact_wallet::wallet::SyntheticContributionFixture::generate();
            let mut transactions = unrelated.compact_block().vtx;
            assert_eq!(transactions.len(), 1);
            // Compact transaction IDs and block hashes are explicitly fabricated
            // public fixture data; note ciphertext/commitments are genuine.
            transactions[0].txid = vec![62; 32];
            cumulative_metadata.ironwood_commitment_tree_size +=
                u32::try_from(transactions[0].ironwood_actions.len()).unwrap();
            transactions
        } else {
            vec![]
        };
        blocks.push(CompactBlock {
            height: first.height + u64::from(i),
            hash: hash.to_vec(),
            prev_hash: previous.hash.clone(),
            time: first.time,
            chain_metadata: Some(cumulative_metadata),
            vtx,
            ..Default::default()
        });
    }
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for block in &blocks {
        for action in block.vtx.iter().flat_map(|tx| &tx.ironwood_actions) {
            tree.append(
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
                    &action.cmx.clone().try_into().unwrap(),
                ))
                .unwrap(),
            )
            .unwrap();
        }
        let mut encoded = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree(&tree, &mut encoded).unwrap();
        trees.push(TreeState {
            network: "test".into(),
            height: block.height,
            hash: display_hash(&block.hash),
            time: first.time,
            sapling_tree: "000000".into(),
            orchard_tree: "000000".into(),
            ironwood_tree: hex::encode(&encoded),
        });
    }
    let fake = Fake {
        owner_fvks: [
            fvk.clone(),
            FullViewingKey::from(fixture.owner_spending_key(1)),
        ],
        blocks: Arc::new(blocks),
        trees: Arc::new(trees),
        mode: Arc::new(AtomicU8::new(0)),
        accepted_connections: Arc::new(AtomicUsize::new(0)),
        rpc_methods: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let connections = fake.accepted_connections.clone();
    let listener = listener.tap_io(move |_| {
        let count = connections.fetch_add(1, Ordering::SeqCst) + 1;
        on_connection(count);
    });
    let app = Router::new()
        .route("/{*path}", post(handle))
        .with_state(fake.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (fake, endpoint, server, fvk)
}
pub fn source(endpoint: &str) -> ChainAdapter {
    ChainAdapter::synthetic_loopback_for_qualification(
        endpoint,
        NetworkPolicy {
            retries: 0,
            ..Default::default()
        },
    )
    .unwrap()
}
pub fn ephemeral_database_key() -> DatabaseKey {
    let mut key_bytes = [0; 32];
    UnwrapErr(SysRng).fill_bytes(&mut key_bytes);
    DatabaseKey::from_bytes(key_bytes)
}
pub fn database(fvk: &FullViewingKey) -> (tempfile::TempDir, std::path::PathBuf, DatabaseKey) {
    database_with_prior_height(fvk, 4_465_039)
}
pub(crate) fn database_with_prior_height(
    fvk: &FullViewingKey,
    prior_height: u32,
) -> (tempfile::TempDir, std::path::PathBuf, DatabaseKey) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("synthetic-wallet.db");
    let key = ephemeral_database_key();
    let mut wallet =
        DedicatedTestnetWallet::from_encrypted_connection(create_encrypted(&path, &key).unwrap())
            .unwrap();
    wallet
        .import_dedicated_fvk(
            fvk,
            AccountBirthday::from_parts(
                ChainState::empty(prior_height.into(), BlockHash([50; 32])),
                None,
            ),
        )
        .unwrap();
    drop(wallet);
    (directory, path, key)
}
pub fn controller(
    path: &std::path::Path,
    key: &DatabaseKey,
    endpoint: &str,
) -> ProtectedWalletSync {
    ProtectedWalletSync::from_encrypted_connection(
        open_encrypted(path, key).unwrap(),
        source(endpoint),
        NonZeroU32::MIN,
    )
    .unwrap()
}
