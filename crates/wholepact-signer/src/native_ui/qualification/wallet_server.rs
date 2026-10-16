//! Controlled HTTP/2 fixtures. All keys, notes, hashes and ciphertexts are public,
//! never-funded synthetic data. This server cannot receive or submit transactions.
use orchard::keys::FullViewingKey;
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wholepact_chain::{BackendIdentity, ChainAdapter};
use wholepact_wallet::wallet::AccountUuid;
use wholepact_wallet::wallet::{protected_sync::*, DedicatedTestnetWallet};
use zcash_client_backend::{
    data_api::{chain::ChainState, AccountBirthday},
    proto::{
        compact_formats::CompactBlock,
        service::{BlockId, BlockRange, TreeState},
    },
};
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
    body::{Body, Bytes},
    extract::{Request, State},
    http::Response,
    routing::post,
    Router,
};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use wholepact_chain::NetworkPolicy;
use wholepact_storage_security::{create_encrypted, open_encrypted, DatabaseKey};
use zcash_client_backend::proto::service::{Empty, LightdInfo};
use zcash_primitives::block::BlockHash;

#[derive(Clone)]
pub struct Fake {
    pub blocks: Arc<Vec<CompactBlock>>,
    pub trees: Arc<Vec<TreeState>>,
    pub mode: Arc<AtomicU8>,
    fvk_canary: [u8; 96],
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
    assert!(!request.headers().contains_key("authorization"));
    let bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap();
    assert!(!bytes
        .windows(fake.fvk_canary.len())
        .any(|w| w == fake.fvk_canary));
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
pub(super) async fn fake_server(
    fvk: &FullViewingKey,
) -> (Fake, String, tokio::task::JoinHandle<()>, FullViewingKey) {
    let block_count = 1u32;
    let mut first = fixed_block(fvk);
    first.time = now() as u32;
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    for action in &first.vtx[0].ironwood_actions {
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
    for i in 1..block_count {
        let previous = blocks.last().unwrap();
        let mut hash = [61; 32];
        hash[..4].copy_from_slice(&i.to_le_bytes());
        blocks.push(CompactBlock {
            height: first.height + u64::from(i),
            hash: hash.to_vec(),
            prev_hash: previous.hash.clone(),
            time: first.time,
            chain_metadata: first.chain_metadata,
            ..Default::default()
        });
    }
    for block in &blocks {
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
        blocks: Arc::new(blocks),
        trees: Arc::new(trees),
        mode: Arc::new(AtomicU8::new(0)),
        fvk_canary: fvk.to_bytes(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/{*path}", post(handle))
        .with_state(fake.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (fake, endpoint, server, fvk.clone())
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
pub fn database(fvk: &FullViewingKey) -> (tempfile::TempDir, std::path::PathBuf, DatabaseKey) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("synthetic-wallet.db");
    let key = DatabaseKey::from_bytes([83; 32]);
    let mut wallet =
        DedicatedTestnetWallet::from_encrypted_connection(create_encrypted(&path, &key).unwrap())
            .unwrap();
    wallet
        .import_dedicated_fvk(
            fvk,
            AccountBirthday::from_parts(
                ChainState::empty(4_465_039u32.into(), BlockHash([50; 32])),
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

// Fabricated compact ciphertext for the fixed genuine BIP39/ZIP32 account.
fn fixed_block(fvk: &FullViewingKey) -> CompactBlock {
    use rand::{rngs::StdRng, SeedableRng};
    use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactTx};
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::from_raw(200_000),
            zcash_protocol::memo::MemoBytes::empty().into_bytes(),
        )
        .unwrap();
    let (bundle, _) = builder
        .build::<i64>(StdRng::from_seed([0x59; 32]))
        .unwrap()
        .unwrap();
    let actions: Vec<_> = bundle.actions().iter().map(Into::into).collect();
    let size = actions.len() as u32;
    CompactBlock {
        height: 4_465_040,
        hash: vec![51; 32],
        prev_hash: vec![50; 32],
        vtx: vec![CompactTx {
            txid: vec![52; 32],
            ironwood_actions: actions,
            ..Default::default()
        }],
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: size,
        }),
        ..Default::default()
    }
}
