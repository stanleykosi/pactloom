//! Finite TLS loopback provider for actual born PUBLIC receivers. Read-only
//! until a same-owner merged/held submission guard arms ONE exact synthetic send.
//! The parent fixture owns the isolated ephemeral TLS identity/trust boundary.
//! This helper neither installs trust nor constructs a ChainAdapter/context,
//! account, native approval, submitted transaction or financial capability.

use super::synthetic_born_submission_sink_v1::SyntheticSinkControlV1;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::Response,
    routing::post,
};
use prost::Message;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
use wholepact_wallet::wallet::synthetic_born_receiver_blocks_v1::{
    BlockId, BlockRange, Empty, LightdInfo, SyntheticBornReceiverBlocksV1,
};

const SERVICE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";
const MAX_REQUESTS: usize = 4096;
const MAX_CONNECTIONS: usize = 512;

#[derive(Clone)]
struct PublicState {
    material: Arc<SyntheticBornReceiverBlocksV1>,
    requests: Arc<AtomicUsize>,
    denied: Arc<AtomicUsize>,
    deadline: Instant,
    sink: SyntheticSinkControlV1,
}

pub(super) struct SyntheticBornProviderV1 {
    endpoint: String,
    state: PublicState,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<io::Result<()>>>,
}

impl SyntheticBornProviderV1 {
    /// Only a real TLS listener is served. The caller must independently arrange
    /// and disclose its process-isolated test root; no certificate verification
    /// setting is changed here and HTTP is never labeled as HTTPS.
    pub(super) async fn start(
        material: SyntheticBornReceiverBlocksV1,
        mut tls: ServerConfig,
        deadline: Instant,
    ) -> io::Result<Self> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(900) {
            return Err(io::Error::other("invalid synthetic provider lifetime"));
        }
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("https://{}", listener.local_addr()?);
        let state = PublicState {
            material: Arc::new(material),
            requests: Arc::new(AtomicUsize::new(0)),
            denied: Arc::new(AtomicUsize::new(0)),
            deadline,
            sink: SyntheticSinkControlV1::default(),
        };
        let application = Router::new()
            .route("/{*path}", post(public_read))
            .with_state(state.clone());
        let listener = TlsListener {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            accepted: 0,
            deadline,
        };
        let (shutdown, receive) = oneshot::channel();
        let server = tokio::spawn(async move {
            let serve = axum::serve(listener, application).with_graceful_shutdown(async move {
                tokio::select! {
                    _ = receive => {},
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {},
                }
            });
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline + Duration::from_secs(2)),
                serve,
            )
            .await
            .map_err(|_| io::Error::other("synthetic provider shutdown deadline"))?
        });
        Ok(Self {
            endpoint,
            state,
            shutdown: Some(shutdown),
            server: Some(server),
        })
    }
    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(super) fn sink_control(&self) -> &SyntheticSinkControlV1 {
        &self.state.sink
    }
    pub(super) fn original_material(&self) -> &Arc<SyntheticBornReceiverBlocksV1> {
        &self.state.material
    }
    pub(super) fn original_deadline(&self) -> Instant {
        self.state.deadline
    }
    pub(super) fn served_requests(&self) -> usize {
        self.state
            .requests
            .load(Ordering::SeqCst)
            .saturating_sub(self.state.denied.load(Ordering::SeqCst))
    }
    pub(super) fn denied_requests(&self) -> usize {
        self.state.denied.load(Ordering::SeqCst)
    }
    /// Parent awaits this before its outer TempDir owner is released.
    pub(super) async fn shutdown(mut self) -> io::Result<()> {
        if let Some(signal) = self.shutdown.take() {
            let _ = signal.send(());
        }
        let Some(mut server) = self.server.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
            Ok(result) => result.map_err(|_| io::Error::other("synthetic provider task failed"))?,
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err(io::Error::other(
                    "synthetic provider failed bounded shutdown",
                ))
            }
        }
    }
}
impl Drop for SyntheticBornProviderV1 {
    fn drop(&mut self) {
        if let Some(signal) = self.shutdown.take() {
            let _ = signal.send(());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    accepted: usize,
    deadline: Instant,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.accepted >= MAX_CONNECTIONS || Instant::now() >= self.deadline {
                return std::future::pending().await;
            }
            let Ok((socket, address)) = self.listener.accept().await else {
                return std::future::pending().await;
            };
            self.accepted += 1;
            let until = self.deadline.min(Instant::now() + Duration::from_secs(2));
            if let Ok(Ok(stream)) = tokio::time::timeout_at(
                tokio::time::Instant::from_std(until),
                self.acceptor.accept(socket),
            )
            .await
            {
                return (stream, address);
            }
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

async fn public_read(State(state): State<PublicState>, request: Request) -> Response<Body> {
    let count = state.requests.fetch_add(1, Ordering::SeqCst);
    let method = request
        .uri()
        .path()
        .strip_prefix(SERVICE)
        .map(str::to_owned);
    if count >= MAX_REQUESTS
        || Instant::now() >= state.deadline
        || request.uri().query().is_some()
        || request.headers().contains_key("authorization")
    {
        return refused(&state);
    }
    let body_limit = if method.as_deref() == Some("SendTransaction") {
        2 * 1024 * 1024 + 32
    } else {
        4096
    };
    let read_deadline = state.deadline.min(Instant::now() + Duration::from_secs(2));
    let Ok(Ok(bytes)) = tokio::time::timeout_at(
        tokio::time::Instant::from_std(read_deadline),
        to_bytes(request.into_body(), body_limit),
    )
    .await
    else {
        return refused(&state);
    };
    if bytes.len() < 5
        || bytes[0] != 0
        || u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize != bytes.len() - 5
    {
        return refused(&state);
    }
    let data = &bytes[5..];
    let reply = if method.as_deref() == Some("SendTransaction") {
        state.sink.receive(data).map(|encoded| {
            let mut frame = vec![0];
            frame.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            frame.extend(encoded);
            frame
        })
    } else {
        reply(&state.material, method.as_deref().unwrap_or(""), data)
    };
    let Some(body) = reply else {
        return refused(&state);
    };
    if Instant::now() >= state.deadline {
        return refused(&state);
    }
    Response::builder()
        .header("content-type", "application/grpc")
        .header("grpc-status", "0")
        .header("age", "0")
        .body(Body::from(body))
        .expect("fixed public fixture response")
}
fn refused(state: &PublicState) -> Response<Body> {
    state.denied.fetch_add(1, Ordering::SeqCst);
    Response::builder()
        .header("content-type", "application/grpc")
        .header("grpc-status", "12")
        .body(Body::empty())
        .expect("fixed refused fixture response")
}
fn exact<M: Message + Default>(data: &[u8]) -> Option<M> {
    let value = M::decode(data).ok()?;
    (value.encode_to_vec() == data).then_some(value)
}
fn frame<M: Message>(values: &[M]) -> Vec<u8> {
    let mut result = Vec::new();
    for value in values {
        let bytes = value.encode_to_vec();
        result.push(0);
        result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        result.extend(bytes);
    }
    result
}
fn reply(material: &SyntheticBornReceiverBlocksV1, method: &str, data: &[u8]) -> Option<Vec<u8>> {
    let tip = material.blocks().last()?;
    match method {
        "GetLightdInfo" => {
            exact::<Empty>(data)?;
            Some(frame(&[LightdInfo {
                // Truthful fixture software labels, not claims to run a real
                // lightwalletd/zcashd or to provide consensus evidence. Durable
                // historical material retains these exact nonempty reports.
                version: "synthetic-born-provider-v1".into(),
                zcashd_subversion: "synthetic-no-zcashd-backend".into(),
                // Pinned upstream tag18 is named lightwallet_protocol_version;
                // wholepact-chain's narrow wire projection calls it protocol_version.
                lightwallet_protocol_version: "synthetic-compact-rpc-v1".into(),
                chain_name: "test".into(),
                sapling_activation_height: 280_000,
                consensus_branch_id: "77190ad9".into(),
                block_height: tip.height,
                estimated_height: tip.height,
                ..Default::default()
            }]))
        }
        "GetLatestBlock" => {
            exact::<Empty>(data)?;
            Some(frame(&[BlockId {
                height: tip.height,
                hash: tip.hash.clone(),
            }]))
        }
        "GetBlock" => {
            let id = exact::<BlockId>(data)?;
            if !id.hash.is_empty() {
                return None;
            }
            Some(frame(&[material
                .blocks()
                .iter()
                .find(|b| b.height == id.height)?
                .clone()]))
        }
        "GetTreeState" => {
            let id = exact::<BlockId>(data)?;
            if !id.hash.is_empty() {
                return None;
            }
            Some(frame(&[material
                .trees()
                .iter()
                .find(|b| b.height == id.height)?
                .clone()]))
        }
        "GetBlockRange" => {
            let range = exact::<BlockRange>(data)?;
            let start = range.start?;
            let end = range.end?;
            if !range.pool_types.is_empty()
                || !start.hash.is_empty()
                || !end.hash.is_empty()
                || end.height < start.height
                || end.height - start.height >= 32
                || start.height < material.blocks().first()?.height
                || end.height > tip.height
            {
                return None;
            }
            Some(frame(
                &material
                    .blocks()
                    .iter()
                    .filter(|b| b.height >= start.height && b.height <= end.height)
                    .cloned()
                    .collect::<Vec<_>>(),
            ))
        }
        // No transaction lookup, address/nullifier/FVK query, mempool,
        // external forwarding or arbitrary provider method is implemented.
        _ => None,
    }
}

#[cfg(all(test, feature = "durable-proposal"))]
#[path = "synthetic_born_provider_v1/durable_metadata_tests.rs"]
mod durable_metadata_tests;
