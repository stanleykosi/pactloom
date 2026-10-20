//! Finite TLS loopback provider for actual born PUBLIC receivers. Read-only
//! until a same-owner merged/held submission guard arms ONE exact synthetic send.
//! The parent fixture owns the isolated ephemeral TLS identity/trust boundary.
//! This helper neither installs trust nor constructs a ChainAdapter/context,
//! account, native approval, submitted transaction or financial capability.

use super::synthetic_born_submission_sink_v1::SyntheticSinkControlV1;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::Response,
    routing::post,
    Router,
};
use prost::Message;
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};
use wholepact_wallet::wallet::synthetic_born_receiver_blocks_v1::{
    BlockId, BlockRange, Empty, LightdInfo, SyntheticBornReceiverBlocksV1,
};

const SERVICE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";
const MAX_REQUESTS: usize = 4096;
const MAX_CONNECTIONS: usize = 512;

// Diagnostic observations only, never source/effect authority. Independent atomic
// counters are not an atomic timeline and do not establish a causal failure.
const MAX_DIAGNOSTIC_COUNT: usize = 1_000_000;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SyntheticProviderDiagnosticsV1 {
    pub(super) accepted_connections: usize,
    pub(super) accept_errors: usize,
    pub(super) handshake_successes: usize,
    pub(super) handshake_errors: usize,
    pub(super) handshake_timeouts: usize,
    pub(super) connection_limit_stops: usize,
    pub(super) connection_deadline_stops: usize,
    pub(super) requests: usize,
    pub(super) denied: usize,
    pub(super) request_limit_denials: usize,
    pub(super) request_deadline_denials: usize,
    pub(super) request_shape_denials: usize,
    pub(super) body_read_errors: usize,
    pub(super) body_read_timeouts: usize,
    pub(super) frame_denials: usize,
    pub(super) method_denials: usize,
    pub(super) replies: usize,
    pub(super) deadline_elapsed: bool,
    pub(super) server_finished: bool,
    pub(super) clamped: bool,
}
impl SyntheticProviderDiagnosticsV1 {
    pub(super) fn validate(&self) -> bool {
        [
            self.accepted_connections,
            self.accept_errors,
            self.handshake_successes,
            self.handshake_errors,
            self.handshake_timeouts,
            self.connection_limit_stops,
            self.connection_deadline_stops,
            self.requests,
            self.denied,
            self.request_limit_denials,
            self.request_deadline_denials,
            self.request_shape_denials,
            self.body_read_errors,
            self.body_read_timeouts,
            self.frame_denials,
            self.method_denials,
            self.replies,
        ]
        .into_iter()
        .all(|value| value <= MAX_DIAGNOSTIC_COUNT)
    }
}
#[derive(Default)]
struct ProviderCountersV1 {
    accepted_connections: AtomicUsize,
    accept_errors: AtomicUsize,
    handshake_successes: AtomicUsize,
    handshake_errors: AtomicUsize,
    handshake_timeouts: AtomicUsize,
    connection_limit_stops: AtomicUsize,
    connection_deadline_stops: AtomicUsize,
    requests: AtomicUsize,
    denied: AtomicUsize,
    request_limit_denials: AtomicUsize,
    request_deadline_denials: AtomicUsize,
    request_shape_denials: AtomicUsize,
    body_read_errors: AtomicUsize,
    body_read_timeouts: AtomicUsize,
    frame_denials: AtomicUsize,
    method_denials: AtomicUsize,
    replies: AtomicUsize,
    server_finished: AtomicBool,
    clamped: AtomicBool,
}
#[derive(Clone)]
pub(super) struct SyntheticProviderDiagnosticHandleV1 {
    counters: Arc<ProviderCountersV1>,
    deadline: Instant,
}
impl SyntheticProviderDiagnosticHandleV1 {
    pub(super) fn snapshot(&self) -> SyntheticProviderDiagnosticsV1 {
        let c = &self.counters;
        SyntheticProviderDiagnosticsV1 {
            accepted_connections: c.accepted_connections.load(Ordering::SeqCst),
            accept_errors: c.accept_errors.load(Ordering::SeqCst),
            handshake_successes: c.handshake_successes.load(Ordering::SeqCst),
            handshake_errors: c.handshake_errors.load(Ordering::SeqCst),
            handshake_timeouts: c.handshake_timeouts.load(Ordering::SeqCst),
            connection_limit_stops: c.connection_limit_stops.load(Ordering::SeqCst),
            connection_deadline_stops: c.connection_deadline_stops.load(Ordering::SeqCst),
            requests: c.requests.load(Ordering::SeqCst),
            denied: c.denied.load(Ordering::SeqCst),
            request_limit_denials: c.request_limit_denials.load(Ordering::SeqCst),
            request_deadline_denials: c.request_deadline_denials.load(Ordering::SeqCst),
            request_shape_denials: c.request_shape_denials.load(Ordering::SeqCst),
            body_read_errors: c.body_read_errors.load(Ordering::SeqCst),
            body_read_timeouts: c.body_read_timeouts.load(Ordering::SeqCst),
            frame_denials: c.frame_denials.load(Ordering::SeqCst),
            method_denials: c.method_denials.load(Ordering::SeqCst),
            replies: c.replies.load(Ordering::SeqCst),
            deadline_elapsed: Instant::now() >= self.deadline,
            server_finished: c.server_finished.load(Ordering::SeqCst),
            clamped: c.clamped.load(Ordering::SeqCst),
        }
    }
    fn increment(&self, counter: &AtomicUsize) {
        if counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                (value < MAX_DIAGNOSTIC_COUNT).then(|| value + 1)
            })
            .is_err()
        {
            self.counters.clamped.store(true, Ordering::SeqCst);
        }
    }
}
struct ProviderTaskFinishedV1(SyntheticProviderDiagnosticHandleV1);
impl Drop for ProviderTaskFinishedV1 {
    fn drop(&mut self) {
        self.0
            .counters
            .server_finished
            .store(true, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct PublicState {
    material: Arc<SyntheticBornReceiverBlocksV1>,
    requests: Arc<AtomicUsize>,
    denied: Arc<AtomicUsize>,
    deadline: Instant,
    expires_at_ms: u64,
    sink: SyntheticSinkControlV1,
    diagnostics: SyntheticProviderDiagnosticHandleV1,
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
        tls: ServerConfig,
        deadline: Instant,
    ) -> io::Result<Self> {
        Self::start_at(material, tls, deadline, "127.0.0.1:0").await
    }
    async fn start_at(
        material: SyntheticBornReceiverBlocksV1,
        mut tls: ServerConfig,
        deadline: Instant,
        address: &str,
    ) -> io::Result<Self> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(900) {
            return Err(io::Error::other("invalid synthetic provider lifetime"));
        }
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind(address).await?;
        let endpoint = format!("https://{}", listener.local_addr()?);
        let wall_now = fixture_now_ms()?;
        let expires_at_ms = wall_now
            .checked_add(
                u64::try_from(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .map_err(|_| io::Error::other("fixture bound"))?,
            )
            .ok_or_else(|| io::Error::other("fixture bound"))?;
        let state = PublicState {
            material: Arc::new(material),
            requests: Arc::new(AtomicUsize::new(0)),
            denied: Arc::new(AtomicUsize::new(0)),
            deadline,
            expires_at_ms,
            sink: SyntheticSinkControlV1::default(),
            diagnostics: SyntheticProviderDiagnosticHandleV1 {
                counters: Arc::new(ProviderCountersV1::default()),
                deadline,
            },
        };
        let application = Router::new()
            .route("/{*path}", post(public_read))
            .with_state(state.clone());
        let listener = TlsListener {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            accepted: 0,
            deadline,
            diagnostics: state.diagnostics.clone(),
        };
        let (shutdown, receive) = oneshot::channel();
        let finished = ProviderTaskFinishedV1(state.diagnostics.clone());
        let server = tokio::spawn(async move {
            let _finished = finished;
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
    pub(super) fn diagnostic_handle_v1(&self) -> SyntheticProviderDiagnosticHandleV1 {
        self.state.diagnostics.clone()
    }
    pub(super) fn diagnostics_snapshot_v1(&self) -> SyntheticProviderDiagnosticsV1 {
        self.state.diagnostics.snapshot()
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
    diagnostics: SyntheticProviderDiagnosticHandleV1,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let connection_limit = self.accepted >= MAX_CONNECTIONS;
            if connection_limit || Instant::now() >= self.deadline {
                if connection_limit {
                    self.diagnostics
                        .increment(&self.diagnostics.counters.connection_limit_stops);
                } else {
                    self.diagnostics
                        .increment(&self.diagnostics.counters.connection_deadline_stops);
                }
                return std::future::pending().await;
            }
            let Ok((socket, address)) = self.listener.accept().await else {
                self.diagnostics
                    .increment(&self.diagnostics.counters.accept_errors);
                return std::future::pending().await;
            };
            self.accepted += 1;
            self.diagnostics
                .increment(&self.diagnostics.counters.accepted_connections);
            let until = self.deadline.min(Instant::now() + Duration::from_secs(2));
            match tokio::time::timeout_at(
                tokio::time::Instant::from_std(until),
                self.acceptor.accept(socket),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    self.diagnostics
                        .increment(&self.diagnostics.counters.handshake_successes);
                    return (stream, address);
                }
                Ok(Err(_)) => self
                    .diagnostics
                    .increment(&self.diagnostics.counters.handshake_errors),
                Err(_) => self
                    .diagnostics
                    .increment(&self.diagnostics.counters.handshake_timeouts),
            }
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

async fn public_read(State(state): State<PublicState>, request: Request) -> Response<Body> {
    let count = state.requests.fetch_add(1, Ordering::SeqCst);
    let d = &state.diagnostics;
    d.increment(&d.counters.requests);
    let method = request
        .uri()
        .path()
        .strip_prefix(SERVICE)
        .map(str::to_owned);
    let request_limit = count >= MAX_REQUESTS;
    let request_expired = !request_limit && Instant::now() >= state.deadline;
    if request_limit
        || request_expired
        || request.uri().query().is_some()
        || request.headers().contains_key("authorization")
    {
        if request_limit {
            d.increment(&d.counters.request_limit_denials);
        } else if request_expired {
            d.increment(&d.counters.request_deadline_denials);
        } else {
            d.increment(&d.counters.request_shape_denials);
        }
        return refused(&state);
    }
    let body_limit = if method.as_deref() == Some("SendTransaction") {
        2 * 1024 * 1024 + 32
    } else {
        4096
    };
    let read_deadline = state.deadline.min(Instant::now() + Duration::from_secs(2));
    let bytes = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(read_deadline),
        to_bytes(request.into_body(), body_limit),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            d.increment(&d.counters.body_read_errors);
            return refused(&state);
        }
        Err(_) => {
            d.increment(&d.counters.body_read_timeouts);
            return refused(&state);
        }
    };
    if bytes.len() < 5
        || bytes[0] != 0
        || u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize != bytes.len() - 5
    {
        d.increment(&d.counters.frame_denials);
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
        d.increment(&d.counters.method_denials);
        return refused(&state);
    };
    if Instant::now() >= state.deadline {
        d.increment(&d.counters.request_deadline_denials);
        return refused(&state);
    }
    d.increment(&d.counters.replies);
    Response::builder()
        .header("content-type", "application/grpc")
        .header("grpc-status", "0")
        .header("age", "0")
        .body(Body::from(body))
        .expect("fixed public fixture response")
}
fn refused(state: &PublicState) -> Response<Body> {
    state.denied.fetch_add(1, Ordering::SeqCst);
    state
        .diagnostics
        .increment(&state.diagnostics.counters.denied);
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedPublicProviderV1 {
    version: u32,
    endpoint: String,
    material: Vec<u8>,
    expires_at_ms: u64,
}
fn fixture_now_ms() -> io::Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::other("synthetic fixture clock"))?
            .as_millis(),
    )
    .map_err(|_| io::Error::other("synthetic fixture clock"))
}
impl SyntheticBornProviderV1 {
    pub(super) fn preserve_public_original_v1(&self) -> io::Result<Vec<u8>> {
        if Instant::now() >= self.state.deadline || fixture_now_ms()? >= self.state.expires_at_ms {
            return Err(io::Error::other("expired original fixture"));
        }
        let expires_at_ms = self.state.expires_at_ms;
        let material = self
            .state
            .material
            .preserve_public_original_v1()
            .map_err(|_| io::Error::other("fixture material"))?;
        let bytes = serde_json::to_vec(&PreservedPublicProviderV1 {
            version: 1,
            endpoint: self.endpoint.clone(),
            material,
            expires_at_ms,
        })
        .map_err(|_| io::Error::other("fixture encoding"))?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(io::Error::other("fixture limit"));
        }
        Ok(bytes)
    }
    pub(super) async fn reopen_public_original_v1(
        bytes: &[u8],
        tls: ServerConfig,
        original_cutoff: Instant,
    ) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            return Err(io::Error::other("fixture limit"));
        }
        let saved: PreservedPublicProviderV1 =
            serde_json::from_slice(bytes).map_err(|_| io::Error::other("fixture encoding"))?;
        let address: std::net::SocketAddr = saved
            .endpoint
            .strip_prefix("https://")
            .ok_or_else(|| io::Error::other("fixture endpoint"))?
            .parse()
            .map_err(|_| io::Error::other("fixture endpoint"))?;
        if saved.version != 1 || !address.ip().is_loopback() || address.port() == 0 {
            return Err(io::Error::other("fixture endpoint"));
        }
        let observed = Instant::now();
        let remaining = saved
            .expires_at_ms
            .checked_sub(fixture_now_ms()?)
            .filter(|v| *v > 0 && *v <= 900_000)
            .ok_or_else(|| io::Error::other("expired original fixture"))?;
        let deadline = original_cutoff.min(
            observed
                .checked_add(Duration::from_millis(remaining))
                .ok_or_else(|| io::Error::other("fixture bound"))?,
        );
        let material = SyntheticBornReceiverBlocksV1::reopen_public_original_v1(&saved.material)
            .map_err(|_| io::Error::other("fixture material"))?;
        Self::start_at(material, tls, deadline, &address.to_string()).await
    }
}

#[cfg(test)]
mod provider_diagnostic_tests {
    use super::*;
    #[test]
    fn provider_diagnostics_are_bounded_inert_and_closed() {
        let handle = SyntheticProviderDiagnosticHandleV1 {
            counters: Arc::new(ProviderCountersV1::default()),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let first = handle.snapshot();
        assert!(first.validate());
        assert_eq!(first.handshake_errors, 0);
        assert!(!first.clamped && !first.server_finished);
        handle
            .counters
            .handshake_errors
            .store(MAX_DIAGNOSTIC_COUNT, Ordering::SeqCst);
        handle.increment(&handle.counters.handshake_errors);
        let clamped = handle.snapshot();
        assert!(clamped.validate() && clamped.clamped);
        assert_eq!(clamped.handshake_errors, MAX_DIAGNOSTIC_COUNT);
        let bytes = serde_json::to_vec(&clamped).unwrap();
        assert!(bytes.len() < 1024);
        let decoded: SyntheticProviderDiagnosticsV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.validate());
        let mut object = serde_json::to_value(&decoded).unwrap();
        object
            .as_object_mut()
            .unwrap()
            .insert("raw_error".into(), "forbidden".into());
        assert!(serde_json::from_value::<SyntheticProviderDiagnosticsV1>(object).is_err());
        let mut invalid = decoded;
        invalid.requests = MAX_DIAGNOSTIC_COUNT + 1;
        assert!(!invalid.validate());
        let finished = ProviderTaskFinishedV1(handle.clone());
        drop(finished);
        assert!(handle.snapshot().server_finished);
    }
}
