//! CI-only loopback mechanism qualification, not payment or public-chain evidence.
//! No owner, permission callback, RPC, or private material is moved into the driver.
use crate::{
    connect_driver::{connect_until, connect_until_observed, TestConnectObservation},
    proxy::ProxyRoute,
};
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_rustls::{
    rustls::{crypto::ring, ServerConfig},
    TlsAcceptor,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
#[path = "tests/ephemeral_tls.rs"]
mod ephemeral_tls;
const LIMIT: Duration = Duration::from_secs(8);
#[derive(Default)]
struct Evidence {
    accepted: AtomicUsize,
    tls: AtomicUsize,
    timed_out: AtomicUsize,
    tls_errors: AtomicUsize,
    proxy_headers: AtomicUsize,
    proxy_target_connected: AtomicUsize,
    proxy_copy_finished: AtomicUsize,
    proxy_copy_outcome: AtomicUsize,
    closed: AtomicUsize,
    rpc: AtomicUsize,
    start: AtomicBool,
}
// Closed diagnostic state is owned only by this exact, serial CI selector.
// Global case/phase/check identify occurrence context, not causal task identity,
// when a concurrent worker panics. The source unit and location identify its check.
const CASES: &[&str] = &[
    "unstarted",
    "direct_inline",
    "direct_driven",
    "http_connect_inline",
    "http_connect_driven",
    "cancel_before_poll",
    "expired_before_poll",
    "cancel_during_tls",
    "stalled_deadline",
    "drop_unconsumed",
    "queued_deadline",
    "direct_hostname_refusal",
    "http_connect_hostname_refusal",
];
const PHASES: &[&str] = &[
    "started",
    "caller_resumed",
    "connect_returned",
    "assertions_passed",
    "cleanup_verified",
    "cleanup_started",
    "probe_started",
    "probe_finished",
];
const CHECKS: &[&str] = &[
    "none",
    "expect_no_http",
    "expect_local_owner",
    "expect_driven_success",
    "expect_tls_success",
    "expect_no_tls_timeout",
    "probe_ready",
    "probe_unary",
    "expect_probe_count",
    "expect_inline_failure",
    "expect_tls_timeout",
    "socket_close",
    "server_join",
    "proxy_join",
    "expect_initial_pending",
    "expect_hostname_refusal",
    "expect_accepted",
    "expect_no_tls_success",
    "caller_accepted",
    "driver_finished",
    "expect_driver_started",
    "expect_driver_success",
    "expect_original_timeout",
    "stalled_server_join",
    "expect_inline_rpc_failure",
    "expect_probe_success",
    "expect_single_connection",
];
static CHECK: AtomicUsize = AtomicUsize::new(0);
fn checking(check: usize) {
    CHECK.store(check, Ordering::SeqCst);
}
const OUTCOMES: &[&str] = &[
    "unobserved",
    "success",
    "timeout",
    "transport_unavailable",
    "other_error",
];
const PROBE_OUTCOMES: &[&str] = &[
    "none",
    "success",
    "readiness_error",
    "unary_error",
    "timeout",
];
static PROBE_OUTCOME: AtomicUsize = AtomicUsize::new(0);
static OUTCOME: AtomicUsize = AtomicUsize::new(0);
static CASE: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static FAILURE_RECORDED: AtomicBool = AtomicBool::new(false);
static CURRENT_COUNTS: std::sync::Mutex<Option<Arc<Evidence>>> = std::sync::Mutex::new(None);
fn diagnostic_row() -> serde_json::Value {
    let counts = CURRENT_COUNTS.try_lock().ok().and_then(|g| g.clone());
    let count = |f: fn(&Evidence) -> &AtomicUsize| {
        counts
            .as_ref()
            .map_or(0, |c| f(c).load(Ordering::SeqCst).min(16))
    };
    let clamped = counts.as_ref().is_some_and(|e| {
        [
            &e.accepted,
            &e.tls,
            &e.timed_out,
            &e.tls_errors,
            &e.closed,
            &e.rpc,
            &e.proxy_headers,
            &e.proxy_target_connected,
            &e.proxy_copy_finished,
        ]
        .iter()
        .any(|v| v.load(Ordering::SeqCst) > 16)
    });
    let copy_outcome = counts.as_ref().map_or("none", |e| {
        ["none", "success", "io_error", "timeout"]
            .get(e.proxy_copy_outcome.load(Ordering::SeqCst))
            .copied()
            .unwrap_or("none")
    });
    serde_json::json!({"probe_outcome":PROBE_OUTCOMES.get(PROBE_OUTCOME.load(Ordering::SeqCst)).unwrap_or(&"none"),"outcome":OUTCOMES.get(OUTCOME.load(Ordering::SeqCst)).unwrap_or(&"unobserved"),"proxy_copy_outcome":copy_outcome,"active_check":CHECKS.get(CHECK.load(Ordering::SeqCst)).unwrap_or(&"none"),"counts_clamped":clamped,"tls_errors":count(|e|&e.tls_errors),"proxy_headers":count(|e|&e.proxy_headers),"proxy_target_connected":count(|e|&e.proxy_target_connected),"proxy_copy_finished":count(|e|&e.proxy_copy_finished),"schema":1,"case":CASES.get(CASE.load(Ordering::SeqCst)).unwrap_or(&"unstarted"),"phase":PHASES.get(PHASE.load(Ordering::SeqCst)).unwrap_or(&"started"),"counts_available":counts.is_some(),"accepted":count(|e|&e.accepted),"tls_success":count(|e|&e.tls),"tls_timeout":count(|e|&e.timed_out),"sockets_closed":count(|e|&e.closed),"http_requests":count(|e|&e.rpc),"cleanup_verified":false})
}
fn emit_diagnostic(prefix: &str, row: &serde_json::Value) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(prefix.as_bytes());
    let _ = serde_json::to_writer(&mut out, row);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}
fn observe(phase: usize, outcome: &'static str) {
    PHASE.store(phase, Ordering::SeqCst);
    if outcome != "unobserved" {
        OUTCOME.store(
            OUTCOMES
                .iter()
                .position(|value| *value == outcome)
                .unwrap_or(0),
            Ordering::SeqCst,
        );
    }
    let mut row = diagnostic_row();
    row["cleanup_verified"] = (phase == 4).into();
    emit_diagnostic("CI_SYNTHETIC_CONNECT_DRIVER_OBSERVATION ", &row);
}
fn begin_case(case: usize) {
    CASE.store(case, Ordering::SeqCst);
    OUTCOME.store(0, Ordering::SeqCst);
    PROBE_OUTCOME.store(0, Ordering::SeqCst);
    checking(0);
    if let Ok(mut counts) = CURRENT_COUNTS.lock() {
        *counts = None;
    }
    observe(0, "unobserved");
}
fn connect_outcome(result: &Result<Channel, crate::ChainError>) -> &'static str {
    match result {
        Ok(_) => "success",
        Err(crate::ChainError::Timeout) => "timeout",
        Err(crate::ChainError::TransportUnavailable) => "transport_unavailable",
        Err(_) => "other_error",
    }
}
fn record_panic(info: &std::panic::PanicHookInfo<'_>) {
    if FAILURE_RECORDED.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut row = diagnostic_row();
    let (unit, line, column) = info.location().map_or(("other", 0, 0), |location| {
        let file = location.file();
        let unit = if file.ends_with("connect_driver_tests.rs") {
            "connect_driver_tests"
        } else if file.ends_with("connect_driver.rs") {
            "connect_driver"
        } else if file.ends_with("tests/ephemeral_tls.rs") {
            "ephemeral_tls"
        } else {
            "other"
        };
        (
            unit,
            location.line().min(10000),
            location.column().min(1000),
        )
    });
    row["source_unit"] = unit.into();
    row["line"] = line.into();
    row["column"] = column.into();
    emit_diagnostic("CI_SYNTHETIC_CONNECT_DRIVER_FAILURE ", &row);
}
struct Tracked(TcpStream, Arc<Evidence>);
impl Drop for Tracked {
    fn drop(&mut self) {
        self.1.closed.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsyncRead for Tracked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, b)
    }
}
impl AsyncWrite for Tracked {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
struct Listener {
    tcp: Option<TcpListener>,
    addr: std::net::SocketAddr,
    tls: TlsAcceptor,
    evidence: Arc<Evidence>,
    accepted: Option<oneshot::Sender<()>>,
    gate: bool,
}
impl axum::serve::Listener for Listener {
    type Io = tokio_rustls::server::TlsStream<Tracked>;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = if self.gate {
                let Some(listener) = self.tcp.take() else {
                    return std::future::pending().await;
                };
                let accepted = listener.accept().await.expect("single loopback accept");
                // Physically close the listener before the caller barrier. A failed
                // original socket cannot be healed by tonic reconnecting later.
                drop(listener);
                accepted
            } else {
                self.tcp
                    .as_ref()
                    .expect("ordinary listener retained")
                    .accept()
                    .await
                    .expect("loopback accept")
            };
            self.evidence.accepted.fetch_add(1, Ordering::SeqCst);
            let tcp = Tracked(tcp, self.evidence.clone());
            if let Some(tx) = self.accepted.take() {
                let _ = tx.send(());
            }
            while self.gate && !self.evidence.start.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            match timeout(Duration::from_secs(2), self.tls.accept(tcp)).await {
                Ok(Ok(tls)) => {
                    self.evidence.tls.fetch_add(1, Ordering::SeqCst);
                    return (tls, addr);
                }
                Err(_) => {
                    self.evidence.timed_out.fetch_add(1, Ordering::SeqCst);
                }
                Ok(Err(_)) => {
                    self.evidence.tls_errors.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.addr)
    }
}
struct Server {
    single_accept: bool,
    addr: std::net::SocketAddr,
    pem: Vec<u8>,
    evidence: Arc<Evidence>,
    accepted: oneshot::Receiver<()>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}
async fn server(gate: bool) -> Server {
    let (pem, cert, key) = ephemeral_tls::identity();
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let evidence = Arc::new(Evidence::default());
    if let Ok(mut current) = CURRENT_COUNTS.lock() {
        *current = Some(evidence.clone());
    }
    let counts = evidence.clone();
    let app = axum::Router::new()
        .route(
            "/probe",
            axum::routing::post(|| async {
                (
                    [("content-type", "application/grpc"), ("grpc-status", "0")],
                    vec![0u8; 5],
                )
            }),
        )
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let counts = counts.clone();
                async move {
                    // Count every HTTP request, including unmatched routes, not only our probe.
                    counts.rpc.fetch_add(1, Ordering::SeqCst);
                    next.run(request).await
                }
            },
        ));
    let (tx, accepted) = oneshot::channel();
    let (stop, rx) = oneshot::channel();
    let listener = Listener {
        tcp: Some(tcp),
        addr,
        tls: TlsAcceptor::from(Arc::new(config)),
        evidence: evidence.clone(),
        accepted: Some(tx),
        gate,
    };
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    Server {
        single_accept: gate,
        addr,
        pem,
        evidence,
        accepted,
        stop,
        task,
    }
}
fn endpoint(s: &Server, wrong_name: bool) -> Endpoint {
    Endpoint::from_shared(format!("https://{}", s.addr))
        .unwrap()
        .connect_timeout(LIMIT)
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(s.pem.clone()))
                .domain_name(if wrong_name {
                    "wrong.invalid"
                } else {
                    "wholepact-proxy-test.invalid"
                }),
        )
        .unwrap()
}
async fn until(mut predicate: impl FnMut() -> bool) {
    timeout(LIMIT, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("bounded observation");
}
async fn cleanup(s: Server) {
    observe(5, "unobserved");
    checking(11);
    until(|| {
        s.evidence.closed.load(Ordering::SeqCst) == s.evidence.accepted.load(Ordering::SeqCst)
    })
    .await;
    let _ = s.stop.send(());
    checking(12);
    timeout(LIMIT, s.task)
        .await
        .expect("server shutdown deadline")
        .expect("server joined");
}
async fn route(s: &Server, tunnel: bool) -> (ProxyRoute, Option<JoinHandle<()>>) {
    if !tunnel {
        return (ProxyRoute::Direct, None);
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let destination = s.addr;
    let single_accept = s.single_accept;
    let counts = s.evidence.clone();
    let task = tokio::spawn(async move {
        let mut listener = Some(listener);
        let (mut client, _) = listener.as_ref().unwrap().accept().await.unwrap();
        if single_accept {
            drop(listener.take());
        }
        let mut header = Vec::new();
        timeout(LIMIT, async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(client.read_u8().await.unwrap());
                assert!(header.len() < 8192);
            }
        })
        .await
        .unwrap();
        assert!(header.starts_with(b"CONNECT "));
        counts.proxy_headers.fetch_add(1, Ordering::SeqCst);
        let mut target = TcpStream::connect(destination).await.unwrap();
        counts.proxy_target_connected.fetch_add(1, Ordering::SeqCst);
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let copied = timeout(
            LIMIT,
            tokio::io::copy_bidirectional(&mut client, &mut target),
        )
        .await;
        counts.proxy_copy_outcome.store(
            match &copied {
                Ok(Ok(_)) => 1,
                Ok(Err(_)) => 2,
                Err(_) => 3,
            },
            Ordering::SeqCst,
        );
        let _ = copied.expect("proxy ownership deadline");
        counts.proxy_copy_finished.fetch_add(1, Ordering::SeqCst);
    });
    (
        ProxyRoute::HttpTunnel(format!("http://{addr}").parse().unwrap()),
        Some(task),
    )
}
#[derive(Clone, PartialEq, prost::Message)]
struct Empty {}
async fn probe_until(channel: Channel, deadline: Instant) -> usize {
    let attempted = async {
        if Instant::now() >= deadline {
            return 4;
        }
        let mut grpc = tonic::client::Grpc::new(channel);
        checking(6);
        if grpc.ready().await.is_err() {
            return 2;
        }
        if Instant::now() >= deadline {
            return 4;
        }
        checking(7);
        let response: Result<tonic::Response<Empty>, tonic::Status> = grpc
            .unary(
                tonic::Request::new(Empty {}),
                tonic::codegen::http::uri::PathAndQuery::from_static("/probe"),
                tonic_prost::ProstCodec::default(),
            )
            .await;
        if Instant::now() >= deadline {
            return 4;
        }
        if response.is_ok() {
            1
        } else {
            3
        }
    };
    let result = tokio::time::timeout_at(deadline, attempted)
        .await
        .unwrap_or(4);
    let result = if Instant::now() >= deadline {
        4
    } else {
        result
    };
    PROBE_OUTCOME.store(result, Ordering::SeqCst);
    observe(7, "unobserved");
    result
}
async fn scheduling(tunnel: bool, driven: bool) {
    begin_case(match (tunnel, driven) {
        (false, false) => 1,
        (false, true) => 2,
        (true, false) => 3,
        (true, true) => 4,
    });
    let mut s = server(true).await;
    let ep = endpoint(&s, false);
    let (route, proxy) = route(&s, tunnel).await;
    let counts = s.evidence.clone();
    let accepted = std::mem::replace(&mut s.accepted, oneshot::channel().1);
    // This borrowed Rc is intentionally !Send. It never enters the connect task.
    let owner = Rc::new(Cell::new(0));
    let borrowed = &owner;
    let deadline = Instant::now() + LIMIT;
    let blocker = async {
        checking(18);
        tokio::time::timeout_at(deadline, accepted)
            .await
            .unwrap()
            .unwrap();
        counts.start.store(true, Ordering::SeqCst);
        borrowed.set(1);
        std::thread::sleep(Duration::from_millis(2500));
        observe(1, "unobserved");
        checking(1);
        assert_eq!(counts.rpc.load(Ordering::SeqCst), 0);
        checking(26);
        assert_eq!(counts.accepted.load(Ordering::SeqCst), 1);
        // These observations happen before join can repoll the inline connector.
        if driven {
            checking(4);
            assert_eq!(counts.tls.load(Ordering::SeqCst), 1);
            checking(5);
            assert_eq!(counts.timed_out.load(Ordering::SeqCst), 0);
        } else {
            checking(17);
            assert_eq!(counts.tls.load(Ordering::SeqCst), 0);
            checking(10);
            assert_eq!(counts.timed_out.load(Ordering::SeqCst), 1);
        }
        borrowed.set(2);
    };
    let connect = async {
        if driven {
            connect_until(route, ep, deadline).await
        } else {
            tokio::time::timeout_at(deadline, route.connect(&ep))
                .await
                .unwrap_or(Err(crate::ChainError::Timeout))
        }
    };
    let (result, ()) = tokio::join!(connect, blocker);
    observe(2, connect_outcome(&result));
    checking(2);
    assert_eq!(owner.get(), 2);
    if driven {
        checking(3);
        let channel = result.expect("independent initial TLS must progress");
        checking(4);
        assert_eq!(s.evidence.tls.load(Ordering::SeqCst), 1);
        checking(5);
        assert_eq!(s.evidence.timed_out.load(Ordering::SeqCst), 0);
        observe(6, "success");
        let probe_result = probe_until(channel, deadline).await;
        checking(25);
        assert_eq!(probe_result, 1);
        checking(8);
        assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 1);
    } else {
        if let Ok(channel) = result {
            // A tonic Channel handle is not evidence of a usable HTTP/2 socket.
            // Exercise the actual service under the original remaining budget.
            observe(6, "unobserved");
            let probe_result = probe_until(channel, deadline).await;
            checking(24);
            assert!(matches!(probe_result, 2 | 3 | 4));
        }
        checking(10);
        assert_eq!(s.evidence.timed_out.load(Ordering::SeqCst), 1);
        checking(1);
        assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 0);
    }
    checking(26);
    assert_eq!(s.evidence.accepted.load(Ordering::SeqCst), 1);
    if tunnel {
        assert_eq!(s.evidence.proxy_headers.load(Ordering::SeqCst), 1);
        assert_eq!(s.evidence.proxy_target_connected.load(Ordering::SeqCst), 1);
    }
    observe(3, "unobserved");
    cleanup(s).await;
    if let Some(proxy) = proxy {
        checking(13);
        timeout(LIMIT, proxy).await.unwrap().unwrap();
    }
    observe(4, "unobserved");
}
async fn poll_once<F: Future>(future: Pin<&mut F>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        checking(14);
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "initial connect unexpectedly complete"
        );
        Poll::Ready(())
    })
    .await;
}
async fn cancel_before_poll() {
    begin_case(5);
    let s = server(false).await;
    let observation = Arc::new(TestConnectObservation::default());
    let f = connect_until_observed(
        ProxyRoute::Direct,
        endpoint(&s, false),
        Instant::now() + LIMIT,
        observation.clone(),
    );
    drop(f);
    tokio::task::yield_now().await;
    assert!(!observation.started.load(Ordering::SeqCst));
    assert!(!observation.finished.load(Ordering::SeqCst));
    assert_eq!(s.evidence.accepted.load(Ordering::SeqCst), 0);
    cleanup(s).await;
    observe(4, "unobserved");
    begin_case(6);
    let s = server(false).await;
    assert!(matches!(
        connect_until(ProxyRoute::Direct, endpoint(&s, false), Instant::now()).await,
        Err(crate::ChainError::Timeout)
    ));
    assert_eq!(s.evidence.accepted.load(Ordering::SeqCst), 0);
    cleanup(s).await;
    observe(4, "unobserved");
}
async fn stalled(deadline_case: bool) {
    begin_case(if deadline_case { 8 } else { 7 });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut started = Some(tx);
        let mut buf = [0; 4096];
        let mut received = 0;
        loop {
            let n = timeout(LIMIT, stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            received += n;
            if let Some(tx) = started.take() {
                let _ = tx.send(());
            }
        }
        received
    });
    let (pem, _, _) = ephemeral_tls::identity();
    let ep = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(pem))
                .domain_name("wholepact-proxy-test.invalid"),
        )
        .unwrap();
    let deadline = Instant::now()
        + if deadline_case {
            Duration::from_millis(300)
        } else {
            LIMIT
        };
    let observation = Arc::new(TestConnectObservation::default());
    let mut f = Box::pin(connect_until_observed(
        ProxyRoute::Direct,
        ep,
        deadline,
        observation.clone(),
    ));
    poll_once(f.as_mut()).await;
    timeout(LIMIT, rx).await.unwrap().unwrap();
    if deadline_case {
        checking(22);
        assert!(matches!(f.as_mut().await, Err(crate::ChainError::Timeout)));
        assert!(Instant::now() >= deadline);
    }
    drop(f);
    checking(19);
    until(|| observation.finished.load(Ordering::SeqCst)).await;
    checking(20);
    assert!(observation.started.load(Ordering::SeqCst));
    assert!(!observation.succeeded.load(Ordering::SeqCst));
    checking(23);
    timeout(LIMIT, task)
        .await
        .expect("cancelled socket close deadline")
        .expect("stalled server joined");
    observe(4, "unobserved");
}
async fn drop_unconsumed(deadline_race: bool) {
    begin_case(if deadline_race { 10 } else { 9 });
    let s = server(false).await;
    let observation = Arc::new(TestConnectObservation::default());
    let deadline = Instant::now()
        + if deadline_race {
            Duration::from_secs(3)
        } else {
            LIMIT
        };
    let mut f = Box::pin(connect_until_observed(
        ProxyRoute::Direct,
        endpoint(&s, false),
        deadline,
        observation.clone(),
    ));
    poll_once(f.as_mut()).await;
    checking(19);
    until(|| observation.finished.load(Ordering::SeqCst)).await;
    checking(20);
    assert!(observation.started.load(Ordering::SeqCst));
    checking(21);
    assert!(observation.succeeded.load(Ordering::SeqCst));
    assert_eq!(s.evidence.tls.load(Ordering::SeqCst), 1);
    checking(1);
    assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 0);
    // The actual child returned a Channel, but this caller has never polled its result.
    if deadline_race {
        tokio::time::sleep_until(deadline).await;
        checking(22);
        assert!(matches!(f.as_mut().await, Err(crate::ChainError::Timeout)));
    }
    drop(f);
    cleanup(s).await;
    observe(4, "unobserved");
}
async fn refusal(tunnel: bool) {
    begin_case(if tunnel { 12 } else { 11 });
    let s = server(false).await;
    let (route, proxy) = route(&s, tunnel).await;
    let result = connect_until(route, endpoint(&s, true), Instant::now() + LIMIT).await;
    observe(2, connect_outcome(&result));
    checking(15);
    assert!(matches!(
        result,
        Err(crate::ChainError::TransportUnavailable)
    ));
    checking(16);
    assert_eq!(s.evidence.accepted.load(Ordering::SeqCst), 1);
    checking(17);
    assert_eq!(s.evidence.tls.load(Ordering::SeqCst), 0);
    assert_eq!(s.evidence.timed_out.load(Ordering::SeqCst), 0);
    checking(1);
    assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 0);
    observe(3, "unobserved");
    cleanup(s).await;
    if let Some(proxy) = proxy {
        checking(13);
        timeout(LIMIT, proxy).await.unwrap().unwrap();
    }
    observe(4, "unobserved");
}
#[test]
#[ignore = "CI-only actual loopback TLS scheduling and cancellation qualification"]
fn independent_connect_preserves_tls_deadline_and_cancellation() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(record_panic));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run_mechanism));
    // Restore outside unwinding; set_hook is forbidden on a panicking thread.
    std::panic::set_hook(original_hook);
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
fn run_mechanism() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        scheduling(false, false).await;
        scheduling(false, true).await;
        scheduling(true, false).await;
        scheduling(true, true).await;
        cancel_before_poll().await;
        stalled(false).await;
        drop_unconsumed(false).await;
        drop_unconsumed(true).await;
        stalled(true).await;
        refusal(false).await;
        refusal(true).await;
    });
    runtime.shutdown_timeout(LIMIT);
    println!("CI_SYNTHETIC_CONNECT_DRIVER {{\"schema\":1,\"cases\":{{\"direct_scheduling\":true,\"http_connect_scheduling\":true,\"cancel_before_poll\":true,\"cancel_during_tls\":true,\"drop_unconsumed_connected_result\":true,\"original_deadline\":true,\"tls_hostname_refusal\":true}},\"cleanup_verified\":true,\"current_thread_guarantee\":false,\"public_chain_verified\":false}}");
}
