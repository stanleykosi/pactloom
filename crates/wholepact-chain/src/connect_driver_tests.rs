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
    closed: AtomicUsize,
    rpc: AtomicUsize,
    start: AtomicBool,
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
    tcp: TcpListener,
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
            let (tcp, addr) = self.tcp.accept().await.expect("loopback accept");
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
                Ok(Err(_)) => {}
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}
struct Server {
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
        tcp,
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
    until(|| {
        s.evidence.closed.load(Ordering::SeqCst) == s.evidence.accepted.load(Ordering::SeqCst)
    })
    .await;
    let _ = s.stop.send(());
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
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
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
        let mut target = TcpStream::connect(destination).await.unwrap();
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = timeout(
            LIMIT,
            tokio::io::copy_bidirectional(&mut client, &mut target),
        )
        .await
        .expect("proxy ownership deadline");
    });
    (
        ProxyRoute::HttpTunnel(format!("http://{addr}").parse().unwrap()),
        Some(task),
    )
}
#[derive(Clone, PartialEq, prost::Message)]
struct Empty {}
async fn probe(channel: Channel) {
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.expect("channel ready");
    let response: tonic::Response<Empty> = grpc
        .unary(
            tonic::Request::new(Empty {}),
            tonic::codegen::http::uri::PathAndQuery::from_static("/probe"),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .expect("real h2 RPC after caller resumes");
    drop(response);
}
async fn scheduling(tunnel: bool, driven: bool) {
    let mut s = server(true).await;
    let ep = endpoint(&s, false);
    let (route, proxy) = route(&s, tunnel).await;
    let counts = s.evidence.clone();
    let accepted = std::mem::replace(&mut s.accepted, oneshot::channel().1);
    // This borrowed Rc is intentionally !Send. It never enters the connect task.
    let owner = Rc::new(Cell::new(0));
    let borrowed = &owner;
    let blocker = async {
        timeout(LIMIT, accepted).await.unwrap().unwrap();
        counts.start.store(true, Ordering::SeqCst);
        borrowed.set(1);
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(counts.rpc.load(Ordering::SeqCst), 0);
        borrowed.set(2);
    };
    let connect = async {
        if driven {
            connect_until(route, ep, Instant::now() + LIMIT).await
        } else {
            route.connect(&ep).await
        }
    };
    let (result, ()) = tokio::join!(connect, blocker);
    assert_eq!(owner.get(), 2);
    if driven {
        let channel = result.expect("independent initial TLS must progress");
        assert_eq!(s.evidence.tls.load(Ordering::SeqCst), 1);
        assert_eq!(s.evidence.timed_out.load(Ordering::SeqCst), 0);
        probe(channel).await;
        assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 1);
    } else {
        assert!(result.is_err());
        assert_eq!(s.evidence.timed_out.load(Ordering::SeqCst), 1);
        assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 0);
    }
    cleanup(s).await;
    if let Some(proxy) = proxy {
        timeout(LIMIT, proxy).await.unwrap().unwrap();
    }
}
async fn poll_once<F: Future>(future: Pin<&mut F>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "initial connect unexpectedly complete"
        );
        Poll::Ready(())
    })
    .await;
}
async fn cancel_before_poll() {
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
    let s = server(false).await;
    assert!(matches!(
        connect_until(ProxyRoute::Direct, endpoint(&s, false), Instant::now()).await,
        Err(crate::ChainError::Timeout)
    ));
    assert_eq!(s.evidence.accepted.load(Ordering::SeqCst), 0);
    cleanup(s).await;
}
async fn stalled(deadline_case: bool) {
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
        assert!(matches!(f.as_mut().await, Err(crate::ChainError::Timeout)));
        assert!(Instant::now() >= deadline);
    }
    drop(f);
    until(|| observation.finished.load(Ordering::SeqCst)).await;
    assert!(observation.started.load(Ordering::SeqCst));
    assert!(!observation.succeeded.load(Ordering::SeqCst));
    timeout(LIMIT, task)
        .await
        .expect("cancelled socket close deadline")
        .expect("stalled server joined");
}
async fn drop_unconsumed(deadline_race: bool) {
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
    until(|| observation.finished.load(Ordering::SeqCst)).await;
    assert!(observation.started.load(Ordering::SeqCst));
    assert!(observation.succeeded.load(Ordering::SeqCst));
    assert_eq!(s.evidence.tls.load(Ordering::SeqCst), 1);
    assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 0);
    // The actual child returned a Channel, but this caller has never polled its result.
    if deadline_race {
        tokio::time::sleep_until(deadline).await;
        assert!(matches!(f.as_mut().await, Err(crate::ChainError::Timeout)));
    }
    drop(f);
    cleanup(s).await;
}
async fn refusal(tunnel: bool) {
    let s = server(false).await;
    let (route, proxy) = route(&s, tunnel).await;
    assert!(matches!(
        connect_until(route, endpoint(&s, true), Instant::now() + LIMIT).await,
        Err(crate::ChainError::TransportUnavailable)
    ));
    assert_eq!(s.evidence.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(s.evidence.tls.load(Ordering::SeqCst), 0);
    assert_eq!(s.evidence.timed_out.load(Ordering::SeqCst), 0);
    assert_eq!(s.evidence.rpc.load(Ordering::SeqCst), 0);
    cleanup(s).await;
    if let Some(proxy) = proxy {
        timeout(LIMIT, proxy).await.unwrap().unwrap();
    }
}
#[test]
#[ignore = "CI-only actual loopback TLS scheduling and cancellation qualification"]
fn independent_connect_preserves_tls_deadline_and_cancellation() {
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
