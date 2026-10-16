// Historical public-testnet RPC bytes are offline parsing fixtures, not wallet records,
// live chain observations, independent consensus evidence or payment proof.
use super::*;
use prost::Message;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters, TEST_NETWORK};

pub(super) fn fixture() -> (
    BackendIdentity,
    NetworkPolicy,
    rpc::LightdInfo,
    rpc::BlockId,
    rpc::CompactBlock,
) {
    (
        BackendIdentity {
            source_id: "local-fixture".into(),
            endpoint: "https://example.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus",
        },
        NetworkPolicy::default(),
        rpc::LightdInfo {
            version: "fixture".into(),
            chain_name: "test".into(),
            sapling_activation_height: 280_000,
            consensus_branch_id: "77190ad9".into(),
            block_height: 4_498_144,
            estimated_height: 4_498_145,
            ..Default::default()
        },
        rpc::BlockId {
            height: 4_498_144,
            hash: vec![1; 32],
        },
        rpc::CompactBlock {
            height: 4_498_144,
            hash: vec![1; 32],
            prev_hash: vec![2; 32],
            time: 1_800_000_000,
            vtx: vec![],
        },
    )
}
#[test]
fn profile_matches_pinned_upstream_testnet_activation() {
    assert_eq!(u32::from(BranchId::Nu7), NU7_BRANCH_ID);
    assert_eq!(
        u32::from(TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap()) as u64,
        NU7_ACTIVATION_HEIGHT
    );
}
#[test]
fn fresh_single_provider_context_is_never_signing_authority() {
    let (id, p, i, t, b) = fixture();
    let c = validate_context(&id, &p, &i, &t, &b, &t, 1_800_000_010, 1_800_000_020).unwrap();
    assert!(c.check_fresh_at(1_800_000_040).is_ok());
    assert_eq!(c.check_fresh_at(1_800_000_071), Err(ChainError::StaleChain));
    assert_eq!(c.check_fresh_at(1_800_000_019), Err(ChainError::StaleChain));
    assert!(!c.authorizes_signing());
    assert!(!c.independently_consensus_verified());
}
#[test]
fn mainnet_wrong_branch_and_lag_reject() {
    let (id, p, mut i, t, b) = fixture();
    i.chain_name = "main".into();
    assert_eq!(validate_info(&i), Err(ChainError::WrongNetwork));
    i.chain_name = "test".into();
    i.consensus_branch_id = "37a5165b".into();
    assert_eq!(validate_info(&i), Err(ChainError::WrongBranch));
    i.consensus_branch_id = "77190ad9".into();
    i.estimated_height += 5;
    assert!(matches!(
        validate_context(&id, &p, &i, &t, &b, &t, 1_800_000_010, 1_800_000_020),
        Err(ChainError::StaleChain)
    ));
}
#[test]
fn changed_tip_stale_block_and_clock_skew_reject() {
    let (id, p, i, t, mut b) = fixture();
    let mut changed = t.clone();
    changed.hash[0] = 5;
    assert!(matches!(
        validate_context(&id, &p, &i, &t, &b, &changed, 1_800_000_010, 1_800_000_020),
        Err(ChainError::ContradictoryChain)
    ));
    b.time -= 2000;
    assert!(matches!(
        validate_context(&id, &p, &i, &t, &b, &t, 1_800_000_010, 1_800_000_020),
        Err(ChainError::StaleChain)
    ));
    b.time = 1_800_000_100;
    assert!(matches!(
        validate_context(&id, &p, &i, &t, &b, &t, 1_800_000_010, 1_800_000_020),
        Err(ChainError::StaleChain)
    ));
}
#[test]
fn contradictory_sources_do_not_average_into_confidence() {
    let (id, p, i, t, b) = fixture();
    let c = validate_context(&id, &p, &i, &t, &b, &t, 1_800_000_010, 1_800_000_020).unwrap();
    let mut other = c.clone();
    other.tip.hash = "11".repeat(32);
    assert_eq!(
        compare_contexts(&c, &other, 1_800_000_030),
        Err(ChainError::ContradictoryChain)
    );
}
#[test]
fn malformed_or_missing_tree_is_not_an_empty_pool() {
    assert_eq!(
        parse_ironwood_tree(""),
        Err(ChainError::UnsupportedCapability)
    );
    assert!(parse_ironwood_tree("000000").is_ok()); // explicitly serialized empty tree
    let impossible = format!("0001{}00", "00".repeat(32));
    assert_eq!(
        parse_ironwood_tree(&impossible),
        Err(ChainError::MalformedEvidence)
    );
    assert_eq!(
        parse_ironwood_tree(&"00".repeat(2000)),
        Err(ChainError::ResourceLimit)
    );
    for bad in ["0000fdffffffff", "00000000", "01", "zz", "000020"] {
        assert!(parse_ironwood_tree(bad).is_err(), "{bad}");
    }
}
#[test]
fn protobuf_tags_and_hash_display_order_are_explicit() {
    let t = rpc::TreeState {
        ironwood_tree: "000000".into(),
        ..Default::default()
    };
    assert_eq!(t.encode_to_vec()[0], (7 << 3) | 2);
    let hash: Vec<u8> = (0..32).collect();
    assert_eq!(
        block_identity(1, &hash).unwrap().hash,
        hex::encode(hash.iter().rev().copied().collect::<Vec<_>>())
    );
    assert!(block_identity(1, &[0; 32]).is_err());
}
#[test]
fn constructor_is_offline_and_rejects_unsafe_configuration() {
    for endpoint in [
        "http://example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid/?token=x",
        "https://example.invalid/path",
    ] {
        assert!(ChainAdapter::testnet("fixture", endpoint, NetworkPolicy::default()).is_err());
    }
    assert!(
        ChainAdapter::testnet(
            "fixture",
            "https://example.invalid",
            NetworkPolicy::default()
        )
        .is_ok()
    );
    let p = NetworkPolicy {
        retries: 3,
        ..Default::default()
    };
    assert!(ChainAdapter::testnet("fixture", "https://example.invalid", p).is_err());
}

#[tokio::test]
async fn real_tonic_wire_handles_local_fake_not_found_and_bounded_timeout() {
    use axum::{Router, http::StatusCode, routing::post};
    let app = Router::new()
        .route(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
            post(|| async {
                let (_, _, info, _, _) = fixture();
                let mut frame = vec![0];
                let bytes = info.encode_to_vec();
                frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                frame.extend_from_slice(&bytes);
                (
                    [("content-type", "application/grpc"), ("grpc-status", "0")],
                    frame,
                )
            }),
        )
        .route(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction",
            post(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "application/grpc"), ("grpc-status", "5")],
                    Vec::<u8>::new(),
                )
            }),
        )
        .route(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                StatusCode::OK
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async {
        axum::serve(listener, app).await.unwrap();
    });
    let p = NetworkPolicy {
        request_timeout: Duration::from_millis(50),
        retries: 1,
        retry_delay: Duration::from_millis(1),
        ..Default::default()
    };
    let rpc = rpc::Rpc::for_test(&format!("http://{address}"), p);
    assert_eq!(rpc.info().await.unwrap().consensus_branch_id, "77190ad9");
    assert_eq!(
        rpc.transaction([1; 32]).await.unwrap_err(),
        ChainError::NotObserved
    );
    let start = std::time::Instant::now();
    assert!(matches!(
        rpc.latest().await.unwrap_err(),
        ChainError::Timeout | ChainError::ObservationInterrupted
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    server.abort();
}

#[test]
fn captured_public_testnet_evidence_decodes_but_is_not_current_authority() {
    fn frame<M: Message + Default>(bytes: &[u8]) -> M {
        assert_eq!(bytes[0], 0);
        assert_eq!(
            u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize,
            bytes.len() - 5
        );
        M::decode(&bytes[5..]).unwrap()
    }
    let info: rpc::LightdInfo = frame(include_bytes!("../evidence/GetLightdInfo.response.grpc"));
    let first: rpc::BlockId = frame(include_bytes!("../evidence/GetLatestBlock.response.grpc"));
    let last: rpc::BlockId = frame(include_bytes!(
        "../evidence/GetLatestBlock-after.response.grpc"
    ));
    let block: rpc::CompactBlock = frame(include_bytes!("../evidence/GetBlock.response.grpc"));
    let tree: rpc::TreeState = frame(include_bytes!("../evidence/GetTreeState.response.grpc"));
    let (mut identity, policy, _, _, _) = fixture();
    identity.source_id = "testnet-zec-rocks".into();
    identity.endpoint = "https://testnet.zec.rocks:443".into();
    // Exact historical receipt times; these are NOT the current wall clock.
    let start = 1_791_903_104;
    let finish = 1_791_903_130;
    let context = validate_context(
        &identity, &policy, &info, &first, &block, &last, start, finish,
    )
    .unwrap();
    assert_eq!(context.tip.height, 4_498_249);
    assert_eq!(tree.hash, context.tip.hash);
    assert_eq!(tree.height, context.tip.height);
    assert_eq!(tree.network, "test");
    assert_eq!(tree.time, block.time);
    let (root, count, digest) = parse_ironwood_tree(&tree.ironwood_tree).unwrap();
    assert!(count > 0);
    println!(
        "Captured provider-only Ironwood root={}, leaf_count={}, encoding_sha256={}",
        hex::encode(root),
        count,
        digest
    );
    assert!(!context.authorizes_signing());
    assert_eq!(
        context.check_fresh_at(start + 61),
        Err(ChainError::StaleChain)
    );
}

#[tokio::test]
async fn real_adapter_local_fake_observes_pending_inclusion_reorg_and_anchor() {
    use axum::{
        Router,
        body::Bytes,
        http::{StatusCode, Uri},
        routing::post,
    };
    use std::sync::{Arc, Mutex};
    use zcash_primitives::transaction::{Authorized, TransactionData};
    // A syntactically parseable, empty synthetic transaction. It cannot pay anyone.
    let tx = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu7,
        0,
        4_498_200u32.into(),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    let txid = tx.txid();
    let mut bytes = vec![];
    tx.write(&mut bytes).unwrap();
    assert!(verify_transaction_id(&bytes, txid).is_ok());
    assert_eq!(
        verify_transaction_id(&bytes, TxId::from_bytes([3; 32])),
        Err(ChainError::ContradictoryChain)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        verify_transaction_id(&trailing, txid),
        Err(ChainError::MalformedEvidence)
    );
    let mined = Arc::new(Mutex::new(0u64));
    let state = mined.clone();
    let app = Router::new().fallback(post(move |uri: Uri, request: Bytes| {
        let state = state.clone();
        let bytes = bytes.clone();
        async move {
            let (_, _, mut info, tip, mut block) = fixture();
            block.time = now().unwrap() as u32;
            info.estimated_height = info.block_height;
            let mut response = vec![];
            match uri.path().rsplit('/').next().unwrap() {
                "GetLightdInfo" => response = info.encode_to_vec(),
                "GetLatestBlock" => response = tip.encode_to_vec(),
                "GetBlock" => {
                    let requested = rpc::BlockId::decode(&request[5..]).unwrap();
                    block.height = requested.height;
                    block.vtx = vec![rpc::CompactTx {
                        index: 1,
                        txid: txid.as_ref().to_vec(),
                    }];
                    response = block.encode_to_vec();
                }
                "GetTreeState" => {
                    response = rpc::TreeState {
                        network: "test".into(),
                        height: tip.height,
                        hash: block_identity(tip.height, &tip.hash).unwrap().hash,
                        time: block.time,
                        ironwood_tree: "000000".into(),
                    }
                    .encode_to_vec()
                }
                "GetTransaction" => {
                    let query = rpc::TxFilter::decode(&request[5..]).unwrap();
                    assert_eq!(query.hash, txid.as_ref());
                    response = rpc::RawTransaction {
                        data: bytes,
                        height: *state.lock().unwrap(),
                    }
                    .encode_to_vec();
                }
                _ => {}
            }
            let mut frame = vec![0];
            frame.extend_from_slice(&(response.len() as u32).to_be_bytes());
            frame.extend(response);
            (
                StatusCode::OK,
                [("content-type", "application/grpc"), ("grpc-status", "0")],
                frame,
            )
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async {
        axum::serve(listener, app).await.unwrap();
    });
    let (identity, policy, _, _, _) = fixture();
    let adapter = ChainAdapter {
        identity,
        policy,
        rpc: rpc::Rpc::for_test(&format!("http://{address}"), policy),
    };
    let pending = adapter
        .observe_transaction(&txid.to_string())
        .await
        .unwrap();
    assert_eq!(pending.status, TransactionStatus::PendingObserved);
    assert!(!pending.clears_authorization_exposure);
    assert!(
        pending
            .context
            .rpc_cache_observations()
            .iter()
            .any(|m| m.method == "GetTransaction")
    );
    assert_eq!(
        pending
            .context
            .rpc_cache_observations()
            .iter()
            .filter(|m| m.method == "GetBlock")
            .count(),
        2
    );
    *mined.lock().unwrap() = 4_498_140;
    let included = adapter
        .observe_transaction(&txid.to_string())
        .await
        .unwrap();
    assert!(matches!(
        included.status,
        TransactionStatus::Included {
            confirmations: 5,
            ..
        }
    ));
    *mined.lock().unwrap() = u64::MAX;
    assert_eq!(
        adapter
            .observe_transaction(&txid.to_string())
            .await
            .unwrap()
            .status,
        TransactionStatus::Reorganized
    );
    *mined.lock().unwrap() = 4_498_145;
    assert!(matches!(
        adapter.observe_transaction(&txid.to_string()).await,
        Err(ChainError::ContradictoryChain)
    ));
    let anchor = adapter
        .ironwood_anchor(&pending.context, pending.context.tip.height)
        .await
        .unwrap();
    assert_eq!(anchor.leaf_count, 0);
    assert!(!anchor.proves_note_membership);
    assert!(!anchor.proves_unspentness);
    server.abort();
}

#[test]
fn cache_age_can_only_shorten_local_observation_lifetime() {
    let (id, p, i, t, b) = fixture();
    let mut c = validate_context(&id, &p, &i, &t, &b, &t, 1_800_000_010, 1_800_000_020).unwrap();
    let metadata = RpcCacheObservation {
        method: "GetLatestBlock",
        cache_status: CacheStatus::Hit,
        reported_age_seconds: Some(20),
        malformed_age: false,
    };
    apply_cache_observations(&mut c, vec![metadata.clone()]).unwrap();
    assert_eq!(c.valid_until_unix_seconds, 1_800_000_050);
    assert!(!c.provider_refresh_time_verified);
    let mut stale = metadata;
    stale.reported_age_seconds = Some(100);
    assert_eq!(
        apply_cache_observations(&mut c, vec![stale]),
        Err(ChainError::StaleChain)
    );
}

#[path = "tests/ephemeral_tls.rs"]
mod ephemeral_tls;

mod proxy_integration {
    use super::*;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{ServerConfig, crypto::ring},
    };

    struct TlsListener {
        listener: TcpListener,
        acceptor: TlsAcceptor,
    }
    impl axum::serve::Listener for TlsListener {
        type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
        type Addr = std::net::SocketAddr;
        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                let (stream, address) = self.listener.accept().await.unwrap();
                if let Ok(stream) = self.acceptor.accept(stream).await {
                    return (stream, address);
                }
            }
        }
        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.listener.local_addr()
        }
    }
    fn policy() -> NetworkPolicy {
        NetworkPolicy {
            request_timeout: Duration::from_secs(2),
            retries: 0,
            ..Default::default()
        }
    }
    async fn tls_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, Vec<u8>) {
        let (certificate_pem, certificate, key) = ephemeral_tls::identity();
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key.into())
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
            axum::routing::post(|| async {
                let (_, _, info, _, _) = fixture();
                let data = info.encode_to_vec();
                let mut frame = vec![0];
                frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
                frame.extend_from_slice(&data);
                (
                    [
                        ("content-type", "application/grpc"),
                        ("grpc-status", "0"),
                        ("x-cache", "hit"),
                        ("age", "12"),
                        ("x-private-canary", "do-not-retain"),
                    ],
                    frame,
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(
                TlsListener {
                    listener,
                    acceptor: TlsAcceptor::from(Arc::new(config)),
                },
                app,
            )
            .await
            .unwrap();
        });
        (address, server, certificate_pem)
    }
    async fn proxy(
        destination: Option<std::net::SocketAddr>,
        response: &'static [u8],
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(client.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            client.write_all(response).await.unwrap();
            if let Some(destination) = destination {
                let mut server = tokio::net::TcpStream::connect(destination).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            }
            request
        });
        (format!("http://{address}"), task)
    }
    #[tokio::test]
    async fn native_tonic_uses_connect_then_verified_tls_and_keeps_cache_evidence() {
        let (address, server, certificate_pem) = tls_server().await;
        let (proxy_url, tunnel) = proxy(
            Some(address),
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        )
        .await;
        let client = rpc::Rpc::for_proxy_test(
            "https://wholepact-proxy-test.invalid:443",
            &proxy_url,
            policy(),
            Some(certificate_pem.as_slice()),
        );
        let info = client.info().await.unwrap();
        assert_eq!(info.consensus_branch_id, "77190ad9");
        assert_eq!(info.cache.cache_status, CacheStatus::Hit);
        assert_eq!(info.cache.reported_age_seconds, Some(12));
        let serialized = serde_json::to_string(&info.cache).unwrap();
        assert!(!serialized.contains("do-not-retain"));
        let request = tokio::time::timeout(Duration::from_secs(2), tunnel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request, b"CONNECT wholepact-proxy-test.invalid:443 HTTP/1.1\r\nHost: wholepact-proxy-test.invalid:443\r\n\r\n");
        server.abort();
    }
    #[tokio::test]
    async fn proxy_tunnel_does_not_disable_certificate_or_hostname_verification() {
        let (address, server, certificate_pem) = tls_server().await;
        for (endpoint, root) in [
            ("https://wholepact-proxy-test.invalid:443", None),
            (
                "https://different-name.invalid:443",
                Some(certificate_pem.as_slice()),
            ),
        ] {
            let (proxy_url, tunnel) = proxy(
                Some(address),
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
            )
            .await;
            let client = rpc::Rpc::for_proxy_test(endpoint, &proxy_url, policy(), root);
            assert_eq!(
                client.info().await.unwrap_err(),
                ChainError::TransportUnavailable
            );
            tunnel.await.unwrap();
        }
        server.abort();
    }
    #[tokio::test]
    async fn proxy_denial_and_oversized_headers_are_bounded_and_never_fall_back() {
        let oversized: &'static [u8] = Box::leak(
            format!("HTTP/1.1 200 OK\r\nX-Fill: {}", "a".repeat(9000))
                .into_bytes()
                .into_boxed_slice(),
        );
        for response in [
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 14\r\n\r\nprivate-canary".as_slice(),
            oversized,
        ] {
            let (proxy_url, proxy) = proxy(None, response).await;
            // A direct fallback would be observable as a TCP accept here.
            let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("https://{}", direct.local_addr().unwrap());
            let client = rpc::Rpc::for_proxy_test(&endpoint, &proxy_url, policy(), None);
            let error = client.info().await.unwrap_err();
            assert_eq!(error, ChainError::TransportUnavailable);
            assert!(!error.to_string().contains("private-canary"));
            assert!(
                tokio::time::timeout(Duration::from_millis(25), direct.accept())
                    .await
                    .is_err()
            );
            proxy.await.unwrap();
        }
    }
    #[tokio::test]
    async fn proxy_handshake_hang_respects_whole_request_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        let p = NetworkPolicy {
            request_timeout: Duration::from_millis(60),
            retries: 2,
            ..policy()
        };
        let client = rpc::Rpc::for_proxy_test(
            "https://wholepact-proxy-test.invalid:443",
            &proxy_url,
            p,
            None,
        );
        let start = std::time::Instant::now();
        assert_eq!(client.info().await.unwrap_err(), ChainError::Timeout);
        assert!(start.elapsed() < Duration::from_millis(500));
    }
}

#[test]
fn additional_cache_evidence_only_shortens_original_request_lifetime() {
    let (id, policy, info, tip, block) = fixture();
    let original = validate_context(
        &id,
        &policy,
        &info,
        &tip,
        &block,
        &tip,
        1_800_000_010,
        1_800_000_020,
    )
    .unwrap();
    let evidence = |age| RpcCacheObservation {
        method: "GetBlockRange",
        cache_status: CacheStatus::Hit,
        reported_age_seconds: Some(age),
        malformed_age: false,
    };
    let shortened = original
        .with_additional_cache_observations(vec![evidence(20)])
        .unwrap();
    assert_eq!(shortened.valid_until_unix_seconds(), 1_800_000_050);
    let unchanged = shortened
        .with_additional_cache_observations(vec![evidence(1)])
        .unwrap();
    assert_eq!(unchanged.valid_until_unix_seconds(), 1_800_000_050);
    let shortened = unchanged
        .with_additional_cache_observations(vec![evidence(30)])
        .unwrap();
    assert_eq!(shortened.valid_until_unix_seconds(), 1_800_000_040);
    assert_eq!(shortened.rpc_cache_observations().len(), 3);
    assert!(matches!(
        shortened.with_additional_cache_observations(vec![evidence(1000)]),
        Err(ChainError::StaleChain)
    ));
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn synthetic_factory_rejects_dns_remote_and_credential_endpoints() {
    for endpoint in [
        "http://localhost:1234",
        "http://example.invalid",
        "http://192.0.2.1",
        "http://127.0.0.1/x",
        "http://user@127.0.0.1",
        "http://[2001:db8::1]:1234",
    ] {
        assert!(
            ChainAdapter::synthetic_loopback_for_qualification(endpoint, NetworkPolicy::default())
                .is_err()
        );
    }
    for endpoint in ["http://127.0.0.1:1234", "http://[::1]:1234"] {
        let source =
            ChainAdapter::synthetic_loopback_for_qualification(endpoint, NetworkPolicy::default())
                .unwrap();
        assert_eq!(
            source.identity().trust_profile,
            "synthetic_never_chain_evidence"
        );
    }
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn offline_qualification_context_is_fixed_bounded_and_permanently_synthetic() {
    let context = synthetic_chain_context_for_qualification(1_800_000_000).unwrap();
    assert_eq!(context.tip().height, 4_498_144);
    assert_eq!(
        context.source().trust_profile,
        "synthetic_never_chain_evidence"
    );
    assert_eq!(
        context.source().endpoint,
        "synthetic://offline-never-network"
    );
    assert!(!context.authorizes_signing());
    assert!(!context.independently_consensus_verified());
    assert!(context.check_fresh_at(1_800_000_061).is_err());
    assert!(synthetic_chain_context_for_qualification(u64::MAX).is_err());
    let wallet = synthetic_wallet_chain_context_for_qualification(1_800_000_000).unwrap();
    assert_eq!(wallet.tip().height, 4_465_040);
    assert_eq!(
        wallet.source().trust_profile,
        "synthetic_never_chain_evidence"
    );
    assert_eq!(
        wallet.source().endpoint,
        "synthetic://wallet-offline-never-network"
    );
    assert_ne!(wallet.source(), context.source());
    assert!(!wallet.authorizes_signing());
    assert!(!wallet.independently_consensus_verified());
    assert!(wallet.check_fresh_at(1_800_000_061).is_err());
    assert!(synthetic_wallet_chain_context_for_qualification(u64::MAX).is_err());
    let confirmed = synthetic_wallet_confirmation_context_for_qualification(1_800_000_020).unwrap();
    assert_eq!(confirmed.tip().height, 4_465_050);
    assert_eq!(confirmed.source(), wallet.source());
    assert_ne!(confirmed.tip().hash, wallet.tip().hash);
    assert!(!confirmed.authorizes_signing());
    assert!(confirmed.check_fresh_at(1_800_000_081).is_err());
    assert!(synthetic_wallet_confirmation_context_for_qualification(u64::MAX).is_err());
}
