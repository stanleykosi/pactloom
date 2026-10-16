//! Synthetic in-memory maintained TLS, with fresh local OpenSSL identities. No
//! sockets/listeners, installed credentials, persistent wallets or native owners.
use super::*;
use std::io::Cursor;

fn response(scope: &OfflineClockScopeV1) -> OfflineClockResponseV1 {
    OfflineClockResponseV1 {
        scope: scope.clone(),
        challenge: "33".repeat(32),
        channel_binding: "44".repeat(32),
        witness_time_ms: 5000,
    }
}
fn scope() -> OfflineClockScopeV1 {
    OfflineClockScopeV1 {
        witness_id: "synthetic-witness".into(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        witness_policy_digest: "11".repeat(32),
        operation_id: "synthetic-operation".into(),
        authorization_id: "synthetic-authorization".into(),
        original_request_digest: "22".repeat(32),
        original_admission_digest: "55".repeat(32),
        original_not_before_ms: 3000,
        original_expires_at_ms: 30_000,
    }
}
#[test]
fn fixed_ceiling_charges_full_rtt_and_margin_without_renewal() {
    let scope = scope();
    let reply = response(&scope);
    let start = Instant::now();
    let receive = start + Duration::from_millis(123);
    let ceiling = validate_response(
        &scope,
        &reply.challenge,
        &reply.channel_binding,
        &reply,
        start,
        receive,
        start + Duration::from_secs(120),
    )
    .unwrap();
    assert_eq!(ceiling, receive + Duration::from_millis(23_877));
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    for advance in [0, 1, 100, 23_876] {
        let elapsed = Duration::from_millis(advance);
        check_continuity(receive, wall, ceiling, receive + elapsed, wall + elapsed).unwrap();
        assert_eq!(ceiling, receive + Duration::from_millis(23_877));
    }
    assert!(
        check_continuity(
            receive,
            wall,
            ceiling,
            ceiling,
            wall + Duration::from_millis(23_877)
        )
        .is_err()
    );
    let owner_end = receive + Duration::from_secs(2);
    assert_eq!(
        validate_response(
            &scope,
            &reply.challenge,
            &reply.channel_binding,
            &reply,
            start,
            receive,
            owner_end
        )
        .unwrap(),
        owner_end
    );
    let mut long = scope.clone();
    long.original_expires_at_ms = 1_000_000;
    let long_reply = response(&long);
    assert_eq!(
        validate_response(
            &long,
            &long_reply.challenge,
            &long_reply.channel_binding,
            &long_reply,
            start,
            receive,
            start + Duration::from_secs(999)
        )
        .unwrap(),
        receive + MAX_OBSERVATION
    );
}
#[test]
fn response_replay_scope_substitution_slow_roundtrip_and_expiry_are_rejected() {
    let s = scope();
    let start = Instant::now();
    let receive = start + Duration::from_millis(1);
    let end = start + Duration::from_secs(120);
    let validate = |r: &OfflineClockResponseV1| {
        validate_response(
            &s,
            &"33".repeat(32),
            &"44".repeat(32),
            r,
            start,
            receive,
            end,
        )
    };
    for change in [0, 1, 2, 3, 4] {
        let mut r = response(&s);
        match change {
            0 => r.challenge = "aa".repeat(32),
            1 => r.channel_binding = "bb".repeat(32),
            2 => r.scope.original_expires_at_ms += 1,
            3 => r.scope.original_request_digest = "cc".repeat(32),
            _ => r.scope.account_id.push('x'),
        };
        assert!(validate(&r).is_err());
    }
    let mut r = response(&s);
    assert!(
        validate_response(
            &s,
            &r.challenge,
            &r.channel_binding,
            &r,
            start,
            start + MAX_RTT + Duration::from_nanos(1),
            end
        )
        .is_err()
    );
    assert!(
        validate_response(
            &s,
            &r.challenge,
            &r.channel_binding,
            &r,
            receive,
            start,
            end
        )
        .is_err()
    );
    assert!(
        validate_response(
            &s,
            &r.challenge,
            &r.channel_binding,
            &r,
            start,
            receive,
            receive
        )
        .is_err()
    );
    for time in [0, 2999, 28_999, 30_000, u64::MAX] {
        r.witness_time_ms = time;
        assert!(validate(&r).is_err());
    }
}
#[test]
fn suspend_and_wall_clock_discontinuity_cannot_extend_monotonic_evidence() {
    let receive = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(12345);
    let end = receive + Duration::from_secs(120);
    assert!(
        check_continuity(
            receive,
            wall,
            end,
            receive + Duration::from_secs(1),
            wall + Duration::from_secs(3)
        )
        .is_err()
    );
    assert!(
        check_continuity(
            receive,
            wall,
            end,
            receive + Duration::from_secs(3),
            wall + Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(check_continuity(receive, wall, end, receive, wall - Duration::from_secs(1)).is_err());
}

struct TlsFixture {
    client: ClientTls,
    server: ServerTls,
    writer: String,
}
fn tls_fixture() -> TlsFixture {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    let temp = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let run = |args: &[&str]| {
        assert!(
            Command::new("openssl")
                .current_dir(temp.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("installed OpenSSL is required for synthetic TLS tests")
                .success(),
            "ephemeral TLS generation failed"
        )
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-sha256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Wholepact ephemeral clock CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    ]);
    for (name, purpose) in [("server", "serverAuth"), ("writer", "clientAuth")] {
        run(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            &format!("/CN=synthetic-{name}"),
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ]);
        fs::write(temp.path().join(format!("{name}.ext")),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={purpose}\nsubjectAltName=DNS:localhost\n")).unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
        run(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
        run(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            &format!("{name}.key"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.pk8"),
        ]);
    }
    run(&["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
    let cert = |name: &str| {
        CertificateDer::from(fs::read(temp.path().join(format!("{name}.der"))).unwrap())
    };
    let key = |name: &str| {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(temp.path().join(format!("{name}.pk8"))).unwrap(),
        ))
    };
    let server = ServerTls::new(vec![cert("ca")], vec![cert("server")], key("server")).unwrap();
    let writer = certificate_digest(&cert("writer"));
    let client = ClientTls::new(
        "localhost".into(),
        server.certificate_digest.clone(),
        vec![cert("ca")],
        vec![cert("writer")],
        key("writer"),
    )
    .unwrap();
    temp.close().unwrap();
    TlsFixture {
        client,
        server,
        writer,
    }
}
fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> std::result::Result<(), rustls::Error> {
    for _ in 0..32 {
        let mut progressed = false;
        if client.wants_write() {
            let mut b = Vec::new();
            client.write_tls(&mut b).unwrap();
            server.read_tls(&mut Cursor::new(b)).unwrap();
            server.process_new_packets()?;
            progressed = true;
        }
        if server.wants_write() {
            let mut b = Vec::new();
            server.write_tls(&mut b).unwrap();
            client.read_tls(&mut Cursor::new(b)).unwrap();
            client.process_new_packets()?;
            progressed = true;
        }
        if !progressed {
            return Ok(());
        }
    }
    panic!("synthetic TLS handshake failed to quiesce")
}
fn connections(tls: &TlsFixture) -> (ClientConnection, ServerConnection) {
    let mut client =
        ClientConnection::new(tls.client.config.clone(), tls.client.server_name.clone()).unwrap();
    let mut server = ServerConnection::new(tls.server.config.clone()).unwrap();
    pump(&mut client, &mut server).unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(client.alpn_protocol(), Some(ALPN));
    assert_eq!(server.alpn_protocol(), Some(ALPN));
    assert_eq!(
        certificate_digest(&client.peer_certificates().unwrap()[0]),
        tls.client.pinned_certificate
    );
    assert_eq!(
        certificate_digest(&server.peer_certificates().unwrap()[0]),
        tls.writer
    );
    (client, server)
}
#[test]
fn real_in_memory_mtls_carries_exact_journal_time_and_rejects_new_channel_replay() {
    let tls = tls_fixture();
    let f = crate::offline_clock_v1::tests::fixture("11".repeat(32), tls.writer.clone());
    let (mut client, mut server) = connections(&tls);
    let ce = Zeroizing::new(
        client
            .export_keying_material([0u8; 32], crate::session::EXPORTER_LABEL, None)
            .unwrap(),
    );
    let se = Zeroizing::new(
        server
            .export_keying_material([0u8; 32], crate::session::EXPORTER_LABEL, None)
            .unwrap(),
    );
    assert!(*ce == *se);
    let mut nonce = [0; 32];
    SystemRandom::new().fill(&mut nonce).unwrap();
    let challenge = hex::encode(nonce);
    let binding = channel_binding(&ce, &f.scope, &challenge).unwrap();
    let request = OfflineClockRequestV1 {
        scope: f.scope.clone(),
        challenge: challenge.clone(),
        channel_binding: binding.clone(),
    };
    write_frame(
        &mut client.writer(),
        &WireRequest::ObserveOfflineAdmissionTimeV1(Box::new(request)),
    )
    .unwrap();
    pump(&mut client, &mut server).unwrap();
    let WireRequest::ObserveOfflineAdmissionTimeV1(request) =
        read_frame(&mut server.reader()).unwrap()
    else {
        panic!("clock request")
    };
    let peer = certificate_digest(&server.peer_certificates().unwrap()[0]);
    let server_binding = channel_binding(&se, &request.scope, &request.challenge).unwrap();
    let response = f
        .journal
        .observe_offline_clock_v1(&peer, &request, &server_binding, || Ok(9000))
        .unwrap();
    write_frame(
        &mut server.writer(),
        &WireResponse::OfflineAdmissionTimeV1(Box::new(response)),
    )
    .unwrap();
    pump(&mut client, &mut server).unwrap();
    let WireResponse::OfflineAdmissionTimeV1(response) = read_frame(&mut client.reader()).unwrap()
    else {
        panic!("clock response")
    };
    let start = Instant::now();
    let received = start + Duration::from_millis(10);
    validate_response(
        &f.scope,
        &challenge,
        &binding,
        &response,
        start,
        received,
        start + MAX_OBSERVATION,
    )
    .unwrap();
    let (next, _) = connections(&tls);
    let next_exporter = Zeroizing::new(
        next.export_keying_material([0u8; 32], crate::session::EXPORTER_LABEL, None)
            .unwrap(),
    );
    let next_binding = channel_binding(&next_exporter, &f.scope, &challenge).unwrap();
    assert_ne!(binding, next_binding);
    assert!(
        validate_response(
            &f.scope,
            &challenge,
            &next_binding,
            &response,
            start,
            received,
            start + MAX_OBSERVATION
        )
        .is_err()
    );
    SystemRandom::new().fill(&mut nonce).unwrap();
    let next_challenge = hex::encode(nonce);
    assert!(
        validate_response(
            &f.scope,
            &next_challenge,
            &binding,
            &response,
            start,
            received,
            start + MAX_OBSERVATION
        )
        .is_err()
    );
}
#[test]
fn maintained_tls_rejects_wrong_hostname_and_untrusted_ca() {
    let tls = tls_fixture();
    let other = tls_fixture();
    let mut client = ClientConnection::new(
        tls.client.config.clone(),
        ServerName::try_from("wrong.invalid").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(tls.server.config.clone()).unwrap();
    assert!(pump(&mut client, &mut server).is_err());
    let mut client =
        ClientConnection::new(tls.client.config.clone(), tls.client.server_name.clone()).unwrap();
    let mut server = ServerConnection::new(other.server.config.clone()).unwrap();
    assert!(pump(&mut client, &mut server).is_err());
}

#[test]
fn failed_observation_is_permanently_poisoned_without_renewing_its_ceiling() {
    // Private cfg(test) state construction isolates the poison-state behavior.
    // It does not manufacture production clock provenance or open a connection.
    let tls = tls_fixture();
    let scope = scope();
    let client = AuthorityClient::new(
        "127.0.0.1:1".parse().unwrap(),
        tls.client,
        scope.witness_id.clone(),
        scope.account_id.clone(),
        scope.network_profile_id.clone(),
        scope.witness_policy_digest.clone(),
    )
    .unwrap();
    let received = Instant::now();
    let original_ceiling = received + Duration::from_secs(120);
    let make = || AuthenticatedOfflineClockV1 {
        client: &client,
        scope: scope.clone(),
        witness_time_ms: 5000,
        round_trip: Duration::from_millis(1),
        continuity_started: received,
        wall_at_start: std::time::SystemTime::now(),
        ceiling: original_ceiling,
        failed: std::sync::atomic::AtomicBool::new(false),
    };
    let mut observation = make();
    assert_eq!(
        observation.round_trip_upper_bound(),
        Duration::from_millis(1001)
    );
    observation.round_trip = Duration::from_nanos(1_000_001);
    assert_eq!(
        observation.round_trip_upper_bound(),
        Duration::from_millis(1002)
    );
    observation.check_current(&scope).unwrap();
    let mut wrong = scope.clone();
    wrong.authorization_id.push('x');
    assert!(matches!(
        observation.check_current(&wrong),
        Err(AuthorityError::InvalidBinding)
    ));
    assert!(matches!(
        observation.check_current(&scope),
        Err(AuthorityError::Expired)
    ));
    assert_eq!(observation.monotonic_ceiling(), original_ceiling);

    let mut observation = make();
    observation.wall_at_start = std::time::SystemTime::now() + Duration::from_secs(10);
    assert!(observation.check_current(&scope).is_err());
    // Even if the OS wall clock is subsequently repaired, failure stays final.
    observation.wall_at_start = std::time::SystemTime::now();
    assert!(matches!(
        observation.check_current(&scope),
        Err(AuthorityError::Expired)
    ));
    assert_eq!(observation.monotonic_ceiling(), original_ceiling);
}

#[test]
fn suspend_during_exchange_or_between_receive_samples_invalidates_the_response() {
    let started = Instant::now();
    let wall_at_start = std::time::UNIX_EPOCH + Duration::from_secs(100_000);
    let deadline = started + MAX_RTT;
    let received = started + Duration::from_millis(10);
    // Instant may pause during suspend. These represent an old response held
    // through suspend, and a suspend between receive-Instant and wall sampling.
    for wall_at_receive in [
        wall_at_start + Duration::from_secs(3600),
        wall_at_start + Duration::from_secs(2),
    ] {
        assert!(
            check_continuity(started, wall_at_start, deadline, received, wall_at_receive,).is_err()
        );
    }
    assert!(
        check_continuity(
            started,
            wall_at_start,
            deadline,
            received,
            wall_at_start - Duration::from_secs(1),
        )
        .is_err()
    );
}

#[test]
fn one_continuity_origin_cannot_spend_the_margin_before_and_after_receipt() {
    let started = Instant::now();
    let wall_at_start = std::time::UNIX_EPOCH + Duration::from_secs(100_000);
    let received = started + Duration::from_millis(100);
    let wall_at_receive = wall_at_start + Duration::from_millis(900);
    check_continuity(
        started,
        wall_at_start,
        started + MAX_RTT,
        received,
        wall_at_receive,
    )
    .unwrap();
    // 800ms discrepancy before receipt plus 700ms afterward exceeds the one
    // charged margin, even though either segment alone would be tolerated.
    let now = started + Duration::from_millis(200);
    let wall_now = wall_at_start + Duration::from_millis(1700);
    assert!(
        check_continuity(
            started,
            wall_at_start,
            started + MAX_OBSERVATION,
            now,
            wall_now,
        )
        .is_err()
    );
    assert!(
        check_continuity(
            received,
            wall_at_receive,
            started + MAX_OBSERVATION,
            now,
            wall_now,
        )
        .is_ok(),
        "a reset baseline would incorrectly accept this case"
    );
}
