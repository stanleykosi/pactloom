//! Local synthetic qualification only. No real credentials, accounts or network
//! endpoints. TLS credentials are generated ephemerally under a temporary directory.
use crate::{
    policy::{Event, Ledger},
    *,
};
use std::{
    path::Path,
    sync::{Arc, Barrier},
};
use wholepact_storage_security::DatabaseKey;

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn policy() -> AccountPolicy {
    AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-witness".into(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        owner_certificate_digest: h('a'),
        initial_writer_certificate_digest: h('b'),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('c')],
        agreement_ids: vec!["synthetic-agreement".into()],
        recipient_scope_digests: vec![h('d')],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 80,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 10,
        maximum_permit_lifetime_ms: 60_000,
        policy_expires_at_ms: 1_000_000,
    }
}
fn request(head: &AuthorityHead, number: u8, debit: u64) -> ReserveAuthorization {
    ReserveAuthorization {
        automation: None,
        operation_id: format!("op-{number}"),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        writer_epoch: 1,
        expected_head: head.clone(),
        authorization_id: format!("authorization-{number}"),
        original_consent_ref: format!("{number:064x}"),
        enrollment_ref: h('c'),
        accepted_manifest_ref: h('e'),
        agreement_id: "synthetic-agreement".into(),
        obligation_id: format!("obligation-{number}"),
        proposal_id: format!("proposal-{number}"),
        proposal_digest: h('f'),
        manifest_digest: h('1'),
        effects_digest: h('2'),
        artifact_digest: h('3'),
        review_binding: h('4'),
        recipient_scope_digest: h('d'),
        inputs: vec![InputReservation {
            input_id: format!("input-{number}"),
            nullifier: format!("{:064x}", u16::from(number) + 256),
            action_index: 0,
            value_zatoshis: 100,
        }],
        maximum_debit_zatoshis: debit,
        fee_share_zatoshis: 2,
        transaction_fee_zatoshis: 4,
        transaction_expiry_height: 1000,
        reviewed_at_ms: 1000,
        permit_expires_at_ms: 60_000,
    }
}
fn mutate(j: &AuthorityJournal, r: ReserveAuthorization) -> Result<ReservationPermit> {
    match j.mutate(
        &h('b'),
        AuthorityMutation::ReserveAuthorization(Box::new(r)),
        snapshot(j).last_witness_time_ms.max(1000) + 1,
    )? {
        MutationResult::Reserved(p) => Ok(*p),
        _ => panic!("wrong response"),
    }
}
fn snapshot(j: &AuthorityJournal) -> AccountSnapshot {
    j.snapshot(&h('a'), "synthetic-account", "synthetic-testnet")
        .unwrap()
}
fn create(dir: &Path) -> AuthorityJournal {
    let journal = AuthorityJournal::create_encrypted(
        &dir.join("authority.db"),
        &DatabaseKey::from_bytes([19; 32]),
        policy(),
    )
    .unwrap();
    journal.synthetic_activate(&h('b'), 998).unwrap();
    journal
}
fn open(dir: &Path) -> AuthorityJournal {
    AuthorityJournal::open_encrypted(
        &dir.join("authority.db"),
        &DatabaseKey::from_bytes([19; 32]),
        "synthetic-account",
        "synthetic-testnet",
    )
    .unwrap()
}
fn control(j: &AuthorityJournal, operation: &str, action: OwnerControl) -> AccountSnapshot {
    let s = snapshot(j);
    let request = OwnerControlRequest {
        operation_id: operation.into(),
        account_id: s.account_id,
        network_profile_id: s.network_profile_id,
        expected_head: s.head,
        writer_epoch: s.writer_epoch,
        control: action,
    };
    match j
        .mutate(
            &h('a'),
            AuthorityMutation::OwnerControl(request),
            s.last_witness_time_ms.max(1000) + 1,
        )
        .unwrap()
    {
        MutationResult::Controlled(s) => s,
        _ => panic!("wrong response"),
    }
}

fn active_ledger() -> Ledger {
    active_ledger_with_policy(policy())
}
fn active_ledger_with_policy(policy: AccountPolicy) -> Ledger {
    let mut ledger = Ledger::new(policy).unwrap();
    let session_id = crate::session::session_id(&[42; 32]);
    let disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1".into(),
        server_name: "localhost".into(),
        witness_id: ledger.policy.witness_id.clone(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        policy_digest: ledger.snapshot.policy_digest.clone(),
        pinned_server_certificate_digest: h('0'),
    };
    let acquire = AcquireWriterRequest {
        operation_id: "pure-acquire".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: ledger.snapshot.head.clone(),
        reconciled_history_digest: crate::session::history_digest(&ledger.snapshot).unwrap(),
        session_id: session_id.clone(),
        disclosure,
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::AcquireWriter(acquire),
            authenticated_certificate_digest: h('b'),
            witness_time_ms: 998,
            writer_session_id: None,
        })
        .unwrap();
    let activate = OwnerControlRequest {
        operation_id: "pure-activate".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
        writer_epoch: 1,
        control: OwnerControl::ActivateWriter { session_id },
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::OwnerControl(activate),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 999,
            writer_session_id: None,
        })
        .unwrap();
    ledger
}
#[test]
fn pure_policy_is_authoritative_exact_and_conservative() {
    let mut l = active_ledger();
    let r = request(&l.snapshot.head, 1, 60);
    let event = Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(r.clone())),
        authenticated_certificate_digest: h('b'),
        witness_time_ms: 1001,
        writer_session_id: Some(crate::session::session_id(&[42; 32])),
    };
    let first = l.apply(&event).unwrap();
    assert!(l.apply(&event).unwrap() == first);
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 60);
    assert_eq!(l.snapshot.reserved_input_value_zatoshis, 100);
    let mut changed = event.clone();
    if let AuthorityMutation::ReserveAuthorization(r) = &mut changed.mutation {
        r.maximum_debit_zatoshis = 61;
    }
    assert!(matches!(l.apply(&changed), Err(AuthorityError::Conflict)));
    let mut second = request(&l.snapshot.head, 2, 50);
    assert!(matches!(
        l.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(second.clone())),
            ..event.clone()
        }),
        Err(AuthorityError::BudgetExceeded)
    ));
    second.maximum_debit_zatoshis = 30;
    second.recipient_scope_digest = h('e');
    assert!(matches!(
        l.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(second)),
            ..event
        }),
        Err(AuthorityError::PolicyDenied)
    ));
    assert_eq!(l.snapshot.head.sequence, 3);
    let mut raw = serde_json::to_value(&r).unwrap();
    raw["aggregate_budget_zatoshis"] = serde_json::json!(1_000_000);
    assert!(serde_json::from_value::<ReserveAuthorization>(raw).is_err());
}

#[test]
fn exact_binding_rejects_missing_duplicate_oversize_and_wrong_scopes() {
    let l = Ledger::new(policy()).unwrap();
    let good = request(&l.snapshot.head, 1, 60);
    for mutation in 0..5 {
        let mut r = good.clone();
        match mutation {
            0 => r.inputs.push(r.inputs[0].clone()),
            1 => r.inputs[0].value_zatoshis = 1,
            2 => r.original_consent_ref.clear(),
            3 => r.operation_id = "a".repeat(129),
            _ => r.transaction_expiry_height = 0,
        }
        assert!(r.validate().is_err());
    }
    let mut wrong = good;
    wrong.network_profile_id = "other-network".into();
    let mut l = l;
    assert!(matches!(
        l.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(wrong)),
            authenticated_certificate_digest: h('b'),
            witness_time_ms: 1001,
            writer_session_id: None
        }),
        Err(AuthorityError::Permission)
    ));
}

#[test]
fn independent_connections_serialize_cas_and_one_account_budget() {
    let dir = private_dir();
    let original = create(dir.path());
    let head = snapshot(&original).head;
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for n in [1, 2] {
        let j = open(dir.path());
        let b = barrier.clone();
        let r = request(&head, n, 60);
        threads.push(std::thread::spawn(move || {
            b.wait();
            mutate(&j, r)
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(AuthorityError::StaleHead)))
            .count(),
        1
    );
    assert_eq!(snapshot(&original).outstanding_debit_zatoshis, 60);
    assert!(matches!(
        mutate(&original, request(&snapshot(&original).head, 3, 60)),
        Err(AuthorityError::BudgetExceeded)
    ));
}

#[test]
fn durable_lost_response_replay_takeover_pause_and_revoke_never_clear() {
    let dir = private_dir();
    let j = create(dir.path());
    let r = request(&snapshot(&j).head, 1, 60);
    let original = mutate(&j, r.clone()).unwrap();
    drop(j); // Simulated response lost after commit, followed by process restart.
    let j = open(dir.path());
    assert!(mutate(&j, r.clone()).unwrap() == original);
    let paused = control(&j, "pause", OwnerControl::Pause);
    assert_eq!(paused.outstanding_debit_zatoshis, 60);
    assert!(matches!(
        mutate(&j, request(&paused.head, 2, 20)),
        Err(AuthorityError::SessionRequired)
    ));
    assert!(mutate(&j, r.clone()).unwrap() == original);
    let replacement = control(
        &j,
        "replace",
        OwnerControl::ReplaceWriter {
            writer_certificate_digest: h('f'),
        },
    );
    assert_eq!(replacement.writer_epoch, 2);
    assert_eq!(replacement.reserved_input_value_zatoshis, 100);
    let mut next = request(&replacement.head, 2, 20);
    next.writer_epoch = 2;
    assert!(matches!(
        mutate(&j, next.clone()),
        Err(AuthorityError::Permission)
    ));
    let replacement = j
        .synthetic_activate(&h('f'), snapshot(&j).last_witness_time_ms + 1)
        .unwrap();
    next.expected_head = replacement.head;
    next.obligation_id = r.obligation_id.clone();
    assert!(matches!(
        j.mutate(
            &h('f'),
            AuthorityMutation::ReserveAuthorization(Box::new(next)),
            snapshot(&j).last_witness_time_ms + 1
        ),
        Err(AuthorityError::ObligationReserved)
    ));
    let revoked = control(&j, "revoke", OwnerControl::Revoke);
    assert_eq!(revoked.outstanding_debit_zatoshis, 60);
    assert!(mutate(&j, r).unwrap() == original);
    assert!(matches!(
        j.resolution_capability(),
        Err(AuthorityError::ResolutionUnavailable)
    ));
}

#[test]
fn all_selected_inputs_are_reserved_even_when_debit_is_small() {
    let dir = private_dir();
    let j = create(dir.path());
    let mut a = request(&snapshot(&j).head, 1, 10);
    a.inputs.push(InputReservation {
        input_id: "second-input".into(),
        nullifier: h('8'),
        action_index: 1,
        value_zatoshis: 50,
    });
    mutate(&j, a.clone()).unwrap();
    assert_eq!(snapshot(&j).reserved_input_value_zatoshis, 150);
    let mut b = request(&snapshot(&j).head, 2, 10);
    b.inputs[0].nullifier = a.inputs[1].nullifier.clone();
    assert!(matches!(
        mutate(&j, b.clone()),
        Err(AuthorityError::InputReserved)
    ));
    b.inputs[0].nullifier = h('9');
    b.inputs[0].input_id = a.inputs[1].input_id.clone();
    assert!(matches!(mutate(&j, b), Err(AuthorityError::InputReserved)));
}

#[test]
fn independent_backup_is_quarantined_and_account_identity_cannot_reset_history() {
    let dir = private_dir();
    let j = create(dir.path());
    let request = request(&snapshot(&j).head, 1, 60);
    mutate(&j, request.clone()).unwrap();
    let backup_key = DatabaseKey::from_bytes([23; 32]);
    j.backup_quarantined(
        &dir.path().join("staging.db"),
        &dir.path().join("backup.db"),
        &backup_key,
    )
    .unwrap();
    let restored = AuthorityJournal::open_encrypted(
        &dir.path().join("backup.db"),
        &backup_key,
        "synthetic-account",
        "synthetic-testnet",
    )
    .unwrap();
    let s = snapshot(&restored);
    assert_eq!(s.writer_status, WriterStatus::Quarantined);
    assert_eq!(s.outstanding_debit_zatoshis, 60);
    assert!(matches!(
        mutate(&restored, request.clone()),
        Err(AuthorityError::RecoveryRequired)
    ));
    assert!(mutate(&j, request).is_ok());
    assert!(
        AuthorityJournal::open_encrypted(
            &dir.path().join("authority.db"),
            &DatabaseKey::from_bytes([19; 32]),
            "new-account",
            "synthetic-testnet"
        )
        .is_err()
    );
    assert!(
        AuthorityJournal::create_encrypted(
            &dir.path().join("authority.db"),
            &DatabaseKey::from_bytes([19; 32]),
            policy()
        )
        .is_err()
    );
}

#[test]
fn clock_rollback_and_expiry_stop_new_reservations_but_keep_exposure() {
    let mut l = active_ledger();
    let a = request(&l.snapshot.head, 1, 60);
    let event = Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(a)),
        authenticated_certificate_digest: h('b'),
        witness_time_ms: 1001,
        writer_session_id: Some(crate::session::session_id(&[42; 32])),
    };
    let result = l.apply(&event).unwrap();
    let next = request(&l.snapshot.head, 2, 20);
    assert!(matches!(
        l.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(next.clone())),
            witness_time_ms: 1000,
            ..event.clone()
        }),
        Err(AuthorityError::Expired)
    ));
    assert!(matches!(
        l.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(next)),
            witness_time_ms: 60_001,
            ..event.clone()
        }),
        Err(AuthorityError::Expired)
    ));
    assert!(
        l.apply(&Event {
            original_request_link: None,
            witness_time_ms: 60_001,
            ..event
        })
        .unwrap()
            == result
    );
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 60);
}

#[test]
fn witness_process_exit_child() {
    let Ok(path) = std::env::var("WHOLEPACT_SYNTHETIC_AUTHORITY_CRASH_DIR") else {
        return;
    };
    let journal = open(Path::new(&path));
    let exact = request(&snapshot(&journal).head, 41, 60);
    mutate(&journal, exact).unwrap();
    // No destructor/checkpoint or response delivery. SQLite FULL-sync commit has
    // already completed; this is a synthetic abrupt process termination.
    std::process::exit(73);
}

#[test]
fn abrupt_process_exit_preserves_exact_reservation_and_replay() {
    let dir = private_dir();
    let journal = create(dir.path());
    let exact = request(&snapshot(&journal).head, 41, 60);
    drop(journal);
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::witness_process_exit_child"])
        .env("WHOLEPACT_SYNTHETIC_AUTHORITY_CRASH_DIR", dir.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(73));
    let recovered = open(dir.path());
    let state = snapshot(&recovered);
    assert_eq!(state.outstanding_reservations, 1);
    assert_eq!(state.outstanding_debit_zatoshis, 60);
    let permit = mutate(&recovered, exact.clone()).unwrap();
    permit.matches_request(&exact).unwrap();
    assert_eq!(snapshot(&recovered).head.sequence, 3);
}

#[test]
fn unaffiliated_certificates_cannot_probe_operations_or_quarantine() {
    let dir = private_dir();
    let journal = create(dir.path());
    let known = request(&snapshot(&journal).head, 1, 60);
    mutate(&journal, known.clone()).unwrap();
    let missing = request(&snapshot(&journal).head, 2, 20);
    for r in [known.clone(), missing.clone()] {
        assert!(matches!(
            journal.mutate(
                &h('e'),
                AuthorityMutation::ReserveAuthorization(Box::new(r)),
                1002
            ),
            Err(AuthorityError::Permission)
        ));
    }
    control(&journal, "quarantine", OwnerControl::RequireRecovery);
    for r in [known, missing] {
        assert!(matches!(
            journal.mutate(
                &h('e'),
                AuthorityMutation::ReserveAuthorization(Box::new(r)),
                1003
            ),
            Err(AuthorityError::Permission)
        ));
    }
}

#[test]
fn mtls_client_authenticates_exact_permits_and_rejects_wrong_peer_or_name() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::{fs, net::TcpListener, process::Command};
    let dir = private_dir();
    fn openssl(dir: &Path, args: &[&str]) {
        let output = Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ephemeral synthetic TLS fixture setup failed"
        );
    }
    openssl(
        dir.path(),
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Wholepact synthetic ephemeral CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    for (name, eku) in [
        ("server", "serverAuth"),
        ("writer", "clientAuth"),
        ("owner", "clientAuth"),
        ("outsider", "clientAuth"),
    ] {
        openssl(
            dir.path(),
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN=synthetic-{name}"),
            ],
        );
        fs::write(dir.path().join(format!("{name}.ext")), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\nsubjectAltName=DNS:localhost\n")).unwrap();
        openssl(
            dir.path(),
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &format!("{name}.pem"),
                "-days",
                "1",
                "-extfile",
                &format!("{name}.ext"),
            ],
        );
        openssl(
            dir.path(),
            &[
                "x509",
                "-in",
                &format!("{name}.pem"),
                "-outform",
                "DER",
                "-out",
                &format!("{name}.der"),
            ],
        );
        openssl(
            dir.path(),
            &[
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                &format!("{name}.key"),
                "-outform",
                "DER",
                "-out",
                &format!("{name}.key.der"),
            ],
        );
    }
    openssl(
        dir.path(),
        &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
    );
    let cert = |name: &str| {
        CertificateDer::from(fs::read(dir.path().join(format!("{name}.der"))).unwrap())
    };
    let key = |name: &str| {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(dir.path().join(format!("{name}.key.der"))).unwrap(),
        ))
    };
    let mut p = policy();
    p.initial_writer_certificate_digest = transport::certificate_digest(&cert("writer"));
    p.owner_certificate_digest = transport::certificate_digest(&cert("owner"));
    let now = now_ms().unwrap();
    p.policy_expires_at_ms = now + 120_000;
    let policy_digest = p.policy_digest().unwrap();
    let j = AuthorityJournal::create_encrypted(
        &dir.path().join("tls.db"),
        &DatabaseKey::from_bytes([51; 32]),
        p,
    )
    .unwrap();
    let tls = ServerTls::new(vec![cert("ca")], vec![cert("server")], key("server")).unwrap();
    let journal = Arc::new(j);
    let server = AuthorityServer::new(journal.clone(), tls);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        server.serve_test_connections(listener, 34).unwrap();
    });
    let client = |identity: &str, hostname: &str, pin: String| {
        AuthorityClient::new(
            address,
            ClientTls::new(
                hostname.into(),
                pin,
                vec![cert("ca")],
                vec![cert(identity)],
                key(identity),
            )
            .unwrap(),
            "synthetic-witness".into(),
            "synthetic-account".into(),
            "synthetic-testnet".into(),
            policy_digest.clone(),
        )
        .unwrap()
    };
    let pin = transport::certificate_digest(&cert("server"));
    let slow = std::net::TcpStream::connect(address).unwrap(); // accepted connection 1
    let c = client("writer", "localhost", pin.clone());
    let owner = client("owner", "localhost", pin.clone());
    let began = std::time::Instant::now();
    let initial = c.snapshot().unwrap(); // 2
    assert!(began.elapsed() < std::time::Duration::from_secs(2));
    drop(slow);
    let history = c.reconcile_history().unwrap(); // 3,4
    assert_eq!(history.permits().unwrap().len(), 0);
    let pending = c.acquire_writer(&history, "tls-acquire").unwrap(); // 5
    // Certificate possession and a pending (unactivated) session cannot reserve.
    let mut early = request(&pending.acquired_head, 1, 60);
    early.reviewed_at_ms = now;
    early.permit_expires_at_ms = now + 60_000;
    assert!(matches!(
        c.reserve(early),
        Err(AuthorityError::SessionRequired)
    )); // 6
    let activate = OwnerControlRequest {
        operation_id: "tls-activate".into(),
        account_id: initial.account_id.clone(),
        network_profile_id: initial.network_profile_id.clone(),
        expected_head: pending.acquired_head.clone(),
        writer_epoch: pending.writer_epoch,
        control: OwnerControl::ActivateWriter {
            session_id: pending.session_id.clone(),
        },
    };
    let active = owner.control(activate).unwrap(); // 7
    let mut r = request(&active.head, 1, 60);
    r.reviewed_at_ms = now;
    r.permit_expires_at_ms = now + 60_000;
    let permit = c.reserve(r.clone()).unwrap(); // 8
    let replay = c.reserve(r.clone()).unwrap(); // 9
    assert!(permit.descriptor() == replay.descriptor());
    let reconciled = c.reconcile_history().unwrap(); // 10,11
    assert_eq!(reconciled.permits().unwrap().len(), 1);
    assert!(reconciled.permits().unwrap()[0] == *permit.descriptor());
    let live_session = c.verify_active_session(&reconciled).unwrap();
    assert!(live_session.snapshot() == reconciled.snapshot());
    assert_eq!(
        live_session.history_digest(),
        reconciled.history_digest().unwrap()
    );
    let dispatch = AuthorizeDispatch {
        operation_id: "tls-dispatch".into(),
        account_id: r.account_id.clone(),
        network_profile_id: r.network_profile_id.clone(),
        writer_epoch: r.writer_epoch,
        expected_head: reconciled.snapshot().head.clone(),
        reservation_operation_id: r.operation_id.clone(),
        reservation_request_digest: r.request_digest().unwrap(),
        final_transaction_digest: h('7'),
        final_transaction_id: h('8'),
        transaction_expiry_height: r.transaction_expiry_height,
        backend_disclosure_digest: h('9'),
        reviewed_at_ms: now,
        admission_expires_at_ms: now + 60_000,
    };
    let admission = c.authorize_dispatch(dispatch.clone()).unwrap();
    admission.matches_request(&dispatch).unwrap();
    assert!(admission.descriptor().reservation == *permit.descriptor());
    assert!(c.authorize_dispatch(dispatch).unwrap().descriptor() == admission.descriptor());
    // The test deliberately exercises more than the 32-connection burst; allow
    // the fixed production admission bucket to replenish, never disable it.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let progress = ReportProgress {
        operation_id: "tls-progress".into(),
        account_id: r.account_id.clone(),
        network_profile_id: r.network_profile_id.clone(),
        writer_epoch: r.writer_epoch,
        expected_head: admission.descriptor().committed_head.clone(),
        reservation_operation_id: r.operation_id.clone(),
        reservation_request_digest: r.request_digest().unwrap(),
        progress: AuthorizationProgress::SubmissionUncertain,
        evidence_digest: h('8'),
    };
    let observed = c.report_progress(progress).unwrap(); // 12
    assert_eq!(observed.outstanding_debit_zatoshis, 60);
    assert_eq!(observed.reserved_input_value_zatoshis, 100);
    let clone = client("writer", "localhost", pin.clone());
    assert!(matches!(
        clone.reserve(r.clone()),
        Err(AuthorityError::SessionRequired)
    )); // local refusal
    let paused = owner
        .control(OwnerControlRequest {
            operation_id: "tls-pause".into(),
            account_id: r.account_id.clone(),
            network_profile_id: r.network_profile_id.clone(),
            expected_head: observed.head,
            writer_epoch: 1,
            control: OwnerControl::Pause,
        })
        .unwrap(); // 13
    assert!(c.reserve(r.clone()).unwrap().descriptor() == permit.descriptor()); // 14: issued permit survives
    let mut next = request(&paused.head, 2, 20);
    next.reviewed_at_ms = now;
    next.permit_expires_at_ms = now + 60_000;
    assert!(matches!(c.reserve(next), Err(AuthorityError::Inactive))); // 15
    let restored_history = clone.reconcile_history().unwrap(); // 16,17
    assert_eq!(restored_history.permits().unwrap().len(), 1);
    let replacement = clone
        .acquire_writer(&restored_history, "tls-reacquire")
        .unwrap(); // 18
    assert!(matches!(
        clone.reserve(r.clone()),
        Err(AuthorityError::SessionRequired)
    )); // 19 pending cannot mint historical permit
    let activated = owner
        .control(OwnerControlRequest {
            operation_id: "tls-reactivate".into(),
            account_id: r.account_id.clone(),
            network_profile_id: r.network_profile_id.clone(),
            expected_head: replacement.acquired_head,
            writer_epoch: 1,
            control: OwnerControl::ActivateWriter {
                session_id: replacement.session_id,
            },
        })
        .unwrap(); // 20
    assert!(clone.reserve(r.clone()).unwrap().descriptor() == permit.descriptor()); // 21 original exact replay
    let mut next = request(&activated.head, 2, 20);
    next.reviewed_at_ms = now;
    next.permit_expires_at_ms = now + 60_000;
    assert!(matches!(
        c.reserve(next),
        Err(AuthorityError::SessionRequired)
    )); // 22 old live session fenced
    let outsider = client("outsider", "localhost", pin.clone());
    assert!(matches!(
        outsider.snapshot(),
        Err(AuthorityError::Permission)
    )); // 23
    let probe = |id: &str| OwnerControlRequest {
        operation_id: id.into(),
        account_id: r.account_id.clone(),
        network_profile_id: r.network_profile_id.clone(),
        expected_head: activated.head.clone(),
        writer_epoch: 1,
        control: OwnerControl::Pause,
    };
    assert!(matches!(
        outsider.control(probe("tls-activate")),
        Err(AuthorityError::Permission)
    )); //24
    assert!(matches!(
        outsider.control(probe("absent")),
        Err(AuthorityError::Permission)
    )); //25
    let quarantined = owner
        .control(OwnerControlRequest {
            operation_id: "tls-quarantine".into(),
            control: OwnerControl::RequireRecovery,
            ..probe("unused")
        })
        .unwrap(); //26
    assert_eq!(quarantined.outstanding_debit_zatoshis, 60);
    assert!(matches!(
        outsider.control(probe("tls-activate")),
        Err(AuthorityError::Permission)
    )); //27
    assert!(matches!(
        outsider.control(probe("absent")),
        Err(AuthorityError::Permission)
    )); //28
    assert!(matches!(
        clone.reserve(r),
        Err(AuthorityError::RecoveryRequired)
    )); //29
    assert!(matches!(
        client("writer", "wrong.invalid", pin).snapshot(),
        Err(AuthorityError::Authentication)
    )); //30
    assert!(matches!(
        client("writer", "localhost", h('0')).snapshot(),
        Err(AuthorityError::Authentication)
    )); //31
    server_thread.join().unwrap();
}

#[test]
fn writer_mac_binds_exact_channel_scope_generation_and_request() {
    let ledger = active_ledger();
    let receipt = ledger.snapshot.active_writer_session.as_ref().unwrap();
    let original =
        AuthorityMutation::ReserveAuthorization(Box::new(request(&ledger.snapshot.head, 1, 60)));
    let channel = [11; 32];
    let proof = crate::session::proof(
        &[42; 32],
        (
            &receipt.session_id,
            &receipt.disclosure,
            receipt.writer_epoch,
        ),
        &channel,
        &original,
    )
    .unwrap();
    crate::session::verify(&[42; 32], receipt, &channel, &original, &proof).unwrap();
    assert!(crate::session::verify(&[42; 32], receipt, &[12; 32], &original, &proof).is_err());
    let mut changed = original.clone();
    if let AuthorityMutation::ReserveAuthorization(r) = &mut changed {
        r.maximum_debit_zatoshis += 1;
    }
    assert!(crate::session::verify(&[42; 32], receipt, &channel, &changed, &proof).is_err());
    for field in 0..5 {
        let mut other = receipt.clone();
        match field {
            0 => other.writer_epoch += 1,
            1 => other.disclosure.endpoint = "127.0.0.1:2".into(),
            2 => other.disclosure.witness_id = "other-witness".into(),
            3 => other.disclosure.account_id = "other-account".into(),
            _ => other.disclosure.pinned_server_certificate_digest = h('1'),
        }
        assert!(crate::session::verify(&[42; 32], &other, &channel, &original, &proof).is_err());
    }
}

#[test]
fn acquired_session_lost_response_retries_exactly_on_a_new_channel() {
    let dir = private_dir();
    let j = AuthorityJournal::create_encrypted(
        &dir.path().join("authority.db"),
        &DatabaseKey::from_bytes([19; 32]),
        policy(),
    )
    .unwrap();
    let state = snapshot(&j);
    let key = [33; 32];
    let descriptor = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1".into(),
        server_name: "localhost".into(),
        witness_id: state.witness_id.clone(),
        account_id: state.account_id.clone(),
        network_profile_id: state.network_profile_id.clone(),
        policy_digest: state.policy_digest.clone(),
        pinned_server_certificate_digest: h('0'),
    };
    let mutation = AuthorityMutation::AcquireWriter(AcquireWriterRequest {
        operation_id: "acquisition-lost-response".into(),
        account_id: state.account_id,
        network_profile_id: state.network_profile_id,
        writer_epoch: 1,
        expected_head: state.head.clone(),
        reconciled_history_digest: crate::session::history_digest(&snapshot(&j)).unwrap(),
        session_id: crate::session::session_id(&key),
        disclosure: descriptor,
    });
    let first = j
        .mutate_on_channel(&h('b'), mutation.clone(), None, &key, &h('0'), 1000)
        .unwrap();
    let MutationResult::WriterPending(receipt) = &first else {
        panic!("expected pending")
    };
    let channel = [34; 32];
    let proof = crate::session::proof(
        &key,
        (
            &receipt.session_id,
            &receipt.disclosure,
            receipt.writer_epoch,
        ),
        &channel,
        &mutation,
    )
    .unwrap();
    assert!(
        j.mutate_on_channel(
            &h('b'),
            mutation.clone(),
            Some(proof.clone()),
            &channel,
            &h('0'),
            1001
        )
        .unwrap()
            == first
    );
    assert_eq!(snapshot(&j).head.sequence, 1);
    assert!(matches!(
        j.mutate_on_channel(&h('b'), mutation, Some(proof), &[35; 32], &h('0'), 1001),
        Err(AuthorityError::Authentication)
    ));
}

#[test]
fn complete_history_crosses_page_boundaries_without_skipping_originals() {
    let dir = private_dir();
    let journal = create(dir.path());
    for number in 1..=20 {
        let head = snapshot(&journal).head;
        mutate(&journal, request(&head, number, 4)).unwrap();
    }
    let complete = snapshot(&journal);
    let mut after = 0;
    let mut reconstructed = Ledger::new(policy()).unwrap();
    let mut permits = 0;
    let mut pages = 0;
    loop {
        let page = journal
            .history(
                &h('b'),
                "synthetic-account",
                "synthetic-testnet",
                &complete.head,
                after,
                8,
            )
            .unwrap();
        assert!(
            encode(&crate::protocol::WireResponse::History(Box::new(
                page.clone()
            )))
            .is_ok()
        );
        assert!(page.entries.len() <= 8);
        for entry in page.entries {
            assert_eq!(entry.sequence, after + 1);
            let result = reconstructed
                .apply(&Event {
                    original_request_link: entry.original_request_link,
                    mutation: entry.mutation,
                    authenticated_certificate_digest: entry.authenticated_certificate_digest,
                    witness_time_ms: entry.witness_time_ms,
                    writer_session_id: entry.writer_session_id,
                })
                .unwrap();
            if matches!(result, MutationResult::Reserved(_)) {
                permits += 1;
            }
            assert_eq!(entry.head, reconstructed.snapshot.head.digest);
            after = entry.sequence;
        }
        pages += 1;
        match page.next_after_sequence {
            Some(cursor) => assert_eq!(cursor, after),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(permits, 20);
    assert!(reconstructed.snapshot == complete);
    let old = complete.head;
    control(&journal, "pagination-pause", OwnerControl::Pause);
    assert!(matches!(
        journal.history(
            &h('b'),
            "synthetic-account",
            "synthetic-testnet",
            &old,
            0,
            8
        ),
        Err(AuthorityError::StaleHead)
    ));
}

#[test]
fn dispatch_admission_is_durable_exact_and_never_recalls_or_clears_exposure() {
    let dir = private_dir();
    let journal = create(dir.path());
    let original = request(&snapshot(&journal).head, 1, 60);
    let permit = mutate(&journal, original.clone()).unwrap();
    let dispatch = AuthorizeDispatch {
        operation_id: "dispatch-1".into(),
        account_id: original.account_id.clone(),
        network_profile_id: original.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: snapshot(&journal).head,
        reservation_operation_id: original.operation_id.clone(),
        reservation_request_digest: original.request_digest().unwrap(),
        final_transaction_digest: h('7'),
        final_transaction_id: h('8'),
        transaction_expiry_height: original.transaction_expiry_height,
        backend_disclosure_digest: h('9'),
        reviewed_at_ms: 60_001,
        admission_expires_at_ms: 120_001,
    };
    // Signing permission has expired, but an already produced exact signature
    // was not recalled. Dispatch requires this distinct fresh native window.
    assert!(dispatch.reviewed_at_ms > original.permit_expires_at_ms);
    let mutation = AuthorityMutation::AuthorizeDispatch(dispatch.clone());
    let result = journal.mutate(&h('b'), mutation.clone(), 60_002).unwrap();
    let MutationResult::DispatchAdmitted(admission) = &result else {
        panic!("missing admission")
    };
    admission.matches_request(&dispatch).unwrap();
    assert!(admission.reservation == permit);
    let after = snapshot(&journal);
    assert_eq!(after.outstanding_debit_zatoshis, 60);
    assert_eq!(after.reserved_input_value_zatoshis, 100);
    assert_eq!(after.outstanding_reservations, 1);
    drop(journal); // The response could have been lost after durable commit.
    let reopened = open(dir.path());
    assert!(reopened.mutate(&h('b'), mutation.clone(), 60_003).unwrap() == result);
    let mut changed = dispatch.clone();
    changed.final_transaction_digest = h('6');
    assert!(matches!(
        reopened.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeDispatch(changed.clone()),
            60_004
        ),
        Err(AuthorityError::Conflict)
    ));
    changed.operation_id = "different-final-bytes".into();
    changed.expected_head = after.head;
    assert!(matches!(
        reopened.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeDispatch(changed),
            60_004
        ),
        Err(AuthorityError::Conflict)
    ));
    let mut wrong_expiry = dispatch.clone();
    wrong_expiry.operation_id = "different-transaction-expiry".into();
    wrong_expiry.expected_head = snapshot(&reopened).head;
    wrong_expiry.transaction_expiry_height += 1;
    assert!(matches!(
        reopened.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeDispatch(wrong_expiry),
            60_004
        ),
        Err(AuthorityError::InvalidBinding)
    ));
    control(&reopened, "stop-dispatch", OwnerControl::Revoke);
    // Already admitted sends cannot be recalled by this later control. This is
    // historical evidence; actual use still checks the new dispatch deadline.
    assert!(reopened.mutate(&h('b'), mutation, 60_005).unwrap() == result);
    let mut new = dispatch;
    new.operation_id = "new-dispatch-after-revoke".into();
    new.expected_head = snapshot(&reopened).head;
    assert!(matches!(
        reopened.mutate(&h('b'), AuthorityMutation::AuthorizeDispatch(new), 60_006),
        Err(AuthorityError::SessionRequired)
    ));
    assert_eq!(snapshot(&reopened).outstanding_debit_zatoshis, 60);
}

/// Synthetic ledger semantics only. These values are not node qualification.
#[test]
fn resolution_preserves_originals_and_reopens_every_budget() {
    let mut ledger = active_ledger();
    let mut originals = Vec::new();
    for n in [1, 2] {
        let r = request(&ledger.snapshot.head, n, 40);
        let session = ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .unwrap()
            .session_id
            .clone();
        let result = ledger
            .apply(&Event {
                original_request_link: None,
                mutation: AuthorityMutation::ReserveAuthorization(Box::new(r.clone())),
                authenticated_certificate_digest: h('b'),
                witness_time_ms: 1000 + u64::from(n),
                writer_session_id: Some(session),
            })
            .unwrap();
        originals.push((r, result));
    }
    // Synthetic setup of separately tested authenticated dispatch/source history.
    ledger.resolution_source = Some(h('6'));
    for (r, _) in &originals {
        ledger
            .final_transactions
            .insert(r.operation_id.clone(), (h('7'), h('8')));
    }
    for (n, (r, _)) in originals.iter().enumerate() {
        let record = ResolutionRecord {
            operation_id: format!("synthetic-resolution-{n}"),
            account_id: r.account_id.clone(),
            network_profile_id: r.network_profile_id.clone(),
            expected_head: ledger.snapshot.head.clone(),
            reservation_operation_id: r.operation_id.clone(),
            reservation_request_digest: r.request_digest().unwrap(),
            final_transaction_id: h('8'),
            final_transaction_digest: h('7'),
            source_descriptor_digest: h('6'),
            evidence_digest: h('5'),
            consumed_nullifiers: vec![r.inputs[0].nullifier.clone()],
            conflict: None,
            inclusion_block_hash: h('4'),
            inclusion_block_height: 4_500_000,
        };
        let mut wrong = record.clone();
        wrong.consumed_nullifiers = vec![h('0')];
        assert!(matches!(
            ledger.apply(&Event {
                original_request_link: None,
                mutation: AuthorityMutation::QualifiedResolution(wrong),
                authenticated_certificate_digest: h('a'),
                witness_time_ms: 1010 + n as u64,
                writer_session_id: None
            }),
            Err(AuthorityError::InvalidBinding)
        ));
        let mut unrelated_extra = record.clone();
        unrelated_extra.consumed_nullifiers.push(h('0'));
        assert!(matches!(
            ledger.apply(&Event {
                original_request_link: None,
                mutation: AuthorityMutation::QualifiedResolution(unrelated_extra),
                authenticated_certificate_digest: h('a'),
                witness_time_ms: 1010 + n as u64,
                writer_session_id: None,
            }),
            Err(AuthorityError::InvalidBinding)
        ));
        let event = Event {
            original_request_link: None,
            mutation: AuthorityMutation::QualifiedResolution(record),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 1010 + n as u64,
            writer_session_id: None,
        };
        // Read absent-field historical JSON and replay the exact event/receipt.
        // The fixed legacy fixture below independently pins the old encoding.
        let legacy_bytes = serde_json::to_vec(&event).unwrap();
        assert!(!String::from_utf8_lossy(&legacy_bytes).contains("conflict"));
        let loaded: Event = serde_json::from_slice(&legacy_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&loaded).unwrap(), legacy_bytes);
        let first = ledger.apply(&loaded).unwrap();
        let first_bytes = serde_json::to_vec(&first).unwrap();
        let head = ledger.snapshot.head.clone();
        let replay: Event = serde_json::from_slice(&legacy_bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&ledger.apply(&replay).unwrap()).unwrap(),
            first_bytes
        );
        assert_eq!(ledger.snapshot.head, head);
    }
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 0);
    assert_eq!(ledger.snapshot.settled_debit_zatoshis, 80);
    assert_eq!(ledger.snapshot.remaining_budget_zatoshis().unwrap(), 20);
    let denied = request(&ledger.snapshot.head, 3, 40);
    assert!(matches!(
        ledger.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(denied)),
            authenticated_certificate_digest: h('b'),
            witness_time_ms: 1015,
            writer_session_id: Some(
                ledger
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .unwrap()
                    .session_id
                    .clone()
            ),
        }),
        Err(AuthorityError::BudgetExceeded)
    ));
    let reopen = ReopenResolutions {
        operation_id: "synthetic-reopen".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
    };
    let event = Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReopenResolutions(reopen),
        authenticated_certificate_digest: h('a'),
        witness_time_ms: 1020,
        writer_session_id: None,
    };
    ledger.apply(&event).unwrap();
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 80);
    assert_eq!(ledger.snapshot.settled_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.remaining_budget_zatoshis().unwrap(), 20);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 200);
    assert_eq!(ledger.snapshot.outstanding_reservations, 2);
    ledger.apply(&event).unwrap(); // Idempotent; never double-count.
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 80);
    for (r, original) in originals {
        assert!(ledger.operations[&r.operation_id].2 == original);
    }
}

#[test]
fn remote_owner_cannot_inject_resolution_or_reopen_json() {
    let dir = private_dir();
    let journal = create(dir.path());
    let head = snapshot(&journal).head;
    let mutation = AuthorityMutation::ReopenResolutions(ReopenResolutions {
        operation_id: "forged-reopen".into(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        expected_head: head.clone(),
    });
    assert!(matches!(
        journal.mutate_on_channel(&h('a'), mutation, None, &[0; 32], &h('0'), 1001),
        Err(AuthorityError::Permission)
    ));
    assert_eq!(snapshot(&journal).head, head);
    assert!(matches!(
        journal.resolve_reservation(&h('a'), "synthetic-account", "synthetic-testnet", "unknown"),
        Err(AuthorityError::InvalidBinding)
    ));
}

#[test]
fn reconciled_history_and_writer_session_share_budget_commitment() {
    let ledger = active_ledger();
    let mut history = ReconciledAuthorityHistory {
        completed_dispatches_v1: Vec::new(),
        durable_payment_history_supported_v1: false,
        construction_transport_history:
            crate::construction_transport_handoff_v1::ConstructionTransportHistoryV1 {
                version: 1,
                ..Default::default()
            },
        manual_roster_construction_records_v3: Default::default(),
        manual_roster_construction_records: Default::default(),
        manual_roster_attempt: None,
        manual_attempt: None,
        pending_birth_commit: None,
        account_use_history: ledger.account_use_history.clone(),
        account_policy: ledger.policy.clone(),
        disclosure: ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .unwrap()
            .disclosure
            .clone(),
        snapshot: ledger.snapshot,
        permits: vec![],
        offline_permits: vec![],
        born_offline_permits: vec![],
        born_offline_dispatches: vec![],
        automatic_key_use_admissions: vec![],
        recovery_fences: vec![],
        committed_operation_ids: std::collections::BTreeSet::new(),
        owner_controls: std::collections::BTreeMap::new(),
        history_heads: std::collections::BTreeMap::new(),
    };
    let original = history.history_digest().unwrap();
    assert_eq!(
        original,
        crate::session::history_digest(history.snapshot()).unwrap()
    );
    history.snapshot.settled_debit_zatoshis = 1;
    assert_ne!(original, history.history_digest().unwrap());
    history.snapshot.settled_debit_zatoshis = 0;
    history.snapshot.aggregate_budget_zatoshis -= 1;
    assert_ne!(original, history.history_digest().unwrap());
}

#[path = "recovery_tests.rs"]
mod recovery_tests;

#[path = "automation_tests.rs"]
mod automation_tests;

#[path = "offline_ledger_tests.rs"]
mod offline_ledger_tests;

// Append to authority/src/tests.rs. Child inherits the existing synthetic
// private_dir/create/open/control/snapshot/request helpers through use super::*.
#[path = "offline_connected_journal_tests.rs"]
mod offline_connected_journal_tests;

#[path = "account_use_ledger_tests.rs"]
mod account_use_ledger_tests;

#[path = "pending_birth_schema_tests.rs"]
mod pending_birth_schema_tests;

/// Private accounting fixture, deliberately not a canonical node observation.
/// The source qualifier is tested separately; injecting this map is test-only.
#[test]
fn canonical_conflict_cannot_free_witness_budget_or_original_reservations() {
    let mut ledger = active_ledger();
    let request = request(&ledger.snapshot.head, 1, 40);
    let session = ledger
        .snapshot
        .active_writer_session
        .as_ref()
        .unwrap()
        .session_id
        .clone();
    let original = ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(request.clone())),
            authenticated_certificate_digest: h('b'),
            witness_time_ms: 1001,
            writer_session_id: Some(session),
        })
        .unwrap();
    let record = ResolutionRecord {
        operation_id: "synthetic-conflict-record".into(),
        account_id: request.account_id.clone(),
        network_profile_id: request.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
        reservation_operation_id: request.operation_id.clone(),
        reservation_request_digest: request.request_digest().unwrap(),
        final_transaction_id: h('7'),
        final_transaction_digest: h('8'),
        source_descriptor_digest: h('6'),
        evidence_digest: h('5'),
        consumed_nullifiers: vec![request.inputs[0].nullifier.clone()],
        conflict: Some(wholepact_chain::local_node::CanonicalConflictCandidate {
            included_transaction_id: h('9'),
            original_transaction_hex: "00".into(),
            nullifier: request.inputs[0].nullifier.clone(),
        }),
        inclusion_block_hash: h('4'),
        inclusion_block_height: 4_500_000,
    };
    // Malformed raw original cannot enter the ordinary protected ledger path.
    ledger.resolution_source = Some(h('6'));
    ledger
        .final_transactions
        .insert(request.operation_id.clone(), (h('8'), h('7')));
    assert!(
        ledger
            .apply(&Event {
                original_request_link: None,
                mutation: AuthorityMutation::QualifiedResolution(record.clone()),
                authenticated_certificate_digest: h('a'),
                witness_time_ms: 1002,
                writer_session_id: None
            })
            .is_err()
    );
    ledger.resolutions.insert(
        request.operation_id.clone(),
        ResolutionReceipt {
            record,
            committed_head: ledger.snapshot.head.clone(),
        },
    );
    ledger.recompute_exposure().unwrap();
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 40);
    assert_eq!(ledger.snapshot.settled_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 100);
    assert_eq!(ledger.snapshot.outstanding_reservations, 1);
    assert!(ledger.obligations.contains(&request.obligation_id));
    assert!(ledger.nullifiers.contains(&request.inputs[0].nullifier));
    let reopen = ReopenResolutions {
        operation_id: "synthetic-conflict-reopen".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReopenResolutions(reopen),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 1003,
            writer_session_id: None,
        })
        .unwrap();
    assert!(ledger.resolutions.is_empty());
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 40);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 100);
    assert!(ledger.operations[&request.operation_id].2 == original);
}

/// Frozen synthetic pre-conflict JSON shape. No node or authenticated issuer.
#[test]
fn legacy_resolution_json_preserves_bytes_append_digest_and_receipt() {
    const RECEIPT: &str = r#"{"record":{"operation_id":"synthetic-legacy-resolution","account_id":"synthetic-account","network_profile_id":"synthetic-testnet","expected_head":{"sequence":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"reservation_operation_id":"op-1","reservation_request_digest":"1111111111111111111111111111111111111111111111111111111111111111","final_transaction_id":"2222222222222222222222222222222222222222222222222222222222222222","final_transaction_digest":"3333333333333333333333333333333333333333333333333333333333333333","source_descriptor_digest":"4444444444444444444444444444444444444444444444444444444444444444","evidence_digest":"5555555555555555555555555555555555555555555555555555555555555555","consumed_nullifiers":["6666666666666666666666666666666666666666666666666666666666666666"],"inclusion_block_hash":"7777777777777777777777777777777777777777777777777777777777777777","inclusion_block_height":4500000},"committed_head":{"sequence":2,"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
    const EVENT: &str = r#"{"mutation":{"method":"qualified_resolution","body":{"operation_id":"synthetic-legacy-resolution","account_id":"synthetic-account","network_profile_id":"synthetic-testnet","expected_head":{"sequence":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"reservation_operation_id":"op-1","reservation_request_digest":"1111111111111111111111111111111111111111111111111111111111111111","final_transaction_id":"2222222222222222222222222222222222222222222222222222222222222222","final_transaction_digest":"3333333333333333333333333333333333333333333333333333333333333333","source_descriptor_digest":"4444444444444444444444444444444444444444444444444444444444444444","evidence_digest":"5555555555555555555555555555555555555555555555555555555555555555","consumed_nullifiers":["6666666666666666666666666666666666666666666666666666666666666666"],"inclusion_block_hash":"7777777777777777777777777777777777777777777777777777777777777777","inclusion_block_height":4500000}},"authenticated_certificate_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","witness_time_ms":1010,"writer_session_id":null}"#;
    const REQUEST: &str = r#"{"method":"resolve_reservation","body":{"account_id":"synthetic-account","network_profile_id":"synthetic-testnet","reservation_operation_id":"op-1"}}"#;
    let receipt: ResolutionReceipt = serde_json::from_str(RECEIPT).unwrap();
    assert!(receipt.record.conflict.is_none());
    assert_eq!(serde_json::to_string(&receipt).unwrap(), RECEIPT);
    let event: Event = serde_json::from_str(EVENT).unwrap();
    assert_eq!(serde_json::to_string(&event).unwrap(), EVENT);
    assert_eq!(
        digest(
            "wholepact:authority-append:v2",
            &(&receipt.record.expected_head, &event)
        )
        .unwrap(),
        "93dabc1df0bc4fb6ab2aec208b687181e9a7dfa763596f38026fc929e45587d3"
    );
    let request: crate::protocol::WireRequest = serde_json::from_str(REQUEST).unwrap();
    assert_eq!(serde_json::to_string(&request).unwrap(), REQUEST);
}
