//! Joined synthetic qualification: real proof, ephemeral native decision fixtures,
//! actual owner-mTLS enrollment/activation, HPKE request, complete witness replay,
//! challenge clock, maintained signatures, immutable result and exact file return.
//! This does not qualify attended input, live chain validity or financial use.
use super::*;
use std::{
    net::TcpListener,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use wholepact_authority::*;
use wholepact_storage_security::{DatabaseKey, create_encrypted};
mod tls;
use tls::Tls;
struct Witness {
    writer: AuthorityClient,
    owner: AuthorityClient,
    server: Arc<RwLock<Option<AuthorityServer>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Witness {
    fn new(f: &Fixture, tls: &Tls, incoming: &Incoming) -> Self {
        let t = &incoming.original.terms;
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: incoming.policy.witness_id.clone(),
            account_id: t.account_id.clone(),
            network_profile_id: t.network_profile_id.clone(),
            owner_certificate_digest: tls.pin("owner"),
            initial_writer_certificate_digest: tls.pin("writer"),
            initial_writer_epoch: 1,
            enrollment_refs: vec![t.enrollment_ref.clone()],
            agreement_ids: vec![t.agreement_id.clone()],
            recipient_scope_digests: vec![t.recipient_scope_digest.clone()],
            aggregate_budget_zatoshis: 1_000_000_000,
            per_operation_limit_zatoshis: 1_000_000_000,
            maximum_fee_share_zatoshis: 1_000_000,
            maximum_transaction_fee_zatoshis: 1_000_000,
            maximum_permit_lifetime_ms: 600_000,
            policy_expires_at_ms: incoming.policy.expires_at_ms + 300_000,
        };
        let digest = policy.policy_digest().unwrap();
        let journal = Arc::new(
            AuthorityJournal::create_encrypted(
                &f.dir.path().join("final-witness.sqlite"),
                &DatabaseKey::from_bytes(random32()),
                policy,
            )
            .unwrap(),
        );
        let server = Arc::new(RwLock::new(Some(AuthorityServer::new(
            journal,
            ServerTls::new(
                vec![tls.cert("ca")],
                vec![tls.cert("server")],
                tls.key("server"),
            )
            .unwrap(),
        ))));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let serving = server.clone();
        let worker = thread::spawn(move || {
            let mut calls = vec![];
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let server = serving.clone();
                        calls.push(thread::spawn(move || {
                            let _ = server
                                .read()
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                .serve_connection(socket);
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
            for call in calls {
                call.join().unwrap();
            }
        });
        let client = |name: &str| {
            AuthorityClient::new(
                endpoint,
                ClientTls::new(
                    "localhost".into(),
                    tls.pin("server"),
                    vec![tls.cert("ca")],
                    vec![tls.cert(name)],
                    tls.key(name),
                )
                .unwrap(),
                incoming.policy.witness_id.clone(),
                t.account_id.clone(),
                t.network_profile_id.clone(),
                digest.clone(),
            )
            .unwrap()
        };
        Self {
            writer: client("writer"),
            owner: client("owner"),
            server,
            stop,
            worker: Some(worker),
        }
    }
    fn control(&self, id: &str, control: OwnerControl) {
        let before = self.owner.snapshot().unwrap();
        self.owner
            .control(OwnerControlRequest {
                operation_id: id.into(),
                account_id: before.account_id,
                network_profile_id: before.network_profile_id,
                expected_head: before.head,
                writer_epoch: before.writer_epoch,
                control,
            })
            .unwrap();
    }
    fn configure(&self, f: &Fixture, incoming: &mut Incoming) {
        self.control(
            "final-enroll-offline",
            OwnerControl::EnrollOfflinePolicy {
                policy: incoming.policy.clone(),
                expected_previous_digest: None,
            },
        );
        let h = self.writer.reconcile_history().unwrap();
        let session = self
            .writer
            .acquire_writer(&h, "final-acquire-writer")
            .unwrap();
        self.control(
            "final-activate-writer",
            OwnerControl::ActivateWriter {
                session_id: session.session_id,
            },
        );
        incoming.original.reservation_request.expected_head = self.writer.snapshot().unwrap().head;
        incoming.original.reservation_request_digest = incoming
            .original
            .reservation_request
            .request_digest()
            .unwrap();
        incoming.original.reference = incoming.original.reference_digest().unwrap();
        use std::os::unix::fs::PermissionsExt;
        let key = f.dir.path().join("final-witness-transport.key");
        std::fs::write(&key, f.witness_secret.as_slice()).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut owner = self.server.write().unwrap();
        let server = owner.take().unwrap();
        *owner = Some(
            server
                .with_offline_witness_v1(OfflineWitnessConfigurationV1 {
                    expected_offline_policy_digest: incoming.policy.policy_digest().unwrap(),
                    witness_transport_key_file: key,
                    offline_signer_public_key: *f.profile.transport_public_key(),
                    intent_profile: OfflineWitnessIntentProfileV1::NamedVerifier {
                        owner_setup_digest: f.profile.record.original_setup_digest.clone(),
                    },
                    encrypted_inbox: create_encrypted(
                        f.dir.path().join("final-witness-inbox.sqlite"),
                        &DatabaseKey::from_bytes(random32()),
                    )
                    .unwrap(),
                    encrypted_outbox: create_encrypted(
                        f.dir.path().join("final-witness-outbox.sqlite"),
                        &DatabaseKey::from_bytes(random32()),
                    )
                    .unwrap(),
                })
                .unwrap(),
        );
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
#[test]
#[ignore = "one real proof plus ephemeral authenticated witness and native fixture; serialized release qualification"]
fn named_recipient_final_join_signs_once_retains_and_recovers_exact_return() {
    let tls = Tls::new();
    let f = Fixture::new_with_certificate(Some(tls.pin("server")));
    let mut incoming = incoming(&f);
    let witness = Witness::new(&f, &tls, &incoming);
    witness.configure(&f, &mut incoming);
    let prepared = incoming.prepare(&f).unwrap();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    let retained = prepared
        .approve(decision, &f.journal, &f.session, &f.vault, &incoming.now)
        .unwrap();
    // Before witness admission a canonical request, native intent and valid
    // verifier assertion still cannot produce final spending authority.
    let authorization = &incoming.original.terms.authorization_id;
    assert!(
        f.profile
            .prepare_final_signing(
                &f.journal,
                &f.session,
                &f.vault,
                &witness.writer,
                authorization,
                NamedRecipientOperation::new()
            )
            .is_err()
    );
    let courier = f.dir.path().join("final-original-courier.json");
    let export = retained
        .prepare_file_export(&f.journal, &f.session, &f.vault, &courier)
        .unwrap();
    let decision = recovery_test_decision(f.native(), export.digest());
    export
        .write_new_file(decision, &f.journal, &f.session, &f.vault)
        .unwrap();
    let bytes = Zeroizing::new(std::fs::read(&courier).unwrap());
    let handoff = OfflineIntentHandoffV1::parse(&bytes).unwrap();
    let delivery = witness
        .writer
        .submit_offline_intent_v1(
            handoff.request().clone(),
            &handoff.encrypted_intent().unwrap(),
            handoff.admission_export_template().clone(),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
    assert!(!delivery.ciphertext().is_empty());
    let prepared = f
        .profile
        .prepare_final_signing(
            &f.journal,
            &f.session,
            &f.vault,
            &witness.writer,
            authorization,
            NamedRecipientOperation::new(),
        )
        .unwrap();
    let other = recovery_test_authority();
    let wrong = recovery_test_decision(&other, prepared.digest());
    assert!(
        prepared
            .approve_and_sign(wrong, &f.journal, &f.session, &f.vault, &witness.writer)
            .is_err()
    );
    drop(other);
    let count: usize = f
        .journal
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM signer_named_recipient_started",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    // Cancellation remains a shared live fence after preparation, not a flag
    // serialized into final consent or reset by starting the worker.
    let operation = NamedRecipientOperation::new();
    let prepared = f
        .profile
        .prepare_final_signing(
            &f.journal,
            &f.session,
            &f.vault,
            &witness.writer,
            authorization,
            operation.clone(),
        )
        .unwrap();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    operation.revoke();
    assert!(
        prepared
            .approve_and_sign(decision, &f.journal, &f.session, &f.vault, &witness.writer)
            .is_err()
    );
    let count: usize = f
        .journal
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM signer_named_recipient_started",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let prepared = f
        .profile
        .prepare_final_signing(
            &f.journal,
            &f.session,
            &f.vault,
            &witness.writer,
            authorization,
            NamedRecipientOperation::new(),
        )
        .unwrap();
    assert!(
        prepared
            .display()
            .contains("not independent multi-owner verification")
    );
    let decision = recovery_test_decision(f.native(), prepared.digest());
    let outcome = prepared
        .approve_and_sign(decision, &f.journal, &f.session, &f.vault, &witness.writer)
        .unwrap();
    assert_eq!(outcome.authorization_id, *authorization);
    assert!(
        f.profile
            .prepare_final_signing(
                &f.journal,
                &f.session,
                &f.vault,
                &witness.writer,
                authorization,
                NamedRecipientOperation::new()
            )
            .is_err()
    );
    let before = f
        .journal
        .named_recipient_history_inventory(&f.session)
        .unwrap();
    assert_eq!(before.started.len(), 1);
    assert_eq!(before.results.len(), 1);
    let (original, started, result) = {
        let c = f.journal.connection.lock().unwrap();
        let read = |table: &str| -> String {
            c.query_row(&format!("SELECT payload FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        (
            serde_json::from_str::<NamedRecipientOriginalRecordV1>(&read(
                "signer_named_recipient_originals",
            ))
            .unwrap(),
            serde_json::from_str::<NamedRecipientStartedRecordV1>(&read(
                "signer_named_recipient_started",
            ))
            .unwrap(),
            serde_json::from_str::<NamedRecipientResultRecordV1>(&read(
                "signer_named_recipient_results",
            ))
            .unwrap(),
        )
    };
    assert_eq!(started.final_review.as_ref().unwrap().return_sequence, 1);
    assert!(result.validate(&started, &original).is_ok());
    let mut bad = result.clone();
    bad.encrypted_return.as_mut().unwrap().projection_digest = "96".repeat(32);
    assert!(bad.validate(&started, &original).is_err());
    let mut bad = result.clone();
    let returned = bad.encrypted_return.as_mut().unwrap();
    returned.envelope_hex = hex::encode(b"not a maintained encrypted envelope");
    returned.envelope_digest = super::super::super::named_recipient_records::domain_digest(
        b"wholepact.encrypted-envelope.v1\0",
        b"not a maintained encrypted envelope",
    );
    assert!(bad.validate(&started, &original).is_err());
    // Read-only maintained HPKE authentication in the private synthetic fixture.
    // No public generic import guard, replay ledger or online consumer is opened.
    use super::super::super::named_intent_transport as wire;
    let encrypted = wire::EncryptedEnvelope::from_bytes(
        hex::decode(&result.encrypted_return.as_ref().unwrap().envelope_hex).unwrap(),
    )
    .unwrap();
    let recipient = wire::TransportSecret::from_bytes(*f.return_secret).unwrap();
    let sender = wire::TransportPublicKey::from_bytes(*f.profile.transport_public_key()).unwrap();
    let t = &original.terms;
    let context = wire::MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-return:{}", t.offline_signer_key_digest),
        recipient_id: format!("offline-return:{}", t.return_recipient_key_digest),
        artifact_kind: wire::ArtifactKind::OfflineAuthorizationReturn,
    };
    let (authenticated, _) =
        wire::authenticate(&encrypted, &recipient, &sender, &context, None).unwrap();
    let signed = Zeroizing::new(hex::decode(&result.result_hex).unwrap());
    let projection = super::super::super::named_recipient_records::signature_return_projection(
        &original, &started, &signed,
    )
    .unwrap();
    assert_eq!(authenticated.preview().order.sequence, 1);
    assert_eq!(authenticated.fields().len(), 1);
    assert_eq!(authenticated.fields()[0].bytes(), projection.as_slice());
    // Revoking a separately prepared file step creates no file and never signs.
    let cancelled_path = f.dir.path().join("cancelled-return.wp");
    let operation = NamedRecipientOperation::new();
    let file = f
        .profile
        .prepare_retained_return_file(
            &f.journal,
            &f.session,
            &f.vault,
            authorization,
            &cancelled_path,
            operation.clone(),
        )
        .unwrap();
    let decision = recovery_test_decision(f.native(), file.digest());
    operation.revoke();
    assert!(
        file.write(decision, &f.journal, &f.session, &f.vault)
            .is_err()
    );
    assert!(!cancelled_path.exists());
    let path = f.dir.path().join("final-exact-return.wp");
    let file = f
        .profile
        .prepare_retained_return_file(
            &f.journal,
            &f.session,
            &f.vault,
            authorization,
            &path,
            NamedRecipientOperation::new(),
        )
        .unwrap();
    let decision = recovery_test_decision(f.native(), file.digest());
    file.write(decision, &f.journal, &f.session, &f.vault)
        .unwrap();
    let envelope = std::fs::read(&path).unwrap();
    assert_eq!(
        outcome.return_envelope_digest,
        super::super::super::named_recipient_records::domain_digest(
            b"wholepact.encrypted-envelope.v1\0",
            &envelope
        )
    );
    assert!(
        f.profile
            .prepare_retained_return_file(
                &f.journal,
                &f.session,
                &f.vault,
                authorization,
                &path,
                NamedRecipientOperation::new()
            )
            .is_err()
    );
    let second = f.dir.path().join("final-exact-return-second.wp");
    let file = f
        .profile
        .prepare_retained_return_file(
            &f.journal,
            &f.session,
            &f.vault,
            authorization,
            &second,
            NamedRecipientOperation::new(),
        )
        .unwrap();
    let decision = recovery_test_decision(f.native(), file.digest());
    file.write(decision, &f.journal, &f.session, &f.vault)
        .unwrap();
    assert_eq!(std::fs::read(second).unwrap(), envelope);
    let after = f
        .journal
        .named_recipient_history_inventory(&f.session)
        .unwrap();
    assert!(before == after);
    assert_eq!(
        witness.writer.snapshot().unwrap().outstanding_reservations,
        1
    );
}
