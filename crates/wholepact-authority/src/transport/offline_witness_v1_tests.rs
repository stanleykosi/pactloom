//! Local synthetic qualification: real maintained mTLS/exporter/framing, pinned
//! HPKE and encrypted SQLite owners. No socket orchestration, native consent,
//! wallet, transaction proof/signature or financial activation is exercised.
use super::*;
use crate::offline::{OfflineEnrollmentPolicy, ReserveOfflineAuthorization};
use crate::offline_witness_transport_v1 as mail;
use std::{os::unix::fs::PermissionsExt, path::Path};
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
#[path = "offline_witness_v1_test_tls.rs"]
mod tls;
use tls::*;

fn random() -> [u8; 32] {
    let mut value = [0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut value).unwrap();
    value
}
fn database_key() -> DatabaseKey {
    DatabaseKey::from_bytes(random())
}
fn clock() -> mail::Timestamp {
    mail::Timestamp::from_unix_seconds((now_ms().unwrap() / 1000) as i64).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn exporter(connection: &ClientConnection) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        connection
            .export_keying_material([0u8; 32], crate::session::EXPORTER_LABEL, None)
            .unwrap(),
    )
}
struct Channel {
    client: ClientConnection,
    server: ServerConnection,
    key: Zeroizing<[u8; 32]>,
    peer: String,
}
impl Channel {
    fn new(client: &ClientTls, server: &ServerTls) -> Self {
        let (client, server) = connections(client, server);
        let key = exporter(&client);
        let server_key = Zeroizing::new(
            server
                .export_keying_material([0u8; 32], crate::session::EXPORTER_LABEL, None)
                .unwrap(),
        );
        assert!(*key == *server_key);
        let peer = certificate_digest(&server.peer_certificates().unwrap()[0]);
        Self {
            client,
            server,
            key,
            peer,
        }
    }
    fn request(&mut self, request: &WireRequest) -> WireRequest {
        let mut frame = Vec::new();
        write_frame(&mut frame, request).unwrap();
        let mut received = Vec::new();
        for chunk in frame.chunks(4096) {
            self.client.writer().write_all(chunk).unwrap();
            pump(&mut self.client, &mut self.server).unwrap();
            drain_available(&mut self.server.reader(), &mut received);
        }
        assert_eq!(received, frame);
        read_frame(&mut std::io::Cursor::new(received)).unwrap()
    }
    fn response(&mut self, response: &WireResponse) -> WireResponse {
        let mut frame = Vec::new();
        write_frame(&mut frame, response).unwrap();
        let mut received = Vec::new();
        for chunk in frame.chunks(4096) {
            self.server.writer().write_all(chunk).unwrap();
            pump(&mut self.client, &mut self.server).unwrap();
            drain_available(&mut self.client.reader(), &mut received);
        }
        assert_eq!(received, frame);
        read_frame(&mut std::io::Cursor::new(received)).unwrap()
    }
    fn mutate(
        &mut self,
        server: &AuthorityServer,
        mutation: AuthorityMutation,
    ) -> Result<MutationResult> {
        let WireRequest::Mutate {
            mutation,
            session_proof,
        } = self.request(&WireRequest::Mutate {
            mutation: Box::new(mutation),
            session_proof: None,
        })
        else {
            panic!("mutation frame")
        };
        let result = server.journal.mutate_on_channel(
            &self.peer,
            *mutation,
            session_proof,
            &self.key,
            &server.tls.certificate_digest,
            now_ms()?,
        )?;
        let WireResponse::Mutation(result) = self.response(&WireResponse::Mutation(result)) else {
            panic!("mutation result")
        };
        Ok(result)
    }
}
fn drain_available(reader: &mut impl Read, received: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => received.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("synthetic TLS plaintext read failed: {error}"),
        }
        assert!(received.len() <= MAX_FRAME_BYTES + 4);
    }
}
struct Fixture {
    // Field order drops all connections and keys before deleting the directory.
    server: AuthorityServer,
    tls: TlsFixture,
    request: ReserveOfflineAuthorization,
    offline: OfflineEnrollmentPolicy,
    signer: mail::TransportSecret,
    witness_public: mail::TransportPublicKey,
    template: OfflineAdmissionExportPlan,
    session: WriterSessionReceipt,
    session_key: Zeroizing<[u8; 32]>,
    journal_key: DatabaseKey,
    inbox_key: DatabaseKey,
    outbox_key: DatabaseKey,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let tls = tls_fixture();
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let (mut request, mut account, mut offline) = crate::offline::tests::fixture();
        let now = now_ms().unwrap();
        let signer = mail::TransportSecret::from_bytes(random()).unwrap();
        let witness_key = Zeroizing::new(random());
        let witness = mail::TransportSecret::from_bytes(*witness_key).unwrap();
        let witness_public = witness.public_key().unwrap();
        let key_path = dir.path().join("witness.key");
        std::fs::write(&key_path, witness_key.as_slice()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        account.owner_certificate_digest = tls.owner.client_certificate.clone();
        account.initial_writer_certificate_digest = tls.writer.clone();
        account.policy_expires_at_ms = now + 120_000;
        offline.witness_certificate_digest = tls.server.certificate_digest.clone();
        offline.witness_transport_key_digest = witness_public.fingerprint();
        offline.offline_signer_key_digest = signer.public_key().unwrap().fingerprint();
        offline.valid_from_ms = now - 10_000;
        offline.expires_at_ms = now + 100_000;
        request.intent.terms.offline_policy_digest = offline.policy_digest().unwrap();
        request.intent.terms.offline_signer_key_digest = offline.offline_signer_key_digest.clone();
        request.intent.terms.snapshot.observed_at_ms = now - 2000;
        request.requested_at_ms = (now / 1000 - 1) * 1000;
        request.admission_expires_at_ms = (now / 1000 + 40) * 1000;
        let journal_key = database_key();
        let inbox_key = database_key();
        let outbox_key = database_key();
        let journal = Arc::new(
            AuthorityJournal::create_encrypted(
                &dir.path().join("journal.db"),
                &journal_key,
                account,
            )
            .unwrap(),
        );
        let mut server = AuthorityServer::new(journal, tls.server.clone());
        let mut owner = Channel::new(&tls.owner, &tls.server);
        let initial = server
            .journal
            .snapshot(
                &owner.peer,
                &offline.account_id,
                &offline.network_profile_id,
            )
            .unwrap();
        let enrolled = owner
            .mutate(
                &server,
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    operation_id: "enroll-offline".into(),
                    account_id: offline.account_id.clone(),
                    network_profile_id: offline.network_profile_id.clone(),
                    writer_epoch: initial.writer_epoch,
                    expected_head: initial.head,
                    control: OwnerControl::EnrollOfflinePolicy {
                        policy: offline.clone(),
                        expected_previous_digest: None,
                    },
                }),
            )
            .unwrap();
        let MutationResult::Controlled(enrolled) = enrolled else {
            panic!("owner enrollment")
        };
        let mut writer = Channel::new(&tls.client, &tls.server);
        let disclosure = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1".into(),
            server_name: "localhost".into(),
            witness_id: enrolled.witness_id.clone(),
            account_id: enrolled.account_id.clone(),
            network_profile_id: enrolled.network_profile_id.clone(),
            policy_digest: enrolled.policy_digest.clone(),
            pinned_server_certificate_digest: tls.server.certificate_digest.clone(),
        };
        let pending = writer
            .mutate(
                &server,
                AuthorityMutation::AcquireWriter(AcquireWriterRequest {
                    operation_id: "acquire-writer".into(),
                    account_id: enrolled.account_id.clone(),
                    network_profile_id: enrolled.network_profile_id.clone(),
                    writer_epoch: enrolled.writer_epoch,
                    expected_head: enrolled.head.clone(),
                    reconciled_history_digest: crate::session::history_digest(&enrolled).unwrap(),
                    session_id: crate::session::session_id(&writer.key),
                    disclosure,
                }),
            )
            .unwrap();
        let MutationResult::WriterPending(session) = pending else {
            panic!("pending actual writer")
        };
        let active = owner
            .mutate(
                &server,
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    operation_id: "activate-writer".into(),
                    account_id: enrolled.account_id,
                    network_profile_id: enrolled.network_profile_id,
                    writer_epoch: session.writer_epoch,
                    expected_head: session.acquired_head.clone(),
                    control: OwnerControl::ActivateWriter {
                        session_id: session.session_id.clone(),
                    },
                }),
            )
            .unwrap();
        let MutationResult::Controlled(active) = active else {
            panic!("owner activation")
        };
        request.expected_head = active.head;
        request.validate().unwrap();
        let template = OfflineAdmissionExportPlan {
            message_id: hex::encode(&random()[..16]),
            sequence: 0,
            issued_at_unix_seconds: (now / 1000) as i64,
            expires_at_unix_seconds: (now / 1000 + 39) as i64,
            purpose: "Return this exact pre-reserved admission".into(),
            persistence_warning: "The recipient may retain the original ciphertext".into(),
            sender_id: format!("offline-admission:{}", offline.policy_digest().unwrap()),
            recipient_id: format!("offline-admission:{}", offline.offline_signer_key_digest),
            sender_key_fingerprint: witness_public.fingerprint(),
            recipient_key_fingerprint: offline.offline_signer_key_digest.clone(),
        };
        server = server
            .with_offline_witness_v1(OfflineWitnessConfigurationV1 {
                expected_offline_policy_digest: offline.policy_digest().unwrap(),
                witness_transport_key_file: key_path,
                offline_signer_public_key: *signer.public_key().unwrap().as_bytes(),
                intent_profile: OfflineWitnessIntentProfileV1::Independent,
                encrypted_inbox: create_encrypted(dir.path().join("inbox.db"), &inbox_key).unwrap(),
                encrypted_outbox: create_encrypted(dir.path().join("outbox.db"), &outbox_key)
                    .unwrap(),
            })
            .unwrap();
        Self {
            server,
            tls,
            request,
            offline,
            signer,
            witness_public,
            template,
            session,
            session_key: writer.key,
            journal_key,
            inbox_key,
            outbox_key,
            dir,
        }
    }
    fn envelope(
        &self,
        request: &ReserveOfflineAuthorization,
        fields: Option<Vec<mail::DisclosureField>>,
        sender: &mail::TransportSecret,
    ) -> mail::EncryptedEnvelope {
        let terms = &request.intent.terms;
        let export = mail::ExportRequest {
            context: mail::MessageContext {
                network_profile_id: terms.network_profile_id.clone(),
                agreement_id: terms.agreement_id.clone(),
                proposal_id: terms.proposal_id.clone(),
                proposal_revision: terms.proposal_revision,
                sender_id: format!("offline-intent:{}", terms.offline_signer_key_digest),
                recipient_id: format!("offline-intent:{}", terms.offline_policy_digest),
                artifact_kind: mail::ArtifactKind::OfflineReservationIntent,
            },
            order: mail::MessageOrder {
                message_id: hex::encode(&random()[..16]),
                sequence: 1,
                issued_at: clock(),
                expires_at: mail::Timestamp::from_unix_seconds(
                    self.template.expires_at_unix_seconds,
                )
                .unwrap(),
            },
            purpose: "Authenticate the exact original offline reservation".into(),
            persistence_warning: "The witness retains the original encrypted intent".into(),
        };
        let fields = fields.unwrap_or_else(|| {
            vec![
                mail::DisclosureField::new(
                    "offline-reservation-intent-v1",
                    encode(&request.intent).unwrap().to_vec(),
                )
                .unwrap(),
            ]
        });
        let prepared = mail::prepare_export(
            export,
            fields,
            &sender.public_key().unwrap(),
            &self.witness_public,
            &clock(),
        )
        .unwrap();
        let digest = prepared.preview().digest().unwrap();
        // cfg(test) synthetic sender only: no production issuer/native owner is constructed.
        prepared.seal_qualified(sender, &digest, &clock()).unwrap()
    }
    fn wire(
        &self,
        request: ReserveOfflineAuthorization,
        envelope: &mail::EncryptedEnvelope,
        channel: &Channel,
    ) -> OfflineWitnessRequestV1 {
        let mut wire = OfflineWitnessRequestV1 {
            request,
            original_envelope_hex: hex::encode(envelope.as_bytes()),
            export_template: self.template.clone(),
            proof: protocol::WriterSessionProof {
                session_id: String::new(),
                tag: String::new(),
            },
        };
        wire.proof = crate::session::proof(
            &self.session_key,
            (
                &self.session.session_id,
                &self.session.disclosure,
                self.session.writer_epoch,
            ),
            &channel.key,
            &AuthorityMutation::ReserveOfflineAuthorization(Box::new(wire.record().unwrap())),
        )
        .unwrap();
        wire
    }
    fn submit(
        &self,
        wire: OfflineWitnessRequestV1,
        channel: &mut Channel,
    ) -> Result<OfflineWitnessDeliveryBodyV1> {
        let WireRequest::SubmitOfflineIntentV1(wire) =
            channel.request(&WireRequest::SubmitOfflineIntentV1(Box::new(wire)))
        else {
            panic!("offline frame")
        };
        let response =
            self.server
                .serve_offline_intent_v1(&channel.peer, &channel.key, &wire, deadline())?;
        let WireResponse::OfflineAdmissionDeliveryV1(body) = channel.response(&response) else {
            panic!("delivery frame")
        };
        body.validate()?;
        Ok(*body)
    }
    fn control(&self, operation: &str, control: OwnerControl) {
        let mut owner = Channel::new(&self.tls.owner, &self.tls.server);
        let snapshot = self.snapshot();
        owner
            .mutate(
                &self.server,
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    operation_id: operation.into(),
                    account_id: snapshot.account_id,
                    network_profile_id: snapshot.network_profile_id,
                    writer_epoch: snapshot.writer_epoch,
                    expected_head: snapshot.head,
                    control,
                }),
            )
            .unwrap();
    }
    fn snapshot(&self) -> AccountSnapshot {
        self.server
            .journal
            .snapshot(
                &self.tls.writer,
                &self.offline.account_id,
                &self.offline.network_profile_id,
            )
            .unwrap()
    }
    fn configuration(&self, root: &Path) -> OfflineWitnessConfigurationV1 {
        OfflineWitnessConfigurationV1 {
            expected_offline_policy_digest: self.offline.policy_digest().unwrap(),
            witness_transport_key_file: root.join("witness.key"),
            offline_signer_public_key: *self.signer.public_key().unwrap().as_bytes(),
            intent_profile: OfflineWitnessIntentProfileV1::Independent,
            encrypted_inbox: open_encrypted(root.join("inbox.db"), &self.inbox_key).unwrap(),
            encrypted_outbox: open_encrypted(root.join("outbox.db"), &self.outbox_key).unwrap(),
        }
    }
}

#[test]
fn actual_owner_writer_hpke_journal_delivery_and_restart_recover_exact_original() {
    let mut f = Fixture::new();
    let envelope = f.envelope(&f.request, None, &f.signer);
    let mut channel = Channel::new(&f.tls.client, &f.tls.server);
    let wire = f.wire(f.request.clone(), &envelope, &channel);
    let body = f.submit(wire, &mut channel).unwrap();
    assert!(!body.recovered_original);
    assert_eq!(body.export_plan.sequence, 1);
    assert_eq!(f.snapshot().outstanding_debit_zatoshis, 70);
    let first_head = f.snapshot().head;
    let request_digest = f.request.request_digest().unwrap();
    let expected = mail::OfflineMinimalAdmissionExpected {
        intent: &f.request.intent,
        offline_policy: &f.offline,
        witness_account_policy_digest: &body.witness_account_policy_digest,
        original_operation_id: &f.request.operation_id,
        original_request_digest: &request_digest,
        original_export_plan: &body.export_plan,
        expected_committed_head: &body.committed_head,
        admission_expires_at_ms: f.request.admission_expires_at_ms,
    };
    let mut inbox = mail::SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(f.dir.path().join("recipient.db"), &database_key()).unwrap(),
    )
    .unwrap();
    let artifact = mail::EncryptedEnvelope::from_bytes(body.validate().unwrap()).unwrap();
    let received = mail::open_offline_minimal_admission(
        &artifact,
        &f.signer,
        &f.witness_public,
        &expected,
        &clock(),
        &mut inbox,
    )
    .unwrap();
    assert_eq!(
        received.statement().review_package_digest,
        f.request.intent.terms.review_package_digest
    );
    let mut retry_channel = Channel::new(&f.tls.client, &f.tls.server);
    let retry = f
        .submit(
            f.wire(f.request.clone(), &envelope, &retry_channel),
            &mut retry_channel,
        )
        .unwrap();
    assert!(retry.recovered_original);
    assert_eq!(body.ciphertext_hex, retry.ciphertext_hex);
    assert!(body.export_plan == retry.export_plan && f.snapshot().head == first_head);
    // Reopen the encrypted databases with the same temporary keys and the real
    // retained owner policy. This does not restore a writer lease or reseal.
    let replacement = AuthorityServer::new(
        Arc::new(
            AuthorityJournal::open_encrypted(
                &f.dir.path().join("journal.db"),
                &f.journal_key,
                &f.offline.account_id,
                &f.offline.network_profile_id,
            )
            .unwrap(),
        ),
        f.tls.server.clone(),
    );
    let old = std::mem::replace(&mut f.server, replacement);
    drop(old);
    let configuration = f.configuration(f.dir.path());
    f.server = f.server.with_offline_witness_v1(configuration).unwrap();
    f.control("pause-after-emission", OwnerControl::Pause);
    let lookup = OfflineAdmissionDeliveryLookupV1::from_request(&f.request).unwrap();
    let recovered = f
        .server
        .serve_offline_delivery_recovery_v1(&f.tls.writer, &lookup, deadline())
        .unwrap();
    let WireResponse::OfflineAdmissionDeliveryV1(recovered) = recovered else {
        panic!("historical recovery")
    };
    assert!(recovered.recovered_original && recovered.ciphertext_hex == body.ciphertext_hex);
    assert_eq!(f.snapshot().outstanding_debit_zatoshis, 70);
    let mut changed = lookup;
    changed.original_request_digest = hex::encode(random());
    assert!(
        f.server
            .serve_offline_delivery_recovery_v1(&f.tls.writer, &changed, deadline())
            .is_err()
    );
    assert!(
        f.server
            .serve_offline_delivery_recovery_v1(&hex::encode(random()), &changed, deadline())
            .is_err()
    );
}

#[test]
fn exporter_substitution_wrong_hpke_sender_and_changed_exact_payload_cannot_reserve() {
    let f = Fixture::new();
    let envelope = f.envelope(&f.request, None, &f.signer);
    let first = Channel::new(&f.tls.client, &f.tls.server);
    let mut next = Channel::new(&f.tls.client, &f.tls.server);
    assert!(
        f.submit(f.wire(f.request.clone(), &envelope, &first), &mut next)
            .is_err()
    );
    let rogue = mail::TransportSecret::from_bytes(random()).unwrap();
    let wrong = f.envelope(&f.request, None, &rogue);
    assert!(
        f.submit(f.wire(f.request.clone(), &wrong, &next), &mut next)
            .is_err()
    );
    // The first prepared ciphertext remains fixed even when authentication fails.
    let mut changed = f.request.intent.clone();
    changed.terms.review_package_digest = hex::encode(random());
    let changed = f.envelope(
        &f.request,
        Some(vec![
            mail::DisclosureField::new(
                "offline-reservation-intent-v1",
                encode(&changed).unwrap().to_vec(),
            )
            .unwrap(),
        ]),
        &f.signer,
    );
    assert!(
        f.submit(f.wire(f.request.clone(), &changed, &next), &mut next)
            .is_err()
    );
    assert_eq!(f.snapshot().outstanding_debit_zatoshis, 0);
}

#[test]
fn missing_committed_ciphertext_is_uncertain_and_never_resealed() {
    let f = Fixture::new();
    let envelope = f.envelope(&f.request, None, &f.signer);
    let mut channel = Channel::new(&f.tls.client, &f.tls.server);
    f.submit(f.wire(f.request.clone(), &envelope, &channel), &mut channel)
        .unwrap();
    let outbox = open_encrypted(f.dir.path().join("outbox.db"), &f.outbox_key).unwrap();
    assert_eq!(
        outbox
            .connection()
            .execute("DELETE FROM outbox", [])
            .unwrap(),
        1
    );
    let lookup = OfflineAdmissionDeliveryLookupV1::from_request(&f.request).unwrap();
    assert!(matches!(
        f.server
            .serve_offline_delivery_recovery_v1(&f.tls.writer, &lookup, deadline()),
        Err(AuthorityError::Uncertain)
    ));
    let mut next = Channel::new(&f.tls.client, &f.tls.server);
    assert!(matches!(
        f.submit(f.wire(f.request.clone(), &envelope, &next), &mut next),
        Err(AuthorityError::Uncertain)
    ));
    assert_eq!(
        outbox
            .connection()
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(f.snapshot().outstanding_debit_zatoshis, 70);
}

#[test]
fn named_profile_requires_exact_selected_header_and_never_changes_policy_digest() {
    for altered in 0..5 {
        let mut f = Fixture::new();
        let setup = hex::encode(random());
        let mut configuration = f.configuration(f.dir.path());
        configuration.intent_profile = OfflineWitnessIntentProfileV1::NamedVerifier {
            owner_setup_digest: setup.clone(),
        };
        f.server = AuthorityServer::new(Arc::clone(&f.server.journal), f.tls.server.clone())
            .with_offline_witness_v1(configuration)
            .unwrap();
        let mut terms = serde_json::to_value(&f.request.intent.terms).unwrap();
        terms
            .as_object_mut()
            .unwrap()
            .remove("review_package_digest");
        let mut header = mail::NamedReviewBindingV1 {
            schema_version: 1,
            disclosure_profile: mail::NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
            owner_setup_digest: setup,
            assertion_package_digest: hex::encode(random()),
            original_context_digest: digest("wholepact:named-verifier-original-context:v1", &terms)
                .unwrap(),
        };
        f.request.intent.terms.review_package_digest = header.review_package_digest().unwrap();
        match altered {
            1 => header.owner_setup_digest = hex::encode(random()),
            2 => header.original_context_digest = hex::encode(random()),
            3 => header.assertion_package_digest = hex::encode(random()),
            _ => {}
        }
        let mut fields = vec![
            mail::DisclosureField::new(
                "offline-reservation-intent-v1",
                encode(&f.request.intent).unwrap().to_vec(),
            )
            .unwrap(),
        ];
        if altered != 4 {
            fields.push(
                mail::DisclosureField::new(
                    mail::NAMED_REVIEW_BINDING_FIELD_V1,
                    header.canonical_bytes().unwrap(),
                )
                .unwrap(),
            );
        }
        let envelope = f.envelope(&f.request, Some(fields), &f.signer);
        let mut channel = Channel::new(&f.tls.client, &f.tls.server);
        let result = f.submit(f.wire(f.request.clone(), &envelope, &channel), &mut channel);
        assert_eq!(result.is_ok(), altered == 0);
        assert_eq!(
            f.snapshot().outstanding_debit_zatoshis,
            if altered == 0 { 70 } else { 0 }
        );
        assert_eq!(
            f.request.intent.terms.offline_policy_digest,
            f.offline.policy_digest().unwrap()
        );
    }
}

#[test]
fn independent_profile_rejects_named_extra_fields_and_exact_intent_substitution() {
    for named_extra in [false, true] {
        let f = Fixture::new();
        let mut intent = f.request.intent.clone();
        if !named_extra {
            intent.terms.review_package_digest = hex::encode(random());
        }
        let mut fields = vec![
            mail::DisclosureField::new(
                "offline-reservation-intent-v1",
                encode(&intent).unwrap().to_vec(),
            )
            .unwrap(),
        ];
        if named_extra {
            fields.push(
                mail::DisclosureField::new(mail::NAMED_REVIEW_BINDING_FIELD_V1, b"{}".to_vec())
                    .unwrap(),
            );
        }
        let envelope = f.envelope(&f.request, Some(fields), &f.signer);
        let mut channel = Channel::new(&f.tls.client, &f.tls.server);
        assert!(
            f.submit(f.wire(f.request.clone(), &envelope, &channel), &mut channel)
                .is_err()
        );
        assert_eq!(f.snapshot().outstanding_debit_zatoshis, 0);
    }
}

#[test]
fn configuration_rejects_substituted_policy_certificate_keys_and_same_database() {
    let f = Fixture::new();
    for altered in 0..5 {
        let mut configuration = f.configuration(f.dir.path());
        let mut tls = f.tls.server.clone();
        match altered {
            0 => configuration.expected_offline_policy_digest = hex::encode(random()),
            1 => {
                configuration.offline_signer_public_key =
                    *mail::TransportSecret::from_bytes(random())
                        .unwrap()
                        .public_key()
                        .unwrap()
                        .as_bytes()
            }
            2 => tls.certificate_digest = hex::encode(random()),
            3 => {
                configuration.encrypted_outbox =
                    open_encrypted(f.dir.path().join("inbox.db"), &f.inbox_key).unwrap()
            }
            _ => {
                let path = f.dir.path().join("other-witness.key");
                std::fs::write(&path, random()).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                configuration.witness_transport_key_file = path;
            }
        }
        assert!(
            AuthorityServer::new(Arc::clone(&f.server.journal), tls)
                .with_offline_witness_v1(configuration)
                .is_err()
        );
    }
    assert_eq!(f.snapshot().outstanding_debit_zatoshis, 0);
}

#[test]
fn policy_pause_and_expired_original_cannot_start_new_admission() {
    let f = Fixture::new();
    f.control(
        "pause-offline",
        OwnerControl::SetOfflinePolicyStatus {
            enrollment_ref: f.offline.enrollment_ref.clone(),
            policy_digest: f.offline.policy_digest().unwrap(),
            status: OfflineEnrollmentStatus::Paused,
        },
    );
    let envelope = f.envelope(&f.request, None, &f.signer);
    let mut channel = Channel::new(&f.tls.client, &f.tls.server);
    assert!(
        f.submit(f.wire(f.request.clone(), &envelope, &channel), &mut channel)
            .is_err()
    );
    assert_eq!(f.snapshot().outstanding_debit_zatoshis, 0);
    let now = now_ms().unwrap();
    assert!(CurrentOfflineWitnessWindowV1::capture(now - 100, now, deadline()).is_err());
    assert!(
        CurrentOfflineWitnessWindowV1::capture(now + 10_000, now + 20_000, deadline()).is_err()
    );
    let window = CurrentOfflineWitnessWindowV1::capture(
        now - 100,
        now + 20_000,
        Instant::now() + Duration::from_millis(1),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(3));
    assert!(window.check().is_err());
}

#[test]
fn blocked_outbox_transaction_cannot_seal_after_original_monotonic_ceiling() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let key = database_key();
    let path = dir.path().join("outbox.db");
    let mut outbox =
        mail::SqliteOutbox::from_encrypted_connection(create_encrypted(&path, &key).unwrap())
            .unwrap();
    let lock = open_encrypted(&path, &key).unwrap();
    let sender = mail::TransportSecret::from_bytes(random()).unwrap();
    let recipient = mail::TransportSecret::from_bytes(random())
        .unwrap()
        .public_key()
        .unwrap();
    let now = clock();
    let request = mail::ExportRequest {
        context: mail::MessageContext {
            network_profile_id: "synthetic-testnet".into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: "synthetic-witness".into(),
            recipient_id: "synthetic-recipient".into(),
            artifact_kind: mail::ArtifactKind::OfflineMinimalAuthorityAdmission,
        },
        order: mail::MessageOrder {
            message_id: hex::encode(&random()[..16]),
            sequence: 1,
            issued_at: now.clone(),
            expires_at: mail::Timestamp::from_unix_seconds(now.unix_seconds() + 60).unwrap(),
        },
        purpose: "Negative current-boundary fixture".into(),
        persistence_warning: "No ciphertext should exist".into(),
    };
    let prepared = mail::prepare_export(
        request,
        vec![mail::DisclosureField::new("negative-test", b"inert".to_vec()).unwrap()],
        &sender.public_key().unwrap(),
        &recipient,
        &now,
    )
    .unwrap();
    let approved = prepared.preview().digest().unwrap();
    lock.connection().execute_batch("BEGIN IMMEDIATE").unwrap();
    let limit = Instant::now() + Duration::from_millis(60);
    let first_wall = now_ms().unwrap();
    let joined = std::thread::spawn(move || {
        outbox.enqueue_validated_before(prepared, &sender, &approved, &now, limit, first_wall)
    });
    std::thread::sleep(Duration::from_millis(100));
    lock.connection().execute_batch("ROLLBACK").unwrap();
    assert!(matches!(
        joined.join().unwrap(),
        Err(mail::TransportError::InvalidTime)
    ));
    assert_eq!(
        lock.connection()
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
