#![cfg(feature = "transport-workflows")]
//! Synthetic transport identities only. No live enrollment, signer or settlement.
use serde_json::json;
use sha2::{Digest, Sha256};
use wholepact_core::{AgreementDraft, IntentStatus, ParticipationIntent};
use wholepact_engine::{Access, Engine, transport_workflows::*};
use wholepact_storage_security::DatabaseKey;
use wholepact_store::Store;
use wholepact_transport::*;

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
fn now() -> Timestamp {
    Timestamp::from_unix_seconds(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    )
    .unwrap()
}
fn later(now: &Timestamp, delta: i64) -> Timestamp {
    Timestamp::from_unix_seconds(now.unix_seconds() + delta).unwrap()
}
fn actor() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: "owner".into(),
        ..Access::default()
    }
}
fn draft() -> AgreementDraft {
    serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap()
}
fn secret(byte: u8) -> TransportSecret {
    TransportSecret::from_bytes([byte; 32]).unwrap()
}
fn peer() -> TransportPublicKey {
    secret(11).public_key().unwrap()
}
fn organizer() -> TransportPublicKey {
    secret(22).public_key().unwrap()
}
fn grant(now: &Timestamp) -> TransportPeerGrantRequest {
    TransportPeerGrantRequest {
        grant_id: "grant-one".into(),
        participant_id: "participant-one".into(),
        sender_key_fingerprint: peer().fingerprint(),
        recipient_id: draft().organizer_identity,
        recipient_key_fingerprint: organizer().fingerprint(),
        allow_intent: true,
        allow_withdrawal: true,
        expires_at: later(now, 3600),
    }
}
fn intent() -> ParticipationIntent {
    serde_json::from_value(json!({"intent_id":"intent-one","agreement_id":draft().agreement_id,"participant_id":"participant-one","desired_contribution":"1000000000","maximum_net_debit":"1000010000","fee_cap":"10000","conditions":[],"valid_until":null,"status":"active"})).unwrap()
}
fn context(kind: ArtifactKind, revision: u64) -> MessageContext {
    MessageContext {
        network_profile_id: draft().network_profile_id,
        agreement_id: draft().agreement_id,
        proposal_id: NONBINDING_INTENT_CONTEXT.into(),
        proposal_revision: revision,
        sender_id: "participant-one".into(),
        recipient_id: draft().organizer_identity,
        artifact_kind: kind,
    }
}
fn request(kind: ArtifactKind, revision: u64, sequence: u64, now: &Timestamp) -> ExportRequest {
    ExportRequest {
        context: context(kind, revision),
        order: MessageOrder {
            message_id: format!("{sequence:032x}"),
            sequence,
            issued_at: now.clone(),
            expires_at: later(now, 600),
        },
        purpose: "Synthetic nonbinding participation".into(),
        persistence_warning: "The recipient can retain this selected disclosure.".into(),
    }
}
fn prepared_intent(revision: u64, sequence: u64, now: &Timestamp) -> PreparedExport {
    prepare_intent_message(
        request(ArtifactKind::ParticipationIntent, revision, sequence, now),
        TransportIntent {
            schema_version: 1,
            expected_agreement_revision: revision,
            intent: intent(),
        },
        &peer(),
        &organizer(),
        now,
    )
    .unwrap()
}
fn receive(
    prepared: PreparedExport,
    inbox: &mut SqliteReplayLedger,
    now: &Timestamp,
    sender: &TransportSecret,
) -> ReceivedArtifact {
    let expected = prepared.preview().context.clone();
    let approved = prepared.preview().digest().unwrap();
    let encrypted = prepared.seal(sender, &approved, now).unwrap();
    open_envelope(
        &encrypted,
        &secret(22),
        &sender.public_key().unwrap(),
        &expected,
        now,
        inbox,
    )
    .unwrap()
}
fn setup(engine: &Engine, now: &Timestamp) {
    engine
        .create(&actor(), "create-agreement-0001", draft())
        .unwrap();
    engine
        .grant_transport_peer(
            &actor(),
            "grant-peer-command-0001",
            &draft().agreement_id,
            1,
            grant(now),
        )
        .unwrap();
}

#[test]
fn encrypted_engine_outbox_inbox_intent_withdrawal_and_restart_are_nonbinding() {
    let dir = private_dir();
    let path = dir.path().join("engine.db");
    let key = DatabaseKey::from_bytes([91; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let now = now();
    setup(&engine, &now);
    let mut outbox = SqliteOutbox::open(dir.path().join("outbox.db")).unwrap();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let prepared = prepared_intent(2, 1, &now);
    let approved = prepared.preview().digest().unwrap();
    let queued = outbox
        .enqueue(prepared, &secret(11), &approved, &now)
        .unwrap();
    let received = open_envelope(
        queued.envelope(),
        &secret(22),
        &peer(),
        &context(ArtifactKind::ParticipationIntent, 2),
        &now,
        &mut inbox,
    )
    .unwrap();
    let imported = engine
        .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
        .unwrap();
    assert_eq!(imported.agreement.revision, 3);
    assert_eq!(imported.agreement.intents.len(), 1);
    assert_eq!(imported.agreement.authorization_exposure, "unknown");
    assert_eq!(imported.agreement.chain_observation, "unknown");
    let replay = engine
        .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, imported.operation_id);
    let prepared = prepare_withdrawal_message(
        request(ArtifactKind::IntentWithdrawal, 3, 2, &now),
        TransportIntentWithdrawal {
            schema_version: 1,
            expected_agreement_revision: 3,
            participant_id: "participant-one".into(),
            intent_id: "intent-one".into(),
        },
        &peer(),
        &organizer(),
        &now,
    )
    .unwrap();
    let approved = prepared.preview().digest().unwrap();
    let queued = outbox
        .enqueue(prepared, &secret(11), &approved, &now)
        .unwrap();
    let withdrawal = open_envelope(
        queued.envelope(),
        &secret(22),
        &peer(),
        &context(ArtifactKind::IntentWithdrawal, 3),
        &now,
        &mut inbox,
    )
    .unwrap();
    let result = engine
        .import_nonbinding_transport(&actor(), &mut inbox, &withdrawal, &now)
        .unwrap();
    assert_eq!(result.agreement.revision, 4);
    assert_eq!(result.agreement.intents[0].status, IntentStatus::Withdrawn);
    assert_eq!(
        engine
            .withdraw(
                &actor(),
                "owner-cannot-withdraw-remote",
                &draft().agreement_id,
                "intent-one",
                4
            )
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    drop(engine);
    let engine = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    let replay = engine
        .import_nonbinding_transport(&actor(), &mut inbox, &withdrawal, &later(&now, 700))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, result.operation_id);
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        4
    );
    assert!(
        inbox
            .pending_domain_sequences(
                &context(ArtifactKind::ParticipationIntent, 2),
                "engine-nonbinding-intents-v1"
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn owner_prepares_exact_read_only_invitation_without_enrolling_recipient() {
    let engine = Engine::in_memory().unwrap();
    engine
        .create(&actor(), "create-agreement-0001", draft())
        .unwrap();
    let now = now();
    let invitation = PrivateInvitation {
        schema_version: 1,
        invitation_id: "01".repeat(16),
        organizer_key_fingerprint: organizer().fingerprint(),
        invited_participant_id: "participant-one".into(),
        agreement_manifest_digest: engine
            .invitation_agreement_digest(&actor(), &draft().agreement_id)
            .unwrap(),
        offered_roles: vec![InvitationRole::Contributor],
        purpose: draft().purpose,
        recipient_summary: "Synthetic beneficiary instructions remain unverified.".into(),
        fee_summary: "Pro-rata fees will require exact later approval.".into(),
        visibility_summary: "Invitation review only; no wallet access.".into(),
        coordination_deadline: later(&now, 1200),
    };
    let mut transport = request(ArtifactKind::Invitation, 1, 1, &now);
    transport.context.sender_id = draft().organizer_identity;
    transport.context.recipient_id = "participant-one".into();
    let prepared = engine
        .prepare_private_invitation(
            &actor(),
            InvitationExportRequest {
                expected_agreement_revision: 1,
                transport,
                invitation: invitation.clone(),
            },
            &organizer(),
            &peer(),
            &now,
        )
        .unwrap();
    let expected = prepared.preview().context.clone();
    let approved = prepared.preview().digest().unwrap();
    let file = prepared.seal(&secret(22), &approved, &now).unwrap();
    let dir = private_dir();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = open_envelope(
        &file,
        &secret(11),
        &organizer(),
        &expected,
        &now,
        &mut inbox,
    )
    .unwrap();
    let review = review_invitation(&received).unwrap();
    assert!(review.is_read_only());
    assert!(!review.authorization_allowed());
    assert!(
        engine
            .transport_peer_grants(&actor(), &draft().agreement_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        2
    );
    let mut transport = request(ArtifactKind::Invitation, 1, 2, &now);
    transport.context.sender_id = draft().organizer_identity;
    transport.context.recipient_id = "participant-one".into();
    let mut altered = invitation;
    altered.agreement_manifest_digest = "ff".repeat(32);
    assert_eq!(
        engine
            .prepare_private_invitation(
                &actor(),
                InvitationExportRequest {
                    expected_agreement_revision: 1,
                    transport,
                    invitation: altered
                },
                &organizer(),
                &peer(),
                &now
            )
            .err()
            .unwrap()
            .code,
        "INVALID_TERMS"
    );
}

#[test]
fn no_enrollment_wrong_peer_and_wrong_local_owner_fail_before_domain_mutation() {
    let engine = Engine::in_memory().unwrap();
    engine
        .create(&actor(), "create-agreement-0001", draft())
        .unwrap();
    let now = now();
    let dir = private_dir();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = receive(prepared_intent(2, 1, &now), &mut inbox, &now, &secret(11));
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        1
    );
    let reader = Access {
        include_owned_agreements: true,
        principal_id: "reader".into(),
        agreement_ids: [draft().agreement_id].into(),
        all_agreements: false,
    };
    assert_eq!(
        engine
            .grant_transport_peer(
                &reader,
                "grant-denied-command-001",
                &draft().agreement_id,
                1,
                grant(&now)
            )
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    engine
        .grant_transport_peer(
            &actor(),
            "grant-peer-command-001",
            &draft().agreement_id,
            1,
            grant(&now),
        )
        .unwrap();
    assert_eq!(
        engine
            .import_nonbinding_transport(&reader, &mut inbox, &received, &now)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    let forged = prepare_intent_message(
        request(ArtifactKind::ParticipationIntent, 2, 2, &now),
        TransportIntent {
            schema_version: 1,
            expected_agreement_revision: 2,
            intent: intent(),
        },
        &secret(33).public_key().unwrap(),
        &organizer(),
        &now,
    )
    .unwrap();
    let forged = receive(forged, &mut inbox, &now, &secret(33));
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &forged, &now)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        2
    );
    engine
        .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
        .unwrap();
}

#[test]
fn revocation_and_expired_grant_block_even_a_completed_engine_replay() {
    let engine = Engine::in_memory().unwrap();
    let now = now();
    setup(&engine, &now);
    let dir = private_dir();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = receive(prepared_intent(2, 1, &now), &mut inbox, &now, &secret(11));
    engine
        .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
        .unwrap();
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &later(&now, 3600))
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    engine
        .revoke_transport_peer(
            &actor(),
            "revoke-peer-command-001",
            &draft().agreement_id,
            3,
            "grant-one",
        )
        .unwrap();
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    // Retrying the old enrollment request never reactivates a revoked grant.
    assert!(
        engine
            .grant_transport_peer(
                &actor(),
                "grant-peer-command-0001",
                &draft().agreement_id,
                1,
                grant(&now)
            )
            .unwrap()
            .replayed
    );
    assert!(
        engine
            .transport_peer_grants(&actor(), &draft().agreement_id)
            .unwrap()[0]
            .revoked
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        4
    );
}

#[test]
fn changed_revision_and_expired_transport_remain_pending_without_mutation() {
    let engine = Engine::in_memory().unwrap();
    let now = now();
    setup(&engine, &now);
    let dir = private_dir();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let stale = receive(prepared_intent(1, 1, &now), &mut inbox, &now, &secret(11));
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &stale, &now)
            .err()
            .unwrap()
            .code,
        "REVISION_CONFLICT"
    );
    let expired = receive(prepared_intent(2, 2, &now), &mut inbox, &now, &secret(11));
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &expired, &later(&now, 600))
            .err()
            .unwrap()
            .code,
        "INVALID_TIME"
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        2
    );
    assert_eq!(
        inbox
            .pending_domain_sequences(
                &context(ArtifactKind::ParticipationIntent, 2),
                "engine-nonbinding-intents-v1"
            )
            .unwrap(),
        vec![1, 2]
    );
}

fn fixture_peer_access(received: &ReceivedArtifact) -> Access {
    let p = received.preview();
    let data = json!({"network":p.context.network_profile_id,"agreement":p.context.agreement_id,"participant":p.context.sender_id,
        "sender_key":p.sender_key_fingerprint,"recipient":p.context.recipient_id,"recipient_key":p.recipient_key_fingerprint});
    let mut hash = Sha256::new();
    hash.update(b"wholepact:transport-peer-principal:v1\0");
    hash.update(serde_json::to_vec(&data).unwrap());
    Access {
        include_owned_agreements: true,
        principal_id: format!("transport-peer:{}", hex::encode(hash.finalize())),
        agreement_ids: [draft().agreement_id].into(),
        all_agreements: false,
    }
}

#[test]
fn actual_engine_commit_before_inbox_completion_reconciles_without_second_operation() {
    let dir = private_dir();
    let path = dir.path().join("engine.db");
    let key = DatabaseKey::from_bytes([92; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let now = now();
    setup(&engine, &now);
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = receive(prepared_intent(2, 1, &now), &mut inbox, &now, &secret(11));
    let ticket = inbox
        .domain_import_ticket(&received, "engine-nonbinding-intents-v1")
        .unwrap();
    // Precisely reproduce the production driver's domain command, then interrupt
    // before its separate inbox completion. This is a real engine/store commit.
    let peer_access = fixture_peer_access(&received);
    let committed = engine
        .add_intent(
            &peer_access,
            ticket.idempotency_key(),
            &draft().agreement_id,
            2,
            intent(),
        )
        .unwrap();
    drop(engine);
    drop(inbox);
    let engine = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let retained = inbox
        .retained_for_context(&context(ArtifactKind::ParticipationIntent, 2), 1)
        .unwrap()
        .unwrap();
    let historical = recover_received(
        &retained,
        &secret(22),
        &peer(),
        &context(ArtifactKind::ParticipationIntent, 2),
    )
    .unwrap();
    let reconciled = engine
        .import_nonbinding_transport(
            &actor(),
            &mut inbox,
            historical.artifact(),
            &later(&now, 700),
        )
        .unwrap();
    assert!(reconciled.replayed);
    assert_eq!(committed.operation_id, reconciled.operation_id);
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .intents
            .len(),
        1
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        3
    );
    assert!(
        inbox
            .pending_domain_sequences(
                &context(ArtifactKind::ParticipationIntent, 2),
                "engine-nonbinding-intents-v1"
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn plaintext_store_and_payload_substitution_are_rejected() {
    let dir = private_dir();
    let engine = Engine::open(dir.path().join("plaintext.db")).unwrap();
    engine
        .create(&actor(), "create-agreement-0001", draft())
        .unwrap();
    let now = now();
    assert_eq!(
        engine
            .grant_transport_peer(
                &actor(),
                "grant-peer-command-0001",
                &draft().agreement_id,
                1,
                grant(&now)
            )
            .err()
            .unwrap()
            .code,
        "ENCRYPTED_STORAGE_REQUIRED"
    );
    let mut changed = intent();
    changed.participant_id = "someone-else".into();
    assert_eq!(
        prepare_intent_message(
            request(ArtifactKind::ParticipationIntent, 1, 1, &now),
            TransportIntent {
                schema_version: 1,
                expected_agreement_revision: 1,
                intent: changed
            },
            &peer(),
            &organizer(),
            &now
        )
        .err()
        .unwrap()
        .code,
        "INVALID_TERMS"
    );
}

#[test]
fn revocation_committed_after_grant_check_fences_the_pending_engine_mutation() {
    let engine = Engine::in_memory().unwrap();
    let now = now();
    setup(&engine, &now);
    let dir = private_dir();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = receive(prepared_intent(2, 1, &now), &mut inbox, &now, &secret(11));
    // A request already passed a grant check and derived its scoped access.
    let peer = fixture_peer_access(&received);
    let ticket = inbox
        .domain_import_ticket(&received, "engine-nonbinding-intents-v1")
        .unwrap();
    // Another request revokes the grant before the exact engine write.
    engine
        .revoke_transport_peer(
            &actor(),
            "revoke-during-import-001",
            &draft().agreement_id,
            2,
            "grant-one",
        )
        .unwrap();
    let error = engine
        .add_intent(
            &peer,
            ticket.idempotency_key(),
            &draft().agreement_id,
            2,
            intent(),
        )
        .err()
        .unwrap();
    assert_eq!(error.code, "REVISION_CONFLICT");
    assert!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .intents
            .is_empty()
    );
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        3
    );
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
}

#[test]
fn stale_restored_peer_grants_are_quarantined_before_import_replay_or_enrollment() {
    let dir = private_dir();
    let source = dir.path().join("source.db");
    let source_key = DatabaseKey::from_bytes([93; 32]);
    let backup_key = DatabaseKey::from_bytes([94; 32]);
    let restore_key = DatabaseKey::from_bytes([95; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&source, &source_key).unwrap());
    let now = now();
    setup(&engine, &now);
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = receive(prepared_intent(2, 1, &now), &mut inbox, &now, &secret(11));
    engine
        .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
        .unwrap();
    let archive = dir.path().join("archive.db");
    Store::open_encrypted(&source, &source_key)
        .unwrap()
        .backup_agreement_journal(&archive, &backup_key)
        .unwrap();
    engine
        .revoke_transport_peer(
            &actor(),
            "revoke-after-backup-001",
            &draft().agreement_id,
            3,
            "grant-one",
        )
        .unwrap();
    let (restored, report) = wholepact_store::backup::restore_agreement_journal(
        &archive,
        &backup_key,
        dir.path().join("restored.db"),
        &restore_key,
    )
    .unwrap();
    assert!(report.recovery_required);
    let restored = Engine::from_store(restored);
    let history = restored
        .transport_peer_grants(&actor(), &draft().agreement_id)
        .unwrap();
    assert!(!history[0].revoked); // Historical archive predates revocation.
    assert!(history[0].recovery_required); // It is not an active current permission.
    assert_eq!(
        restored
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
            .err()
            .unwrap()
            .code,
        "RECOVERY_REQUIRED"
    );
    let mut new_grant = grant(&now);
    new_grant.grant_id = "new-grant".into();
    assert_eq!(
        restored
            .grant_transport_peer(
                &actor(),
                "blocked-restored-enrollment",
                &draft().agreement_id,
                3,
                new_grant
            )
            .err()
            .unwrap()
            .code,
        "RECOVERY_REQUIRED"
    );
}

#[test]
fn recovered_host_keeps_old_peer_grants_quarantined_and_allows_fresh_enrollment() {
    let dir = private_dir();
    let path = dir.path().join("recovered-host.db");
    let key = DatabaseKey::from_bytes([96; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&path, &key).unwrap());
    let now = now();
    setup(&engine, &now);
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let completed = receive(prepared_intent(2, 1, &now), &mut inbox, &now, &secret(11));
    engine
        .import_nonbinding_transport(&actor(), &mut inbox, &completed, &now)
        .unwrap();
    drop(engine);

    // Synthetic post-recovery fixture: the host's global fence is clear, but
    // historical grants remain individually quarantined. This isolates the
    // transport boundary; it does not qualify host-authority reconciliation.
    let store = Store::open_encrypted(&path, &key).unwrap();
    assert!(!store.recovery_state().unwrap().recovery_required);
    let mut record = store.get_agreement(&draft().agreement_id).unwrap().unwrap();
    record.payload["transport_peer_grants"]["grant-one"]["recovery_required"] = json!(true);
    record.payload["view"]["revision"] = json!(record.revision + 1);
    let historical_grant = record.payload["transport_peer_grants"]["grant-one"].clone();
    let fixture_command = wholepact_store::CommandContext::for_request(
        "synthetic-host-recovery",
        "quarantine-historical-peer-grant",
        &json!({"agreement_id":draft().agreement_id}),
    )
    .unwrap();
    store
        .update_agreement(
            &fixture_command,
            &draft().agreement_id,
            record.revision,
            record.payload,
            "synthetic_peer_quarantine",
        )
        .unwrap();
    drop(store);

    let engine = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    assert!(!engine.transport_recovery_required().unwrap());
    let history = engine
        .transport_peer_grants(&actor(), &draft().agreement_id)
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(serde_json::to_value(&history[0]).unwrap(), historical_grant);

    let pending = receive(
        prepare_withdrawal_message(
            request(ArtifactKind::IntentWithdrawal, 4, 2, &now),
            TransportIntentWithdrawal {
                schema_version: 1,
                expected_agreement_revision: 4,
                participant_id: "participant-one".into(),
                intent_id: "intent-one".into(),
            },
            &peer(),
            &organizer(),
            &now,
        )
        .unwrap(),
        &mut inbox,
        &now,
        &secret(11),
    );
    // Both an already-completed replay and a current, never-imported command
    // must check the persisted grant quarantine, even on an active host.
    for received in [&completed, &pending] {
        assert_eq!(
            engine
                .nonbinding_transport_requirements(&actor(), &inbox, received, &now)
                .err()
                .unwrap()
                .code,
            "PERMISSION_DENIED"
        );
        assert_eq!(
            engine
                .import_nonbinding_transport(&actor(), &mut inbox, received, &now)
                .unwrap_err()
                .code,
            "PERMISSION_DENIED"
        );
    }
    assert_eq!(
        engine
            .get(&actor(), &draft().agreement_id)
            .unwrap()
            .revision,
        4
    );

    // The owner explicitly enrolls the same participant and pinned keys with a
    // new grant identity and narrower scope. Retaining the original must neither
    // prevent enrollment nor create an ambiguous pair of current permissions.
    let mut fresh = grant(&now);
    fresh.grant_id = "grant-after-recovery".into();
    fresh.allow_intent = false;
    engine
        .grant_transport_peer(
            &actor(),
            "explicit-recovered-peer-enrollment",
            &draft().agreement_id,
            4,
            fresh,
        )
        .unwrap();
    let history = engine
        .transport_peer_grants(&actor(), &draft().agreement_id)
        .unwrap();
    assert_eq!(history.len(), 2);
    let original = history
        .iter()
        .find(|g| g.request.grant_id == "grant-one")
        .unwrap();
    assert_eq!(serde_json::to_value(original).unwrap(), historical_grant);
    let fresh = history
        .iter()
        .find(|g| g.request.grant_id == "grant-after-recovery")
        .unwrap();
    assert!(!fresh.recovery_required && !fresh.revoked);
    assert!(!fresh.request.allow_intent && fresh.request.allow_withdrawal);

    // New withdrawal permission cannot resurrect historical intent permission,
    // including an operation whose successful result is still in the journal.
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &completed, &now)
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    let fresh_withdrawal = receive(
        prepare_withdrawal_message(
            request(ArtifactKind::IntentWithdrawal, 5, 3, &now),
            TransportIntentWithdrawal {
                schema_version: 1,
                expected_agreement_revision: 5,
                participant_id: "participant-one".into(),
                intent_id: "intent-one".into(),
            },
            &peer(),
            &organizer(),
            &now,
        )
        .unwrap(),
        &mut inbox,
        &now,
        &secret(11),
    );
    let imported = engine
        .import_nonbinding_transport(&actor(), &mut inbox, &fresh_withdrawal, &now)
        .unwrap();
    assert_eq!(imported.agreement.revision, 6);
    assert_eq!(
        imported.agreement.intents[0].status,
        IntentStatus::Withdrawn
    );
    drop(engine);

    let engine = Engine::from_store(Store::open_encrypted(&path, &key).unwrap());
    let history = engine
        .transport_peer_grants(&actor(), &draft().agreement_id)
        .unwrap();
    assert_eq!(history.len(), 2);
    let original = history
        .iter()
        .find(|g| g.request.grant_id == "grant-one")
        .unwrap();
    assert_eq!(serde_json::to_value(original).unwrap(), historical_grant);
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &completed, &now)
            .unwrap_err()
            .code,
        "PERMISSION_DENIED"
    );
    assert!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &fresh_withdrawal, &now)
            .unwrap()
            .replayed
    );
}

#[test]
fn future_revision_cannot_anticipate_a_concurrent_grant_revocation() {
    let engine = Engine::in_memory().unwrap();
    let now = now();
    setup(&engine, &now); // Enrolled grant was checked at revision 2.
    let dir = private_dir();
    let mut inbox = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let received = receive(prepared_intent(3, 1, &now), &mut inbox, &now, &secret(11));
    assert_eq!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    engine
        .revoke_transport_peer(
            &actor(),
            "future-revision-revoke-001",
            &draft().agreement_id,
            2,
            "grant-one",
        )
        .unwrap();
    assert!(
        engine
            .import_nonbinding_transport(&actor(), &mut inbox, &received, &now)
            .is_err()
    );
    let current = engine.get(&actor(), &draft().agreement_id).unwrap();
    assert_eq!(current.revision, 3);
    assert!(current.intents.is_empty());
}
