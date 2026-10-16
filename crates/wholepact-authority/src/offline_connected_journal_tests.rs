//! Encrypted-journal regression fixtures. All account/key material is fixed
//! SYNTHETIC test data. The envelope below is deliberately INVALID HPKE and the
//! receipt/inbox callbacks simulate a trusted configured bridge. These tests do
//! NOT authenticate transport, establish native spending consent or qualify HPKE.
//! They exercise the actual encrypted journal transactions, durable links, outcome
//! fencing, reopen, backup and migration when an authorized runner executes them.
use super::*;
use crate::offline::{OfflineEnrollmentPolicy, ReserveOfflineAuthorization};
use crate::offline_retry::{OfflineOriginalBridge, OriginalTransportReceipt};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

struct Fixture {
    journal: AuthorityJournal,
    request: ReserveOfflineAuthorization,
    policy: OfflineEnrollmentPolicy,
    ciphertext: Vec<u8>,
    receipt: OriginalTransportReceipt,
    prepared: String,
}
impl Fixture {
    fn new(dir: &Path) -> Self {
        let journal = create(dir);
        let (mut request, _, mut policy) = crate::offline::tests::fixture();
        policy.enrollment_ref = h('c');
        request.intent.terms.enrollment_ref = policy.enrollment_ref.clone();
        request.intent.terms.recipient_scope_digest = h('d');
        request.intent.terms.offline_policy_digest = policy.policy_digest().unwrap();
        control(
            &journal,
            "connected-offline-enroll",
            OwnerControl::EnrollOfflinePolicy {
                policy: policy.clone(),
                expected_previous_digest: None,
            },
        );
        request.expected_head = snapshot(&journal).head;
        let t = &request.intent.terms;
        let template = OfflineAdmissionExportPlan {
            message_id: "11".repeat(16),
            sequence: 0,
            issued_at_unix_seconds: 3,
            expires_at_unix_seconds: 20,
            purpose: "Synthetic exact admission".into(),
            persistence_warning: "Synthetic test evidence only".into(),
            sender_id: format!("offline-admission:{}", t.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
            sender_key_fingerprint: policy.witness_transport_key_digest.clone(),
            recipient_key_fingerprint: policy.offline_signer_key_digest.clone(),
        };
        let ciphertext = b"SYNTHETIC INVALID HPKE; TRUSTED CALLBACK SIMULATION ONLY".to_vec();
        let peer = h('b');
        let bridge = OfflineOriginalBridge {
            journal: &journal,
            peer: &peer,
        };
        let retained = bridge
            .prepare(&request, &ciphertext, template, 3000)
            .unwrap();
        assert!(retained.export_plan().is_none());
        let prepared = retained.prepared_record_digest().unwrap();
        let sender = format!("offline-intent:{}", t.offline_signer_key_digest);
        let recipient = format!("offline-intent:{}", t.offline_policy_digest);
        let mut hash = Sha256::new();
        hash.update(b"wholepact.encrypted-envelope.v1\0");
        hash.update(&ciphertext);
        let receipt = OriginalTransportReceipt {
            network_profile_id: t.network_profile_id.clone(),
            agreement_id: t.agreement_id.clone(),
            proposal_id: t.proposal_id.clone(),
            proposal_revision: t.proposal_revision,
            stream_digest: crate::digest(
                "wholepact.transport-stream.v1",
                &(&t.network_profile_id, &t.agreement_id, &sender, &recipient),
            )
            .unwrap(),
            sender_id: sender,
            recipient_id: recipient,
            artifact_kind: "offline_reservation_intent".into(),
            message_id: "22".repeat(16),
            sequence: 1,
            issued_at_unix_seconds: 2,
            expires_at_unix_seconds: 25,
            sender_key_fingerprint: policy.offline_signer_key_digest.clone(),
            recipient_key_fingerprint: policy.witness_transport_key_digest.clone(),
            preview_digest: h('3'),
            content_digest: h('4'),
            payload_digest: h('5'),
            envelope_digest: hex::encode(hash.finalize()),
        };
        Self {
            journal,
            request,
            policy,
            ciphertext,
            receipt,
            prepared,
        }
    }
    fn authenticated_callback(&self) {
        let peer = h('b');
        OfflineOriginalBridge {
            journal: &self.journal,
            peer: &peer,
        }
        .record_authenticated_receipt(
            &self.prepared,
            &self.request.operation_id,
            self.receipt.clone(),
            3001,
        )
        .unwrap();
    }
    /// Simulates the privileged post-success callback; no real inbox or HPKE runs.
    fn inbox_success_marker(&self) {
        let peer = h('b');
        OfflineOriginalBridge {
            journal: &self.journal,
            peer: &peer,
        }
        .record_inbox_accepted(
            &self.prepared,
            &self.request.operation_id,
            self.receipt.clone(),
            3002,
        )
        .unwrap();
    }
    fn bind_request(&self, request: &ReserveOfflineAuthorization) -> AuthenticatedOfflineIntent {
        OfflineIntentAuthenticationIssuer::for_test(self.policy.clone())
            .unwrap()
            .bind_verified_intent(
                request,
                &request.intent,
                &self.policy.offline_signer_key_digest,
                &self.policy.witness_transport_key_digest,
                &self.receipt.envelope_digest,
            )
            .unwrap()
    }
    fn commit(&self, now: u64) -> Result<CommittedOfflineAdmission> {
        self.journal.commit_offline_prepared_for_test(
            &h('b'),
            self.request.clone(),
            self.bind_request(&self.request),
            now,
        )
    }
    fn control_plan(&self, issued: i64) -> OfflineAdmissionExportPlan {
        let t = &self.request.intent.terms;
        OfflineAdmissionExportPlan {
            message_id: "33".repeat(16),
            sequence: 1,
            issued_at_unix_seconds: issued,
            expires_at_unix_seconds: issued + 10,
            purpose: "Synthetic terminal control".into(),
            persistence_warning: "No signing authority; exposure may remain".into(),
            sender_id: format!("offline-admission:{}", t.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
            sender_key_fingerprint: self.policy.witness_transport_key_digest.clone(),
            recipient_key_fingerprint: self.policy.offline_signer_key_digest.clone(),
        }
    }
}
fn original_event(j: &AuthorityJournal, operation: &str) -> Option<Event> {
    let c = j.connection.lock().unwrap();
    let bytes: Option<Vec<u8>> = c
        .connection()
        .query_row(
            "SELECT payload FROM authority_events WHERE operation_id=?1",
            [operation],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    bytes.map(|b| crate::decode(&b).unwrap())
}
fn event_bytes(j: &AuthorityJournal) -> Vec<Vec<u8>> {
    let c = j.connection.lock().unwrap();
    let mut q = c
        .connection()
        .prepare("SELECT payload FROM authority_events ORDER BY sequence")
        .unwrap();
    let rows = q
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows
}
/// Exact synthetic encrypted-table content comparison, not a hash-only count.
fn offline_bytes(j: &AuthorityJournal) -> Vec<(String, Vec<Vec<u8>>)> {
    let c = j.connection.lock().unwrap();
    let mut result = Vec::new();
    for (table, select) in [
        (
            "originals",
            "SELECT payload FROM authority_offline_originals ORDER BY operation_id",
        ),
        (
            "ciphertexts",
            "SELECT envelope FROM authority_offline_originals ORDER BY operation_id",
        ),
        (
            "receipts",
            "SELECT payload FROM authority_offline_original_receipts ORDER BY prepared_digest",
        ),
        (
            "inbox",
            "SELECT payload FROM authority_offline_inbox_acceptances ORDER BY prepared_digest",
        ),
        (
            "outcomes",
            "SELECT payload FROM authority_offline_outcomes ORDER BY prepared_digest",
        ),
    ] {
        let mut query = c.connection().prepare(select).unwrap();
        let rows = query
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<Vec<u8>>>>()
            .unwrap();
        result.push((table.into(), rows));
    }
    result
}

#[test]
fn connected_encrypted_inbox_link_fence_restart_pause_and_backup() {
    let dir = private_dir();
    let mut f = Fixture::new(dir.path());
    f.authenticated_callback();
    // Simulate a process boundary after callback allocation, before inbox success.
    drop(f.journal);
    f.journal = open(dir.path());
    let peer = h('b');
    let retained = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    }
    .recover(
        &f.request.operation_id,
        &f.request.request_digest().unwrap(),
        3002,
    )
    .unwrap()
    .unwrap();
    assert!(retained.request() == &f.request);
    assert_eq!(retained.original_envelope_bytes(), f.ciphertext);
    assert_eq!(retained.export_plan().unwrap().sequence, 1);
    assert!(retained.authenticated_receipt() == Some(&f.receipt));
    f.inbox_success_marker();
    let committed = f.commit(3003).unwrap();
    let descriptor = committed.descriptor().clone();
    let event = original_event(&f.journal, &f.request.operation_id).unwrap();
    let link = event
        .original_request_link
        .as_ref()
        .expect("durable original event link");
    assert_eq!(link.prepared_record_digest, f.prepared);
    assert_eq!(
        link.reservation_request_digest,
        f.request.request_digest().unwrap()
    );
    assert_eq!(event.witness_time_ms, 3003);
    let bridge = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    };
    let capability = bridge
        .select_admission_export(&f.request.operation_id, 3004)
        .unwrap();
    assert!(capability.descriptor() == &descriptor);
    let plan = capability.export_plan().clone();
    drop(capability);
    assert!(matches!(
        bridge.select_admission_export(&f.request.operation_id, 3005),
        Err(AuthorityError::Uncertain)
    ));
    let historical = bridge
        .recover_admission_export_history(&f.request.operation_id)
        .unwrap()
        .unwrap();
    assert!(historical.descriptor() == &descriptor && historical.export_plan() == &plan);
    assert!(!historical.authorization_allowed());
    // Restart preserves the first event/time, source bytes and conservative exposure.
    let before_bytes = offline_bytes(&f.journal);
    drop(f.journal);
    f.journal = open(dir.path());
    assert!(f.commit(3005).unwrap().descriptor() == &descriptor);
    assert_eq!(offline_bytes(&f.journal), before_bytes);
    assert_eq!(snapshot(&f.journal).outstanding_reservations, 1);
    assert_eq!(snapshot(&f.journal).outstanding_debit_zatoshis, 70);
    assert_eq!(snapshot(&f.journal).reserved_input_value_zatoshis, 100);
    control(
        &f.journal,
        "connected-offline-pause",
        OwnerControl::SetOfflinePolicyStatus {
            enrollment_ref: f.policy.enrollment_ref.clone(),
            policy_digest: f.policy.policy_digest().unwrap(),
            status: OfflineEnrollmentStatus::Paused,
        },
    );
    assert_eq!(snapshot(&f.journal).outstanding_debit_zatoshis, 70);
    let bridge = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    };
    assert!(bridge
        .recover_admission_export_history(&f.request.operation_id)
        .unwrap()
        .is_some());
    assert!(matches!(f.commit(3006), Err(AuthorityError::Inactive)));
    let source_rows = offline_bytes(&f.journal);
    let source_events = event_bytes(&f.journal);
    let backup_key = DatabaseKey::from_bytes([23; 32]); // SYNTHETIC storage key only.
    f.journal
        .backup_quarantined(
            &dir.path().join("offline-backup.staging"),
            &dir.path().join("offline-backup.db"),
            &backup_key,
        )
        .unwrap();
    let backup = AuthorityJournal::open_encrypted(
        &dir.path().join("offline-backup.db"),
        &backup_key,
        "synthetic-account",
        "synthetic-testnet",
    )
    .unwrap();
    assert_eq!(offline_bytes(&backup), source_rows);
    assert_eq!(event_bytes(&backup), source_events);
    assert_eq!(snapshot(&backup).writer_status, WriterStatus::Quarantined);
    assert_eq!(snapshot(&backup).outstanding_debit_zatoshis, 70);
    assert!(matches!(
        OfflineOriginalBridge {
            journal: &backup,
            peer: &peer
        }
        .recover_admission_export_history(&f.request.operation_id),
        Err(AuthorityError::RecoveryRequired)
    ));
}

#[test]
fn connected_encrypted_callback_without_inbox_never_reserves() {
    let dir = private_dir();
    let f = Fixture::new(dir.path());
    f.authenticated_callback();
    let before = snapshot(&f.journal);
    let events = event_bytes(&f.journal);
    assert!(matches!(
        f.commit(3003),
        Err(AuthorityError::Authentication)
    ));
    assert!(snapshot(&f.journal) == before);
    assert_eq!(event_bytes(&f.journal), events);
    assert!(original_event(&f.journal, &f.request.operation_id).is_none());
    f.inbox_success_marker();
    let retained = offline_bytes(&f.journal);
    f.journal.connection.lock().unwrap().connection().execute_batch(
        "CREATE TEMP TRIGGER fail_linked_offline_append BEFORE INSERT ON authority_events BEGIN SELECT RAISE(ABORT,'synthetic linked append failure'); END;"
    ).unwrap();
    assert!(matches!(f.commit(3003), Err(AuthorityError::Storage)));
    assert!(snapshot(&f.journal) == before);
    assert_eq!(offline_bytes(&f.journal), retained);
    f.journal
        .connection
        .lock()
        .unwrap()
        .connection()
        .execute_batch("DROP TRIGGER fail_linked_offline_append")
        .unwrap();
    assert!(f.commit(3003).is_ok());
}

#[test]
fn connected_encrypted_legacy_descriptor_cannot_upgrade_even_with_matching_source() {
    let dir = private_dir();
    let f = Fixture::new(dir.path());
    f.authenticated_callback();
    f.inbox_success_marker();
    f.journal
        .commit_offline_for_test(&h('b'), f.request.clone(), f.bind_request(&f.request), 3003)
        .unwrap();
    assert!(original_event(&f.journal, &f.request.operation_id)
        .unwrap()
        .original_request_link
        .is_none());
    let peer = h('b');
    let bridge = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    };
    assert!(matches!(
        bridge.select_admission_export(&f.request.operation_id, 3004),
        Err(AuthorityError::Authentication)
    ));
    assert!(bridge
        .recover_admission_export_history(&f.request.operation_id)
        .unwrap()
        .is_none());
    assert_eq!(snapshot(&f.journal).outstanding_debit_zatoshis, 70);
}

#[test]
fn connected_encrypted_no_admission_control_blocks_original_and_reminted_intent() {
    let dir = private_dir();
    let mut f = Fixture::new(dir.path());
    f.authenticated_callback();
    // No actual-inbox marker: terminal nonfinancial control is permitted before
    // emission. The absence of an inbox marker never permits financial admission.
    let peer = h('b');
    let bridge = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    };
    let control = bridge
        .select_control_export(&f.request.operation_id, f.control_plan(4), 4000)
        .unwrap();
    assert!(matches!(
        control.descriptor().outcome,
        OfflineAdmissionControlOutcome::NoAdmission
    ));
    assert!(matches!(f.commit(4001), Err(AuthorityError::Conflict)));
    let mut reminted = f.request.clone();
    reminted.operation_id = "reminted-original".into();
    assert!(matches!(
        f.journal.commit_offline_prepared_for_test(
            &peer,
            reminted.clone(),
            f.bind_request(&reminted),
            4001
        ),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(snapshot(&f.journal).outstanding_debit_zatoshis, 0);
    let selected = control.descriptor().clone();
    drop(control);
    drop(f.journal);
    f.journal = open(dir.path());
    let bridge = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    };
    assert!(
        bridge
            .recover_control_export_history(&f.request.operation_id)
            .unwrap()
            .unwrap()
            .descriptor()
            == &selected
    );
    assert!(matches!(
        bridge.select_control_export(&f.request.operation_id, f.control_plan(5), 5000),
        Err(AuthorityError::Uncertain)
    ));
    assert!(matches!(f.commit(5001), Err(AuthorityError::Conflict)));
}

#[test]
fn connected_encrypted_abandoned_admission_preserves_exposure_after_original_expiry() {
    let dir = private_dir();
    let f = Fixture::new(dir.path());
    f.authenticated_callback();
    f.inbox_success_marker();
    f.commit(3003).unwrap();
    let exposure = snapshot(&f.journal);
    let peer = h('b');
    let bridge = OfflineOriginalBridge {
        journal: &f.journal,
        peer: &peer,
    };
    let control = bridge
        .select_control_export(&f.request.operation_id, f.control_plan(32), 31_001)
        .unwrap();
    assert!(matches!(
        control.descriptor().outcome,
        OfflineAdmissionControlOutcome::ExposureRetained { .. }
    ));
    assert!(snapshot(&f.journal) == exposure);
    assert!(matches!(
        bridge.select_admission_export(&f.request.operation_id, 31_002),
        Err(AuthorityError::Uncertain)
    ));
    assert_eq!(snapshot(&f.journal).outstanding_debit_zatoshis, 70);
    assert_eq!(snapshot(&f.journal).reserved_input_value_zatoshis, 100);
}

#[test]
fn connected_encrypted_v3_migration_preserves_history_and_rejects_wrong_identity_first() {
    let dir = private_dir();
    let key = DatabaseKey::from_bytes([19; 32]);
    let legacy = AuthorityJournal::create_encrypted_legacy_v3_for_test(
        &dir.path().join("authority.db"),
        &key,
        policy(),
    )
    .unwrap();
    legacy.synthetic_activate(&h('b'), 998).unwrap();
    let exact = request(&snapshot(&legacy).head, 51, 60);
    let permit = mutate(&legacy, exact.clone()).unwrap();
    let before = snapshot(&legacy);
    let events = event_bytes(&legacy);
    drop(legacy);
    assert!(matches!(
        AuthorityJournal::open_encrypted(
            &dir.path().join("authority.db"),
            &key,
            "wrong-account",
            "synthetic-testnet"
        ),
        Err(AuthorityError::InvalidBinding)
    ));
    {
        let raw = wholepact_storage_security::open_encrypted(dir.path().join("authority.db"), &key)
            .unwrap();
        assert_eq!(
            raw.connection()
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            raw.connection()
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name='authority_offline_originals'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
    let migrated = open(dir.path());
    assert!(snapshot(&migrated) == before);
    assert_eq!(event_bytes(&migrated), events);
    assert!(mutate(&migrated, exact).unwrap() == permit);
    assert!(offline_bytes(&migrated)
        .iter()
        .all(|(_, rows)| rows.is_empty()));
    assert_eq!(
        migrated
            .connection
            .lock()
            .unwrap()
            .connection()
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(
        migrated
            .connection
            .lock()
            .unwrap()
            .connection()
            .query_row(
                "SELECT count(*) FROM authority_pending_birth_commit",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    // Schema 6 adds empty construction handoff tables; migration cannot invent
    // a credential, grant or transport fence for retained legacy history.
    for table in [
        "authority_construction_transport_grants",
        "authority_construction_transport_credentials",
        "authority_transport_fences",
    ] {
        assert_eq!(
            migrated
                .connection
                .lock()
                .unwrap()
                .connection()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| {
                    r.get::<_, u64>(0)
                })
                .unwrap(),
            0
        );
    }
    drop(migrated);
    let reopened = open(dir.path());
    assert_eq!(snapshot(&reopened).outstanding_debit_zatoshis, 60);
    assert_eq!(event_bytes(&reopened), events);
}

#[test]
fn connected_controller_proof_input_cannot_replay_channel_session_or_changed_original() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path());
    fixture.authenticated_callback();
    fixture.inbox_success_marker();
    let before = snapshot(&fixture.journal);
    let peer = h('b');
    let bridge = OfflineOriginalBridge {
        journal: &fixture.journal,
        peer: &peer,
    };
    let proof = fixture
        .journal
        .offline_controller_proof_for_test(
            &peer,
            &fixture.request,
            &fixture.bind_request(&fixture.request),
        )
        .unwrap();
    let mut wrong_version = proof.clone();
    wrong_version.schema_version = 2;
    assert!(matches!(
        bridge.commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(wrong_version),
            &[0xaa; 32],
            &"0".repeat(64),
            3003
        ),
        Err(AuthorityError::UnsupportedVersion)
    ));
    assert!(bridge
        .commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(proof.clone()),
            &[0xaa; 32],
            &"1".repeat(64),
            3003
        )
        .is_err());
    let mut wrong_mac = proof.clone();
    wrong_mac.tag = h('9');
    assert!(bridge
        .commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(wrong_mac),
            &[0xaa; 32],
            &"0".repeat(64),
            3003
        )
        .is_err());
    assert!(bridge
        .commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(proof.clone()),
            &[0xbb; 32],
            &"0".repeat(64),
            3003
        )
        .is_err());
    let other_dir = private_dir();
    // Distinct synthetic genesis gives an actually distinct session. Reusing
    // Fixture::new would deliberately reproduce the same deterministic test key.
    let mut other_policy = policy();
    other_policy.witness_id.push_str("-other");
    let other = AuthorityJournal::create_encrypted(
        &other_dir.path().join("other.db"),
        &DatabaseKey::from_bytes([19; 32]),
        other_policy,
    )
    .unwrap();
    other.synthetic_activate(&peer, 998).unwrap();
    let other_proof = other
        .offline_controller_proof_for_test(
            &peer,
            &fixture.request,
            &fixture.bind_request(&fixture.request),
        )
        .unwrap();
    assert_ne!(other_proof.session_id, proof.session_id);
    assert!(bridge
        .commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(other_proof),
            &[0xaa; 32],
            &"0".repeat(64),
            3003
        )
        .is_err());
    // Even a genuine channel MAC for a changed request cannot replace retention.
    let mut changed = fixture.request.clone();
    changed.requested_at_ms += 1;
    let changed_auth = fixture.bind_request(&changed);
    let changed_proof = fixture
        .journal
        .offline_controller_proof_for_test(&peer, &changed, &changed_auth)
        .unwrap();
    assert!(bridge
        .commit_admission_export(
            changed,
            changed_auth,
            Some(changed_proof),
            &[0xaa; 32],
            &"0".repeat(64),
            3003
        )
        .is_err());
    assert!(snapshot(&fixture.journal) == before);
    let mut input = serde_json::to_value(&proof).unwrap();
    input
        .as_object_mut()
        .unwrap()
        .insert("approved".into(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<OfflineControllerProofInput>(input).is_err());
    let committed = bridge
        .commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(proof.clone()),
            &[0xaa; 32],
            &"0".repeat(64),
            3003,
        )
        .unwrap();
    assert!(committed.descriptor().request == fixture.request);
    assert!(matches!(
        bridge.commit_admission_export(
            fixture.request.clone(),
            fixture.bind_request(&fixture.request),
            Some(proof),
            &[0xaa; 32],
            &"0".repeat(64),
            3004
        ),
        Err(AuthorityError::Uncertain)
    ));
}
