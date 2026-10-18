//! Isolated never-funded storage/witness fixtures; the fake artifact/result here
//! does not qualify actual cryptographic signing, native human origin or chain.
use super::*;
use crate::authority_bridge::protocol::AuthorizationDeliveryScope;
use crate::consent_journal::{
    authority::fixture,
    tests::{enroll, proposal, terms},
};
use sha2::{Digest, Sha256};
use wholepact_authority::{AccountPolicy, AuthorityHead, AuthorityJournal, transport::synthetic};
use wholepact_storage_security::DatabaseKey;

struct Fixture {
    private_directory: crate::files::PrivateDirectory,
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    key: DatabaseKey,
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    original: OriginalAuthorizationEvidence,
    witness: AuthorityJournal,
    request: RetainedAuthorizationRequest,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("signer.sqlite");
        let key = DatabaseKey::from_bytes([0x74; 32]);
        let private_directory = crate::files::PrivateDirectory::open(directory.path()).unwrap();
        let journal = SignerConsentJournal::create_encrypted(
            &path,
            &key,
            "account-alice",
            1,
            false,
            &private_directory
                .signer_journal_source_owner_for_test(&path)
                .unwrap(),
        )
        .unwrap();
        let session = fixture::session(&journal, "synthetic-owner");
        let bytes = b"never-funded-local-bridge-artifact-canary";
        let mut proposal_input = proposal("agreement-a", "obligation-a", "proposal-a")
            .input()
            .clone();
        proposal_input.artifact_digest = Some(hex::encode(Sha256::digest(bytes)));
        let p = wholepact_core::Proposal::validate(proposal_input).unwrap();
        let (enrollment, manifest) = enroll(&journal, &session, &p, 1_000_000_000);
        let mut t = terms(&session, &enrollment, &manifest, "authorization-a");
        t.artifact_digest = hex::encode(Sha256::digest(bytes));
        let original = journal
            .record_original_consent_release(fixture::approve_spend(&session, t))
            .unwrap();
        let mut request = RetainedAuthorizationRequest::from_original(
            &original,
            bytes,
            AuthorityHead {
                sequence: 0,
                digest: "00".repeat(32),
            },
            AuthorizationDeliveryScope {
                candidate_id: "proposal-a".into(),
            },
        )
        .unwrap();
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: "synthetic-independent-witness".into(),
            account_id: "account-alice".into(),
            network_profile_id: request.reservation.network_profile_id.clone(),
            owner_certificate_digest: "a1".repeat(32),
            initial_writer_certificate_digest: "b2".repeat(32),
            initial_writer_epoch: 1,
            enrollment_refs: vec![enrollment.reference().into()],
            agreement_ids: vec!["agreement-a".into()],
            recipient_scope_digests: vec![request.reservation.recipient_scope_digest.clone()],
            aggregate_budget_zatoshis: 1_000_000_000,
            per_operation_limit_zatoshis: 500_000_000,
            maximum_fee_share_zatoshis: 12_000,
            maximum_transaction_fee_zatoshis: 30_000,
            maximum_permit_lifetime_ms: 120_000,
            policy_expires_at_ms: request.reservation.permit_expires_at_ms + 120_000,
        };
        let witness = AuthorityJournal::create_encrypted(
            &directory.path().join("independent-witness.sqlite"),
            &DatabaseKey::from_bytes([0x85; 32]),
            policy,
        )
        .unwrap();
        synthetic::activate(
            &witness,
            &"b2".repeat(32),
            request.reservation.reviewed_at_ms.saturating_sub(2),
        )
        .unwrap();
        request.reservation.expected_head = synthetic::snapshot(
            &witness,
            &"b2".repeat(32),
            "account-alice",
            &request.reservation.network_profile_id,
        )
        .unwrap()
        .head;
        Self {
            private_directory,
            _directory: directory,
            path,
            key,
            journal,
            session,
            original,
            witness,
            request,
        }
    }
    fn lease(&self) -> OriginalAuthorizationLease<'_> {
        self.journal
            .acquire_original_authorization("authorization-a", &self.session)
            .unwrap()
    }
    fn permit(&self) -> AuthenticatedPermit {
        synthetic::reserve(
            &self.witness,
            &"b2".repeat(32),
            self.request.reservation.clone(),
            self.request.reservation.reviewed_at_ms + 1,
        )
        .unwrap()
    }
    fn result(&self) -> RetainedAuthorizationResult {
        let signed = b"never-funded-bridge-result-storage-canary";
        let outbox = "{\"synthetic_storage_fixture_only\":true}";
        RetainedAuthorizationResult {
            authorization_id: "authorization-a".into(),
            original_consent_ref: self.original.original_consent().reference().into(),
            request_digest: self.request.reservation.request_digest().unwrap(),
            result_digest: hex::encode(Sha256::digest(signed)),
            signed_pczt_hex: hex::encode(signed),
            outbox_digest: hex::encode(Sha256::digest(outbox.as_bytes())),
            outbox_payload: outbox.into(),
        }
    }
}
#[test]
fn exact_original_witness_request_replay_and_substitution_fail_closed() {
    let f = Fixture::new();
    let lease = f.lease();
    f.journal.bridge_retain_request(&lease, &f.request).unwrap();
    f.journal.bridge_retain_request(&lease, &f.request).unwrap();
    let saved = f.journal.bridge_request(&lease).unwrap();
    assert!(saved == f.request);
    let mut changed = f.request.clone();
    changed.reservation.expected_head.digest = "ff".repeat(32);
    assert!(matches!(
        f.journal.bridge_retain_request(&lease, &changed),
        Err(BridgeError::Conflict)
    ));
    let mut changed = f.request.clone();
    changed.artifact_hex = hex::encode(b"substituted");
    assert!(f.journal.bridge_retain_request(&lease, &changed).is_err());
    let mut changed = f.request.clone();
    changed.reservation.original_consent_ref = "11".repeat(32);
    assert!(f.journal.bridge_retain_request(&lease, &changed).is_err());
    let permit = f.permit();
    f.journal.bridge_retain_permit(&lease, &permit).unwrap();
    let replay = f.permit();
    f.journal.bridge_retain_permit(&lease, &replay).unwrap();
    assert!(permit.descriptor() == replay.descriptor());
    let snapshot = synthetic::snapshot(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    assert_eq!(snapshot.outstanding_reservations, 1);
    assert_eq!(snapshot.outstanding_debit_zatoshis, 400_012_000);
}
#[test]
fn one_way_key_use_fence_and_exact_result_outbox_are_atomic_and_immutable() {
    let f = Fixture::new();
    let lease = f.lease();
    f.journal.bridge_retain_request(&lease, &f.request).unwrap();
    let permit = f.permit();
    f.journal.bridge_retain_permit(&lease, &permit).unwrap();
    assert!(f.journal.bridge_retain_result(&lease, &f.result()).is_err());
    f.journal.bridge_begin_key_use(&lease, &permit).unwrap();
    assert!(matches!(
        f.journal.bridge_result(&lease),
        Err(BridgeError::Uncertain)
    ));
    assert!(matches!(
        f.journal.bridge_begin_key_use(&lease, &permit),
        Err(BridgeError::Uncertain)
    ));
    f.journal.bridge_retain_result(&lease, &f.result()).unwrap();
    f.journal.bridge_retain_result(&lease, &f.result()).unwrap();
    let replay = f.journal.bridge_result(&lease).unwrap();
    assert!(replay == f.result());
    let mut changed = f.result();
    changed.outbox_payload = "{\"changed\":true}".into();
    changed.outbox_digest = hex::encode(Sha256::digest(changed.outbox_payload.as_bytes()));
    assert!(matches!(
        f.journal.bridge_retain_result(&lease, &changed),
        Err(BridgeError::Conflict)
    ));
    let c = f.journal.connection.lock().unwrap();
    for table in [
        "signer_bridge_requests",
        "signer_bridge_permits",
        "signer_bridge_keyuse",
        "signer_bridge_results",
    ] {
        assert!(c.execute(&format!("DELETE FROM {table}"), []).is_err());
    }
    drop(c);
    drop(lease);
    let bytes = std::fs::read(&f.path).unwrap();
    assert!(!bytes.windows(20).any(|b| b == b"never-funded-bridge-"));
}
#[test]
fn reopened_history_replays_exact_result_but_never_reconstructs_spend_approval() {
    let f = Fixture::new();
    {
        let lease = f.lease();
        f.journal.bridge_retain_request(&lease, &f.request).unwrap();
        let permit = f.permit();
        f.journal.bridge_retain_permit(&lease, &permit).unwrap();
        f.journal.bridge_begin_key_use(&lease, &permit).unwrap();
        f.journal.bridge_retain_result(&lease, &f.result()).unwrap();
    }
    let reopened = SignerConsentJournal::open_encrypted(
        &f.path,
        &f.key,
        "account-alice",
        &f.private_directory
            .signer_journal_source_owner_for_test(&f.path)
            .unwrap(),
    )
    .unwrap();
    let fresh = fixture::session(&reopened, "synthetic-owner");
    let lease = reopened
        .acquire_original_authorization("authorization-a", &fresh)
        .unwrap();
    assert!(lease.require_current_spending_decision().is_err());
    assert!(reopened.bridge_result(&lease).unwrap() == f.result());
    let wrong = fixture::session(&reopened, "another-synthetic-owner");
    assert!(
        reopened
            .acquire_original_authorization("authorization-a", &wrong)
            .is_err()
    );
}

fn prepare_reconciliation(f: &Fixture, writer: &str) -> PreparedWriterReconciliation {
    let (history, active) = synthetic::reconciled_session(
        &f.witness,
        writer,
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    f.session
        .prepare_writer_reconciliation(&f.journal, history, active)
        .unwrap()
}
fn commit_reconciliation(
    f: &Fixture,
    prepared: PreparedWriterReconciliation,
) -> SignerAccountState {
    let decision = fixture::decision(&f.session, prepared.review_digest());
    let approved = f
        .session
        .approve_writer_reconciliation(prepared, decision)
        .unwrap();
    f.journal.reconcile_writer(approved).unwrap()
}
#[test]
fn writer_reconciliation_keeps_originals_imports_remote_exposure_and_fences_stale_history() {
    let f = Fixture::new();
    f.permit();
    let first = prepare_reconciliation(&f, &"b2".repeat(32));
    assert!(first.display().unwrap().contains("authorization-a"));
    assert_eq!(commit_reconciliation(&f, first).writer_epoch, 1);
    let stale = prepare_reconciliation(&f, &"b2".repeat(32));
    let mut remote = f.request.reservation.clone();
    remote.operation_id = "remote-operation".into();
    remote.authorization_id = "remote-authorization".into();
    remote.original_consent_ref = "91".repeat(32);
    remote.obligation_id = "remote-obligation".into();
    remote.inputs[0].nullifier = "92".repeat(32);
    remote.inputs[0].input_id = "remote-input".into();
    remote.expected_head = synthetic::snapshot(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &remote.network_profile_id,
    )
    .unwrap()
    .head;
    synthetic::reserve(
        &f.witness,
        &"b2".repeat(32),
        remote.clone(),
        remote.reviewed_at_ms + 2,
    )
    .unwrap();
    let current = prepare_reconciliation(&f, &"b2".repeat(32));
    assert_eq!(current.reservation_count(), 2);
    commit_reconciliation(&f, current);
    let decision = fixture::decision(&f.session, stale.review_digest());
    assert!(matches!(
        f.journal.reconcile_writer(
            f.session
                .approve_writer_reconciliation(stale, decision)
                .unwrap()
        ),
        Err(JournalError::Conflict)
    ));
    let counts: (u64,u64,u64) = f.journal.connection.lock().unwrap().query_row(
        "SELECT (SELECT count(*) FROM signer_original_consents),(SELECT count(*) FROM signer_release_intents),(SELECT count(*) FROM signer_remote_exposures)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(counts, (1, 1, 2));
    assert!(matches!(
        f.journal
            .acquire_original_authorization("remote-authorization", &f.session),
        Err(JournalError::NotFound)
    ));
    let p = proposal("agreement-a", "fresh-obligation", "fresh-proposal");
    let (e, m) = enroll(&f.journal, &f.session, &p, 1_000_000_000);
    let mut t = terms(&f.session, &e, &m, "fresh-authorization");
    t.input_bindings[0].nullifier = "93".repeat(32);
    // Both local and remote exposure count, while the matching local copy is
    // deduplicated: 800,024,000 + 400,012,000 exceeds the original billion budget.
    assert!(matches!(
        f.journal
            .record_original_consent_release(fixture::approve_spend(&f.session, t.clone())),
        Err(JournalError::BudgetExceeded)
    ));
    let (e, m) = enroll(&f.journal, &f.session, &p, 1_300_000_000);
    let mut t = terms(&f.session, &e, &m, "fresh-authorization");
    t.input_bindings[0].nullifier = remote.inputs[0].nullifier.clone();
    assert!(matches!(
        f.journal
            .record_original_consent_release(fixture::approve_spend(&f.session, t.clone())),
        Err(JournalError::InputReserved)
    ));
    t.input_bindings[0].nullifier = "94".repeat(32);
    f.journal
        .record_original_consent_release(fixture::approve_spend(&f.session, t))
        .unwrap();
    let reopened = SignerConsentJournal::open_encrypted(
        &f.path,
        &f.key,
        "account-alice",
        &f.private_directory
            .signer_journal_source_owner_for_test(&f.path)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM signer_remote_exposures", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
}
#[test]
fn writer_reconciliation_advances_only_reviewed_owner_replacement_and_stales_old_session() {
    let f = Fixture::new();
    f.permit();
    let original_ref = f.original.original_consent().reference().to_string();
    let old = synthetic::snapshot(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    let now = f.request.reservation.reviewed_at_ms + 3;
    synthetic::control(
        &f.witness,
        &"a1".repeat(32),
        wholepact_authority::OwnerControlRequest {
            operation_id: "replace-writer".into(),
            account_id: "account-alice".into(),
            network_profile_id: f.request.reservation.network_profile_id.clone(),
            expected_head: old.head,
            writer_epoch: 1,
            control: wholepact_authority::OwnerControl::ReplaceWriter {
                writer_certificate_digest: "c3".repeat(32),
            },
        },
        now,
    )
    .unwrap();
    synthetic::activate(&f.witness, &"c3".repeat(32), now + 1).unwrap();
    let prepared = prepare_reconciliation(&f, &"c3".repeat(32));
    assert_eq!(prepared.writer_epoch(), 2);
    let bad = fixture::decision(&f.session, &"ff".repeat(32));
    assert!(matches!(
        f.session.approve_writer_reconciliation(prepared, bad),
        Err(JournalError::Permission)
    ));
    assert_eq!(f.journal.account_state().unwrap().writer_epoch, 1);
    commit_reconciliation(&f, prepare_reconciliation(&f, &"c3".repeat(32)));
    assert_eq!(f.journal.account_state().unwrap().writer_epoch, 2);
    assert!(matches!(
        f.journal
            .acquire_original_authorization("authorization-a", &f.session),
        Err(JournalError::Permission)
    ));
    let reference: String = f
        .journal
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT reference FROM signer_original_consents", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(reference, original_ref);
    f.journal.require_recovery().unwrap();
    let fresh = fixture::session(&f.journal, "synthetic-owner");
    let (history, active) = synthetic::reconciled_session(
        &f.witness,
        &"c3".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    assert!(matches!(
        fresh.prepare_writer_reconciliation(&f.journal, history, active),
        Err(JournalError::RecoveryRequired)
    ));
    assert!(f.journal.account_state().unwrap().recovery_required);
}

#[test]
fn writer_reconciliation_capacity_failure_rolls_back_all_remote_copies_and_receipts() {
    let mut f = Fixture::new();
    f.permit();
    let prepared = prepare_reconciliation(&f, &"b2".repeat(32));
    let decision = fixture::decision(&f.session, prepared.review_digest());
    let approved = f
        .session
        .approve_writer_reconciliation(prepared, decision)
        .unwrap();
    f.journal.capacity_limits = (0, u64::MAX);
    assert!(matches!(
        f.journal.reconcile_writer(approved),
        Err(JournalError::Limit)
    ));
    let counts: (u64,u64,u64) = f.journal.connection.lock().unwrap().query_row(
        "SELECT (SELECT count(*) FROM signer_original_consents),(SELECT count(*) FROM signer_remote_exposures),(SELECT count(*) FROM signer_writer_reconciliations)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(counts, (1, 0, 0));
    assert_eq!(f.journal.account_state().unwrap().writer_epoch, 1);
}

#[test]
fn exact_redelivery_requires_retained_result_and_preserves_original_and_key_use() {
    let f = Fixture::new();
    let original = f.original.original_consent();
    let t = original.terms();
    let result = f.result();
    let recipient = TransportIdentityBinding::LocalProcess {
        transport_identity_id: "33".repeat(32),
        channel_key_digest: "34".repeat(32),
        channel_binding_digest: "35".repeat(32),
        uid: 1000,
        pid: 1234,
        process_instance: "36".repeat(32),
        signer_generation: 1,
        account_id: t.account_id.clone(),
        agreement_id: t.agreement_id.clone(),
        participant_id: "alice".into(),
        manifest_digest: t.manifest_digest.clone(),
    };
    let record = ResultRedeliveryRecord::new(ResultRedeliveryTerms {
        request: ResultRedeliveryRequest {
            operation_id: "redelivery-a".into(),
            authorization_id: t.authorization_id.clone(),
            expected_original_consent_ref: original.reference().into(),
            expected_enrollment_ref: f.original.enrollment().reference().into(),
            expected_manifest_ref: f.original.accepted_manifest().reference().into(),
        },
        account_id: t.account_id.clone(),
        principal_id: t.principal_id.clone(),
        agreement_id: t.agreement_id.clone(),
        participant_id: "alice".into(),
        manifest_digest: t.manifest_digest.clone(),
        effects_digest: t.effects_digest.clone(),
        maximum_debit_zatoshis: t.maximum_debit_zatoshis,
        transaction_expiry_height: t.transaction_expiry_height,
        result_digest: result.result_digest().into(),
        outbox_digest: result.outbox_digest().into(),
        recipient,
        receipt: t.receipt.clone(),
    })
    .unwrap();
    assert!(
        f.journal
            .record_result_redelivery(fixture::approve_redelivery(&f.session, record.clone()))
            .is_err()
    );
    let lease = f.lease();
    f.journal.bridge_retain_request(&lease, &f.request).unwrap();
    let permit = f.permit();
    f.journal.bridge_retain_permit(&lease, &permit).unwrap();
    f.journal.bridge_begin_key_use(&lease, &permit).unwrap();
    f.journal.bridge_retain_result(&lease, &result).unwrap();
    f.journal
        .record_result_redelivery(fixture::approve_redelivery(&f.session, record.clone()))
        .unwrap();
    f.journal
        .record_result_redelivery(fixture::approve_redelivery(&f.session, record.clone()))
        .unwrap();
    assert!(
        f.journal
            .result_redelivery(&lease, "redelivery-a")
            .unwrap()
            .unwrap()
            == record
    );
    let mut changed = record.terms().clone();
    changed.outbox_digest = "ff".repeat(32);
    assert!(
        f.journal
            .record_result_redelivery(fixture::approve_redelivery(
                &f.session,
                ResultRedeliveryRecord::new(changed).unwrap()
            ))
            .is_err()
    );
    assert!(f.journal.bridge_result(&lease).unwrap() == result);
    assert!(f.journal.bridge_begin_key_use(&lease, &permit).is_err());
    let c = f.journal.connection.lock().unwrap();
    assert!(
        c.execute("DELETE FROM signer_result_redeliveries", [])
            .is_err()
    );
    let count: u64 = c
        .query_row("SELECT count(*) FROM signer_result_redeliveries", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn dispatch_retry_retains_exact_head_deadline_backend_and_original_result() {
    use crate::authority_bridge::{
        disclosure::RetainedWitnessDisclosure,
        dispatch_ipc::{BackendDisclosure, DispatchBackend, DispatchRequest, DispatchTransaction},
        ipc::HistoryRequest,
    };
    use crate::consent_journal::RetainedDispatch;
    let mut f = Fixture::new();
    let original = f.original.original_consent();
    let t = original.terms();
    let witness = wholepact_authority::WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:19443".into(),
        server_name: "synthetic.invalid".into(),
        witness_id: "synthetic-independent-witness".into(),
        account_id: t.account_id.clone(),
        network_profile_id: f.request.reservation.network_profile_id.clone(),
        policy_digest: "a1".repeat(32),
        pinned_server_certificate_digest: "b2".repeat(32),
    };
    let nonce = "c3".repeat(32);
    let head = f.request.reservation.expected_head.clone();
    f.request.disclosure = Some(RetainedWitnessDisclosure {
        descriptor: witness.clone(),
        original_consent_ref: original.reference().into(),
        native_review_digest: wholepact_core::proposal::canonical_digest(
            "wholepact:exact-native-witness-disclosure:v1",
            &(&witness, &head, &nonce, original),
        )
        .unwrap(),
        expected_head: head.clone(),
        nonce,
        native_origin_measurement: t.receipt.trusted_launch_measurement().into(),
        native_principal_id: t.principal_id.clone(),
    });
    let backend = BackendDisclosure {
        schema_version: 1,
        profile_id: "synthetic-profile".into(),
        principal_id: "synthetic-owner".into(),
        agreement_id: t.agreement_id.clone(),
        submission_journal_identity: "synthetic-private-journal-canary".into(),
        descriptor: DispatchTransaction {
            operation_id: "submission-a".into(),
            obligation_id: t.obligation_id.clone(),
            proposal_id: t.proposal_id.clone(),
            transaction_id: "d4".repeat(32),
            bytes_sha256: "e5".repeat(32),
            expiry_height: t.transaction_expiry_height,
            network: "testnet".into(),
            consensus_branch_id: 0x77190ad9,
        },
        backend: DispatchBackend {
            source_id: "synthetic-provider".into(),
            endpoint: "https://synthetic.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        purpose: "submit_exact_retained_transaction".into(),
        confidence: "single_tls_provider_report_not_consensus".into(),
        minimum_expiry_margin_blocks: 10,
    };
    let request = DispatchRequest {
        history: HistoryRequest {
            authorization_id: t.authorization_id.clone(),
            expected_original_consent_ref: original.reference().into(),
            expected_enrollment_ref: f.original.enrollment().reference().into(),
            expected_manifest_ref: f.original.accepted_manifest().reference().into(),
        },
        operation_id: "dispatch-a".into(),
        backend,
    };
    let exact = wholepact_authority::AuthorizeDispatch {
        operation_id: request.operation_id.clone(),
        account_id: t.account_id.clone(),
        network_profile_id: witness.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: head,
        reservation_operation_id: t.authorization_id.clone(),
        reservation_request_digest: f.request.reservation.request_digest().unwrap(),
        final_transaction_digest: request.backend.descriptor.bytes_sha256.clone(),
        final_transaction_id: request.backend.descriptor.transaction_id.clone(),
        transaction_expiry_height: t.transaction_expiry_height,
        backend_disclosure_digest: request.backend.digest().unwrap(),
        reviewed_at_ms: f.request.reservation.reviewed_at_ms,
        admission_expires_at_ms: f.request.reservation.reviewed_at_ms + 120_000,
    };
    let record = RetainedDispatch {
        request,
        exact,
        witness,
    };
    let lease = f.lease();
    assert!(f.journal.retain_dispatch(&lease, &record).is_err());
    f.journal.bridge_retain_request(&lease, &f.request).unwrap();
    let permit = f.permit();
    f.journal.bridge_retain_permit(&lease, &permit).unwrap();
    f.journal.bridge_begin_key_use(&lease, &permit).unwrap();
    f.journal.bridge_retain_result(&lease, &f.result()).unwrap();
    f.journal.retain_dispatch(&lease, &record).unwrap();
    f.journal.retain_dispatch(&lease, &record).unwrap();
    assert!(
        f.journal
            .retained_dispatch(&lease, "dispatch-a")
            .unwrap()
            .unwrap()
            == record
    );
    let mut changed = record.clone();
    changed.exact.expected_head.digest = "f6".repeat(32);
    assert!(matches!(
        f.journal.retain_dispatch(&lease, &changed),
        Err(BridgeError::Conflict)
    ));
    let mut changed = record.clone();
    changed.exact.reviewed_at_ms += 1;
    changed.exact.admission_expires_at_ms += 1;
    assert!(matches!(
        f.journal.retain_dispatch(&lease, &changed),
        Err(BridgeError::Conflict)
    ));
    let mut changed = record.clone();
    changed.request.backend.backend.endpoint = "https://changed.invalid".into();
    changed.exact.backend_disclosure_digest = changed.request.backend.digest().unwrap();
    assert!(matches!(
        f.journal.retain_dispatch(&lease, &changed),
        Err(BridgeError::Conflict)
    ));
    assert!(f.journal.bridge_result(&lease).unwrap() == f.result());
    assert!(f.journal.bridge_begin_key_use(&lease, &permit).is_err());
    assert!(f
        .journal
        .connection
        .lock()
        .unwrap()
        .execute("DELETE FROM signer_dispatch_requests", [])
        .is_err());
    drop(lease);
    let reopened = SignerConsentJournal::open_encrypted(
        &f.path,
        &f.key,
        "account-alice",
        &f.private_directory
            .signer_journal_source_owner_for_test(&f.path)
            .unwrap(),
    )
    .unwrap();
    let session = fixture::session(&reopened, "synthetic-owner");
    let lease = reopened
        .acquire_original_authorization("authorization-a", &session)
        .unwrap();
    assert!(
        reopened
            .retained_dispatch(&lease, "dispatch-a")
            .unwrap()
            .unwrap()
            == record
    );
    let bytes = std::fs::read(&f.path).unwrap();
    assert!(
        !bytes
            .windows(b"synthetic-private-journal-canary".len())
            .any(|b| b == b"synthetic-private-journal-canary")
    );
}

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[path = "recovery_protocol_tests.rs"]
mod recovery_protocol_tests;

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[path = "host_recovery_continuity_tests.rs"]
mod host_recovery_continuity_tests;

// The private Fixture supplies a retained original/request/permit/result through synthetic
// fixture APIs. This is fabricated never-funded history, not native approval,
// cryptographic signing, a broadcast, or independently authenticated settlement.
#[cfg(all(
    feature = "authority-signing",
    feature = "native-ui",
    target_os = "linux"
))]
#[test]
fn permanent_stop_reads_coparty_settlement_without_local_dispatch_and_rejects_tamper() {
    use wholepact_chain::{
        BlockIdentity, ConfirmationPolicy, ReconciliationReport, SettlementObservationState,
        SourceTip,
    };
    let f = Fixture::new();
    {
        let lease = f.lease();
        f.journal.bridge_retain_request(&lease, &f.request).unwrap();
        let permit = f.permit();
        f.journal.bridge_retain_permit(&lease, &permit).unwrap();
        // This stores the fixture's one-way uncertainty marker and inert canary
        // result. It never accesses a spending key or creates a signature.
        f.journal.bridge_begin_key_use(&lease, &permit).unwrap();
        f.journal.bridge_retain_result(&lease, &f.result()).unwrap();
    }
    let node = wholepact_chain::local_node::LocalNodeSourceDescriptor {
        source_id: "synthetic-historical-node".into(),
        endpoint: "127.0.0.1:12345".into(),
        server_name: "localhost".into(),
        pinned_certificate_sha256: "11".repeat(32),
        client_certificate_sha256: "22".repeat(32),
        trusted_root_sha256: vec!["33".repeat(32)],
        node_release: wholepact_chain::local_node::ZEBRA_RELEASE.into(),
        node_source_commit: wholepact_chain::local_node::ZEBRA_SOURCE_COMMIT.into(),
        network: "testnet".into(),
        consensus_branch_id: wholepact_chain::NU7_BRANCH_ID,
        activation_height: wholepact_chain::NU7_ACTIVATION_HEIGHT,
        confirmation_policy: ConfirmationPolicy::new(
            10,
            10,
            vec!["synthetic-historical-node".into()],
        )
        .unwrap(),
    };
    let prepared = f
        .session
        .prepare_settlement_source(&f.journal, node.clone(), "44".repeat(32))
        .unwrap();
    let decision = fixture::decision(&f.session, prepared.review_digest());
    let source = f
        .journal
        .record_settlement_source(
            f.session
                .approve_settlement_source(prepared, decision)
                .unwrap(),
        )
        .unwrap();
    let original = f.original.original_consent();
    let terms = original.terms();
    let block = BlockIdentity {
        height: 2_999_900,
        hash: "55".repeat(32),
    };
    let report = ReconciliationReport {
        transaction_id: "66".repeat(32),
        expiry_height: terms.transaction_expiry_height,
        policy: node.confirmation_policy.clone(),
        observed_at_unix_seconds: 100,
        valid_until_unix_seconds: 130,
        state: SettlementObservationState::ConfirmationPolicyMet {
            block: block.clone(),
            confirmations: 21,
        },
        last_inclusion: Some(block.clone()),
        confidence_lost: false,
        reorganization_observed: false,
        source_ids: vec![node.source_id.clone()],
        source_tips: vec![SourceTip {
            source_id: node.source_id.clone(),
            tip: BlockIdentity {
                height: 2_999_920,
                hash: "77".repeat(32),
            },
        }],
        independently_consensus_verified: false,
        clears_authorization_exposure: false,
        permits_replacement: false,
    };
    let nullifiers: Vec<_> = terms
        .input_bindings
        .iter()
        .map(|i| i.nullifier.clone())
        .collect();
    let payload = serde_json::json!({
        "original_consent_ref": original.reference(),
        "request_digest": f.request.reservation.request_digest().unwrap(), "source": source,
        "transaction": {"operation_id":"synthetic-coparty-dispatch", "obligation_id":terms.obligation_id,
            "proposal_id":terms.proposal_id, "transaction_id":"66".repeat(32),"bytes_sha256":"88".repeat(32),
            "expiry_height":terms.transaction_expiry_height,"network":"testnet","consensus_branch_id":wholepact_chain::NU7_BRANCH_ID},
        "report": report, "archive": null,
        "witness": {"record": {"operation_id":"synthetic-historical-resolution","account_id":terms.account_id,
            "network_profile_id":f.request.reservation.network_profile_id,
            "expected_head":{"sequence":3,"digest":"99".repeat(32)},"reservation_operation_id":terms.authorization_id,
            "reservation_request_digest":f.request.reservation.request_digest().unwrap(),
            "final_transaction_id":"66".repeat(32),"final_transaction_digest":"88".repeat(32),
            "source_descriptor_digest":"44".repeat(32),"evidence_digest":"aa".repeat(32),
            "consumed_nullifiers":nullifiers,"inclusion_block_hash":block.hash,"inclusion_block_height":block.height},
            "committed_head":{"sequence":4,"digest":"bb".repeat(32)}},
        "consumed_nullifiers":nullifiers
    });
    let c = f.journal.connection.lock().unwrap();
    assert!(f.request.disclosure.is_none());
    assert_eq!(
        c.query_row("SELECT count(*) FROM signer_dispatch_requests", [], |r| r
            .get::<_, u64>(
            0
        ))
        .unwrap(),
        0
    );
    c.execute("INSERT INTO signer_settlement_events(evidence_id,authorization_id,source_ref,kind,payload) VALUES(?1,?2,?3,'canonical_consumed',?4)",
        rusqlite::params!["cc".repeat(32),terms.authorization_id,source.reference(),payload.to_string()]).unwrap();
    c.execute(
        "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
        [],
    )
    .unwrap();
    let account = storage::read_account(&c).unwrap();
    assert!(account.recovery_required);
    let before = c.total_changes();
    let result =
        crate::consent_journal::settlement::read_permanent_stop_history(&c, &account).unwrap();
    assert_eq!(before, c.total_changes());
    assert_eq!(result["current_authentication"], false);
    assert_eq!(result["release_authority"], false);
    let row = &result["settlement_events"][0];
    assert_eq!(row["retained_dispatch_present"], false);
    assert_eq!(row["historical_kind"], "canonical_consumed");
    assert_eq!(
        row["historical_maximum_debit_zatoshis"],
        terms.maximum_debit_zatoshis.to_string()
    );
    assert_eq!(row["current_canonical_status"], "unknown");
    assert_eq!(row["spendable_budget"], "unknown");
    let display = serde_json::to_string(&result).unwrap();
    assert!(!display.contains("never-funded-bridge-result-storage-canary"));
    assert!(!display.contains("signed_pczt_hex"));
    assert!(
        storage::read_original(&c, &terms.authorization_id)
            .unwrap()
            .unwrap()
            == f.original
    );
    // Append a malformed synthetic history row without rewriting the valid one.
    let mut wrong = payload.clone();
    wrong["witness"]["record"]["reservation_request_digest"] = serde_json::json!("dd".repeat(32));
    c.execute("INSERT INTO signer_settlement_events(evidence_id,authorization_id,source_ref,kind,payload) VALUES(?1,?2,?3,'canonical_consumed',?4)",
        rusqlite::params!["ee".repeat(32),terms.authorization_id,source.reference(),wrong.to_string()]).unwrap();
    let before = c.total_changes();
    assert!(crate::consent_journal::settlement::read_permanent_stop_history(&c, &account).is_err());
    assert_eq!(before, c.total_changes());
    assert!(
        storage::read_original(&c, &terms.authorization_id)
            .unwrap()
            .unwrap()
            == f.original
    );
}

// Pure historical corruption fixture. Both alternate records are valid original
// retained records; no live permission or key-use capability is constructed.
#[test]
fn permanent_stop_history_rejects_substituted_original_row_enrollment_and_manifest() {
    let f = Fixture::new();
    let other = proposal("agreement-b", "obligation-b", "proposal-b");
    let (enrollment, manifest) = enroll(&f.journal, &f.session, &other, 1_000_000_000);
    let account = f.journal.account_state().unwrap();
    let mut c = f.journal.connection.lock().unwrap();
    let tx = c.transaction().unwrap();
    super::super::writer_history::WriterLocalInventory::read(&tx, &account, f.journal.capacity_limits()).unwrap();
    let trigger: String = tx.query_row("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='signer_consents_no_update'", [], |r| r.get(0)).unwrap();
    // Restore the exact original schema after inserting the malformed fixture,
    // so rejection must validate row linkage rather than a missing trigger.
    for column in ["enrollment_ref", "manifest_ref"] {
        tx.execute_batch("SAVEPOINT historical_substitution; DROP TRIGGER signer_consents_no_update;").unwrap();
        let replacement = if column == "enrollment_ref" { enrollment.reference() } else { manifest.reference() };
        tx.execute(&format!("UPDATE signer_original_consents SET {column}=?1 WHERE authorization_id=?2"),
            rusqlite::params![replacement, f.original.original_consent().terms().authorization_id]).unwrap();
        tx.execute_batch(&trigger).unwrap();
        storage::verify_schema(&tx).unwrap();
        assert!(tx.prepare("PRAGMA foreign_key_check").unwrap().query([]).unwrap().next().unwrap().is_none());
        let before = tx.total_changes();
        assert!(super::super::writer_history::WriterLocalInventory::read(&tx, &account, f.journal.capacity_limits()).is_err());
        assert_eq!(before, tx.total_changes());
        tx.execute_batch("ROLLBACK TO historical_substitution; RELEASE historical_substitution;").unwrap();
    }
    super::super::writer_history::WriterLocalInventory::read(&tx, &account, f.journal.capacity_limits()).unwrap();
    tx.rollback().unwrap();
}
