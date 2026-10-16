//! Synthetic HPKE + SQLCipher component qualification fixtures. Deterministic fixture
//! key bytes are not live credentials. No authority issuer/factory is constructed.
//! Only this in-crate test uses seal_qualified to create authenticated wire input.
use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use wholepact_authority::offline::{
    OfflineAuthoritySemantics, OfflineAuthorizationTerms, OfflineReservationIntent,
    OfflineSnapshotCommitment, OfflineUnknownFact,
};
use wholepact_authority::{AuthorityHead, InputReservation};
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
fn h(n: u8) -> String {
    format!("{n:064x}")
}
fn original_fixture(
    witness: &TransportPublicKey,
    signer: &TransportPublicKey,
) -> (
    ReserveOfflineAuthorization,
    AccountPolicy,
    OfflineEnrollmentPolicy,
) {
    let account = AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-witness".into(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        owner_certificate_digest: h(1),
        initial_writer_certificate_digest: h(2),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h(3)],
        agreement_ids: vec!["synthetic-agreement".into()],
        recipient_scope_digests: vec![h(4)],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 80,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 10,
        maximum_permit_lifetime_ms: 60_000,
        policy_expires_at_ms: 100_000,
    };
    let offline = OfflineEnrollmentPolicy {
        schema_version: 1,
        account_id: account.account_id.clone(),
        network_profile_id: account.network_profile_id.clone(),
        witness_id: account.witness_id.clone(),
        witness_transport_key_digest: witness.fingerprint(),
        witness_certificate_digest: h(6),
        enrollment_ref: h(3),
        offline_signer_key_digest: signer.fingerprint(),
        return_recipient_key_digest: h(8),
        source_identity_digest: h(9),
        source_policy_digest: h(10),
        maximum_admission_lifetime_ms: 50_000,
        valid_from_ms: 1,
        expires_at_ms: 90_000,
        semantics: OfflineAuthoritySemantics::ExactEffectsPreReservedMayDrainAfterRevocation,
    };
    let request = ReserveOfflineAuthorization {
        schema_version: 1,
        operation_id: "synthetic-offline-reservation".into(),
        writer_epoch: 1,
        expected_head: AuthorityHead {
            sequence: 1,
            digest: h(11),
        },
        intent: OfflineReservationIntent {
            schema_version: 1,
            intent_id: "synthetic-native-reservation-intent".into(),
            native_reservation_review_digest: h(12),
            terms: OfflineAuthorizationTerms {
                account_id: account.account_id.clone(),
                network_profile_id: account.network_profile_id.clone(),
                consensus_branch_id: 0x77190ad9,
                authorization_id: "synthetic-authorization".into(),
                enrollment_ref: h(3),
                accepted_manifest_ref: h(13),
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                proposal_id: "synthetic-proposal".into(),
                proposal_revision: 1,
                proposal_digest: h(14),
                manifest_digest: h(15),
                effects_digest: h(16),
                artifact_digest: h(17),
                review_binding: h(18),
                review_package_digest: h(19),
                recipient_scope_digest: h(4),
                offline_signer_key_digest: signer.fingerprint(),
                return_recipient_key_digest: h(8),
                offline_policy_digest: offline.policy_digest().unwrap(),
                snapshot: OfflineSnapshotCommitment {
                    source_id: "synthetic-source".into(),
                    source_identity_digest: h(9),
                    source_policy_digest: h(10),
                    snapshot_digest: h(20),
                    observed_at_ms: 1000,
                    tip_height: 100,
                    tip_hash: h(21),
                    anchor_height: 95,
                    anchor_hash: h(22),
                    anchor_root: h(23),
                },
                inputs: vec![InputReservation {
                    input_id: "synthetic-input".into(),
                    nullifier: h(24),
                    action_index: 0,
                    value_zatoshis: 100,
                }],
                maximum_debit_zatoshis: 70,
                fee_share_zatoshis: 2,
                transaction_fee_zatoshis: 4,
                transaction_expiry_height: 200,
                unknown_facts: OfflineUnknownFact::ALL.to_vec(),
                semantics: offline.semantics,
            },
        },
        requested_at_ms: 2000,
        admission_expires_at_ms: 30_000,
    };
    (request, account, offline)
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "wholepact-synthetic-control-{}-{}-{nanos}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    request: ReserveOfflineAuthorization,
    account: AccountPolicy,
    offline: OfflineEnrollmentPolicy,
    original_plan: OfflineAdmissionExportPlan,
    control_plan: OfflineAdmissionExportPlan,
    control: OfflineAdmissionControl,
    witness: TransportSecret,
    signer: TransportSecret,
}
impl Fixture {
    fn new(outcome: OfflineAdmissionControlOutcome) -> Self {
        let witness = TransportSecret::from_bytes([0x31; 32]).unwrap();
        let signer = TransportSecret::from_bytes([0x32; 32]).unwrap();
        let (request, account, offline) = original_fixture(
            &witness.public_key().unwrap(),
            &signer.public_key().unwrap(),
        );
        let original_plan = OfflineAdmissionExportPlan {
            message_id: "11".repeat(16),
            sequence: 1,
            issued_at_unix_seconds: 2,
            expires_at_unix_seconds: 30,
            purpose: "Synthetic original admission".into(),
            persistence_warning: "Synthetic recipient can retain".into(),
            sender_id: format!(
                "offline-admission:{}",
                request.intent.terms.offline_policy_digest
            ),
            recipient_id: format!(
                "offline-admission:{}",
                request.intent.terms.offline_signer_key_digest
            ),
            sender_key_fingerprint: witness.public_key().unwrap().fingerprint(),
            recipient_key_fingerprint: signer.public_key().unwrap().fingerprint(),
        };
        original_plan
            .matches_preparation(&request, &offline)
            .unwrap();
        let mut control_plan = original_plan.clone();
        control_plan.message_id = "22".repeat(16);
        control_plan.issued_at_unix_seconds = 40;
        control_plan.expires_at_unix_seconds = 50;
        control_plan.purpose = "Synthetic non-authorizing control".into();
        let control = OfflineAdmissionControl {
            schema_version: 1,
            witness_id: account.witness_id.clone(),
            witness_policy_digest: account.policy_digest().unwrap(),
            witness_transport_key_digest: witness.public_key().unwrap().fingerprint(),
            request_digest: request.request_digest().unwrap(),
            request: request.clone(),
            prepared_record_digest: h(31),
            authenticated_receipt_digest: h(32),
            original_export_plan_digest: original_plan.plan_digest().unwrap(),
            original_sequence: 1,
            selected_head: AuthorityHead {
                sequence: 2,
                digest: h(33),
            },
            selected_at_ms: 40000,
            outcome,
        };
        control.validate_export_plan(&control_plan).unwrap();
        Self {
            request,
            account,
            offline,
            original_plan,
            control_plan,
            control,
            witness,
            signer,
        }
    }
    fn expected(&self) -> OfflineControlImportExpected<'_> {
        OfflineControlImportExpected {
            request: &self.request,
            account_policy: &self.account,
            offline_policy: &self.offline,
            original_export_plan: &self.original_plan,
            prepared_record_digest: &self.control.prepared_record_digest,
            authenticated_receipt_digest: &self.control.authenticated_receipt_digest,
        }
    }
    fn envelope(
        &self,
        control: &OfflineAdmissionControl,
        context: MessageContext,
        sender: &TransportSecret,
    ) -> EncryptedEnvelope {
        let p = &self.control_plan;
        let prepared = prepare_export(
            ExportRequest {
                context,
                order: MessageOrder {
                    message_id: p.message_id.clone(),
                    sequence: p.sequence,
                    issued_at: Timestamp::from_unix_seconds(p.issued_at_unix_seconds).unwrap(),
                    expires_at: Timestamp::from_unix_seconds(p.expires_at_unix_seconds).unwrap(),
                },
                purpose: p.purpose.clone(),
                persistence_warning: p.persistence_warning.clone(),
            },
            vec![
                DisclosureField::new(CONTROL_FIELD, crate::types::encode(control).unwrap())
                    .unwrap(),
            ],
            &sender.public_key().unwrap(),
            &self.signer.public_key().unwrap(),
            &time(40),
        )
        .unwrap();
        let approved = prepared.preview().digest().unwrap();
        prepared
            .seal_qualified(sender, &approved, &time(40))
            .unwrap()
    }
    fn valid_envelope(&self) -> EncryptedEnvelope {
        self.envelope(
            &self.control,
            control_context(&self.expected()).unwrap(),
            &self.witness,
        )
    }
}
fn time(n: i64) -> Timestamp {
    Timestamp::from_unix_seconds(n).unwrap()
}
fn outcome_count(inbox: &SqliteReplayLedger) -> i64 {
    inbox
        .connection
        .query_row("SELECT count(*) FROM offline_control_outcomes", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn synthetic_hpke_atomic_control_failure_rolls_back_retry_and_restart_preserve_exact_record() {
    let f = Fixture::new(OfflineAdmissionControlOutcome::NoAdmission);
    let temp = Temp::new();
    let path = temp.0.join("inbox.db");
    let key = DatabaseKey::from_bytes([0x41; 32]);
    let mut inbox =
        SqliteReplayLedger::from_encrypted_connection(create_encrypted(&path, &key).unwrap())
            .unwrap();
    let envelope = f.valid_envelope();
    let witness_key = f.witness.public_key().unwrap();
    // A test-only trigger fails the SECOND insert, after replay insertion in the
    // same transaction. Runtime open verifies exact schema; production adds none.
    inbox.connection.execute_batch("CREATE TEMP TRIGGER synthetic_fail_control BEFORE INSERT ON offline_control_outcomes BEGIN SELECT RAISE(ABORT,'synthetic injected second insert failure'); END;").unwrap();
    assert_eq!(
        accept_offline_control(
            &envelope,
            &f.signer,
            &witness_key,
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .err(),
        Some(TransportError::Storage)
    );
    assert_eq!(inbox.record_count().unwrap(), 0);
    assert_eq!(outcome_count(&inbox), 0);
    inbox
        .connection
        .execute_batch("DROP TRIGGER synthetic_fail_control;")
        .unwrap();
    let receipt = accept_offline_control(
        &envelope,
        &f.signer,
        &witness_key,
        &f.expected(),
        &time(40),
        &mut inbox,
    )
    .unwrap();
    assert!(receipt.terminal_control_recorded());
    assert!(!receipt.authorization_allowed());
    assert!(matches!(
        receipt.control().outcome,
        OfflineAdmissionControlOutcome::NoAdmission
    ));
    assert_eq!(inbox.record_count().unwrap(), 1);
    assert_eq!(outcome_count(&inbox), 1);
    assert_eq!(
        accept_offline_control(
            &envelope,
            &f.signer,
            &witness_key,
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .err(),
        Some(TransportError::Replay)
    );
    let stored: Vec<u8> = inbox
        .connection
        .query_row("SELECT envelope FROM receipts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, envelope.as_bytes());
    let envelope_digest = receipt.envelope_digest().to_owned();
    drop(inbox);
    let inbox = SqliteReplayLedger::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
        .unwrap();
    let recovered =
        recover_offline_control_receipt(&f.signer, &witness_key, &f.expected(), &time(51), &inbox)
            .unwrap()
            .unwrap();
    assert_eq!(recovered.envelope_digest(), envelope_digest);
    assert!(!recovered.currently_within_transport_window());
    assert_eq!(
        recovered.control().control_digest().unwrap(),
        f.control.control_digest().unwrap()
    );
    let stored_after: Vec<u8> = inbox
        .connection
        .query_row("SELECT envelope FROM receipts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored_after, stored);
    assert_eq!(outcome_count(&inbox), 1);
    // Corrupt/missing typed history is not reconstructed from valid ciphertext.
    inbox
        .connection
        .execute("DELETE FROM offline_control_outcomes", [])
        .unwrap();
    assert_eq!(
        recover_offline_control_receipt(&f.signer, &witness_key, &f.expected(), &time(51), &inbox)
            .err(),
        Some(TransportError::DomainConflict)
    );
}

#[test]
fn synthetic_hpke_atomic_control_rejects_forged_keys_and_context_before_any_commit() {
    let f = Fixture::new(OfflineAdmissionControlOutcome::ExposureRetained {
        admission_digest: h(34),
    });
    let temp = Temp::new();
    let key = DatabaseKey::from_bytes([0x42; 32]);
    let mut inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(temp.0.join("inbox.db"), &key).unwrap(),
    )
    .unwrap();
    let witness_key = f.witness.public_key().unwrap();
    let stranger = TransportSecret::from_bytes([0x35; 32]).unwrap();
    let valid = f.valid_envelope();
    assert!(
        accept_offline_control(
            &valid,
            &stranger,
            &witness_key,
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .is_err()
    );
    assert!(
        accept_offline_control(
            &valid,
            &f.signer,
            &stranger.public_key().unwrap(),
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .is_err()
    );
    let forged_sender = f.envelope(
        &f.control,
        control_context(&f.expected()).unwrap(),
        &stranger,
    );
    assert!(
        accept_offline_control(
            &forged_sender,
            &f.signer,
            &witness_key,
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .is_err()
    );
    let mut wrong_context = control_context(&f.expected()).unwrap();
    wrong_context.proposal_id = "synthetic-wrong-proposal".into();
    let wrong = f.envelope(&f.control, wrong_context, &f.witness);
    assert!(
        accept_offline_control(
            &wrong,
            &f.signer,
            &witness_key,
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .is_err()
    );
    let mut forged_control = f.control.clone();
    forged_control.original_export_plan_digest = h(35);
    let forged = f.envelope(
        &forged_control,
        control_context(&f.expected()).unwrap(),
        &f.witness,
    );
    assert!(
        accept_offline_control(
            &forged,
            &f.signer,
            &witness_key,
            &f.expected(),
            &time(40),
            &mut inbox
        )
        .is_err()
    );
    assert_eq!(inbox.record_count().unwrap(), 0);
    assert_eq!(outcome_count(&inbox), 0);
    assert_eq!(
        accept_offline_control(
            &valid,
            &f.signer,
            &witness_key,
            &f.expected(),
            &time(50),
            &mut inbox
        )
        .err(),
        Some(TransportError::InvalidTime)
    );
    let receipt = accept_offline_control(
        &valid,
        &f.signer,
        &witness_key,
        &f.expected(),
        &time(40),
        &mut inbox,
    )
    .unwrap();
    assert!(
        matches!(&receipt.control().outcome,OfflineAdmissionControlOutcome::ExposureRetained { admission_digest } if admission_digest == &h(34))
    );
    assert!(!receipt.authorization_allowed());
    assert_eq!(outcome_count(&inbox), 1);
}
