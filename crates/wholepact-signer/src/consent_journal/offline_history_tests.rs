//! Synthetic source tests, staged but NOT RUN. SQL shape fixtures are not a
//! native consent/authentication, encrypted storage, cryptographic signing or
//! production offline end-to-end qualification.
use super::*;
use rusqlite::params;
use wholepact_authority::InputReservation;
use wholepact_authority::offline::*;

pub(in crate::consent_journal) fn h(n: u8) -> String {
    format!("{n:064x}")
}
fn fixture() -> (
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
        witness_transport_key_digest: h(5),
        witness_certificate_digest: h(6),
        enrollment_ref: h(3),
        offline_signer_key_digest: h(7),
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
                offline_signer_key_digest: h(7),
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
pub(in crate::consent_journal) fn connection() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    c.execute(
        "INSERT INTO signer_account VALUES(1,'synthetic-account',1,1)",
        [],
    )
    .unwrap();
    c
}
pub(in crate::consent_journal) fn full_admission() -> (
    OfflineAuthorizationAdmission,
    OfflineEnrollmentPolicy,
    OfflineRemoteHistoryProvenance,
) {
    let (request, account, policy) = fixture();
    let admission = OfflineAuthorizationAdmission {
        schema_version: 1,
        witness_id: account.witness_id.clone(),
        witness_policy_digest: account.policy_digest().unwrap(),
        witness_transport_key_digest: policy.witness_transport_key_digest.clone(),
        request_digest: request.request_digest().unwrap(),
        request,
        committed_head: AuthorityHead {
            sequence: 2,
            digest: h(30),
        },
        reserved_at_ms: 3_000,
        account_outstanding_debit_zatoshis: 70,
        account_reserved_input_value_zatoshis: 100,
        writer_session_id: h(31),
    };
    let provenance = OfflineRemoteHistoryProvenance {
        witness: WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:443".into(),
            server_name: "synthetic.invalid".into(),
            witness_id: account.witness_id.clone(),
            account_id: account.account_id.clone(),
            network_profile_id: account.network_profile_id.clone(),
            policy_digest: account.policy_digest().unwrap(),
            pinned_server_certificate_digest: policy.witness_certificate_digest.clone(),
        },
        enrollment_operation: OwnerControlRequest {
            operation_id: "synthetic-enrollment-op".into(),
            account_id: account.account_id.clone(),
            network_profile_id: account.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: AuthorityHead {
                sequence: 0,
                digest: h(0),
            },
            control: OwnerControl::EnrollOfflinePolicy {
                policy: policy.clone(),
                expected_previous_digest: None,
            },
        },
        account_policy: account,
        history_head: admission.committed_head.clone(),
        history_digest: h(32),
    };
    (admission, policy, provenance)
}
pub(in crate::consent_journal) fn minimal(
    admission: &OfflineAuthorizationAdmission,
) -> OfflineLocalAdmissionHistory {
    let terms = admission.request.intent.terms.clone();
    let statement = OfflineMinimalAdmissionHistoryStatement {
        schema_version: 1,
        witness_id: admission.witness_id.clone(),
        witness_transport_key_digest: admission.witness_transport_key_digest.clone(),
        witness_policy_digest: admission.witness_policy_digest.clone(),
        operation_id: admission.request.operation_id.clone(),
        authorization_id: terms.authorization_id.clone(),
        request_digest: admission.request_digest.clone(),
        intent_digest: admission.request.intent.intent_digest().unwrap(),
        terms_digest: terms.terms_digest().unwrap(),
        review_package_digest: terms.review_package_digest.clone(),
        original_admission_digest: transport_history_digest(
            b"wholepact.offline-original-admission-assertion.v1\0",
            encode(admission).unwrap().as_bytes(),
        ),
        original_export_plan_digest: h(33),
        committed_head: admission.committed_head.clone(),
        reserved_at_ms: admission.reserved_at_ms,
        admission_expires_at_ms: admission.request.admission_expires_at_ms,
    };
    OfflineLocalAdmissionHistory {
        statement_digest: statement.statement_digest().unwrap(),
        owner_setup_digest: h(34),
        pinned_witness_certificate_digest: h(6),
        source_envelope_digest: h(35),
        source_content_digest: h(36),
        intent_digest: statement.intent_digest.clone(),
        admission_request_digest: statement.request_digest.clone(),
        authenticated_package_digest: terms.review_package_digest.clone(),
        statement,
        terms,
    }
}
pub(in crate::consent_journal) fn insert_local(
    c: &Connection,
    local: &OfflineLocalAdmissionHistory,
) {
    let t = &local.terms;
    c.execute(
        "INSERT INTO signer_offline_local_admissions VALUES(?1,?2,?3,?4,?5)",
        params![
            t.authorization_id,
            t.account_id,
            t.obligation_id,
            t.maximum_debit_zatoshis.to_string(),
            encode(local).unwrap().as_str()
        ],
    )
    .unwrap();
    for i in &t.inputs {
        c.execute(
            "INSERT INTO signer_offline_local_inputs VALUES(?1,?2,?3)",
            params![t.authorization_id, t.account_id, i.nullifier],
        )
        .unwrap();
    }
}
pub(in crate::consent_journal) fn insert_remote(
    c: &Connection,
    admission: &OfflineAuthorizationAdmission,
    policy: &OfflineEnrollmentPolicy,
    provenance: &OfflineRemoteHistoryProvenance,
) {
    let t = &admission.request.intent.terms;
    c.execute(
        "INSERT INTO signer_offline_enrollments VALUES(?1,?2,?3,?4)",
        params![
            policy.policy_digest().unwrap(),
            policy.enrollment_ref,
            policy.account_id,
            encode(policy).unwrap().as_str()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO signer_offline_intents VALUES(?1,?2,?3,?4)",
        params![
            admission.request.intent.intent_digest().unwrap(),
            t.authorization_id,
            t.offline_policy_digest,
            encode(&admission.request.intent).unwrap().as_str()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO signer_offline_admissions VALUES(?1,?2,?3)",
        params![
            t.authorization_id,
            admission.request_digest,
            encode(admission).unwrap().as_str()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO signer_offline_remote_exposures VALUES(?1,?2,?3,?4,?5)",
        params![
            t.authorization_id,
            t.account_id,
            t.obligation_id,
            t.maximum_debit_zatoshis.to_string(),
            encode(provenance).unwrap().as_str()
        ],
    )
    .unwrap();
    for i in &t.inputs {
        c.execute(
            "INSERT INTO signer_offline_remote_inputs VALUES(?1,?2,?3)",
            params![t.authorization_id, t.account_id, i.nullifier],
        )
        .unwrap();
    }
}
pub(in crate::consent_journal) fn original(
    local: &OfflineLocalAdmissionHistory,
) -> OfflineOriginalConsentHistory {
    let mut original = OfflineOriginalConsentHistory {
        reference: h(0),
        account_id: local.terms.account_id.clone(),
        authorization_id: local.terms.authorization_id.clone(),
        return_recipient_key_digest: local.terms.return_recipient_key_digest.clone(),
        admission_request_digest: local.admission_request_digest.clone(),
        intent_digest: local.intent_digest.clone(),
        terms_digest: local.terms.terms_digest().unwrap(),
        authenticated_package_digest: local.authenticated_package_digest.clone(),
        native_review_digest: h(40),
        receipt: OfflineNativeConsentHistoryReceipt {
            native_session_id: h(41),
            trusted_launch_measurement: h(42),
            permission_generation: 1,
            nonce: h(43),
            reviewed_at_ms: 4_000,
            expires_at_ms: 5_000,
            intent_digest: local.intent_digest.clone(),
            admission_request_digest: local.admission_request_digest.clone(),
            authenticated_package_digest: local.authenticated_package_digest.clone(),
        },
    };
    original.reference = digest(
        "wholepact:offline-original-consent-history:v1",
        &(
            &original.account_id,
            &original.authorization_id,
            &original.return_recipient_key_digest,
            &original.admission_request_digest,
            &original.intent_digest,
            &original.terms_digest,
            &original.authenticated_package_digest,
            &original.native_review_digest,
            &original.receipt,
        ),
    )
    .unwrap();
    original
}
pub(in crate::consent_journal) fn insert_original(
    c: &Connection,
    original: &OfflineOriginalConsentHistory,
) {
    c.execute(
        "INSERT INTO signer_offline_original_consents VALUES(?1,?2,?3,?4,?5)",
        params![
            original.reference,
            original.authorization_id,
            original.account_id,
            original.receipt.nonce,
            encode(original).unwrap().as_str()
        ],
    )
    .unwrap();
}
pub(in crate::consent_journal) fn insert_keyuse(
    c: &Connection,
    original: &OfflineOriginalConsentHistory,
) {
    let record = OfflineLocalKeyUseHistory {
        authorization_id: original.authorization_id.clone(),
        original_consent_ref: original.reference.clone(),
        admission_request_digest: original.admission_request_digest.clone(),
        authenticated_package_digest: original.authenticated_package_digest.clone(),
    };
    c.execute(
        "INSERT INTO signer_offline_keyuse VALUES(?1,?2,?3)",
        params![
            record.authorization_id,
            record.original_consent_ref,
            encode(&record).unwrap().as_str()
        ],
    )
    .unwrap();
}
#[test]
fn minimal_local_admission_survives_without_private_remote_descriptor() {
    let c = connection();
    let (admission, _, _) = full_admission();
    let local = minimal(&admission);
    insert_local(&c, &local);
    let records = read_all(&c, "synthetic-account").unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].admission().is_none());
    assert!(records[0].original_consent().is_none());
    assert_eq!(
        records[0].signature_knowledge(),
        OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown
    );
    assert!(matches!(
        require_accountwide_online_admission(&c),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
    let legacy: u64 = c
        .query_row("SELECT count(*) FROM signer_original_consents", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(legacy, 0);
    storage::verify_schema(&c).unwrap();
}
#[test]
fn matching_local_remote_origins_are_complete_once_and_conservative() {
    let c = connection();
    let (admission, policy, provenance) = full_admission();
    insert_remote(&c, &admission, &policy, &provenance);
    insert_local(&c, &minimal(&admission));
    let records = read_all(&c, "synthetic-account").unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].admission().is_some());
    assert!(records[0].local_admission().is_some());
    require_accountwide_online_admission(&c).unwrap();
    let total:u64=c.query_row("SELECT sum(CAST(maximum_debit AS INTEGER)) FROM (SELECT maximum_debit FROM signer_offline_remote_exposures UNION ALL SELECT maximum_debit FROM signer_offline_local_admissions l WHERE NOT EXISTS(SELECT 1 FROM signer_offline_remote_exposures r WHERE r.authorization_id=l.authorization_id))",[],|r|r.get(0)).unwrap();
    assert_eq!(total, 70);
}
#[test]
fn minimal_origin_mismatch_cannot_hide_behind_deduplicated_authorization() {
    let c = connection();
    let (admission, policy, provenance) = full_admission();
    insert_remote(&c, &admission, &policy, &provenance);
    let mut local = minimal(&admission);
    local.statement.committed_head.digest = h(80);
    local.statement_digest = local.statement.statement_digest().unwrap();
    insert_local(&c, &local);
    assert!(read_all(&c, "synthetic-account").is_err());
}
#[test]
fn original_consent_and_keyuse_remain_distinct_unknown_signature_states() {
    let c = connection();
    let (admission, _, _) = full_admission();
    let local = minimal(&admission);
    insert_local(&c, &local);
    let original = original(&local);
    insert_original(&c, &original);
    assert_eq!(
        read_all(&c, "synthetic-account").unwrap()[0].signature_knowledge(),
        OfflineSignatureKnowledge::OriginalConsentRetainedSignatureUnknown
    );
    insert_keyuse(&c, &original);
    assert_eq!(
        read_all(&c, "synthetic-account").unwrap()[0].signature_knowledge(),
        OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown
    );
    assert!(c.execute("DELETE FROM signer_offline_keyuse", []).is_err());
    assert!(
        c.execute(
            "UPDATE signer_offline_original_consents SET reference='forged'",
            []
        )
        .is_err()
    );
}
#[test]
fn retained_result_integrity_never_claims_current_validity_or_settlement() {
    use sha2::{Digest, Sha256};
    let c = connection();
    let (admission, _, _) = full_admission();
    let local = minimal(&admission);
    insert_local(&c, &local);
    let original = original(&local);
    insert_original(&c, &original);
    insert_keyuse(&c, &original);
    let bytes = b"synthetic unverified artifact, no signatures";
    let result = OfflineRetainedResultHistory {
        authorization_id: original.authorization_id.clone(),
        original_consent_ref: original.reference.clone(),
        admission_request_digest: original.admission_request_digest.clone(),
        authenticated_package_digest: original.authenticated_package_digest.clone(),
        signed_artifact_digest: hex::encode(Sha256::digest(bytes)),
        return_recipient_key_digest: original.return_recipient_key_digest.clone(),
    };
    c.execute(
        "INSERT INTO signer_offline_results VALUES(?1,?2,?3,?4)",
        params![
            result.authorization_id,
            result.signed_artifact_digest,
            hex::encode(bytes),
            encode(&result).unwrap().as_str()
        ],
    )
    .unwrap();
    let records = read_all(&c, "synthetic-account").unwrap();
    assert_eq!(
        records[0].signature_knowledge(),
        OfflineSignatureKnowledge::ExactResultRetainedCurrentValidityUnknown
    );
    assert_eq!(
        records[0].retained_result().unwrap().signed_artifact_digest,
        hex::encode(Sha256::digest(bytes))
    );
    // Private preservation is checked without exposing bytes on the public reader.
    assert_eq!(
        records[0].result.as_ref().unwrap().1.as_str(),
        hex::encode(bytes)
    );
}
#[test]
fn prereview_intent_cannot_substitute_for_original_consent() {
    let c = connection();
    let (admission, _, _) = full_admission();
    let local = minimal(&admission);
    insert_local(&c, &local);
    let mut original = original(&local);
    original.reference = local.intent_digest.clone();
    insert_original(&c, &original);
    assert!(read_all(&c, "synthetic-account").is_err());
}
#[test]
fn missing_inputs_and_denormalized_debit_drift_are_rejected() {
    let c = connection();
    let (admission, _, _) = full_admission();
    let local = minimal(&admission);
    c.execute(
        "INSERT INTO signer_offline_local_admissions VALUES(?1,?2,?3,'70',?4)",
        params![
            local.terms.authorization_id,
            local.terms.account_id,
            local.terms.obligation_id,
            encode(&local).unwrap().as_str()
        ],
    )
    .unwrap();
    assert!(read_all(&c, "synthetic-account").is_err());
    let c = connection();
    c.execute(
        "INSERT INTO signer_offline_local_admissions VALUES(?1,?2,?3,'069',?4)",
        params![
            local.terms.authorization_id,
            local.terms.account_id,
            local.terms.obligation_id,
            encode(&local).unwrap().as_str()
        ],
    )
    .unwrap();
    assert!(read_all(&c, "synthetic-account").is_err());
}
#[test]
fn original_without_local_minimal_admission_is_rejected_by_foreign_key() {
    let c = connection();
    let (admission, _, _) = full_admission();
    let original = original(&minimal(&admission));
    assert!(
        c.execute(
            "INSERT INTO signer_offline_original_consents VALUES(?1,?2,?3,?4,?5)",
            params![
                original.reference,
                original.authorization_id,
                original.account_id,
                original.receipt.nonce,
                encode(&original).unwrap().as_str()
            ]
        )
        .is_err()
    );
}

#[test]
fn legacy_inventory_rejects_local_only_admission_instead_of_filtering_it() {
    let c = connection();
    require_legacy_journal(&c).unwrap();
    let (admission, _, _) = full_admission();
    insert_local(&c, &minimal(&admission));
    assert!(matches!(
        require_legacy_journal(&c),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
}

#[path = "offline_reconciliation_tests.rs"]
pub(in crate::consent_journal) mod reconciliation_tests;
