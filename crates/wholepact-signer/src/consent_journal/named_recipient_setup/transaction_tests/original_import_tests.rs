//! Actual encrypted/native fixture entry paths, authored but not executed here.
//! Uses the parent setup Fixture, never raw live-profile or AuthenticatedReceipt
//! constructors. Invalid ciphertext is deliberately not encrypted or signed.
use super::super::{
    NamedIntentExportTemplate, NamedRecipientOriginalInputs, PreparedNamedRecipientOriginalImport,
};
use super::*;
use crate::consent_journal::named_recipient_records::{
    NamedRecipientOriginalRecordV1, NamedRecipientOutputPurposeV1, NamedRecipientOwnExpectationsV1,
    NamedRecipientOwnInputV1, NamedRecipientOwnOutputV1, transport_fingerprint,
};
use wholepact_authority::{OfflineAdmissionExportPlan, offline::OfflineEnrollmentPolicy};
use wholepact_protocol::own_effects::{
    OwnEffectsPolicy, OwnInputExpectation, OwnOutputExpectation, OwnOutputPurpose,
};
use wholepact_transport::{
    EncryptedEnvelope, MessageOrder, NAMED_REVIEW_DISCLOSURE_PROFILE_V1, NamedReviewBindingV1,
    Timestamp, TransportError,
};

fn fixture_now() -> Timestamp {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Timestamp::from_unix_seconds(i64::try_from(seconds).unwrap()).unwrap()
}
fn hash_label(n: u8) -> String {
    format!("{n:064x}")
}
fn inert_outer_envelope() -> EncryptedEnvelope {
    EncryptedEnvelope::from_bytes(
        serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"suite":"HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305",
            "encapsulated_key":"11".repeat(32),"ciphertext":"AA",
        }))
        .unwrap(),
    )
    .unwrap()
}
fn candidate(
    f: &Fixture,
    live: &LiveNamedRecipientProfile,
) -> (
    NamedRecipientOriginalRecordV1,
    OwnEffectsPolicy,
    OfflineEnrollmentPolicy,
    NamedIntentExportTemplate,
) {
    let (admission, mut policy, _) =
        crate::consent_journal::offline_history::tests::full_admission();
    let mut request = admission.request;
    let now = fixture_now();
    let seconds = now.unix_seconds();
    let start_ms = u64::try_from(seconds).unwrap() * 1000;
    let end_ms = start_ms + 30_000;
    request.requested_at_ms = start_ms;
    request.admission_expires_at_ms = end_ms;
    policy.valid_from_ms = start_ms;
    policy.expires_at_ms = end_ms;
    policy.maximum_admission_lifetime_ms = 30_000;
    let terms = &mut request.intent.terms;
    let manifest = f.manifest.proposal_input();
    let proposal = wholepact_core::Proposal::validate(manifest.clone()).unwrap();
    let owner = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == live.record.account_id)
        .unwrap();
    terms.account_id = live.record.account_id.clone();
    terms.network_profile_id = manifest.manifest.agreement.network_profile_id.clone();
    terms.enrollment_ref = live.record.enrollment_ref.clone();
    terms.accepted_manifest_ref = live.record.manifest_ref.clone();
    terms.agreement_id = manifest.manifest.agreement.agreement_id.clone();
    terms.obligation_id = manifest.manifest.agreement.obligation_id.clone();
    terms.proposal_id = manifest.proposal_id.clone();
    terms.proposal_revision = u64::from(manifest.manifest.agreement.revision);
    terms.proposal_digest = f.manifest.proposal_digest().into();
    terms.manifest_digest = f.manifest.manifest_digest().into();
    terms.artifact_digest = manifest.artifact_digest.clone().unwrap();
    terms.effects_digest = manifest.effects_commitment.clone().unwrap();
    terms.transaction_expiry_height = manifest.manifest.expiry_height;
    terms.maximum_debit_zatoshis =
        proposal.accounting().participant_net_debits[&owner.participant_id].as_zatoshis();
    terms.fee_share_zatoshis = owner.fee_share.as_zatoshis();
    terms.transaction_fee_zatoshis = manifest.manifest.transaction_fee.as_zatoshis();
    terms.inputs[0].input_id = "input-alice".into();
    terms.inputs[0].value_zatoshis = 500_000_000;
    terms.offline_signer_key_digest = transport_fingerprint(&live.record.transport_public_key);
    terms.return_recipient_key_digest =
        transport_fingerprint(&live.record.return_transport_public_key);
    policy.account_id = terms.account_id.clone();
    policy.network_profile_id = terms.network_profile_id.clone();
    policy.enrollment_ref = terms.enrollment_ref.clone();
    policy.witness_transport_key_digest =
        transport_fingerprint(&live.record.witness_transport_public_key);
    policy.witness_certificate_digest = live.record.witness_certificate_digest.clone();
    policy.offline_signer_key_digest = terms.offline_signer_key_digest.clone();
    policy.return_recipient_key_digest = terms.return_recipient_key_digest.clone();
    terms.offline_policy_digest = policy.policy_digest().unwrap();
    let header =
        NamedReviewBindingV1 {
            schema_version: 1,
            disclosure_profile: NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
            owner_setup_digest: live.record.original_setup_digest.clone(),
            assertion_package_digest: hash_label(40),
            original_context_digest:
                wholepact_offline_bridge::named_verifier_original_context_digest(terms).unwrap(),
        };
    terms.review_package_digest = header.review_package_digest().unwrap();
    let fvk = f.vault.account().fvk().unwrap();
    let receiver = fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let own = OwnEffectsPolicy {
        account_id: terms.account_id.clone(),
        own_fvk: fvk,
        manifest_digest: hex::decode(&terms.manifest_digest)
            .unwrap()
            .try_into()
            .unwrap(),
        anchor: hex::decode(&terms.snapshot.anchor_root)
            .unwrap()
            .try_into()
            .unwrap(),
        expiry_height: terms.transaction_expiry_height,
        maximum_selected_net_debit_zatoshis: owner.maximum_net_debit.as_zatoshis(),
        exact_selected_net_debit_zatoshis: terms.maximum_debit_zatoshis,
        declared_fee_share_zatoshis: terms.fee_share_zatoshis,
        exact_transaction_fee_zatoshis: terms.transaction_fee_zatoshis,
        own_inputs: vec![OwnInputExpectation {
            action_index: 0,
            nullifier: hex::decode(&terms.inputs[0].nullifier)
                .unwrap()
                .try_into()
                .unwrap(),
            value_zatoshis: 500_000_000,
        }],
        outputs: vec![OwnOutputExpectation {
            action_index: 1,
            receiver,
            value_zatoshis: 99_988_000,
            memo: [0; 512],
            purpose: OwnOutputPurpose::OwnReturn,
        }],
    };
    let expected = NamedRecipientOwnExpectationsV1 {
        schema_version: 1,
        full_viewing_key_digest: live.record.full_viewing_key_digest.clone(),
        manifest_digest: terms.manifest_digest.clone(),
        anchor: terms.snapshot.anchor_root.clone(),
        expiry_height: terms.transaction_expiry_height,
        maximum_selected_net_debit_zatoshis: own.maximum_selected_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: own.exact_selected_net_debit_zatoshis,
        declared_fee_share_zatoshis: own.declared_fee_share_zatoshis,
        exact_transaction_fee_zatoshis: own.exact_transaction_fee_zatoshis,
        own_inputs: vec![NamedRecipientOwnInputV1 {
            action_index: 0,
            nullifier: terms.inputs[0].nullifier.clone(),
            value_zatoshis: 500_000_000,
        }],
        outputs: vec![NamedRecipientOwnOutputV1 {
            action_index: 1,
            receiver_hex: hex::encode(own.outputs[0].receiver.to_raw_address_bytes()),
            value_zatoshis: 99_988_000,
            memo_hex: "00".repeat(512),
            purpose: NamedRecipientOutputPurposeV1::OwnReturn,
        }],
    };
    let template = OfflineAdmissionExportPlan {
        message_id: "21".repeat(16),
        sequence: 0,
        issued_at_unix_seconds: seconds,
        expires_at_unix_seconds: seconds + 30,
        purpose: "Synthetic exact admission reply".into(),
        persistence_warning: "Synthetic controller retains exact request".into(),
        sender_id: format!("offline-admission:{}", terms.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", terms.offline_signer_key_digest),
        sender_key_fingerprint: policy.witness_transport_key_digest.clone(),
        recipient_key_fingerprint: terms.offline_signer_key_digest.clone(),
    };
    let original = NamedRecipientOriginalRecordV1 {
        schema_version: 1,
        reference: hash_label(1),
        profile_ref: live.record.reference.clone(),
        terms: terms.clone(),
        original_artifact_digest: terms.artifact_digest.clone(),
        canonical_artifact_digest: hash_label(41),
        transformation_digest: hash_label(42),
        named_assertion_digest: hash_label(43),
        assertion_package_digest: hash_label(40),
        validity_not_before_ms: start_ms,
        validity_expires_ms: end_ms,
        original_request_digest: hash_label(44),
        reservation_request_digest: hash_label(45),
        reservation_request: request,
        admission_export_template: template,
        own_policy_digest: hash_label(46),
        own_expectations: expected,
    };
    let outgoing = NamedIntentExportTemplate {
        order: MessageOrder {
            message_id: "31".repeat(16),
            sequence: 0,
            issued_at: now,
            expires_at: Timestamp::from_unix_seconds(seconds + 30).unwrap(),
        },
        purpose: "Synthetic native request only".into(),
        persistence_warning: "Synthetic controller may retain original request".into(),
    };
    (original, own, policy, outgoing)
}
fn prepare(f: &Fixture, live: &LiveNamedRecipientProfile) -> PreparedNamedRecipientOriginalImport {
    let (original, own, policy, outgoing) = candidate(f, live);
    live.prepare_original_import(
        &f.journal,
        &f.session,
        &f.vault,
        NamedRecipientOriginalInputs {
            proposed: original,
            own_policy: own,
            proposed_policy: policy,
            assertion_envelope: inert_outer_envelope(),
            outgoing,
            now: fixture_now(),
        },
    )
    .unwrap()
}
fn assert_no_original_writes(f: &Fixture) {
    let c = f.journal.connection.lock().unwrap();
    for table in [
        "signer_named_recipient_originals",
        "signer_named_recipient_receipts",
        "signer_named_intent_outbox",
        "signer_named_recipient_started",
        "signer_named_recipient_results",
    ] {
        let count: u64 = c
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "failed native import must not create {table}");
    }
}
#[test]
fn first_original_actual_native_invalid_assertion_rolls_back_all_owned_tables() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let prepared = prepare(&f, &live);
    let authorization = prepared.authorization_id().to_owned();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault, &fixture_now()),
        Err(TransportError::Authentication)
    ));
    assert_no_original_writes(&f);
    assert!(
        live.recover_original_intent_export(&f.journal, &f.session, &f.vault, &authorization)
            .unwrap()
            .is_none()
    );
}
#[test]
fn first_original_actual_native_wrong_digest_and_foreign_instance_never_write() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let prepared = prepare(&f, &live);
    let decision = recovery_test_decision(f.native(), &hash_label(99));
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault, &fixture_now()),
        Err(TransportError::WrongContext)
    ));
    let prepared = prepare(&f, &live);
    let other = recovery_test_authority();
    let decision = recovery_test_decision(&other, prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault, &fixture_now()),
        Err(TransportError::WrongContext)
    ));
    assert_no_original_writes(&f);
}
#[test]
fn first_original_expired_native_review_and_invalidated_session_never_write() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let mut prepared = prepare(&f, &live);
    prepared.expire_fixture_review();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault, &fixture_now()),
        Err(TransportError::AuthorityUnavailable)
    ));
    let prepared = prepare(&f, &live);
    let decision = recovery_test_decision(f.native(), prepared.digest());
    f.session.invalidate().unwrap();
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault, &fixture_now()),
        Err(TransportError::AuthorityUnavailable)
    ));
    assert_no_original_writes(&f);
}
#[test]
fn first_original_proposed_policy_pin_mismatch_is_not_enrollment_authority() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let (original, own, mut policy, outgoing) = candidate(&f, &live);
    policy.witness_certificate_digest = hash_label(98);
    assert!(matches!(
        live.prepare_original_import(
            &f.journal,
            &f.session,
            &f.vault,
            NamedRecipientOriginalInputs {
                proposed: original,
                own_policy: own,
                proposed_policy: policy,
                assertion_envelope: inert_outer_envelope(),
                outgoing,
                now: fixture_now(),
            }
        ),
        Err(TransportError::WrongContext)
    ));
    assert_no_original_writes(&f);
}

#[test]
fn first_original_fixed_window_expiry_cannot_be_renewed_by_fresh_native_decision() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let mut prepared = prepare(&f, &live);
    prepared.expire_fixture_original_window();
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault, &fixture_now()),
        Err(TransportError::AuthorityUnavailable)
    ));
    assert_no_original_writes(&f);
}

#[test]
fn named_unresolved_started_fences_only_its_original_return_stream() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let (original, _, _, _) = candidate(&f, &live);
    // Inert row shapes suffice to prove refusal precedes any result decoding,
    // key use or resequencing. This is not an authenticated original fixture.
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE signer_named_recipient_originals(reference TEXT,profile_ref TEXT,payload TEXT); CREATE TABLE signer_named_recipient_started(authorization_id TEXT,original_ref TEXT,payload TEXT); CREATE TABLE signer_named_recipient_results(authorization_id TEXT,payload TEXT);").unwrap();
    let next = |o: &NamedRecipientOriginalRecordV1| {
        super::super::inbox::next_return_sequence_for_test(&c, o)
    };
    assert_eq!(next(&original).unwrap(), 1);
    c.execute(
        "INSERT INTO signer_named_recipient_originals VALUES(?1,?2,?3)",
        params![
            original.reference,
            original.profile_ref,
            encode(&original).unwrap().as_str()
        ],
    )
    .unwrap();
    c.execute("INSERT INTO signer_named_recipient_started VALUES(?1,?2,'not decoded before unresolved refusal')",params![original.terms.authorization_id,original.reference]).unwrap();
    assert!(matches!(
        next(&original),
        Err(TransportError::ImportCommittedButUnavailable)
    ));
    let mut distinct = original.clone();
    distinct.terms.agreement_id = "another-return-stream".into();
    assert_eq!(next(&distinct).unwrap(), 1);
    distinct = original.clone();
    distinct.terms.network_profile_id = "another-network-stream".into();
    assert_eq!(next(&distinct).unwrap(), 1);
    distinct = original.clone();
    distinct.profile_ref = "55".repeat(32);
    assert_eq!(next(&distinct).unwrap(), 1);
    // A row merely claiming a result is not enough to reopen the stream.
    c.execute(
        "INSERT INTO signer_named_recipient_results VALUES(?1,'{}')",
        [&original.terms.authorization_id],
    )
    .unwrap();
    assert!(next(&original).is_err());
}
