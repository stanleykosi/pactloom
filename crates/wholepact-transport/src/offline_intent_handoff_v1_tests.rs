//! In-memory ephemeral transport fixture. No wallet, native decision, witness
//! admission, persistence, provider or proof operation is created.
use super::*;
use crate::{
    ArtifactKind, DisclosureField, ExportRequest, MessageContext, MessageOrder, Timestamp,
    TransportPublicKey, TransportSecret, prepare_export, random_message_id,
};
use wholepact_authority::offline::{
    OfflineAuthoritySemantics, OfflineAuthorizationTerms, OfflineEnrollmentPolicy,
    OfflineReservationIntent, OfflineSnapshotCommitment, OfflineUnknownFact,
};
use wholepact_authority::{AccountPolicy, AuthorityHead, InputReservation};
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

fn fixture() -> OfflineIntentHandoffV1 {
    let fresh = || {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        TransportSecret::from_bytes(b).unwrap()
    };
    let witness = fresh();
    let signer = fresh();
    let (request, _, policy) = original_fixture(
        &witness.public_key().unwrap(),
        &signer.public_key().unwrap(),
    );
    let now = Timestamp::from_unix_seconds(2).unwrap();
    let t = &request.intent.terms;
    let prepared = prepare_export(
        ExportRequest {
            context: MessageContext {
                network_profile_id: t.network_profile_id.clone(),
                agreement_id: t.agreement_id.clone(),
                proposal_id: t.proposal_id.clone(),
                proposal_revision: t.proposal_revision,
                sender_id: format!("offline-intent:{}", t.offline_signer_key_digest),
                recipient_id: format!("offline-intent:{}", t.offline_policy_digest),
                artifact_kind: ArtifactKind::OfflineReservationIntent,
            },
            order: MessageOrder {
                message_id: random_message_id().unwrap(),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: Timestamp::from_unix_seconds(30).unwrap(),
            },
            purpose: "Synthetic original intent".into(),
            persistence_warning: "Synthetic receiver retains exact bytes".into(),
        },
        vec![
            DisclosureField::new(
                "offline-reservation-intent-v1",
                serde_json::to_vec(&request.intent).unwrap(),
            )
            .unwrap(),
        ],
        &signer.public_key().unwrap(),
        &witness.public_key().unwrap(),
        &now,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    let ciphertext = prepared.seal_qualified(&signer, &digest, &now).unwrap();
    let template = OfflineAdmissionExportPlan {
        message_id: random_message_id().unwrap(),
        sequence: 0,
        issued_at_unix_seconds: 2,
        expires_at_unix_seconds: 30,
        purpose: "Synthetic admission".into(),
        persistence_warning: "Synthetic retained reply".into(),
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        sender_key_fingerprint: policy.witness_transport_key_digest,
        recipient_key_fingerprint: policy.offline_signer_key_digest,
    };
    OfflineIntentHandoffV1::from_untrusted_parts(request, template, ciphertext.as_bytes()).unwrap()
}
#[test]
fn exact_handoff_roundtrip_preserves_original_request_template_and_ciphertext() {
    let original = fixture();
    let bytes = original.canonical_bytes().unwrap();
    let parsed = OfflineIntentHandoffV1::parse(&bytes).unwrap();
    assert!(parsed.request() == original.request());
    assert!(parsed.admission_export_template() == original.admission_export_template());
    assert_eq!(parsed.admission_export_template().sequence, 0);
    assert_eq!(
        parsed.encrypted_intent().unwrap(),
        original.encrypted_intent().unwrap()
    );
    assert_eq!(parsed.commitment().unwrap(), original.commitment().unwrap());
    assert!(!parsed.grants_signing_authority());
}
#[test]
fn handoff_refuses_unknown_fields_noncanonical_encoding_and_changed_reply_scope() {
    let original = fixture();
    let bytes = original.canonical_bytes().unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["trusted"] = true.into();
    assert!(OfflineIntentHandoffV1::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    assert!(OfflineIntentHandoffV1::parse(&serde_json::to_vec_pretty(&original).unwrap()).is_err());
    let mut changed = fixture();
    changed.admission_export_template.sequence = 1;
    assert!(changed.canonical_bytes().is_err());
    let mut changed = fixture();
    changed.admission_export_template.recipient_key_fingerprint = "ff".repeat(32);
    assert!(changed.canonical_bytes().is_err());
    let mut changed = fixture();
    changed.admission_export_template.expires_at_unix_seconds = 31;
    assert!(changed.canonical_bytes().is_err());
    let mut changed = fixture();
    changed.encrypted_intent_base64.push('=');
    assert!(changed.canonical_bytes().is_err());
}
#[test]
fn changed_original_head_is_distinct_data_and_never_becomes_authority() {
    let mut original = fixture();
    let first = original.commitment().unwrap();
    original.request.expected_head.digest = "ee".repeat(32);
    assert_ne!(first, original.commitment().unwrap());
    assert!(!original.grants_signing_authority());
    // Structural parsing cannot authenticate this substitution. The server must
    // compare the exact encrypted intent and current original ledger state.
    assert!(OfflineIntentHandoffV1::parse(&original.canonical_bytes().unwrap()).is_ok());
    assert!(
        OfflineIntentHandoffV1::parse(&vec![b' '; MAX_OFFLINE_INTENT_HANDOFF_BYTES_V1 + 1])
            .is_err()
    );
}
