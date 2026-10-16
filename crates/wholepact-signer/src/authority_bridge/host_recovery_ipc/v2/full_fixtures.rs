//! Synthetic DTO fixtures only, copied from existing journal shape fixtures.
use crate::consent_journal::{
    OfflineLocalAdmissionHistory, OfflineMinimalAdmissionHistoryStatement,
    OfflineRemoteHistoryProvenance,
};
use wholepact_authority::{
    AccountPolicy, AuthorityHead, InputReservation, OwnerControl, OwnerControlRequest,
    WitnessDisclosureDescriptor, offline::*,
};
fn h(n: u8) -> String {
    format!("{n:064x}")
}
fn transport_history_digest(domain: &[u8], value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(value);
    hex::encode(h.finalize())
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
pub(super) fn full_admission() -> (
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
pub(super) fn minimal(admission: &OfflineAuthorizationAdmission) -> OfflineLocalAdmissionHistory {
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
            serde_json::to_string(admission).unwrap().as_bytes(),
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
