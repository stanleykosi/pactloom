//! Immutable legacy online serialization/hash baselines, independent of the view.
//! Generated from the pre-refactor version-two field order and domain constants.
use super::*;
use crate::{policy::Event, *};
use sha2::{Digest, Sha256};

const REQUEST: &str = r#"{"operation_id":"synthetic-golden-operation","account_id":"synthetic-account","network_profile_id":"synthetic-testnet","writer_epoch":1,"expected_head":{"sequence":2,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"authorization_id":"synthetic-authorization","original_consent_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","enrollment_ref":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","accepted_manifest_ref":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","agreement_id":"synthetic-agreement","obligation_id":"synthetic-obligation","proposal_id":"synthetic-proposal","proposal_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","manifest_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","effects_digest":"1111111111111111111111111111111111111111111111111111111111111111","artifact_digest":"2222222222222222222222222222222222222222222222222222222222222222","review_binding":"3333333333333333333333333333333333333333333333333333333333333333","recipient_scope_digest":"4444444444444444444444444444444444444444444444444444444444444444","inputs":[{"input_id":"synthetic-input","nullifier":"5555555555555555555555555555555555555555555555555555555555555555","action_index":0,"value_zatoshis":100}],"maximum_debit_zatoshis":60,"fee_share_zatoshis":2,"transaction_fee_zatoshis":4,"transaction_expiry_height":1000,"reviewed_at_ms":1000,"permit_expires_at_ms":60000}"#;
const REQUEST_DIGEST: &str = "15bee844c1d86080ab739133c4505b8757cf6a72a95df34fd79b0b244f30569f";
const RESULT_SHA256: &str = "921567f3f64c1658f0f1e608a0ea396fb439975f6af8fbb3b5f68d3942c0c27c";
const EVENT_HEAD_DIGEST: &str = "b5a1838c28b4f3ab9d691c029b96f706203ab213a3b843879dbe30bbce32ed50";

fn fixture() -> (ReserveAuthorization, MutationResult) {
    let request: ReserveAuthorization = crate::decode(REQUEST.as_bytes()).unwrap();
    request.validate().unwrap();
    let permit = ReservationPermit {
        protocol_version: 2,
        witness_id: "synthetic-witness".into(),
        policy_digest: "8".repeat(64),
        request_digest: request.request_digest().unwrap(),
        request: request.clone(),
        committed_head: AuthorityHead {
            sequence: 3,
            digest: "9".repeat(64),
        },
        reserved_at_ms: 1001,
        account_outstanding_debit_zatoshis: 60,
        account_reserved_input_value_zatoshis: 100,
        writer_session_id: "7".repeat(64),
    };
    permit.matches_request(&request).unwrap();
    (request, MutationResult::Reserved(Box::new(permit)))
}

#[test]
fn legacy_online_wire_and_request_hash_are_unchanged() {
    let (request, result) = fixture();
    assert_eq!(serde_json::to_string(&request).unwrap(), REQUEST);
    assert_eq!(request.request_digest().unwrap(), REQUEST_DIGEST);
    assert_eq!(
        hex::encode(Sha256::digest(&*encode(&result).unwrap())),
        RESULT_SHA256
    );
    let encoded_before = encode(&result).unwrap();
    let view = ReservationView::from_result(&result).unwrap();
    assert_eq!(view.request_digest, REQUEST_DIGEST);
    assert_eq!(view.operation_id, request.operation_id);
    assert_eq!(view.account_id, request.account_id);
    assert_eq!(view.network_profile_id, request.network_profile_id);
    assert_eq!(view.obligation_id, request.obligation_id);
    assert_eq!(view.proposal_id, request.proposal_id);
    assert_eq!(view.effects_digest, request.effects_digest);
    assert_eq!(
        view.transaction_expiry_height,
        request.transaction_expiry_height
    );
    assert_eq!(view.maximum_debit_zatoshis, request.maximum_debit_zatoshis);
    assert!(view.inputs == request.inputs.as_slice());
    assert_eq!(&*encode(&result).unwrap(), &*encoded_before);
    let decoded: MutationResult = crate::decode(&encoded_before).unwrap();
    assert!(decoded == result);
}

#[test]
fn legacy_event_chain_digest_does_not_hash_the_new_view() {
    let (request, _) = fixture();
    let head = request.expected_head.clone();
    let event = Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(request)),
        authenticated_certificate_digest: "6".repeat(64),
        witness_time_ms: 1001,
        writer_session_id: Some("7".repeat(64)),
    };
    assert_eq!(
        digest("wholepact:authority-append:v2", &(&head, &event)).unwrap(),
        EVENT_HEAD_DIGEST
    );
}

#[test]
fn original_request_event_link_changes_head_but_not_session_mutation_transcript() {
    let (request, _) = fixture();
    let head = request.expected_head.clone();
    let mutation = AuthorityMutation::ReserveAuthorization(Box::new(request));
    let original_mutation = encode(&mutation).unwrap();
    let mut event = Event {
        mutation,
        authenticated_certificate_digest: "6".repeat(64),
        witness_time_ms: 1001,
        writer_session_id: Some("7".repeat(64)),
        original_request_link: None,
    };
    assert_eq!(
        digest("wholepact:authority-append:v2", &(&head, &event)).unwrap(),
        EVENT_HEAD_DIGEST
    );
    event.original_request_link = Some(crate::OriginalCommitLink {
        prepared_record_digest: "1".repeat(64),
        authenticated_receipt_digest: "2".repeat(64),
        reservation_request_digest: "3".repeat(64),
        export_plan_digest: "4".repeat(64),
        original_envelope_digest: "5".repeat(64),
        inbox_acceptance_digest: "6".repeat(64),
    });
    assert_ne!(
        digest("wholepact:authority-append:v2", &(&head, &event)).unwrap(),
        EVENT_HEAD_DIGEST
    );
    assert_eq!(&*encode(&event.mutation).unwrap(), &*original_mutation);
    // This fixture tests wire binding only. Ledger rejects online events bearing
    // offline links; no original-request authority follows from constructing DTOs.
}
