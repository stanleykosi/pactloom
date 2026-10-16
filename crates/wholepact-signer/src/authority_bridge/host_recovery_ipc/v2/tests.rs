//! Pure synthetic DTO/consumer tests only; no native decisions, credentials,
//! sockets, proofs or runtime effects are created by these fixtures.
use super::*;
use crate::authority_bridge::host_publication_ipc::v2::HostRecoveryPublicationRequestV2;
fn fixture() -> HostRecoveryContinuityEvidenceV2 {
    serde_json::from_str(include_str!("fixtures/minimal_evidence.json")).unwrap()
}
#[test]
fn minimal_only_history_keeps_unknown_exposure_without_fabricating_online_fields() {
    let e = fixture();
    e.validate().unwrap();
    assert_eq!(
        e.complete_history.conservative_debit_zatoshis().unwrap(),
        70
    );
    assert_eq!(
        e.complete_history
            .unresolved_offline_authorizations()
            .unwrap(),
        std::collections::BTreeSet::from(["synthetic-offline".into()])
    );
    assert_eq!(
        e.complete_history.conservative_obligations().unwrap(),
        std::collections::BTreeSet::from(["synthetic-offline-obligation".into()])
    );
    let HostRecoveryReservationOriginV2::Offline { origin } = &e.complete_history.origins[0] else {
        panic!("wrong origin");
    };
    assert!(origin.replayed_admission.is_none());
    assert!(origin.retained_remote.is_none());
    assert!(origin.original.is_none());
    assert!(origin.key_use.is_none());
    assert!(origin.retained_result.is_none());
    let value = serde_json::to_value(origin).unwrap();
    assert!(value.get("writer_epoch").is_none());
    assert!(value.get("original_consent_ref").is_none());
    assert!(require_complete_origin_endpoint().is_err());
}
#[test]
fn no_duplicate_omitted_admission_or_upgraded_signature_knowledge() {
    let e = fixture();
    let mut duplicate = e.clone();
    duplicate
        .complete_history
        .origins
        .push(duplicate.complete_history.origins[0].clone());
    assert!(duplicate.validate().is_err());
    let mut bad = e.clone();
    let HostRecoveryReservationOriginV2::Offline { origin } = &mut bad.complete_history.origins[0]
    else {
        panic!("wrong origin");
    };
    origin.minimal_local = None;
    assert!(bad.validate().is_err());
    let mut bad = e;
    let HostRecoveryReservationOriginV2::Offline { origin } = &mut bad.complete_history.origins[0]
    else {
        panic!("wrong origin");
    };
    origin.signature_knowledge =
        OfflineSignatureKnowledgeV2::ExactResultRetainedCurrentValidityUnknown;
    assert!(bad.validate().is_err());
}
#[test]
fn exact_minimal_terms_pin_and_original_links_are_revalidated() {
    for field in [
        "maximum_debit_zatoshis",
        "nullifier",
        "terms_digest",
        "pinned_witness_certificate_digest",
    ] {
        let mut value = serde_json::to_value(fixture()).unwrap();
        let local = &mut value["complete_history"]["origins"][0]["origin"]["minimal_local"];
        match field {
            "maximum_debit_zatoshis" => local["terms"][field] = 69.into(),
            "nullifier" => local["terms"]["inputs"][0][field] = "ee".repeat(32).into(),
            "terms_digest" => local["statement"][field] = "ee".repeat(32).into(),
            _ => local[field] = "ee".repeat(32).into(),
        }
        assert!(
            serde_json::from_value::<HostRecoveryContinuityEvidenceV2>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
#[test]
fn publication_binds_local_journal_even_if_witness_head_is_unchanged() {
    let e = fixture();
    let request = HostRecoveryPublicationRequestV2 {
        schema_version: 2,
        continuity: e.request.clone(),
        target_profile: "/synthetic/successor".into(),
        generation_manifest_digest: "77".repeat(32),
        continuity_evidence_digest: e.digest().unwrap(),
    };
    request.matches_evidence(&e).unwrap();
    let mut changed = e.clone();
    changed.complete_history.complete_journal_digest = "ee".repeat(32);
    assert!(request.matches_evidence(&changed).is_err());
    assert!(e.require_unchanged(&changed, Duration::ZERO).is_err());
    assert!(e.require_unchanged(&e, Duration::from_secs(30)).is_err());
    assert!(e.require_unchanged(&e, Duration::from_secs(29)).is_ok());
}
#[test]
fn complete_origin_wire_cannot_downgrade_or_claim_current_authority() {
    let e = fixture();
    assert!(
        serde_json::from_value::<super::super::HostRecoveryContinuityEvidence>(
            serde_json::to_value(&e).unwrap()
        )
        .is_err()
    );
    let mut wrong = e.clone();
    wrong.request.schema_version = 1;
    assert!(wrong.validate().is_err());
    for flag in [
        "approved",
        "all_signatures_known",
        "financial_authority",
        "writer_epoch",
        "current_key_use",
    ] {
        let mut value = serde_json::to_value(&e).unwrap();
        value[flag] = true.into();
        assert!(serde_json::from_value::<HostRecoveryContinuityEvidenceV2>(value).is_err());
    }
    let mut value = serde_json::to_value(e).unwrap();
    value["complete_history"]["origins"][0]["origin"]["signature_knowledge"] = "unsigned".into();
    assert!(serde_json::from_value::<HostRecoveryContinuityEvidenceV2>(value).is_err());
}
#[test]
fn legacy_request_bytes_and_digest_are_unchanged() {
    let bytes = include_str!("fixtures/legacy_request.json");
    let v1: super::super::HostRecoveryContinuityRequest = serde_json::from_str(bytes).unwrap();
    assert_eq!(serde_json::to_string(&v1).unwrap(), bytes);
    assert_eq!(
        v1.digest().unwrap(),
        include_str!("fixtures/legacy_request.sha256")
    );
    let mut v2 = fixture().request;
    assert_ne!(v1.digest().unwrap(), v2.digest().unwrap());
    v2.schema_version = 1;
    assert!(v2.digest().is_err());
}
#[test]
fn receipt_acceptance_needs_exact_authentication_and_complete_body_is_bounded() {
    let mut e = fixture();
    let r = OfflineReviewReceiptMetadataV2 {
        account_id: e.request.account_id.clone(),
        authorization_id: "synthetic-review".into(),
        terms_digest: "11".repeat(32),
        package_digest: "22".repeat(32),
        envelope_digest: "33".repeat(32),
        authenticated: None,
        accepted_receipt_digest: Some("44".repeat(32)),
    };
    e.complete_history.review_receipts.push(r);
    assert!(e.validate().is_err());
    let r = &mut e.complete_history.review_receipts[0];
    r.accepted_receipt_digest = None;
    r.authenticated = Some(OfflineAuthenticatedReviewMetadataV2 {
        account_id: r.account_id.clone(),
        authorization_id: r.authorization_id.clone(),
        owner_setup_digest: "55".repeat(32),
        terms_digest: r.terms_digest.clone(),
        package_digest: r.package_digest.clone(),
        preview_json: "x".repeat(MAX_COMPLETE_HISTORY_BYTES),
        sequence: 1,
        envelope_digest: r.envelope_digest.clone(),
        content_digest: "66".repeat(32),
    });
    assert!(e.validate().is_err());
}

#[path = "full_fixtures.rs"]
mod full_fixtures;
fn joined_fixture() -> HostRecoveryContinuityEvidenceV2 {
    let (admission, policy, provenance) = full_fixtures::full_admission();
    let mut e = fixture();
    e.request.expected_witness = provenance.witness.clone();
    e.head = provenance.history_head.clone();
    e.complete_history.retained_enrollments = vec![policy.clone()];
    e.complete_history.retained_reservation_intents = vec![admission.request.intent.clone()];
    e.complete_history.origins = vec![HostRecoveryReservationOriginV2::Offline {
        origin: Box::new(HostRecoveryOfflineOriginV2 {
            replayed_admission: Some(admission.clone()),
            retained_remote: Some(RetainedOfflineRemoteV2 {
                admission: admission.clone(),
                policy,
                provenance,
            }),
            minimal_local: Some(full_fixtures::minimal(&admission)),
            original: None,
            key_use: None,
            retained_result: None,
            signature_knowledge: OfflineSignatureKnowledgeV2::HistoricalAdmissionSignatureUnknown,
        }),
    }];
    e
}
#[test]
fn full_replay_retained_remote_and_minimal_local_count_exactly_once() {
    let e = joined_fixture();
    e.validate().unwrap();
    assert_eq!(
        e.complete_history.conservative_debit_zatoshis().unwrap(),
        70
    );
    assert!(
        e.complete_history
            .unresolved_offline_authorizations()
            .unwrap()
            .is_empty()
    );
    let mut changed = e.clone();
    let HostRecoveryReservationOriginV2::Offline { origin } =
        &mut changed.complete_history.origins[0]
    else {
        panic!("wrong origin")
    };
    origin.replayed_admission = None;
    changed.validate().unwrap();
    assert_eq!(
        changed
            .complete_history
            .conservative_debit_zatoshis()
            .unwrap(),
        70
    );
    assert_eq!(
        changed
            .complete_history
            .unresolved_offline_authorizations()
            .unwrap()
            .len(),
        1
    );
    assert_ne!(e.digest().unwrap(), changed.digest().unwrap());
}
#[test]
fn mismatched_remote_and_minimal_copies_cannot_be_joined() {
    let mut e = joined_fixture();
    let HostRecoveryReservationOriginV2::Offline { origin } = &mut e.complete_history.origins[0]
    else {
        panic!("wrong origin")
    };
    origin
        .retained_remote
        .as_mut()
        .unwrap()
        .admission
        .writer_session_id = "ee".repeat(32);
    assert!(e.validate().is_err());
    let mut e = joined_fixture();
    let HostRecoveryReservationOriginV2::Offline { origin } = &mut e.complete_history.origins[0]
    else {
        panic!("wrong origin")
    };
    origin
        .minimal_local
        .as_mut()
        .unwrap()
        .statement
        .original_admission_digest = "ee".repeat(32);
    assert!(e.validate().is_err());
}

#[test]
fn mixed_online_and_offline_union_keeps_both_full_debits_and_fences() {
    use wholepact_authority::{ReservationPermit, ReserveAuthorization};
    let mut e = joined_fixture();
    let HostRecoveryReservationOriginV2::Offline { origin } = &e.complete_history.origins[0] else {
        panic!("wrong origin")
    };
    let t = origin.terms().unwrap();
    let request = ReserveAuthorization {
        automation: None,
        operation_id: "synthetic-online-operation".into(),
        account_id: t.account_id.clone(),
        network_profile_id: t.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: e.head.clone(),
        authorization_id: "synthetic-online".into(),
        original_consent_ref: "91".repeat(32),
        enrollment_ref: t.enrollment_ref.clone(),
        accepted_manifest_ref: t.accepted_manifest_ref.clone(),
        agreement_id: t.agreement_id.clone(),
        obligation_id: "synthetic-online-obligation".into(),
        proposal_id: t.proposal_id.clone(),
        proposal_digest: t.proposal_digest.clone(),
        manifest_digest: t.manifest_digest.clone(),
        effects_digest: t.effects_digest.clone(),
        artifact_digest: t.artifact_digest.clone(),
        review_binding: t.review_binding.clone(),
        recipient_scope_digest: t.recipient_scope_digest.clone(),
        inputs: t.inputs.clone(),
        maximum_debit_zatoshis: 70,
        fee_share_zatoshis: 2,
        transaction_fee_zatoshis: 4,
        transaction_expiry_height: 200,
        reviewed_at_ms: 1000,
        permit_expires_at_ms: 30000,
    };
    e.head = wholepact_authority::AuthorityHead {
        sequence: 3,
        digest: "92".repeat(32),
    };
    let permit = ReservationPermit {
        protocol_version: 2,
        witness_id: e.request.expected_witness.witness_id.clone(),
        policy_digest: e.request.expected_witness.policy_digest.clone(),
        request_digest: request.request_digest().unwrap(),
        request,
        committed_head: e.head.clone(),
        reserved_at_ms: 4000,
        account_outstanding_debit_zatoshis: 140,
        account_reserved_input_value_zatoshis: 200,
        writer_session_id: e.writer_session_id.clone(),
    };
    e.complete_history
        .origins
        .push(HostRecoveryReservationOriginV2::Online { permit });
    e.validate().unwrap();
    assert_eq!(
        e.complete_history.conservative_debit_zatoshis().unwrap(),
        140
    );
    assert_eq!(
        e.complete_history.conservative_obligations().unwrap().len(),
        2
    );
    assert!(
        e.complete_history
            .unresolved_offline_authorizations()
            .unwrap()
            .is_empty()
    );
    // A nonbinding offline intent cannot borrow an admitted online ID either.
    let mut intent_collision = e.clone();
    intent_collision
        .complete_history
        .origins
        .retain(|origin| matches!(origin, HostRecoveryReservationOriginV2::Online { .. }));
    intent_collision
        .complete_history
        .retained_reservation_intents[0]
        .terms
        .authorization_id = "synthetic-online".into();
    assert!(intent_collision.validate().is_err());
    // An offline review receipt cannot borrow this online authorization ID.
    let offline_terms = match &e.complete_history.origins[0] {
        HostRecoveryReservationOriginV2::Offline { origin } => origin.terms().unwrap(),
        _ => panic!("wrong origin"),
    };
    let receipt = OfflineReviewReceiptMetadataV2 {
        account_id: e.request.account_id.clone(),
        authorization_id: "synthetic-online".into(),
        terms_digest: offline_terms.terms_digest().unwrap(),
        package_digest: offline_terms.review_package_digest.clone(),
        envelope_digest: "33".repeat(32),
        authenticated: None,
        accepted_receipt_digest: None,
    };
    e.complete_history.review_receipts.push(receipt);
    assert!(e.validate().is_err());
}

#[test]
fn receipt_and_matching_admitted_origin_must_have_identical_terms_and_package() {
    let mut e = fixture();
    let HostRecoveryReservationOriginV2::Offline { origin } = &e.complete_history.origins[0] else {
        panic!("wrong origin")
    };
    let t = origin.terms().unwrap();
    let receipt = OfflineReviewReceiptMetadataV2 {
        account_id: t.account_id.clone(),
        authorization_id: t.authorization_id.clone(),
        terms_digest: t.terms_digest().unwrap(),
        package_digest: t.review_package_digest.clone(),
        envelope_digest: "33".repeat(32),
        authenticated: None,
        accepted_receipt_digest: None,
    };
    e.complete_history.review_receipts.push(receipt);
    e.validate().unwrap();
    let mut changed = e.clone();
    changed.complete_history.review_receipts[0].terms_digest = "ee".repeat(32);
    assert!(changed.validate().is_err());
    let mut changed = e.clone();
    changed.complete_history.review_receipts[0].package_digest = "ee".repeat(32);
    assert!(changed.validate().is_err());
    let mut pending_only = e;
    pending_only.complete_history.review_receipts[0].authorization_id =
        "synthetic-pending-only".into();
    pending_only.complete_history.review_receipts[0].terms_digest = "ee".repeat(32);
    pending_only.validate().unwrap();
    assert_eq!(
        pending_only
            .complete_history
            .conservative_debit_zatoshis()
            .unwrap(),
        70
    );
    // Even before admission, a same-ID retained intent is an exact binding.
    let mut pending = joined_fixture();
    let terms = &pending.complete_history.retained_reservation_intents[0].terms;
    let receipt = OfflineReviewReceiptMetadataV2 {
        account_id: terms.account_id.clone(),
        authorization_id: terms.authorization_id.clone(),
        terms_digest: terms.terms_digest().unwrap(),
        package_digest: terms.review_package_digest.clone(),
        envelope_digest: "33".repeat(32),
        authenticated: None,
        accepted_receipt_digest: None,
    };
    pending.complete_history.origins.clear();
    pending.complete_history.review_receipts.push(receipt);
    pending.validate().unwrap();
    pending.complete_history.review_receipts[0].package_digest = "ee".repeat(32);
    assert!(pending.validate().is_err());
}
// Synthetic historical audit regression only. No native authority, keys,
// credentials, sockets, proof execution or fresh birth enrollment is created.
// Append to host_recovery_ipc::v2::tests after pending_birth_commit lands.
use wholepact_authority::{
    AccountPolicy,
    account_use::{AccountUseGenesis, AccountUseIdentity},
    account_use_link::account_use_witness_origin_digest,
    pending_birth::{PendingBirthCommitRecord, PendingBirthRequest},
};

fn birth_h(n: u8) -> String {
    format!("{n:064x}")
}

pub(crate) fn pending_birth_fixture() -> HostRecoveryContinuityEvidenceV2 {
    let mut policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-birth-witness".into(),
        account_id: birth_h(1),
        network_profile_id: "synthetic-testnet".into(),
        owner_certificate_digest: birth_h(2),
        initial_writer_certificate_digest: birth_h(3),
        initial_writer_epoch: 1,
        enrollment_refs: vec![birth_h(4)],
        agreement_ids: vec!["synthetic-birth-agreement".into()],
        recipient_scope_digests: vec![birth_h(5)],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 80,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 10,
        maximum_permit_lifetime_ms: 60_000,
        policy_expires_at_ms: 100_000,
    };
    let original_terms_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &policy,
    )
    .unwrap();
    let mut witness = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1911".into(),
        server_name: "synthetic.invalid".into(),
        witness_id: policy.witness_id.clone(),
        account_id: policy.account_id.clone(),
        network_profile_id: policy.network_profile_id.clone(),
        policy_digest: birth_h(0),
        pinned_server_certificate_digest: birth_h(6),
    };
    let genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: policy.account_id.clone(),
            full_viewing_key_digest: birth_h(7),
            network_profile_id: policy.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: policy.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&witness).unwrap(),
        owner_certificate_digest: policy.owner_certificate_digest.clone(),
        native_birth_digest: birth_h(8),
    };
    policy.account_use_genesis = Some(genesis.clone());
    witness.policy_digest = policy.policy_digest().unwrap();
    let request = PendingBirthRequest {
        version: 1,
        operation_id: "synthetic-birth-operation".into(),
        generation_instance_id: birth_h(9),
        native_birth_digest: genesis.native_birth_digest.clone(),
        original_terms_digest,
        original_target_digest: birth_h(10),
        disclosure: witness.clone(),
        policy: policy.clone(),
        issued_at_ms: 1000,
        initial_commit_deadline_ms: 2000,
    };
    let commit = PendingBirthCommitRecord {
        version: 1,
        request_digest: request.digest().unwrap(),
        authenticated_owner_certificate_digest: policy.owner_certificate_digest.clone(),
        owner_approval_evidence_digest: birth_h(11),
        local_target_digest: birth_h(12),
        local_owner_review_digest: birth_h(13),
        committed_at_ms: 1500,
        request,
    };
    // Historical validation checks the ORIGINAL commit window. It must not
    // reinterpret this old record as a fresh birth request or native approval.
    commit.validate().unwrap();
    HostRecoveryContinuityEvidenceV2 {
        request: HostRecoveryContinuityRequestV2 {
            schema_version: 2,
            inventory_digest: birth_h(14),
            generation_id: birth_h(15),
            account_id: policy.account_id,
            network_profile_id: policy.network_profile_id,
            expected_writer_epoch: 1,
            expected_witness: witness,
        },
        writer_certificate_digest: policy.initial_writer_certificate_digest,
        writer_session_id: birth_h(16),
        writer_session_expires_at_ms: 90_000,
        head: AuthorityHead {
            sequence: 3,
            digest: birth_h(17),
        },
        history_digest: birth_h(18),
        complete_history: HostRecoveryHistoryV2 {
            schema_version: 2,
            complete_journal_digest: birth_h(19),
            pending_birth_commit: Some(commit),
            origins: vec![],
            retained_enrollments: vec![],
            retained_reservation_intents: vec![],
            review_receipts: vec![],
            account_use: AccountUseHistoryV2 {
                genesis: Some(genesis),
                exclusion: None,
                witness_ack: None,
            },
        },
    }
}

#[test]
fn original_birth_metadata_is_bound_even_when_snapshot_and_journal_pins_are_unchanged() {
    let original = pending_birth_fixture();
    original.validate().unwrap();
    let original_digest = original.digest().unwrap();
    for field in ["owner_approval", "local_review", "commit_time"] {
        let mut changed = original.clone();
        let commit = changed
            .complete_history
            .pending_birth_commit
            .as_mut()
            .unwrap();
        match field {
            "owner_approval" => commit.owner_approval_evidence_digest = birth_h(70),
            "local_review" => commit.local_owner_review_digest = birth_h(71),
            "commit_time" => commit.committed_at_ms += 1,
            _ => unreachable!(),
        }
        // Every alternate remains syntactically valid historical metadata and
        // retains the same policy, witness, event head, session and journal pin.
        // Exact metadata equality must independently detect the substitution.
        commit.validate().unwrap();
        changed.validate().unwrap();
        assert!(changed.request == original.request);
        assert_eq!(changed.head, original.head);
        assert_eq!(changed.history_digest, original.history_digest);
        assert_eq!(changed.writer_session_id, original.writer_session_id);
        assert_eq!(
            changed.complete_history.complete_journal_digest,
            original.complete_history.complete_journal_digest,
        );
        assert_ne!(changed.digest().unwrap(), original_digest, "{field}");
        assert!(
            original
                .require_unchanged(&changed, Duration::ZERO)
                .is_err()
        );
    }
    assert!(
        original
            .require_unchanged(&original, Duration::ZERO)
            .is_ok()
    );
}

#[test]
fn original_birth_record_cannot_be_stripped_or_rebound_to_another_genesis() {
    let original = pending_birth_fixture();
    let mut missing_commit = original.clone();
    missing_commit.complete_history.pending_birth_commit = None;
    assert!(missing_commit.validate().is_err());
    let mut missing_genesis = original.clone();
    missing_genesis.complete_history.account_use.genesis = None;
    assert!(missing_genesis.validate().is_err());
    let mut rebound = original.clone();
    let genesis = rebound
        .complete_history
        .account_use
        .genesis
        .as_mut()
        .unwrap();
    genesis.native_birth_digest = birth_h(72);
    genesis.validate().unwrap();
    assert!(rebound.validate().is_err());
    // Optional legacy absence stays omitted rather than injecting null into
    // old metadata-absent source shapes. The same guarded public v2 endpoint
    // remains unavailable regardless of successful audit DTO validation.
    let mut absent = original.clone();
    absent.complete_history.pending_birth_commit = None;
    absent.complete_history.account_use.genesis = None;
    absent.validate().unwrap();
    // Absence is valid syntax only. It cannot replace this authenticated born
    // evidence across the exact review/currentness comparison.
    assert!(original.require_unchanged(&absent, Duration::ZERO).is_err());
    let json = serde_json::to_value(&absent.complete_history).unwrap();
    assert!(json.get("pending_birth_commit").is_none());
    assert!(require_complete_origin_endpoint().is_err());
}

#[test]
fn pending_intent_preserves_exact_enrollment_linkage() {
    let mut pending = joined_fixture();
    pending.complete_history.origins.clear();
    pending.validate().unwrap();
    for field in [
        "enrollment_ref",
        "offline_signer_key",
        "return_recipient_key",
    ] {
        let mut changed = pending.clone();
        let terms = &mut changed.complete_history.retained_reservation_intents[0].terms;
        match field {
            "enrollment_ref" => terms.enrollment_ref = "ee".repeat(32),
            "offline_signer_key" => terms.offline_signer_key_digest = "ee".repeat(32),
            "return_recipient_key" => terms.return_recipient_key_digest = "ee".repeat(32),
            _ => unreachable!(),
        }
        // The terms and policy are individually well formed; their exact link
        // must still fail before the historical reader accepts the document.
        terms.validate().unwrap();
        assert!(changed.validate().is_err(), "{field}");
    }
}

#[test]
fn retained_intent_must_match_replay_only_and_minimal_only_origins() {
    for minimal_only in [false, true] {
        let mut evidence = joined_fixture();
        let HostRecoveryReservationOriginV2::Offline { origin } =
            &mut evidence.complete_history.origins[0]
        else {
            panic!("wrong origin")
        };
        origin.retained_remote = None;
        if minimal_only {
            origin.replayed_admission = None;
        } else {
            origin.minimal_local = None;
        }
        evidence.validate().unwrap();
        let mut changed_terms = evidence.clone();
        changed_terms.complete_history.retained_reservation_intents[0]
            .terms
            .maximum_debit_zatoshis -= 1;
        assert!(changed_terms.validate().is_err());
        let mut changed_intent = evidence;
        changed_intent.complete_history.retained_reservation_intents[0]
            .native_reservation_review_digest = "ee".repeat(32);
        // Same terms are insufficient when the original intent itself is pinned.
        assert!(changed_intent.validate().is_err());
    }
}
