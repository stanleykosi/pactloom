//! Never-funded pure replay fixtures. No live source, native approval, socket or key use.
use super::*;
use crate::policy::{Event, Ledger};
use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};
pub(crate) fn h(c: char) -> String {
    c.to_string().repeat(64)
}
pub(crate) fn fixture() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    Ledger,
    Vec<Event>,
    DurablePaymentAdmissionTermsV1,
) {
    let (birth, inner, _, _) = crate::manual_session_continuation::tests::continued_fixture();
    let extension = ManualRosterEnrollmentExtensionV2 {
        version: 2,
        roster: HostRosterAppendBindingV2 {
            version: 2,
            generation_id: inner.terms.host.generation_id.clone(),
            store_destination_identity: inner.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: h('d'),
            },
        },
        signer_roster_record_digest: h('e'),
        account_extension: inner,
    };
    let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
    let mut events = vec![crate::manual_roster_witness_v2::tests::extension_event(
        &ledger, &extension,
    )];
    ledger.apply(&events[0]).unwrap();
    crate::manual_roster_witness_v2::tests::bootstrap(
        &birth,
        &extension,
        &mut ledger,
        &mut events,
        5_000,
        h('7'),
    );
    let old = &extension.account_extension;
    let mut fixed = DurableFixedCandidateBindingV1 {
        schema_version: 1,
        network_profile_id: old.terms.identity.network_profile_id.clone(),
        agreement_id: old.terms.scope.agreement_id.clone(),
        obligation_id: old.terms.scope.obligation_id.clone(),
        proposal_id: "fixed-proposal".into(),
        revision: 1,
        expiry_height: 140,
        proposal_digest: h('1'),
        manifest_digest: h('2'),
        unsigned_artifact_digest: h('3'),
        proved_artifact_digest: h('4'),
        effects_commitment: h('5'),
        policy_digest: h('6'),
        review_binding: h('7'),
        action_mapping_digest: h('8'),
        anchor: h('9'),
        proposal_binding: String::new(),
    };
    fixed.proposal_binding = fixed.canonical_binding();
    let mut terms = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: old.terms.identity.clone(),
        original_policy_digest: old.terms.original_policy_digest.clone(),
        original_genesis_digest: old.terms.account_use_genesis_digest.clone(),
        original_birth_commit_digest: old.terms.birth_commit_digest.clone(),
        original_roster_extension_digest: extension.digest().unwrap(),
        original_enrollment_ref: old.enrollment_ref.clone(),
        writer_certificate_digest: old.terms.signer.writer_certificate_digest.clone(),
        fixed,
        authorization_id: "fixed-authorization".into(),
        recipient_policy_scope_digest: old.terms.scope.recipient_scope_digests[0].clone(),
        concrete_recipient_scope_digest: h('a'),
        inputs: vec![InputReservation {
            input_id: "fixed-input".into(),
            nullifier: h('b'),
            action_index: 0,
            value_zatoshis: 50,
        }],
        maximum_debit_zatoshis: 40,
        fee_share_zatoshis: 2,
        transaction_fee_zatoshis: 3,
        valid_from_ms: 128_000,
        valid_until_ms: 800_000,
    };
    terms.authorization_id = terms.canonical_authorization_id();
    (birth, ledger, events, terms)
}
pub(crate) fn history(
    birth: &crate::pending_birth::PendingBirthCommitRecord,
    events: &[Event],
) -> ReconciledAuthorityHistory {
    crate::transport::synthetic::recorded_fixture_history(
        birth,
        &serde_json::to_vec(events).unwrap(),
    )
    .unwrap()
}
pub(crate) fn admission(
    birth: &crate::pending_birth::PendingBirthCommitRecord,
    events: &[Event],
    terms: DurablePaymentAdmissionTermsV1,
) -> OwnerControlRequest {
    prepare_durable_payment_request_v1(terms, &history(birth, events)).unwrap()
}
pub(crate) fn owner_event(l: &Ledger, r: OwnerControlRequest, now: u64) -> Event {
    Event {
        mutation: AuthorityMutation::OwnerControl(r),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: None,
        original_request_link: None,
    }
}
pub(crate) fn admitted_fixture() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    Ledger,
    Vec<Event>,
    OwnerControlRequest,
) {
    let (birth, mut l, mut events, terms) = fixture();
    let r = admission(&birth, &events, terms);
    let e = owner_event(&l, r.clone(), 128_000);
    l.apply(&e).unwrap();
    events.push(e);
    (birth, l, events, r)
}
pub(crate) fn activate(
    birth: &crate::pending_birth::PendingBirthCommitRecord,
    l: &mut Ledger,
    events: &mut Vec<Event>,
    admission: &OwnerControlRequest,
) {
    let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
        panic!()
    };
    let e = Event {
        mutation: AuthorityMutation::AcquireWriter(AcquireWriterRequest {
            operation_id: record.acquire_operation_id(admission).unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: l.snapshot.writer_epoch,
            expected_head: l.snapshot.head.clone(),
            reconciled_history_digest: crate::session::history_digest(&l.snapshot).unwrap(),
            session_id: h('c'),
            disclosure: birth.request.disclosure.clone(),
        }),
        authenticated_certificate_digest: l.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 129_000,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&e).unwrap();
    events.push(e);
    let r = OwnerControlRequest {
        operation_id: "durable-activate".into(),
        account_id: l.policy.account_id.clone(),
        network_profile_id: l.policy.network_profile_id.clone(),
        writer_epoch: l.snapshot.writer_epoch,
        expected_head: l.snapshot.head.clone(),
        control: OwnerControl::ActivateWriter { session_id: h('c') },
    };
    let e = owner_event(l, r, 130_000);
    l.apply(&e).unwrap();
    events.push(e);
}
pub(crate) fn reservation(l: &Ledger, a: &OwnerControlRequest) -> ReserveAuthorization {
    let OwnerControl::AdmitDurablePaymentV1 { record } = &a.control else {
        panic!()
    };
    let t = &record.terms;
    let f = &t.fixed;
    ReserveAuthorization {
        automation: None,
        operation_id: t.authorization_id.clone(),
        account_id: t.identity.account_id.clone(),
        network_profile_id: t.identity.network_profile_id.clone(),
        writer_epoch: a.writer_epoch,
        expected_head: l.snapshot.head.clone(),
        authorization_id: t.authorization_id.clone(),
        original_consent_ref: h('d'),
        enrollment_ref: t.original_enrollment_ref.clone(),
        accepted_manifest_ref: h('e'),
        agreement_id: f.agreement_id.clone(),
        obligation_id: f.obligation_id.clone(),
        proposal_id: f.proposal_id.clone(),
        proposal_digest: f.proposal_digest.clone(),
        manifest_digest: f.manifest_digest.clone(),
        effects_digest: f.effects_commitment.clone(),
        artifact_digest: f.proved_artifact_digest.clone(),
        review_binding: f.review_binding.clone(),
        recipient_scope_digest: t.recipient_policy_scope_digest.clone(),
        inputs: t.inputs.clone(),
        maximum_debit_zatoshis: t.maximum_debit_zatoshis,
        fee_share_zatoshis: t.fee_share_zatoshis,
        transaction_fee_zatoshis: t.transaction_fee_zatoshis,
        transaction_expiry_height: f.expiry_height,
        reviewed_at_ms: 131_000,
        permit_expires_at_ms: 132_000,
    }
}
#[test]
fn canonical_fixed_projection_matches_protocol_fixture() {
    let mut f = DurableFixedCandidateBindingV1 {
        schema_version: 1,
        network_profile_id: "ironwood-testnet-nu7-candidate".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        proposal_id: "proposal".into(),
        revision: 1,
        expiry_height: 140,
        proposal_digest: "01".repeat(32),
        manifest_digest: "02".repeat(32),
        unsigned_artifact_digest: "03".repeat(32),
        proved_artifact_digest: "04".repeat(32),
        effects_commitment: "05".repeat(32),
        policy_digest: "06".repeat(32),
        review_binding: "07".repeat(32),
        action_mapping_digest: "08".repeat(32),
        anchor: "09".repeat(32),
        proposal_binding: String::new(),
    };
    f.proposal_binding = f.canonical_binding();
    assert_eq!(
        f.proposal_binding,
        "e29644405bf78d4955852c35ba531d97b0bacf6dfa74ecc81b05e1f6bd0beacd"
    );
    f.validate().unwrap();
    let encoded = serde_json::to_value(&f).unwrap();
    for key in encoded.as_object().unwrap().keys() {
        let mut changed = encoded.clone();
        changed[key] = if let Some(n) = changed[key].as_u64() {
            serde_json::json!(n + 1)
        } else {
            serde_json::json!(format!("{}a", changed[key].as_str().unwrap()))
        };
        let changed: DurableFixedCandidateBindingV1 = serde_json::from_value(changed).unwrap();
        assert!(changed.validate().is_err(), "unbound {key}");
    }
    let mut unknown = encoded;
    unknown["native_approved"] = true.into();
    assert!(serde_json::from_value::<DurableFixedCandidateBindingV1>(unknown).is_err());
}
#[test]
fn every_admission_term_and_context_is_bound() {
    let (birth, _, events, terms) = fixture();
    let request = admission(&birth, &events, terms);
    let encoded = serde_json::to_value(&request).unwrap();
    let terms = &encoded["control"]["record"]["terms"];
    // The enum uses the maintained tagged protocol representation.
    assert!(terms.is_object());
    for key in terms.as_object().unwrap().keys() {
        let mut changed = encoded.clone();
        let v = &mut changed["control"]["record"]["terms"][key];
        if let Some(n) = v.as_u64() {
            *v = serde_json::json!(n + 1);
        } else if let Some(s) = v.as_str() {
            *v = serde_json::json!(format!("{s}a"));
        } else if v.is_array() {
            v.as_array_mut().unwrap().clear();
        } else {
            v.as_object_mut()
                .unwrap()
                .insert("unknown".into(), true.into());
        }
        match serde_json::from_value::<OwnerControlRequest>(changed) {
            Err(_) => {}
            Ok(r) => {
                let OwnerControl::AdmitDurablePaymentV1 { record } = &r.control else {
                    panic!()
                };
                assert!(
                    record
                        .validate_request(&r, &birth.request.disclosure)
                        .is_err(),
                    "unbound {key}"
                );
            }
        }
    }
    let OwnerControl::AdmitDurablePaymentV1 { record } = &request.control else {
        panic!()
    };
    for index in 0..6 {
        let mut r = request.clone();
        match index {
            0 => r.operation_id.push('x'),
            1 => r.account_id = h('f'),
            2 => r.network_profile_id.push('x'),
            3 => r.writer_epoch += 1,
            4 => r.expected_head.sequence += 1,
            _ => r.expected_head.digest = h('f'),
        }
        assert!(record
            .validate_request(&r, &birth.request.disclosure)
            .is_err());
    }
    let mut foreign = birth.request.disclosure.clone();
    foreign.endpoint = "127.0.0.1:1912".into();
    assert!(record.validate_request(&request, &foreign).is_err());
}
#[test]
fn exact_admission_preserves_birth_policy_exposure_and_old_sessions() {
    let (birth, mut l, mut events, terms) = fixture();
    let policy = l.policy.clone();
    let before = l.snapshot.clone();
    let sessions = l.sessions.clone();
    let r = admission(&birth, &events, terms);
    let e = owner_event(&l, r.clone(), 128_000);
    l.apply(&e).unwrap();
    events.push(e);
    assert!(l.policy == policy);
    assert!(l.sessions == sessions);
    assert!(l.snapshot.pending_writer_session.is_none());
    assert!(l.snapshot.active_writer_session.is_none());
    assert_eq!(
        l.snapshot.outstanding_debit_zatoshis,
        before.outstanding_debit_zatoshis
    );
    assert_eq!(
        l.snapshot.settled_debit_zatoshis,
        before.settled_debit_zatoshis
    );
    assert!(l.snapshot.transport_fences == before.transport_fences);
    l.validate_durable_payment_birth_v1(Some(&birth)).unwrap();
    assert!(l.validate_durable_payment_birth_v1(None).is_err());
    assert!(l
        .require_unfenced_durable_payment_session_v1(&h('7'))
        .is_err());
    activate(&birth, &mut l, &mut events, &r);
    let request = reservation(&l, &r);
    assert!(!l.policy.enrollment_refs.contains(&request.enrollment_ref));
    let e = Event {
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(request)),
        authenticated_certificate_digest: l.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 131_001,
        writer_session_id: Some(h('c')),
        original_request_link: None,
    };
    l.apply(&e).unwrap();
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 40);
    assert_eq!(l.snapshot.outstanding_reservations, 1);
    assert!(l.policy == policy);
    events.push(e.clone());
    let before = l.snapshot.clone();
    let mut replay = e;
    replay.witness_time_ms = 9_000_000;
    l.apply(&replay).unwrap();
    assert!(l.snapshot == before);
    let read = history(&birth, &events);
    assert_eq!(
        read.durable_payment_online_permits_v1(&r.operation_id)
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn every_stable_reservation_field_is_exact_but_fresh_refs_are_signer_owned() {
    let (birth, mut l, mut events, a) = admitted_fixture();
    activate(&birth, &mut l, &mut events, &a);
    let original = reservation(&l, &a);
    let OwnerControl::AdmitDurablePaymentV1 { record } = &a.control else {
        panic!()
    };
    let encoded = serde_json::to_value(&original).unwrap();
    for key in encoded.as_object().unwrap().keys() {
        if [
            "expected_head",
            "original_consent_ref",
            "accepted_manifest_ref",
            "reviewed_at_ms",
            "permit_expires_at_ms",
        ]
        .contains(&key.as_str())
        {
            continue;
        }
        let mut changed = encoded.clone();
        let v = &mut changed[key];
        if let Some(n) = v.as_u64() {
            *v = serde_json::json!(n + 1);
        } else if let Some(s) = v.as_str() {
            *v = serde_json::json!(format!("{s}a"));
        } else if v.is_array() {
            v.as_array_mut().unwrap().clear();
        } else {
            continue;
        }
        let changed: ReserveAuthorization = serde_json::from_value(changed).unwrap();
        assert!(
            crate::durable_payment_policy_v1::require_exact_reservation_v1(
                &record.terms,
                a.writer_epoch,
                &changed
            )
            .is_err(),
            "unbound {key}"
        );
    }
    let mut fresh = original;
    fresh.original_consent_ref = h('a');
    fresh.accepted_manifest_ref = h('b');
    crate::durable_payment_policy_v1::require_exact_reservation_v1(
        &record.terms,
        a.writer_epoch,
        &fresh,
    )
    .unwrap();
}

#[test]
fn authorization_id_matches_existing_signer_canonical_domain() {
    let (_, _, _, mut terms) = fixture();
    terms.fixed.proposal_binding =
        "e29644405bf78d4955852c35ba531d97b0bacf6dfa74ecc81b05e1f6bd0beacd".into();
    terms.identity.account_id = "1".repeat(64);
    assert_eq!(
        terms.canonical_authorization_id(),
        "durable-v1-e99a15da169bb56dac14f8c057c60eaa648e87b6b0fcb870b6899ab7b7011c0f"
    );
    let first = terms.canonical_authorization_id();
    terms.identity.account_id = "2".repeat(64);
    assert_ne!(terms.canonical_authorization_id(), first);
}
