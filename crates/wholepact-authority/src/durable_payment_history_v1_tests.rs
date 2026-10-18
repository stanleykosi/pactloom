//! Replay and compatibility boundaries, with deliberately no live native issuer.
use super::{tests::*, *};
use crate::policy::Event;
#[test]
fn admission_alone_is_not_legacy_v2_v3_or_empty_construction_history() {
    let (birth, _, events, a) = admitted_fixture();
    let h = history(&birth, &events);
    assert!(h.permits().is_err());
    assert!(h.require_legacy_online_only().is_err());
    assert!(h.require_original_roster_preconstruction_history().is_err());
    assert!(h.construction_history_v1().is_err());
    assert!(h.construction_history_v2().is_err());
    assert!(h.construction_history_with_transport_v1().is_err());
    assert!(h
        .durable_payment_online_permits_v1(&a.operation_id)
        .unwrap()
        .is_empty());
    assert!(h.durable_payment_admission_v1(&a.operation_id).unwrap() == Some(&a));
}
#[test]
fn history_uses_original_event_time_after_all_live_deadlines() {
    let (birth, mut ledger, mut events, a) = admitted_fixture();
    activate(&birth, &mut ledger, &mut events, &a);
    let r = reservation(&ledger, &a);
    let e = Event {
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(r)),
        authenticated_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 131_001,
        writer_session_id: Some(h('c')),
        original_request_link: None,
    };
    ledger.apply(&e).unwrap();
    events.push(e.clone());
    // These 1970 event deadlines are long past the actual test clock. Full
    // historical replay must never consult that clock or renew any lease.
    let history = history(&birth, &events);
    assert_eq!(
        history
            .durable_payment_online_permits_v1(&a.operation_id)
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        ledger.require_durable_payment_mutation_v1(
            &a.operation_id,
            &e.mutation,
            e.writer_session_id.as_deref(),
            900_000
        ),
        Err(AuthorityError::Expired)
    ));
    assert!(history
        .durable_payment_admission_v1(&a.operation_id)
        .unwrap()
        .is_some());
}
#[test]
fn cas_drain_and_original_bounds_are_not_renewed() {
    let (birth, ledger, events, terms) = fixture();
    let r = admission(&birth, &events, terms.clone());
    assert!(matches!(
        ledger.validate_new_durable_payment_admission_v1(&r, 126_999),
        Err(AuthorityError::Expired)
    ));
    assert!(matches!(
        ledger.validate_new_durable_payment_admission_v1(&r, 800_000),
        Err(AuthorityError::Expired)
    ));
    let mut stale = r.clone();
    stale.expected_head.digest = h('f');
    assert!(ledger
        .validate_new_durable_payment_admission_v1(&stale, 128_000)
        .is_err());
    let original = history(&birth, &events);
    for change in 0..8 {
        let mut t = terms.clone();
        match change {
            0 => t.valid_until_ms = 900_001,
            1 => t.valid_from_ms = 2_999,
            2 => t.maximum_debit_zatoshis = 51,
            3 => t.fee_share_zatoshis = 4,
            4 => t.transaction_fee_zatoshis = 4,
            5 => t.recipient_policy_scope_digest = h('f'),
            6 => t.original_enrollment_ref = ledger.policy.enrollment_refs[0].clone(),
            _ => t.original_birth_commit_digest = h('f'),
        }
        assert!(
            prepare_durable_payment_request_v1(t, &original).is_err(),
            "unbounded {change}"
        );
    }
}
#[test]
fn one_admission_and_one_original_session_never_create_replacements() {
    let (birth, mut l, mut events, a) = admitted_fixture();
    assert!(matches!(
        l.validate_new_durable_payment_admission_v1(&a, 128_000),
        Err(AuthorityError::StaleHead)
    ));
    activate(&birth, &mut l, &mut events, &a);
    let acquire = events[events.len() - 2].clone();
    l.require_durable_payment_mutation_v1(&a.operation_id, &acquire.mutation, None, 131_000)
        .unwrap();
    let mut alternate = acquire.mutation.clone();
    let AuthorityMutation::AcquireWriter(ref mut r) = alternate else {
        panic!()
    };
    r.session_id = h('f');
    assert!(matches!(
        l.require_durable_payment_mutation_v1(&a.operation_id, &alternate, None, 131_000),
        Err(AuthorityError::RecoveryRequired)
    ));
    assert!(matches!(
        l.require_durable_payment_mutation_v1(&a.operation_id, &acquire.mutation, None, 429_000),
        Err(AuthorityError::RecoveryRequired)
    ));
    let mut old_bootstrap = acquire.mutation.clone();
    let AuthorityMutation::AcquireWriter(ref mut r) = old_bootstrap else {
        panic!()
    };
    r.operation_id = l
        .manual_roster_extension()
        .unwrap()
        .unwrap()
        .extension
        .acquire_operation_id()
        .unwrap();
    assert!(l
        .require_durable_payment_mutation_v1(&a.operation_id, &old_bootstrap, None, 131_000)
        .is_err());
    let mut e = owner_event(&l, a, 131_000);
    e.mutation = alternate;
    e.authenticated_certificate_digest = l.policy.initial_writer_certificate_digest.clone();
    assert!(l.apply(&e).is_err());
}
#[test]
fn birth_or_bootstrap_omission_and_foreign_disclosure_fail() {
    let (birth, mut l, events, terms) = fixture();
    let prefix = history(&birth, &events[..1]);
    assert!(prepare_durable_payment_request_v1(terms.clone(), &prefix).is_err());
    let request = admission(&birth, &events, terms);
    let mut changed = request.clone();
    let OwnerControl::AdmitDurablePaymentV1 { record } = &mut changed.control else {
        panic!()
    };
    record.witness_native_review_digest = h('f');
    // Pure event replay verifies historical shape; original authenticated birth
    // validation is a separate mandatory full-load/reconciliation boundary.
    let event = owner_event(&l, changed, 128_000);
    l.apply(&event).unwrap();
    assert!(l.validate_durable_payment_birth_v1(Some(&birth)).is_err());
    let mut altered_events = events;
    altered_events.push(event);
    assert!(crate::transport::synthetic::recorded_fixture_history(
        &birth,
        &serde_json::to_vec(&altered_events).unwrap()
    )
    .is_err());
}
#[test]
fn original_common_budget_input_and_obligation_exclusions_remain() {
    let (birth, mut l, events, terms) = fixture();
    let a = admission(&birth, &events, terms);
    l.snapshot.settled_debit_zatoshis = 41;
    assert!(matches!(
        l.validate_new_durable_payment_admission_v1(&a, 128_000),
        Err(AuthorityError::BudgetExceeded)
    ));
    l.snapshot.settled_debit_zatoshis = 0;
    l.input_ids.insert("fixed-input".into());
    assert!(matches!(
        l.validate_new_durable_payment_admission_v1(&a, 128_000),
        Err(AuthorityError::InputReserved)
    ));
    l.input_ids.clear();
    l.nullifiers.insert(h('b'));
    assert!(matches!(
        l.validate_new_durable_payment_admission_v1(&a, 128_000),
        Err(AuthorityError::InputReserved)
    ));
    l.nullifiers.clear();
    l.obligations.insert("synthetic-new-obligation".into());
    assert!(matches!(
        l.validate_new_durable_payment_admission_v1(&a, 128_000),
        Err(AuthorityError::ObligationReserved)
    ));
}
#[test]
fn raw_terms_cannot_serialize_native_approval_or_unknown_fields() {
    let (_, _, _, t) = fixture();
    let mut value = serde_json::to_value(t).unwrap();
    value["native_approved"] = true.into();
    assert!(serde_json::from_value::<DurablePaymentAdmissionTermsV1>(value).is_err());
    let (birth, _, events, t) = fixture();
    let a = admission(&birth, &events, t);
    let mut value = serde_json::to_value(&a).unwrap();
    value["control"]["record"]["source"] = true.into();
    assert!(serde_json::from_value::<OwnerControlRequest>(value).is_err());
}

#[test]
fn unused_admission_can_acquire_later_without_renewing_its_end() {
    let (birth, mut ledger, mut events, admission) = admitted_fixture();
    let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
        panic!()
    };
    let acquire = Event {
        mutation: AuthorityMutation::AcquireWriter(AcquireWriterRequest {
            operation_id: record.acquire_operation_id(&admission).unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            reconciled_history_digest: crate::session::history_digest(&ledger.snapshot).unwrap(),
            session_id: h('c'),
            disclosure: birth.request.disclosure.clone(),
        }),
        authenticated_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 600_000,
        writer_session_id: None,
        original_request_link: None,
    };
    ledger.apply(&acquire).unwrap();
    assert_eq!(
        ledger
            .snapshot
            .pending_writer_session
            .as_ref()
            .unwrap()
            .expires_at_ms,
        800_000
    );
    events.push(acquire);
    let replay = history(&birth, &events);
    assert!(
        replay
            .durable_payment_admission_v1(&admission.operation_id)
            .unwrap()
            == Some(&admission)
    );
}

#[test]
fn unrelated_owner_history_is_never_a_fake_empty_supported_profile() {
    let (birth, mut ledger, mut events, terms) = fixture();
    let request = OwnerControlRequest {
        operation_id: "unsupported-resolution-source".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        writer_epoch: ledger.snapshot.writer_epoch,
        expected_head: ledger.snapshot.head.clone(),
        control: OwnerControl::EnrollResolutionSource {
            source_descriptor_digest: h('f'),
        },
    };
    let event = owner_event(&ledger, request, 8_000);
    ledger.apply(&event).unwrap();
    events.push(event);
    let history = history(&birth, &events);
    assert!(prepare_durable_payment_request_v1(terms, &history).is_err());
    assert!(ledger
        .require_supported_durable_payment_history_v1()
        .is_err());
}
