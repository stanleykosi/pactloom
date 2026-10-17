//! Inert historical fixtures. No native owner, authenticated current observation,
//! live dispatch wrapper or broadcast capability is manufactured here.
use super::*;
use crate::policy::{Event, Ledger};
fn fixture() -> (Ledger, BornOfflineDispatchRequestV1) {
    let (mut l, _, record) = crate::born_offline_admission_v1::tests::fixture();
    let session = l.snapshot.active_writer_session.clone().unwrap();
    let event = Event {
        mutation: AuthorityMutation::ReserveBornOfflineV1(Box::new(record)),
        authenticated_certificate_digest: session.writer_certificate_digest.clone(),
        witness_time_ms: 254001,
        writer_session_id: Some(session.session_id.clone()),
        original_request_link: None,
    };
    let MutationResult::BornOfflineReservedV1(a) = l.apply(&event).unwrap() else {
        panic!()
    };
    let r = BornOfflineDispatchRequestV1 {
        version: 1,
        dispatch: AuthorizeDispatch {
            operation_id: "inert-born-dispatch".into(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: l.snapshot.writer_epoch,
            expected_head: l.snapshot.head.clone(),
            reservation_operation_id: a.request.reservation.operation_id.clone(),
            reservation_request_digest: a.request.request_digest().unwrap(),
            final_transaction_digest: "11".repeat(32),
            final_transaction_id: "22".repeat(32),
            transaction_expiry_height: a.request.reservation.intent.terms.transaction_expiry_height,
            backend_disclosure_digest: "33".repeat(32),
            reviewed_at_ms: 255100,
            admission_expires_at_ms: 255900,
        },
        original_admission_digest: a.admission_digest().unwrap(),
        construction_link_digest: a.request.construction_link.digest().unwrap(),
        current_input_observation_digest: "44".repeat(32),
        observed_at_ms: 255000,
        observation_expires_at_ms: 256000,
        native_review_digest: "55".repeat(32),
    };
    (l, r)
}
fn event(l: &Ledger, r: &BornOfflineDispatchRequestV1) -> Event {
    let session = l.snapshot.active_writer_session.as_ref().unwrap();
    Event {
        mutation: AuthorityMutation::AuthorizeBornOfflineDispatchV1(Box::new(r.clone())),
        authenticated_certificate_digest: session.writer_certificate_digest.clone(),
        witness_time_ms: 255101,
        writer_session_id: Some(session.session_id.clone()),
        original_request_link: None,
    }
}
#[test]
fn dispatch_preserves_original_bucket_and_retries_only_identical_final_bytes() {
    let (mut l, r) = fixture();
    let before = l.snapshot.clone();
    let e = event(&l, &r);
    let result = l.apply(&e).unwrap();
    let MutationResult::BornOfflineDispatchAdmittedV1(a) = &result else {
        panic!()
    };
    a.matches_request(&r).unwrap();
    assert!(l.apply(&e).unwrap() == result);
    l.recompute_exposure().unwrap();
    assert_eq!(
        l.snapshot.outstanding_debit_zatoshis,
        before.outstanding_debit_zatoshis
    );
    assert_eq!(
        l.snapshot.reserved_input_value_zatoshis,
        before.reserved_input_value_zatoshis
    );
    assert_eq!(
        l.snapshot.outstanding_reservations,
        before.outstanding_reservations
    );
    assert!(crate::reservation_view::ReservationView::from_result(&result).is_none());
    let mut changed = r.clone();
    changed.dispatch.operation_id = "second-inert-dispatch".into();
    changed.dispatch.expected_head = l.snapshot.head.clone();
    assert!(l.apply(&event(&l, &changed)).is_ok());
    changed.dispatch.operation_id = "changed-final-bytes".into();
    changed.dispatch.expected_head = l.snapshot.head.clone();
    changed.dispatch.final_transaction_digest = "99".repeat(32);
    assert!(matches!(
        l.apply(&event(&l, &changed)),
        Err(AuthorityError::Conflict)
    ));
    changed.dispatch.final_transaction_digest = r.dispatch.final_transaction_digest.clone();
    changed.dispatch.backend_disclosure_digest = "98".repeat(32);
    assert!(matches!(
        l.apply(&event(&l, &changed)),
        Err(AuthorityError::Conflict)
    ));
    assert!(
        l.validate_born_dispatch_current_v1(&r, &e.authenticated_certificate_digest, 255900)
            .is_err()
    );
    // Historical replay remains evidence, never an opaque current wrapper.
    assert!(l.replay(&e).unwrap().is_some());
}
#[test]
fn dispatch_rejects_substituted_origin_scope_window_and_session_without_mutating() {
    for field in 0..13 {
        let (mut l, mut r) = fixture();
        match field {
            0 => r.original_admission_digest = "61".repeat(32),
            1 => r.construction_link_digest = "62".repeat(32),
            2 => r.dispatch.reservation_request_digest = "63".repeat(32),
            3 => r.dispatch.reservation_operation_id = "absent-original".into(),
            4 => r.dispatch.account_id = "different-account".into(),
            5 => r.dispatch.transaction_expiry_height += 1,
            6 => r.dispatch.writer_epoch += 1,
            7 => r.dispatch.expected_head.digest = "64".repeat(32),
            8 => r.dispatch.admission_expires_at_ms = 256001,
            9 => r.observation_expires_at_ms = r.observed_at_ms + 60001,
            10 => r.dispatch.reviewed_at_ms = r.observed_at_ms - 1,
            11 => l.snapshot.writer_status = WriterStatus::Paused,
            _ => {
                l.snapshot
                    .active_writer_session
                    .as_mut()
                    .unwrap()
                    .reconciled_head
                    .digest = "65".repeat(32)
            }
        }
        let before = l.snapshot.clone();
        assert!(l.apply(&event(&l, &r)).is_err(), "field {field}");
        assert!(l.snapshot == before);
    }
}
