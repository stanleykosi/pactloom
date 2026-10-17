//! Never-funded replay fixtures. Long nonspending retention is not live authority.
use super::*;
use crate::construction_transport_handoff_v1::{
    ConstructionTransportMutationV1, ConstructionTransportRequestV1,
};

#[test]
fn original_retention_v2_preserves_short_reserve_consume_and_single_exposure() {
    let (birth, extension, events, completed, _temporary, _certificate, _key) =
        construction_fixture_v3_with_original_retention();
    let AuthorityMutation::ReserveManualRosterConstructionV3(request) = &events[13].mutation else {
        panic!("exact modeled retained V3 reservation");
    };
    let scope = &request.construction.plan.retained.selection.scope.selection;
    assert_eq!(scope.version, 2);
    assert_eq!(scope.invocation.version, 2);
    assert!(
        scope.invocation.construction_expires_at_ms - scope.invocation.requested_at_ms
            > scope.inventory.enrollment.scope.maximum_permit_lifetime_ms
    );
    assert!(scope.invocation.requested_at_ms < 130_001);
    assert!(
        request.construction.admission_expires_at_ms
            < request.construction.plan.completion_expires_at_ms()
    );
    assert!(
        request.construction.admission_expires_at_ms - request.construction.requested_at_ms
            <= wholepact_core::manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS
    );

    // Re-labeling the new scope as the legacy version cannot lengthen a legacy
    // owner. No timestamp, approval, or previously consumed capability changes.
    let mut legacy = scope.clone();
    legacy.version = 1;
    legacy.invocation.version = 1;
    legacy.purpose = "prepare_one_private_contribution".into();
    assert!(legacy.validate().is_err());
    let legacy_plan =
        wholepact_core::manual_roster_construction_v2::ManualRosterConstructionPlanV2 {
            version: 2,
            retained: request.construction.plan.retained.clone(),
            retained_evidence_digest: request.construction.plan.retained_evidence_digest.clone(),
            proposal: request.construction.plan.proposal.clone(),
            participants: request.construction.plan.participants.clone(),
        };
    assert!(legacy_plan.validate().is_err());

    let mut before_reserve = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events[..13] {
        before_reserve.apply(event).unwrap();
    }
    let before = before_reserve.snapshot.clone();
    let mut late_reserve = events[13].clone();
    late_reserve.witness_time_ms = request.construction.admission_expires_at_ms;
    assert!(matches!(
        before_reserve.apply(&late_reserve),
        Err(AuthorityError::Expired)
    ));
    assert!(before_reserve.snapshot == before);
    // This inert wrapper exercises only the maintained scope recursion. It is
    // not a credential, authenticated transport request, or native approval.
    let wrapped_reserve =
        AuthorityMutation::UseConstructionTransportV1(Box::new(ConstructionTransportRequestV1 {
            version: 1,
            credential_id: h('a'),
            mutation: ConstructionTransportMutationV1::Reserve(request.clone()),
        }));
    assert!(matches!(
        before_reserve.require_roster_construction_scope_v3(
            &wrapped_reserve,
            request.construction.admission_expires_at_ms,
        ),
        Err(AuthorityError::Expired)
    ));
    assert!(before_reserve.snapshot == before);
    before_reserve.apply(&events[13]).unwrap();
    let reserved = before_reserve.snapshot.clone();
    let mut late_consume = events[14].clone();
    late_consume.witness_time_ms = request.construction.admission_expires_at_ms;
    assert!(matches!(
        before_reserve.apply(&late_consume),
        Err(AuthorityError::Expired)
    ));
    assert!(before_reserve.snapshot == reserved);
    let AuthorityMutation::ConsumeManualRosterConstructionV3(consume) = &events[14].mutation else {
        panic!("exact modeled retained V3 consumption");
    };
    let wrapped_consume =
        AuthorityMutation::UseConstructionTransportV1(Box::new(ConstructionTransportRequestV1 {
            version: 1,
            credential_id: h('a'),
            mutation: ConstructionTransportMutationV1::Consume(Box::new(consume.clone())),
        }));
    assert!(matches!(
        before_reserve.require_roster_construction_scope_v3(
            &wrapped_consume,
            request.construction.admission_expires_at_ms,
        ),
        Err(AuthorityError::Expired)
    ));
    assert!(before_reserve.snapshot == reserved);
    assert_eq!(reserved.outstanding_reservations, 1);
    assert_eq!(reserved.outstanding_debit_zatoshis, 400_012_000);
    assert!(matches!(
        completed.require_unconsumed_roster_construction_v3(&events[14].mutation),
        Err(AuthorityError::Uncertain)
    ));
    let history = crate::manual_roster_witness_v2::tests::history(&birth, &completed, &events);
    let origins = history.construction_history_v2().unwrap();
    assert!(
        matches!(&origins.origins()[0], ConstructionOriginHistoryV2::CommonContextV3 { origin } if origin.consumed().is_some())
    );
    assert_eq!(completed.snapshot.outstanding_reservations, 1);
    assert_eq!(
        completed.snapshot.outstanding_debit_zatoshis,
        reserved.outstanding_debit_zatoshis
    );
    assert!(request.enrollment() == &extension.account_extension.terms);
}
