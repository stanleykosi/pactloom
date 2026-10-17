//! Immutable protocol equivalence only. Uses the existing never-funded signed
//! replay fixture; no process, wallet, native owner, socket or clock is created.
use super::*;
use crate::{ConstructionHistoryV2, ConstructionOriginHistoryV2};

fn fixture() -> (
    ManualRosterEnrollmentExtensionV2,
    ManualRosterSessionContinuationV2,
    ManualRosterConstructionReservationRecordV3,
    ManualRosterConstructionConsumedRecordV3,
) {
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "../../wholepact-signer/src/consent_journal/fixtures/common-context-authority-audit.synthetic.json"
    )).unwrap();
    assert_eq!(raw["native_actors_exercised"], false);
    let history: ConstructionHistoryV2 =
        serde_json::from_value(raw["complete_history"].clone()).unwrap();
    history.validate().unwrap();
    assert_eq!(history.origins().len(), 1);
    let ConstructionOriginHistoryV2::CommonContextV3 { origin } = &history.origins()[0] else {
        panic!("fixed synthetic V3 archive");
    };
    (
        origin.extension().clone(),
        origin.continuation().clone(),
        origin.reservation().clone(),
        origin.consumed().unwrap().clone(),
    )
}
fn different(value: &str) -> String {
    if value == "c0".repeat(32) {
        "c1".repeat(32)
    } else {
        "c0".repeat(32)
    }
}

// Pre-refactor validator bodies are retained as an independent equivalence
// oracle. No optimized private helper or proof is used by these bodies.
fn legacy_request(
    r: &ManualRosterConstructionReservationRequestV3,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<()> {
    r.construction
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    validate_plan_original(&r.construction.plan, e)?;
    c.validate_for(e)?;
    for h in [
        &r.expected_head.digest,
        &r.session_id,
        &r.signer_intent_digest,
        &r.native_review_digest,
        &r.attempt_digest,
    ] {
        hash(h)?;
    }
    if r.version != 3
        || r.attempt_digest != c.digest_for(e)?
        || r.attempt_sequence != c.sequence()
        || r.attempt_sequence
            <= r
                .construction
                .plan
                .retained
                .selection
                .scope
                .selection
                .inventory
                .attempt
                .attempt_sequence
        || r.attempt_digest
            == r
                .construction
                .plan
                .retained
                .selection
                .scope
                .selection
                .inventory
                .attempt
                .continuation_digest
        || r.writer_epoch != e.account_extension.terms.signer.writer_epoch
        || r.reviewed_at_ms < r.construction.requested_at_ms
        || r.reviewed_at_ms < c.inner().issued_at_ms
        || r.reviewed_at_ms >= r.construction.admission_expires_at_ms
    {
        return Err(AuthorityError::InvalidBinding);
    }
    id(&r.construction.operation_id)?;
    Ok(())
}
fn legacy_reservation(
    r: &ManualRosterConstructionReservationRecordV3,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<()> {
    legacy_request(&r.request, e, c)?;
    let t = &e.account_extension.terms;
    validate_snapshot(
        &r.snapshot,
        &r.session,
        e,
        &r.request.expected_head,
        r.admitted_at_ms,
        &r.request.session_id,
    )?;
    if r.admitted_at_ms < r.request.reviewed_at_ms
        || r.admitted_at_ms >= r.request.construction.admission_expires_at_ms
        || r.admitted_at_ms >= r.session.expires_at_ms
        || r.construction_expires_at_ms != r.request.completion_deadline_ms()
        || r.reserved_debit_zatoshis != r.request.maximum_net_debit_zatoshis()?
        || r.reserved_input_value_zatoshis != r.request.input_value_zatoshis()?
        || r.snapshot.outstanding_debit_zatoshis < r.reserved_debit_zatoshis
        || r.snapshot.reserved_input_value_zatoshis < r.reserved_input_value_zatoshis
        || r.snapshot.aggregate_budget_zatoshis < r.snapshot.outstanding_debit_zatoshis
        || r
            .snapshot
            .outstanding_debit_zatoshis
            .checked_add(r.snapshot.settled_debit_zatoshis)
            .is_none_or(|n| {
                n > t.scope.aggregate_budget_zatoshis
                    || n > r.snapshot.aggregate_budget_zatoshis
            })
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
fn legacy_digest(r: &ManualRosterConstructionReservationRecordV3, e: &ManualRosterEnrollmentExtensionV2, c: &ManualRosterSessionContinuationV2) -> Result<String> {
    legacy_reservation(r, e, c)?;
    digest("wholepact:manual-roster-construction-reservation:v3", r)
}
fn legacy_consume(
    q: &ManualRosterConstructionConsumeRequestV3,
    r: &ManualRosterConstructionReservationRecordV3,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<()> {
    legacy_reservation(r, e, c)?;
    let t = &e.account_extension.terms;
    if q.version != 3
        || q.operation_id != format!("roster-construct-consume-v3-{}", legacy_digest(r, e, c)?)
        || q.reservation_operation_id != r.request.construction.operation_id
        || q.reservation_digest != legacy_digest(r, e, c)?
        || q.account_id != t.identity.account_id
        || q.network_profile_id != t.identity.network_profile_id
        || q.writer_epoch != r.request.writer_epoch
        || q.session_id != r.session.session_id
        || q.expected_head != r.snapshot.head
        || q.common_invocation_digest != r.request.invocation_digest()?
        || q.current_caller_binding_digest
            != r.request.construction.current_caller_binding_digest
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}

#[test]
fn call_local_validation_preserves_complete_records_and_canonical_identifiers() {
    let (e, c, r, consumed) = fixture();
    legacy_request(&r.request, &e, &c).unwrap();
    legacy_reservation(&r, &e, &c).unwrap();
    legacy_consume(&consumed.request, &r, &e, &c).unwrap();
    r.request.validate_for(&e, &c).unwrap();
    r.validate_for(&e, &c).unwrap();
    consumed.validate_for(&r, &e, &c).unwrap();
    let expected = legacy_digest(&r, &e, &c).unwrap();
    assert_eq!(r.digest_for(&e, &c).unwrap(), expected);
    assert_eq!(consumed.request.reservation_digest, expected);
    assert_eq!(construction_consume_operation_id_v3(&r, &e, &c).unwrap(),
        format!("roster-construct-consume-v3-{expected}"));
    assert_eq!(r.request.maximum_net_debit_zatoshis().unwrap(), r.reserved_debit_zatoshis);
    assert_eq!(r.request.digest_for(&e, &c).unwrap(),
        digest("wholepact:manual-roster-construction-reservation-request:v3", &r.request).unwrap());
}

#[test]
fn call_local_validation_rejects_substituted_plan_extension_attempt_and_amounts() {
    let (e, c, r, consumed) = fixture();
    let edits: &[fn(&mut ManualRosterConstructionReservationRequestV3)] = &[
        |q| q.version += 1,
        |q| q.construction.version += 1,
        |q| q.construction.plan.version += 1,
        |q| q.construction.plan.common_context_digest = different(&q.construction.plan.common_context_digest),
        |q| q.construction.plan.retained.selected_inputs[0].value_zatoshis += 1,
        |q| q.attempt_digest = different(&q.attempt_digest),
        |q| q.attempt_sequence += 1,
        |q| q.writer_epoch += 1,
        |q| q.expected_head.digest = "malformed".into(),
        |q| q.reviewed_at_ms = q.construction.admission_expires_at_ms,
    ];
    for edit in edits {
        let mut changed = r.request.clone();
        edit(&mut changed);
        assert!(legacy_request(&changed, &e, &c).is_err());
        assert!(changed.validate_for(&e, &c).is_err());
        assert!(changed.digest_for(&e, &c).is_err());
    }
    let mut foreign = e.clone();
    foreign.signer_roster_record_digest = different(&foreign.signer_roster_record_digest);
    foreign.validate().unwrap();
    assert!(legacy_request(&r.request, &foreign, &c).is_err());
    assert!(r.request.validate_for(&foreign, &c).is_err());
    let mut other = c.clone();
    other.continuation.attempt_nonce = different(&other.continuation.attempt_nonce);
    other.validate_for(&e).unwrap();
    assert!(legacy_request(&r.request, &e, &other).is_err());
    assert!(r.request.validate_for(&e, &other).is_err());
    let edits: &[fn(&mut ManualRosterConstructionReservationRecordV3)] = &[
        |x| x.reserved_debit_zatoshis += 1,
        |x| x.reserved_input_value_zatoshis += 1,
        |x| x.snapshot.outstanding_debit_zatoshis = 0,
        |x| x.admitted_at_ms = x.session.expires_at_ms,
        |x| x.construction_expires_at_ms += 1,
    ];
    for edit in edits {
        let mut changed = r.clone();
        edit(&mut changed);
        assert!(legacy_reservation(&changed, &e, &c).is_err());
        assert!(changed.validate_for(&e, &c).is_err());
        assert!(changed.digest_for(&e, &c).is_err());
        assert!(construction_consume_operation_id_v3(&changed, &e, &c).is_err());
        // Recomputing both canonical identifiers cannot bypass full validation
        // of the mutated reservation or inherit the preceding valid call.
        let mut q = consumed.request.clone();
        q.reservation_digest = digest("wholepact:manual-roster-construction-reservation:v3", &changed).unwrap();
        q.operation_id = format!("roster-construct-consume-v3-{}", q.reservation_digest);
        assert!(legacy_consume(&q, &changed, &e, &c).is_err());
        assert!(q.validate_for(&changed, &e, &c).is_err());
    }
    r.validate_for(&e, &c).unwrap();
}

#[test]
fn call_local_validation_keeps_every_consume_join_and_revalidates_each_call() {
    let (e, c, r, consumed) = fixture();
    let edits: &[fn(&mut ManualRosterConstructionConsumeRequestV3)] = &[
        |q| q.version += 1,
        |q| q.operation_id.push('x'),
        |q| q.reservation_operation_id.push('x'),
        |q| q.reservation_digest = different(&q.reservation_digest),
        |q| q.account_id = different(&q.account_id),
        |q| q.network_profile_id.push('x'),
        |q| q.writer_epoch += 1,
        |q| q.session_id = different(&q.session_id),
        |q| q.expected_head.sequence += 1,
        |q| q.common_invocation_digest = different(&q.common_invocation_digest),
        |q| q.current_caller_binding_digest = different(&q.current_caller_binding_digest),
    ];
    for edit in edits {
        consumed.request.validate_for(&r, &e, &c).unwrap();
        let mut changed = consumed.request.clone();
        edit(&mut changed);
        assert!(legacy_consume(&changed, &r, &e, &c).is_err());
        assert!(changed.validate_for(&r, &e, &c).is_err());
    }
    // A successful call cannot carry validation over altered underlying plan
    // bytes even when supplied identifiers are recomputed from those bytes.
    let mut changed = r.clone();
    changed.request.construction.plan.common_context_digest = different(&changed.request.construction.plan.common_context_digest);
    let mut q = consumed.request.clone();
    q.reservation_digest = digest("wholepact:manual-roster-construction-reservation:v3", &changed).unwrap();
    q.operation_id = format!("roster-construct-consume-v3-{}", q.reservation_digest);
    assert!(legacy_consume(&q, &changed, &e, &c).is_err());
    assert!(q.validate_for(&changed, &e, &c).is_err());
    consumed.validate_for(&r, &e, &c).unwrap();
}
