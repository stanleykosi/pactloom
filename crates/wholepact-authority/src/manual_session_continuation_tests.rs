//! Pure synthetic replay. No native approval, live namespace, keys or sockets.
use super::*;
use crate::manual_enrollment::tests::{extension_event, fixture};
use crate::policy::{Event, Ledger};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
pub(crate) fn continued_fixture() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualEnrollmentExtension,
    Vec<Event>,
    Ledger,
) {
    let (mut birth, mut e) = fixture();
    birth.request.policy.policy_expires_at_ms = 1_000_000;
    let mut original = birth.request.policy.clone();
    original.account_use_genesis = None;
    birth.request.original_terms_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &original,
    )
    .unwrap();
    birth.request.disclosure.policy_digest = birth.request.policy.policy_digest().unwrap();
    birth.request_digest = birth.request.digest().unwrap();
    e.terms.birth_request_digest = birth.request_digest.clone();
    e.terms.birth_commit_digest = original_birth_commit_digest(&birth).unwrap();
    e.terms.original_policy_digest = birth.request.policy.policy_digest().unwrap();
    e.terms.scope.expires_at_ms = 900_000;
    e.validate_original_birth(&birth).unwrap();
    let mut l = Ledger::new(birth.request.policy.clone()).unwrap();
    let mut events = vec![extension_event(&l, &e)];
    l.apply(&events[0]).unwrap();
    bootstrap(
        &birth,
        &e,
        &mut l,
        &mut events,
        5000,
        crate::session::session_id(&[0x33; 32]),
    );
    let continuation = next(&e, &l, 128_000, 'b');
    let event = continuation_event(&e, &l, continuation, 128_000);
    l.apply(&event).unwrap();
    events.push(event);
    bootstrap(
        &birth,
        &e,
        &mut l,
        &mut events,
        129_000,
        crate::session::session_id(&[0x44; 32]),
    );
    (birth, e, events, l)
}
fn bootstrap(
    birth: &crate::pending_birth::PendingBirthCommitRecord,
    e: &ManualEnrollmentExtension,
    l: &mut Ledger,
    events: &mut Vec<Event>,
    now: u64,
    session: String,
) {
    let attempt = l.latest_manual_attempt().unwrap();
    let acquire = Event {
        mutation: AuthorityMutation::AcquireWriter(AcquireWriterRequest {
            operation_id: attempt.acquire_operation_id(e).unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            reconciled_history_digest: crate::session::history_digest(&l.snapshot).unwrap(),
            session_id: session.clone(),
            disclosure: birth.request.disclosure.clone(),
        }),
        authenticated_certificate_digest: l.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&acquire).unwrap();
    events.push(acquire);
    let activate = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: format!("activate-{}", attempt.sequence),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ActivateWriter {
                session_id: session.clone(),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: now + 1000,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&activate).unwrap();
    events.push(activate);
    let mutation = if let Some(c) = &attempt.continuation {
        AuthorityMutation::AdmitBornManualEnrollmentV2(BornManualEnrollmentAdmissionRequestV2 {
            version: 2,
            operation_id: c.admission_operation_id(e).unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            extension_digest: e.digest().unwrap(),
            enrollment_ref: e.enrollment_ref.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            session_id: session.clone(),
            attempt_digest: attempt.attempt_digest,
            attempt_sequence: attempt.sequence,
        })
    } else {
        AuthorityMutation::AdmitBornManualEnrollment(BornManualEnrollmentAdmissionRequest {
            version: 1,
            operation_id: e.admission_operation_id().unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            extension_digest: e.digest().unwrap(),
            enrollment_ref: e.enrollment_ref.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            session_id: session.clone(),
        })
    };
    let admission = Event {
        mutation,
        authenticated_certificate_digest: l.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: now + 2000,
        writer_session_id: Some(session),
        original_request_link: None,
    };
    l.apply(&admission).unwrap();
    events.push(admission);
}
fn next(
    e: &ManualEnrollmentExtension,
    l: &Ledger,
    now: u64,
    nonce: char,
) -> ManualEnrollmentSessionContinuation {
    let previous = l.latest_manual_attempt().unwrap();
    ManualEnrollmentSessionContinuation {
        version: 1,
        extension_digest: e.digest().unwrap(),
        sequence: previous.sequence + 1,
        previous_attempt_digest: previous.attempt_digest.clone(),
        expected_snapshot: l.snapshot.clone(),
        expected_previous_admission_digest: previous.last_admission_digest(e).unwrap(),
        attempt_nonce: h(nonce),
        fresh_process_binding_digest: h('d'),
        fresh_signer_review_digest: h('e'),
        issued_at_ms: now,
        initial_commit_deadline_ms: now + 30_000,
    }
}
fn continuation_event(
    e: &ManualEnrollmentExtension,
    l: &Ledger,
    c: ManualEnrollmentSessionContinuation,
    now: u64,
) -> Event {
    Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: c.owner_operation_id(e).unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ContinueManualEnrollmentSession {
                record: Box::new(ManualEnrollmentSessionContinuationRecord {
                    continuation: c,
                    owner_signature_evidence_digest: h('d'),
                    native_review_digest: h('e'),
                }),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: None,
        original_request_link: None,
    }
}
#[test]
fn successor_preserves_all_originals_and_replays_exact_accounting() {
    let (birth, e, events, l) = continued_fixture();
    assert_eq!(l.snapshot.head.sequence, 8);
    assert_eq!(l.sessions.len(), 2);
    assert_eq!(l.activated_sessions.len(), 2);
    assert_eq!(l.snapshot.writer_epoch, 1);
    assert_eq!(l.snapshot.aggregate_budget_zatoshis, 100);
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 0);
    assert!(l.policy == birth.request.policy);
    let latest = l.latest_manual_attempt().unwrap();
    assert_eq!(latest.sequence, 2);
    assert!(matches!(
        latest.admission,
        Some(ManualEnrollmentAdmissionEvidence::Continued { .. })
    ));
    let mut replay = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events {
        replay.apply(event).unwrap();
    }
    replay.validate_manual_birth(Some(&birth)).unwrap();
    assert!(replay.snapshot == l.snapshot);
    assert!(replay.manual_extension().unwrap().unwrap().extension == e);
}
#[test]
fn exact_prior_deadline_must_drain_and_full_snapshot_cannot_be_replaced() {
    let (birth, e, events, _) = continued_fixture();
    let mut l = Ledger::new(birth.request.policy).unwrap();
    for event in &events[..4] {
        l.apply(event).unwrap();
    }
    let c = next(&e, &l, 126_999, 'f');
    let event = continuation_event(&e, &l, c, 126_999);
    assert!(matches!(l.apply(&event), Err(AuthorityError::Expired)));
    let c = next(&e, &l, 127_000, 'f');
    let mut event = continuation_event(&e, &l, c, 127_000);
    let original = l.snapshot.clone();
    if let AuthorityMutation::OwnerControl(r) = &mut event.mutation {
        if let OwnerControl::ContinueManualEnrollmentSession { record } = &mut r.control {
            record
                .continuation
                .expected_snapshot
                .outstanding_debit_zatoshis = 1;
            r.operation_id = record.continuation.owner_operation_id(&e).unwrap();
        }
    }
    assert!(l.apply(&event).is_err());
    assert!(l.snapshot == original);
    let c = next(&e, &l, 127_000, 'f');
    l.apply(&continuation_event(&e, &l, c, 127_000)).unwrap();
    assert!(l.snapshot.pending_writer_session.is_none());
    assert!(l.snapshot.active_writer_session.is_none());
    assert_eq!(l.sessions.len(), 1);
}
#[test]
fn first_signature_review_and_time_remain_immutable_on_exact_retry() {
    let (birth, e, events, _) = continued_fixture();
    let mut l = Ledger::new(birth.request.policy).unwrap();
    for event in &events[..5] {
        l.apply(event).unwrap();
    }
    let before = l.snapshot.clone();
    let mut retry = events[4].clone();
    retry.witness_time_ms = 200_000;
    assert!(matches!(l.apply(&retry), Ok(MutationResult::Controlled(_))));
    assert!(l.snapshot == before);
    if let AuthorityMutation::OwnerControl(r) = &mut retry.mutation {
        if let OwnerControl::ContinueManualEnrollmentSession { record } = &mut r.control {
            record.native_review_digest = h('f');
        }
    }
    assert!(matches!(l.apply(&retry), Err(AuthorityError::Conflict)));
    assert_eq!(
        l.latest_manual_attempt().unwrap().attempt_digest,
        l.latest_manual_attempt()
            .unwrap()
            .continuation
            .unwrap()
            .digest_for(&e)
            .unwrap()
    );
}
#[test]
fn old_attempt_live_retries_never_regain_authority_after_successor() {
    let (_, e, events, l) = continued_fixture();
    for event in &events[1..4] {
        assert!(
            l.require_manual_bootstrap_scope(&e.digest().unwrap(), &event.mutation, 132_000)
                .is_err()
        );
    }
    let mut replay = events[7].clone();
    let AuthorityMutation::AdmitBornManualEnrollmentV2(ref mut r) = replay.mutation else {
        panic!("v2")
    };
    r.attempt_sequence = 1;
    assert!(
        l.require_manual_bootstrap_scope(&e.digest().unwrap(), &replay.mutation, 132_000)
            .is_err()
    );
    assert!(
        l.require_manual_bootstrap_scope(&e.digest().unwrap(), &events[7].mutation, 251_000)
            .is_err()
    );
}
#[test]
fn no_skip_duplicate_nonce_or_expired_uncommitted_proposal() {
    let (birth, e, events, l) = continued_fixture();
    let mut replay = Ledger::new(birth.request.policy).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    for change in [0, 1, 2, 3] {
        let mut c = next(&e, &l, 252_000, 'f');
        match change {
            0 => c.sequence += 1,
            1 => c.previous_attempt_digest = h('0'),
            2 => c.attempt_nonce = h('b'),
            _ => c.initial_commit_deadline_ms = c.issued_at_ms + 1,
        };
        let now = if change == 3 { 252_001 } else { 252_000 };
        let event = continuation_event(&e, &replay, c, now);
        assert!(replay.apply(&event).is_err());
    }
    assert!(replay.snapshot == l.snapshot);
}
#[test]
fn unsupported_or_excluded_history_cannot_be_projected_to_fresh_continuation() {
    let (_, e, _, mut l) = continued_fixture();
    let c = next(&e, &l, 252_000, 'f');
    let event = continuation_event(&e, &l, c, 252_000);
    l.snapshot.writer_epoch = 2;
    assert!(l.apply(&event).is_err());
    l.snapshot.writer_epoch = 1;
    l.snapshot.writer_status = WriterStatus::Quarantined;
    assert!(l.apply(&event).is_err());
    l.snapshot.writer_status = WriterStatus::Active;
    l.policy.account_use_genesis = None;
    assert!(l.apply(&event).is_err());
}
#[test]
fn admission_v2_is_strict_distinct_and_deadline_never_renews() {
    let (_, e, _, l) = continued_fixture();
    let attempt = l.latest_manual_attempt().unwrap();
    let c = attempt.continuation.as_ref().unwrap();
    let Some(ManualEnrollmentAdmissionEvidence::Continued { record }) = &attempt.admission else {
        panic!("v2")
    };
    record.validate_for(&e, c).unwrap();
    assert_eq!(record.publication_expires_at_ms, 251_000);
    let mut changed = record.clone();
    changed.publication_expires_at_ms += 1;
    assert!(changed.validate_for(&e, c).is_err());
    let mut value = serde_json::to_value(record).unwrap();
    value["approved"] = true.into();
    assert!(serde_json::from_value::<BornManualEnrollmentAdmissionRecordV2>(value).is_err());
    assert!(
        serde_json::from_value::<BornManualEnrollmentAdmissionRecord>(
            serde_json::to_value(record).unwrap()
        )
        .is_err()
    );
}
