//! Pure synthetic replay fixtures. No live approvals, namespaces, keys, sockets,
//! funds, native ceremonies, proofs or financial admission are exercised.
use super::*;
use crate::policy::{Event, Ledger};
use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn fixture() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Ledger,
    Vec<Event>,
) {
    let (birth, inner, _, _) = crate::manual_session_continuation::tests::continued_fixture();
    let e = ManualRosterEnrollmentExtensionV2 {
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
    e.validate_original_birth(&birth).unwrap();
    let mut l = Ledger::new(birth.request.policy.clone()).unwrap();
    let event = extension_event(&l, &e);
    l.apply(&event).unwrap();
    (birth, e, l, vec![event])
}
pub(crate) fn extension_event(l: &Ledger, e: &ManualRosterEnrollmentExtensionV2) -> Event {
    Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: e.owner_operation_id().unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ExtendManualRosterEnrollmentV2 {
                record: Box::new(ManualRosterEnrollmentExtensionRecordV2 {
                    extension: e.clone(),
                    account_record: ManualEnrollmentExtensionRecord {
                        extension: e.account_extension.clone(),
                        owner_signature_evidence_digest: h('a'),
                        native_review_digest: h('b'),
                    },
                }),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: 4_000,
        writer_session_id: None,
        original_request_link: None,
    }
}
pub(crate) fn bootstrap(
    birth: &crate::pending_birth::PendingBirthCommitRecord,
    e: &ManualRosterEnrollmentExtensionV2,
    l: &mut Ledger,
    events: &mut Vec<Event>,
    now: u64,
    session: String,
) {
    let a = l.latest_manual_roster_attempt_v2().unwrap();
    let acquire = Event {
        mutation: AuthorityMutation::AcquireWriter(AcquireWriterRequest {
            operation_id: a.acquire_operation_id(e).unwrap(),
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
            operation_id: format!("roster-activate-{}", a.sequence),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ActivateWriter {
                session_id: session.clone(),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: now + 1_000,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&activate).unwrap();
    events.push(activate);
    let admit = Event {
        mutation: AuthorityMutation::AdmitBornManualRosterEnrollmentV2(
            BornManualRosterAdmissionRequestV2 {
                version: 2,
                operation_id: a.admission_operation_id(e).unwrap(),
                account_id: l.policy.account_id.clone(),
                network_profile_id: l.policy.network_profile_id.clone(),
                extension_digest: e.digest().unwrap(),
                enrollment_ref: e.account_extension.enrollment_ref.clone(),
                writer_epoch: 1,
                expected_head: l.snapshot.head.clone(),
                session_id: session.clone(),
                attempt_digest: a.attempt_digest,
                attempt_sequence: a.sequence,
            },
        ),
        authenticated_certificate_digest: l.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: now + 2_000,
        writer_session_id: Some(session),
        original_request_link: None,
    };
    l.apply(&admit).unwrap();
    events.push(admit);
}
pub(crate) fn continuation(
    l: &Ledger,
    e: &ManualRosterEnrollmentExtensionV2,
    now: u64,
    nonce: char,
) -> ManualRosterSessionContinuationV2 {
    let a = l.latest_manual_roster_attempt_v2().unwrap();
    ManualRosterSessionContinuationV2 {
        version: 2,
        roster_extension_digest: e.digest().unwrap(),
        continuation: ManualEnrollmentSessionContinuation {
            version: 1,
            extension_digest: e.account_extension.digest().unwrap(),
            sequence: a.sequence + 1,
            previous_attempt_digest: a.attempt_digest.clone(),
            expected_snapshot: l.snapshot.clone(),
            expected_previous_admission_digest: a.last_admission_digest(e).unwrap(),
            attempt_nonce: h(nonce),
            fresh_process_binding_digest: h('c'),
            fresh_signer_review_digest: h('d'),
            issued_at_ms: now,
            initial_commit_deadline_ms: now + 30_000,
        },
    }
}
pub(crate) fn continuation_event(
    l: &Ledger,
    e: &ManualRosterEnrollmentExtensionV2,
    c: ManualRosterSessionContinuationV2,
    now: u64,
) -> Event {
    Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: c.owner_operation_id(e).unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ContinueManualRosterSessionV2 {
                record: Box::new(ManualRosterSessionContinuationRecordV2 {
                    continuation: c,
                    owner_signature_evidence_digest: h('e'),
                    native_review_digest: h('f'),
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
fn roster_and_account_predecessors_stay_distinct_and_original_policy_is_unchanged() {
    let (birth, e, mut l, mut events) = fixture();
    let original = e.account_extension.clone();
    let policy = l.policy.clone();
    let checkpoint = l.snapshot.account_use_checkpoint.clone();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    assert!(l.policy == policy);
    assert!(l.manual_extension().unwrap().unwrap().extension == original);
    assert!(l.snapshot.account_use_checkpoint == checkpoint);
    assert_eq!(original.sequence, 1);
    assert!(original.predecessor_digest.is_none());
    assert!(original.terms.host.scope_predecessor_digest.is_none());
    assert_eq!(l.snapshot.aggregate_budget_zatoshis, 100);
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 0);
    assert_eq!(l.snapshot.settled_debit_zatoshis, 0);
    assert!(l.latest_manual_attempt().is_err());
    let a = l.latest_manual_roster_attempt_v2().unwrap();
    assert_eq!(a.sequence, 1);
    let mut replay = Ledger::new(birth.request.policy).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    assert!(replay.snapshot == l.snapshot);
    assert!(replay.latest_manual_roster_attempt_v2().unwrap() == a);
}
#[test]
fn exact_retry_never_extends_deadline_and_legacy_or_altered_wrapper_is_denied() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let original = l
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .admission
        .unwrap();
    let mut retry = events.last().unwrap().clone();
    retry.witness_time_ms += 1_000;
    l.require_manual_roster_bootstrap_scope_v2(
        &e.digest().unwrap(),
        &retry.mutation,
        retry.witness_time_ms,
    )
    .unwrap();
    let MutationResult::ManualRosterEnrollmentAdmittedV2(retried) = l.apply(&retry).unwrap() else {
        panic!("wrong result")
    };
    assert!(*retried == original);
    retry.witness_time_ms = original.publication_expires_at_ms;
    assert!(matches!(
        l.require_manual_roster_bootstrap_scope_v2(
            &e.digest().unwrap(),
            &retry.mutation,
            retry.witness_time_ms
        ),
        Err(AuthorityError::Expired)
    ));
    assert!(
        l.require_manual_bootstrap_scope(
            &e.account_extension.digest().unwrap(),
            &events.last().unwrap().mutation,
            8_000
        )
        .is_err()
    );
    let mut other = e.clone();
    other.roster.predecessor = HostRosterPredecessorV2::InitialPublicationV2 {
        audit_digest: h('8'),
    };
    assert!(original.validate_for(&other, None).is_err());
    other = e.clone();
    other.signer_roster_record_digest = h('9');
    assert!(original.validate_for(&other, None).is_err());
    let mut legacy = crate::manual_enrollment::tests::extension_event(&l, &e.account_extension);
    legacy.witness_time_ms = 8_000;
    assert!(l.apply(&legacy).is_err());
}
#[test]
fn successor_binds_full_roster_prior_admission_and_keeps_all_sessions() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let original = l.latest_manual_roster_attempt_v2().unwrap();
    let c = continuation(&l, &e, 128_000, '6');
    let ev = continuation_event(&l, &e, c.clone(), 128_000);
    l.apply(&ev).unwrap();
    events.push(ev);
    bootstrap(&birth, &e, &mut l, &mut events, 129_000, h('7'));
    assert_eq!(l.sessions.len(), 2);
    assert_eq!(l.activated_sessions.len(), 2);
    assert_eq!(l.snapshot.writer_epoch, 1);
    let a = l.latest_manual_roster_attempt_v2().unwrap();
    assert_eq!(a.sequence, 2);
    assert!(a.continuation == Some(c));
    assert!(a.last_admission_digest(&e).unwrap() != original.last_admission_digest(&e).unwrap());
    assert_eq!(
        original.admission.unwrap().publication_expires_at_ms,
        127_000
    );
    let mut replay = Ledger::new(birth.request.policy).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    assert!(replay.snapshot == l.snapshot);
}
#[test]
fn stale_head_wrong_ancestry_early_continuation_and_reused_nonce_fail_closed() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let early = continuation_event(&l, &e, continuation(&l, &e, 8_000, '6'), 8_000);
    assert!(l.apply(&early).is_err());
    for edit in 0..4 {
        let mut c = continuation(&l, &e, 128_000, '6');
        match edit {
            0 => c.continuation.previous_attempt_digest = h('7'),
            1 => c.continuation.expected_snapshot.head.digest = h('8'),
            2 => c.continuation.expected_previous_admission_digest = Some(h('9')),
            _ => c.roster_extension_digest = h('a'),
        }
        // Wrong wrapper fails before an operation ID can even be derived.
        if c.validate_for(&e).is_err() {
            continue;
        }
        assert!(l.apply(&continuation_event(&l, &e, c, 128_000)).is_err());
    }
    let first = continuation_event(&l, &e, continuation(&l, &e, 128_000, '6'), 128_000);
    l.apply(&first).unwrap();
    let reused = continuation_event(&l, &e, continuation(&l, &e, 129_000, '6'), 129_000);
    assert!(l.apply(&reused).is_err());
}
#[test]
fn roster_extension_cannot_reset_used_or_unknown_or_excluded_history() {
    let (birth, e, l, _) = fixture();
    let (_, _, _, used) = crate::manual_session_continuation::tests::continued_fixture();
    let event = extension_event(&used, &e);
    let mut used = used;
    assert!(used.apply(&event).is_err());
    let mut missing = birth.request.policy.clone();
    missing.account_use_genesis = None;
    let unknown = Ledger::new(missing).unwrap();
    let mut unknown = unknown;
    assert!(unknown.apply(&extension_event(&unknown, &e)).is_err());
    let mut excluded = l;
    let g = excluded
        .policy
        .account_use_genesis
        .as_ref()
        .unwrap()
        .clone();
    excluded
        .account_use_history
        .exclude(crate::account_use::PermanentAccountExclusion {
            version: 1,
            identity: g.identity.clone(),
            genesis_digest: g.digest().unwrap(),
            operation_id: "synthetic-exclusion".into(),
            native_review_digest: h('a'),
            reason: crate::account_use::ExclusionReason::RetirementRequested,
        })
        .unwrap();
    assert!(excluded.require_supported_manual_history().is_err());
}
#[test]
fn inert_v2_records_reject_approval_flags_and_cross_version_reinterpretation() {
    let (_, e, _, _) = fixture();
    let mut json = serde_json::to_value(&e).unwrap();
    json["approved"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ManualRosterEnrollmentExtensionV2>(json).is_err());
    assert!(
        serde_json::from_value::<ManualEnrollmentExtension>(serde_json::to_value(e).unwrap())
            .is_err()
    );
}

pub(crate) fn history(
    birth: &crate::pending_birth::PendingBirthCommitRecord,
    ledger: &Ledger,
    events: &[Event],
) -> ReconciledAuthorityHistory {
    ReconciledAuthorityHistory {
        completed_dispatches_v1: Vec::new(),
        durable_payment_history_supported_v1: false,
        construction_transport_history: ledger.construction_transport_history_v1(),
        manual_roster_construction_records_v3: ledger.roster_construction_history_v3(),
        manual_roster_construction_records: ledger.roster_construction_history_v2(),
        manual_roster_attempt: Some(ledger.latest_manual_roster_attempt_v2().unwrap()),
        manual_attempt: None,
        pending_birth_commit: Some(birth.clone()),
        account_use_history: ledger.account_use_history.clone(),
        account_policy: ledger.policy.clone(),
        snapshot: ledger.snapshot.clone(),
        permits: Vec::new(),
        offline_permits: Vec::new(),
        born_offline_permits: vec![],
        born_offline_dispatches: vec![],
        automatic_key_use_admissions: Vec::new(),
        recovery_fences: Vec::new(),
        committed_operation_ids: ledger.operations.keys().cloned().collect(),
        owner_controls: events
            .iter()
            .filter_map(|e| match &e.mutation {
                AuthorityMutation::OwnerControl(r) => Some((r.operation_id.clone(), r.clone())),
                _ => None,
            })
            .collect(),
        history_heads: [(
            ledger.snapshot.head.sequence,
            ledger.snapshot.head.digest.clone(),
        )]
        .into_iter()
        .collect(),
        disclosure: birth.request.disclosure.clone(),
    }
}

#[test]
fn public_legacy_history_accessors_cannot_erase_roster_binding() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let mut h = history(&birth, &l, &events);
    let enrollment = &e.account_extension.enrollment_ref;
    assert!(h.manual_enrollment_extension(enrollment).is_err());
    assert!(h.latest_manual_attempt(enrollment).is_err());
    assert!(h.manual_session_continuation(&e.digest().unwrap()).is_err());
    assert!(h.manual_roster_enrollment_extension(enrollment).unwrap() == Some(&e));
    assert_eq!(
        h.latest_manual_roster_attempt_v2(enrollment)
            .unwrap()
            .sequence,
        1
    );
    // Historical extension remains evidence, while current quarantine is never
    // masked by a stale original-attempt snapshot.
    h.snapshot.writer_status = WriterStatus::Quarantined;
    assert!(
        h.latest_manual_roster_attempt_v2(enrollment)
            .unwrap()
            .snapshot
            .writer_status
            == WriterStatus::Quarantined
    );
    h.pending_birth_commit = None;
    assert!(h.manual_roster_enrollment_extension(enrollment).is_err());
}

#[test]
fn first_roster_attempt_can_continue_without_fabricating_prior_admission() {
    let (birth, e, mut l, mut events) = fixture();
    let c = continuation(&l, &e, 5_000, '6');
    assert!(c.continuation.expected_previous_admission_digest.is_none());
    let event = continuation_event(&l, &e, c.clone(), 5_000);
    l.apply(&event).unwrap();
    events.push(event);
    bootstrap(&birth, &e, &mut l, &mut events, 6_000, h('7'));
    let current = l.latest_manual_roster_attempt_v2().unwrap();
    assert_eq!(current.sequence, 2);
    assert!(current.continuation == Some(c.clone()));
    assert!(
        current
            .admission
            .as_ref()
            .unwrap()
            .validate_for(&e, Some(&c))
            .is_ok()
    );
    assert!(
        current
            .admission
            .as_ref()
            .unwrap()
            .validate_for(&e, None)
            .is_err()
    );
    assert!(
        !l.operations
            .contains_key(&e.admission_operation_id().unwrap())
    );
    let h = history(&birth, &l, &events);
    assert!(
        h.manual_roster_session_continuation_v2(&c.digest_for(&e).unwrap())
            .unwrap()
            == Some(&c)
    );
    let mut replay = Ledger::new(birth.request.policy).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    assert!(replay.snapshot == l.snapshot);
}

#[test]
fn roster_admission_rejects_wrong_peer_session_head_and_cross_version_attempt() {
    let (birth, e, mut complete, mut events) = fixture();
    bootstrap(&birth, &e, &mut complete, &mut events, 5_000, h('5'));
    let good = events.last().unwrap().clone();
    for variant in 0..11 {
        let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
        for event in &events[..events.len() - 1] {
            ledger.apply(event).unwrap();
        }
        let mut bad = good.clone();
        match variant {
            0 => {
                bad.authenticated_certificate_digest =
                    birth.request.policy.owner_certificate_digest.clone()
            }
            1 => bad.writer_session_id = None,
            2 => bad.writer_session_id = Some(h('6')),
            _ => {
                let AuthorityMutation::AdmitBornManualRosterEnrollmentV2(r) = &mut bad.mutation
                else {
                    panic!("fixture is not roster admission")
                };
                match variant {
                    3 => r.extension_digest = e.account_extension.digest().unwrap(),
                    4 => {
                        r.attempt_digest =
                            crate::manual_session_continuation::initial_manual_attempt_digest(
                                &e.account_extension,
                            )
                            .unwrap()
                    }
                    5 => r.attempt_sequence = 2,
                    6 => r.session_id = h('7'),
                    7 => r.expected_head.digest = h('8'),
                    8 => r.writer_epoch += 1,
                    9 => r.operation_id = e.account_extension.admission_operation_id().unwrap(),
                    _ => r.version = 1,
                }
            }
        }
        let before = ledger.snapshot.clone();
        assert!(
            ledger.apply(&bad).is_err(),
            "mutated admission variant {variant}"
        );
        assert!(ledger.snapshot == before);
        assert!(
            ledger
                .latest_manual_roster_attempt_v2()
                .unwrap()
                .admission
                .is_none()
        );
    }
    let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events[..events.len() - 1] {
        ledger.apply(event).unwrap();
    }
    let mut legacy = good;
    legacy.mutation =
        AuthorityMutation::AdmitBornManualEnrollment(BornManualEnrollmentAdmissionRequest {
            version: 1,
            operation_id: e.account_extension.admission_operation_id().unwrap(),
            account_id: e.account_extension.terms.identity.account_id.clone(),
            network_profile_id: e
                .account_extension
                .terms
                .identity
                .network_profile_id
                .clone(),
            extension_digest: e.account_extension.digest().unwrap(),
            enrollment_ref: e.account_extension.enrollment_ref.clone(),
            writer_epoch: e.account_extension.terms.signer.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            session_id: h('5'),
        });
    assert!(ledger.apply(&legacy).is_err());
}

#[test]
fn roster_initial_and_continued_evidence_cannot_be_reinterpreted_or_renewed() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let original = l
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .admission
        .unwrap();
    for variant in 0..8 {
        let mut bad = original.clone();
        match variant {
            0 => bad.admitted_at_ms += 1,
            1 => bad.publication_expires_at_ms += 1,
            2 => bad.snapshot.active_writer_session = None,
            3 => bad.snapshot.writer_certificate_digest = h('6'),
            4 => bad.snapshot.head.sequence += 1,
            5 => bad.snapshot.policy_digest = h('7'),
            6 => bad.snapshot.last_witness_time_ms += 1,
            _ => bad.session.session_id = h('8'),
        }
        assert!(
            bad.validate_for(&e, None).is_err(),
            "changed record {variant}"
        );
    }
    let encoded = serde_json::to_value(&original).unwrap();
    let roundtrip: BornManualRosterAdmissionRecordV2 =
        serde_json::from_value(encoded.clone()).unwrap();
    assert!(roundtrip == original);
    // Identical structural fields are inert; validation still binds the distinct
    // full V2 roster digest and initial-attempt domain, never the inner V1.
    let as_legacy: crate::manual_session_continuation::BornManualEnrollmentAdmissionRecordV2 =
        serde_json::from_value(encoded).unwrap();
    let c = continuation(&l, &e, 128_000, '6');
    assert!(
        as_legacy
            .validate_for(&e.account_extension, &c.continuation)
            .is_err()
    );
    assert!(original.validate_for(&e, Some(&c)).is_err());
}

#[test]
fn roster_wrappers_cannot_rewrite_original_first_account_extension_or_policy() {
    let (birth, e, _, _) = fixture();
    for variant in 0..7 {
        let mut bad = e.clone();
        match variant {
            0 => bad.account_extension.sequence = 2,
            1 => bad.account_extension.predecessor_digest = Some(h('6')),
            2 => bad.account_extension.terms.host.scope_predecessor_digest = Some(h('7')),
            3 => {
                bad.account_extension.terms.scope.aggregate_budget_zatoshis =
                    birth.request.policy.aggregate_budget_zatoshis + 1
            }
            4 => bad.account_extension.terms.original_policy_digest = h('8'),
            5 => bad.roster.generation_id = h('9'),
            _ => bad.roster.store_destination_identity.push_str("-other"),
        }
        assert!(
            bad.validate_original_birth(&birth).is_err(),
            "rewritten original {variant}"
        );
    }
}

#[cfg(feature = "pending-birth-foundation")]
#[test]
fn roster_signing_domains_bind_exact_wrapper_and_never_grant_native_approval() {
    use crate::manual_roster_continuation_signature_v2::*;
    use crate::manual_roster_signature_v2::manual_roster_enrollment_owner_signing_bytes_v2;
    let (_, e, l, _) = fixture();
    let c = continuation(&l, &e, 5_000, '6');
    let initial = manual_roster_enrollment_owner_signing_bytes_v2(&e).unwrap();
    let successor = manual_roster_continuation_owner_signing_bytes_v2(&e, &c).unwrap();
    assert_ne!(initial, successor);
    let mut changed = e.clone();
    changed.roster.predecessor = HostRosterPredecessorV2::EnrollmentV1 {
        audit_digest: h('d'),
    };
    assert_ne!(
        initial,
        manual_roster_enrollment_owner_signing_bytes_v2(&changed).unwrap()
    );
    assert!(manual_roster_continuation_owner_signing_bytes_v2(&changed, &c).is_err());
    let mut changed_continuation = c.clone();
    changed_continuation
        .continuation
        .fresh_process_binding_digest = h('9');
    assert_ne!(
        successor,
        manual_roster_continuation_owner_signing_bytes_v2(&e, &changed_continuation).unwrap()
    );
    // Malformed data cannot skip signature verification or manufacture a native
    // decision. These fixtures contain no key material or real certificates.
    let fake = ManualRosterContinuationOwnerSignatureV2 {
        version: 2,
        extension: e,
        continuation: c,
        scheme: "approved-native-focus".into(),
        owner_certificate_der: vec![0],
        signature: vec![0],
    };
    assert!(verify_manual_roster_continuation_owner_signature_v2(&fake, &h('a')).is_err());
    let mut json = serde_json::to_value(&fake).unwrap();
    json["native_approval"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ManualRosterContinuationOwnerSignatureV2>(json).is_err());
}

#[test]
fn successor_fences_old_bootstrap_and_cannot_enter_legacy_continuation_route() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let c = continuation(&l, &e, 128_000, '6');
    let old_acquire = events[1].mutation.clone();
    let old_admission = events[3].mutation.clone();
    let legacy = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: c
                .continuation
                .owner_operation_id(&e.account_extension)
                .unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ContinueManualEnrollmentSession {
                record: Box::new(
                    crate::manual_session_continuation::ManualEnrollmentSessionContinuationRecord {
                        continuation: c.continuation.clone(),
                        owner_signature_evidence_digest: h('c'),
                        native_review_digest: h('d'),
                    },
                ),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: 128_000,
        writer_session_id: None,
        original_request_link: None,
    };
    assert!(l.apply(&legacy).is_err());
    l.apply(&continuation_event(&l, &e, c, 128_000)).unwrap();
    assert!(l.snapshot.active_writer_session.is_none());
    assert!(l.snapshot.pending_writer_session.is_none());
    assert_eq!(l.sessions.len(), 1);
    for mutation in [&old_acquire, &old_admission] {
        assert!(
            l.require_manual_roster_bootstrap_scope_v2(&e.digest().unwrap(), mutation, 129_000)
                .is_err()
        );
    }
    let pause = AuthorityMutation::OwnerControl(OwnerControlRequest {
        operation_id: "not-an-enrollment-operation".into(),
        account_id: l.policy.account_id.clone(),
        network_profile_id: l.policy.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: l.snapshot.head.clone(),
        control: OwnerControl::Pause,
    });
    assert!(
        l.require_manual_roster_bootstrap_scope_v2(&e.digest().unwrap(), &pause, 129_000)
            .is_err()
    );
}

#[test]
fn permanent_exclusion_preserves_historical_roster_audit_but_denies_live_scope() {
    let (birth, e, mut l, mut events) = fixture();
    bootstrap(&birth, &e, &mut l, &mut events, 5_000, h('5'));
    let original = l
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .admission
        .unwrap();
    let original_event = events.last().unwrap().clone();
    let genesis = l.policy.account_use_genesis.as_ref().unwrap();
    let exclusion = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: "synthetic-roster-retirement".into(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::PermanentlyExcludeAccount {
                exclusion: crate::account_use::PermanentAccountExclusion {
                    version: 1,
                    identity: genesis.identity.clone(),
                    genesis_digest: genesis.digest().unwrap(),
                    operation_id: "synthetic-roster-retirement".into(),
                    native_review_digest: h('a'),
                    reason: crate::account_use::ExclusionReason::RetirementRequested,
                },
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: 8_000,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&exclusion).unwrap();
    events.push(exclusion);
    assert!(
        l.require_manual_roster_bootstrap_scope_v2(
            &e.digest().unwrap(),
            &original_event.mutation,
            9_000
        )
        .is_err()
    );
    let before = l.snapshot.clone();
    let MutationResult::ManualRosterEnrollmentAdmittedV2(retained) =
        l.apply(&original_event).unwrap()
    else {
        panic!("wrong historical result")
    };
    assert!(*retained == original);
    assert!(l.snapshot == before);
    assert_eq!(l.snapshot.aggregate_budget_zatoshis, 100);
    assert_eq!(l.sessions.len(), 1);
    let mut replay = Ledger::new(birth.request.policy).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    assert!(replay.snapshot == l.snapshot);
    assert!(replay.require_supported_manual_history().is_err());
}
