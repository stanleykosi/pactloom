//! Pure synthetic atomic-transition tests. No portable capability is enabled.
use super::*;
use crate::offline::*;

fn offline_fixture() -> (
    Ledger,
    ReserveOfflineAuthorization,
    OfflineEnrollmentPolicy,
    AuthenticatedOfflineIntent,
) {
    let mut ledger = active_ledger();
    let (mut r, _, mut p) = crate::offline::tests::fixture();
    p.enrollment_ref = ledger.policy.enrollment_refs[0].clone();
    r.intent.terms.enrollment_ref = p.enrollment_ref.clone();
    r.intent.terms.recipient_scope_digest = ledger.policy.recipient_scope_digests[0].clone();
    r.intent.terms.offline_policy_digest = p.policy_digest().unwrap();
    let owner = OwnerControlRequest {
        operation_id: "offline-enroll".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
        writer_epoch: 1,
        control: OwnerControl::EnrollOfflinePolicy {
            policy: p.clone(),
            expected_previous_digest: None,
        },
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::OwnerControl(owner),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 1000,
            writer_session_id: None,
        })
        .unwrap();
    r.expected_head = ledger.snapshot.head.clone();
    let issuer = OfflineIntentAuthenticationIssuer::for_test(p.clone()).unwrap();
    let auth = issuer
        .bind_verified_intent(
            &r,
            &r.intent,
            &p.offline_signer_key_digest,
            &p.witness_transport_key_digest,
            &h('9'),
        )
        .unwrap();
    (ledger, r, p, auth)
}
fn event(r: ReserveOfflineAuthorization, auth: &AuthenticatedOfflineIntent) -> Event {
    Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveOfflineAuthorization(Box::new(
            OfflineReservationRecord {
                request: r,
                authentication: auth.evidence().clone(),
            },
        )),
        authenticated_certificate_digest: h('b'),
        witness_time_ms: 3000,
        writer_session_id: Some(crate::session::session_id(&[42; 32])),
    }
}
#[test]
fn offline_and_manual_share_lifetime_input_and_obligation_gates() {
    let (mut ledger, r, _, auth) = offline_fixture();
    let original = event(r.clone(), &auth);
    let reserved = ledger.apply(&original).unwrap();
    assert!(ledger.apply(&original).unwrap() == reserved);
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 70);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 100);
    let manual = request(&ledger.snapshot.head, 2, 40);
    assert!(matches!(
        ledger.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(manual)),
            ..original.clone()
        }),
        Err(AuthorityError::BudgetExceeded)
    ));
    let mut manual = request(&ledger.snapshot.head, 2, 20);
    manual.obligation_id = r.intent.terms.obligation_id.clone();
    assert!(matches!(
        ledger.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(manual)),
            ..original.clone()
        }),
        Err(AuthorityError::ObligationReserved)
    ));
    let mut manual = request(&ledger.snapshot.head, 2, 20);
    manual.inputs[0].nullifier = r.intent.terms.inputs[0].nullifier.clone();
    assert!(matches!(
        ledger.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(manual)),
            ..original
        }),
        Err(AuthorityError::InputReserved)
    ));
}
#[test]
fn authenticating_controller_does_not_authenticate_offline_signer_intent() {
    let (mut ledger, r, policy, auth) = offline_fixture();
    let issuer = OfflineIntentAuthenticationIssuer::for_test(policy.clone()).unwrap();
    assert!(
        issuer
            .bind_verified_intent(
                &r,
                &r.intent,
                &h('a'),
                &policy.witness_transport_key_digest,
                &h('9')
            )
            .is_err()
    );
    assert!(
        issuer
            .bind_verified_intent(
                &r,
                &r.intent,
                &policy.offline_signer_key_digest,
                &h('a'),
                &h('9')
            )
            .is_err()
    );
    let mut substituted = event(r.clone(), &auth);
    if let AuthorityMutation::ReserveOfflineAuthorization(body) = &mut substituted.mutation {
        body.request.intent.native_reservation_review_digest = h('a');
    }
    assert!(matches!(
        ledger.apply(&substituted),
        Err(AuthorityError::Authentication)
    ));
    let dir = private_dir();
    let journal = create(dir.path());
    let before = snapshot(&journal);
    assert!(matches!(
        journal.mutate_on_channel(
            &h('b'),
            event(r, &auth).mutation,
            None,
            &[0; 32],
            &h('0'),
            3000
        ),
        Err(AuthorityError::Permission)
    ));
    assert!(snapshot(&journal) == before);
}
#[test]
fn offline_pause_prevents_new_admission_but_does_not_recall_existing_effects() {
    let (mut ledger, r, p, auth) = offline_fixture();
    let original = event(r.clone(), &auth);
    ledger.apply(&original).unwrap();
    let control = OwnerControlRequest {
        operation_id: "pause-offline".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
        writer_epoch: 1,
        control: OwnerControl::SetOfflinePolicyStatus {
            enrollment_ref: p.enrollment_ref.clone(),
            policy_digest: p.policy_digest().unwrap(),
            status: OfflineEnrollmentStatus::Paused,
        },
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::OwnerControl(control),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 3001,
            writer_session_id: None,
        })
        .unwrap();
    assert!(matches!(
        ledger.apply(&original),
        Ok(MutationResult::OfflineReserved(_))
    ));
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 70);
    let mut next = r;
    next.operation_id = "new-offline".into();
    next.expected_head = ledger.snapshot.head.clone();
    let issuer = OfflineIntentAuthenticationIssuer::for_test(p.clone()).unwrap();
    let next_auth = issuer
        .bind_verified_intent(
            &next,
            &next.intent,
            &p.offline_signer_key_digest,
            &p.witness_transport_key_digest,
            &h('9'),
        )
        .unwrap();
    assert!(matches!(
        ledger.apply(&Event {
            original_request_link: None,
            witness_time_ms: 3002,
            ..event(next, &next_auth)
        }),
        Err(AuthorityError::Inactive)
    ));
}
#[test]
fn offline_new_operation_cannot_reuse_native_intent() {
    let (mut ledger, r, policy, auth) = offline_fixture();
    ledger.apply(&event(r.clone(), &auth)).unwrap();
    let mut next = r;
    next.operation_id = "new-offline".into();
    next.expected_head = ledger.snapshot.head.clone();
    assert!(auth.matches(&next, auth.evidence()).is_err());
    let issuer = OfflineIntentAuthenticationIssuer::for_test(policy.clone()).unwrap();
    let next_auth = issuer
        .bind_verified_intent(
            &next,
            &next.intent,
            &policy.offline_signer_key_digest,
            &policy.witness_transport_key_digest,
            &h('9'),
        )
        .unwrap();
    assert!(matches!(
        ledger.apply(&event(next, &next_auth)),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(ledger.snapshot.outstanding_reservations, 1);
}
#[test]
fn legacy_history_accessor_refuses_to_drop_an_offline_origin() {
    let (mut ledger, r, _, auth) = offline_fixture();
    let MutationResult::OfflineReserved(p) = ledger.apply(&event(r, &auth)).unwrap() else {
        panic!("offline result");
    };
    let history = ReconciledAuthorityHistory {
        construction_transport_history:
            crate::construction_transport_handoff_v1::ConstructionTransportHistoryV1 {
                version: 1,
                ..Default::default()
            },
        manual_roster_construction_records_v3: Default::default(),
        manual_roster_construction_records: Default::default(),
        manual_roster_attempt: None,
        manual_attempt: None,
        pending_birth_commit: None,
        account_use_history: ledger.account_use_history.clone(),
        account_policy: ledger.policy.clone(),
        snapshot: ledger.snapshot.clone(),
        permits: vec![],
        offline_permits: vec![*p],
        automatic_key_use_admissions: vec![],
        recovery_fences: vec![],
        committed_operation_ids: Default::default(),
        owner_controls: Default::default(),
        history_heads: Default::default(),
        disclosure: ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .unwrap()
            .disclosure
            .clone(),
    };
    assert!(matches!(
        history.permits(),
        Err(AuthorityError::OfflineHistoryUnsupported)
    ));
    assert_eq!(history.reservation_evidence().count(), 1);
    let facts = serde_json::to_value(history.retirement_history_facts().unwrap()).unwrap();
    assert_eq!(facts["offline_reservation_descriptors"], 1);
    assert_eq!(facts["online_reservation_descriptors"], 0);
    assert_eq!(
        facts["outstanding_debit_zatoshis"],
        history.snapshot().outstanding_debit_zatoshis
    );
    assert_eq!(
        facts["reserved_input_value_zatoshis"],
        history.snapshot().reserved_input_value_zatoshis
    );
    assert_eq!(facts["account_birth_semantics"], "legacy_unknown");
    assert_eq!(facts["canonical_unspentness"], "unknown");
    assert_eq!(facts["retirement_completion"], "unavailable");

    assert!(matches!(
        history.reservation_evidence().next(),
        Some(ReservationEvidenceRef::OfflineV1(_))
    ));
}

#[test]
fn offline_durable_commit_and_exact_restart_replay_share_the_same_reservation() {
    let (_, mut r, p, _) = offline_fixture();
    let dir = private_dir();
    let journal = create(dir.path());
    control(
        &journal,
        "offline-policy",
        OwnerControl::EnrollOfflinePolicy {
            policy: p.clone(),
            expected_previous_digest: None,
        },
    );
    r.expected_head = snapshot(&journal).head;
    let issuer = OfflineIntentAuthenticationIssuer::for_test(p.clone()).unwrap();
    let bind = || {
        issuer
            .bind_verified_intent(
                &r,
                &r.intent,
                &p.offline_signer_key_digest,
                &p.witness_transport_key_digest,
                &h('9'),
            )
            .unwrap()
    };
    // Abort the immutable event append: no success receipt and no exposure update.
    journal.connection.lock().unwrap().connection().execute_batch("CREATE TEMP TRIGGER fail_offline_append BEFORE INSERT ON authority_events BEGIN SELECT RAISE(ABORT,'synthetic offline append failure'); END;").unwrap();
    assert!(
        journal
            .commit_offline_for_test(&h('b'), r.clone(), bind(), 3000)
            .is_err()
    );
    assert_eq!(snapshot(&journal).outstanding_debit_zatoshis, 0);
    journal
        .connection
        .lock()
        .unwrap()
        .connection()
        .execute_batch("DROP TRIGGER fail_offline_append")
        .unwrap();
    let original = journal
        .commit_offline_for_test(&h('b'), r.clone(), bind(), 3000)
        .unwrap();
    assert_eq!(snapshot(&journal).outstanding_debit_zatoshis, 70);
    let original_descriptor = original.descriptor().clone();
    drop(original);
    drop(journal);
    let reopened = open(dir.path());
    let replay = reopened
        .commit_offline_for_test(&h('b'), r.clone(), bind(), 3001)
        .unwrap();
    assert!(replay.descriptor() == &original_descriptor);
    assert_eq!(snapshot(&reopened).outstanding_reservations, 1);
    assert_eq!(snapshot(&reopened).outstanding_debit_zatoshis, 70);
}

#[test]
fn offline_consumption_and_reorg_preserve_account_lifetime_budget() {
    let (mut ledger, r, _, auth) = offline_fixture();
    let MutationResult::OfflineReserved(original) = ledger.apply(&event(r.clone(), &auth)).unwrap()
    else {
        panic!("offline admission");
    };
    ledger.resolution_source = Some(h('e'));
    ledger
        .final_transactions
        .insert(r.operation_id.clone(), (h('a'), h('b')));
    let resolution = ResolutionRecord {
        operation_id: "offline-resolution".into(),
        account_id: r.intent.terms.account_id.clone(),
        network_profile_id: r.intent.terms.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
        reservation_operation_id: r.operation_id.clone(),
        reservation_request_digest: original.request_digest.clone(),
        final_transaction_id: h('b'),
        final_transaction_digest: h('a'),
        source_descriptor_digest: h('e'),
        evidence_digest: h('f'),
        consumed_nullifiers: r
            .intent
            .terms
            .inputs
            .iter()
            .map(|i| i.nullifier.clone())
            .collect(),
        conflict: None,
        inclusion_block_hash: h('9'),
        inclusion_block_height: 110,
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::QualifiedResolution(resolution),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 3001,
            writer_session_id: None,
        })
        .unwrap();
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.settled_debit_zatoshis, 70);
    let over = request(&ledger.snapshot.head, 2, 40);
    assert!(matches!(
        ledger.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveAuthorization(Box::new(over)),
            witness_time_ms: 3001,
            ..event(r.clone(), &auth)
        }),
        Err(AuthorityError::BudgetExceeded)
    ));
    let reopen = ReopenResolutions {
        operation_id: "offline-reorg".into(),
        account_id: r.intent.terms.account_id.clone(),
        network_profile_id: r.intent.terms.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
    };
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReopenResolutions(reopen),
            authenticated_certificate_digest: h('a'),
            witness_time_ms: 3002,
            writer_session_id: None,
        })
        .unwrap();
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 70);
    assert_eq!(ledger.snapshot.settled_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 100);
}

#[test]
fn offline_reservations_obey_the_shared_automation_account_pending_cap() {
    let (mut ledger, r, _, auth) = offline_fixture();
    ledger.automation_account_policy = Some(WitnessAutomationAccountPolicy {
        policy_id: "shared-account-cap".into(),
        writer_epoch: 1,
        maximum_outstanding_debit_zatoshis: 60,
        valid_from_ms: 1,
        expires_at_ms: 90000,
    });
    assert!(matches!(
        ledger.apply(&event(r, &auth)),
        Err(AuthorityError::BudgetExceeded)
    ));
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.outstanding_reservations, 0);
}
