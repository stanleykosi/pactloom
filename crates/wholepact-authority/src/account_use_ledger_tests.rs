//! Pure source tests. No credentials, sockets, keys or financial actions.
use super::*;
use crate::account_use::*;
fn birth_policy() -> AccountPolicy {
    let mut p = policy();
    p.account_id = h('1');
    p.account_use_genesis = Some(AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: p.account_id.clone(),
            full_viewing_key_digest: h('2'),
            network_profile_id: p.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_origin_digest: crate::digest(
            "wholepact:account-use-witness-origin:v1",
            &("127.0.0.1:1", "localhost", p.witness_id.as_str(), h('9')),
        )
        .unwrap(),
        witness_id: p.witness_id.clone(),
        owner_certificate_digest: p.owner_certificate_digest.clone(),
        native_birth_digest: h('3'),
    });
    p
}
fn exclude_event(l: &Ledger) -> Event {
    let g = l.policy.account_use_genesis.as_ref().unwrap();
    Event {
        original_request_link: None,
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: 2000,
        writer_session_id: None,
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: "permanent-exclusion".into(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: l.snapshot.writer_epoch,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::PermanentlyExcludeAccount {
                exclusion: PermanentAccountExclusion {
                    version: 1,
                    identity: g.identity.clone(),
                    genesis_digest: g.digest().unwrap(),
                    operation_id: "permanent-exclusion".into(),
                    native_review_digest: h('4'),
                    reason: ExclusionReason::RetirementRequested,
                },
            },
        }),
    }
}
fn reserve_event(l: &Ledger, number: u8) -> Event {
    let mut r = request(&l.snapshot.head, number, 60);
    r.account_id = l.policy.account_id.clone();
    Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(r)),
        authenticated_certificate_digest: h('b'),
        witness_time_ms: 1001,
        writer_session_id: Some(crate::session::session_id(&[42; 32])),
    }
}
#[test]
fn exclusion_keeps_charges_and_exact_history_but_blocks_fresh_reservation() {
    let mut l = active_ledger_with_policy(birth_policy());
    let reservation = reserve_event(&l, 1);
    let old_result = l.apply(&reservation).unwrap();
    let charges = (
        l.snapshot.outstanding_debit_zatoshis,
        l.snapshot.settled_debit_zatoshis,
        l.snapshot.reserved_input_value_zatoshis,
    );
    let event = exclude_event(&l);
    let result = l.apply(&event).unwrap();
    assert!(
        l.snapshot
            .account_use_checkpoint
            .as_ref()
            .unwrap()
            .permanent_exclusion_digest
            .is_some()
    );
    assert_eq!(
        charges,
        (
            l.snapshot.outstanding_debit_zatoshis,
            l.snapshot.settled_debit_zatoshis,
            l.snapshot.reserved_input_value_zatoshis
        )
    );
    assert!(l.apply(&event).unwrap() == result);
    assert!(l.apply(&reservation).unwrap() == old_result);
    let mut new_event = reserve_event(&l, 2);
    new_event.witness_time_ms = 2001;
    assert!(matches!(
        l.apply(&new_event),
        Err(AuthorityError::PolicyDenied)
    ));
}
#[test]
fn wrong_owner_and_changed_exclusion_retry_cannot_commit() {
    let mut l = active_ledger_with_policy(birth_policy());
    let mut event = exclude_event(&l);
    event.authenticated_certificate_digest = h('b');
    let head = l.snapshot.head.clone();
    assert!(l.apply(&event).is_err());
    assert!(l.snapshot.head == head);
    event.authenticated_certificate_digest = h('a');
    l.apply(&event).unwrap();
    if let AuthorityMutation::OwnerControl(r) = &mut event.mutation {
        if let OwnerControl::PermanentlyExcludeAccount { exclusion } = &mut r.control {
            exclusion.native_review_digest = h('5');
        }
    }
    assert!(matches!(l.apply(&event), Err(AuthorityError::Conflict)));
}
#[test]
fn legacy_encoding_omits_unknown_provenance_and_does_not_migrate_it() {
    let p = policy();
    let encoded = serde_json::to_string(&p).unwrap();
    assert!(!encoded.contains("account_use"));
    let l = Ledger::new(p).unwrap();
    assert!(l.snapshot.account_use_checkpoint.is_none());
    assert!(l.account_use_history.genesis().is_none());
    assert!(
        !serde_json::to_string(&l.snapshot)
            .unwrap()
            .contains("account_use")
    );
}
#[test]
fn birth_policy_cannot_rebind_original_witness_or_owner() {
    let mut p = birth_policy();
    p.witness_id = "substitute-witness".into();
    assert!(Ledger::new(p).is_err());
    let mut p = birth_policy();
    p.owner_certificate_digest = h('7');
    assert!(Ledger::new(p).is_err());
}
#[test]
fn replacement_writer_does_not_remove_exclusion_or_restore_new_sessions() {
    let mut l = active_ledger_with_policy(birth_policy());
    l.apply(&exclude_event(&l)).unwrap();
    let checkpoint = l.snapshot.account_use_checkpoint.clone();
    let mut replace = exclude_event(&l);
    if let AuthorityMutation::OwnerControl(r) = &mut replace.mutation {
        r.operation_id = "replace-after-retirement".into();
        r.control = OwnerControl::ReplaceWriter {
            writer_certificate_digest: h('6'),
        };
    }
    replace.witness_time_ms = 2001;
    l.apply(&replace).unwrap();
    assert!(l.snapshot.account_use_checkpoint == checkpoint);
    let mut event = reserve_event(&l, 2);
    event.authenticated_certificate_digest = h('6');
    event.witness_time_ms = 2002;
    assert!(matches!(l.apply(&event), Err(AuthorityError::PolicyDenied)));
}

#[test]
fn excluded_account_cannot_activate_or_reenable_offline_scope() {
    let mut l = active_ledger_with_policy(birth_policy());
    l.apply(&exclude_event(&l)).unwrap();
    for (index, action) in [
        OwnerControl::ActivateWriter { session_id: h('8') },
        OwnerControl::SetOfflinePolicyStatus {
            enrollment_ref: h('c'),
            policy_digest: h('d'),
            status: OfflineEnrollmentStatus::Active,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = exclude_event(&l);
        if let AuthorityMutation::OwnerControl(r) = &mut event.mutation {
            r.operation_id = format!("attempt-{index}");
            r.control = action;
        }
        event.witness_time_ms = 2001;
        let head = l.snapshot.head.clone();
        assert!(matches!(l.apply(&event), Err(AuthorityError::PolicyDenied)));
        assert!(l.snapshot.head == head);
    }
}

// Modeled replay fixture assembled only from successful pure Ledger transitions.
// It does not qualify transport authentication or any live witness session.
fn exclusion_history() -> (
    ReconciledAuthorityHistory,
    PermanentAccountExclusion,
    Ledger,
) {
    let mut l = active_ledger_with_policy(birth_policy());
    let event = exclude_event(&l);
    let request = match &event.mutation {
        AuthorityMutation::OwnerControl(r) => r.clone(),
        _ => unreachable!(),
    };
    let exclusion = match &request.control {
        OwnerControl::PermanentlyExcludeAccount { exclusion } => exclusion.clone(),
        _ => unreachable!(),
    };
    l.apply(&event).unwrap();
    let disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1".into(),
        server_name: "localhost".into(),
        witness_id: l.policy.witness_id.clone(),
        account_id: l.policy.account_id.clone(),
        network_profile_id: l.policy.network_profile_id.clone(),
        policy_digest: l.snapshot.policy_digest.clone(),
        pinned_server_certificate_digest: h('9'),
    };
    let history_heads = std::collections::BTreeMap::from([
        (
            request.expected_head.sequence,
            request.expected_head.digest.clone(),
        ),
        (l.snapshot.head.sequence, l.snapshot.head.digest.clone()),
    ]);
    (
        ReconciledAuthorityHistory {
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
            account_use_history: l.account_use_history.clone(),
            account_policy: l.policy.clone(),
            snapshot: l.snapshot.clone(),
            permits: vec![],
            offline_permits: vec![],
            born_offline_permits: vec![],
            born_offline_dispatches: vec![],
            automatic_key_use_admissions: vec![],
            recovery_fences: vec![],
            committed_operation_ids: std::collections::BTreeSet::from([request
                .operation_id
                .clone()]),
            owner_controls: std::collections::BTreeMap::from([(
                request.operation_id.clone(),
                request,
            )]),
            history_heads,
            disclosure,
        },
        exclusion,
        l,
    )
}
#[test]
fn receipt_binds_original_event_and_rejects_origin_substitution() {
    let (mut history, exclusion, mut ledger) = exclusion_history();
    let g = history.account_policy.account_use_genesis.clone().unwrap();
    let original = history.disclosure.clone();
    let receipt =
        crate::account_use_link::reconcile_account_exclusion(&history, &g, &original, &exclusion)
            .unwrap();
    // A genuine later pure Ledger transition does not change receipt identity.
    let mut later = exclude_event(&ledger);
    if let AuthorityMutation::OwnerControl(r) = &mut later.mutation {
        r.operation_id = "later-pause".into();
        r.control = OwnerControl::Pause;
    }
    later.witness_time_ms = 2001;
    ledger.apply(&later).unwrap();
    history.snapshot = ledger.snapshot.clone();
    history.history_heads.insert(
        ledger.snapshot.head.sequence,
        ledger.snapshot.head.digest.clone(),
    );
    if let AuthorityMutation::OwnerControl(r) = later.mutation {
        history
            .committed_operation_ids
            .insert(r.operation_id.clone());
        history.owner_controls.insert(r.operation_id.clone(), r);
    }
    let again =
        crate::account_use_link::reconcile_account_exclusion(&history, &g, &original, &exclusion)
            .unwrap();
    assert!(receipt.receipt_digest().unwrap() == again.receipt_digest().unwrap());
    let mut substitute = original.clone();
    substitute.pinned_server_certificate_digest = h('7');
    assert!(
        crate::account_use_link::reconcile_account_exclusion(&history, &g, &substitute, &exclusion)
            .is_err()
    );
    // A modeled same-name witness projection cannot substitute its pin either;
    // the original genesis's origin digest remains independently bound.
    history.disclosure = substitute.clone();
    assert!(
        crate::account_use_link::reconcile_account_exclusion(&history, &g, &substitute, &exclusion)
            .is_err()
    );
}
#[test]
fn missing_exclusion_operation_or_unknown_genesis_never_acknowledges() {
    let (mut history, exclusion, _) = exclusion_history();
    let g = history.account_policy.account_use_genesis.clone().unwrap();
    let original = history.disclosure.clone();
    history.owner_controls.clear();
    assert!(
        crate::account_use_link::reconcile_account_exclusion(&history, &g, &original, &exclusion)
            .is_err()
    );
    history.account_use_history = AccountUseHistory::unknown_legacy();
    assert!(
        crate::account_use_link::reconcile_account_exclusion(&history, &g, &original, &exclusion)
            .is_err()
    );
}

#[test]
fn raw_birth_claim_cannot_create_a_witness_database() {
    let dir = private_dir();
    let path = dir.path().join("claimed-birth.db");
    assert!(matches!(
        AuthorityJournal::create_encrypted(
            &path,
            &DatabaseKey::from_bytes([19; 32]),
            birth_policy()
        ),
        Err(AuthorityError::Permission)
    ));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[test]
fn historical_replay_is_not_a_reissued_execution_admission() {
    let mut l = active_ledger_with_policy(birth_policy());
    let reservation = reserve_event(&l, 1);
    l.apply(&reservation).unwrap();
    l.apply(&exclude_event(&l)).unwrap();
    assert!(l.replay(&reservation).unwrap().is_some());
    assert!(matches!(
        l.require_account_use_for_new_mutation(&reservation.mutation),
        Err(AuthorityError::PolicyDenied)
    ));
}

#[test]
fn complete_exclusion_ack_keeps_offline_exposure_and_legacy_gate() {
    use crate::{offline::tests::fixture, offline_admission::OfflineReservationRecord};
    let mut ledger = active_ledger_with_policy(birth_policy());
    let (mut request, _, mut policy) = fixture();
    policy.account_id = ledger.policy.account_id.clone();
    policy.enrollment_ref = ledger.policy.enrollment_refs[0].clone();
    policy.witness_certificate_digest = h('9');
    request.intent.terms.account_id = policy.account_id.clone();
    request.intent.terms.enrollment_ref = policy.enrollment_ref.clone();
    request.intent.terms.recipient_scope_digest = ledger.policy.recipient_scope_digests[0].clone();
    request.intent.terms.offline_policy_digest = policy.policy_digest().unwrap();
    let enroll = OwnerControlRequest {
        operation_id: "typed-recovery-offline-enrollment".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        expected_head: ledger.snapshot.head.clone(),
        writer_epoch: ledger.snapshot.writer_epoch,
        control: OwnerControl::EnrollOfflinePolicy {
            policy: policy.clone(),
            expected_previous_digest: None,
        },
    };
    let mut heads = std::collections::BTreeMap::from([(
        enroll.expected_head.sequence,
        enroll.expected_head.digest.clone(),
    )]);
    ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::OwnerControl(enroll.clone()),
            authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
            witness_time_ms: 1000,
            writer_session_id: None,
        })
        .unwrap();
    heads.insert(
        ledger.snapshot.head.sequence,
        ledger.snapshot.head.digest.clone(),
    );
    request.expected_head = ledger.snapshot.head.clone();
    let issuer = OfflineIntentAuthenticationIssuer::for_test(policy.clone()).unwrap();
    let authentication = issuer
        .bind_verified_intent(
            &request,
            &request.intent,
            &policy.offline_signer_key_digest,
            &policy.witness_transport_key_digest,
            &h('9'),
        )
        .unwrap();
    let offline = match ledger
        .apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::ReserveOfflineAuthorization(Box::new(
                OfflineReservationRecord {
                    request,
                    authentication: authentication.evidence().clone(),
                },
            )),
            authenticated_certificate_digest: ledger
                .policy
                .initial_writer_certificate_digest
                .clone(),
            witness_time_ms: 3000,
            writer_session_id: Some(crate::session::session_id(&[42; 32])),
        })
        .unwrap()
    {
        MutationResult::OfflineReserved(admission) => *admission,
        _ => panic!("wrong synthetic reservation result"),
    };
    heads.insert(
        ledger.snapshot.head.sequence,
        ledger.snapshot.head.digest.clone(),
    );
    let mut exclude = exclude_event(&ledger);
    exclude.witness_time_ms = 4000;
    let exclusion_request = match &exclude.mutation {
        AuthorityMutation::OwnerControl(request) => request.clone(),
        _ => unreachable!(),
    };
    let exclusion = match &exclusion_request.control {
        OwnerControl::PermanentlyExcludeAccount { exclusion } => exclusion.clone(),
        _ => unreachable!(),
    };
    ledger.apply(&exclude).unwrap();
    heads.insert(
        ledger.snapshot.head.sequence,
        ledger.snapshot.head.digest.clone(),
    );
    let disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1".into(),
        server_name: "localhost".into(),
        witness_id: ledger.policy.witness_id.clone(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        policy_digest: ledger.snapshot.policy_digest.clone(),
        pinned_server_certificate_digest: h('9'),
    };
    let mut history = ReconciledAuthorityHistory {
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
        offline_permits: vec![offline],
        born_offline_permits: vec![],
        born_offline_dispatches: vec![],
        automatic_key_use_admissions: vec![],
        recovery_fences: vec![],
        committed_operation_ids: std::collections::BTreeSet::from([
            enroll.operation_id.clone(),
            exclusion_request.operation_id.clone(),
        ]),
        owner_controls: std::collections::BTreeMap::from([
            (enroll.operation_id.clone(), enroll),
            (exclusion_request.operation_id.clone(), exclusion_request),
        ]),
        history_heads: heads,
        disclosure: disclosure.clone(),
    };
    let genesis = history.account_policy.account_use_genesis.clone().unwrap();
    let before = history.history_digest().unwrap();
    assert!(
        crate::account_use_link::reconcile_account_exclusion(
            &history,
            &genesis,
            &disclosure,
            &exclusion
        )
        .is_err()
    );
    let receipt = crate::account_use_link::reconcile_account_exclusion_complete(
        &history,
        &genesis,
        &disclosure,
        &exclusion,
    )
    .unwrap();
    assert_eq!(receipt.evidence().committed_head, ledger.snapshot.head);
    assert_eq!(history.history_digest().unwrap(), before);
    assert_eq!(history.reservation_evidence().count(), 1);
    assert_eq!(history.snapshot.outstanding_debit_zatoshis, 70);
    let mut substituted = disclosure.clone();
    substituted.pinned_server_certificate_digest = h('7');
    assert!(
        crate::account_use_link::reconcile_account_exclusion_complete(
            &history,
            &genesis,
            &substituted,
            &exclusion
        )
        .is_err()
    );
    history.owner_controls.remove(&exclusion.operation_id);
    assert!(
        crate::account_use_link::reconcile_account_exclusion_complete(
            &history,
            &genesis,
            &disclosure,
            &exclusion
        )
        .is_err()
    );
}
