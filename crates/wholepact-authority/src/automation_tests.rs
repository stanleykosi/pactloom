//! Isolated encrypted journals and deterministic synthetic ledger values only.
use super::*;
fn account_policy() -> WitnessAutomationAccountPolicy {
    WitnessAutomationAccountPolicy {
        policy_id: "auto-policy".into(),
        writer_epoch: 1,
        maximum_outstanding_debit_zatoshis: 100,
        valid_from_ms: 900,
        expires_at_ms: 100_000,
    }
}
fn grant() -> WitnessAutomationGrant {
    WitnessAutomationGrant {
        account_policy_id: "auto-policy".into(),
        binding: AutomationGrantBinding {
            grant_id: "grant-a".into(),
            revision: 1,
            terms_digest: h('5'),
            application_id: "app-a".into(),
        },
        writer_epoch: 1,
        enrollment_ref: h('c'),
        agreement_ids: vec!["synthetic-agreement".into()],
        recipient_scope_digests: vec![h('d')],
        maximum_payment_debit_zatoshis: 60,
        maximum_payment_fee_zatoshis: 5,
        maximum_outstanding_debit_zatoshis: 60,
        maximum_authorization_lifetime_ms: 60_000,
        valid_from_ms: 900,
        expires_at_ms: 100_000,
        status: AutomationGrantStatus::Active,
    }
}
fn install(j: &AuthorityJournal, g: WitnessAutomationGrant) {
    control(
        j,
        &format!("control-{}-{}", g.binding.grant_id, g.binding.revision),
        OwnerControl::SetAutomationGrant {
            grant: g,
            account_policy: account_policy(),
        },
    );
}
fn auto_request(
    j: &AuthorityJournal,
    n: u8,
    amount: u64,
    g: &WitnessAutomationGrant,
) -> ReserveAuthorization {
    let mut r = request(&snapshot(j).head, n, amount);
    r.automation = Some(g.binding.clone());
    r
}
fn admission(j: &AuthorityJournal, r: &ReserveAuthorization) -> AuthorizeAutomaticKeyUse {
    AuthorizeAutomaticKeyUse {
        operation_id: format!("key-use-{}", r.operation_id),
        account_id: r.account_id.clone(),
        network_profile_id: r.network_profile_id.clone(),
        writer_epoch: r.writer_epoch,
        expected_head: snapshot(j).head,
        reservation_operation_id: r.operation_id.clone(),
        reservation_request_digest: r.request_digest().unwrap(),
        automation: r.automation.clone().unwrap(),
        reviewed_at_ms: 1000,
        admission_expires_at_ms: 50_000,
    }
}
#[test]
fn automation_manual_serialization_and_old_hashes_remain_identical() {
    let r = request(&active_ledger().snapshot.head, 1, 40);
    let json = serde_json::to_value(&r).unwrap();
    assert!(json.get("automation").is_none());
    let old: ReserveAuthorization = serde_json::from_value(json.clone()).unwrap();
    assert!(old == r);
    assert_eq!(r.request_digest().unwrap(), old.request_digest().unwrap());
    assert_eq!(
        serde_json::to_vec(&r).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );
}
#[test]
fn automation_pause_before_admission_blocks_reserved_key_use_and_preserves_debit() {
    let dir = private_dir();
    let j = create(dir.path());
    let mut g = grant();
    install(&j, g.clone());
    let r = auto_request(&j, 1, 40, &g);
    mutate(&j, r.clone()).unwrap();
    g.binding.revision += 1;
    g.status = AutomationGrantStatus::Paused;
    install(&j, g);
    let a = admission(&j, &r);
    assert!(matches!(
        j.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeAutomaticKeyUse(a),
            1010
        ),
        Err(AuthorityError::InvalidBinding)
    ));
    assert_eq!(snapshot(&j).outstanding_debit_zatoshis, 40);
    drop(j);
    assert_eq!(snapshot(&open(dir.path())).outstanding_debit_zatoshis, 40);
}
#[test]
fn automation_committed_admission_is_never_reminted_after_restart_or_revoke() {
    let dir = private_dir();
    let j = create(dir.path());
    let mut g = grant();
    install(&j, g.clone());
    let r = auto_request(&j, 1, 40, &g);
    mutate(&j, r.clone()).unwrap();
    let a = admission(&j, &r);
    let result = j
        .mutate(
            &h('b'),
            AuthorityMutation::AuthorizeAutomaticKeyUse(a.clone()),
            1010,
        )
        .unwrap();
    let MutationResult::AutomaticKeyUseAdmitted(retained) = result else {
        panic!("wrong response")
    };
    retained.matches_request(&a).unwrap();
    g.binding.revision += 1;
    g.status = AutomationGrantStatus::Revoked;
    install(&j, g);
    assert!(matches!(
        j.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeAutomaticKeyUse(a.clone()),
            1012
        ),
        Err(AuthorityError::Uncertain)
    ));
    drop(j);
    let j = open(dir.path());
    assert!(matches!(
        j.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeAutomaticKeyUse(a.clone()),
            1013
        ),
        Err(AuthorityError::Uncertain)
    ));
    let (history, _) = crate::transport::synthetic::reconciled_session(
        &j,
        &h('b'),
        "synthetic-account",
        "synthetic-testnet",
    )
    .unwrap();
    assert!(history.account_policy() == &policy());
    assert_eq!(history.automatic_key_use_admissions().len(), 1);
    assert!(history.automatic_key_use_admissions()[0] == *retained);
    assert!(history.automation_account_policy() == Some(&account_policy()));
    let mut changed = a;
    changed.admission_expires_at_ms += 1;
    assert!(matches!(
        j.mutate(
            &h('b'),
            AuthorityMutation::AuthorizeAutomaticKeyUse(changed),
            1014
        ),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(snapshot(&j).outstanding_debit_zatoshis, 40);
}
#[test]
fn automation_grant_revisions_share_pending_and_manual_account_lifetime_budget() {
    let dir = private_dir();
    let j = create(dir.path());
    let mut g = grant();
    install(&j, g.clone());
    mutate(&j, auto_request(&j, 1, 40, &g)).unwrap();
    g.binding.revision += 1;
    install(&j, g.clone());
    assert!(matches!(
        mutate(&j, auto_request(&j, 2, 30, &g)),
        Err(AuthorityError::BudgetExceeded)
    ));
    let mut other = g.clone();
    other.binding.grant_id = "grant-b".into();
    other.binding.application_id = "app-b".into();
    other.binding.revision = 1;
    install(&j, other.clone());
    mutate(&j, auto_request(&j, 3, 40, &other)).unwrap();
    assert!(matches!(
        mutate(&j, request(&snapshot(&j).head, 4, 30)),
        Err(AuthorityError::BudgetExceeded)
    ));
    assert_eq!(snapshot(&j).outstanding_debit_zatoshis, 80);
}
#[test]
fn automation_wrong_application_enrollment_scope_expiry_and_revision_fail_closed() {
    let dir = private_dir();
    let j = create(dir.path());
    let g = grant();
    install(&j, g.clone());
    for mutation in 0..5 {
        let mut r = auto_request(&j, 1, 40, &g);
        match mutation {
            0 => r.automation.as_mut().unwrap().application_id = "wrong-app".into(),
            1 => r.automation.as_mut().unwrap().revision = 2,
            2 => r.enrollment_ref = h('f'),
            3 => r.recipient_scope_digest = h('f'),
            _ => r.permit_expires_at_ms = 101_000,
        }
        assert!(mutate(&j, r).is_err());
    }
    assert_eq!(snapshot(&j).outstanding_debit_zatoshis, 0);
}
#[test]
fn automation_recovery_epoch_never_activates_historical_grant() {
    let dir = private_dir();
    let j = create(dir.path());
    let g = grant();
    install(&j, g.clone());
    control(
        &j,
        "replace",
        OwnerControl::ReplaceWriter {
            writer_certificate_digest: h('9'),
        },
    );
    j.synthetic_activate(&h('9'), 1010).unwrap();
    let mut r = auto_request(&j, 1, 40, &g);
    r.writer_epoch = 2;
    assert!(matches!(
        j.mutate(
            &h('9'),
            AuthorityMutation::ReserveAuthorization(Box::new(r)),
            1012
        ),
        Err(AuthorityError::Expired)
    ));
    assert_eq!(snapshot(&j).outstanding_debit_zatoshis, 0);
}
#[test]
fn automation_consumption_reopens_grant_outstanding_without_refunding_lifetime() {
    let mut l = active_ledger();
    let mut g = grant();
    g.maximum_payment_debit_zatoshis = 40;
    g.maximum_outstanding_debit_zatoshis = 40;
    l.apply(&Event {
        original_request_link: None,
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: "install".into(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            expected_head: l.snapshot.head.clone(),
            writer_epoch: 1,
            control: OwnerControl::SetAutomationGrant {
                grant: g.clone(),
                account_policy: account_policy(),
            },
        }),
        authenticated_certificate_digest: h('a'),
        witness_time_ms: 1000,
        writer_session_id: None,
    })
    .unwrap();
    let session = Some(
        l.snapshot
            .active_writer_session
            .as_ref()
            .unwrap()
            .session_id
            .clone(),
    );
    let mut r = request(&l.snapshot.head, 1, 40);
    r.automation = Some(g.binding.clone());
    l.apply(&Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(r.clone())),
        authenticated_certificate_digest: h('b'),
        witness_time_ms: 1001,
        writer_session_id: session.clone(),
    })
    .unwrap();
    // Only this pure fixture supplies synthetic canonical evidence. Production
    // resolution remains the separately qualified validating-node route.
    l.resolution_source = Some(h('6'));
    l.final_transactions
        .insert(r.operation_id.clone(), (h('7'), h('8')));
    l.apply(&Event {
        original_request_link: None,
        mutation: AuthorityMutation::QualifiedResolution(ResolutionRecord {
            operation_id: "consume".into(),
            account_id: r.account_id.clone(),
            network_profile_id: r.network_profile_id.clone(),
            expected_head: l.snapshot.head.clone(),
            reservation_operation_id: r.operation_id.clone(),
            reservation_request_digest: r.request_digest().unwrap(),
            final_transaction_id: h('8'),
            final_transaction_digest: h('7'),
            source_descriptor_digest: h('6'),
            evidence_digest: h('5'),
            consumed_nullifiers: vec![r.inputs[0].nullifier.clone()],
            conflict: None,
            inclusion_block_hash: h('4'),
            inclusion_block_height: 4_500_000,
        }),
        authenticated_certificate_digest: h('a'),
        witness_time_ms: 1002,
        writer_session_id: None,
    })
    .unwrap();
    let mut second = request(&l.snapshot.head, 2, 40);
    second.automation = Some(g.binding.clone());
    l.apply(&Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReserveAuthorization(Box::new(second.clone())),
        authenticated_certificate_digest: h('b'),
        witness_time_ms: 1003,
        writer_session_id: session.clone(),
    })
    .unwrap();
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 40);
    assert_eq!(l.snapshot.settled_debit_zatoshis, 40);
    assert_eq!(l.snapshot.remaining_budget_zatoshis().unwrap(), 20);
    l.apply(&Event {
        original_request_link: None,
        mutation: AuthorityMutation::ReopenResolutions(ReopenResolutions {
            operation_id: "reopen".into(),
            account_id: r.account_id.clone(),
            network_profile_id: r.network_profile_id.clone(),
            expected_head: l.snapshot.head.clone(),
        }),
        authenticated_certificate_digest: h('a'),
        witness_time_ms: 1004,
        writer_session_id: None,
    })
    .unwrap();
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 80);
    assert_eq!(l.snapshot.settled_debit_zatoshis, 0);
    assert_eq!(l.snapshot.remaining_budget_zatoshis().unwrap(), 20);
    let a = AuthorizeAutomaticKeyUse {
        operation_id: "key-use".into(),
        account_id: r.account_id,
        network_profile_id: r.network_profile_id,
        writer_epoch: 1,
        expected_head: l.snapshot.head.clone(),
        reservation_operation_id: second.operation_id.clone(),
        reservation_request_digest: second.request_digest().unwrap(),
        automation: g.binding,
        reviewed_at_ms: 1000,
        admission_expires_at_ms: 50_000,
    };
    assert!(matches!(
        l.apply(&Event {
            original_request_link: None,
            mutation: AuthorityMutation::AuthorizeAutomaticKeyUse(a),
            authenticated_certificate_digest: h('b'),
            witness_time_ms: 1005,
            writer_session_id: session
        }),
        Err(AuthorityError::BudgetExceeded)
    ));
}
#[test]
fn automation_two_connections_serialize_manual_and_grant_reservations() {
    let dir = private_dir();
    let j = create(dir.path());
    let g = grant();
    install(&j, g.clone());
    let auto = auto_request(&j, 1, 60, &g);
    let manual = request(&snapshot(&j).head, 2, 60);
    let other = open(dir.path());
    let barrier = Arc::new(Barrier::new(2));
    let a = barrier.clone();
    let first = std::thread::spawn(move || {
        a.wait();
        mutate(&j, auto)
    });
    let second = std::thread::spawn(move || {
        barrier.wait();
        mutate(&other, manual)
    });
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(outcomes
        .iter()
        .any(|r| matches!(r, Err(AuthorityError::StaleHead))));
    assert_eq!(snapshot(&open(dir.path())).outstanding_debit_zatoshis, 60);
}
#[test]
fn automation_account_pending_cap_is_shared_and_distinct_from_lifetime() {
    let dir = private_dir();
    let j = create(dir.path());
    let mut p = account_policy();
    p.maximum_outstanding_debit_zatoshis = 60;
    let a = grant();
    control(
        &j,
        "first-policy",
        OwnerControl::SetAutomationGrant {
            grant: a.clone(),
            account_policy: p.clone(),
        },
    );
    let mut b = a.clone();
    b.binding.grant_id = "grant-b".into();
    b.binding.application_id = "app-b".into();
    control(
        &j,
        "second-grant",
        OwnerControl::SetAutomationGrant {
            grant: b.clone(),
            account_policy: p,
        },
    );
    mutate(&j, auto_request(&j, 1, 40, &a)).unwrap();
    assert!(matches!(
        mutate(&j, auto_request(&j, 2, 30, &b)),
        Err(AuthorityError::BudgetExceeded)
    ));
    assert!(matches!(
        mutate(&j, request(&snapshot(&j).head, 3, 30)),
        Err(AuthorityError::BudgetExceeded)
    ));
    assert_eq!(snapshot(&j).aggregate_budget_zatoshis, 100);
    assert_eq!(snapshot(&j).outstanding_debit_zatoshis, 40);
}
#[test]
fn automation_account_policy_identity_is_immutable_and_replacement_fences_old_grants() {
    let mut l = active_ledger();
    let g = grant();
    let p = account_policy();
    l.set_automation_grant(&g, &p, 1000).unwrap();
    let mut widened = p.clone();
    widened.maximum_outstanding_debit_zatoshis = 99;
    let mut renewed = g.clone();
    renewed.binding.revision = 2;
    assert!(matches!(
        l.set_automation_grant(&renewed, &widened, 1001),
        Err(AuthorityError::Conflict)
    ));
    let mut replacement = p.clone();
    replacement.policy_id = "replacement-policy".into();
    let mut other = g.clone();
    other.binding.grant_id = "grant-b".into();
    other.account_policy_id = replacement.policy_id.clone();
    l.set_automation_grant(&other, &replacement, 1001).unwrap();
    let mut r = request(&l.snapshot.head, 1, 40);
    r.automation = Some(g.binding.clone());
    assert!(matches!(
        l.check_automation_reservation(&r, 1002, true),
        Err(AuthorityError::InvalidBinding)
    ));
    assert!(matches!(
        l.set_automation_grant(&renewed, &p, 1002),
        Err(AuthorityError::Conflict)
    ));
    // Pausing old authority is allowed without reactivating its old account cap.
    renewed.status = AutomationGrantStatus::Paused;
    l.set_automation_grant(&renewed, &p, 1002).unwrap();
    assert!(l.automation_account_policy.as_ref() == Some(&replacement));
}
#[test]
fn automation_precommit_uses_identical_immutable_witness_bounds() {
    let p = policy();
    let account = account_policy();
    let g = grant();
    g.validate_account_bounds(&account, &p).unwrap();
    for case in 0..7 {
        let mut candidate = g.clone();
        let mut account = account.clone();
        match case {
            0 => candidate.enrollment_ref = h('f'),
            1 => candidate.agreement_ids = vec!["not-enrolled".into()],
            2 => candidate.recipient_scope_digests = vec![h('f')],
            3 => candidate.maximum_payment_fee_zatoshis = 6,
            4 => candidate.maximum_authorization_lifetime_ms = 60_001,
            5 => account.expires_at_ms = p.policy_expires_at_ms + 1,
            _ => account.maximum_outstanding_debit_zatoshis = 101,
        }
        assert!(candidate.validate_account_bounds(&account, &p).is_err());
    }
}
