//! Synthetic deterministic ledger evidence only. These fixtures do not construct
//! a native decision, namespace owner, authenticated channel or signing authority.
use super::*;
use crate::{
    manual_enrollment::tests::bootstrap_events,
    policy::{Event, Ledger},
};
fn h(n: u8) -> String {
    format!("{n:064x}")
}
pub(crate) fn record(
    ledger: &Ledger,
    birth: &PendingBirthCommitRecord,
) -> BornOfflineEnrollmentRecordV1 {
    let common = &ledger.manual_extension().unwrap().unwrap().extension;
    let (extension, attempt, admission) =
        if let Some(roster) = ledger.manual_roster_extension().unwrap() {
            let a = ledger.latest_manual_roster_attempt_v2().unwrap();
            (
                roster.extension.digest().unwrap(),
                a.attempt_digest.clone(),
                a.admission
                    .as_ref()
                    .unwrap()
                    .digest_for(&roster.extension, a.continuation.as_ref())
                    .unwrap(),
            )
        } else {
            let a = ledger.latest_manual_attempt().unwrap();
            (
                common.digest().unwrap(),
                a.attempt_digest.clone(),
                a.last_admission_digest(common).unwrap().unwrap(),
            )
        };
    let session = ledger.snapshot.active_writer_session.clone().unwrap();
    let issued = ledger.snapshot.last_witness_time_ms + 100;
    let expiry = (issued + 5000)
        .min(session.expires_at_ms)
        .min(common.terms.scope.expires_at_ms);
    let policy=OfflineEnrollmentPolicy {
        schema_version:1,account_id:ledger.policy.account_id.clone(),network_profile_id:ledger.policy.network_profile_id.clone(),witness_id:ledger.policy.witness_id.clone(),witness_transport_key_digest:h(30),witness_certificate_digest:birth.request.disclosure.pinned_server_certificate_digest.clone(),enrollment_ref:common.enrollment_ref.clone(),offline_signer_key_digest:h(31),return_recipient_key_digest:h(32),source_identity_digest:h(33),source_policy_digest:h(34),maximum_admission_lifetime_ms:500.min(ledger.policy.maximum_permit_lifetime_ms).min(common.terms.scope.maximum_permit_lifetime_ms),valid_from_ms:issued,expires_at_ms:expiry,semantics:crate::offline::OfflineAuthoritySemantics::ExactEffectsPreReservedMayDrainAfterRevocation,
    };
    let g = ledger.policy.account_use_genesis.as_ref().unwrap();
    BornOfflineEnrollmentRecordV1 {
        enrollment: BornOfflineEnrollmentV1 {
            version: 1,
            policy,
            assurance: BornOfflineAssuranceV1::NamedVerifierOwnEffectsV1 {
                owner_setup_digest: h(35),
            },
            original_policy_digest: ledger.policy.policy_digest().unwrap(),
            account_use_genesis_digest: g.digest().unwrap(),
            birth_request_digest: birth.request_digest.clone(),
            birth_commit_digest: crate::manual_enrollment::original_birth_commit_digest(birth)
                .unwrap(),
            native_birth_digest: g.native_birth_digest.clone(),
            original_witness_origin_digest: g.witness_origin_digest.clone(),
            owner_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
            manual_extension_digest: extension,
            manual_attempt_digest: attempt,
            manual_admission_digest: admission,
            original_writer_session: session,
            expected_head: ledger.snapshot.head.clone(),
            issued_at_ms: issued,
            first_commit_deadline_ms: expiry,
        },
        owner_signature_evidence_digest: h(36),
        native_review_digest: h(37),
    }
}
pub(crate) fn event(ledger: &Ledger, r: &BornOfflineEnrollmentRecordV1) -> Event {
    Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: r.enrollment.owner_operation_id().unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: r.enrollment.expected_head.clone(),
            control: OwnerControl::EnrollBornOfflineV1 {
                record: Box::new(r.clone()),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: r.enrollment.issued_at_ms + 1,
        writer_session_id: None,
        original_request_link: None,
    }
}
#[test]
fn exact_born_enrollment_preserves_policy_session_charges_and_original_history() {
    let (birth, _, events, mut ledger) = bootstrap_events();
    let r = record(&ledger, &birth);
    r.enrollment.validate_original_birth(&birth).unwrap();
    let original_policy = ledger.policy.clone();
    let before = ledger.snapshot.clone();
    assert!(
        !original_policy
            .enrollment_refs
            .contains(&r.enrollment.policy.enrollment_ref)
    );
    assert!(
        ledger
            .set_offline_policy(&r.enrollment.policy, None, r.enrollment.issued_at_ms)
            .is_err()
    );
    let e = event(&ledger, &r);
    let result = ledger.apply(&e).unwrap();
    assert!(ledger.policy == original_policy);
    assert!(ledger.snapshot.active_writer_session == before.active_writer_session);
    assert_eq!(
        ledger.snapshot.outstanding_debit_zatoshis,
        before.outstanding_debit_zatoshis
    );
    assert_eq!(
        ledger.snapshot.reserved_input_value_zatoshis,
        before.reserved_input_value_zatoshis
    );
    assert_eq!(
        ledger.snapshot.aggregate_budget_zatoshis,
        before.aggregate_budget_zatoshis
    );
    assert_eq!(ledger.operations.len(), events.len() + 1);
    assert!(ledger.born_offline_enrollment_v1().unwrap() == Some(&r));
    let head = ledger.snapshot.head.clone();
    assert!(ledger.apply(&e).unwrap() == result);
    assert!(ledger.snapshot.head == head);
    assert!(matches!(
        ledger.require_supported_manual_history(),
        Err(AuthorityError::OfflineHistoryUnsupported)
    ));
    let mut replay = Ledger::new(original_policy).unwrap();
    for old in &events {
        replay.apply(old).unwrap();
    }
    replay.apply(&e).unwrap();
    replay.validate_born_offline_birth_v1(Some(&birth)).unwrap();
    assert!(replay.snapshot == ledger.snapshot);
}
#[test]
fn roster_parent_attempt_and_original_admission_are_not_replaced_by_single_account_projection() {
    let (birth, roster, _, mut ledger) =
        crate::manual_roster_construction_v2::tests::construction_fixture();
    let r = record(&ledger, &birth);
    assert_eq!(
        r.enrollment.manual_extension_digest,
        roster.digest().unwrap()
    );
    let mut wrong = r.clone();
    wrong.enrollment.manual_extension_digest = roster.account_extension.digest().unwrap();
    assert!(
        ledger
            .validate_new_born_offline_enrollment_v1(&wrong, wrong.enrollment.issued_at_ms)
            .is_err()
    );
    ledger.apply(&event(&ledger, &r)).unwrap();
    ledger.validate_born_offline_birth_v1(Some(&birth)).unwrap();
}
#[test]
fn exact_scope_substitution_missing_session_and_expiry_fail_closed() {
    let (birth, _, _, ledger) = bootstrap_events();
    let r = record(&ledger, &birth);
    let now = r.enrollment.issued_at_ms;
    for field in 0..7 {
        let mut wrong = r.clone();
        match field {
            0 => wrong.enrollment.manual_extension_digest = h(70),
            1 => wrong.enrollment.manual_attempt_digest = h(71),
            2 => wrong.enrollment.manual_admission_digest = h(72),
            3 => wrong.enrollment.policy.enrollment_ref = h(73),
            4 => wrong.enrollment.original_writer_session.session_id = h(74),
            5 => wrong.enrollment.expected_head.digest = h(75),
            _ => wrong.enrollment.policy.witness_certificate_digest = h(76),
        }
        assert!(
            ledger
                .validate_new_born_offline_enrollment_v1(&wrong, now)
                .is_err()
        );
    }
    assert!(
        ledger
            .validate_new_born_offline_enrollment_v1(&r, r.enrollment.first_commit_deadline_ms)
            .is_err()
    );
    assert!(
        ledger
            .validate_new_born_offline_enrollment_v1(&r, now - 1)
            .is_err()
    );
    let (_, _, _, mut missing) = bootstrap_events();
    missing.snapshot.active_writer_session = None;
    assert!(
        missing
            .validate_new_born_offline_enrollment_v1(&r, now)
            .is_err()
    );
}
#[test]
fn original_birth_and_single_session_ceiling_cannot_be_reinterpreted_or_renewed() {
    let (birth, _, _, ledger) = bootstrap_events();
    let r = record(&ledger, &birth);
    for field in 0..5 {
        let mut changed = r.enrollment.clone();
        match field {
            0 => changed.birth_request_digest = h(80),
            1 => changed.birth_commit_digest = h(81),
            2 => changed.native_birth_digest = h(82),
            3 => changed.account_use_genesis_digest = h(83),
            _ => changed.original_witness_origin_digest = h(84),
        }
        assert!(changed.validate_original_birth(&birth).is_err());
    }
    let mut renewed = r.enrollment.clone();
    renewed.policy.expires_at_ms = renewed.original_writer_session.expires_at_ms + 1;
    assert!(renewed.validate().is_err());
    let mut too_long = r.enrollment.clone();
    too_long.first_commit_deadline_ms = too_long.issued_at_ms + BORN_OFFLINE_FIRST_COMMIT_MS + 1;
    assert!(too_long.validate().is_err());
    let mut missing_birth = ledger;
    assert!(missing_birth.validate_born_offline_birth_v1(None).is_ok());
    missing_birth.apply(&event(&missing_birth, &r)).unwrap();
    assert!(missing_birth.validate_born_offline_birth_v1(None).is_err());
}
#[test]
fn named_assurance_is_explicit_strict_and_committed_without_changing_policy_domain() {
    let (birth, _, _, ledger) = bootstrap_events();
    let r = record(&ledger, &birth);
    let old_policy = r.enrollment.policy.policy_digest().unwrap();
    let old = r.enrollment.digest().unwrap();
    let mut independent = r.enrollment.clone();
    independent.assurance = BornOfflineAssuranceV1::Independent;
    assert_ne!(independent.digest().unwrap(), old);
    assert_eq!(independent.policy.policy_digest().unwrap(), old_policy);
    let mut value = serde_json::to_value(&r).unwrap();
    value["enrollment"]["assurance"]["unchecked_authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<BornOfflineEnrollmentRecordV1>(value).is_err());
}
#[test]
fn changed_retry_and_second_enrollment_cannot_replace_original_evidence() {
    let (birth, _, _, mut ledger) = bootstrap_events();
    let r = record(&ledger, &birth);
    let e = event(&ledger, &r);
    ledger.apply(&e).unwrap();
    let original = ledger.snapshot.clone();
    let mut changed = e.clone();
    if let AuthorityMutation::OwnerControl(OwnerControlRequest {
        control: OwnerControl::EnrollBornOfflineV1 { record },
        ..
    }) = &mut changed.mutation
    {
        record.native_review_digest = h(90);
    }
    assert!(matches!(
        ledger.apply(&changed),
        Err(AuthorityError::Conflict)
    ));
    let mut second = r.clone();
    second.enrollment.assurance = BornOfflineAssuranceV1::Independent;
    second.enrollment.expected_head = ledger.snapshot.head.clone();
    assert!(ledger.apply(&event(&ledger, &second)).is_err());
    assert!(ledger.snapshot == original);
}

#[test]
fn paused_revoked_quarantined_or_permanently_excluded_history_cannot_enroll() {
    for status in [
        WriterStatus::Paused,
        WriterStatus::Revoked,
        WriterStatus::Quarantined,
    ] {
        let (birth, _, _, mut ledger) = bootstrap_events();
        let r = record(&ledger, &birth);
        ledger.snapshot.writer_status = status;
        assert!(
            ledger
                .validate_new_born_offline_enrollment_v1(&r, r.enrollment.issued_at_ms)
                .is_err()
        );
    }
    let (birth, _, _, mut ledger) = bootstrap_events();
    let mut r = record(&ledger, &birth);
    let g = ledger.policy.account_use_genesis.as_ref().unwrap();
    let exclusion = crate::account_use::PermanentAccountExclusion {
        version: 1,
        identity: g.identity.clone(),
        genesis_digest: g.digest().unwrap(),
        operation_id: "synthetic-born-offline-retired".into(),
        native_review_digest: h(91),
        reason: crate::account_use::ExclusionReason::RetirementRequested,
    };
    let e = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: exclusion.operation_id.clone(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::PermanentlyExcludeAccount { exclusion },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: r.enrollment.issued_at_ms,
        writer_session_id: None,
        original_request_link: None,
    };
    ledger.apply(&e).unwrap();
    r.enrollment.expected_head = ledger.snapshot.head.clone();
    assert!(ledger.apply(&event(&ledger, &r)).is_err());
    assert!(ledger.offline_policies.is_empty());
}

#[test]
fn full_original_session_owner_and_policy_ceilings_fail_closed() {
    let (birth, extension, _, ledger) = bootstrap_events();
    let original = record(&ledger, &birth);
    let now = original.enrollment.issued_at_ms;
    for field in 0..6 {
        let mut changed = original.clone();
        let e = &mut changed.enrollment;
        match field {
            0 => e.original_writer_session.acquired_head.digest = h(100),
            1 => e.original_writer_session.reconciled_head.digest = h(101),
            2 => e.original_writer_session.reconciled_history_digest = h(102),
            3 => e.original_writer_session.acquired_at_ms += 1,
            4 => e.owner_certificate_digest = h(103),
            _ => {
                e.policy.maximum_admission_lifetime_ms =
                    ledger.policy.maximum_permit_lifetime_ms + 1
            }
        }
        changed.validate().unwrap();
        assert!(
            ledger
                .validate_new_born_offline_enrollment_v1(&changed, now)
                .is_err()
        );
    }
    let mut beyond_manual = original.clone();
    beyond_manual.enrollment.policy.expires_at_ms = extension.terms.scope.expires_at_ms + 1;
    beyond_manual.validate().unwrap();
    beyond_manual
        .enrollment
        .validate_original_policy(&ledger.policy)
        .unwrap();
    assert!(matches!(
        ledger.validate_new_born_offline_enrollment_v1(&beyond_manual, now),
        Err(AuthorityError::PolicyDenied)
    ));
    let mut beyond_account = original.enrollment.clone();
    beyond_account.policy.expires_at_ms = ledger.policy.policy_expires_at_ms + 1;
    beyond_account.original_writer_session.expires_at_ms = beyond_account.policy.expires_at_ms;
    beyond_account.validate().unwrap();
    assert!(matches!(
        beyond_account.validate_original_policy(&ledger.policy),
        Err(AuthorityError::PolicyDenied)
    ));
    let mut at_limit = original;
    at_limit.enrollment.policy.maximum_admission_lifetime_ms =
        extension.terms.scope.maximum_permit_lifetime_ms;
    ledger
        .validate_new_born_offline_enrollment_v1(&at_limit, now)
        .unwrap();
}

#[test]
fn fenced_original_writer_session_cannot_enroll_or_clear_the_fence() {
    let (birth, _, _, mut ledger) = bootstrap_events();
    let r = record(&ledger, &birth);
    ledger.snapshot.transport_fences = Some(
        crate::construction_transport_handoff_v1::ConstructionTransportFenceSnapshotV1 {
            version: 1,
            fenced_session_ids: std::collections::BTreeSet::from([r
                .enrollment
                .original_writer_session
                .session_id
                .clone()]),
        },
    );
    let before = ledger.snapshot.clone();
    assert!(matches!(
        ledger.validate_new_born_offline_enrollment_v1(&r, r.enrollment.issued_at_ms),
        Err(AuthorityError::SessionRequired)
    ));
    assert!(ledger.apply(&event(&ledger, &r)).is_err());
    assert!(ledger.snapshot == before);
    assert!(ledger.offline_policies.is_empty());
}
