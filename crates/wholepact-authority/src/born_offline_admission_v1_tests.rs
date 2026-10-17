//! Inert historical ledger DTOs only. No namespace owner, native decision,
//! authenticated input/clock or signing capability is fabricated here.
use super::*;
use crate::policy::{Event, Ledger};
fn h(n: u8) -> String {
    format!("{n:064x}")
}
fn fingerprint(bytes: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"wholepact.transport-key.v1\0");
    hash.update(bytes);
    hex::encode(hash.finalize())
}
pub(crate) fn fixture() -> (Ledger, Vec<Event>, BornOfflineReservationRecordV1) {
    let (birth, roster, events, ledger) =
        crate::manual_roster_construction_v3::tests::construction_fixture_v3();
    fixture_from_construction(birth, roster, events, ledger, false)
}
pub(crate) fn owner_fixture() -> (Ledger, Vec<Event>, BornOfflineReservationRecordV1) {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let mut ledger = Ledger::new(f.birth.request.policy.clone()).unwrap();
    for event in &f.events {
        ledger.apply(event).unwrap();
    }
    let roster = ledger
        .manual_roster_extension()
        .unwrap()
        .unwrap()
        .extension
        .clone();
    fixture_from_construction(f.birth, roster, f.events, ledger, true)
}
fn fixture_from_construction(
    birth: crate::pending_birth::PendingBirthCommitRecord,
    roster: crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    mut events: Vec<Event>,
    mut ledger: Ledger,
    owner: bool,
) -> (Ledger, Vec<Event>, BornOfflineReservationRecordV1) {
    let manual = roster.account_extension.clone();
    let continuation = ledger
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .continuation
        .unwrap();
    let construction = match &ledger.operations["alice-reservation-v3"].2 {
        MutationResult::ManualRosterConstructionReservedV3(r) => r.as_ref().clone(),
        MutationResult::ConstructionTransportReservedV1(r) => r.original.clone(),
        _ => panic!("actual original reservation"),
    };
    let consume_id = crate::manual_roster_construction_v3::construction_consume_operation_id_v3(
        &construction,
        &roster,
        &continuation,
    )
    .unwrap();
    let consumed = match &ledger.operations[&consume_id].2 {
        MutationResult::ManualRosterConstructionConsumedV3(c) => c.as_ref().clone(),
        MutationResult::ConstructionTransportConsumedV1(c) => c.original.clone(),
        _ => panic!("actual original consume"),
    };
    let construction_link = crate::born_offline_construction_v1::BornOfflineConstructionLinkV1 {
        version: 1,
        reservation_operation_id: construction.request.construction.operation_id.clone(),
        reservation_digest: construction.digest_for(&roster, &continuation).unwrap(),
        consume_operation_id: consume_id,
        consume_digest: consumed
            .digest_for(&construction, &roster, &continuation)
            .unwrap(),
        plan_digest: construction.request.construction.plan.digest().unwrap(),
        common_context_digest: construction
            .request
            .construction
            .plan
            .common_context_digest
            .clone(),
        invocation_digest: construction.request.invocation_digest().unwrap(),
        checkpoint_origin_digest: h(83),
    };
    let mut enrollment = crate::born_offline_enrollment_v1::tests::record(&ledger, &birth);
    if owner {
        let origin = ledger
            .born_offline_construction_origin_v1(&construction_link)
            .unwrap();
        enrollment.enrollment.owner_continuation = Some(
            crate::born_offline_owner_continuation_v1::BornOfflineOwnerContinuationV1 {
                version: 1,
                construction_reservation_operation_id: construction_link
                    .reservation_operation_id
                    .clone(),
                construction_consume_operation_id: construction_link.consume_operation_id.clone(),
                construction_origin_digest: origin.digest().unwrap(),
                construction_transport_credential_id: origin.transport_credential_id.unwrap(),
            },
        );
        enrollment.enrollment.policy.expires_at_ms = enrollment
            .enrollment
            .policy
            .expires_at_ms
            .min(construction.construction_expires_at_ms);
        enrollment.enrollment.first_commit_deadline_ms = enrollment
            .enrollment
            .first_commit_deadline_ms
            .min(construction.construction_expires_at_ms);
    }
    enrollment.enrollment.policy.maximum_admission_lifetime_ms = 1000;
    enrollment.enrollment.policy.witness_transport_key_digest = fingerprint(&[0x51; 32]);
    enrollment.enrollment.policy.offline_signer_key_digest = fingerprint(&[0x52; 32]);
    let event = crate::born_offline_enrollment_v1::tests::event(&ledger, &enrollment);
    ledger.apply(&event).unwrap();
    events.push(event);
    let artifacts = BornOfflineArtifactRecordV1 {
        binding: BornOfflineArtifactBindingV1 {
            version: 1,
            enrollment_digest: enrollment.enrollment.digest().unwrap(),
            namespace_binding_digest: h(80),
            witness_public_key_hex: hex::encode([0x51; 32]),
            offline_signer_public_key_hex: hex::encode([0x52; 32]),
            expected_head: ledger.snapshot.head.clone(),
            issued_at_ms: 253500,
            first_commit_deadline_ms: 254000,
        },
        native_review_digest: h(81),
    };
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: artifacts.binding.owner_operation_id().unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            expected_head: ledger.snapshot.head.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            control: OwnerControl::InstallBornOfflineArtifactsV1 {
                record: Box::new(artifacts.clone()),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: 253501,
        writer_session_id: None,
        original_request_link: None,
    };
    ledger.apply(&event).unwrap();
    events.push(event);
    let (mut reservation, _, _) = crate::offline::tests::fixture();
    let p = &enrollment.enrollment.policy;
    let t = &mut reservation.intent.terms;
    t.account_id = ledger.policy.account_id.clone();
    t.network_profile_id = ledger.policy.network_profile_id.clone();
    t.enrollment_ref = manual.enrollment_ref.clone();
    t.agreement_id = manual.terms.scope.agreement_id.clone();
    t.obligation_id = manual.terms.scope.obligation_id.clone();
    t.recipient_scope_digest = manual.terms.scope.recipient_scope_digests[0].clone();
    t.offline_policy_digest = p.policy_digest().unwrap();
    t.offline_signer_key_digest = p.offline_signer_key_digest.clone();
    t.return_recipient_key_digest = p.return_recipient_key_digest.clone();
    t.snapshot.source_identity_digest = p.source_identity_digest.clone();
    t.snapshot.source_policy_digest = p.source_policy_digest.clone();
    let plan = &construction.request.construction.plan;
    let proposal = plan.validate().unwrap();
    let allocation = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == t.account_id)
        .unwrap();
    t.maximum_debit_zatoshis = construction.reserved_debit_zatoshis;
    t.fee_share_zatoshis = allocation.fee_share.as_zatoshis();
    t.transaction_fee_zatoshis = proposal.manifest().transaction_fee.as_zatoshis();
    t.proposal_id = proposal.input().proposal_id.clone();
    t.proposal_revision = plan.common_context.candidate_revision;
    t.proposal_digest = proposal.proposal_digest().into();
    t.manifest_digest = proposal.manifest_digest().into();
    t.consensus_branch_id = plan.common_context.consensus_branch_id;
    t.transaction_expiry_height = plan.common_context.expiry_height;
    t.snapshot.tip_height = plan.common_context.reference_tip_height;
    t.snapshot.tip_hash = plan.common_context.reference_tip_hash_protocol.clone();
    t.snapshot.anchor_height = plan.common_context.anchor_height;
    t.snapshot.anchor_hash = plan.common_context.anchor_hash_protocol.clone();
    t.snapshot.anchor_root = plan.common_context.anchor_root.clone();
    t.inputs = plan
        .selected_inputs()
        .iter()
        .enumerate()
        .map(|(index, i)| InputReservation {
            input_id: i.input_id.clone(),
            nullifier: i.nullifier.clone(),
            value_zatoshis: i.value_zatoshis,
            action_index: index as u64,
        })
        .collect();
    reservation.expected_head = ledger.snapshot.head.clone();
    reservation.writer_epoch = ledger.snapshot.writer_epoch;
    reservation.requested_at_ms = 254000;
    reservation.admission_expires_at_ms = 255000;
    let authentication = OfflineIntentAuthenticationRecord {
        intent_digest: reservation.intent.intent_digest().unwrap(),
        reservation_request_digest: reservation.request_digest().unwrap(),
        policy_digest: p.policy_digest().unwrap(),
        sender_fingerprint: p.offline_signer_key_digest.clone(),
        witness_fingerprint: p.witness_transport_key_digest.clone(),
        envelope_digest: h(82),
    };
    let request = BornOfflineReservationRequestV1 {
        version: 1,
        enrollment_digest: enrollment.enrollment.digest().unwrap(),
        artifact_binding_digest: artifacts.binding.digest().unwrap(),
        construction_link,
        reservation,
    };
    ledger
        .validate_born_offline_request_v1(&request, 254001)
        .unwrap();
    (
        ledger,
        events,
        BornOfflineReservationRecordV1 {
            request,
            authentication,
        },
    )
}
pub(crate) fn event(ledger: &Ledger, record: &BornOfflineReservationRecordV1) -> Event {
    let enrollment = &ledger
        .born_offline_enrollment_v1()
        .unwrap()
        .unwrap()
        .enrollment;
    Event {
        mutation: AuthorityMutation::ReserveBornOfflineV1(Box::new(record.clone())),
        authenticated_certificate_digest: enrollment.born_transport_certificate_v1().into(),
        witness_time_ms: 254001,
        writer_session_id: enrollment.born_event_writer_session_v1(),
        original_request_link: None,
    }
}

#[test]
fn born_original_reservation_replays_exactly_preserves_policy_and_retains_shared_exposure() {
    let (mut ledger, events, record) = fixture();
    let before = ledger.snapshot.clone();
    let policy = ledger.policy.clone();
    let event = event(&ledger, &record);
    let result = ledger.apply(&event).unwrap();
    let after = ledger.snapshot.clone();
    assert!(ledger.apply(&event).unwrap() == result);
    assert!(ledger.snapshot == after);
    assert!(ledger.policy == policy);
    assert!(before.active_writer_session == after.active_writer_session);
    assert_eq!(
        after.outstanding_debit_zatoshis,
        before.outstanding_debit_zatoshis
    );
    assert_eq!(
        after.reserved_input_value_zatoshis,
        before.reserved_input_value_zatoshis
    );
    assert_eq!(
        after.outstanding_reservations,
        before.outstanding_reservations
    );
    assert!(crate::exposure_view::ExposureView::from_result(&result).is_none());
    assert!(crate::reservation_view::ReservationView::from_result(&result).is_none());
    ledger.recompute_exposure().unwrap();
    assert!(ledger.snapshot == after);
    let MutationResult::BornOfflineReservedV1(admission) = result else {
        panic!("purpose must remain distinct")
    };
    let enrollment = &ledger
        .born_offline_enrollment_v1()
        .unwrap()
        .unwrap()
        .enrollment;
    assert!(
        admission
            .reserved
            .validate_reserved_policy_bounds(&policy, &enrollment.policy)
            .is_err()
    );
    assert_ne!(
        admission.admission_digest().unwrap(),
        crate::offline_clock_v1::OfflineClockScopeV1::from_descriptor(&admission.reserved)
            .unwrap()
            .original_admission_digest
    );
    assert!(matches!(
        ledger.check_input_obligation_exclusions(
            &record.request.reservation.intent.terms.obligation_id,
            std::iter::empty()
        ),
        Err(AuthorityError::ObligationReserved)
    ));
    let input = &record.request.reservation.intent.terms.inputs[0];
    assert!(matches!(
        ledger.check_input_obligation_exclusions(
            "another-obligation",
            std::iter::once(("another-input", input.nullifier.as_str()))
        ),
        Err(AuthorityError::InputReserved)
    ));
    let mut replay = Ledger::new(policy).unwrap();
    for old in events {
        replay.apply(&old).unwrap();
    }
    replay.apply(&event).unwrap();
    assert!(replay.snapshot == after);
}
#[test]
fn born_continuation_is_not_a_generic_progress_reservation() {
    let (mut ledger, _, record) = fixture();
    let admitted = event(&ledger, &record);
    ledger.apply(&admitted).unwrap();
    let before = ledger.snapshot.clone();
    let original = &record.request.reservation;
    let progress = Event {
        mutation: AuthorityMutation::ReportProgress(ReportProgress {
            operation_id: "inert-generic-born-progress".into(),
            account_id: original.intent.terms.account_id.clone(),
            network_profile_id: original.intent.terms.network_profile_id.clone(),
            writer_epoch: original.writer_epoch,
            expected_head: before.head.clone(),
            reservation_operation_id: original.operation_id.clone(),
            reservation_request_digest: original.request_digest().unwrap(),
            progress: AuthorizationProgress::SubmissionUncertain,
            evidence_digest: h(84),
        }),
        authenticated_certificate_digest: admitted.authenticated_certificate_digest,
        witness_time_ms: admitted.witness_time_ms + 1,
        writer_session_id: admitted.writer_session_id,
        original_request_link: None,
    };
    assert!(ledger.apply(&progress).is_err());
    assert!(ledger.snapshot == before);
    ledger.recompute_exposure().unwrap();
    assert!(ledger.snapshot == before);
}

#[test]
fn born_origin_manual_limits_and_authenticated_record_substitutions_are_rejected() {
    let (ledger, _, record) = fixture();
    for change in 0..10 {
        let mut r = record.request.clone();
        match change {
            0 => r.enrollment_digest = h(90),
            1 => r.artifact_binding_digest = h(91),
            2 => r.reservation.intent.terms.enrollment_ref = h(92),
            3 => r.reservation.intent.terms.agreement_id = "other-agreement".into(),
            4 => r.reservation.intent.terms.obligation_id = "other-obligation".into(),
            5 => r.reservation.intent.terms.maximum_debit_zatoshis += 1,
            6 => r.reservation.intent.terms.fee_share_zatoshis += 1,
            7 => r.reservation.intent.terms.transaction_fee_zatoshis += 1,
            8 => r.reservation.admission_expires_at_ms = 255001,
            _ => r.reservation.writer_epoch += 1,
        };
        assert!(
            ledger.validate_born_offline_request_v1(&r, 254001).is_err(),
            "change {change}"
        );
    }
    for change in 0..3 {
        let (mut l, _, mut r) = fixture();
        match change {
            0 => r.authentication.envelope_digest = "invalid".into(),
            1 => r.authentication.sender_fingerprint = h(93),
            _ => r.authentication.reservation_request_digest = h(94),
        };
        let before = l.snapshot.clone();
        assert!(l.apply(&event(&l, &r)).is_err());
        assert!(l.snapshot == before);
    }
}
#[test]
fn born_session_substitution_fence_pause_and_time_fail_without_releasing_exposure() {
    for change in 0..6 {
        let (mut ledger, _, record) = fixture();
        match change {
            0 => {
                ledger
                    .snapshot
                    .active_writer_session
                    .as_mut()
                    .unwrap()
                    .acquired_head
                    .digest = h(95)
            }
            1 => ledger.snapshot.writer_status = WriterStatus::Paused,
            2 => {
                let session = ledger
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .unwrap()
                    .session_id
                    .clone();
                ledger.activated_sessions.remove(&session);
            }
            3 => {
                let session = ledger
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .unwrap()
                    .session_id
                    .clone();
                ledger.snapshot.transport_fences=Some(crate::construction_transport_handoff_v1::ConstructionTransportFenceSnapshotV1{version:1,fenced_session_ids:std::collections::BTreeSet::from([session])});
            }
            4 => {
                let p = &ledger
                    .born_offline_enrollment_v1()
                    .unwrap()
                    .unwrap()
                    .enrollment
                    .policy;
                ledger.offline_policy_states.insert(
                    p.enrollment_ref.clone(),
                    (p.policy_digest().unwrap(), OfflineEnrollmentStatus::Paused),
                );
            }
            _ => ledger.snapshot.last_witness_time_ms = 255000,
        };
        assert!(
            ledger
                .validate_born_offline_request_v1(&record.request, 254001)
                .is_err(),
            "change {change}"
        );
    }
    let (ledger, _, record) = fixture();
    for now in [253499, 253999, 255000, 260000, u64::MAX] {
        assert!(
            ledger
                .validate_born_offline_request_v1(&record.request, now)
                .is_err()
        );
    }
}
#[test]
fn born_artifact_install_cannot_replace_key_or_original_session() {
    let (ledger, events, _) = fixture();
    let artifact_event = events.last().unwrap();
    let mut before = Ledger::new(ledger.policy.clone()).unwrap();
    for event in &events[..events.len() - 1] {
        before.apply(event).unwrap();
    }
    let AuthorityMutation::OwnerControl(OwnerControlRequest {
        control: OwnerControl::InstallBornOfflineArtifactsV1 { record },
        ..
    }) = &artifact_event.mutation
    else {
        panic!()
    };
    for change in 0..5 {
        let mut bad = record.as_ref().clone();
        match change {
            0 => bad.binding.witness_public_key_hex = hex::encode([0x53; 32]),
            1 => bad.binding.offline_signer_public_key_hex = hex::encode([0x54; 32]),
            2 => bad.binding.enrollment_digest = h(96),
            3 => bad.binding.expected_head.digest = h(97),
            _ => bad.binding.first_commit_deadline_ms = 253500,
        };
        assert!(
            before
                .validate_new_born_offline_artifacts_v1(&bad, 253501)
                .is_err()
        );
    }
    assert!(
        ledger
            .validate_new_born_offline_artifacts_v1(record, 253502)
            .is_err()
    );
}
#[test]
fn born_shared_budget_includes_settled_and_existing_outstanding_debit() {
    let (mut ledger, _, record) = fixture();
    ledger.snapshot.settled_debit_zatoshis = ledger.policy.aggregate_budget_zatoshis;
    let before = ledger.snapshot.clone();
    assert!(matches!(
        ledger.apply(&event(&ledger, &record)),
        Err(AuthorityError::BudgetExceeded)
    ));
    assert!(ledger.snapshot == before);
}
#[test]
fn born_continuation_requires_exact_consumption_and_cannot_reuse_original_charge() {
    for field in 0..8 {
        let (ledger, _, mut r) = fixture();
        let link = &mut r.request.construction_link;
        match field {
            0 => link.reservation_operation_id = "missing".into(),
            1 => link.consume_operation_id = "missing".into(),
            2 => link.reservation_digest = h(90),
            3 => link.consume_digest = h(91),
            4 => link.plan_digest = h(92),
            5 => link.common_context_digest = h(93),
            6 => link.invocation_digest = h(94),
            _ => r.request.reservation.intent.terms.inputs[0].nullifier = h(95),
        }
        assert!(
            ledger
                .validate_born_offline_request_v1(&r.request, 254001)
                .is_err()
        );
    }
    let (mut ledger, _, r) = fixture();
    ledger.apply(&event(&ledger, &r)).unwrap();
    let before = ledger.snapshot.clone();
    let mut changed = r.clone();
    changed.request.reservation.operation_id = "second-born-operation".into();
    changed.request.reservation.intent.intent_id = "second-born-intent".into();
    changed.request.reservation.intent.terms.authorization_id = "second-authorization".into();
    changed.request.reservation.expected_head = ledger.snapshot.head.clone();
    assert!(matches!(
        ledger.validate_born_offline_request_v1(&changed.request, 254001),
        Err(AuthorityError::Conflict)
    ));
    assert!(ledger.snapshot == before);
}

#[test]
fn owner_continuation_consumed_handoff_keeps_old_mac_fenced_and_one_original_charge() {
    let (mut ledger, events, record) = owner_fixture();
    let before = ledger.snapshot.clone();
    let enrollment = ledger
        .born_offline_enrollment_v1()
        .unwrap()
        .unwrap()
        .enrollment
        .clone();
    assert!(
        ledger
            .require_unfenced_transport(&enrollment.original_writer_session.session_id)
            .is_err()
    );
    let mut wrong = event(&ledger, &record);
    wrong.authenticated_certificate_digest = enrollment
        .original_writer_session
        .writer_certificate_digest
        .clone();
    wrong.writer_session_id = Some(enrollment.original_writer_session.session_id.clone());
    assert!(ledger.apply(&wrong).is_err());
    assert!(ledger.snapshot == before);
    let mut wrong = record.clone();
    wrong.request.construction_link.reservation_operation_id = "other-original".into();
    assert!(ledger.apply(&event(&ledger, &wrong)).is_err());
    let original = event(&ledger, &record);
    let result = ledger.apply(&original).unwrap();
    assert!(ledger.apply(&original).unwrap() == result);
    ledger.recompute_exposure().unwrap();
    assert_eq!(
        ledger.snapshot.outstanding_debit_zatoshis,
        before.outstanding_debit_zatoshis
    );
    assert_eq!(
        ledger.snapshot.reserved_input_value_zatoshis,
        before.reserved_input_value_zatoshis
    );
    assert_eq!(
        ledger.snapshot.outstanding_reservations,
        before.outstanding_reservations
    );
    assert!(
        ledger
            .require_unfenced_transport(&enrollment.original_writer_session.session_id)
            .is_err()
    );
    assert!(
        ledger
            .require_born_offline_original_session_v1(enrollment.policy.expires_at_ms)
            .is_err()
    );
    let mut replay = Ledger::new(ledger.policy.clone()).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    replay.apply(&original).unwrap();
    assert!(replay.snapshot == ledger.snapshot);
}
#[test]
fn owner_continuation_transport_rejects_cross_origin_certificate_and_scope() {
    use crate::born_offline_owner_continuation_v1::BornOfflineTransportAuthenticationV1 as Auth;
    let (ledger, _, _) = owner_fixture();
    let e = &ledger
        .born_offline_enrollment_v1()
        .unwrap()
        .unwrap()
        .enrollment;
    let auth = Auth::OriginalOwnerContinuationV1 {
        enrollment_digest: e.digest().unwrap(),
        continuation_digest: e.owner_continuation.as_ref().unwrap().digest().unwrap(),
    };
    assert!(
        auth.select_original_proof(e, &e.owner_certificate_digest)
            .unwrap()
            .is_none()
    );
    assert!(
        auth.select_original_proof(e, &e.original_writer_session.writer_certificate_digest)
            .is_err()
    );
    let (legacy, _, _) = fixture();
    let old = &legacy
        .born_offline_enrollment_v1()
        .unwrap()
        .unwrap()
        .enrollment;
    assert!(
        auth.select_original_proof(old, &old.original_writer_session.writer_certificate_digest)
            .is_err()
    );
    let mut changed = e.clone();
    changed
        .owner_continuation
        .as_mut()
        .unwrap()
        .construction_origin_digest = h(99);
    assert!(ledger.require_born_transport_lineage_v1(&changed).is_err());
    changed = e.clone();
    changed
        .owner_continuation
        .as_mut()
        .unwrap()
        .construction_transport_credential_id = h(98);
    assert!(ledger.require_born_transport_lineage_v1(&changed).is_err());
}
