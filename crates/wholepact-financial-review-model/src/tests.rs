use super::*;

fn bounds() -> OriginalBounds {
    OriginalBounds::from_absolute(
        TimeObservation { wall_ms: 100, monotonic_ms: 10 },
        TimeObservation { wall_ms: 200, monotonic_ms: 110 },
    ).unwrap()
}

fn scope(action: ActionKind) -> ReviewScopeDescriptor {
    let role = match action {
        ActionKind::WitnessAppendExact => Role::Witness(OwnerSlot::First),
        ActionKind::HostIntakeExact | ActionKind::HostCompleteExact
        | ActionKind::HostDispatchExact => Role::Host,
        _ => Role::Signer(OwnerSlot::First),
    };
    ReviewScopeDescriptor {
        coordinator_instance: InstanceId([1; 32]), session_epoch: SessionEpoch(1),
        review_epoch: ReviewEpoch(1), review_id: ReviewId([2; 32]),
        action_id: ActionId([3; 32]), action, account: AccountId([4; 32]),
        review_surface_instance: InstanceId([5; 32]),
        peer: PeerBindingDescriptor {
            role, principal: PrincipalId([6; 32]), process_instance: InstanceId([7; 32]),
            worker_instance: InstanceId([8; 32]), channel_instance: InstanceId([9; 32]),
            actual_binding: BindingDescriptor([10; 32]),
        },
        source: SourceDescriptor {
            kind: SourceKind::PathBacked, identity: SourceId([11; 32]),
            original_pin: BindingDescriptor([12; 32]),
        },
        reviewed_binding: BindingDescriptor([13; 32]),
        reviewed_key_use_batch: if action == ActionKind::SignExact { 2 } else { 0 },
    }
}

fn trace(action: ActionKind) -> ReviewTrace { ReviewTrace::new(scope(action), bounds()).unwrap() }

fn send_at(model: &mut ReviewTrace, observation: Observation, time: TimeObservation)
    -> Result<ObservationReceipt, Rejection>
{
    model.observe(Event {
        header: EventHeader {
            scope: model.scope().clone(), sequence: model.last_sequence() + 1, observed_at: time,
        }, observation,
    })
}

fn send(model: &mut ReviewTrace, observation: Observation) -> Result<ObservationReceipt, Rejection> {
    send_at(model, observation, TimeObservation { wall_ms: 101, monotonic_ms: 11 })
}

fn focus() -> Observation {
    Observation::FocusBatch { focused_at_end: true, loss_observed_in_batch: false }
}

fn blur() -> Observation {
    Observation::FocusBatch { focused_at_end: false, loss_observed_in_batch: true }
}

fn arm(model: &mut ReviewTrace) {
    assert_eq!(send(model, focus()), Ok(ObservationReceipt::FocusObserved));
    assert_eq!(send(model, Observation::InitialHumanReviewed), Ok(ObservationReceipt::HumanReviewObserved));
}

fn next_effect(model: &ReviewTrace) -> PreparedEffectDescriptor {
    let index = model.records().len();
    let kind = model.scope().action.effect_order()[index];
    PreparedEffectDescriptor {
        kind, effect_id: EffectId([50 + index as u8; 32]),
        challenge: ChallengeId([70 + index as u8; 32]),
        payload_binding: BindingDescriptor([90 + index as u8; 32]),
        reviewed_binding: model.scope().reviewed_binding,
        predecessor: model.records().last().map(|record| record.descriptor.effect_id),
        batch_width: if kind == EffectKind::KeyUseExactBatch {
            model.scope().reviewed_key_use_batch
        } else { 1 },
    }
}

fn prepare(model: &mut ReviewTrace) -> PreparedEffectDescriptor {
    let effect = next_effect(model);
    assert_eq!(send(model, Observation::PrepareEffect(effect.clone())), Ok(ObservationReceipt::PreparationObserved));
    effect
}

fn admit(model: &mut ReviewTrace, effect: &PreparedEffectDescriptor) {
    assert_eq!(send(model, Observation::FinalAdmit(effect.clone())), Ok(ObservationReceipt::FinalAdmissionObserved));
}

fn outcome(model: &mut ReviewTrace, effect: &PreparedEffectDescriptor, result: EffectOutcome) {
    assert_eq!(send(model, Observation::OutcomeObserved { effect: effect.clone(), outcome: result }),
        Ok(ObservationReceipt::OutcomeObserved));
}

fn complete_next(model: &mut ReviewTrace) -> PreparedEffectDescriptor {
    let effect = prepare(model);
    admit(model, &effect);
    outcome(model, &effect, EffectOutcome::Completed);
    effect
}

#[test]
fn initial_review_and_preparation_are_not_final_admission() {
    let mut model = trace(ActionKind::SignExact);
    let effect = next_effect(&model);
    assert_eq!(send(&mut model, Observation::InitialHumanReviewed), Err(Rejection::WrongPhase));
    assert_eq!(send(&mut model, Observation::PrepareEffect(effect.clone())), Err(Rejection::WrongPhase));
    assert_eq!(send(&mut model, Observation::FinalAdmit(effect.clone())), Err(Rejection::WrongPhase));
    arm(&mut model);
    assert_eq!(model.status(), ReviewStatus::Armed);
    assert!(model.records().is_empty());
    let effect = prepare(&mut model);
    assert_eq!(model.records()[0].progress, EffectProgress::Prepared);
    assert_eq!(send(&mut model, Observation::WorkerStartedObservation(effect.clone())), Err(Rejection::WrongPhase));
    admit(&mut model, &effect);
    assert_eq!(model.records()[0].progress, EffectProgress::Admitted);
    assert_eq!(send(&mut model, Observation::WorkerStartedObservation(effect.clone())), Ok(ObservationReceipt::StartObserved));
    assert_eq!(model.records()[0].progress, EffectProgress::InFlight);
    assert_eq!(send(&mut model, Observation::WorkerStartedObservation(effect.clone())), Err(Rejection::WrongPhase));
    outcome(&mut model, &effect, EffectOutcome::Completed);
    assert_eq!(model.status(), ReviewStatus::Armed);
    assert_eq!(model.records().len(), 1); // No automatic successor.
}

#[test]
fn all_cancel_blur_admit_permutations_have_one_processed_linearization_point() {
    let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for source in [SourceKind::PathBacked, SourceKind::Canonical] {
        for owner in [OwnerSlot::First, OwnerSlot::Second] {
            for order in orders {
                let mut original = scope(ActionKind::SignExact);
                original.source.kind = source;
                original.peer.role = Role::Signer(owner);
                let mut model = ReviewTrace::new(original, bounds()).unwrap();
                arm(&mut model);
                let effect = prepare(&mut model);
                let mut admissions = 0;
                for event in order {
                    let observation = match event {
                        0 => Observation::FinalAdmit(effect.clone()), 1 => Observation::Cancel,
                        _ => blur(),
                    };
                    if send(&mut model, observation) == Ok(ObservationReceipt::FinalAdmissionObserved) {
                        admissions += 1;
                    }
                }
                assert_eq!(admissions, usize::from(order[0] == 0));
                assert!(matches!(model.status(), ReviewStatus::Invalidated(_)));
                assert!(send(&mut model, Observation::FinalAdmit(effect.clone())).is_err());
                if admissions == 1 {
                    // Coordinator cancellation does not prove no historical start.
                    assert_eq!(send(&mut model, Observation::WorkerStartedObservation(effect.clone())),
                        Ok(ObservationReceipt::StartObserved));
                    outcome(&mut model, &effect, EffectOutcome::Completed);
                    let next = next_effect(&model);
                    assert!(send(&mut model, Observation::PrepareEffect(next)).is_err());
                }
            }
        }
    }
}

#[test]
fn each_revocation_before_or_after_admission_stays_closed() {
    for revocation in [blur(), Observation::Cancel, Observation::Close,
        Observation::PeerLost, Observation::PeerRestarted, Observation::CheckOriginalBounds]
    {
        for revoke_first in [true, false] {
            let mut model = trace(ActionKind::SignExact);
            arm(&mut model);
            let effect = prepare(&mut model);
            if !revoke_first { admit(&mut model, &effect); }
            let time = if revocation == Observation::CheckOriginalBounds {
                bounds().expires()
            } else { TimeObservation { wall_ms: 101, monotonic_ms: 11 } };
            let _ = send_at(&mut model, revocation.clone(), time);
            assert!(matches!(model.status(), ReviewStatus::Invalidated(_)));
            assert!(send_at(&mut model, Observation::FinalAdmit(effect.clone()), time).is_err());
            assert!(send_at(&mut model, focus(), time).is_err());
            assert!(send_at(&mut model, Observation::InitialHumanReviewed, time).is_err());
            let admissions = usize::from(matches!(model.records()[0].progress,
                EffectProgress::Admitted | EffectProgress::Outcome(EffectOutcome::Unknown)));
            assert_eq!(admissions, usize::from(!revoke_first));
        }
    }
}

#[test]
fn blur_and_refocus_in_same_batch_invalidates_before_any_admit() {
    let mut model = trace(ActionKind::SignExact);
    arm(&mut model);
    let effect = prepare(&mut model);
    send(&mut model, Observation::FocusBatch { focused_at_end: true, loss_observed_in_batch: true }).unwrap();
    assert_eq!(model.status(), ReviewStatus::Invalidated(Invalidation::FocusLost));
    assert!(send(&mut model, Observation::FinalAdmit(effect)).is_err());
    assert!(send(&mut model, focus()).is_err());
}

#[test]
fn every_original_scope_field_is_exact_and_cannot_be_rebound() {
    let original = scope(ActionKind::SignExact);
    let mut variants = Vec::new();
    macro_rules! changed { ($field:ident, $value:expr) => {{
        let mut s = original.clone(); s.$field = $value; variants.push(s);
    }}; }
    changed!(coordinator_instance, InstanceId([200; 32]));
    changed!(session_epoch, SessionEpoch(2)); changed!(review_epoch, ReviewEpoch(2));
    changed!(review_id, ReviewId([200; 32])); changed!(action_id, ActionId([200; 32]));
    changed!(action, ActionKind::ReturnExact); changed!(account, AccountId([200; 32]));
    changed!(review_surface_instance, InstanceId([200; 32]));
    changed!(reviewed_binding, BindingDescriptor([200; 32])); changed!(reviewed_key_use_batch, 3);
    for field in 0..6 {
        let mut s = original.clone();
        match field {
            0 => s.peer.role = Role::Signer(OwnerSlot::Second),
            1 => s.peer.principal = PrincipalId([200; 32]),
            2 => s.peer.process_instance = InstanceId([200; 32]),
            3 => s.peer.worker_instance = InstanceId([200; 32]),
            4 => s.peer.channel_instance = InstanceId([200; 32]),
            _ => s.peer.actual_binding = BindingDescriptor([200; 32]),
        }
        variants.push(s);
    }
    for field in 0..3 {
        let mut s = original.clone();
        match field {
            0 => s.source.kind = SourceKind::Canonical,
            1 => s.source.identity = SourceId([200; 32]),
            _ => s.source.original_pin = BindingDescriptor([200; 32]),
        }
        variants.push(s);
    }
    for wrong_scope in variants {
        let mut model = ReviewTrace::new(original.clone(), bounds()).unwrap();
        arm(&mut model);
        let effect = prepare(&mut model);
        let sequence = model.last_sequence() + 1;
        assert_eq!(model.observe(Event {
            header: EventHeader { scope: wrong_scope, sequence,
                observed_at: TimeObservation { wall_ms: 101, monotonic_ms: 11 } },
            observation: Observation::FinalAdmit(effect.clone()),
        }), Err(Rejection::ScopeMismatch));
        assert!(send(&mut model, Observation::FinalAdmit(effect)).is_err());
    }
}

#[test]
fn every_prepared_effect_field_must_match_at_final_admission() {
    for field in 0..7 {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let original = prepare(&mut model);
        let mut wrong = original.clone();
        match field {
            0 => wrong.kind = EffectKind::KeyUseExactBatch,
            1 => wrong.effect_id = EffectId([201; 32]),
            2 => wrong.challenge = ChallengeId([201; 32]),
            3 => wrong.payload_binding = BindingDescriptor([201; 32]),
            4 => wrong.reviewed_binding = BindingDescriptor([201; 32]),
            5 => wrong.predecessor = Some(EffectId([201; 32])),
            _ => wrong.batch_width = 2,
        }
        assert_eq!(send(&mut model, Observation::FinalAdmit(wrong)), Err(Rejection::EffectMismatch));
        assert!(send(&mut model, Observation::FinalAdmit(original)).is_err());
    }
}

#[test]
fn preparation_requires_exact_order_anchor_predecessor_and_batch() {
    for field in 0..4 {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let mut wrong = next_effect(&model);
        match field {
            0 => wrong.kind = EffectKind::KeyUseExactBatch,
            1 => wrong.reviewed_binding = BindingDescriptor([202; 32]),
            2 => wrong.predecessor = Some(EffectId([202; 32])),
            _ => wrong.batch_width = 2,
        }
        assert_eq!(send(&mut model, Observation::PrepareEffect(wrong)), Err(Rejection::EffectMismatch));
    }
    let mut model = trace(ActionKind::SignExact);
    arm(&mut model);
    complete_next(&mut model);
    let mut next = next_effect(&model);
    next.predecessor = None;
    assert_eq!(send(&mut model, Observation::PrepareEffect(next)), Err(Rejection::EffectMismatch));
}

#[test]
fn event_replay_gap_reordering_and_overflow_invalidate_without_wrapping() {
    for wrong_sequence in [0, 1, 2, 99, u64::MAX] {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let effect = prepare(&mut model); // next sequence is 4
        assert_eq!(model.observe(Event {
            header: EventHeader { scope: model.scope().clone(), sequence: wrong_sequence,
                observed_at: TimeObservation { wall_ms: 101, monotonic_ms: 11 } },
            observation: Observation::FinalAdmit(effect.clone()),
        }), Err(Rejection::EventOrder));
        assert!(send(&mut model, Observation::FinalAdmit(effect)).is_err());
    }
    let mut model = trace(ActionKind::SignExact);
    model.last_sequence = u64::MAX; // Exhaustion seam, unreachable through wrapping.
    assert_eq!(model.observe(Event {
        header: EventHeader { scope: model.scope().clone(), sequence: 0,
            observed_at: TimeObservation { wall_ms: 101, monotonic_ms: 11 } },
        observation: focus(),
    }), Err(Rejection::EventOrder));
}

#[test]
fn duplicate_admit_outcome_and_old_challenge_never_reissue() {
    for result in [EffectOutcome::Completed, EffectOutcome::KnownNoEffect, EffectOutcome::Unknown] {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let effect = prepare(&mut model);
        admit(&mut model, &effect);
        assert_eq!(send(&mut model, Observation::FinalAdmit(effect.clone())), Err(Rejection::WrongPhase));
        outcome(&mut model, &effect, result);
        assert_eq!(send(&mut model, Observation::FinalAdmit(effect.clone())), Err(Rejection::WrongPhase));
        assert_eq!(send(&mut model, Observation::OutcomeObserved { effect: effect.clone(), outcome: result }), Err(Rejection::WrongPhase));
        if result == EffectOutcome::Completed {
            let mut next = next_effect(&model);
            next.challenge = effect.challenge;
            assert_eq!(send(&mut model, Observation::PrepareEffect(next)), Err(Rejection::ReusedEffectOrChallenge));
        } else {
            let next = next_effect(&model);
            assert_eq!(send(&mut model, Observation::PrepareEffect(next)), Err(Rejection::WrongPhase));
        }
    }
    let mut model = trace(ActionKind::SignExact);
    arm(&mut model);
    let prior = complete_next(&mut model);
    let mut next = next_effect(&model);
    next.effect_id = prior.effect_id;
    assert_eq!(send(&mut model, Observation::PrepareEffect(next)), Err(Rejection::ReusedEffectOrChallenge));
}

#[test]
fn unknown_is_not_in_model_reconciliation_or_retry_permission() {
    let mut model = trace(ActionKind::SignExact);
    arm(&mut model);
    let effect = prepare(&mut model);
    admit(&mut model, &effect);
    outcome(&mut model, &effect, EffectOutcome::Unknown);
    assert_eq!(model.status(), ReviewStatus::Unknown);
    assert_eq!(send(&mut model, Observation::OutcomeObserved { effect: effect.clone(), outcome: EffectOutcome::Completed }), Err(Rejection::WrongPhase));
    assert_eq!(send(&mut model, Observation::PrepareEffect(effect)), Err(Rejection::WrongPhase));
    assert_eq!(send(&mut model, Observation::InitialHumanReviewed), Err(Rejection::WrongPhase));
}

#[test]
fn final_admission_before_blur_can_report_only_its_exact_result() {
    for result in [EffectOutcome::Completed, EffectOutcome::KnownNoEffect, EffectOutcome::Unknown] {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let effect = prepare(&mut model);
        admit(&mut model, &effect);
        send(&mut model, blur()).unwrap();
        outcome(&mut model, &effect, result);
        assert_eq!(model.status(), ReviewStatus::Invalidated(Invalidation::FocusLost));
        let next = next_effect(&model);
        assert!(send(&mut model, Observation::PrepareEffect(next)).is_err());
    }
}

#[test]
fn peer_death_and_restart_quarantine_admitted_unknown_not_reconnect() {
    for loss in [Observation::PeerLost, Observation::PeerRestarted] {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let effect = prepare(&mut model);
        admit(&mut model, &effect);
        send(&mut model, loss).unwrap();
        assert_eq!(model.records()[0].progress, EffectProgress::Outcome(EffectOutcome::Unknown));
        assert_eq!(send(&mut model, Observation::WorkerStartedObservation(effect.clone())), Err(Rejection::WrongPhase));
        assert_eq!(send(&mut model, Observation::OutcomeObserved { effect: effect.clone(), outcome: EffectOutcome::Completed }), Err(Rejection::WrongPhase));
        assert!(send(&mut model, focus()).is_err());
        assert!(send(&mut model, Observation::FinalAdmit(effect)).is_err());
    }
}

#[test]
fn original_bounds_never_slide_and_equality_expires_either_clock() {
    for expired in [TimeObservation { wall_ms: 200, monotonic_ms: 109 },
        TimeObservation { wall_ms: 199, monotonic_ms: 110 },
        TimeObservation { wall_ms: u64::MAX, monotonic_ms: u64::MAX }]
    {
        let mut model = trace(ActionKind::SignExact);
        let original = model.original_bounds();
        arm(&mut model);
        let effect = prepare(&mut model);
        send_at(&mut model, focus(), TimeObservation { wall_ms: 199, monotonic_ms: 109 }).unwrap();
        assert_eq!(model.original_bounds(), original);
        assert_eq!(send_at(&mut model, Observation::FinalAdmit(effect), expired), Err(Rejection::Invalidated(Invalidation::Expired)));
        assert_eq!(model.original_bounds(), original);
    }
}

#[test]
fn clock_rollback_before_issuance_or_after_delay_is_terminal() {
    for backwards in [TimeObservation { wall_ms: 99, monotonic_ms: 11 },
        TimeObservation { wall_ms: 101, monotonic_ms: 9 },
        TimeObservation { wall_ms: 100, monotonic_ms: 11 },
        TimeObservation { wall_ms: 101, monotonic_ms: 10 }]
    {
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        let effect = prepare(&mut model);
        assert_eq!(send_at(&mut model, Observation::FinalAdmit(effect.clone()), backwards),
            Err(Rejection::Invalidated(Invalidation::ClockRollback)));
        assert!(send(&mut model, Observation::FinalAdmit(effect)).is_err());
        assert_eq!(model.original_bounds(), bounds());
    }
}

#[test]
fn absolute_bounds_reject_equal_reversed_and_wrapped_values() {
    for (issued, expires) in [(10, 10), (11, 10), (u64::MAX, 0)] {
        assert_eq!(OriginalBounds::from_absolute(
            TimeObservation { wall_ms: issued, monotonic_ms: issued },
            TimeObservation { wall_ms: expires, monotonic_ms: expires }), Err(Rejection::InvalidOriginalBounds));
    }
    let original = OriginalBounds::from_absolute(
        TimeObservation { wall_ms: u64::MAX - 1, monotonic_ms: u64::MAX - 1 },
        TimeObservation { wall_ms: u64::MAX, monotonic_ms: u64::MAX }).unwrap();
    let mut model = ReviewTrace::new(scope(ActionKind::ReturnExact), original).unwrap();
    assert_eq!(send_at(&mut model, focus(), original.expires()), Err(Rejection::Invalidated(Invalidation::Expired)));
}

#[test]
fn consumed_then_expired_can_report_no_effect_but_never_reissue() {
    let mut model = trace(ActionKind::SignExact);
    arm(&mut model);
    let effect = prepare(&mut model);
    admit(&mut model, &effect);
    assert_eq!(send_at(&mut model, Observation::OutcomeObserved {
        effect: effect.clone(), outcome: EffectOutcome::KnownNoEffect,
    }, bounds().expires()), Ok(ObservationReceipt::OutcomeObserved));
    assert!(send_at(&mut model, Observation::FinalAdmit(effect), bounds().expires()).is_err());
}

#[test]
fn committed_started_then_blur_never_admits_key_use_or_result_retention() {
    for completed_count in [5, 6] { // CommitStarted, then KeyUseExactBatch.
        let mut model = trace(ActionKind::SignExact);
        arm(&mut model);
        for _ in 0..completed_count { complete_next(&mut model); }
        let next = prepare(&mut model);
        assert_eq!(next.kind, if completed_count == 5 { EffectKind::KeyUseExactBatch } else { EffectKind::RetainExactResult });
        send(&mut model, blur()).unwrap();
        assert!(send(&mut model, Observation::FinalAdmit(next)).is_err());
    }
}

#[test]
fn every_supported_plan_is_finite_exact_and_never_extends() {
    for action in [ActionKind::ContinueExact, ActionKind::AdmitExact, ActionKind::AcquireExact,
        ActionKind::ActivateExact, ActionKind::SignExact, ActionKind::WitnessAppendExact,
        ActionKind::ReturnExact, ActionKind::HostIntakeExact, ActionKind::HostCompleteExact,
        ActionKind::HostDispatchExact]
    {
        let mut model = trace(action);
        arm(&mut model);
        let count = action.effect_order().len();
        assert!((1..=MAX_PLAN_EFFECTS).contains(&count));
        for &kind in action.effect_order() { assert_eq!(complete_next(&mut model).kind, kind); }
        assert_eq!(model.records().len(), count);
        assert_eq!(model.status(), ReviewStatus::Completed);
        let prior = model.records().last().unwrap().descriptor.clone();
        assert_eq!(send(&mut model, Observation::PrepareEffect(prior.clone())), Err(Rejection::WrongPhase));
        assert_eq!(send(&mut model, Observation::FinalAdmit(prior)), Err(Rejection::WrongPhase));
    }
}

#[test]
fn role_and_key_use_bounds_are_checked_without_broad_sign_permission() {
    let mut wrong_role = scope(ActionKind::ReturnExact);
    wrong_role.peer.role = Role::Host;
    assert!(matches!(ReviewTrace::new(wrong_role, bounds()), Err(Rejection::WrongRole)));
    for width in [0, 9, u8::MAX] {
        let mut invalid = scope(ActionKind::SignExact);
        invalid.reviewed_key_use_batch = width;
        assert!(matches!(ReviewTrace::new(invalid, bounds()), Err(Rejection::InvalidBatchWidth)));
    }
    let mut invalid = scope(ActionKind::ReturnExact);
    invalid.reviewed_key_use_batch = 1;
    assert!(matches!(ReviewTrace::new(invalid, bounds()), Err(Rejection::InvalidBatchWidth)));
    let mut valid = scope(ActionKind::SignExact);
    valid.reviewed_key_use_batch = MAX_KEY_USE_BATCH;
    let mut model = ReviewTrace::new(valid, bounds()).unwrap();
    arm(&mut model);
    for _ in 0..5 { complete_next(&mut model); }
    let mut key_use = next_effect(&model);
    assert_eq!(key_use.batch_width, 8);
    key_use.batch_width = 7;
    assert_eq!(send(&mut model, Observation::PrepareEffect(key_use)), Err(Rejection::EffectMismatch));
}

#[test]
fn return_payload_or_current_observation_never_substitutes_host_intake() {
    let mut signer = trace(ActionKind::ReturnExact);
    arm(&mut signer);
    let payload = complete_next(&mut signer);
    let mut host = trace(ActionKind::HostIntakeExact);
    arm(&mut host);
    let intake = prepare(&mut host);
    assert_ne!(payload.kind, intake.kind);
    assert_eq!(send(&mut host, Observation::FinalAdmit(payload)), Err(Rejection::EffectMismatch));
    assert!(send(&mut host, Observation::FinalAdmit(intake)).is_err());
    // Current/Ready/Finish are deliberately not admission variants in this model.
    assert_eq!(ActionKind::ReturnExact.effect_order(), &[EffectKind::DiscloseExactReturnPayload]);
}

#[test]
fn only_two_exact_drain_categories_survive_revocation_without_new_admission() {
    for action in [ActionKind::WitnessAppendExact, ActionKind::HostDispatchExact] {
        let mut model = trace(action);
        arm(&mut model);
        for _ in 1..action.effect_order().len() { complete_next(&mut model); }
        let effect = prepare(&mut model);
        admit(&mut model, &effect);
        send(&mut model, blur()).unwrap();
        outcome(&mut model, &effect, EffectOutcome::Completed);
        let kind = if action == ActionKind::WitnessAppendExact {
            DrainKind::WitnessCommittedReceiptCompletion
        } else { DrainKind::DispatchOutcomeRecord };
        let record = Observation::DrainObserved { effect: effect.clone(), kind,
            evidence_binding: BindingDescriptor([210; 32]) };
        assert_eq!(send(&mut model, record.clone()), Ok(ObservationReceipt::DrainObserved));
        assert_eq!(send(&mut model, record), Err(Rejection::InvalidDrain));
        assert!(send(&mut model, Observation::FinalAdmit(effect)).is_err());
    }
    for action in [ActionKind::ReturnExact, ActionKind::SignExact] {
        let mut model = trace(action);
        arm(&mut model);
        let effect = complete_next(&mut model);
        send(&mut model, blur()).unwrap();
        assert_eq!(send(&mut model, Observation::DrainObserved { effect,
            kind: DrainKind::DispatchOutcomeRecord, evidence_binding: BindingDescriptor([210; 32]) }),
            Err(Rejection::InvalidDrain));
    }
}

fn session() -> SessionTrace {
    let signer = trace(ActionKind::ReturnExact);
    let mut host = scope(ActionKind::HostIntakeExact);
    host.review_id = ReviewId([20; 32]); host.action_id = ActionId([21; 32]);
    host.peer.process_instance = InstanceId([22; 32]);
    host.peer.principal = PrincipalId([23; 32]);
    host.peer.worker_instance = InstanceId([24; 32]);
    host.peer.channel_instance = InstanceId([25; 32]);
    SessionTrace::new(vec![signer, ReviewTrace::new(host, bounds()).unwrap()]).unwrap()
}

fn session_send(model: &mut SessionTrace, index: usize, observation: Observation)
    -> Result<ObservationReceipt, Rejection>
{
    model.observe(Event { header: EventHeader { scope: model.reviews()[index].scope().clone(),
        sequence: model.last_sequence() + 1, observed_at: TimeObservation { wall_ms: 101, monotonic_ms: 11 } },
        observation })
}

fn session_prepare(model: &mut SessionTrace, index: usize) -> PreparedEffectDescriptor {
    session_send(model, index, focus()).unwrap();
    session_send(model, index, Observation::InitialHumanReviewed).unwrap();
    let mut effect = next_effect(&model.reviews()[index]);
    effect.effect_id = EffectId([150 + index as u8; 32]);
    effect.challenge = ChallengeId([160 + index as u8; 32]);
    session_send(model, index, Observation::PrepareEffect(effect.clone())).unwrap();
    effect
}

#[test]
fn session_blur_in_one_role_prevents_every_other_role_admission() {
    for interrupted in [0, 1] {
        for same_batch_refocus in [false, true] {
            let mut model = session();
            let signer = session_prepare(&mut model, 0);
            let host = session_prepare(&mut model, 1);
            session_send(&mut model, interrupted, Observation::FocusBatch {
                focused_at_end: same_batch_refocus, loss_observed_in_batch: true }).unwrap();
            assert_eq!(model.invalidation(), Some(Invalidation::FocusLost));
            assert!(session_send(&mut model, 0, Observation::FinalAdmit(signer)).is_err());
            assert!(session_send(&mut model, 1, Observation::FinalAdmit(host)).is_err());
            assert!(model.reviews().iter().all(|r| r.status() == ReviewStatus::Invalidated(Invalidation::FocusLost)));
        }
    }
}

#[test]
fn session_cancel_after_one_admission_only_allows_that_exact_historical_outcome() {
    let mut model = session();
    let signer = session_prepare(&mut model, 0);
    let host = session_prepare(&mut model, 1);
    session_send(&mut model, 0, Observation::FinalAdmit(signer.clone())).unwrap();
    session_send(&mut model, 1, Observation::Cancel).unwrap();
    assert_eq!(session_send(&mut model, 0, Observation::OutcomeObserved {
        effect: signer, outcome: EffectOutcome::Completed }), Ok(ObservationReceipt::OutcomeObserved));
    assert!(session_send(&mut model, 1, Observation::FinalAdmit(host)).is_err());
    assert_eq!(model.invalidation(), Some(Invalidation::Cancelled));
}

#[test]
fn session_challenges_cannot_cross_roles_even_for_prepared_only_records() {
    let mut model = session();
    let signer = session_prepare(&mut model, 0);
    session_send(&mut model, 1, focus()).unwrap();
    session_send(&mut model, 1, Observation::InitialHumanReviewed).unwrap();
    let mut host = next_effect(&model.reviews()[1]);
    host.challenge = signer.challenge;
    assert_eq!(session_send(&mut model, 1, Observation::PrepareEffect(host)), Err(Rejection::ReusedEffectOrChallenge));
    assert!(session_send(&mut model, 0, Observation::FinalAdmit(signer)).is_err());
}

#[test]
fn session_rejects_mixed_epochs_duplicate_roles_and_nonfresh_registration() {
    assert!(SessionTrace::new(Vec::new()).is_err());
    assert!(SessionTrace::new(vec![trace(ActionKind::ReturnExact), trace(ActionKind::ReturnExact)]).is_err());
    let mut second = scope(ActionKind::HostIntakeExact);
    second.session_epoch = SessionEpoch(2);
    assert!(SessionTrace::new(vec![trace(ActionKind::ReturnExact), ReviewTrace::new(second, bounds()).unwrap()]).is_err());
    let mut used = trace(ActionKind::ReturnExact);
    arm(&mut used);
    assert!(SessionTrace::new(vec![used]).is_err());
    let mut other_surface = scope(ActionKind::HostIntakeExact);
    other_surface.review_id = ReviewId([20; 32]);
    other_surface.action_id = ActionId([21; 32]);
    other_surface.review_surface_instance = InstanceId([26; 32]);
    assert!(SessionTrace::new(vec![trace(ActionKind::ReturnExact),
        ReviewTrace::new(other_surface, bounds()).unwrap()]).is_err());
}

#[test]
fn session_global_order_and_peer_loss_are_not_bypassed_by_role_switching() {
    let mut model = session();
    let signer = session_prepare(&mut model, 0);
    let host = session_prepare(&mut model, 1);
    session_send(&mut model, 0, Observation::FinalAdmit(signer.clone())).unwrap();
    session_send(&mut model, 1, Observation::PeerRestarted).unwrap();
    assert_eq!(model.reviews()[0].records()[0].progress, EffectProgress::Outcome(EffectOutcome::Unknown));
    assert!(session_send(&mut model, 1, Observation::FinalAdmit(host)).is_err());
    let mut model = session();
    let signer = session_prepare(&mut model, 0);
    assert_eq!(model.observe(Event { header: EventHeader {
        scope: model.reviews()[0].scope().clone(), sequence: 99,
        observed_at: TimeObservation { wall_ms: 101, monotonic_ms: 11 } },
        observation: Observation::FinalAdmit(signer) }), Err(Rejection::EventOrder));
    assert!(model.reviews().iter().all(|r| r.status() == ReviewStatus::Invalidated(Invalidation::EventOrder)));
}

#[test]
fn session_unknown_or_no_effect_stops_other_roles_but_allows_admitted_drain() {
    for result in [EffectOutcome::Unknown, EffectOutcome::KnownNoEffect] {
        let mut model = session();
        let signer = session_prepare(&mut model, 0);
        let host = session_prepare(&mut model, 1);
        session_send(&mut model, 0, Observation::FinalAdmit(signer.clone())).unwrap();
        session_send(&mut model, 0, Observation::OutcomeObserved { effect: signer, outcome: result }).unwrap();
        assert_eq!(model.invalidation(), Some(if result == EffectOutcome::Unknown {
            Invalidation::UnknownOutcome
        } else { Invalidation::KnownNoEffect }));
        assert!(session_send(&mut model, 1, Observation::FinalAdmit(host)).is_err());

        let mut model = session();
        let signer = session_prepare(&mut model, 0);
        let host = session_prepare(&mut model, 1);
        session_send(&mut model, 0, Observation::FinalAdmit(signer.clone())).unwrap();
        session_send(&mut model, 1, Observation::FinalAdmit(host.clone())).unwrap();
        session_send(&mut model, 0, Observation::OutcomeObserved { effect: signer, outcome: result }).unwrap();
        assert_eq!(session_send(&mut model, 1, Observation::OutcomeObserved {
            effect: host, outcome: EffectOutcome::Completed }), Ok(ObservationReceipt::OutcomeObserved));
        assert!(model.invalidation().is_some());
    }
}

#[test]
fn session_original_expiry_and_rollback_close_all_without_renewing_bounds() {
    for at in [bounds().expires(), TimeObservation { wall_ms: 100, monotonic_ms: 11 }] {
        let mut model = session();
        let signer = session_prepare(&mut model, 0);
        let host = session_prepare(&mut model, 1);
        let originals: Vec<_> = model.reviews().iter().map(|review| review.original_bounds()).collect();
        assert!(model.observe(Event { header: EventHeader {
            scope: model.reviews()[0].scope().clone(), sequence: model.last_sequence() + 1,
            observed_at: at }, observation: Observation::FinalAdmit(signer) }).is_err());
        assert!(session_send(&mut model, 1, Observation::FinalAdmit(host)).is_err());
        assert_eq!(originals, model.reviews().iter().map(|review| review.original_bounds()).collect::<Vec<_>>());
    }
}
