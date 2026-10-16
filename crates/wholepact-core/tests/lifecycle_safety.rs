use wholepact_core::*;

fn released(confirmations: u32) -> Lifecycle {
    Lifecycle::new(100, confirmations)
        .unwrap()
        .apply(LifecycleEvent::PrepareProposal)
        .unwrap()
        .apply(LifecycleEvent::AwaitAuthorization)
        .unwrap()
        .apply(LifecycleEvent::RecordLocalAuthorization)
        .unwrap()
        .apply(LifecycleEvent::RecordReleaseIntent {
            operation_id: "release-1".into(),
        })
        .unwrap()
}
fn observation(status: ChainStatus, tip: u32, inclusion: Option<u32>) -> ChainObservation {
    ChainObservation {
        observation_id: "obs-1".into(),
        source_id: "synthetic-source".into(),
        trust_profile_id: "test-only".into(),
        observed_at: "2026-10-13T14:00:00Z".into(),
        tip_height: tip,
        tip_hash: "a".repeat(64),
        synchronized: true,
        status,
        inclusion_height: inclusion,
        inclusion_hash: inclusion.map(|_| "b".repeat(64)),
        confirmations: inclusion.map(|h| tip - h + 1).unwrap_or(0),
        evidence_ref: "test-fixture-not-chain-evidence".into(),
    }
}
fn history(exposure: AuthorizationExposure) -> Vec<RevisionExposure> {
    vec![RevisionExposure {
        proposal_id: "proposal-old".into(),
        obligation_id: "obligation-1".into(),
        maximum_net_debit: Amount::from_zatoshis(100).unwrap(),
        exposure,
        input_ids: vec!["input-original".into()],
    }]
}

#[test]
fn cancellation_decline_and_obsolete_do_not_recall_released_authorization() {
    let state = released(10);
    for event in [
        LifecycleEvent::RequestCancellation,
        LifecycleEvent::Decline,
        LifecycleEvent::MarkObsolete,
        LifecycleEvent::RequireRevision,
    ] {
        let state = state.apply(event).unwrap();
        assert!(state.authorization_exposure().may_still_execute());
        assert_eq!(
            check_replacement(
                "obligation-1",
                &history(state.authorization_exposure()),
                false
            )
            .unwrap_err()
            .code,
            ErrorCode::OutstandingExposure
        );
    }
    assert!(state
        .apply(LifecycleEvent::DiscardUnreleasedAuthorization)
        .is_err());
}

#[test]
fn unsigned_closure_blocks_export_until_reviewed_again() {
    let state = Lifecycle::new(100, 10)
        .unwrap()
        .apply(LifecycleEvent::PrepareProposal)
        .unwrap()
        .apply(LifecycleEvent::AwaitAuthorization)
        .unwrap()
        .apply(LifecycleEvent::RecordLocalAuthorization)
        .unwrap();
    for event in [
        LifecycleEvent::Decline,
        LifecycleEvent::RequestCancellation,
        LifecycleEvent::FailValidation,
        LifecycleEvent::MarkObsolete,
        LifecycleEvent::RequireRevision,
    ] {
        let closed = state.apply(event).unwrap();
        assert!(closed
            .apply(LifecycleEvent::RecordReleaseIntent {
                operation_id: "late-export".into()
            })
            .is_err());
        assert!(closed
            .apply(LifecycleEvent::DiscardUnreleasedAuthorization)
            .is_ok());
    }
}

#[test]
fn timeout_and_backend_rejection_retain_exposure_and_exact_retry_identity() {
    let state = released(10)
        .apply(LifecycleEvent::RecordReadyForSubmission)
        .unwrap()
        .apply(LifecycleEvent::RecordSubmissionIntent {
            transaction_bytes_digest: "a".repeat(64),
        })
        .unwrap()
        .apply(LifecycleEvent::RecordBackendRejection)
        .unwrap();
    assert_eq!(
        state.authorization_exposure(),
        AuthorizationExposure::OutstandingUncertain
    );
    assert_eq!(state.chain_status(), ChainStatus::BackendRejected);
    assert!(state
        .apply(LifecycleEvent::RecordSubmissionIntent {
            transaction_bytes_digest: "a".repeat(64)
        })
        .is_ok());
    assert_eq!(
        state
            .apply(LifecycleEvent::RecordSubmissionIntent {
                transaction_bytes_digest: "b".repeat(64)
            })
            .unwrap_err()
            .code,
        ErrorCode::OutstandingExposure
    );
}

#[test]
fn expiry_is_inclusive_and_confidence_is_height_based() {
    let state = released(1);
    assert!(state
        .observe(observation(ChainStatus::ExpiredObserved, 100, None))
        .is_err());
    assert_eq!(
        state
            .observe(observation(ChainStatus::ExpiredObserved, 101, None))
            .unwrap()
            .authorization_exposure(),
        AuthorizationExposure::ExpiredObserved
    );
    assert!(state
        .observe(observation(
            ChainStatus::ConfirmationPolicyMet,
            100,
            Some(100)
        ))
        .is_ok());
    assert!(state
        .observe(observation(
            ChainStatus::ConfirmationPolicyMet,
            101,
            Some(101)
        ))
        .is_err());
    let state = released(10);
    assert!(state
        .observe(observation(ChainStatus::ExpiredObserved, 109, None))
        .is_err());
    assert!(state
        .observe(observation(ChainStatus::ExpiredObserved, 110, None))
        .is_ok());
    let mut stale = observation(ChainStatus::ExpiredObserved, 110, None);
    stale.synchronized = false;
    assert_eq!(
        state.observe(stale).unwrap_err().code,
        ErrorCode::StaleChain
    );
}

#[test]
fn reorganization_reopens_every_resolution_and_blocks_further_replacement() {
    for observed in [
        observation(ChainStatus::ExpiredObserved, 110, None),
        observation(ChainStatus::ConflictedObserved, 110, Some(101)),
        observation(ChainStatus::ConfirmationPolicyMet, 109, Some(100)),
    ] {
        let resolved = released(10).observe(observed).unwrap();
        assert!(!resolved.authorization_exposure().may_still_execute());
        let reopened = resolved.apply(LifecycleEvent::MarkReorganization).unwrap();
        assert_eq!(
            reopened.authorization_exposure(),
            AuthorizationExposure::OutstandingUncertain
        );
        assert!(reopened.recovery_required());
        assert_eq!(
            check_replacement(
                "obligation-1",
                &history(reopened.authorization_exposure()),
                reopened.recovery_required()
            )
            .unwrap_err()
            .code,
            ErrorCode::RecoveryRequired
        );
    }
}

#[test]
fn exposure_accounting_is_conservative_and_settled_obligations_cannot_pay_twice() {
    assert_eq!(
        outstanding_exposure(&history(AuthorizationExposure::Released))
            .unwrap()
            .as_zatoshis(),
        100
    );
    assert_eq!(
        outstanding_exposure(&history(AuthorizationExposure::ExpiredObserved)).unwrap(),
        Amount::ZERO
    );
    assert!(check_replacement(
        "obligation-1",
        &history(AuthorizationExposure::ExpiredObserved),
        false
    )
    .is_ok());
    assert!(check_replacement(
        "obligation-1",
        &history(AuthorizationExposure::Consumed),
        false
    )
    .is_err());
    assert!(check_replacement("obligation-1", &[], true).is_err());
    let mut duplicate = history(AuthorizationExposure::Released);
    duplicate.push(duplicate[0].clone());
    assert!(outstanding_exposure(&duplicate).is_err());
}

#[test]
fn contradictory_resolution_reopens_risk_without_trusting_new_success() {
    let settled = released(10)
        .observe(observation(
            ChainStatus::ConfirmationPolicyMet,
            109,
            Some(100),
        ))
        .unwrap();
    let contradiction = settled
        .observe(observation(ChainStatus::ExpiredObserved, 110, None))
        .unwrap();
    assert_eq!(
        contradiction.authorization_exposure(),
        AuthorizationExposure::OutstandingUncertain
    );
    assert!(contradiction.recovery_required());
    let mut older = observation(ChainStatus::ExpiredObserved, 110, None);
    older.observed_at = "2026-10-12T14:00:00Z".into();
    assert_eq!(
        settled.observe(older).unwrap_err().code,
        ErrorCode::StaleChain
    );
}
