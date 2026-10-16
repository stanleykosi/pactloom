use super::*;
use crate::{TransactionStatus, tests::fixture, validate_context};
const NOW: u64 = 1_800_000_020;
const TXID: &str = "0101010101010101010101010101010101010101010101010101010101010101";
fn observation(source: &str, status: TransactionStatus) -> SourceObservation {
    let (mut id, p, i, t, b) = fixture();
    id.source_id = source.into();
    let mut context = validate_context(&id, &p, &i, &t, &b, &t, NOW - 10, NOW).unwrap();
    if let TransactionStatus::Included { block, .. } = &status
        && block.height == context.tip.height
    {
        context.tip.hash = block.hash.clone();
    }
    SourceObservation {
        source_id: source.into(),
        observation: Ok(TransactionObservation {
            transaction_id: TXID.into(),
            context,
            confirms_raw_transaction_id: !matches!(status, TransactionStatus::NotObserved),
            status,
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
        }),
    }
}
fn included(confirmations: u64, hash: u8) -> TransactionStatus {
    TransactionStatus::Included {
        block: BlockIdentity {
            height: 4_498_145 - confirmations,
            hash: hex::encode([hash; 32]),
        },
        confirmations,
    }
}
fn reconciler(sources: &[&str]) -> SettlementReconciler {
    SettlementReconciler::new(
        TXID,
        4_498_200,
        ConfirmationPolicy::new(10, 10, sources.iter().map(|s| (*s).into()).collect()).unwrap(),
    )
    .unwrap()
}
#[test]
fn confirmation_reorg_and_disappearance_reduce_confidence_without_clearing_exposure() {
    let mut r = reconciler(&["a"]);
    let confirmed = r
        .reconcile(&[observation("a", included(10, 2))], NOW)
        .unwrap();
    assert!(confirmed.state.confirmation_policy_met());
    assert_eq!(
        confirmed.state_at(NOW + 60),
        SettlementObservationState::Stale
    );
    let reorg = r
        .reconcile(&[observation("a", TransactionStatus::Reorganized)], NOW + 1)
        .unwrap();
    assert_eq!(reorg.state, SettlementObservationState::Reorganized);
    assert!(reorg.confidence_lost && reorg.reorganization_observed);
    assert_eq!(reorg.last_inclusion, confirmed.last_inclusion);
    let mined_again = r
        .reconcile(&[observation("a", included(1, 3))], NOW + 2)
        .unwrap();
    assert!(mined_again.reorganization_observed);
    assert!(matches!(
        mined_again.state,
        SettlementObservationState::Included {
            confirmations: 1,
            ..
        }
    ));
    let lost = r
        .reconcile(&[observation("a", TransactionStatus::NotObserved)], NOW + 3)
        .unwrap();
    assert_eq!(lost.state, SettlementObservationState::InclusionUncertain);
    for report in [confirmed, reorg, mined_again, lost] {
        assert!(
            !report.clears_authorization_exposure
                && !report.permits_replacement
                && !report.independently_consensus_verified
        );
    }
}
#[test]
fn all_selected_sources_are_required_and_disagreement_never_votes_into_success() {
    let mut r = reconciler(&["a", "b"]);
    let ok = r
        .reconcile(
            &[
                observation("a", included(10, 2)),
                observation("b", included(10, 2)),
            ],
            NOW,
        )
        .unwrap();
    assert!(ok.state.confirmation_policy_met());
    let missing = r
        .reconcile(&[observation("a", included(10, 2))], NOW)
        .unwrap();
    assert_eq!(
        missing.state,
        SettlementObservationState::BackendUnavailable
    );
    assert!(missing.confidence_lost);
    let partial = r
        .reconcile(
            &[
                SourceObservation {
                    source_id: "a".into(),
                    observation: Err(ChainError::Timeout),
                },
                observation("b", included(10, 2)),
            ],
            NOW,
        )
        .unwrap();
    assert_eq!(partial.source_tips.len(), 1);
    assert_eq!(partial.source_tips[0].source_id, "b");
    let contradictory = r
        .reconcile(
            &[
                observation("a", included(10, 2)),
                observation("b", TransactionStatus::NotObserved),
            ],
            NOW,
        )
        .unwrap();
    assert_eq!(
        contradictory.state,
        SettlementObservationState::Contradictory
    );
    let mut behind = observation("b", included(10, 2));
    if let Ok(o) = &mut behind.observation {
        o.context.tip.height -= 1;
        if let TransactionStatus::Included { confirmations, .. } = &mut o.status {
            *confirmations -= 1;
        }
    }
    assert_eq!(
        r.reconcile(&[observation("a", included(10, 2)), behind], NOW)
            .unwrap()
            .state,
        SettlementObservationState::MissingAncestry
    );
    let mut fork = observation("b", included(10, 2));
    fork.observation.as_mut().unwrap().context.tip.hash = hex::encode([9; 32]);
    assert_eq!(
        r.reconcile(&[observation("a", included(10, 2)), fork], NOW)
            .unwrap()
            .state,
        SettlementObservationState::Contradictory
    );
}
#[test]
fn stale_and_malformed_observations_do_not_retain_a_success_label() {
    let mut r = reconciler(&["a"]);
    r.reconcile(&[observation("a", included(10, 2))], NOW)
        .unwrap();
    let stale = r
        .reconcile(&[observation("a", included(10, 2))], NOW + 51)
        .unwrap();
    assert_eq!(stale.state, SettlementObservationState::Stale);
    assert!(stale.confidence_lost);
    let mut inflated = observation("a", included(1, 2));
    if let TransactionStatus::Included { confirmations, .. } =
        &mut inflated.observation.as_mut().unwrap().status
    {
        *confirmations = 10;
    }
    assert_eq!(
        r.reconcile(&[inflated], NOW).unwrap().state,
        SettlementObservationState::Contradictory
    );
    let mut wrong = observation("a", included(10, 2));
    wrong.observation.as_mut().unwrap().transaction_id = hex::encode([4; 32]);
    assert_eq!(
        r.reconcile(&[wrong], NOW).unwrap().state,
        SettlementObservationState::Contradictory
    );
    let duplicate = [
        observation("a", included(10, 2)),
        observation("a", included(10, 2)),
    ];
    assert_eq!(
        r.reconcile(&duplicate, NOW).unwrap().state,
        SettlementObservationState::Contradictory
    );
}
#[test]
fn expiry_boundary_is_height_based_and_never_a_replacement_permission() {
    let policy = ConfirmationPolicy::new(10, 10, vec!["a".into()]).unwrap();
    let mut r = SettlementReconciler::new(TXID, 4_498_144, policy.clone()).unwrap();
    // Inclusion at the exact expiry height is permitted, one block later is not.
    assert!(matches!(
        r.reconcile(&[observation("a", included(1, 2))], NOW)
            .unwrap()
            .state,
        SettlementObservationState::Included { .. }
    ));
    let mut r = SettlementReconciler::new(TXID, 4_498_134, policy.clone()).unwrap();
    let report = r
        .reconcile(&[observation("a", TransactionStatus::NotObserved)], NOW)
        .unwrap();
    assert_eq!(report.state, SettlementObservationState::PastExpiryObserved);
    assert!(!report.permits_replacement && !report.clears_authorization_exposure);
    let mut r = SettlementReconciler::new(TXID, 4_498_135, policy).unwrap();
    assert_eq!(
        r.reconcile(&[observation("a", TransactionStatus::NotObserved)], NOW)
            .unwrap()
            .state,
        SettlementObservationState::NotObserved
    );
    assert_eq!(
        r.reconcile(&[observation("a", included(1, 2))], NOW)
            .unwrap()
            .state,
        SettlementObservationState::Contradictory
    );
}
#[test]
fn restart_never_restores_fresh_success_and_bounds_fail_closed() {
    let mut r = reconciler(&["a"]);
    let report = r
        .reconcile(&[observation("a", included(10, 2))], NOW)
        .unwrap();
    let restored = SettlementReconciler::restore(report).unwrap();
    assert_eq!(
        restored.last_report().unwrap().state_at(NOW),
        SettlementObservationState::Stale
    );
    for confirmations in [0, 101] {
        assert!(ConfirmationPolicy::new(confirmations, 10, vec!["a".into()]).is_err());
    }
    assert!(ConfirmationPolicy::new(10, 0, vec!["a".into()]).is_err());
    assert!(ConfirmationPolicy::new(10, 10, vec!["a".into(), "a".into()]).is_err());
    assert!(ConfirmationPolicy::new(10, 10, vec!["private?token=x".into()]).is_err());
    assert!(
        SettlementReconciler::new(
            TXID,
            0,
            ConfirmationPolicy::new(10, 10, vec!["a".into()]).unwrap()
        )
        .is_err()
    );
}

#[test]
fn restored_confirmation_loss_survives_degradation_until_fresh_recovery() {
    let confirmed = reconciler(&["a"])
        .reconcile(&[observation("a", included(10, 2))], NOW)
        .unwrap();
    let cases = [
        (vec![], SettlementObservationState::BackendUnavailable),
        (
            vec![SourceObservation {
                source_id: "a".into(),
                observation: Err(ChainError::Timeout),
            }],
            SettlementObservationState::BackendUnavailable,
        ),
        (
            vec![observation("a", TransactionStatus::NotObserved)],
            SettlementObservationState::InclusionUncertain,
        ),
        (
            vec![observation("a", TransactionStatus::Reorganized)],
            SettlementObservationState::Reorganized,
        ),
        (
            vec![SourceObservation {
                source_id: "a".into(),
                observation: Err(ChainError::StaleChain),
            }],
            SettlementObservationState::Stale,
        ),
        (
            vec![SourceObservation {
                source_id: "a".into(),
                observation: Err(ChainError::ContradictoryChain),
            }],
            SettlementObservationState::Contradictory,
        ),
    ];
    for (evidence, expected) in cases {
        let mut restored = SettlementReconciler::restore(confirmed.clone()).unwrap();
        assert!(restored.last_report().unwrap().confidence_lost);
        let degraded = restored.reconcile(&evidence, NOW + 1).unwrap();
        assert_eq!(degraded.state, expected);
        assert!(degraded.confidence_lost);
        assert_eq!(degraded.last_inclusion, confirmed.last_inclusion);
        // The operator reconstructs this reconciler from its durable snapshot
        // each tick. More than one restart must not erase the prior loss signal.
        let mut again = SettlementReconciler::restore(degraded).unwrap();
        let still_degraded = again.reconcile(&evidence, NOW + 2).unwrap();
        assert_eq!(still_degraded.state, expected);
        assert!(still_degraded.confidence_lost);
        let recovered = again
            .reconcile(&[observation("a", included(10, 2))], NOW + 3)
            .unwrap();
        assert!(recovered.state.confirmation_policy_met());
        assert!(!recovered.confidence_lost);
        assert!(!recovered.clears_authorization_exposure && !recovered.permits_replacement);
        let lost_again = again.reconcile(&[], NOW + 4).unwrap();
        assert!(lost_again.confidence_lost);
    }
}
