//! Pure synthetic lookup tests; no authenticated history or issuer is fabricated.
use super::*;
fn operation() -> OwnerControlRequest {
    let (_, account, policy) = crate::offline::tests::fixture();
    OwnerControlRequest {
        operation_id: "synthetic-original-offline-enrollment".into(),
        account_id: account.account_id,
        network_profile_id: account.network_profile_id,
        writer_epoch: 1,
        expected_head: AuthorityHead {
            sequence: 0,
            digest: "11".repeat(32),
        },
        control: OwnerControl::EnrollOfflinePolicy {
            policy,
            expected_previous_digest: None,
        },
    }
}
fn policy_digest(operation: &OwnerControlRequest) -> String {
    let OwnerControl::EnrollOfflinePolicy { policy, .. } = &operation.control else {
        panic!("fixture");
    };
    policy.policy_digest().unwrap()
}
#[test]
fn exact_policy_digest_preserves_the_original_operation_identity() {
    let operation = operation();
    let digest = policy_digest(&operation);
    let found = offline_enrollment_operation_from([&operation].into_iter(), &digest)
        .unwrap()
        .unwrap();
    assert!(found == &operation);
    assert_eq!(found.operation_id, "synthetic-original-offline-enrollment");
}
#[test]
fn absent_or_malformed_policy_digest_cannot_choose_an_unrelated_enrollment() {
    let operation = operation();
    assert!(
        offline_enrollment_operation_from([&operation].into_iter(), &"99".repeat(32))
            .unwrap()
            .is_none()
    );
    assert!(offline_enrollment_operation_from([&operation].into_iter(), "not-a-digest").is_err());
}
#[test]
fn repeated_policy_digest_with_distinct_operations_is_ambiguous() {
    let first = operation();
    let mut second = first.clone();
    second.operation_id = "synthetic-later-enrollment".into();
    second.expected_head.sequence = 4;
    assert!(matches!(
        offline_enrollment_operation_from([&first, &second].into_iter(), &policy_digest(&first)),
        Err(AuthorityError::Conflict)
    ));
}
