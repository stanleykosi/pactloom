#![cfg(feature = "operator-chain")]
use std::sync::{Arc, Mutex};
use wholepact_chain::{
    ChainAdapter, ConfirmationPolicy, EncryptedSubmissionJournal, NetworkPolicy,
};
use wholepact_service::{operator::TaskFailure, operator_chain::*};
use wholepact_storage_security::{DatabaseKey, create_encrypted};
struct Deny;
impl ObservationAuthority for Deny {
    fn acquire(
        &self,
        _: &ObservationScope,
        _: u64,
    ) -> Result<Box<dyn ObservationLease + '_>, TaskFailure> {
        Err(TaskFailure::PermissionLost)
    }
}
#[test]
fn observation_requires_exact_existing_journal_and_matching_sources() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let connection = create_encrypted(
        dir.path().join("observation.sqlite"),
        &DatabaseKey::from_bytes([71; 32]),
    )
    .unwrap();
    let journal = Arc::new(Mutex::new(
        EncryptedSubmissionJournal::from_encrypted_connection(connection).unwrap(),
    ));
    let source = || {
        ChainAdapter::testnet(
            "chosen",
            "https://example.invalid",
            NetworkPolicy::default(),
        )
        .unwrap()
    };
    let policy = ConfirmationPolicy::new(3, 3, vec!["chosen".into()]).unwrap();
    // These are pure constructors: no DNS or provider calls occur.
    assert!(
        ChainObservationTask::new(
            "profile".into(),
            "missing-operation",
            policy.clone(),
            vec![source()],
            journal.clone(),
            Arc::new(Deny)
        )
        .is_err()
    );
    let wrong_policy = ConfirmationPolicy::new(3, 3, vec!["different".into()]).unwrap();
    assert!(
        ChainObservationTask::new(
            "profile".into(),
            "missing-operation",
            wrong_policy,
            vec![source()],
            journal.clone(),
            Arc::new(Deny)
        )
        .is_err()
    );
    assert!(
        ChainObservationTask::new(
            "profile".into(),
            "missing-operation",
            policy.clone(),
            vec![source(), source()],
            journal.clone(),
            Arc::new(Deny)
        )
        .is_err()
    );
    assert!(
        ChainObservationTask::new(
            "".into(),
            "missing-operation",
            policy,
            vec![source()],
            journal,
            Arc::new(Deny)
        )
        .is_err()
    );
}
