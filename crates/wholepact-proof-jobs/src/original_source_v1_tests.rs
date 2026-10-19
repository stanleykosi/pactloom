//! Data-only encrypted source and first-attempt continuity regressions. These
//! tests do not create native approval, run a proof, sign, submit, or recover a
//! process. Synthetic row mutations are negative fixtures, never success proof.
use super::*;
use std::{cell::Cell, path::PathBuf};
use wholepact_protocol::synthetic::review_fixture;
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};

const KEY: [u8; 32] = [0x39; 32];
const IDEM: &str = "synthetic-original-source-checkpoint";
struct Allow;
impl LocalProofConsent for Allow {
    fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
        scope.principal_id == "synthetic-original-source-owner"
    }
}
struct Deny;
impl LocalProofConsent for Deny {
    fn permits(&self, _: &CheckpointScope, _: LocalAction) -> bool {
        false
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    jobs: ProofJobStore,
    pczt: Vec<u8>,
    policy: ReviewPolicy,
    scope: CheckpointScope,
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("synthetic-original-proof.sqlite");
        let jobs = ProofJobStore::from_original_encrypted_connection_v1(
            create_encrypted(&path, &DatabaseKey::from_bytes(KEY)).unwrap(),
        )
        .unwrap();
        let fixture = review_fixture().unwrap();
        let review = verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
        let scope = CheckpointScope {
            principal_id: "synthetic-original-source-owner".into(),
            candidate_id: "synthetic-original-source-candidate".into(),
            manifest_digest: hex::encode(fixture.policy.manifest_digest),
            artifact_digest: digest(&fixture.pczt_bytes),
            effects_commitment: review.shielded_sighash().into(),
            coordination_request_digest: "34".repeat(32),
            review_binding: review.review_binding().into(),
            account_ids: fixture
                .policy
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect(),
            local_operator: "synthetic-original-source-prover".into(),
            purpose: "data-only original checkpoint regression".into(),
            retention_policy: "temporary encrypted fixture only".into(),
        };
        Self {
            _dir: dir,
            path,
            jobs,
            pczt: fixture.pczt_bytes,
            policy: fixture.policy,
            scope,
        }
    }
    fn enqueue(&self) -> OriginalEnqueueOutcomeV1<'_> {
        self.jobs
            .original_source_v1()
            .unwrap()
            .enqueue_original_once_v1(
                &self.scope,
                IDEM,
                &self.pczt,
                &self.policy,
                ProvingLimits { maximum_actions: 8 },
                &Allow,
            )
            .unwrap()
    }
    fn counts(&self) -> (u64, u64) {
        self.jobs
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT (SELECT count(*) FROM proof_jobs),(SELECT count(*) FROM proof_events)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }
}

#[test]
fn original_factory_is_distinct_and_reopen_retains_actual_origin_only() {
    let f = Fixture::new();
    let original = f.jobs.original_source_v1().unwrap().origin_commitment();
    let legacy = ProofJobStore::from_encrypted_connection(
        open_encrypted(&f.path, &DatabaseKey::from_bytes(KEY)).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        legacy.original_source_v1(),
        Err(JobError::InvalidRequest)
    ));
    let reopened = ProofJobStore::from_original_encrypted_connection_v1(
        open_encrypted(&f.path, &DatabaseKey::from_bytes(KEY)).unwrap(),
    )
    .unwrap();
    let source = reopened.original_source_v1().unwrap();
    assert_eq!(source.origin_commitment(), original);
    source.check_current().unwrap();
    assert!(
        source
            .status_for_key(
                &f.scope.principal_id,
                IDEM,
                &f.scope.coordination_request_digest,
                &Allow
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn only_confirmed_new_enqueue_yields_continuation_and_replay_never_does() {
    let f = Fixture::new();
    let (first, fresh) = f.enqueue().into_parts();
    let fresh = fresh.unwrap();
    assert_eq!(fresh.summary(), &first);
    assert!(fresh.matches_source(&f.jobs.original_source_v1().unwrap()));
    assert_eq!(f.counts(), (1, 1));
    let (again, second) = f.enqueue().into_parts();
    assert_eq!(first, again);
    assert!(second.is_none());
    assert_eq!(f.counts(), (1, 1));
    let mut different = f.scope.clone();
    different.purpose.push_str(" changed");
    assert!(matches!(
        f.jobs
            .original_source_v1()
            .unwrap()
            .enqueue_original_once_v1(
                &different,
                IDEM,
                &f.pczt,
                &f.policy,
                ProvingLimits { maximum_actions: 8 },
                &Allow,
            ),
        Err(JobError::IdempotencyConflict)
    ));
    assert_eq!(f.counts(), (1, 1));
    // Identical inode and key on another actual handle do not transfer this
    // live continuation to an independently opened facade.
    let reopened = ProofJobStore::from_original_encrypted_connection_v1(
        open_encrypted(&f.path, &DatabaseKey::from_bytes(KEY)).unwrap(),
    )
    .unwrap();
    let other = reopened.original_source_v1().unwrap();
    assert_eq!(
        other.origin_commitment(),
        f.jobs.original_source_v1().unwrap().origin_commitment()
    );
    assert!(!fresh.matches_source(&other));
}

#[test]
fn reopen_of_queued_row_is_inspect_only_and_cannot_reissue_continuation() {
    let f = Fixture::new();
    let (first, token) = f.enqueue().into_parts();
    drop(token);
    let reopened = ProofJobStore::from_original_encrypted_connection_v1(
        open_encrypted(&f.path, &DatabaseKey::from_bytes(KEY)).unwrap(),
    )
    .unwrap();
    let source = reopened.original_source_v1().unwrap();
    let (saved, fresh) = source
        .enqueue_original_once_v1(
            &f.scope,
            IDEM,
            &f.pczt,
            &f.policy,
            ProvingLimits { maximum_actions: 8 },
            &Allow,
        )
        .unwrap()
        .into_parts();
    assert_eq!(saved, first);
    assert!(fresh.is_none());
    assert_eq!(
        source
            .status(&f.scope.principal_id, &first.job_id, &Allow)
            .unwrap(),
        first
    );
    assert!(matches!(
        source.load_verified(&f.scope.principal_id, &first.job_id, &Allow),
        Err(JobError::StateConflict)
    ));
}

#[test]
fn refused_consent_and_failed_event_transaction_return_no_token_or_rows() {
    let f = Fixture::new();
    assert!(matches!(
        f.jobs
            .original_source_v1()
            .unwrap()
            .enqueue_original_once_v1(
                &f.scope,
                IDEM,
                &f.pczt,
                &f.policy,
                ProvingLimits { maximum_actions: 8 },
                &Deny,
            ),
        Err(JobError::ConsentDenied)
    ));
    assert_eq!(f.counts(), (0, 0));
    f.jobs.connection.lock().unwrap().execute_batch(
        "CREATE TRIGGER synthetic_abort_queued BEFORE INSERT ON proof_events BEGIN SELECT RAISE(ABORT,'synthetic'); END;",
    ).unwrap();
    assert!(matches!(
        f.jobs
            .original_source_v1()
            .unwrap()
            .enqueue_original_once_v1(
                &f.scope,
                IDEM,
                &f.pczt,
                &f.policy,
                ProvingLimits { maximum_actions: 8 },
                &Allow,
            ),
        Err(JobError::Storage)
    ));
    assert_eq!(f.counts(), (0, 0));
    f.jobs
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER synthetic_abort_queued")
        .unwrap();
    assert!(f.enqueue().into_parts().1.is_some());
}

#[test]
fn source_lock_contention_refuses_without_wait_or_new_entry() {
    let f = Fixture::new();
    let source = f.jobs.original_source_v1().unwrap();
    let held = f.jobs.connection.lock().unwrap();
    assert_eq!(source.check_current(), Err(JobError::ResourceExhausted));
    assert!(matches!(
        source.enqueue_original_once_v1(
            &f.scope,
            IDEM,
            &f.pczt,
            &f.policy,
            ProvingLimits { maximum_actions: 8 },
            &Allow
        ),
        Err(JobError::ResourceExhausted)
    ));
    drop(held);
    assert_eq!(f.counts(), (0, 0));
}

#[test]
fn consumed_continuation_retains_atomic_queued_attempt_zero_and_request_gates() {
    for (state, attempt) in [
        ("queued", 1),
        ("running", 1),
        ("uncertain", 0),
        ("failed", 1),
    ] {
        let f = Fixture::new();
        let (saved, fresh) = f.enqueue().into_parts();
        f.jobs
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE proof_jobs SET state=?1,attempt=?2 WHERE job_id=?3",
                params![state, attempt, &saved.job_id],
            )
            .unwrap();
        assert_eq!(
            fresh.unwrap().run_original_queued_v1(&Allow),
            Err(JobError::StateConflict)
        );
        assert_eq!(f.counts(), (1, 1));
    }
    let f = Fixture::new();
    let (saved, fresh) = f.enqueue().into_parts();
    f.jobs
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE proof_jobs SET request_digest=?1 WHERE job_id=?2",
            params!["ab".repeat(32), &saved.job_id],
        )
        .unwrap();
    assert_eq!(
        fresh.unwrap().run_original_queued_v1(&Allow),
        Err(JobError::IdempotencyConflict)
    );
    assert_eq!(f.counts(), (1, 1));
    let f = Fixture::new();
    let (_, fresh) = f.enqueue().into_parts();
    assert_eq!(
        fresh.unwrap().run_original_queued_v1(&Deny),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(f.counts(), (1, 1));
}

#[test]
fn original_path_replacement_refuses_continuation_before_any_proof_effect() {
    let f = Fixture::new();
    let (_, fresh) = f.enqueue().into_parts();
    // Exclusive creation correctly refuses the original live WAL/SHM sidecars.
    // Prepare a separate closed encrypted file, then replace only the main path;
    // leave the original held connection and its sidecars intact for the check.
    let replacement_path = f.path.with_extension("replacement");
    let replacement =
        create_encrypted(&replacement_path, &DatabaseKey::from_bytes([0x40; 32])).unwrap();
    drop(replacement);
    std::fs::rename(&f.path, f.path.with_extension("retained-original")).unwrap();
    std::fs::rename(&replacement_path, &f.path).unwrap();
    assert_eq!(
        fresh.unwrap().run_original_queued_v1(&Allow),
        Err(JobError::Storage)
    );
    assert_eq!(f.counts(), (1, 1));
}

#[test]
fn live_file_identity_is_rechecked_inside_enqueue_after_consent_callback() {
    struct MoveDuringRetain {
        path: PathBuf,
        calls: Cell<u32>,
    }
    impl LocalProofConsent for MoveDuringRetain {
        fn permits(&self, _: &CheckpointScope, action: LocalAction) -> bool {
            assert_eq!(action, LocalAction::RetainPrivateWitnesses);
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == 2 {
                std::fs::rename(&self.path, self.path.with_extension("retained-original")).unwrap();
            }
            true
        }
    }
    let f = Fixture::new();
    let consent = MoveDuringRetain {
        path: f.path.clone(),
        calls: Cell::new(0),
    };
    assert!(matches!(
        f.jobs
            .original_source_v1()
            .unwrap()
            .enqueue_original_once_v1(
                &f.scope,
                IDEM,
                &f.pczt,
                &f.policy,
                ProvingLimits { maximum_actions: 8 },
                &consent,
            ),
        Err(JobError::Storage)
    ));
    assert_eq!(consent.calls.get(), 2);
    assert_eq!(f.counts(), (0, 0));
}

#[test]
fn selected_attempt_history_rejects_real_queued_job_without_repair_or_effect() {
    let f = Fixture::new();
    let (queued, token) = f.enqueue().into_parts();
    drop(token);
    let source = f.jobs.original_source_v1().unwrap();
    assert_eq!(
        source.original_attempt_history_digest_v1(&f.scope.principal_id, &queued.job_id, &Allow),
        Err(JobError::StateConflict)
    );
    assert_eq!(
        source.original_attempt_history_digest_v1(&f.scope.principal_id, &queued.job_id, &Deny),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(
        source
            .status(&f.scope.principal_id, &queued.job_id, &Allow)
            .unwrap(),
        queued
    );
    assert_eq!(f.counts(), (1, 1));
}

#[test]
fn selected_event_digest_binds_complete_inert_shape_and_refuses_every_extra_transition() {
    let f = Fixture::new();
    let (queued, token) = f.enqueue().into_parts();
    drop(token);
    let mut inert = record(
        &f.jobs.connection.lock().unwrap(),
        &f.scope.principal_id,
        &queued.job_id,
    )
    .unwrap()
    .unwrap();
    // In-memory shape only, NEVER written as a successful proof row or passed
    // to a source factory/issuer. Actual proof success is separately qualified.
    inert.summary.state = JobState::Succeeded;
    inert.summary.attempt = 1;
    inert.summary.result_digest = Some("56".repeat(32));
    inert.summary.proof_verified = true;
    let original = vec![
        (3, "queued".into(), 0),
        (7, "running".into(), 1),
        (9, "succeeded".into(), 1),
    ];
    let expected = original_event_history_digest_v1(&inert, &original).unwrap();
    let invalid = vec![
        vec![],
        original[..2].to_vec(),
        vec![
            original[0].clone(),
            original[1].clone(),
            original[2].clone(),
            original[2].clone(),
        ],
        vec![
            original[1].clone(),
            original[0].clone(),
            original[2].clone(),
        ],
        vec![
            (0, "queued".into(), 0),
            original[1].clone(),
            original[2].clone(),
        ],
        vec![
            original[0].clone(),
            (3, "running".into(), 1),
            original[2].clone(),
        ],
        vec![
            original[0].clone(),
            (7, "running".into(), 2),
            original[2].clone(),
        ],
        vec![
            original[0].clone(),
            (7, "uncertain".into(), 1),
            original[2].clone(),
        ],
        vec![
            original[0].clone(),
            original[1].clone(),
            (9, "failed".into(), 1),
        ],
    ];
    for events in invalid {
        assert_eq!(
            original_event_history_digest_v1(&inert, &events),
            Err(JobError::StateConflict)
        );
    }
    let changed_sequence = vec![
        (4, "queued".into(), 0),
        original[1].clone(),
        original[2].clone(),
    ];
    assert_ne!(
        original_event_history_digest_v1(&inert, &changed_sequence).unwrap(),
        expected
    );
    inert.request_digest = "67".repeat(32);
    assert_ne!(
        original_event_history_digest_v1(&inert, &original).unwrap(),
        expected
    );
    let before_scope = original_event_history_digest_v1(&inert, &original).unwrap();
    inert.scope.retention_policy.push_str(" altered");
    let prior = original_event_history_digest_v1(&inert, &original).unwrap();
    assert_ne!(prior, before_scope);
    inert.summary.result_digest = Some("78".repeat(32));
    assert_ne!(
        original_event_history_digest_v1(&inert, &original).unwrap(),
        prior
    );
    inert.summary.attempt = 2;
    assert_eq!(
        original_event_history_digest_v1(&inert, &original),
        Err(JobError::StateConflict)
    );
    inert.summary.attempt = 1;
    inert.summary.state = JobState::Uncertain;
    assert_eq!(
        original_event_history_digest_v1(&inert, &original),
        Err(JobError::StateConflict)
    );
    assert_eq!(f.counts(), (1, 1));
}
