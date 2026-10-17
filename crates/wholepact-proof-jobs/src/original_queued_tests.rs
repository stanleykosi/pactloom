//! Negative atomic admission fixtures only. Directly changed synthetic states
//! are not genuine completion evidence and no proof is executed by these tests.
use super::*;
use wholepact_protocol::synthetic::review_fixture;
use wholepact_storage_security::{DatabaseKey, create_encrypted};

struct FixtureConsent;
impl LocalProofConsent for FixtureConsent {
    fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
        scope.principal_id == "synthetic-queued-only-owner"
    }
}

#[test]
fn original_queued_admission_atomically_denies_every_prior_attempt_without_private_proving() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(
            dir.path().join("synthetic-original-queued.sqlite"),
            &DatabaseKey::from_bytes([0x64; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let fixture = review_fixture().unwrap();
    let review = verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
    let scope = CheckpointScope {
        principal_id: "synthetic-queued-only-owner".into(),
        candidate_id: "synthetic-original".into(),
        manifest_digest: hex::encode(fixture.policy.manifest_digest),
        artifact_digest: digest(&fixture.pczt_bytes),
        effects_commitment: review.shielded_sighash().into(),
        coordination_request_digest: "12".repeat(32),
        review_binding: review.review_binding().into(),
        account_ids: fixture
            .policy
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        local_operator: "synthetic-private-prover".into(),
        purpose: "negative atomic state qualification".into(),
        retention_policy: "temporary synthetic encrypted fixture".into(),
    };
    let queued = jobs
        .enqueue(
            &scope,
            "synthetic-original-queued-key",
            &fixture.pczt_bytes,
            &fixture.policy,
            ProvingLimits { maximum_actions: 8 },
            &FixtureConsent,
        )
        .unwrap();
    // Succeeded rows require an actual verified result. Do not manufacture a
    // completion row merely to exercise rejection; the joined real-proof stage
    // must establish that successor separately.
    for (state, attempt) in [
        ("queued", 1),
        ("uncertain", 0),
        ("uncertain", 1),
        ("running", 1),
        ("failed", 1),
    ] {
        // Deliberately synthetic negative records, never a constructor fixture.
        jobs.connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE proof_jobs SET state=?1,attempt=?2 WHERE job_id=?3",
                params![state, attempt, &queued.job_id],
            )
            .unwrap();
        let before = jobs
            .status(&scope.principal_id, &queued.job_id, &FixtureConsent)
            .unwrap();
        assert_eq!(
            jobs.run_original_queued(&scope.principal_id, &queued.job_id, &FixtureConsent),
            Err(JobError::StateConflict)
        );
        let after = jobs
            .status(&scope.principal_id, &queued.job_id, &FixtureConsent)
            .unwrap();
        assert_eq!(before, after);
        assert!(after.result_digest.is_none());
    }
}
