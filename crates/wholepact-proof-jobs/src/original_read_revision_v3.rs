//! Same-original proof-store observation. This detects mutation around an audit;
//! it does NOT verify a proof, inspect private artifact bytes, or grant consent.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    data_version: i64,
    total_changes: u64,
    schema_version: i64,
    user_version: i64,
    application_id: i64,
}
impl Stamp {
    fn read(connection: &Connection) -> Result<Self> {
        Ok(Self {
            data_version: connection
                .pragma_query_value(None, "data_version", |r| r.get(0))
                .map_err(db)?,
            total_changes: connection.total_changes(),
            schema_version: connection
                .pragma_query_value(None, "schema_version", |r| r.get(0))
                .map_err(db)?,
            user_version: connection
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .map_err(db)?,
            application_id: connection
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .map_err(db)?,
        })
    }
}

/// Non-Clone, non-serializable observation of one exact row on one original
/// connection. Capture before full load_verified/history validation, then check
/// afterward. Current consent, proof verification and native checks stay separate.
pub struct OriginalProofReadRevisionV3<'a> {
    source: OriginalProofJobSourceV1<'a>,
    scope: CheckpointScope,
    summary: JobSummary,
    request_digest: String,
    maximum_actions: usize,
    stamp: Stamp,
}
impl OriginalProofReadRevisionV3<'_> {
    pub fn check_current_v3(&self) -> Result<()> {
        let connection = self
            .source
            .store
            .connection
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => JobError::ResourceExhausted,
                std::sync::TryLockError::Poisoned(_) => JobError::Storage,
            })?;
        if !connection.is_autocommit() {
            return Err(JobError::StateConflict);
        }
        check_original_connection(Some(self.source.origin), &connection)?;
        if Stamp::read(&connection)? != self.stamp {
            return Err(JobError::StateConflict);
        }
        let current = record(&connection, &self.scope.principal_id, &self.summary.job_id)?
            .ok_or(JobError::NotFound)?;
        if current.scope != self.scope
            || current.summary != self.summary
            || current.request_digest != self.request_digest
            || current.maximum_actions != self.maximum_actions
            || Stamp::read(&connection)? != self.stamp
        {
            return Err(JobError::StateConflict);
        }
        check_original_connection(Some(self.source.origin), &connection)
    }
}
impl<'a> OriginalProofJobSourceV1<'a> {
    pub fn pin_original_read_revision_v3(
        &self,
        principal: &str,
        job_id: &str,
        scope: &CheckpointScope,
    ) -> Result<OriginalProofReadRevisionV3<'a>> {
        validate_scope(scope)?;
        if scope.principal_id != principal || !bounded(job_id, 128) {
            return Err(JobError::InvalidRequest);
        }
        let connection = self
            .store
            .connection
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => JobError::ResourceExhausted,
                std::sync::TryLockError::Poisoned(_) => JobError::Storage,
            })?;
        if !connection.is_autocommit() {
            return Err(JobError::StateConflict);
        }
        check_original_connection(Some(self.origin), &connection)?;
        let stamp = Stamp::read(&connection)?;
        let retained = record(&connection, principal, job_id)?.ok_or(JobError::NotFound)?;
        if &retained.scope != scope
            || stamp.application_id != APPLICATION_ID
            || stamp.user_version != 1
            || Stamp::read(&connection)? != stamp
        {
            return Err(JobError::StateConflict);
        }
        check_original_connection(Some(self.origin), &connection)?;
        Ok(OriginalProofReadRevisionV3 {
            source: OriginalProofJobSourceV1 {
                store: self.store,
                origin: self.origin,
            },
            scope: scope.clone(),
            summary: retained.summary,
            request_digest: retained.request_digest,
            maximum_actions: retained.maximum_actions,
            stamp,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! Real encrypted enqueue/change-detector integration. No proof execution,
    //! native issuer, completed-row fabrication, signing or authority acceptance.
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_protocol::synthetic::review_fixture;
    use wholepact_storage_security::{create_encrypted, open_encrypted, DatabaseKey};
    struct Consent;
    impl LocalProofConsent for Consent {
        fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
            scope.principal_id == "synthetic-revision-owner"
        }
    }
    struct Fixture {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        store: ProofJobStore,
        scope: CheckpointScope,
        job: String,
    }
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("original-proof.sqlite");
        let store = ProofJobStore::from_original_encrypted_connection_v1(
            create_encrypted(&path, &DatabaseKey::from_bytes([0x65; 32])).unwrap(),
        )
        .unwrap();
        let upstream = review_fixture().unwrap();
        let review = verify_review(&upstream.pczt_bytes, &upstream.policy).unwrap();
        let scope = CheckpointScope {
            principal_id: "synthetic-revision-owner".into(),
            candidate_id: "synthetic-revision-candidate".into(),
            manifest_digest: hex::encode(upstream.policy.manifest_digest),
            artifact_digest: digest(&upstream.pczt_bytes),
            effects_commitment: review.shielded_sighash().into(),
            coordination_request_digest: "32".repeat(32),
            review_binding: review.review_binding().into(),
            account_ids: upstream
                .policy
                .participants
                .iter()
                .map(|owner| owner.account_id.clone())
                .collect(),
            local_operator: "synthetic-local-prover".into(),
            purpose: "encrypted change detector only".into(),
            retention_policy: "temporary synthetic checkpoint".into(),
        };
        let source = store.original_source_v1().unwrap();
        let (summary, fresh) = source
            .enqueue_original_once_v1(
                &scope,
                "synthetic-revision-enqueue",
                &upstream.pczt_bytes,
                &upstream.policy,
                ProvingLimits { maximum_actions: 8 },
                &Consent,
            )
            .unwrap()
            .into_parts();
        drop(fresh); // No proof runner is admitted or invoked.
        assert_eq!(summary.state, JobState::Queued);
        Fixture {
            _dir: dir,
            path,
            store,
            scope,
            job: summary.job_id,
        }
    }
    #[test]
    fn encrypted_proof_pin_is_change_detection_not_verified_proof_or_consent() {
        let f = fixture();
        let source = f.store.original_source_v1().unwrap();
        let pin = source
            .pin_original_read_revision_v3(&f.scope.principal_id, &f.job, &f.scope)
            .unwrap();
        pin.check_current_v3().unwrap();
        assert!(source
            .load_verified(&f.scope.principal_id, &f.job, &Consent)
            .is_err());
        pin.check_current_v3().unwrap();
        let mut wrong = f.scope.clone();
        wrong.candidate_id.push_str("-other");
        assert!(source
            .pin_original_read_revision_v3(&f.scope.principal_id, &f.job, &wrong)
            .is_err());
        assert!(source
            .pin_original_read_revision_v3("different-principal", &f.job, &f.scope)
            .is_err());
    }
    #[test]
    fn encrypted_proof_pin_detects_already_open_other_connection_and_own_writes() {
        let f = fixture();
        let external = open_encrypted(&f.path, &DatabaseKey::from_bytes([0x65; 32])).unwrap();
        let source = f.store.original_source_v1().unwrap();
        let pin = source
            .pin_original_read_revision_v3(&f.scope.principal_id, &f.job, &f.scope)
            .unwrap();
        // Negative mutation only, never evidence of genuine proof completion.
        external
            .connection()
            .execute(
                "UPDATE proof_jobs SET idem_key='changed-key' WHERE job_id=?1",
                [&f.job],
            )
            .unwrap();
        assert_eq!(pin.check_current_v3(), Err(JobError::StateConflict));
        let next = source
            .pin_original_read_revision_v3(&f.scope.principal_id, &f.job, &f.scope)
            .unwrap();
        f.store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE proof_jobs SET idem_key='changed-again' WHERE job_id=?1",
                [&f.job],
            )
            .unwrap();
        assert_eq!(next.check_current_v3(), Err(JobError::StateConflict));
    }
    #[test]
    fn encrypted_proof_pin_detects_schema_and_original_file_changes() {
        let f = fixture();
        let source = f.store.original_source_v1().unwrap();
        let pin = source
            .pin_original_read_revision_v3(&f.scope.principal_id, &f.job, &f.scope)
            .unwrap();
        f.store
            .connection
            .lock()
            .unwrap()
            .execute_batch("CREATE TABLE synthetic_revision_probe(value INTEGER)")
            .unwrap();
        assert_eq!(pin.check_current_v3(), Err(JobError::StateConflict));
        let next = source
            .pin_original_read_revision_v3(&f.scope.principal_id, &f.job, &f.scope)
            .unwrap();
        std::fs::rename(&f.path, f.path.with_extension("moved")).unwrap();
        std::fs::write(&f.path, b"synthetic replacement, not a proof store").unwrap();
        assert_eq!(next.check_current_v3(), Err(JobError::Storage));
    }
}
