//! Source-preserving status-only inspection under an embedding's held directory
//! exclusion lock. This owner cannot become a job store, worker or private reader.
use super::*;
use std::path::Path;
use wholepact_storage_security::{DatabaseFileIdentity, DatabaseKey, EncryptedReadSnapshot};

pub struct ProofStatusSnapshot {
    snapshot: EncryptedReadSnapshot,
}
impl ProofStatusSnapshot {
    /// Requires complete source quiescence for this owner's lifetime. The
    /// bounded private encrypted copy includes durable WAL, excludes SHM, and
    /// may leave encrypted temporary remnants after a crash/cleanup failure.
    /// The embedding must obtain native disclosure approval before this call.
    pub fn open(path: &Path, key: &DatabaseKey) -> Result<Self> {
        let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)
            .map_err(|_| JobError::Storage)?;
        let c = snapshot.connection();
        let app: i64 = c
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(db)?;
        let version: i64 = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db)?;
        if app != APPLICATION_ID || version != 1 {
            return Err(JobError::UnsupportedSchema);
        }
        let reference = Connection::open_in_memory().map_err(db)?;
        reference
            .execute_batch(backup::TEMPLATE.create_sql)
            .map_err(db)?;
        if schema(c)? != schema(&reference)? {
            return Err(JobError::UnsupportedSchema);
        }
        let integrity: String = c
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(db)?;
        let jobs: i64 = c
            .query_row("SELECT count(*) FROM proof_jobs", [], |r| r.get(0))
            .map_err(db)?;
        if integrity != "ok"
            || !(0..=MAX_JOBS).contains(&jobs)
            || c.query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
            .map_err(db)?
            .is_some()
        {
            return Err(JobError::Storage);
        }
        let owner = Self { snapshot };
        owner.check_source_unchanged()?;
        Ok(owner)
    }
    pub fn source_database_identity(&self) -> Result<DatabaseFileIdentity> {
        self.snapshot
            .source_database_identity()
            .map_err(|_| JobError::Storage)
    }
    pub fn check_source_unchanged(&self) -> Result<()> {
        self.snapshot
            .check_source_unchanged()
            .map_err(|_| JobError::Storage)
    }
    pub fn status_for_key(
        &self,
        principal: &str,
        idempotency_key: &str,
        expected_coordination_request_digest: &str,
        consent: &dyn LocalProofConsent,
    ) -> Result<Option<JobSummary>> {
        self.check_source_unchanged()?;
        if !hash_text(expected_coordination_request_digest)
            || !bounded(principal, 128)
            || !(16..=128).contains(&idempotency_key.len())
            || !idempotency_key.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(JobError::InvalidRequest);
        }
        let job_id = job_id_for_key(principal, idempotency_key)?;
        // An inconsistent stored key/job binding is corruption, never absence.
        let matching: i64 = self.snapshot.connection().query_row(
            "SELECT count(*) FROM proof_jobs WHERE job_id=?2 OR (principal_id=?1 AND idem_key=?3)",
            params![principal, &job_id, idempotency_key], |r| r.get(0),
        ).map_err(db)?;
        if matching > 1 {
            return Err(JobError::Storage);
        }
        let binding: Option<(String, String, String)> = self.snapshot.connection().query_row(
            "SELECT job_id,idem_key,principal_id FROM proof_jobs WHERE job_id=?2 OR (principal_id=?1 AND idem_key=?3)",
            params![principal, &job_id, idempotency_key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional().map_err(db)?;
        if binding
            .as_ref()
            .is_some_and(|(stored_id, stored_key, stored_principal)| {
                stored_id != &job_id
                    || stored_key != idempotency_key
                    || stored_principal != principal
            })
        {
            return Err(JobError::Storage);
        }
        let result = if let Some(r) = record(self.snapshot.connection(), principal, &job_id)? {
            gate(consent, &r.scope, LocalAction::InspectStatus)?;
            let has_result: bool = self
                .snapshot
                .connection()
                .query_row(
                    "SELECT result IS NOT NULL FROM proof_jobs WHERE job_id=?1",
                    [&job_id],
                    |row| row.get(0),
                )
                .map_err(db)?;
            if !hash_text(&r.request_digest)
                || !hash_text(&r.summary.input_digest)
                || r.summary
                    .result_digest
                    .as_ref()
                    .is_some_and(|value| !hash_text(value))
                || (r.summary.state == JobState::Succeeded) != r.summary.result_digest.is_some()
                || has_result != r.summary.result_digest.is_some()
            {
                return Err(JobError::Storage);
            }
            // This is retained job-state metadata only. No proof bytes are read
            // or newly verified by this inspector, even for a saved success.
            if r.scope.coordination_request_digest != expected_coordination_request_digest {
                return Err(JobError::IdempotencyConflict);
            }
            Some(r.summary)
        } else {
            None
        };
        self.check_source_unchanged()?;
        Ok(result)
    }
}
type SchemaRow = (String, String, String, Option<String>);
fn schema(c: &Connection) -> Result<Vec<SchemaRow>> {
    let mut statement = c.prepare("SELECT type,CASE WHEN length(name)<=128 THEN name ELSE NULL END,CASE WHEN length(tbl_name)<=128 THEN tbl_name ELSE NULL END,CASE WHEN length(sql)<=16384 THEN sql ELSE NULL END FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name,tbl_name,sql LIMIT 32").map_err(db)?;
    let rows = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    Ok(rows)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
