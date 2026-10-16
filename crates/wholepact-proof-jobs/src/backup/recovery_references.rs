//! Bounded semantic inventory of immutable historical proof checkpoints.
//! No worker is started and no saved success label establishes a current proof,
//! authorization, delivery permission, or chain observation.
use super::super::{self as jobs, CheckpointScope, JobState};
use std::collections::BTreeSet;
use wholepact_storage_security::bundle::{
    BundleError, JournalKind,
    recovery::{RecoveryCell, RecoveryProvenance, RecoveryTable, VerifiedRecoveryComponent},
};

pub struct ProofRecoveryReference {
    pub job_id: String,
    pub scope_digest: String,
    pub request_digest: String,
    pub scope: CheckpointScope,
    pub historical_state: JobState,
    pub retained_result_digest: Option<String>,
}

pub fn recovery_references(
    source: &VerifiedRecoveryComponent,
) -> Result<Vec<ProofRecoveryReference>, BundleError> {
    recovery_references_parts(source.provenance(), source.tables())
}

/// Trusted native complete-inventory validation after private-data approval.
/// No user-facing disclosure is authorized; use historical_proof for handoff.
pub fn successor_recovery_references(
    source: &wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
) -> Result<Vec<ProofRecoveryReference>, BundleError> {
    recovery_references_parts(source.provenance(), source.tables())
}

/// Complete owner validation of a sealed archived current journal. This is
/// historical inspection only and cannot start a worker or release an artifact.
pub fn archived_recovery_references(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
) -> Result<Vec<ProofRecoveryReference>, BundleError> {
    recovery_references_parts(source.provenance(), source.tables())
}

pub(super) fn recovery_references_parts(
    p: &RecoveryProvenance,
    tables: &[RecoveryTable],
) -> Result<Vec<ProofRecoveryReference>, BundleError> {
    if p.kind != JournalKind::ProofWitness
        || p.application_id != super::TEMPLATE.application_id
        || p.schema_version != super::TEMPLATE.schema_version
    {
        return Err(BundleError::Unsupported);
    }
    let table = tables
        .iter()
        .find(|table| table.name() == "proof_jobs")
        .ok_or(BundleError::Unsupported)?;
    let expected = [
        "job_id",
        "principal_id",
        "idem_key",
        "request_digest",
        "scope",
        "input_digest",
        "input",
        "policy",
        "maximum_actions",
        "state",
        "attempt",
        "result",
        "result_digest",
    ];
    if table.columns().iter().map(String::as_str).ne(expected) || table.rows().len() > 64 {
        return Err(BundleError::Integrity);
    }
    let mut result = Vec::with_capacity(table.rows().len());
    let mut ids = BTreeSet::new();
    for row in table.rows() {
        let c = row.cells();
        if c.len() != expected.len() {
            return Err(BundleError::Integrity);
        }
        let job_id = text(&c[0])?;
        let principal = text(&c[1])?;
        let idem = text(&c[2])?;
        let request = text(&c[3])?;
        let encoded_scope = blob(&c[4], 8192)?;
        let scope: CheckpointScope =
            serde_json::from_slice(encoded_scope).map_err(|_| BundleError::Integrity)?;
        jobs::validate_scope(&scope).map_err(|_| BundleError::Integrity)?;
        let input = blob(&c[6], jobs::MAX_ARTIFACT_BYTES)?;
        let encoded_policy = blob(&c[7], jobs::MAX_POLICY_BYTES)?;
        let policy = jobs::policy::decode(encoded_policy).map_err(|_| BundleError::Integrity)?;
        let maximum_actions =
            usize::try_from(integer(&c[8])?).map_err(|_| BundleError::Integrity)?;
        let limits = wholepact_protocol::proving::ProvingLimits { maximum_actions };
        jobs::validate_input(input, &policy, &scope, limits).map_err(|_| BundleError::Integrity)?;
        let state = JobState::parse(text(&c[9])?).map_err(|_| BundleError::Integrity)?;
        let _attempt = u32::try_from(integer(&c[10])?).map_err(|_| BundleError::Integrity)?;
        if !ids.insert(job_id.to_string())
            || principal != scope.principal_id
            || jobs::job_id_for_key(principal, idem).map_err(|_| BundleError::Integrity)? != job_id
            || text(&c[5])? != jobs::digest(input)
            || request
                != jobs::framed_digest(&[
                    encoded_scope,
                    input,
                    encoded_policy,
                    &(maximum_actions as u64).to_le_bytes(),
                ])
        {
            return Err(BundleError::Integrity);
        }
        let retained_result_digest = match (&c[11], &c[12]) {
            (RecoveryCell::Null, RecoveryCell::Null) if state != JobState::Succeeded => None,
            (RecoveryCell::Blob(bytes), RecoveryCell::Text(digest))
                if state == JobState::Succeeded
                    && bytes.len() <= jobs::MAX_ARTIFACT_BYTES
                    && jobs::digest(bytes) == *digest =>
            {
                Some(digest.clone())
            }
            _ => return Err(BundleError::Integrity),
        };
        result.push(ProofRecoveryReference {
            job_id: job_id.into(),
            scope_digest: jobs::digest(encoded_scope),
            request_digest: request.into(),
            scope,
            historical_state: state,
            retained_result_digest,
        });
    }
    let events = tables
        .iter()
        .find(|table| table.name() == "proof_events")
        .ok_or(BundleError::Unsupported)?;
    if events
        .columns()
        .iter()
        .map(String::as_str)
        .ne(["sequence", "job_id", "state", "attempt"])
    {
        return Err(BundleError::Integrity);
    }
    for row in events.rows() {
        let c = row.cells();
        if c.len() != 4 || integer(&c[0])? <= 0 || !ids.contains(text(&c[1])?) {
            return Err(BundleError::Integrity);
        }
        JobState::parse(text(&c[2])?).map_err(|_| BundleError::Integrity)?;
        u32::try_from(integer(&c[3])?).map_err(|_| BundleError::Integrity)?;
    }
    Ok(result)
}

fn text(cell: &RecoveryCell) -> Result<&str, BundleError> {
    match cell {
        RecoveryCell::Text(value) => Ok(value),
        _ => Err(BundleError::Integrity),
    }
}
fn blob(cell: &RecoveryCell, maximum: usize) -> Result<&[u8], BundleError> {
    match cell {
        RecoveryCell::Blob(value) if value.len() <= maximum => Ok(value),
        _ => Err(BundleError::Integrity),
    }
}
fn integer(cell: &RecoveryCell) -> Result<i64, BundleError> {
    match cell {
        RecoveryCell::Integer(value) => Ok(*value),
        _ => Err(BundleError::Integrity),
    }
}
