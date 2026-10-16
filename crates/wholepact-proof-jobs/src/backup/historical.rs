//! Exact, current-native-approved metadata only. No proof/witness bytes, worker,
//! recovered job activation or rerun capability is returned.
use super::recovery_references::recovery_references_parts;
use serde::Serialize;
use wholepact_storage_security::bundle::{
    BundleError,
    recovery::{
        RecoveryTable,
        evidence::{RecoveredEvidence, history::*},
    },
};

#[derive(Serialize)]
pub struct HistoricalProofMetadata {
    pub origin: HistoricalOrigin,
    pub references: HistoricalReferences,
    pub request_digest: String,
    pub historical_state: crate::JobState,
    pub retained_result_digest: Option<String>,
    pub restrictions: HistoricalRestrictions,
}
pub fn historical_proof<'a>(
    source: &RecoveredEvidence,
    principal: &str,
    job_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalProofMetadata>, BundleError> {
    historical_proof_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        job_id,
        authority,
    )
}

/// Current archived job metadata under one exact, freshly approved disclosure.
/// The sealed archive identity includes its root, selected node and entry; a
/// matching journal checksum from another capsule is not interchangeable.
pub fn archived_historical_proof<'a>(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
    principal: &str,
    job_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalProofMetadata>, BundleError> {
    historical_proof_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        job_id,
        authority,
    )
}

fn historical_proof_parts<'a>(
    identity: HistoricalDisclosureIdentity<'_>,
    tables: &[RecoveryTable],
    principal: &str,
    job_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalProofMetadata>, BundleError> {
    let reference = recovery_references_parts(identity.provenance(), tables)?
        .into_iter()
        .find(|item| item.job_id == job_id)
        .ok_or(BundleError::Invalid)?;
    let references = HistoricalReferences {
        artifact_id: reference.job_id.clone(),
        historical_principal_id: reference.scope.principal_id.clone(),
        candidate_id: Some(reference.scope.candidate_id.clone()),
        proof_job_id: Some(reference.job_id.clone()),
        account_ids: reference.scope.account_ids.clone(),
        manifest_digest: Some(reference.scope.manifest_digest.clone()),
        proof_scope_digest: Some(reference.scope_digest.clone()),
        proved_artifact_digest: reference.retained_result_digest.clone(),
        ..HistoricalReferences::default()
    };
    let metadata = HistoricalProofMetadata {
        origin: HistoricalOrigin::from_source(identity),
        references: references.clone(),
        request_digest: reference.request_digest,
        historical_state: reference.historical_state,
        retained_result_digest: reference.retained_result_digest,
        restrictions: HistoricalRestrictions::default(),
    };
    HistoricalDisclosure::authorize_from_source(
        identity,
        principal,
        HistoricalAction::ProofMetadata,
        references,
        metadata,
        authority,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
