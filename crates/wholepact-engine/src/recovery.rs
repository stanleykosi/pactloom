//! Complete, typed semantic inspection of authenticated coordination history.
//! Every item is historical. Account membership is a conservative union and
//! never a claim that unknown external signatures or accounts do not exist.
use super::*;
pub use crate::participant_records::historical::{
    HistoricalParticipantRecord, HistoricalParticipantSelection,
    archived_historical_participant_record, historical_participant_record,
};
use std::collections::BTreeSet;
use wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent;
use wholepact_store::recovery::StoreRecoveryInventory;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryAttempt {
    pub agreement_id: String,
    pub obligation_id: String,
    pub candidate_id: String,
    pub manifest_digest: String,
    pub job_id: Option<String>,
    pub artifact_digest: Option<String>,
    pub transaction_id: Option<String>,
    pub transaction_bytes_digest: Option<String>,
    pub account_id: Option<String>,
    pub authorization_id: Option<String>,
    pub release_operation_id: Option<String>,
}

/// Not a wire DTO or activation permission. Construction validates every
/// current envelope and every older retained operation/idempotency envelope.
pub struct CoordinationRecoveryInventory {
    store: StoreRecoveryInventory,
    attempts: Vec<RecoveryAttempt>,
    digest: String,
}
impl CoordinationRecoveryInventory {
    pub fn store_inventory(&self) -> &StoreRecoveryInventory {
        &self.store
    }
    pub fn accounts(&self) -> &BTreeSet<String> {
        self.store.accounts()
    }
    pub fn obligations(&self) -> &BTreeSet<String> {
        self.store.obligations()
    }
    pub fn attempts(&self) -> &[RecoveryAttempt] {
        &self.attempts
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

pub fn inspect_coordination_recovery(
    source: &VerifiedRecoveryComponent,
) -> Result<CoordinationRecoveryInventory> {
    inspect_coordination_inventory(StoreRecoveryInventory::inspect(source).map_err(store_error)?)
}

/// Trusted native complete-inventory validation after separate private-data
/// approval. This does not expose a user history endpoint or mutable Store.
pub fn inspect_successor_coordination_recovery(
    source: &wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
) -> Result<CoordinationRecoveryInventory> {
    inspect_coordination_inventory(
        StoreRecoveryInventory::inspect_successor(source).map_err(store_error)?,
    )
}
/// Strict archived current-generation inspection. The source is sealed by the
/// storage archive reader; inherited permissions and observations stay historical.
pub fn inspect_archived_coordination_recovery(
    source: &wholepact_storage_security::generation_archive::ArchivedGenerationSource,
) -> Result<CoordinationRecoveryInventory> {
    inspect_coordination_inventory(
        StoreRecoveryInventory::inspect_archived_generation(source).map_err(store_error)?,
    )
}

fn inspect_coordination_inventory(
    store: StoreRecoveryInventory,
) -> Result<CoordinationRecoveryInventory> {
    let mut attempts = Vec::new();
    for record in store
        .agreements()
        .iter()
        .chain(store.historical_agreements())
    {
        // Current schema writes every default/optional field explicitly. A
        // missing field or nested serde decoder that discarded an unfamiliar
        // field cannot silently become an empty recovered exposure history.
        let raw: Envelope =
            serde_json::from_value(record.payload.clone()).map_err(|_| invalid())?;
        if serde_json::to_value(&raw).map_err(|_| invalid())? != record.payload {
            return Err(invalid());
        }
        let envelope = decode(record)?;
        envelope.view.agreement.validate()?;
        planning::validate_recovery_snapshots(&envelope.view)?;
        #[cfg(feature = "transport-workflows")]
        for (id, value) in &envelope.transport_peer_grants {
            let grant: crate::transport_workflows::TransportPeerGrant =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if grant.schema_version != 1
                || grant.request.grant_id != *id
                || grant.agreement_id != record.id
                || grant.network_profile_id != envelope.view.agreement.network_profile_id
            {
                return Err(invalid());
            }
        }
        #[cfg(not(feature = "transport-workflows"))]
        if !envelope.transport_peer_grants.is_empty() {
            return Err(invalid());
        }
        if envelope.view.agreement.agreement_id != record.id {
            return Err(invalid());
        }
        for intent in &envelope.view.intents {
            intent.validate()?;
            if intent.agreement_id != record.id {
                return Err(invalid());
            }
        }
        for candidate in &envelope.view.candidates {
            let proposal = candidate.verified_snapshot()?;
            if proposal.manifest().agreement.agreement_id != record.id
                || proposal.manifest().agreement.obligation_id
                    != envelope.view.agreement.obligation_id
            {
                return Err(invalid());
            }
            let base = RecoveryAttempt {
                agreement_id: record.id.clone(),
                obligation_id: proposal.manifest().agreement.obligation_id.clone(),
                candidate_id: candidate.candidate_id.clone(),
                manifest_digest: candidate.manifest_digest.clone(),
                job_id: None,
                artifact_digest: proposal.input().artifact_digest.clone(),
                transaction_id: None,
                transaction_bytes_digest: None,
                account_id: None,
                authorization_id: None,
                release_operation_id: None,
            };
            attempts.push(base.clone());
            for job in &candidate.proof_jobs {
                let mut attempt = base.clone();
                attempt.job_id = Some(job.job_id.clone());
                attempt.artifact_digest = job
                    .result_digest
                    .clone()
                    .or_else(|| Some(job.input_digest.clone()));
                attempts.push(attempt);
            }
        }
        for (receipt_key, receipt) in &envelope.checkpoint_receipts {
            let candidate = envelope
                .view
                .candidates
                .iter()
                .find(|c| c.candidate_id == receipt.candidate_id)
                .ok_or_else(invalid)?;
            if !candidates::valid_checkpoint_receipt_index(receipt_key, &receipt.job_id)
                || receipt.manifest_digest != candidate.manifest_digest
                || receipt.prepared_revision > record.revision
            {
                return Err(invalid());
            }
            attempts.push(RecoveryAttempt {
                agreement_id: record.id.clone(),
                obligation_id: envelope.view.agreement.obligation_id.clone(),
                candidate_id: receipt.candidate_id.clone(),
                manifest_digest: receipt.manifest_digest.clone(),
                job_id: Some(receipt.job_id.clone()),
                artifact_digest: Some(receipt.artifact_digest.clone()),
                transaction_id: None,
                transaction_bytes_digest: None,
                account_id: None,
                authorization_id: None,
                release_operation_id: None,
            });
        }
        for retained in envelope.participant_records.values() {
            let archive = retained.recovery_archive();
            // Restore always discards positive currency. It also authenticates
            // the exact proposal/own-authorization/transaction associations.
            wholepact_core::records::SettlementRecord::restore(archive.clone())?;
            attempts.push(RecoveryAttempt {
                agreement_id: record.id.clone(),
                obligation_id: archive.proposal.manifest.agreement.obligation_id.clone(),
                candidate_id: archive.proposal.proposal_id.clone(),
                manifest_digest: archive.own_authorization.manifest_digest.clone(),
                job_id: None,
                artifact_digest: archive.proposal.artifact_digest.clone(),
                transaction_id: Some(archive.transaction.transaction_id.clone()),
                transaction_bytes_digest: Some(
                    archive.transaction.transaction_bytes_digest.clone(),
                ),
                account_id: Some(archive.own_authorization.account_id.clone()),
                authorization_id: Some(archive.own_authorization.authorization_record_ref.clone()),
                release_operation_id: archive.own_authorization.release_operation_id.clone(),
            });
        }
    }
    for (claim_id, claim) in store.construction_claims() {
        let proposal = claim.validate().map_err(store_error)?;
        if !store
            .agreements()
            .iter()
            .chain(store.historical_agreements())
            .any(|record| {
                record.id == proposal.manifest().agreement.agreement_id
                    && record.revision == claim.agreement_revision()
                    && record.payload.pointer("/view/agreement")
                        == serde_json::to_value(&proposal.manifest().agreement)
                            .ok()
                            .as_ref()
            })
        {
            return Err(invalid());
        }
        let checkpoint = store
            .construction_checkpoints()
            .iter()
            .find(|(id, _)| id == claim_id)
            .map(|(_, c)| c);
        // A pre-randomness claim remains an uncertain attempt even when no
        // ordinary candidate, receipt or private checkpoint was ever retained.
        attempts.push(RecoveryAttempt {
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            obligation_id: proposal.manifest().agreement.obligation_id.clone(),
            candidate_id: claim.candidate_id().into(),
            manifest_digest: proposal.manifest_digest().into(),
            job_id: checkpoint.map(|c| c.job_id.clone()),
            artifact_digest: checkpoint.map(|c| c.scope.artifact_digest.clone()),
            transaction_id: None,
            transaction_bytes_digest: None,
            account_id: None,
            authorization_id: None,
            release_operation_id: None,
        });
    }
    for (claim_id, claim) in store.construction_claims_v3() {
        let proposal = claim.validate().map_err(store_error)?;
        if !store
            .agreements()
            .iter()
            .chain(store.historical_agreements())
            .any(|record| {
                record.id == proposal.manifest().agreement.agreement_id
                    && record.revision == claim.agreement_revision()
                    && record.payload.pointer("/view/agreement")
                        == serde_json::to_value(&proposal.manifest().agreement)
                            .ok()
                            .as_ref()
            })
        {
            return Err(invalid());
        }
        let checkpoint = store
            .construction_checkpoints_v3()
            .iter()
            .find(|(id, _)| id == claim_id)
            .map(|(_, c)| c);
        // A pre-randomness claim remains an uncertain attempt even when no
        // ordinary candidate, receipt or private checkpoint was ever retained.
        attempts.push(RecoveryAttempt {
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            obligation_id: proposal.manifest().agreement.obligation_id.clone(),
            candidate_id: claim.candidate_id().into(),
            manifest_digest: proposal.manifest_digest().into(),
            job_id: checkpoint.map(|c| c.job_id.clone()),
            artifact_digest: checkpoint.map(|c| c.scope.artifact_digest.clone()),
            transaction_id: None,
            transaction_bytes_digest: None,
            account_id: None,
            authorization_id: None,
            release_operation_id: None,
        });
    }
    attempts.sort_by_cached_key(|value| serde_json::to_string(value).unwrap_or_default());
    attempts.dedup();
    // Keep the established identity byte-for-byte for claimless generations.
    // V2 is selected only when the new complete historical records exist.
    let digest =
        if store.construction_claims().is_empty() && store.construction_checkpoints().is_empty() {
            wholepact_core::proposal::canonical_digest(
                "wholepact:host-coordination-recovery-inventory:v1",
                &(
                    store.provenance(),
                    store.accounts(),
                    store.obligations(),
                    &attempts,
                    store.releases(),
                    store.effects(),
                ),
            )?
        } else {
            wholepact_core::proposal::canonical_digest(
                "wholepact:host-coordination-recovery-inventory:v2",
                &(
                    store.provenance(),
                    store.accounts(),
                    store.obligations(),
                    &attempts,
                    store.releases(),
                    store.effects(),
                    store.construction_claims(),
                    store.construction_checkpoints(),
                ),
            )?
        };
    let digest = if store.construction_claims_v3().is_empty()
        && store.construction_checkpoints_v3().is_empty()
    {
        digest
    } else {
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-coordination-recovery-inventory:v3",
            &(
                &digest,
                store.construction_claims_v3(),
                store.construction_checkpoints_v3(),
            ),
        )?
    };
    Ok(CoordinationRecoveryInventory {
        store,
        attempts,
        digest,
    })
}
fn invalid() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Historical coordination inventory has incompatible or inconsistent semantic bindings",
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
